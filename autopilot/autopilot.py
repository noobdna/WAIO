#!/usr/bin/env python3
"""autopilot/autopilot.py -- WAIO Autopilot mission engine (WAIO-AUTO-001).

  autopilot.py run    --mission FILE --state DIR   # start, or resume the same mission
  autopilot.py status --state DIR

One mission in, then autonomous decompose -> run -> test -> repair ->
re-test until the mission's own acceptance checks pass, or until it must
stop. See autopilot_lib.py for the mission format and state machine.

Before EVERY task start (and every retry) the engine requires all three:
  1. Guardian not blocking and no Emergency Shutdown lock -- read through
     security/lib.sh itself (the same functions every WAIO worker uses);
     any error doing so counts as blocking (fail closed);
  2. a fresh heartbeat from the independent watchdog process
     (autopilot_watchdog.py) -- if the monitor is down, no new task starts;
  3. the command passes the policy (never run otherwise).
A failed check saves state and exits (PAUSED_GUARDIAN / AWAITING_HUMAN);
`run` again resumes without repeating PASSED work.

Task commands run with a scrubbed environment, in their own process
group, under a macOS sandbox profile (no network; writes only inside the
workspace and temp dirs; no reads of ~/.ssh or the Keychain). Where
sandbox-exec is unavailable (e.g. Linux CI) the run records
sandbox="unavailable" and relies on the policy alone.

  autopilot.py stop       --state DIR [--now]   # operator stop request
  autopilot.py clear-stop --state DIR           # allow `run` to resume

`stop` closes the gate: no new task or retry starts, running work
finishes. `stop --now` also asks the watchdog to stop running work.
The watchdog does the same on its own when the Guardian turns blocking
or the shutdown lock appears. An interrupted task is not counted as a
failed attempt.

Exit codes: 0 COMPLETE, 1 INCOMPLETE, 2 usage/mission error,
3 AWAITING_HUMAN, 4 PAUSED_GUARDIAN, 5 another engine holds the lock,
6 STOPPED_BY_OPERATOR.
"""

import argparse
import ctypes
import ctypes.util
import datetime
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import autopilot_lib as al  # noqa: E402

WAIO_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENV_KEEP = ("PATH", "HOME", "LANG", "LC_ALL", "LC_CTYPE", "TMPDIR")
WATCHDOG_MAX_AGE = float(os.environ.get("AUTOPILOT_WATCHDOG_MAX_AGE", "15"))
# How often run_cmd samples the task's process tree, and how long it keeps
# reading output after the task's group was killed before giving up on a
# pipe that an escaped process still holds open.
TREE_SAMPLE_S = float(os.environ.get("AUTOPILOT_TREE_SAMPLE_S", "0.5"))
DRAIN_TIMEOUT_S = float(os.environ.get("AUTOPILOT_DRAIN_TIMEOUT_S", "3"))
LLAMA_BIN = os.environ.get("AUTOPILOT_LLAMA_BIN", "/Volumes/LocalAI/runtime/llama-b11700/llama-completion")
LLAMA_MODEL = os.environ.get("AUTOPILOT_LLAMA_MODEL", "/Volumes/LocalAI/models/qwen2.5-3b-instruct-q4_k_m.gguf")


def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class Engine(object):
    def __init__(self, mission_path, state_dir):
        self.state_dir = os.path.abspath(state_dir)
        self.mission_path = mission_path
        self.lock = threading.Lock()
        self.stop_reason = None
        self.sandbox = "macos" if shutil.which("sandbox-exec") else "unavailable"
        self.task_roots = set()
        self.orphan_mode = init_orphan_tracking()
        # Per-engine sandbox signature (macOS): which of the TAG_OPS this
        # engine's task sandbox denies. Two engines in one login session share
        # a responsible process, so without it each would reap the other's
        # task processes (a false stop of work still running elsewhere).
        self.sandbox_tag = new_sandbox_tag()
        if self.orphan_mode["kind"] == "responsible":
            self.orphan_mode["tag"] = self.sandbox_tag

    # ---- persistence -------------------------------------------------
    def p(self, name):
        return os.path.join(self.state_dir, name)

    def event(self, kind, **kw):
        rec = dict(ts=now_iso(), event=kind, **kw)
        with open(self.p("events.jsonl"), "a") as f:
            f.write(json.dumps(rec, sort_keys=True) + "\n")

    def save(self):
        tmp = self.p(".state.json.tmp")
        with open(tmp, "w") as f:
            json.dump(self.state, f, indent=1, sort_keys=True)
        os.replace(tmp, self.p("state.json"))

    # ---- engine lock + heartbeat ---------------------------------------
    def acquire(self):
        lock = self.p("engine.lock")
        try:
            os.mkdir(lock)
        except FileExistsError:
            try:
                pid = int(open(os.path.join(lock, "pid")).read().strip())
                os.kill(pid, 0)
                return False
            except (OSError, ValueError):
                self.event("stale_engine_lock_taken_over")
        with open(os.path.join(lock, "pid"), "w") as f:
            f.write(str(os.getpid()))
        return True

    def release(self):
        shutil.rmtree(self.p("engine.lock"), ignore_errors=True)

    def heartbeat_loop(self):
        while not self._hb_stop.is_set():
            with open(self.p("engine.hb"), "w") as f:
                f.write("%d %f\n" % (os.getpid(), time.time()))
            self._hb_stop.wait(2)

    # ---- the three gates ---------------------------------------------
    def guardian_ok(self):
        script = ('source "$1/security/lib.sh" >/dev/null 2>&1 || exit 9; '
                  'is_shutdown_active && exit 3; guardian_is_blocking && exit 2; exit 0')
        env = {k: v for k, v in os.environ.items() if k in ENV_KEEP or k.startswith("WAIO_")}
        try:
            rc = subprocess.run(["bash", "-c", script, "_", WAIO_DIR], env=env, cwd=WAIO_DIR,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20).returncode
        except (OSError, subprocess.TimeoutExpired):
            rc = 9
        return {0: (True, ""), 2: (False, "guardian_blocking"), 3: (False, "shutdown_lock_active")}.get(
            rc, (False, "guardian_check_error_fail_closed"))

    def watchdog_ok(self):
        try:
            age = time.time() - os.path.getmtime(self.p("watchdog.hb"))
        except OSError:
            return False, "watchdog_heartbeat_missing"
        return (True, "") if age <= WATCHDOG_MAX_AGE else (False, "watchdog_heartbeat_stale_%ds" % age)

    def operator_ok(self):
        return (False, "operator_stop_requested") if os.path.exists(self.p("STOP")) else (True, "")

    def gates(self):
        for check in (self.operator_ok, self.guardian_ok, self.watchdog_ok):
            ok, why = check()
            if not ok:
                return False, why
        return True, ""

    # ---- running one command -------------------------------------------
    def sandbox_profile(self):
        ws = os.path.realpath(self.ws)
        home = os.path.expanduser("~")
        return ('(version 1)(allow default)(deny network*)'
                '(deny file-write*)'
                '(allow file-write* (subpath "%s") (subpath "/private/tmp") (subpath "/private/var/folders")'
                ' (literal "/dev/null") (literal "/dev/tty") (regex #"^/dev/fd/"))'
                '(deny file-read* (subpath "%s/.ssh") (subpath "%s/Library/Keychains") (subpath "%s/security/state"))'
                '%s'
                % (ws, home, home, WAIO_DIR, "".join("(deny %s)" % op for op in self.sandbox_tag)))

    def run_cmd(self, cmd, tid, phase):
        env = {k: v for k, v in os.environ.items() if k in ENV_KEEP}
        env["AUTOPILOT_TASK"] = tid
        # A repair may rewrite a source file within the same second and at
        # the same size; Python would then trust its stale bytecode cache.
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        argv = ["bash", "-c", cmd]
        if self.sandbox == "macos":
            argv = ["sandbox-exec", "-p", self.sandbox_profile()] + argv
        timeout = self.mission["limits"]["task_timeout_s"]
        task_start = time.time()
        proc = subprocess.Popen(argv, cwd=self.ws, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                stdin=subprocess.DEVNULL, start_new_session=True)
        with self.lock:
            self.task_roots.add(proc.pid)
            ts = self.state["tasks"][tid]
            # pgid_start lets the watchdog tell this group from a later one
            # that reused the number (it never signals a mismatch).
            ts.update(pid=proc.pid, pgid=proc.pid, pgid_start=self.process_table().get(proc.pid, (0, ""))[1],
                      phase=phase, deadline=time.time() + timeout)
            self.save()
        seen, deadline = {}, time.time() + timeout
        out = None
        while out is None:
            try:
                out, _ = proc.communicate(timeout=min(TREE_SAMPLE_S, max(0.05, deadline - time.time())))
                rc = proc.returncode
            except subprocess.TimeoutExpired:
                self.sample_descendants(proc.pid, seen)
                if time.time() < deadline:
                    continue
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except OSError:
                    pass
                rc = "TIMEOUT"
                try:
                    out, _ = proc.communicate(timeout=DRAIN_TIMEOUT_S)
                except subprocess.TimeoutExpired:
                    # An escaped process still holds the output pipe. Waiting
                    # for EOF would hang the engine; reap it and move on.
                    self.reap_escaped(tid, seen, proc.pid, task_start, set(self.task_roots))
                    proc.stdout.close()
                    proc.wait()
                    out = b""
                    self.event("task_output_abandoned", task=tid)
        with self.lock:
            self.task_roots.discard(proc.pid)
            roots = set(self.task_roots)
        self.reap_escaped(tid, seen, proc.pid, task_start, roots)
        with self.lock:
            for k in ("pid", "pgid", "pgid_start", "deadline", "phase"):
                self.state["tasks"][tid].pop(k, None)
            self.save()
        return rc, (out or b"").decode("utf-8", "replace")

    # ---- escaped descendants -------------------------------------------
    @staticmethod
    def process_table():
        """{pid: (ppid, start)} for every process, or {} if ps fails."""
        try:
            out = subprocess.run(["ps", "-A", "-o", "pid=,ppid=,lstart="], capture_output=True,
                                 text=True, timeout=10).stdout
        except (OSError, subprocess.TimeoutExpired):
            return {}
        table = {}
        for line in out.splitlines():
            parts = line.split(None, 2)
            if len(parts) == 3 and parts[0].isdigit() and parts[1].isdigit():
                table[int(parts[0])] = (int(parts[1]), parts[2].strip())
        return table

    @classmethod
    def sample_descendants(cls, root, seen):
        """Add every current descendant of root to seen as pid -> start
        time. A process that setsid()s out of the task's group keeps its
        parent until that parent exits, so sampling while the task runs
        records it even though killpg will no longer reach it."""
        table = cls.process_table()
        frontier, found = [root], set()
        while frontier:
            parent = frontier.pop()
            for pid, (ppid, _) in table.items():
                if ppid == parent and pid not in found:
                    found.add(pid)
                    frontier.append(pid)
        for pid in found:
            seen.setdefault(pid, table[pid][1])

    def reap_escaped(self, tid, seen, pgid, task_start, live_roots):
        """SIGKILL task processes that outlived the task: descendants recorded
        by sampling (only while their start time still matches, never a
        reused pid), plus escaped orphans identified afterwards
        (find_escaped_orphans), which catches a double fork that finished
        between two samples."""
        table = self.process_table() if seen else {}
        targets = set()
        for pid, start in seen.items():
            if table.get(pid, (None, None))[1] != start:
                continue
            try:
                if os.getpgid(pid) == pgid:
                    continue  # still in the task's group: killpg's job, not an escape
            except OSError:
                continue
            targets.add(pid)
        found = find_escaped_orphans(self.orphan_mode, task_start, live_roots)
        orphans = {pid for pid, z in found.items() if not z} - targets
        zombies = {pid for pid, z in found.items() if z} - targets
        killed, reaped = [], 0
        for pid in sorted(targets | orphans):
            try:
                os.kill(pid, signal.SIGKILL)
                killed.append(pid)
            except OSError:
                pass
        if self.orphan_mode["kind"] == "subreaper":
            for pid in sorted(orphans | zombies):
                try:
                    os.waitpid(pid, 0)  # reparented to us: reap it, or it stays a zombie
                    reaped += pid in zombies
                except OSError:
                    pass
        if killed or reaped:
            self.event("escaped_process_killed", task=tid, count=len(killed),
                       orphans=len(orphans & set(killed)), zombies_reaped=reaped, mode=self.orphan_mode["kind"])

    # ---- repair --------------------------------------------------------
    def repair(self, task, test_out):
        rep = task.get("repair")
        if not rep:
            return "no_repair_defined"
        if rep["kind"] == "cmd":
            ok, rule = al.policy_check(rep["cmd"], self.mission["forbidden"])
            if not ok:
                return "repair_blocked_policy:" + rule
            rc, out = self.run_cmd(rep["cmd"], task["id"], "repair")
            return "repair_cmd_exit_%s" % rc
        return self.repair_local_ai(task, rep, test_out)

    def repair_local_ai(self, task, rep, test_out):
        target = os.path.realpath(os.path.join(self.ws, rep.get("file", "")))
        if not target.startswith(os.path.realpath(self.ws) + os.sep) or not os.path.isfile(target):
            return "repair_target_outside_workspace_or_missing"
        src = open(target).read()
        prompt = ("You fix code so its tests pass. Reply with the COMPLETE corrected file in one ```python block, nothing else.\n"
                  "Instruction: %s\nFile %s:\n```python\n%s\n```\nTest output:\n%s\nCorrected file:\n"
                  % (rep.get("instruction", ""), rep["file"], src, al.redact(test_out, 1500)))
        ai_cmd = os.environ.get("AUTOPILOT_LOCAL_AI_CMD")
        try:
            if ai_cmd:
                r = subprocess.run(["bash", "-c", ai_cmd], input=prompt.encode(), capture_output=True, timeout=600)
            else:
                if not os.path.exists(LLAMA_BIN):
                    return "local_ai_unavailable"
                r = subprocess.run([LLAMA_BIN, "-m", LLAMA_MODEL, "-p", prompt, "-n", "768", "--temp", "0",
                                    "-no-cnv", "--no-display-prompt"], capture_output=True, timeout=600,
                                   stdin=subprocess.DEVNULL)
        except (OSError, subprocess.TimeoutExpired) as e:
            return "local_ai_error:%s" % type(e).__name__
        blocks = re.findall(r"```(?:python)?\n(.*?)```", r.stdout.decode("utf-8", "replace"), re.S)
        if not blocks or not blocks[-1].strip():
            return "local_ai_no_code_block"
        old_mtime = os.path.getmtime(target)
        with open(target, "w") as f:
            f.write(blocks[-1])
        # Make sure any mtime-based cache (pyc, build tools) sees a change,
        # even when the rewrite lands in the same second as the original.
        new_mtime = max(time.time(), old_mtime + 2)
        os.utime(target, (new_mtime, new_mtime))
        return "local_ai_rewrote:%s" % rep["file"]

    # ---- one task, end to end --------------------------------------------
    def execute(self, task):
        tid, lim = task["id"], self.mission["limits"]
        for c in [task.get("cmd"), task["test"]] + ([task["repair"]["cmd"]] if (task.get("repair") or {}).get("kind") == "cmd" else []):
            if c:
                ok, rule = al.policy_check(c, self.mission["forbidden"])
                if not ok:
                    self.transition(tid, "BLOCKED_POLICY", rule=rule)
                    return
        if task.get("cmd") and self.state["tasks"][tid]["attempts"] == 0 and not self.state["tasks"][tid].get("cmd_done"):
            rc, out = self.run_cmd(task["cmd"], tid, "cmd")
            self.event("task_cmd", task=tid, exit=rc, output=al.redact(out, 800))
            if rc != 0 and self.interrupted_by_gate(tid):
                return
            with self.lock:
                self.state["tasks"][tid]["cmd_done"] = True
        first = True
        while True:
            # The first test of a task started under an open gate runs to
            # completion (a graceful stop lets running work finish);
            # every RETRY needs the gate open again.
            if not first:
                if self.stop_reason:
                    self.transition(tid, "PENDING", note="stopping: " + self.stop_reason)
                    return
                ok, why = self.gates()
                if not ok:
                    self.stop_reason = why
                    self.transition(tid, "PENDING", note="gate refused before retry: " + why)
                    return
            first = False
            rc, out = self.run_cmd(task["test"], tid, "test")
            if rc == 0:
                self.transition(tid, "PASSED", test_output=al.redact(out, 800))
                return
            if self.interrupted_by_gate(tid):
                return
            if rc == "TIMEOUT":
                self.transition(tid, "TIMED_OUT")
                return
            sig = al.failure_signature(rc, out)
            with self.lock:
                nxt = al.record_failure(self.state["tasks"][tid], sig, lim["max_attempts"])
            self.event("task_test_failed", task=tid, exit=rc, signature=sig, output=al.redact(out, 800))
            if nxt != "PENDING":
                self.transition(tid, nxt, signature=sig)
                return
            result = self.repair(task, out)
            self.event("task_repair", task=tid, result=result)

    def interrupted_by_gate(self, tid):
        """A non-zero exit right after a gate closed (the watchdog stops
        running work on Guardian block / shutdown / operator stop --now)
        is an interruption, not a failure: no attempt is counted and the
        task goes back to PENDING for resume."""
        ok, why = self.gates()
        if ok:
            return False
        self.stop_reason = why
        self.transition(tid, "PENDING", note="interrupted: " + why)
        return True

    def transition(self, tid, status, **kw):
        with self.lock:
            ts = self.state["tasks"][tid]
            ts["history"].append(dict(ts=now_iso(), to=status, **kw))
            ts["status"] = status
            self.save()
        self.event("task_state", task=tid, to=status, **{k: v for k, v in kw.items() if k != "test_output"})

    # ---- workspace evidence -----------------------------------------------
    def snapshot(self):
        snap = {}
        for root, dirs, files in os.walk(self.ws):
            dirs[:] = [d for d in dirs if d not in ("__pycache__", ".git")]
            for fn in files:
                path = os.path.join(root, fn)
                try:
                    snap[os.path.relpath(path, self.ws)] = hashlib.sha256(open(path, "rb").read()).hexdigest()
                except OSError:
                    pass
        return snap

    # ---- main --------------------------------------------------------------
    def run(self):
        os.makedirs(self.state_dir, exist_ok=True)
        try:
            raw = open(self.mission_path, "rb").read()
            mission, errs = al.validate_mission(json.loads(raw))
        except (OSError, ValueError) as e:
            mission, errs = None, [str(e)]
        if errs:
            print("autopilot: mission rejected: " + "; ".join(errs), file=sys.stderr)
            return 2
        self.mission = mission
        self.ws = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(self.mission_path)), mission["workspace"]))
        if not os.path.isdir(self.ws):
            print("autopilot: workspace does not exist: " + self.ws, file=sys.stderr)
            return 2
        if not self.acquire():
            print("autopilot: another engine is running for this state dir", file=sys.stderr)
            return 5
        self._hb_stop = threading.Event()
        hb = threading.Thread(target=self.heartbeat_loop, daemon=True)
        hb.start()
        try:
            return self._run(raw)
        finally:
            self._hb_stop.set()
            self.release()

    def _run(self, raw):
        msha = hashlib.sha256(raw).hexdigest()
        if os.path.exists(self.p("state.json")):
            # Never guess from a damaged state: refuse, leave the file as evidence.
            try:
                self.state = json.load(open(self.p("state.json")))
                ok = (isinstance(self.state, dict) and isinstance(self.state.get("tasks"), dict)
                      and set(self.state["tasks"]) >= {t["id"] for t in self.mission["tasks"]}
                      and all(isinstance(v, dict) and "status" in v for v in self.state["tasks"].values()))
            except (OSError, ValueError):
                ok = False
            if not ok:
                self.event("state_unreadable_refused")
                print("autopilot: state.json is unreadable or inconsistent with the mission; refusing to resume "
                      "(file left untouched for inspection)", file=sys.stderr)
                return 2
            if self.state.get("mission_sha256") != msha:
                print("autopilot: state dir belongs to a different mission file; refusing", file=sys.stderr)
                return 2
            changed = al.resume_state(self.state, self.mission)
            self.event("resumed", changed=changed)
        else:
            self.state = al.initial_state(self.mission)
            self.state.update(mission_sha256=msha, started_at=now_iso(), workspace_before=self.snapshot(),
                              sandbox=self.sandbox)
            self.event("mission_started", mission_id=self.mission["mission_id"], sandbox=self.sandbox)
        self.save()
        deadline = time.time() + self.mission["limits"]["mission_timeout_s"]
        threads = []
        while True:
            threads = [t for t in threads if t.is_alive()]
            if self.stop_reason or time.time() > deadline:
                break
            with self.lock:
                running = {tid for tid, ts in self.state["tasks"].items() if ts["status"] == "RUNNING"}
                ready = [t for t in al.ready_tasks(self.state, self.mission) if t["id"] not in running]
                self.save()
            slots = self.mission["limits"]["max_parallel"] - len(threads)
            for task in ready[:max(slots, 0)]:
                ok, why = self.gates()
                if not ok:
                    self.stop_reason = why
                    break
                self.transition(task["id"], "RUNNING")
                th = threading.Thread(target=self.execute, args=(task,))
                th.start()
                threads.append(th)
            if not threads and not ready:
                break
            time.sleep(0.2)
        for t in threads:
            t.join()
        if time.time() > deadline and not self.stop_reason:
            self.stop_reason = "mission_timeout"
        if self.stop_reason:
            if self.stop_reason.startswith("operator"):
                self.state["status"] = "STOPPED_BY_OPERATOR"
            elif self.stop_reason.startswith(("guardian", "shutdown", "watchdog")):
                self.state["status"] = "PAUSED_GUARDIAN"
            else:
                self.state["status"] = "INCOMPLETE"
            self.state["stop_reason"] = self.stop_reason
            self.save()
            self.event("mission_paused", reason=self.stop_reason)
            print("autopilot: paused (%s); state saved, run again to resume" % self.stop_reason)
            return {"PAUSED_GUARDIAN": 4, "STOPPED_BY_OPERATOR": 6}.get(self.state["status"], 1)
        # acceptance: only meaningful once nothing is left to run
        self.state["acceptance"] = {}
        for a in self.mission["acceptance"]:
            ok, rule = al.policy_check(a["cmd"], self.mission["forbidden"])
            if not ok:
                self.state["acceptance"][a["id"]] = {"passed": False, "exit": "BLOCKED_POLICY:" + rule}
                continue
            rc, out = self._run_acceptance(a)
            self.state["acceptance"][a["id"]] = {"passed": rc == a.get("expect_exit", 0), "exit": rc, "output": al.redact(out, 800)}
        verdict, reasons = al.mission_verdict(self.state)
        self.state.update(status=verdict, reasons=reasons, finished_at=now_iso())
        after = self.snapshot()
        before = self.state.get("workspace_before", {})
        self.state["changed_files"] = sorted(k for k in set(before) | set(after) if before.get(k) != after.get(k))
        self.save()
        self.event("mission_finished", verdict=verdict, reasons=reasons)
        report = {k: self.state.get(k) for k in ("mission_id", "status", "reasons", "acceptance", "changed_files",
                                                 "sandbox", "started_at", "finished_at")}
        report["tasks"] = {tid: {"status": ts["status"], "attempts": ts["attempts"]}
                           for tid, ts in self.state["tasks"].items()}
        with open(self.p("report.json"), "w") as f:
            json.dump(report, f, indent=1, sort_keys=True)
        print("autopilot: %s%s" % (verdict, (" -- " + "; ".join(reasons)) if reasons else ""))
        return {"COMPLETE": 0, "AWAITING_HUMAN": 3}.get(verdict, 1)

    def _run_acceptance(self, a):
        self.state["tasks"]["_acceptance"] = {"status": "ACCEPTANCE", "attempts": 0, "signatures": [], "history": []}
        try:
            return self.run_cmd(a["cmd"], "_acceptance", "acceptance")
        finally:
            self.state["tasks"].pop("_acceptance", None)


# ---- escaped-orphan identification (time-independent) ------------------
# Sampling the process tree misses a double fork that completes between two
# samples: the grandchild is already reparented when we look. Each platform
# can recognize such orphans afterwards without relying on timing:
#   Linux: the engine is a child subreaper, so every orphan from a task is
#     reparented to the engine itself.
#   macOS: no subreaper, but an escaped orphan keeps the engine's
#     "responsible process" and the task sandbox (network denied). A
#     user-started app is responsible for itself, and an ordinary shell job
#     is not sandboxed, so neither can match.
_LIBC = None


def _libc():
    global _LIBC
    if _LIBC is None:
        try:
            _LIBC = ctypes.CDLL(ctypes.util.find_library("c") or None, use_errno=True)
        except OSError:
            _LIBC = False
    return _LIBC


def init_orphan_tracking():
    libc = _libc()
    if not libc:
        return {"kind": "none"}
    if sys.platform.startswith("linux"):
        try:
            if libc.prctl(36, 1, 0, 0, 0) == 0:  # PR_SET_CHILD_SUBREAPER
                return {"kind": "subreaper"}
        except AttributeError:
            pass
        return {"kind": "none"}
    if sys.platform == "darwin":
        try:
            rf = libc.responsibility_get_pid_responsible_for_pid
            rf.restype, rf.argtypes = ctypes.c_int, [ctypes.c_int]
            libc.sandbox_check.restype = ctypes.c_int
            return {"kind": "responsible", "responsible": rf(os.getpid())}
        except AttributeError:
            pass
    return {"kind": "none"}


# Operations no task needs (privileged system calls, app launching,
# NVRAM). Denying any subset is harmless, and sandbox_check reports each
# one exactly (each was verified alone and in random subsets on macOS 13).
# job-creation is excluded: sandboxed processes report it denied anyway.
TAG_OPS = ("system-audit", "system-swap", "system-set-time", "system-reboot", "system-acct",
           "system-kext-load", "nvram-delete", "nvram-set", "file-revoke", "system-package-check",
           "mach-priv-host-port", "system-nfssvc", "process-info-setcontrol", "lsopen",
           "distributed-notification-post")


def new_sandbox_tag():
    """A random subset of TAG_OPS with 5..10 members (never all or none, so
    an app sandbox that denies every privileged op cannot match)."""
    import random
    rng = random.SystemRandom()
    while True:
        tag = tuple(op for op in TAG_OPS if rng.random() < 0.5)
        if 5 <= len(tag) <= 10:
            return tag


def _sandbox_tag_of(libc, pid):
    return tuple(op for op in TAG_OPS if libc.sandbox_check(pid, op.encode(), 0) == 1)


def _etime_seconds(text):
    """ps etime '[[dd-]hh:]mm:ss' -> seconds (None if unparsable)."""
    try:
        days, _, rest = text.rpartition("-")
        parts = [int(x) for x in rest.split(":")]
        while len(parts) < 3:
            parts.insert(0, 0)
        return (int(days) if days else 0) * 86400 + parts[0] * 3600 + parts[1] * 60 + parts[2]
    except ValueError:
        return None


def find_escaped_orphans(mode, task_start, exclude):
    """{pid: is_zombie} for orphans that came from a task started at
    task_start. Under the Linux subreaper an exited intermediate child of
    a double fork also lands here, as a zombie: it is reaped, not killed."""
    if mode["kind"] == "none":
        return {}
    try:
        out = subprocess.run(["ps", "-A", "-o", "pid=,ppid=,pgid=,uid=,stat=,etime="], capture_output=True,
                             text=True, timeout=10).stdout
    except (OSError, subprocess.TimeoutExpired):
        return {}
    me, my_pgid, uid, now = os.getpid(), os.getpgid(0), os.getuid(), time.time()
    libc = _libc()
    found = {}
    for line in out.splitlines():
        f = line.split()
        if len(f) != 6 or not all(x.isdigit() for x in f[:4]):
            continue
        pid, ppid, pgid, puid = (int(x) for x in f[:4])
        zombie = f[4].startswith("Z")
        age = _etime_seconds(f[5])
        if pid in exclude or puid != uid or age is None or now - age < task_start - 2:
            continue
        if mode["kind"] == "subreaper":
            # Our own short-lived helpers (ps, Guardian checks) share our
            # process group; a running task root is in `exclude`.
            if ppid == me and pgid != my_pgid:
                found[pid] = zombie
        elif ppid == 1 and libc.responsibility_get_pid_responsible_for_pid(pid) == mode["responsible"] \
                and libc.sandbox_check(pid, None, 0) == 1 and libc.sandbox_check(pid, b"network-outbound", 0) == 1 \
                and _sandbox_tag_of(libc, pid) == mode.get("tag"):
            found[pid] = zombie
    return found


def main(argv):
    ap = argparse.ArgumentParser(prog="autopilot.py")
    sub = ap.add_subparsers(dest="cmd")
    r = sub.add_parser("run")
    r.add_argument("--mission", required=True)
    r.add_argument("--state", required=True)
    s = sub.add_parser("status")
    s.add_argument("--state", required=True)
    k = sub.add_parser("stop")
    k.add_argument("--state", required=True)
    k.add_argument("--now", action="store_true")
    c = sub.add_parser("clear-stop")
    c.add_argument("--state", required=True)
    a = ap.parse_args(argv)
    if a.cmd == "stop":
        os.makedirs(a.state, exist_ok=True)
        with open(os.path.join(a.state, "STOP"), "w") as f:
            json.dump({"requested_at": now_iso(), "now": bool(a.now)}, f)
        with open(os.path.join(a.state, "events.jsonl"), "a") as f:
            f.write(json.dumps({"ts": now_iso(), "event": "operator_stop_requested", "now": bool(a.now)}) + "\n")
        print("stop requested%s" % (" (running work will be stopped by the watchdog)" if a.now else ""))
        return 0
    if a.cmd == "clear-stop":
        try:
            os.remove(os.path.join(a.state, "STOP"))
        except OSError:
            pass
        with open(os.path.join(a.state, "events.jsonl"), "a") as f:
            f.write(json.dumps({"ts": now_iso(), "event": "operator_stop_cleared"}) + "\n")
        print("stop cleared")
        return 0
    if a.cmd == "run":
        return Engine(a.mission, a.state).run()
    if a.cmd == "status":
        try:
            st = json.load(open(os.path.join(a.state, "state.json")))
        except (OSError, ValueError):
            print("no state", file=sys.stderr)
            return 2
        print(json.dumps({"mission_id": st["mission_id"], "status": st["status"], "stop_reason": st.get("stop_reason"),
                          "tasks": {k: v["status"] for k, v in st["tasks"].items()}}, sort_keys=True))
        return 0
    ap.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
