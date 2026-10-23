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

Exit codes: 0 COMPLETE, 1 INCOMPLETE, 2 usage/mission error,
3 AWAITING_HUMAN, 4 PAUSED_GUARDIAN, 5 another engine holds the lock.
"""

import argparse
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
# A pid-less engine.lock younger than this belongs to an engine that has
# made the directory but not yet written its pid: it is live, not stale.
ENGINE_LOCK_GRACE_S = 10
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
            except (OSError, ValueError):
                # No readable pid yet: the holder may be between its mkdir
                # and its pid write. Only an old pid-less lock is stale;
                # an unreadable age counts as fresh (never steal on doubt).
                try:
                    age = time.time() - os.path.getmtime(lock)
                except OSError:
                    age = 0
                if age < ENGINE_LOCK_GRACE_S:
                    return False
            else:
                try:
                    os.kill(pid, 0)
                    return False
                except ProcessLookupError:
                    pass  # holder is gone: stale
                except OSError:
                    return False  # exists but not ours to signal: live
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

    def gates(self):
        for check in (self.guardian_ok, self.watchdog_ok):
            ok, why = check()
            if not ok:
                return False, why
        return True, ""

    # ---- running one command -------------------------------------------
    def sandbox_profile(self):
        ws = os.path.realpath(self.ws)
        # The sandbox matches resolved paths (/var -> /private/var).
        home = os.path.realpath(os.path.expanduser("~"))
        return ('(version 1)(allow default)(deny network*)'
                '(deny file-write*)'
                '(allow file-write* (subpath "%s") (subpath "/private/tmp") (subpath "/private/var/folders")'
                ' (literal "/dev/null") (literal "/dev/tty") (regex #"^/dev/fd/"))'
                '(deny file-write* (subpath "%s"))'
                '(deny file-read* (subpath "%s/.ssh") (subpath "%s/Library/Keychains") (subpath "%s/security/state")'
                ' (literal "%s/.waio.env") (subpath "%s/.config/gh"))'
                % (ws, os.path.realpath(self.state_dir), home, home, WAIO_DIR, home, home))

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
        proc = subprocess.Popen(argv, cwd=self.ws, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                stdin=subprocess.DEVNULL, start_new_session=True)
        with self.lock:
            ts = self.state["tasks"][tid]
            ts.update(pid=proc.pid, pgid=proc.pid, phase=phase, deadline=time.time() + timeout)
            self.save()
        try:
            out, _ = proc.communicate(timeout=timeout)
            rc = proc.returncode
        except subprocess.TimeoutExpired:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except OSError:
                pass
            out, _ = proc.communicate()
            rc = "TIMEOUT"
        with self.lock:
            for k in ("pid", "pgid", "deadline", "phase"):
                self.state["tasks"][tid].pop(k, None)
            self.save()
        return rc, (out or b"").decode("utf-8", "replace")

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
            with self.lock:
                self.state["tasks"][tid]["cmd_done"] = True
        while True:
            if self.stop_reason:
                self.transition(tid, "PENDING", note="stopping: " + self.stop_reason)
                return
            ok, why = self.gates()
            if not ok:
                self.stop_reason = why
                self.transition(tid, "PENDING", note="gate refused: " + why)
                return
            rc, out = self.run_cmd(task["test"], tid, "test")
            if rc == 0:
                self.transition(tid, "PASSED", test_output=al.redact(out, 800))
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
            ok, why = self.gates()
            if not ok:
                self.stop_reason = why
                self.transition(tid, "PENDING", note="gate refused before repair: " + why)
                return
            result = self.repair(task, out)
            self.event("task_repair", task=tid, result=result)

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
        ws_real = os.path.realpath(self.ws)
        home_real = os.path.realpath(os.path.expanduser("~"))
        if ws_real == os.sep or ws_real == home_real or home_real.startswith(ws_real.rstrip(os.sep) + os.sep):
            print("autopilot: workspace may not be /, the home directory, or above it: " + ws_real, file=sys.stderr)
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
            self.state = json.load(open(self.p("state.json")))
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
            return self._pause()
        # acceptance: only meaningful once nothing is left to run
        self.state["acceptance"] = {}
        for a in self.mission["acceptance"]:
            ok, rule = al.policy_check(a["cmd"], self.mission["forbidden"])
            if not ok:
                self.state["acceptance"][a["id"]] = {"passed": False, "exit": "BLOCKED_POLICY:" + rule}
                continue
            ok, why = self.gates()
            if not ok:
                self.stop_reason = why
                self.state.pop("acceptance", None)
                return self._pause()
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

    def _pause(self):
        self.state["status"] = "PAUSED_GUARDIAN" if self.stop_reason.startswith(("guardian", "shutdown", "watchdog")) else "INCOMPLETE"
        self.state["stop_reason"] = self.stop_reason
        self.save()
        self.event("mission_paused", reason=self.stop_reason)
        print("autopilot: paused (%s); state saved, run again to resume" % self.stop_reason)
        return 4 if self.state["status"] == "PAUSED_GUARDIAN" else 1

    def _run_acceptance(self, a):
        self.state["tasks"]["_acceptance"] = {"status": "ACCEPTANCE", "attempts": 0, "signatures": [], "history": []}
        try:
            return self.run_cmd(a["cmd"], "_acceptance", "acceptance")
        finally:
            self.state["tasks"].pop("_acceptance", None)


def main(argv):
    ap = argparse.ArgumentParser(prog="autopilot.py")
    sub = ap.add_subparsers(dest="cmd")
    r = sub.add_parser("run")
    r.add_argument("--mission", required=True)
    r.add_argument("--state", required=True)
    s = sub.add_parser("status")
    s.add_argument("--state", required=True)
    a = ap.parse_args(argv)
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
