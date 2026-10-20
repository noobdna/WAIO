"""autopilot/autopilot_lib.py -- pure core of the WAIO Autopilot mission
engine (WAIO-AUTO-001): mission parsing/validation, the command policy,
the task state machine, scheduling, failure signatures and redaction.
No I/O, no subprocess; autopilot.py does the running.

ROLE SPLIT (load-bearing):
    WAIO EXECUTES              autopilot.py runs tasks, one mission at a time
    TAKOMACHI/GUARDIAN GUARDS  security/guardian.sh state + SHUTDOWN.lock are
                               checked before EVERY task start; any error
                               reading them is treated as blocking
    DuCoPA PRESERVES CONTROL   nothing here can write Guardian/DuCoPA state,
                               the kill switch, or the shutdown lock: those
                               paths are forbidden to every task command
    watchdog (separate proc)   autopilot_watchdog.py enforces deadlines and
                               reaps orphans independently of the engine;
                               a stale watchdog heartbeat stops new tasks

MISSION FILE (JSON):
  mission_id   [A-Za-z0-9_.-]{1,64}
  goal         free text
  workspace    directory every task runs in; must already exist
  limits       {task_timeout_s, max_attempts, mission_timeout_s, max_parallel}
  forbidden    extra regexes, added to the built-in policy
  acceptance   [{id, cmd, expect_exit}]  -- re-run at the end; ALL must pass
  tasks        [{id, cmd?, test, deps?, priority?, idempotent?, repair?}]
               repair: {"kind": "cmd", "cmd": "..."} or
                       {"kind": "local_ai", "file": "rel/path", "instruction": "..."}

TASK STATES: PENDING -> RUNNING -> PASSED
                                -> FAILED (attempts exhausted)
                                -> STUCK (same failure signature twice in a row)
                                -> BLOCKED_POLICY (forbidden command: never run)
                                -> TIMED_OUT
             RUNNING found on resume -> PENDING if idempotent, else BLOCKED_RESUME
             any dependency not PASSED -> SKIPPED_DEP
"""

import hashlib
import re

MISSION_ID_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
TASK_ID_RE = re.compile(r"^[A-Za-z0-9_.-]{1,48}$")

DEFAULT_LIMITS = {"task_timeout_s": 120, "max_attempts": 3, "mission_timeout_s": 1800, "max_parallel": 2}
HARD_LIMITS = {"task_timeout_s": 3600, "max_attempts": 10, "mission_timeout_s": 6 * 3600, "max_parallel": 4}

TERMINAL = frozenset({"PASSED", "FAILED", "STUCK", "BLOCKED_POLICY", "BLOCKED_RESUME", "TIMED_OUT", "SKIPPED_DEP"})
NEEDS_HUMAN = frozenset({"BLOCKED_POLICY", "BLOCKED_RESUME"})

# Built-in command policy. A match means the command is NEVER run: the
# task becomes BLOCKED_POLICY and waits for a human. The macOS sandbox
# (autopilot.py) is the technical backstop; this list is the first line
# and also applies where no sandbox exists.
POLICY = [
    ("privilege", r"\bsudo\b|\bsu\s|\bdoas\b"),
    ("publish", r"\bgit\s+(push|remote\s+add|config\s+--global)\b|\bgh\s+(pr|release|repo)\b|\bnpm\s+publish\b"),
    ("network", r"\b(curl|wget|ssh|scp|sftp|rsync|nc|ncat|telnet|nmap|masscan)\b"),
    ("host_control", r"\b(launchctl|pmset|systemctl|shutdown|reboot|halt|killall|pkill)\b|\bkill\s+-"),
    ("control_plane", r"security/(guardian|ducopa|killswitch|lib\.sh|state|recover|self_dev)|SHUTDOWN\.lock|GUARDIAN_STATE|\.ssh/|authorized_keys"),
    ("destructive", r"\brm\s+-[a-zA-Z]*[rf][a-zA-Z]*\s+(/|~|\$HOME|\.\.)|\bgit\s+(reset\s+--hard|clean\s+-[a-z]*f|checkout\s+--\s|push\s+--force)\b|\bmkfs\b|\bdd\s+if="),
    ("escape", r"(^|[\s;&|])cd\s+(/|~|\.\.)|\.\./\.\.|\bchmod\s+[0-7]*[67][0-7]{2}\s+/"),
    ("secrets", r"\bsecurity\s+find-(generic|internet)-password\b|\.waio\.env\b|id_(rsa|ed25519)\b|\bkeychain\b"),
]

_REDACT = [
    (re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]{8,}"), r"\1[REDACTED]"),
    (re.compile(r"\b(sk|pk|ghp|gho|github_pat|xox[abp])[-_][A-Za-z0-9_-]{10,}"), "[REDACTED]"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S), "[REDACTED PRIVATE KEY]"),
    (re.compile(r"(?i)\b(password|passwd|secret|api[_-]?key|token)\s*[:=]\s*\S+"), r"\1=[REDACTED]"),
]


def redact(text, limit=4000):
    s = (text or "")[-limit:]
    for rx, rep in _REDACT:
        s = rx.sub(rep, s)
    return s


def policy_check(cmd, extra=()):
    """-> (allowed, rule_name)."""
    for name, rx in POLICY + [("mission_forbidden", x) for x in extra or ()]:
        if re.search(rx, cmd or ""):
            return False, name
    return True, ""


def failure_signature(exit_code, output):
    """Stable fingerprint of a failure: exit code + the output tail with
    numbers, hex ids and paths normalized, so the 'same' failure on a
    re-run hashes the same even when timings or temp names change."""
    tail = "\n".join((output or "").strip().splitlines()[-12:])
    # A number counts even with a unit glued on ("0.012s", "12ms"): with \b
    # on both sides those kept their digits, so the same failure under a
    # different timing hashed differently and STUCK detection never fired.
    # Digits inside identifiers (test_calc2) are left alone.
    tail = re.sub(r"0x[0-9a-fA-F]+|(?<![A-Za-z_])\d+(?:\.\d+)?", "N", tail)
    tail = re.sub(r"/[^\s:'\"]+", "PATH", tail)
    return hashlib.sha256(("%s|%s" % (exit_code, tail)).encode()).hexdigest()[:16]


def validate_mission(m):
    """-> (mission | None, [errors]). Clamps limits to HARD_LIMITS and
    rejects cycles, unknown dependencies and duplicate ids."""
    errs = []
    if not isinstance(m, dict):
        return None, ["mission must be a JSON object"]
    if not MISSION_ID_RE.match(str(m.get("mission_id", ""))):
        errs.append("mission_id missing or invalid")
    if not isinstance(m.get("workspace"), str) or not m["workspace"]:
        errs.append("workspace missing")
    limits = dict(DEFAULT_LIMITS)
    for k, v in (m.get("limits") or {}).items():
        if k in DEFAULT_LIMITS and isinstance(v, (int, float)) and v > 0:
            limits[k] = min(v, HARD_LIMITS[k])
    tasks = m.get("tasks")
    if not isinstance(tasks, list) or not tasks:
        errs.append("tasks must be a non-empty list")
        tasks = []
    ids = set()
    for t in tasks:
        if not isinstance(t, dict) or not TASK_ID_RE.match(str(t.get("id", ""))):
            errs.append("task id missing or invalid: %r" % (t.get("id") if isinstance(t, dict) else t))
            continue
        if t["id"] in ids:
            errs.append("duplicate task id %s" % t["id"])
        ids.add(t["id"])
        if not isinstance(t.get("test"), str) or not t["test"].strip():
            errs.append("task %s has no test (a task without a real test can never PASS)" % t["id"])
        rep = t.get("repair")
        if rep is not None and (not isinstance(rep, dict) or rep.get("kind") not in ("cmd", "local_ai")):
            errs.append("task %s repair.kind must be cmd or local_ai" % t["id"])
    for t in tasks:
        for d in (t.get("deps") or []) if isinstance(t, dict) else []:
            if d not in ids:
                errs.append("task %s depends on unknown task %s" % (t.get("id"), d))
    if not errs and _has_cycle(tasks):
        errs.append("task dependencies contain a cycle")
    acc = m.get("acceptance")
    if not isinstance(acc, list) or not acc:
        errs.append("acceptance must be a non-empty list (completion needs evidence)")
    if errs:
        return None, errs
    out = dict(m)
    out["limits"] = limits
    out["forbidden"] = [str(x) for x in m.get("forbidden") or []]
    return out, []


def _has_cycle(tasks):
    deps = {t["id"]: list(t.get("deps") or []) for t in tasks}
    state = {}

    def visit(n):
        if state.get(n) == 1:
            return True
        if state.get(n) == 2:
            return False
        state[n] = 1
        if any(visit(d) for d in deps.get(n, [])):
            return True
        state[n] = 2
        return False

    return any(visit(n) for n in deps)


def initial_state(mission):
    return {
        "mission_id": mission["mission_id"],
        "status": "RUNNING",
        "tasks": {t["id"]: {"status": "PENDING", "attempts": 0, "signatures": [], "history": []} for t in mission["tasks"]},
        "acceptance": {},
    }


def resume_state(state, mission):
    """Applied once when an engine starts on an existing state: a task
    left RUNNING was interrupted. Re-run it only if declared idempotent."""
    changed = []
    by_id = {t["id"]: t for t in mission["tasks"]}
    for tid, ts in state["tasks"].items():
        if ts["status"] == "RUNNING":
            new = "PENDING" if by_id.get(tid, {}).get("idempotent") else "BLOCKED_RESUME"
            ts["status"] = new
            ts["history"].append({"event": "resumed_from_running", "to": new})
            changed.append((tid, new))
    if state.get("status") not in ("COMPLETE",):
        state["status"] = "RUNNING"
    return changed


def ready_tasks(state, mission):
    """PENDING tasks whose deps all PASSED, highest priority first. Also
    marks SKIPPED_DEP where a dependency ended in any other terminal state."""
    ready = []
    for t in mission["tasks"]:
        ts = state["tasks"][t["id"]]
        if ts["status"] != "PENDING":
            continue
        dstates = [state["tasks"][d]["status"] for d in t.get("deps") or []]
        if any(s in TERMINAL and s != "PASSED" for s in dstates):
            ts["status"] = "SKIPPED_DEP"
            ts["history"].append({"event": "skipped", "reason": "a dependency did not pass"})
            continue
        if all(s == "PASSED" for s in dstates):
            ready.append(t)
    return sorted(ready, key=lambda t: (-int(t.get("priority", 0)), t["id"]))


def record_failure(ts, signature, max_attempts):
    """Updates attempts/signatures and returns the next status:
    STUCK if this signature repeats the previous one, FAILED if out of
    attempts, else PENDING (retry, after repair)."""
    ts["attempts"] += 1
    prev = ts["signatures"][-1] if ts["signatures"] else None
    ts["signatures"].append(signature)
    if prev == signature:
        return "STUCK"
    if ts["attempts"] >= max_attempts:
        return "FAILED"
    return "PENDING"


def mission_verdict(state):
    """COMPLETE only when every task PASSED and every acceptance check
    passed. Anything else is reported with its reasons -- never success."""
    reasons = []
    for tid, ts in sorted(state["tasks"].items()):
        if ts["status"] != "PASSED":
            reasons.append("task %s is %s" % (tid, ts["status"]))
    acc = state.get("acceptance") or {}
    if not acc:
        reasons.append("acceptance not run")
    for aid, a in sorted(acc.items()):
        if not a.get("passed"):
            reasons.append("acceptance %s failed (exit %s)" % (aid, a.get("exit")))
    if not reasons:
        return "COMPLETE", []
    if any(ts["status"] in NEEDS_HUMAN for ts in state["tasks"].values()):
        return "AWAITING_HUMAN", reasons
    return "INCOMPLETE", reasons
