#!/usr/bin/env python3
"""autopilot/autopilot_watchdog.py -- independent monitor for the WAIO
Autopilot engine. Runs as its OWN process, never imported by the engine.

  autopilot_watchdog.py --state DIR [--interval 2] [--max-iterations N]

Only one watchdog may watch a state dir: a second one exits 5 before it
writes anything (two would double-stop tasks and double-notify the Guardian).

Each iteration it:
  1. writes DIR/watchdog.hb -- the engine refuses to start any task while
     this heartbeat is missing or stale, so "monitor down" means "no new
     work", never "unmonitored work";
  2. reads DIR/state.json and, for every RUNNING task that recorded a
     process group, SIGTERMs then SIGKILLs the group when:
       - the Guardian is blocking or the shutdown lock is present
         (checked via security/lib.sh; an error counts as blocking)
       - the operator asked `autopilot.py stop --now`
       - its deadline passed
       - the engine heartbeat is stale/dead (the task is an orphan)
  3. logs each action to DIR/watchdog.jsonl (append-only, separate from
     the engine's own events.jsonl) and tells the Guardian through the
     existing WAIO -> Guardian interface (guardian_notify_event, severity
     warning: a caution signal, it does not itself block WAIO).

It never edits state.json: the engine records what happened to its own
tasks, and on resume a task left RUNNING is re-run only if declared
idempotent. It never touches Guardian/DuCoPA state beyond that one
notify call.

KNOWN LIMIT (co-failure): the watchdog runs on the same host and as the
same user as the engine. Task commands cannot signal it (kill/pkill are
forbidden by policy), but the user account itself could. Real separation
needs a different OS user or host, and that is an operator decision.
"""

import argparse
import datetime
import fcntl
import json
import os
import signal
import subprocess
import sys
import time

WAIO_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENGINE_HB_MAX_AGE = float(os.environ.get("AUTOPILOT_ENGINE_HB_MAX_AGE", "10"))
TERM_GRACE_S = float(os.environ.get("AUTOPILOT_TERM_GRACE_S", "3"))


def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def group_alive(pgid):
    try:
        os.killpg(pgid, 0)
        return True
    except OSError:
        return False


def engine_alive(state_dir):
    try:
        pid, ts = open(os.path.join(state_dir, "engine.hb")).read().split()
        os.kill(int(pid), 0)
        return time.time() - float(ts) <= ENGINE_HB_MAX_AGE
    except (OSError, ValueError):
        return False


def guardian_block_reason():
    """'' when work may continue; otherwise why running work must stop.
    Same lib.sh functions the engine gates on; an error fails closed."""
    env = {k: v for k, v in os.environ.items() if k in ("PATH", "HOME", "LANG", "TMPDIR") or k.startswith("WAIO_")}
    script = ('source "$1/security/lib.sh" >/dev/null 2>&1 || exit 9; is_shutdown_active && exit 3; '
              'guardian_is_blocking && { guardian_get_state; exit 2; }; exit 0')
    try:
        r = subprocess.run(["bash", "-c", script, "_", WAIO_DIR], env=env, cwd=WAIO_DIR,
                           capture_output=True, timeout=20)
    except (OSError, subprocess.TimeoutExpired):
        return "guardian_check_error"
    if r.returncode == 0:
        return ""
    if r.returncode == 2:
        return "guardian_" + (r.stdout.decode().strip() or "BLOCKED")
    if r.returncode == 3:
        return "shutdown_lock_active"
    return "guardian_check_error"


def operator_stop_now(state_dir):
    try:
        return bool(json.load(open(os.path.join(state_dir, "STOP"))).get("now"))
    except (OSError, ValueError, AttributeError):
        return False


def notify_guardian(detail):
    env = {k: v for k, v in os.environ.items() if k in ("PATH", "HOME", "LANG", "TMPDIR") or k.startswith("WAIO_")}
    script = 'source "$1/security/lib.sh" >/dev/null 2>&1 && guardian_notify_event autopilot_watchdog warning "$2" autopilot autopilot'
    try:
        return subprocess.run(["bash", "-c", script, "_", WAIO_DIR, detail], env=env, cwd=WAIO_DIR,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20).returncode
    except (OSError, subprocess.TimeoutExpired):
        return -1


def stop_group(pgid):
    for sig, wait in ((signal.SIGTERM, TERM_GRACE_S), (signal.SIGKILL, 1.0)):
        try:
            os.killpg(pgid, sig)
        except OSError:
            return True
        end = time.time() + wait
        while time.time() < end:
            if not group_alive(pgid):
                return True
            time.sleep(0.1)
    return not group_alive(pgid)


def acquire_single_instance(state_dir):
    """fd holding DIR/watchdog.lock, or None if another watchdog holds it.
    flock, not the engine's mkdir lock: the kernel drops it when the holder
    dies (even kill -9), so there is no stale lock to take over and no
    takeover race. The fd is non-inheritable, so child processes cannot
    keep it alive."""
    fd = os.open(os.path.join(state_dir, "watchdog.lock"), os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        os.close(fd)
        return None
    os.ftruncate(fd, 0)
    os.write(fd, b"%d\n" % os.getpid())
    return fd


def iteration(state_dir):
    with open(os.path.join(state_dir, "watchdog.hb"), "w") as f:
        f.write("%d %f\n" % (os.getpid(), time.time()))
    try:
        st = json.load(open(os.path.join(state_dir, "state.json")))
    except (OSError, ValueError):
        return []
    actions = []
    alive = engine_alive(state_dir)
    running = [ts for ts in st.get("tasks", {}).values()
               if ts.get("status") in ("RUNNING", "ACCEPTANCE") and isinstance(ts.get("pgid"), int)]
    # Only pay for the Guardian check when there is running work to stop.
    block = guardian_block_reason() if running else ""
    stop_now = operator_stop_now(state_dir) if running else False
    for tid, ts in sorted(st.get("tasks", {}).items()):
        pgid = ts.get("pgid")
        if ts.get("status") not in ("RUNNING", "ACCEPTANCE") or not isinstance(pgid, int) or not group_alive(pgid):
            continue
        reason = None
        if block:
            reason = block
        elif stop_now:
            reason = "operator_stop_now"
        elif ts.get("deadline") and time.time() > ts["deadline"]:
            reason = "deadline_exceeded"
        elif not alive:
            reason = "orphaned_engine_dead"
        if not reason:
            continue
        stopped = stop_group(pgid)
        rec = {"ts": now_iso(), "task": tid, "phase": ts.get("phase"), "action": "stop_process_group",
               "reason": reason, "stopped": stopped}
        # Evidence first: the record exists even if the notify call hangs or fails.
        log = os.path.join(state_dir, "watchdog.jsonl")
        with open(log, "a") as f:
            f.write(json.dumps(rec, sort_keys=True) + "\n")
        rc = notify_guardian("autopilot task %s stopped: %s" % (tid, reason))
        with open(log, "a") as f:
            f.write(json.dumps({"ts": now_iso(), "task": tid, "action": "guardian_notified", "rc": rc}, sort_keys=True) + "\n")
        rec["guardian_notify_rc"] = rc
        actions.append(rec)
    return actions


def main(argv):
    ap = argparse.ArgumentParser(prog="autopilot_watchdog.py")
    ap.add_argument("--state", required=True)
    ap.add_argument("--interval", type=float, default=2.0)
    ap.add_argument("--max-iterations", type=int, default=0, help="0 = run until killed")
    a = ap.parse_args(argv)
    os.makedirs(a.state, exist_ok=True)
    lock_fd = acquire_single_instance(a.state)  # held until this process exits
    if lock_fd is None:
        print("autopilot_watchdog: another watchdog already watches %s" % a.state, file=sys.stderr)
        return 5
    n = 0
    while True:
        iteration(a.state)
        n += 1
        if a.max_iterations and n >= a.max_iterations:
            return 0
        time.sleep(a.interval)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
