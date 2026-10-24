#!/usr/bin/env python3
"""autopilot/autopilot_watchdog.py -- independent monitor for the WAIO
Autopilot engine. Runs as its OWN process, never imported by the engine.

  autopilot_watchdog.py --state DIR [--interval 2] [--max-iterations N]

Each iteration it:
  1. writes DIR/watchdog.hb -- the engine refuses to start any task while
     this heartbeat is missing or stale, so "monitor down" means "no new
     work", never "unmonitored work";
  2. reads DIR/state.json and, for every RUNNING task that recorded a
     process group:
       - deadline passed            -> SIGTERM, then SIGKILL, the group
       - engine heartbeat stale/dead -> the task is an orphan: same
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


def iteration(state_dir):
    with open(os.path.join(state_dir, "watchdog.hb"), "w") as f:
        f.write("%d %f\n" % (os.getpid(), time.time()))
    try:
        st = json.load(open(os.path.join(state_dir, "state.json")))
    except (OSError, ValueError):
        return []
    actions = []
    alive = engine_alive(state_dir)
    for tid, ts in sorted(st.get("tasks", {}).items()):
        pgid = ts.get("pgid")
        if ts.get("status") not in ("RUNNING", "ACCEPTANCE") or not isinstance(pgid, int) or not group_alive(pgid):
            continue
        reason = None
        if ts.get("deadline") and time.time() > ts["deadline"]:
            reason = "deadline_exceeded"
        elif not alive:
            reason = "orphaned_engine_dead"
        if not reason:
            continue
        stopped = stop_group(pgid)
        rec = {"ts": now_iso(), "task": tid, "phase": ts.get("phase"), "action": "stop_process_group",
               "reason": reason, "stopped": stopped}
        rec["guardian_notify_rc"] = notify_guardian("autopilot task %s stopped: %s" % (tid, reason))
        with open(os.path.join(state_dir, "watchdog.jsonl"), "a") as f:
            f.write(json.dumps(rec, sort_keys=True) + "\n")
        actions.append(rec)
    return actions


def main(argv):
    ap = argparse.ArgumentParser(prog="autopilot_watchdog.py")
    ap.add_argument("--state", required=True)
    ap.add_argument("--interval", type=float, default=2.0)
    ap.add_argument("--max-iterations", type=int, default=0, help="0 = run until killed")
    a = ap.parse_args(argv)
    os.makedirs(a.state, exist_ok=True)
    n = 0
    while True:
        iteration(a.state)
        n += 1
        if a.max_iterations and n >= a.max_iterations:
            return 0
        time.sleep(a.interval)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
