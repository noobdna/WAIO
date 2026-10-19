"""security/killswitch/killswitch_enforce.py -- the TEST-ENVIRONMENT
enforcement point for the DuCoPA Independent Kill Switch.

A test service/worker asks, before honouring a session, calling an
endpoint, or running a worker:

  python3 killswitch_enforce.py check <session|endpoint|worker> <ID> <TESTENV_DIR>

and receives one JSON line {"verdict": "ALLOW"|"DENY", "reason": ...};
exit 0 for ALLOW, 1 for DENY.

DELIBERATELY STANDALONE: standard library only, imports nothing from
killswitch_lib.py/killswitch_io.py and never contacts the gate. It reads
only the marker files the gate already wrote, so containment keeps
working when the control plane (the gate, WAIO itself, the network
between them) is stopped or unreachable.

Safe behaviour, by failure mode:
  - target contained (marker present)        -> DENY
  - marker present but unreadable/corrupt    -> DENY (fail closed)
  - marker directory unreadable/not a dir    -> DENY (state unknown)
  - test-environment marker missing          -> DENY (not a test env)
  - invalid kind/ID                          -> DENY
  - control plane stopped / unreachable      -> no effect: markers are
                                                sticky; nothing here
                                                ever expires or clears
                                                them (release is a
                                                separate, human Recover
                                                step, not implemented)
"""

import json
import os
import re
import stat
import sys

KIND_DIRS = {"session": "sessions", "endpoint": "endpoints", "worker": "workers"}
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")
MARKER = ".killswitch-test-env"


def verdict(kind, ident, testenv):
    if kind not in KIND_DIRS or not _ID.fullmatch(ident or ""):
        return "DENY", "invalid kind or id"
    try:
        with open(os.path.join(testenv, MARKER)) as f:
            if "environment=test" not in [ln.strip() for ln in f.read(4096).splitlines()]:
                return "DENY", "not a declared test environment"
    except OSError:
        return "DENY", "not a declared test environment"
    kind_dir = os.path.join(testenv, KIND_DIRS[kind])
    if not os.path.lexists(kind_dir):
        return "ALLOW", "no containment recorded"
    try:
        if not stat.S_ISDIR(os.lstat(kind_dir).st_mode):
            return "DENY", "containment state is not a directory (state unknown)"
        os.listdir(kind_dir)
    except OSError:
        return "DENY", "containment state unreadable (state unknown)"
    marker = os.path.join(kind_dir, ident + ".contained")
    if not os.path.lexists(marker):
        return "ALLOW", "no containment recorded"
    try:
        with open(marker) as f:
            data = json.loads(f.read(8192))
        if not isinstance(data, dict) or data.get("target_id") != ident:
            return "DENY", "containment marker corrupt (fail closed)"
    except (OSError, ValueError):
        return "DENY", "containment marker unreadable or corrupt (fail closed)"
    return "DENY", "contained by %s (command %s)" % (data.get("action", "?"), data.get("command_id", "?"))


def main(argv):
    if len(argv) != 5 or argv[1] != "check":
        print(json.dumps({"verdict": "DENY", "reason": "usage: check KIND ID TESTENV_DIR"}))
        return 1
    v, reason = verdict(argv[2], argv[3], argv[4])
    print(json.dumps({"verdict": v, "reason": reason, "kind": argv[2], "id": argv[3]}))
    return 0 if v == "ALLOW" else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
