"""security/killswitch/killswitch_sign.py -- OPERATOR-SIDE signer for
DuCoPA Independent Kill Switch commands.

Intended to run where the operator key lives (the operator's own session,
or the separate Guardian machine), NOT inside WAIO's AI-driven processes.
The gate (killswitch_gate.sh) only ever verifies; it has no signing
code path, so nothing on the gate side can mint a command by itself.

Usage:
  python3 killswitch_sign.py --issuer ID --key-file PATH --action ACTION \
      --target TARGET_ID --reason "TEXT" [--environment test] \
      [--origin human_operator] [--event-ref EVENT_ID] \
      [--command-id ID] [--issued-at YYYY-MM-DDTHH:MM:SSZ]

Prints the signed command JSON on stdout. Refuses (exit 1) if the key
file is not a private regular file owned by the current user. It does
NOT pre-check the action/target/environment: the gate is the authority,
and the test suite deliberately signs commands the gate must refuse.
"""

import argparse
import datetime
import json
import os
import secrets
import stat
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import killswitch_lib as ksl  # noqa: E402


def main():
    p = argparse.ArgumentParser(description="sign a Kill Switch command")
    p.add_argument("--issuer", required=True)
    p.add_argument("--key-file", required=True)
    p.add_argument("--action", required=True)
    p.add_argument("--target", required=True)
    p.add_argument("--reason", required=True)
    p.add_argument("--environment", default="test")
    p.add_argument("--origin", default="human_operator")
    p.add_argument("--event-ref", default="")
    p.add_argument("--command-id", default="")
    p.add_argument("--issued-at", default="")
    a = p.parse_args()

    try:
        st = os.lstat(a.key_file)
    except OSError:
        print("killswitch_sign: key file not found", file=sys.stderr)
        return 1
    if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or st.st_mode & 0o077:
        print("killswitch_sign: key file must be a private (0600/0400) regular file owned by you", file=sys.stderr)
        return 1
    with open(a.key_file, "rb") as f:
        key = f.read()

    issued = a.issued_at or ksl.format_ts(datetime.datetime.now(datetime.timezone.utc))
    cmd = {
        "schema": ksl.SCHEMA_COMMAND,
        "command_id": a.command_id or ("ks-" + secrets.token_hex(8)),
        "action": a.action,
        "target_id": a.target,
        "environment": a.environment,
        "issued_at": issued,
        "origin": a.origin,
        "issuer": a.issuer,
        "reason": a.reason,
        "event_ref": a.event_ref,
    }
    cmd["signature"] = ksl.sign(cmd, key)
    print(json.dumps(cmd, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
