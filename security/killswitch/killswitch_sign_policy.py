"""security/killswitch/killswitch_sign_policy.py -- OPERATOR-SIDE signer
for pre-approved containment policies (and, for drills, sensor events).

Runs where the operator key lives, never inside WAIO's AI processes;
the gate only verifies (see killswitch_policy.py).

Usage:
  python3 killswitch_sign_policy.py --key-file PATH UNSIGNED_JSON_FILE

UNSIGNED_JSON_FILE is a policy (waio.killswitch.policy.v1) or sensor
event (waio.killswitch.sensor_event.v1) with every field except
"signature". Prints the signed object on stdout. Like killswitch_sign.py
it does not pre-validate content: the gate is the authority.
"""

import argparse
import json
import os
import stat
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import killswitch_policy as ksp  # noqa: E402


def main():
    p = argparse.ArgumentParser(description="sign a Kill Switch policy or sensor event")
    p.add_argument("--key-file", required=True)
    p.add_argument("unsigned")
    a = p.parse_args()
    try:
        st = os.lstat(a.key_file)
    except OSError:
        print("killswitch_sign_policy: key file not found", file=sys.stderr)
        return 1
    if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or st.st_mode & 0o077:
        print("killswitch_sign_policy: key file must be a private (0600/0400) regular file owned by you", file=sys.stderr)
        return 1
    with open(a.key_file, "rb") as f:
        key = f.read()
    with open(a.unsigned) as f:
        obj = json.load(f)
    obj.pop("signature", None)
    obj["signature"] = ksp.sign(obj, key)
    print(json.dumps(obj, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
