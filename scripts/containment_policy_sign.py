#!/usr/bin/env python3
"""Operator tool: add or replace one signed rule in a containment-runner policy.

    scripts/containment_policy_sign.py --private-key PEM --policy POLICY.json \
        --entity NAME --action quarantine_agent:WORKER --expires-at 2026-10-25T00:00:00Z \
        --max-executions 3 --rule-id rule-x --approved-by NAME --reason "TEXT"

Signs with the operator's PRIVATE key (RSA, via the openssl CLI). The
containment runner (security/containment_runner/) only ever reads the
matching PUBLIC key, so keep the private key off the machine's detection
path (another account, an external volume, or a passphrase-protected
file). The policy file is written 0600.

Key pair (once):
    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out signing.pem
    openssl pkey -in signing.pem -pubout -out ~/.config/waio/containment-policy.pub.pem
"""
import argparse
import base64
import json
import os
import subprocess
import sys


def main():
    ap = argparse.ArgumentParser()
    for a in ("--private-key", "--policy", "--entity", "--action", "--expires-at", "--rule-id", "--approved-by", "--reason"):
        ap.add_argument(a, required=True)
    ap.add_argument("--max-executions", type=int, required=True)
    a = ap.parse_args()
    if not a.action.startswith("quarantine_agent:"):
        sys.exit("only quarantine_agent:<WORKER> rules can be signed: the runner refuses every other action")
    rule = {"rule_id": a.rule_id, "entity": a.entity, "action": a.action, "approved_by": a.approved_by,
            "reason": a.reason, "expires_at": a.expires_at, "max_executions": a.max_executions}
    data = json.dumps(rule, sort_keys=True).encode()
    p = subprocess.run(["openssl", "dgst", "-sha256", "-sign", a.private_key], input=data, capture_output=True)
    if p.returncode != 0:
        sys.exit("signing failed: " + p.stderr.decode(errors="replace").strip())
    rule["signature"] = "rsa-sha256:" + base64.b64encode(p.stdout).decode()
    policy = {"version": 2, "rules": []}
    if os.path.exists(a.policy):
        with open(a.policy) as f:
            policy = json.load(f)
    policy["rules"] = [r for r in policy.get("rules", []) if r.get("entity") != a.entity] + [rule]
    fd = os.open(a.policy + ".tmp", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(policy, f, indent=2, sort_keys=True)
    os.chmod(a.policy + ".tmp", 0o600)
    os.replace(a.policy + ".tmp", a.policy)
    print(f"signed rule {a.rule_id} for {a.entity} -> {a.policy}")


if __name__ == "__main__":
    main()
