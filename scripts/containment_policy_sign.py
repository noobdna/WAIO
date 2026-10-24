#!/usr/bin/env python3
"""Operator tool: write a signed containment-runner policy (format v3).

    scripts/containment_policy_sign.py --private-key SIGNING.pem --policy OUT.json \
        --serial N --rules RULES.json [--max-rule-lifetime SECONDS] [--print-key-id]

RULES.json is a JSON list of rules:
    {"rule_id", "entity", "action": "quarantine_agent:WORKER", "approved_by",
     "reason", "expires_at", "max_executions"[, "issued_at"]}
issued_at defaults to now. The whole document (serial, issued_at, key_id,
rules, optional max_rule_lifetime_s) is signed once with the operator's
PRIVATE key (RSA-SHA256 via openssl). The runner holds only public keys.

Refuses: a non-quarantine action, a rule lifetime above the limit
(default 7 days, hard cap 30 days), a serial that is not higher than the
serial of an existing policy at OUT (a new policy must supersede the old
one; revocation = drop the rule and bump the serial).

Key pair (once; keep SIGNING.pem off the detection path):
    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out signing.pem
    openssl pkey -in signing.pem -pubout -out pub.pem
    scripts/containment_policy_sign.py --private-key signing.pem --print-key-id
    install the public key as ~/.config/waio/containment-keys/<key_id>.pub.pem
"""
import argparse
import base64
import datetime
import hashlib
import json
import os
import subprocess
import sys

OPENSSL = "/usr/bin/openssl"
DEFAULT_MAX = 7 * 86400
HARD_MAX = 30 * 86400


def run(args, data=None):
    p = subprocess.run([OPENSSL] + args, input=data, capture_output=True)
    if p.returncode != 0:
        sys.exit("openssl failed: " + p.stderr.decode(errors="replace").strip())
    return p.stdout


def key_id(private_key):
    der = run(["pkey", "-in", private_key, "-pubout", "-outform", "DER"])
    return hashlib.sha256(der).hexdigest()[:16]


def parse(t):
    return datetime.datetime.strptime(t, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--private-key", required=True)
    ap.add_argument("--policy")
    ap.add_argument("--serial", type=int)
    ap.add_argument("--rules")
    ap.add_argument("--max-rule-lifetime", type=int)
    ap.add_argument("--print-key-id", action="store_true")
    a = ap.parse_args()
    kid = key_id(a.private_key)
    if a.print_key_id:
        print(kid)
        return
    if not (a.policy and a.serial and a.rules):
        sys.exit("--policy, --serial and --rules are required")
    if a.serial < 1:
        sys.exit("--serial must be a positive integer")
    max_life = DEFAULT_MAX if a.max_rule_lifetime is None else a.max_rule_lifetime
    if not 0 < max_life <= HARD_MAX:
        sys.exit(f"--max-rule-lifetime must be in 1..{HARD_MAX}")
    now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    now_s = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    rules = json.load(open(a.rules))
    if not isinstance(rules, list):
        sys.exit("RULES.json must be a JSON list")
    for r in rules:
        if not str(r.get("action", "")).startswith("quarantine_agent:"):
            sys.exit(f"rule {r.get('rule_id')!r}: only quarantine_agent:<WORKER> rules can be signed")
        r.setdefault("issued_at", now_s)
        life = (parse(r["expires_at"]) - parse(r["issued_at"])).total_seconds()
        if not 0 < life <= max_life:
            sys.exit(f"rule {r.get('rule_id')!r}: lifetime {life:.0f} s is outside 1..{max_life}")
    if os.path.exists(a.policy):
        try:
            old = json.load(open(a.policy)).get("policy_serial", 0)
        except (ValueError, AttributeError):
            old = 0
        if isinstance(old, int) and a.serial <= old:
            sys.exit(f"--serial {a.serial} must be higher than the existing policy's serial {old}")
    doc = {"version": 3, "policy_serial": a.serial, "issued_at": now_s, "key_id": kid, "rules": rules}
    if a.max_rule_lifetime is not None:
        doc["max_rule_lifetime_s"] = max_life
    data = json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    doc["signature"] = "rsa-sha256:" + base64.b64encode(run(["dgst", "-sha256", "-sign", a.private_key], data)).decode()
    fd = os.open(a.policy + ".tmp", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(doc, f, indent=2, sort_keys=True)
    os.chmod(a.policy + ".tmp", 0o600)
    os.replace(a.policy + ".tmp", a.policy)
    print(f"signed policy serial {a.serial} ({len(rules)} rule(s), key_id {kid}) -> {a.policy}")


if __name__ == "__main__":
    main()
