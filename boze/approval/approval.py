#!/usr/bin/env python3
"""boze/approval/approval.py -- BOZE human-signed approval gate (U3).

A human approves one exact action on one exact payload by signing a small
canonical request file with their own SSH key, off-host:

    ssh-keygen -Y sign -f ~/.ssh/boze_approval -n boze-approval request.json
    -> request.json.sig

BOZE then checks, in order:
  1. the request bytes are the canonical encoding (no ambiguity in what was signed)
  2. fields are well formed; issued_at is not in the future; now < expires_at;
     the approval window is at most MAX_TTL
  3. it binds the expected job_id, action and payload_sha256 (and nonce,
     when the caller recorded one)
  4. the allowed_signers file is a regular file owned by us or root and not
     group/other-writable
  5. `ssh-keygen -Y verify` accepts the signature for a principal listed in
     allowed_signers, under the namespace "boze-approval"
consume() then records the nonce in an append-only ledger under flock, so
each signed approval can be used exactly once.

Nothing here executes the approved action. Python 3.9 stdlib + /usr/bin/ssh-keygen.
"""

import argparse
import datetime
import fcntl
import hashlib
import json
import os
import re
import secrets
import stat
import subprocess
import sys
import tempfile
import time

NAMESPACE = "boze-approval"
VERSION = 1
MAX_TTL = 24 * 3600
CLOCK_SKEW = 300
MAX_SIG_BYTES = 8192
MAX_REQUEST_BYTES = 4096
SSH_KEYGEN = "/usr/bin/ssh-keygen"
FIELDS = ("action", "expires_at", "issued_at", "job_id", "nonce", "payload_sha256", "v")
ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
NONCE_RE = re.compile(r"^[0-9a-f]{32}$")
PRINCIPAL_RE = re.compile(r"^[A-Za-z0-9._@+-]{1,128}$")


class ApprovalError(Exception):
    """The approval is not valid for the requested use."""


def _canonical(obj):
    return (json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def make_request(job_id, action, payload_sha256, ttl_seconds=3600, now=None):
    """Return the canonical request bytes for a human to sign."""
    now = int(time.time() if now is None else now)
    if not ID_RE.match(job_id or "") or not ID_RE.match(action or ""):
        raise ApprovalError("job_id/action must match %s" % ID_RE.pattern)
    if not HEX64.match(payload_sha256 or ""):
        raise ApprovalError("payload_sha256 must be 64 lowercase hex chars")
    if not isinstance(ttl_seconds, int) or not 60 <= ttl_seconds <= MAX_TTL:
        raise ApprovalError("ttl_seconds must be 60..%d" % MAX_TTL)
    return _canonical({"v": VERSION, "job_id": job_id, "action": action,
                       "payload_sha256": payload_sha256, "nonce": secrets.token_hex(16),
                       "issued_at": now, "expires_at": now + ttl_seconds})


def parse_request(data):
    if not isinstance(data, bytes) or len(data) > MAX_REQUEST_BYTES:
        raise ApprovalError("request missing or too large")
    try:
        obj = json.loads(data.decode("ascii"))
    except (UnicodeDecodeError, ValueError):
        raise ApprovalError("request is not ASCII JSON")
    if not isinstance(obj, dict) or tuple(sorted(obj)) != FIELDS:
        raise ApprovalError("request fields must be exactly %s" % (FIELDS,))
    if _canonical(obj) != data:
        raise ApprovalError("request is not in canonical form")
    if obj["v"] != VERSION:
        raise ApprovalError("unsupported request version")
    for k in ("issued_at", "expires_at"):
        if not isinstance(obj[k], int) or isinstance(obj[k], bool):
            raise ApprovalError("%s must be an integer" % k)
    if not (ID_RE.match(obj["job_id"]) and ID_RE.match(obj["action"])
            and HEX64.match(obj["payload_sha256"]) and NONCE_RE.match(obj["nonce"])):
        raise ApprovalError("malformed request field")
    return obj


def _check_signers_file(path):
    try:
        st = os.lstat(path)
    except OSError:
        raise ApprovalError("allowed_signers not found")
    if not stat.S_ISREG(st.st_mode):
        raise ApprovalError("allowed_signers must be a regular file (no symlink)")
    if st.st_uid not in (os.getuid(), 0):
        raise ApprovalError("allowed_signers has an unexpected owner")
    if st.st_mode & 0o022:
        raise ApprovalError("allowed_signers is group/other-writable")


def _run(args, stdin=None):
    env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}
    try:
        return subprocess.run([SSH_KEYGEN] + args, input=stdin, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, env=env, timeout=20, check=False)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise ApprovalError("ssh-keygen failed to run: %s" % type(e).__name__)


def verify(request_bytes, sig_bytes, allowed_signers, expect, now=None):
    """Return {"principal": ..., "request": {...}} or raise ApprovalError.

    expect: dict with job_id, action, payload_sha256 and optionally nonce.
    """
    req = parse_request(request_bytes)
    now = int(time.time() if now is None else now)
    if req["expires_at"] - req["issued_at"] > MAX_TTL or req["expires_at"] <= req["issued_at"]:
        raise ApprovalError("approval window invalid")
    if req["issued_at"] > now + CLOCK_SKEW:
        raise ApprovalError("approval issued in the future")
    if now >= req["expires_at"]:
        raise ApprovalError("approval expired")
    for k in ("job_id", "action", "payload_sha256", "nonce"):
        if k in expect and expect[k] != req[k]:
            raise ApprovalError("approval is for a different %s" % k)
    for k in ("job_id", "action", "payload_sha256"):
        if k not in expect:
            raise ApprovalError("caller must state the expected %s" % k)
    if not isinstance(sig_bytes, bytes) or not 0 < len(sig_bytes) <= MAX_SIG_BYTES \
            or not sig_bytes.startswith(b"-----BEGIN SSH SIGNATURE-----"):
        raise ApprovalError("signature missing or malformed")
    _check_signers_file(allowed_signers)
    with tempfile.TemporaryDirectory(prefix="boze-sig-") as d:
        sig_path = os.path.join(d, "req.sig")
        with open(sig_path, "wb") as f:
            f.write(sig_bytes)
        r = _run(["-Y", "find-principals", "-s", sig_path, "-f", allowed_signers])
        if r.returncode != 0:
            raise ApprovalError("signature key is not in allowed_signers")
        principals = [p for p in r.stdout.decode("utf-8", "replace").split("\n") if p]
        for p in principals:
            if not PRINCIPAL_RE.match(p):
                continue
            v = _run(["-Y", "verify", "-f", allowed_signers, "-I", p, "-n", NAMESPACE,
                      "-s", sig_path], stdin=request_bytes)
            if v.returncode == 0:
                return {"principal": p, "request": req}
    raise ApprovalError("signature does not verify for this request/namespace")


def consume(ledger_path, verified):
    """Record the nonce as used. Raises ApprovalError on replay."""
    req = verified["request"]
    lock = ledger_path + ".lock"
    fd = os.open(lock, os.O_WRONLY | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            with open(ledger_path, "r", encoding="ascii") as f:
                for line in f:
                    try:
                        if json.loads(line).get("nonce") == req["nonce"]:
                            raise ApprovalError("approval already used (replay)")
                    except ValueError:
                        raise ApprovalError("approval ledger is corrupt")
        except FileNotFoundError:
            pass
        entry = {"nonce": req["nonce"], "job_id": req["job_id"], "action": req["action"],
                 "payload_sha256": req["payload_sha256"], "principal": verified["principal"],
                 "consumed_at": datetime.datetime.now(datetime.timezone.utc).isoformat()}
        wfd = os.open(ledger_path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        try:
            os.write(wfd, _canonical(entry))
            os.fsync(wfd)
        finally:
            os.close(wfd)
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def main(argv=None):
    ap = argparse.ArgumentParser(description="BOZE approval requests")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("request")
    r.add_argument("--job-id", required=True)
    r.add_argument("--action", required=True)
    r.add_argument("--payload", required=True, help="file whose exact bytes are approved")
    r.add_argument("--ttl", type=int, default=3600)
    r.add_argument("--out", required=True)
    v = sub.add_parser("verify", help="check only; does not consume")
    v.add_argument("--request", required=True)
    v.add_argument("--sig", required=True)
    v.add_argument("--allowed-signers", required=True)
    v.add_argument("--payload", required=True)
    a = ap.parse_args(argv)
    try:
        if a.cmd == "request":
            with open(a.payload, "rb") as f:
                data = make_request(a.job_id, a.action, sha256_bytes(f.read()), a.ttl)
            fd = os.open(a.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
            with os.fdopen(fd, "wb") as f:
                f.write(data)
            print("wrote %s\nsign off-host with:\n  ssh-keygen -Y sign -f <key> -n %s %s"
                  % (a.out, NAMESPACE, os.path.basename(a.out)))
        else:
            with open(a.request, "rb") as f:
                req = f.read()
            with open(a.sig, "rb") as f:
                sig = f.read()
            with open(a.payload, "rb") as f:
                psha = sha256_bytes(f.read())
            parsed = parse_request(req)
            res = verify(req, sig, a.allowed_signers,
                         {"job_id": parsed["job_id"], "action": parsed["action"], "payload_sha256": psha})
            print(json.dumps({"ok": True, "principal": res["principal"], "request": res["request"]}))
    except (ApprovalError, OSError) as e:
        print(json.dumps({"ok": False, "error": str(e)}))
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
