"""Authorization and planning for security/containment_runner/containment_runner.sh.

Pure checks: reads a Decision Engine report, the signed policy, the trusted
public keys, the runner's own ledgers and the security audit log, and prints
one JSON line per containment recommendation saying what the runner may do.
Never executes anything; never writes anything.

Policy format v3 (one document, one signature):
  {"version": 3, "policy_serial": N, "issued_at": T, "key_id": K,
   ["max_rule_lifetime_s": S,] "rules": [...], "signature": "rsa-sha256:<b64>"}
  rule: {"rule_id", "entity", "action", "approved_by", "reason",
         "issued_at", "expires_at", "max_executions"}
The signature is RSA-SHA256 by the operator's PRIVATE key over the canonical
JSON of the document without "signature" (sort_keys, separators (",", ":"),
ASCII). The runner only holds PUBLIC keys, one file per key in the trusted
key directory, named <key_id>.pub.pem, where key_id is the first 16 hex
digits of SHA-256 over the key's DER encoding. Rotation = add a key file;
retiring a key = remove its file.

Lifecycle:
  - anti-rollback: a policy whose policy_serial is lower than the highest
    serial this runner has accepted is refused (a saved copy of an older
    policy -- including one that still lists a since-revoked rule -- is
    dead). Revocation = remove the rule and bump the serial.
  - lifetime: every rule needs issued_at and expires_at; expires_at must be
    after issued_at and at most max_rule_lifetime_s after it (default 7 days;
    a signed policy may lower or raise it up to a hard cap of 30 days);
    issued_at may not be more than CLOCK_SKEW_S in the future.
  - release-aware: if the audit log shows the target was released by a human
    (guardian_agent_released) at or after the rule's issued_at, the runner
    refuses until a rule issued strictly after that release exists.
  - replay: per-rule max_executions and a global hourly limit; idempotency
    per report/entity/action.
Only quarantine_agent:<REGISTERED_WORKER> is ever allowed.
"""
import base64
import datetime
import hashlib
import json
import os
import stat
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "red_alert"))
import containment_approval_lib as cal  # noqa: E402

POLICY_VERSION = 3
MAX_REPORT_BYTES = 8 * 1024 * 1024
MAX_POLICY_BYTES = 1024 * 1024
MAX_PUBKEY_BYTES = 64 * 1024
DEFAULT_MAX_RULE_LIFETIME_S = 7 * 86400
HARD_MAX_RULE_LIFETIME_S = 30 * 86400
CLOCK_SKEW_S = 300
# Absolute, root-owned openssl only: a caller-controlled PATH with a fake
# openssl that always "verifies" would otherwise authorize any policy.
OPENSSL = "/usr/bin/openssl"
RULE_FIELDS = ("rule_id", "entity", "action", "approved_by", "reason", "issued_at", "expires_at", "max_executions")


class Refuse(Exception):
    pass


def canonical(doc):
    return json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def read_checked(path, max_bytes, owner_only=None, what="file"):
    """Reads a file through one O_NOFOLLOW descriptor and checks THAT
    descriptor (fstat), so a symlink or a swap between check and read can
    never substitute another file. owner_only = forbidden mode bits, or
    None to skip the owner/mode check."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0))
    except OSError as e:
        raise Refuse(f"{what} unreadable or a symlink ({type(e).__name__})")
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise Refuse(f"{what} must be a regular file")
        if owner_only is not None and (st.st_uid != os.getuid() or st.st_mode & owner_only):
            raise Refuse(f"{what} must be a regular file owned by this user, not group/other-writable")
        if st.st_size > max_bytes:
            raise Refuse(f"{what} too large ({st.st_size} bytes > {max_bytes})")
        chunks, total = [], 0
        while True:
            b = os.read(fd, 65536)
            if not b:
                break
            total += len(b)
            if total > max_bytes:
                raise Refuse(f"{what} too large (grew past {max_bytes} bytes)")
            chunks.append(b)
        return b"".join(chunks)
    finally:
        os.close(fd)


def trusted_openssl():
    try:
        st = os.stat(OPENSSL)
    except OSError:
        raise Refuse(f"{OPENSSL} not found")
    if st.st_uid != 0 or st.st_mode & 0o022 or not stat.S_ISREG(st.st_mode):
        raise Refuse(f"{OPENSSL} must be a root-owned regular file, not group/other-writable")
    return OPENSSL


def _openssl(openssl, args, data=None):
    try:
        return subprocess.run([openssl] + args, input=data, capture_output=True, timeout=10, env={"PATH": "/usr/bin:/bin"})
    except (OSError, subprocess.TimeoutExpired):
        return None


def key_id_of(openssl, pubkey_pem):
    """First 16 hex digits of SHA-256 over the public key's DER encoding."""
    with tempfile.NamedTemporaryFile(prefix="cr-pub.") as pub:
        pub.write(pubkey_pem)
        pub.flush()
        p = _openssl(openssl, ["pkey", "-pubin", "-in", pub.name, "-outform", "DER"])
    if p is None or p.returncode != 0 or not p.stdout:
        return None
    return hashlib.sha256(p.stdout).hexdigest()[:16]


def verify_rsa(openssl, pubkey_pem, data, signature):
    """True iff signature is "rsa-sha256:<base64>" over data, valid for the
    public key bytes pubkey_pem. Any error is a failed verification."""
    if not isinstance(signature, str) or not signature.startswith("rsa-sha256:"):
        return False
    try:
        raw = base64.b64decode(signature.split(":", 1)[1], validate=True)
    except ValueError:
        return False
    # Private 0600 copies (mkstemp): openssl reads exactly the bytes that
    # were checked, never the original paths again.
    with tempfile.NamedTemporaryFile(prefix="cr-sig.") as sig, tempfile.NamedTemporaryFile(prefix="cr-pub.") as pub:
        sig.write(raw)
        sig.flush()
        pub.write(pubkey_pem)
        pub.flush()
        p = _openssl(openssl, ["dgst", "-sha256", "-verify", pub.name, "-signature", sig.name], data)
    return p is not None and p.returncode == 0 and b"Verified OK" in p.stdout


def ts(value):
    """Strict UTC timestamp (YYYY-MM-DDTHH:MM:SSZ) or None."""
    return cal.parse_utc_timestamp(value) if isinstance(value, str) else None


def registry_names(path):
    names = set()
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                names.add(line.split("|", 1)[0].upper())
    return names


def recent_executions(log_path, now, window_s=3600):
    n = 0
    try:
        with open(log_path) as f:
            for line in f:
                try:
                    t = float(line.split()[0])
                except (ValueError, IndexError):
                    continue
                if now.timestamp() - t < window_s:
                    n += 1
    except OSError:
        pass
    return n


def last_release(audit_log, target):
    """Latest guardian_agent_released time for target in the audit log, or None.
    Unreadable log -> treated as "released just now" (fail closed)."""
    latest = None
    try:
        with open(audit_log, errors="replace") as f:
            for line in f:
                if "guardian_agent_released" not in line:
                    continue
                try:
                    e = json.loads(line)
                except ValueError:
                    continue
                if e.get("event_type") == "guardian_agent_released" and str(e.get("worker", "")).upper() == target:
                    t = ts(e.get("timestamp"))
                    if t is not None and (latest is None or t > latest):
                        latest = t
    except FileNotFoundError:
        return None
    except OSError:
        return datetime.datetime.max.replace(tzinfo=datetime.timezone.utc)
    return latest


def load_policy(policy_file, key_dir, state_dir, now):
    """Returns (policy, serial) or raises Refuse. Verifies version, key id,
    signature, policy-level issued_at and serial (anti-rollback)."""
    openssl = trusted_openssl()
    raw = read_checked(policy_file, MAX_POLICY_BYTES, owner_only=0o022, what="policy file")
    try:
        pol = json.loads(raw)
    except ValueError as e:
        raise Refuse(f"policy unreadable/malformed: {type(e).__name__}")
    if not isinstance(pol, dict):
        raise Refuse("policy is not a JSON object")
    if pol.get("version") != POLICY_VERSION:
        raise Refuse(f"policy version {pol.get('version')!r} refused (only version {POLICY_VERSION}; no migration of older formats)")
    key_id = pol.get("key_id")
    if not isinstance(key_id, str) or len(key_id) != 16 or any(c not in "0123456789abcdef" for c in key_id):
        raise Refuse("policy key_id missing or malformed")
    pub = read_checked(os.path.join(key_dir, key_id + ".pub.pem"), MAX_PUBKEY_BYTES, owner_only=0o022, what=f"trusted key {key_id}")
    if key_id_of(openssl, pub) != key_id:
        raise Refuse(f"trusted key file {key_id}.pub.pem does not match its key_id")
    unsigned = {k: v for k, v in pol.items() if k != "signature"}
    if not verify_rsa(openssl, pub, canonical(unsigned), pol.get("signature")):
        raise Refuse("policy signature invalid")
    serial = pol.get("policy_serial")
    if not isinstance(serial, int) or isinstance(serial, bool) or serial < 1:
        raise Refuse("policy_serial missing or not a positive integer")
    issued = ts(pol.get("issued_at"))
    if issued is None:
        raise Refuse("policy issued_at missing or malformed")
    if (issued - now).total_seconds() > CLOCK_SKEW_S:
        raise Refuse("policy issued_at is in the future")
    seen = 0
    try:
        seen = int(open(os.path.join(state_dir, "policy_serial")).read().strip() or 0)
    except (OSError, ValueError):
        seen = 0
    if serial < seen:
        raise Refuse(f"policy_serial {serial} is lower than the highest accepted ({seen}): rollback refused")
    if not isinstance(pol.get("rules"), list):
        raise Refuse("policy has no rules list")
    return pol, serial


def plan(report_file, policy_file, key_dir, state_dir, registry_file, audit_log, max_per_hour, now=None):
    """Yields one dict per RECOMMEND_CONTAINMENT decision (or one global REFUSE).
    The first item may be {"status": "SERIAL", "serial": N}: the serial the
    caller should record as accepted once it acts on this plan."""
    now = now or datetime.datetime.now(datetime.timezone.utc)
    try:
        report = json.loads(read_checked(report_file, MAX_REPORT_BYTES, what="decision report"))
    except Refuse as e:
        yield {"status": "REFUSE", "entity": None, "why": str(e)}
        return
    except Exception as e:
        yield {"status": "REFUSE", "entity": None, "why": f"decision report unreadable/malformed: {type(e).__name__}"}
        return
    decisions = report.get("decisions") if isinstance(report, dict) else None
    if not isinstance(decisions, list):
        yield {"status": "REFUSE", "entity": None, "why": "decision report has no decisions list"}
        return
    recs = [d for d in decisions if isinstance(d, dict) and d.get("recommended_action") == "RECOMMEND_CONTAINMENT"]
    if not recs:
        return
    try:
        pol, serial = load_policy(policy_file, key_dir, state_dir, now)
    except Refuse as e:
        yield {"status": "REFUSE", "entity": None, "why": str(e)}
        return
    max_life = pol.get("max_rule_lifetime_s", DEFAULT_MAX_RULE_LIFETIME_S)
    if not isinstance(max_life, int) or isinstance(max_life, bool) or not 0 < max_life <= HARD_MAX_RULE_LIFETIME_S:
        yield {"status": "REFUSE", "entity": None, "why": f"max_rule_lifetime_s must be an integer in 1..{HARD_MAX_RULE_LIFETIME_S}"}
        return
    yield {"status": "SERIAL", "serial": serial}
    rules = pol["rules"]
    registered = registry_names(registry_file)
    report_hash = cal.compute_decision_report_hash(report)
    budget_left = max_per_hour - recent_executions(os.path.join(state_dir, "executions.log"), now)
    seen = set()

    for rec in recs:
        entity = rec.get("entity")
        out = {"entity": entity, "report_hash": report_hash}

        def refuse(why):
            return dict(out, status="REFUSE", why=why)

        if not isinstance(entity, str) or not entity:
            yield refuse("decision has no entity")
            continue
        if entity in seen:
            yield dict(out, status="DUPLICATE", why="entity listed twice in one report")
            continue
        seen.add(entity)
        lc = rec.get("local_corroboration")
        if not (isinstance(lc, dict) and lc.get("present") is True):
            yield refuse("no trusted local corroboration")
            continue
        matching = [r for r in rules if isinstance(r, dict) and r.get("entity") == entity]
        if not matching:
            yield refuse("no pre-approved policy rule for this exact entity")
            continue
        if len(matching) > 1:
            yield refuse("more than one policy rule names this entity (ambiguous policy, fail closed)")
            continue
        rule = matching[0]
        missing = [k for k in RULE_FIELDS if rule.get(k) in (None, "")]
        if missing:
            yield refuse(f"policy rule missing {missing[0]}")
            continue
        issued, expires = ts(rule.get("issued_at")), ts(rule.get("expires_at"))
        if issued is None or expires is None:
            yield refuse("policy rule issued_at/expires_at malformed")
            continue
        if (issued - now).total_seconds() > CLOCK_SKEW_S:
            yield refuse("policy rule issued_at is in the future")
            continue
        if expires <= issued:
            yield refuse("policy rule expires_at is not after issued_at")
            continue
        if (expires - issued).total_seconds() > max_life:
            yield refuse(f"policy rule lifetime exceeds {max_life} s")
            continue
        if cal.is_expired(expires, now):
            yield refuse("policy rule expired")
            continue
        action = rule.get("action")
        if not (isinstance(action, str) and action.startswith("quarantine_agent:")):
            yield refuse(f"action {action!r} refused: the runner may only quarantine one registered agent")
            continue
        target = action.split(":", 1)[1].upper()
        if target not in registered:
            yield refuse(f"quarantine target {target!r} is not a registered worker")
            continue
        rid = str(rule.get("rule_id"))
        if not rid.replace("-", "").replace("_", "").isalnum():
            yield refuse("rule_id has unsafe characters")
            continue
        try:
            max_exec = int(rule.get("max_executions"))
        except (TypeError, ValueError):
            yield refuse("max_executions is not an integer")
            continue
        released = last_release(audit_log, target)
        if released is not None and released >= issued:
            yield refuse(f"{target} was released by a human at or after this rule was issued; re-quarantine needs a rule issued after the release")
            continue
        out.update(action="quarantine_agent", target=target, rule_id=rid)
        key_id = hashlib.sha256(f"{report_hash}|{entity}|quarantine_agent|{target}".encode()).hexdigest()[:32]
        out["key"] = key_id
        if os.path.isfile(os.path.join(state_dir, "done", key_id)):
            yield dict(out, status="DUPLICATE", why="this report/entity/action was already executed")
            continue
        ledger = os.path.join(state_dir, "ledger", rid)
        used = int(open(ledger).read().strip() or 0) if os.path.isfile(ledger) else 0
        if used >= max_exec:
            yield refuse(f"policy rule {rid} execution budget exhausted ({used}/{max_exec})")
            continue
        if budget_left <= 0:
            yield dict(out, status="RATE_LIMITED", why=f"global limit of {max_per_hour} automated quarantines per hour reached")
            continue
        budget_left -= 1
        yield dict(out, status="PLAN", why=f"policy serial {serial} rule {rid} ({used + 1}/{max_exec}) approved_by={rule.get('approved_by')}")


if __name__ == "__main__":
    report_file, policy_file, key_dir, state_dir, registry_file, audit_log, max_per_hour = sys.argv[1:8]
    for item in plan(report_file, policy_file, key_dir, state_dir, registry_file, audit_log, int(max_per_hour)):
        print(json.dumps(item, ensure_ascii=False))
