"""Authorization and planning for security/containment_runner/containment_runner.sh.

Pure checks: reads a Decision Engine report, a signed policy and the
runner's own ledgers, and prints one JSON line per containment
recommendation saying what the runner may do. Never executes anything.

Policy format: version 2, one rule per exact entity, the same rule
fields the e2e harness uses. Signatures are RSA-SHA256 ("rsa-sha256:"
+ base64) over the rule's canonical JSON, made with the operator's
PRIVATE key, which never lives on this code path: the runner only holds
the PUBLIC key, so nothing that can read the runner's files can mint a
rule (an HMAC key would let any same-user process sign one). Further
restrictions, beyond the e2e harness:
  - quarantine_agent:<REGISTERED_WORKER> is the ONLY action; any other
    action, emergency_shutdown included, is refused (shutdown stays a
    human decision through the RED ALERT gate);
  - a global rate limit (executions in the last hour) on top of each
    rule's own max_executions budget;
  - the policy FILE itself must be a regular file owned by this user and
    not writable by group/other.
"""
import datetime
import hashlib
import json
import os
import stat
import subprocess
import sys
import tempfile
import base64

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "red_alert"))
import containment_approval_lib as cal  # noqa: E402


def _owner_only(path, forbid):
    try:
        st = os.stat(path)
    except OSError:
        return False
    return stat.S_ISREG(st.st_mode) and st.st_uid == os.getuid() and not st.st_mode & forbid


def verify_rsa(pubkey_file, data, signature):
    """True iff signature is "rsa-sha256:<base64>" over data, valid for pubkey_file."""
    if not isinstance(signature, str) or not signature.startswith("rsa-sha256:"):
        return False
    try:
        raw = base64.b64decode(signature.split(":", 1)[1], validate=True)
    except ValueError:
        return False
    with tempfile.NamedTemporaryFile(prefix="cr-sig.") as sig:
        sig.write(raw)
        sig.flush()
        try:
            p = subprocess.run(["openssl", "dgst", "-sha256", "-verify", pubkey_file, "-signature", sig.name],
                               input=data, capture_output=True, timeout=10)
        except (OSError, subprocess.TimeoutExpired):
            return False
    return p.returncode == 0


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


def plan(report_file, policy_file, pubkey_file, state_dir, registry_file, max_per_hour, now=None):
    """Yields one dict per RECOMMEND_CONTAINMENT decision (or one global REFUSE)."""
    now = now or datetime.datetime.now(datetime.timezone.utc)
    try:
        with open(report_file) as f:
            report = json.load(f)
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

    if not _owner_only(policy_file, 0o022):
        yield {"status": "REFUSE", "entity": None, "why": "policy file must be a regular file owned by this user, not group/other-writable"}
        return
    if not _owner_only(pubkey_file, 0o022):
        yield {"status": "REFUSE", "entity": None, "why": "policy public key must be a regular file owned by this user, not group/other-writable"}
        return
    try:
        with open(policy_file) as f:
            pol = json.load(f)
    except Exception as e:
        yield {"status": "REFUSE", "entity": None, "why": f"policy unreadable/malformed: {type(e).__name__}"}
        return
    rules = pol.get("rules") if isinstance(pol, dict) else None
    if not isinstance(rules, list):
        yield {"status": "REFUSE", "entity": None, "why": "policy has no rules list"}
        return

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
        rule = next((r for r in rules if isinstance(r, dict) and r.get("entity") == entity), None)
        if rule is None:
            yield refuse("no pre-approved policy rule for this exact entity")
            continue
        missing = [k for k in ("rule_id", "approved_by", "reason", "expires_at", "action", "max_executions", "signature") if not rule.get(k)]
        if missing:
            yield refuse(f"policy rule missing {missing[0]}")
            continue
        unsigned = {k: v for k, v in rule.items() if k != "signature"}
        if not verify_rsa(pubkey_file, json.dumps(unsigned, sort_keys=True).encode(), rule.get("signature")):
            yield refuse("policy rule signature invalid")
            continue
        exp = cal.parse_utc_timestamp(rule.get("expires_at"))
        if exp is None or cal.is_expired(exp, now):
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
        yield dict(out, status="PLAN", why=f"policy rule {rid} ({used + 1}/{max_exec}) approved_by={rule.get('approved_by')}")


if __name__ == "__main__":
    report_file, policy_file, pubkey_file, state_dir, registry_file, max_per_hour = sys.argv[1:7]
    for item in plan(report_file, policy_file, pubkey_file, state_dir, registry_file, int(max_per_hour)):
        print(json.dumps(item, ensure_ascii=False))
