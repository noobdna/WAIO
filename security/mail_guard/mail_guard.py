#!/usr/bin/env python3
"""security/mail_guard/mail_guard.py -- MAIL GUARD command line (P2).

Network subcommands (pull, policy-publish) are meant to be run through
security/mail_guard/mail_guard.sh, which does the DuCoPA egress check
first and passes the checked host as --expect-host. This file refuses to
contact any other host.

  host            print the host a network subcommand will contact
  pull            R2 -> security/state/mail_guard/events.jsonl (read-only token)
  status          events -> dashboard JSON (no network)
  incidents       events -> RawIncident JSONL on stdout (no network)
  prune           drop local events older than keep_days (no network)
  policy-build    new unsigned policy body + diff + BOZE request (no network)
  policy-publish  verify signed approval, consume it, write KV (--execute)

Exit codes: 0 ok, 2 refused/failed, 3 not configured.
"""

import argparse
import datetime
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)
sys.path.insert(0, REPO)

import mail_guard_lib as L  # noqa: E402

DEFAULT_STATE = os.path.join(REPO, "security", "state", "mail_guard")
R2_AK = ("MAILGUARD_R2_ACCESS_KEY_ID", "com.waio.mailguard.r2-access-key-id")
R2_SK = ("MAILGUARD_R2_SECRET_ACCESS_KEY", "com.waio.mailguard.r2-secret-access-key")
KV_TOKEN = ("MAILGUARD_KV_API_TOKEN", "com.waio.mailguard.kv-api-token")
KV_HOST = "api.cloudflare.com"


class NotConfigured(Exception):
    pass


def load_config(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            cfg = json.load(f)
    except FileNotFoundError:
        raise NotConfigured("config not found (copy security/mail_guard/config.example.json)")
    except (OSError, ValueError):
        raise L.MailGuardError("config unreadable")
    if not isinstance(cfg, dict):
        raise L.MailGuardError("config must be a JSON object")
    return cfg


def host_for(target, cfg):
    if target == "r2":
        return L.r2_host(cfg.get("account_id"))
    return KV_HOST


def cmd_host(a):
    print(host_for(a.target, load_config(a.config)))


def cmd_pull(a):
    cfg = load_config(a.config)
    host = L.r2_host(cfg.get("account_id"))
    endpoint = L.check_endpoint(a.endpoint or "https://" + host, a.expect_host)
    if a.expect_host != host:
        raise L.MailGuardError("--expect-host does not match the configured account")
    ak, sk = L.secret(*R2_AK), L.secret(*R2_SK)
    if not ak or not sk:
        raise NotConfigured("R2 read-only credentials not available (env or Keychain)")
    client = L.R2Client(endpoint, cfg.get("bucket", "waio-mailguard-events"), ak, sk)
    res = L.pull(client, a.state_dir, max_objects=a.max_objects)
    kept = L.prune_events(a.state_dir, int(cfg.get("keep_days", 30)))
    res["kept_local"] = kept
    _write_pull_status(a.state_dir, True, None, res)
    print(json.dumps(res, sort_keys=True))


def _write_pull_status(state_dir, ok, reason, res=None):
    L.ensure_state_dir(state_dir)
    L._write_json_atomic(os.path.join(state_dir, "last_pull.json"),
                         {"at": L.iso(L.utcnow()), "ok": ok, "reason": reason, "result": res})


def cmd_pull_failed(a):
    """Record a pull that the shell wrapper refused (e.g. egress not listed)."""
    _write_pull_status(a.state_dir, False, a.reason[:200])


def cmd_status(a):
    now = L.utcnow()
    out = {"generated_at": L.iso(now), "available": False, "reason": None}
    try:
        last_pull = L._read_json(os.path.join(a.state_dir, "last_pull.json"), None)
        events = L.load_events(a.state_dir, since=now - datetime.timedelta(days=7))
        out["last_pull"] = {k: last_pull.get(k) for k in ("at", "ok", "reason")} if isinstance(last_pull, dict) else None
        if not os.path.exists(os.path.join(a.state_dir, "events.jsonl")):
            out["reason"] = "no events pulled yet (collector not configured or never run)"
        else:
            out["available"] = True
        out.update(L.summarize(events, now))
        pub = _last_publish(a.state_dir)
        out["last_publish"] = pub
    except L.MailGuardError as e:
        out["reason"] = str(e)
    data = json.dumps(out, sort_keys=True, indent=1, ensure_ascii=True) + "\n"
    if a.out == "-":
        sys.stdout.write(data)
    else:
        os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
        tmp = a.out + ".tmp"
        with open(tmp, "w", encoding="ascii") as f:
            f.write(data)
        os.replace(tmp, a.out)


def _last_publish(state_dir):
    path = os.path.join(state_dir, "policy", "publish.log.jsonl")
    last = None
    try:
        with open(path, "r", encoding="ascii") as f:
            for line in f:
                try:
                    last = json.loads(line)
                except ValueError:
                    continue
    except (FileNotFoundError, UnicodeDecodeError):
        return None
    if not isinstance(last, dict):
        return None
    return {k: last.get(k) for k in ("published_at", "version", "mode", "principal")}


def cmd_incidents(a):
    now = L.utcnow()
    events = L.load_events(a.state_dir, since=now - datetime.timedelta(days=a.days))
    for r in L.incident_records(events, now, a.min_messages):
        print(json.dumps(r, ensure_ascii=False))


def cmd_prune(a):
    print(json.dumps({"kept": L.prune_events(a.state_dir, a.keep_days)}))


def _policy_dir(state_dir):
    d = os.path.join(state_dir, "policy")
    os.makedirs(d, mode=0o700, exist_ok=True)
    return d


def _load_base(a, pdir):
    if a.base_none:
        return None
    path = a.base or os.path.join(pdir, "published-current.json")
    try:
        with open(path, "r", encoding="ascii") as f:
            return json.load(f)
    except FileNotFoundError:
        if a.base:
            raise L.MailGuardError("base policy not found")
        raise L.MailGuardError("no locally published policy yet; pass --base FILE or --base-none for v1")
    except (OSError, ValueError, UnicodeDecodeError):
        raise L.MailGuardError("base policy unreadable")


def _excl_write(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)


def cmd_policy_build(a):
    from boze.approval import approval as A
    pdir = _policy_dir(a.state_dir)
    base = _load_base(a, pdir)
    version = a.version or ((base or {}).get("version", 0) + 1)
    changes = {}
    for f in ("sender_block", "url_block", "sender_allow"):
        for op in ("add", "remove"):
            v = getattr(a, "%s_%s" % (op, f))
            if v:
                changes["%s_%s" % (op, f)] = v
    for f in ("mode", "quarantine_threshold", "review_threshold", "catchall_quarantine_threshold"):
        if getattr(a, f) is not None:
            changes[f] = getattr(a, f)
    if a.set_route:
        changes["set_route"] = dict(r.split("=", 1) for r in a.set_route)
    if a.remove_route:
        changes["remove_route"] = a.remove_route
    body = L.build_policy(base, version, changes, ttl_days=a.ttl_days)
    body_bytes = L.canonical(body)
    stem = os.path.join(pdir, "policy-v%d" % version)
    req = A.make_request(L.POLICY_JOB_ID, L.publish_action(version), L.sha256_hex(body_bytes), a.approval_ttl)
    diff = "\n".join(L.diff_policy(base, body)) + "\n"
    try:
        _excl_write(stem + ".body.json", body_bytes)
        _excl_write(stem + ".diff.txt", diff.encode("utf-8"))
        _excl_write(stem + ".request.json", req)
    except FileExistsError:
        raise L.MailGuardError("policy-v%d files already exist in %s; remove them or use a new version" % (version, pdir))
    sys.stdout.write(diff)
    print("\nbody sha256: %s" % L.sha256_hex(body_bytes))
    print("to approve, sign OFF-HOST and copy the .sig back next to the request:")
    print("  ssh-keygen -Y sign -f <key> -n %s policy-v%d.request.json" % (A.NAMESPACE, version))


def cmd_policy_publish(a):
    from boze.approval import approval as A
    pdir = _policy_dir(a.state_dir)
    stem = os.path.join(pdir, "policy-v%d" % a.version)
    with open(stem + ".body.json", "rb") as f:
        body = f.read()
    with open(stem + ".request.json", "rb") as f:
        req = f.read()
    try:
        with open(stem + ".request.json.sig", "rb") as f:
            sig = f.read()
    except FileNotFoundError:
        raise L.MailGuardError("no signature yet: %s.request.json.sig" % os.path.basename(stem))
    signers = a.allowed_signers or os.environ.get("BOZE_ALLOWED_SIGNERS")
    if not signers:
        raise NotConfigured("pass --allowed-signers or set BOZE_ALLOWED_SIGNERS (no default on purpose)")
    if not a.execute:
        res = A.verify(req, sig, signers, {"job_id": L.POLICY_JOB_ID, "action": L.publish_action(a.version),
                                            "payload_sha256": L.sha256_hex(body)})
        print(json.dumps({"ok": True, "dry_run": True, "principal": res["principal"],
                          "note": "signature valid; re-run with --execute to consume it and write KV"}))
        return
    cfg = load_config(a.config)
    endpoint = L.check_endpoint(a.endpoint or "https://" + KV_HOST, a.expect_host)
    if a.expect_host != KV_HOST:
        raise L.MailGuardError("--expect-host must be %s" % KV_HOST)
    token = L.secret(*KV_TOKEN)
    if not token:
        raise NotConfigured("KV API token not available (env or Keychain)")
    kv = L.KVClient(endpoint, cfg.get("account_id"), cfg.get("kv_namespace_id"), token)
    entry = L.publish(kv, body, req, sig, signers, os.path.join(pdir, "approval-ledger.jsonl"),
                      os.path.join(pdir, "publish.log.jsonl"), A)
    full = dict(json.loads(body), approved_by_sig_sha256=entry["sig_sha256"])
    L._write_json_atomic(os.path.join(pdir, "published-current.json"), full)
    print(json.dumps(entry, sort_keys=True))


def main(argv=None):
    ap = argparse.ArgumentParser(description="WAIO MAIL GUARD (800 side)")
    ap.add_argument("--state-dir", default=os.environ.get("MAILGUARD_STATE_DIR", DEFAULT_STATE))
    ap.add_argument("--config", default=None)
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("host")
    s.add_argument("target", choices=("r2", "kv"))
    s = sub.add_parser("pull")
    s.add_argument("--expect-host", required=True)
    s.add_argument("--endpoint", help=argparse.SUPPRESS)
    s.add_argument("--max-objects", type=int, default=L.MAX_OBJECTS_PER_RUN)
    s = sub.add_parser("pull-failed")
    s.add_argument("--reason", required=True)
    s = sub.add_parser("status")
    s.add_argument("--out", default=os.path.join(REPO, "logs", "mail-guard-status-latest.json"))
    s = sub.add_parser("incidents")
    s.add_argument("--days", type=int, default=2)
    s.add_argument("--min-messages", type=int, default=1)
    s = sub.add_parser("prune")
    s.add_argument("--keep-days", type=int, default=30)

    s = sub.add_parser("policy-build")
    g = s.add_mutually_exclusive_group()
    g.add_argument("--base")
    g.add_argument("--base-none", action="store_true", help="first policy (v1); no base")
    s.add_argument("--version", type=int)
    s.add_argument("--mode", choices=L.MODES)
    for f in ("sender_block", "url_block", "sender_allow"):
        s.add_argument("--add-" + f.replace("_", "-"), dest="add_" + f, action="append", default=[])
        s.add_argument("--remove-" + f.replace("_", "-"), dest="remove_" + f, action="append", default=[])
    for f in ("quarantine_threshold", "review_threshold", "catchall_quarantine_threshold"):
        s.add_argument("--" + f.replace("_", "-"), dest=f, type=int)
    s.add_argument("--set-route", action="append", default=[], metavar="LOCAL=DEST")
    s.add_argument("--remove-route", action="append", default=[], metavar="LOCAL")
    s.add_argument("--ttl-days", type=int, default=30)
    s.add_argument("--approval-ttl", type=int, default=3600)

    s = sub.add_parser("policy-publish")
    s.add_argument("--version", type=int, required=True)
    s.add_argument("--allowed-signers")
    s.add_argument("--execute", action="store_true")
    s.add_argument("--expect-host", default="")
    s.add_argument("--endpoint", help=argparse.SUPPRESS)

    a = ap.parse_args(argv)
    if a.config is None:
        a.config = os.path.join(a.state_dir, "config.json")
    try:
        {"host": cmd_host, "pull": cmd_pull, "pull-failed": cmd_pull_failed, "status": cmd_status,
         "incidents": cmd_incidents, "prune": cmd_prune, "policy-build": cmd_policy_build,
         "policy-publish": cmd_policy_publish}[a.cmd](a)
    except NotConfigured as e:
        print(json.dumps({"ok": False, "not_configured": True, "error": str(e)}), file=sys.stderr)
        return 3
    except L.MailGuardError as e:
        print(json.dumps({"ok": False, "error": str(e)}), file=sys.stderr)
        return 2
    except Exception as e:  # noqa: BLE001 -- boze ApprovalError and OSError end here
        print(json.dumps({"ok": False, "error": "%s: %s" % (type(e).__name__, e)}), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
