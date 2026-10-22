"""security/killswitch/killswitch_evidence.py -- evidence preservation
for the DuCoPA Independent Kill Switch ("Preserve Evidence" between
Contain and Recover). Invoked by killswitch_gate.sh only.

  preserve INCIDENT_ID OUT_ROOT [--command-id ID]... [--event-id ID]...
      Copies, into a NEW directory OUT_ROOT/INCIDENT_ID (refuses if it
      exists): the gate's result records for the given command ids, the
      stored event records, a full copy of the audit log + checkpoint
      and its integrity verdict at preservation time, the current and
      released containment markers of every target involved, plus
      timeline.json, scope.json, recovery.md and MANIFEST.json (sha256
      of every file). Files are left read-only (0400).
  verify BUNDLE_DIR
      Re-hashes every file against MANIFEST.json; reports ok, or which
      files are modified / missing / unexpected.

TAMPER EVIDENCE, STATED HONESTLY: with KILLSWITCH_AUDIT_HMAC_KEY_FILE
set, MANIFEST.json carries an HMAC over the file list, so an attacker
who can rewrite the bundle but not read that key cannot forge a
consistent manifest. Without the key the manifest is plain sha256: it
detects accidental or partial modification, not a writer who rewrites
both a file and the manifest. The bundle records which mode applied.

Standard library only; file copies and hashing, nothing else.
"""

import datetime
import hashlib
import hmac
import json
import os
import shutil
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import killswitch_lib as ksl  # noqa: E402

MANIFEST = "MANIFEST.json"
_RELEASE_FOR = {v: k for k, v in ksl.RELEASE_ACTIONS.items()}


def out(obj):
    print(json.dumps(obj, ensure_ascii=False, sort_keys=True))


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _mac_key():
    path = os.environ.get("KILLSWITCH_AUDIT_HMAC_KEY_FILE", "")
    if path and os.path.isfile(path) and os.access(path, os.R_OK):
        with open(path, "rb") as f:
            return f.read()
    return None


def _manifest_mac(files, key):
    body = json.dumps(files, sort_keys=True, separators=(",", ":")).encode()
    return hmac.new(key, body, hashlib.sha256).hexdigest()


def _write_json(path, obj):
    with open(path, "w") as f:
        f.write(json.dumps(obj, ensure_ascii=False, sort_keys=True, indent=2) + "\n")


def _load_json(path):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def preserve(incident_id, out_root, command_ids, event_ids):
    e = os.environ
    if not ksl.valid_id(incident_id) or not all(ksl.valid_id(i) for i in command_ids + event_ids):
        return out({"ok": False, "detail": "invalid incident/command/event id"})
    if not command_ids and not event_ids:
        return out({"ok": False, "detail": "nothing to preserve (give --command-id and/or --event-id)"})
    state, testenv = e.get("KS_STATE_DIR", ""), e.get("KS_TEST_ENV", "")
    bundle = os.path.join(out_root, incident_id)
    try:
        os.makedirs(out_root, 0o700, exist_ok=True)
        os.mkdir(bundle, 0o700)
    except FileExistsError:
        return out({"ok": False, "detail": "bundle %s already exists; evidence is never overwritten" % incident_id})
    except OSError as exc:
        return out({"ok": False, "detail": "cannot create bundle: %s" % exc.strerror})

    missing, targets = [], []
    for sub in ("commands", "events", "audit", "containment"):
        os.mkdir(os.path.join(bundle, sub), 0o700)
    for cid in command_ids:
        src = os.path.join(state, "results", cid + ".json")
        if os.path.isfile(src):
            shutil.copyfile(src, os.path.join(bundle, "commands", cid + ".json"))
            rec = _load_json(src) or {}
            if rec.get("target_id") and rec.get("action"):
                targets.append({"action": rec["action"], "target_id": rec["target_id"],
                                "execution_result": rec.get("execution_result", "")})
        else:
            missing.append("command:" + cid)
    for eid in event_ids:
        src = os.path.join(state, "events", eid, "record.json")
        if os.path.isfile(src):
            shutil.copyfile(src, os.path.join(bundle, "events", eid + ".json"))
        else:
            missing.append("event:" + eid)

    audit_log, checkpoint = e.get("KS_AUDIT_LOG", ""), e.get("KS_AUDIT_CHECKPOINT", "")
    timeline, ids = [], set(command_ids) | set(event_ids)
    if os.path.isfile(audit_log):
        shutil.copyfile(audit_log, os.path.join(bundle, "audit", "killswitch-audit.jsonl"))
        with open(audit_log) as f:
            for lineno, raw in enumerate(f, 1):
                try:
                    entry = json.loads(raw)
                except ValueError:
                    continue
                d = entry.get("detail") if isinstance(entry.get("detail"), dict) else {}
                if entry.get("ref_id") in ids or d.get("command_id") in ids or d.get("event_id") in ids:
                    timeline.append({"line": lineno, "timestamp": entry.get("timestamp"),
                                     "event_type": entry.get("event_type"), "ref_id": entry.get("ref_id"),
                                     "execution_result": d.get("execution_result", "")})
    else:
        missing.append("audit_log")
    if os.path.isfile(checkpoint):
        shutil.copyfile(checkpoint, os.path.join(bundle, "audit", "checkpoint"))
    with open(os.path.join(bundle, "audit", "integrity_at_preservation.txt"), "w") as f:
        f.write(e.get("KS_AUDIT_INTEGRITY", "unknown") + "\n")

    for t in targets:
        contain = ksl.RELEASE_ACTIONS.get(t["action"], t["action"])
        sub = ksl.ACTIONS.get(contain)
        if not sub or not testenv:
            continue
        kind_dir = os.path.join(testenv, sub)
        dest = os.path.join(bundle, "containment", sub)
        os.makedirs(dest, 0o700, exist_ok=True)
        cur = os.path.join(kind_dir, t["target_id"] + ".contained")
        if os.path.isfile(cur) and not os.path.islink(cur):
            shutil.copyfile(cur, os.path.join(dest, os.path.basename(cur)))
        rel = os.path.join(kind_dir, "released")
        if os.path.isdir(rel):
            for name in sorted(os.listdir(rel)):
                if name.startswith(t["target_id"] + ".") and os.path.isfile(os.path.join(rel, name)):
                    shutil.copyfile(os.path.join(rel, name), os.path.join(dest, name))

    preserved_at = ksl.format_ts(ksl.parse_ts(e.get("KS_NOW", "")) or
                                 datetime.datetime.now(datetime.timezone.utc))
    _write_json(os.path.join(bundle, "timeline.json"), {"incident_id": incident_id, "entries": timeline})
    _write_json(os.path.join(bundle, "scope.json"), {
        "incident_id": incident_id, "environment": "test", "preserved_at": preserved_at,
        "command_ids": command_ids, "event_ids": event_ids, "targets": targets, "missing": missing,
        "audit_integrity_at_preservation": e.get("KS_AUDIT_INTEGRITY", "unknown"),
    })
    lines = ["# Recovery steps for %s (test environment)" % incident_id, ""]
    for t in targets:
        contain = ksl.RELEASE_ACTIONS.get(t["action"], t["action"])
        if contain in _RELEASE_FOR:
            lines += ["## %s (%s, %s)" % (t["target_id"], contain, t["execution_result"]),
                      "1. Confirm root cause is addressed (see timeline.json, events/).",
                      "2. Operator signs a release on the operator host:",
                      "   python3 security/killswitch/killswitch_sign.py --issuer <issuer> --key-file <key> \\",
                      "     --action %s --target %s --reason \"<why it is safe to release>\"" % (_RELEASE_FOR[contain], t["target_id"]),
                      "3. killswitch_gate.sh execute <signed.json> --enforce-test",
                      "4. Re-verify: killswitch_enforce.py check <kind> %s <testenv> -> ALLOW;" % t["target_id"],
                      "   then re-run tests/waio_v2_redteam_e2e_test.sh.", ""]
    with open(os.path.join(bundle, "recovery.md"), "w") as f:
        f.write("\n".join(lines) + "\n")

    files = {}
    for root, _dirs, names in os.walk(bundle):
        for name in names:
            full = os.path.join(root, name)
            rel = os.path.relpath(full, bundle)
            if rel != MANIFEST:
                files[rel] = sha256_file(full)
    key = _mac_key()
    _write_json(os.path.join(bundle, MANIFEST), {
        "incident_id": incident_id, "files": files,
        "mac_mode": "hmac-sha256" if key else "sha256-unkeyed",
        "manifest_mac": _manifest_mac(files, key) if key else None,
    })
    for root, dirs, names in os.walk(bundle, topdown=False):
        for name in names:
            os.chmod(os.path.join(root, name), 0o400)
    out({"ok": True, "bundle": bundle, "files": len(files) + 1, "missing": missing,
         "mac_mode": "hmac-sha256" if key else "sha256-unkeyed", "timeline_entries": len(timeline)})


def verify(bundle):
    man = _load_json(os.path.join(bundle, MANIFEST))
    if not isinstance(man, dict) or not isinstance(man.get("files"), dict):
        return out({"ok": False, "verdict": "manifest_missing_or_corrupt"})
    files = man["files"]
    modified, missing_f, extra = [], [], []
    for rel, digest in sorted(files.items()):
        full = os.path.join(bundle, rel)
        if not os.path.isfile(full):
            missing_f.append(rel)
        elif sha256_file(full) != digest:
            modified.append(rel)
    for root, _dirs, names in os.walk(bundle):
        for name in names:
            rel = os.path.relpath(os.path.join(root, name), bundle)
            if rel != MANIFEST and rel not in files:
                extra.append(rel)
    mac_ok = None
    if man.get("mac_mode") == "hmac-sha256":
        key = _mac_key()
        mac_ok = bool(key) and hmac.compare_digest(_manifest_mac(files, key), str(man.get("manifest_mac")))
    ok = not (modified or missing_f or extra) and mac_ok is not False
    out({"ok": ok, "verdict": "ok" if ok else "tampered", "modified": modified, "missing": missing_f,
         "unexpected": sorted(extra), "mac_mode": man.get("mac_mode"), "manifest_mac_valid": mac_ok})


def main(argv):
    if len(argv) >= 4 and argv[1] == "preserve":
        cids, eids, rest = [], [], argv[4:]
        while rest:
            if len(rest) >= 2 and rest[0] == "--command-id":
                cids.append(rest[1])
            elif len(rest) >= 2 and rest[0] == "--event-id":
                eids.append(rest[1])
            else:
                out({"ok": False, "detail": "usage"})
                return 2
            rest = rest[2:]
        preserve(argv[2], argv[3], cids, eids)
        return 0
    if len(argv) == 3 and argv[1] == "verify":
        verify(argv[2])
        return 0
    out({"ok": False, "detail": "usage: preserve INCIDENT_ID OUT_ROOT [--command-id ID]... [--event-id ID]... | verify BUNDLE"})
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
