"""security/wad/wad_adapters.py -- detector outputs -> WAD events (PR 3).

Reads each detector's own output file and turns every record into a WAD
event (wad_lib.normalize_event's input shape) plus a provenance record.
Conversion reuses security/intelligence/intelligence_lib.py's existing
from_* adapters unchanged; no risk, confidence or decision logic is added
here. Schema validation stays in wad_lib.normalize_event.

Sources (what each detector writes today):
  shadow_ai     JSONL of findings (shadow_ai_monitor.sh stdout,
                shadow_ai_lib.build_finding); time = finding "detected_at".
  attack_graph  one JSON document (attack_graph.sh latest_graph.json:
                nodes, analysis.attack_paths); nodes and paths carry no time
                of their own, so the document's "generated_at" is used and
                provenance says so.
  saas_ato      JSONL of events (saas_ato_lib.build_event); time = "timestamp".
  probe_detector  BLOCKED: needs PR #182, which is not merged.

SIGNATURES. No detector signs its output today. An adapter accepts an
optional envelope field `wad_sig` = {"alg": "hmac-sha256", "key_id":
<detector>, "mac": <hex>} over the canonical JSON of the record (JSONL) or
document (attack_graph) without `wad_sig`, verified against that detector's
own key, $WAD_PRODUCER_KEY_DIR/<detector>.key. signature_status is:
  verified                     mac matches the detector's own key
  unsigned                     no wad_sig (every detector today)
  unverifiable_no_trusted_key  wad_sig present, no usable key for it
  invalid                      malformed envelope, wrong key_id or bad mac
                               -> the record is rejected, never accepted
Only "verified" means signed. This module never signs anything: a
signature WAD made itself would prove only that WAD read a file, not who
wrote it. HMAC is symmetric, so "verified" proves the record was produced
by a holder of that key file, which includes any process able to read it.
"""

import hashlib
import hmac
import json
import os
import re
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
sys.path.insert(0, os.path.join(_HERE, "..", "intelligence"))
import intelligence_lib as il  # noqa: E402
import wad_lib as wl  # noqa: E402

ADAPTER_VERSION = "wad-adapters/1"
MAX_SOURCE_BYTES = 16 * 1024 * 1024
SIG_FIELD = "wad_sig"
SOURCES = ("shadow_ai", "attack_graph", "saas_ato")
BLOCKED = {"probe_detector": "blocked: the probe-detector adapter needs PR #182, which is not merged"}
STATUSES = ("verified", "unsigned", "unverifiable_no_trusted_key", "invalid")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


class SourceFailure(Exception):
    """The detector's output as a whole is unusable (missing, unreadable,
    a symlink, too large, not UTF-8, wrong shape, invalid signature)."""


def read_source(path):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as e:
        raise SourceFailure(f"unreadable_or_symlink: {e.strerror}")
    with os.fdopen(fd, "rb") as f:
        data = f.read(MAX_SOURCE_BYTES + 1)
    if len(data) > MAX_SOURCE_BYTES:
        raise SourceFailure("too_large")
    try:
        return data, data.decode("utf-8")
    except UnicodeDecodeError:
        raise SourceFailure("not_utf8")


def load_keys(key_dir):
    """{detector: key bytes} for detectors whose key file is a regular file
    (not a symlink) of at least 16 bytes. Others are simply absent."""
    keys = {}
    if not key_dir:
        return keys
    for det in SOURCES:
        try:
            fd = os.open(os.path.join(key_dir, det + ".key"), os.O_RDONLY | os.O_NOFOLLOW)
        except OSError:
            continue
        with os.fdopen(fd, "rb") as f:
            k = f.read(4096)
        if len(k) >= 16:
            keys[det] = k
    return keys


def signature_status(obj, detector, keys):
    """-> (status, obj without the envelope)."""
    if not isinstance(obj, dict) or SIG_FIELD not in obj:
        return "unsigned", obj
    sig = obj[SIG_FIELD]
    body = {k: v for k, v in obj.items() if k != SIG_FIELD}
    if not (isinstance(sig, dict) and sig.get("alg") == "hmac-sha256" and sig.get("key_id") == detector
            and isinstance(sig.get("mac"), str) and _HEX64.match(sig["mac"])):
        return "invalid", body
    key = keys.get(detector)
    if key is None:
        return "unverifiable_no_trusted_key", body
    expected = hmac.new(key, wl.canonical(body).encode("utf-8"), hashlib.sha256).hexdigest()
    return ("verified" if hmac.compare_digest(expected, sig["mac"]) else "invalid"), body


def _clip(text, limit):
    if not isinstance(text, str):
        return ""
    return "".join(c if c.isprintable() else " " for c in text)[:limit]


def _event(detector, record, raw_risk, raw_conf, observed, ts_source, prov):
    """intelligence_lib record -> WAD event. intelligence_lib defaults a
    missing risk/confidence to LOW; for WAD a missing value must stay
    missing (insufficient), so the raw presence decides."""
    source_id = record.get("source_finding_id") or record.get("id") or ""
    eid = "wa-" + wl.sha256_hex(f"{detector}\x00{source_id}\x00{observed}")[:40]
    return {
        "event_id": eid,
        "source_module": record.get("source_module"),
        "entity": record.get("entity"),
        "entity_type": record.get("entity_type"),
        "category": _clip(record.get("category") or "", 64),
        "risk": record.get("risk") if raw_risk is not None else None,
        "confidence": record.get("confidence") if raw_conf is not None else None,
        "observed_at": observed,
        "summary": _clip(record.get("summary") or "", 1024),
        "_provenance": dict(prov, source_record_id=_clip(str(source_id), 128), timestamp_source=ts_source),
    }


def convert(detector, path, keys, require_signed=False):
    """-> {"events": [...], "rejected": [...], "failure": None|reason,
    "signature_counts": {...}}. A SourceFailure becomes `failure`; one bad
    record becomes a `rejected` entry and the rest still convert."""
    out = {"detector": detector, "path": path, "events": [], "rejected": [], "failure": None,
           "signature_counts": {s: 0 for s in STATUSES}}
    if detector in BLOCKED:
        out["failure"] = BLOCKED[detector]
        return out
    if detector not in SOURCES:
        out["failure"] = f"unknown_detector:{detector}"
        return out
    try:
        data, text = read_source(path)
    except SourceFailure as e:
        out["failure"] = str(e)
        return out
    base = {"adapter": ADAPTER_VERSION, "detector": detector,
            "source_file_sha256": hashlib.sha256(data).hexdigest()}

    def reject(index, reasons):
        out["rejected"].append({"detector": detector, "index": index, "reasons": reasons})

    def gate(index, status):
        out["signature_counts"][status] += 1
        if status == "invalid":
            reject(index, ["signature_invalid"])
            return False
        if require_signed and status != "verified":
            reject(index, [f"signature_required:{status}"])
            return False
        return True

    if detector == "attack_graph":
        try:
            doc = json.loads(text)
        except json.JSONDecodeError:
            out["failure"] = "not_json"
            return out
        if not isinstance(doc, dict) or not isinstance(doc.get("nodes"), dict):
            out["failure"] = "bad_document_shape"
            return out
        status, doc = signature_status(doc, detector, keys)
        out["signature_counts"][status] += 1
        if status == "invalid" or (require_signed and status != "verified"):
            out["failure"] = "signature_invalid" if status == "invalid" else f"signature_required:{status}"
            return out
        observed = doc.get("generated_at")
        ts_source = "detector_document_generated_at" if observed is not None else "absent"
        analysis = doc.get("analysis") if isinstance(doc.get("analysis"), dict) else {}
        items = [("node", n, v) for n, v in doc["nodes"].items()] + \
                [("path", None, p) for p in (analysis.get("attack_paths") or [])]
        for i, (kind, name, item) in enumerate(items):
            if not isinstance(item, dict):
                reject(i, ["not_an_object"])
                continue
            prov = dict(base, source_index=i, signature_status=status)
            if kind == "node":
                rec = il.from_attack_graph_node(name, item)
                raw_risk = item.get("highest_risk")
            else:
                if not isinstance(item.get("path"), list):
                    reject(i, ["bad_path"])
                    continue
                rec = il.from_attack_graph_path(item)
                raw_risk = item.get("path_risk")
            out["events"].append(_event(detector, rec, raw_risk, rec["confidence"], observed, ts_source, prov))
        return out

    convert_one = il.from_shadow_ai_finding if detector == "shadow_ai" else il.from_saas_ato_finding
    time_field = "detected_at" if detector == "shadow_ai" else "timestamp"
    for i, line in enumerate(text.splitlines()):
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            reject(i, ["unparseable"])
            continue
        if not isinstance(obj, dict):
            reject(i, ["not_an_object"])
            continue
        status, obj = signature_status(obj, detector, keys)
        if not gate(i, status):
            continue
        rec = convert_one(obj)
        observed = obj.get(time_field)
        prov = dict(base, source_index=i, signature_status=status)
        out["events"].append(_event(detector, rec, obj.get("risk"), obj.get("confidence"), observed,
                                    "detector_record" if observed is not None else "absent", prov))
    return out
