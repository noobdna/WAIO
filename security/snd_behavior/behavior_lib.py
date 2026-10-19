"""security/snd_behavior/behavior_lib.py -- SND@ID / SND@HOME behavior
monitoring: per-principal baselines and deviation detection (pure, no I/O).

============================================================
SCOPE, STATED NARROWLY
============================================================
READ-ONLY / DRY-RUN. This module turns already-collected identity and
access events into structured detection records. It never contains,
never calls security/killswitch/, and never contacts SND or any IdP.
Its output deliberately uses the field names killswitch_lib.normalize_event
accepts (source, event_id, type, severity, target_ref, summary,
observed_at), so an operator can hand a detection to
`killswitch_gate.sh evaluate-event` -- which itself only recommends.

SND@ID DOES NOT EXIST YET (no project on this machine, no reference in
this repository). SND@HOME's real event schema is not verifiable from
here either. So the input contract below is this module's OWN minimal
interface (waio.snd.auth_event.v1); security/snd_behavior/snd_id_mock.py
emits it for tests. A real collector must map onto it; nothing here
claims to be SND@ID.

INPUT (one JSON object per line; every other field is DROPPED):
  source     snd_id | snd_home
  event_id   [A-Za-z0-9_.-]{1,64}
  ts         YYYY-MM-DDTHH:MM:SSZ (UTC)
  principal  opaque account id
  action     login_success | login_failure | privilege_change |
             data_access | mfa_change
  region     coarse location code (country/region, e.g. JP, JP-13, US)
  device_id  opaque device id
  bytes      int, data_access only
  role       new role, privilege_change only
DATA MINIMIZATION: IP addresses, user agents, request/response bodies,
tokens and message content are not part of the contract and are never
stored, even if a collector sends them.

CONTEXT (operator-declared, never inferred): travel / schedule_change /
emergency_change windows downgrade -- never suppress, never upgrade --
the matching detections, and the record names the context id applied.
An auth-failure burst is never downgraded by any context.
"""

import datetime
import hashlib
import re

SCHEMA_INPUT = "waio.snd.auth_event.v1"
SCHEMA_DETECTION = "waio.snd.detection.v1"
SCHEMA_BASELINE = "waio.snd.baseline.v1"

ACTIONS = frozenset({"login_success", "login_failure", "privilege_change", "data_access", "mfa_change"})
SOURCES = frozenset({"snd_id", "snd_home"})
ELEVATED_ROLES = frozenset({"admin", "owner", "root", "superuser", "global_admin", "domain_admin"})

RISK_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
SEVERITY = {"LOW": "low", "MEDIUM": "medium", "HIGH": "high", "CRITICAL": "critical"}

# rule -> (killswitch event type, recommended containment action)
RULE_TYPE = {
    "off_hours_login": "anomalous_auth",
    "new_region_login": "anomalous_auth",
    "new_device_login": "anomalous_auth",
    "impossible_travel": "impossible_travel",
    "auth_failure_burst": "anomalous_auth",
    "privilege_escalation": "privilege_change",
    "bulk_data_access": "bulk_data_access",
    "mfa_change_unfamiliar": "anomalous_auth",
}
RECOMMEND = {"anomalous_auth": "revoke_test_session", "impossible_travel": "revoke_test_session",
             "privilege_change": "revoke_test_session", "bulk_data_access": "revoke_test_session"}

DEFAULTS = {
    "tz_offset_hours": 9,            # principal-local hour for off-hours checks (JST)
    "min_baseline_logins": 10,       # below this, off-hours is not judged
    "hour_tolerance": 1,             # +/- hours around any seen login hour
    "impossible_travel_minutes": 120,
    "failure_burst_count": 5,
    "failure_burst_minutes": 10,
    "bulk_window_minutes": 60,
    "bulk_multiplier": 5.0,          # vs. baseline p95 of a single access
    "bulk_floor_bytes": 50 * 1024 * 1024,
}

_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")
_CODE = re.compile(r"[A-Z0-9][A-Z0-9-]{0,15}")
_TS = "%Y-%m-%dT%H:%M:%SZ"


def parse_ts(text):
    try:
        return datetime.datetime.strptime(text, _TS).replace(tzinfo=datetime.timezone.utc)
    except (TypeError, ValueError):
        return None


def fmt_ts(dt):
    return dt.astimezone(datetime.timezone.utc).strftime(_TS)


def normalize(raw):
    """Returns (event, error). Keeps only the contract fields."""
    if not isinstance(raw, dict):
        return None, "event must be an object"
    src = str(raw.get("source", "")).lower()
    if src not in SOURCES:
        return None, "source must be snd_id or snd_home"
    ev = {"source": src}
    for k in ("event_id", "principal", "device_id"):
        v = raw.get(k)
        if not isinstance(v, str) or not _ID.fullmatch(v):
            return None, "%s missing or invalid" % k
        ev[k] = v
    ts = parse_ts(raw.get("ts"))
    if ts is None:
        return None, "ts invalid"
    ev["ts"] = ts
    act = raw.get("action")
    if act not in ACTIONS:
        return None, "action invalid"
    ev["action"] = act
    region = str(raw.get("region", "")).upper()
    ev["region"] = region if _CODE.fullmatch(region) else "UNKNOWN"
    b = raw.get("bytes", 0)
    ev["bytes"] = b if isinstance(b, int) and not isinstance(b, bool) and b >= 0 else 0
    role = str(raw.get("role", "")).lower()
    ev["role"] = role if re.fullmatch(r"[a-z_]{1,32}", role) else ""
    return ev, None


def _local_hour(ts, tz):
    return (ts + datetime.timedelta(hours=tz)).hour


def _p95(values):
    if not values:
        return 0
    s = sorted(values)
    return s[min(len(s) - 1, int(round(0.95 * (len(s) - 1))))]


def build_baseline(events, cfg=None):
    """events: normalized, any order. Returns a JSON-able baseline."""
    c = dict(DEFAULTS, **(cfg or {}))
    prof = {}
    for ev in events:
        p = prof.setdefault(ev["principal"], {"login_hours": {}, "regions": set(), "devices": set(),
                                              "access_bytes": [], "roles": set(), "logins": 0})
        if ev["action"] == "login_success":
            h = str(_local_hour(ev["ts"], c["tz_offset_hours"]))
            p["login_hours"][h] = p["login_hours"].get(h, 0) + 1
            p["logins"] += 1
            p["regions"].add(ev["region"])
            p["devices"].add(ev["device_id"])
        elif ev["action"] == "data_access":
            p["access_bytes"].append(ev["bytes"])
        elif ev["action"] == "privilege_change" and ev["role"]:
            p["roles"].add(ev["role"])
    return {"schema": SCHEMA_BASELINE, "config": c, "principals": {
        k: {"login_hours": v["login_hours"], "logins": v["logins"], "regions": sorted(v["regions"]),
            "devices": sorted(v["devices"]), "access_p95_bytes": _p95(v["access_bytes"]),
            "access_samples": len(v["access_bytes"]), "roles": sorted(v["roles"])}
        for k, v in sorted(prof.items())}}


def _active_contexts(contexts, principal, ts, kind):
    out = []
    for cx in contexts or []:
        if cx.get("principal") != principal or cx.get("kind") != kind:
            continue
        start, end = parse_ts(cx.get("start")), parse_ts(cx.get("end"))
        if start and end and start <= ts <= end:
            out.append(cx)
    return out


def _downgrade(risk, floor="LOW"):
    i = max(RISK_ORDER.index(floor), RISK_ORDER.index(risk) - 2)
    return RISK_ORDER[i]


def _detection(rule, risk, confidence, reason, evs, targets, context_id=""):
    first, last = evs[0], evs[-1]
    etype = RULE_TYPE[rule]
    did = "det-" + hashlib.sha256(("%s|%s|%s" % (rule, first["principal"],
                                   ",".join(e["event_id"] for e in evs))).encode()).hexdigest()[:20]
    recommended = RECOMMEND.get(etype, "MONITOR") if risk in ("HIGH", "CRITICAL") else "MONITOR"
    return {
        "schema": SCHEMA_DETECTION,
        "event_id": did,
        "source": last["source"],
        "observed_at": fmt_ts(last["ts"]),
        "principal": first["principal"],
        "rule": rule,
        "type": etype,
        "risk": risk,
        "severity": SEVERITY[risk],
        "confidence": round(confidence, 2),
        "detection_reason": reason,
        "summary": "%s: %s" % (rule, reason),
        "recommended_action": recommended,
        "target_ref": (targets or {}).get(first["principal"], ""),
        "evidence_event_ids": [e["event_id"] for e in evs],
        "context_applied": context_id,
        "mode": "DRY_RUN",
        "read_only": True,
        "execution_result": "NOT_EXECUTED",
    }


def detect(baseline, events, contexts=None, targets=None):
    """events: normalized. Returns a list of detection records, in time
    order. Pure: same inputs, same output (ids are content hashes)."""
    c = baseline.get("config", DEFAULTS)
    profiles = baseline.get("principals", {})
    tz, tol = c["tz_offset_hours"], c["hour_tolerance"]
    out = []
    by_p = {}
    for ev in sorted(events, key=lambda e: (e["ts"], e["event_id"])):
        by_p.setdefault(ev["principal"], []).append(ev)

    for principal, evs in sorted(by_p.items()):
        prof = profiles.get(principal, {"login_hours": {}, "logins": 0, "regions": [], "devices": [],
                                        "access_p95_bytes": 0, "access_samples": 0, "roles": []})
        hours = {int(h) for h in prof["login_hours"]}
        last_login, failures, access_window = None, [], []
        burst_reported_at = None
        for ev in evs:
            ts, act = ev["ts"], ev["action"]
            if act == "login_failure":
                failures = [f for f in failures if (ts - f["ts"]).total_seconds() <= c["failure_burst_minutes"] * 60]
                failures.append(ev)
                if len(failures) >= c["failure_burst_count"] and burst_reported_at is None:
                    out.append(_detection("auth_failure_burst", "HIGH", 0.8,
                                          "%d failed logins within %d min" % (len(failures), c["failure_burst_minutes"]),
                                          list(failures), targets))
                    burst_reported_at = ts
                continue

            if act == "login_success":
                if burst_reported_at is not None and (ts - burst_reported_at).total_seconds() <= c["failure_burst_minutes"] * 60:
                    out.append(_detection("auth_failure_burst", "CRITICAL", 0.9,
                                          "successful login right after a failed-login burst", failures + [ev], targets))
                failures, burst_reported_at = [], None
                new_region = ev["region"] not in prof["regions"] and prof["logins"] > 0
                new_device = ev["device_id"] not in prof["devices"] and prof["logins"] > 0
                lh = _local_hour(ts, tz)
                if prof["logins"] >= c["min_baseline_logins"] and \
                        not any(min(abs(lh - h), 24 - abs(lh - h)) <= tol for h in hours):
                    risk, cid = "MEDIUM", ""
                    sched = [cx for cx in _active_contexts(contexts, principal, ts, "schedule_change")
                             if _hour_in(lh, cx.get("hours"))] + _active_contexts(contexts, principal, ts, "emergency_change")
                    if sched:
                        risk, cid = "LOW", sched[0].get("context_id", "")
                    out.append(_detection("off_hours_login", risk, min(1.0, prof["logins"] / 30.0),
                                          "login at local hour %02d, never seen in %d baseline logins" % (lh, prof["logins"]),
                                          [ev], targets, cid))
                travel = [cx for cx in _active_contexts(contexts, principal, ts, "travel")
                          if ev["region"] in (cx.get("regions") or [])]
                if new_region:
                    risk = "HIGH" if new_device else "MEDIUM"
                    cid = ""
                    if travel:
                        risk, cid = _downgrade(risk), travel[0].get("context_id", "")
                    out.append(_detection("new_region_login", risk, 0.7 if new_device else 0.55,
                                          "login from region %s (baseline: %s)%s" % (
                                              ev["region"], ",".join(prof["regions"]) or "none",
                                              " on a new device" if new_device else ""), [ev], targets, cid))
                elif new_device:
                    out.append(_detection("new_device_login", "LOW", 0.4, "login from a device not in baseline", [ev], targets))
                if last_login is not None and last_login["region"] != ev["region"] and \
                        "UNKNOWN" not in (last_login["region"], ev["region"]) and \
                        _country(last_login["region"]) != _country(ev["region"]) and \
                        (ts - last_login["ts"]).total_seconds() <= c["impossible_travel_minutes"] * 60:
                    risk, cid = "HIGH", ""
                    if travel:
                        risk, cid = "LOW", travel[0].get("context_id", "")
                    out.append(_detection("impossible_travel", risk, 0.75,
                                          "logins from %s then %s within %d min" % (
                                              last_login["region"], ev["region"],
                                              int((ts - last_login["ts"]).total_seconds() // 60)),
                                          [last_login, ev], targets, cid))
                last_login = ev
            elif act == "privilege_change" and ev["role"] in ELEVATED_ROLES and ev["role"] not in prof["roles"]:
                risk, cid = "HIGH", ""
                emerg = _active_contexts(contexts, principal, ts, "emergency_change")
                if emerg:
                    risk, cid = "MEDIUM", emerg[0].get("context_id", "")
                out.append(_detection("privilege_escalation", risk, 0.85,
                                      "granted elevated role '%s' not held in baseline" % ev["role"], [ev], targets, cid))
            elif act == "data_access":
                access_window = [a for a in access_window if (ts - a["ts"]).total_seconds() <= c["bulk_window_minutes"] * 60]
                access_window.append(ev)
                total = sum(a["bytes"] for a in access_window)
                threshold = max(c["bulk_floor_bytes"], c["bulk_multiplier"] * prof["access_p95_bytes"])
                if total > threshold and not any(d["rule"] == "bulk_data_access" and d["principal"] == principal and
                                                 set(d["evidence_event_ids"]) & {a["event_id"] for a in access_window}
                                                 for d in out):
                    risk = "CRITICAL" if total > 10 * threshold else "HIGH"
                    cid = ""
                    emerg = _active_contexts(contexts, principal, ts, "emergency_change")
                    if emerg:
                        risk, cid = "MEDIUM", emerg[0].get("context_id", "")
                    out.append(_detection("bulk_data_access", risk, 0.8 if prof["access_samples"] >= 10 else 0.6,
                                          "%d bytes read within %d min (threshold %d)" % (
                                              total, c["bulk_window_minutes"], int(threshold)),
                                          list(access_window), targets, cid))
            elif act == "mfa_change":
                if ev["device_id"] not in prof["devices"] or ev["region"] not in prof["regions"]:
                    out.append(_detection("mfa_change_unfamiliar", "HIGH", 0.7,
                                          "MFA settings changed from an unfamiliar device/region", [ev], targets))
    return sorted(out, key=lambda d: (d["observed_at"], d["event_id"]))


def _country(region):
    return region.split("-", 1)[0]


def _hour_in(hour, window):
    if not isinstance(window, list) or len(window) != 2:
        return False
    a, b = window
    return a <= hour <= b if a <= b else (hour >= a or hour <= b)
