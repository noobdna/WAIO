"""security/yashi/gap_detectors.py -- input contracts and rule logic for
the two techniques YASHI records as detection GAPs: YT-PII-EXPOSURE and
YT-AI-SCAM.

STATUS: SCHEMA + RULES ONLY. NOT PRODUCTION-READY.
A 2026-10-20 search of this repository found no telemetry source for
either event type. No collector emits them, and nothing in SND@HOME,
shadow_ai, saas_ato or intelligence carries breach notices or call/
message deception signals. So this module defines:
  - the event shape a future collector must emit (SCHEMAS);
  - validate_event(): field-level checks, so a collector bug becomes
    INVALID / INSUFFICIENT_DATA rather than a silent miss;
  - evaluate_pii_exposure() / evaluate_ai_scam(): rules exercised by
    synthetic events only (tests/yashi_learning_test.sh G-series).
Every result carries production_ready: False and the data_source note
below, so nothing downstream can mistake it for a validated detector.

Safety: pure functions only, with no I/O, network or subprocess. A
subject is referenced by an opaque `subject_ref` and never by a raw
address (validate_event rejects anything containing '@'). The only
action is HUMAN_REVIEW: nothing is blocked, suspended or reported.
"""

DATA_SOURCE_NOTE = "no telemetry source wired (schema only, 2026-10-20); synthetic-event tests only"

PII_CATEGORIES = {
    "government_id": "HIGH", "financial": "HIGH", "credentials": "HIGH", "health": "HIGH",
    "contact": "MEDIUM", "address": "MEDIUM", "date_of_birth": "MEDIUM",
    "email_address": "LOW", "name": "LOW",
}
PII_SOURCE_TYPES = ("breach_notification", "vendor_notice", "regulator", "self_report")

AI_SCAM_CHANNELS = ("voice", "video", "email", "sms", "chat")
AI_SCAM_IDENTITIES = ("executive", "family", "vendor", "support", "government", "other")
# indicator -> weight. verified_via_known_channel is a counter-signal.
AI_SCAM_INDICATORS = {
    "urgent_payment_request": 3,
    "new_payment_destination": 3,
    "secrecy_request": 2,
    "out_of_band_callback_failed": 3,
    "caller_id_mismatch": 2,
    "synthetic_media_suspected": 2,
    "credential_or_code_request": 3,
    "verified_via_known_channel": 0,
}

SCHEMAS = {
    "pii_exposure_notice": {
        "required": {"event_id": str, "observed_at": str, "source": str, "source_type": str,
                     "subject_ref": str, "data_categories": list, "exposure_confirmed": bool},
        "enums": {"source_type": PII_SOURCE_TYPES},
        "list_enums": {"data_categories": tuple(PII_CATEGORIES)},
    },
    "ai_scam_signal": {
        "required": {"event_id": str, "observed_at": str, "channel": str,
                     "claimed_identity_type": str, "indicators": list},
        "enums": {"channel": AI_SCAM_CHANNELS, "claimed_identity_type": AI_SCAM_IDENTITIES},
        "list_enums": {"indicators": tuple(AI_SCAM_INDICATORS)},
    },
}


def _result(event, status, severity="NONE", reasons=(), recommendations=()):
    return {
        "event_id": (event or {}).get("event_id") if isinstance(event, dict) else None,
        "status": status, "severity": severity,
        "reasons": list(reasons), "recommendations": list(recommendations),
        "recommended_action": "HUMAN_REVIEW",
        "production_ready": False, "data_source": DATA_SOURCE_NOTE,
    }


def validate_event(event, event_type):
    """-> (status, problems). status is OK, INSUFFICIENT_DATA (a
    required field is missing or empty) or INVALID (wrong type, unknown
    enum value, or a raw address in subject_ref)."""
    schema = SCHEMAS[event_type]
    if not isinstance(event, dict):
        return "INVALID", ["event is not an object"]
    missing, invalid = [], []
    for field, typ in schema["required"].items():
        v = event.get(field)
        if v is None or (typ is str and v == ""):
            missing.append(field)
        elif not isinstance(v, typ):
            invalid.append("%s must be %s" % (field, typ.__name__))
    for field, allowed in schema["enums"].items():
        if isinstance(event.get(field), str) and event[field] and event[field] not in allowed:
            invalid.append("%s=%r not in %s" % (field, event[field], "/".join(allowed)))
    for field, allowed in schema["list_enums"].items():
        bad = [x for x in event.get(field) or [] if x not in allowed] if isinstance(event.get(field), list) else []
        if bad:
            invalid.append("%s has unknown values %s" % (field, bad))
    if "@" in str(event.get("subject_ref", "")):
        invalid.append("subject_ref must be an opaque reference, not an address")
    if invalid:
        return "INVALID", invalid
    if missing:
        return "INSUFFICIENT_DATA", ["missing " + ", ".join(missing)]
    return "OK", []


def evaluate_pii_exposure(event):
    st, problems = validate_event(event, "pii_exposure_notice")
    if st != "OK":
        return _result(event, st, reasons=problems)
    cats = event["data_categories"]
    if not cats:
        return _result(event, "NO_FINDING", reasons=["notice lists no exposed data categories"])
    order = ["LOW", "MEDIUM", "HIGH"]
    sev = max((PII_CATEGORIES[c] for c in cats), key=order.index)
    reasons = ["exposed: " + ", ".join(sorted(cats))]
    if not event["exposure_confirmed"]:
        # False-positive guard: "may have been affected" notices are common.
        sev = "LOW"
        reasons.append("exposure not confirmed by the notifier -- severity capped at LOW")
    recs = ["expect more convincing phishing that uses the exposed data"]
    if "credentials" in cats:
        recs.insert(0, "rotate the affected credentials and review sign-in history")
    if "government_id" in cats or "financial" in cats:
        recs.append("watch for identity-fraud and account-opening attempts")
    return _result(event, "DETECTED", sev, reasons, recs)


def evaluate_ai_scam(event):
    st, problems = validate_event(event, "ai_scam_signal")
    if st != "OK":
        return _result(event, st, reasons=problems)
    ind = set(event["indicators"])
    if "verified_via_known_channel" in ind:
        # False-positive guard: a request confirmed through an independent,
        # previously known channel is the legitimate case this rule must pass.
        return _result(event, "NO_FINDING", reasons=["request verified via a known channel"])
    score = sum(AI_SCAM_INDICATORS[i] for i in ind)
    pressure = ind & {"urgent_payment_request", "new_payment_destination", "credential_or_code_request", "secrecy_request"}
    if not pressure:
        # Synthetic-looking media with no ask attached is not a scam finding.
        return _result(event, "NO_FINDING", reasons=["no payment, credential or secrecy request"])
    sev = "HIGH" if score >= 7 else "MEDIUM" if score >= 4 else "LOW"
    recs = ["verify through a known, independent channel before acting",
            "do not change payment details on the strength of this contact"]
    return _result(event, "DETECTED", sev, ["indicators: " + ", ".join(sorted(ind)), "score %d" % score], recs)
