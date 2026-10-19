"""security/killswitch/killswitch_policy.py -- pre-approved containment
policies for the DuCoPA Independent Kill Switch (pure, no I/O).

WHY THIS EXISTS: killswitch_lib.evaluate_event() only ever recommends;
a human must sign each command. That is too slow for a decoy hit, where
any access at all is hostile. This module lets an operator sign, IN
ADVANCE, a narrow standing policy ("if sensor S reports a decoy_access
on test-endpoint-X, block test-endpoint-X, at most N times, until T"),
so the gate can act on a matching event without a per-event signature.

What still holds (nothing here widens the gate's authority):
  - the policy is HMAC-signed by an issuer key from the same keyring and
    the issuer must be authorized (authz.conf) for every rule's action
  - every rule's (action, target, test) must be on targets.conf; only
    containment actions may appear in a policy, never release actions
  - environment is "test" only; lifetime is capped at MAX_POLICY_SECONDS
  - the EVENT must be signed by a sensor key named in the policy, so a
    forged or AI-written event file cannot trigger anything
  - the event must be fresh; one event id executes at most once (the
    gate derives the command id from policy id + event id) and the
    policy's max_executions is enforced by the gate with atomic slots
  - the synthesized command's origin is "preapproved_policy", recorded
    as such, never "human_operator"

An AI component has no route to a policy: it cannot sign one (no key),
and it cannot sign a sensor event (no sensor key). Key separation is a
deployment property, same caveat as killswitch_lib's header.
"""

import hashlib
import hmac
import json
import re

import killswitch_lib as ksl

SCHEMA_POLICY = "waio.killswitch.policy.v1"
SCHEMA_SENSOR_EVENT = "waio.killswitch.sensor_event.v1"
ORIGIN = "preapproved_policy"

POLICY_FIELDS = frozenset({
    "schema", "policy_id", "issuer", "issued_at", "expires_at", "environment",
    "sensor_ids", "rules", "max_executions", "reason", "signature",
})
RULE_FIELDS = frozenset({"source", "event_type", "action", "target_id"})
SENSOR_EVENT_FIELDS = frozenset({
    "schema", "event_id", "sensor_id", "source", "type", "severity",
    "target_ref", "observed_at", "summary", "signature",
})

MAX_POLICY_BYTES = 8192
MAX_POLICY_SECONDS = 7 * 24 * 3600
MAX_RULES = 16
MAX_EXECUTIONS_CAP = 20
TRIGGER_SEVERITIES = frozenset({"high", "critical"})


def canonical(obj):
    body = {k: v for k, v in obj.items() if k != "signature"}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def sign(obj, key_bytes):
    return hmac.new(key_bytes, canonical(obj), hashlib.sha256).hexdigest()


def verify(obj, key_bytes):
    sig = obj.get("signature")
    if key_bytes is None or not isinstance(sig, str) or not re.fullmatch(r"[0-9a-f]{64}", sig):
        return False
    return hmac.compare_digest(sign(obj, key_bytes), sig)


def _parse(text, fields, limit, what):
    if text is None:
        return None, "no %s input" % what
    if len(text.encode("utf-8", "replace")) > limit:
        return None, "%s exceeds %d bytes" % (what, limit)
    try:
        obj = json.loads(text)
    except ValueError:
        return None, "%s is not valid JSON" % what
    if not isinstance(obj, dict) or set(obj) != fields:
        return None, "%s fields mismatch" % what
    return obj, None


def parse_policy(text):
    pol, err = _parse(text, POLICY_FIELDS, MAX_POLICY_BYTES, "policy")
    if err:
        return None, err
    if not isinstance(pol["rules"], list) or not pol["rules"] or len(pol["rules"]) > MAX_RULES:
        return None, "policy rules must be a non-empty list of at most %d" % MAX_RULES
    for r in pol["rules"]:
        if not isinstance(r, dict) or set(r) != RULE_FIELDS or any(not isinstance(v, str) for v in r.values()):
            return None, "policy rule fields mismatch"
    if not isinstance(pol["sensor_ids"], list) or not pol["sensor_ids"] or \
            not all(ksl.valid_id(s) for s in pol["sensor_ids"]):
        return None, "policy sensor_ids must be a non-empty list of ids"
    if not isinstance(pol["max_executions"], int) or isinstance(pol["max_executions"], bool):
        return None, "policy max_executions must be an integer"
    for k in ("schema", "policy_id", "issuer", "issued_at", "expires_at", "environment", "reason", "signature"):
        if not isinstance(pol[k], str):
            return None, "policy field %s must be a string" % k
    return pol, None


def parse_sensor_event(text):
    ev, err = _parse(text, SENSOR_EVENT_FIELDS, ksl.MAX_EVENT_BYTES, "sensor event")
    if err:
        return None, err
    if any(not isinstance(v, str) for v in ev.values()):
        return None, "every sensor event field must be a string"
    return ev, None


def policy_command_id(policy_id, event_id):
    return "pol-" + hashlib.sha256(("%s|%s" % (policy_id, event_id)).encode()).hexdigest()[:24]


def evaluate(pol, ev, now, issuer_key, sensor_key, authz, targets,
             freshness_seconds=ksl.DEFAULT_FRESHNESS_SECONDS):
    """Returns {'decision','code','detail','command'}; 'command' is the
    synthesized (unsigned) command record on ALLOW, {} otherwise."""
    def deny(code, detail):
        return {"decision": "DENY", "code": code, "detail": detail, "command": {}}

    if pol.get("schema") != SCHEMA_POLICY or ev.get("schema") != SCHEMA_SENSOR_EVENT:
        return deny("DENIED_SCHEMA", "policy/event schema mismatch")
    for v in (pol["policy_id"], pol["issuer"], ev["event_id"], ev["sensor_id"]):
        if not ksl.valid_id(v):
            return deny("DENIED_INVALID_INPUT", "invalid id in policy or event")

    # authentication first: policy by its issuer, event by its sensor
    if not verify(pol, issuer_key):
        return deny("DENIED_UNAUTHENTICATED", "policy signature does not verify for issuer '%s'" % pol["issuer"])
    if ev["sensor_id"] not in pol["sensor_ids"]:
        return deny("DENIED_SENSOR_NOT_TRUSTED", "sensor '%s' is not named by policy" % ev["sensor_id"])
    if not verify(ev, sensor_key):
        return deny("DENIED_UNAUTHENTICATED", "event signature does not verify for sensor '%s'" % ev["sensor_id"])

    if pol["environment"] not in ksl.ALLOWED_ENVIRONMENTS:
        return deny("DENIED_PRODUCTION", "policy environment '%s' refused" % pol["environment"])
    issued, expires = ksl.parse_ts(pol["issued_at"]), ksl.parse_ts(pol["expires_at"])
    if issued is None or expires is None:
        return deny("DENIED_INVALID_INPUT", "policy timestamps invalid")
    if (expires - issued).total_seconds() > MAX_POLICY_SECONDS or expires <= issued:
        return deny("DENIED_POLICY_INVALID", "policy lifetime must be 0-%ds" % MAX_POLICY_SECONDS)
    if now >= expires:
        return deny("DENIED_POLICY_EXPIRED", "policy expired at %s" % pol["expires_at"])
    if (issued - now).total_seconds() > ksl.MAX_FUTURE_SKEW_SECONDS:
        return deny("DENIED_POLICY_INVALID", "policy issued in the future")
    if not 1 <= pol["max_executions"] <= MAX_EXECUTIONS_CAP:
        return deny("DENIED_POLICY_INVALID", "max_executions must be 1-%d" % MAX_EXECUTIONS_CAP)
    ok, err = ksl.validate_reason(pol["reason"])
    if not ok:
        return deny("DENIED_INVALID_INPUT", "policy reason rejected: %s" % err)

    # every rule must be inside the gate's existing allowlists
    granted = authz.get(pol["issuer"], set())
    for r in pol["rules"]:
        if r["action"] not in ksl.ACTIONS:
            return deny("DENIED_ACTION_NOT_ALLOWLISTED", "policy rule action '%s' is not a containment action" % r["action"])
        if r["action"] not in granted:
            return deny("DENIED_UNAUTHORIZED", "issuer '%s' is not authorized for '%s'" % (pol["issuer"], r["action"]))
        if (r["action"], r["target_id"], "test") not in targets:
            return deny("DENIED_TARGET_NOT_ALLOWLISTED", "policy target '%s' not allowlisted for '%s'" % (r["target_id"], r["action"]))

    observed = ksl.parse_ts(ev["observed_at"])
    if observed is None:
        return deny("DENIED_INVALID_INPUT", "event observed_at invalid")
    age = (now - observed).total_seconds()
    if age > freshness_seconds or age < -ksl.MAX_FUTURE_SKEW_SECONDS:
        return deny("DENIED_STALE", "event is %ds old, limit %ds" % (int(age), freshness_seconds))
    if ev["severity"].lower() not in TRIGGER_SEVERITIES:
        return deny("DENIED_POLICY_NO_MATCH", "event severity '%s' below policy trigger" % ev["severity"])

    match = next((r for r in pol["rules"] if r["source"] == ev["source"] and
                  r["event_type"] == ev["type"] and r["target_id"] == ev["target_ref"]), None)
    if match is None:
        return deny("DENIED_POLICY_NO_MATCH", "no policy rule matches %s/%s/%s" % (ev["source"], ev["type"], ev["target_ref"]))

    command = {
        "schema": ksl.SCHEMA_COMMAND,
        "command_id": policy_command_id(pol["policy_id"], ev["event_id"]),
        "action": match["action"],
        "target_id": match["target_id"],
        "environment": "test",
        "issued_at": ev["observed_at"],
        "origin": ORIGIN,
        "issuer": pol["issuer"],
        "reason": "policy %s matched %s event %s" % (pol["policy_id"], ev["type"], ev["event_id"]),
        "event_ref": ev["event_id"],
        "policy_id": pol["policy_id"],
        "max_executions": pol["max_executions"],
    }
    return {"decision": "ALLOW", "code": "ALLOWED_BY_POLICY", "detail": "policy %s rule matched" % pol["policy_id"],
            "command": command}
