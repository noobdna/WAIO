"""security/wad/wad_lib.py -- pure core of WAIO Adaptive Defense (WAD).

Pipeline position:

    Intelligence Layer -> Decision Engine -\
    sensor events (wad-event/1) ------------> WAD: normalize -> assess
                                              -> plan -> (wad_cli.py) run

WAD turns a threat event into a THREAT LEVEL (L0-L4) and an ordered
response PLAN, using a versioned policy file (security/wad/policies/).
Everything here is a pure function of its arguments: no I/O, no clock,
no subprocess. wad_cli.py owns state, audit, locking and execution.

SAFETY FLOORS -- enforced in code, never overridable by a policy file:
  1. A level that restricts or isolates (L3/L4) is reachable only with
     TRUSTED LOCAL corroboration (`local: true`). This is the same
     invariant the Decision Engine enforces (ARCHITECTURE.md Phase 104):
     global intelligence alone never justifies containment.
  2. Destructive actions (restrict_network, isolate_host and their
     releases) always require human approval. validate_policy() rejects
     a policy that marks one automatic. WAD v1 has no executor for them
     at all: the plan carries them as `pending_approval` hand-offs.
  3. Uncertain input never produces a confident verdict: an incomplete
     event, or LOW confidence, is capped at L2 (warn a human) and the
     assessment says `uncertain: true` with the reasons.
"""

import copy
import datetime
import hashlib
import json
import re

POLICY_SCHEMA = "wad-policy/1"
EVENT_SCHEMA = "wad-event/1"

RISK_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
CONFIDENCE_ORDER = ["LOW", "MEDIUM", "HIGH"]
LEVELS = ["L0", "L1", "L2", "L3", "L4"]

# Highest level an uncertain assessment may reach (safety floor 3).
UNCERTAIN_CAP = "L2"
# Lowest level that needs trusted local corroboration (safety floor 1).
LOCAL_REQUIRED_FROM = "L3"

# Action catalog. `class` decides how the runner may treat a step:
#   passive / notify / reversible_local -> may run automatically
#   destructive                          -> human approval, never automatic
# `rollback` names the compensating action used when a workflow marked
# atomic fails part-way (see wad_cli.py run_plan()).
ACTIONS = {
    "observe": {"class": "passive", "rollback": None},
    "monitor_up": {"class": "reversible_local", "rollback": "monitor_down"},
    "monitor_down": {"class": "reversible_local", "rollback": "monitor_up"},
    "warn": {"class": "notify", "rollback": None},
    "restrict_network": {"class": "destructive", "rollback": "unrestrict_network"},
    "unrestrict_network": {"class": "destructive", "rollback": "restrict_network"},
    "isolate_host": {"class": "destructive", "rollback": "release_host"},
    "release_host": {"class": "destructive", "rollback": "isolate_host"},
}
AUTO_CLASSES = frozenset({"passive", "notify", "reversible_local"})

_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_SOURCE_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_OPERATOR_RE = re.compile(r"^[A-Za-z0-9._@-]{1,64}$")
# Identities that name an automated actor are refused as operators: a
# human gate must not be satisfiable by the automation it gates.
_AUTOMATED_IDENTITY_RE = re.compile(
    r"(claude|anthropic|openai|gpt|llm|\bai\b|^ai[._-]|[._-]ai$|bot|agent|autopilot|wad|"
    r"automation|cron|launchd|daemon|system|root)",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------

def canonical_json(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def parse_utc(text):
    """ISO-8601 'YYYY-MM-DDTHH:MM:SS[.ffffff]Z' (or +00:00) -> aware
    datetime, else None. Naive or non-UTC offsets are refused rather
    than guessed."""
    if not isinstance(text, str) or len(text) > 40:
        return None
    t = text.strip()
    if t.endswith("Z"):
        t = t[:-1] + "+00:00"
    try:
        dt = datetime.datetime.fromisoformat(t)
    except ValueError:
        return None
    if dt.tzinfo is None or dt.utcoffset() != datetime.timedelta(0):
        return None
    return dt


def format_utc(dt):
    return dt.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _has_control_chars(text):
    return any(ord(c) < 32 or ord(c) == 127 for c in text)


def level_index(level):
    return LEVELS.index(level)


def validate_operator(identity, allowlist=None):
    """Presence/shape check for a human operator name. NOT
    authentication -- the result says so (`authenticated: False`).
    Refuses identities that name an automated actor."""
    if not isinstance(identity, str) or not _OPERATOR_RE.match(identity):
        return {"valid": False, "reason": "bad_identity_format", "authenticated": False}
    if _AUTOMATED_IDENTITY_RE.search(identity):
        return {"valid": False, "reason": "automated_identity_refused", "authenticated": False}
    if allowlist is not None and identity not in allowlist:
        return {"valid": False, "reason": "identity_not_in_allowlist", "authenticated": False}
    return {"valid": True, "reason": "shape_ok_not_authenticated", "authenticated": False}


def validate_reason(text, min_len=10):
    if not isinstance(text, str) or _has_control_chars(text):
        return False
    return len(text.strip()) >= min_len and len(text) <= 500


# ---------------------------------------------------------------------
# policy
# ---------------------------------------------------------------------

def validate_policy(policy):
    """Returns a list of error strings; empty means valid. Enforces the
    module header's safety floors on top of shape checks."""
    errors = []
    if not isinstance(policy, dict):
        return ["policy is not an object"]
    if policy.get("schema") != POLICY_SCHEMA:
        errors.append("schema must be %s" % POLICY_SCHEMA)
    if not isinstance(policy.get("policy_id"), str) or not _SOURCE_RE.match(policy.get("policy_id", "")):
        errors.append("policy_id missing or malformed")
    v = policy.get("version")
    if not isinstance(v, int) or isinstance(v, bool) or v < 1:
        errors.append("version must be a positive integer")

    def _pos_int(path, value):
        if not isinstance(value, int) or isinstance(value, bool) or value < 1:
            errors.append("%s must be a positive integer" % path)

    fr = policy.get("freshness") or {}
    _pos_int("freshness.max_event_age_seconds", fr.get("max_event_age_seconds"))
    _pos_int("freshness.max_future_skew_seconds", fr.get("max_future_skew_seconds"))
    _pos_int("dedup_window_seconds", policy.get("dedup_window_seconds"))
    rl = policy.get("rate_limits") or {}
    _pos_int("rate_limits.auto_actions_per_hour", rl.get("auto_actions_per_hour"))
    _pos_int("rate_limits.per_entity_cooldown_seconds", rl.get("per_entity_cooldown_seconds"))
    _pos_int("circuit_breaker.max_consecutive_failures",
             (policy.get("circuit_breaker") or {}).get("max_consecutive_failures"))
    _pos_int("step_timeout_seconds", policy.get("step_timeout_seconds"))
    if isinstance(policy.get("step_timeout_seconds"), int) and policy["step_timeout_seconds"] > 300:
        errors.append("step_timeout_seconds must be <= 300")

    levels = policy.get("levels")
    if not isinstance(levels, dict) or sorted(levels) != LEVELS:
        errors.append("levels must define exactly %s" % ",".join(LEVELS))
        levels = {}
    for name, spec in sorted(levels.items()):
        if not isinstance(spec, dict):
            errors.append("levels.%s is not an object" % name)
            continue
        steps = spec.get("steps")
        if not isinstance(steps, list) or not steps:
            errors.append("levels.%s.steps must be a non-empty list" % name)
            continue
        for s in steps:
            if s not in ACTIONS:
                errors.append("levels.%s: unknown action %r" % (name, s))
        if not isinstance(spec.get("atomic", False), bool):
            errors.append("levels.%s.atomic must be boolean" % name)
        auto = spec.get("auto_actions", [])
        if not isinstance(auto, list):
            errors.append("levels.%s.auto_actions must be a list" % name)
            auto = []
        for a in auto:
            if a not in steps:
                errors.append("levels.%s: auto action %r is not one of its steps" % (name, a))
            elif ACTIONS[a]["class"] not in AUTO_CLASSES:
                # safety floor 2
                errors.append("levels.%s: destructive action %r may never be automatic" % (name, a))
        if level_index(name) < level_index(LOCAL_REQUIRED_FROM):
            for s in steps:
                if s in ACTIONS and ACTIONS[s]["class"] == "destructive":
                    errors.append("levels.%s: destructive action %r below %s" % (name, s, LOCAL_REQUIRED_FROM))

    rules = policy.get("level_rules")
    if not isinstance(rules, list) or not rules:
        errors.append("level_rules must be a non-empty list")
        rules = []
    for i, r in enumerate(rules):
        where = "level_rules[%d]" % i
        if not isinstance(r, dict):
            errors.append("%s is not an object" % where)
            continue
        if r.get("risk") not in RISK_ORDER:
            errors.append("%s.risk invalid" % where)
        if r.get("min_confidence", "LOW") not in CONFIDENCE_ORDER:
            errors.append("%s.min_confidence invalid" % where)
        if "local" in r and not isinstance(r["local"], bool):
            errors.append("%s.local must be boolean" % where)
        if r.get("level") not in LEVELS:
            errors.append("%s.level invalid" % where)
        elif level_index(r["level"]) >= level_index(LOCAL_REQUIRED_FROM) and r.get("local") is not True:
            # safety floor 1
            errors.append("%s: %s requires local: true" % (where, r["level"]))
    return errors


def policy_digest(policy):
    return sha256_hex(canonical_json(policy))


def diff_policies(old, new):
    """Flat path-level diff: [{"path", "old", "new"}], sorted by path.
    Lists are compared as whole values so a reordered step list shows
    up as one change, which is what a reviewer needs to see."""
    out = []

    def walk(a, b, path):
        if isinstance(a, dict) and isinstance(b, dict):
            for k in sorted(set(a) | set(b)):
                p = "%s.%s" % (path, k) if path else k
                if k not in a:
                    out.append({"path": p, "old": None, "new": b[k], "change": "added"})
                elif k not in b:
                    out.append({"path": p, "old": a[k], "new": None, "change": "removed"})
                else:
                    walk(a[k], b[k], p)
        elif a != b:
            out.append({"path": path, "old": a, "new": b, "change": "changed"})

    walk(old, new, "")
    return out


# ---------------------------------------------------------------------
# events
# ---------------------------------------------------------------------

def normalize_event(raw):
    """raw -> (event, errors). Accepts a wad-event/1 sensor event or a
    Decision Engine Decision Record (kind == "decision_record", carrying
    `observed_at` added by the CLI from the report's generated_at).

    Never raises on malformed input. An event with errors is still
    returned (as far as it could be read) so the caller can audit it and
    route it to a human; `errors` non-empty means "incomplete"."""
    errors = []
    if not isinstance(raw, dict):
        return ({"incomplete": True}, ["event is not an object"])

    if raw.get("kind") == "decision_record":
        lc = raw.get("local_corroboration") or {}
        sources = raw.get("source_modules") if isinstance(raw.get("source_modules"), list) else []
        body = {
            "entity": raw.get("entity"),
            "risk": raw.get("risk"),
            "confidence": raw.get("confidence"),
            "sources": sorted(str(s) for s in sources),
            "observed_at": raw.get("observed_at"),
        }
        src = {
            "schema": EVENT_SCHEMA,
            "event_id": "de-" + sha256_hex(canonical_json(body))[:32],
            "source": "decision_engine",
            "entity": raw.get("entity"),
            "entity_type": raw.get("entity_type") or "unknown",
            "observed_at": raw.get("observed_at"),
            "risk": raw.get("risk"),
            "confidence": raw.get("confidence"),
            "local": bool(lc.get("present")) if isinstance(lc, dict) else False,
            "seq": 0,
            "detail": {"source_modules": body["sources"],
                       "decision_engine_action": raw.get("recommended_action")},
        }
    else:
        src = raw
        if src.get("schema") != EVENT_SCHEMA:
            errors.append("schema must be %s" % EVENT_SCHEMA)

    ev = {"schema": EVENT_SCHEMA}

    eid = src.get("event_id")
    if isinstance(eid, str) and _ID_RE.match(eid):
        ev["event_id"] = eid
    else:
        errors.append("event_id missing or malformed")
        ev["event_id"] = None

    source = src.get("source")
    if isinstance(source, str) and _SOURCE_RE.match(source):
        ev["source"] = source
    else:
        errors.append("source missing or malformed")
        ev["source"] = None

    entity = src.get("entity")
    if isinstance(entity, str) and entity.strip() and len(entity) <= 256 and not _has_control_chars(entity):
        ev["entity"] = entity
    else:
        errors.append("entity missing or malformed")
        ev["entity"] = None

    et = src.get("entity_type", "unknown")
    ev["entity_type"] = et if isinstance(et, str) and _SOURCE_RE.match(et) else "unknown"

    obs = parse_utc(src.get("observed_at"))
    if obs is None:
        errors.append("observed_at missing or not UTC ISO-8601")
        ev["observed_at"] = None
    else:
        ev["observed_at"] = format_utc(obs)

    risk = src.get("risk")
    if risk in RISK_ORDER:
        ev["risk"] = risk
    else:
        errors.append("risk missing or unknown")
        ev["risk"] = None

    conf = src.get("confidence")
    if conf in CONFIDENCE_ORDER:
        ev["confidence"] = conf
    else:
        errors.append("confidence missing or unknown")
        ev["confidence"] = None

    local = src.get("local", False)
    if not isinstance(local, bool):
        errors.append("local must be boolean")
        local = False
    ev["local"] = local

    seq = src.get("seq", 0)
    if not isinstance(seq, int) or isinstance(seq, bool) or seq < 0:
        errors.append("seq must be a non-negative integer")
        seq = 0
    ev["seq"] = seq

    detail = src.get("detail", {})
    if not isinstance(detail, dict):
        errors.append("detail must be an object")
        detail = {}
    ev["detail"] = detail
    try:
        if len(canonical_json(detail)) > 8192:
            errors.append("detail larger than 8192 bytes")
            ev["detail"] = {"truncated": True}
    except (TypeError, ValueError):
        errors.append("detail not serializable")
        ev["detail"] = {}

    ev["incomplete"] = bool(errors)
    ev["digest"] = sha256_hex(canonical_json({k: v for k, v in ev.items() if k != "digest"}))
    return ev, errors


def dedup_key(event):
    """Identity of an event for duplicate/replay detection. None when
    the event has no usable identity (it cannot be deduplicated, so the
    runner treats it as new but incomplete)."""
    if not event.get("event_id") or not event.get("source"):
        return None
    return sha256_hex("%s|%s" % (event["source"], event["event_id"]))


def check_freshness(event, now, policy):
    """-> None if acceptable, else a reason string. Applies to complete
    events only; an incomplete event has no trustworthy time."""
    obs = parse_utc(event.get("observed_at"))
    if obs is None:
        return None
    fr = policy["freshness"]
    age = (now - obs).total_seconds()
    if age > fr["max_event_age_seconds"]:
        return "stale: %ds old > %ds" % (int(age), fr["max_event_age_seconds"])
    if -age > fr["max_future_skew_seconds"]:
        return "future: %ds ahead > %ds" % (int(-age), fr["max_future_skew_seconds"])
    return None


def sort_events(events):
    """Order a batch by (observed_at, seq, event_id); events without a
    time go last so a garbage line cannot jump ahead of real ones."""
    def key(e):
        return (e.get("observed_at") is None, e.get("observed_at") or "", e.get("seq") or 0, e.get("event_id") or "")
    return sorted(events, key=key)


# ---------------------------------------------------------------------
# assessment and planning
# ---------------------------------------------------------------------

def assess(event, errors, policy):
    """-> assessment dict: level, reasons, confidence, uncertain."""
    reasons = []
    if errors:
        reasons.append("incomplete event: " + "; ".join(errors))
        # Safety floor 3: never silently drop and never act on it -- a
        # human sees it (L2), nothing destructive is planned.
        return {
            "level": UNCERTAIN_CAP,
            "rule": None,
            "confidence": event.get("confidence") or "UNKNOWN",
            "uncertain": True,
            "reasons": reasons + ["capped at %s pending human review" % UNCERTAIN_CAP],
        }

    risk, conf, local = event["risk"], event["confidence"], event["local"]
    level, matched = "L0", None
    for i, r in enumerate(policy["level_rules"]):
        if r["risk"] != risk:
            continue
        if CONFIDENCE_ORDER.index(conf) < CONFIDENCE_ORDER.index(r.get("min_confidence", "LOW")):
            continue
        if "local" in r and r["local"] != local:
            continue
        level, matched = r["level"], i
        break
    reasons.append("risk=%s confidence=%s local=%s -> %s (%s)" % (
        risk, conf, local, level, "level_rules[%d]" % matched if matched is not None else "no rule matched"))

    uncertain = False
    # Defense in depth for floors 1 and 3 (validate_policy already
    # refuses a policy that would break floor 1).
    if level_index(level) >= level_index(LOCAL_REQUIRED_FROM) and not local:
        reasons.append("capped at %s: no trusted local corroboration" % UNCERTAIN_CAP)
        level, uncertain = UNCERTAIN_CAP, True
    if conf == "LOW" and level_index(level) > level_index(UNCERTAIN_CAP):
        reasons.append("capped at %s: LOW confidence" % UNCERTAIN_CAP)
        level, uncertain = UNCERTAIN_CAP, True
    return {"level": level, "rule": matched, "confidence": conf, "uncertain": uncertain, "reasons": reasons}


def plan_for(level, policy):
    """-> list of step dicts for a level. mode is one of
    auto | pending_approval. Destructive steps are always
    pending_approval regardless of what the policy says."""
    spec = policy["levels"][level]
    auto = set(spec.get("auto_actions", []))
    steps = []
    for i, action in enumerate(spec["steps"]):
        cls = ACTIONS[action]["class"]
        mode = "auto" if (action in auto and cls in AUTO_CLASSES) else "pending_approval"
        steps.append({"index": i, "action": action, "class": cls, "mode": mode,
                      "rollback": ACTIONS[action]["rollback"]})
    return {"level": level, "atomic": bool(spec.get("atomic", False)), "steps": steps}


def recovery_plan(active_level, policy):
    """Compensating plan for an entity currently at active_level: the
    rollback of every rollback-able step of that level, in reverse
    order. Recovery is always operator-initiated; destructive releases
    stay pending_approval."""
    base = plan_for(active_level, policy)
    steps = []
    for s in reversed(base["steps"]):
        rb = s["rollback"]
        if not rb:
            continue
        cls = ACTIONS[rb]["class"]
        steps.append({"index": len(steps), "action": rb, "class": cls,
                      "mode": "auto" if cls in AUTO_CLASSES else "pending_approval",
                      "rollback": ACTIONS[rb]["rollback"]})
    return {"level": "recover:" + active_level, "atomic": False, "steps": steps}


def higher_level(a, b):
    return a if level_index(a) >= level_index(b) else b


def copy_policy(policy):
    return copy.deepcopy(policy)
