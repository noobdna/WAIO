"""security/wad/wad_lib.py -- WAIO Adaptive Defense (WAD) core: event
normalization, idempotency/replay screening, threat-level assessment,
versioned defense policy, and dry-run response planning.

Position in the pipeline:

    detector events (JSON) -> WAD ingest (this file: validate, dedupe,
    replay/clock screening) -> Intelligence Layer records/profiles
    (intelligence_lib.aggregate_by_entity, reused unchanged) -> Decision
    Engine (decision_engine_lib.decide_for_profile, reused unchanged,
    including its local-corroboration cap) -> WAD threat level -> WAD
    policy -> response PLAN (dry run) -> WAD ledger (security/wad/wad.py)

SAFETY BOUNDARY: this module PLANS, IT NEVER EXECUTES. There is no
execute mode. Every step in a plan is one of DRY_RUN_PLANNED,
AWAITING_APPROVAL, SUPPRESSED_RATE_LIMIT or HALTED_KILLSWITCH; nothing
here calls guardian.sh, ducopa.sh, the containment runner, a firewall,
or any network tool. tests/wad_engine_test.sh's S-series keeps this true
in code.

Scoring is NOT reimplemented here: risk/confidence -> recommended action
is the Decision Engine's own stated table. WAD adds what that stage does
not have: event-level hygiene (schema, duplicates, conflicting replays,
stale/future timestamps), a fail-safe for missing information
(UNDETERMINED: a human looks, nothing disruptive is ever planned), a
versioned policy with hard invariants and a diff, and runaway limits.

Order independence: events are sorted canonically before aggregation, so
the same set of events always yields the same assessment regardless of
arrival order (aggregate_by_entity takes entity_type from the first
record it sees).

No I/O in this module; the clock is always passed in.
"""

import datetime
import hashlib
import json
import os
import re
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "..", "intelligence"))
sys.path.insert(0, os.path.join(_HERE, "..", "decision_engine"))
import intelligence_lib as il  # noqa: E402
import decision_engine_lib as de  # noqa: E402

RISKS = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
CONFIDENCES = ("LOW", "MEDIUM", "HIGH")

# Threat levels, least to most severe. UNDETERMINED sits with L2 for
# visibility (a human must look) but may never carry a disruptive action.
LEVELS = ("L0", "L1", "L2", "L3", "L4")
UNDETERMINED = "UNDETERMINED"
ALL_LEVELS = LEVELS + (UNDETERMINED,)
LEVEL_NAMES = {
    "L0": "NORMAL",
    "L1": "ELEVATED",
    "L2": "HIGH",
    "L3": "SEVERE",
    "L4": "CRITICAL",
    UNDETERMINED: "UNDETERMINED (insufficient information)",
}
_LEVEL_RANK = {"L0": 0, "L1": 1, UNDETERMINED: 2, "L2": 2, "L3": 3, "L4": 4}

# Action catalogue. The CLASS of each action is fixed here in code, not
# taken from the policy file: a policy cannot reclassify isolate_agent as
# "observe" to dodge the approval requirement.
ACTION_CLASSES = {
    "monitor_increase": "observe",
    "warn_operator": "notify",
    "restrict_egress": "disruptive",
    "isolate_agent": "disruptive",
    "recover": "disruptive",
}
DISRUPTIVE = frozenset(a for a, c in ACTION_CLASSES.items() if c == "disruptive")
# Levels that may never carry a disruptive action, whatever the policy says.
NON_DISRUPTIVE_LEVELS = frozenset({"L0", "L1", UNDETERMINED})

HARD_LIMITS = {
    "max_disruptive_per_hour": (0, 20),
    "replay_window_s": (60, 7 * 86400),
    "clock_skew_s": (0, 900),
    "max_events_per_run": (1, 100000),
}

STEP_PLANNED = "DRY_RUN_PLANNED"
STEP_AWAITING = "AWAITING_APPROVAL"
STEP_SUPPRESSED = "SUPPRESSED_RATE_LIMIT"
STEP_HALTED = "HALTED_KILLSWITCH"

_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_MODULE_RE = re.compile(r"^[a-z0-9_]{1,64}$")
_ETYPE_RE = re.compile(r"^[a-z_]{1,32}$")
_POLICY_ID_RE = re.compile(r"^[a-z0-9-]{1,64}$")
_MAX_ENTITY = 256
_MAX_SUMMARY = 1024
_MAX_CATEGORY = 64


class PolicyError(Exception):
    pass


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_hex(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def parse_ts(value):
    """Strict ISO-8601 with an explicit timezone -> aware datetime, or None.
    A naive timestamp is refused (None): guessing its zone could move an
    event across the replay window."""
    if not isinstance(value, str) or not value or len(value) > 40:
        return None
    try:
        dt = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        return None
    return dt.astimezone(datetime.timezone.utc)


def _clean_text(value, limit):
    return isinstance(value, str) and 0 < len(value) <= limit and value.isprintable()


# ---------------------------------------------------------------- events

def normalize_event(raw, now, limits):
    """raw (decoded JSON) -> (event, None) or (None, [reason codes]).

    Missing risk/confidence/observed_at is NOT an error: the event is kept
    with insufficient=True so a human sees it, but it never drives a
    disruptive plan. A value that is present but wrong (bad enum, wrong
    type, bad pattern, control characters, a timestamp outside the replay
    window or in the future) IS an error: the event is rejected and the
    rejection is audited.
    """
    if not isinstance(raw, dict):
        return None, ["not_an_object"]
    errors = []
    event_id = raw.get("event_id")
    if not (isinstance(event_id, str) and _ID_RE.match(event_id)):
        errors.append("bad_event_id")
    source = raw.get("source_module")
    if not (isinstance(source, str) and _MODULE_RE.match(source)):
        errors.append("bad_source_module")
    entity = raw.get("entity")
    if not _clean_text(entity, _MAX_ENTITY):
        errors.append("bad_entity")
    etype = raw.get("entity_type")
    if not (isinstance(etype, str) and _ETYPE_RE.match(etype)):
        errors.append("bad_entity_type")
    category = raw.get("category", "")
    if category not in ("", None) and not _clean_text(category, _MAX_CATEGORY):
        errors.append("bad_category")
    summary = raw.get("summary", "")
    if summary not in ("", None) and not _clean_text(summary, _MAX_SUMMARY):
        errors.append("bad_summary")

    missing = []
    risk = raw.get("risk")
    if risk is None:
        missing.append("risk")
    elif risk not in RISKS:
        errors.append("bad_risk")
    confidence = raw.get("confidence")
    if confidence is None:
        missing.append("confidence")
    elif confidence not in CONFIDENCES:
        errors.append("bad_confidence")

    observed = raw.get("observed_at")
    observed_dt = None
    if observed is None:
        missing.append("observed_at")
    else:
        observed_dt = parse_ts(observed)
        if observed_dt is None:
            errors.append("bad_observed_at")
        else:
            age = (now - observed_dt).total_seconds()
            if age < -limits["clock_skew_s"]:
                errors.append("observed_in_future")
            elif age > limits["replay_window_s"]:
                errors.append("outside_replay_window")

    if errors:
        return None, errors

    content = {
        "event_id": event_id,
        "source_module": source,
        "entity": entity,
        "entity_type": etype,
        "category": category or "",
        "risk": risk,
        "confidence": confidence,
        "observed_at": observed_dt.strftime("%Y-%m-%dT%H:%M:%SZ") if observed_dt else None,
        "summary": summary or "",
    }
    content["key"] = sha256_hex(source + "\x00" + event_id)
    content["digest"] = sha256_hex(canonical({k: v for k, v in content.items() if k != "key"}))
    content["insufficient"] = sorted(missing)
    # Provenance is attached by wad.py `ingest` in-process (wad_adapters);
    # wad.py strips it from --events files, so a file cannot claim it. It is
    # kept out of the digest: the same finding re-read from a newer scan
    # file is still the same event.
    if isinstance(raw.get("_provenance"), dict):
        content["provenance"] = raw["_provenance"]
    return content, None


def screen_events(raw_events, seen, now, limits):
    """Splits a batch into accepted / duplicate / conflict / rejected.

    seen: {key: digest} of events already decided (from the ledger).
    - same key + same digest as seen, or as earlier in this batch -> duplicate
      (a no-op, audited once per run).
    - same key + DIFFERENT digest -> conflict: never accepted, flagged for a
      human (an altered replay, or a buggy producer reusing ids).
    """
    accepted, duplicates, conflicts, rejected = [], [], [], []
    batch = {}
    for index, raw in enumerate(raw_events):
        event, errors = normalize_event(raw, now, limits)
        if errors:
            ref = raw.get("event_id") if isinstance(raw, dict) else None
            rejected.append({"index": index, "event_id": ref if isinstance(ref, str) else None,
                             "reasons": errors})
            continue
        key, digest = event["key"], event["digest"]
        prior = seen.get(key, batch.get(key))
        if prior is None:
            batch[key] = digest
            accepted.append(event)
        elif prior == digest:
            duplicates.append({"event_id": event["event_id"], "key": key})
        else:
            conflicts.append({"event_id": event["event_id"], "key": key,
                              "entity": event["entity"]})
    # A key that conflicts within this batch taints the accepted copy too:
    # we cannot tell which of the two versions is genuine.
    conflict_keys = {c["key"] for c in conflicts}
    if conflict_keys:
        for event in [e for e in accepted if e["key"] in conflict_keys]:
            accepted.remove(event)
            conflicts.append({"event_id": event["event_id"], "key": event["key"],
                              "entity": event["entity"]})
    accepted.sort(key=lambda e: (e["observed_at"] or "", e["source_module"], e["event_id"]))
    return {"accepted": accepted, "duplicates": duplicates,
            "conflicts": conflicts, "rejected": rejected}


# ---------------------------------------------------------------- assessment

def to_record(event):
    """WAD event -> Intelligence Layer record shape (intelligence_lib's
    adapter contract)."""
    return {
        "id": "wad:" + event["key"][:16],
        "source_module": event["source_module"],
        "source_finding_id": event["event_id"],
        "entity": event["entity"],
        "entity_type": event["entity_type"],
        "category": event["category"],
        "risk": event["risk"],
        "confidence": event["confidence"],
        "detected_at": event["observed_at"],
        "summary": event["summary"],
        "raw": {},
    }


def level_for_decision(decision):
    action = decision["recommended_action"]
    if action == "RECOMMEND_CONTAINMENT":
        return "L4" if decision["risk"] == "CRITICAL" else "L3"
    return {"NO_ACTION": "L0", "MONITOR": "L1", "ALERT_HUMAN": "L2"}.get(action, UNDETERMINED)


def assess(events, conflicts, now):
    """accepted events (+ conflicts) -> one assessment per entity, sorted.

    Only events with full information feed the Decision Engine. An entity
    with insufficient or conflicting evidence and a computed level below
    L2 is raised to UNDETERMINED (never silently treated as normal); at
    L2+ the computed level stands and the gap is recorded as a reason.
    """
    complete = [e for e in events if not e["insufficient"]]
    profiles = il.aggregate_by_entity([to_record(e) for e in complete])
    gaps = {}
    for e in events:
        if e["insufficient"]:
            gaps.setdefault(e["entity"], []).append(
                f"event {e['event_id']} from {e['source_module']} lacks {','.join(e['insufficient'])}")
    for c in conflicts:
        gaps.setdefault(c["entity"], []).append(
            f"event {c['event_id']} reused an id with different content (conflict)")
    entity_events = {}
    for e in events:
        entity_events.setdefault(e["entity"], []).append(e)

    out = []
    for entity in sorted(set(profiles) | set(gaps)):
        reasons = []
        if entity in profiles:
            decision = de.decide_for_profile(profiles[entity], now=now)
            level = level_for_decision(decision)
            reasons.append("decision_engine: " + decision["reasoning"])
            risk, confidence = decision["risk"], decision["confidence"]
            local = decision["local_corroboration"]
            capped = decision["capped_from_recommend_containment"]
            sources = decision["source_modules"]
        else:
            decision, level = None, UNDETERMINED
            risk, confidence, local, capped, sources = None, None, {"present": False, "modules": []}, False, []
        if entity in gaps:
            reasons.extend(gaps[entity])
            if _LEVEL_RANK[level] < _LEVEL_RANK["L2"]:
                reasons.append(f"computed level {level} raised to UNDETERMINED: information is incomplete")
                level = UNDETERMINED
            else:
                reasons.append(f"level {level} stands on complete evidence; incomplete evidence noted")
        types = sorted({e["entity_type"] for e in entity_events.get(entity, [])})
        if len(types) > 1:
            reasons.append(f"entity reported with differing entity_type {types}")
        out.append({
            "entity": entity,
            "entity_type": decision["entity_type"] if decision else (types[0] if types else None),
            "threat_level": level,
            "threat_level_name": LEVEL_NAMES[level],
            "risk": risk,
            "confidence": confidence,
            "source_modules": sources,
            "local_corroboration": local,
            "capped_from_recommend_containment": capped,
            "event_ids": sorted(e["event_id"] for e in entity_events.get(entity, [])),
            "event_keys": sorted(e["key"] for e in entity_events.get(entity, [])),
            "reasons": reasons,
        })
    out.sort(key=lambda a: (-_LEVEL_RANK[a["threat_level"]], a["entity"]))
    return out


# ---------------------------------------------------------------- policy

def validate_policy(policy):
    """Returns the policy unchanged, or raises PolicyError naming every
    violated invariant. Invariants are enforced in code, not trusted from
    the file:
      - every disruptive action requires approval;
      - action names and classes come from ACTION_CLASSES only;
      - L0, L1 and UNDETERMINED carry no disruptive action;
      - L0 <= L1 <= L2 <= L3 <= L4 (a higher level never does less);
      - limits inside HARD_LIMITS.
    """
    errs = []
    if not isinstance(policy, dict):
        raise PolicyError("policy must be a JSON object")
    if not (isinstance(policy.get("policy_id"), str) and _POLICY_ID_RE.match(policy["policy_id"])):
        errs.append("policy_id missing or malformed")
    version = policy.get("version")
    if not (isinstance(version, int) and not isinstance(version, bool) and version >= 1):
        errs.append("version must be an integer >= 1")
    actions = policy.get("actions")
    if not isinstance(actions, dict):
        errs.append("actions must be an object")
        actions = {}
    for name, spec in actions.items():
        if name not in ACTION_CLASSES:
            errs.append(f"unknown action {name!r}")
            continue
        if not isinstance(spec, dict):
            errs.append(f"action {name} must be an object")
            continue
        if spec.get("class") != ACTION_CLASSES[name]:
            errs.append(f"action {name} class must be {ACTION_CLASSES[name]!r}")
        if not isinstance(spec.get("requires_approval"), bool):
            errs.append(f"action {name} requires_approval must be true/false")
        elif name in DISRUPTIVE and not spec["requires_approval"]:
            errs.append(f"disruptive action {name} must require approval")
    levels = policy.get("levels")
    if not isinstance(levels, dict) or set(levels) != set(ALL_LEVELS):
        errs.append(f"levels must define exactly {list(ALL_LEVELS)}")
        levels = {}
    for level, resp in levels.items():
        if not (isinstance(resp, list) and all(isinstance(a, str) for a in resp)) or len(set(resp)) != len(resp):
            errs.append(f"level {level} must be a list of distinct action names")
            continue
        for a in resp:
            if a not in actions:
                errs.append(f"level {level} uses undefined action {a!r}")
            if level in NON_DISRUPTIVE_LEVELS and a in DISRUPTIVE:
                errs.append(f"level {level} may not carry disruptive action {a}")
    if not errs:
        for lower, higher in zip(LEVELS, LEVELS[1:]):
            missing = set(levels[lower]) - set(levels[higher])
            if missing:
                errs.append(f"level {higher} drops {sorted(missing)} present at {lower}")
    limits = policy.get("limits")
    if not isinstance(limits, dict) or set(limits) != set(HARD_LIMITS):
        errs.append(f"limits must define exactly {sorted(HARD_LIMITS)}")
    else:
        for k, (lo, hi) in HARD_LIMITS.items():
            v = limits[k]
            if not (isinstance(v, int) and not isinstance(v, bool) and lo <= v <= hi):
                errs.append(f"limit {k} must be an integer in [{lo}, {hi}]")
    if errs:
        raise PolicyError("; ".join(errs))
    return policy


def policy_digest(policy):
    return sha256_hex(canonical(policy))


def policy_ref(policy):
    return {"policy_id": policy["policy_id"], "version": policy["version"],
            "digest": policy_digest(policy)}


def diff_policies(old, new):
    """Structured comparison of two VALID policies. `loosening` lists every
    change that makes the policy respond less (an action removed from a
    level, a higher rate limit, a wider replay window or clock skew); a
    human reviewing a policy change reads that list first."""
    changes, loosening = [], []
    if old["version"] == new["version"] and policy_digest(old) != policy_digest(new):
        changes.append("content changed without a version bump")
        loosening.append("content changed without a version bump")
    if new["version"] < old["version"]:
        loosening.append(f"version goes backwards {old['version']} -> {new['version']}")
    for level in ALL_LEVELS:
        before, after = set(old["levels"][level]), set(new["levels"][level])
        for a in sorted(after - before):
            changes.append(f"{level}: + {a}")
        for a in sorted(before - after):
            changes.append(f"{level}: - {a}")
            loosening.append(f"{level} no longer does {a}")
    for name in sorted(set(old["actions"]) | set(new["actions"])):
        o, n = old["actions"].get(name), new["actions"].get(name)
        if o != n:
            changes.append(f"action {name}: {o} -> {n}")
            if o and n and o.get("requires_approval") and not n.get("requires_approval"):
                loosening.append(f"action {name} no longer requires approval")
    for k in sorted(HARD_LIMITS):
        o, n = old["limits"][k], new["limits"][k]
        if o != n:
            changes.append(f"limit {k}: {o} -> {n}")
            if (k == "max_disruptive_per_hour" and n > o) or (k in ("replay_window_s", "clock_skew_s") and n > o) \
                    or (k == "max_events_per_run" and n > o):
                loosening.append(f"limit {k} raised {o} -> {n}")
    return {"from": policy_ref(old), "to": policy_ref(new),
            "identical": policy_digest(old) == policy_digest(new),
            "changes": changes, "loosening": loosening}


# ---------------------------------------------------------------- planning

def plan_responses(assessments, policy, disruptive_last_hour, killswitch_active):
    """assessments -> one plan per assessment. Nothing here executes.

    disruptive_last_hour: disruptive steps already planned (not suppressed)
    in the trailing hour, from the ledger. Past the policy limit, further
    disruptive steps are SUPPRESSED and the plan says so; observe/notify
    steps still go ahead so a human hears about it.
    killswitch_active: every step is HALTED_KILLSWITCH; the assessment is
    still recorded.
    """
    budget = policy["limits"]["max_disruptive_per_hour"] - disruptive_last_hour
    plans = []
    for a in assessments:
        steps, notes = [], []
        for action in policy["levels"][a["threat_level"]]:
            spec = policy["actions"][action]
            if killswitch_active:
                status = STEP_HALTED
            elif action in DISRUPTIVE:
                if budget <= 0:
                    status = STEP_SUPPRESSED
                    notes.append(f"{action} suppressed: disruptive limit "
                                 f"{policy['limits']['max_disruptive_per_hour']}/h reached")
                else:
                    budget -= 1
                    status = STEP_AWAITING
            else:
                status = STEP_AWAITING if spec["requires_approval"] else STEP_PLANNED
            steps.append({"action": action, "class": ACTION_CLASSES[action],
                          "requires_approval": bool(spec["requires_approval"] or action in DISRUPTIVE),
                          "mode": "dry_run", "status": status})
        if killswitch_active:
            notes.append("kill switch active: no step may proceed")
        plans.append({"entity": a["entity"], "threat_level": a["threat_level"],
                      "steps": steps, "notes": notes})
    return plans


def count_disruptive(plan):
    return sum(1 for s in plan["steps"] if s["class"] == "disruptive" and s["status"] == STEP_AWAITING)
