"""security/wad/wad_response.py -- WAD controlled response workflow (PR 2).

Pure functions only: nothing here reads files, writes files or executes
anything. wad.py replays the ledger through these functions and appends the
resulting records under its lock.

STEP STATE MACHINE. Every step of a wad_decision plan starts in the state
its planning status implies and moves only along these edges:

    awaiting_approval --approve--> approved
    awaiting_approval --reject---> rejected                (terminal)
    planned           --start----> executing
    approved          --start----> executing
    executing         --complete-> done
    executing         --fail-----> failed
    done | failed     --rollback-> rolled_back             (terminal)

suppressed (rate limit) and halted (kill switch) steps are terminal from the
start. Any other (state, action) pair is refused. The step's current state
is always recomputed from the ledger, so a refused or duplicate request can
never move it.

DRY RUN ONLY. "Executing" a step calls dry_run_execute(), which returns a
description of what would have been done and does nothing. There is no live
mode and no executor binding; binding isolate_agent to the containment
runner is PR 4 and needs PRs #209/#211 merged first.

APPROVAL IS NOT AUTHENTICATION. Approvals reuse
security/red_alert/containment_approval_lib (identity allowlist, reason
strength, expiry). Its validate_approver_identity() always returns
authenticated=False: the identity is a name the caller typed, checked
against an allowlist, not proven. Every approval record says so.
"""

import hashlib
import json
import os
import re
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "..", "red_alert"))
import containment_approval_lib as cal  # noqa: E402

AWAITING, PLANNED, APPROVED, REJECTED = "awaiting_approval", "planned", "approved", "rejected"
EXECUTING, DONE, FAILED, ROLLED_BACK = "executing", "done", "failed", "rolled_back"
SUPPRESSED, HALTED = "suppressed", "halted"

# PR 1 planning status -> initial workflow state.
INITIAL_STATE = {
    "AWAITING_APPROVAL": AWAITING,
    "DRY_RUN_PLANNED": PLANNED,
    "SUPPRESSED_RATE_LIMIT": SUPPRESSED,
    "HALTED_KILLSWITCH": HALTED,
}

TRANSITIONS = {
    (AWAITING, "approve"): APPROVED,
    (AWAITING, "reject"): REJECTED,
    (PLANNED, "start"): EXECUTING,
    (APPROVED, "start"): EXECUTING,
    (EXECUTING, "complete"): DONE,
    (EXECUTING, "fail"): FAILED,
    (DONE, "rollback"): ROLLED_BACK,
    (FAILED, "rollback"): ROLLED_BACK,
}
TERMINAL = frozenset({REJECTED, ROLLED_BACK, SUPPRESSED, HALTED})

# Compensating action for rollback. None = not reversible (refused).
COMPENSATION = {
    "monitor_increase": "monitor_restore",
    "warn_operator": None,
    "restrict_egress": "release_egress",
    "isolate_agent": "release_isolation",
    "recover": None,
}

# Identities that are never accepted as a human approver, even if someone
# put them on the allowlist: automated or service accounts. wad.py also
# passes `reserved`, the names of WAIO components under security/, which
# are refused the same way.
_AUTOMATED_RE = re.compile(r"^(wad|waio|system|root|daemon|cron|launchd|automation|autopilot"
                           r"|takomachi|claude.*|.*[-_]bot|bot)$", re.IGNORECASE)
_STEP_ID_RE = re.compile(r"^[0-9a-f]{16}$")


def next_state(state, action):
    """The state `action` moves `state` to, or None if the edge does not exist."""
    return TRANSITIONS.get((state, action))


def step_id(run_id, entity, index, action):
    text = json.dumps([run_id, entity, index, action], separators=(",", ":"))
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def valid_step_id(value):
    return isinstance(value, str) and bool(_STEP_ID_RE.match(value))


# Source modules whose output is computed from another module's findings, so
# their agreement is not independent corroboration.
DERIVED_SOURCE = {"attack_graph": "shadow_ai_monitor"}


def evidence_provenance(events):
    """Accepted WAD events behind one decision -> a summary of how much of the
    evidence is signature-verified, how its time is known, and which source
    modules are independent. Visibility only: nothing here changes a level,
    a plan or a gate."""
    sig, ts = {}, {}
    no_detection_time = 0
    for e in events:
        p = e.get("provenance")
        if p is None:
            status, tsrc = "no_provenance_direct_events_file", "unknown"
        else:
            status, tsrc = p.get("signature_status", "unknown"), p.get("timestamp_source", "unknown")
            if p.get("detection_time_known") is False:
                no_detection_time += 1
        sig[status] = sig.get(status, 0) + 1
        ts[tsrc] = ts.get(tsrc, 0) + 1
    modules = sorted({e.get("source_module") for e in events if e.get("source_module")})
    independent = [m for m in modules if DERIVED_SOURCE.get(m) not in modules]
    notes = []
    for m in modules:
        if DERIVED_SOURCE.get(m) in modules:
            notes.append(f"{m} is derived from {DERIVED_SOURCE[m]} findings: not independent corroboration")
    verified = sig.get("verified", 0)
    if events and verified == 0:
        notes.append("no supporting event is signature-verified")
    if no_detection_time:
        notes.append(f"{no_detection_time} event(s) carry a scan time, not a detection time")
    return {"events": len(events), "source_modules": modules, "independent_source_modules": independent,
            "signature_status": sig, "all_verified": bool(events) and verified == len(events),
            "timestamp_source": ts, "detection_time_unknown": no_detection_time, "notes": notes}


def decision_digest(decision):
    """sha256 over the decision record minus its chain field, so an approval
    is bound to the exact plan it approved."""
    body = {k: v for k, v in decision.items() if k not in ("prev_hash", "mac")}
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def replay_steps(entries):
    """Ledger entries (oldest first) -> {step_id: step}. A step carries its
    decision context, current state and transition history. Transition
    records that do not fit the machine are ignored here; wad.py never
    writes them, and the chain makes inserting them detectable."""
    steps = {}
    for e in entries:
        et = e.get("event_type")
        if et == "wad_decision":
            plan = e.get("plan") or {}
            for i, s in enumerate(plan.get("steps") or []):
                sid = step_id(e.get("run_id"), e.get("entity"), i, s.get("action"))
                steps[sid] = {
                    "step_id": sid, "run_id": e.get("run_id"), "entity": e.get("entity"),
                    "index": i, "action": s.get("action"), "class": s.get("class"),
                    "requires_approval": bool(s.get("requires_approval")),
                    "decided_at": e.get("timestamp"), "decision_digest": decision_digest(e),
                    "state": INITIAL_STATE.get(s.get("status"), HALTED),
                    "approved_at": None, "history": [],
                }
        elif et == "wad_step_transition":
            st = steps.get(e.get("step_id"))
            if st is None or st["state"] != e.get("from") or next_state(e.get("from"), e.get("action")) != e.get("to"):
                continue
            st["state"] = e.get("to")
            st["history"].append({"action": e.get("action"), "to": e.get("to"), "at": e.get("timestamp")})
            if e.get("to") == APPROVED:
                st["approved_at"] = e.get("timestamp")
            if e.get("to") == DONE:
                st["done_at"] = e.get("timestamp")
    return steps


def check_operator(identity, allowlist, reserved=()):
    """-> (ok, reason, identity_check). allowlist None means none configured:
    refused (fail closed). Automated identities and `reserved` component
    names are refused even when allowlisted. Never claims authentication."""
    if allowlist is None:
        return False, "no_approver_allowlist_configured", {"valid": False, "authenticated": False}
    ic = cal.validate_approver_identity(identity, allowlist=allowlist)
    if not ic["valid"]:
        return False, ic["reason"], ic
    name = identity.strip()
    if _AUTOMATED_RE.match(name) or name.lower() in {r.lower() for r in reserved}:
        return False, "automated_identity_refused", dict(ic, valid=False)
    return True, ic["reason"], ic


# ------------------------------------------------- optional evidence policy
# OFF unless an approval policy file exists (wad.py: WAD_APPROVAL_POLICY,
# default $WAD_STATE_DIR/approval_policy.json). When present it can require,
# for DISRUPTIVE steps only, that the decision's evidence is all
# signature-verified and/or comes from at least N independent source
# modules (wad_response.evidence_provenance). It is an extra gate on top of
# every other approval check, never a replacement; it says nothing about
# who the approver is. A present but invalid policy refuses every approval.
POLICY_OFF = {"mode": "off"}
_POLICY_KEYS = {"version", "disruptive_requires"}
_RULE_KEYS = {"all_verified", "min_independent_sources"}


def parse_approval_policy(obj):
    """Decoded JSON -> {"mode": "on", "all_verified": bool,
    "min_independent_sources": int} or {"mode": "invalid", "error": str}.
    Strict: unknown keys, wrong types or out-of-range values are invalid,
    and so is a policy that requires nothing (it would look on while
    enforcing nothing)."""
    if not isinstance(obj, dict) or set(obj) - _POLICY_KEYS or obj.get("version") != 1:
        return {"mode": "invalid", "error": "expected {version: 1, disruptive_requires: {...}}, no other keys"}
    rules = obj.get("disruptive_requires")
    if not isinstance(rules, dict) or not rules or set(rules) - _RULE_KEYS:
        return {"mode": "invalid", "error": "disruptive_requires must use only all_verified / min_independent_sources"}
    av = rules.get("all_verified", False)
    mn = rules.get("min_independent_sources", 1)
    if not isinstance(av, bool):
        return {"mode": "invalid", "error": "all_verified must be true or false"}
    if isinstance(mn, bool) or not isinstance(mn, int) or not 1 <= mn <= 5:
        return {"mode": "invalid", "error": "min_independent_sources must be an integer 1..5"}
    if not av and mn == 1:
        return {"mode": "invalid", "error": "policy requires nothing; remove the file to turn it off"}
    return {"mode": "on", "all_verified": av, "min_independent_sources": mn}


def check_evidence_policy(step, evidence, policy):
    """-> violations. Only disruptive steps are subject to it."""
    mode = (policy or POLICY_OFF).get("mode")
    if mode == "off" or step.get("class") != "disruptive":
        return []
    if mode != "on":
        return ["approval_policy_invalid:" + str(policy.get("error", "unknown"))]
    if not isinstance(evidence, dict):
        return ["evidence_unknown:decision has no evidence_provenance"]
    v = []
    if policy["all_verified"] and not evidence.get("all_verified"):
        v.append("evidence_not_all_verified")
    n = len(evidence.get("independent_source_modules") or [])
    if n < policy["min_independent_sources"]:
        v.append(f"independent_sources_below_min:{n}<{policy['min_independent_sources']}")
    return v


def check_approval(step, identity, reason, allowlist, now, killswitch, ttl_s, current_digest, reserved=(),
                   evidence=None, evidence_policy=None):
    """Every gate for approving `step`; all run, none short-circuit.
    -> {"allowed": bool, "violations": [...], "authenticated": False}"""
    v = check_evidence_policy(step, evidence, evidence_policy)
    if next_state(step["state"], "approve") is None:
        v.append(f"illegal_transition:{step['state']}->approve")
    ok, why, _ = check_operator(identity, allowlist, reserved)
    if not ok:
        v.append(why)
    rc = cal.validate_reason(reason)
    if rc["status"] != "OK":
        v.append(f"reason_{rc['status'].lower()}")
    decided = cal.parse_utc_timestamp(step.get("decided_at"))
    if cal.is_expired(cal.compute_expiry(decided, ttl_s), now):
        v.append("approval_window_expired")
    if killswitch:
        v.append("killswitch_active")
    if current_digest != step["decision_digest"]:
        v.append("decision_altered")
    return {"allowed": not v, "violations": v, "authenticated": False}


def check_start(step, now, killswitch, ttl_s, breaker_open=False):
    v = []
    if next_state(step["state"], "start") is None:
        v.append(f"illegal_transition:{step['state']}->start")
    if killswitch:
        v.append("killswitch_active")
    if breaker_open:
        v.append("breaker_open")
    if step["state"] == APPROVED:
        approved = cal.parse_utc_timestamp(step.get("approved_at"))
        if cal.is_expired(cal.compute_expiry(approved, ttl_s), now):
            v.append("approval_expired_before_start")
    return {"allowed": not v, "violations": v}


def check_rollback(step, identity, reason, allowlist, killswitch, reserved=()):
    v = []
    if next_state(step["state"], "rollback") is None:
        v.append(f"illegal_transition:{step['state']}->rollback")
    if COMPENSATION.get(step["action"]) is None:
        v.append(f"no_compensating_action:{step['action']}")
    ok, why, _ = check_operator(identity, allowlist, reserved)
    if not ok:
        v.append(why)
    rc = cal.validate_reason(reason)
    if rc["status"] != "OK":
        v.append(f"reason_{rc['status'].lower()}")
    if killswitch:
        v.append("killswitch_active")      # a rollback releases a restriction: loosening
    return {"allowed": not v, "violations": v, "authenticated": False}


BREAKER_MAX_CONSECUTIVE_FAILURES = 3


def breaker_state(entries, threshold=BREAKER_MAX_CONSECUTIVE_FAILURES):
    """Circuit breaker derived from the ledger (no separate state file).
    Consecutive `failed` outcomes are counted per step action; a `done` of
    that action resets its count. When any count reaches `threshold` the
    breaker opens and stays open (every start is refused) until a
    wad_breaker_reset record, written only on an operator's request.
    -> {"open": bool, "counts": {action: n}, "tripped_by": action or None}"""
    counts, open_, by = {}, False, None
    for e in entries:
        et = e.get("event_type")
        if et == "wad_breaker_reset":
            counts, open_, by = {}, False, None
        elif et == "wad_step_transition":
            a = e.get("step_action")
            if e.get("to") == FAILED:
                counts[a] = counts.get(a, 0) + 1
                if counts[a] >= threshold and not open_:
                    open_, by = True, a
            elif e.get("to") == DONE:
                counts[a] = 0
    return {"open": open_, "counts": counts, "tripped_by": by}


def dry_run_execute(action, entity):
    """Does nothing. Returns what a live executor would have been asked to do."""
    return {"result": "DRY_RUN", "would": f"{action} {entity}"}


def rollback_order(steps, run_id, entity):
    """Done/failed steps of one plan, newest completion first (reverse order)."""
    mine = [s for s in steps.values() if s["run_id"] == run_id and s["entity"] == entity
            and s["state"] in (DONE, FAILED)]
    return sorted(mine, key=lambda s: (len(s["history"]) and s["history"][-1]["at"] or "", s["index"]), reverse=True)
