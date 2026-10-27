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


def check_approval(step, identity, reason, allowlist, now, killswitch, ttl_s, current_digest, reserved=()):
    """Every gate for approving `step`; all run, none short-circuit.
    -> {"allowed": bool, "violations": [...], "authenticated": False}"""
    v = []
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


def check_start(step, now, killswitch, ttl_s):
    v = []
    if next_state(step["state"], "start") is None:
        v.append(f"illegal_transition:{step['state']}->start")
    if killswitch:
        v.append("killswitch_active")
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


def dry_run_execute(action, entity):
    """Does nothing. Returns what a live executor would have been asked to do."""
    return {"result": "DRY_RUN", "would": f"{action} {entity}"}


def rollback_order(steps, run_id, entity):
    """Done/failed steps of one plan, newest completion first (reverse order)."""
    mine = [s for s in steps.values() if s["run_id"] == run_id and s["entity"] == entity
            and s["state"] in (DONE, FAILED)]
    return sorted(mine, key=lambda s: (len(s["history"]) and s["history"][-1]["at"] or "", s["index"]), reverse=True)
