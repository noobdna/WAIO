"""security/decision_engine/decision_engine_lib.py -- pure decision-rule
core for the WAIO Decision Engine.

Position in the requested pipeline:

    Shadow AI Monitor -\\
    Attack Graph        -> WAIO Intelligence/Evidence Layer -> WAIO Decision Engine -> DuCoPA -> Contain/Recover
    Incident Learning  -/

CRITICAL SAFETY BOUNDARY -- stated here first, and nowhere diluted
anywhere else in this module or its own CLI wrapper
(security/decision_engine/decision_engine.sh): this module PROPOSES, IT
NEVER DISPOSES. Every function here returns a recommended action plus
explicit reasoning -- nothing in this module, and nothing in its CLI
wrapper, ever calls security/guardian.sh,
security/guardian_intervene_wrapper.sh,
security/guardian_intervene_quarantine_wrapper.sh,
security/guardian_release_agent.sh, security/ducopa.sh,
security/recovery_engine.sh, security/recover.sh, or
security/incident_learning/knowledge_manager.sh's own approve/reject/
hold/promote verbs. A RECOMMEND_CONTAINMENT decision is, and remains, a
human reading this module's own output and THEN separately, by hand,
running one of WAIO's existing containment tools -- this module does
not queue-and-auto-execute or shortcut that handoff in any way. This
mirrors the exact same "never auto-adopt without a human gate"
principle already load-bearing throughout
security/incident_learning/knowledge_manager.sh (CANDIDATE is never
sufficient on its own to reach PROMOTED) and
security/guardian_intervene_wrapper.sh (every real intervention requires
an explicit human-run wrapper). tests/decision_engine_test.sh's own
D-series exists specifically to keep this true in code, not just in
this comment.

This module's INPUT is deliberately narrow: only the WAIO Intelligence/
Evidence Layer's own already-aggregated entity profiles (entity,
entity_type, highest_risk, highest_confidence, source_modules,
record_count) -- see
security/intelligence/intelligence_lib.py's own aggregate_by_entity()
header for that shape. This module does not reach further upstream to
Shadow AI Monitor or Attack Graph directly, matching the same
one-stage-consumes-only-the-stage-before-it discipline already used
throughout this pipeline's prior phases.

No I/O in this module -- every function is a pure function of its
arguments, same convention as every other `_lib.py` in this pipeline
(shadow_ai_lib.py, attack_graph_lib.py, intelligence_lib.py).
"""

RISK_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

# Ordered least to most severe -- index is used as the sort key in
# rank_decisions() below (higher index = more urgent = sorted first).
ACTIONS = ["NO_ACTION", "MONITOR", "ALERT_HUMAN", "RECOMMEND_CONTAINMENT"]


def _risk_index(risk):
    return RISK_ORDER.index(risk) if risk in RISK_ORDER else 0


def decide_action(risk, confidence, multi_source):
    """Deliberately simple, fully stated decision table -- never a
    weighted/blended score, same "state the basis, not just the
    verdict" posture as every other classification step in this
    pipeline (incident_confidence.sh's own formula, Attack Graph's own
    classify_risk()):

      CRITICAL risk                                -> RECOMMEND_CONTAINMENT
      HIGH risk + (HIGH confidence OR multi-source) -> RECOMMEND_CONTAINMENT
      HIGH risk, otherwise                          -> ALERT_HUMAN
      MEDIUM risk + HIGH confidence + multi-source  -> ALERT_HUMAN
      MEDIUM risk, otherwise                        -> MONITOR
      LOW risk                                      -> NO_ACTION

    "multi_source" (more than one evidence-producing module
    independently corroborated this entity) raises an action the same
    way corroboration already raises confidence_score elsewhere in this
    pipeline -- it is evidence STRENGTH, not a new kind of risk.
    """
    if risk == "CRITICAL":
        return "RECOMMEND_CONTAINMENT"
    if risk == "HIGH":
        if confidence == "HIGH" or multi_source:
            return "RECOMMEND_CONTAINMENT"
        return "ALERT_HUMAN"
    if risk == "MEDIUM":
        if multi_source and confidence == "HIGH":
            return "ALERT_HUMAN"
        return "MONITOR"
    return "NO_ACTION"


def requires_human_review(action):
    """Everything except NO_ACTION deserves a human's eyes on it at
    least once -- true for MONITOR/ALERT_HUMAN/RECOMMEND_CONTAINMENT.
    """
    return action != "NO_ACTION"


def requires_human_approval_to_act(action):
    """Only RECOMMEND_CONTAINMENT implies an actual intervention a
    human might take using WAIO's EXISTING containment tools (see this
    module's own header) -- MONITOR/ALERT_HUMAN are visibility-only,
    nothing to approve.
    """
    return action == "RECOMMEND_CONTAINMENT"


def decide_for_profile(profile):
    """profile: one Intelligence Layer entity profile dict. Returns a
    Decision Record. Never mutates the input, never discards the
    profile's own identifying fields -- a Decision Record always traces
    back to exactly which entity, at what risk/confidence, from which
    source modules, produced it.
    """
    risk = profile.get("highest_risk", "LOW")
    confidence = profile.get("highest_confidence", "LOW")
    source_modules = profile.get("source_modules") or []
    multi_source = len(source_modules) > 1
    action = decide_action(risk, confidence, multi_source)
    reasoning = (
        f"risk={risk} confidence={confidence} multi_source={multi_source} "
        f"({len(source_modules)} source module(s): {source_modules}) -> {action}"
    )
    return {
        "entity": profile.get("entity"),
        "entity_type": profile.get("entity_type"),
        "risk": risk,
        "confidence": confidence,
        "source_modules": source_modules,
        "record_count": profile.get("record_count", 0),
        "recommended_action": action,
        "requires_human_review": requires_human_review(action),
        "requires_human_approval_to_act": requires_human_approval_to_act(action),
        "reasoning": reasoning,
    }


def decide_all(entities):
    """entities: the Intelligence Layer report's own 'entities' dict
    (entity name -> profile, as intelligence_layer.sh's own `ingest`
    output shapes it). Returns one Decision Record per entity, in
    whatever order the input dict iterates -- see rank_decisions() for
    the actual human-facing ordering.
    """
    return [decide_for_profile(p) for p in entities.values()]


_ACTION_SEVERITY = {a: i for i, a in enumerate(ACTIONS)}


def rank_decisions(decisions):
    """Sorts decisions most-urgent-first: by recommended_action
    severity (RECOMMEND_CONTAINMENT first), then by risk, then by
    entity name as a final deterministic tie-break -- the order a human
    reviewing this report actually wants to read it in.
    """
    return sorted(
        decisions,
        key=lambda d: (
            -_ACTION_SEVERITY.get(d["recommended_action"], 0),
            -_risk_index(d["risk"]),
            d["entity"],
        ),
    )


def decision_summary(ranked):
    """ranked (from rank_decisions) -> counts by action, plus the full
    list of entities awaiting human approval to act (the
    RECOMMEND_CONTAINMENT ones) -- the one list a human reviewing this
    report most needs to see first.
    """
    counts = {a: 0 for a in ACTIONS}
    for d in ranked:
        counts[d["recommended_action"]] = counts.get(d["recommended_action"], 0) + 1
    pending_approval = [d["entity"] for d in ranked if d["requires_human_approval_to_act"]]
    return {
        "decision_count": len(ranked),
        "action_counts": counts,
        "pending_human_approval": pending_approval,
    }
