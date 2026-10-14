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

SAFETY INVARIANT ADDED THIS PHASE (ARCHITECTURE.md Phase 104, closing
a gap GLOBAL_ATTACK_COMMONALITY_AB_CORRELATION_INVESTIGATION.md Sec.7.7
identified): decide_action()'s own table below is UNCHANGED -- it still
documents exactly when RECOMMEND_CONTAINMENT is the table's own answer.
What changed is decide_for_profile(): it now applies ONE MORE gate
AFTER consulting that table -- see local_corroboration_for_profile()
below -- that caps the final recommended_action at ALERT_HUMAN whenever
no TRUSTED LOCAL evidence-producing module (WAIO's own observation of
its real local environment -- Shadow AI Monitor, Attack Graph, SaaS
ATO Monitor) independently corroborates the same entity. Global public
threat intelligence (global_patrol, critical_infra_watch) and the
SND@HOME crossref signal (snd_home_crossref -- itself explicitly
documented elsewhere as non-causal) are
deliberately NOT trusted local evidence: two global sources agreeing
with each other, however high their stated risk/confidence, is still
zero evidence that anything is actually happening inside WAIO's own
environment right now. This was a REAL, measured gap, not a
hypothetical one: the one real Phase C evaluation (2026-10-12, 74
real global_patrol-only records) produced 11 RECOMMEND_CONTAINMENT
decisions, 100% with multi_source=False and zero local corroboration
of any kind -- see tests/decision_engine_test.sh's own R-series, which
replays that exact real input file and asserts all 11 are now capped.
"""

RISK_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

# Ordered least to most severe -- index is used as the sort key in
# rank_decisions() below (higher index = more urgent = sorted first).
ACTIONS = ["NO_ACTION", "MONITOR", "ALERT_HUMAN", "RECOMMEND_CONTAINMENT"]

# Source modules that represent WAIO's own observation of its REAL
# LOCAL environment (process/network/SaaS-account state) -- as opposed
# to a module that only describes public threat intelligence about
# events elsewhere in the world. A closed, explicit allowlist, not a
# guess at what "looks local": a module name this file has never heard
# of is never treated as local corroboration, fail-safe.
#
# Deliberately EXCLUDED:
#   - "global_patrol", "critical_infra_watch", "incident_learning" --
#     all three are public-OSINT-sourced (CISA/GHSA/JPCERT/etc. via
#     security/incident_learning/'s own Collectors), describing events
#     that happened somewhere else, not inside WAIO's own environment.
#   - "snd_home_crossref" -- documented elsewhere as textual
#     co-occurrence between a cached local-network snapshot and a
#     GLOBAL entity, carrying its own mandatory confidence_caveat
#     stating it is never causal/network/geographic proof. Counting it
#     as trusted local evidence here would quietly reintroduce the
#     exact gap this phase closes.
LOCAL_SOURCE_MODULES = frozenset({"shadow_ai_monitor", "attack_graph", "saas_ato"})

# A local module's OWN record for this entity must report at least
# this risk to count as corroborating -- mere PRESENCE of a local
# module name in source_modules is not proof (e.g. an Attack Graph
# node that happens to mention this entity at LOW risk is
# CONTRADICTORY evidence against a global source's own CRITICAL
# rating, not corroborating evidence for it).
_MIN_LOCAL_CORROBORATION_RISK = frozenset({"MEDIUM", "HIGH", "CRITICAL"})

# Same 30-day staleness convention already load-bearing in
# security/incident_learning/incident_confidence.sh's own formula --
# reused here, not reinvented.
LOCAL_CORROBORATION_STALENESS_DAYS = 30


import datetime


def _risk_index(risk):
    return RISK_ORDER.index(risk) if risk in RISK_ORDER else 0


def _parse_detected_at(value):
    """Best-effort ISO-8601 parse of a record's own detected_at field.
    Returns None on anything missing or malformed -- never raises.

    Missing is NOT the same as stale: a record with no detected_at at
    all (e.g. every Attack Graph record, by that module's own
    documented design -- see intelligence_lib.py's own
    from_attack_graph_node()/from_attack_graph_path()) is treated as
    unknown-freshness, not stale-and-excluded; a record that DOES
    carry a value this file can't parse is treated the same way,
    fail-safe, rather than guessed at either way.
    """
    if not isinstance(value, str) or not value:
        return None
    try:
        text = value.replace("Z", "+00:00")
        dt = datetime.datetime.fromisoformat(text)
    except (ValueError, TypeError):
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return dt


def local_corroboration_for_profile(profile, now=None):
    """Derives whether `profile` (an Intelligence Layer entity profile)
    has TRUSTED LOCAL corroboration -- never trusts a caller-supplied
    boolean, always re-derives this from the profile's own
    already-validated `source_modules` list (and, when present, its
    own `records` list for a per-record risk/staleness refinement).

    Returns (has_local_corroboration: bool, contributing_modules: list[str]).

    Step 1 -- candidate modules: the intersection of profile's own
    source_modules with LOCAL_SOURCE_MODULES above. A malformed/missing
    source_modules (not a list) yields no candidates, fail-safe. If
    there are no candidates at all, this returns (False, []) and never
    looks at `records` -- there is nothing local to corroborate with.

    Step 2 -- refinement using `records`, WHEN AVAILABLE: profile's own
    `records` list (each an Intelligence Record carrying its own
    source_module/risk/detected_at -- see intelligence_lib.py's own
    aggregate_by_entity() header) is used to confirm or disqualify each
    candidate module:
      - a candidate module with an actual record showing risk >= MEDIUM
        and NOT stale (detected_at, if parseable, <= 30 days old) is
        CONFIRMED.
      - a candidate module with an actual record showing risk < MEDIUM,
        or a parseable-and-stale detected_at, is DISQUALIFIED (fail
        CLOSED -- contradictory or stale evidence never corroborates).
      - a candidate module with NO matching record in `records` at all
        (records missing, empty, or simply contains none from that
        module) is NEITHER confirmed nor disqualified by this step --
        it stays trusted at the source_modules level from Step 1. This
        is a deliberate "don't invent missing integrations" choice:
        every existing caller of decide_for_profile() (every test in
        tests/decision_engine_test.sh predating this phase, and the
        real Intelligence Layer's own historical output before this
        phase) supplies source_modules without always supplying the
        full per-record detail, and source_modules itself is already
        validated, structured pipeline data (the same data multi_source
        already relies on) -- not a bare caller-supplied boolean.

    `now` is caller-injectable for exact test reproducibility (same
    "clock is always caller-injected" convention already established
    elsewhere in this pipeline's approval-gate tooling); defaults to
    the real current UTC time only when the caller does not care to
    fix it, since the many pre-existing callers of
    decide_for_profile()/decide_all() do not pass one.
    """
    source_modules = profile.get("source_modules")
    if not isinstance(source_modules, list):
        source_modules = []
    candidates = sorted(
        {m for m in source_modules if isinstance(m, str) and m in LOCAL_SOURCE_MODULES}
    )
    if not candidates:
        return False, []

    records = profile.get("records")
    if not isinstance(records, list):
        records = []

    now = now or datetime.datetime.now(datetime.timezone.utc)
    confirmed = set()
    disqualified = set()
    for record in records:
        if not isinstance(record, dict):
            continue
        source_module = record.get("source_module")
        if source_module not in candidates:
            continue
        risk_ok = record.get("risk") in _MIN_LOCAL_CORROBORATION_RISK
        detected_at = _parse_detected_at(record.get("detected_at"))
        stale = (
            detected_at is not None
            and (now - detected_at).total_seconds() > LOCAL_CORROBORATION_STALENESS_DAYS * 86400
        )
        if risk_ok and not stale:
            confirmed.add(source_module)
        else:
            disqualified.add(source_module)

    trusted = set(candidates)
    # Only a module this step actually SAW disqualifying evidence for,
    # and never ALSO saw confirming evidence for (a module can appear
    # in more than one record), loses its Step-1 trust -- fail closed
    # only on evidence actually examined, never on evidence simply
    # absent.
    for source_module in disqualified - confirmed:
        trusted.discard(source_module)

    trusted = sorted(trusted)
    return (len(trusted) > 0), trusted


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


def decide_for_profile(profile, now=None):
    """profile: one Intelligence Layer entity profile dict. Returns a
    Decision Record. Never mutates the input, never discards the
    profile's own identifying fields -- a Decision Record always traces
    back to exactly which entity, at what risk/confidence, from which
    source modules, produced it.

    SAFETY GATE (see local_corroboration_for_profile() and this
    module's own header): decide_action()'s table may say
    RECOMMEND_CONTAINMENT, but that is only ever the FINAL
    recommended_action when at least one TRUSTED LOCAL evidence-
    producing module also corroborates this entity. Otherwise the
    action is capped at ALERT_HUMAN -- global/aggregate evidence alone
    is never sufficient to recommend containment. `capped_from_
    recommend_containment` and `local_corroboration` are both recorded
    explicitly on the returned record, so this is never a silent
    downgrade.
    """
    risk = profile.get("highest_risk", "LOW")
    confidence = profile.get("highest_confidence", "LOW")
    source_modules = profile.get("source_modules") or []
    if not isinstance(source_modules, list):
        source_modules = []
    multi_source = len(source_modules) > 1
    action = decide_action(risk, confidence, multi_source)

    has_local_corroboration, local_modules = local_corroboration_for_profile(profile, now=now)
    capped = action == "RECOMMEND_CONTAINMENT" and not has_local_corroboration
    if capped:
        action = "ALERT_HUMAN"

    reasoning = (
        f"risk={risk} confidence={confidence} multi_source={multi_source} "
        f"({len(source_modules)} source module(s): {source_modules}) -> {action}"
    )
    if capped:
        reasoning += (
            " [CAPPED from RECOMMEND_CONTAINMENT: global/aggregate evidence alone "
            "is never sufficient to recommend containment -- no trusted local "
            f"corroboration found (local_source_modules={local_modules})]"
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
        "local_corroboration": {"present": has_local_corroboration, "modules": local_modules},
        "capped_from_recommend_containment": capped,
        "reasoning": reasoning,
    }


def decide_all(entities, now=None):
    """entities: the Intelligence Layer report's own 'entities' dict
    (entity name -> profile, as intelligence_layer.sh's own `ingest`
    output shapes it). Returns one Decision Record per entity, in
    whatever order the input dict iterates -- see rank_decisions() for
    the actual human-facing ordering. `now` is forwarded to every
    decide_for_profile() call, so a caller wanting exact reproducibility
    across an entire report fixes it once here.
    """
    return [decide_for_profile(p, now=now) for p in entities.values()]


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
