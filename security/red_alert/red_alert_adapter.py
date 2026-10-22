"""security/red_alert/red_alert_adapter.py -- pure adapter functions that
turn WAIO Global Cyber Intelligence Patrol (Phase 100) / Critical
Infrastructure & Military Precursor Watch (Phase 101) findings, and
SND@HOME cross-reference signals (security/red_alert/snd_crossref.py), into
the WAIO Intelligence/Evidence Layer's own documented "Intelligence Record"
shape -- see security/intelligence/intelligence_lib.py's own adapter-function
header for that exact contract: id, source_module, source_finding_id,
entity, entity_type, category, risk, confidence, detected_at, summary, raw.

WHY THIS FILE EXISTS: Global Patrol and Critical Infra Watch already
collect/correlate/score public threat intelligence end to end, but by
explicit prior-phase design never feed the WAIO Decision Engine ("No
automated connection to Guardian or the Decision Engine", ARCHITECTURE.md
Phase 100/101). This file is the missing connection: it lets
red_alert_cron.sh feed their already-computed findings into the SAME
aggregation + Decision Engine pipeline every other evidence-producing
module (Shadow AI Monitor, Attack Graph, Incident Learning, SaaS ATO
Monitor) already uses, without duplicating or modifying any of them.

security/intelligence/intelligence_lib.py is imported here, NOT modified --
this file plays the same architectural role for Global Patrol/Critical
Infra Watch/SND@HOME-crossref that intelligence_layer.sh's own ingest()
function already plays for Shadow AI/Attack Graph/Incident Learning/SaaS
ATO: a thin adapter layer in front of that module's own pure
aggregate_by_entity()/rank_profiles()/report_summary(), reused unchanged.
This file adds NO new scoring, ranking, or escalation logic of its own --
every risk/confidence value below is carried through from what
knowledge_manager.sh's own candidate_confidence_level() (CONFIRMED/HIGH/
MEDIUM/LOW/UNVERIFIED) already computed, mapped onto this layer's existing
RISK/CONFIDENCE scales via one small, fully-stated table (same "state the
basis, never a black box" posture as every other classification step in
this pipeline).

A RECOMMEND_CONTAINMENT decision the Decision Engine later derives from one
of these records means exactly what decision_engine_lib.py's own header
already says it means: a human reads it, and separately judges by hand
whether WAIO has anything it can actually act on locally -- NOT a claim
that WAIO observed or can contain the underlying global incident. A pure
global-intelligence finding with no local corroboration is expected to
often land here with nothing for a human to do about it; that is the
Decision Engine's own, unmodified, approved behavior, not something this
file works around.

No I/O in this module -- every function is a pure function of its
arguments, same convention as every other _lib.py in this pipeline.
"""

import os
import sys

sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "intelligence")
)
import intelligence_lib as il  # noqa: E402  (re-exported below for callers)

aggregate_by_entity = il.aggregate_by_entity
rank_profiles = il.rank_profiles
report_summary = il.report_summary

# knowledge_manager.sh's own candidate_confidence_level() labels, mapped
# onto this layer's existing RISK_ORDER / CONFIDENCE_ORDER scales
# (intelligence_lib.py's own, reused unchanged). Deliberately a flat,
# fully-stated table, never a formula.
_RISK_FROM_CONFIDENCE_LEVEL = {
    "CONFIRMED": "CRITICAL",
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
    "UNVERIFIED": "LOW",
}
_CONFIDENCE_FROM_CONFIDENCE_LEVEL = {
    "CONFIRMED": "HIGH",
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
    "UNVERIFIED": "LOW",
}


def _risk_from_level(level):
    return _RISK_FROM_CONFIDENCE_LEVEL.get(level, "LOW")


def _confidence_from_level(level):
    return _CONFIDENCE_FROM_CONFIDENCE_LEVEL.get(level, "LOW")


def from_global_patrol_entity(entry, source_module):
    """One Global Patrol "new_incidents" entry (global_patrol_report.py's
    own _candidate_summary() shape) OR one Critical Infra Watch
    confirmed_activity entry (critical_infra_watch.py's own build_section()
    shape) -> Intelligence Record. Both shapes carry an `id`,
    `confidence_level`, `source`, `source_url`, and either `attack_pattern`
    (+ `incident_type`) or `critical_sectors`; this function reads only
    fields present in either shape via .get(), never assumes one over the
    other.

    entity is the entry's own `id` -- same per-incident granularity
    incident_learning's own from_incident_learning_candidate() uses for a
    candidate with no extracted CVE, so a Global Patrol/Critical Infra
    Watch entity never silently collides with an unrelated
    incident_learning entity string.

    source_module must be "global_patrol" or "critical_infra_watch" --
    passed explicitly by the caller (red_alert_cron.sh knows which report
    section produced this entry), not guessed from the entry's own shape.
    """
    level = entry.get("confidence_level", "UNVERIFIED")
    entry_id = entry.get("id", "unknown")
    attack_pattern = entry.get("attack_pattern") or entry.get("incident_type") or "unclassified"
    country = entry.get("country") or "unknown"
    return {
        "id": f"INTEL-{source_module}-{entry_id}",
        "source_module": source_module,
        "source_finding_id": entry_id,
        "entity": entry_id,
        "entity_type": "critical_infra_activity" if "critical_sectors" in entry else "global_patrol_incident",
        "category": attack_pattern,
        "risk": _risk_from_level(level),
        "confidence": _confidence_from_level(level),
        "detected_at": entry.get("published_at") or entry.get("collected_at"),
        "summary": (
            f"{source_module} entry {entry_id}: attack_pattern={attack_pattern} "
            f"country={country} confidence_level={level} "
            f"source={entry.get('source')}"
        ),
        "raw": entry,
    }


def from_precursor_hypothesis(hypothesis):
    """One Critical Infra Watch precursor_hypothesis (critical_infra_watch.py's
    own build_section() shape: attack_pattern, member_ids,
    countries_involved, member_summaries, risk_increase_reasoning,
    alternative_explanations, confidence_caveat) -> Intelligence Record.

    entity is the hypothesis's own attack_pattern (not any one member's
    id): a precursor_hypothesis is BY CONSTRUCTION about a pattern shared
    across >=2 countries, not about any single incident -- see
    critical_infra_watch.py's own S1 gate (ARCHITECTURE.md Phase 101
    Section 2). risk/confidence are fixed at HIGH/HIGH, stated plainly
    here rather than re-derived: reaching this function at all already
    required every member to be independently-corroborated
    HIGH/CONFIRMED confirmed_activity across >=2 distinct countries (the
    strongest, most-filtered signal in this entire pipeline) -- raising it
    further to CRITICAL is deliberately NOT done here, since this
    function has no local-footprint information of its own; `raw` carries
    the hypothesis's own confidence_caveat/alternative_explanations
    unabridged, so a human reviewing the eventual Decision Record always
    sees the full original caveat, never a stripped summary.
    """
    pattern = hypothesis.get("attack_pattern", "unclassified")
    countries = hypothesis.get("countries_involved") or []
    member_ids = hypothesis.get("member_ids") or []
    return {
        "id": f"INTEL-critical_infra_watch-hypothesis-{pattern}",
        "source_module": "critical_infra_watch",
        "source_finding_id": None,
        "entity": pattern,
        "entity_type": "precursor_hypothesis",
        "category": pattern,
        "risk": "HIGH",
        "confidence": "HIGH",
        "detected_at": None,
        "summary": (
            f"precursor_hypothesis for attack_pattern={pattern}: "
            f"{len(member_ids)} corroborated member(s) across "
            f"{len(countries)} countr(y/ies) ({', '.join(countries)}). "
            f"{hypothesis.get('confidence_caveat', '')}"
        ),
        "raw": hypothesis,
    }


def from_snd_crossref_signal(signal):
    """One snd_crossref.py build_crossref_signals() match -> Intelligence
    Record. entity is DELIBERATELY the SAME `entity_id` the matched
    global finding itself uses (from_global_patrol_entity()'s own
    `entity_id` parameter) -- NOT a new, separate entity string. This is
    the one load-bearing design choice that makes requirement #3's
    read-only comparison actually useful to the Decision Engine without
    inventing any new escalation logic: when intelligence_lib.py's own
    aggregate_by_entity() later rolls up records sharing one entity key,
    a global finding that ALSO has a local SND@HOME textual match
    naturally gets source_modules=[..., "snd_home_crossref"] and
    multi_source=True on its profile -- decision_engine_lib.py's own
    ALREADY-APPROVED, UNMODIFIED decide_action() table is what decides
    whether that raises the recommended action, never this file.

    confidence is fixed at MEDIUM, never HIGH -- a textual keyword match
    is evidence worth a human's attention, never proof. risk is fixed at
    LOW: this record's own job is to raise CONFIDENCE (via multi_source)
    on whatever risk the matched global finding already carries, not to
    independently assert a risk level of its own (aggregate_by_entity()
    takes the HIGHER of this record's risk and the global finding's own
    risk, so LOW here never lowers an already-higher risk, only ever
    leaves it unchanged or raises confidence).
    """
    entity_id = signal.get("entity_id", "unknown")
    return {
        "id": f"INTEL-snd_home_crossref-{entity_id}-{signal.get('snd_section')}-{signal.get('match_keyword')}",
        "source_module": "snd_home_crossref",
        "source_finding_id": None,
        "entity": entity_id,
        "entity_type": "snd_home_crossref_signal",
        "category": "possible_local_global_overlap",
        "risk": "LOW",
        "confidence": "MEDIUM",
        "detected_at": None,
        "summary": (
            f"SND@HOME {signal.get('snd_section')} text matched keyword "
            f"'{signal.get('match_keyword')}' from entity {entity_id}. "
            f"{signal.get('confidence_caveat', '')}"
        ),
        "raw": signal,
    }
