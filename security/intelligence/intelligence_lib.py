"""security/intelligence/intelligence_lib.py -- pure normalization and
aggregation core for the WAIO Intelligence / Evidence Layer.

Sits between the individual evidence-producing modules and a future
Decision Engine, per the requested pipeline shape:

    Shadow AI Monitor -\\
    Attack Graph        -> WAIO Intelligence/Evidence Layer -> WAIO Decision Engine -> DuCoPA -> Contain/Recover
    Incident Learning  -/

Its one job: take each source's own native JSON shape and normalize it
into one common "Intelligence Record" schema, then aggregate records
that are about the SAME real-world entity (a process name, a CVE id, a
graph node, an attack path) into one Entity Profile a Decision Engine
could act on without having to understand three different upstream
schemas. This layer DECIDES NOTHING and ACTS ON NOTHING -- it has no
risk-escalation authority beyond what each source already computed; it
only rolls multiple already-classified risk/confidence values up to
their highest observed value per entity, same "state the basis, never
a black box" posture as every other classification step in this repo.

Coupling is DELIBERATELY loose, same discipline
security/attack_graph/attack_graph_lib.py already established for its
own upstream (Shadow AI Monitor): this module never imports
shadow_ai_lib.py, attack_graph_lib.py, or
security/incident_learning/knowledge_manager.sh's own Python helpers.
It depends only on each source's own documented JSON/data shape:
  - Shadow AI Monitor finding: see
    security/shadow_ai/shadow_ai_lib.py's own build_finding() header.
  - Attack Graph node/edge: see
    security/attack_graph/attack_graph_lib.py's own build_graph()
    header.
  - Incident Learning candidate: see
    security/incident_learning/knowledge_manager.sh's own state-machine
    header (the raw per-candidate JSON file shape).

No I/O in this module -- every function is a pure function of its
arguments (already-loaded dicts), directly unit-testable with no
fixture files, same convention as
security/attack_graph/attack_graph_lib.py and
fx_validation/validation_lib.py.
"""

RISK_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
CONFIDENCE_ORDER = ["LOW", "MEDIUM", "HIGH"]


def _index(value, order):
    return order.index(value) if value in order else 0


def _higher(a, b, order):
    return a if _index(a, order) >= _index(b, order) else b


def higher_risk(a, b):
    return _higher(a, b, RISK_ORDER)


def higher_confidence(a, b):
    return _higher(a, b, CONFIDENCE_ORDER)


# --- source adapters: SOURCE'S OWN SHAPE -> common Intelligence Record ----
#
# Every adapter returns a dict with exactly these keys, regardless of
# source: id, source_module, source_finding_id, entity, entity_type,
# category, risk, confidence, detected_at, summary, raw. `raw` always
# carries the ORIGINAL, untouched source object, so a human (or a
# future Decision Engine) can always trace a normalized record back to
# exactly what produced it -- normalization never discards the
# original evidence, only adds a common lens on top of it.

def from_shadow_ai_finding(finding):
    """Shadow AI Monitor finding -> Intelligence Record. entity is the
    finding's own process comm when present, else its signature_matched
    (covers a listening_port finding with no resolved owning process).
    """
    process = finding.get("process") or {}
    entity = process.get("comm") or finding.get("signature_matched") or "unknown"
    return {
        "id": f"INTEL-shadow_ai-{finding.get('id', 'unknown')}",
        "source_module": "shadow_ai_monitor",
        "source_finding_id": finding.get("id"),
        "entity": entity,
        "entity_type": "process",
        "category": finding.get("category"),
        "risk": finding.get("risk", "LOW"),
        "confidence": finding.get("confidence", "LOW"),
        "detected_at": finding.get("detected_at"),
        "summary": finding.get("reason", ""),
        "raw": finding,
    }


def from_attack_graph_node(name, node):
    """Attack Graph node -> Intelligence Record. A node already
    aggregates one or more Shadow AI findings (see its own
    finding_ids) -- confidence here reflects how much upstream evidence
    actually supports this node: a single contributing finding is
    MEDIUM, two or more is HIGH (same "more independent evidence raises
    confidence" reasoning
    security/incident_learning/incident_confidence.sh's own
    corroboration bonus already uses, applied here to finding COUNT
    rather than source count since that is what a graph node actually
    tracks).
    """
    finding_ids = node.get("finding_ids") or []
    confidence = "HIGH" if len(finding_ids) >= 2 else "MEDIUM"
    return {
        "id": f"INTEL-attack_graph-node-{name}",
        "source_module": "attack_graph",
        "source_finding_id": None,
        "entity": name,
        "entity_type": "graph_node",
        "category": node.get("category"),
        "risk": node.get("highest_risk", "LOW"),
        "confidence": confidence,
        "detected_at": None,
        "summary": (
            f"node '{name}' highest_risk={node.get('highest_risk')} "
            f"from {len(finding_ids)} contributing finding(s)"
        ),
        "raw": node,
    }


def from_attack_graph_path(path):
    """Attack Graph attack_path -> Intelligence Record. entity is
    '<from>->...->(final hop)' using the FULL path, so a direct 1-hop
    path and a longer chain to the same ultimate target are tracked as
    distinct entities (they are distinct findings about distinct
    routes, even when they share an endpoint). confidence is a fixed
    MEDIUM -- a path's own confidence isn't separately tracked upstream
    (attack_graph_lib.py's own find_attack_paths() has no confidence
    field, only path_risk), so this is a deliberate, documented default
    rather than an invented number.
    """
    entity = "->".join(path.get("path", []))
    return {
        "id": f"INTEL-attack_graph-path-{entity}",
        "source_module": "attack_graph",
        "source_finding_id": None,
        "entity": entity,
        "entity_type": "attack_path",
        "category": "lateral_movement",
        "risk": path.get("path_risk", "LOW"),
        "confidence": "MEDIUM",
        "detected_at": None,
        "summary": f"possible lateral movement path: {entity} (risk {path.get('path_risk')})",
        "raw": path,
    }


def classify_risk_from_confidence_score(score):
    """Incident Learning's own confidence_score (0-100, see
    incident_confidence.sh's own formula) -> this layer's RISK scale.
    Deliberately simple fixed thresholds, stated plainly:
      >= 80 -> CRITICAL, >= 65 -> HIGH, >= 50 -> MEDIUM, else LOW.
    50 is Incident Learning's own default KNOWLEDGE_MIN_CONFIDENCE
    threshold for ever reaching CANDIDATE at all, so a candidate this
    layer ever sees is already at least MEDIUM by construction; the
    higher bands exist for PROMOTED entries this layer may also ingest,
    which can carry any score that originally cleared the human gate.
    """
    try:
        score = int(score)
    except (TypeError, ValueError):
        return "LOW"
    if score >= 80:
        return "CRITICAL"
    if score >= 65:
        return "HIGH"
    if score >= 50:
        return "MEDIUM"
    return "LOW"


def classify_confidence_from_corroboration(count):
    """Incident Learning's own evidence_corroborating_count -> this
    layer's CONFIDENCE scale: 0 -> LOW, 1 -> MEDIUM, >=2 -> HIGH. Same
    thresholds incident_confidence.sh's own formula already uses for
    its +15/+30 corroboration bonus, reapplied here as a confidence
    label rather than a score delta.
    """
    try:
        count = int(count)
    except (TypeError, ValueError):
        count = 0
    if count >= 2:
        return "HIGH"
    if count == 1:
        return "MEDIUM"
    return "LOW"


def from_incident_learning_candidate(candidate):
    """An Incident Learning candidate's own raw state-file JSON ->
    Intelligence Record. entity is the first CVE in its own cve_list
    when present (so multiple candidates about the same real CVE
    correlate under one entity at aggregation time), else the
    candidate's own id (e.g. a GHSA advisory with no extracted CVE).
    Only meaningful for a candidate that has actually been scored
    (reached at least SCORED) -- an earlier-stage candidate has no
    confidence_score yet and is reported at LOW/LOW rather than
    guessed at.
    """
    cve_list = candidate.get("cve_list") or []
    entity = cve_list[0] if cve_list else candidate.get("id", "unknown")
    score = candidate.get("confidence_score")
    corroborating = candidate.get("evidence_corroborating_count")
    risk = classify_risk_from_confidence_score(score) if score is not None else "LOW"
    confidence = (
        classify_confidence_from_corroboration(corroborating)
        if corroborating is not None
        else "LOW"
    )
    return {
        "id": f"INTEL-incident_learning-{candidate.get('id', 'unknown')}",
        "source_module": "incident_learning",
        "source_finding_id": candidate.get("id"),
        "entity": entity,
        "entity_type": "cve" if cve_list else "incident_candidate",
        "category": candidate.get("source_type"),
        "risk": risk,
        "confidence": confidence,
        "detected_at": candidate.get("collected_at") or candidate.get("created_at"),
        "summary": candidate.get("reason", ""),
        "raw": candidate,
    }


# --- aggregation -----------------------------------------------------------

def aggregate_by_entity(records):
    """records (from any mix of the adapters above) -> {entity: profile}.

    profile = {
      entity, entity_type (of the FIRST record seen for this entity --
        two records sharing an entity string are expected to agree;
        this is not re-validated here), highest_risk, highest_confidence,
      source_modules (sorted list of distinct contributing modules),
      record_count, records (the full list, for traceability).
    }
    Never mutates the input list. An entity seen from only one source
    still gets a complete profile (source_modules has one entry) --
    multi-source corroboration is a property of the profile, not a
    requirement to appear in it at all.
    """
    profiles = {}
    for r in records:
        entity = r["entity"]
        if entity not in profiles:
            profiles[entity] = {
                "entity": entity,
                "entity_type": r["entity_type"],
                "highest_risk": r["risk"],
                "highest_confidence": r["confidence"],
                "source_modules": set(),
                "record_count": 0,
                "records": [],
            }
        p = profiles[entity]
        p["highest_risk"] = higher_risk(p["highest_risk"], r["risk"])
        p["highest_confidence"] = higher_confidence(p["highest_confidence"], r["confidence"])
        p["source_modules"].add(r["source_module"])
        p["record_count"] += 1
        p["records"].append(r)

    for p in profiles.values():
        p["source_modules"] = sorted(p["source_modules"])

    return profiles


def rank_profiles(profiles):
    """profiles (the dict from aggregate_by_entity) -> a list of
    profiles sorted by (risk desc, confidence desc, record_count desc,
    entity name asc for a fully deterministic tie-break). Deliberately
    simple, stated ranking -- never a weighted/blended score -- same
    posture as every other ranking/classification step in this repo.
    """
    return sorted(
        profiles.values(),
        key=lambda p: (
            -_index(p["highest_risk"], RISK_ORDER),
            -_index(p["highest_confidence"], CONFIDENCE_ORDER),
            -p["record_count"],
            p["entity"],
        ),
    )


def report_summary(ranked):
    """ranked (from rank_profiles) -> the top-level counts block: how
    many entities at each risk level, and the top 5 entities by the
    same ranking (a Decision Engine's own likely first read -- "what
    needs attention first").
    """
    risk_counts = {r: 0 for r in RISK_ORDER}
    multi_source_count = 0
    for p in ranked:
        risk_counts[p["highest_risk"]] = risk_counts.get(p["highest_risk"], 0) + 1
        if len(p["source_modules"]) > 1:
            multi_source_count += 1
    return {
        "entity_count": len(ranked),
        "risk_counts": risk_counts,
        "multi_source_entity_count": multi_source_count,
        "top_entities": [
            {
                "entity": p["entity"],
                "entity_type": p["entity_type"],
                "risk": p["highest_risk"],
                "confidence": p["highest_confidence"],
                "source_modules": p["source_modules"],
            }
            for p in ranked[:5]
        ],
    }
