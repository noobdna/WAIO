"""security/red_alert/snd_crossref.py -- read-only, pure-function
comparison between PDC's last committed SND@HOME snapshot
(security/continuity.sh's own `snd-get`, Phase 88, unmodified) and the
current set of Global Patrol / Critical Infra Watch entities. Implements
WAIO GLOBAL RED ALERT requirement #3 ("read-only comparison against
SND@HOME observations").

SCOPE, STATED NARROWLY: this module never calls `security/continuity.sh`
itself, makes no network call, and has no subprocess/os.system/os.popen of
its own (same "pure function of its arguments" convention as every other
_lib.py in this pipeline, and the same `D2b`-class static guarantee
decision_engine_lib.py/global_patrol_report.py/critical_infra_watch.py
already each prove in their own suites). Its caller (red_alert_cron.sh)
is responsible for reading `security/continuity.sh snd-get`'s own stdout
(JSON or nothing) and handing the parsed dict (or None) to
`build_crossref_signals()` below.

WHAT THIS MODULE ACTUALLY DOES: a SIMPLE, CASE-INSENSITIVE KEYWORD MATCH
between whatever text SND@HOME's own snapshot contains (its `active_alerts`/
`lan_status`/`system_status`/`terminals` sections -- note: SND@HOME's own
exact internal field shapes are NOT independently verifiable from this
repo, per ARCHITECTURE.md Phase 88's own finding that SND@HOME's source
is not present on this machine; this module therefore never assumes a
specific nested key exists, and instead flattens each section to its own
JSON text for matching, defensively, against malformed/unexpected input)
and each Global Patrol/Critical Infra Watch entity's own `attack_pattern`/
`incident_type`/`affected_sector`/`critical_sectors` keywords.

A MATCH IS NEVER A CLAIM OF A REAL RELATIONSHIP. Every signal this module
emits carries a mandatory, non-empty `confidence_caveat` stating plainly
that this is a textual keyword co-occurrence only, not a verified causal,
network, or geographic relationship between the local SND@HOME observation
and the global finding -- same "pair every claim with an alternative
explanation" posture Critical Infra Watch's own precursor_hypotheses
already established (ARCHITECTURE.md Phase 101 Section 2). No numeric
probability/likelihood/percent/eta key exists anywhere in this module's
output (verified by tests/red_alert_test.sh's own recursive scan, same
technique as Critical Infra Watch's own S2).

If no SND@HOME snapshot is available, `build_crossref_signals()` returns
an empty list -- never an error, never blocks the rest of a RED ALERT run
(same graceful-degradation posture dashboard/collect_snd_status.sh's own
header already states for itself).

No I/O in this module.
"""

import json


def _flatten_to_text(value):
    """Any JSON-shaped value -> one lowercase text blob for keyword
    matching. Defensive by construction: a dict/list is serialized via
    json.dumps (never assumes a specific key exists), a plain
    str/int/float/bool/None is stringified directly, and anything that
    fails to serialize contributes an empty string rather than raising --
    this module must never crash on SND@HOME's own (unverified) output
    shape.
    """
    if value is None:
        return ""
    if isinstance(value, str):
        return value.lower()
    try:
        return json.dumps(value, ensure_ascii=False).lower()
    except (TypeError, ValueError):
        return str(value).lower()


def _snd_sections(snd_status):
    """snd_status: the `snd_status` object inside `continuity.sh snd-get`'s
    own {'pdc_cached_at', 'snd_status'} envelope (dashboard/
    collect_snd_status.sh's own write_status() shape:
    lan_status/system_status/active_alerts/terminals). Returns
    {section_name: flattened_text}, skipping any section that is None
    (SND@HOME unavailable at the time that snapshot was taken) or absent.
    """
    if not isinstance(snd_status, dict):
        return {}
    sections = {}
    for name in ("active_alerts", "lan_status", "system_status", "terminals"):
        text = _flatten_to_text(snd_status.get(name))
        if text and text != "null":
            sections[name] = text
    return sections


def _entity_keywords(entity):
    """One Global Patrol/Critical Infra Watch entry or precursor
    hypothesis -> a sorted list of its own distinct, non-generic keyword
    strings to match against (attack_pattern/incident_type/
    affected_sector/critical_sectors only -- never raw_text/claimed_impact,
    so a match is always traceable to a specific classification field,
    never free-text noise). Generic sentinels ("unclassified", "unknown")
    are excluded -- matching against them would produce a meaningless
    universal match on almost any SND@HOME snapshot.
    """
    keywords = set()
    for key in ("attack_pattern", "incident_type", "affected_sector"):
        v = entity.get(key)
        if v and v not in ("unclassified", "unknown"):
            keywords.add(str(v).lower())
    for v in entity.get("critical_sectors") or []:
        if v and v not in ("unclassified", "unknown"):
            keywords.add(str(v).lower())
    return sorted(keywords)


def build_crossref_signals(snd_status, entities):
    """snd_status: the parsed `snd_status` dict from `continuity.sh
    snd-get` (or None if no snapshot exists yet / parsing failed --
    red_alert_cron.sh's job, not this function's). entities: a list of
    Global Patrol/Critical Infra Watch entries, each a dict carrying at
    least `id` and whichever of attack_pattern/incident_type/
    affected_sector/critical_sectors it has.

    Returns a list of signal dicts, one per (section, entity, keyword)
    match found:
      {
        "entity_id": entity's own id (so the caller can align this
          signal's eventual Intelligence Record to the SAME entity key
          the global finding itself uses -- see red_alert_adapter.py's
          own from_snd_crossref_signal() header for why that alignment
          matters),
        "snd_section": which SND@HOME section matched
          (active_alerts/lan_status/system_status/terminals),
        "match_keyword": the specific keyword string that matched,
        "confidence_caveat": mandatory, non-empty, explaining this is a
          textual match only.
      }
    Never returns a numeric field of any kind.
    """
    if not snd_status:
        return []
    sections = _snd_sections(snd_status)
    if not sections:
        return []

    signals = []
    for entity in entities:
        entity_id = entity.get("id")
        if not entity_id:
            continue
        for keyword in _entity_keywords(entity):
            for section_name, section_text in sections.items():
                if keyword in section_text:
                    signals.append({
                        "entity_id": entity_id,
                        "snd_section": section_name,
                        "match_keyword": keyword,
                        "confidence_caveat": (
                            f"textual keyword match only ('{keyword}' found in "
                            f"SND@HOME's own {section_name} snapshot text) -- "
                            "this is NOT a verified causal, network, or "
                            "geographic relationship between the local "
                            "SND@HOME observation and this global finding; a "
                            "human must independently confirm any real "
                            "connection before acting on it."
                        ),
                    })
    return signals
