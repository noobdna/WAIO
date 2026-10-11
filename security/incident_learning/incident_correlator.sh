#!/bin/bash
set -uo pipefail

# security/incident_learning/incident_correlator.sh -- Incident
# Learning Engine, Correlate step (Phase 98: Global Incident
# Intelligence & Auto-Learning). Scans every non-terminal candidate's
# own attack_pattern (incident_normalizer.sh's own deterministic
# correlation key, set at NORMALIZED) against every OTHER candidate and
# every already-PROMOTED security/knowledge/ entry, and records the
# matches as related_incidents -- the mechanism that lets WAIO notice
# "the same kind of attack is showing up across multiple companies/
# countries/sources", per this phase's own design goal.
#
# This is deliberately NOT a state-machine stage: it never advances,
# never rejects, never touches status at all -- see
# knowledge_manager.sh's own candidate_annotate() header for why
# correlation has no natural (FROM, TO) transition edge to attach to.
# It writes exactly one field (related_incidents) via the new `km
# annotate` verb, which is reserved (knowledge_manager.sh's own
# _km_reserved_field_violation) against every other write path -- a
# Collector or any other pipeline stage cannot forge this field.
#
# Scope / what counts as "related": two records sharing the exact same
# attack_pattern string (incident_type + its own attack_vector_list/
# ttp_list, see incident_normalizer.sh's own header), excluding:
#   - the record matching itself
#   - the generic 'unclassified' sentinel (and any bare incident_type
#     with no attack_vector_list/ttp_list contribution at all) -- every
#     uncategorized incident sharing a single catch-all label would
#     otherwise "correlate" with every other one, which is noise, not
#     signal
#   - another record from the exact same source AND same source_url
#     (that is the same incident re-collected, incident_analyzer.sh's
#     own duplicate-detection job, not a second independent sighting of
#     the same pattern)
# This is a correlation of PATTERN, not of truth: two UNVERIFIED,
# single-source reports sharing an attack_pattern are still listed as
# related to each other -- related_incidents is descriptive context
# for a human reviewer (and for this pipeline's own future pattern-
# learning use), never a confidence or verification signal by itself.
# Nothing here changes confidence_score or evidence_* in any way.
#
# Only candidates NOT currently PROMOTED or REJECTED are updated
# (candidate_annotate's own terminal-state refusal) -- but EVERY
# candidate/knowledge file, any status, is still read as a potential
# MATCH target, so a fresh CANDIDATE can correlate against an entry
# that was already PROMOTED weeks ago. Safe to re-run every cron cycle:
# related_incidents is simply recomputed and re-written each time (not
# a "write once" field like evidence_*/confidence_score), so a
# candidate's own correlation picture stays current as new incidents
# arrive -- see candidate_annotate's own header for why repeated
# annotate calls are normal, expected usage here, not a hazard.
#
# This file never reads/writes any Control Plane file (same DuCoPA
# boundary as every other file in this domain) and makes no network
# call -- it only reads already-local candidate/knowledge state files
# already on disk.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$SCRIPT_DIR"
KM_SCRIPT="security/incident_learning/knowledge_manager.sh"
km() { bash "$KM_SCRIPT" "$@"; }

KNOWLEDGE_STATE_DIR_RESOLVED="${KNOWLEDGE_MANAGER_STATE_DIR:-$SCRIPT_DIR/security/state/incident_learning/candidates}"
KNOWLEDGE_BASE_DIR_RESOLVED="${KNOWLEDGE_MANAGER_KNOWLEDGE_DIR:-$SCRIPT_DIR/security/knowledge}"

# find_related ID STATE_FILE CANDIDATES_DIR KNOWLEDGE_DIR -- prints a
# JSON array of matching ids (sorted, deduplicated), or "[]" if this
# candidate's own attack_pattern is empty/missing/a bare catch-all
# with nothing to correlate on. Pure read, no side effects.
find_related() {
  python3 -c "
import glob, json, os, sys

this_id, this_state_file, candidates_dir, knowledge_dir = sys.argv[1:5]

def load(path):
    try:
        return json.load(open(path))
    except Exception:
        return None

this_d = load(this_state_file) or {}
pattern = this_d.get('attack_pattern') or ''
this_source = this_d.get('source')
this_source_url = this_d.get('source_url') or ''

# 'unclassified' (bare, no attack_vector_list/ttp_list contribution)
# is the correlation-engine's own catch-all sentinel -- see
# incident_normalizer.sh's own attack_pattern header. Any OTHER
# incident_type value standing alone (e.g. a lone 'data_breach' with
# no attack_vector_list match) is still a meaningful, specific-enough
# signal to correlate on.
if not pattern or pattern == 'unclassified':
    print('[]')
    sys.exit(0)

related = set()
for base_dir in (candidates_dir, knowledge_dir):
    for path in sorted(glob.glob(os.path.join(base_dir, '*.json'))):
        other_id = os.path.splitext(os.path.basename(path))[0]
        if other_id == this_id:
            continue
        d = load(path)
        if d is None:
            continue
        if (d.get('attack_pattern') or '') != pattern:
            continue
        other_source = d.get('source')
        other_source_url = d.get('source_url') or ''
        if other_source == this_source and this_source_url and other_source_url == this_source_url:
            continue
        related.add(d.get('id') or other_id)

print(json.dumps(sorted(related)))
" "$1" "$2" "$3" "$4"
}

# process_one ID -- correlates a single candidate. Skips (no audit
# noise beyond the skip line itself) a terminal candidate (PROMOTED/
# REJECTED) -- candidate_annotate would refuse it anyway; checked here
# too so the log reads clearly instead of surfacing annotate's own
# error text for an entirely expected, routine case.
process_one() {
  local id="$1"
  local current
  current="$(km status "$id" 2>/dev/null)" || { echo "[CORRELATOR] ERROR: unknown candidate '$id'" >&2; return 1; }
  case "$current" in
    PROMOTED|REJECTED)
      echo "[CORRELATOR] $id: skipping (status=$current, terminal -- not annotatable)"
      return 0
      ;;
  esac

  local state_file="$KNOWLEDGE_STATE_DIR_RESOLVED/$id.json"
  local related_json count
  related_json="$(find_related "$id" "$state_file" "$KNOWLEDGE_STATE_DIR_RESOLVED" "$KNOWLEDGE_BASE_DIR_RESOLVED")"
  count="$(python3 -c "import json,sys; print(len(json.loads(sys.argv[1])))" "$related_json")"

  if [ "$count" -eq 0 ]; then
    echo "[CORRELATOR] $id: no related incidents found (attack_pattern empty/unclassified, or no match)"
    return 0
  fi

  km annotate "$id" "correlated: $count related incident(s) sharing the same attack_pattern" \
    "related_incidents=$related_json" >/dev/null
  echo "[CORRELATOR] $id: related_incidents=$related_json"
}

if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
  if [ -n "${1:-}" ]; then
    process_one "$1"
  else
    for f in "$KNOWLEDGE_STATE_DIR_RESOLVED"/*.json; do
      [ -e "$f" ] || continue
      process_one "$(basename "$f" .json)"
    done
  fi
fi
