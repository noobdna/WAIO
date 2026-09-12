#!/bin/bash
set -uo pipefail

# security/incident_learning/incident_confidence.sh -- Incident
# Learning Engine, Step 3 (part 2): ANALYZED -> SCORED -> CANDIDATE or
# REJECTED (the SCORED->CANDIDATE/REJECTED split itself already lives
# in knowledge_manager.sh's own `score` command -- this file only
# computes the number that decides which way it goes).
#
# Confidence formula (0-100, clamped), built entirely from
# incident_evidence.sh's own recorded fields -- no new data is fetched
# here:
#   + source credibility base weight:
#       vendor_advisory=40, cert=35, news=20, unknown=5
#   + corroboration bonus: +15 per corroborating source, capped at +30
#     (i.e. 2 corroborating sources already gets the full bonus --
#     a 3rd doesn't count for more, so a single very talkative
#     "source" can't be split into many corroborating entries to
#     game this)
#   - staleness penalty: -25 if evidence_age_days > 30 (an incident
#     reported a month ago is not necessarily wrong, but WAIO's own
#     detection value from it has already had a month to either matter
#     or not -- treated as a confidence reducer, not a rejection)
#   - self-reported-uncorroborated penalty: -20 if
#     evidence_self_reported_uncorroborated=true (the source's own
#     text already flags itself as unverified/single-source/no
#     confirmation -- taken at face value, per incident_evidence.sh's
#     own header)
#
# This is deliberately simple and fully auditable (every input term is
# already sitting on the candidate's own state file, inspectable by a
# human) rather than a black-box model -- matching this repo's existing
# "no automated component confirms its own trust without a traceable
# reason" posture (segment_manager.sh's audit trail, recovery_engine.sh's
# escalate_to_human, etc.).
#
# KNOWLEDGE_MIN_CONFIDENCE (default 50, same default as
# knowledge_manager.sh's own `score` command) decides SCORED->CANDIDATE
# vs SCORED->REJECTED; this file does not duplicate that threshold
# logic, it only computes the confidence_score value and hands it to
# `knowledge_manager.sh score`, which owns the threshold decision.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$SCRIPT_DIR"
KM_SCRIPT="security/incident_learning/knowledge_manager.sh"
km() { bash "$KM_SCRIPT" "$@"; }

KNOWLEDGE_STATE_DIR_RESOLVED="${KNOWLEDGE_MANAGER_STATE_DIR:-$SCRIPT_DIR/security/state/incident_learning/candidates}"

# compute_confidence STATE_FILE -- prints an integer 0-100.
compute_confidence() {
  python3 -c "
import json, sys

d = json.load(open(sys.argv[1]))

WEIGHTS = {'vendor_advisory': 40, 'cert': 35, 'news': 20, 'unknown': 5}
source_type = d.get('evidence_source_type', d.get('source_type', 'unknown'))
score = WEIGHTS.get(source_type, WEIGHTS['unknown'])

corroborating = d.get('evidence_corroborating_count', 0) or 0
score += min(corroborating, 2) * 15

age_days = d.get('evidence_age_days', 0) or 0
if age_days > 30:
    score -= 25

if d.get('evidence_self_reported_uncorroborated') in (True, 'true', 'True'):
    score -= 20

score = max(0, min(100, score))
print(score)
" "$1"
}

process_one() {
  local id="$1"
  local current
  current="$(km status "$id" 2>/dev/null)" || { echo "[CONFIDENCE] ERROR: unknown candidate '$id'" >&2; return 1; }
  # Step 8 crash-recovery: `km score` itself is what makes ANALYZED->
  # SCORED->CANDIDATE/REJECTED resumable (see knowledge_manager.sh's
  # own header on the `score` command) -- a candidate crash-stranded at
  # SCORED (interrupted between the two writes) is passed through here
  # unchanged; `km score` detects SCORED on its own and completes only
  # the remaining threshold decision, using the confidence_score value
  # already recorded rather than a freshly recomputed one.
  if [ "$current" != "ANALYZED" ] && [ "$current" != "SCORED" ]; then
    echo "[CONFIDENCE] $id: skipping (status=$current, not ANALYZED/SCORED)"
    return 0
  fi

  local state_file="$KNOWLEDGE_STATE_DIR_RESOLVED/$id.json"
  local score
  if [ "$current" = "ANALYZED" ]; then
    score="$(compute_confidence "$state_file")"
  else
    score="$(python3 -c "import json; print(json.load(open('$state_file')).get('confidence_score', 0))")"
  fi

  km score "$id" "$score" >/dev/null
  echo "[CONFIDENCE] $id: score=$score -> $(km status "$id")"
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
