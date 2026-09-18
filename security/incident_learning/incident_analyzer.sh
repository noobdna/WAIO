#!/bin/bash
set -uo pipefail

# security/incident_learning/incident_analyzer.sh -- Incident Learning
# Engine, Step 5 (formerly Step 3's own hardcoded placeholder --
# ARCHITECTURE.md Phase 74/75): VERIFIED -> ANALYZED, or VERIFIED ->
# REJECTED when this candidate duplicates (or is suspected of
# contaminating) an already-PROMOTED knowledge entry.
#
# Per knowledge_manager.sh's own header ("VERIFIED -> ANALYZED
# (incident_analyzer.sh: checked against existing knowledge)"), this
# file checks a VERIFIED candidate against security/knowledge/ (already-
# PROMOTED entries) ONLY -- never against other in-flight candidates
# still earlier in the pipeline. Checking against other candidates
# would mean two records describing the same real incident, collected
# around the same time, could reject each other depending purely on
# processing order; checking only against what has already survived
# the full human gate is a stable, order-independent target.
#
# "Duplicate of existing knowledge" (a legitimate REJECTED, not an
# error) is any of:
#   - at least one CVE id in common with a promoted entry's own cve_list
#   - at least one IOC in common with a promoted entry's own ioc_list
#   - the exact same source_url as a promoted entry (a second collection
#     of the same source, most likely re-fetched by a Collector that
#     doesn't yet dedupe on its own side)
# "Contamination suspected" is treated narrowly and literally, matching
# this pipeline's own "deliberately simple and fully auditable, never a
# black-box judgment call" posture (see incident_confidence.sh's own
# header): byte-identical raw_text to an already-promoted entry, which
# cannot be explained by two independent sources describing the same
# incident in their own words.
#
# A candidate matching none of the above reaches ANALYZED, with the
# audit reason stating exactly how many existing knowledge entries it
# was checked against (0 the first time this pipeline ever runs, same
# as every other auditable decision in this domain -- see
# incident_confidence.sh's own formula for the same "state the basis,
# not just the verdict" convention).
#
# Single write only (VERIFIED -> ANALYZED or VERIFIED -> REJECTED, never
# both) -- unlike incident_evidence.sh/incident_confidence.sh's own
# two-step stages, there is no crash window inside this file's own
# logic to make resumable: transition_allowed()'s VERIFIED->ANALYZED and
# VERIFIED->REJECTED edges were already legal advance targets before
# this file existed (knowledge_manager.sh unchanged this phase), and
# candidate_transition's own tmp+mv is what makes the one write atomic,
# the same guarantee every other writer in this domain already relies
# on.
#
# This file never reads/writes any Control Plane file (same DuCoPA
# boundary as every other file in this domain) and makes no network
# call -- it only reads this candidate's own state file and the
# already-local security/knowledge/*.json entries.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$SCRIPT_DIR"
KM_SCRIPT="security/incident_learning/knowledge_manager.sh"
km() { bash "$KM_SCRIPT" "$@"; }

KNOWLEDGE_STATE_DIR_RESOLVED="${KNOWLEDGE_MANAGER_STATE_DIR:-$SCRIPT_DIR/security/state/incident_learning/candidates}"
KNOWLEDGE_BASE_DIR_RESOLVED="${KNOWLEDGE_MANAGER_KNOWLEDGE_DIR:-$SCRIPT_DIR/security/knowledge}"

# find_duplicate STATE_FILE KNOWLEDGE_DIR -- prints one line,
# "<KIND><US><matched knowledge id><US><human-readable detail>" (<US> =
# \x1f, the same tag-separator convention security/lib.sh's
# validate_reason_strength already uses). KIND is CLEAN, DUPLICATE, or
# CONTAMINATION. Pure read, no side effects; a missing/unreadable
# knowledge file is skipped, not fatal (a partially-written file left
# by some unrelated process should never crash the analyzer -- it
# simply isn't matched against).
find_duplicate() {
  python3 -c "
import glob, json, os, sys

state_file, knowledge_dir = sys.argv[1], sys.argv[2]
US = '\x1f'

d = json.load(open(state_file))
cve_set = set(d.get('cve_list') or [])
ioc_set = set(d.get('ioc_list') or [])
source_url = d.get('source_url') or ''
raw_text = d.get('raw_text') or ''

for path in sorted(glob.glob(os.path.join(knowledge_dir, '*.json'))):
    try:
        k = json.load(open(path))
    except Exception:
        continue
    kid = k.get('id') or os.path.splitext(os.path.basename(path))[0]

    cve_overlap = cve_set & set(k.get('cve_list') or [])
    if cve_overlap:
        print(f'DUPLICATE{US}{kid}{US}CVE overlap: {sorted(cve_overlap)}')
        sys.exit(0)

    ioc_overlap = ioc_set & set(k.get('ioc_list') or [])
    if ioc_overlap:
        print(f'DUPLICATE{US}{kid}{US}IOC overlap: {sorted(ioc_overlap)}')
        sys.exit(0)

    if source_url and source_url == (k.get('source_url') or ''):
        print(f'DUPLICATE{US}{kid}{US}same source_url: {source_url}')
        sys.exit(0)

    if raw_text and raw_text == (k.get('raw_text') or ''):
        print(f'CONTAMINATION{US}{kid}{US}identical raw_text to an existing promoted entry')
        sys.exit(0)

print(f'CLEAN{US}{US}')
" "$1" "$2"
}

# process_one ID -- analyzes a single VERIFIED candidate. Skips (no-op,
# logged) anything not currently at VERIFIED -- including a candidate
# already ANALYZED/REJECTED by an earlier run, same "only act on the
# one status this stage owns" idiom incident_normalizer.sh established.
process_one() {
  local id="$1"
  local current
  current="$(km status "$id" 2>/dev/null)" || { echo "[ANALYZER] ERROR: unknown candidate '$id'" >&2; return 1; }
  if [ "$current" != "VERIFIED" ]; then
    echo "[ANALYZER] $id: skipping (status=$current, not VERIFIED)"
    return 0
  fi

  local state_file="$KNOWLEDGE_STATE_DIR_RESOLVED/$id.json"
  local result kind kid detail
  result="$(find_duplicate "$state_file" "$KNOWLEDGE_BASE_DIR_RESOLVED")"
  IFS=$'\x1f' read -r kind kid detail <<< "$result"

  case "$kind" in
    DUPLICATE)
      km advance "$id" REJECTED "duplicate of existing knowledge entry '$kid' ($detail)" >/dev/null
      echo "[ANALYZER] $id: REJECTED (duplicate of '$kid': $detail)"
      ;;
    CONTAMINATION)
      km advance "$id" REJECTED "contamination suspected: matches existing knowledge entry '$kid' ($detail)" >/dev/null
      echo "[ANALYZER] $id: REJECTED (contamination suspected against '$kid': $detail)"
      ;;
    *)
      local count
      count="$(find "$KNOWLEDGE_BASE_DIR_RESOLVED" -maxdepth 1 -name '*.json' 2>/dev/null | wc -l | tr -d ' ')"
      km advance "$id" ANALYZED "no duplicate/contamination found against $count existing knowledge entries" >/dev/null
      echo "[ANALYZER] $id: VERIFIED -> ANALYZED (checked against $count existing knowledge entries)"
      ;;
  esac
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
