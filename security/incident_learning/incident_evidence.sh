#!/bin/bash
set -uo pipefail

# security/incident_learning/incident_evidence.sh -- Incident Learning
# Engine, Step 3 (part 1): NORMALIZED -> VERIFIED.
#
# "Verified" here means "this candidate's own evidence has been
# examined and recorded" -- it does NOT mean "confirmed true". A
# single-source, uncorroborated claim still reaches VERIFIED (its
# evidence is simply weak); incident_confidence.sh (Step 3 part 2) is
# what turns weak evidence into a low score, and knowledge_manager.sh's
# own SCORED->REJECTED edge is what stops a low-confidence candidate
# from ever reaching a human. This file's only rejection path is
# "there is no source to trace at all" (see below) -- a categorically
# different problem from "the source is weak".
#
# Evidence recorded per candidate (folded into the state file via
# knowledge_manager.sh's own `record-evidence` command -- final-audit
# fix: this used to go through `advance`'s generic KEY=VALUE mechanism,
# which meant nothing stopped a direct `advance ID VERIFIED ...
# evidence_corroborating_count=99` call from forging these fields and
# bypassing this file's own computation entirely; `record-evidence` is
# a dedicated verb, mirroring `score`'s existing separation from
# `advance` for confidence_score, and whitelists exactly these four
# field names):
#   evidence_source_type          -- copied from the candidate's own source_type
#   evidence_corroborating_count  -- len(corroborating_sources), 0 if the
#                                     Collector didn't report any
#   evidence_age_days             -- days between collected_at and now
#   evidence_self_reported_uncorroborated -- true if the raw text itself
#                                     contains phrases like "single
#                                     source" / "no corroboration" /
#                                     "unverified" -- a Collector's own
#                                     raw text sometimes already flags
#                                     this; treated as a signal toward
#                                     LOWER confidence, on the theory
#                                     that content designed to look
#                                     authoritative rarely undercuts
#                                     itself this way, so take it at
#                                     face value rather than discard it
#
# NORMALIZED -> REJECTED only when source_url is empty/missing: a
# candidate with literally no traceable source can never be verified
# against anything, regardless of how it scores otherwise (design
# requirement: reject unusable evidence, don't let it slide through as
# merely "low confidence").
#
# This file never reads/writes any Control Plane file (same DuCoPA
# boundary as every other file in this domain) and makes no network
# call -- corroboration is currently limited to what the Collector
# itself already reported; fetching/verifying external corroborating
# URLs for real is out of scope until a real Collector exists to make
# that meaningful.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$SCRIPT_DIR"
KM_SCRIPT="security/incident_learning/knowledge_manager.sh"
km() { bash "$KM_SCRIPT" "$@"; }

# process_one ID -- evidence-check a single NORMALIZED candidate.
# Skips (no-op, logged) anything not currently at NORMALIZED or
# VERIFIED.
#
# Step 8 crash-recovery: this function makes two separate writes
# (NORMALIZED->VERIFIED, then VERIFIED->ANALYZED). A crash/kill between
# them used to strand a candidate at VERIFIED forever -- this function
# only ever accepted NORMALIZED, so no later run (this one included)
# would ever pick it back up, and incident_confidence.sh only accepts
# ANALYZED/SCORED, so it wouldn't either. process_one is now resumable:
# a candidate found already at VERIFIED skips straight to completing
# the second write (evidence fields were already computed and
# persisted by the interrupted run -- never recomputed a second time,
# both to avoid redundant work and so the exact same evidence that was
# actually recorded is what the pipeline completes with).
process_one() {
  local id="$1"
  local current
  current="$(km status "$id" 2>/dev/null)" || { echo "[EVIDENCE] ERROR: unknown candidate '$id'" >&2; return 1; }
  if [ "$current" != "NORMALIZED" ] && [ "$current" != "VERIFIED" ]; then
    echo "[EVIDENCE] $id: skipping (status=$current, not NORMALIZED/VERIFIED)"
    return 0
  fi

  local state_file="$KNOWLEDGE_STATE_DIR_RESOLVED/$id.json"
  local reason="resuming from VERIFIED (evidence already recorded by an earlier, interrupted run)"

  if [ "$current" = "NORMALIZED" ]; then
    local source_type source_url raw_text collected_at corroborating_count age_days self_reported

    source_type="$(python3 -c "import json; print(json.load(open('$state_file')).get('source_type','unknown'))")"
    source_url="$(python3 -c "import json; print(json.load(open('$state_file')).get('source_url',''))")"
    raw_text="$(python3 -c "import json; print(json.load(open('$state_file')).get('raw_text',''))")"
    collected_at="$(python3 -c "import json; print(json.load(open('$state_file')).get('collected_at','') or json.load(open('$state_file')).get('created_at',''))")"

    if [ -z "$source_url" ]; then
      # NOT `km reject` -- that CLI verb is reserved for an actual human
      # decision (event human_rejected/action human_gate, per
      # knowledge_manager.sh's own header) and this is an automated
      # pipeline decision with no human involved, same category as
      # incident_confidence.sh's own low-confidence auto-reject. `km
      # advance ... REJECTED` logs it as event=advanced/action=pipeline
      # instead, so the audit trail never mislabels an automated
      # rejection as a human one (see tests/incident_learning_cron_test.sh's
      # CR6 for why this distinction is load-bearing: Step 6's cron
      # wrapper must be provably human-gate-free).
      km advance "$id" REJECTED "no usable evidence: source_url is empty -- candidate has no traceable source" >/dev/null
      echo "[EVIDENCE] $id: REJECTED (no source_url)"
      return 0
    fi

    corroborating_count="$(python3 -c "import json; print(len(json.load(open('$state_file')).get('corroborating_sources', []) or []))")"

    age_days="$(python3 -c "
import sys
from datetime import datetime, timezone
collected = sys.argv[1]
try:
    dt = datetime.strptime(collected, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    print((now - dt).days)
except Exception:
    print(0)
" "$collected_at")"

    self_reported="$(python3 -c "
import re, sys
raw = sys.argv[1].lower()
flags = ['single source', 'no corroboration', 'unverified', 'no vendor confirmation']
print('true' if any(f in raw for f in flags) else 'false')
" "$raw_text")"

    reason="evidence recorded: source_type=$source_type, corroborating=$corroborating_count, age_days=$age_days, self_reported_uncorroborated=$self_reported"

    km record-evidence "$id" "$reason" \
      "evidence_source_type=$source_type" \
      "evidence_corroborating_count=$corroborating_count" \
      "evidence_age_days=$age_days" \
      "evidence_self_reported_uncorroborated=$self_reported" >/dev/null
  fi

  # Placeholder for VERIFIED -> ANALYZED: real duplicate/pattern
  # analysis against existing security/knowledge/ entries is
  # incident_analyzer.sh's own job (not yet implemented). Advancing
  # here immediately, with an explicitly labeled placeholder reason (not
  # a real analysis claim), keeps the pipeline runnable end-to-end
  # today without pretending analysis happened -- both the audit log
  # and this comment say plainly that it didn't. Reached either right
  # after the VERIFIED write above (fresh run) or directly on entry
  # (resuming from a previously-completed VERIFIED write) -- either
  # way this is the only remaining step.
  km advance "$id" ANALYZED "placeholder: no duplicate/pattern analysis implemented yet (incident_analyzer.sh, not yet implemented)" >/dev/null

  echo "[EVIDENCE] $id: VERIFIED -> ANALYZED ($reason)"
}

# Resolve the same state dir knowledge_manager.sh itself would use, so
# this file can read a candidate's JSON directly (faster than shelling
# out to `km status`/a hypothetical `km get-field` for every field) --
# kept as a single override-aware resolution, not hardcoded, so this
# file honors KNOWLEDGE_MANAGER_STATE_DIR exactly like knowledge_manager.sh
# does when a test suite overrides it.
KNOWLEDGE_STATE_DIR_RESOLVED="${KNOWLEDGE_MANAGER_STATE_DIR:-$SCRIPT_DIR/security/state/incident_learning/candidates}"

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
