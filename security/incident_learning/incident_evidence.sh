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
# This file's own job stops at VERIFIED (Phase 75 -- previously it
# advanced a fresh VERIFIED candidate straight to ANALYZED via a
# hardcoded placeholder, since incident_analyzer.sh did not yet exist;
# see that file's own header for the real VERIFIED->ANALYZED/REJECTED
# logic it now owns). A candidate already at VERIFIED (or anywhere
# later) is simply skipped here, not reprocessed -- see process_one's
# own skip check below.
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
#   evidence_corroborating_count  -- self-reported corroborating_sources
#                                     count PLUS cross-source matches (see
#                                     cross_source_corroboration_count
#                                     below); 0 if neither found anything
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
# Cross-source corroboration: a Collector's own self-reported
# corroborating_sources is a single Collector saying "I already knew of
# another source for this at collection time" -- it says nothing about
# two INDEPENDENT Collectors in this same pipeline both reporting the
# same CVE without either knowing about the other (e.g. a CISA KEV
# entry and a GHSA advisory for the same CVE id). That second kind of
# corroboration is something this pipeline can already see for itself,
# by comparing this candidate's own cve_list (populated by
# incident_normalizer.sh) against every other candidate's cve_list on
# disk: an overlap with a candidate from a DIFFERENT source is counted
# as one additional corroborating source -- counted per DISTINCT SOURCE,
# never per matching candidate id (see cross_source_corroboration_count's
# own header below for why that distinction is load-bearing: a single
# other source can legitimately have more than one matching candidate,
# e.g. two separate GHSA advisories for two CVEs chained together in one
# KEV entry, and must still only count once). Same "different source
# only, never let one talkative source count itself multiple times"
# rule incident_confidence.sh's own header already documents for the
# self-reported case applies here too, now enforced at the source-id
# level rather than the candidate-id level. This does NOT retroactively
# update a candidate that was already evidence-checked before the
# matching candidate existed -- record-evidence writes once, like every
# other field here; a candidate's evidence_* fields, once recorded, are
# never touched again by any later run (incident_evidence.sh's own
# process_one() only ever acts on a candidate currently at NORMALIZED --
# see its header below). Within a single incident_learning_cron.sh
# cycle this is a non-issue: every collector's output is fully collected
# and normalized (Step 1) BEFORE evidence-checking begins for any of
# them (Step 2), so two collectors that both ran THIS cycle always see
# each other regardless of which of them ran first (see that file's own
# COLLECTOR_ORDER for why the two real collectors' relative order is
# pinned anyway, for a different reason: ghsa_collector.sh's own lookup
# needs the CVE to already exist as a candidate). It only matters ACROSS
# cycles -- a candidate already REJECTED/CANDIDATE/etc. in an earlier
# cycle does not get re-scored just because a genuinely corroborating
# candidate from a different source shows up in a later cycle; reopening
# an already-decided candidate would be a real state-machine change
# (a new transition edge), deliberately out of scope here. Still zero
# network calls and zero new external dependency: this only reads state
# files already on disk in the same directory this file already
# resolves below.
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

# cross_source_corroboration_count ID STATE_FILE -- counts DISTINCT
# OTHER SOURCES (Collectors) that have at least one candidate sharing a
# CVE id with this candidate's own cve_list. Prints an integer >= 0.
# Zero whenever this candidate has no cve_list yet (e.g. hand-built
# fixtures that skip incident_normalizer.sh entirely) -- same "nothing
# to match" outcome as any other candidate with no CVEs extracted.
#
# Counts by DISTINCT SOURCE, not by distinct matching candidate id --
# closes a real double-counting gap: a candidate whose own cve_list has
# more than one CVE (e.g. a KEV entry describing a chained
# vulnerability, "this can be chained to achieve unauthenticated
# exploitation of CVE-...") can legitimately match MULTIPLE separate
# candidates from the very same OTHER collector (e.g. two distinct GHSA
# advisories, one per chained CVE). That is still only ONE independent
# source corroborating this incident, not two -- counting it twice
# would let a single source's own record-keeping shape (how many
# separate advisories it happens to split one incident across) silently
# inflate corroboration, the same class of gaming
# incident_confidence.sh's own header already rules out for a single
# self-reported source ("a single very talkative source can't be split
# into many corroborating entries").
cross_source_corroboration_count() {
  local this_id="$1" this_state_file="$2"
  python3 -c "
import glob, json, os, sys

state_dir, this_id, this_state_file = sys.argv[1:4]

def load(path):
    try:
        return json.load(open(path))
    except Exception:
        return None

this_d = load(this_state_file) or {}
this_cves = set(this_d.get('cve_list') or [])
this_source = this_d.get('source')

if not this_cves:
    print(0)
    sys.exit(0)

matching_sources = set()
for path in glob.glob(os.path.join(state_dir, '*.json')):
    other_id = os.path.splitext(os.path.basename(path))[0]
    if other_id == this_id:
        continue
    d = load(path)
    if d is None:
        continue
    other_source = d.get('source')
    if other_source == this_source:
        continue
    other_cves = set(d.get('cve_list') or [])
    if this_cves & other_cves:
        matching_sources.add(other_source)

print(len(matching_sources))
" "$KNOWLEDGE_STATE_DIR_RESOLVED" "$this_id" "$this_state_file"
}

# process_one ID -- evidence-check a single NORMALIZED candidate.
# Skips (no-op, logged) anything not currently at NORMALIZED -- this
# includes VERIFIED and everything later, since this file's own job
# (recording evidence) is already done at that point (Phase 75: a
# single write, NORMALIZED->VERIFIED only; no later resume branch is
# needed here any more -- see incident_analyzer.sh for what now owns
# VERIFIED->ANALYZED/REJECTED).
process_one() {
  local id="$1"
  local current
  current="$(km status "$id" 2>/dev/null)" || { echo "[EVIDENCE] ERROR: unknown candidate '$id'" >&2; return 1; }
  if [ "$current" != "NORMALIZED" ]; then
    echo "[EVIDENCE] $id: skipping (status=$current, not NORMALIZED)"
    return 0
  fi

  local state_file="$KNOWLEDGE_STATE_DIR_RESOLVED/$id.json"
  local source_type source_url raw_text collected_at corroborating_count cross_source_count age_days self_reported reason

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
  cross_source_count="$(cross_source_corroboration_count "$id" "$state_file")"
  corroborating_count=$((corroborating_count + cross_source_count))

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

  reason="evidence recorded: source_type=$source_type, corroborating=$corroborating_count (self-reported=$((corroborating_count - cross_source_count)), cross-source=$cross_source_count), age_days=$age_days, self_reported_uncorroborated=$self_reported"

  km record-evidence "$id" "$reason" \
    "evidence_source_type=$source_type" \
    "evidence_corroborating_count=$corroborating_count" \
    "evidence_age_days=$age_days" \
    "evidence_self_reported_uncorroborated=$self_reported" >/dev/null

  echo "[EVIDENCE] $id: NORMALIZED -> VERIFIED ($reason)"
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
