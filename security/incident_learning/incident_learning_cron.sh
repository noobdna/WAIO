#!/bin/bash
set -uo pipefail

# security/incident_learning/incident_learning_cron.sh -- Incident
# Learning Engine, Step 6: scheduled entry point for the AUTOMATED
# portion of the pipeline only.
#
# Deliberately thin, same posture as security/segment_monitor_cron.sh
# (this file's own direct model -- see that file's header): it adds no
# new logic, only sequences already-reviewed, already-tested entry
# points and logs when it ran.
#
#   1. every security/incident_learning/collectors/*.sh (mock_collector.sh
#      and, since Phase 81, the first real Collector,
#      cisa_kev_collector.sh -- a future additional real Collector only
#      has to exist in that directory and conform to the Collector
#      contract documented in mock_collector.sh's own header to be
#      picked up here automatically, no change to this file required),
#      piped through incident_normalizer.sh -- COLLECTED -> NORMALIZED
#   2. incident_evidence.sh (no id argument: processes every
#      NORMALIZED candidate) -- NORMALIZED -> VERIFIED (or -> REJECTED
#      if unusable, i.e. no traceable source_url)
#   3. incident_analyzer.sh (no id argument: processes every VERIFIED
#      candidate) -- VERIFIED -> ANALYZED (or -> REJECTED if it
#      duplicates/contaminates an already-promoted knowledge entry;
#      Phase 75 -- previously incident_evidence.sh's own hardcoded
#      placeholder)
#   4. incident_confidence.sh (no id argument: processes every ANALYZED
#      candidate) -- ANALYZED -> SCORED -> CANDIDATE or REJECTED
#
# What this file NEVER does, on purpose (the entire point of Step 6
# being "automate only what was already safe to automate"): it never
# calls knowledge_manager.sh's `approve`, `reject`, `hold`, `release`,
# or `promote`, and never calls incident_human_gate.sh at all. Reaching
# CANDIDATE via this schedule is exactly as far as automation goes --
# per the Incident Learning Engine's own founding constraint
# ("自動学習＝無条件で自動採用にはするな" -- never auto-adopt without a
# gate), a human must still run incident_human_gate.sh review/approve/
# reject/hold by hand for every candidate this schedule produces.
# Nothing reachable from this file's own code path ever writes into
# security/knowledge/.
#
# Meant to be invoked periodically by a per-user launchd agent -- see
# security/incident_learning/com.waio.incident-learning.plist.example.
# Safe to also run by hand at any time; running it twice back-to-back
# (sequentially, one finishing before the next starts) is a no-op
# beyond repeating the same idempotent calls (mock_collector.sh's
# fixed ids are already-existing candidates the second time, so
# incident_normalizer.sh skips them; a candidate already past NORMALIZED/
# ANALYZED is likewise skipped by incident_evidence.sh/incident_confidence.sh --
# see each file's own idempotency notes). Running it a SECOND time
# while a FIRST run is still in progress is handled differently (Phase
# 78): the second invocation's own lock acquisition fails immediately
# and it exits 0 having done nothing, rather than racing the first.
#
# DuCoPA alignment (explicit, load-bearing, same as every other file in
# this domain): THIS FILE ITSELF never reads or writes
# security/egress_allowlist.conf, security/segments.conf, sshd_config,
# or any other Control Plane file -- it never sources security/lib.sh.
# Since Phase 81, one of the collector scripts it invokes as a
# subprocess (cisa_kev_collector.sh) does touch the Control Plane (a
# real, egress_check()-gated outbound fetch) -- a deliberate, reviewed
# exception scoped to that one file alone (see its own header), not a
# change to this wrapper's own boundary.
#
# Phase 78: this is the ONLY scheduled entry point into the whole
# pipeline (per the Phase 74 runtime-wiring audit), so a portable
# mkdir-based mutual-exclusion lock (security/incident_learning/lock.sh
# -- see that file's own header for why it is a standalone copy of
# security/lib.sh's own already-hardened primitive, not a `source
# security/lib.sh` call) now wraps this entire run. Overlapping
# invocations -- a launchd re-fire before the previous run finished, or
# an operator manually re-running this same script while the scheduled
# one is still going -- previously risked two loops both picking up
# the same candidate at the same status and racing to write it
# (candidate_transition's read-modify-write is not itself atomic across
# processes). A run that cannot acquire the lock immediately
# (MAX_WAIT_ITERATIONS=0, fail-closed, not fail-open -- see lock.sh's
# own header for why this deliberately differs from the audit log's
# own lock contract) logs that it skipped and exits 0 -- not an error,
# the expected outcome of a scheduled trigger landing on top of a
# still-running previous one.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$SCRIPT_DIR"
source security/incident_learning/lock.sh

LOG_FILE="${INCIDENT_LEARNING_CRON_LOG:-logs/incident-learning-cron.log}"
mkdir -p "$(dirname "$LOG_FILE")"

log() {
  printf '%s %s\n' "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" "$1" >>"$LOG_FILE"
}

# COLLECTORS_DIR: test-isolation override, same convention as every
# other env var in this domain (KNOWLEDGE_MANAGER_*, INCIDENT_LEARNING_
# CRON_LOCK_DIR above). Added alongside Phase 81's real (non-mock)
# Collector (security/incident_learning/collectors/cisa_kev_collector.sh)
# -- without this override, every test that invokes this wrapper end-to-
# end (tests/incident_learning_cron_test.sh, _lock_test.sh) would also
# invoke that real collector's own outbound network call, which is
# exactly the non-deterministic, network-dependent CI behavior every
# other suite in this repo goes out of its way to avoid. Unset (the
# default) resolves to the exact same real directory this has always
# been -- zero behavior change for a real deployment.
COLLECTORS_DIR="${INCIDENT_LEARNING_COLLECTORS_DIR:-security/incident_learning/collectors}"

CRON_LOCK_DIR="${INCIDENT_LEARNING_CRON_LOCK_DIR:-security/state/incident_learning/.cron.lock}"
mkdir -p "$(dirname "$CRON_LOCK_DIR")" 2>/dev/null || true

if ! il_lock_acquire "$CRON_LOCK_DIR" 0; then
  log "skipped: another incident_learning_cron.sh run is already in progress (lock held at $CRON_LOCK_DIR)"
  exit 0
fi
trap 'il_lock_release "$CRON_LOCK_DIR"' EXIT

log "run start"

collector_count=0
for collector in "$COLLECTORS_DIR"/*.sh; do
  [ -e "$collector" ] || continue
  collector_count=$((collector_count + 1))
  if bash "$collector" 2>>"$LOG_FILE" | bash security/incident_learning/incident_normalizer.sh >>"$LOG_FILE" 2>&1; then
    log "$(basename "$collector") | incident_normalizer.sh: ok"
  else
    log "$(basename "$collector") | incident_normalizer.sh: exited non-zero"
  fi
done
if [ "$collector_count" -eq 0 ]; then
  log "no collectors found under $COLLECTORS_DIR -- nothing to collect this run"
fi

if bash security/incident_learning/incident_evidence.sh >>"$LOG_FILE" 2>&1; then
  log "incident_evidence.sh: ok"
else
  log "incident_evidence.sh: exited non-zero"
fi

if bash security/incident_learning/incident_analyzer.sh >>"$LOG_FILE" 2>&1; then
  log "incident_analyzer.sh: ok"
else
  log "incident_analyzer.sh: exited non-zero"
fi

if bash security/incident_learning/incident_confidence.sh >>"$LOG_FILE" 2>&1; then
  log "incident_confidence.sh: ok"
else
  log "incident_confidence.sh: exited non-zero"
fi

log "run end (human gate untouched -- CANDIDATE/REJECTED candidates from this run still require a human via incident_human_gate.sh)"
