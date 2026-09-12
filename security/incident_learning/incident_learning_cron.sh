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
#   1. every security/incident_learning/collectors/*.sh (currently just
#      mock_collector.sh; a future real Collector -- CISA KEV/CERT/NVD/
#      vendor advisory -- only has to exist in that directory and
#      conform to the Collector contract documented in
#      mock_collector.sh's own header to be picked up here automatically,
#      no change to this file required), piped through
#      incident_normalizer.sh -- COLLECTED -> NORMALIZED
#   2. incident_evidence.sh (no id argument: processes every
#      NORMALIZED candidate) -- NORMALIZED -> VERIFIED -> ANALYZED (or
#      -> REJECTED if unusable)
#   3. incident_confidence.sh (no id argument: processes every ANALYZED
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
# is a no-op beyond repeating the same idempotent calls (mock_collector.sh's
# fixed ids are already-existing candidates the second time, so
# incident_normalizer.sh skips them; a candidate already past NORMALIZED/
# ANALYZED is likewise skipped by incident_evidence.sh/incident_confidence.sh --
# see each file's own idempotency notes).
#
# DuCoPA alignment (explicit, load-bearing, same as every other file in
# this domain): never reads or writes security/egress_allowlist.conf,
# security/segments.conf, sshd_config, or any other Control Plane file.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$SCRIPT_DIR"

LOG_FILE="${INCIDENT_LEARNING_CRON_LOG:-logs/incident-learning-cron.log}"
mkdir -p "$(dirname "$LOG_FILE")"

log() {
  printf '%s %s\n' "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" "$1" >>"$LOG_FILE"
}

log "run start"

collector_count=0
for collector in security/incident_learning/collectors/*.sh; do
  [ -e "$collector" ] || continue
  collector_count=$((collector_count + 1))
  if bash "$collector" 2>>"$LOG_FILE" | bash security/incident_learning/incident_normalizer.sh >>"$LOG_FILE" 2>&1; then
    log "$(basename "$collector") | incident_normalizer.sh: ok"
  else
    log "$(basename "$collector") | incident_normalizer.sh: exited non-zero"
  fi
done
if [ "$collector_count" -eq 0 ]; then
  log "no collectors found under security/incident_learning/collectors/ -- nothing to collect this run"
fi

if bash security/incident_learning/incident_evidence.sh >>"$LOG_FILE" 2>&1; then
  log "incident_evidence.sh: ok"
else
  log "incident_evidence.sh: exited non-zero"
fi

if bash security/incident_learning/incident_confidence.sh >>"$LOG_FILE" 2>&1; then
  log "incident_confidence.sh: ok"
else
  log "incident_confidence.sh: exited non-zero"
fi

log "run end (human gate untouched -- CANDIDATE/REJECTED candidates from this run still require a human via incident_human_gate.sh)"
