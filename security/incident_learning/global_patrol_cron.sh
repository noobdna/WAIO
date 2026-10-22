#!/bin/bash
set -uo pipefail

# security/incident_learning/global_patrol_cron.sh -- WAIO Global Cyber
# Intelligence Patrol: a 72-hour scheduled entry point that sits ON TOP
# OF the existing Incident Learning Engine, not beside/instead of it.
#
# Explicit scope decided before implementation (user-approved design):
#   1. Reuse every existing real Collector
#      (cisa_kev_collector.sh/ghsa_collector.sh/cisa_advisories_collector.sh/
#      jpcert_collector.sh/cert_ee_collector.sh) and the full existing
#      Collect->Normalize->Verify->Analyze->Correlate->Score pipeline
#      (incident_learning_cron.sh) exactly as-is -- zero new external
#      sources, zero changes to the classification engine, state
#      machine, Decision Engine, or Human Gate.
#   2. Add a NEW, INDEPENDENT 72-hour schedule (this file) that:
#        a. invokes incident_learning_cron.sh (collection), never
#           aborting on its failure (same "log and continue" posture
#           that file's own header already documents for each of ITS
#           internal steps -- this file just applies the same posture
#           one layer up);
#        b. diffs the current candidate set against the PREVIOUS
#           patrol's own recorded snapshot (security/incident_learning/
#           global_patrol_report.py, Step 3b below) to find what's
#           genuinely NEW since last patrol ("新規情報を優先する");
#        c. writes a human-readable Global Patrol report (JSON + MD)
#           under logs/ -- read-only reporting, no Dashboard change
#           this phase (explicit user decision, deferred).
#
# What this file NEVER does, by explicit design (same posture as
# incident_learning_cron.sh's own "what this file never does" section):
# it never calls knowledge_manager.sh's `approve`/`reject`/`hold`/
# `release`/`promote`, never calls incident_human_gate.sh, never calls
# any Guardian tool (guardian.sh/guardian_intervene_wrapper.sh/
# guardian_intervene_quarantine_wrapper.sh/guardian_release_agent.sh/
# guardian_approve.sh/ducopa.sh), never calls recovery_engine.sh or
# recover.sh, and never calls decision_engine.sh/decision_engine_lib.py.
# The "WAIO連携評価" (WAIO assessment) section of the generated report
# is a STATIC, DESK-REVIEW mapping table (see global_patrol_report.py's
# own WAIO_ASSESSMENT_TABLE) -- a description of what WAIO's EXISTING
# modules COULD observe for a given incident category, never a claim
# that any attack was actually detected or contained by collecting
# public information about it. tests/global_patrol_cron_test.sh's own
# G-series asserts zero references to any of the tool names above,
# the same structural "recommends, never executes" guard
# tests/decision_engine_test.sh's own D5 already establishes for
# decision_engine.sh.
#
# INDEPENDENCE FROM THE EXISTING HOURLY SCHEDULE (explicit requirement):
# this file has its OWN lock directory
# (security/state/incident_learning/.global_patrol_cron.lock, DISTINCT
# from incident_learning_cron.sh's own
# security/state/incident_learning/.cron.lock) and its OWN launchd
# plist (com.waio.global-patrol.plist.example, Label
# com.waio.global-patrol, DISTINCT from com.waio.incident-learning).
# The two schedules can safely overlap in wall-clock time: if this
# file's call into incident_learning_cron.sh lands while the hourly
# schedule's own invocation of that SAME script is still running, that
# inner script's OWN lock (il_lock_acquire with MAX_WAIT_ITERATIONS=0,
# already proven under real concurrency by
# tests/incident_learning_lock_test.sh) makes the second caller's
# invocation a clean, already-tested no-op ("skipped: another ... run
# is already in progress", exit 0) -- not a new race this file
# introduces, just the existing fail-closed lock doing its job for a
# second caller. This file's own `run_pipeline` step below treats that
# exit-0-skip exactly the same as a real "ok": either way, this cycle's
# report is built from whatever candidates already exist at the time of
# the diff/report step, honestly reflecting the data available at that
# moment (never falsely claims this cycle re-collected everything).
#
# Not wired into the hourly schedule at all -- a human loads BOTH
# plists independently (com.waio.incident-learning.plist for the 1h
# collection schedule, com.waio.global-patrol.plist for this 72h
# report schedule). Removing/unloading one never affects the other.
#
# Meant to be run manually once first for verification (per explicit
# instruction), THEN loaded as a launchd LaunchAgent for unattended 72h
# operation -- see com.waio.global-patrol.plist.example's own header
# for the exact commands. A LaunchAgent plist placed under
# ~/Library/LaunchAgents is auto-loaded by launchd at every user login
# (the same mechanism com.waio.incident-learning.plist already relies
# on in this deployment) -- this is what gives the 72h schedule
# reboot/logout-survival without any change to this script itself;
# this script has no code path of its own that could "remember" to
# restart itself after a reboot, by design (same as every other
# launchd-driven *_cron.sh wrapper in this repo).

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$SCRIPT_DIR"
source security/incident_learning/lock.sh

LOG_FILE="${GLOBAL_PATROL_LOG:-logs/global-patrol-cron.log}"
mkdir -p "$(dirname "$LOG_FILE")"

log() {
  printf '%s %s\n' "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" "$1" >>"$LOG_FILE"
}

# Own, independent lock -- see header. Fail-closed (MAX_WAIT_ITERATIONS=0,
# same posture as incident_learning_cron.sh's own CRON_LOCK_DIR): a
# second invocation (a manual re-run landing on top of a still-running
# scheduled one, or a launchd re-fire before the previous run finished)
# skips cleanly rather than racing the first.
LOCK_DIR="${GLOBAL_PATROL_LOCK_DIR:-security/state/incident_learning/.global_patrol_cron.lock}"
mkdir -p "$(dirname "$LOCK_DIR")" 2>/dev/null || true

if ! il_lock_acquire "$LOCK_DIR" 0; then
  log "skipped: another global_patrol_cron.sh run is already in progress (lock held at $LOCK_DIR)"
  exit 0
fi
# Single combined trap: LEVELS_TMP is assigned AFTER this trap is set,
# but the trap string is single-quoted (expanded at EXIT time, not
# here), so it still cleans up correctly -- same idiom
# incident_learning_cron.sh's own trap already uses for CRON_LOCK_DIR.
trap 'rm -f "${LEVELS_TMP:-}" 2>/dev/null; il_lock_release "$LOCK_DIR"' EXIT

log "run start"

# --- Step A: collection (reuse the existing, unmodified pipeline) ---
# Overridable only for test isolation (GLOBAL_PATROL_PIPELINE_SCRIPT);
# a real deployment never sets it and always runs the real
# incident_learning_cron.sh.
PIPELINE_SCRIPT="${GLOBAL_PATROL_PIPELINE_SCRIPT:-security/incident_learning/incident_learning_cron.sh}"
PIPELINE_STATUS="ok"
if bash "$PIPELINE_SCRIPT" >>"$LOG_FILE" 2>&1; then
  log "$PIPELINE_SCRIPT: ok"
else
  PIPELINE_STATUS="degraded"
  log "$PIPELINE_SCRIPT: exited non-zero (collection degraded this cycle -- report will note this; next scheduled run is NOT blocked by this failure)"
fi

# --- Step B: derive each candidate's confidence_level via the ONE
# canonical, already-reviewed derivation (knowledge_manager.sh's own
# candidate_confidence_level) -- never re-implemented here, to avoid
# two independent copies of the UNVERIFIED/LOW/MEDIUM/HIGH/CONFIRMED
# threshold logic drifting apart over time. Sourced in a subshell so
# this file's own environment/traps are untouched by it. ---
CANDIDATES_DIR="${KNOWLEDGE_MANAGER_STATE_DIR:-security/state/incident_learning/candidates}"
LEVELS_TMP="$(mktemp "${TMPDIR:-/tmp}/waio-global-patrol-levels.XXXXXX.json")"
(
  source security/incident_learning/knowledge_manager.sh
  printf '{'
  first=1
  for f in "$CANDIDATES_DIR"/*.json; do
    [ -e "$f" ] || continue
    id="$(basename "$f" .json)"
    level="$(candidate_confidence_level "$id" 2>/dev/null)" || level="UNVERIFIED"
    [ "$first" -eq 1 ] && first=0 || printf ','
    printf '"%s":"%s"' "$id" "$level"
  done
  printf '}'
) >"$LEVELS_TMP" 2>>"$LOG_FILE"

# --- Step C: diff against the previous patrol + render the report.
# All read/write of security/state/incident_learning/patrol/last_patrol.json
# and logs/global-patrol-report-*.{json,md} happens inside this one
# script -- see its own header for the all-or-nothing commit contract. ---
STATE_FILE="${GLOBAL_PATROL_STATE_FILE:-security/state/incident_learning/patrol/last_patrol.json}"
OUTPUT_DIR="${GLOBAL_PATROL_OUTPUT_DIR:-logs}"
mkdir -p "$(dirname "$STATE_FILE")" "$OUTPUT_DIR"

GENERATED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

if python3 security/incident_learning/global_patrol_report.py \
    "$CANDIDATES_DIR" "$STATE_FILE" "$OUTPUT_DIR" "$GENERATED_AT" "$LEVELS_TMP" "$PIPELINE_STATUS" \
    >>"$LOG_FILE" 2>&1; then
  log "global_patrol_report.py: ok"
else
  log "global_patrol_report.py: exited non-zero -- no report written and last_patrol.json NOT updated this cycle (all-or-nothing; previous snapshot preserved byte-for-byte, same posture as continuity.sh's own snapshot commit). Next scheduled run is NOT blocked by this failure."
fi

log "run end (Human Gate / Guardian / Decision Engine untouched -- this schedule is read-only reporting only)"
