#!/bin/bash
set -uo pipefail

# security/segment_monitor_cron.sh -- Phase 51 (2026-09-02): scheduled
# entry point for the Segment Recovery MVP's detection side (Phase 49
# left this "invoked on a timer" question explicitly for a future
# phase -- see security/health_checker.sh's own header).
#
# Deliberately thin: adds no new logic. It only calls two
# already-reviewed, already-tested entry points in sequence and logs
# when it ran:
#   1. security/health_checker.sh monitor-all -- detection only. Drives
#      at most the normal<->suspicious<->isolated edges of the
#      Incident State Machine; never invokes recovery_engine.sh, never
#      runs with --execute, never mutates a remote host.
#   2. dashboard/collect_segment_status.sh -- read-only snapshot
#      (logs/waio-segments-latest.json) for the Dashboard.
# No recovery action is ever triggered automatically by this schedule.
#
# Meant to be invoked periodically by a per-user launchd agent -- see
# security/com.waio.segment-monitor.plist.example. Safe to also run by
# hand at any time; running it twice back-to-back is a no-op beyond
# repeating the same two idempotent calls.
#
# Never touches SND_HOME or Takomachi -- both are independent projects
# (see SND_HOME's own CLAUDE.md, "混在させない"). This script only runs
# WAIO's own existing segment scripts against WAIO's own
# security/segments.conf.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"

LOG_FILE="${SEGMENT_MONITOR_CRON_LOG:-logs/segment-monitor-cron.log}"
mkdir -p "$(dirname "$LOG_FILE")"

log() {
  printf '%s %s\n' "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" "$1" >>"$LOG_FILE"
}

log "run start"

if ./security/health_checker.sh monitor-all >>"$LOG_FILE" 2>&1; then
  log "health_checker.sh monitor-all: ok"
else
  log "health_checker.sh monitor-all: exited non-zero (expected when a segment is unreachable; see the Incident State Machine, not a script error)"
fi

if ./dashboard/collect_segment_status.sh >>"$LOG_FILE" 2>&1; then
  log "collect_segment_status.sh: ok"
else
  log "collect_segment_status.sh: FAILED"
fi

log "run end"
