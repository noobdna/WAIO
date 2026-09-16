#!/bin/bash
set -uo pipefail

# dashboard/refresh_dashboard_cron.sh -- Phase 52 (2026-09-02): scheduled
# entry point for the Dashboard's two snapshots that had no periodic
# refresh at all before this phase.
#
# Before this phase, three JSON snapshots fed dashboard/index.html:
#   - logs/waio-status-latest.json    (dashboard/collect_status.sh)
#   - logs/incident-history-latest.json (dashboard/build_incident_history.sh)
#   - logs/waio-segments-latest.json  (dashboard/collect_segment_status.sh)
# Only the third had a schedule (security/segment_monitor_cron.sh,
# Phase 51). The first two only ever regenerated in one of two ways:
# an operator running the collector by hand, or security/lib.sh's
# trigger_shutdown() opportunistically kicking both off in the
# background when WAIO_AUTO_DASHBOARD_REFRESH=1 is set -- an
# event-driven refresh tied to an actual shutdown, not a schedule. On
# a quiet day with no incident, both snapshots could go stale
# indefinitely. This script closes that gap the same way Phase 51
# closed it for segments: a thin wrapper, no new logic, run on a
# launchd timer.
#
# Deliberately its own file/launchd agent, not folded into
# security/segment_monitor_cron.sh: segment monitoring is coupled to
# health_checker.sh's own Incident State Machine detection logic (a
# security/ concern with its own audit log), while this is purely a
# dashboard/ display-layer refresh (no security state is read or
# written here) -- same separation-of-concerns choice Phase 49 already
# made between logs/segment-audit.jsonl and logs/security-audit.jsonl.
# trigger_shutdown()'s own WAIO_AUTO_DASHBOARD_REFRESH-gated refresh is
# untouched and still fires independently on an actual shutdown, for
# the fastest-possible refresh right when it matters most; this script
# only adds the missing "meanwhile, on a quiet day" cadence.
#
# Both collectors run in their fast, default (no --run-tests) mode:
# read-only, local-file-only, no SSH/network call of any kind (verified
# against both scripts' own source before this phase). Never touches
# dashboard/collect_segment_status.sh or security/segments.conf --
# that stays Phase 51's job, to avoid two schedules racing to write
# the same file.
#
# Never touches SND_HOME or Takomachi -- both are independent projects
# (see SND_HOME's own CLAUDE.md, "混在させない").

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"

LOG_FILE="${DASHBOARD_REFRESH_CRON_LOG:-logs/dashboard-refresh-cron.log}"
mkdir -p "$(dirname "$LOG_FILE")"

log() {
  printf '%s %s\n' "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" "$1" >>"$LOG_FILE"
}

log "run start"

if ./dashboard/collect_status.sh >>"$LOG_FILE" 2>&1; then
  log "collect_status.sh: ok"
else
  log "collect_status.sh: FAILED"
fi

if ./dashboard/build_incident_history.sh >>"$LOG_FILE" 2>&1; then
  log "build_incident_history.sh: ok"
else
  log "build_incident_history.sh: FAILED"
fi

log "run end"
