#!/bin/bash
set -uo pipefail

# security/continuity_prepare_cron.sh -- WAIO Pre-Disconnect Cache
# (PDC), PREPARE step: periodic entry point that keeps PDC's own
# picture of "are we still connected" fresh while WAIO is online, so
# RECOVER never has to make that judgment from scratch under pressure.
# See security/continuity.sh's own header for the full PREPARE/OPERATE/
# RECOVER/RESYNC lifecycle and the TERN-inspired concept this borrows
# its naming from (local-reference-while-available, no jamming-
# detection/avoidance concept implemented or intended).
#
# Deliberately thin, same shape as security/segment_monitor_cron.sh
# (Phase 51), which this script always runs first: adds no new
# detection logic of its own, only calls already-reviewed entry points
# in sequence and logs when it ran.
#   1. security/health_checker.sh monitor-all -- unchanged, reused
#      as-is (Phase 49/51). Drives the Incident State Machine's
#      detection edges for every security/segments.conf entry,
#      including any Takomachi/external-API dependency entries this
#      deployment has added there (see security/segments.conf.example's
#      PDC section).
#   2. security/continuity.sh's continuity_update_state -- derives and
#      persists CONNECTED/DEGRADED/OFFLINE from every segment's
#      resulting status, logging a continuity_state_changed/
#      continuity_resync event only on an actual change.
#   3. security/continuity.sh's continuity_write_snapshot -- refreshes
#      security/state/continuity/last_known_good.json (segment
#      statuses + policy-file SHA-256 hashes only -- never file
#      contents, never cached response content, never a credential).
# Never calls recovery_engine.sh, never runs with --execute, never
# mutates a remote host or the Context Cache. Safe to run by hand at
# any time; running it twice back-to-back is a no-op beyond repeating
# the same idempotent calls.
#
# Meant to be invoked periodically by a per-user launchd agent -- see
# security/com.waio.continuity-prepare.plist.example.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"

LOG_FILE="${CONTINUITY_PREPARE_CRON_LOG:-logs/continuity-prepare-cron.log}"
mkdir -p "$(dirname "$LOG_FILE")"

log() {
  printf '%s %s\n' "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" "$1" >>"$LOG_FILE"
}

log "run start"

if ./security/health_checker.sh monitor-all >>"$LOG_FILE" 2>&1; then
  log "health_checker.sh monitor-all: ok"
else
  log "health_checker.sh monitor-all: exited non-zero (expected when a dependency is unreachable; see the Incident State Machine, not a script error)"
fi

source security/continuity.sh
NEW_STATE="$(continuity_update_state)"
log "continuity_update_state: $NEW_STATE"

if continuity_write_snapshot; then
  log "continuity_write_snapshot: ok"
else
  log "continuity_write_snapshot: FAILED"
fi

log "run end"
