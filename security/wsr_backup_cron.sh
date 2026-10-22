#!/bin/bash
set -uo pipefail

# security/wsr_backup_cron.sh -- WAIO Local Survival & Recovery (WSR)
# Phase A, periodic entry point: keeps a rolling set of verified local
# backups of WAIO's own gitignored critical config/audit-history/
# recovery-metadata fresh, so a disk failure never has to be
# discovered as "there was no backup after all". See security/
# wsr_backup.sh's own header for the full design, what is backed up,
# and the destination/retention/safety rules.
#
# Deliberately thin, same shape as security/continuity_prepare_cron.sh
# and security/segment_monitor_cron.sh: adds no new logic of its own,
# only calls the one already-reviewed entry point (wsr_backup_create)
# and logs when it ran. Never restores, never registers anything,
# never requires sudo. Safe to run by hand at any time; a run that
# finds nothing new to do beyond the existing retention window is a
# no-op beyond the one new snapshot it creates.
#
# Meant to be invoked periodically by a per-user launchd agent -- not
# wired into one this phase (no security/com.waio.wsr-backup.plist.
# example yet; deferred to a later, explicit scheduling phase).

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"

LOG_FILE="${WSR_BACKUP_CRON_LOG:-logs/wsr-backup-cron.log}"
mkdir -p "$(dirname "$LOG_FILE")"

log() {
  printf '%s %s\n' "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" "$1" >>"$LOG_FILE"
}

log "run start"

source security/wsr_backup.sh

if wsr_backup_create >>"$LOG_FILE" 2>&1; then
  log "wsr_backup_create: ok"
else
  log "wsr_backup_create: FAILED (see logs/wsr-backup-audit.jsonl and the output above for why)"
fi

log "run end"
