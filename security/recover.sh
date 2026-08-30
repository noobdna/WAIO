#!/bin/bash
set -uo pipefail

# security/recover.sh -- the ONLY way to clear an Emergency Shutdown.
# Deliberately manual and explicit (requirement: no auto-recovery, a
# human must confirm the cause has been investigated). Requires
# --confirm "<non-empty reason>"; refuses to run otherwise.
#
# --guardian-confirm "<reason>" is the same gate, reserved for the
# Guardian SSH path (see security/guardian_recover_wrapper.sh and
# ARCHITECTURE.md Phase 34/35) -- identical validation and effect, only
# the audit_log event_type differs, so the audit trail can tell which
# party recovered the system.
#
# Usage: ./security/recover.sh --confirm "investigated: <what you found>"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"
source security/lib.sh

if [ ! -f "$SHUTDOWN_LOCK" ]; then
  echo "[RECOVER] No active shutdown (no $SHUTDOWN_LOCK). Nothing to do."
  exit 0
fi

MODE="${1:-}"
CONFIRM_REASON="${2:-}"
case "$MODE" in
  --confirm) EVENT_TYPE="recovery_confirmed" ;;
  --guardian-confirm) EVENT_TYPE="recovery_confirmed_guardian" ;;
  *) EVENT_TYPE="" ;;
esac

if [ -z "$EVENT_TYPE" ] || [ -z "$CONFIRM_REASON" ]; then
  echo "[RECOVER] ERROR: refusing to clear an active shutdown without explicit confirmation."
  echo "[RECOVER] Usage: $0 --confirm \"<reason: what you investigated and why it's safe to resume>\""
  echo "[RECOVER]    or: $0 --guardian-confirm \"<reason>\"  (reserved for the Guardian SSH path)"
  echo "[RECOVER] Current shutdown record:"
  sed 's/^/  /' "$SHUTDOWN_LOCK"
  exit 1
fi

echo "[RECOVER] Current shutdown record:"
sed 's/^/  /' "$SHUTDOWN_LOCK"

RUN_ID="recover-$(date -u +%Y%m%dT%H%M%SZ)"
rm -f "$SHUTDOWN_LOCK"
audit_log "$EVENT_TYPE" "$RUN_ID" "n/a" "n/a" "n/a" "cleared" "$CONFIRM_REASON"

echo "[RECOVER] Shutdown cleared. Reason recorded: $CONFIRM_REASON"
echo "[RECOVER] Audit event written to $SECURITY_AUDIT_LOG"
