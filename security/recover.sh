#!/bin/bash
set -uo pipefail

# security/recover.sh -- the ONLY way to clear an Emergency Shutdown.
# Deliberately manual and explicit (requirement: no auto-recovery, a
# human must confirm the cause has been investigated). Requires
# --confirm "<non-empty reason>"; refuses to run otherwise.
#
# Usage: ./security/recover.sh --confirm "investigated: <what you found>"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"
source security/lib.sh

if [ ! -f "$SHUTDOWN_LOCK" ]; then
  echo "[RECOVER] No active shutdown (no $SHUTDOWN_LOCK). Nothing to do."
  exit 0
fi

if [ "${1:-}" != "--confirm" ] || [ -z "${2:-}" ]; then
  echo "[RECOVER] ERROR: refusing to clear an active shutdown without explicit confirmation."
  echo "[RECOVER] Usage: $0 --confirm \"<reason: what you investigated and why it's safe to resume>\""
  echo "[RECOVER] Current shutdown record:"
  sed 's/^/  /' "$SHUTDOWN_LOCK"
  exit 1
fi

CONFIRM_REASON="$2"

echo "[RECOVER] Current shutdown record:"
sed 's/^/  /' "$SHUTDOWN_LOCK"

RUN_ID="recover-$(date -u +%Y%m%dT%H%M%SZ)"
rm -f "$SHUTDOWN_LOCK"
audit_log "recovery_confirmed" "$RUN_ID" "n/a" "n/a" "n/a" "cleared" "$CONFIRM_REASON"

echo "[RECOVER] Shutdown cleared. Reason recorded: $CONFIRM_REASON"
echo "[RECOVER] Audit event written to $SECURITY_AUDIT_LOG"
