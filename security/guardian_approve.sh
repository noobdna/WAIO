#!/bin/bash
set -uo pipefail

# security/guardian_approve.sh -- the ONLY way to clear a Guardian Control
# Plane state of WARNING, BLOCKED, or HUMAN_APPROVAL_REQUIRED back to
# NORMAL. Deliberately manual and explicit, same discipline as
# security/recover.sh: requires --confirm "<non-empty reason>".
#
# Does NOT clear a Guardian state of SHUTDOWN -- that state mirrors the
# real Emergency Shutdown lock (security/lib.sh's SHUTDOWN_LOCK) and must
# go through security/recover.sh instead, so there is exactly one
# recovery path for the real shutdown mechanism, never two (requirement:
# reuse SHUTDOWN.lock's existing safety machinery, don't build a
# competing one).
#
# Usage: ./security/guardian_approve.sh --confirm "<reason>"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"
source security/lib.sh

CURRENT_STATE="$(guardian_get_state)"
if [ "$CURRENT_STATE" = "NORMAL" ]; then
  echo "[GUARDIAN APPROVE] Guardian state is already NORMAL. Nothing to do."
  exit 0
fi

MODE="${1:-}"
CONFIRM_REASON="${2:-}"

if [ "$MODE" != "--confirm" ] || [ -z "$CONFIRM_REASON" ]; then
  echo "[GUARDIAN APPROVE] ERROR: refusing to clear Guardian state '$CURRENT_STATE' without a reason."
  echo "[GUARDIAN APPROVE] Usage: $0 --confirm \"<reason: what you investigated and why it's safe to resume>\""
  if [ "$CURRENT_STATE" = "SHUTDOWN" ]; then
    echo "[GUARDIAN APPROVE] NOTE: state is SHUTDOWN -- use ./security/recover.sh instead, not this command."
  fi
  exit 1
fi

RUN_ID="guardian-approve-$(date -u +%Y%m%dT%H%M%SZ)"
if guardian_approve "$CONFIRM_REASON" "$RUN_ID" "operator"; then
  echo "[GUARDIAN APPROVE] Guardian state cleared ($CURRENT_STATE -> NORMAL). Reason recorded: $CONFIRM_REASON"
  echo "[GUARDIAN APPROVE] Audit event written to $SECURITY_AUDIT_LOG"
  exit 0
else
  echo "[GUARDIAN APPROVE] ERROR: could not clear Guardian state '$CURRENT_STATE'."
  exit 1
fi
