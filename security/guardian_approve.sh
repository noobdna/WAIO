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
# Minimum reason strength (same discipline as security/recover.sh's own
# Phase 54 hardening, shared via security/lib.sh's validate_reason_strength):
# a non-empty reason alone used to be sufficient here -- "x" would clear
# any Guardian state. Now the trimmed reason must be both
# WAIO_GUARDIAN_MIN_REASON_LENGTH characters (default 20) and contain
# WAIO_GUARDIAN_MIN_REASON_DISTINCT_CHARS distinct characters (default 8).
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

MIN_REASON_LENGTH="${WAIO_GUARDIAN_MIN_REASON_LENGTH:-20}"
MIN_REASON_DISTINCT_CHARS="${WAIO_GUARDIAN_MIN_REASON_DISTINCT_CHARS:-8}"
REASON_CHECK="$(validate_reason_strength "$CONFIRM_REASON" "$MIN_REASON_LENGTH" "$MIN_REASON_DISTINCT_CHARS")"
REASON_STATUS="${REASON_CHECK%%$'\x1f'*}"
REASON_PAYLOAD="${REASON_CHECK#*$'\x1f'}"
REASON_ERROR=""
case "$REASON_STATUS" in
  EMPTY) REASON_ERROR="reason is empty after trimming whitespace" ;;
  TOO_SHORT) REASON_ERROR="reason is $REASON_PAYLOAD character(s), minimum is $MIN_REASON_LENGTH -- describe what you investigated and why it's safe to resume" ;;
  LOW_VARIETY) REASON_ERROR="reason has too little variety ($REASON_PAYLOAD distinct characters, minimum $MIN_REASON_DISTINCT_CHARS) -- looks like padding, not a real explanation" ;;
  OK) CONFIRM_REASON="$REASON_PAYLOAD" ;;
  *) REASON_ERROR="internal error validating reason (unexpected validator output)" ;;
esac

if [ -n "$REASON_ERROR" ]; then
  echo "[GUARDIAN APPROVE] ERROR: refusing to clear Guardian state '$CURRENT_STATE' without a sufficiently descriptive reason."
  echo "[GUARDIAN APPROVE]   reason rejected: $REASON_ERROR"
  echo "[GUARDIAN APPROVE] Usage: $0 --confirm \"<reason: what you investigated and why it's safe to resume>\""
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
