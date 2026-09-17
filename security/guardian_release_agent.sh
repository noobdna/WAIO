#!/bin/bash
set -uo pipefail

# security/guardian_release_agent.sh -- the operator-facing CLI to clear
# one agent off the Guardian quarantine list (security/guardian.sh's
# guardian_quarantine_agent / guardian_is_quarantined / guardian_release_agent,
# gated separately from waio.sh's guardian_is_blocking check -- see G24 in
# tests/ducopa_guardian_test.sh). Mirrors security/guardian_approve.sh's
# discipline: requires --confirm "<non-empty reason>"; a no-op, exit 0, if
# the named agent isn't currently quarantined.
#
# Quarantine itself has no CLI (ARCHITECTURE.md Phase 57 leaves
# quarantine an explicit, Guardian-driven action, not something this
# phase auto-triggers), but until now nothing let an operator release one
# without hand-sourcing security/lib.sh and calling guardian_release_agent
# directly -- every other Guardian action already has a CLI
# (guardian_approve.sh, recover.sh); this closes that gap.
#
# Minimum reason strength (same discipline as security/recover.sh's own
# Phase 54 hardening and security/guardian_approve.sh, shared via
# security/lib.sh's validate_reason_strength): the trimmed reason must be
# both WAIO_GUARDIAN_MIN_REASON_LENGTH characters (default 20) and
# contain WAIO_GUARDIAN_MIN_REASON_DISTINCT_CHARS distinct characters
# (default 8) -- same two env vars as guardian_approve.sh, one shared
# threshold for the whole Guardian CLI surface.
#
# Usage: ./security/guardian_release_agent.sh AGENT --confirm "<reason>"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"
source security/lib.sh

AGENT="${1:-}"
MODE="${2:-}"
CONFIRM_REASON="${3:-}"

if [ -z "$AGENT" ]; then
  echo "[GUARDIAN RELEASE] ERROR: no agent name given."
  echo "[GUARDIAN RELEASE] Usage: $0 AGENT --confirm \"<reason: what you investigated and why it's safe to release>\""
  exit 1
fi

if ! guardian_is_quarantined "$AGENT"; then
  echo "[GUARDIAN RELEASE] '$AGENT' is not currently quarantined. Nothing to do."
  exit 0
fi

if [ "$MODE" != "--confirm" ] || [ -z "$CONFIRM_REASON" ]; then
  echo "[GUARDIAN RELEASE] ERROR: refusing to release quarantined agent '$AGENT' without a reason."
  echo "[GUARDIAN RELEASE] Usage: $0 AGENT --confirm \"<reason: what you investigated and why it's safe to release>\""
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
  TOO_SHORT) REASON_ERROR="reason is $REASON_PAYLOAD character(s), minimum is $MIN_REASON_LENGTH -- describe what you investigated and why it's safe to release" ;;
  LOW_VARIETY) REASON_ERROR="reason has too little variety ($REASON_PAYLOAD distinct characters, minimum $MIN_REASON_DISTINCT_CHARS) -- looks like padding, not a real explanation" ;;
  OK) CONFIRM_REASON="$REASON_PAYLOAD" ;;
  *) REASON_ERROR="internal error validating reason (unexpected validator output)" ;;
esac

if [ -n "$REASON_ERROR" ]; then
  echo "[GUARDIAN RELEASE] ERROR: refusing to release quarantined agent '$AGENT' without a sufficiently descriptive reason."
  echo "[GUARDIAN RELEASE]   reason rejected: $REASON_ERROR"
  echo "[GUARDIAN RELEASE] Usage: $0 AGENT --confirm \"<reason: what you investigated and why it's safe to release>\""
  exit 1
fi

RUN_ID="guardian-release-$(date -u +%Y%m%dT%H%M%SZ)"
if guardian_release_agent "$AGENT" "$CONFIRM_REASON" "$RUN_ID"; then
  echo "[GUARDIAN RELEASE] '$AGENT' released from quarantine. Reason recorded: $CONFIRM_REASON"
  echo "[GUARDIAN RELEASE] Audit event written to $SECURITY_AUDIT_LOG"
  exit 0
else
  echo "[GUARDIAN RELEASE] ERROR: could not release '$AGENT' from quarantine."
  exit 1
fi
