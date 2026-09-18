#!/bin/bash
set -uo pipefail

# security/guardian_intervene_wrapper.sh -- the sole command a Guardian
# SSH key for the *intervention* direction is permitted to run, via an
# authorized_keys "command=" forced-command restriction on the WAIO
# side. See ARCHITECTURE.md Phase 64 for the full design.
#
# This is the mirror image of security/guardian_recover_wrapper.sh: that
# one lets a Guardian-authenticated SSH connection RELEASE a WAIO-side
# stop (--guardian-confirm); this one lets it REQUEST one. Deliberately
# scoped to the single least-authority action available in
# security/guardian.sh's state machine: HUMAN_APPROVAL_REQUIRED. It
# NEVER trips the real Emergency Shutdown (SHUTDOWN_LOCK), NEVER
# quarantines any agent, and never writes any state beyond what
# guardian_require_human_approval already exposes to WAIO's own trusted
# internal callers -- this file grants a remote Guardian channel no more
# authority than an operator running that same function already has.
# A future phase MAY expose additional, separately-keyed actions behind
# their own forced-command wrappers (one key, one fixed command each --
# never an argument-driven action selector over SSH); not built here,
# see ARCHITECTURE.md Phase 64's own scope note for why.
#
# Same SSH_ORIGINAL_COMMAND-quoting safety as guardian_recover_wrapper.sh:
# sshd re-parses the authorized_keys "command=" value itself as shell
# text, so the Guardian-supplied reason (whatever the remote client
# typed, exposed here as $SSH_ORIGINAL_COMMAND) must never be
# interpolated directly into that value -- doing so would let
# quotes/backticks/$()/; in the reason text break out and run arbitrary
# commands. Routing through this script avoids that: "command=" only
# ever names this fixed path, and here "${SSH_ORIGINAL_COMMAND}" is a
# single already-expanded parameter passed as one argument to a bash
# function, never re-parsed as shell syntax.
#
# Minimum reason strength (Phase 71, closes Phase 68 finding 5; same
# discipline as security/recover.sh/guardian_approve.sh/
# guardian_release_agent.sh, shared via security/lib.sh's
# validate_reason_strength): the trimmed reason must be both
# WAIO_GUARDIAN_MIN_REASON_LENGTH characters (default 20) and contain
# WAIO_GUARDIAN_MIN_REASON_DISTINCT_CHARS distinct characters (default
# 8) -- same two env vars and thresholds as the rest of the Guardian
# CLI surface. A one-keystroke or low-variety reason now refuses before
# ever calling guardian_require_human_approval, instead of escalating
# the Guardian Control Plane state on effectively no explanation.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"
source security/lib.sh

RUN_ID="guardian-intervene-$(date -u +%Y%m%dT%H%M%SZ)"
REASON="${SSH_ORIGINAL_COMMAND:-guardian intervention request, no reason text supplied}"

MIN_REASON_LENGTH="${WAIO_GUARDIAN_MIN_REASON_LENGTH:-20}"
MIN_REASON_DISTINCT_CHARS="${WAIO_GUARDIAN_MIN_REASON_DISTINCT_CHARS:-8}"
REASON_CHECK="$(validate_reason_strength "$REASON" "$MIN_REASON_LENGTH" "$MIN_REASON_DISTINCT_CHARS")"
REASON_STATUS="${REASON_CHECK%%$'\x1f'*}"
REASON_PAYLOAD="${REASON_CHECK#*$'\x1f'}"
REASON_ERROR=""
case "$REASON_STATUS" in
  EMPTY) REASON_ERROR="reason is empty after trimming whitespace" ;;
  TOO_SHORT) REASON_ERROR="reason is $REASON_PAYLOAD character(s), minimum is $MIN_REASON_LENGTH -- describe why WAIO should require human approval before any new dispatch" ;;
  LOW_VARIETY) REASON_ERROR="reason has too little variety ($REASON_PAYLOAD distinct characters, minimum $MIN_REASON_DISTINCT_CHARS) -- looks like padding, not a real explanation" ;;
  OK) REASON="$REASON_PAYLOAD" ;;
  *) REASON_ERROR="internal error validating reason (unexpected validator output)" ;;
esac

if [ -n "$REASON_ERROR" ]; then
  echo "[GUARDIAN INTERVENE] ERROR: refusing to request HUMAN_APPROVAL_REQUIRED without a sufficiently descriptive reason."
  echo "[GUARDIAN INTERVENE]   reason rejected: $REASON_ERROR"
  exit 1
fi

guardian_require_human_approval "$REASON" "$RUN_ID"
echo "[GUARDIAN INTERVENE] Guardian Control Plane state is now $(guardian_get_state) (requested: HUMAN_APPROVAL_REQUIRED). Reason recorded: $REASON"
echo "[GUARDIAN INTERVENE] Clearing requires explicit confirmation on the WAIO side: ./security/guardian_approve.sh --confirm \"<reason>\""
