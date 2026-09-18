#!/bin/bash
set -uo pipefail

# security/guardian_intervene_quarantine_wrapper.sh -- a second,
# separately-keyed Guardian intervention action (Phase 72), alongside
# security/guardian_intervene_wrapper.sh's HUMAN_APPROVAL_REQUIRED
# (Phase 64). Deliberately narrower in blast radius than that one:
# HUMAN_APPROVAL_REQUIRED blocks ALL new dispatch system-wide;
# quarantining blocks dispatch to exactly one named agent, leaving
# every other agent unaffected (see tests/ducopa_guardian_test.sh's own
# G24 for why quarantine and the Guardian's global state are already
# two separate mechanisms). Reuses guardian_quarantine_agent, the exact
# same function security/guardian.sh's own opt-in automatic-quarantine
# policy (Phase 60) and a future manual-quarantine CLI would call --
# never a parallel mechanism. NEVER touches the real Emergency Shutdown
# (SHUTDOWN_LOCK), NEVER touches guardian_set_state/the Guardian's
# global state machine, and never affects any agent other than the one
# named.
#
# Deployment (authorized_keys forced-command, a distinct SSH key from
# guardian_intervene_wrapper.sh's own) is explicitly OUT OF SCOPE for
# this phase -- see ARCHITECTURE.md Phase 72. This file is code +
# tests only; no real key was generated, no authorized_keys or
# sshd_config.d file was touched, no SSH connection to any real host
# was made.
#
# Same SSH_ORIGINAL_COMMAND-quoting safety as guardian_recover_wrapper.sh
# and guardian_intervene_wrapper.sh: sshd re-parses the authorized_keys
# "command=" value itself as shell text, so the Guardian-supplied text
# (whatever the remote client typed, exposed here as
# $SSH_ORIGINAL_COMMAND) must never be interpolated directly into that
# value. Routing through this script avoids that: "command=" only ever
# names this fixed path, and here "${SSH_ORIGINAL_COMMAND}" is a single
# already-expanded parameter, never re-parsed as shell syntax.
#
# Command shape: "<AGENT> <reason text>" -- the first whitespace-
# delimited token is the target agent name (a workers/registry.conf
# NAME); everything after the first run of whitespace is the reason,
# with its own internal spacing preserved exactly (`read` with two
# variables, not a manual split, so multi-word reasons are never
# mangled). This is data for a single, fixed action (which agent, and
# why), never an action selector -- the wrapper always does exactly one
# thing: quarantine the named agent. Guardian_quarantine_agent's own
# exact-line writes make no assumption the name is real/registered
# (same as security/guardian_release_agent.sh's own CLI already
# accepts any string), and never executes AGENT or REASON as shell
# text -- both are passed as plain data through bash function
# parameters and security/lib.sh's audit_log (which shells out to
# python3 with argv, never string interpolation).
#
# Minimum reason strength (same discipline as every other reason-gated
# Guardian CLI since Phase 54/59/71, shared via security/lib.sh's
# validate_reason_strength): the trimmed reason must be both
# WAIO_GUARDIAN_MIN_REASON_LENGTH characters (default 20) and contain
# WAIO_GUARDIAN_MIN_REASON_DISTINCT_CHARS distinct characters (default
# 8) -- same two env vars and thresholds as the rest of the Guardian
# CLI surface. A missing agent name, or a too-short/low-variety reason,
# refuses (exit 1) before guardian_quarantine_agent is ever called.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"
source security/lib.sh

RUN_ID="guardian-intervene-quarantine-$(date -u +%Y%m%dT%H%M%SZ)"
COMMAND="${SSH_ORIGINAL_COMMAND:-}"

AGENT=""
REASON=""
read -r AGENT REASON <<< "$COMMAND"

if [ -z "$AGENT" ]; then
  echo "[GUARDIAN INTERVENE QUARANTINE] ERROR: no agent name given."
  echo "[GUARDIAN INTERVENE QUARANTINE] Expected command shape: \"<AGENT> <reason: what you observed and why this agent must stop dispatching>\""
  exit 1
fi

MIN_REASON_LENGTH="${WAIO_GUARDIAN_MIN_REASON_LENGTH:-20}"
MIN_REASON_DISTINCT_CHARS="${WAIO_GUARDIAN_MIN_REASON_DISTINCT_CHARS:-8}"
REASON_CHECK="$(validate_reason_strength "$REASON" "$MIN_REASON_LENGTH" "$MIN_REASON_DISTINCT_CHARS")"
REASON_STATUS="${REASON_CHECK%%$'\x1f'*}"
REASON_PAYLOAD="${REASON_CHECK#*$'\x1f'}"
REASON_ERROR=""
case "$REASON_STATUS" in
  EMPTY) REASON_ERROR="reason is empty after trimming whitespace" ;;
  TOO_SHORT) REASON_ERROR="reason is $REASON_PAYLOAD character(s), minimum is $MIN_REASON_LENGTH -- describe what you observed and why '$AGENT' must stop dispatching" ;;
  LOW_VARIETY) REASON_ERROR="reason has too little variety ($REASON_PAYLOAD distinct characters, minimum $MIN_REASON_DISTINCT_CHARS) -- looks like padding, not a real explanation" ;;
  OK) REASON="$REASON_PAYLOAD" ;;
  *) REASON_ERROR="internal error validating reason (unexpected validator output)" ;;
esac

if [ -n "$REASON_ERROR" ]; then
  echo "[GUARDIAN INTERVENE QUARANTINE] ERROR: refusing to quarantine '$AGENT' without a sufficiently descriptive reason."
  echo "[GUARDIAN INTERVENE QUARANTINE]   reason rejected: $REASON_ERROR"
  exit 1
fi

if guardian_is_quarantined "$AGENT"; then
  echo "[GUARDIAN INTERVENE QUARANTINE] '$AGENT' is already quarantined. Nothing to do."
  exit 0
fi

guardian_quarantine_agent "$AGENT" "$REASON" "$RUN_ID"
echo "[GUARDIAN INTERVENE QUARANTINE] '$AGENT' quarantined. Reason recorded: $REASON"
echo "[GUARDIAN INTERVENE QUARANTINE] Release requires explicit confirmation on the WAIO side: ./security/guardian_release_agent.sh $AGENT --confirm \"<reason>\""
