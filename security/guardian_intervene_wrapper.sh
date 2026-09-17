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

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"
source security/lib.sh

RUN_ID="guardian-intervene-$(date -u +%Y%m%dT%H%M%SZ)"
REASON="${SSH_ORIGINAL_COMMAND:-guardian intervention request, no reason text supplied}"

guardian_require_human_approval "$REASON" "$RUN_ID"
echo "[GUARDIAN INTERVENE] Guardian Control Plane state is now $(guardian_get_state) (requested: HUMAN_APPROVAL_REQUIRED). Reason recorded: $REASON"
echo "[GUARDIAN INTERVENE] Clearing requires explicit confirmation on the WAIO side: ./security/guardian_approve.sh --confirm \"<reason>\""
