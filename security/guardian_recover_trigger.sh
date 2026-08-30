#!/bin/bash
set -uo pipefail

# security/guardian_recover_trigger.sh -- Phase 37: the Guardian-side half
# of the Guardian Recovery Protocol (see ARCHITECTURE.md Phase 33-37).
# Wraps the ssh invocation manually verified end-to-end in Phase 36
# (`ssh -i ~/.ssh/waio_guardian ... <user>@<750> "<reason>"`) into a single
# command with a required reason and a fail-closed failure path: no retry,
# no fallback, no swallowed errors -- a failure here looks exactly like a
# failure would to an operator running the raw ssh command by hand.
#
# Tracked, generic -- same separation Phase 35 established for
# security/guardian_recover_wrapper.sh: this file carries no
# deployment-specific host/user of its own. It is meant to be copied
# standalone to 800号機 (the Guardian machine has no checkout of this repo)
# and invoked with the real target set via environment variables. See
# ARCHITECTURE.md Phase 37 for the actual deployed invocation.
#
# Usage:
#   GUARDIAN_TARGET_HOST=<750's LAN address> GUARDIAN_TARGET_USER=<user> \
#     ./guardian_recover_trigger.sh "<reason: what you investigated and why it's safe to resume>"

GUARDIAN_KEY_PATH="${GUARDIAN_KEY_PATH:-$HOME/.ssh/waio_guardian}"
GUARDIAN_CONNECT_TIMEOUT="${GUARDIAN_CONNECT_TIMEOUT:-10}"
REASON="${1:-}"

if [ -z "${GUARDIAN_TARGET_HOST:-}" ] || [ -z "${GUARDIAN_TARGET_USER:-}" ]; then
  echo "[GUARDIAN TRIGGER] ERROR: GUARDIAN_TARGET_HOST and GUARDIAN_TARGET_USER must both be set." >&2
  echo "[GUARDIAN TRIGGER] Usage: GUARDIAN_TARGET_HOST=<host> GUARDIAN_TARGET_USER=<user> $0 \"<reason>\"" >&2
  exit 1
fi

if [ -z "$REASON" ]; then
  echo "[GUARDIAN TRIGGER] ERROR: refusing to send a recovery request without a reason." >&2
  echo "[GUARDIAN TRIGGER] Usage: GUARDIAN_TARGET_HOST=<host> GUARDIAN_TARGET_USER=<user> $0 \"<reason: what you investigated and why it's safe to resume>\"" >&2
  exit 1
fi

echo "[GUARDIAN TRIGGER] target: ${GUARDIAN_TARGET_USER}@${GUARDIAN_TARGET_HOST}"
echo "[GUARDIAN TRIGGER] reason: $REASON"

ssh -i "$GUARDIAN_KEY_PATH" -o BatchMode=yes -o ConnectTimeout="$GUARDIAN_CONNECT_TIMEOUT" \
  "${GUARDIAN_TARGET_USER}@${GUARDIAN_TARGET_HOST}" "$REASON"
RC=$?

if [ "$RC" -ne 0 ]; then
  echo "[GUARDIAN TRIGGER] ERROR: recovery request failed (ssh exit code $RC)." >&2
fi

exit "$RC"
