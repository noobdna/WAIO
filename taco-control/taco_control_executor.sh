#!/bin/bash
set -uo pipefail

# taco-control/taco_control_executor.sh -- minimal Execution Plane
# dispatch handler for the 750 (management) -> 800 (execution) control
# channel (per-user instruction; not part of WAIO's own DuCoPA/segment
# subsystem -- that already exists separately as
# security/segment_manager.sh + health_checker.sh + recovery_engine.sh
# and is untouched by this file).
#
# Deployment: copy this file onto the execution host (800号機) and run
# it there directly at its own console. This file does not reach
# anything over SSH itself -- the 750->800 channel's own SSH host-key
# trust is unresolved as of this writing (see this repo's own session
# notes: 192.168.1.80 presented a host key identical to 750's own
# during verification, not yet reconciled), so this script is
# deliberately a plain local script for now, invoked by whoever is
# physically at 800's console, or later by 750 over SSH once that trust
# question is settled -- not by this file reaching out on its own.
#
# Reads exactly one command from $TACO_CONTROL_DIR/commands/next.command
# (default ~/taco-control/commands/next.command), executes it ONLY if
# it is a recognized, whitelisted command -- no eval, no arbitrary
# shell, same discipline as security/recovery_engine.sh's own
# ALLOWED_ACTIONS -- and records the outcome:
#   state/control.status -- "DISPATCHED" after this run (success or
#                            rejection alike -- it means "a dispatch was
#                            processed", not "it succeeded"; see
#                            state/last.result for the actual outcome)
#   state/last.result     -- the command's own result text
#   logs/dispatch.log      -- append-only: timestamp|command|result
#
# Today's only whitelisted command is PING, which returns a liveness
# proof (this host's own hostname + current UTC time), so a caller can
# tell the command was genuinely executed HERE and not just echoed
# back by something else along the way.

CONTROL_DIR="${TACO_CONTROL_DIR:-$HOME/taco-control}"
COMMAND_FILE="$CONTROL_DIR/commands/next.command"
STATE_DIR="$CONTROL_DIR/state"
LOG_FILE="$CONTROL_DIR/logs/dispatch.log"

mkdir -p "$CONTROL_DIR/commands" "$STATE_DIR" "$CONTROL_DIR/logs"

if [ ! -f "$COMMAND_FILE" ]; then
  echo "[TACO-CONTROL] no command file at $COMMAND_FILE -- nothing to do" >&2
  exit 0
fi

COMMAND="$(cat "$COMMAND_FILE")"
TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

case "$COMMAND" in
  PING)
    RESULT="PONG from $(hostname) at $TS"
    STATUS=0
    ;;
  *)
    RESULT="ERROR: unrecognized command '$COMMAND' -- only PING is currently allowed"
    echo "[TACO-CONTROL] $RESULT" >&2
    STATUS=1
    ;;
esac

echo "DISPATCHED" > "$STATE_DIR/control.status"
echo "$RESULT" > "$STATE_DIR/last.result"
echo "$TS|$COMMAND|$RESULT" >> "$LOG_FILE"

echo "[TACO-CONTROL] executed '$COMMAND' -> $RESULT"
exit "$STATUS"
