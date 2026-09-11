#!/bin/bash
set -uo pipefail

# taco-control/taco_control_dispatch.sh -- 750 (management) side
# trigger for the minimal 750->800 control channel (see
# taco_control_executor.sh's own header for the full picture and its
# deliberate scope limits).
#
# NOT YET FUNCTIONAL end-to-end: this script's ssh call will fail with
# "Host key verification failed" until 192.168.1.80's SSH host key is
# independently verified and deliberately added to this machine's own
# known_hosts (see this repo's own session notes) -- this file
# intentionally does NOT pass -o StrictHostKeyChecking=no or otherwise
# bypass that check itself, per explicit instruction not to touch
# known_hosts/SSH config from this side. Once that trust is
# established through whatever separate, deliberate process the
# operator chooses, this script works as-is with no changes needed.
#
# Usage: taco_control_dispatch.sh COMMAND
#   e.g. taco_control_dispatch.sh PING

TACO_HOST="${TACO_CONTROL_HOST:-192.168.1.80}"
TACO_USER="${TACO_CONTROL_USER:-masa}"
TACO_REMOTE_DIR="${TACO_CONTROL_REMOTE_DIR:-taco-control}"

COMMAND="${1:-}"
if [ -z "$COMMAND" ]; then
  echo "Usage: $0 COMMAND" >&2
  exit 1
fi

ssh -o BatchMode=yes "${TACO_USER}@${TACO_HOST}" "
  mkdir -p \"\$HOME/$TACO_REMOTE_DIR/commands\"
  echo '$COMMAND' > \"\$HOME/$TACO_REMOTE_DIR/commands/next.command\"
  bash \"\$HOME/$TACO_REMOTE_DIR/taco_control_executor.sh\"
  echo '--- state/control.status ---'
  cat \"\$HOME/$TACO_REMOTE_DIR/state/control.status\"
  echo '--- state/last.result ---'
  cat \"\$HOME/$TACO_REMOTE_DIR/state/last.result\"
"
