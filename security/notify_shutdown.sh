#!/bin/bash
set -uo pipefail

# security/notify_shutdown.sh -- Phase 40-B-1: an optional, fully
# decoupled local notification for a human operator when an Emergency
# Shutdown is active. Purely observational -- it never writes to
# security/state/SHUTDOWN.lock, never calls security/recover.sh, and is
# not called by security/lib.sh's trigger_shutdown() or any existing
# guard call site. Not wired to run automatically anywhere yet; a future
# phase can decide how/when to invoke it. Never touches Takomachi or any
# network destination -- macOS local notifications only.
#
# Usage: ./security/notify_shutdown.sh
# Exit codes: 0 always, whether or not a notification was actually shown
# (no active shutdown, or osascript unavailable, are both treated as a
# clean no-op, not a failure -- this script's own success/failure is
# never allowed to look like a WAIO-state problem).
#
# Injection safety: the shutdown reason comes from
# security/state/SHUTDOWN.lock, which can carry attacker-influenced text
# (the same class of untrusted string security/guardian_recover_wrapper.sh
# guards against for the Guardian SSH path, Phase 35). It is never
# interpolated into the AppleScript source text passed to osascript --
# the script here is a fixed, single-quoted heredoc, and the reason/title
# are read at AppleScript runtime via `system attribute`, from
# environment variables, never re-parsed as script syntax.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"
source security/lib.sh

if ! is_shutdown_active; then
  echo "[NOTIFY SHUTDOWN] No active shutdown. Nothing to do."
  exit 0
fi

WAIO_NOTIFY_MSG="$(sed -n 's/^reason: //p' "$SHUTDOWN_LOCK" | head -1)"
if [ -z "$WAIO_NOTIFY_MSG" ]; then
  WAIO_NOTIFY_MSG="(no reason recorded in $SHUTDOWN_LOCK)"
fi
WAIO_NOTIFY_TITLE="WAIO Emergency Shutdown"
export WAIO_NOTIFY_TITLE WAIO_NOTIFY_MSG

if ! command -v osascript >/dev/null 2>&1; then
  echo "[NOTIFY SHUTDOWN] osascript not available on this system -- skipping local notification (not an error)."
  echo "[NOTIFY SHUTDOWN] Active shutdown reason: $WAIO_NOTIFY_MSG"
  exit 0
fi

osascript <<'APPLESCRIPT'
display notification (system attribute "WAIO_NOTIFY_MSG") with title (system attribute "WAIO_NOTIFY_TITLE")
APPLESCRIPT
RC=$?

if [ "$RC" -ne 0 ]; then
  echo "[NOTIFY SHUTDOWN] osascript exited non-zero ($RC) -- notification may not have been shown. Active shutdown reason: $WAIO_NOTIFY_MSG"
else
  echo "[NOTIFY SHUTDOWN] Local notification sent."
fi

exit 0
