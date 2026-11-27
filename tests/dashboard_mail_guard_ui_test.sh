#!/bin/bash
set -uo pipefail

# tests/dashboard_mail_guard_ui_test.sh -- dashboard/index.html's MAIL GUARD
# panel (renderMailGuard). Checks live in tests/dashboard_mail_guard_ui_check.mjs,
# which executes the page's real inline <script> under a minimal DOM stub.
# SKIPS -- not fails -- if node is not on PATH.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR" || exit 1
echo "=== Dashboard: MAIL GUARD UI panel ==="
if ! command -v node >/dev/null 2>&1; then
  echo "[DASHBOARD MAIL GUARD UI TEST] SKIP: node not found on PATH"
  exit 0
fi
node "$SCRIPT_DIR/tests/dashboard_mail_guard_ui_check.mjs"
exit $?
