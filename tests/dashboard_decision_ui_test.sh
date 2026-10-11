#!/bin/bash
set -uo pipefail

# tests/dashboard_decision_ui_test.sh -- regression suite for
# dashboard/index.html's new "System Overview" and "Decision Engine"
# panels and their renderOverview()/renderDecision() JS logic.
#
# Same split as tests/dashboard_takomachi_ui_test.sh: the actual checks
# live in the companion tests/dashboard_decision_ui_check.mjs, which
# extracts and executes the page's own real inline <script> under a
# minimal DOM stub. Requires node; SKIPS -- not fails -- if node is
# not on PATH.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"

echo "=== Dashboard: System Overview / Decision Engine UI panels ==="

if ! command -v node >/dev/null 2>&1; then
  echo "[DASHBOARD DECISION UI TEST] SKIP: node not found on PATH -- cannot execute dashboard/index.html's inline script for this check."
  exit 0
fi

node "$SCRIPT_DIR/tests/dashboard_decision_ui_check.mjs"
exit $?
