#!/bin/bash
set -uo pipefail

# tests/dashboard_incident_ui_test.sh -- regression suite for the
# incident-timeline panel's origin labelling (production vs. test
# artifact) in dashboard/index.html's renderIncidentHistory().
#
# Same split as tests/dashboard_guardian_ui_test.sh: the actual checks
# live in the companion tests/dashboard_incident_ui_check.mjs, which
# extracts and executes the page's own real inline <script> under a
# minimal DOM stub. Requires node; SKIPS -- not fails -- if node is
# not on PATH.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"

echo "=== Dashboard: incident timeline origin labelling ==="

if ! command -v node >/dev/null 2>&1; then
  echo "[DASHBOARD INCIDENT UI TEST] SKIP: node not found on PATH -- cannot execute dashboard/index.html's inline script for this check."
  exit 0
fi

node "$SCRIPT_DIR/tests/dashboard_incident_ui_check.mjs"
exit $?
