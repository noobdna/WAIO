#!/bin/bash
set -uo pipefail

# tests/dashboard_missing_data_ui_test.sh -- shell wrapper for
# tests/dashboard_missing_data_ui_check.mjs (audit finding D-2,
# 2026-11-06). Executes dashboard/index.html's own inline script under
# Node with a minimal DOM stub. No browser, no network.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"

echo "=== Dashboard: missing / stale snapshot handling (D-2) ==="

if ! command -v node >/dev/null 2>&1; then
  echo "[DASHBOARD MISSING DATA UI TEST] SKIP: node not found on PATH -- cannot execute dashboard/index.html's inline script for this check."
  exit 0
fi

node "$SCRIPT_DIR/tests/dashboard_missing_data_ui_check.mjs"
exit $?
