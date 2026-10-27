#!/bin/bash
set -uo pipefail

# tests/dashboard_touch_tooltip_test.sh -- dashboard/earth_weather.html's chart
# tooltips work with touch (iPad) as well as a mouse. The checks live in
# tests/dashboard_touch_tooltip_check.mjs, which runs the page's own
# bindTooltip() under fake pointer events. Requires node; SKIPS -- not
# fails -- if node is not on PATH.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR" || exit 1

echo "=== Dashboard: touch-friendly chart tooltips (earth_weather.html) ==="
if ! command -v node >/dev/null 2>&1; then
  echo "[DASHBOARD TOUCH TOOLTIP TEST] SKIP: node not found on PATH."
  exit 0
fi
node "$SCRIPT_DIR/tests/dashboard_touch_tooltip_check.mjs"
exit $?
