#!/bin/bash
set -uo pipefail

# tests/ipad_chart_touch_test.sh -- dashboard/earth_weather.html's charts with
# touch. Chart marks render 7-13px wide on an iPad; a tap anywhere on the plot
# must show the nearest mark's tooltip (bindNearestTooltip), and the mouse
# must keep per-mark hover only.
#
# Runs the page in WebKit (tests/ipad_reconnect_check.swift, the generic
# scenario driver) at iPad Pro 11" portrait, served by the real
# dashboard/serve_dashboard.py on a free loopback port with an empty logs dir
# (embedded sample data). Taps are SIMULATED: a PointerEvent with pointerType
# "touch" is dispatched to whatever document.elementFromPoint() returns at
# that spot, so hit-testing is real but no finger is involved.
#
# macOS only (WKWebView). SKIPS -- not fails -- without swiftc/WebKit.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR" || exit 1
# WAIO_TEST_NO_SKIP=1 (set in CI): a missing tool is a failure, never a silent green skip
SKIP_RC=0; [ "${WAIO_TEST_NO_SKIP:-}" = 1 ] && SKIP_RC=1

echo "=== Dashboard: chart tooltips by touch (earth_weather.html) ==="
if [ "$(uname)" != "Darwin" ] || ! command -v swiftc >/dev/null 2>&1; then
  echo "[IPAD CHART TOUCH TEST] SKIP: needs macOS with swiftc (WebKit); not available here."
  exit "$SKIP_RC"
fi

WORK="$(mktemp -d "${TMPDIR:-/tmp}/waio-ipad-chart.XXXXXX")"
mkdir -p "$WORK/logs"
SERVER_PID=""
cleanup() {
  # only the server this suite started; never by name or pattern
  if [ -n "$SERVER_PID" ]; then kill "$SERVER_PID" 2>/dev/null; wait "$SERVER_PID" 2>/dev/null; fi
  rm -rf "${WORK:?}"
}
trap cleanup EXIT

PASS=0; FAIL=0
check() { if [ "$2" = "$3" ]; then PASS=$((PASS+1)); echo "  PASS: $1"; else FAIL=$((FAIL+1)); echo "  FAIL: $1 (expected='$2' actual='$3')"; fi; }

if ! swiftc -O -o "$WORK/scenario" tests/ipad_reconnect_check.swift > "$WORK/build.log" 2>&1; then
  echo "[IPAD CHART TOUCH TEST] SKIP: could not build the WebKit driver (toolchain problem, not a result)."
  exit "$SKIP_RC"
fi

PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')"
WAIO_DASHBOARD_BIND=127.0.0.1 WAIO_DASHBOARD_PORT="$PORT" WAIO_DASHBOARD_AUTH_FILE= WAIO_DASHBOARD_ALLOWED_CLIENTS= \
  WAIO_DASHBOARD_LOGS_ROOT="$WORK/logs" python3 dashboard/serve_dashboard.py > "$WORK/server.log" 2>&1 &
SERVER_PID=$!
for _ in $(seq 1 100); do curl -s -o /dev/null --max-time 1 "http://127.0.0.1:$PORT/" && break; sleep 0.1; done  # up to 10 s (CI)

# tap(chartId, fx, fy, pointerType): fx/fy are fractions of the chart's box.
# Returns what was hit and the tooltip state afterwards.
TAP='function tap(id, fx, fy, type) {
  const svg = document.getElementById(id); svg.scrollIntoView({block: "center"});
  const b = svg.getBoundingClientRect(); const cx = b.left + b.width * fx, cy = b.top + b.height * fy;
  const target = document.elementFromPoint(cx, cy);
  target.dispatchEvent(new PointerEvent("pointerdown", {pointerType: type, clientX: cx, clientY: cy, bubbles: true}));
  const tip = svg.parentElement.querySelector(".tooltip");
  return {hit: target.tagName + (target.getAttribute("class") ? "." + target.getAttribute("class") : ""), shown: tip.style.opacity === "1", text: tip.textContent};
}
function hideAll() { document.body.dispatchEvent(new PointerEvent("pointerdown", {pointerType: "touch", bubbles: true})); }'
J() { printf 'js:(() => { %s\n %s })()' "$TAP" "$1"; }

"$WORK/scenario" "http://127.0.0.1:$PORT/earth_weather.html" wait:2 \
  "$(J 'const r = []; for (const id of ["mainChart", "lagChart"]) { const o = document.querySelector("#" + id + " rect.chart-touch"); const b = o.getBoundingClientRect(); r.push(Math.round(Math.min(b.width, b.height))); } return JSON.stringify(r);')" \
  "$(J 'hideAll(); return JSON.stringify(tap("mainChart", 0.53, 0.6, "touch"));')" \
  "$(J 'hideAll(); const svg = document.getElementById("mainChart"); svg.scrollIntoView({block: "center"}); const b = svg.getBoundingClientRect(); const qs = [...svg.querySelectorAll("circle[stroke-width=\"2\"]")].map(c => { const r = c.getBoundingClientRect(); return {x: r.left + r.width / 2, y: r.top + r.height / 2}; }); for (let px = b.left + 2; px < b.right - 2; px += 1) { const q = qs.reduce((a, c) => Math.abs(c.x - px) < Math.abs(a.x - px) ? c : a); const d = Math.abs(q.x - px); const el = document.elementFromPoint(px, q.y); if (d >= 6 && d <= 18 && el && el.getAttribute("class") === "chart-touch") { const r = tap("mainChart", (px - b.left) / b.width, (q.y - b.top) / b.height, "touch"); r.offsetPx = Math.round(d); return JSON.stringify(r); } } return JSON.stringify({hit: "no free spot found", shown: false, text: ""});')" \
  "$(J 'hideAll(); return JSON.stringify(tap("lagChart", 0.31, 0.5, "touch"));')" \
  "$(J 'hideAll(); return JSON.stringify(tap("mainChart", 0.53, 0.6, "pen"));')" \
  "$(J 'hideAll(); return JSON.stringify(tap("mainChart", 0.53, 0.6, "mouse"));')" \
  "$(J 'tap("lagChart", 0.31, 0.5, "touch"); hideAll(); return JSON.stringify({shown: document.querySelector("#lagChart").parentElement.querySelector(".tooltip").style.opacity === "1"});')" \
  > "$WORK/run.txt" 2>&1

res() { grep '^RESULT ' "$WORK/run.txt" | sed -n "${1}p" | sed 's/^RESULT //'; }
fld() { res "$1" | python3 -c "import json,sys; d=json.load(sys.stdin); print($2)" 2>/dev/null; }

check "C1 touch overlay covers each plot (at least 44px in both directions)" "True" "$(res 1 | python3 -c 'import json,sys; print(all(v >= 44 for v in json.load(sys.stdin)))' 2>/dev/null)"
check "C2 tap between weather points hits the overlay and shows the nearest point" "rect.chart-touch True True" \
  "$(fld 2 "d['hit'], d['shown'], d['text'].count('Z  ') == 1" | tr -d "(),'")"
check "C3 tap 6-18px beside an earthquake marker, on the overlay (not on any mark): earthquake tooltip" "rect.chart-touch True True" "$(fld 3 "d['hit'], d['shown'], '震度' in d['text']" | tr -d "(),'")"
check "C4 tap on the lag chart: nearest lag point" "True True" "$(fld 4 "d['shown'], d['text'].startswith('lag=')" | tr -d "(),'")"
check "C5 Apple Pencil (pen) works the same as a finger" "True" "$(fld 5 "d['shown']")"
check "C6 mouse on the overlay does nothing (desktop keeps per-mark hover only)" "False" "$(fld 6 "d['shown']")"
check "C7 a tap elsewhere hides the tooltip" "False" "$(fld 7 "d['shown']")"
grep -q '^ERROR\|RESULT ERROR' "$WORK/run.txt" && { FAIL=$((FAIL+1)); echo "  FAIL: driver/JS error:"; grep -E '^ERROR|RESULT ERROR' "$WORK/run.txt" | cut -c1-300; }

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
