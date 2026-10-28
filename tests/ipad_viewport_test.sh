#!/bin/bash
set -uo pipefail

# tests/ipad_viewport_test.sh -- iPad Pro layout check for dashboard/index.html
# and dashboard/earth_weather.html (docs/IPAD_PRO_TEST_REPORT.md).
#
# Serves the pages with the real dashboard/serve_dashboard.py on a free
# loopback port, with an EMPTY logs dir (so the pages render their embedded
# sample data and no live state is read), then lays each page out in WebKit
# via tests/ipad_viewport_check.swift at iPad Pro portrait/landscape sizes,
# Split View, Slide Over and a desktop size. Fails on: horizontal page
# overflow, an element sticking out past the right edge, visible text under
# 12px, or a touch target under 44x44 CSS px.
#
# macOS only (WKWebView). SKIPS -- not fails -- without swiftc/WebKit, e.g.
# on the Linux CI runner. Screenshots: $IPAD_VIEWPORT_OUT if set, else a
# temp dir that is removed afterwards.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR" || exit 1
# WAIO_TEST_NO_SKIP=1 (set in CI): a missing tool is a failure, never a silent green skip
SKIP_RC=0; [ "${WAIO_TEST_NO_SKIP:-}" = 1 ] && SKIP_RC=1

echo "=== Dashboard: iPad Pro viewport layout ==="
if [ "$(uname)" != "Darwin" ] || ! command -v swiftc >/dev/null 2>&1; then
  echo "[IPAD VIEWPORT TEST] SKIP: needs macOS with swiftc (WebKit); not available here."
  exit "$SKIP_RC"
fi

WORK="$(mktemp -d "${TMPDIR:-/tmp}/waio-ipad-viewport.XXXXXX")"
OUT="${IPAD_VIEWPORT_OUT:-$WORK/shots}"
mkdir -p "$WORK/logs" "$OUT"
SERVER_PID=""
cleanup() {
  # only the server this suite started; never by name or pattern
  if [ -n "$SERVER_PID" ]; then kill "$SERVER_PID" 2>/dev/null; wait "$SERVER_PID" 2>/dev/null; fi
  rm -rf "${WORK:?}"
}
trap cleanup EXIT

if ! swiftc -O -o "$WORK/vpcheck" tests/ipad_viewport_check.swift > "$WORK/build.log" 2>&1; then
  echo "[IPAD VIEWPORT TEST] SKIP: could not build the WebKit checker (toolchain problem, not a layout result):"
  sed 's/^/  /' "$WORK/build.log" | head -5
  exit "$SKIP_RC"
fi

PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')"
WAIO_DASHBOARD_BIND=127.0.0.1 WAIO_DASHBOARD_PORT="$PORT" WAIO_DASHBOARD_AUTH_FILE= WAIO_DASHBOARD_ALLOWED_CLIENTS= \
  WAIO_DASHBOARD_LOGS_ROOT="$WORK/logs" python3 dashboard/serve_dashboard.py > "$WORK/server.log" 2>&1 &
SERVER_PID=$!
for _ in $(seq 1 100); do curl -s -o /dev/null --max-time 1 "http://127.0.0.1:$PORT/" && break; sleep 0.1; done  # up to 10 s (CI)

VIEWPORTS="pro11-portrait:834x1194 pro11-landscape:1194x834 pro13-portrait:1024x1366 pro13-landscape:1366x1024 split-half:678x1024 slideover:375x1024 desktop:1440x900"
# shellcheck disable=SC2086
"$WORK/vpcheck" "http://127.0.0.1:$PORT/" "$OUT" $VIEWPORTS > "$WORK/index.jsonl"
# shellcheck disable=SC2086
"$WORK/vpcheck" "http://127.0.0.1:$PORT/earth_weather.html" "$OUT" $(echo $VIEWPORTS | sed 's/\([a-z0-9-]*\):/ew-\1:/g') > "$WORK/ew.jsonl"

python3 - "$WORK" <<'PY'
import json, sys
work = sys.argv[1]
passed = failed = 0
for page, f in (("index.html", "index"), ("earth_weather.html", "ew")):
    rows = [json.loads(l) for l in open(f"{work}/{f}.jsonl") if l.strip()]
    if len(rows) != 7:
        print(f"  FAIL: {page}: expected 7 viewport results, got {len(rows)}"); failed += 1; continue
    for d in rows:
        m = d.get("m", {})
        if "error" in d or not isinstance(m, dict) or "hOverflow" not in m:
            print(f"  FAIL: {page} {d.get('viewport')}: no measurement ({d})"); failed += 1; continue
        checks = [
            ("no horizontal page overflow", not m["hOverflow"], m["scrollWidth"]),
            ("nothing sticks out past the right edge", m["overflowingCount"] == 0, m["overflowing"]),
            ("no visible text under 12px", m["smallTextCount"] == 0, m["smallTextSample"]),
            ("every touch target at least 44x44", not m["tinyTargets"], m["tinyTargets"]),
        ]
        for label, ok, detail in checks:
            name = f"{page} {d['viewport']} ({d['size']}): {label}"
            if ok: passed += 1; print(f"  PASS: {name}")
            else: failed += 1; print(f"  FAIL: {name} -- {detail}")
print(f"\n=== Results: {passed} passed, {failed} failed ===")
sys.exit(1 if failed else 0)
PY
