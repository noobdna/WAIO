#!/bin/bash
set -uo pipefail

# tests/ipad_reconnect_test.sh -- dashboard/index.html when the connection to
# the server drops and comes back, as it does when an iPad's SSH port forward
# closes because the SSH app went to the background (docs/IPAD_PRO_ACCESS.md).
#
# Runs the page in WebKit (tests/ipad_reconnect_check.swift) against the real
# dashboard/serve_dashboard.py on a free loopback port, with a fixture
# waio-status-latest.json whose state (CONTAINMENT) differs from the
# embedded sample's (NORMAL). The suite stops and restarts its own server
# mid-scenario.
#
#   R1  live data shown, no connection notice
#   R2  server gone: the last live CONTAINMENT stays (never the sample's
#       NORMAL), the notice is shown, the labels stop saying live/refreshed
#   R3  server back: live again, notice gone
#   R4  auto-refresh on + returning to the tab (visibilitychange, simulated):
#       new data at once, not after the 10s timer
#   R5  auto-refresh off: visibilitychange does not fetch (opt-in kept)
#   R6  never live (no logs): embedded sample, no connection notice
#
# macOS only (WKWebView). SKIPS -- not fails -- without swiftc/WebKit.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR" || exit 1
# WAIO_TEST_NO_SKIP=1 (set in CI): a missing tool is a failure, never a silent green skip
SKIP_RC=0; [ "${WAIO_TEST_NO_SKIP:-}" = 1 ] && SKIP_RC=1

echo "=== Dashboard: dropped connection and reconnect (iPad SSH forward) ==="
if [ "$(uname)" != "Darwin" ] || ! command -v swiftc >/dev/null 2>&1; then
  echo "[IPAD RECONNECT TEST] SKIP: needs macOS with swiftc (WebKit); not available here."
  exit "$SKIP_RC"
fi

WORK="$(mktemp -d "${TMPDIR:-/tmp}/waio-ipad-reconnect.XXXXXX")"
mkdir -p "$WORK/logs" "$WORK/empty"
cleanup() {
  # only the server this suite started (pid file); never by name or pattern
  [ -f "$WORK/srv.pid" ] && kill "$(cat "$WORK/srv.pid")" 2>/dev/null
  rm -rf "${WORK:?}"
}
trap cleanup EXIT

PASS=0; FAIL=0
check() { if [ "$2" = "$3" ]; then PASS=$((PASS+1)); echo "  PASS: $1"; else FAIL=$((FAIL+1)); echo "  FAIL: $1 (expected='$2' actual='$3')"; fi; }

if ! swiftc -O -o "$WORK/scenario" tests/ipad_reconnect_check.swift > "$WORK/build.log" 2>&1; then
  echo "[IPAD RECONNECT TEST] SKIP: could not build the WebKit driver (toolchain problem, not a result):"
  sed 's/^/  /' "$WORK/build.log" | head -5
  exit "$SKIP_RC"
fi

# fixture: the page's own FALLBACK_STATUS with a state the sample does not have
node -e '
const fs = require("fs"); const s = fs.readFileSync("dashboard/index.html", "utf8");
const d = eval("(" + s.match(/const FALLBACK_STATUS = (\{[\s\S]*?\n\});/)[1] + ")");
Object.assign(d, { waio_status: "CONTAINMENT", waio_status_note: "fixture", generated_at: new Date().toISOString() });
fs.writeFileSync(process.argv[1], JSON.stringify(d));' "$WORK/logs/waio-status-latest.json" || { echo "  FAIL: fixture"; exit 1; }

PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')"
# ctl start LOGSDIR | ctl stop | ctl set-status STATE -- run by the WebKit driver's sh: steps.
# start fails if the port is already answering; stop waits until it no longer does.
# Up to 10 s each way: a CI runner's first python3 start can take several seconds.
cat > "$WORK/ctl" <<EOF
#!/bin/sh
up() { curl -s -o /dev/null --max-time 1 "http://127.0.0.1:$PORT/"; }
case "\$1" in
  start)
    if up; then echo "ctl: port $PORT already answering" >> "$WORK/ctl.log"; exit 1; fi
    (cd "$SCRIPT_DIR" && WAIO_DASHBOARD_BIND=127.0.0.1 WAIO_DASHBOARD_PORT=$PORT WAIO_DASHBOARD_AUTH_FILE= WAIO_DASHBOARD_ALLOWED_CLIENTS= \\
      WAIO_DASHBOARD_LOGS_ROOT="\$2" exec python3 dashboard/serve_dashboard.py >> "$WORK/server.log" 2>&1) &
    echo \$! > "$WORK/srv.pid"
    i=0; while [ \$i -lt 100 ]; do i=\$((i+1)); up && { echo "ctl: started" >> "$WORK/ctl.log"; exit 0; }; sleep 0.1; done
    echo "ctl: start failed" >> "$WORK/ctl.log"; exit 1 ;;
  stop)
    kill "\$(cat "$WORK/srv.pid")" 2>/dev/null
    i=0; while [ \$i -lt 100 ]; do i=\$((i+1)); up || { echo "ctl: stopped" >> "$WORK/ctl.log"; exit 0; }; sleep 0.1; done
    echo "ctl: stop failed" >> "$WORK/ctl.log"; exit 1 ;;
  set-status)
    python3 -c 'import json,sys; p=sys.argv[1]; d=json.load(open(p)); d["waio_status"]=sys.argv[2]; json.dump(d, open(p,"w"))' "$WORK/logs/waio-status-latest.json" "\$2" ;;
esac
EOF
chmod +x "$WORK/ctl"

URL="http://127.0.0.1:$PORT/"
SNAP='js:JSON.stringify({badge: document.getElementById("waioStatusBadge").textContent, source: document.getElementById("dataSourceStatus").textContent, refreshed: document.getElementById("refreshStatus").textContent, notice: !document.getElementById("connectionNotice").hidden, noticeText: document.getElementById("connectionNotice").textContent})'
CLICK='js:document.getElementById("refreshNowBtn").click(); "clicked"'
# Returning to the tab is SIMULATED: the offscreen WebKit view reports "hidden", so the
# test sets visibilityState to "visible" (what iPadOS does on return) and fires the event.
VIS='js:Object.defineProperty(document, "visibilityState", {configurable: true, get: () => "visible"}); document.dispatchEvent(new Event("visibilitychange")); "visible"'
TOGGLE='js:document.getElementById("autoRefreshToggle").click(); String(document.getElementById("autoRefreshToggle").checked)'

show_start_failure() { echo "  FAIL: test server did not start${1:-}"; sed 's/^/    ctl: /' "$WORK/ctl.log" 2>/dev/null; tail -5 "$WORK/server.log" 2>/dev/null | sed 's/^/    server: /'; }
"$WORK/ctl" start "$WORK/logs" || { show_start_failure; exit 1; }
"$WORK/scenario" "$URL" wait:2 "$SNAP" "sh:$WORK/ctl stop" "$CLICK" wait:2 "$SNAP" "sh:$WORK/ctl start $WORK/logs" "$CLICK" wait:2 "$SNAP" \
  "$TOGGLE" wait:1 "sh:$WORK/ctl set-status RECOVERY" "$VIS" wait:1.5 "$SNAP" \
  "$TOGGLE" wait:0.5 "sh:$WORK/ctl set-status ISOLATED" "$VIS" wait:1.5 "$SNAP" > "$WORK/run1.txt" 2>&1
"$WORK/ctl" stop
check "R0 server control: start, stop, start, stop all confirmed" "started stopped started stopped" "$(sed 's/ctl: //' "$WORK/ctl.log" | tr '\n' ' ' | sed 's/ $//')"

snap() { grep '^RESULT {' "$WORK/run1.txt" | sed -n "${1}p" | sed 's/^RESULT //' | python3 -c "import json,sys; d=json.load(sys.stdin); print($2)"; }
check "R1 live: CONTAINMENT from the server, labelled live, no notice" "CONTAINMENT True False" "$(snap 1 "d['badge'], d['source'].startswith('live:'), d['notice']" | tr -d "(),'")"
check "R2 server gone: last live CONTAINMENT kept (not the sample's NORMAL)" "CONTAINMENT" "$(snap 2 "d['badge']")"
check "R2 server gone: connection notice shown, says connection lost" "True True" "$(snap 2 "d['notice'], d['noticeText'].startswith('Connection to the dashboard server lost')" | tr -d "(),'")"
check "R2 server gone: labels no longer claim live / refreshed" "False True" "$(snap 2 "d['source'].startswith('live:'), d['refreshed'].startswith('refresh failed')" | tr -d "(),'")"
check "R3 server back: live again, notice gone, refreshed" "CONTAINMENT True False True" "$(snap 3 "d['badge'], d['source'].startswith('live:'), d['notice'], d['refreshed'].startswith('refreshed')" | tr -d "(),'")"
check "R4 auto-refresh on, tab visible again: new state at once (no 10s wait)" "RECOVERY" "$(snap 4 "d['badge']")"
check "R5 auto-refresh off: visibilitychange does not fetch" "RECOVERY" "$(snap 5 "d['badge']")"

"$WORK/ctl" start "$WORK/empty" || { show_start_failure " (R6)"; exit 1; }
"$WORK/scenario" "$URL" wait:2 "$SNAP" > "$WORK/run2.txt" 2>&1
"$WORK/ctl" stop
r6="$(grep '^RESULT {' "$WORK/run2.txt" | sed 's/^RESULT //' | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['badge'], d['source'].startswith('sample:'), d['notice'])")"
check "R6 never live (no logs): embedded sample, no connection notice (unchanged behaviour)" "NORMAL True False" "$r6"

grep -q '^ERROR' "$WORK/run1.txt" "$WORK/run2.txt" && { FAIL=$((FAIL+1)); echo "  FAIL: driver error:"; grep -h '^ERROR' "$WORK/run1.txt" "$WORK/run2.txt"; }
echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
