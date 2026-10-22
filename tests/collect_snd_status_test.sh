#!/bin/bash
set -uo pipefail

# tests/collect_snd_status_test.sh -- regression suite for Phase 76
# (Dashboard integration): dashboard/collect_snd_status.sh.
#
# SND_HOME itself is not present on this machine as of this phase (only
# a backup copy on an external volume, per this phase's own investigation
# in ARCHITECTURE.md) -- so this suite drives the script entirely via
# the SND_HOME_API_URL/SND_HOME_API_TOKEN environment-variable
# overrides against a local, unauthenticated Python http.server
# fixture standing in for SND_HOME, plus the same static egress_check/
# trigger_shutdown-absence guard as
# tests/collect_takomachi_status_test.sh.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"

PASS=0
FAIL=0
declare -a FAILURES=()

assert_eq() {
  local label="$1" expected="$2" actual="$3"
  if [ "$expected" = "$actual" ]; then
    PASS=$((PASS + 1)); echo "  PASS: $label"
  else
    FAIL=$((FAIL + 1)); FAILURES+=("$label (expected='$expected' actual='$actual')")
    echo "  FAIL: $label (expected='$expected' actual='$actual')"
  fi
}

OUT_PATH="logs/snd-status-latest.json"
out_get() {
  python3 -c "
import json
d = json.load(open('$OUT_PATH'))
node = d
for part in '$1'.split('.'):
    node = node[part]
print(json.dumps(node))
" 2>/dev/null
}

MOCK_PORT=18934
MOCK_PID=""

start_mock() {
  python3 - "$MOCK_PORT" > /dev/null 2>&1 <<'PYEOF' &
import json, sys
from http.server import BaseHTTPRequestHandler, HTTPServer

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/api/lan/status":
            body = json.dumps({"devices_total": 5, "devices_online": 4}).encode()
        elif self.path == "/api/system/latest":
            body = json.dumps({"cpu_pct": 12.3}).encode()
        elif self.path == "/api/alerts/active":
            body = json.dumps([{"id": "a1", "severity": "warning"}]).encode()
        elif self.path == "/api/lan/terminals":
            # Real SND_HOME shape (routes/lan.js: {status, data}), one
            # operator-confirmed terminal (nickname set) and one that
            # isn't (nickname null) -- SN5 below proves both render
            # distinctly, not just an always-empty/always-full stub.
            body = json.dumps({"status": "ok", "data": [
                {"terminalId": "aa:bb:cc:dd:ee:01", "displayIp": "192.168.1.44", "online": True,
                 "macs": ["aa:bb:cc:dd:ee:01"], "nickname": "living-room-pc",
                 "firstSeenAt": "2026-09-01T00:00:00.000Z", "lastSeenAt": "2026-09-19T00:00:00.000Z"},
                {"terminalId": "aa:bb:cc:dd:ee:02", "displayIp": "192.168.1.77", "online": True,
                 "macs": ["aa:bb:cc:dd:ee:02"], "nickname": None,
                 "firstSeenAt": "2026-09-19T00:00:00.000Z", "lastSeenAt": "2026-09-19T00:05:00.000Z"},
            ]}).encode()
        else:
            self.send_response(404); self.end_headers(); return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a):
        pass

HTTPServer(("127.0.0.1", int(sys.argv[1])), Handler).serve_forever()
PYEOF
  MOCK_PID=$!
  sleep 0.5
}

stop_mock() {
  [ -n "$MOCK_PID" ] && kill "$MOCK_PID" 2>/dev/null
  wait "$MOCK_PID" 2>/dev/null
  MOCK_PID=""
}
# --- Edge-case mock (ephemeral port, threaded) -------------------------
# start_edge_mock MODE ROUTES_JSON -- MODE is one of:
#   ok     every route in ROUTES_JSON answers 200 + its JSON
#   html   every route answers 200 with a text/html page (a captive
#          portal / some other web app that happens to own the port)
#   stall  the FIRST route in ROUTES_JSON answers 200 + its JSON but
#          declares a larger Content-Length and then hangs (headers
#          arrive, body never completes -- curl hits --max-time with
#          %{http_code}=200 already set)
#   huge   the FIRST route answers 200 with a ~1.5 MB valid JSON body
# Every request's Authorization header is appended to $EDGE_AUTH_LOG.
# Binds 127.0.0.1:0 and writes the chosen port to a file -- no fixed
# port, so it can never collide with another suite or a live service.
EDGE_TMP="$(mktemp -d)"
EDGE_AUTH_LOG="$EDGE_TMP/auth.log"
EDGE_PID=""
EDGE_PORT=""
start_edge_mock() {
  local mode="$1" routes="$2"
  rm -f "$EDGE_TMP/port"
  : > "$EDGE_AUTH_LOG"
  python3 - "$EDGE_TMP/port" "$mode" "$EDGE_AUTH_LOG" "$routes" > /dev/null 2>&1 <<'PYEOF' &
import json, sys, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
port_file, mode, auth_log, routes_json = sys.argv[1:5]
routes = json.loads(routes_json)
first = next(iter(routes))

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        with open(auth_log, "a") as f:
            f.write("%s %s\n" % (self.path, self.headers.get("Authorization", "")))
        if self.path not in routes:
            self.send_response(404); self.end_headers(); return
        ctype = "application/json"
        body = json.dumps(routes[self.path]).encode()
        length = len(body)
        if mode == "html":
            ctype, body = "text/html", b"<html><body>Login required</body></html>"
            length = len(body)
        elif mode == "stall" and self.path == first:
            length = len(body) + 4096
        elif mode == "huge" and self.path == first:
            obj = dict(routes[self.path]) if isinstance(routes[self.path], dict) else {}
            obj["pad"] = "x" * 1500000
            body = json.dumps(obj).encode()
            length = len(body)
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(length))
        self.end_headers()
        self.wfile.write(body)
        self.wfile.flush()
        if mode == "stall" and self.path == first:
            time.sleep(8)
    def log_message(self, *a):
        pass

srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
srv.daemon_threads = True
with open(port_file + ".tmp", "w") as f:
    f.write(str(srv.server_address[1]))
import os; os.rename(port_file + ".tmp", port_file)
srv.serve_forever()
PYEOF
  EDGE_PID=$!
  local i=0
  while [ ! -s "$EDGE_TMP/port" ] && [ "$i" -lt 50 ]; do sleep 0.1; i=$((i + 1)); done
  EDGE_PORT="$(cat "$EDGE_TMP/port" 2>/dev/null)"
}
stop_edge_mock() {
  [ -n "$EDGE_PID" ] && kill "$EDGE_PID" 2>/dev/null
  [ -n "$EDGE_PID" ] && wait "$EDGE_PID" 2>/dev/null
  EDGE_PID=""
}

# Recording curl wrapper: logs its own argv (one line per call) then
# execs the real curl with stdin untouched, so a test can prove what
# any local user would see in `ps` for that process.
REAL_CURL="$(command -v curl)"
mkdir -p "$EDGE_TMP/bin"
cat > "$EDGE_TMP/bin/curl" <<STUBEOF
#!/bin/bash
printf '%s\n' "\$*" >> "$EDGE_TMP/curl-argv.log"
exec "$REAL_CURL" "\$@"
STUBEOF
chmod +x "$EDGE_TMP/bin/curl"
curl_argv_reset() { : > "$EDGE_TMP/curl-argv.log"; }
curl_argv_calls() { wc -l < "$EDGE_TMP/curl-argv.log" | tr -d ' '; }

assert_not_contains() {
  local label="$1" haystack="$2" needle="$3"
  case "$haystack" in
    *"$needle"*) FAIL=$((FAIL + 1)); FAILURES+=("$label (found '$needle')"); echo "  FAIL: $label (found '$needle')" ;;
    *) PASS=$((PASS + 1)); echo "  PASS: $label" ;;
  esac
}
assert_contains() {
  local label="$1" haystack="$2" needle="$3"
  case "$haystack" in
    *"$needle"*) PASS=$((PASS + 1)); echo "  PASS: $label" ;;
    *) FAIL=$((FAIL + 1)); FAILURES+=("$label (expected to contain '$needle', got '$haystack')"); echo "  FAIL: $label (expected to contain '$needle', got '$haystack')" ;;
  esac
}

cleanup_all() { stop_mock; stop_edge_mock; rm -rf "$EDGE_TMP"; }
trap cleanup_all EXIT

BEFORE_LOCK_HASH="not_present"
[ -f security/state/SHUTDOWN.lock ] && BEFORE_LOCK_HASH="$(shasum -a 256 security/state/SHUTDOWN.lock | awk '{print $1}')"

echo "=== Dashboard: SND status collector (Phase 76) ==="

echo "[SN1] no SND_HOME_API_URL configured (default, this deployment's normal state): reports not configured, zero network attempts, exits 0"
unset SND_HOME_API_URL SND_HOME_API_TOKEN 2>/dev/null || true
./dashboard/collect_snd_status.sh >/dev/null 2>&1
SN1_RC=$?
assert_eq "SN1 exit 0" "0" "$SN1_RC"
assert_eq "SN1 configured false" "false" "$(out_get configured)"
assert_eq "SN1 available false" "false" "$(out_get available)"

echo "[SN2] SND_HOME_API_URL configured but unreachable: reports unavailable with a clear reason, exits 0"
SND_HOME_API_URL="http://127.0.0.1:1" ./dashboard/collect_snd_status.sh >/dev/null 2>&1
SN2_RC=$?
assert_eq "SN2 exit 0" "0" "$SN2_RC"
assert_eq "SN2 configured true" "true" "$(out_get configured)"
assert_eq "SN2 available false" "false" "$(out_get available)"

echo "[SN3] SND_HOME_API_URL configured, with a token, unreachable: still exits 0 cleanly (bash 3.2 empty-array-under-set-u regression guard)"
SND_HOME_API_URL="http://127.0.0.1:1" SND_HOME_API_TOKEN="tok" ./dashboard/collect_snd_status.sh >/dev/null 2>&1
SN3_RC=$?
assert_eq "SN3 exit 0" "0" "$SN3_RC"

echo "[SN4] SND_HOME reachable and returning real-shaped data: available true, lan/system/alerts all populated"
start_mock
SND_HOME_API_URL="http://127.0.0.1:$MOCK_PORT" ./dashboard/collect_snd_status.sh >/dev/null 2>&1
SN4_RC=$?
stop_mock
assert_eq "SN4 exit 0" "0" "$SN4_RC"
assert_eq "SN4 available true" "true" "$(out_get available)"
assert_eq "SN4 lan_status devices_online" "4" "$(out_get lan_status.devices_online)"
assert_eq "SN4 active_alerts count" "1" "$(out_get active_alerts | python3 -c 'import json,sys; print(len(json.load(sys.stdin)))')"

echo "[SN5] GET /api/lan/terminals: existing SND_HOME endpoint reused as-is, envelope unwrapped to a plain list, confirmed/unconfirmed nicknames both pass through untouched"
TERMINALS_JSON="$(out_get terminals)"
assert_eq "SN5 terminals count" "2" "$(echo "$TERMINALS_JSON" | python3 -c 'import json,sys; print(len(json.load(sys.stdin)))')"
assert_eq "SN5 first terminal mac" '["aa:bb:cc:dd:ee:01"]' "$(echo "$TERMINALS_JSON" | python3 -c 'import json,sys; print(json.dumps(json.load(sys.stdin)[0]["macs"]))')"
assert_eq "SN5 first terminal displayIp" '"192.168.1.44"' "$(echo "$TERMINALS_JSON" | python3 -c 'import json,sys; print(json.dumps(json.load(sys.stdin)[0]["displayIp"]))')"
assert_eq "SN5 first terminal nickname (confirmed)" '"living-room-pc"' "$(echo "$TERMINALS_JSON" | python3 -c 'import json,sys; print(json.dumps(json.load(sys.stdin)[0]["nickname"]))')"
assert_eq "SN5 second terminal nickname (unconfirmed, null preserved)" "null" "$(echo "$TERMINALS_JSON" | python3 -c 'import json,sys; print(json.dumps(json.load(sys.stdin)[1]["nickname"]))')"

SND_ROUTES='{"/api/lan/status": {"devices_total": 2, "devices_online": 1}, "/api/system/latest": {"cpu_pct": 1.0}, "/api/alerts/active": [], "/api/lan/terminals": {"status": "ok", "data": []}}'

echo "[SN6] SND_HOME_API_TOKEN reaches SND_HOME as a Bearer header but never appears in curl's argv (visible to every local user via ps)"
start_edge_mock ok "$SND_ROUTES"
curl_argv_reset
PATH="$EDGE_TMP/bin:$PATH" SND_HOME_API_URL="http://127.0.0.1:$EDGE_PORT" SND_HOME_API_TOKEN="sn6-secret-token" \
  ./dashboard/collect_snd_status.sh >/dev/null 2>&1
stop_edge_mock
assert_eq "SN6 available true" "true" "$(out_get available)"
assert_eq "SN6 curl called once per endpoint" "4" "$(curl_argv_calls)"
assert_not_contains "SN6 token absent from curl argv" "$(cat "$EDGE_TMP/curl-argv.log")" "sn6-secret-token"
assert_eq "SN6 every request carried the Bearer header" "4" "$(grep -c ' Bearer sn6-secret-token$' "$EDGE_AUTH_LOG")"

echo "[SN7] SND_HOME_API_URL validation: credentials embedded in the URL are refused and never echoed (output JSON is served by the dashboard; stdout lands in logs); non-http(s) schemes are refused; neither makes any curl call"
start_edge_mock ok "$SND_ROUTES"
curl_argv_reset
SN7_OUT="$(PATH="$EDGE_TMP/bin:$PATH" SND_HOME_API_URL="http://snduser:sn7-url-pass@127.0.0.1:$EDGE_PORT" ./dashboard/collect_snd_status.sh 2>&1)"
stop_edge_mock
assert_eq "SN7a configured true" "true" "$(out_get configured)"
assert_eq "SN7a available false" "false" "$(out_get available)"
assert_eq "SN7a no curl call made" "0" "$(curl_argv_calls)"
assert_not_contains "SN7a password absent from output JSON" "$(cat "$OUT_PATH")" "sn7-url-pass"
assert_not_contains "SN7a password absent from stdout" "$SN7_OUT" "sn7-url-pass"
assert_contains "SN7a reason names the problem" "$(out_get reason)" "credentials"
for bad in "file:///etc" "gopher://127.0.0.1:1/" "127.0.0.1:1" "http://"; do
  curl_argv_reset
  PATH="$EDGE_TMP/bin:$PATH" SND_HOME_API_URL="$bad" ./dashboard/collect_snd_status.sh >/dev/null 2>&1
  assert_eq "SN7b '$bad' available false" "false" "$(out_get available)"
  assert_eq "SN7b '$bad' no curl call made" "0" "$(curl_argv_calls)"
  assert_contains "SN7b '$bad' reason says invalid" "$(out_get reason)" "invalid SND_HOME_API_URL"
done

echo "[SN8] a 200 whose body is not SND_HOME JSON (captive portal / another web app on that port) is NOT reported as AVAILABLE"
start_edge_mock html "$SND_ROUTES"
SND_HOME_API_URL="http://127.0.0.1:$EDGE_PORT" ./dashboard/collect_snd_status.sh >/dev/null 2>&1
stop_edge_mock
assert_eq "SN8 available false" "false" "$(out_get available)"
assert_contains "SN8 reason says the body was not JSON" "$(out_get reason)" "not a JSON object"

echo "[D1] this script never sources security/lib.sh and never actually CALLS egress_check/trigger_shutdown (static guard, same rationale as tests/collect_takomachi_status_test.sh's own D1)"
SOURCES_LIB="$(grep -cE '^\s*source security/lib\.sh\b' dashboard/collect_snd_status.sh || true)"
assert_eq "D1 does not source security/lib.sh" "0" "$SOURCES_LIB"
CALLS_GUARDS="$(grep -cE '\b(egress_check|trigger_shutdown)\s*"' dashboard/collect_snd_status.sh || true)"
assert_eq "D1 never calls egress_check/trigger_shutdown as functions" "0" "$CALLS_GUARDS"

echo "[D2] this deployment's real security/state/SHUTDOWN.lock is byte-for-byte unchanged by everything above"
AFTER_LOCK_HASH="not_present"
[ -f security/state/SHUTDOWN.lock ] && AFTER_LOCK_HASH="$(shasum -a 256 security/state/SHUTDOWN.lock | awk '{print $1}')"
assert_eq "D2 real SHUTDOWN.lock checksum unchanged" "$BEFORE_LOCK_HASH" "$AFTER_LOCK_HASH"

echo
echo "=== Results: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
  echo "Failures:"
  for f in "${FAILURES[@]}"; do echo "  - $f"; done
  exit 1
fi
exit 0
