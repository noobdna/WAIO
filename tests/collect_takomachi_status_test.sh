#!/bin/bash
set -uo pipefail

# tests/collect_takomachi_status_test.sh -- regression suite for
# Phase 76 (Dashboard integration): dashboard/collect_takomachi_status.sh.
#
# Deliberately does NOT attempt to test the real macOS Keychain +
# real Takomachi path -- per tests/orchestrate_worker_test.sh's own
# documented finding (still true here), TAKOMACHI_API_KEY Keychain
# access only succeeds from an interactive GUI Terminal session, so
# that combination stays "manually verified only" like every other
# Takomachi-dispatch case in this repo. This suite instead: (a) drives
# the script entirely via the TAKOMACHI_API_KEY/TAKOMACHI_API_URL
# environment-variable overrides against a local, unauthenticated
# Python http.server fixture standing in for Takomachi, and (b)
# statically verifies the script can never reach
# security/lib.sh's egress_check/trigger_shutdown (see that file's own
# header for why that boundary is load-bearing here).
#
# Every invocation in this suite uses a 5s wall-clock tool timeout in
# the harness that runs it (not expressible in the suite itself) --
# the script's own curl calls are already bounded to 3s each via
# --max-time, so the suite as a whole cannot hang even if a step
# behaves unexpectedly.

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

OUT_PATH="logs/takomachi-status-latest.json"
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

MOCK_PORT=18933
MOCK_PID=""

start_mock() {
  python3 - "$MOCK_PORT" > /dev/null 2>&1 <<'PYEOF' &
import json, sys
from http.server import BaseHTTPRequestHandler, HTTPServer

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/health":
            body = json.dumps({"agent_manager": {"status": "ok"}, "task_queue": {"status": "ok"}, "plugin_system": {"status": "ok"}, "checked_at": "2026-09-18T00:00:00Z"}).encode()
        elif self.path == "/agents":
            # Deliberately omits waio-ai/waio-orchestrate (present in
            # workers/takomachi_agents.conf) so TK4 below can prove the new
            # expected_agents drift check actually detects a real
            # mismatch, not just an always-true/always-false stub.
            body = json.dumps([{"id": "waio-research", "status": "idle"}, {"id": "waio-analysis", "status": "busy"}]).encode()
        elif self.path == "/tasks":
            body = json.dumps([{"id": "t1", "status": "in_progress", "assigned_agent_id": "waio-analysis"}]).encode()
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

# Keychain isolation: the collector falls back to `security
# find-generic-password` when TAKOMACHI_API_KEY is unset (TK1). Without
# this stub that is a REAL Keychain read of the operator's Takomachi
# key -- and from a GUI session it can succeed, so TK1 would silently
# run with the live key instead of testing the "no key" path. The stub
# records each call and finds nothing.
mkdir -p "$EDGE_TMP/secbin"
cat > "$EDGE_TMP/secbin/security" <<STUBEOF
#!/bin/bash
printf '%s\n' "\$*" >> "$EDGE_TMP/security-calls.log"
exit 44
STUBEOF
chmod +x "$EDGE_TMP/secbin/security"
export PATH="$EDGE_TMP/secbin:$PATH"

cleanup_all() { stop_mock; stop_edge_mock; rm -rf "$EDGE_TMP"; }
trap cleanup_all EXIT

BEFORE_LOCK_HASH="not_present"
[ -f security/state/SHUTDOWN.lock ] && BEFORE_LOCK_HASH="$(shasum -a 256 security/state/SHUTDOWN.lock | awk '{print $1}')"

echo "=== Dashboard: Takomachi status collector (Phase 76) ==="

echo "[TK1] no TAKOMACHI_API_KEY at all (unset, and this test env has no real Keychain entry): reports unavailable, exits 0, no hang"
unset TAKOMACHI_API_KEY 2>/dev/null || true
TAKOMACHI_API_URL="http://127.0.0.1:1" ./dashboard/collect_takomachi_status.sh >/dev/null 2>&1
TK1_RC=$?
assert_eq "TK1 exit 0" "0" "$TK1_RC"
assert_eq "TK1 Keychain lookup went to the test stub, not the real Keychain" "1" "$(grep -c 'find-generic-password' "$EDGE_TMP/security-calls.log" 2>/dev/null || echo 0)"
assert_eq "TK1 available false" "false" "$(out_get available)"

echo "[TK2] a key is present but Takomachi is unreachable: reports unavailable with a clear reason, exits 0"
TAKOMACHI_API_KEY="fake-key" TAKOMACHI_API_URL="http://127.0.0.1:1" ./dashboard/collect_takomachi_status.sh >/dev/null 2>&1
TK2_RC=$?
assert_eq "TK2 exit 0" "0" "$TK2_RC"
assert_eq "TK2 available false" "false" "$(out_get available)"
assert_eq "TK2 expected_agents null when Takomachi unreachable (registration status unknown, not 'missing')" "null" "$(out_get expected_agents)"

echo "[TK3] Takomachi reachable and returning real-shaped data: available true, health/agents/tasks all populated"
start_mock
TAKOMACHI_API_KEY="fake-key" TAKOMACHI_API_URL="http://127.0.0.1:$MOCK_PORT" ./dashboard/collect_takomachi_status.sh >/dev/null 2>&1
TK3_RC=$?
stop_mock
assert_eq "TK3 exit 0" "0" "$TK3_RC"
assert_eq "TK3 available true" "true" "$(out_get available)"
assert_eq "TK3 health agent_manager status" '"ok"' "$(out_get health.agent_manager.status)"
assert_eq "TK3 agents count" "2" "$(out_get agents.count)"
assert_eq "TK3 tasks count" "1" "$(out_get tasks.count)"

echo "[TK4] expected_agents drift check: workers/takomachi_agents.conf lists 4 ids, the mock above only registered 2 -- waio-ai/waio-orchestrate must show up as explicitly 'missing', not silently absent"
assert_eq "TK4 source" '"workers/takomachi_agents.conf"' "$(out_get expected_agents.source)"
assert_eq "TK4 all_registered is false" "false" "$(out_get expected_agents.all_registered)"
MISSING_JSON="$(out_get expected_agents.missing)"
assert_contains_json() {
  local label="$1" haystack="$2" needle="$3"
  case "$haystack" in
    *"$needle"*) PASS=$((PASS + 1)); echo "  PASS: $label" ;;
    *) FAIL=$((FAIL + 1)); FAILURES+=("$label (expected '$haystack' to contain '$needle')"); echo "  FAIL: $label (expected '$haystack' to contain '$needle')" ;;
  esac
}
assert_contains_json "TK4 missing includes waio-ai" "$MISSING_JSON" '"waio-ai"'
assert_contains_json "TK4 missing includes waio-orchestrate" "$MISSING_JSON" '"waio-orchestrate"'
REGISTERED_JSON="$(out_get expected_agents.registered)"
assert_contains_json "TK4 registered includes waio-research" "$REGISTERED_JSON" '"waio-research"'
assert_contains_json "TK4 registered includes waio-analysis" "$REGISTERED_JSON" '"waio-analysis"'

TK_ROUTES='{"/health": {"agent_manager": {"status": "ok"}, "task_queue": {"status": "ok"}, "plugin_system": {"status": "ok"}}, "/agents": [{"id": "waio-research", "status": "idle"}], "/tasks": []}'

echo "[TK5] TAKOMACHI_API_KEY reaches Takomachi as a Bearer header but never appears in curl's argv (visible to every local user via ps)"
start_edge_mock ok "$TK_ROUTES"
curl_argv_reset
PATH="$EDGE_TMP/bin:$PATH" TAKOMACHI_API_KEY="tk5-secret-key" TAKOMACHI_API_URL="http://127.0.0.1:$EDGE_PORT" \
  ./dashboard/collect_takomachi_status.sh >/dev/null 2>&1
stop_edge_mock
assert_eq "TK5 available true" "true" "$(out_get available)"
assert_eq "TK5 curl called once per endpoint" "3" "$(curl_argv_calls)"
assert_not_contains "TK5 key absent from curl argv" "$(cat "$EDGE_TMP/curl-argv.log")" "tk5-secret-key"
assert_eq "TK5 every request carried the Bearer header" "3" "$(grep -c ' Bearer tk5-secret-key$' "$EDGE_AUTH_LOG")"

echo "[TK6] a 200 /health whose body is not Takomachi JSON (captive portal / another web app on :3000) is NOT reported as AVAILABLE"
start_edge_mock html "$TK_ROUTES"
TAKOMACHI_API_KEY="fake-key" TAKOMACHI_API_URL="http://127.0.0.1:$EDGE_PORT" ./dashboard/collect_takomachi_status.sh >/dev/null 2>&1
stop_edge_mock
assert_eq "TK6 available false" "false" "$(out_get available)"
assert_contains "TK6 reason says the body was not JSON" "$(out_get reason)" "not a JSON object"

echo "[TK7] headers say 200 but the /health body never completes (curl hits --max-time with %{http_code}=200 already set): a timed-out transfer is NOT available"
start_edge_mock stall "$TK_ROUTES"
TAKOMACHI_API_KEY="fake-key" TAKOMACHI_API_URL="http://127.0.0.1:$EDGE_PORT" ./dashboard/collect_takomachi_status.sh >/dev/null 2>&1
stop_edge_mock
assert_eq "TK7 available false" "false" "$(out_get available)"
assert_contains "TK7 reason names the transport error" "$(out_get reason)" "curl exit 28"

echo "[D1] this script never sources security/lib.sh and never actually CALLS egress_check/trigger_shutdown (static guard -- prose in this script's own header and JSON 'note' field legitimately mentions both names, so the check looks for an actual sourcing line / function call, not just the words)"
SOURCES_LIB="$(grep -cE '^\s*source security/lib\.sh\b' dashboard/collect_takomachi_status.sh || true)"
assert_eq "D1 does not source security/lib.sh" "0" "$SOURCES_LIB"
CALLS_GUARDS="$(grep -cE '\b(egress_check|trigger_shutdown)\s*"' dashboard/collect_takomachi_status.sh || true)"
assert_eq "D1 never calls egress_check/trigger_shutdown as functions" "0" "$CALLS_GUARDS"

echo "[D2] this deployment's real security/state/SHUTDOWN.lock (a pre-existing, unrelated Red Team fixture, per ARCHITECTURE.md) is byte-for-byte unchanged by everything TK1-TK3/D1 above"
AFTER_LOCK_HASH="not_present"
[ -f security/state/SHUTDOWN.lock ] && AFTER_LOCK_HASH="$(shasum -a 256 security/state/SHUTDOWN.lock | awk '{print $1}')"
assert_eq "D2 real SHUTDOWN.lock checksum unchanged (present-or-absent state preserved either way)" "$BEFORE_LOCK_HASH" "$AFTER_LOCK_HASH"

echo
echo "=== Results: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
  echo "Failures:"
  for f in "${FAILURES[@]}"; do echo "  - $f"; done
  exit 1
fi
exit 0
