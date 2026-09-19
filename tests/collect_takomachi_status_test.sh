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
trap stop_mock EXIT

BEFORE_LOCK_HASH="not_present"
[ -f security/state/SHUTDOWN.lock ] && BEFORE_LOCK_HASH="$(shasum -a 256 security/state/SHUTDOWN.lock | awk '{print $1}')"

echo "=== Dashboard: Takomachi status collector (Phase 76) ==="

echo "[TK1] no TAKOMACHI_API_KEY at all (unset, and this test env has no real Keychain entry): reports unavailable, exits 0, no hang"
unset TAKOMACHI_API_KEY 2>/dev/null || true
TAKOMACHI_API_URL="http://127.0.0.1:1" ./dashboard/collect_takomachi_status.sh >/dev/null 2>&1
TK1_RC=$?
assert_eq "TK1 exit 0" "0" "$TK1_RC"

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
