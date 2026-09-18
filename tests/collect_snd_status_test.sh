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
