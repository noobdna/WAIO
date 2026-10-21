#!/bin/bash
# tests/collect_ducopa_control_status_test.sh -- dashboard/collect_ducopa_control_status.sh
# against a Python http.server fixture standing in for Takomachi's DuCoPA
# control plane (response shapes copied from Takomachi's
# src/api-gateway/server.ts getControlHeartbeat and
# src/dual-control-plane/types.ts LockdownEpisode). Never contacts a real
# Takomachi: the fixture binds 127.0.0.1 on an ephemeral port, and the
# collector's output goes to a temp file via WAIO_DUCOPA_CONTROL_STATUS_OUT,
# so nothing is written into this checkout's logs/.

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

assert_contains() {
  local label="$1" haystack="$2" needle="$3"
  case "$haystack" in
    *"$needle"*) PASS=$((PASS + 1)); echo "  PASS: $label" ;;
    *) FAIL=$((FAIL + 1)); FAILURES+=("$label (expected '$haystack' to contain '$needle')"); echo "  FAIL: $label (expected '$haystack' to contain '$needle')" ;;
  esac
}

WORK="$(mktemp -d "${TMPDIR:-/tmp}/ducopa-control-status-test.XXXXXX")"
export WAIO_DUCOPA_CONTROL_STATUS_OUT="$WORK/out.json"
COLLECTOR=./dashboard/collect_ducopa_control_status.sh

out_get() {
  python3 -c "
import json, sys
node = json.load(open(sys.argv[1]))
for part in sys.argv[2].split('.'):
    node = node[part]
print(json.dumps(node))
" "$WAIO_DUCOPA_CONTROL_STATUS_OUT" "$1" 2>/dev/null
}

MOCK_PID=""
MOCK_PORT=""
start_mock() {
  # start_mock MODE -- MODE picks the fixture's answers (see do_GET below).
  rm -f "$WORK/port" "$WORK/requests.log"
  python3 - "$1" "$WORK/port" "$WORK/requests.log" > /dev/null 2>&1 <<'PYEOF' &
import json, sys, time
from http.server import BaseHTTPRequestHandler, HTTPServer

mode, port_file, req_log = sys.argv[1:4]
HEARTBEAT = {"checked_at": "2026-10-21T00:00:00.000Z", "dispatch_state": "running",
             "system_health": {"agent_manager": {"status": "ok"}, "task_queue": {"status": "ok"}}}
EPISODE = {"id": "ep-1", "status": "active", "entered_reason": "fixture lockdown",
           "trigger_category": "test", "entered_by": "fixture", "entered_via": "api",
           "entered_at": "2026-10-21T00:00:00.000Z"}

class Handler(BaseHTTPRequestHandler):
    def record(self):
        with open(req_log, "a") as f:
            f.write("%s %s %s\n" % (self.command, self.path, self.headers.get("Authorization", "-")))
    def reply(self, code, obj=None, raw=None):
        body = raw if raw is not None else json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)
    def do_GET(self):
        self.record()
        if mode == "hang":
            time.sleep(10); return
        if mode == "401":
            return self.reply(401, {"error": "Unauthorized"})
        if mode == "404":
            return self.reply(404, {"error": "NotFound"})
        if self.path == "/control/heartbeat":
            if mode == "notjson":
                return self.reply(200, raw=b"<html>not json</html>")
            hb = dict(HEARTBEAT)
            if mode == "lockdown":
                hb["dispatch_state"] = "lockdown"
            if mode == "badstate":
                hb["dispatch_state"] = "probably-fine"
            if mode == "missingfield":
                del hb["system_health"]
            return self.reply(200, hb)
        if self.path == "/control/lockdown":
            if mode == "lockdown_500":
                return self.reply(500, {"error": "boom"})
            return self.reply(200, EPISODE if mode == "lockdown" else None)
        return self.reply(404, {"error": "NotFound"})
    def do_POST(self):
        self.record(); self.reply(405, {"error": "fixture: no POST expected"})
    do_PUT = do_DELETE = do_PATCH = do_POST
    def log_message(self, *a):
        pass

srv = HTTPServer(("127.0.0.1", 0), Handler)
with open(port_file, "w") as f:
    f.write(str(srv.server_address[1]))
srv.serve_forever()
PYEOF
  MOCK_PID=$!
  for _ in $(seq 1 50); do [ -s "$WORK/port" ] && break; sleep 0.1; done
  MOCK_PORT="$(cat "$WORK/port" 2>/dev/null)"
}

stop_mock() {
  [ -n "$MOCK_PID" ] && kill "$MOCK_PID" 2>/dev/null
  [ -n "$MOCK_PID" ] && wait "$MOCK_PID" 2>/dev/null
  MOCK_PID=""
}
cleanup() { stop_mock; rm -rf "$WORK"; }
trap cleanup EXIT

run_against() {
  # run_against MODE -- start fixture, run collector with a read key, stop fixture
  start_mock "$1"
  TAKOMACHI_CONTROL_READ_KEY="fixture-read-key" TAKOMACHI_API_URL="http://127.0.0.1:$MOCK_PORT" "$COLLECTOR" > "$WORK/stdout" 2>&1
  RC=$?
  stop_mock
}

BEFORE_LOCK_HASH="not_present"
[ -f security/state/SHUTDOWN.lock ] && BEFORE_LOCK_HASH="$(shasum -a 256 security/state/SHUTDOWN.lock | awk '{print $1}')"
BEFORE_LOGS_HASH="$(ls -la logs/ducopa-control-status-latest.json 2>/dev/null | shasum -a 256 | awk '{print $1}')"

echo "=== Dashboard: DuCoPA control-plane status collector (read-only DETECT bridge) ==="

echo "[DC1] no TAKOMACHI_CONTROL_READ_KEY: unavailable, exit 0, no request made"
rm -f "$WORK/requests.log"
env -u TAKOMACHI_CONTROL_READ_KEY TAKOMACHI_API_URL="http://127.0.0.1:1" "$COLLECTOR" >/dev/null 2>&1
assert_eq "DC1 exit 0" "0" "$?"
assert_eq "DC1 available false" "false" "$(out_get available)"
assert_contains "DC1 reason names the missing key" "$(out_get reason)" "no TAKOMACHI_CONTROL_READ_KEY"

echo "[DC2] key set, Takomachi unreachable: unavailable with reason, exit 0"
TAKOMACHI_CONTROL_READ_KEY="k" TAKOMACHI_API_URL="http://127.0.0.1:1" "$COLLECTOR" >/dev/null 2>&1
assert_eq "DC2 exit 0" "0" "$?"
assert_eq "DC2 available false" "false" "$(out_get available)"
assert_eq "DC2 http_status 000" '"000"' "$(out_get http_status)"
assert_contains "DC2 reason says unreachable" "$(out_get reason)" "unreachable"

echo "[DC3] heartbeat up, dispatch running, no lockdown"
run_against running
assert_eq "DC3 exit 0" "0" "$RC"
assert_eq "DC3 available true" "true" "$(out_get available)"
assert_eq "DC3 dispatch_state running" '"running"' "$(out_get dispatch_state)"
assert_eq "DC3 lockdown known and inactive" "false" "$(out_get lockdown.active)"
assert_eq "DC3 system_health passed through" '"ok"' "$(out_get heartbeat.system_health.task_queue.status)"

echo "[DC4] Takomachi in lockdown with an active episode"
run_against lockdown
assert_eq "DC4 dispatch_state lockdown" '"lockdown"' "$(out_get dispatch_state)"
assert_eq "DC4 lockdown active" "true" "$(out_get lockdown.active)"
assert_eq "DC4 episode reason" '"fixture lockdown"' "$(out_get lockdown.episode.entered_reason)"

echo "[DC5] 401 (wrong key or channel disabled): unavailable, says both"
run_against 401
assert_eq "DC5 available false" "false" "$(out_get available)"
assert_eq "DC5 http_status 401" '"401"' "$(out_get http_status)"
assert_contains "DC5 reason covers wrong key" "$(out_get reason)" "wrong TAKOMACHI_CONTROL_READ_KEY"
assert_contains "DC5 reason covers disabled channel" "$(out_get reason)" "disabled"

echo "[DC6] 404 (control channel disabled on Takomachi)"
run_against 404
assert_eq "DC6 available false" "false" "$(out_get available)"
assert_contains "DC6 reason says disabled" "$(out_get reason)" "control channel is disabled"

echo "[DC7] fail closed on a bad heartbeat: unknown state, missing field, non-JSON"
run_against badstate
assert_eq "DC7a unknown dispatch_state -> available false" "false" "$(out_get available)"
assert_eq "DC7a no guessed dispatch_state" "null" "$(out_get dispatch_state)"
run_against missingfield
assert_eq "DC7b missing system_health -> available false" "false" "$(out_get available)"
run_against notjson
assert_eq "DC7c non-JSON heartbeat -> available false" "false" "$(out_get available)"

echo "[DC8] lockdown endpoint failing leaves lockdown unknown (not 'no lockdown')"
run_against lockdown_500
assert_eq "DC8 heartbeat still available" "true" "$(out_get available)"
assert_eq "DC8 lockdown.available false" "false" "$(out_get lockdown.available)"
assert_eq "DC8 lockdown.active unknown (null)" "null" "$(out_get lockdown.active)"

echo "[DC9] only GETs, only the two control paths, with the read key as bearer"
run_against lockdown
REQS="$(cat "$WORK/requests.log" 2>/dev/null)"
assert_eq "DC9 exactly 2 requests" "2" "$(printf '%s\n' "$REQS" | grep -c .)"
assert_eq "DC9 no non-GET request" "0" "$(printf '%s\n' "$REQS" | grep -vc '^GET ')"
assert_eq "DC9 paths" "/control/heartbeat /control/lockdown" "$(printf '%s\n' "$REQS" | awk '{print $2}' | sort | tr '\n' ' ' | sed 's/ $//')"
assert_eq "DC9 bearer is the read key" "2" "$(printf '%s\n' "$REQS" | grep -c 'Bearer fixture-read-key$')"

echo "[DC10] a hanging Takomachi is bounded by the 3s timeout"
start_mock hang
T0=$SECONDS
TAKOMACHI_CONTROL_READ_KEY="k" TAKOMACHI_API_URL="http://127.0.0.1:$MOCK_PORT" "$COLLECTOR" >/dev/null 2>&1
ELAPSED=$((SECONDS - T0))
stop_mock
assert_eq "DC10 available false" "false" "$(out_get available)"
assert_eq "DC10 returned within 6s" "true" "$([ "$ELAPSED" -le 6 ] && echo true || echo false)"

echo "[DC11] static: GET-only and outside the DLP shutdown path"
# Comments and the NOTE= display string (which names lib.sh on purpose) are not code.
code_only() { grep -vE '^\s*#|^NOTE=' "$COLLECTOR"; }
assert_eq "DC11 no POST/PUT/DELETE/PATCH" "0" "$(code_only | grep -cE -- '-X (POST|PUT|DELETE|PATCH)|--data|-d ')"
assert_eq "DC11 does not source security/lib.sh" "0" "$(code_only | grep -cE '^\s*(source|\.)\s+\S*lib\.sh')"
assert_eq "DC11 never calls egress_check/trigger_shutdown" "0" "$(code_only | grep -cE 'egress_check|trigger_shutdown')"
assert_eq "DC11 no write-scope control path (pause/resume/enter/exit/approvals)" "0" "$(code_only | grep -cE '/control/(dispatch|lockdown/(enter|exit)|approvals|agents|tasks)')"

echo "[DC12] side effects: no SHUTDOWN.lock change, nothing written to this checkout's logs/"
AFTER_LOCK_HASH="not_present"
[ -f security/state/SHUTDOWN.lock ] && AFTER_LOCK_HASH="$(shasum -a 256 security/state/SHUTDOWN.lock | awk '{print $1}')"
assert_eq "DC12 SHUTDOWN.lock unchanged" "$BEFORE_LOCK_HASH" "$AFTER_LOCK_HASH"
AFTER_LOGS_HASH="$(ls -la logs/ducopa-control-status-latest.json 2>/dev/null | shasum -a 256 | awk '{print $1}')"
assert_eq "DC12 logs/ducopa-control-status-latest.json untouched" "$BEFORE_LOGS_HASH" "$AFTER_LOGS_HASH"

echo ""
echo "=== Summary: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
  for f in "${FAILURES[@]}"; do echo "  - $f"; done
  exit 1
fi
exit 0
