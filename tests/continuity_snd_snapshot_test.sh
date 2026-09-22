#!/bin/bash
set -uo pipefail

# tests/continuity_snd_snapshot_test.sh -- regression suite for the
# WAIO Pre-Disconnect Cache (PDC) / SND@HOME read-only snapshot
# integration: security/continuity.sh's continuity_snd_snapshot_refresh
# and continuity_snd_snapshot_get.
#
# SND@HOME itself is not present on this machine (same finding as
# ARCHITECTURE.md's Phase 53/76 investigations) -- so, exactly like
# tests/collect_snd_status_test.sh, this suite drives everything via
# the SND_HOME_API_URL environment-variable override against a local,
# unauthenticated Python http.server fixture standing in for SND@HOME.
# dashboard/collect_snd_status.sh itself is invoked unmodified, exactly
# as continuity_snd_snapshot_refresh calls it in real operation -- this
# suite never stubs or bypasses it.
#
# Isolation: every WAIO_CONTINUITY_*/SEGMENT_MANAGER_*/WAIO_SHUTDOWN_LOCK/
# WAIO_AUDIT_LOG/WAIO_GUARDIAN_* path is redirected under a scratch temp
# dir, same pattern as tests/continuity_engine_test.sh -- this suite
# never reads or writes this deployment's real security/state/,
# logs/security-audit.jsonl, or logs/continuity-audit.jsonl. The one
# real, shared, always-regenerable file this suite does write is
# logs/snd-status-latest.json -- dashboard/collect_snd_status.sh's own
# fixed output path is not fixture-overridable (same as
# tests/collect_snd_status_test.sh already accepts).

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
  if [[ "$haystack" == *"$needle"* ]]; then
    PASS=$((PASS + 1)); echo "  PASS: $label"
  else
    FAIL=$((FAIL + 1)); FAILURES+=("$label (expected to contain '$needle')")
    echo "  FAIL: $label (expected to contain '$needle', got: $haystack)"
  fi
}

FIXTURE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/waio-pdc-snd-test.XXXXXX")"
trap 'rm -rf "$FIXTURE_DIR"; [ -n "${MOCK_PID:-}" ] && kill "$MOCK_PID" 2>/dev/null; true' EXIT

mkdir -p "$FIXTURE_DIR/continuity_state"

# --- isolation: same variables tests/continuity_engine_test.sh already
# establishes this pattern with, plus a fixture HOME so
# continuity_snd_snapshot_refresh's own "$HOME/.waio.env" fallback
# check never sees this machine's real one. -------------------------
export HOME="$FIXTURE_DIR"
export SEGMENT_MANAGER_CONF="$FIXTURE_DIR/segments_empty.conf"
export SEGMENT_MANAGER_STATE_DIR="$FIXTURE_DIR/segments_state"
export SEGMENT_MANAGER_AUDIT_LOG="$FIXTURE_DIR/segment-audit.jsonl"
: > "$SEGMENT_MANAGER_CONF"
export WAIO_CONTINUITY_STATE_DIR="$FIXTURE_DIR/continuity_state"
export WAIO_CONTINUITY_CACHE_DIR="$FIXTURE_DIR/continuity_state/context_cache"
export WAIO_CONTINUITY_STATE_FILE="$FIXTURE_DIR/continuity_state/CONTINUITY_STATE"
export WAIO_CONTINUITY_SNAPSHOT_FILE="$FIXTURE_DIR/continuity_state/last_known_good.json"
export WAIO_CONTINUITY_SND_SNAPSHOT_FILE="$FIXTURE_DIR/continuity_state/snd_snapshot.json"
export WAIO_CONTINUITY_AUDIT_LOG="$FIXTURE_DIR/continuity-audit.jsonl"
export WAIO_SHUTDOWN_LOCK="$FIXTURE_DIR/SHUTDOWN.lock"
export WAIO_AUDIT_LOG="$FIXTURE_DIR/security-audit.jsonl"
export WAIO_AUDIT_LOG_CHECKPOINT="$FIXTURE_DIR/audit-checkpoint"
export WAIO_AUDIT_INTEGRITY_ALERTS="$FIXTURE_DIR/audit-alerts.jsonl"
export WAIO_AUDIT_LOG_LOCK_DIR="$FIXTURE_DIR/audit-lock"
export WAIO_GUARDIAN_STATE_FILE="$FIXTURE_DIR/GUARDIAN_STATE"
export WAIO_GUARDIAN_QUARANTINE_FILE="$FIXTURE_DIR/GUARDIAN_QUARANTINE"
export WAIO_GUARDIAN_CRITICAL_EVENTS_FILE="$FIXTURE_DIR/GUARDIAN_CRITICAL_EVENTS"

source security/continuity.sh

snd_snap_get_field() {
  # snd_snap_get_field DOTTED_PATH -- reads a field out of the current
  # CONTINUITY_SND_SNAPSHOT_FILE, e.g. "snd_status.available" or
  # "snd_status.lan_status.devices_online".
  python3 -c "
import json
try:
    d = json.load(open('$WAIO_CONTINUITY_SND_SNAPSHOT_FILE'))
    node = d
    for part in '$1'.split('.'):
        node = node[part]
    print(json.dumps(node))
except Exception:
    print('__ERROR__')
" 2>/dev/null
}

MOCK_PORT=18944
MOCK_PID=""
MOCK_BEHAVIOR_FILE="$FIXTURE_DIR/mock_behavior"
echo "ok" > "$MOCK_BEHAVIOR_FILE"

start_mock() {
  python3 - "$MOCK_PORT" "$MOCK_BEHAVIOR_FILE" > /dev/null 2>&1 <<'PYEOF' &
import json, sys
from http.server import BaseHTTPRequestHandler, HTTPServer

behavior_file = sys.argv[2]

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            behavior = open(behavior_file).read().strip()
        except Exception:
            behavior = "ok"
        if behavior == "down":
            self.connection.close()
            return
        if self.path == "/api/lan/status":
            body = json.dumps({"devices_total": 3, "devices_online": 2}).encode()
        elif self.path == "/api/system/latest":
            if behavior == "leak":
                body = json.dumps({"cpu_pct": 5.0, "note": "sk-abcdefghijklmnopqrstuvwx"}).encode()
            else:
                body = json.dumps({"cpu_pct": 5.0}).encode()
        elif self.path == "/api/alerts/active":
            body = json.dumps([]).encode()
        elif self.path == "/api/lan/terminals":
            body = json.dumps({"status": "ok", "data": []}).encode()
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

echo "=== WAIO PDC / SND@HOME read-only snapshot integration test suite ==="
echo

# --- 5. SND_HOME_API_URL unset: complete no-op -----------------------
echo "[S1] SND_HOME_API_URL unset (and no ~/.waio.env): refresh is a complete no-op"
unset SND_HOME_API_URL SND_HOME_API_TOKEN 2>/dev/null || true
rm -f "$WAIO_CONTINUITY_SND_SNAPSHOT_FILE"
: > "$WAIO_CONTINUITY_AUDIT_LOG"
continuity_snd_snapshot_refresh
S1_RC=$?
assert_eq "S1 exit code 0 (no-op is a success, not a failure)" "0" "$S1_RC"
assert_eq "S1 no snapshot file created" "false" "$([ -f "$WAIO_CONTINUITY_SND_SNAPSHOT_FILE" ] && echo true || echo false)"
assert_eq "S1 no audit event logged at all (true no-op, not even a skip)" "0" "$(wc -l < "$WAIO_CONTINUITY_AUDIT_LOG" | tr -d ' ')"

echo
echo "[S2] continuity_snd_snapshot_get with nothing cached yet: exit 1, empty output"
OUT_S2="$(continuity_snd_snapshot_get 2>&1)"; RC_S2=$?
assert_eq "S2 exit code" "1" "$RC_S2"
assert_eq "S2 empty output" "" "$OUT_S2"

# --- ONLINE -> SNAPSHOT -----------------------------------------------
echo
echo "[S3] ONLINE: SND_HOME_API_URL configured and reachable -- refresh succeeds and commits a snapshot"
echo "ok" > "$MOCK_BEHAVIOR_FILE"
start_mock
SND_HOME_API_URL="http://127.0.0.1:$MOCK_PORT" continuity_snd_snapshot_refresh
S3_RC=$?
assert_eq "S3 exit code 0" "0" "$S3_RC"
assert_eq "S3 snapshot file created" "true" "$([ -f "$WAIO_CONTINUITY_SND_SNAPSHOT_FILE" ] && echo true || echo false)"
assert_eq "S3 snapshot available=true" "true" "$(snd_snap_get_field snd_status.available)"
assert_eq "S3 snapshot lan_status carried through" "2" "$(snd_snap_get_field snd_status.lan_status.devices_online)"
assert_contains "S3 audit log has pdc_snd_snapshot_refresh" "$(cat "$WAIO_CONTINUITY_AUDIT_LOG")" "pdc_snd_snapshot_refresh"
FIRST_CACHED_AT="$(snd_snap_get_field pdc_cached_at | tr -d '"')"

echo
echo "[S4] continuity_snd_snapshot_get now returns the committed snapshot"
OUT_S4="$(continuity_snd_snapshot_get)"; RC_S4=$?
assert_eq "S4 exit code" "0" "$RC_S4"
assert_contains "S4 output contains the snapshot's own snd_status" "$OUT_S4" "\"available\": true"

# --- OFFLINE -> LAST KNOWN STATE preserved ----------------------------
echo
echo "[S5] OFFLINE: SND_HOME_API_URL configured but unreachable -- refresh fails, PREVIOUS snapshot is untouched"
stop_mock
SNAPSHOT_BEFORE="$(cat "$WAIO_CONTINUITY_SND_SNAPSHOT_FILE")"
: > "$WAIO_CONTINUITY_AUDIT_LOG"
SND_HOME_API_URL="http://127.0.0.1:1" continuity_snd_snapshot_refresh
S5_RC=$?
assert_eq "S5 exit code 1 (refresh failed)" "1" "$S5_RC"
SNAPSHOT_AFTER="$(cat "$WAIO_CONTINUITY_SND_SNAPSHOT_FILE")"
assert_eq "S5 snapshot file byte-for-byte unchanged (Last Known State preserved)" "$SNAPSHOT_BEFORE" "$SNAPSHOT_AFTER"
assert_contains "S5 audit log records the skip, not a silent failure" "$(cat "$WAIO_CONTINUITY_AUDIT_LOG")" "pdc_snd_snapshot_refresh_skipped"

echo
echo "[S6] OFFLINE: dashboard/collect_snd_status.sh itself, called the same way, DOES overwrite its own logs/snd-status-latest.json with available:false -- proving PDC's snd_snapshot.json genuinely differs from (and protects against) that file's own overwrite-on-failure behavior"
SND_STATUS_LATEST_AVAILABLE="$(python3 -c "import json; print(json.load(open('logs/snd-status-latest.json')).get('available'))" 2>/dev/null)"
assert_eq "S6 logs/snd-status-latest.json now reports unavailable (its own known overwrite-on-failure behavior, unmodified)" "False" "$SND_STATUS_LATEST_AVAILABLE"
assert_eq "S6 but PDC's own snd_snapshot.json still reports the LAST GOOD data" "true" "$(snd_snap_get_field snd_status.available)"

echo
echo "[S7] continuity_snd_snapshot_get still returns the last known good state while offline"
OUT_S7="$(continuity_snd_snapshot_get)"
assert_contains "S7 still returns the last good snapshot" "$OUT_S7" "\"available\": true"

# --- RECOVER: SND_HOME reachable again --------------------------------
echo
echo "[S8] RECOVER: SND_HOME_API_URL reachable again -- refresh succeeds and the snapshot is refreshed (newer pdc_cached_at, updated data)"
sleep 1.1
echo "ok" > "$MOCK_BEHAVIOR_FILE"
start_mock
SND_HOME_API_URL="http://127.0.0.1:$MOCK_PORT" continuity_snd_snapshot_refresh
S8_RC=$?
stop_mock
assert_eq "S8 exit code 0" "0" "$S8_RC"
SECOND_CACHED_AT="$(snd_snap_get_field pdc_cached_at | tr -d '"')"
if [ "$SECOND_CACHED_AT" \> "$FIRST_CACHED_AT" ]; then
  PASS=$((PASS + 1)); echo "  PASS: S8 snapshot's pdc_cached_at advanced after recovery ($FIRST_CACHED_AT -> $SECOND_CACHED_AT)"
else
  FAIL=$((FAIL + 1)); FAILURES+=("S8 pdc_cached_at"); echo "  FAIL: S8 pdc_cached_at did not advance ($FIRST_CACHED_AT -> $SECOND_CACHED_AT)"
fi
assert_eq "S8 snapshot still available=true after recovery" "true" "$(snd_snap_get_field snd_status.available)"

# --- 4. token/secret contamination -------------------------------------
echo
echo "[S9] a credential-shaped string in SND_HOME's own response is refused -- never committed to the snapshot, previous good snapshot preserved"
SNAPSHOT_BEFORE_LEAK="$(cat "$WAIO_CONTINUITY_SND_SNAPSHOT_FILE")"
: > "$WAIO_CONTINUITY_AUDIT_LOG"
echo "leak" > "$MOCK_BEHAVIOR_FILE"
start_mock
SND_HOME_API_URL="http://127.0.0.1:$MOCK_PORT" continuity_snd_snapshot_refresh
S9_RC=$?
stop_mock
assert_eq "S9 exit code 1 (refused)" "1" "$S9_RC"
SNAPSHOT_AFTER_LEAK="$(cat "$WAIO_CONTINUITY_SND_SNAPSHOT_FILE")"
assert_eq "S9 snapshot unchanged (leaked content never committed)" "$SNAPSHOT_BEFORE_LEAK" "$SNAPSHOT_AFTER_LEAK"
assert_contains "S9 audit log has pdc_snd_snapshot_write_denied" "$(cat "$WAIO_CONTINUITY_AUDIT_LOG")" "pdc_snd_snapshot_write_denied"
echo "  (secret_leak_check's own existing contract also tripped the fixture WAIO_SHUTDOWN_LOCK here -- same as it would for any worker; not new PDC behavior. Clearing it now so later cases are unaffected.)"
rm -f "$WAIO_SHUTDOWN_LOCK"
echo "ok" > "$MOCK_BEHAVIOR_FILE"

echo
echo "[S10] SND_HOME_API_TOKEN itself is never written into the snapshot file, even on a successful refresh"
: > "$WAIO_CONTINUITY_AUDIT_LOG"
start_mock
SND_HOME_API_URL="http://127.0.0.1:$MOCK_PORT" SND_HOME_API_TOKEN="tok-should-never-appear-in-any-file" continuity_snd_snapshot_refresh >/dev/null 2>&1
stop_mock
assert_eq "S10 token string absent from the committed snapshot" "false" "$(grep -q 'tok-should-never-appear-in-any-file' "$WAIO_CONTINUITY_SND_SNAPSHOT_FILE" && echo true || echo false)"
assert_eq "S10 token string absent from logs/snd-status-latest.json" "false" "$(grep -q 'tok-should-never-appear-in-any-file' logs/snd-status-latest.json && echo true || echo false)"
assert_eq "S10 token string absent from PDC's own audit log" "false" "$(grep -q 'tok-should-never-appear-in-any-file' "$WAIO_CONTINUITY_AUDIT_LOG" && echo true || echo false)"

# --- default-path non-interference -------------------------------------
echo
echo "[S11] a refresh attempt against a URL that returns no data at all (bad host, connection refused instantly) still exits cleanly, matching dashboard/collect_snd_status.sh's own always-exits-0 contract downstream"
unset SND_HOME_API_TOKEN 2>/dev/null || true
SND_HOME_API_URL="http://127.0.0.1:1" continuity_snd_snapshot_refresh >/dev/null 2>&1
assert_eq "S11 dashboard/collect_snd_status.sh's own real SHUTDOWN.lock/audit posture unaffected (still no shutdown tripped by an unreachable SND_HOME)" "false" "$([ -f "$WAIO_SHUTDOWN_LOCK" ] && echo true || echo false)"

echo
echo "=== Summary: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
  echo "Failures:"
  for f in "${FAILURES[@]}"; do echo "  - $f"; done
  exit 1
fi
exit 0
