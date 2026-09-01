#!/bin/bash
set -uo pipefail

# tests/segment_monitor_cron_test.sh -- regression suite for Phase 51
# (scheduled segment monitoring): security/segment_monitor_cron.sh.
#
# The wrapper itself adds no new logic -- it only sequences two
# already-tested entry points (security/health_checker.sh monitor-all,
# dashboard/collect_segment_status.sh) and logs when it ran. This
# suite checks that plumbing, not the Incident State Machine itself
# (already covered by tests/segment_recovery_test.sh): the wrapper
# exits 0 even when a segment is unreachable (that's an expected
# state-machine transition, not a script error), writes its own run
# log, and never invokes security/recovery_engine.sh (no
# 'recovering'/'recovered'/'failed' status ever appears from this
# wrapper alone).
#
# Same fixture-sandbox pattern as tests/segment_recovery_test.sh:
# SEGMENT_MANAGER_CONF/SEGMENT_MANAGER_STATE_DIR/
# SEGMENT_MANAGER_AUDIT_LOG overrides mean this suite never reads or
# writes this deployment's real security/segments.conf or
# security/state/segments/. dashboard/collect_segment_status.sh's own
# output path (logs/waio-segments-latest.json) is not
# fixture-overridable -- same accepted limitation as
# tests/segment_recovery_test.sh's own DC1 case -- so this does
# regenerate that real, gitignored, always-regenerable snapshot file.

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

FIXTURE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/waio-segment-cron-test.XXXXXX")"
trap 'rm -rf "$FIXTURE_DIR"; [ -n "${LISTENER_PID:-}" ] && kill "$LISTENER_PID" 2>/dev/null; true' EXIT

mkdir -p "$FIXTURE_DIR/state"

LISTEN_PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')"
python3 -m http.server "$LISTEN_PORT" --bind 127.0.0.1 >/dev/null 2>&1 &
LISTENER_PID=$!
sleep 0.3

UNREACHABLE_PORT=1

cat > "$FIXTURE_DIR/segments.conf" <<EOF
UP|127.0.0.1|$LISTEN_PORT|ECHO|reachable fixture segment
DOWN|127.0.0.1|$UNREACHABLE_PORT|ECHO|unreachable fixture segment
EOF

export SEGMENT_MANAGER_CONF="$FIXTURE_DIR/segments.conf"
export SEGMENT_MANAGER_STATE_DIR="$FIXTURE_DIR/state"
export SEGMENT_MANAGER_AUDIT_LOG="$FIXTURE_DIR/segment-audit.jsonl"
export SEGMENT_MONITOR_CRON_LOG="$FIXTURE_DIR/segment-monitor-cron.log"
export HEALTH_CHECK_TIMEOUT=1
export HEALTH_CHECK_RETRIES=2
export HEALTH_CHECK_RETRY_DELAY=0

echo "=== Segment Monitor Cron (Phase 51) regression suite ==="
echo

echo "[SC1] wrapper exits 0 even though one fixture segment (DOWN) is unreachable"
bash security/segment_monitor_cron.sh
SC1_RC=$?
assert_eq "SC1 exit code 0" "0" "$SC1_RC"

echo
echo "[SC2] wrapper's own run log records start/end and both sub-step results"
SC2_LOG="$(cat "$FIXTURE_DIR/segment-monitor-cron.log" 2>/dev/null || true)"
assert_contains "SC2 log has run start" "$SC2_LOG" "run start"
assert_contains "SC2 log has health_checker.sh result" "$SC2_LOG" "health_checker.sh monitor-all"
assert_contains "SC2 log has collect_segment_status.sh result" "$SC2_LOG" "collect_segment_status.sh: ok"
assert_contains "SC2 log has run end" "$SC2_LOG" "run end"

echo
echo "[SC3] detection ran: DOWN transitioned out of 'normal' (health_checker.sh's job), UP did not"
SC3_DOWN_STATUS="$(bash security/segment_manager.sh status DOWN)"
SC3_UP_STATUS="$(bash security/segment_manager.sh status UP)"
assert_eq "SC3 DOWN is suspicious after one failed check" "suspicious" "$SC3_DOWN_STATUS"
assert_eq "SC3 UP still normal (reachable)" "normal" "$SC3_UP_STATUS"

echo
echo "[SC4] no recovery action was ever invoked (no 'recovering'/'recovered'/'failed' status anywhere -- this wrapper never calls recovery_engine.sh)"
SC4_BAD=0
for id in UP DOWN; do
  case "$(bash security/segment_manager.sh status "$id")" in
    recovering|recovered|failed) SC4_BAD=$((SC4_BAD + 1)) ;;
  esac
done
assert_eq "SC4 zero segments in a recovery-only status" "0" "$SC4_BAD"

echo
echo "[SC5] dashboard/collect_segment_status.sh's snapshot was actually regenerated (wrapper's second step)"
SC5_JSON_OK="$(python3 -c "
import json
try:
    d = json.load(open('logs/waio-segments-latest.json'))
    need = {'generated_at','segments','recent_events'}
    print('true' if need.issubset(d.keys()) else 'false')
except Exception:
    print('false')
")"
assert_eq "SC5 snapshot JSON has expected shape" "true" "$SC5_JSON_OK"

echo
echo "[SC6] script is executable (as launchd/cron will invoke it directly)"
assert_eq "SC6 executable bit set" "true" "$([ -x security/segment_monitor_cron.sh ] && echo true || echo false)"

echo
echo "=== Results: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
  echo "Failures:"
  for f in "${FAILURES[@]}"; do echo "  - $f"; done
  exit 1
fi
exit 0
