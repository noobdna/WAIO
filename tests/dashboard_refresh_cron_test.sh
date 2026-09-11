#!/bin/bash
set -uo pipefail

# tests/dashboard_refresh_cron_test.sh -- regression suite for Phase 52
# (scheduled dashboard refresh): dashboard/refresh_dashboard_cron.sh.
#
# The wrapper adds no new logic -- it only sequences two already-tested
# entry points (dashboard/collect_status.sh, dashboard/
# build_incident_history.sh) in their fast, default (no --run-tests)
# mode and logs when it ran. This suite checks that plumbing: the
# wrapper exits 0, writes its own run log, and both snapshot files it
# calls are regenerated with a fresh generated_at timestamp.
#
# Like tests/segment_recovery_test.sh's own DC1 case, neither
# collector's output path (logs/waio-status-latest.json,
# logs/incident-history-latest.json) is fixture-overridable, so this
# does regenerate this deployment's real, gitignored, always-
# regenerable snapshot files -- it never touches
# security/segments.conf, security/state/, or logs/segment-audit.jsonl
# (Phase 51's territory, untouched here).

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

FIXTURE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/waio-dashboard-cron-test.XXXXXX")"
trap 'rm -rf "$FIXTURE_DIR"' EXIT

export DASHBOARD_REFRESH_CRON_LOG="$FIXTURE_DIR/dashboard-refresh-cron.log"

echo "=== Dashboard Refresh Cron (Phase 52) regression suite ==="
echo

BEFORE_STATUS_TS=""
[ -f logs/waio-status-latest.json ] && BEFORE_STATUS_TS="$(python3 -c "import json; print(json.load(open('logs/waio-status-latest.json')).get('generated_at',''))" 2>/dev/null || true)"
BEFORE_HISTORY_TS=""
[ -f logs/incident-history-latest.json ] && BEFORE_HISTORY_TS="$(python3 -c "import json; print(json.load(open('logs/incident-history-latest.json')).get('generated_at',''))" 2>/dev/null || true)"

# ensure the two timestamps we're about to compare can't collide with
# whatever ran immediately before this suite
sleep 1.1

BEFORE_SEGMENTS_CHECKSUM="$([ -f logs/waio-segments-latest.json ] && shasum -a 256 logs/waio-segments-latest.json | awk '{print $1}' || echo "absent")"

echo "[DC1] wrapper exits 0"
bash dashboard/refresh_dashboard_cron.sh
DC1_RC=$?
assert_eq "DC1 exit code 0" "0" "$DC1_RC"

echo
echo "[DC2] wrapper's own run log records start/end and both sub-step results"
DC2_LOG="$(cat "$DASHBOARD_REFRESH_CRON_LOG" 2>/dev/null || true)"
assert_contains "DC2 log has run start" "$DC2_LOG" "run start"
assert_contains "DC2 log has collect_status.sh result" "$DC2_LOG" "collect_status.sh: ok"
assert_contains "DC2 log has build_incident_history.sh result" "$DC2_LOG" "build_incident_history.sh: ok"
assert_contains "DC2 log has run end" "$DC2_LOG" "run end"

echo
echo "[DC3] logs/waio-status-latest.json was actually regenerated (fresh generated_at, valid shape)"
DC3_STATUS_OK="$(python3 -c "
import json
try:
    d = json.load(open('logs/waio-status-latest.json'))
    ts = d.get('generated_at','')
    print('true' if ts and ts != '$BEFORE_STATUS_TS' and 'waio_status' in d else 'false')
except Exception:
    print('false')
")"
assert_eq "DC3 waio-status-latest.json refreshed" "true" "$DC3_STATUS_OK"

echo
echo "[DC4] logs/incident-history-latest.json was actually regenerated (fresh generated_at, valid shape)"
DC4_HISTORY_OK="$(python3 -c "
import json
try:
    d = json.load(open('logs/incident-history-latest.json'))
    ts = d.get('generated_at','')
    print('true' if ts and ts != '$BEFORE_HISTORY_TS' and 'incidents' in d else 'false')
except Exception:
    print('false')
")"
assert_eq "DC4 incident-history-latest.json refreshed" "true" "$DC4_HISTORY_OK"

echo
echo "[DC5] segment snapshot untouched by this wrapper (Phase 51's territory, not called here)"
AFTER_SEGMENTS_CHECKSUM="$([ -f logs/waio-segments-latest.json ] && shasum -a 256 logs/waio-segments-latest.json | awk '{print $1}' || echo "absent")"
assert_eq "DC5 waio-segments-latest.json checksum unchanged" "$BEFORE_SEGMENTS_CHECKSUM" "$AFTER_SEGMENTS_CHECKSUM"

echo
echo "[DC6] script is executable (as launchd will invoke it directly)"
assert_eq "DC6 executable bit set" "true" "$([ -x dashboard/refresh_dashboard_cron.sh ] && echo true || echo false)"

echo
echo "=== Results: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
  echo "Failures:"
  for f in "${FAILURES[@]}"; do echo "  - $f"; done
  exit 1
fi
exit 0
