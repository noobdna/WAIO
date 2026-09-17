#!/bin/bash
set -uo pipefail

# tests/collect_status_guardian_test.sh -- regression suite for Phase 61
# (Dashboard visibility for the DuCoPA Guardian Control Plane):
# dashboard/collect_status.sh's new "guardian_control_plane" JSON
# section (state, is_blocking, quarantined_agents, critical_event_counts).
#
# Isolates every INPUT this script's new code reads
# (WAIO_GUARDIAN_STATE_FILE/WAIO_GUARDIAN_QUARANTINE_FILE/
# WAIO_GUARDIAN_CRITICAL_EVENTS_FILE/WAIO_SHUTDOWN_LOCK/WAIO_AUDIT_LOG),
# same test-isolation pattern as tests/ducopa_guardian_test.sh -- this
# suite never reads or writes this deployment's real
# security/state/GUARDIAN_STATE, GUARDIAN_QUARANTINE, or
# GUARDIAN_CRITICAL_EVENTS.
#
# Like tests/dashboard_refresh_cron_test.sh, collect_status.sh's OUTPUT
# path (logs/waio-status-latest.json) is NOT fixture-overridable -- this
# suite does regenerate that deployment-local, gitignored, always-
# regenerable snapshot file, same accepted tradeoff as every other
# dashboard test in this repo.

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

STATUS_PATH="logs/waio-status-latest.json"

# jq_get FIELD_PATH -- fetches one field from the just-written status
# JSON via python3 (no jq dependency assumed, matching this repo's own
# python3-everywhere convention).
status_get() {
  python3 -c "
import json
d = json.load(open('$STATUS_PATH'))
node = d
for part in '$1'.split('.'):
    node = node[part]
print(json.dumps(node))
" 2>/dev/null
}

FIXTURE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/waio-collect-status-guardian-test.XXXXXX")"
trap 'rm -rf "$FIXTURE_DIR"' EXIT

fixture_reset() {
  local suffix="${1:-default}"
  export WAIO_GUARDIAN_STATE_FILE="$FIXTURE_DIR/GUARDIAN_STATE-$suffix"
  export WAIO_GUARDIAN_QUARANTINE_FILE="$FIXTURE_DIR/GUARDIAN_QUARANTINE-$suffix"
  export WAIO_GUARDIAN_CRITICAL_EVENTS_FILE="$FIXTURE_DIR/GUARDIAN_CRITICAL_EVENTS-$suffix"
  export WAIO_SHUTDOWN_LOCK="$FIXTURE_DIR/SHUTDOWN-$suffix.lock"
  export WAIO_AUDIT_LOG="$FIXTURE_DIR/audit-$suffix.jsonl"
  rm -f "$WAIO_GUARDIAN_STATE_FILE" "$WAIO_GUARDIAN_QUARANTINE_FILE" \
    "$WAIO_GUARDIAN_CRITICAL_EVENTS_FILE" "$WAIO_SHUTDOWN_LOCK" "$WAIO_AUDIT_LOG"
}

REAL_STATE_PRESENT_BEFORE="false"
[ -f "security/state/GUARDIAN_STATE" ] && REAL_STATE_PRESENT_BEFORE="true"
REAL_QUARANTINE_PRESENT_BEFORE="false"
[ -f "security/state/GUARDIAN_QUARANTINE" ] && REAL_QUARANTINE_PRESENT_BEFORE="true"
REAL_CRITICAL_EVENTS_PRESENT_BEFORE="false"
[ -f "security/state/GUARDIAN_CRITICAL_EVENTS" ] && REAL_CRITICAL_EVENTS_PRESENT_BEFORE="true"

echo "=== Dashboard: DuCoPA Guardian Control Plane visibility (Phase 61) ==="

echo "[CS1] no Guardian state files at all: state NORMAL, not blocking, empty lists"
fixture_reset "cs1"
./dashboard/collect_status.sh >/dev/null
assert_eq "CS1 exit 0" "0" "$?"
assert_eq "CS1 state NORMAL" '"NORMAL"' "$(status_get guardian_control_plane.state)"
assert_eq "CS1 not blocking" "false" "$(status_get guardian_control_plane.is_blocking)"
assert_eq "CS1 no quarantined agents" "[]" "$(status_get guardian_control_plane.quarantined_agents)"
assert_eq "CS1 no critical event counts" "{}" "$(status_get guardian_control_plane.critical_event_counts)"

echo "[CS2] Guardian state BLOCKED is reflected and reported as blocking"
fixture_reset "cs2"
printf 'BLOCKED\n' > "$WAIO_GUARDIAN_STATE_FILE"
./dashboard/collect_status.sh >/dev/null
assert_eq "CS2 state BLOCKED" '"BLOCKED"' "$(status_get guardian_control_plane.state)"
assert_eq "CS2 is blocking" "true" "$(status_get guardian_control_plane.is_blocking)"

echo "[CS3] Guardian state WARNING is reflected but reported as NOT blocking (matches guardian_is_blocking's own semantics)"
fixture_reset "cs3"
printf 'WARNING\n' > "$WAIO_GUARDIAN_STATE_FILE"
./dashboard/collect_status.sh >/dev/null
assert_eq "CS3 state WARNING" '"WARNING"' "$(status_get guardian_control_plane.state)"
assert_eq "CS3 not blocking" "false" "$(status_get guardian_control_plane.is_blocking)"

echo "[CS4] a corrupted Guardian state file is fail-closed BLOCKED here too (matches guardian_get_state)"
fixture_reset "cs4"
printf 'GARBAGE\n' > "$WAIO_GUARDIAN_STATE_FILE"
./dashboard/collect_status.sh >/dev/null 2>&1
assert_eq "CS4 fail-closed to BLOCKED" '"BLOCKED"' "$(status_get guardian_control_plane.state)"
assert_eq "CS4 is blocking" "true" "$(status_get guardian_control_plane.is_blocking)"

echo "[CS5] quarantined_agents lists every agent, in file order"
fixture_reset "cs5"
printf 'ECHO\nRPI\nHOST800\n' > "$WAIO_GUARDIAN_QUARANTINE_FILE"
./dashboard/collect_status.sh >/dev/null
assert_eq "CS5 all three agents listed" '["ECHO", "RPI", "HOST800"]' "$(status_get guardian_control_plane.quarantined_agents)"

echo "[CS6] critical_event_counts parses AGENT|COUNT lines as a JSON object with integer values"
fixture_reset "cs6"
printf 'ECHO|2\nRPI|5\n' > "$WAIO_GUARDIAN_CRITICAL_EVENTS_FILE"
./dashboard/collect_status.sh >/dev/null
assert_eq "CS6 ECHO count is an integer 2" "2" "$(status_get guardian_control_plane.critical_event_counts.ECHO)"
assert_eq "CS6 RPI count is an integer 5" "5" "$(status_get guardian_control_plane.critical_event_counts.RPI)"

echo "[CS7] pre-existing top-level keys are unaffected by this addition"
fixture_reset "cs7"
./dashboard/collect_status.sh >/dev/null
assert_eq "CS7 waio_status still present" '"NORMAL"' "$(status_get waio_status)"
assert_eq "CS7 shutdown.active still present" "false" "$(status_get shutdown.active)"
assert_eq "CS7 old guardian key untouched (SSH config not present here)" "false" "$(status_get guardian.authorized_keys_entry_present)"

echo "[CS8] this deployment's real Guardian Control Plane state files were never created/touched by this suite"
REAL_STATE_PRESENT_AFTER="false"
[ -f "security/state/GUARDIAN_STATE" ] && REAL_STATE_PRESENT_AFTER="true"
REAL_QUARANTINE_PRESENT_AFTER="false"
[ -f "security/state/GUARDIAN_QUARANTINE" ] && REAL_QUARANTINE_PRESENT_AFTER="true"
REAL_CRITICAL_EVENTS_PRESENT_AFTER="false"
[ -f "security/state/GUARDIAN_CRITICAL_EVENTS" ] && REAL_CRITICAL_EVENTS_PRESENT_AFTER="true"
assert_eq "CS8 real GUARDIAN_STATE presence unchanged" "$REAL_STATE_PRESENT_BEFORE" "$REAL_STATE_PRESENT_AFTER"
assert_eq "CS8 real GUARDIAN_QUARANTINE presence unchanged" "$REAL_QUARANTINE_PRESENT_BEFORE" "$REAL_QUARANTINE_PRESENT_AFTER"
assert_eq "CS8 real GUARDIAN_CRITICAL_EVENTS presence unchanged" "$REAL_CRITICAL_EVENTS_PRESENT_BEFORE" "$REAL_CRITICAL_EVENTS_PRESENT_AFTER"

echo
echo "=== Results: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
  echo "Failures:"
  for f in "${FAILURES[@]}"; do echo "  - $f"; done
  exit 1
fi
exit 0
