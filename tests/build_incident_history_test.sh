#!/bin/bash
set -uo pipefail

# tests/build_incident_history_test.sh -- unit tests for
# dashboard/build_incident_history.sh's trigger<->recovery pairing
# logic, using synthetic audit-log fixtures via WAIO_AUDIT_LOG
# (security/lib.sh respects this override). The real
# logs/security-audit.jsonl is never read or modified by this suite.
# logs/incident-history-latest.json (the real one) is backed up before
# this suite runs and restored afterward, trap-guaranteed, same idiom
# as tests/waio_test.sh's registry.conf swap-aside-and-restore.
#
# Standalone file, not wired into .github/workflows/lint.yml's
# regression job -- covered by the existing bash -n/shellcheck globs
# only, same treatment as tests/llm_dispatch_test.sh/response60_test.sh.

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

OUTPUT_PATH="logs/incident-history-latest.json"
OUTPUT_BACKUP="logs/incident-history-latest.json.testbackup.$$"
if [ -f "$OUTPUT_PATH" ]; then
  cp "$OUTPUT_PATH" "$OUTPUT_BACKUP"
fi
REAL_AUDIT_LOG="logs/security-audit.jsonl"
REAL_AUDIT_CHECKSUM_BEFORE="$([ -f "$REAL_AUDIT_LOG" ] && shasum -a 256 "$REAL_AUDIT_LOG" | awk '{print $1}' || echo "absent")"
restore_output() {
  if [ -f "$OUTPUT_BACKUP" ]; then
    mv -f "$OUTPUT_BACKUP" "$OUTPUT_PATH"
  else
    rm -f "$OUTPUT_PATH"
  fi
}
trap restore_output EXIT

FIXTURE_LOG="$(mktemp /tmp/waio_incident_test_audit.XXXXXX)"

run_with_fixture() {
  WAIO_AUDIT_LOG="$FIXTURE_LOG" ./dashboard/build_incident_history.sh > /dev/null 2>&1
}

echo "=== build_incident_history.sh: trigger<->recovery pairing (synthetic fixtures, real audit log never touched) ==="

echo "[T1] empty audit log -- zero incidents, valid structure"
: > "$FIXTURE_LOG"
run_with_fixture
T1_TOTAL="$(python3 -c "import json; print(json.load(open('$OUTPUT_PATH'))['total_incidents'])")"
T1_OPEN="$(python3 -c "import json; print(json.load(open('$OUTPUT_PATH'))['open_incidents'])")"
assert_eq "T1 total_incidents" "0" "$T1_TOTAL"
assert_eq "T1 open_incidents" "0" "$T1_OPEN"

echo "[T2] single trigger + local recovery"
cat > "$FIXTURE_LOG" <<'EOF'
{"timestamp": "2026-01-01T00:00:00Z", "event_type": "shutdown_triggered", "run_id": "t2run", "stage": "1", "worker": "UNIT_TEST", "destination": "dest-t2", "decision": "denied", "reason": "T2 test trip"}
{"timestamp": "2026-01-01T00:00:01Z", "event_type": "recovery_confirmed", "run_id": "recover-t2", "stage": "n/a", "worker": "n/a", "destination": "n/a", "decision": "cleared", "reason": "T2 cleanup"}
EOF
run_with_fixture
T2_JSON="$(cat "$OUTPUT_PATH")"
T2_STATUS="$(python3 -c "import json; print(json.load(open('$OUTPUT_PATH'))['incidents'][0]['status'])")"
T2_ACTOR="$(python3 -c "import json; print(json.load(open('$OUTPUT_PATH'))['incidents'][0]['recovery']['actor'])")"
assert_eq "T2 status resolved" "resolved" "$T2_STATUS"
assert_eq "T2 actor local" "local" "$T2_ACTOR"

echo "[T3] single trigger + guardian recovery"
cat > "$FIXTURE_LOG" <<'EOF'
{"timestamp": "2026-01-01T00:00:00Z", "event_type": "shutdown_triggered", "run_id": "t3run", "stage": "1", "worker": "UNIT_TEST", "destination": "dest-t3", "decision": "denied", "reason": "T3 test trip"}
{"timestamp": "2026-01-01T00:00:01Z", "event_type": "recovery_confirmed_guardian", "run_id": "recover-t3", "stage": "n/a", "worker": "n/a", "destination": "n/a", "decision": "cleared", "reason": "T3 cleanup"}
EOF
run_with_fixture
T3_ACTOR="$(python3 -c "import json; print(json.load(open('$OUTPUT_PATH'))['incidents'][0]['recovery']['actor'])")"
assert_eq "T3 actor guardian" "guardian" "$T3_ACTOR"

echo "[T4] trigger with no recovery yet -- open incident"
cat > "$FIXTURE_LOG" <<'EOF'
{"timestamp": "2026-01-01T00:00:00Z", "event_type": "shutdown_triggered", "run_id": "t4run", "stage": "1", "worker": "UNIT_TEST", "destination": "dest-t4", "decision": "denied", "reason": "T4 test trip, no recovery"}
EOF
run_with_fixture
T4_STATUS="$(python3 -c "import json; print(json.load(open('$OUTPUT_PATH'))['incidents'][0]['status'])")"
T4_OPEN="$(python3 -c "import json; print(json.load(open('$OUTPUT_PATH'))['open_incidents'])")"
assert_eq "T4 status open" "open" "$T4_STATUS"
assert_eq "T4 open_incidents count" "1" "$T4_OPEN"

echo "[T5] duplicate trigger while already active -- idempotency, still one incident"
cat > "$FIXTURE_LOG" <<'EOF'
{"timestamp": "2026-01-01T00:00:00Z", "event_type": "shutdown_triggered", "run_id": "t5run-a", "stage": "1", "worker": "UNIT_TEST", "destination": "dest-t5", "decision": "denied", "reason": "T5 first trip"}
{"timestamp": "2026-01-01T00:00:01Z", "event_type": "shutdown_triggered", "run_id": "t5run-b", "stage": "1", "worker": "UNIT_TEST", "destination": "dest-t5", "decision": "denied", "reason": "T5 duplicate trip"}
{"timestamp": "2026-01-01T00:00:02Z", "event_type": "recovery_confirmed", "run_id": "recover-t5", "stage": "n/a", "worker": "n/a", "destination": "n/a", "decision": "cleared", "reason": "T5 cleanup"}
EOF
run_with_fixture
T5_TOTAL="$(python3 -c "import json; print(json.load(open('$OUTPUT_PATH'))['total_incidents'])")"
T5_DUP="$(python3 -c "import json; print(json.load(open('$OUTPUT_PATH'))['incidents'][0]['duplicate_trigger_count'])")"
T5_REASON="$(python3 -c "import json; print(json.load(open('$OUTPUT_PATH'))['incidents'][0]['detection']['reason'])")"
assert_eq "T5 still one incident (idempotent)" "1" "$T5_TOTAL"
assert_eq "T5 duplicate_trigger_count" "1" "$T5_DUP"
assert_eq "T5 original reason preserved" "T5 first trip" "$T5_REASON"

echo "[T6] two independent, fully resolved incidents in sequence -- no cross-contamination"
cat > "$FIXTURE_LOG" <<'EOF'
{"timestamp": "2026-01-01T00:00:00Z", "event_type": "shutdown_triggered", "run_id": "t6run-1", "stage": "1", "worker": "UNIT_TEST", "destination": "dest-t6a", "decision": "denied", "reason": "T6 incident A"}
{"timestamp": "2026-01-01T00:00:01Z", "event_type": "recovery_confirmed", "run_id": "recover-t6a", "stage": "n/a", "worker": "n/a", "destination": "n/a", "decision": "cleared", "reason": "T6 A cleanup"}
{"timestamp": "2026-01-01T00:00:02Z", "event_type": "shutdown_triggered", "run_id": "t6run-2", "stage": "1", "worker": "UNIT_TEST", "destination": "dest-t6b", "decision": "denied", "reason": "T6 incident B"}
{"timestamp": "2026-01-01T00:00:03Z", "event_type": "recovery_confirmed_guardian", "run_id": "recover-t6b", "stage": "n/a", "worker": "n/a", "destination": "n/a", "decision": "cleared", "reason": "T6 B cleanup"}
EOF
run_with_fixture
T6_TOTAL="$(python3 -c "import json; print(json.load(open('$OUTPUT_PATH'))['total_incidents'])")"
T6_A_REASON="$(python3 -c "import json; print(json.load(open('$OUTPUT_PATH'))['incidents'][0]['detection']['reason'])")"
T6_B_REASON="$(python3 -c "import json; print(json.load(open('$OUTPUT_PATH'))['incidents'][1]['detection']['reason'])")"
T6_A_ACTOR="$(python3 -c "import json; print(json.load(open('$OUTPUT_PATH'))['incidents'][0]['recovery']['actor'])")"
T6_B_ACTOR="$(python3 -c "import json; print(json.load(open('$OUTPUT_PATH'))['incidents'][1]['recovery']['actor'])")"
assert_eq "T6 two incidents" "2" "$T6_TOTAL"
assert_eq "T6 incident A reason" "T6 incident A" "$T6_A_REASON"
assert_eq "T6 incident B reason" "T6 incident B" "$T6_B_REASON"
assert_eq "T6 incident A actor local" "local" "$T6_A_ACTOR"
assert_eq "T6 incident B actor guardian" "guardian" "$T6_B_ACTOR"

echo "[T7] real audit log is never read or modified by this script when WAIO_AUDIT_LOG overrides it"
assert_eq "T7 real audit log checksum unchanged" "$REAL_AUDIT_CHECKSUM_BEFORE" "$([ -f "$REAL_AUDIT_LOG" ] && shasum -a 256 "$REAL_AUDIT_LOG" | awk '{print $1}' || echo "absent")"

rm -f "$FIXTURE_LOG"

echo
echo "=== Summary: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
  echo "Failures:"
  for f in "${FAILURES[@]}"; do echo "  - $f"; done
  exit 1
fi
exit 0
