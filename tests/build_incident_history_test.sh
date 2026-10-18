#!/bin/bash
set -uo pipefail

# tests/build_incident_history_test.sh -- unit tests for
# dashboard/build_incident_history.sh's trigger<->recovery pairing
# logic, using synthetic audit-log fixtures via WAIO_AUDIT_LOG
# (security/lib.sh respects this override). The real
# logs/security-audit.jsonl is never read or modified by this suite.
# Every output goes to a private temp root via tests/lib/test_isolation.sh
# and WAIO_INCIDENT_HISTORY_OUTPUT -- the real
# logs/incident-history-latest.json is never written (it used to be
# backed up and restored around the run, which still briefly replaced
# the file the live Dashboard serves).
#
# Wired into .github/workflows/lint.yml's regression job. Previously
# left standalone "same treatment as tests/llm_dispatch_test.sh/
# response60_test.sh" -- re-investigated and found neither of those
# files' actual exclusion reasons applies here: this suite makes no
# real network/cost-incurring call (unlike llm_dispatch_test.sh) and is
# a pure pass/fail regression check, not a timing/scoring measurement
# (unlike response60_test.sh). No technical reason to keep it out of CI.

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

source tests/lib/test_isolation.sh
waio_test_isolate build-incident-history || exit 3
trap waio_test_cleanup EXIT
waio_test_assert_isolated || { echo "ABORT: test isolation could not be guaranteed" >&2; exit 3; }

OUTPUT_PATH="$WAIO_TEST_ROOT/logs/incident-history-latest.json"
export WAIO_INCIDENT_HISTORY_OUTPUT="$OUTPUT_PATH"
export WAIO_RESPONSE60_JSON="$WAIO_TEST_ROOT/logs/response60-latest.json"
LIVE_OUTPUT="logs/incident-history-latest.json"
LIVE_OUTPUT_SUM_BEFORE="$([ -f "$LIVE_OUTPUT" ] && shasum -a 256 "$LIVE_OUTPUT" | awk '{print $1}' || echo "absent")"
# The live audit log is append-only and other jobs (incident-learning
# cron) legitimately append to it while this suite runs, so a whole-file
# checksum is not a stable "untouched" check. Compare the bytes that
# existed before the run instead, plus "nothing this suite would write
# was appended".
REAL_AUDIT_LOG="logs/security-audit.jsonl"
REAL_AUDIT_SIZE_BEFORE="$([ -f "$REAL_AUDIT_LOG" ] && wc -c < "$REAL_AUDIT_LOG" | tr -d ' ' || echo 0)"
REAL_AUDIT_PREFIX_BEFORE="$([ -f "$REAL_AUDIT_LOG" ] && head -c "$REAL_AUDIT_SIZE_BEFORE" "$REAL_AUDIT_LOG" | shasum -a 256 | awk '{print $1}' || echo "absent")"

FIXTURE_LOG="$WAIO_TEST_ROOT/fixture-audit.jsonl"

run_with_fixture() {
  WAIO_AUDIT_LOG="$FIXTURE_LOG" ./dashboard/build_incident_history.sh > /dev/null 2>&1
}

# jget EXPR -- evaluates a python expression over the output JSON (d).
jget() {
  python3 -c "import json, sys; d = json.load(open(sys.argv[1])); print($1)" "$OUTPUT_PATH" 2>/dev/null || echo "jget-error"
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

echo "[T8] F-16 regression: an audit log larger than ARG_MAX (~1 MiB) is still reconstructed"
python3 - "$FIXTURE_LOG" <<'PY'
import json, sys
with open(sys.argv[1], "w") as f:
    f.write(json.dumps({"timestamp": "2026-01-01T00:00:00Z", "event_type": "shutdown_triggered", "run_id": "t8run", "worker": "RESEARCH", "destination": "exfil.example:443", "reason": "T8 open incident behind 1.2 MB of filler"}) + "\n")
    for i in range(5000):
        f.write(json.dumps({"timestamp": "2026-01-01T00:00:01Z", "event_type": "egress_allowed", "run_id": "f%d" % i, "worker": "GHSA_COLLECTOR", "destination": "api.github.com:443", "reason": "x" * 200}) + "\n")
PY
T8_BYTES="$(wc -c < "$FIXTURE_LOG" | tr -d ' ')"
assert_eq "T8 fixture exceeds 1.1 MB" "true" "$([ "$T8_BYTES" -gt 1153433 ] && echo true || echo false)"
T8_OUT="$(WAIO_AUDIT_LOG="$FIXTURE_LOG" ./dashboard/build_incident_history.sh 2>&1)"; T8_RC=$?
assert_eq "T8 exit 0" "0" "$T8_RC"
assert_eq "T8 no ARG_MAX error" "false" "$([[ "$T8_OUT" == *"Argument list too long"* ]] && echo true || echo false)"
assert_eq "T8 the one open incident is visible" "1:1" "$(jget 'str(d["total_incidents"]) + ":" + str(d["open_incidents"])')"
assert_eq "T8 lines_read counts every line" "5001" "$(jget 'd["input_stats"]["lines_read"]')"

echo "[T9] failure is reported, never masked: non-zero exit, no 'Written', previous output left intact"
printf '{"sentinel": "previous good output"}\n' > "$OUTPUT_PATH"
T9_SUM_BEFORE="$(shasum -a 256 "$OUTPUT_PATH" | awk '{print $1}')"
mkdir -p "$WAIO_TEST_ROOT/readonly"; chmod 555 "$WAIO_TEST_ROOT/readonly"
T9_OUT="$(WAIO_AUDIT_LOG="$FIXTURE_LOG" WAIO_INCIDENT_HISTORY_OUTPUT="$WAIO_TEST_ROOT/readonly/out.json" ./dashboard/build_incident_history.sh 2>&1)"; T9_RC=$?
chmod 755 "$WAIO_TEST_ROOT/readonly"
assert_eq "T9 non-zero exit on write failure" "true" "$([ "$T9_RC" -ne 0 ] && echo true || echo false)"
assert_eq "T9 does not claim 'Written'" "false" "$([[ "$T9_OUT" == *"Written to"* ]] && echo true || echo false)"
assert_eq "T9 reports NOT updated" "true" "$([[ "$T9_OUT" == *"was NOT updated"* ]] && echo true || echo false)"
assert_eq "T9 no partial/temp file left" "0" "$(find "$WAIO_TEST_ROOT/readonly" -type f | wc -l | tr -d ' ')"
assert_eq "T9 unrelated previous output untouched" "$T9_SUM_BEFORE" "$(shasum -a 256 "$OUTPUT_PATH" | awk '{print $1}')"

echo "[T10] ordering: events are paired by timestamp, not raw file order"
cat > "$FIXTURE_LOG" <<'EOF'
{"timestamp": "2026-01-01T00:00:03Z", "event_type": "recovery_confirmed", "run_id": "recover-b", "worker": "n/a", "destination": "n/a", "reason": "T10 B cleanup"}
{"timestamp": "2026-01-01T00:00:02Z", "event_type": "shutdown_triggered", "run_id": "b", "worker": "UNIT_TEST", "destination": "dest-b", "reason": "T10 incident B"}
{"timestamp": "2026-01-01T00:00:01Z", "event_type": "recovery_confirmed_guardian", "run_id": "recover-a", "worker": "n/a", "destination": "n/a", "reason": "T10 A cleanup"}
{"timestamp": "2026-01-01T00:00:00Z", "event_type": "shutdown_triggered", "run_id": "a", "worker": "UNIT_TEST", "destination": "dest-a", "reason": "T10 incident A"}
EOF
run_with_fixture
assert_eq "T10 two resolved incidents" "2:0" "$(jget 'str(d["total_incidents"]) + ":" + str(d["open_incidents"])')"
assert_eq "T10 chronological order" "T10 incident A|T10 incident B" "$(jget '"|".join(i["detection"]["reason"] for i in d["incidents"])')"
assert_eq "T10 A paired with its own (guardian) recovery" "guardian:2026-01-01T00:00:01Z" "$(jget 'd["incidents"][0]["recovery"]["actor"] + ":" + d["incidents"][0]["recovery"]["recovered_at"]')"
assert_eq "T10 no orphan recoveries" "0" "$(jget 'd["input_stats"]["orphan_recoveries"]')"

echo "[T11] same-second ties keep file order (stable sort)"
cat > "$FIXTURE_LOG" <<'EOF'
{"timestamp": "2026-01-01T00:00:00Z", "event_type": "shutdown_triggered", "run_id": "t11", "worker": "UNIT_TEST", "destination": "dest-t11", "reason": "T11 trip"}
{"timestamp": "2026-01-01T00:00:00Z", "event_type": "recovery_confirmed", "run_id": "recover-t11", "worker": "n/a", "destination": "n/a", "reason": "T11 cleanup"}
EOF
run_with_fixture
assert_eq "T11 trip-then-recovery in the same second resolves" "resolved" "$(jget 'd["incidents"][0]["status"]')"

echo "[T12] missing/malformed timestamps and missing fields: never dropped, flagged and counted"
cat > "$FIXTURE_LOG" <<'EOF'
{"timestamp": "2026-01-01T00:00:00Z", "event_type": "egress_allowed", "worker": "X"}
{"event_type": "shutdown_triggered", "reason": "T12 no timestamp, no worker/run_id/destination"}
{"timestamp": "yesterday", "event_type": "recovery_confirmed", "reason": "T12 bad timestamp"}
EOF
run_with_fixture
assert_eq "T12 incident still reconstructed" "1" "$(jget 'd["total_incidents"]')"
assert_eq "T12 detection timestamp flagged invalid, not invented" "None:False" "$(jget 'str(d["incidents"][0]["detection"]["triggered_at"]) + ":" + str(d["incidents"][0]["detection"]["timestamp_valid"])')"
assert_eq "T12 missing fields are null" "None|None|None" "$(jget '"|".join(str(d["incidents"][0]["detection"][k]) for k in ("worker", "run_id", "destination"))')"
assert_eq "T12 recovery paired but its timestamp flagged" "resolved:None:False" "$(jget 'd["incidents"][0]["status"] + ":" + str(d["incidents"][0]["recovery"]["recovered_at"]) + ":" + str(d["incidents"][0]["recovery"]["timestamp_valid"])')"
assert_eq "T12 invalid_timestamp_events" "2" "$(jget 'd["input_stats"]["invalid_timestamp_events"]')"

echo "[T13] duplicate (replayed) events are ignored and counted; a re-trigger with a new hash is still a duplicate trigger"
cat > "$FIXTURE_LOG" <<'EOF'
{"timestamp": "2026-01-01T00:00:00Z", "event_type": "shutdown_triggered", "run_id": "t13", "worker": "UNIT_TEST", "destination": "dest-t13", "reason": "T13 trip", "prev_hash": "aaa"}
{"timestamp": "2026-01-01T00:00:00Z", "event_type": "shutdown_triggered", "run_id": "t13", "worker": "UNIT_TEST", "destination": "dest-t13", "reason": "T13 trip", "prev_hash": "aaa"}
{"timestamp": "2026-01-01T00:00:01Z", "event_type": "shutdown_triggered", "run_id": "t13b", "worker": "UNIT_TEST", "destination": "dest-t13", "reason": "T13 genuine re-trip", "prev_hash": "bbb"}
{"timestamp": "2026-01-01T00:00:02Z", "event_type": "recovery_confirmed", "run_id": "recover-t13", "worker": "n/a", "destination": "n/a", "reason": "T13 cleanup", "prev_hash": "ccc"}
{"timestamp": "2026-01-01T00:00:02Z", "event_type": "recovery_confirmed", "run_id": "recover-t13", "worker": "n/a", "destination": "n/a", "reason": "T13 cleanup", "prev_hash": "ccc"}
EOF
run_with_fixture
assert_eq "T13 one incident" "1" "$(jget 'd["total_incidents"]')"
assert_eq "T13 duplicate_trigger_count counts only the genuine re-trip" "1" "$(jget 'd["incidents"][0]["duplicate_trigger_count"]')"
assert_eq "T13 duplicate_events_ignored" "2" "$(jget 'd["input_stats"]["duplicate_events_ignored"]')"
assert_eq "T13 replayed recovery is not an orphan" "0" "$(jget 'd["input_stats"]["orphan_recoveries"]')"

echo "[T14] malformed input: bad JSON, non-object JSON, binary garbage -- skipped and counted, valid events kept"
{
  printf '{"timestamp": "2026-01-01T00:00:00Z", "event_type": "shutdown_triggered", "run_id": "t14", "worker": "UNIT_TEST", "destination": "dest-t14", "reason": "T14 trip"}\n'
  printf '{not json\n'
  printf '[1, 2, 3]\n'
  printf '"just a string"\n'
  printf '\xff\xfe\x00garbage\n'
  printf '{"timestamp": "2026-01-01T00:00:01Z", "event_type": "recovery_confirmed", "run_id": "recover-t14", "worker": "n/a", "destination": "n/a", "reason": "T14 cleanup"}\n'
} > "$FIXTURE_LOG"
run_with_fixture
assert_eq "T14 exit status 0 (malformed lines do not abort)" "0" "$?"
assert_eq "T14 incident reconstructed" "resolved" "$(jget 'd["incidents"][0]["status"]')"
assert_eq "T14 malformed_lines" "4" "$(jget 'd["input_stats"]["malformed_lines"]')"

echo "[T15] orphan recovery (no open incident) is counted, never fabricated into an incident"
cat > "$FIXTURE_LOG" <<'EOF'
{"timestamp": "2026-01-01T00:00:00Z", "event_type": "recovery_confirmed", "run_id": "recover-orphan", "worker": "n/a", "destination": "n/a", "reason": "T15 orphan"}
EOF
run_with_fixture
assert_eq "T15 zero incidents, one orphan" "0:1" "$(jget 'str(d["total_incidents"]) + ":" + str(d["input_stats"]["orphan_recoveries"])')"

echo "[T16] test artifacts are labelled and split from production; labels never hide or close an incident"
cat > "$FIXTURE_LOG" <<'EOF'
{"timestamp": "2026-01-01T00:00:00Z", "event_type": "shutdown_triggered", "run_id": "redteam", "worker": "MALICIOUS_TEST_WORKER", "destination": "198.51.100.1:9999", "reason": "response60-style fixture trip"}
{"timestamp": "2026-01-01T00:00:01Z", "event_type": "recovery_confirmed", "run_id": "recover-x", "worker": "n/a", "destination": "n/a", "reason": "fixture cleanup"}
{"timestamp": "2026-01-01T00:00:02Z", "event_type": "shutdown_triggered", "run_id": "run-42", "worker": "RESEARCH", "destination": "exfil.example:443", "reason": "genuine-looking trip"}
{"timestamp": "2026-01-01T00:00:03Z", "event_type": "recovery_confirmed", "run_id": "recover-y", "worker": "n/a", "destination": "n/a", "reason": "operator cleanup"}
{"timestamp": "2026-01-01T00:00:04Z", "event_type": "shutdown_triggered", "run_id": "run-43", "worker": "RPI", "destination": "203.0.113.7:22", "reason": "TEST-NET-3 destination, still open"}
EOF
run_with_fixture
assert_eq "T16 totals: 3 incidents, 1 production, 2 test artifacts" "3:1:2" "$(jget '":".join(str(d[k]) for k in ("total_incidents", "production_incidents", "test_artifact_incidents"))')"
assert_eq "T16 fixture trip origin + basis" "test_artifact:rfc5737_destination,test_fixture_worker,redteam_run_id" "$(jget 'd["incidents"][0]["origin"] + ":" + ",".join(d["incidents"][0]["origin_basis"])')"
assert_eq "T16 genuine-looking trip is production with no basis" "production:" "$(jget 'd["incidents"][1]["origin"] + ":" + ",".join(d["incidents"][1]["origin_basis"])')"
assert_eq "T16 an OPEN test-artifact incident still counts as open" "open:1" "$(jget 'd["incidents"][2]["status"] + ":" + str(d["open_incidents"])')"
assert_eq "T16 'UNIT_TEST'-style worker names alone are NOT treated as test artifacts" "production" "$(
  printf '{"timestamp": "2026-01-01T00:00:00Z", "event_type": "shutdown_triggered", "run_id": "r", "worker": "UNIT_TEST", "destination": "dest", "reason": "x"}\n' > "$FIXTURE_LOG"; run_with_fixture; jget 'd["incidents"][0]["origin"]')"

echo "[T17] the live Dashboard output and the live audit log were never written by this suite"
assert_eq "T17 live incident-history-latest.json unchanged" "$LIVE_OUTPUT_SUM_BEFORE" "$([ -f "$LIVE_OUTPUT" ] && shasum -a 256 "$LIVE_OUTPUT" | awk '{print $1}' || echo "absent")"
assert_eq "T17 live audit log: pre-existing bytes unchanged" "$REAL_AUDIT_PREFIX_BEFORE" "$([ -f "$REAL_AUDIT_LOG" ] && head -c "$REAL_AUDIT_SIZE_BEFORE" "$REAL_AUDIT_LOG" | shasum -a 256 | awk '{print $1}' || echo "absent")"
assert_eq "T17 live audit log: nothing this suite writes was appended" "0" "$([ -f "$REAL_AUDIT_LOG" ] && tail -c +"$((REAL_AUDIT_SIZE_BEFORE + 1))" "$REAL_AUDIT_LOG" | { grep -cE 't[0-9]+run|UNIT_TEST|fixture-audit' || true; } || echo 0)"
assert_eq "T17 no stubbed privileged/network/notify command was called" "0:0:0" "$(waio_test_stub_calls sudo):$(waio_test_stub_calls ssh):$(waio_test_stub_calls osascript)"

echo
echo "=== Summary: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
  echo "Failures:"
  for f in "${FAILURES[@]}"; do echo "  - $f"; done
  exit 1
fi
exit 0
