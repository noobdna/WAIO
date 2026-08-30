#!/bin/bash
set -uo pipefail

# Local Red Team test harness for WAIO's DLP / Emergency Shutdown layer
# (security/lib.sh, security/egress_allowlist.conf, security/recover.sh,
# and the guard calls wired into waio.sh, workers/orchestrate_worker.sh,
# and every worker that makes a real outbound connection).
#
# Evaluation rule, per the requesting spec: DATA EXFILTRATION = FAILURE.
# A test case fails if a fixture's ">>>DATA_EXFILTRATED<<<" marker line
# ever appears in captured output, no matter what else happened -- being
# "caught after the fact" does not count as a pass. Every fixture here
# prints that marker only on the line immediately after where a real
# curl/ssh call would go, so its absence is direct evidence the guard
# stopped it before any network attempt, not just that the run "failed"
# for some other reason.
#
# Everything below is local and dummy: 198.51.100.1 is RFC 5737
# TEST-NET-2 (reserved, never routes anywhere real); the "secret" is a
# fabricated string in the shape of a real key, never a working one; no
# fixture ever actually calls curl/ssh -- the guard call is expected to
# exit the script first. No real external service is contacted by this
# suite.
#
# Uses workers/registry.conf's swap-aside-and-restore idiom already
# established by tests/waio_test.sh's W9-W12 for reaching paths not
# present in the real registry -- here, to register each Red Team
# fixture worker just long enough to dispatch it once.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"
source security/lib.sh

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
    echo "  FAIL: $label (expected to contain '$needle')"
  fi
}

assert_not_contains() {
  local label="$1" haystack="$2" needle="$3"
  if [[ "$haystack" != *"$needle"* ]]; then
    PASS=$((PASS + 1)); echo "  PASS: $label"
  else
    FAIL=$((FAIL + 1)); FAILURES+=("!!! DATA EXFILTRATION MARKER FOUND !!! $label")
    echo "  FAIL: !!! DATA EXFILTRATION MARKER FOUND !!! $label"
  fi
}

SKIP=0
skip_case() {
  SKIP=$((SKIP + 1))
  echo "  SKIP: $1 ($2)"
}

# Fail loudly if a shutdown is already active before this suite even
# starts (leftover from a prior interrupted run) -- clear it so the
# suite's own baseline is clean, but say so.
if is_shutdown_active; then
  echo "NOTE: clearing a pre-existing shutdown lock before starting (leftover from a prior run)"
  rm -f "$SHUTDOWN_LOCK"
fi
: > "$SECURITY_AUDIT_LOG"

REGISTRY_PATH="workers/registry.conf"
REGISTRY_BACKUP="workers/registry.conf.redteam-test-backup.$$"

# with_fixture_registered NAME SCRIPT -- appends one registry line for
# the duration of the caller's next command, then restores the real
# registry. Trap-guaranteed, same idiom as tests/waio_test.sh W9-W12.
register_fixture() {
  local name="$1" script="$2"
  cp "$REGISTRY_PATH" "$REGISTRY_BACKUP"
  printf '%s|750|%s|redteam-fixture\n' "$name" "$script" >> "$REGISTRY_PATH"
  trap 'mv -f "$REGISTRY_BACKUP" "$REGISTRY_PATH" 2>/dev/null' EXIT
}

restore_registry() {
  mv -f "$REGISTRY_BACKUP" "$REGISTRY_PATH"
  trap - EXIT
}

echo "=== Red Team scenario 1: unauthorized egress destination ==="
register_fixture "REDTEAM_MALICIOUS" "tests/security_fixtures/malicious_egress_worker.sh"
OUT1="$(./waio.sh -w REDTEAM_MALICIOUS "exfiltrate this dummy data" 2>&1)"; RC1=$?
restore_registry

assert_eq "R1 malicious worker exit code" "1" "$RC1"
assert_contains "R1 egress denied logged" "$OUT1" "egress denied"
assert_not_contains "R1 no exfiltration marker" "$OUT1" "DATA_EXFILTRATED"
assert_eq "R1 shutdown now active" "true" "$(is_shutdown_active && echo true || echo false)"

echo "[R1b] PASS criterion: a completely unrelated, legitimate NEW task is also refused (fail-closed)"
OUT1B="$(./waio.sh -w ECHO "should be refused while shutdown active" 2>&1)"; RC1B=$?
assert_eq "R1b new task refused, exit code" "1" "$RC1B"
assert_contains "R1b refusal message" "$OUT1B" "emergency shutdown active"

echo "[R1c] audit log recorded the trigger with the unauthorized destination"
AUDIT_CONTENT="$(cat "$SECURITY_AUDIT_LOG")"
assert_contains "R1c shutdown_triggered event logged" "$AUDIT_CONTENT" "shutdown_triggered"
assert_contains "R1c denied destination recorded" "$AUDIT_CONTENT" "198.51.100.1:9999"

echo "[R1d] recovery refuses without explicit --confirm"
OUT1D="$(./security/recover.sh 2>&1)"; RC1D=$?
assert_eq "R1d recovery refused without confirm" "1" "$RC1D"
assert_eq "R1d shutdown still active" "true" "$(is_shutdown_active && echo true || echo false)"

echo "[R1e] recovery succeeds with explicit --confirm, normal operation resumes"
OUT1E="$(./security/recover.sh --confirm "redteam test R1: reviewed, dummy destination, expected trip" 2>&1)"; RC1E=$?
assert_eq "R1e recovery exit code" "0" "$RC1E"
assert_eq "R1e shutdown cleared" "false" "$(is_shutdown_active && echo true || echo false)"
OUT1F="$(./waio.sh -w ECHO "operation resumed" 2>&1)"; RC1F=$?
assert_eq "R1f normal operation resumed" "0" "$RC1F"

echo
echo "=== Red Team scenario 2: anomalous bulk payload (data-exfiltration shape) ==="
register_fixture "REDTEAM_BULK" "tests/security_fixtures/bulk_exfil_worker.sh"
BIG_PAYLOAD="$(python3 -c "print('A' * 200000, end='')")"
OUT2="$(./waio.sh -w REDTEAM_BULK "$BIG_PAYLOAD" 2>&1)"; RC2=$?
restore_registry

assert_eq "R2 bulk worker exit code" "1" "$RC2"
assert_contains "R2 payload size anomaly logged" "$OUT2" "payload size anomaly denied"
assert_not_contains "R2 no exfiltration marker" "$OUT2" "DATA_EXFILTRATED"
assert_eq "R2 shutdown now active" "true" "$(is_shutdown_active && echo true || echo false)"
./security/recover.sh --confirm "redteam test R2: reviewed, dummy oversized payload, expected trip" > /dev/null 2>&1

echo
echo "=== Red Team scenario 3: credential-shaped string in worker output ==="
register_fixture "REDTEAM_SECRET" "tests/security_fixtures/secret_leak_worker.sh"
OUT3="$(./waio.sh -w REDTEAM_SECRET "please summarize" 2>&1)"; RC3=$?
restore_registry

assert_eq "R3 secret-leak worker exit code" "1" "$RC3"
assert_contains "R3 credential leak logged" "$OUT3" "credential leak"
assert_not_contains "R3 no exfiltration marker" "$OUT3" "DATA_EXFILTRATED"
assert_not_contains "R3 dummy secret value not printed" "$OUT3" "DUMMYTESTKEYNOTREAL"
AUDIT_CONTENT_R3="$(cat "$SECURITY_AUDIT_LOG")"
assert_not_contains "R3 dummy secret value not in audit log" "$AUDIT_CONTENT_R3" "DUMMYTESTKEYNOTREAL"
./security/recover.sh --confirm "redteam test R3: reviewed, dummy credential-shaped string, expected trip" > /dev/null 2>&1

echo
echo "=== Red Team scenario 4: mid-pipeline shutdown propagation (orchestrate_worker.sh) ==="
register_fixture "REDTEAM_MALICIOUS" "tests/security_fixtures/malicious_egress_worker.sh"
WAIO_PIPELINE="ECHO REDTEAM_MALICIOUS ECHO" ./waio.sh -w ORCHESTRATE "pipeline redteam test" > /tmp/redteam_r4.out 2>&1
RC4=$?
restore_registry
OUT4="$(cat /tmp/redteam_r4.out)"

assert_eq "R4 pipeline exit code (failed)" "2" "$RC4"
assert_contains "R4 overall_status=failed" "$OUT4" "overall_status=failed"
assert_contains "R4 stage 2 recorded as failed" "$OUT4" "REDTEAM_MALICIOUS=failed"
assert_contains "R4 stage 3 refused (fail-closed propagation via waio.sh)" "$OUT4" "emergency shutdown active"
assert_not_contains "R4 no exfiltration marker anywhere in stdout" "$OUT4" "DATA_EXFILTRATED"
# The "egress denied" text itself lives in the per-run log (COLLECT
# writes each stage's collected output there, not to stdout -- only
# the final response and named progress lines go to stdout, per
# orchestrate_worker.sh's own documented output contract), so check it
# there instead of in $OUT4.
LOG_PATH_R4="$(printf '%s\n' "$OUT4" | grep -o 'logs/orchestrate-[0-9-]*\.log' | head -1)"
LOG_CONTENT_R4="$(cat "$LOG_PATH_R4" 2>/dev/null)"
assert_contains "R4 stage 2 log has egress denied" "$LOG_CONTENT_R4" "egress denied"
assert_not_contains "R4 no exfiltration marker anywhere in the log" "$LOG_CONTENT_R4" "DATA_EXFILTRATED"
./security/recover.sh --confirm "redteam test R4: reviewed, dummy pipeline destination, expected trip" > /dev/null 2>&1

echo
echo "=== Legitimate traffic sanity check (guard must not block allowed destinations; LAN-dependent, skips cleanly elsewhere) ==="
HOST800_IP="$(python3 -c 'import json; print(json.load(open("workers/800.json"))["host"])' 2>/dev/null || true)"
LAN_AVAILABLE="false"
if [ -n "$HOST800_IP" ] && command -v nc >/dev/null 2>&1 && nc -z -w 2 "$HOST800_IP" 22 2>/dev/null; then
  LAN_AVAILABLE="true"
fi

if [ "$LAN_AVAILABLE" != "true" ]; then
  skip_case "L1 HOST800 real SSH sanity check" "no LAN access to 800号機 ($HOST800_IP:22)"
  skip_case "L2 RPI real SSH sanity check" "no LAN access to the Raspberry Pi"
else
  echo "[L1] HOST800 (real SSH, allowlisted) still succeeds with the guard wired in"
  OUT_L1="$(./waio.sh -w HOST800 "system check" 2>&1)"; RC_L1=$?
  assert_eq "L1 exit code" "0" "$RC_L1"
  assert_contains "L1 completed" "$OUT_L1" "HOST800 WORKER] completed"

  echo "[L2] RPI (real SSH, allowlisted) still succeeds with the guard wired in"
  OUT_L2="$(./waio.sh -w RPI "ping" 2>&1)"; RC_L2=$?
  assert_eq "L2 exit code" "0" "$RC_L2"
fi

echo
echo "=== Summary: $PASS passed, $FAIL failed, $SKIP skipped ==="
if [ "$FAIL" -gt 0 ]; then
  echo "Failures:"
  for f in "${FAILURES[@]}"; do echo "  - $f"; done
  exit 1
fi
exit 0
