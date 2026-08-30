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
# 110000 bytes: comfortably over MAX_PAYLOAD_BYTES's 100000-byte default
# threshold, but kept under Linux's MAX_ARG_STRLEN (128 KiB = 131072
# bytes, a per-argument execve() limit) -- a larger value passed exec()
# fine on macOS but failed with exit 126 (E2BIG) on GitHub's
# ubuntu-latest runner, since a single shell argument this size hits
# that kernel limit before ever reaching this script's own guard logic.
BIG_PAYLOAD="$(python3 -c "print('A' * 110000, end='')")"
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
echo "=== Phase 24: direct unit tests for security/lib.sh's own edge cases ==="
echo "(security/lib.sh is already sourced above -- these call its functions directly, not through a fixture worker, to reach branches the Red Team scenarios above don't exercise on their own)"

echo "[U1] recover.sh: no active shutdown -> 'nothing to do', exit 0"
assert_eq "U1 precondition: shutdown not active" "false" "$(is_shutdown_active && echo true || echo false)"
OUT_U1="$(./security/recover.sh 2>&1)"; RC_U1=$?
assert_eq "U1 exit code" "0" "$RC_U1"
assert_contains "U1 message" "$OUT_U1" "Nothing to do"

echo "[U2] payload_size_check: a payload within the limit is allowed, no shutdown"
if payload_size_check "small dummy payload" "phase24" "u2" "UNIT_TEST" "localhost:3000"; then U2_RC=0; else U2_RC=1; fi
assert_eq "U2 within-limit payload allowed" "0" "$U2_RC"
assert_eq "U2 no shutdown tripped" "false" "$(is_shutdown_active && echo true || echo false)"

echo "[U3] secret_leak_check: clean output (no credential-shaped string) is allowed, no shutdown"
if secret_leak_check "this is a perfectly normal response with no secrets" "phase24" "u3" "UNIT_TEST" "localhost:3000"; then U3_RC=0; else U3_RC=1; fi
assert_eq "U3 clean output allowed" "0" "$U3_RC"
assert_eq "U3 no shutdown tripped" "false" "$(is_shutdown_active && echo true || echo false)"

echo "[U4] egress_check: a wildcard port ('*') allowlist entry matches any port on that host"
ALLOWLIST_PATH="security/egress_allowlist.conf"
ALLOWLIST_BACKUP="security/egress_allowlist.conf.phase24-test-backup.$$"
cp "$ALLOWLIST_PATH" "$ALLOWLIST_BACKUP"
printf '203.0.113.5|*|phase24 dummy wildcard test entry (RFC 5737 TEST-NET-3, reserved)\n' >> "$ALLOWLIST_PATH"
trap 'mv -f "$ALLOWLIST_BACKUP" "$ALLOWLIST_PATH" 2>/dev/null' EXIT
if egress_check "203.0.113.5" "51234" "phase24" "u4" "UNIT_TEST"; then U4_RC=0; else U4_RC=1; fi
mv -f "$ALLOWLIST_BACKUP" "$ALLOWLIST_PATH"
trap - EXIT
assert_eq "U4 wildcard port entry allows any port on that host" "0" "$U4_RC"

echo "[U5] egress_check: allowlist file missing entirely -> denied, fail-closed, shutdown tripped"
mv "$ALLOWLIST_PATH" "$ALLOWLIST_BACKUP"
trap 'mv -f "$ALLOWLIST_BACKUP" "$ALLOWLIST_PATH" 2>/dev/null' EXIT
if egress_check "localhost" "3000" "phase24" "u5" "UNIT_TEST"; then U5_RC=0; else U5_RC=1; fi
mv -f "$ALLOWLIST_BACKUP" "$ALLOWLIST_PATH"
trap - EXIT
assert_eq "U5 egress_check denies when allowlist missing (fail-closed)" "1" "$U5_RC"
assert_eq "U5 shutdown tripped" "true" "$(is_shutdown_active && echo true || echo false)"
./security/recover.sh --confirm "phase24 U5: reviewed, dummy missing-allowlist test, expected trip" > /dev/null 2>&1

echo "[U6] trigger_shutdown: idempotent -- the first trip's reason is preserved, not overwritten by a second"
trigger_shutdown "phase24 U6 first reason" "u6run" "1" "UNIT_TEST" "dest-a"
trigger_shutdown "phase24 U6 second reason should not overwrite" "u6run" "2" "UNIT_TEST" "dest-b"
LOCK_CONTENT_U6="$(cat "$SHUTDOWN_LOCK" 2>/dev/null)"
assert_contains "U6 lock still shows the first reason" "$LOCK_CONTENT_U6" "phase24 U6 first reason"
assert_not_contains "U6 lock was not overwritten by the second reason" "$LOCK_CONTENT_U6" "second reason should not overwrite"
AUDIT_U6="$(cat "$SECURITY_AUDIT_LOG")"
U6_TRIGGER_COUNT="$(printf '%s\n' "$AUDIT_U6" | grep -c 'phase24 U6')"
assert_eq "U6 both trigger attempts still logged to audit (2 events)" "2" "$U6_TRIGGER_COUNT"
./security/recover.sh --confirm "phase24 U6: reviewed, dummy idempotency test, expected trip" > /dev/null 2>&1

echo "[U7] egress_check: denies even an allowlisted destination while shutdown is already active (defense in depth)"
trigger_shutdown "phase24 U7 setup trip" "u7run" "1" "UNIT_TEST" "dest-setup"
if egress_check "localhost" "3000" "phase24" "u7" "UNIT_TEST"; then U7_RC=0; else U7_RC=1; fi
assert_eq "U7 allowlisted destination still denied while shutdown active" "1" "$U7_RC"
AUDIT_U7="$(cat "$SECURITY_AUDIT_LOG")"
assert_contains "U7 denial reason recorded as shutdown already active" "$AUDIT_U7" "shutdown already active"
./security/recover.sh --confirm "phase24 U7: reviewed, dummy defense-in-depth test, expected trip" > /dev/null 2>&1

echo
echo "=== Phase 25: real production workers denied, not a fixture stand-in ==="
echo "(R1-R4 above all use purpose-built fixture workers to prove the guard mechanism works in general. Neither host800_worker.sh's nor rpi_worker.sh's own egress_check call site had ever been proven to actually deny -- only to allow, via L1/L2 below. These two cases close that gap: temporarily drop each real worker's own allowlist entry and dispatch it for real.)"
ALLOWLIST_PATH="security/egress_allowlist.conf"
ALLOWLIST_BACKUP="security/egress_allowlist.conf.phase25-test-backup.$$"
if command -v timeout >/dev/null 2>&1; then TIMEOUT_CMD="timeout 20"; else TIMEOUT_CMD=""; fi

echo "[R5] HOST800: denied when its own allowlist entry is temporarily removed (no real SSH attempted)"
cp "$ALLOWLIST_PATH" "$ALLOWLIST_BACKUP"
grep -v '^192\.168\.1\.91|' "$ALLOWLIST_PATH" > "${ALLOWLIST_PATH}.phase25tmp" && mv "${ALLOWLIST_PATH}.phase25tmp" "$ALLOWLIST_PATH"
trap 'mv -f "$ALLOWLIST_BACKUP" "$ALLOWLIST_PATH" 2>/dev/null' EXIT
OUT_R5="$($TIMEOUT_CMD ./waio.sh -w HOST800 "system check" 2>&1)"; RC_R5=$?
mv -f "$ALLOWLIST_BACKUP" "$ALLOWLIST_PATH"
trap - EXIT
assert_eq "R5 exit code" "1" "$RC_R5"
assert_contains "R5 egress denied by HOST800's own guard call" "$OUT_R5" "egress denied by DLP guard"
assert_eq "R5 shutdown tripped" "true" "$(is_shutdown_active && echo true || echo false)"
./security/recover.sh --confirm "phase25 R5: reviewed, dummy allowlist-removal test on the real HOST800 worker, expected trip" > /dev/null 2>&1

echo "[R6] RPI: denied when its own allowlist entry is temporarily removed (no real SSH attempted)"
cp "$ALLOWLIST_PATH" "$ALLOWLIST_BACKUP"
grep -v '^192\.168\.1\.150|' "$ALLOWLIST_PATH" > "${ALLOWLIST_PATH}.phase25tmp" && mv "${ALLOWLIST_PATH}.phase25tmp" "$ALLOWLIST_PATH"
trap 'mv -f "$ALLOWLIST_BACKUP" "$ALLOWLIST_PATH" 2>/dev/null' EXIT
OUT_R6="$($TIMEOUT_CMD ./waio.sh -w RPI "ping" 2>&1)"; RC_R6=$?
mv -f "$ALLOWLIST_BACKUP" "$ALLOWLIST_PATH"
trap - EXIT
assert_eq "R6 exit code" "1" "$RC_R6"
assert_contains "R6 egress denied by RPI's own guard call" "$OUT_R6" "egress denied by DLP guard"
assert_eq "R6 shutdown tripped" "true" "$(is_shutdown_active && echo true || echo false)"
./security/recover.sh --confirm "phase25 R6: reviewed, dummy allowlist-removal test on the real RPI worker, expected trip" > /dev/null 2>&1

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
