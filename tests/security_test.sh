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

# Phase 29 gitignored the real security/egress_allowlist.conf (it holds
# this deployment's real destinations), so a fresh checkout of this repo
# -- including every CI run -- has no such file until an operator copies
# it from the .example template (see README.md's Setup section). This
# suite's R2/R3/R5/R6/U4 cases need a real, on-disk allowlist to reach
# the specific denial paths they're testing (payload size, secret leak,
# a removed single entry), not the generic "file missing entirely" path
# U5 already covers on its own -- so if there is no real file yet,
# synthesize the exact baseline this suite has always assumed, run with
# that, and remove it again afterward so a bare checkout is left exactly
# as it was found. An operator's own real file, if already present, is
# never touched.
ALLOWLIST_PATH_FOR_SETUP="security/egress_allowlist.conf"
CREATED_ALLOWLIST_FOR_TEST="false"
if [ ! -f "$ALLOWLIST_PATH_FOR_SETUP" ]; then
  cat > "$ALLOWLIST_PATH_FOR_SETUP" <<'EOF'
localhost|3000|Takomachi API gateway (RESEARCH/ANALYSIS/AI/HEALTHCHECK)
192.168.1.150|22|Raspberry Pi (RPI worker)
192.168.1.91|22|800号機 (HOST800 worker, host read from workers/800.json)
EOF
  CREATED_ALLOWLIST_FOR_TEST="true"
  echo "NOTE: security/egress_allowlist.conf not found -- synthesized a test-only baseline for this run (removed again at the end); see README.md's Setup section for a real deployment."
fi

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
echo "=== Phase 35: Guardian Recovery Protocol (--guardian-confirm, security/guardian_recover_wrapper.sh) ==="
echo "(Local invocation only -- no real SSH, consistent with Phase 35 explicitly deferring the 800->750 reachability work.)"

trigger_shutdown "phase35 G1/G2 test trip" "g1run" "1" "UNIT_TEST" "dest-g1"

echo "[G1] --guardian-confirm refuses without a reason, same as --confirm"
OUT_G1="$(./security/recover.sh --guardian-confirm 2>&1)"; RC_G1=$?
assert_eq "G1 recovery refused without reason" "1" "$RC_G1"
assert_eq "G1 shutdown still active" "true" "$(is_shutdown_active && echo true || echo false)"

echo "[G2] --guardian-confirm with a reason clears the shutdown, audit log distinguishes the guardian actor"
OUT_G2="$(./security/recover.sh --guardian-confirm "phase35 G2: guardian path test" 2>&1)"; RC_G2=$?
assert_eq "G2 recovery exit code" "0" "$RC_G2"
assert_eq "G2 shutdown cleared" "false" "$(is_shutdown_active && echo true || echo false)"
AUDIT_CONTENT_G2="$(cat "$SECURITY_AUDIT_LOG")"
assert_contains "G2 audit log records guardian actor" "$AUDIT_CONTENT_G2" "recovery_confirmed_guardian"

echo "[G3] guardian_recover_wrapper.sh forwards SSH_ORIGINAL_COMMAND as the reason, without real SSH"
trigger_shutdown "phase35 G3 test trip" "g3run" "1" "UNIT_TEST" "dest-g3"
G3_REASON="phase35 G3 wrapper reason $$"
OUT_G3="$(SSH_ORIGINAL_COMMAND="$G3_REASON" ./security/guardian_recover_wrapper.sh 2>&1)"; RC_G3=$?
assert_eq "G3 wrapper exit code" "0" "$RC_G3"
assert_eq "G3 shutdown cleared" "false" "$(is_shutdown_active && echo true || echo false)"
assert_contains "G3 exact reason text forwarded" "$OUT_G3" "$G3_REASON"

echo "[G4] guardian_recover_wrapper.sh: shell-metacharacter reason text is never re-executed (command-injection check)"
trigger_shutdown "phase35 G4 test trip" "g4run" "1" "UNIT_TEST" "dest-g4"
G4_MARKER="/tmp/waio_phase35_g4_pwned_$$"
rm -f "$G4_MARKER" 2>/dev/null
G4_INJECT='phase35 G4 injection test `touch '"$G4_MARKER"'` $(touch '"$G4_MARKER"') ; touch '"$G4_MARKER"' ; echo pwned'
OUT_G4="$(SSH_ORIGINAL_COMMAND="$G4_INJECT" ./security/guardian_recover_wrapper.sh 2>&1)"; RC_G4=$?
assert_eq "G4 wrapper exit code" "0" "$RC_G4"
assert_eq "G4 shutdown cleared" "false" "$(is_shutdown_active && echo true || echo false)"
assert_eq "G4 no command executed (marker file absent)" "false" "$([ -e "$G4_MARKER" ] && echo true || echo false)"
assert_contains "G4 injection text recorded literally in output" "$OUT_G4" "injection test"
rm -f "$G4_MARKER" 2>/dev/null

echo
echo "=== Phase 37: Guardian-side recovery trigger (security/guardian_recover_trigger.sh) ==="
echo "(No real SSH to 750 -- this is the client-side wrapper meant to run on 800号機 itself; H3 attempts a real outbound SSH connection to a reserved, non-routable test address to prove the failure path isn't swallowed.)"

echo "[H1] refuses without GUARDIAN_TARGET_HOST/GUARDIAN_TARGET_USER set, before attempting anything"
OUT_H1="$(unset GUARDIAN_TARGET_HOST GUARDIAN_TARGET_USER; ./security/guardian_recover_trigger.sh "phase37 H1 reason" 2>&1)"; RC_H1=$?
assert_eq "H1 exit code" "1" "$RC_H1"
assert_contains "H1 error mentions missing target" "$OUT_H1" "GUARDIAN_TARGET_HOST and GUARDIAN_TARGET_USER must both be set"

echo "[H2] refuses without a reason, even with a target configured"
OUT_H2="$(GUARDIAN_TARGET_HOST="192.0.2.1" GUARDIAN_TARGET_USER="nobody" ./security/guardian_recover_trigger.sh 2>&1)"; RC_H2=$?
assert_eq "H2 exit code" "1" "$RC_H2"
assert_contains "H2 error mentions missing reason" "$OUT_H2" "refusing to send a recovery request without a reason"

echo "[H3] a real (but unreachable) SSH attempt fails loudly, not silently -- exit code and error text both surface"
OUT_H3="$(GUARDIAN_TARGET_HOST="192.0.2.1" GUARDIAN_TARGET_USER="nobody" GUARDIAN_CONNECT_TIMEOUT="2" GUARDIAN_KEY_PATH="/dev/null" ./security/guardian_recover_trigger.sh "phase37 H3 unreachable-target reason" 2>&1)"; RC_H3=$?
assert_eq "H3 non-zero exit surfaced, not swallowed" "false" "$([ "$RC_H3" -eq 0 ] && echo true || echo false)"
assert_contains "H3 error text mentions the ssh failure" "$OUT_H3" "recovery request failed"

echo
echo "=== Phase 40-C: guardian_recover_trigger.sh's optional persisted config file fallback ==="
echo "(GUARDIAN_CONFIG_PATH always points at a throwaway temp file here -- the real \$HOME/.guardian_recover_trigger.conf, if any, is never read or touched.)"

J_CONF="$(mktemp /tmp/waio_phase40c_test_conf.XXXXXX)"
rm -f "$J_CONF"

echo "[J1] no config file, no env vars -- refuses exactly as before this phase (regression, not a new behavior)"
OUT_J1="$(unset GUARDIAN_TARGET_HOST GUARDIAN_TARGET_USER; GUARDIAN_CONFIG_PATH="$J_CONF" ./security/guardian_recover_trigger.sh "should be refused" 2>&1)"; RC_J1=$?
assert_eq "J1 exit code" "1" "$RC_J1"
assert_contains "J1 error mentions missing target" "$OUT_J1" "GUARDIAN_TARGET_HOST and GUARDIAN_TARGET_USER must both be set"

echo "[J2] config file present, no env vars -- its values are used as a fallback"
cat > "$J_CONF" <<'EOF'
# comment line, ignored
GUARDIAN_TARGET_HOST=192.0.2.2
GUARDIAN_TARGET_USER=fromconfig
GUARDIAN_SOMETHING_ELSE=ignored
EOF
OUT_J2="$(unset GUARDIAN_TARGET_HOST GUARDIAN_TARGET_USER; GUARDIAN_CONFIG_PATH="$J_CONF" GUARDIAN_CONNECT_TIMEOUT="2" GUARDIAN_KEY_PATH="/dev/null" ./security/guardian_recover_trigger.sh "phase40c J2 reason" 2>&1)"; RC_J2=$?
assert_eq "J2 non-zero exit (unreachable target, expected)" "false" "$([ "$RC_J2" -eq 0 ] && echo true || echo false)"
assert_contains "J2 used the config file's host/user" "$OUT_J2" "target: fromconfig@192.0.2.2"

echo "[J3] env var set AND config file present with different values -- env var wins, file is never consulted for that value"
OUT_J3="$(GUARDIAN_TARGET_HOST="192.0.2.3" GUARDIAN_TARGET_USER="fromenv" GUARDIAN_CONFIG_PATH="$J_CONF" GUARDIAN_CONNECT_TIMEOUT="2" GUARDIAN_KEY_PATH="/dev/null" ./security/guardian_recover_trigger.sh "phase40c J3 reason" 2>&1)"; RC_J3=$?
assert_contains "J3 env var host/user used, not the config file's" "$OUT_J3" "target: fromenv@192.0.2.3"
assert_not_contains "J3 config file's values did not leak through" "$OUT_J3" "fromconfig"

rm -f "$J_CONF"

echo
echo "=== Phase 40-B-1: notify_shutdown.sh -- optional, decoupled local notification (never wired into trigger_shutdown(), never touches Takomachi) ==="
echo "(K3/K4 shadow osascript with a fake executable prepended to PATH -- no real system notification fires during this suite.)"

echo "[K1] no active shutdown -- no-op, exit 0, osascript never invoked"
K1_FAKE_LOG="$(mktemp /tmp/waio_phase40b1_k1.XXXXXX)"
rm -f "$K1_FAKE_LOG"
K1_FAKE_DIR="$(mktemp -d /tmp/waio_phase40b1_k1dir.XXXXXX)"
cat > "$K1_FAKE_DIR/osascript" <<EOF
#!/bin/bash
echo "CALLED" >> "$K1_FAKE_LOG"
exit 0
EOF
chmod +x "$K1_FAKE_DIR/osascript"
OUT_K1="$(PATH="$K1_FAKE_DIR:$PATH" ./security/notify_shutdown.sh 2>&1)"; RC_K1=$?
assert_eq "K1 exit code" "0" "$RC_K1"
assert_contains "K1 no-op message" "$OUT_K1" "No active shutdown"
assert_eq "K1 osascript never invoked" "false" "$([ -f "$K1_FAKE_LOG" ] && echo true || echo false)"
rm -rf "$K1_FAKE_DIR" "$K1_FAKE_LOG"

echo "[K2] active shutdown, osascript genuinely unavailable -- skips gracefully, exit 0, reason still surfaced in output"
OSASCRIPT_PRESENT="$(command -v osascript >/dev/null 2>&1 && echo true || echo false)"
if [ "$OSASCRIPT_PRESENT" = "true" ]; then
  skip_case "K2 osascript-unavailable path" "osascript is present on this machine (this path is naturally exercised in CI, which has none)"
else
  trigger_shutdown "phase40b1 K2 test trip" "k2run" "1" "UNIT_TEST" "dest-k2"
  OUT_K2="$(./security/notify_shutdown.sh 2>&1)"; RC_K2=$?
  assert_eq "K2 exit code" "0" "$RC_K2"
  assert_contains "K2 skip message" "$OUT_K2" "osascript not available"
  assert_contains "K2 reason still surfaced" "$OUT_K2" "phase40b1 K2 test trip"
  ./security/recover.sh --confirm "phase40b1 K2 cleanup" > /dev/null 2>&1
fi

echo "[K3] active shutdown, osascript shadowed with a fake on PATH -- correct title/reason passed via env vars, not embedded in the script text"
trigger_shutdown "phase40b1 K3 test trip" "k3run" "1" "UNIT_TEST" "dest-k3"
K3_FAKE_LOG="$(mktemp /tmp/waio_phase40b1_k3.XXXXXX)"
K3_FAKE_DIR="$(mktemp -d /tmp/waio_phase40b1_k3dir.XXXXXX)"
cat > "$K3_FAKE_DIR/osascript" <<EOF
#!/bin/bash
{ echo "TITLE=\$WAIO_NOTIFY_TITLE"; echo "MSG=\$WAIO_NOTIFY_MSG"; cat; } >> "$K3_FAKE_LOG"
exit 0
EOF
chmod +x "$K3_FAKE_DIR/osascript"
OUT_K3="$(PATH="$K3_FAKE_DIR:$PATH" ./security/notify_shutdown.sh 2>&1)"; RC_K3=$?
K3_LOG_CONTENT="$(cat "$K3_FAKE_LOG")"
assert_eq "K3 exit code" "0" "$RC_K3"
assert_contains "K3 correct title passed via env var" "$K3_LOG_CONTENT" "TITLE=WAIO Emergency Shutdown"
assert_contains "K3 correct reason passed via env var" "$K3_LOG_CONTENT" "MSG=phase40b1 K3 test trip"
assert_contains "K3 AppleScript source reads via system attribute, never embeds the reason directly" "$K3_LOG_CONTENT" 'system attribute "WAIO_NOTIFY_MSG"'
rm -rf "$K3_FAKE_DIR" "$K3_FAKE_LOG"
./security/recover.sh --confirm "phase40b1 K3 cleanup" > /dev/null 2>&1

echo "[K4] active shutdown with an injection-shaped reason -- fake osascript receives the literal text, untouched, never executed as shell/AppleScript"
K4_MARKER="/tmp/waio_phase40b1_k4_pwned_$$"
rm -f "$K4_MARKER" 2>/dev/null
K4_INJECT='phase40b1 K4 injection test `touch '"$K4_MARKER"'` $(touch '"$K4_MARKER"') "quoted" ; echo pwned'
trigger_shutdown "$K4_INJECT" "k4run" "1" "UNIT_TEST" "dest-k4"
K4_FAKE_LOG="$(mktemp /tmp/waio_phase40b1_k4.XXXXXX)"
K4_FAKE_DIR="$(mktemp -d /tmp/waio_phase40b1_k4dir.XXXXXX)"
cat > "$K4_FAKE_DIR/osascript" <<EOF
#!/bin/bash
echo "MSG=\$WAIO_NOTIFY_MSG" >> "$K4_FAKE_LOG"
exit 0
EOF
chmod +x "$K4_FAKE_DIR/osascript"
OUT_K4="$(PATH="$K4_FAKE_DIR:$PATH" ./security/notify_shutdown.sh 2>&1)"; RC_K4=$?
K4_LOG_CONTENT="$(cat "$K4_FAKE_LOG")"
assert_eq "K4 exit code" "0" "$RC_K4"
assert_eq "K4 no command executed (marker file absent)" "false" "$([ -e "$K4_MARKER" ] && echo true || echo false)"
assert_contains "K4 injection text passed through literally, unexecuted" "$K4_LOG_CONTENT" "injection test"
rm -rf "$K4_FAKE_DIR" "$K4_FAKE_LOG"
rm -f "$K4_MARKER" 2>/dev/null
./security/recover.sh --confirm "phase40b1 K4 cleanup" > /dev/null 2>&1

echo
echo "=== notify_shutdown.sh auto-notify: WAIO_AUTO_NOTIFY-gated wiring into trigger_shutdown() ==="
echo "(All cases shadow osascript with a fake executable prepended to PATH -- no real system notification fires during this suite, even when WAIO_AUTO_NOTIFY=1 is set below.)"

echo "[O1] WAIO_AUTO_NOTIFY unset (the default) -- trigger_shutdown fires, osascript is NEVER invoked, matching this function's behavior before this change"
unset WAIO_AUTO_NOTIFY
O1_FAKE_LOG="$(mktemp /tmp/waio_o1.XXXXXX)"
rm -f "$O1_FAKE_LOG"
O1_FAKE_DIR="$(mktemp -d /tmp/waio_o1dir.XXXXXX)"
cat > "$O1_FAKE_DIR/osascript" <<EOF
#!/bin/bash
echo "CALLED" >> "$O1_FAKE_LOG"
exit 0
EOF
chmod +x "$O1_FAKE_DIR/osascript"
PATH="$O1_FAKE_DIR:$PATH" trigger_shutdown "phase-notify O1: WAIO_AUTO_NOTIFY unset" "o1run" "1" "UNIT_TEST" "dest-o1"
sleep 1
assert_eq "O1 osascript never invoked (default behavior unchanged)" "false" "$([ -f "$O1_FAKE_LOG" ] && echo true || echo false)"
./security/recover.sh --confirm "phase-notify O1 cleanup" > /dev/null 2>&1
rm -rf "$O1_FAKE_DIR" "$O1_FAKE_LOG"

echo "[O2] WAIO_AUTO_NOTIFY=1 -- trigger_shutdown fires, osascript IS invoked with the real reason"
O2_FAKE_LOG="$(mktemp /tmp/waio_o2.XXXXXX)"
rm -f "$O2_FAKE_LOG"
O2_FAKE_DIR="$(mktemp -d /tmp/waio_o2dir.XXXXXX)"
cat > "$O2_FAKE_DIR/osascript" <<EOF
#!/bin/bash
echo "MSG=\$WAIO_NOTIFY_MSG" >> "$O2_FAKE_LOG"
exit 0
EOF
chmod +x "$O2_FAKE_DIR/osascript"
PATH="$O2_FAKE_DIR:$PATH" WAIO_AUTO_NOTIFY=1 trigger_shutdown "phase-notify O2: auto-notify reason" "o2run" "1" "UNIT_TEST" "dest-o2"
O2_WAITED=0
while [ ! -f "$O2_FAKE_LOG" ] && [ "$O2_WAITED" -lt 20 ]; do
  sleep 0.1
  O2_WAITED=$((O2_WAITED + 1))
done
O2_LOG_CONTENT="$(cat "$O2_FAKE_LOG" 2>/dev/null || true)"
assert_eq "O2 osascript invoked (opt-in fired)" "true" "$([ -f "$O2_FAKE_LOG" ] && echo true || echo false)"
assert_contains "O2 correct reason reached the notifier" "$O2_LOG_CONTENT" "auto-notify reason"
./security/recover.sh --confirm "phase-notify O2 cleanup" > /dev/null 2>&1
rm -rf "$O2_FAKE_DIR" "$O2_FAKE_LOG"

echo "[O3] WAIO_AUTO_NOTIFY=1 does not alter trigger_shutdown()'s own callers' contract (egress_check's exit code/denial behavior unchanged)"
O3_FAKE_DIR="$(mktemp -d /tmp/waio_o3dir.XXXXXX)"
cat > "$O3_FAKE_DIR/osascript" <<'EOF'
#!/bin/bash
exit 0
EOF
chmod +x "$O3_FAKE_DIR/osascript"
O3_RC="$(PATH="$O3_FAKE_DIR:$PATH" WAIO_AUTO_NOTIFY=1 bash -c 'source security/lib.sh; egress_check "203.0.113.77" "9999" "o3run" "1" "UNIT_TEST"; echo $?' | tail -1)"
assert_eq "O3 egress_check still denies exactly as before (exit 1)" "1" "$O3_RC"
assert_eq "O3 shutdown still tripped as before" "true" "$(is_shutdown_active && echo true || echo false)"
./security/recover.sh --confirm "phase-notify O3 cleanup" > /dev/null 2>&1
rm -rf "$O3_FAKE_DIR"
unset WAIO_AUTO_NOTIFY

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

echo "[L3] HEALTHCHECK (real dispatch through Takomachi's GET /health, no LLM cost) -- independent of LAN_AVAILABLE above, gated on Keychain/Takomachi instead"
OUT_L3="$(./waio.sh -w HEALTHCHECK "status check" 2>&1)"; RC_L3=$?
case "$OUT_L3" in
  *"could not retrieve TAKOMACHI_API_KEY"*)
    skip_case "L3 HEALTHCHECK real dispatch" "Keychain credential not retrievable in this execution context"
    ;;
  *"egress denied by DLP guard"*)
    skip_case "L3 HEALTHCHECK real dispatch" "localhost:3000 not in this deployment's egress_allowlist.conf"
    ;;
  *"GET /health failed"*)
    skip_case "L3 HEALTHCHECK real dispatch" "Takomachi not reachable/responding on localhost:3000"
    ;;
  *)
    assert_eq "L3 exit code" "0" "$RC_L3"
    assert_contains "L3 completed" "$OUT_L3" "HEALTHCHECK WORKER] completed"
    ;;
esac

echo
echo "=== Red Team Phase 2: Guardian channel real-SSH verification (LAN-dependent, reuses LAN_AVAILABLE above -- the existing production waio_guardian key/authorized_keys entry is exercised, never modified) ==="
if [ "$LAN_AVAILABLE" != "true" ]; then
  skip_case "N1 Guardian real SSH auth" "no LAN access to 800号機 ($HOST800_IP:22)"
  skip_case "N2 forced-command containment (injection) over real SSH" "no LAN access to 800号機 ($HOST800_IP:22)"
  skip_case "N3 no-port-forwarding over real SSH" "no LAN access to 800号機 ($HOST800_IP:22)"
  skip_case "N4 no-pty over real SSH" "no LAN access to 800号機 ($HOST800_IP:22)"
else
  echo "[N1] Guardian real SSH auth: a real test shutdown, cleared via 800号機's deployed guardian_recover_trigger.sh over a real SSH hop"
  trigger_shutdown "redteam phase2 N1: real Guardian SSH auth verification" "redteam-n1" "1" "REDTEAM" "dest-n1"
  OUT_N1="$(ssh -o BatchMode=yes -o ConnectTimeout=5 "masa@$HOST800_IP" 'GUARDIAN_TARGET_HOST=192.168.1.116 GUARDIAN_TARGET_USER=masa ~/guardian_recover_trigger.sh "redteam phase2 N1 verification"' 2>&1)"; RC_N1=$?
  assert_eq "N1 exit code" "0" "$RC_N1"
  assert_eq "N1 shutdown cleared" "false" "$(is_shutdown_active && echo true || echo false)"
  AUDIT_CONTENT_N1="$(tail -1 "$SECURITY_AUDIT_LOG")"
  assert_contains "N1 audit log records guardian actor" "$AUDIT_CONTENT_N1" "recovery_confirmed_guardian"

  echo "[N2] forced-command containment: an injection-shaped reason sent over real SSH never executes on 750"
  trigger_shutdown "redteam phase2 N2: forced-command injection over real SSH" "redteam-n2" "1" "REDTEAM" "dest-n2"
  N2_MARKER="/tmp/redteam_phase2_n2_pwned_$$"
  rm -f "$N2_MARKER" 2>/dev/null
  N2_INJECT="redteam phase2 N2 injection \`touch $N2_MARKER\` \$(touch $N2_MARKER) ; touch $N2_MARKER ; echo pwned"
  OUT_N2="$(ssh -o BatchMode=yes -o ConnectTimeout=5 "masa@$HOST800_IP" "ssh -i ~/.ssh/waio_guardian -o BatchMode=yes -o ConnectTimeout=5 masa@192.168.1.116 '$N2_INJECT'" 2>&1)"; RC_N2=$?
  assert_eq "N2 exit code" "0" "$RC_N2"
  assert_eq "N2 shutdown cleared" "false" "$(is_shutdown_active && echo true || echo false)"
  assert_eq "N2 no command executed on 750 (marker file absent)" "false" "$([ -e "$N2_MARKER" ] && echo true || echo false)"
  assert_contains "N2 injection text recorded literally" "$OUT_N2" "injection"
  rm -f "$N2_MARKER" 2>/dev/null

  echo "[N3] no-port-forwarding: a real port-forward attempt over the Guardian key is rejected by sshd (the local listener always opens -- client-side plumbing -- so the tunnel must actually be used once to trigger sshd's channel-open rejection)"
  OUT_N3="$(ssh -o BatchMode=yes -o ConnectTimeout=5 "masa@$HOST800_IP" '
LOG=/tmp/redteam_phase2_n3.log
rm -f "$LOG"
ssh -i ~/.ssh/waio_guardian -o BatchMode=yes -o ConnectTimeout=5 -N -L 12346:127.0.0.1:22 masa@192.168.1.116 > "$LOG" 2>&1 &
SSHPID=$!
sleep 2
nc -zv -w3 127.0.0.1 12346 2>&1
sleep 1
kill $SSHPID 2>/dev/null
wait $SSHPID 2>/dev/null
cat "$LOG"
rm -f "$LOG"
' 2>&1)"
  assert_contains "N3 port-forward administratively prohibited" "$OUT_N3" "administratively prohibited"

  echo "[N4] no-pty: a real -tt PTY request over the Guardian key fails closed (connection aborts, wrapper never runs)"
  OUT_N4="$(ssh -o BatchMode=yes -o ConnectTimeout=5 "masa@$HOST800_IP" 'ssh -tt -i ~/.ssh/waio_guardian -o BatchMode=yes -o ConnectTimeout=5 masa@192.168.1.116 "redteam phase2 N4 pty-probe" 2>&1'; echo "RC=$?")"
  assert_contains "N4 PTY allocation request failed" "$OUT_N4" "PTY allocation request failed"
  assert_contains "N4 ssh exit non-zero (connection aborted, not silently degraded)" "$OUT_N4" "RC=255"
  assert_eq "N4 no shutdown state change (wrapper never reached)" "false" "$(is_shutdown_active && echo true || echo false)"
fi

if [ "$CREATED_ALLOWLIST_FOR_TEST" = "true" ]; then
  rm -f "$ALLOWLIST_PATH_FOR_SETUP"
  echo "NOTE: removed the test-only synthesized security/egress_allowlist.conf -- checkout left exactly as it was found."
fi

echo
echo "=== Phase 40-D: .example template format stays valid over time (Phase 30's noted gap) ==="
echo "(Read-only against the three tracked .example files -- the real, gitignored files they template are never touched.)"

echo "[I1] workers/750.json.example is valid JSON"
I1_ERR="$(python3 -c 'import json; json.load(open("workers/750.json.example"))' 2>&1)"; RC_I1=$?
assert_eq "I1 valid JSON" "0" "$RC_I1"

echo "[I2] workers/800.json.example is valid JSON with non-empty host/user (the keys real code -- host800_worker.sh, jobs/*.sh -- actually reads)"
I2_HOST="$(python3 -c 'import json; print(json.load(open("workers/800.json.example"))["host"])' 2>/dev/null)"; RC_I2_HOST=$?
I2_USER="$(python3 -c 'import json; print(json.load(open("workers/800.json.example"))["user"])' 2>/dev/null)"; RC_I2_USER=$?
assert_eq "I2 host key present and parseable" "0" "$RC_I2_HOST"
assert_eq "I2 host non-empty" "false" "$([ -z "$I2_HOST" ] && echo true || echo false)"
assert_eq "I2 user key present and parseable" "0" "$RC_I2_USER"
assert_eq "I2 user non-empty" "false" "$([ -z "$I2_USER" ] && echo true || echo false)"

echo "[I3] security/egress_allowlist.conf.example: every non-comment/non-blank line has a non-empty HOST and PORT (egress_check()'s own parsing contract, security/lib.sh)"
I3_BAD_LINES=0
while IFS='|' read -r a_host a_port a_label; do
  case "$a_host" in ""|\#*) continue ;; esac
  if [ -z "$a_host" ] || [ -z "$a_port" ]; then
    I3_BAD_LINES=$((I3_BAD_LINES + 1))
  fi
done < security/egress_allowlist.conf.example
assert_eq "I3 no malformed HOST|PORT|LABEL lines" "0" "$I3_BAD_LINES"

echo
echo "=== Summary: $PASS passed, $FAIL failed, $SKIP skipped ==="
if [ "$FAIL" -gt 0 ]; then
  echo "Failures:"
  for f in "${FAILURES[@]}"; do echo "  - $f"; done
  exit 1
fi
exit 0
