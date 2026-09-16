#!/bin/bash
set -uo pipefail

# tests/recovery_hardening_test.sh -- regression suite for the
# recovery-hardening work (2026-09-13): security/recover.sh's minimum
# reason-strength validation, security/lib.sh's audit_log() actor
# attribution, and the _reconcile_recovery_audit() bypass-detection
# check wired into waio.sh and security/recover.sh.
#
# Everything here runs against scratch fixtures via
# WAIO_SHUTDOWN_LOCK/WAIO_AUDIT_LOG/WAIO_RECOVER_RECONCILE_MARKER
# overrides (security/lib.sh) -- this suite never reads or writes this
# deployment's real security/state/SHUTDOWN.lock,
# logs/security-audit.jsonl, or security/state/.last_reconciled_trigger,
# and makes no SSH/network call of any kind (every shutdown here is a
# purely local dummy trip against a fixture lock file, exactly like
# tests/security_test.sh's own U1/U5-U7 unit-level cases). Safe to run
# in CI or on a machine with real LAN access alike.

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

count_events() {
  # count_events LOGFILE EVENT_TYPE -- grep -c prints "0" (exit 1, not
  # an error) for a legitimate zero-match count, so a bare `|| echo 0`
  # fallback would print an EXTRA spurious "0" on top of grep's own
  # correct "0" in that exact case; capture-then-default avoids it.
  local n
  n="$(grep -c "\"event_type\": \"$2\"" "$1" 2>/dev/null)"
  echo "${n:-0}"
}

# Explicit XXXXXX template (not `mktemp -d -t prefix`): GNU mktemp
# (Linux CI) and BSD/macOS mktemp disagree on `-t` with no XXXXXX in the
# template -- see tests/segment_recovery_test.sh's own header for the
# same note.
FIXTURE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/waio-recovery-hardening-test.XXXXXX")"
trap 'rm -rf "$FIXTURE_DIR"' EXIT

fixture_reset() {
  # fixture_reset [SUFFIX] -- points every override at a fresh set of
  # scratch paths (one bare `rm -f` per file is not enough on its own:
  # a distinct filename per scenario keeps unrelated cases from ever
  # sharing a marker/lock/log, so a bug in one can't masquerade as a
  # pass/fail in another).
  local suffix="${1:-default}"
  export WAIO_AUDIT_LOG="$FIXTURE_DIR/audit-$suffix.jsonl"
  export WAIO_SHUTDOWN_LOCK="$FIXTURE_DIR/SHUTDOWN-$suffix.lock"
  export WAIO_RECOVER_RECONCILE_MARKER="$FIXTURE_DIR/marker-$suffix"
  # Audit-log tamper-evidence state (added alongside audit_log()'s hash
  # chaining, 2026-09-13): without these three overrides too,
  # audit_log() falls back to this deployment's REAL
  # security/state/.audit_log_chain_checkpoint et al -- caught during
  # implementation when exactly that happened and left stray files
  # there (cleaned up manually; this fixture_reset fix is what
  # prevents a recurrence).
  export WAIO_AUDIT_LOG_CHECKPOINT="$FIXTURE_DIR/checkpoint-$suffix"
  export WAIO_AUDIT_INTEGRITY_ALERTS="$FIXTURE_DIR/alerts-$suffix.jsonl"
  export WAIO_AUDIT_LOG_LOCK_DIR="$FIXTURE_DIR/lock-$suffix"
  rm -rf "$WAIO_AUDIT_LOG" "$WAIO_SHUTDOWN_LOCK" "$WAIO_RECOVER_RECONCILE_MARKER" \
    "$WAIO_AUDIT_LOG_CHECKPOINT" "$WAIO_AUDIT_INTEGRITY_ALERTS" "$WAIO_AUDIT_LOG_LOCK_DIR"
}

trip() {
  # trip REASON RUN_ID WORKER DEST -- a purely local dummy shutdown
  # against the currently-exported fixture lock/audit paths. No network
  # call of any kind (same shape as security/lib.sh's own trigger_shutdown
  # unit-tested directly in tests/security_test.sh's Phase 24 section).
  bash -c 'source security/lib.sh; trigger_shutdown "$1" "$2" "1" "$3" "$4"' _ "$1" "$2" "$3" "$4"
}

echo "=== Reason-strength validation (security/recover.sh) ==="

echo "[RH1] too-short reason is refused, lock remains active"
fixture_reset "rh1"
trip "dummy trip RH1" "rh1run" "RH1WORKER" "rh1dest"
OUT="$(./security/recover.sh --confirm "short" 2>&1)"; RC=$?
assert_eq "RH1 exit code" "1" "$RC"
assert_contains "RH1 error mentions minimum length" "$OUT" "minimum is 20"
assert_eq "RH1 lock still present" "true" "$([ -f "$WAIO_SHUTDOWN_LOCK" ] && echo true || echo false)"

echo "[RH2] whitespace-only reason is refused (empty after trim)"
OUT="$(./security/recover.sh --confirm "                    " 2>&1)"; RC=$?
assert_eq "RH2 exit code" "1" "$RC"
assert_contains "RH2 error mentions empty-after-trim" "$OUT" "empty after trimming"

echo "[RH3] long but low-entropy (padding) reason is refused"
OUT="$(./security/recover.sh --confirm "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" 2>&1)"; RC=$?
assert_eq "RH3 exit code" "1" "$RC"
assert_contains "RH3 error mentions too little variety" "$OUT" "too little variety"
assert_eq "RH3 lock still present" "true" "$([ -f "$WAIO_SHUTDOWN_LOCK" ] && echo true || echo false)"

echo "[RH4] a sufficiently descriptive reason succeeds"
OUT="$(./security/recover.sh --confirm "investigated the dummy trip, confirmed safe to resume" 2>&1)"; RC=$?
assert_eq "RH4 exit code" "0" "$RC"
assert_eq "RH4 lock cleared" "false" "$([ -f "$WAIO_SHUTDOWN_LOCK" ] && echo true || echo false)"

echo "[RH5] exact 20-char/high-variety boundary is accepted (regression lock-in against this repo's own shortest pre-existing cleanup reason, tests/security_test.sh's 'phase40b1 K2 cleanup')"
fixture_reset "rh5"
trip "dummy trip RH5" "rh5run" "RH5WORKER" "rh5dest"
OUT="$(./security/recover.sh --confirm "phase40b1 K2 cleanup" 2>&1)"; RC=$?
assert_eq "RH5 exit code" "0" "$RC"

echo "[RH6] leading/trailing whitespace is trimmed before validation, and the TRIMMED value is what's audited"
fixture_reset "rh6"
trip "dummy trip RH6" "rh6run" "RH6WORKER" "rh6dest"
OUT="$(./security/recover.sh --confirm "   investigated: safe to resume now   " 2>&1)"; RC=$?
assert_eq "RH6 exit code" "0" "$RC"
assert_contains "RH6 audit reason has no leading/trailing spaces" "$(tail -1 "$WAIO_AUDIT_LOG")" '"reason": "investigated: safe to resume now"'

echo "[RH7] the same validation applies to --guardian-confirm"
fixture_reset "rh7"
trip "dummy trip RH7" "rh7run" "RH7WORKER" "rh7dest"
OUT="$(./security/recover.sh --guardian-confirm "short" 2>&1)"; RC=$?
assert_eq "RH7a exit code (short reason refused)" "1" "$RC"
assert_contains "RH7a error mentions minimum length" "$OUT" "minimum is 20"
OUT="$(./security/recover.sh --guardian-confirm "long enough guardian reason text" 2>&1)"; RC=$?
assert_eq "RH7b exit code (valid reason succeeds)" "0" "$RC"

echo "[RH8] Japanese reason with no spaces is accepted (regression for the multi-byte-length locale bug found and fixed during implementation -- see the python3 UTF-8 decode note in security/recover.sh)"
fixture_reset "rh8"
trip "dummy trip RH8" "rh8run" "RH8WORKER" "rh8dest"
OUT="$(./security/recover.sh --confirm "800号機の到達性を確認し復旧を確認したため解除する" 2>&1)"; RC=$?
assert_eq "RH8 exit code" "0" "$RC"

echo "[RH9] the same check is correct even under an empty/C locale (the exact condition that exposed the RH8 bug during implementation)"
fixture_reset "rh9"
trip "dummy trip RH9" "rh9run" "RH9WORKER" "rh9dest"
OUT="$(LC_ALL=C LANG=C ./security/recover.sh --confirm "800号機の到達性を確認し復旧を確認したため解除する" 2>&1)"; RC=$?
assert_eq "RH9 exit code (LC_ALL=C/LANG=C)" "0" "$RC"

echo "[RH10] WAIO_RECOVER_MIN_REASON_LENGTH / _DISTINCT_CHARS overrides are honored"
fixture_reset "rh10"
trip "dummy trip RH10" "rh10run" "RH10WORKER" "rh10dest"
OUT="$(WAIO_RECOVER_MIN_REASON_LENGTH=5 WAIO_RECOVER_MIN_REASON_DISTINCT_CHARS=4 ./security/recover.sh --confirm "abcdef" 2>&1)"; RC=$?
assert_eq "RH10 exit code" "0" "$RC"

echo "[RH11] no active shutdown -> unaffected, still 'nothing to do' regardless of reason strength"
fixture_reset "rh11"
OUT="$(./security/recover.sh --confirm "short" 2>&1)"; RC=$?
assert_eq "RH11 exit code" "0" "$RC"
assert_contains "RH11 nothing-to-do message" "$OUT" "Nothing to do"

echo
echo "=== Actor attribution (security/lib.sh's audit_log()) ==="

echo "[RH12] a recovery event records actor_user/actor_uid/actor_tty/actor_ssh_connection"
fixture_reset "rh12"
trip "dummy trip RH12" "rh12run" "RH12WORKER" "rh12dest"
./security/recover.sh --confirm "investigated RH12 and confirmed safe to resume" >/dev/null 2>&1
LAST_LINE="$(tail -1 "$WAIO_AUDIT_LOG")"
EXPECT_USER="$(id -un 2>/dev/null)"
EXPECT_UID="$(id -u 2>/dev/null)"
assert_contains "RH12 actor_user matches current OS user" "$LAST_LINE" "\"actor_user\": \"$EXPECT_USER\""
assert_contains "RH12 actor_uid matches current OS uid" "$LAST_LINE" "\"actor_uid\": \"$EXPECT_UID\""
assert_contains "RH12 actor_tty key present" "$LAST_LINE" "\"actor_tty\":"
assert_contains "RH12 actor_ssh_connection key present" "$LAST_LINE" "\"actor_ssh_connection\":"

echo "[RH13] actor_ssh_connection is null with no SSH_CONNECTION in the environment"
fixture_reset "rh13"
trip "dummy trip RH13" "rh13run" "RH13WORKER" "rh13dest"
OUT="$(env -u SSH_CONNECTION bash -c './security/recover.sh --confirm "investigated RH13 and confirmed safe to resume"' 2>&1)"
assert_contains "RH13 recover succeeded" "$OUT" "Shutdown cleared"
assert_contains "RH13 actor_ssh_connection is null" "$(tail -1 "$WAIO_AUDIT_LOG")" "\"actor_ssh_connection\": null"

echo "[RH14] actor_ssh_connection reflects a real SSH_CONNECTION value when one is set (env var only -- no real SSH performed)"
fixture_reset "rh14"
trip "dummy trip RH14" "rh14run" "RH14WORKER" "rh14dest"
SSH_CONNECTION="203.0.113.9 1234 203.0.113.10 22" ./security/recover.sh --confirm "investigated RH14 and confirmed safe to resume" >/dev/null 2>&1
assert_contains "RH14 actor_ssh_connection reflects the env var" "$(tail -1 "$WAIO_AUDIT_LOG")" "\"actor_ssh_connection\": \"203.0.113.9 1234 203.0.113.10 22\""

echo "[RH15] actor attribution also lands on non-recovery audit events (egress_denied), since it is added inside audit_log() itself, not per call site"
fixture_reset "rh15"
OUT="$(bash -c 'source security/lib.sh; egress_check "203.0.113.55" "9999" "rh15run" "1" "RH15WORKER"' 2>&1)"
assert_contains "RH15 actor_user present on a non-recovery event" "$(tail -1 "$WAIO_AUDIT_LOG")" "\"actor_user\": \"$EXPECT_USER\""
./security/recover.sh --confirm "investigated RH15 and confirmed safe to resume" >/dev/null 2>&1

echo
echo "=== Bypass detection (_reconcile_recovery_audit, wired into waio.sh and security/recover.sh) ==="

echo "[RH16] a SHUTDOWN.lock removed directly (not via recover.sh) is detected by waio.sh's own preamble, without blocking dispatch"
fixture_reset "rh16"
trip "dummy trip for RH16 bypass simulation" "rh16run" "RH16WORKER" "rh16dest"
assert_eq "RH16 precondition: dummy lock exists" "true" "$([ -f "$WAIO_SHUTDOWN_LOCK" ] && echo true || echo false)"
rm -f "$WAIO_SHUTDOWN_LOCK"   # THE BYPASS -- direct deletion, not security/recover.sh
OUT="$(./waio.sh -w ECHO "post-bypass dispatch" 2>&1)"; RC=$?
assert_eq "RH16 dispatch is not blocked (advisory only)" "0" "$RC"
assert_contains "RH16 dispatch still completed normally" "$OUT" "ECHO WORKER] completed"
assert_contains "RH16 stderr warning printed" "$OUT" "possible unaudited recovery detected"
assert_eq "RH16 exactly one shutdown_lock_bypass_suspected event logged" "1" "$(count_events "$WAIO_AUDIT_LOG" shutdown_lock_bypass_suspected)"
assert_contains "RH16 event references the original trigger's run_id" "$(tail -1 "$WAIO_AUDIT_LOG")" "rh16run"

echo "[RH17] a second dispatch does not re-log the same unresolved trigger (dedup via the marker file)"
OUT="$(./waio.sh -w ECHO "second post-bypass dispatch" 2>&1)"; RC=$?
assert_eq "RH17 exit code" "0" "$RC"
assert_eq "RH17 still exactly one bypass event (no duplicate)" "1" "$(count_events "$WAIO_AUDIT_LOG" shutdown_lock_bypass_suspected)"

echo "[RH18] a subsequent, properly-resolved trigger/recover cycle logs no additional bypass event"
trip "second dummy trip, will be resolved properly" "rh18run" "RH18WORKER" "rh18dest"
OUT="$(./security/recover.sh --confirm "investigated the RH18 dummy trip and confirmed safe to resume" 2>&1)"; RC=$?
assert_eq "RH18 recover.sh exit code" "0" "$RC"
assert_eq "RH18 still exactly one bypass event total" "1" "$(count_events "$WAIO_AUDIT_LOG" shutdown_lock_bypass_suspected)"

echo "[RH19] security/recover.sh's own entry point detects the same class of bypass"
fixture_reset "rh19"
trip "dummy trip for RH19 bypass simulation" "rh19run" "RH19WORKER" "rh19dest"
rm -f "$WAIO_SHUTDOWN_LOCK"
OUT="$(./security/recover.sh 2>&1)"; RC=$?
assert_eq "RH19 exit code (still 'nothing to do', behavior unchanged)" "0" "$RC"
assert_contains "RH19 nothing-to-do message unchanged" "$OUT" "Nothing to do"
assert_eq "RH19 bypass event logged from recover.sh's own entry point" "1" "$(count_events "$WAIO_AUDIT_LOG" shutdown_lock_bypass_suspected)"

echo "[RH20] a malformed/garbage audit log never aborts dispatch (set -euo pipefail safety)"
fixture_reset "rh20"
printf 'not json at all\n{"event_type": "shutdown_triggered", garbage\n' > "$WAIO_AUDIT_LOG"
OUT="$(./waio.sh -w ECHO "garbage audit log dispatch" 2>&1)"; RC=$?
assert_eq "RH20 exit code (no abort despite malformed audit log)" "0" "$RC"
assert_contains "RH20 dispatch still completed" "$OUT" "ECHO WORKER] completed"

echo "[RH21] a missing audit log entirely never aborts dispatch"
fixture_reset "rh21"
OUT="$(./waio.sh -w ECHO "no audit log at all dispatch" 2>&1)"; RC=$?
assert_eq "RH21 exit code" "0" "$RC"

echo
echo "=== Summary: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
  echo "Failures:"
  for f in "${FAILURES[@]}"; do echo "  - $f"; done
  exit 1
fi
exit 0
