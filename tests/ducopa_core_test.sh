#!/bin/bash
set -uo pipefail

# tests/ducopa_core_test.sh -- regression suite for the standalone DuCoPA
# core state machine, security/ducopa.sh.
#
# Unlike tests/ducopa_guardian_test.sh (which exercises
# security/guardian.sh and its wiring into waio.sh/security/lib.sh/
# security/recover.sh), this suite sources ONLY security/ducopa.sh --
# never security/lib.sh, never waio.sh -- to prove the two are actually
# decoupled, not just decoupled by convention. D0 below asserts that
# structurally (greps security/ducopa.sh itself for any reference to the
# real production shutdown/recovery machinery). Every other case runs
# against scratch fixtures via WAIO_DUCOPA_STATE_FILE/
# WAIO_DUCOPA_AUDIT_LOG -- this deployment's real
# security/state/DUCOPA_STATE and security/state/ducopa/audit.jsonl are
# never read or written by this suite. No SSH/network call of any kind.

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
  local n
  n="$(grep -c "\"event_type\": \"$2\"" "$1" 2>/dev/null)"
  echo "${n:-0}"
}

FIXTURE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/waio-ducopa-core-test.XXXXXX")"
trap 'rm -rf "$FIXTURE_DIR"' EXIT

fixture_reset() {
  local suffix="${1:-default}"
  export WAIO_DUCOPA_STATE_FILE="$FIXTURE_DIR/DUCOPA_STATE-$suffix"
  export WAIO_DUCOPA_AUDIT_LOG="$FIXTURE_DIR/audit-$suffix.jsonl"
  rm -f "$WAIO_DUCOPA_STATE_FILE" "$WAIO_DUCOPA_AUDIT_LOG"
}

# ducopa_call FUNC [ARGS...] -- invokes one ducopa_* function in a fresh
# subshell against the currently-exported fixture paths, sourcing ONLY
# security/ducopa.sh (never security/lib.sh).
ducopa_call() {
  bash -c 'source security/ducopa.sh; "$@"' _ "$@"
}

echo "=== D0: structural decoupling -- security/ducopa.sh references none of the real production machinery ==="

for forbidden in "trigger_shutdown" "SHUTDOWN_LOCK" "security/lib.sh" "recover.sh" "waio.sh" "guardian.sh"; do
  if grep -q -- "$forbidden" security/ducopa.sh; then
    FAIL=$((FAIL + 1)); FAILURES+=("D0 must not reference '$forbidden'")
    echo "  FAIL: D0 security/ducopa.sh must not reference '$forbidden'"
  else
    PASS=$((PASS + 1)); echo "  PASS: D0 security/ducopa.sh does not reference '$forbidden'"
  fi
done

echo "[D0b] security/ducopa.sh is not sourced by security/lib.sh, waio.sh, security/recover.sh, or security/guardian.sh"
for f in security/lib.sh waio.sh security/recover.sh security/guardian.sh security/guardian_approve.sh; do
  if grep -q "ducopa" "$f"; then
    FAIL=$((FAIL + 1)); FAILURES+=("D0b $f must not reference ducopa")
    echo "  FAIL: D0b $f must not reference ducopa"
  else
    PASS=$((PASS + 1)); echo "  PASS: D0b $f does not reference ducopa"
  fi
done

echo "[D0c] the real production SHUTDOWN.lock is untouched by sourcing/using security/ducopa.sh"
REAL_LOCK_BEFORE=""
[ -f security/state/SHUTDOWN.lock ] && REAL_LOCK_BEFORE="$(cat security/state/SHUTDOWN.lock)"
fixture_reset "d0c"
ducopa_call ducopa_notify_event "d0c probe" "shutdown" "must never touch the real lock" "tester" >/dev/null
REAL_LOCK_AFTER=""
[ -f security/state/SHUTDOWN.lock ] && REAL_LOCK_AFTER="$(cat security/state/SHUTDOWN.lock)"
assert_eq "D0c real SHUTDOWN.lock content unchanged" "$REAL_LOCK_BEFORE" "$REAL_LOCK_AFTER"

echo "=== State machine basics ==="

echo "[D1] ranks: NORMAL=0 WARNING=1 BLOCKED=2 HUMAN_APPROVAL_REQUIRED=3 SHUTDOWN=4"
assert_eq "D1 NORMAL rank" "0" "$(ducopa_call ducopa_state_rank NORMAL)"
assert_eq "D1 WARNING rank" "1" "$(ducopa_call ducopa_state_rank WARNING)"
assert_eq "D1 BLOCKED rank" "2" "$(ducopa_call ducopa_state_rank BLOCKED)"
assert_eq "D1 HUMAN_APPROVAL_REQUIRED rank" "3" "$(ducopa_call ducopa_state_rank HUMAN_APPROVAL_REQUIRED)"
assert_eq "D1 SHUTDOWN rank" "4" "$(ducopa_call ducopa_state_rank SHUTDOWN)"
assert_eq "D1 unknown state rank is -1" "-1" "$(ducopa_call ducopa_state_rank BOGUS)"

echo "[D2] default state (no file yet) is NORMAL"
fixture_reset "d2"
assert_eq "D2 default state" "NORMAL" "$(ducopa_call ducopa_get_state)"

echo "[D3] ducopa_set_state rejects an unknown state, leaves state unchanged, exit 1"
fixture_reset "d3"
OUT_D3="$(ducopa_call ducopa_set_state "NOT_A_REAL_STATE" "bogus" "tester" 2>&1)"; RC_D3=$?
assert_eq "D3 rejected, exit 1" "1" "$RC_D3"
assert_eq "D3 state unchanged" "NORMAL" "$(ducopa_call ducopa_get_state)"

echo "[D4] a corrupted state file is read as BLOCKED (fail closed), not NORMAL"
fixture_reset "d4"
printf 'GARBAGE\n' > "$WAIO_DUCOPA_STATE_FILE"
assert_eq "D4 corrupted file -> BLOCKED" "BLOCKED" "$(ducopa_call ducopa_get_state 2>/dev/null)"

echo "[D5] an empty state file reads as NORMAL (not corrupted, just untouched)"
fixture_reset "d5"
: > "$WAIO_DUCOPA_STATE_FILE"
assert_eq "D5 empty file -> NORMAL" "NORMAL" "$(ducopa_call ducopa_get_state)"

echo "[D6] valid explicit transition through all 5 states persists and is audited"
fixture_reset "d6"
for s in WARNING BLOCKED HUMAN_APPROVAL_REQUIRED SHUTDOWN NORMAL; do
  ducopa_call ducopa_set_state "$s" "d6 exercising $s" "tester" >/dev/null
  assert_eq "D6 state is now $s" "$s" "$(ducopa_call ducopa_get_state)"
done
assert_eq "D6 five ducopa_state_changed events logged" "5" "$(count_events "$WAIO_DUCOPA_AUDIT_LOG" "ducopa_state_changed")"

echo "=== ducopa_is_blocking ==="

echo "[D7] NORMAL and WARNING do not block; BLOCKED/HUMAN_APPROVAL_REQUIRED/SHUTDOWN do"
fixture_reset "d7"
for s in NORMAL WARNING; do
  ducopa_call ducopa_set_state "$s" "d7 $s" "tester" >/dev/null
  assert_eq "D7 $s is_blocking=false" "false" "$(ducopa_call ducopa_is_blocking >/dev/null 2>&1 && echo true || echo false)"
done
for s in BLOCKED HUMAN_APPROVAL_REQUIRED SHUTDOWN; do
  ducopa_call ducopa_set_state "$s" "d7 $s" "tester" >/dev/null
  assert_eq "D7 $s is_blocking=true" "true" "$(ducopa_call ducopa_is_blocking >/dev/null 2>&1 && echo true || echo false)"
done

echo "=== ducopa_notify_event: severity escalation, never downgrades ==="

echo "[D8] info severity logs but never changes state"
fixture_reset "d8"
ducopa_call ducopa_notify_event "noteworthy_thing" "info" "just fyi" "tester" >/dev/null
assert_eq "D8 state stays NORMAL" "NORMAL" "$(ducopa_call ducopa_get_state)"
assert_eq "D8 event logged" "1" "$(count_events "$WAIO_DUCOPA_AUDIT_LOG" "ducopa_event_notified")"

echo "[D9] warning severity escalates NORMAL -> WARNING"
fixture_reset "d9"
ducopa_call ducopa_notify_event "odd_pattern" "warning" "elevated activity" "tester" >/dev/null
assert_eq "D9 escalated to WARNING" "WARNING" "$(ducopa_call ducopa_get_state)"

echo "[D10] critical severity escalates NORMAL -> BLOCKED"
fixture_reset "d10"
ducopa_call ducopa_notify_event "policy_violation" "critical" "dangerous op attempted" "tester" >/dev/null
assert_eq "D10 escalated to BLOCKED" "BLOCKED" "$(ducopa_call ducopa_get_state)"

echo "[D11] shutdown severity escalates NORMAL -> SHUTDOWN (locally only, see D0c)"
fixture_reset "d11"
ducopa_call ducopa_notify_event "critical_anomaly" "shutdown" "stop everything" "tester" >/dev/null
assert_eq "D11 escalated to SHUTDOWN" "SHUTDOWN" "$(ducopa_call ducopa_get_state)"

echo "[D12] escalation never downgrades an already-more-severe state"
fixture_reset "d12"
ducopa_call ducopa_set_state "BLOCKED" "already blocked" "tester" >/dev/null
ducopa_call ducopa_notify_event "minor_thing" "warning" "should not downgrade" "tester" >/dev/null
assert_eq "D12 stays BLOCKED, not downgraded to WARNING" "BLOCKED" "$(ducopa_call ducopa_get_state)"

echo "[D13] a second, equally-severe or lower event never re-logs a redundant state change"
fixture_reset "d13"
ducopa_call ducopa_set_state "BLOCKED" "first" "tester" >/dev/null
ducopa_call ducopa_notify_event "same_severity_again" "critical" "should not add a new state_changed" "tester" >/dev/null
assert_eq "D13 still BLOCKED" "BLOCKED" "$(ducopa_call ducopa_get_state)"
assert_eq "D13 only 1 state_changed event (the initial set_state)" "1" "$(count_events "$WAIO_DUCOPA_AUDIT_LOG" "ducopa_state_changed")"

echo "=== Human approval gate ==="

echo "[D14] ducopa_require_human_approval transitions to HUMAN_APPROVAL_REQUIRED"
fixture_reset "d14"
ducopa_call ducopa_require_human_approval "needs a human" "tester" >/dev/null
assert_eq "D14 state HUMAN_APPROVAL_REQUIRED" "HUMAN_APPROVAL_REQUIRED" "$(ducopa_call ducopa_get_state)"

echo "[D15] ducopa_approve refuses without a reason, state unchanged"
fixture_reset "d15"
ducopa_call ducopa_set_state "HUMAN_APPROVAL_REQUIRED" "needs a human" "tester" >/dev/null
OUT_D15="$(ducopa_call ducopa_approve "" "operator" 2>&1)"; RC_D15=$?
assert_eq "D15 rejected empty reason, exit 1" "1" "$RC_D15"
assert_eq "D15 state unchanged" "HUMAN_APPROVAL_REQUIRED" "$(ducopa_call ducopa_get_state)"

echo "[D16] ducopa_approve clears HUMAN_APPROVAL_REQUIRED -> NORMAL with a reason, and is audited"
fixture_reset "d16"
ducopa_call ducopa_set_state "HUMAN_APPROVAL_REQUIRED" "needs a human" "tester" >/dev/null
OUT_D16="$(ducopa_call ducopa_approve "investigated, confirmed safe to resume" "operator" 2>&1)"; RC_D16=$?
assert_eq "D16 exit 0" "0" "$RC_D16"
assert_eq "D16 state NORMAL" "NORMAL" "$(ducopa_call ducopa_get_state)"
assert_eq "D16 approval_granted event logged" "1" "$(count_events "$WAIO_DUCOPA_AUDIT_LOG" "ducopa_approval_granted")"

echo "[D17] ducopa_approve also clears SHUTDOWN -> NORMAL (this module's own local mirror; no real recover.sh involved)"
fixture_reset "d17"
ducopa_call ducopa_set_state "SHUTDOWN" "local shutdown mirror" "tester" >/dev/null
OUT_D17="$(ducopa_call ducopa_approve "investigated the local mirror, confirmed safe" "operator" 2>&1)"; RC_D17=$?
assert_eq "D17 exit 0" "0" "$RC_D17"
assert_eq "D17 state NORMAL" "NORMAL" "$(ducopa_call ducopa_get_state)"

echo "[D18] ducopa_approve on an already-NORMAL state is a no-op, exit 0"
fixture_reset "d18"
OUT_D18="$(ducopa_call ducopa_approve "should be a no-op" "operator" 2>&1)"; RC_D18=$?
assert_eq "D18 exit 0" "0" "$RC_D18"
assert_contains "D18 already-normal message" "$OUT_D18" "Already NORMAL"

echo "[D19] ducopa_approve refuses without a reason even from BLOCKED (not just HUMAN_APPROVAL_REQUIRED)"
fixture_reset "d19"
ducopa_call ducopa_set_state "BLOCKED" "some incident" "tester" >/dev/null
OUT_D19="$(ducopa_call ducopa_approve "" "operator" 2>&1)"; RC_D19=$?
assert_eq "D19 rejected, exit 1" "1" "$RC_D19"
assert_eq "D19 state still BLOCKED" "BLOCKED" "$(ducopa_call ducopa_get_state)"

echo "=== Summary ==="
echo "PASS=$PASS FAIL=$FAIL"
if [ "$FAIL" -gt 0 ]; then
  echo "Failures:"
  for f in "${FAILURES[@]}"; do echo "  - $f"; done
  exit 1
fi
exit 0
