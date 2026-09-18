#!/bin/bash
set -uo pipefail

# tests/ducopa_guardian_test.sh -- regression suite for the DuCoPA (Dual
# Control Plane Architecture) Guardian Control Plane: security/guardian.sh,
# its wiring into waio.sh (new-task block, agent quarantine), the opt-in
# WAIO_AUTO_GUARDIAN_NOTIFY mirror in security/lib.sh's trigger_shutdown,
# security/recover.sh's Guardian-state reset, and security/guardian_approve.sh.
#
# Everything here runs against scratch fixtures via
# WAIO_GUARDIAN_STATE_FILE/WAIO_GUARDIAN_QUARANTINE_FILE/WAIO_SHUTDOWN_LOCK/
# WAIO_AUDIT_LOG (and the audit-log-integrity/reconciliation overrides
# security/lib.sh already supports) -- same test-isolation pattern as
# tests/recovery_hardening_test.sh. This suite never reads or writes this
# deployment's real security/state/GUARDIAN_STATE, GUARDIAN_QUARANTINE, or
# SHUTDOWN.lock, and makes no SSH/network call of any kind.

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

FIXTURE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/waio-ducopa-guardian-test.XXXXXX")"
trap 'rm -rf "$FIXTURE_DIR"; mv -f "$REGISTRY_BACKUP" "$REGISTRY_PATH" 2>/dev/null' EXIT

REGISTRY_PATH="workers/registry.conf"
REGISTRY_BACKUP="$FIXTURE_DIR/registry.conf.orig"
cp "$REGISTRY_PATH" "$REGISTRY_BACKUP"

fixture_reset() {
  # fixture_reset [SUFFIX] -- points every override (DLP + Guardian) at a
  # fresh set of scratch paths. See tests/recovery_hardening_test.sh's own
  # fixture_reset for why a distinct filename per scenario matters.
  local suffix="${1:-default}"
  export WAIO_AUDIT_LOG="$FIXTURE_DIR/audit-$suffix.jsonl"
  export WAIO_SHUTDOWN_LOCK="$FIXTURE_DIR/SHUTDOWN-$suffix.lock"
  export WAIO_RECOVER_RECONCILE_MARKER="$FIXTURE_DIR/marker-$suffix"
  export WAIO_AUDIT_LOG_CHECKPOINT="$FIXTURE_DIR/checkpoint-$suffix"
  export WAIO_AUDIT_INTEGRITY_ALERTS="$FIXTURE_DIR/alerts-$suffix.jsonl"
  export WAIO_AUDIT_LOG_LOCK_DIR="$FIXTURE_DIR/lock-$suffix"
  export WAIO_GUARDIAN_STATE_FILE="$FIXTURE_DIR/GUARDIAN_STATE-$suffix"
  export WAIO_GUARDIAN_QUARANTINE_FILE="$FIXTURE_DIR/GUARDIAN_QUARANTINE-$suffix"
  export WAIO_GUARDIAN_CRITICAL_EVENTS_FILE="$FIXTURE_DIR/GUARDIAN_CRITICAL_EVENTS-$suffix"
  rm -rf "$WAIO_AUDIT_LOG" "$WAIO_SHUTDOWN_LOCK" "$WAIO_RECOVER_RECONCILE_MARKER" \
    "$WAIO_AUDIT_LOG_CHECKPOINT" "$WAIO_AUDIT_INTEGRITY_ALERTS" "$WAIO_AUDIT_LOG_LOCK_DIR" \
    "$WAIO_GUARDIAN_STATE_FILE" "$WAIO_GUARDIAN_QUARANTINE_FILE" "$WAIO_GUARDIAN_CRITICAL_EVENTS_FILE"
}

# guardian_call FUNC [ARGS...] -- invokes one guardian_* (or is_shutdown_active)
# function in a fresh subshell against the currently-exported fixture
# paths, printing its stdout. Mirrors recovery_hardening_test.sh's `trip`.
guardian_call() {
  bash -c 'source security/lib.sh; "$@"' _ "$@"
}

echo "=== State machine basics (security/guardian.sh) ==="

echo "[G1] default state (no file yet) is NORMAL"
fixture_reset "g1"
assert_eq "G1 default state" "NORMAL" "$(guardian_call guardian_get_state)"

echo "[G2] guardian_set_state rejects an unknown state, leaves state unchanged"
fixture_reset "g2"
OUT_G2="$(guardian_call guardian_set_state "NOT_A_REAL_STATE" "bogus" "g2run" "tester" 2>&1)"; RC_G2=$?
assert_eq "G2 rejected, exit 1" "1" "$RC_G2"
assert_eq "G2 state unchanged" "NORMAL" "$(guardian_call guardian_get_state)"

echo "[G3] a corrupted state file is read as BLOCKED (fail closed), not NORMAL"
fixture_reset "g3"
printf 'GARBAGE\n' > "$WAIO_GUARDIAN_STATE_FILE"
assert_eq "G3 corrupted file -> BLOCKED" "BLOCKED" "$(guardian_call guardian_get_state 2>/dev/null)"

echo "[G4] valid explicit transition through all 5 states persists and is audited"
fixture_reset "g4"
for s in WARNING BLOCKED HUMAN_APPROVAL_REQUIRED SHUTDOWN NORMAL; do
  guardian_call guardian_set_state "$s" "g4 exercising $s" "g4run" "tester" >/dev/null
  assert_eq "G4 state is now $s" "$s" "$(guardian_call guardian_get_state)"
done
assert_eq "G4 five guardian_state_changed events logged" "5" "$(count_events "$WAIO_AUDIT_LOG" "guardian_state_changed")"

echo "=== guardian_is_blocking ==="

echo "[G5] NORMAL and WARNING do not block; BLOCKED/HUMAN_APPROVAL_REQUIRED/SHUTDOWN do"
fixture_reset "g5"
for s in NORMAL WARNING; do
  guardian_call guardian_set_state "$s" "g5 $s" "g5run" "tester" >/dev/null
  assert_eq "G5 $s is_blocking=false" "false" "$(guardian_call guardian_is_blocking >/dev/null 2>&1 && echo true || echo false)"
done
for s in BLOCKED HUMAN_APPROVAL_REQUIRED SHUTDOWN; do
  guardian_call guardian_set_state "$s" "g5 $s" "g5run" "tester" >/dev/null
  assert_eq "G5 $s is_blocking=true" "true" "$(guardian_call guardian_is_blocking >/dev/null 2>&1 && echo true || echo false)"
done

echo "=== guardian_notify_event (WAIO -> Guardian interface) ==="

echo "[G6] info severity logs but never changes state"
fixture_reset "g6"
guardian_call guardian_notify_event "noteworthy_thing" "info" "just fyi" "g6run" "someworker" >/dev/null
assert_eq "G6 state stays NORMAL" "NORMAL" "$(guardian_call guardian_get_state)"
assert_eq "G6 event logged" "1" "$(count_events "$WAIO_AUDIT_LOG" "guardian_event_notified")"

echo "[G7] warning severity escalates NORMAL -> WARNING"
fixture_reset "g7"
guardian_call guardian_notify_event "odd_pattern" "warning" "elevated activity" "g7run" "someworker" >/dev/null
assert_eq "G7 escalated to WARNING" "WARNING" "$(guardian_call guardian_get_state)"

echo "[G8] critical severity escalates NORMAL -> BLOCKED"
fixture_reset "g8"
guardian_call guardian_notify_event "policy_violation" "critical" "dangerous op attempted" "g8run" "someworker" >/dev/null
assert_eq "G8 escalated to BLOCKED" "BLOCKED" "$(guardian_call guardian_get_state)"

echo "[G9] escalation never downgrades an already-more-severe state"
fixture_reset "g9"
guardian_call guardian_set_state "BLOCKED" "already blocked" "g9run" "tester" >/dev/null
guardian_call guardian_notify_event "minor_thing" "warning" "should not downgrade" "g9run" "someworker" >/dev/null
assert_eq "G9 stays BLOCKED, not downgraded to WARNING" "BLOCKED" "$(guardian_call guardian_get_state)"

echo "[G10] shutdown severity escalates to SHUTDOWN AND trips the real SHUTDOWN_LOCK"
fixture_reset "g10"
guardian_call guardian_notify_event "critical_anomaly" "shutdown" "stop everything" "g10run" "someworker" >/dev/null
assert_eq "G10 guardian state SHUTDOWN" "SHUTDOWN" "$(guardian_call guardian_get_state)"
assert_eq "G10 real shutdown lock also active" "true" "$(guardian_call is_shutdown_active >/dev/null 2>&1 && echo true || echo false)"

echo "=== guardian_request_waio_shutdown + recover.sh integration ==="

echo "[G11] guardian_request_waio_shutdown sets SHUTDOWN and trips the real lock"
fixture_reset "g11"
guardian_call guardian_request_waio_shutdown "guardian decided to stop WAIO" "g11run" "guardian-test" "someworker" "n/a" >/dev/null
assert_eq "G11 guardian state SHUTDOWN" "SHUTDOWN" "$(guardian_call guardian_get_state)"
assert_eq "G11 real lock active" "true" "$([ -f "$WAIO_SHUTDOWN_LOCK" ] && echo true || echo false)"

echo "[G12] security/recover.sh --confirm clears BOTH the real lock and the Guardian SHUTDOWN mirror"
OUT_G12="$(./security/recover.sh --confirm "G12: investigated the guardian-triggered stop, safe to resume" 2>&1)"; RC_G12=$?
assert_eq "G12 recover exit 0" "0" "$RC_G12"
assert_eq "G12 real lock cleared" "false" "$([ -f "$WAIO_SHUTDOWN_LOCK" ] && echo true || echo false)"
assert_eq "G12 guardian state back to NORMAL" "NORMAL" "$(guardian_call guardian_get_state)"
assert_eq "G12 guardian_state_changed event recorded for the reset" "true" "$([ "$(count_events "$WAIO_AUDIT_LOG" "guardian_state_changed")" -ge 2 ] && echo true || echo false)"

echo "[G13] recover.sh leaves an unrelated (non-SHUTDOWN) Guardian state alone"
fixture_reset "g13"
guardian_call guardian_set_state "WARNING" "unrelated caution" "g13run" "tester" >/dev/null
bash -c 'source security/lib.sh; trigger_shutdown "$1" "$2" "1" "$3" "$4"' _ "g13 trip" "g13run" "G13WORKER" "g13dest" >/dev/null
OUT_G13="$(./security/recover.sh --confirm "G13: investigated this unrelated real shutdown, safe to resume" 2>&1)"; RC_G13=$?
assert_eq "G13 recover exit 0" "0" "$RC_G13"
assert_eq "G13 guardian WARNING left untouched" "WARNING" "$(guardian_call guardian_get_state)"

echo "=== guardian_require_human_approval (Phase 64: never-downgrade guard) ==="

echo "[G52] NORMAL -> HUMAN_APPROVAL_REQUIRED succeeds and is audited"
fixture_reset "g52"
guardian_call guardian_require_human_approval "g52 needs a human" "g52run" >/dev/null
assert_eq "G52 state HUMAN_APPROVAL_REQUIRED" "HUMAN_APPROVAL_REQUIRED" "$(guardian_call guardian_get_state)"
assert_eq "G52 one guardian_state_changed event" "1" "$(count_events "$WAIO_AUDIT_LOG" "guardian_state_changed")"

echo "[G53] WARNING -> HUMAN_APPROVAL_REQUIRED still escalates (higher rank)"
fixture_reset "g53"
guardian_call guardian_set_state "WARNING" "g53 caution" "g53run" "tester" >/dev/null
guardian_call guardian_require_human_approval "g53 needs a human" "g53run" >/dev/null
assert_eq "G53 state HUMAN_APPROVAL_REQUIRED" "HUMAN_APPROVAL_REQUIRED" "$(guardian_call guardian_get_state)"

echo "[G54] BLOCKED -> HUMAN_APPROVAL_REQUIRED still escalates (higher rank)"
fixture_reset "g54"
guardian_call guardian_set_state "BLOCKED" "g54 incident" "g54run" "tester" >/dev/null
guardian_call guardian_require_human_approval "g54 needs a human" "g54run" >/dev/null
assert_eq "G54 state HUMAN_APPROVAL_REQUIRED" "HUMAN_APPROVAL_REQUIRED" "$(guardian_call guardian_get_state)"

echo "[G55] SHUTDOWN is never downgraded to HUMAN_APPROVAL_REQUIRED -- the never-downgrade guard"
fixture_reset "g55"
guardian_call guardian_set_state "SHUTDOWN" "g55 real incident" "g55run" "tester" >/dev/null
guardian_call guardian_require_human_approval "g55 should not downgrade" "g55run" >/dev/null
assert_eq "G55 state stays SHUTDOWN" "SHUTDOWN" "$(guardian_call guardian_get_state)"
assert_eq "G55 no additional guardian_state_changed event" "1" "$(count_events "$WAIO_AUDIT_LOG" "guardian_state_changed")"
assert_eq "G55 the no-op is still audited (guardian_event_notified)" "1" "$(count_events "$WAIO_AUDIT_LOG" "guardian_event_notified")"

echo "[G56] already HUMAN_APPROVAL_REQUIRED: a repeat call is a no-op, not a duplicate state_changed event"
fixture_reset "g56"
guardian_call guardian_require_human_approval "g56 first request" "g56run" >/dev/null
guardian_call guardian_require_human_approval "g56 second request" "g56run" >/dev/null
assert_eq "G56 state still HUMAN_APPROVAL_REQUIRED" "HUMAN_APPROVAL_REQUIRED" "$(guardian_call guardian_get_state)"
assert_eq "G56 only the first call changed state" "1" "$(count_events "$WAIO_AUDIT_LOG" "guardian_state_changed")"

echo "=== security/guardian_intervene_wrapper.sh (Phase 64: Guardian-initiated intervention channel) ==="

echo "[G57] forwards SSH_ORIGINAL_COMMAND as the reason and sets HUMAN_APPROVAL_REQUIRED, no real SSH involved"
fixture_reset "g57"
G57_REASON="g57: anomalous pattern observed, please pause for review"
OUT_G57="$(SSH_ORIGINAL_COMMAND="$G57_REASON" ./security/guardian_intervene_wrapper.sh 2>&1)"; RC_G57=$?
assert_eq "G57 exit 0" "0" "$RC_G57"
assert_eq "G57 state HUMAN_APPROVAL_REQUIRED" "HUMAN_APPROVAL_REQUIRED" "$(guardian_call guardian_get_state)"
assert_contains "G57 output echoes the reason" "$OUT_G57" "$G57_REASON"
assert_contains "G57 output points at guardian_approve.sh for clearing" "$OUT_G57" "guardian_approve.sh"

echo "[G58] shell-metacharacter reason text is never re-executed (command-injection check, mirrors security_test.sh's G3/G4 for the recovery-direction wrapper)"
fixture_reset "g58"
INJECT_MARKER="$FIXTURE_DIR/g58-pwned-marker"
rm -f "$INJECT_MARKER"
G58_INJECT='g58"; touch '"$INJECT_MARKER"'; echo "'
SSH_ORIGINAL_COMMAND="$G58_INJECT" ./security/guardian_intervene_wrapper.sh >/dev/null 2>&1
assert_eq "G58 injected command never executed" "false" "$([ -f "$INJECT_MARKER" ] && echo true || echo false)"
assert_eq "G58 state still transitioned normally despite the metacharacters" "HUMAN_APPROVAL_REQUIRED" "$(guardian_call guardian_get_state)"

echo "[G59] the wrapper never downgrades an active SHUTDOWN (end-to-end through the wrapper, not just the underlying function)"
fixture_reset "g59"
guardian_call guardian_set_state "SHUTDOWN" "g59 real incident" "g59run" "tester" >/dev/null
SSH_ORIGINAL_COMMAND="g59 should not downgrade" ./security/guardian_intervene_wrapper.sh >/dev/null 2>&1
assert_eq "G59 state stays SHUTDOWN" "SHUTDOWN" "$(guardian_call guardian_get_state)"

echo "[G60] the wrapper never touches the real SHUTDOWN_LOCK -- only the Guardian's own state"
fixture_reset "g60"
SSH_ORIGINAL_COMMAND="g60 request, sufficiently descriptive for validation" ./security/guardian_intervene_wrapper.sh >/dev/null 2>&1
assert_eq "G60 real shutdown lock still absent" "false" "$([ -f "$WAIO_SHUTDOWN_LOCK" ] && echo true || echo false)"

echo "[G61] a missing SSH_ORIGINAL_COMMAND (no reason text supplied) still transitions, with a default reason"
fixture_reset "g61"
OUT_G61="$(env -u SSH_ORIGINAL_COMMAND ./security/guardian_intervene_wrapper.sh 2>&1)"; RC_G61=$?
assert_eq "G61 exit 0" "0" "$RC_G61"
assert_eq "G61 state HUMAN_APPROVAL_REQUIRED" "HUMAN_APPROVAL_REQUIRED" "$(guardian_call guardian_get_state)"
assert_contains "G61 default reason text used" "$OUT_G61" "no reason text supplied"

echo "=== security/guardian_intervene_wrapper.sh: reason-strength validation (Phase 71, closes Phase 68 finding 5; shared security/lib.sh validate_reason_strength) ==="

echo "[G63] wrapper rejects a too-short SSH_ORIGINAL_COMMAND, never escalates Guardian state"
fixture_reset "g63"
OUT_G63="$(SSH_ORIGINAL_COMMAND="too short" ./security/guardian_intervene_wrapper.sh 2>&1)"; RC_G63=$?
assert_eq "G63 refused, exit 1" "1" "$RC_G63"
assert_contains "G63 explains minimum length" "$OUT_G63" "minimum is 20"
assert_eq "G63 state stays NORMAL (never escalated)" "NORMAL" "$(guardian_call guardian_get_state)"

echo "[G64] wrapper rejects a low-variety (padding) SSH_ORIGINAL_COMMAND, never escalates Guardian state"
fixture_reset "g64"
OUT_G64="$(SSH_ORIGINAL_COMMAND="aaaaaaaaaaaaaaaaaaaa" ./security/guardian_intervene_wrapper.sh 2>&1)"; RC_G64=$?
assert_eq "G64 refused, exit 1" "1" "$RC_G64"
assert_contains "G64 explains low variety" "$OUT_G64" "distinct characters"
assert_eq "G64 state stays NORMAL (never escalated)" "NORMAL" "$(guardian_call guardian_get_state)"

echo "[G65] wrapper honors WAIO_GUARDIAN_MIN_REASON_LENGTH/DISTINCT_CHARS overrides, same as guardian_release_agent.sh's own G38"
fixture_reset "g65"
OUT_G65="$(WAIO_GUARDIAN_MIN_REASON_LENGTH=5 WAIO_GUARDIAN_MIN_REASON_DISTINCT_CHARS=3 SSH_ORIGINAL_COMMAND="abcde" ./security/guardian_intervene_wrapper.sh 2>&1)"; RC_G65=$?
assert_eq "G65 accepted under lowered threshold, exit 0" "0" "$RC_G65"
assert_eq "G65 state HUMAN_APPROVAL_REQUIRED" "HUMAN_APPROVAL_REQUIRED" "$(guardian_call guardian_get_state)"

echo "=== security/guardian_intervene_quarantine_wrapper.sh (Phase 72: second, separately-keyed Guardian intervention action) ==="

echo "[G66] no agent name given (empty SSH_ORIGINAL_COMMAND): refuses, nothing quarantined, global state untouched"
fixture_reset "g66"
OUT_G66="$(env -u SSH_ORIGINAL_COMMAND ./security/guardian_intervene_quarantine_wrapper.sh 2>&1)"; RC_G66=$?
assert_eq "G66 refused, exit 1" "1" "$RC_G66"
assert_contains "G66 explains missing agent name" "$OUT_G66" "no agent name given"
assert_eq "G66 global guardian state stays NORMAL" "NORMAL" "$(guardian_call guardian_get_state)"

echo "[G67] agent given, no reason text at all: refuses (EMPTY), agent not quarantined"
fixture_reset "g67"
OUT_G67="$(SSH_ORIGINAL_COMMAND="G67_AGENT" ./security/guardian_intervene_quarantine_wrapper.sh 2>&1)"; RC_G67=$?
assert_eq "G67 refused, exit 1" "1" "$RC_G67"
assert_contains "G67 explains empty reason" "$OUT_G67" "reason is empty"
assert_eq "G67 agent not quarantined" "false" "$(guardian_call guardian_is_quarantined "G67_AGENT" >/dev/null 2>&1 && echo true || echo false)"

echo "[G68] agent given, too-short reason: refuses, agent not quarantined"
fixture_reset "g68"
OUT_G68="$(SSH_ORIGINAL_COMMAND="G68_AGENT too short" ./security/guardian_intervene_quarantine_wrapper.sh 2>&1)"; RC_G68=$?
assert_eq "G68 refused, exit 1" "1" "$RC_G68"
assert_contains "G68 explains minimum length" "$OUT_G68" "minimum is 20"
assert_eq "G68 agent not quarantined" "false" "$(guardian_call guardian_is_quarantined "G68_AGENT" >/dev/null 2>&1 && echo true || echo false)"

echo "[G69] agent given, low-variety (padding) reason: refuses, agent not quarantined"
fixture_reset "g69"
OUT_G69="$(SSH_ORIGINAL_COMMAND="G69_AGENT aaaaaaaaaaaaaaaaaaaa" ./security/guardian_intervene_quarantine_wrapper.sh 2>&1)"; RC_G69=$?
assert_eq "G69 refused, exit 1" "1" "$RC_G69"
assert_contains "G69 explains low variety" "$OUT_G69" "distinct characters"
assert_eq "G69 agent not quarantined" "false" "$(guardian_call guardian_is_quarantined "G69_AGENT" >/dev/null 2>&1 && echo true || echo false)"

echo "[G70] agent + sufficiently descriptive reason: quarantines exactly that agent, global Guardian state untouched, audited"
fixture_reset "g70"
G70_REASON="observed repeated anomalous SSH payloads from this specific worker"
OUT_G70="$(SSH_ORIGINAL_COMMAND="G70_AGENT $G70_REASON" ./security/guardian_intervene_quarantine_wrapper.sh 2>&1)"; RC_G70=$?
assert_eq "G70 exit 0" "0" "$RC_G70"
assert_contains "G70 output echoes the reason" "$OUT_G70" "$G70_REASON"
assert_contains "G70 output points at guardian_release_agent.sh for release" "$OUT_G70" "guardian_release_agent.sh"
assert_eq "G70 agent now quarantined" "true" "$(guardian_call guardian_is_quarantined "G70_AGENT" >/dev/null 2>&1 && echo true || echo false)"
assert_eq "G70 global guardian state stays NORMAL (this action never touches it)" "NORMAL" "$(guardian_call guardian_get_state)"
assert_eq "G70 exactly one guardian_agent_quarantined event" "1" "$(count_events "$WAIO_AUDIT_LOG" "guardian_agent_quarantined")"

echo "[G71] already-quarantined agent: idempotent no-op, exit 0, no duplicate audit event"
fixture_reset "g71"
guardian_call guardian_quarantine_agent "G71_AGENT" "g71 quarantine setup" "g71run" >/dev/null
OUT_G71="$(SSH_ORIGINAL_COMMAND="G71_AGENT a second, equally descriptive reason text" ./security/guardian_intervene_quarantine_wrapper.sh 2>&1)"; RC_G71=$?
assert_eq "G71 exit 0" "0" "$RC_G71"
assert_contains "G71 output says already quarantined" "$OUT_G71" "already quarantined"
assert_eq "G71 exactly one guardian_agent_quarantined event (the setup call, not a duplicate)" "1" "$(count_events "$WAIO_AUDIT_LOG" "guardian_agent_quarantined")"

echo "[G72] shell-metacharacter agent/reason text is never re-executed (command-injection check, mirrors G58 for the human-approval wrapper)"
fixture_reset "g72"
INJECT_MARKER="$FIXTURE_DIR/g72-pwned-marker"
rm -f "$INJECT_MARKER"
G72_INJECT='G72_AGENT"; touch '"$INJECT_MARKER"'; echo "  a sufficiently long and varied reason text'
SSH_ORIGINAL_COMMAND="$G72_INJECT" ./security/guardian_intervene_quarantine_wrapper.sh >/dev/null 2>&1
assert_eq "G72 injected command never executed" "false" "$([ -f "$INJECT_MARKER" ] && echo true || echo false)"

echo "[G73] wrapper honors WAIO_GUARDIAN_MIN_REASON_LENGTH/DISTINCT_CHARS overrides, same as G65/G38"
fixture_reset "g73"
OUT_G73="$(WAIO_GUARDIAN_MIN_REASON_LENGTH=5 WAIO_GUARDIAN_MIN_REASON_DISTINCT_CHARS=3 SSH_ORIGINAL_COMMAND="G73_AGENT abcde" ./security/guardian_intervene_quarantine_wrapper.sh 2>&1)"; RC_G73=$?
assert_eq "G73 accepted under lowered threshold, exit 0" "0" "$RC_G73"
assert_eq "G73 agent quarantined" "true" "$(guardian_call guardian_is_quarantined "G73_AGENT" >/dev/null 2>&1 && echo true || echo false)"

echo "[G74] the wrapper never touches the real SHUTDOWN_LOCK"
fixture_reset "g74"
SSH_ORIGINAL_COMMAND="G74_AGENT a sufficiently long and varied reason text" ./security/guardian_intervene_quarantine_wrapper.sh >/dev/null 2>&1
assert_eq "G74 real shutdown lock still absent" "false" "$([ -f "$WAIO_SHUTDOWN_LOCK" ] && echo true || echo false)"

echo "[G75] end-to-end through waio.sh: the quarantined agent is refused, an unrelated agent dispatches normally (mirrors G24, driven through this wrapper instead of calling guardian_quarantine_agent directly)"
fixture_reset "g75"
printf 'GUARDIAN_TEST_OTHER2|750|workers/echo_worker.sh|echo\n' >> "$REGISTRY_PATH"
SSH_ORIGINAL_COMMAND="ECHO observed repeated anomalous SSH payloads from this worker" ./security/guardian_intervene_quarantine_wrapper.sh >/dev/null 2>&1
OUT_G75A="$(./waio.sh -w ECHO "should be refused" 2>&1)"; RC_G75A=$?
assert_eq "G75 quarantined agent refused, exit 1" "1" "$RC_G75A"
assert_contains "G75 mentions quarantine" "$OUT_G75A" "quarantined"
OUT_G75B="$(./waio.sh -w GUARDIAN_TEST_OTHER2 "unaffected agent" 2>&1)"; RC_G75B=$?
assert_eq "G75 unrelated agent still dispatches, exit 0" "0" "$RC_G75B"
assert_contains "G75 unrelated agent actually ran" "$OUT_G75B" "ECHO WORKER"
mv -f "$REGISTRY_BACKUP" "$REGISTRY_PATH"
cp "$REGISTRY_PATH" "$REGISTRY_BACKUP"

echo "=== Human approval path (security/guardian_approve.sh) ==="

echo "[G14] guardian_approve refuses without a reason"
fixture_reset "g14"
guardian_call guardian_set_state "HUMAN_APPROVAL_REQUIRED" "needs a human" "g14run" "guardian" >/dev/null
OUT_G14="$(guardian_call guardian_approve "" "g14run" "operator" 2>&1)"; RC_G14=$?
assert_eq "G14 rejected empty reason, exit 1" "1" "$RC_G14"
assert_eq "G14 state unchanged" "HUMAN_APPROVAL_REQUIRED" "$(guardian_call guardian_get_state)"

echo "[G15] guardian_approve refuses on SHUTDOWN (must use recover.sh instead)"
fixture_reset "g15"
guardian_call guardian_set_state "SHUTDOWN" "mirrors a real shutdown" "g15run" "guardian" >/dev/null
OUT_G15="$(guardian_call guardian_approve "this reason is long enough for validation" "g15run" "operator" 2>&1)"; RC_G15=$?
assert_eq "G15 rejected, exit 1" "1" "$RC_G15"
assert_contains "G15 points at recover.sh" "$OUT_G15" "recover.sh"
assert_eq "G15 state still SHUTDOWN" "SHUTDOWN" "$(guardian_call guardian_get_state)"

echo "[G16] guardian_approve clears BLOCKED -> NORMAL with a reason, and is audited"
fixture_reset "g16"
guardian_call guardian_set_state "BLOCKED" "some incident" "g16run" "guardian" >/dev/null
OUT_G16="$(guardian_call guardian_approve "investigated the incident, confirmed safe to resume" "g16run" "operator" 2>&1)"; RC_G16=$?
assert_eq "G16 exit 0" "0" "$RC_G16"
assert_eq "G16 state NORMAL" "NORMAL" "$(guardian_call guardian_get_state)"
assert_eq "G16 approval_granted event logged" "1" "$(count_events "$WAIO_AUDIT_LOG" "guardian_approval_granted")"

echo "[G17] security/guardian_approve.sh CLI: no args refused"
fixture_reset "g17"
guardian_call guardian_set_state "WARNING" "cli test setup" "g17run" "guardian" >/dev/null
OUT_G17="$(./security/guardian_approve.sh 2>&1)"; RC_G17=$?
assert_eq "G17 CLI refused, exit 1" "1" "$RC_G17"
assert_eq "G17 state unchanged" "WARNING" "$(guardian_call guardian_get_state)"

echo "[G18] security/guardian_approve.sh CLI: valid --confirm clears state"
OUT_G18="$(./security/guardian_approve.sh --confirm "cli-driven approval, investigated and confirmed safe" 2>&1)"; RC_G18=$?
assert_eq "G18 CLI exit 0" "0" "$RC_G18"
assert_eq "G18 state NORMAL" "NORMAL" "$(guardian_call guardian_get_state)"

echo "[G19] security/guardian_approve.sh CLI: already-NORMAL is a no-op, exit 0"
OUT_G19="$(./security/guardian_approve.sh --confirm "should be a no-op" 2>&1)"; RC_G19=$?
assert_eq "G19 exit 0" "0" "$RC_G19"
assert_contains "G19 already-normal message" "$OUT_G19" "already NORMAL"

echo "=== security/guardian_approve.sh CLI: reason-strength validation (shared security/lib.sh validate_reason_strength) ==="

echo "[G33] CLI rejects a too-short reason, state unchanged"
fixture_reset "g33"
guardian_call guardian_set_state "BLOCKED" "g33 incident" "g33run" "guardian" >/dev/null
OUT_G33="$(./security/guardian_approve.sh --confirm "too short" 2>&1)"; RC_G33=$?
assert_eq "G33 refused, exit 1" "1" "$RC_G33"
assert_contains "G33 explains minimum length" "$OUT_G33" "minimum is 20"
assert_eq "G33 state still BLOCKED" "BLOCKED" "$(guardian_call guardian_get_state)"

echo "[G34] CLI rejects a low-variety (padding) reason, state unchanged"
fixture_reset "g34"
guardian_call guardian_set_state "BLOCKED" "g34 incident" "g34run" "guardian" >/dev/null
OUT_G34="$(./security/guardian_approve.sh --confirm "aaaaaaaaaaaaaaaaaaaa" 2>&1)"; RC_G34=$?
assert_eq "G34 refused, exit 1" "1" "$RC_G34"
assert_contains "G34 explains low variety" "$OUT_G34" "distinct characters"
assert_eq "G34 state still BLOCKED" "BLOCKED" "$(guardian_call guardian_get_state)"

echo "[G35] CLI honors WAIO_GUARDIAN_MIN_REASON_LENGTH/DISTINCT_CHARS overrides"
fixture_reset "g35"
guardian_call guardian_set_state "BLOCKED" "g35 incident" "g35run" "guardian" >/dev/null
OUT_G35="$(WAIO_GUARDIAN_MIN_REASON_LENGTH=5 WAIO_GUARDIAN_MIN_REASON_DISTINCT_CHARS=3 ./security/guardian_approve.sh --confirm "abcde" 2>&1)"; RC_G35=$?
assert_eq "G35 accepted under lowered threshold, exit 0" "0" "$RC_G35"
assert_eq "G35 state NORMAL" "NORMAL" "$(guardian_call guardian_get_state)"

echo "=== Agent quarantine ==="

echo "[G20] guardian_quarantine_agent / guardian_is_quarantined / guardian_release_agent"
fixture_reset "g20"
assert_eq "G20 not quarantined initially" "false" "$(guardian_call guardian_is_quarantined "SOME_AGENT" >/dev/null 2>&1 && echo true || echo false)"
guardian_call guardian_quarantine_agent "SOME_AGENT" "suspicious behavior" "g20run" >/dev/null
assert_eq "G20 now quarantined" "true" "$(guardian_call guardian_is_quarantined "SOME_AGENT" >/dev/null 2>&1 && echo true || echo false)"
guardian_call guardian_quarantine_agent "SOME_AGENT" "duplicate call" "g20run" >/dev/null
assert_eq "G20 duplicate quarantine is idempotent (1 line)" "1" "$(wc -l < "$WAIO_GUARDIAN_QUARANTINE_FILE" | tr -d ' ')"
guardian_call guardian_release_agent "SOME_AGENT" "cleared" "g20run" >/dev/null
assert_eq "G20 released" "false" "$(guardian_call guardian_is_quarantined "SOME_AGENT" >/dev/null 2>&1 && echo true || echo false)"

echo "=== Automatic quarantine policy (opt-in, WAIO_GUARDIAN_AUTO_QUARANTINE) ==="

echo "[G39] default (unset): repeated critical events never auto-quarantine (feature off by default)"
fixture_reset "g39"
for i in 1 2 3 4 5; do
  guardian_call guardian_notify_event "g39_event_$i" "critical" "detail $i" "g39run" "AUTOQ_OFF_AGENT" >/dev/null
done
assert_eq "G39 not quarantined" "false" "$(guardian_call guardian_is_quarantined "AUTOQ_OFF_AGENT" >/dev/null 2>&1 && echo true || echo false)"
assert_eq "G39 no auto-quarantine audit event" "0" "$(count_events "$WAIO_AUDIT_LOG" "guardian_auto_quarantine_triggered")"

echo "[G40] opted in, below threshold: fewer than the default 3 critical events do not quarantine yet"
fixture_reset "g40"
WAIO_GUARDIAN_AUTO_QUARANTINE=1 guardian_call guardian_notify_event "g40_event_1" "critical" "d1" "g40run" "AUTOQ_AGENT" >/dev/null
WAIO_GUARDIAN_AUTO_QUARANTINE=1 guardian_call guardian_notify_event "g40_event_2" "critical" "d2" "g40run" "AUTOQ_AGENT" >/dev/null
assert_eq "G40 not quarantined yet (2 of 3)" "false" "$(guardian_call guardian_is_quarantined "AUTOQ_AGENT" >/dev/null 2>&1 && echo true || echo false)"

echo "[G41] opted in, threshold reached: the 3rd critical event for the same worker quarantines it and is audited"
WAIO_GUARDIAN_AUTO_QUARANTINE=1 guardian_call guardian_notify_event "g40_event_3" "critical" "d3" "g40run" "AUTOQ_AGENT" >/dev/null
assert_eq "G41 quarantined at threshold" "true" "$(guardian_call guardian_is_quarantined "AUTOQ_AGENT" >/dev/null 2>&1 && echo true || echo false)"
assert_eq "G41 exactly one auto-quarantine event" "1" "$(count_events "$WAIO_AUDIT_LOG" "guardian_auto_quarantine_triggered")"
assert_eq "G41 exactly one guardian_agent_quarantined event (reused, not duplicated)" "1" "$(count_events "$WAIO_AUDIT_LOG" "guardian_agent_quarantined")"

echo "[G42] opted in, but an unattributed (unknown/default) worker is never auto-quarantined -- safety guard"
fixture_reset "g42"
for i in 1 2 3 4; do
  WAIO_GUARDIAN_AUTO_QUARANTINE=1 guardian_call guardian_notify_event "g42_event_$i" "critical" "detail $i" "g42run" >/dev/null
done
assert_eq "G42 'unknown' never quarantined" "false" "$(guardian_call guardian_is_quarantined "unknown" >/dev/null 2>&1 && echo true || echo false)"
assert_eq "G42 no auto-quarantine event" "0" "$(count_events "$WAIO_AUDIT_LOG" "guardian_auto_quarantine_triggered")"

echo "[G43] opted in: one worker's critical events never count toward a different worker's counter"
fixture_reset "g43"
WAIO_GUARDIAN_AUTO_QUARANTINE=1 guardian_call guardian_notify_event "g43a" "critical" "d" "g43run" "AUTOQ_A" >/dev/null
WAIO_GUARDIAN_AUTO_QUARANTINE=1 guardian_call guardian_notify_event "g43b" "critical" "d" "g43run" "AUTOQ_B" >/dev/null
WAIO_GUARDIAN_AUTO_QUARANTINE=1 guardian_call guardian_notify_event "g43c" "critical" "d" "g43run" "AUTOQ_A" >/dev/null
assert_eq "G43 AUTOQ_A not yet quarantined (2 of 3, isolated from AUTOQ_B)" "false" "$(guardian_call guardian_is_quarantined "AUTOQ_A" >/dev/null 2>&1 && echo true || echo false)"
assert_eq "G43 AUTOQ_B not quarantined (1 of 3)" "false" "$(guardian_call guardian_is_quarantined "AUTOQ_B" >/dev/null 2>&1 && echo true || echo false)"

echo "[G44] WAIO_GUARDIAN_AUTO_QUARANTINE_THRESHOLD override is honored (threshold=1: a single critical event is enough)"
fixture_reset "g44"
WAIO_GUARDIAN_AUTO_QUARANTINE=1 WAIO_GUARDIAN_AUTO_QUARANTINE_THRESHOLD=1 guardian_call guardian_notify_event "g44_event" "critical" "d" "g44run" "AUTOQ_THRESH1" >/dev/null
assert_eq "G44 quarantined on the first critical event under threshold=1" "true" "$(guardian_call guardian_is_quarantined "AUTOQ_THRESH1" >/dev/null 2>&1 && echo true || echo false)"

echo "[G45] releasing an auto-quarantined agent resets its counter -- a partial rebuild afterward does not immediately re-trigger"
fixture_reset "g45"
WAIO_GUARDIAN_AUTO_QUARANTINE=1 WAIO_GUARDIAN_AUTO_QUARANTINE_THRESHOLD=1 guardian_call guardian_notify_event "g45_event_1" "critical" "d" "g45run" "AUTOQ_RESET" >/dev/null
assert_eq "G45 quarantined first time" "true" "$(guardian_call guardian_is_quarantined "AUTOQ_RESET" >/dev/null 2>&1 && echo true || echo false)"
guardian_call guardian_release_agent "AUTOQ_RESET" "investigated, confirmed safe to release" "g45run" >/dev/null
assert_eq "G45 released" "false" "$(guardian_call guardian_is_quarantined "AUTOQ_RESET" >/dev/null 2>&1 && echo true || echo false)"
WAIO_GUARDIAN_AUTO_QUARANTINE=1 WAIO_GUARDIAN_AUTO_QUARANTINE_THRESHOLD=3 guardian_call guardian_notify_event "g45_event_2" "critical" "d" "g45run" "AUTOQ_RESET" >/dev/null
assert_eq "G45 not immediately re-quarantined after release (counter rebuilds from 0, 1 of 3)" "false" "$(guardian_call guardian_is_quarantined "AUTOQ_RESET" >/dev/null 2>&1 && echo true || echo false)"

echo "[G46] an agent already quarantined manually is left alone by the auto policy -- no duplicate/misleading audit event"
fixture_reset "g46"
guardian_call guardian_quarantine_agent "AUTOQ_MANUAL" "manually quarantined by operator" "g46run" >/dev/null
for i in 1 2 3; do
  WAIO_GUARDIAN_AUTO_QUARANTINE=1 guardian_call guardian_notify_event "g46_event_$i" "critical" "detail $i" "g46run" "AUTOQ_MANUAL" >/dev/null
done
assert_eq "G46 still quarantined (unaffected)" "true" "$(guardian_call guardian_is_quarantined "AUTOQ_MANUAL" >/dev/null 2>&1 && echo true || echo false)"
assert_eq "G46 no auto-quarantine event (already quarantined, no misleading duplicate)" "0" "$(count_events "$WAIO_AUDIT_LOG" "guardian_auto_quarantine_triggered")"
assert_eq "G46 still exactly one guardian_agent_quarantined event (the manual one)" "1" "$(count_events "$WAIO_AUDIT_LOG" "guardian_agent_quarantined")"

echo "[G47] the auto-quarantine policy never changes guardian_notify_event's existing global-state escalation"
fixture_reset "g47"
WAIO_GUARDIAN_AUTO_QUARANTINE=1 guardian_call guardian_notify_event "g47_event" "critical" "dangerous op" "g47run" "AUTOQ_STATE_CHECK" >/dev/null
assert_eq "G47 global guardian state still escalates to BLOCKED" "BLOCKED" "$(guardian_call guardian_get_state)"

# N=40, not 12: manually verified during this fix's own development
# that 12-way concurrency rarely actually collided on this machine (5/5
# clean runs even WITHOUT the lock fix -- too fast/lightly-scheduled to
# reliably overlap), while 40-way concurrency reproduced the real bug
# directly (a bare `W|39` counter, one lost increment, quarantine never
# firing) in 1 of 3 unfixed trials, and 0 of 5 fixed trials failed at
# that same width -- same order of magnitude and same probabilistic
# nature as tests/audit_log_integrity_test.sh's own I10 (Phase 65: ~1-
# in-3 unfixed, 0/20+ fixed). This is best-effort concurrency coverage,
# not a guaranteed regression catch on every single run, by the nature
# of a real race condition -- the primary evidence for this fix is the
# manual statistical reproduction above, not this suite alone.
echo "[G62] concurrent critical events for the SAME worker never lose a counter increment (Phase 70 lock fix, security audit finding) -- 40 truly concurrent events with threshold=40 must still quarantine exactly once"
fixture_reset "g62"
declare -a G62_PIDS=()
for i in $(seq 1 40); do
  ( WAIO_GUARDIAN_AUTO_QUARANTINE=1 WAIO_GUARDIAN_AUTO_QUARANTINE_THRESHOLD=40 guardian_call guardian_notify_event "g62_event_$i" "critical" "concurrent test $i" "g62run" "CONCURRENT_WORKER" ) &
  G62_PIDS+=("$!")
done
for pid in "${G62_PIDS[@]}"; do wait "$pid"; done
assert_eq "G62 worker WAS quarantined despite 40-way concurrency (no lost increments)" "true" "$(guardian_call guardian_is_quarantined "CONCURRENT_WORKER" >/dev/null 2>&1 && echo true || echo false)"
assert_eq "G62 exactly one auto-quarantine event (not zero, not duplicated)" "1" "$(count_events "$WAIO_AUDIT_LOG" "guardian_auto_quarantine_triggered")"
assert_eq "G62 all 40 critical-event notifications were recorded" "40" "$(count_events "$WAIO_AUDIT_LOG" "guardian_event_notified")"

echo "=== Real production caller (Phase 62): workers/orchestrate_worker.sh stage-failure notification ==="

echo "[G48] default (unset WAIO_AUTO_GUARDIAN_STAGE_NOTIFY): a failing ORCHESTRATE stage never touches the Guardian"
fixture_reset "g48"
OUT_G48="$(WAIO_PIPELINE="BOGUS" ./waio.sh -w ORCHESTRATE "g48 request" 2>&1)"; RC_G48=$?
assert_eq "G48 pipeline itself still fails as before (unaffected by this phase)" "2" "$RC_G48"
assert_eq "G48 guardian state stays NORMAL (feature off by default)" "NORMAL" "$(guardian_call guardian_get_state)"
assert_eq "G48 no guardian_event_notified event" "0" "$(count_events "$WAIO_AUDIT_LOG" "guardian_event_notified")"

echo "[G49] opted in: a failing ORCHESTRATE stage notifies the Guardian at WARNING severity, attributed to the failed worker NAME"
fixture_reset "g49"
OUT_G49="$(WAIO_AUTO_GUARDIAN_STAGE_NOTIFY=1 WAIO_PIPELINE="BOGUS" ./waio.sh -w ORCHESTRATE "g49 request" 2>&1)"; RC_G49=$?
assert_eq "G49 pipeline result unaffected (same exit code as G48)" "2" "$RC_G49"
assert_eq "G49 guardian state escalates to WARNING" "WARNING" "$(guardian_call guardian_get_state)"
assert_eq "G49 exactly one guardian_event_notified event" "1" "$(count_events "$WAIO_AUDIT_LOG" "guardian_event_notified")"
G49_EVENT_LINE="$(grep '"event_type": "guardian_event_notified"' "$WAIO_AUDIT_LOG")"
assert_contains "G49 event attributed to worker BOGUS" "$G49_EVENT_LINE" '"worker": "BOGUS"'
assert_contains "G49 event carries warning severity (decision field)" "$G49_EVENT_LINE" '"decision": "warning"'
assert_contains "G49 event names the real detection this codebase already performs" "$G49_EVENT_LINE" "orchestrate_stage_failed"

echo "[G50] opted in, WARNING severity never feeds Phase 60's automatic-quarantine counter, even with it also enabled"
fixture_reset "g50"
for i in 1 2 3 4 5; do
  WAIO_AUTO_GUARDIAN_STAGE_NOTIFY=1 WAIO_GUARDIAN_AUTO_QUARANTINE=1 WAIO_PIPELINE="BOGUS" ./waio.sh -w ORCHESTRATE "g50 request $i" >/dev/null 2>&1
done
assert_eq "G50 BOGUS never auto-quarantined by 5 stage failures (warning != critical)" "false" "$(guardian_call guardian_is_quarantined "BOGUS" >/dev/null 2>&1 && echo true || echo false)"
assert_eq "G50 no auto-quarantine event" "0" "$(count_events "$WAIO_AUDIT_LOG" "guardian_auto_quarantine_triggered")"
assert_eq "G50 guardian state is WARNING, never escalated further by this path" "WARNING" "$(guardian_call guardian_get_state)"

echo "[G51] opted in: a successful stage never generates a Guardian notification"
fixture_reset "g51"
OUT_G51="$(WAIO_AUTO_GUARDIAN_STAGE_NOTIFY=1 WAIO_PIPELINE="ECHO" ./waio.sh -w ORCHESTRATE "g51 request" 2>&1)"; RC_G51=$?
assert_eq "G51 pipeline succeeds" "0" "$RC_G51"
assert_eq "G51 guardian state stays NORMAL" "NORMAL" "$(guardian_call guardian_get_state)"
assert_eq "G51 no guardian_event_notified event" "0" "$(count_events "$WAIO_AUDIT_LOG" "guardian_event_notified")"

echo "=== End-to-end: waio.sh dispatch gates ==="

echo "[G21] waio.sh refuses new dispatch while Guardian state is BLOCKED"
fixture_reset "g21"
guardian_call guardian_set_state "BLOCKED" "g21 incident" "g21run" "guardian" >/dev/null
OUT_G21="$(./waio.sh -w ECHO "should be refused" 2>&1)"; RC_G21=$?
assert_eq "G21 refused, exit 1" "1" "$RC_G21"
assert_contains "G21 mentions Guardian state" "$OUT_G21" "Guardian control plane state is BLOCKED"

echo "[G22] waio.sh refuses new dispatch while Guardian state is HUMAN_APPROVAL_REQUIRED"
fixture_reset "g22"
guardian_call guardian_set_state "HUMAN_APPROVAL_REQUIRED" "g22 needs human" "g22run" "guardian" >/dev/null
OUT_G22="$(./waio.sh -w ECHO "should be refused" 2>&1)"; RC_G22=$?
assert_eq "G22 refused, exit 1" "1" "$RC_G22"
assert_contains "G22 points at guardian_approve.sh" "$OUT_G22" "guardian_approve.sh"

echo "[G23] waio.sh still dispatches normally while Guardian state is WARNING (non-blocking)"
fixture_reset "g23"
guardian_call guardian_set_state "WARNING" "g23 caution only" "g23run" "guardian" >/dev/null
OUT_G23="$(./waio.sh -w ECHO "g23 request" 2>&1)"; RC_G23=$?
assert_eq "G23 dispatch still succeeds" "0" "$RC_G23"

echo "[G24] waio.sh refuses dispatch to a quarantined agent, but other agents are unaffected"
fixture_reset "g24"
# Second harmless registry entry reusing the real (side-effect-free)
# echo_worker.sh under a different NAME, so the "unaffected agent" half of
# this check never has to touch a worker that makes a real network/SSH
# call (RPI/HEALTHCHECK/etc.) -- same registry swap-aside-and-restore
# idiom tests/security_test.sh and tests/waio_test.sh already use.
printf 'GUARDIAN_TEST_OTHER|750|workers/echo_worker.sh|echo\n' >> "$REGISTRY_PATH"
guardian_call guardian_quarantine_agent "ECHO" "g24 quarantine test" "g24run" >/dev/null
OUT_G24A="$(./waio.sh -w ECHO "should be refused" 2>&1)"; RC_G24A=$?
assert_eq "G24 quarantined agent refused, exit 1" "1" "$RC_G24A"
assert_contains "G24 mentions quarantine" "$OUT_G24A" "quarantined"
OUT_G24B="$(./waio.sh -w GUARDIAN_TEST_OTHER "unaffected agent" 2>&1)"; RC_G24B=$?
assert_eq "G24 non-quarantined agent still dispatches, exit 0" "0" "$RC_G24B"
assert_contains "G24 non-quarantined agent actually ran" "$OUT_G24B" "ECHO WORKER"
mv -f "$REGISTRY_BACKUP" "$REGISTRY_PATH"
cp "$REGISTRY_PATH" "$REGISTRY_BACKUP"

echo "[G25] waio.sh refuses new dispatch while Guardian state is SHUTDOWN (even without the real lock present)"
fixture_reset "g25"
guardian_call guardian_set_state "SHUTDOWN" "g25 guardian-only shutdown mirror" "g25run" "guardian" >/dev/null
assert_eq "G25 precondition: real lock NOT present" "false" "$([ -f "$WAIO_SHUTDOWN_LOCK" ] && echo true || echo false)"
OUT_G25="$(./waio.sh -w ECHO "should be refused" 2>&1)"; RC_G25=$?
assert_eq "G25 refused, exit 1" "1" "$RC_G25"
assert_contains "G25 points at recover.sh" "$OUT_G25" "recover.sh"

echo "=== security/guardian_release_agent.sh (operator CLI for quarantine release) ==="

echo "[G28] CLI refuses when no agent name is given"
fixture_reset "g28"
OUT_G28="$(./security/guardian_release_agent.sh 2>&1)"; RC_G28=$?
assert_eq "G28 refused, exit 1" "1" "$RC_G28"
assert_contains "G28 explains missing agent name" "$OUT_G28" "no agent name given"

echo "[G29] CLI is a no-op, exit 0, when the named agent isn't quarantined"
fixture_reset "g29"
OUT_G29="$(./security/guardian_release_agent.sh "NEVER_QUARANTINED" --confirm "should be a no-op" 2>&1)"; RC_G29=$?
assert_eq "G29 exit 0" "0" "$RC_G29"
assert_contains "G29 not-quarantined message" "$OUT_G29" "is not currently quarantined"

echo "[G30] CLI refuses a quarantined agent's release without a reason, state unchanged"
fixture_reset "g30"
guardian_call guardian_quarantine_agent "CLI_AGENT" "g30 quarantine setup" "g30run" >/dev/null
OUT_G30="$(./security/guardian_release_agent.sh "CLI_AGENT" 2>&1)"; RC_G30=$?
assert_eq "G30 refused, exit 1" "1" "$RC_G30"
assert_contains "G30 explains missing reason" "$OUT_G30" "without a reason"
assert_eq "G30 still quarantined" "true" "$(guardian_call guardian_is_quarantined "CLI_AGENT" >/dev/null 2>&1 && echo true || echo false)"

echo "[G31] CLI --confirm releases a quarantined agent, and is audited"
fixture_reset "g31"
guardian_call guardian_quarantine_agent "CLI_AGENT2" "g31 quarantine setup" "g31run" >/dev/null
OUT_G31="$(./security/guardian_release_agent.sh "CLI_AGENT2" --confirm "investigated, confirmed safe to release" 2>&1)"; RC_G31=$?
assert_eq "G31 exit 0" "0" "$RC_G31"
assert_contains "G31 confirms release" "$OUT_G31" "released from quarantine"
assert_eq "G31 no longer quarantined" "false" "$(guardian_call guardian_is_quarantined "CLI_AGENT2" >/dev/null 2>&1 && echo true || echo false)"
assert_eq "G31 released event logged" "1" "$(count_events "$WAIO_AUDIT_LOG" "guardian_agent_released")"

echo "[G32] CLI leaves an unrelated quarantined agent untouched"
fixture_reset "g32"
guardian_call guardian_quarantine_agent "CLI_AGENT_KEEP" "g32 unrelated" "g32run" >/dev/null
guardian_call guardian_quarantine_agent "CLI_AGENT_DROP" "g32 to release" "g32run" >/dev/null
./security/guardian_release_agent.sh "CLI_AGENT_DROP" --confirm "investigated, confirmed safe to release" >/dev/null 2>&1
assert_eq "G32 unrelated agent still quarantined" "true" "$(guardian_call guardian_is_quarantined "CLI_AGENT_KEEP" >/dev/null 2>&1 && echo true || echo false)"
assert_eq "G32 released agent no longer quarantined" "false" "$(guardian_call guardian_is_quarantined "CLI_AGENT_DROP" >/dev/null 2>&1 && echo true || echo false)"

echo "=== security/guardian_release_agent.sh CLI: reason-strength validation (shared security/lib.sh validate_reason_strength) ==="

echo "[G36] CLI rejects a too-short reason, agent still quarantined"
fixture_reset "g36"
guardian_call guardian_quarantine_agent "CLI_AGENT3" "g36 quarantine setup" "g36run" >/dev/null
OUT_G36="$(./security/guardian_release_agent.sh "CLI_AGENT3" --confirm "too short" 2>&1)"; RC_G36=$?
assert_eq "G36 refused, exit 1" "1" "$RC_G36"
assert_contains "G36 explains minimum length" "$OUT_G36" "minimum is 20"
assert_eq "G36 still quarantined" "true" "$(guardian_call guardian_is_quarantined "CLI_AGENT3" >/dev/null 2>&1 && echo true || echo false)"

echo "[G37] CLI rejects a low-variety (padding) reason, agent still quarantined"
fixture_reset "g37"
guardian_call guardian_quarantine_agent "CLI_AGENT4" "g37 quarantine setup" "g37run" >/dev/null
OUT_G37="$(./security/guardian_release_agent.sh "CLI_AGENT4" --confirm "aaaaaaaaaaaaaaaaaaaa" 2>&1)"; RC_G37=$?
assert_eq "G37 refused, exit 1" "1" "$RC_G37"
assert_contains "G37 explains low variety" "$OUT_G37" "distinct characters"
assert_eq "G37 still quarantined" "true" "$(guardian_call guardian_is_quarantined "CLI_AGENT4" >/dev/null 2>&1 && echo true || echo false)"

echo "[G38] CLI honors WAIO_GUARDIAN_MIN_REASON_LENGTH/DISTINCT_CHARS overrides"
fixture_reset "g38"
guardian_call guardian_quarantine_agent "CLI_AGENT5" "g38 quarantine setup" "g38run" >/dev/null
OUT_G38="$(WAIO_GUARDIAN_MIN_REASON_LENGTH=5 WAIO_GUARDIAN_MIN_REASON_DISTINCT_CHARS=3 ./security/guardian_release_agent.sh "CLI_AGENT5" --confirm "abcde" 2>&1)"; RC_G38=$?
assert_eq "G38 accepted under lowered threshold, exit 0" "0" "$RC_G38"
assert_eq "G38 no longer quarantined" "false" "$(guardian_call guardian_is_quarantined "CLI_AGENT5" >/dev/null 2>&1 && echo true || echo false)"

echo "=== Opt-in WAIO_AUTO_GUARDIAN_NOTIFY mirror on trigger_shutdown ==="

echo "[G26] default (unset): trigger_shutdown does NOT touch Guardian state"
fixture_reset "g26"
bash -c 'source security/lib.sh; trigger_shutdown "$1" "$2" "1" "$3" "$4"' _ "g26 trip, no auto-notify" "g26run" "G26WORKER" "g26dest" >/dev/null
assert_eq "G26 guardian state stays NORMAL (default off)" "NORMAL" "$(guardian_call guardian_get_state)"

echo "[G27] WAIO_AUTO_GUARDIAN_NOTIFY=1: trigger_shutdown mirrors into Guardian SHUTDOWN, exactly once"
fixture_reset "g27"
WAIO_AUTO_GUARDIAN_NOTIFY=1 bash -c 'source security/lib.sh; trigger_shutdown "$1" "$2" "1" "$3" "$4"' _ "g27 trip, auto-notify on" "g27run" "G27WORKER" "g27dest" >/dev/null
assert_eq "G27 guardian state now SHUTDOWN" "SHUTDOWN" "$(guardian_call guardian_get_state)"
assert_eq "G27 exactly one shutdown_triggered event (no recursive double-trip)" "1" "$(count_events "$WAIO_AUDIT_LOG" "shutdown_triggered")"

echo "=== Summary ==="
echo "PASS=$PASS FAIL=$FAIL"
if [ "$FAIL" -gt 0 ]; then
  echo "Failures:"
  for f in "${FAILURES[@]}"; do echo "  - $f"; done
  exit 1
fi
exit 0
