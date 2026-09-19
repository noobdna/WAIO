#!/bin/bash
set -uo pipefail

# tests/incident_learning_lock_test.sh -- regression suite for Phase 78
# (concurrent-process locking): security/incident_learning/lock.sh's
# own il_lock_acquire/il_lock_release primitives, plus
# incident_learning_cron.sh's own use of them.
#
# Closes the gap Phase 75/76 both left explicitly open: "concurrent-
# process locking (two invocations racing at the exact same instant)"
# / "so overlapping incident_learning_cron.sh runs... can't corrupt
# candidate state". Does NOT attempt a true simultaneous-instant race
# (this codebase has no portable way to guarantee that) -- instead
# drives il_lock_acquire directly against hand-crafted lock-directory
# states (held-and-fresh, held-and-stale-but-live, held-and-stale-and-
# dead) and separately verifies incident_learning_cron.sh's own
# behavior when it finds the lock already held.
#
# All fixtures use their own scratch temp dir; this suite touches
# neither this deployment's real security/state/incident_learning/
# nor its real logs/incident-learning-cron.log.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"
source security/incident_learning/lock.sh

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

FIXTURE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/waio-il-lock-test.XXXXXX")"
trap 'rm -rf "$FIXTURE_DIR"' EXIT

# backdate_mtime PATH SECONDS_AGO -- portable (macOS/Linux) mtime
# backdating, same technique used to test the age-based branch of any
# mkdir-lock without a real multi-second sleep.
backdate_mtime() {
  local path="$1" secs_ago="$2" stamp
  stamp="$(date -v-"${secs_ago}"S +%Y%m%d%H%M.%S 2>/dev/null || date -d "${secs_ago} seconds ago" +%Y%m%d%H%M.%S)"
  touch -t "$stamp" "$path"
}

echo "=== Incident Learning Engine (Phase 78: concurrent-process locking) regression suite ==="

echo ""
echo "[L1] acquiring a free lock succeeds and records this process's own PID"
L1_LOCK="$FIXTURE_DIR/l1.lock"
il_lock_acquire "$L1_LOCK" 0
assert_eq "L1 acquire returns 0" "0" "$?"
assert_eq "L1 lock directory now exists" "true" "$([ -d "$L1_LOCK" ] && echo true || echo false)"
assert_eq "L1 holder.pid records this shell's own PID" "$$" "$(cat "$L1_LOCK/holder.pid" 2>/dev/null)"

echo ""
echo "[L2] release removes the lock directory entirely"
il_lock_release "$L1_LOCK"
assert_eq "L2 lock directory gone after release" "false" "$([ -d "$L1_LOCK" ] && echo true || echo false)"

echo ""
echo "[L3] a fresh (<=5s old) lock is respected even if MAX_WAIT_ITERATIONS is 0 -- never stolen just because the caller isn't willing to wait"
L3_LOCK="$FIXTURE_DIR/l3.lock"
mkdir "$L3_LOCK"
echo "99999999" > "$L3_LOCK/holder.pid"
il_lock_acquire "$L3_LOCK" 0
assert_eq "L3 acquire fails (returns 1) against a fresh held lock" "1" "$?"
assert_eq "L3 the pre-existing holder.pid is untouched" "99999999" "$(cat "$L3_LOCK/holder.pid" 2>/dev/null)"

echo ""
echo "[L4] a stale (>5s old) lock held by a PID that is still alive (this test's own shell) is correctly NOT stolen"
L4_LOCK="$FIXTURE_DIR/l4.lock"
mkdir "$L4_LOCK"
printf '%s' "$$" > "$L4_LOCK/holder.pid"
backdate_mtime "$L4_LOCK" 10
il_lock_acquire "$L4_LOCK" 0
assert_eq "L4 acquire fails against a stale-but-live holder" "1" "$?"
assert_eq "L4 lock directory still present (not stolen)" "true" "$([ -d "$L4_LOCK" ] && echo true || echo false)"

echo ""
echo "[L5] a stale (>5s old) lock held by a PID that is no longer alive IS reclaimed"
L5_LOCK="$FIXTURE_DIR/l5.lock"
mkdir "$L5_LOCK"
echo "99999999" > "$L5_LOCK/holder.pid"
backdate_mtime "$L5_LOCK" 10
il_lock_acquire "$L5_LOCK" 0
assert_eq "L5 acquire succeeds (lock reclaimed)" "0" "$?"
assert_eq "L5 holder.pid now records this shell's own PID" "$$" "$(cat "$L5_LOCK/holder.pid" 2>/dev/null)"
il_lock_release "$L5_LOCK"

echo ""
echo "[L6] a stale (>5s old) lock with no readable holder.pid at all (holder crashed between mkdir and writing it) is also reclaimed"
L6_LOCK="$FIXTURE_DIR/l6.lock"
mkdir "$L6_LOCK"
backdate_mtime "$L6_LOCK" 10
il_lock_acquire "$L6_LOCK" 0
assert_eq "L6 acquire succeeds (lock reclaimed, no holder.pid to check)" "0" "$?"
il_lock_release "$L6_LOCK"

echo ""
echo "--- incident_learning_cron.sh's own use of this lock ---"

CRON_FIXTURE="$FIXTURE_DIR/cron"
mkdir -p "$CRON_FIXTURE" "$CRON_FIXTURE/collectors"
cp security/incident_learning/collectors/mock_collector.sh "$CRON_FIXTURE/collectors/mock_collector.sh"
export INCIDENT_LEARNING_CRON_LOCK_DIR="$CRON_FIXTURE/.cron.lock"
export INCIDENT_LEARNING_CRON_LOG="$CRON_FIXTURE/cron.log"
export KNOWLEDGE_MANAGER_STATE_DIR="$CRON_FIXTURE/candidates"
export KNOWLEDGE_MANAGER_AUDIT_LOG="$CRON_FIXTURE/audit.jsonl"
export KNOWLEDGE_MANAGER_KNOWLEDGE_DIR="$CRON_FIXTURE/knowledge"
# Phase 81: fixture-local collectors dir, same rationale as
# tests/incident_learning_cron_test.sh's own header -- the real
# security/incident_learning/collectors/ now also holds
# cisa_kev_collector.sh, a real network-calling Collector.
export INCIDENT_LEARNING_COLLECTORS_DIR="$CRON_FIXTURE/collectors"

echo ""
echo "[L7] a normal run acquires and releases its own lock cleanly (lock directory absent afterward)"
bash security/incident_learning/incident_learning_cron.sh >/dev/null 2>&1
L7_RC=$?
assert_eq "L7 exit code 0" "0" "$L7_RC"
assert_eq "L7 lock directory absent after a normal completed run" "false" "$([ -d "$INCIDENT_LEARNING_CRON_LOCK_DIR" ] && echo true || echo false)"
L7_CANDIDATE_COUNT="$(ls "$KNOWLEDGE_MANAGER_STATE_DIR" 2>/dev/null | wc -l | tr -d ' ')"
assert_eq "L7 candidates were actually created this run" "5" "$L7_CANDIDATE_COUNT"

echo ""
echo "[L8] a second run while a lock is already held (simulating an overlapping invocation) is skipped cleanly: exit 0, logs the skip, creates no candidates, never touches the held lock"
rm -rf "$KNOWLEDGE_MANAGER_STATE_DIR"
mkdir -p "$INCIDENT_LEARNING_CRON_LOCK_DIR"
echo "99999999" > "$INCIDENT_LEARNING_CRON_LOCK_DIR/holder.pid"
: > "$INCIDENT_LEARNING_CRON_LOG"
bash security/incident_learning/incident_learning_cron.sh >/dev/null 2>&1
L8_RC=$?
assert_eq "L8 exit code 0 (skip is not an error)" "0" "$L8_RC"
L8_LOG="$(cat "$INCIDENT_LEARNING_CRON_LOG")"
assert_contains "L8 log records the skip" "$L8_LOG" "skipped: another incident_learning_cron.sh run is already in progress"
assert_eq "L8 no candidates were created" "false" "$([ -d "$KNOWLEDGE_MANAGER_STATE_DIR" ] && echo true || echo false)"
assert_eq "L8 the held lock's own holder.pid is untouched" "99999999" "$(cat "$INCIDENT_LEARNING_CRON_LOCK_DIR/holder.pid" 2>/dev/null)"
il_lock_release "$INCIDENT_LEARNING_CRON_LOCK_DIR"

echo ""
echo "[L9] after L8's simulated overlap is cleared, a fresh run proceeds normally -- no lingering lock ever blocks a legitimate future run"
: > "$INCIDENT_LEARNING_CRON_LOG"
bash security/incident_learning/incident_learning_cron.sh >/dev/null 2>&1
L9_RC=$?
assert_eq "L9 exit code 0" "0" "$L9_RC"
L9_LOG="$(cat "$INCIDENT_LEARNING_CRON_LOG")"
assert_contains "L9 this run actually proceeded (not skipped)" "$L9_LOG" "run end"
assert_eq "L9 lock directory absent again afterward" "false" "$([ -d "$INCIDENT_LEARNING_CRON_LOCK_DIR" ] && echo true || echo false)"

echo ""
echo "[L10] a genuine real-process race: two actual incident_learning_cron.sh invocations launched at nearly the same instant against the same fixture -- exactly one processes the batch, the other skips, never both (which would double-process every candidate)"
rm -rf "$KNOWLEDGE_MANAGER_STATE_DIR" "$INCIDENT_LEARNING_CRON_LOCK_DIR"
: > "$INCIDENT_LEARNING_CRON_LOG"
L10_LOG_A="$CRON_FIXTURE/cron-a.log"
L10_LOG_B="$CRON_FIXTURE/cron-b.log"
: > "$L10_LOG_A"; : > "$L10_LOG_B"
(INCIDENT_LEARNING_CRON_LOG="$L10_LOG_A" bash security/incident_learning/incident_learning_cron.sh >/dev/null 2>&1) &
PID_A=$!
(INCIDENT_LEARNING_CRON_LOG="$L10_LOG_B" bash security/incident_learning/incident_learning_cron.sh >/dev/null 2>&1) &
PID_B=$!
wait "$PID_A"; RC_A=$?
wait "$PID_B"; RC_B=$?
assert_eq "L10 both processes exit 0 regardless of which won the race" "0" "$([ "$RC_A" -eq 0 ] && [ "$RC_B" -eq 0 ] && echo 0 || echo 1)"
L10_SKIPPED_COUNT=0
grep -q "skipped: another" "$L10_LOG_A" && L10_SKIPPED_COUNT=$((L10_SKIPPED_COUNT + 1))
grep -q "skipped: another" "$L10_LOG_B" && L10_SKIPPED_COUNT=$((L10_SKIPPED_COUNT + 1))
assert_eq "L10 exactly one of the two racing processes skipped" "1" "$L10_SKIPPED_COUNT"
L10_CANDIDATE_COUNT="$(ls "$KNOWLEDGE_MANAGER_STATE_DIR" 2>/dev/null | wc -l | tr -d ' ')"
assert_eq "L10 exactly one batch worth of candidates exists (5), never double-processed" "5" "$L10_CANDIDATE_COUNT"
assert_eq "L10 lock directory absent after both processes finished" "false" "$([ -d "$INCIDENT_LEARNING_CRON_LOCK_DIR" ] && echo true || echo false)"

echo ""
echo "[D1] DuCoPA boundary: this suite's own run never touched any real Control Plane file"
for real_file in security/egress_allowlist.conf security/segments.conf security/ssh_management_allowlist.conf; do
  if [ -f "$real_file" ]; then
    assert_eq "D1 $real_file unchanged" "" "$(git diff --name-only -- "$real_file" 2>/dev/null)"
  fi
done

echo ""
echo "[D2] security/incident_learning/lock.sh never sources security/lib.sh (static guard -- see that file's own header for why)"
assert_eq "D2 lock.sh does not source security/lib.sh" "0" "$(grep -cE '^\s*source security/lib\.sh\b' security/incident_learning/lock.sh || true)"

echo ""
echo "[D3] no network tool is invoked by lock.sh (static guard)"
assert_eq "D3 zero network-tool invocations" "0" "$(grep -cE '\b(curl|wget|nc )\b' security/incident_learning/lock.sh || true)"

echo ""
echo "=== Summary: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
  echo "Failures:"
  for f in "${FAILURES[@]}"; do echo "  - $f"; done
  exit 1
fi
exit 0
