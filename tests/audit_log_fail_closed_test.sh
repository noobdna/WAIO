#!/bin/bash
set -uo pipefail

# tests/audit_log_fail_closed_test.sh -- audit_log() fails CLOSED when its
# lock cannot be acquired within AUDIT_LOG_LOCK_MAX_WAIT_ITERATIONS.
#
# Before 2026-11-05 audit_log() proceeded WITHOUT the lock after giving
# up. An unlocked append reads the same checkpoint prev_hash as the real
# holder, so the hash chain forks (verify -> broken:N): the tamper-
# evidence chain then reports a false break and can mask a real one. Now
# the event is diverted, whole, to the AUDIT_LOG_INTEGRITY_ALERTS side
# channel as audit_log_lock_timeout, and the chained log and checkpoint
# are untouched. audit_log() still returns 0, because waio.sh and other
# callers run under set -euo pipefail.
#
#   F1  timeout: chained log and checkpoint byte-for-byte unchanged, chain ok
#   F2  timeout: event recorded whole (valid JSON, all fields) to alerts
#   F3  timeout: audit_log returns 75 (EX_TEMPFAIL); a bare call aborts a
#       set -euo pipefail caller, a `|| true` (restrictive) caller survives;
#       stderr warning printed
#   F4  timeout: the live holder's lock is untouched (no steal, no release)
#   F5  timeout: awkward reason text (quotes, backslash, newline) still
#       yields one valid JSON alert line
#   R1  recovery: once the holder releases, the next write chains normally
#   R2  recovery: a dead holder's stale lock is reclaimed and the write chains
#   C1  concurrency with a forced 0.1s budget (timeouts guaranteed): the
#       chain stays fully valid, and log lines + diverted events == writers,
#       so no event is lost (3 rounds x 12 writers)
#   C2  concurrency with the default budget: all 12 writes chained, chain
#       ok, nothing diverted
#
# All fixtures live in a scratch temp dir; nothing under security/state
# or logs/ is touched.

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

FIXTURE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/waio-audit-fail-closed-test.XXXXXX")"
LIVE_PID=""
trap '[ -n "$LIVE_PID" ] && kill "$LIVE_PID" 2>/dev/null; rm -rf "$FIXTURE_DIR"' EXIT
sleep 0 & DEAD_PID=$!; wait "$DEAD_PID" 2>/dev/null
sleep 300 & LIVE_PID=$!

fixture() {
  local d="$FIXTURE_DIR/$1"; mkdir -p "$d"
  export WAIO_AUDIT_LOG="$d/audit.jsonl" WAIO_AUDIT_LOG_CHECKPOINT="$d/checkpoint" \
    WAIO_AUDIT_INTEGRITY_ALERTS="$d/alerts.jsonl" WAIO_AUDIT_LOG_LOCK_DIR="$d/lock" \
    WAIO_SHUTDOWN_LOCK="$d/SHUTDOWN.lock" WAIO_GUARDIAN_STATE_FILE="$d/GS" \
    WAIO_GUARDIAN_QUARANTINE_FILE="$d/GQ" WAIO_GUARDIAN_CRITICAL_EVENTS_FILE="$d/GCE"
  unset WAIO_AUDIT_LOG_LOCK_MAX_WAIT
}
write() { bash -c 'source security/lib.sh; audit_log "$@"' _ "$@"; }
verify() { bash -c 'source security/lib.sh; verify_audit_log_integrity'; }
hold_lock() {  # hold_lock PID -- a lock as the real code leaves one
  mkdir -p "$WAIO_AUDIT_LOG_LOCK_DIR"
  printf 'H-token' > "$WAIO_AUDIT_LOG_LOCK_DIR/owner"
  printf '%s' "$1" > "$WAIO_AUDIT_LOG_LOCK_DIR/holder.pid"
}
sum() { [ -f "$1" ] && python3 -c "import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],'rb').read()).hexdigest())" "$1" || echo absent; }
alert_field() {  # alert_field N FIELD -- FIELD of the Nth alert line
  python3 -c "
import json,sys
lines=[l for l in open(sys.argv[1]) if l.strip()]
print(json.loads(lines[int(sys.argv[2])-1]).get(sys.argv[3]))" "$WAIO_AUDIT_INTEGRITY_ALERTS" "$1" "$2" 2>/dev/null || echo unparseable
}

echo "=== Timeout: fail closed ==="
fixture f1
write seed f1 1 W d allowed "seed 1" >/dev/null 2>&1
write seed f1 2 W d allowed "seed 2" >/dev/null 2>&1
LOG_BEFORE="$(sum "$WAIO_AUDIT_LOG")"; CP_BEFORE="$(sum "$WAIO_AUDIT_LOG_CHECKPOINT")"
hold_lock "$LIVE_PID"
ERR="$FIXTURE_DIR/f1.err"
WAIO_AUDIT_LOG_LOCK_MAX_WAIT=2 bash -c 'source security/lib.sh; audit_log timed_out_event f1run 3 W dest allowed "should be diverted"' 2> "$ERR"; RC=$?
echo "[F1] chained log and checkpoint untouched"
assert_eq "F1 chained log byte-for-byte unchanged" "$LOG_BEFORE" "$(sum "$WAIO_AUDIT_LOG")"
assert_eq "F1 checkpoint byte-for-byte unchanged" "$CP_BEFORE" "$(sum "$WAIO_AUDIT_LOG_CHECKPOINT")"
assert_eq "F1 still exactly the 2 seed lines" "2" "$(wc -l < "$WAIO_AUDIT_LOG" | tr -d ' ')"
rm -rf "$WAIO_AUDIT_LOG_LOCK_DIR"
assert_eq "F1 chain verifies ok" "ok" "$(verify)"
echo "[F2] event recorded whole to the alerts side channel"
assert_eq "F2 one alert line" "1" "$(wc -l < "$WAIO_AUDIT_INTEGRITY_ALERTS" 2>/dev/null | tr -d ' ')"
assert_eq "F2 event_type" "audit_log_lock_timeout" "$(alert_field 1 event_type)"
assert_eq "F2 attempted_event_type" "timed_out_event" "$(alert_field 1 attempted_event_type)"
assert_eq "F2 run_id" "f1run" "$(alert_field 1 run_id)"
assert_eq "F2 destination" "dest" "$(alert_field 1 destination)"
assert_eq "F2 reason" "should be diverted" "$(alert_field 1 reason)"
assert_eq "F2 actor_user recorded" "$(id -un)" "$(alert_field 1 actor_user)"
echo "[F3] signals the caller: 75 (not chained); restrictive callers opt to proceed"
assert_eq "F3 audit_log returns 75 (EX_TEMPFAIL) on timeout" "75" "$RC"
assert_eq "F3 stderr warning names fail-closed" "true" "$(grep -q 'fail-closed' "$ERR" && echo true || echo false)"
fixture f3; hold_lock "$LIVE_PID"
assert_eq "F3 a bare call under set -euo pipefail does NOT continue (the failure surfaces)" "" \
  "$(WAIO_AUDIT_LOG_LOCK_MAX_WAIT=1 bash -euo pipefail -c 'source security/lib.sh; audit_log e r 1 W d allowed x 2>/dev/null; echo survived' 2>/dev/null)"
fixture f3b; hold_lock "$LIVE_PID"
assert_eq "F3 a restrictive '|| true' caller under set -euo pipefail survives the timeout" "survived" \
  "$(WAIO_AUDIT_LOG_LOCK_MAX_WAIT=1 bash -euo pipefail -c 'source security/lib.sh; audit_log e r 1 W d denied x 2>/dev/null || true; echo survived')"
echo "[F4] the live holder's lock is untouched"
assert_eq "F4 owner token untouched" "H-token" "$(cat "$WAIO_AUDIT_LOG_LOCK_DIR/owner" 2>/dev/null)"
assert_eq "F4 holder.pid untouched" "$LIVE_PID" "$(cat "$WAIO_AUDIT_LOG_LOCK_DIR/holder.pid" 2>/dev/null)"
echo "[F5] awkward reason text still yields one valid JSON line"
fixture f5; hold_lock "$LIVE_PID"
AWK_REASON="$(printf 'quote " backslash \\ newline\nend')"
WAIO_AUDIT_LOG_LOCK_MAX_WAIT=1 bash -c 'source security/lib.sh; audit_log e r 1 W d allowed "$1"' _ "$AWK_REASON" 2>/dev/null
assert_eq "F5 exactly one alert line" "1" "$(wc -l < "$WAIO_AUDIT_INTEGRITY_ALERTS" 2>/dev/null | tr -d ' ')"
assert_eq "F5 reason round-trips exactly" "true" "$(python3 -c "
import json,sys; r=json.loads(open(sys.argv[1]).readline())['reason']; print('true' if r==sys.argv[2] else 'false')" "$WAIO_AUDIT_INTEGRITY_ALERTS" "$AWK_REASON" 2>/dev/null || echo false)"

echo
echo "=== Recovery ==="
echo "[R1] once the holder releases, the next write chains normally"
fixture r1
write seed r1 1 W d allowed "seed" >/dev/null 2>&1
hold_lock "$LIVE_PID"
WAIO_AUDIT_LOG_LOCK_MAX_WAIT=1 bash -c 'source security/lib.sh; audit_log diverted r1 2 W d allowed x' 2>/dev/null
rm -rf "$WAIO_AUDIT_LOG_LOCK_DIR"
write after r1 3 W d allowed "after release" >/dev/null 2>&1
assert_eq "R1 log has seed + post-release write (diverted one absent)" "2" "$(wc -l < "$WAIO_AUDIT_LOG" | tr -d ' ')"
assert_eq "R1 chain ok" "ok" "$(verify)"
assert_eq "R1 lock released after the recovered write" "false" "$([ -e "$WAIO_AUDIT_LOG_LOCK_DIR" ] && echo true || echo false)"
echo "[R2] a dead holder's stale lock is reclaimed and the write chains"
fixture r2
write seed r2 1 W d allowed "seed" >/dev/null 2>&1
hold_lock "$DEAD_PID"; touch -t 202001010000 "$WAIO_AUDIT_LOG_LOCK_DIR"
write after r2 2 W d allowed "after stale" >/dev/null 2>&1
assert_eq "R2 write landed in the chained log" "2" "$(wc -l < "$WAIO_AUDIT_LOG" | tr -d ' ')"
assert_eq "R2 chain ok" "ok" "$(verify)"
assert_eq "R2 nothing diverted" "0" "$(cat "$WAIO_AUDIT_INTEGRITY_ALERTS" 2>/dev/null | wc -l | tr -d ' ')"

echo
echo "=== Concurrency ==="
concurrent() {  # concurrent N [MAX_WAIT]
  local n="$1" mw="${2:-}" pids=() k
  for ((k = 1; k <= n; k++)); do
    if [ -n "$mw" ]; then
      WAIO_AUDIT_LOG_LOCK_MAX_WAIT="$mw" bash -c 'source security/lib.sh; audit_log c cr 1 "W$1" d allowed "writer $1"' _ "$k" 2>/dev/null &
    else
      bash -c 'source security/lib.sh; audit_log c cr 1 "W$1" d allowed "writer $1"' _ "$k" 2>/dev/null &
    fi
    pids+=("$!")
  done
  for p in "${pids[@]}"; do wait "$p"; done
}
for round in 1 2 3; do
  echo "[C1] round $round: 12 writers, forced 0.1s budget (timeouts guaranteed)"
  fixture "c1-$round"
  concurrent 12 1
  L="$(cat "$WAIO_AUDIT_LOG" 2>/dev/null | wc -l | tr -d ' ')"
  D="$(grep -c '"audit_log_lock_timeout"' "$WAIO_AUDIT_INTEGRITY_ALERTS" 2>/dev/null)"; D="${D:-0}"
  assert_eq "C1 round $round chain fully valid" "ok" "$(verify)"
  assert_eq "C1 round $round no event lost (chained + diverted = 12)" "12" "$((L + D))"
  assert_eq "C1 round $round at least one timeout really happened" "true" "$([ "$D" -ge 1 ] && echo true || echo false)"
done
echo "[C2] 12 writers, default budget"
fixture c2
concurrent 12
assert_eq "C2 all 12 chained" "12" "$(wc -l < "$WAIO_AUDIT_LOG" | tr -d ' ')"
assert_eq "C2 chain fully valid" "ok" "$(verify)"
assert_eq "C2 nothing diverted" "0" "$(cat "$WAIO_AUDIT_INTEGRITY_ALERTS" 2>/dev/null | wc -l | tr -d ' ')"

echo ""
echo "=== Summary: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
  echo "Failures:"
  printf '  - %s\n' "${FAILURES[@]}"
  exit 1
fi
exit 0
