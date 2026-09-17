#!/bin/bash
set -uo pipefail

# tests/audit_log_integrity_test.sh -- regression suite for Red Team
# finding #3 (2026-09-13): logs/security-audit.jsonl had no integrity
# protection at all -- anyone able to delete security/state/SHUTDOWN.lock
# directly could equally edit or truncate the audit log to erase or
# fabricate evidence, silently defeating the bypass-detection
# reconciliation added earlier the same day (_reconcile_recovery_audit).
#
# Fixed by security/lib.sh's hash-chained audit_log()/
# verify_audit_log_integrity()/_handle_audit_log_integrity_alert(): each
# line now carries prev_hash (the SHA-256 of the immediately preceding
# line's own exact text), and a separate small checkpoint file tracks
# the true last-written state. This is tamper-EVIDENCE, not
# tamper-prevention or authentication -- see security/lib.sh's own
# header comment on verify_audit_log_integrity for exactly what this
# does and does not prove.
#
# Everything here runs against scratch fixtures via
# WAIO_AUDIT_LOG/WAIO_AUDIT_LOG_CHECKPOINT/WAIO_AUDIT_INTEGRITY_ALERTS/
# WAIO_AUDIT_LOG_LOCK_DIR/WAIO_SHUTDOWN_LOCK overrides -- no SSH, no
# network call, no touch of this deployment's real
# logs/security-audit.jsonl or security/state/ at any point. This suite
# also directly attacks its OWN fixture log (deleting/editing/
# truncating/chmod'ing it) to prove detection -- never the real one.

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

FIXTURE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/waio-audit-integrity-test.XXXXXX")"
trap 'chmod -R u+w "$FIXTURE_DIR" 2>/dev/null; rm -rf "$FIXTURE_DIR"' EXIT

fixture_reset() {
  local suffix="${1:-default}"
  export WAIO_AUDIT_LOG="$FIXTURE_DIR/audit-$suffix.jsonl"
  export WAIO_AUDIT_LOG_CHECKPOINT="$FIXTURE_DIR/checkpoint-$suffix"
  export WAIO_AUDIT_INTEGRITY_ALERTS="$FIXTURE_DIR/alerts-$suffix.jsonl"
  export WAIO_AUDIT_LOG_LOCK_DIR="$FIXTURE_DIR/lock-$suffix"
  export WAIO_SHUTDOWN_LOCK="$FIXTURE_DIR/SHUTDOWN-$suffix.lock"
  # Phase 66: this suite's I11/I12 (and any future case) dispatch through
  # the real ./waio.sh, which also gates on the DuCoPA Guardian Control
  # Plane (guardian_is_blocking/guardian_is_quarantined, Phase 57) -- a
  # gap this file predates and never isolated, unlike every
  # Guardian-aware suite added since (tests/ducopa_guardian_test.sh,
  # tests/collect_status_guardian_test.sh, etc.). Without these three
  # overrides, I11/I12 read/write this deployment's REAL
  # security/state/GUARDIAN_STATE/GUARDIAN_QUARANTINE/GUARDIAN_CRITICAL_EVENTS
  # -- harmless when that real state happens to be NORMAL/empty, but a
  # real collision risk if anything else touches it concurrently (see
  # ARCHITECTURE.md Phase 65's own note: this is exactly what was
  # observed once while stress-testing that phase's lock fix).
  export WAIO_GUARDIAN_STATE_FILE="$FIXTURE_DIR/GUARDIAN_STATE-$suffix"
  export WAIO_GUARDIAN_QUARANTINE_FILE="$FIXTURE_DIR/GUARDIAN_QUARANTINE-$suffix"
  export WAIO_GUARDIAN_CRITICAL_EVENTS_FILE="$FIXTURE_DIR/GUARDIAN_CRITICAL_EVENTS-$suffix"
  chmod -R u+w "$FIXTURE_DIR" 2>/dev/null || true
  rm -rf "$WAIO_AUDIT_LOG" "$WAIO_AUDIT_LOG_CHECKPOINT" "$WAIO_AUDIT_INTEGRITY_ALERTS" "$WAIO_AUDIT_LOG_LOCK_DIR" "$WAIO_SHUTDOWN_LOCK" \
    "$WAIO_GUARDIAN_STATE_FILE" "$WAIO_GUARDIAN_QUARANTINE_FILE" "$WAIO_GUARDIAN_CRITICAL_EVENTS_FILE"
}

write_n_entries() {
  # write_n_entries N LABEL -- N legitimate audit_log() calls through
  # the real security/lib.sh, each a separate process (matching how
  # audit_log() is actually always called in production -- never
  # sourced-and-reused within one long-lived shell).
  local n="$1" label="$2" j
  for ((j = 1; j <= n; j++)); do
    bash -c "source security/lib.sh; audit_log \"test_event\" \"${label}-run-\$1\" \"1\" \"TESTWORKER\" \"testdest\" \"allowed\" \"entry \$1 of ${label}\"" _ "$j"
  done
}

verify() {
  bash -c 'source security/lib.sh; verify_audit_log_integrity'
}

echo "=== [I1] a fresh (no prior writes) fixture verifies as ok ==="
fixture_reset "i1"
assert_eq "I1 result" "ok" "$(verify)"

echo "[I2] a normal sequence of writes verifies as ok, chain is well-formed"
fixture_reset "i2"
write_n_entries 5 "i2"
assert_eq "I2 result" "ok" "$(verify)"
assert_eq "I2 log has 5 lines" "5" "$(wc -l < "$WAIO_AUDIT_LOG" | tr -d ' ')"
FIRST_PREV_HASH="$(python3 -c "import json; print(json.loads(open('$WAIO_AUDIT_LOG').readline())['prev_hash'])")"
assert_eq "I2 first line's prev_hash is the genesis marker" "genesis" "$FIRST_PREV_HASH"

echo
echo "=== Tamper scenarios (attacking this suite's OWN fixture, never the real log) ==="

echo "[I3] the log file deleted entirely after entries exist -> detected as 'missing'"
fixture_reset "i3"
write_n_entries 3 "i3"
rm -f "$WAIO_AUDIT_LOG"
assert_eq "I3 result" "missing" "$(verify)"

echo "[I4] a middle line's content silently edited -> detected as a broken chain at the following line"
fixture_reset "i4"
write_n_entries 4 "i4"
python3 -c "
import json
lines = open('$WAIO_AUDIT_LOG').read().splitlines()
obj = json.loads(lines[1])
obj['reason'] = 'TAMPERED: this line was edited after the fact'
lines[1] = json.dumps(obj)
open('$WAIO_AUDIT_LOG', 'w').write('\n'.join(lines) + '\n')
"
assert_eq "I4 result (broken at line 3, the one following the edited line 2)" "broken:3" "$(verify)"

echo "[I5] the LAST line edited (no following line to catch it via chain-walk) -> detected via checkpoint mismatch"
fixture_reset "i5"
write_n_entries 3 "i5"
python3 -c "
import json
lines = open('$WAIO_AUDIT_LOG').read().splitlines()
obj = json.loads(lines[-1])
obj['reason'] = 'TAMPERED: last line rewritten, prev_hash left correct'
lines[-1] = json.dumps(obj)
open('$WAIO_AUDIT_LOG', 'w').write('\n'.join(lines) + '\n')
"
assert_eq "I5 result" "checkpoint_mismatch" "$(verify)"

echo "[I6] the last line deleted (truncation) -> detected as 'truncated'"
fixture_reset "i6"
write_n_entries 4 "i6"
python3 -c "
lines = open('$WAIO_AUDIT_LOG').read().splitlines()
open('$WAIO_AUDIT_LOG', 'w').write('\n'.join(lines[:-1]) + '\n')
"
assert_eq "I6 result" "truncated" "$(verify)"

echo "[I7] the entire log replaced with a shorter, fully self-consistent fake chain (a naive 'rewrite everything' attempt) -> still caught"
fixture_reset "i7"
write_n_entries 5 "i7"
python3 -c "
import hashlib, json
lines = []
prev = 'genesis'
for i in range(2):  # fewer entries than the real 5
    obj = {'timestamp': '2020-01-01T00:00:00Z', 'event_type': 'fake', 'run_id': 'r', 'stage': '1',
           'worker': 'w', 'destination': 'd', 'decision': 'allowed', 'reason': 'forged',
           'actor_user': 'x', 'actor_uid': '0', 'actor_tty': 'not a tty', 'actor_ssh_connection': None,
           'prev_hash': prev}
    text = json.dumps(obj)
    lines.append(text)
    prev = hashlib.sha256(text.encode()).hexdigest()
open('$WAIO_AUDIT_LOG', 'w').write('\n'.join(lines) + '\n')
"
assert_eq "I7 result (internally consistent fake chain, but shorter than the checkpoint recorded)" "truncated" "$(verify)"

echo "[I8] the audit log file made read-only -> detected as 'unwritable'"
fixture_reset "i8"
write_n_entries 2 "i8"
chmod 444 "$WAIO_AUDIT_LOG"
assert_eq "I8 result" "unwritable" "$(verify)"
chmod u+w "$WAIO_AUDIT_LOG"

echo "[I9] a write attempt against an unwritable log is itself detected synchronously, and recorded to the side-channel alert file (not the broken log)"
fixture_reset "i9"
write_n_entries 2 "i9"
chmod 444 "$WAIO_AUDIT_LOG"
OUT_I9="$(bash -c 'source security/lib.sh; audit_log "test_event" "i9run" "1" "TESTWORKER" "testdest" "allowed" "this write should fail"' 2>&1)"
assert_contains "I9 stderr warns about the failed write" "$OUT_I9" "failed to write audit log entry"
assert_contains "I9 side-channel alert file records the failure" "$(cat "$WAIO_AUDIT_INTEGRITY_ALERTS" 2>/dev/null)" "audit_log_write_failed"
assert_eq "I9 log itself still has only its original 2 lines (write was correctly refused, not partially applied)" "2" "$(chmod u+w "$WAIO_AUDIT_LOG"; wc -l < "$WAIO_AUDIT_LOG" | tr -d ' ')"

echo
echo "=== Concurrency (the lock this whole mechanism depends on) ==="

echo "[I10] concurrent audit_log() calls (simulating parallel ORCHESTRATE worker stages) never produce a false-positive broken chain"
fixture_reset "i10"
declare -a PIDS=()
for ((k = 1; k <= 12; k++)); do
  bash -c "source security/lib.sh; audit_log \"test_event\" \"i10run\" \"1\" \"W$k\" \"d\" \"allowed\" \"concurrent write $k\"" &
  PIDS+=("$!")
done
for pid in "${PIDS[@]}"; do wait "$pid"; done
assert_eq "I10 all 12 concurrent writes landed" "12" "$(wc -l < "$WAIO_AUDIT_LOG" | tr -d ' ')"
assert_eq "I10 chain is fully valid despite the race (the lock worked)" "ok" "$(verify)"

echo
echo "=== End-to-end: _handle_audit_log_integrity_alert (wired into waio.sh / security/recover.sh) ==="

echo "[I11] a real ./waio.sh dispatch detects tampering, warns, records the alert, and is NOT blocked by it"
fixture_reset "i11"
write_n_entries 3 "i11"
python3 -c "
import json
lines = open('$WAIO_AUDIT_LOG').read().splitlines()
obj = json.loads(lines[0])
obj['reason'] = 'TAMPERED before a real waio.sh dispatch'
lines[0] = json.dumps(obj)
open('$WAIO_AUDIT_LOG', 'w').write('\n'.join(lines) + '\n')
"
OUT_I11="$(./waio.sh -w ECHO "post-tamper dispatch" 2>&1)"; RC_I11=$?
assert_eq "I11 dispatch is NOT blocked (advisory only)" "0" "$RC_I11"
assert_contains "I11 dispatch still completed normally" "$OUT_I11" "ECHO WORKER] completed"
assert_contains "I11 stderr warning printed" "$OUT_I11" "audit log integrity check failed"
assert_contains "I11 side-channel alert recorded" "$(cat "$WAIO_AUDIT_INTEGRITY_ALERTS" 2>/dev/null)" "audit_log_integrity_violation"
assert_contains "I11 violation also recorded into the (still-writable) main log itself" "$(tail -1 "$WAIO_AUDIT_LOG")" "audit_log_integrity_violation"

echo "[I12] the chain stays evidently, permanently broken at the original tamper point -- appending new (correctly-chained) entries afterward does not 'heal' or hide it"
OUT_I12="$(./waio.sh -w ECHO "second post-tamper dispatch" 2>&1)"; RC_I12=$?
assert_eq "I12 exit code" "0" "$RC_I12"
# I11 edited line 1 (of the original 3), which breaks the link INTO
# line 2 forever -- that is the correct, desired tamper-evidence
# property (a hash chain must not let later legitimate writes launder
# earlier tampering back to "ok"). Still reported as "broken:2" here,
# not a new/different break -- proving this isn't spuriously
# re-triggering on the violation-recording write itself.
assert_eq "I12 tamper from I11 remains permanently visible, not healed by later writes" "broken:2" "$(verify)"

echo
echo "=== Guardian Control Plane isolation (Phase 66): I11/I12's real ./waio.sh dispatch must never read/write this deployment's REAL Guardian state ==="
echo "(this file predates security/guardian.sh (Phase 57) and, until this phase, never overrode"
echo " WAIO_GUARDIAN_STATE_FILE/WAIO_GUARDIAN_QUARANTINE_FILE/WAIO_GUARDIAN_CRITICAL_EVENTS_FILE --"
echo " a real gap noted in ARCHITECTURE.md Phase 65 after it was implicated in one transient,"
echo " concurrency-related I11 failure during that phase's own verification.)"

echo "[I18] fixture_reset points every Guardian override at this fixture, never at the real security/state/ files"
fixture_reset "i18"
assert_contains "I18 WAIO_GUARDIAN_STATE_FILE is under the fixture dir" "$WAIO_GUARDIAN_STATE_FILE" "$FIXTURE_DIR"
assert_contains "I18 WAIO_GUARDIAN_QUARANTINE_FILE is under the fixture dir" "$WAIO_GUARDIAN_QUARANTINE_FILE" "$FIXTURE_DIR"
assert_contains "I18 WAIO_GUARDIAN_CRITICAL_EVENTS_FILE is under the fixture dir" "$WAIO_GUARDIAN_CRITICAL_EVENTS_FILE" "$FIXTURE_DIR"

echo "[I19] a BLOCKED Guardian state written to the FIXTURE file actually gates the real ./waio.sh dispatch -- proving the override is genuinely read, not silently ignored"
fixture_reset "i19"
bash -c 'source security/lib.sh; guardian_set_state "BLOCKED" "i19 fixture-only incident" "i19run" "tester"' >/dev/null
OUT_I19="$(./waio.sh -w ECHO "should be refused" 2>&1)"; RC_I19=$?
assert_eq "I19 dispatch refused by the FIXTURE Guardian state" "1" "$RC_I19"
assert_contains "I19 mentions Guardian state" "$OUT_I19" "Guardian control plane state is BLOCKED"

echo "[I20] this deployment's real security/state/GUARDIAN_STATE/GUARDIAN_QUARANTINE/GUARDIAN_CRITICAL_EVENTS were never read or written by I18/I19 above"
assert_eq "I20 real GUARDIAN_STATE untouched (still absent)" "false" "$([ -f security/state/GUARDIAN_STATE ] && echo true || echo false)"
assert_eq "I20 real GUARDIAN_QUARANTINE untouched (still absent)" "false" "$([ -f security/state/GUARDIAN_QUARANTINE ] && echo true || echo false)"
assert_eq "I20 real GUARDIAN_CRITICAL_EVENTS untouched (still absent)" "false" "$([ -f security/state/GUARDIAN_CRITICAL_EVENTS ] && echo true || echo false)"

echo "[I21] I11/I12's own real-dispatch cases still pass normally now that Guardian state is fixture-isolated (a fresh fixture is NORMAL/not-quarantined by default)"
fixture_reset "i21"
write_n_entries 2 "i21"
OUT_I21="$(./waio.sh -w ECHO "post-isolation-fix sanity dispatch" 2>&1)"; RC_I21=$?
assert_eq "I21 dispatch succeeds" "0" "$RC_I21"
assert_contains "I21 dispatch actually ran" "$OUT_I21" "ECHO WORKER"

echo
echo "=== Lock staleness hardening (Phase 65): age alone must never steal a still-live holder's lock ==="
echo "(root cause of I10's own intermittent ~1-in-3 'broken:N' failure, reproduced and confirmed pre-existing"
echo " on unmodified develop via git stash before this fix -- see ARCHITECTURE.md Phase 65.)"

echo "[I13] a stale-by-age lock whose recorded holder PID is genuinely dead is reclaimed"
fixture_reset "i13"
mkdir -p "$WAIO_AUDIT_LOG_LOCK_DIR"
printf '999999999\n' > "$WAIO_AUDIT_LOG_LOCK_DIR/holder.pid"
OLD_TS="$(python3 -c "import datetime; print((datetime.datetime.now() - datetime.timedelta(seconds=10)).strftime('%Y%m%d%H%M.%S'))")"
touch -t "$OLD_TS" "$WAIO_AUDIT_LOG_LOCK_DIR"
OUT_I13="$(bash -c 'source security/lib.sh; _audit_log_lock_acquire && echo ACQUIRED' 2>&1)"
assert_contains "I13 lock acquired (dead holder PID reclaimed)" "$OUT_I13" "ACQUIRED"
bash -c 'source security/lib.sh; _audit_log_lock_release'

echo "[I14] a stale-by-age lock whose recorded holder PID is still alive is NOT reclaimed"
fixture_reset "i14"
mkdir -p "$WAIO_AUDIT_LOG_LOCK_DIR"
printf '%s\n' "$$" > "$WAIO_AUDIT_LOG_LOCK_DIR/holder.pid"
OLD_TS="$(python3 -c "import datetime; print((datetime.datetime.now() - datetime.timedelta(seconds=10)).strftime('%Y%m%d%H%M.%S'))")"
touch -t "$OLD_TS" "$WAIO_AUDIT_LOG_LOCK_DIR"
I14_MARKER="$FIXTURE_DIR/i14-acquired-marker"
rm -f "$I14_MARKER"
( bash -c 'source security/lib.sh; _audit_log_lock_acquire && echo ACQUIRED > "$1"' _ "$I14_MARKER" ) &
I14_BG_PID=$!
sleep 0.3
assert_eq "I14 lock dir still present (not stolen while holder PID is alive)" "true" "$([ -d "$WAIO_AUDIT_LOG_LOCK_DIR" ] && echo true || echo false)"
assert_eq "I14 background acquire has not yet succeeded" "false" "$([ -f "$I14_MARKER" ] && echo true || echo false)"
rm -rf "$WAIO_AUDIT_LOG_LOCK_DIR"
wait "$I14_BG_PID" 2>/dev/null
rm -f "$I14_MARKER"

echo "[I15] a stale-by-age lock with no holder.pid file at all falls back to the pre-existing age-only reclaim (legacy/defensive compatibility)"
fixture_reset "i15"
mkdir -p "$WAIO_AUDIT_LOG_LOCK_DIR"
OLD_TS="$(python3 -c "import datetime; print((datetime.datetime.now() - datetime.timedelta(seconds=10)).strftime('%Y%m%d%H%M.%S'))")"
touch -t "$OLD_TS" "$WAIO_AUDIT_LOG_LOCK_DIR"
OUT_I15="$(bash -c 'source security/lib.sh; _audit_log_lock_acquire && echo ACQUIRED' 2>&1)"
assert_contains "I15 lock acquired (no pid file -> falls back to age-only reclaim)" "$OUT_I15" "ACQUIRED"
bash -c 'source security/lib.sh; _audit_log_lock_release'

echo "[I16] a successful acquisition records the caller's own PID in the lock directory"
fixture_reset "i16"
HOLDER_PID_OUT="$(bash -c 'source security/lib.sh; _audit_log_lock_acquire; cat "$AUDIT_LOG_LOCK_DIR/holder.pid"; _audit_log_lock_release')"
assert_eq "I16 holder.pid contains a positive integer PID" "true" "$(printf '%s' "$HOLDER_PID_OUT" | grep -qE '^[0-9]+$' && echo true || echo false)"

echo "[I17] release removes the whole lock directory, including holder.pid (rm -rf, not the old rmdir-only-if-empty)"
fixture_reset "i17"
bash -c 'source security/lib.sh; _audit_log_lock_acquire; _audit_log_lock_release'
assert_eq "I17 lock directory fully removed" "false" "$([ -e "$WAIO_AUDIT_LOG_LOCK_DIR" ] && echo true || echo false)"

echo
echo "=== Regression: the existing recovery-hardening/bypass-detection suite still produces zero spurious integrity violations ==="
fixture_reset "reg"
bash -c 'source security/lib.sh; trigger_shutdown "dummy trip for regression check" "regrun" "1" "REGWORKER" "regdest"'
OUT_REG="$(./security/recover.sh --confirm "investigated the regression dummy trip and confirmed safe to resume" 2>&1)"; RC_REG=$?
assert_eq "REG recover.sh exit code" "0" "$RC_REG"
REG_VIOLATION_COUNT="$(grep -c 'audit_log_integrity_violation' "$WAIO_AUDIT_LOG" 2>/dev/null)"
assert_eq "REG no spurious integrity violation after a normal trigger/recover cycle" "0" "${REG_VIOLATION_COUNT:-0}"
assert_eq "REG chain is still valid" "ok" "$(verify)"

echo
echo "=== Summary: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
  echo "Failures:"
  for f in "${FAILURES[@]}"; do echo "  - $f"; done
  exit 1
fi
exit 0
