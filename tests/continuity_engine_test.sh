#!/bin/bash
set -uo pipefail

# tests/continuity_engine_test.sh -- regression suite for the WAIO
# Pre-Disconnect Cache (PDC): security/continuity.sh and its one
# integration point, workers/orchestrate_worker.sh (WAIO_PDC_CACHE /
# WAIO_PDC_FALLBACK). See security/continuity.sh's own header for the
# full PREPARE/OPERATE/RECOVER/RESYNC design.
#
# Everything here runs against scratch fixtures under a temp dir --
# same isolation pattern as tests/segment_recovery_test.sh
# (SEGMENT_MANAGER_*) and tests/audit_log_integrity_test.sh
# (WAIO_SHUTDOWN_LOCK/WAIO_AUDIT_LOG/WAIO_GUARDIAN_*): this suite never
# reads or writes this deployment's real security/segments.conf,
# security/state/, logs/security-audit.jsonl, or
# logs/continuity-audit.jsonl, and never touches any real remote host
# or Takomachi. The only real, un-fixtured entry point exercised is
# ./waio.sh -w ORCHESTRATE itself (same as
# tests/orchestrate_worker_test.sh), dispatching only to workers/
# echo_worker.sh (pure bash, no network, no credentials).

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

assert_not_contains() {
  local label="$1" haystack="$2" needle="$3"
  if [[ "$haystack" != *"$needle"* ]]; then
    PASS=$((PASS + 1)); echo "  PASS: $label"
  else
    FAIL=$((FAIL + 1)); FAILURES+=("$label (expected NOT to contain '$needle')")
    echo "  FAIL: $label (expected NOT to contain '$needle', got: $haystack)"
  fi
}

# --- fixture sandbox. Explicit XXXXXX template, same portability note
# as tests/segment_recovery_test.sh (GNU vs BSD/macOS mktemp -t). ------
FIXTURE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/waio-continuity-test.XXXXXX")"
trap 'rm -rf "$FIXTURE_DIR"; [ -n "${LISTENER_PID:-}" ] && kill "$LISTENER_PID" 2>/dev/null; true' EXIT

mkdir -p "$FIXTURE_DIR/segments_state" "$FIXTURE_DIR/continuity_state" "$FIXTURE_DIR/continuity_cache"

# A local loopback listener stands in for a "reachable" dependency;
# 127.0.0.1:1 (nothing listens there) stands in for an unreachable one
# -- same technique as tests/segment_recovery_test.sh, no real network
# or remote host involved either way.
LISTEN_PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')"
python3 -m http.server "$LISTEN_PORT" --bind 127.0.0.1 >/dev/null 2>&1 &
LISTENER_PID=$!
sleep 0.3
UNREACHABLE_PORT=1

cat > "$FIXTURE_DIR/segments.conf" <<EOF
ECHO-DEP|127.0.0.1|$LISTEN_PORT|ECHO|fixture dependency for the ECHO worker (PDC test)
OTHER|127.0.0.1|$LISTEN_PORT|SOMETHING_ELSE|unrelated fixture segment
EOF

cat > "$FIXTURE_DIR/segments_empty.conf" <<EOF
# no segments configured yet
EOF

# --- isolation: every real state/audit-log/lock path this test's
# call chain could touch is redirected under FIXTURE_DIR, same
# variables tests/audit_log_integrity_test.sh already establishes this
# pattern with. Exported (not just set) so the real ./waio.sh -w
# ORCHESTRATE subprocess used below inherits them too. -------------
export SEGMENT_MANAGER_CONF="$FIXTURE_DIR/segments.conf"
export SEGMENT_MANAGER_STATE_DIR="$FIXTURE_DIR/segments_state"
export SEGMENT_MANAGER_AUDIT_LOG="$FIXTURE_DIR/segment-audit.jsonl"
export WAIO_CONTINUITY_STATE_DIR="$FIXTURE_DIR/continuity_state"
export WAIO_CONTINUITY_CACHE_DIR="$FIXTURE_DIR/continuity_cache"
export WAIO_CONTINUITY_STATE_FILE="$FIXTURE_DIR/continuity_state/CONTINUITY_STATE"
export WAIO_CONTINUITY_SNAPSHOT_FILE="$FIXTURE_DIR/continuity_state/last_known_good.json"
export WAIO_CONTINUITY_AUDIT_LOG="$FIXTURE_DIR/continuity-audit.jsonl"
export WAIO_SHUTDOWN_LOCK="$FIXTURE_DIR/SHUTDOWN.lock"
export WAIO_AUDIT_LOG="$FIXTURE_DIR/security-audit.jsonl"
export WAIO_AUDIT_LOG_CHECKPOINT="$FIXTURE_DIR/audit-checkpoint"
export WAIO_AUDIT_INTEGRITY_ALERTS="$FIXTURE_DIR/audit-alerts.jsonl"
export WAIO_AUDIT_LOG_LOCK_DIR="$FIXTURE_DIR/audit-lock"
export WAIO_GUARDIAN_STATE_FILE="$FIXTURE_DIR/GUARDIAN_STATE"
export WAIO_GUARDIAN_QUARANTINE_FILE="$FIXTURE_DIR/GUARDIAN_QUARANTINE"
export WAIO_GUARDIAN_CRITICAL_EVENTS_FILE="$FIXTURE_DIR/GUARDIAN_CRITICAL_EVENTS"
export RECOVERY_ENGINE_STATE_DIR="$FIXTURE_DIR/recovery_state"
export HEALTH_CHECK_TIMEOUT=1
export HEALTH_CHECK_RETRIES=2
export HEALTH_CHECK_RETRY_DELAY=0

sm() { bash security/segment_manager.sh "$@"; }
ce() { bash security/continuity.sh "$@"; }

echo "=== WAIO Pre-Disconnect Cache (PDC) regression suite ==="
echo

# --- continuity_assess / state derivation --------------------------
echo "--- continuity_assess: CONNECTED / DEGRADED / OFFLINE derivation ---"

echo "[CE1] empty segments.conf -> CONNECTED (nothing to be offline from)"
assert_eq "CE1" "CONNECTED" "$(SEGMENT_MANAGER_CONF="$FIXTURE_DIR/segments_empty.conf" ce assess)"

echo
echo "[CE2] every registered segment normal -> CONNECTED"
sm set ECHO-DEP normal "reset" --force >/dev/null 2>&1
sm set OTHER normal "reset" --force >/dev/null 2>&1
assert_eq "CE2" "CONNECTED" "$(ce assess)"

echo
echo "[CE3] the one registered segment a worker depends on is isolated, others normal -> DEGRADED"
sm set ECHO-DEP suspicious "setup" --force >/dev/null 2>&1
sm set ECHO-DEP isolated "setup" --force >/dev/null 2>&1
assert_eq "CE3" "DEGRADED" "$(ce assess)"

echo
echo "[CE4] every registered segment isolated -> OFFLINE"
sm set OTHER suspicious "setup" --force >/dev/null 2>&1
sm set OTHER isolated "setup" --force >/dev/null 2>&1
assert_eq "CE4" "OFFLINE" "$(ce assess)"

echo
echo "[CE5] Emergency Shutdown active -> OFFLINE regardless of segment status"
sm set ECHO-DEP normal "cleanup" --force >/dev/null 2>&1
sm set OTHER normal "cleanup" --force >/dev/null 2>&1
: > "$WAIO_SHUTDOWN_LOCK"
assert_eq "CE5" "OFFLINE" "$(ce assess)"
rm -f "$WAIO_SHUTDOWN_LOCK"
assert_eq "CE5 cleared -> CONNECTED again" "CONNECTED" "$(ce assess)"

# --- continuity_update_state: persistence + change-only audit events ---
echo
echo "--- continuity_update_state: persists + logs only on an actual change ---"

echo "[CE6] fresh state file defaults read as CONNECTED before any update()"
rm -f "$WAIO_CONTINUITY_STATE_FILE"
assert_eq "CE6" "CONNECTED" "$(ce state)"

echo
echo "[CE7] CONNECTED -> DEGRADED transition is persisted and logged as continuity_state_changed"
: > "$WAIO_CONTINUITY_AUDIT_LOG"
sm set ECHO-DEP suspicious "setup" --force >/dev/null 2>&1
sm set ECHO-DEP isolated "setup" --force >/dev/null 2>&1
UPD1="$(ce update)"
assert_eq "CE7 returned state" "DEGRADED" "$UPD1"
assert_eq "CE7 persisted state" "DEGRADED" "$(ce state)"
assert_contains "CE7 audit log has continuity_state_changed" "$(cat "$WAIO_CONTINUITY_AUDIT_LOG")" "continuity_state_changed"

echo
echo "[CE8] DEGRADED -> CONNECTED transition is logged as continuity_resync, not a generic state_changed"
: > "$WAIO_CONTINUITY_AUDIT_LOG"
sm set ECHO-DEP recovering "setup" --force >/dev/null 2>&1
sm set ECHO-DEP recovered "setup" --force >/dev/null 2>&1
sm set ECHO-DEP normal "recovered" >/dev/null 2>&1
UPD2="$(ce update)"
assert_eq "CE8 returned state" "CONNECTED" "$UPD2"
assert_contains "CE8 audit log has continuity_resync" "$(cat "$WAIO_CONTINUITY_AUDIT_LOG")" "continuity_resync"

echo
echo "[CE9] repeated update() with no change logs nothing new"
: > "$WAIO_CONTINUITY_AUDIT_LOG"
ce update >/dev/null
EVT_COUNT="$(wc -l < "$WAIO_CONTINUITY_AUDIT_LOG" | tr -d ' ')"
assert_eq "CE9 no audit line written for a no-op update" "0" "$EVT_COUNT"

# --- worker-dependency cross-reference ------------------------------
echo
echo "--- continuity_worker_dependency_status / continuity_is_degraded ---"

echo "[CE10] a worker with no matching segments.conf entry reads as unmonitored, not normal"
assert_eq "CE10" "unmonitored" "$(ce dep-status BOGUS_WORKER)"

echo
echo "[CE11] ECHO's dependency currently normal -> continuity_is_degraded is false"
source security/continuity.sh
if continuity_is_degraded ECHO; then
  FAIL=$((FAIL + 1)); FAILURES+=("CE11"); echo "  FAIL: CE11 (expected not degraded)"
else
  PASS=$((PASS + 1)); echo "  PASS: CE11"
fi

echo
echo "[CE12] ECHO's dependency isolated -> continuity_is_degraded is true; suspicious (unconfirmed) is still false"
sm set ECHO-DEP suspicious "setup" --force >/dev/null 2>&1
if continuity_is_degraded ECHO; then
  FAIL=$((FAIL + 1)); FAILURES+=("CE12 suspicious"); echo "  FAIL: CE12 suspicious (expected not degraded on a single unconfirmed check)"
else
  PASS=$((PASS + 1)); echo "  PASS: CE12 suspicious"
fi
sm set ECHO-DEP isolated "confirmed" --force >/dev/null 2>&1
if continuity_is_degraded ECHO; then
  PASS=$((PASS + 1)); echo "  PASS: CE12 isolated"
else
  FAIL=$((FAIL + 1)); FAILURES+=("CE12 isolated"); echo "  FAIL: CE12 isolated (expected degraded)"
fi
sm set ECHO-DEP recovering "cleanup" --force >/dev/null 2>&1
sm set ECHO-DEP recovered "cleanup" --force >/dev/null 2>&1
sm set ECHO-DEP normal "cleanup" >/dev/null 2>&1

echo
echo "[CE13] a worker with two segments.conf entries reports the WORSE of the two"
cat > "$FIXTURE_DIR/segments_multi.conf" <<EOF
MULTI-A|127.0.0.1|$LISTEN_PORT|MULTIDEP|fixture dependency A
MULTI-B|127.0.0.1|$UNREACHABLE_PORT|MULTIDEP|fixture dependency B
EOF
SEGMENT_MANAGER_CONF="$FIXTURE_DIR/segments_multi.conf" sm set MULTI-A normal "reset" --force >/dev/null 2>&1
SEGMENT_MANAGER_CONF="$FIXTURE_DIR/segments_multi.conf" sm set MULTI-B suspicious "setup" --force >/dev/null 2>&1
SEGMENT_MANAGER_CONF="$FIXTURE_DIR/segments_multi.conf" sm set MULTI-B isolated "setup" --force >/dev/null 2>&1
assert_eq "CE13" "isolated" "$(SEGMENT_MANAGER_CONF="$FIXTURE_DIR/segments_multi.conf" ce dep-status MULTIDEP)"
SEGMENT_MANAGER_CONF="$FIXTURE_DIR/segments_multi.conf" sm set MULTI-B recovering "cleanup" --force >/dev/null 2>&1
SEGMENT_MANAGER_CONF="$FIXTURE_DIR/segments_multi.conf" sm set MULTI-B recovered "cleanup" --force >/dev/null 2>&1
SEGMENT_MANAGER_CONF="$FIXTURE_DIR/segments_multi.conf" sm set MULTI-B normal "cleanup" >/dev/null 2>&1

# --- Context Cache ---------------------------------------------------
echo
echo "--- Context Cache: put/get/age, and the secret_leak_check refusal ---"

echo "[CE14] a worker with no cache entry yet: get returns nothing, exit 1"
OUT_CE14="$(continuity_cache_get NEVER_CACHED 2>&1)"; RC_CE14=$?
assert_eq "CE14 exit code" "1" "$RC_CE14"
assert_eq "CE14 empty output" "" "$OUT_CE14"

echo
echo "[CE15] put then get round-trips the exact content, and age is a small non-negative integer"
continuity_cache_put ECHO "hello from CE15" >/dev/null 2>&1
assert_eq "CE15 content round-trips" "hello from CE15" "$(continuity_cache_get ECHO)"
AGE_CE15="$(continuity_cache_age_seconds ECHO)"
case "$AGE_CE15" in
  ''|*[!0-9]*) FAIL=$((FAIL + 1)); FAILURES+=("CE15 age"); echo "  FAIL: CE15 age not a plain non-negative integer: '$AGE_CE15'" ;;
  *) PASS=$((PASS + 1)); echo "  PASS: CE15 age is a plain non-negative integer ($AGE_CE15)" ;;
esac

echo
echo "[CE16] content shaped like a credential is refused -- never written, denial logged"
echo "       (secret_leak_check's own existing contract also trips Emergency Shutdown here,"
echo "       same as it would inside any worker -- this is not new PDC behavior, it is reused"
echo "       as-is; the fixture WAIO_SHUTDOWN_LOCK below is cleared immediately after so later"
echo "       end-to-end cases are unaffected)"
: > "$WAIO_CONTINUITY_AUDIT_LOG"
OUT_CE16="$(continuity_cache_put ECHO "sk-abcdefghijklmnopqrstuvwx" 2>&1)"; RC_CE16=$?
assert_eq "CE16 exit code (refused)" "1" "$RC_CE16"
assert_eq "CE16 cache unchanged (still CE15's content)" "hello from CE15" "$(continuity_cache_get ECHO)"
assert_contains "CE16 audit log has pdc_cache_write_denied" "$(cat "$WAIO_CONTINUITY_AUDIT_LOG")" "pdc_cache_write_denied"
assert_eq "CE16 secret_leak_check's existing contract also tripped the (fixture) Emergency Shutdown" "true" "$([ -f "$WAIO_SHUTDOWN_LOCK" ] && echo true || echo false)"
rm -f "$WAIO_SHUTDOWN_LOCK"

# --- State Snapshot ---------------------------------------------------
echo
echo "--- continuity_write_snapshot ---"
echo "[CE17] snapshot file is valid JSON with the expected top-level shape"
sm set ECHO-DEP normal "reset" --force >/dev/null 2>&1
sm set OTHER normal "reset" --force >/dev/null 2>&1
continuity_write_snapshot
SNAP_OK="$(python3 -c "
import json
try:
    d = json.load(open('$WAIO_CONTINUITY_SNAPSHOT_FILE'))
    need = {'generated_at','continuity_state','segments','policy_file_sha256'}
    print('true' if need.issubset(d.keys()) and len(d['segments']) == 2 else 'false')
except Exception:
    print('false')
")"
assert_eq "CE17" "true" "$SNAP_OK"

echo
echo "[CE18] .example template sanity: every non-comment PDC line added to segments.conf.example has all 5 required fields"
BAD_LINES=0
while IFS='|' read -r a_id a_host a_port a_worker a_label; do
  case "$a_id" in ""|\#*) continue ;; esac
  if [ -z "$a_id" ] || [ -z "$a_host" ] || [ -z "$a_port" ] || [ -z "$a_worker" ] || [ -z "$a_label" ]; then
    BAD_LINES=$((BAD_LINES + 1))
  fi
done < security/segments.conf.example
assert_eq "CE18 no malformed lines in the example template" "0" "$BAD_LINES"

# --- End-to-end via ./waio.sh -w ORCHESTRATE: ONLINE -> CACHE -> -----
# OFFLINE -> FALLBACK -> RECOVER/RESYNC -------------------------------
echo
echo "--- end-to-end: ONLINE -> CACHE -> OFFLINE -> FALLBACK -> RECOVER/RESYNC ---"

sm set ECHO-DEP normal "reset for e2e" --force >/dev/null 2>&1
: > "$WAIO_CONTINUITY_AUDIT_LOG"

echo "[E1] ONLINE, WAIO_PDC_CACHE unset: live dispatch, no cache write (default path unchanged)"
rm -f "$FIXTURE_DIR/continuity_cache/ECHO.json"
E1_OUT="$(WAIO_PIPELINE="ECHO" ./waio.sh -w ORCHESTRATE "e1 request" 2>&1)"
assert_contains "E1 live response reflects this request" "$E1_OUT" "e1 request"
assert_eq "E1 no cache file created (opt-in flag was not set)" "false" "$([ -f "$FIXTURE_DIR/continuity_cache/ECHO.json" ] && echo true || echo false)"

echo
echo "[E2] ONLINE, WAIO_PDC_CACHE=1: live dispatch, and its result is now cached"
E2_OUT="$(WAIO_PIPELINE="ECHO" WAIO_PDC_CACHE=1 ./waio.sh -w ORCHESTRATE "e2 request" 2>&1)"
assert_contains "E2 live response reflects this request" "$E2_OUT" "e2 request"
assert_eq "E2 cache file now exists" "true" "$([ -f "$FIXTURE_DIR/continuity_cache/ECHO.json" ] && echo true || echo false)"
assert_contains "E2 cached content is this request's own result" "$(continuity_cache_get ECHO)" "e2 request"

echo
echo "[E3] dependency goes OFFLINE (ECHO-DEP isolated) -- PDC's own state reflects it"
sm set ECHO-DEP suspicious "outage begins" --force >/dev/null 2>&1
sm set ECHO-DEP isolated "outage confirmed" --force >/dev/null 2>&1
assert_eq "E3 continuity_worker_dependency_status(ECHO)" "isolated" "$(continuity_worker_dependency_status ECHO)"
# Persist the DEGRADED state now (PREPARE's own job in real operation,
# security/continuity_prepare_cron.sh) so E8's RESYNC check below has an
# actual persisted transition to observe, not a same-value no-op.
assert_eq "E3 PDC state persists as DEGRADED (OTHER segment is still normal)" "DEGRADED" "$(ce update)"

echo
echo "[E4] OFFLINE, WAIO_PDC_FALLBACK unset (default): still attempts a live dispatch (ECHO itself has no real dependency, so it still succeeds, but PDC does not intervene) -- proves the default path is unchanged even while a segment is isolated"
E4_OUT="$(WAIO_PIPELINE="ECHO" ./waio.sh -w ORCHESTRATE "e4 request" 2>&1)"
assert_contains "E4 live response reflects this request (PDC did not intervene)" "$E4_OUT" "e4 request"
assert_not_contains "E4 no PDC FALLBACK log line without the opt-in flag" "$E4_OUT" "PDC FALLBACK"

echo
echo "[E5] OFFLINE, WAIO_PDC_FALLBACK=1: serves E2's cached result instead of a live dispatch"
E5_OUT="$(WAIO_PIPELINE="ECHO" WAIO_PDC_FALLBACK=1 ./waio.sh -w ORCHESTRATE "e5 request -- must not appear in the result" 2>&1)"
assert_contains "E5 log shows PDC FALLBACK was used" "$E5_OUT" "PDC FALLBACK"
assert_contains "E5 result is E2's cached content, not a live answer" "$E5_OUT" "e2 request"
assert_not_contains "E5 result does NOT reflect this run's own request (would only appear from a live dispatch)" "$E5_OUT" "e5 request -- must not appear"
assert_contains "E5 audit log recorded the fallback" "$(cat "$WAIO_CONTINUITY_AUDIT_LOG")" "pdc_cache_fallback"

echo
echo "[E6] OFFLINE, WAIO_PDC_FALLBACK=1 AND WAIO_PDC_CACHE=1 together: a served-from-cache result is not re-cached (its age is preserved, not reset)"
AGE_BEFORE="$(continuity_cache_age_seconds ECHO)"
sleep 1.1
WAIO_PIPELINE="ECHO" WAIO_PDC_FALLBACK=1 WAIO_PDC_CACHE=1 ./waio.sh -w ORCHESTRATE "e6 request" >/dev/null 2>&1
AGE_AFTER="$(continuity_cache_age_seconds ECHO)"
if [ "$AGE_AFTER" -ge "$AGE_BEFORE" ]; then
  PASS=$((PASS + 1)); echo "  PASS: E6 cache age kept advancing (not reset by a fallback-served run) before=$AGE_BEFORE after=$AGE_AFTER"
else
  FAIL=$((FAIL + 1)); FAILURES+=("E6"); echo "  FAIL: E6 cache age went backwards (before=$AGE_BEFORE after=$AGE_AFTER) -- a fallback result was wrongly re-cached"
fi

echo
echo "[E7] RECOVER: security/recovery_engine.sh (Phase 49, unmodified) is reused as-is to bring the dependency back"
source security/health_checker.sh
source security/recovery_engine.sh
load_segments
RE_OUT="$(recover_segment ECHO-DEP reconnect --execute 2>&1)"; RE_RC=$?
assert_eq "E7 recovery succeeds against the reachable fixture listener" "0" "$RE_RC"
assert_eq "E7 segment now recovered" "recovered" "$(sm status ECHO-DEP)"
sm set ECHO-DEP normal "incident closed" >/dev/null 2>&1

echo
echo "[E8] RESYNC: continuity_update_state observes the recovery and logs continuity_resync"
: > "$WAIO_CONTINUITY_AUDIT_LOG"
ce update >/dev/null
assert_eq "E8 PDC state back to CONNECTED" "CONNECTED" "$(ce state)"
assert_contains "E8 audit log has continuity_resync" "$(cat "$WAIO_CONTINUITY_AUDIT_LOG")" "continuity_resync"

echo
echo "[E9] OPERATE resumes normally: a fresh request after RESYNC gets a live answer again, not a stale cache hit"
E9_OUT="$(WAIO_PIPELINE="ECHO" WAIO_PDC_FALLBACK=1 ./waio.sh -w ORCHESTRATE "e9 request" 2>&1)"
assert_contains "E9 live response reflects this request" "$E9_OUT" "e9 request"
assert_not_contains "E9 no PDC FALLBACK line (dependency is normal again)" "$E9_OUT" "PDC FALLBACK"

echo
echo "=== Summary: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
  echo "Failures:"
  for f in "${FAILURES[@]}"; do echo "  - $f"; done
  exit 1
fi
exit 0
