#!/bin/bash
set -uo pipefail

# tests/continuity_guardian_containment_test.sh -- WAIO/PDC "Jamming
# Resilience" containment validation (Phase 89).
#
# Proves the full Detect -> Disconnect -> Local Fallback -> Decide ->
# Contain -> Operate -> Recover -> Resync narrative end-to-end, through
# the real ./waio.sh entry point, by chaining two already-shipped,
# already-independently-tested subsystems that had never been exercised
# together before this suite:
#   - WAIO Pre-Disconnect Cache (PDC), security/continuity.sh (Phase 87)
#     -- see tests/continuity_engine_test.sh, whose fixture pattern and
#     E1-E9 end-to-end sequence this file reuses verbatim and extends.
#   - The DuCoPA Guardian Control Plane's containment gate,
#     security/guardian.sh -- see tests/ducopa_guardian_test.sh (its G20
#     and G24 cases: guardian_quarantine_agent/guardian_release_agent/
#     guardian_is_quarantined, and waio.sh refusing dispatch to a
#     quarantined agent), whose guardian_call helper and quarantine/
#     release idiom this file reuses verbatim.
#
# This suite adds NO new production code and changes no existing file:
# it only proves, through fixtures, something the code already does --
# that workers/orchestrate_worker.sh's PDC fallback branch (see its own
# comments around WAIO_PDC_FALLBACK) writes a cached result and
# `continue`s BEFORE ever reaching its live ./waio.sh -w "$m" dispatch
# line, so a cache-served fallback structurally never invokes a
# quarantined worker -- containment and fallback are safe together by
# construction, not by any new integration code.
#
# Same isolation posture as both suites it borrows from: everything
# here runs against scratch fixtures under a temp dir (never this
# deployment's real security/segments.conf, security/state/, or any
# real audit log), a loopback listener stands in for a reachable
# dependency and 127.0.0.1:1 for an unreachable one, and Guardian is
# driven by direct function calls -- no real SSH, no real remote host.
# The only real, un-fixtured entry points exercised are ./waio.sh -w
# ORCHESTRATE and ./waio.sh -w ECHO, both dispatching only to
# workers/echo_worker.sh (pure bash, no network, no credentials).

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

# --- fixture sandbox. Same pattern as tests/continuity_engine_test.sh. ---
FIXTURE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/waio-continuity-guardian-test.XXXXXX")"
trap 'rm -rf "$FIXTURE_DIR"; [ -n "${LISTENER_PID:-}" ] && kill "$LISTENER_PID" 2>/dev/null; true' EXIT

mkdir -p "$FIXTURE_DIR/segments_state" "$FIXTURE_DIR/continuity_state" "$FIXTURE_DIR/continuity_cache"

# A local loopback listener stands in for a "reachable" dependency;
# 127.0.0.1:1 (nothing listens there) stands in for an unreachable one
# -- same technique as tests/continuity_engine_test.sh, no real network
# or remote host involved either way.
LISTEN_PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')"
python3 -m http.server "$LISTEN_PORT" --bind 127.0.0.1 >/dev/null 2>&1 &
LISTENER_PID=$!
sleep 0.3

cat > "$FIXTURE_DIR/segments.conf" <<EOF
ECHO-DEP|127.0.0.1|$LISTEN_PORT|ECHO|fixture dependency for the ECHO worker (PDC+Guardian containment test)
OTHER|127.0.0.1|$LISTEN_PORT|SOMETHING_ELSE|unrelated fixture segment
EOF

# --- isolation: every real state/audit-log/lock path this test's call
# chain could touch is redirected under FIXTURE_DIR -- same variables
# tests/continuity_engine_test.sh already establishes this pattern
# with, exported so the real ./waio.sh subprocesses used below inherit
# them too. ------------------------------------------------------------
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
# guardian_call -- same idiom as tests/ducopa_guardian_test.sh: runs a
# Guardian function in a fresh subshell that sources security/lib.sh
# (which sources security/guardian.sh), so every call sees this
# fixture's exported WAIO_GUARDIAN_* paths exactly as a real worker or
# waio.sh invocation would.
guardian_call() {
  bash -c 'source security/lib.sh; "$@"' _ "$@"
}

source security/continuity.sh

echo "=== WAIO/PDC Jamming Resilience: PDC + Guardian containment end-to-end ==="
echo

sm set ECHO-DEP normal "reset for containment e2e" --force >/dev/null 2>&1
: > "$WAIO_CONTINUITY_AUDIT_LOG"

echo "[C1] PREPARE: ONLINE dispatch with WAIO_PDC_CACHE=1 caches ECHO's latest known-good result"
C1_OUT="$(WAIO_PIPELINE="ECHO" WAIO_PDC_CACHE=1 ./waio.sh -w ORCHESTRATE "c1 request" 2>&1)"
assert_contains "C1 live response reflects this request" "$C1_OUT" "c1 request"
assert_contains "C1 cached content is this request's own result" "$(continuity_cache_get ECHO)" "c1 request"

echo
echo "[C2] Detect / Disconnect: ECHO-DEP goes isolated, PDC state reflects DEGRADED"
sm set ECHO-DEP suspicious "outage begins" --force >/dev/null 2>&1
sm set ECHO-DEP isolated "outage confirmed" --force >/dev/null 2>&1
assert_eq "C2 continuity_worker_dependency_status(ECHO)" "isolated" "$(continuity_worker_dependency_status ECHO)"
assert_eq "C2 PDC state persists as DEGRADED" "DEGRADED" "$(ce update)"

echo
echo "[C3] Decide / Contain: Guardian quarantines ECHO -- containment is real and independent of PDC"
assert_eq "C3 ECHO not quarantined yet" "false" "$(guardian_call guardian_is_quarantined "ECHO" >/dev/null 2>&1 && echo true || echo false)"
guardian_call guardian_quarantine_agent "ECHO" "c3 anomalous behavior observed during outage" "c3run" >/dev/null
assert_eq "C3 ECHO now quarantined" "true" "$(guardian_call guardian_is_quarantined "ECHO" >/dev/null 2>&1 && echo true || echo false)"
C3_OUT="$(./waio.sh -w ECHO "should be refused" 2>&1)"; C3_RC=$?
assert_eq "C3 direct dispatch to quarantined ECHO refused, exit 1" "1" "$C3_RC"
assert_contains "C3 refusal message mentions quarantine" "$C3_OUT" "quarantined"
assert_contains "C3 audit log recorded guardian_dispatch_blocked" "$(cat "$WAIO_AUDIT_LOG")" "guardian_dispatch_blocked"

echo
echo "[C4] Operate: PDC fallback keeps serving ORCHESTRATE from cache WITHOUT ever calling the quarantined worker"
BLOCKED_COUNT_BEFORE="$(grep -c "guardian_dispatch_blocked" "$WAIO_AUDIT_LOG" 2>/dev/null || echo 0)"
: > "$WAIO_CONTINUITY_AUDIT_LOG"
C4_OUT="$(WAIO_PIPELINE="ECHO" WAIO_PDC_FALLBACK=1 ./waio.sh -w ORCHESTRATE "c4 request -- must not appear in the result" 2>&1)"
assert_contains "C4 log shows PDC FALLBACK was used" "$C4_OUT" "PDC FALLBACK"
assert_contains "C4 result is C1's cached content, not a live answer" "$C4_OUT" "c1 request"
assert_not_contains "C4 result does NOT reflect this run's own request" "$C4_OUT" "c4 request -- must not appear"
assert_contains "C4 audit log recorded the fallback" "$(cat "$WAIO_CONTINUITY_AUDIT_LOG")" "pdc_cache_fallback"
BLOCKED_COUNT_AFTER="$(grep -c "guardian_dispatch_blocked" "$WAIO_AUDIT_LOG" 2>/dev/null || echo 0)"
assert_eq "C4 no NEW guardian_dispatch_blocked event (fallback never reached the quarantined worker)" "$BLOCKED_COUNT_BEFORE" "$BLOCKED_COUNT_AFTER"

echo
echo "[C5] Recover: Guardian releases ECHO, then security/recovery_engine.sh (unmodified) restores reachability"
guardian_call guardian_release_agent "ECHO" "c5 incident investigated, confirmed safe to release" "c5run" >/dev/null
assert_eq "C5 ECHO released" "false" "$(guardian_call guardian_is_quarantined "ECHO" >/dev/null 2>&1 && echo true || echo false)"
source security/health_checker.sh
source security/recovery_engine.sh
load_segments
RE_OUT="$(recover_segment ECHO-DEP reconnect --execute 2>&1)"; RE_RC=$?
assert_eq "C5 recovery succeeds against the reachable fixture listener" "0" "$RE_RC"
assert_eq "C5 segment now recovered" "recovered" "$(sm status ECHO-DEP)"
sm set ECHO-DEP normal "incident closed" >/dev/null 2>&1

echo
echo "[C6] Resync: continuity_update_state observes the recovery and logs continuity_resync"
: > "$WAIO_CONTINUITY_AUDIT_LOG"
ce update >/dev/null
assert_eq "C6 PDC state back to CONNECTED" "CONNECTED" "$(ce state)"
assert_contains "C6 audit log has continuity_resync" "$(cat "$WAIO_CONTINUITY_AUDIT_LOG")" "continuity_resync"

echo
echo "[C7] Operate resumes fully: both independent gates (connectivity, containment) are clear"
C7_OUT="$(WAIO_PIPELINE="ECHO" WAIO_PDC_FALLBACK=1 ./waio.sh -w ORCHESTRATE "c7 request" 2>&1)"
assert_contains "C7 live response reflects this request" "$C7_OUT" "c7 request"
assert_not_contains "C7 no PDC FALLBACK line (dependency is normal again)" "$C7_OUT" "PDC FALLBACK"
C7_DIRECT_OUT="$(./waio.sh -w ECHO "c7 direct dispatch" 2>&1)"; C7_DIRECT_RC=$?
assert_eq "C7 direct dispatch to the now-released ECHO succeeds, exit 0" "0" "$C7_DIRECT_RC"
assert_contains "C7 direct dispatch actually ran live" "$C7_DIRECT_OUT" "c7 direct dispatch"

echo
echo "=== Summary: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
  echo "Failures:"
  for f in "${FAILURES[@]}"; do echo "  - $f"; done
  exit 1
fi
exit 0
