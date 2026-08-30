#!/bin/bash
set -uo pipefail

# Phase 17: automated regression suite for workers/orchestrate_worker.sh.
#
# Codifies the manual regression cases already run and documented in
# ARCHITECTURE.md for Phase 7-16/19. Exercises the real ./waio.sh -w
# ORCHESTRATE entry point exactly as a human operator would -- no mocking,
# no stubbing, no changes to orchestrate_worker.sh/waio.sh/registry.conf/
# pipeline.conf. A run's logs/results files land in logs/ and results/
# exactly like any other run (gitignored, not cleaned up here, same as
# every manual verification before this phase).
#
# Two tiers, kept deliberately separate:
#   Tier 1 (always runs) -- ECHO and BOGUS (deliberately unregistered)
#     only. Both are pure bash, no network, no credentials -- portable to
#     any environment with bash + python3 (what orchestrate_worker.sh
#     itself already requires). Covers Phase 7-16/19's flat, parallel,
#     concurrency-cap, and branching regression cases.
#   Tier 2 (skipped, not failed, if unreachable) -- adds the real
#     HOST800 worker (workers/host800_worker.sh, real SSH to
#     workers/800.json's host) for the cases that specifically need a
#     second, distinguishable real worker: parallel merge-order
#     determinism and Router multi-match. This only runs on a network
#     that can actually reach 800号機 (this machine's LAN) -- a
#     preflight TCP check decides whether to attempt it.
#
# Deliberately NOT automated, and not attempted here: anything that
# dispatches RESEARCH/ANALYSIS/AI/HEALTHCHECK (all require
# TAKOMACHI_API_KEY from macOS Keychain, which -- per the Takomachi
# integration phase's own finding, still true today -- only succeeds
# from an interactive GUI Terminal session, not this or any
# non-interactive/scripted shell). That includes the Router "fallback"
# path's full execution (workers/pipeline.conf's default pipeline is
# RESEARCH/ANALYSIS/AI) and any HEALTHCHECK-based case. Those remain
# manually verified only, exactly as every prior phase's ARCHITECTURE.md
# entry already documents.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"

PASS=0
FAIL=0
SKIP=0
declare -a FAILURES=()

assert_eq() {
  # assert_eq "label" "expected" "actual"
  local label="$1" expected="$2" actual="$3"
  if [ "$expected" = "$actual" ]; then
    PASS=$((PASS + 1))
    echo "  PASS: $label"
  else
    FAIL=$((FAIL + 1))
    FAILURES+=("$label (expected='$expected' actual='$actual')")
    echo "  FAIL: $label (expected='$expected' actual='$actual')"
  fi
}

assert_contains() {
  # assert_contains "label" "haystack" "needle"
  local label="$1" haystack="$2" needle="$3"
  if [[ "$haystack" == *"$needle"* ]]; then
    PASS=$((PASS + 1))
    echo "  PASS: $label"
  else
    FAIL=$((FAIL + 1))
    FAILURES+=("$label (expected to contain '$needle')")
    echo "  FAIL: $label (expected to contain '$needle')"
  fi
}

assert_not_contains() {
  # assert_not_contains "label" "haystack" "needle"
  local label="$1" haystack="$2" needle="$3"
  if [[ "$haystack" != *"$needle"* ]]; then
    PASS=$((PASS + 1))
    echo "  PASS: $label"
  else
    FAIL=$((FAIL + 1))
    FAILURES+=("$label (expected NOT to contain '$needle')")
    echo "  FAIL: $label (expected NOT to contain '$needle')"
  fi
}

skip_case() {
  # skip_case "label" "reason"
  SKIP=$((SKIP + 1))
  echo "  SKIP: $1 ($2)"
}

# Runs ./waio.sh -w ORCHESTRATE "<request>" and sets OUT/RC/JSON_PATH.
# Any WAIO_PIPELINE/WAIO_MAX_PARALLEL must already be exported by the
# caller (e.g. "WAIO_PIPELINE=ECHO run_orchestrate '...'").
run_orchestrate() {
  OUT="$(./waio.sh -w ORCHESTRATE "$1" 2>&1)"
  RC=$?
  JSON_PATH="$(printf '%s\n' "$OUT" | grep -o 'results/orchestrate-[0-9-]*\.json' | head -1)"
}

echo "=== Tier 1: ECHO/BOGUS only (portable, no network/Keychain) ==="

echo "--- Phase 7-9: flat sequential pipeline ---"

echo "[T1] single-stage override, success"
WAIO_PIPELINE="ECHO" run_orchestrate "t1 request"
assert_eq "T1 exit code" "0" "$RC"
assert_contains "T1 log has overall_status=ok" "$OUT" "overall_status=ok"

echo "[T2] mid-pipeline failure, last stage recovers"
WAIO_PIPELINE="ECHO BOGUS ECHO" run_orchestrate "t2 request"
assert_eq "T2 exit code" "1" "$RC"
assert_contains "T2 overall_status=degraded" "$OUT" "overall_status=degraded"
assert_contains "T2 FAILURE HANDLING logged" "$OUT" "FAILURE HANDLING"

echo "[T3] sole/last-stage failure"
WAIO_PIPELINE="BOGUS" run_orchestrate "t3 request"
assert_eq "T3 exit code" "2" "$RC"
assert_contains "T3 overall_status=failed" "$OUT" "overall_status=failed"

echo "[T4] self-reference guard, flat pipeline"
WAIO_PIPELINE="ECHO ORCHESTRATE" run_orchestrate "t4 request"
assert_eq "T4 exit code" "1" "$RC"
assert_contains "T4 refuses to recurse" "$OUT" "would recurse, refusing to run"

echo "[T5] empty request, direct script invocation"
DIRECT_OUT="$(./workers/orchestrate_worker.sh "" 2>&1)"
DIRECT_RC=$?
assert_eq "T5 exit code" "1" "$DIRECT_RC"
assert_contains "T5 empty request error" "$DIRECT_OUT" "empty request"

echo "--- Phase 13: parallel stages (fan-out/fan-in) ---"

echo "[T6] 2-member parallel group, all succeed"
WAIO_PIPELINE="ECHO+ECHO ECHO" run_orchestrate "t6 request"
assert_eq "T6 exit code" "0" "$RC"
assert_contains "T6 overall_status=ok" "$OUT" "overall_status=ok"
assert_contains "T6 parallel group logged" "$OUT" "parallel group, 2 members"

echo "[T7] parallel partial failure, not in the last group"
WAIO_PIPELINE="ECHO+BOGUS ECHO" run_orchestrate "t7 request"
assert_eq "T7 exit code" "1" "$RC"
assert_contains "T7 overall_status=degraded" "$OUT" "overall_status=degraded"

echo "[T8] parallel failure inside the last group"
WAIO_PIPELINE="ECHO ECHO+BOGUS" run_orchestrate "t8 request"
assert_eq "T8 exit code" "2" "$RC"
assert_contains "T8 overall_status=failed" "$OUT" "overall_status=failed"

echo "[T9] self-reference guard inside a group"
WAIO_PIPELINE="ECHO+ORCHESTRATE" run_orchestrate "t9 request"
assert_eq "T9 exit code" "1" "$RC"
assert_contains "T9 refuses to recurse" "$OUT" "would recurse, refusing to run"

echo "--- Phase 15: parallel group concurrency cap ---"

echo "[T10] 3-member group, cap 2 (batched)"
WAIO_PIPELINE="ECHO+ECHO+ECHO" WAIO_MAX_PARALLEL=2 run_orchestrate "t10 request"
assert_eq "T10 exit code" "0" "$RC"
assert_contains "T10 cap logged" "$OUT" "max 2 concurrent"

echo "[T11] cap of 1 (fully sequential within the group)"
WAIO_PIPELINE="ECHO+ECHO" WAIO_MAX_PARALLEL=1 run_orchestrate "t11 request"
assert_eq "T11 exit code" "0" "$RC"
assert_contains "T11 cap logged" "$OUT" "max 1 concurrent"

echo "[T12] cap larger than the group (no visible cap)"
WAIO_PIPELINE="ECHO+ECHO" WAIO_MAX_PARALLEL=10 run_orchestrate "t12 request"
assert_eq "T12 exit code" "0" "$RC"
assert_not_contains "T12 no 'max N concurrent' text" "$OUT" "max 10 concurrent"

echo "[T13] invalid WAIO_MAX_PARALLEL (non-numeric)"
WAIO_PIPELINE="ECHO" WAIO_MAX_PARALLEL=abc run_orchestrate "t13 request"
assert_eq "T13 exit code" "1" "$RC"
assert_contains "T13 rejected before running" "$OUT" "must be a positive integer"

echo "[T14] invalid WAIO_MAX_PARALLEL (zero)"
WAIO_PIPELINE="ECHO" WAIO_MAX_PARALLEL=0 run_orchestrate "t14 request"
assert_eq "T14 exit code" "1" "$RC"
assert_contains "T14 rejected before running" "$OUT" "must be a positive integer"

echo "[T15] failure inside a capped batch"
WAIO_PIPELINE="ECHO+BOGUS+ECHO" WAIO_MAX_PARALLEL=2 run_orchestrate "t15 request"
assert_eq "T15 exit code" "2" "$RC"
assert_contains "T15 overall_status=failed" "$OUT" "overall_status=failed"

echo "--- Phase 16: branching stages (?ok:/?fail:) ---"

echo "[T16] ?ok: runs after a success"
WAIO_PIPELINE="ECHO ?ok:ECHO" run_orchestrate "t16 request"
assert_eq "T16 exit code" "0" "$RC"
assert_contains "T16 condition met" "$OUT" "condition met"
assert_contains "T16 overall_status=ok" "$OUT" "overall_status=ok"

echo "[T17] ?fail: skipped after a success"
WAIO_PIPELINE="ECHO ?fail:ECHO" run_orchestrate "t17 request"
assert_eq "T17 exit code" "0" "$RC"
assert_contains "T17 stage skipped" "$OUT" "skipped"
assert_contains "T17 overall_status=ok" "$OUT" "overall_status=ok"

echo "[T18] ?fail: runs after a failure"
WAIO_PIPELINE="BOGUS ?fail:ECHO" run_orchestrate "t18 request"
assert_eq "T18 exit code" "1" "$RC"
assert_contains "T18 overall_status=degraded" "$OUT" "overall_status=degraded"

echo "[T19] ?ok: skipped after a failure"
WAIO_PIPELINE="BOGUS ?ok:ECHO" run_orchestrate "t19 request"
assert_eq "T19 exit code" "2" "$RC"
assert_contains "T19 overall_status=failed" "$OUT" "overall_status=failed"

echo "[T20] all-skipped pipeline is a configuration error"
BEFORE_COUNT="$(ls results/orchestrate-*.json 2>/dev/null | wc -l | tr -d ' ')"
WAIO_PIPELINE="?fail:ECHO" run_orchestrate "t20 request"
AFTER_COUNT="$(ls results/orchestrate-*.json 2>/dev/null | wc -l | tr -d ' ')"
assert_eq "T20 exit code" "1" "$RC"
assert_contains "T20 error message" "$OUT" "every stage was skipped"
assert_eq "T20 no new result files written" "$BEFORE_COUNT" "$AFTER_COUNT"

echo "[T21] unknown condition prefix rejected"
WAIO_PIPELINE="?maybe:ECHO" run_orchestrate "t21 request"
assert_eq "T21 exit code" "1" "$RC"
assert_contains "T21 rejected before running" "$OUT" "unknown condition prefix"

echo "[T22] empty stage after a condition prefix rejected"
WAIO_PIPELINE="?ok:" run_orchestrate "t22 request"
assert_eq "T22 exit code" "1" "$RC"
assert_contains "T22 rejected before running" "$OUT" "empty stage after its condition prefix"

echo "[T23] self-reference guard inside a conditional group"
WAIO_PIPELINE="?ok:ECHO+ORCHESTRATE" run_orchestrate "t23 request"
assert_eq "T23 exit code" "1" "$RC"
assert_contains "T23 refuses to recurse" "$OUT" "would recurse, refusing to run"

echo "[T24] first-executed stage gets the bare request after a leading skip"
WAIO_PIPELINE="?fail:ECHO ECHO" run_orchestrate "t24 raw request marker"
assert_eq "T24 exit code" "0" "$RC"
assert_contains "T24 bare request reached the worker" "$OUT" "received: t24 raw request marker"
assert_not_contains "T24 no 'Original request:' wrapper" "$OUT" "Original request: t24 raw request marker"

echo "[T25] branching composed with a parallel group"
WAIO_PIPELINE="BOGUS ?fail:ECHO+ECHO" run_orchestrate "t25 request"
assert_eq "T25 exit code" "1" "$RC"
assert_contains "T25 overall_status=degraded" "$OUT" "overall_status=degraded"
assert_contains "T25 condition met group ran" "$OUT" "condition met"

echo "--- Phase 19: empty-member guard (stray '+' in a group) ---"

echo "[P19-1] doubled '+' produces an empty member, rejected before running"
WAIO_PIPELINE="ECHO++BOGUS" run_orchestrate "p19-1 request"
assert_eq "P19-1 exit code" "1" "$RC"
assert_contains "P19-1 rejected before running" "$OUT" "empty member (stray '+')"

echo "[P19-2] leading '+' produces an empty member, rejected before running"
WAIO_PIPELINE="+ECHO" run_orchestrate "p19-2 request"
assert_eq "P19-2 exit code" "1" "$RC"
assert_contains "P19-2 rejected before running" "$OUT" "empty member (stray '+')"

echo "[P19-3] a bare '+' alone, rejected before running"
WAIO_PIPELINE="+" run_orchestrate "p19-3 request"
assert_eq "P19-3 exit code" "1" "$RC"
assert_contains "P19-3 rejected before running" "$OUT" "empty member (stray '+')"

echo "[P19-4] trailing '+' is harmlessly tolerated (unchanged pre-existing IFS behavior, group of 1)"
WAIO_PIPELINE="ECHO+" run_orchestrate "p19-4 request"
assert_eq "P19-4 exit code" "0" "$RC"
assert_contains "P19-4 overall_status=ok" "$OUT" "overall_status=ok"

echo "--- JSON result integrity (Phase 8, extended by Phase 13/15/16) ---"

echo "[T26] JSON result is well-formed and has the expected stage shape"
WAIO_PIPELINE="ECHO" run_orchestrate "t26 request"
if [ -n "$JSON_PATH" ] && [ -f "$JSON_PATH" ]; then
  if python3 -c "
import json, sys
d = json.load(open('$JSON_PATH'))
s = d['stages'][0]
assert s['name'] == 'ECHO'
assert s['status'] == 'ok'
assert s['exit_code'] == 0
assert s['step'] == 1
assert isinstance(s['result'], str)
" 2>/tmp/t26_err.log; then
    PASS=$((PASS + 1))
    echo "  PASS: T26 JSON shape"
  else
    FAIL=$((FAIL + 1))
    FAILURES+=("T26 JSON shape ($(cat /tmp/t26_err.log))")
    echo "  FAIL: T26 JSON shape ($(cat /tmp/t26_err.log))"
  fi
else
  FAIL=$((FAIL + 1))
  FAILURES+=("T26 JSON path not found in output")
  echo "  FAIL: T26 JSON path not found in output"
fi

echo "[T27] skipped stage serializes exit_code as JSON null"
WAIO_PIPELINE="ECHO ?fail:ECHO" run_orchestrate "t27 request"
if [ -n "$JSON_PATH" ] && [ -f "$JSON_PATH" ]; then
  if python3 -c "
import json
d = json.load(open('$JSON_PATH'))
skipped = [s for s in d['stages'] if s['status'] == 'skipped']
assert len(skipped) == 1, skipped
assert skipped[0]['exit_code'] is None, skipped[0]
assert skipped[0]['result'] == '', skipped[0]
" 2>/tmp/t27_err.log; then
    PASS=$((PASS + 1))
    echo "  PASS: T27 skipped entry shape"
  else
    FAIL=$((FAIL + 1))
    FAILURES+=("T27 skipped entry shape ($(cat /tmp/t27_err.log))")
    echo "  FAIL: T27 skipped entry shape ($(cat /tmp/t27_err.log))"
  fi
else
  FAIL=$((FAIL + 1))
  FAILURES+=("T27 JSON path not found in output")
  echo "  FAIL: T27 JSON path not found in output"
fi
rm -f /tmp/t26_err.log /tmp/t27_err.log

echo
echo "=== Tier 2: real HOST800 SSH (this machine's LAN only, skipped elsewhere) ==="

HOST800_AVAILABLE="false"
HOST800_IP="$(python3 -c 'import json; print(json.load(open("workers/800.json"))["host"])' 2>/dev/null || true)"
if [ -n "$HOST800_IP" ] && command -v nc >/dev/null 2>&1 && nc -z -w 2 "$HOST800_IP" 22 2>/dev/null; then
  HOST800_AVAILABLE="true"
fi

if [ "$HOST800_AVAILABLE" != "true" ]; then
  skip_case "T28 parallel group with a real second worker" "no LAN access to 800号機 ($HOST800_IP:22)"
  skip_case "T29 parallel merge-order determinism" "no LAN access to 800号機 ($HOST800_IP:22)"
  skip_case "T30 Router multi-match" "no LAN access to 800号機 ($HOST800_IP:22)"
else
  echo "[T28] 2-member parallel group with a real, distinguishable second worker"
  WAIO_PIPELINE="ECHO+HOST800 ECHO" run_orchestrate "t28 system check"
  assert_eq "T28 exit code" "0" "$RC"
  assert_contains "T28 overall_status=ok" "$OUT" "overall_status=ok"

  echo "[T29] parallel merge order follows group-token order, not completion order"
  ORDER_MATCH="true"
  for _ in 1 2; do
    WAIO_PIPELINE="HOST800+ECHO" run_orchestrate "t29 system check"
    FIRST_LABEL="$(printf '%s\n' "$OUT" | grep -oE "^(ECHO|HOST800) \(ok\):" | head -1)"
    if [ "$FIRST_LABEL" != "HOST800 (ok):" ]; then
      ORDER_MATCH="false"
    fi
  done
  assert_eq "T29 merge order is token order across repeated runs" "true" "$ORDER_MATCH"

  echo "[T30] Router multi-match (ECHO + HOST800 keywords, no override)"
  run_orchestrate "t30 please ECHO and check HOST800 system status"
  assert_eq "T30 exit code" "0" "$RC"
  assert_contains "T30 TASK CLASSIFICATION: multi" "$OUT" "TASK CLASSIFICATION: multi"
fi

echo
echo "=== Summary: $PASS passed, $FAIL failed, $SKIP skipped ==="
if [ "$FAIL" -gt 0 ]; then
  echo "Failures:"
  for f in "${FAILURES[@]}"; do
    echo "  - $f"
  done
  exit 1
fi
exit 0
