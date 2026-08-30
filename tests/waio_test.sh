#!/bin/bash
set -uo pipefail

# Phase 22: automated regression suite for waio.sh, the canonical
# dispatch entry point (see ARCHITECTURE.md's "Canonical dispatch
# path"). Complements tests/orchestrate_worker_test.sh (Phase 17,
# extended by 19-21), which exercises orchestrate_worker.sh through
# waio.sh's -w ORCHESTRATE, not waio.sh's own dispatch/validation logic
# directly -- until this phase, waio.sh itself had no automated
# coverage of its own.
#
# Same conventions as tests/orchestrate_worker_test.sh: self-contained
# bash (no bats/shellspec, no shared helper file -- duplicating the
# small assertion helpers here keeps each test file independently
# runnable, matching that script's own stated design choice), no
# mocking, drives the real ./waio.sh entry point exactly as a human
# operator or orchestrate_worker.sh itself would.
#
# Scope: only Keychain-free paths (ECHO/BOGUS-only, same Tier-1
# boundary Phase 17 established for the other suite) -- dispatching to
# RESEARCH/ANALYSIS/AI/HEALTHCHECK is not exercised here for the same
# documented reason (TAKOMACHI_API_KEY from macOS Keychain, GUI
# Terminal only). No LAN-dependent Tier 2 here either: every case below
# is fully portable (bash only, no python3, no network).
#
# workers/registry.conf is briefly renamed aside for four cases (W9-W12)
# to reach paths not otherwise triggerable through its current real
# content (a missing/empty registry, an unsupported remote host, a
# missing worker script) -- guaranteed restored via an explicit restore
# immediately after each case plus a `trap ... EXIT` safety net, same
# idiom tests/orchestrate_worker_test.sh's own P20-1/P21-1 already
# established for workers/pipeline.conf.
#
# Phase 23 (W13-W14) extends this suite one layer further: a registered
# worker's OWN pre-flight guard clauses, specifically
# workers/host800_worker.sh's "unsupported job type" and "empty
# request" checks -- both run and reject before that worker ever
# attempts its real SSH call, so both are exercisable without any LAN
# access to 800号機 (unlike the Tier-2 system/identity cases in
# tests/orchestrate_worker_test.sh, which do need it). W14 calls
# workers/host800_worker.sh directly, the same way W6/T5 already bypass
# waio.sh's own empty-request check to reach a worker's own -- through
# waio.sh, an empty request never gets past waio.sh's check to reach
# any worker script at all.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"

PASS=0
FAIL=0
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

echo "=== waio.sh dispatch/validation (Keychain-free) ==="

echo "[W1] explicit -w override, valid worker"
OUT="$(./waio.sh -w ECHO "w1 request" 2>&1)"; RC=$?
assert_eq "W1 exit code" "0" "$RC"
assert_contains "W1 dispatched to ECHO" "$OUT" "dispatching to ECHO WORKER"

echo "[W2] --worker=NAME form"
OUT="$(./waio.sh --worker=ECHO "w2 request" 2>&1)"; RC=$?
assert_eq "W2 exit code" "0" "$RC"
assert_contains "W2 dispatched to ECHO" "$OUT" "dispatching to ECHO WORKER"

echo "[W3] --worker NAME form (space-separated)"
OUT="$(./waio.sh --worker ECHO "w3 request" 2>&1)"; RC=$?
assert_eq "W3 exit code" "0" "$RC"
assert_contains "W3 dispatched to ECHO" "$OUT" "dispatching to ECHO WORKER"

echo "[W4] -w with an unregistered worker name"
OUT="$(./waio.sh -w BOGUS "w4 request" 2>&1)"; RC=$?
assert_eq "W4 exit code" "1" "$RC"
assert_contains "W4 error text" "$OUT" "is not a registered worker"

echo "[W5] unknown CLI option"
OUT="$(./waio.sh --nonsense-flag "w5 request" 2>&1)"; RC=$?
assert_eq "W5 exit code" "1" "$RC"
assert_contains "W5 error text" "$OUT" "unknown option"

echo "[W6] empty request (no -w)"
OUT="$(./waio.sh "" 2>&1)"; RC=$?
assert_eq "W6 exit code" "1" "$RC"
assert_contains "W6 error text" "$OUT" "request required"

echo "[W7] keyword-based dispatch (no -w), single match"
OUT="$(./waio.sh "please ECHO this text" 2>&1)"; RC=$?
assert_eq "W7 exit code" "0" "$RC"
assert_contains "W7 dispatched via keyword match" "$OUT" "match=keyword"

echo "[W8] no keyword match, multiple workers registered"
OUT="$(./waio.sh "xyz nothing matches standard zzz probe" 2>&1)"; RC=$?
assert_eq "W8 exit code" "1" "$RC"
assert_contains "W8 error text" "$OUT" "no worker NAME/TYPE keyword matched"

echo "--- registry.conf error paths (briefly renamed aside, trap-guaranteed restore) ---"

echo "[W9] registry.conf missing entirely"
REGISTRY_PATH="workers/registry.conf"
REGISTRY_BACKUP="workers/registry.conf.phase22-test-backup.$$"
mv "$REGISTRY_PATH" "$REGISTRY_BACKUP"
trap 'mv -f "$REGISTRY_BACKUP" "$REGISTRY_PATH" 2>/dev/null' EXIT
OUT="$(./waio.sh -w ECHO "w9 request" 2>&1)"; RC=$?
mv "$REGISTRY_BACKUP" "$REGISTRY_PATH"
trap - EXIT
assert_eq "W9 exit code" "1" "$RC"
assert_contains "W9 error text" "$OUT" "registry not found"

echo "[W10] registry.conf present but empty"
mv "$REGISTRY_PATH" "$REGISTRY_BACKUP"
: > "$REGISTRY_PATH"
trap 'mv -f "$REGISTRY_BACKUP" "$REGISTRY_PATH" 2>/dev/null' EXIT
OUT="$(./waio.sh -w ECHO "w10 request" 2>&1)"; RC=$?
rm -f "$REGISTRY_PATH"
mv "$REGISTRY_BACKUP" "$REGISTRY_PATH"
trap - EXIT
assert_eq "W10 exit code" "1" "$RC"
assert_contains "W10 error text" "$OUT" "no workers registered"

echo "[W11] registered worker whose HOST is not '750' (unsupported remote target)"
mv "$REGISTRY_PATH" "$REGISTRY_BACKUP"
printf 'TESTREMOTE|999|workers/echo_worker.sh|test\n' > "$REGISTRY_PATH"
trap 'mv -f "$REGISTRY_BACKUP" "$REGISTRY_PATH" 2>/dev/null' EXIT
OUT="$(./waio.sh -w TESTREMOTE "w11 request" 2>&1)"; RC=$?
rm -f "$REGISTRY_PATH"
mv "$REGISTRY_BACKUP" "$REGISTRY_PATH"
trap - EXIT
assert_eq "W11 exit code" "1" "$RC"
assert_contains "W11 error text" "$OUT" "is not supported yet"

echo "[W12] registered worker pointing at a nonexistent script"
mv "$REGISTRY_PATH" "$REGISTRY_BACKUP"
printf 'TESTMISSING|750|workers/does_not_exist_phase22.sh|test\n' > "$REGISTRY_PATH"
trap 'mv -f "$REGISTRY_BACKUP" "$REGISTRY_PATH" 2>/dev/null' EXIT
OUT="$(./waio.sh -w TESTMISSING "w12 request" 2>&1)"; RC=$?
rm -f "$REGISTRY_PATH"
mv "$REGISTRY_BACKUP" "$REGISTRY_PATH"
trap - EXIT
assert_eq "W12 exit code" "1" "$RC"
assert_contains "W12 error text" "$OUT" "worker script not found or not executable"

echo "--- Phase 23: workers/host800_worker.sh's own pre-SSH guards ---"

echo "[W13] HOST800: unsupported job type (no 'system'/'identity' keyword) -- rejected before any SSH attempt"
OUT="$(./waio.sh -w HOST800 "nothing relevant here" 2>&1)"; RC=$?
assert_eq "W13 exit code" "1" "$RC"
assert_contains "W13 error text" "$OUT" "unsupported job type in request"

echo "[W14] HOST800: empty request, direct script invocation (waio.sh's own empty-request check -- W6 -- would otherwise catch this first, so this bypasses waio.sh the same way T5 bypasses it for orchestrate_worker.sh)"
DIRECT_OUT="$(./workers/host800_worker.sh "" 2>&1)"; DIRECT_RC=$?
assert_eq "W14 exit code" "1" "$DIRECT_RC"
assert_contains "W14 error text" "$DIRECT_OUT" "empty request"

echo
echo "=== Summary: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
  echo "Failures:"
  for f in "${FAILURES[@]}"; do
    echo "  - $f"
  done
  exit 1
fi
exit 0
