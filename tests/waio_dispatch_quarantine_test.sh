#!/bin/bash
set -uo pipefail

# tests/waio_dispatch_quarantine_test.sh -- waio.sh's per-worker Guardian
# quarantine gate must fail closed. guardian_is_quarantined() returns
# "not quarantined" when the quarantine list exists but cannot be read
# (grep fails), which would let waio.sh dispatch to a quarantined
# worker. waio.sh itself refuses dispatch when the list exists but is
# not a readable regular file. guardian_is_quarantined() is left as is:
# tests/e2e/containment_bridge.sh uses it as its containment check,
# where failing closed would wrongly report containment as done.
#
# Fully isolated via tests/lib/test_isolation.sh (temp security/state
# paths, empty HOME, recording stubs); dispatches only to ECHO, which
# needs no Keychain and no network.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"
# shellcheck source=tests/lib/test_isolation.sh
source tests/lib/test_isolation.sh

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
  case "$haystack" in
    *"$needle"*) PASS=$((PASS + 1)); echo "  PASS: $label" ;;
    *) FAIL=$((FAIL + 1)); FAILURES+=("$label (expected to contain '$needle')"); echo "  FAIL: $label (expected to contain '$needle', got: $haystack)" ;;
  esac
}

waio_test_isolate waio-dispatch-quarantine || exit 3
Q="$WAIO_GUARDIAN_QUARANTINE_FILE"
cleanup() { chmod 600 "$Q" 2>/dev/null; rm -rf "$Q" 2>/dev/null; waio_test_cleanup; }
trap cleanup EXIT
waio_test_assert_isolated || { echo "ABORT: test isolation could not be guaranteed" >&2; exit 3; }

dispatch() { ./waio.sh -w ECHO "quarantine probe" 2>&1; }
reset_q() { chmod 600 "$Q" 2>/dev/null; rm -rf "$Q"; }

echo "=== waio.sh dispatch: Guardian quarantine gate fails closed ==="

echo "[Q1] no quarantine list at all: ECHO dispatches (baseline)"
reset_q
OUT="$(dispatch)"; RC=$?
assert_eq "Q1 exit 0" "0" "$RC"
assert_contains "Q1 ECHO ran" "$OUT" "[ECHO WORKER] completed"

echo "[Q2] readable list that names ECHO: refused"
reset_q; printf 'ECHO\n' > "$Q"
OUT="$(dispatch)"; RC=$?
assert_eq "Q2 exit 1" "1" "$RC"
assert_contains "Q2 refusal names quarantine" "$OUT" "quarantined"

echo "[Q3] readable list that names another worker only: ECHO dispatches"
reset_q; printf 'RESEARCH\n' > "$Q"
OUT="$(dispatch)"; RC=$?
assert_eq "Q3 exit 0" "0" "$RC"
assert_contains "Q3 ECHO ran" "$OUT" "[ECHO WORKER] completed"

echo "[Q4] list exists but is unreadable (mode 000), even though it names ECHO: refused, never dispatched"
reset_q; printf 'ECHO\n' > "$Q"; chmod 000 "$Q"
if [ -r "$Q" ]; then
  echo "  SKIP: Q4 running as a user that can read mode-000 files (root?)"
else
  OUT="$(dispatch)"; RC=$?
  assert_eq "Q4 exit 1" "1" "$RC"
  assert_contains "Q4 refusal says the list cannot be read" "$OUT" "cannot be read"
  assert_eq "Q4 ECHO never ran" "0" "$(printf '%s' "$OUT" | grep -c 'ECHO WORKER')"
fi

echo "[Q5] a directory at the list path: refused"
reset_q; mkdir -p "$Q"
OUT="$(dispatch)"; RC=$?
assert_eq "Q5 exit 1" "1" "$RC"
assert_eq "Q5 ECHO never ran" "0" "$(printf '%s' "$OUT" | grep -c 'ECHO WORKER')"

echo "[Q6] a dangling symlink at the list path: refused"
reset_q; ln -s "$WAIO_TEST_ROOT/does-not-exist" "$Q"
OUT="$(dispatch)"; RC=$?
assert_eq "Q6 exit 1" "1" "$RC"
assert_eq "Q6 ECHO never ran" "0" "$(printf '%s' "$OUT" | grep -c 'ECHO WORKER')"
reset_q

echo "[Q7] each refusal is audited as guardian_dispatch_blocked in the isolated audit log"
assert_eq "Q7 refusals audited (Q2, Q4, Q5, Q6)" "4" "$(grep -c 'guardian_dispatch_blocked' "$WAIO_AUDIT_LOG" 2>/dev/null || echo 0)"

echo "[Q8] isolation held: no privileged/network stub was called"
assert_eq "Q8 sudo/ssh/curl/osascript stubs never called" "0:0:0:0" "$(waio_test_stub_calls sudo):$(waio_test_stub_calls ssh):$(waio_test_stub_calls curl):$(waio_test_stub_calls osascript)"

echo ""
echo "=== Summary: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
  echo "Failures:"
  for f in "${FAILURES[@]}"; do echo "  - $f"; done
  exit 1
fi
exit 0
