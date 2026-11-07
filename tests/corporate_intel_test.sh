#!/bin/bash
set -uo pipefail

# tests/corporate_intel_test.sh -- runs the WAIO Corporate Intelligence
# (security/corporate_intel/) Python suites under tests/corporate_intel/
# inside tests/lib/test_isolation.sh's private temp root, then proves
# this checkout's real security state was not touched.
#
# NO NETWORK: every suite reads security/corporate_intel/fixtures/
# (synthetic, CVE-2026-1xxxx ids, RFC 5737 IPs). curl/ssh/etc. are
# replaced by failing stubs for the whole run.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR" || exit 3

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

REAL_STATE_SUM_BEFORE="$( [ -d security/state/corporate_intel ] && find security/state/corporate_intel -type f -exec shasum -a 256 {} + | sort | shasum -a 256 | awk '{print $1}' || echo absent)"
REAL_SHUTDOWN_BEFORE="$([ -f security/state/SHUTDOWN.lock ] && echo present || echo absent)"

# shellcheck source=tests/lib/test_isolation.sh
source tests/lib/test_isolation.sh
waio_test_isolate corporate-intel || exit 3
trap waio_test_cleanup EXIT
waio_test_assert_isolated || { echo "ABORT: test isolation could not be guaranteed" >&2; exit 3; }
export WAIO_CI_STATE_DIR="$WAIO_TEST_ROOT/state/corporate_intel"

echo "=== WAIO Corporate Intelligence: unit suites (collectors / dedupe / correlate / risk / failsafe / secret-leak / boundaries) ==="
for suite in tests/corporate_intel/test_*.py; do
  name="$(basename "$suite" .py)"
  OUT="$(cd tests/corporate_intel && python3 -m unittest "$name" 2>&1)"
  RC=$?
  RAN="$(printf '%s\n' "$OUT" | sed -n 's/^Ran \([0-9]*\) tests\{0,1\}.*/\1/p' | tail -1)"
  assert_eq "$name: all ${RAN:-?} tests pass" "0" "$RC"
  [ "$RC" -eq 0 ] || printf '%s\n' "$OUT" | grep -E '^(FAIL|ERROR):|Error|assert' | head -20
done

echo ""
echo "[CI-E2E] offline CLI end-to-end against the synthetic bank"
M=security/corporate_intel
python3 $M/ci.py ingest --source kev --file $M/fixtures/kev.json --fetched-at 2026-11-06T00:00:00Z 2>/dev/null
for f in $M/fixtures/nvd/*.json; do python3 $M/ci.py ingest --source nvd --file "$f" --fetched-at 2026-11-06T00:00:00Z 2>/dev/null; done
python3 $M/ci.py ingest --source epss --file $M/fixtures/epss.json --fetched-at 2026-11-06T00:00:00Z 2>/dev/null
REPORT_OUT="$(python3 $M/ci.py report --inventory $M/synthetic/example_bank_inventory.json --now 2026-11-07T00:00:00Z 2>&1)"
assert_eq "E2E summary line" "findings=6 P1=2 P2=1 P3=3 P4=0 low_confidence=0" "$(printf '%s\n' "$REPORT_OUT" | grep '^findings=')"
assert_eq "E2E top finding" "P1 EMB-A01 CVE-2026-10001 exact_cpe" \
  "$(printf '%s\n' "$REPORT_OUT" | awk '/^  P/{gsub(/[\[\]]/,""); print $1, $5, $6, $7; exit}')"
REPORT_FILE="$(printf '%s\n' "$REPORT_OUT" | sed -n 's/^report: //p')"
case "$REPORT_FILE" in "$WAIO_CI_STATE_DIR"/reports/*) IN_ROOT=true ;; *) IN_ROOT=false ;; esac
assert_eq "E2E report written inside the isolated state dir" "true" "$IN_ROOT"
assert_eq "E2E offline fetch refused (exit 3)" "3" "$(python3 $M/ci.py fetch --source kev >/dev/null 2>&1; echo $?)"
assert_eq "E2E no curl stub invoked" "0" "$(waio_test_stub_calls curl)"

echo ""
echo "[CI-D] this checkout's real state untouched"
REAL_STATE_SUM_AFTER="$( [ -d security/state/corporate_intel ] && find security/state/corporate_intel -type f -exec shasum -a 256 {} + | sort | shasum -a 256 | awk '{print $1}' || echo absent)"
assert_eq "D1 real security/state/corporate_intel unchanged" "$REAL_STATE_SUM_BEFORE" "$REAL_STATE_SUM_AFTER"
assert_eq "D2 real SHUTDOWN.lock unchanged" "$REAL_SHUTDOWN_BEFORE" "$([ -f security/state/SHUTDOWN.lock ] && echo present || echo absent)"

echo ""
echo "=== Summary: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
  printf '  - %s\n' "${FAILURES[@]}"
  exit 1
fi
exit 0
