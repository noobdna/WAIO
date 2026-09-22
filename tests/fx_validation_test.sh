#!/bin/bash
set -uo pipefail

# tests/fx_validation_test.sh -- regression suite for the FX Forecast
# Validation Engine (fx_validation/*.sh, see ARCHITECTURE.md's "WAIO FX
# Forecast Validation Engine" phase entry for the full design
# rationale): Forecast snapshot -> Actual fetch -> Error/Direction/
# Range-zone scoring -> results JSON -> summary.
#
# Everything here runs against scratch fixtures via
# WAIO_FX_SNAPSHOT_DIR/WAIO_FX_RESULTS_DIR/WAIO_FX_CACHE_DIR overrides
# and fetch_actual_rate.sh's WAIO_FX_FIXTURE_RATES_JSON escape hatch --
# same idiom as tests/audit_log_integrity_test.sh's WAIO_AUDIT_LOG. No
# network call is ever made by this suite, and the real
# results/fx-scenarios/snapshots/ and results/fx_forecast_validation_*
# files are never read or touched.

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

assert_close() {
  local label="$1" expected="$2" actual="$3" tol="${4:-0.001}"
  if python3 -c "import sys; sys.exit(0 if abs(float('$expected') - float('$actual')) <= float('$tol') else 1)"; then
    PASS=$((PASS + 1)); echo "  PASS: $label"
  else
    FAIL=$((FAIL + 1)); FAILURES+=("$label (expected~='$expected' actual='$actual' tol=$tol)")
    echo "  FAIL: $label (expected~='$expected' actual='$actual' tol=$tol)"
  fi
}

WORKDIR="$(mktemp -d)"
cleanup() { rm -rf "$WORKDIR"; }
trap cleanup EXIT

export WAIO_FX_SNAPSHOT_DIR="$WORKDIR/snapshots"
export WAIO_FX_RESULTS_DIR="$WORKDIR/results"
export WAIO_FX_CACHE_DIR="$WORKDIR/cache"
mkdir -p "$WAIO_FX_SNAPSHOT_DIR" "$WAIO_FX_RESULTS_DIR" "$WAIO_FX_CACHE_DIR"

# ---------------------------------------------------------------------
# Fixture 1: a source scenario report whose deadlines are already long
# past (forecast_timestamp = year 2000), so every horizon is DUE the
# instant a validation run happens against it -- deterministic
# regardless of real wall-clock time. Base/median/ranges are simple
# round numbers chosen so range-zone and direction outcomes can be
# hand-verified.
# ---------------------------------------------------------------------
PAST_REPORT="$WORKDIR/past_report.json"
python3 - "$PAST_REPORT" <<'PYEOF'
import json, sys

def horizons(base, upside, downside, median, conf):
    h = {"base_range": base, "upside_range": upside, "downside_range": downside, "median": median, "confidence": conf}
    return {"24h": h, "1w": h, "1m": h}

report = {
    "report_name": "TEST FX Scenario Report",
    "generated_at": "2000-01-01",
    "pairs": [
        {"pair": "USDJPY", "current": 150.00, "horizons": horizons([149.00, 151.00], [151.00, 153.00], [147.00, 149.00], 150.00, 70)},
        {"pair": "EURUSD", "current": 1.1000, "horizons": horizons([1.1000, 1.1100], [1.1100, 1.1300], [1.0800, 1.1000], 1.1050, 65)},
        {"pair": "AUDUSD", "current": 0.7000, "horizons": horizons([0.6900, 0.7000], [0.7000, 0.7200], [0.6700, 0.6900], 0.6950, 60)},
        {"pair": "GBPUSD", "current": 1.3000, "horizons": horizons([1.2900, 1.3100], [1.3100, 1.3300], [1.2700, 1.2900], 1.3000, 68)},
        {"pair": "USDCNY", "current": 7.0000, "horizons": horizons([6.9500, 7.0500], [7.0500, 7.1500], [6.9000, 6.9500], 7.0000, 72)},
    ],
}
with open(sys.argv[1], "w") as f:
    json.dump(report, f)
PYEOF

echo "=== fx_validation: Step 1 -- forecast snapshot save + immutability ==="

SNAP_OUT="$(fx_validation/save_forecast_snapshot.sh "$PAST_REPORT" "2000-01-01T00:00:00+09:00" 2>&1)"
SNAP_RC=$?
assert_eq "snapshot save succeeds" "0" "$SNAP_RC"

SNAPSHOT_PATH="$WAIO_FX_SNAPSHOT_DIR/fx-20000101T000000+0900.json"
if [ -f "$SNAPSHOT_PATH" ]; then
  PASS=$((PASS + 1)); echo "  PASS: snapshot file created at expected path"
else
  FAIL=$((FAIL + 1)); FAILURES+=("snapshot file created at expected path"); echo "  FAIL: snapshot file created at expected path"
fi

# BSD/macOS `stat -f '%Lp'` vs GNU/Linux `stat -c '%a'`: on Linux, `-f`
# means "show FILESYSTEM stats" (a different, valid flag), not "use
# this format string" -- it does not error there, it silently succeeds
# with unrelated multi-line filesystem info, so a naive `stat -f ... ||
# stat -c ...` fallback never triggers on Linux/CI (same class of bug
# already found and fixed in security/lib.sh's
# _waio_mkdir_lock_acquire, confirmed in CI 2026-09-16). Try the BSD
# form, then validate it's actually a bare octal-digit string before
# trusting it; fall back to the GNU form otherwise.
PERM="$(stat -f '%Lp' "$SNAPSHOT_PATH" 2>/dev/null)"
case "$PERM" in
  ''|*[!0-7]*) PERM="$(stat -c '%a' "$SNAPSHOT_PATH" 2>/dev/null)" ;;
esac
assert_eq "snapshot file is read-only (444)" "444" "$PERM"

HASH_BEFORE="$(shasum -a 256 "$SNAPSHOT_PATH" | awk '{print $1}')"

# immutability: re-running with the same forecast timestamp must be
# refused, and must NOT alter the existing file.
if fx_validation/save_forecast_snapshot.sh "$PAST_REPORT" "2000-01-01T00:00:00+09:00" >/dev/null 2>&1; then
  FAIL=$((FAIL + 1)); FAILURES+=("re-saving same forecast_timestamp is refused"); echo "  FAIL: re-saving same forecast_timestamp is refused (it succeeded, should not have)"
else
  PASS=$((PASS + 1)); echo "  PASS: re-saving same forecast_timestamp is refused"
fi

HASH_AFTER="$(shasum -a 256 "$SNAPSHOT_PATH" | awk '{print $1}')"
assert_eq "snapshot content unchanged after refused overwrite attempt" "$HASH_BEFORE" "$HASH_AFTER"

echo ""
echo "=== fx_validation: Step 2-4 -- fetch, error calc, direction, range-zone ==="

# Fixture "actual" rates (Frankfurter response shape). Chosen so each
# pair lands in a different scenario band:
#   USDJPY -> BASE,        direction: flat call, stays in Base -> correct
#   EURUSD -> UPSIDE,      direction: predicted up, moved up   -> correct
#   AUDUSD -> DOWNSIDE,    direction: predicted down, moved dn -> correct
#   GBPUSD -> OUTSIDE_RANGE, direction: flat call, moved far out -> WRONG
#   USDCNY -> BASE,        direction: flat call, stays in Base -> correct
ACTUAL_FIXTURE="$WORKDIR/actual_rates.json"
python3 -c "
import json
rates = {'JPY': 150.00, 'CNY': 7.00, 'EUR': 1.0/1.1150, 'GBP': 1.0/1.3500, 'AUD': 1.0/0.6800}
json.dump({'amount':1.0,'base':'USD','date':'2000-01-02','rates':rates}, open('$ACTUAL_FIXTURE','w'))
"

export WAIO_FX_FIXTURE_RATES_JSON="$ACTUAL_FIXTURE"
VALIDATE_OUT="$(fx_validation/run_validation.sh "$SNAPSHOT_PATH" 2>&1)"
VALIDATE_RC=$?
assert_eq "run_validation.sh exits 0 on successful fetch" "0" "$VALIDATE_RC"

RESULTS_FILE="$WAIO_FX_RESULTS_DIR/fx_forecast_validation_$(date +%Y%m%d).json"
if [ -f "$RESULTS_FILE" ]; then
  PASS=$((PASS + 1)); echo "  PASS: results file created at fx_forecast_validation_YYYYMMDD.json"
else
  FAIL=$((FAIL + 1)); FAILURES+=("results file created"); echo "  FAIL: results file created"
fi

get_field() { python3 -c "import json; d=json.load(open('$RESULTS_FILE')); print(d['results']['$1']['$2']['$3'])"; }

assert_eq "USDJPY 24H status EVALUATED" "EVALUATED" "$(get_field USDJPY 24H status)"
assert_eq "USDJPY 24H range_zone BASE" "BASE" "$(get_field USDJPY 24H range_zone)"
assert_eq "USDJPY 24H direction_correct True" "True" "$(get_field USDJPY 24H direction_correct)"

assert_eq "EURUSD 24H range_zone UPSIDE" "UPSIDE" "$(get_field EURUSD 24H range_zone)"
assert_eq "EURUSD 24H direction_correct True" "True" "$(get_field EURUSD 24H direction_correct)"
# |1.1150 - 1.1050| / 1.1050 * 100 = 0.9050%
assert_close "EURUSD 24H percentage_error ~0.905%" "0.905" "$(get_field EURUSD 24H percentage_error)" "0.02"

assert_eq "AUDUSD 24H range_zone DOWNSIDE" "DOWNSIDE" "$(get_field AUDUSD 24H range_zone)"
assert_eq "AUDUSD 24H direction_correct True" "True" "$(get_field AUDUSD 24H direction_correct)"

assert_eq "GBPUSD 24H range_zone OUTSIDE_RANGE" "OUTSIDE_RANGE" "$(get_field GBPUSD 24H range_zone)"
assert_eq "GBPUSD 24H direction_correct False (flat call, moved far out)" "False" "$(get_field GBPUSD 24H direction_correct)"

assert_eq "USDCNY 24H range_zone BASE" "BASE" "$(get_field USDCNY 24H range_zone)"

# absolute_error hand check: |actual - median| for USD/JPY, actual=150.00 median=150.00
assert_eq "USDJPY 24H absolute_error is 0.0" "0.0" "$(get_field USDJPY 24H absolute_error)"

# same holds across 1W/1M since the fixture uses identical ranges for
# all three horizons and all three were simultaneously due.
assert_eq "USDJPY 1W range_zone BASE" "BASE" "$(get_field USDJPY 1W range_zone)"
assert_eq "USDJPY 1M range_zone BASE" "BASE" "$(get_field USDJPY 1M range_zone)"

echo ""
echo "=== fx_validation: evaluated cells are frozen on re-run ==="

# re-run with DIFFERENT actual rates -- an already-EVALUATED cell must
# keep its original recorded actual, not the new fetch.
ACTUAL_FIXTURE_2="$WORKDIR/actual_rates_2.json"
python3 -c "
import json
rates = {'JPY': 999.00, 'CNY': 999.00, 'EUR': 1.0/1.99, 'GBP': 1.0/1.99, 'AUD': 1.0/1.99}
json.dump({'amount':1.0,'base':'USD','date':'2000-01-03','rates':rates}, open('$ACTUAL_FIXTURE_2','w'))
"
export WAIO_FX_FIXTURE_RATES_JSON="$ACTUAL_FIXTURE_2"
fx_validation/run_validation.sh "$SNAPSHOT_PATH" >/dev/null 2>&1
assert_eq "USDJPY 24H actual unchanged after re-run with different fixture" "150.0" "$(get_field USDJPY 24H actual)"

echo ""
echo "=== fx_validation: DATA_UNAVAILABLE on fetch failure (never guesses) ==="

# Separate results-dir for this scenario: a different forecast_id due
# on the same calendar day as fixture 1 is a real conflict (tested
# further down) -- isolating avoids that here so this block tests
# fetch-failure handling specifically, not the conflict path.
export WAIO_FX_RESULTS_DIR="$WORKDIR/results_unavailable"
mkdir -p "$WAIO_FX_RESULTS_DIR"

SNAP2_OUT="$(fx_validation/save_forecast_snapshot.sh "$PAST_REPORT" "2000-06-01T00:00:00+09:00" 2>&1)"
SNAPSHOT2_PATH="$WAIO_FX_SNAPSHOT_DIR/fx-20000601T000000+0900.json"

unset WAIO_FX_FIXTURE_RATES_JSON
export WAIO_FX_FIXTURE_RATES_JSON="$WORKDIR/does_not_exist.json"
VALIDATE2_OUT="$(fx_validation/run_validation.sh "$SNAPSHOT2_PATH" 2>&1)"
VALIDATE2_RC=$?
assert_eq "run_validation.sh still exits 0 on a failed fetch (degraded, not fatal)" "0" "$VALIDATE2_RC"

RESULTS2_FILE="$WAIO_FX_RESULTS_DIR/fx_forecast_validation_$(date +%Y%m%d).json"
get_field2() { python3 -c "import json; d=json.load(open('$RESULTS2_FILE')); print(d['results']['$1']['$2']['$3'])"; }
assert_eq "USDJPY status DATA_UNAVAILABLE on failed fetch" "DATA_UNAVAILABLE" "$(get_field2 USDJPY 24H status)"
assert_eq "USDJPY actual DATA_UNAVAILABLE on failed fetch (no guess)" "DATA_UNAVAILABLE" "$(get_field2 USDJPY 24H actual)"
assert_eq "USDJPY direction_correct DATA_UNAVAILABLE on failed fetch" "DATA_UNAVAILABLE" "$(get_field2 USDJPY 24H direction_correct)"
assert_eq "USDJPY range_zone DATA_UNAVAILABLE on failed fetch" "DATA_UNAVAILABLE" "$(get_field2 USDJPY 24H range_zone)"

echo ""
echo "=== fx_validation: PENDING when deadline not yet reached ==="

export WAIO_FX_RESULTS_DIR="$WORKDIR/results_pending"
mkdir -p "$WAIO_FX_RESULTS_DIR"

fx_validation/save_forecast_snapshot.sh "$PAST_REPORT" "2099-01-01T00:00:00+09:00" >/dev/null 2>&1
SNAPSHOT3_PATH="$WAIO_FX_SNAPSHOT_DIR/fx-20990101T000000+0900.json"
# no fixture rates file at all -- if the engine tried to fetch anything
# for a PENDING-only run it would fail/attempt network; assert it
# simply never tries (run_validation.sh only calls fetch_actual_rate.sh
# when DUE_COUNT > 0).
unset WAIO_FX_FIXTURE_RATES_JSON
VALIDATE3_OUT="$(fx_validation/run_validation.sh "$SNAPSHOT3_PATH" 2>&1)"
VALIDATE3_RC=$?
assert_eq "run_validation.sh exits 0 for an all-PENDING snapshot" "0" "$VALIDATE3_RC"
assert_eq "future snapshot produces 3 PENDING horizon sections" "3" "$(echo "$VALIDATE3_OUT" | grep -c "all pairs PENDING")"

RESULTS3_FILE="$WAIO_FX_RESULTS_DIR/fx_forecast_validation_$(date +%Y%m%d).json"
get_field3() { python3 -c "import json; d=json.load(open('$RESULTS3_FILE')); print(d['results']['$1']['$2']['$3'])"; }
assert_eq "USDJPY 24H status PENDING for a far-future forecast" "PENDING" "$(get_field3 USDJPY 24H status)"

echo ""
echo "=== fx_validation: conflicting forecast_id on the same validation-day is refused ==="

# Two different forecast snapshots whose 24H deadlines both fall due on
# the same real calendar day must never be silently merged into one
# results/fx_forecast_validation_YYYYMMDD.json -- run_validation.sh
# must refuse instead of guessing which snapshot the file belongs to.
export WAIO_FX_RESULTS_DIR="$WORKDIR/results_conflict"
mkdir -p "$WAIO_FX_RESULTS_DIR"
export WAIO_FX_FIXTURE_RATES_JSON="$ACTUAL_FIXTURE"

fx_validation/save_forecast_snapshot.sh "$PAST_REPORT" "2000-01-01T00:00:00+09:00" >/dev/null 2>&1
fx_validation/run_validation.sh "$SNAPSHOT_PATH" >/dev/null 2>&1

fx_validation/save_forecast_snapshot.sh "$PAST_REPORT" "2000-06-01T00:00:00+09:00" >/dev/null 2>&1
CONFLICT_OUT="$(fx_validation/run_validation.sh "$SNAPSHOT2_PATH" 2>&1)"
CONFLICT_RC=$?
assert_eq "conflicting forecast_id run exits non-zero" "1" "$CONFLICT_RC"
assert_eq "conflicting forecast_id message shown" "1" "$(echo "$CONFLICT_OUT" | grep -c "different forecast_id")"

echo ""
echo "=== fx_validation: validation_lib.py pure-function unit checks ==="

VLIB_CHECK() {
  python3 -c "
import sys
sys.path.insert(0, 'fx_validation')
import validation_lib as vlib
print($1)
"
}
assert_eq "classify_zone exact base lower boundary -> BASE" "BASE" "$(VLIB_CHECK "vlib.classify_zone(149.0, [147.0,149.0], [149.0,151.0], [151.0,153.0])")"
assert_eq "classify_zone just below base lower boundary -> DOWNSIDE" "DOWNSIDE" "$(VLIB_CHECK "vlib.classify_zone(148.99, [147.0,149.0], [149.0,151.0], [151.0,153.0])")"
assert_eq "classify_zone exact upside upper boundary -> UPSIDE" "UPSIDE" "$(VLIB_CHECK "vlib.classify_zone(153.0, [147.0,149.0], [149.0,151.0], [151.0,153.0])")"
assert_eq "classify_zone beyond upside upper boundary -> OUTSIDE_RANGE" "OUTSIDE_RANGE" "$(VLIB_CHECK "vlib.classify_zone(153.01, [147.0,149.0], [149.0,151.0], [151.0,153.0])")"
assert_eq "classify_zone below downside lower boundary -> OUTSIDE_RANGE" "OUTSIDE_RANGE" "$(VLIB_CHECK "vlib.classify_zone(146.99, [147.0,149.0], [149.0,151.0], [151.0,153.0])")"
assert_eq "direction_correct: skewed-up median, actual moved up -> True" "True" "$(VLIB_CHECK "vlib.direction_correct(1.115, 1.105, 1.100, [1.100,1.110])")"
assert_eq "direction_correct: skewed-up median, actual moved down -> False" "False" "$(VLIB_CHECK "vlib.direction_correct(1.090, 1.105, 1.100, [1.100,1.110])")"

echo ""
echo "=== fx_validation: worker registration + egress allowlist ==="

if grep -q "^FXVALIDATION|" workers/registry.conf; then
  PASS=$((PASS + 1)); echo "  PASS: FXVALIDATION registered in workers/registry.conf"
else
  FAIL=$((FAIL + 1)); FAILURES+=("FXVALIDATION registered in workers/registry.conf"); echo "  FAIL: FXVALIDATION registered in workers/registry.conf"
fi

if [ -x "workers/fx_validation_worker.sh" ]; then
  PASS=$((PASS + 1)); echo "  PASS: workers/fx_validation_worker.sh exists and is executable"
else
  FAIL=$((FAIL + 1)); FAILURES+=("workers/fx_validation_worker.sh exists and is executable"); echo "  FAIL: workers/fx_validation_worker.sh exists and is executable"
fi

# Checks the committed .example template, not the real
# security/egress_allowlist.conf -- that file is gitignored/
# per-deployment (same Public/Private Security Boundary pattern as
# security/segments.conf.example's own template-sanity checks
# elsewhere in this codebase) and does not exist at all in a fresh
# checkout/CI runner, only on a configured deployment.
if grep -q "^api.frankfurter.dev|443|" security/egress_allowlist.conf.example; then
  PASS=$((PASS + 1)); echo "  PASS: api.frankfurter.dev present in security/egress_allowlist.conf.example"
else
  FAIL=$((FAIL + 1)); FAILURES+=("api.frankfurter.dev present in egress allowlist example"); echo "  FAIL: api.frankfurter.dev present in security/egress_allowlist.conf.example"
fi

echo ""
echo "=== SUMMARY: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
  echo "Failures:"
  for f in "${FAILURES[@]}"; do
    echo "  - $f"
  done
  exit 1
fi
exit 0
