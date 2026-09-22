#!/bin/bash
set -uo pipefail

# fx_validation/run_validation.sh -- Steps 2-6 of the FX Forecast
# Validation Engine (see ARCHITECTURE.md's "WAIO FX Forecast Validation
# Engine" phase entry for the full design rationale, and
# fx_validation/save_forecast_snapshot.sh's header for Step 1).
#
# For one immutable forecast snapshot: for each pair x horizon whose
# deadline has passed, fetches the live rate, records
# FORECAST -> ACTUAL, computes absolute_error/percentage_error/
# direction_correct, classifies the actual into the
# Downside/Base/Upside/Outside-Range scenario band, and writes the
# whole result set to results/fx_forecast_validation_YYYYMMDD.json
# (YYYYMMDD = the date this validation run executes, not the forecast
# date -- a forecast made once can be validated on three different
# calendar days as its 24H/1W/1M deadlines each come due).
#
# Evaluation is one-way, same "immutable once written" posture as the
# forecast snapshot itself: once a pair/horizon's status is EVALUATED
# in today's results file, a later re-run of this script on the same
# day leaves it untouched -- it is never re-fetched or recomputed, so
# a second run mid-day can't silently replace an earlier real
# observation with a later one. Only entries still PENDING (deadline
# not yet reached) or DATA_UNAVAILABLE (a prior fetch attempt failed)
# remain eligible for (re)attempt.
#
# DATA_UNAVAILABLE handling (hard requirement): if the actual-rate
# fetch fails for any reason, this script records the literal string
# "DATA_UNAVAILABLE" in actual/absolute_error/percentage_error/
# direction_correct/range_zone for every horizon that was due this
# run -- it never substitutes a guess, a stale cache value, or the
# forecast's own median.
#
# Usage: fx_validation/run_validation.sh [snapshot_file]
#   snapshot_file defaults to the most recently created file under
#   results/fx-scenarios/snapshots/ (WAIO_FX_SNAPSHOT_DIR override).
#
# Intermediate state between Pass 1 (decide what's due) and Pass 2
# (fetch + score) is passed via temp files, not encoded into a
# delimited stdout string -- plain files are what every other
# multi-stage script in this codebase already uses (see
# research_worker.sh/weather_agent.sh's own TMP_BODY), and side-step
# any shell quoting hazard entirely.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"

SNAPSHOT_DIR="${WAIO_FX_SNAPSHOT_DIR:-results/fx-scenarios/snapshots}"
RESULTS_DIR="${WAIO_FX_RESULTS_DIR:-results}"
mkdir -p "$RESULTS_DIR"

SNAPSHOT_FILE="${1:-}"
if [ -z "$SNAPSHOT_FILE" ]; then
  SNAPSHOT_FILE="$(ls -1t "$SNAPSHOT_DIR"/fx-*.json 2>/dev/null | head -1)"
fi

if [ -z "$SNAPSHOT_FILE" ] || [ ! -f "$SNAPSHOT_FILE" ]; then
  echo "[FX VALIDATE] ERROR: no forecast snapshot found (looked in $SNAPSHOT_DIR)"
  echo "[FX VALIDATE] run fx_validation/save_forecast_snapshot.sh first"
  exit 1
fi

TODAY="$(date +%Y%m%d)"
RESULTS_FILE="$RESULTS_DIR/fx_forecast_validation_$TODAY.json"

PLAN_FILE="$(mktemp)"
ACTUAL_FILE="$(mktemp)"
trap 'rm -f "$PLAN_FILE" "$ACTUAL_FILE"' EXIT

# --- Pass 1 (pure, no network/side effects): decide which pair/horizon
# cells are due, loading whatever today's results file already has so
# already-EVALUATED cells are never re-touched. Writes {"due": [...],
# "state": {...}} to $PLAN_FILE.
if ! python3 - "$SNAPSHOT_FILE" "$RESULTS_FILE" "$PLAN_FILE" <<'PYEOF'
import json, sys, os, datetime

snapshot_path, results_path, plan_path = sys.argv[1], sys.argv[2], sys.argv[3]

with open(snapshot_path) as f:
    snapshot = json.load(f)

existing = {}
if os.path.exists(results_path):
    with open(results_path) as f:
        existing = json.load(f)

# a results file for today belonging to a DIFFERENT forecast_id is a
# genuine conflict (two snapshots both had a horizon come due on the
# same calendar day) -- refuse to guess which one the file is for
# rather than silently mixing them.
if existing.get("forecast_id") and existing.get("forecast_id") != snapshot["forecast_id"]:
    sys.stderr.write(
        "today's results file already belongs to a different forecast_id (%s vs %s); refusing to mix\n"
        % (existing.get("forecast_id"), snapshot["forecast_id"])
    )
    sys.exit(1)

now = datetime.datetime.now(datetime.timezone.utc)
results = existing.get("results", {}) if existing.get("forecast_id") == snapshot["forecast_id"] else {}

due = []
for pair, pdata in snapshot["pairs"].items():
    results.setdefault(pair, {})
    for horizon, hdata in pdata["horizons"].items():
        cell = results[pair].get(horizon)
        if cell and cell.get("status") == "EVALUATED":
            continue  # frozen: never re-touch a completed evaluation
        deadline = datetime.datetime.fromisoformat(hdata["deadline"])
        if now < deadline:
            results[pair][horizon] = {
                "status": "PENDING",
                "deadline": hdata["deadline"],
                "forecast": {
                    "base_range": hdata["base_range"],
                    "upside_range": hdata["upside_range"],
                    "downside_range": hdata["downside_range"],
                    "median": hdata["median"],
                    "confidence": hdata["confidence"],
                },
            }
        else:
            due.append([pair, horizon])

plan = {
    "due": due,
    "forecast_id": snapshot["forecast_id"],
    "forecast_timestamp": snapshot["forecast_timestamp"],
    "results": results,
    "snapshot_path": snapshot_path,
}
with open(plan_path, "w") as f:
    json.dump(plan, f)
PYEOF
then
  echo "[FX VALIDATE] ERROR: planning step failed (see message above)"
  exit 1
fi

DUE_COUNT="$(python3 -c "import json; print(len(json.load(open('$PLAN_FILE'))['due']))")"

if [ "$DUE_COUNT" -gt 0 ]; then
  if fx_validation/fetch_actual_rate.sh > "$ACTUAL_FILE" 2>/dev/null; then
    :
  else
    echo "[FX VALIDATE] WARNING: actual-rate fetch failed -- recording DATA_UNAVAILABLE for all due cells"
    : > "$ACTUAL_FILE"
  fi
else
  : > "$ACTUAL_FILE"
fi

# --- Pass 2: apply the fetch result (or its absence) to every due cell,
# compute error/direction/range-zone via fx_validation/validation_lib.py,
# and write the results file.
if ! python3 - "$PLAN_FILE" "$ACTUAL_FILE" "$RESULTS_FILE" <<'PYEOF'
import json, sys

sys.path.insert(0, "fx_validation")
import validation_lib as vlib

plan_path, actual_path, results_path = sys.argv[1], sys.argv[2], sys.argv[3]

with open(plan_path) as f:
    plan = json.load(f)

actual_rates = {}
with open(actual_path) as f:
    raw = f.read().strip()
    if raw:
        actual_rates = json.loads(raw)

with open(plan["snapshot_path"]) as f:
    snapshot = json.load(f)

results = plan["results"]

for pair, horizon in plan["due"]:
    hdata = snapshot["pairs"][pair]["horizons"][horizon]
    current_at_forecast = snapshot["pairs"][pair]["current_at_forecast"]
    median = hdata["median"]
    base_range = hdata["base_range"]
    upside_range = hdata["upside_range"]
    downside_range = hdata["downside_range"]

    cell = {
        "deadline": hdata["deadline"],
        "forecast": {
            "base_range": base_range,
            "upside_range": upside_range,
            "downside_range": downside_range,
            "median": median,
            "confidence": hdata["confidence"],
            "current_at_forecast": current_at_forecast,
        },
    }

    if pair not in actual_rates:
        cell["status"] = "DATA_UNAVAILABLE"
        cell["actual"] = "DATA_UNAVAILABLE"
        cell["absolute_error"] = "DATA_UNAVAILABLE"
        cell["percentage_error"] = "DATA_UNAVAILABLE"
        cell["direction_correct"] = "DATA_UNAVAILABLE"
        cell["range_zone"] = "DATA_UNAVAILABLE"
    else:
        actual = actual_rates[pair]
        abs_err, pct_err = vlib.compute_errors(actual, median)

        cell["status"] = "EVALUATED"
        cell["actual"] = actual
        cell["actual_source"] = actual_rates.get("source")
        cell["actual_source_url"] = actual_rates.get("source_url")
        cell["actual_fetched_at"] = actual_rates.get("fetched_at")
        cell["absolute_error"] = round(abs_err, 6)
        cell["percentage_error"] = round(pct_err, 4)
        cell["direction_correct"] = vlib.direction_correct(actual, median, current_at_forecast, base_range)
        cell["range_zone"] = vlib.classify_zone(actual, downside_range, base_range, upside_range)

    results[pair][horizon] = cell

summary = {}
for horizon in ["24H", "1W", "1M"]:
    evaluated = []
    for pair, hz in results.items():
        c = hz.get(horizon)
        if c and c.get("status") == "EVALUATED":
            evaluated.append(c)
    n = len(evaluated)
    if n == 0:
        summary[horizon] = {"pairs_evaluated": 0, "mean_percentage_error": "DATA_UNAVAILABLE", "direction_accuracy_pct": "DATA_UNAVAILABLE"}
    else:
        mean_pct = sum(c["percentage_error"] for c in evaluated) / n
        dir_acc = 100.0 * sum(1 for c in evaluated if c["direction_correct"]) / n
        summary[horizon] = {
            "pairs_evaluated": n,
            "mean_percentage_error": round(mean_pct, 4),
            "direction_accuracy_pct": round(dir_acc, 2),
        }

import datetime
out = {
    "forecast_id": plan["forecast_id"],
    "forecast_timestamp": plan["forecast_timestamp"],
    "validation_run_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
    "results": results,
    "accuracy_summary": summary,
}

with open(results_path, "w") as f:
    json.dump(out, f, indent=2, ensure_ascii=False)
PYEOF
then
  echo "[FX VALIDATE] ERROR: failed to compute/write validation results"
  exit 1
fi

echo "[FX VALIDATE] results written: $RESULTS_FILE"
echo ""

# --- Step 6: summary display, read back from the file just written -----
python3 - "$RESULTS_FILE" <<'PYEOF'
import json, sys

with open(sys.argv[1]) as f:
    out = json.load(f)
results = out['results']
summary = out['accuracy_summary']

PAIR_DISPLAY = {'USDJPY':'USD/JPY','EURUSD':'EUR/USD','AUDUSD':'AUD/USD','GBPUSD':'GBP/USD','USDCNY':'USD/CNY'}
DECIMALS = {'USDJPY':2,'EURUSD':4,'AUDUSD':4,'GBPUSD':4,'USDCNY':4}

def fmt(v, pair):
    if isinstance(v, str):
        return v
    return f'{v:.{DECIMALS[pair]}f}'

print('WAIO FX FORECAST VALIDATION')
print()
for horizon in ['24H', '1W', '1M']:
    rows = [(p, results[p][horizon]) for p in PAIR_DISPLAY if horizon in results.get(p, {})]
    if not rows:
        continue
    if all(c['status'] == 'PENDING' for _, c in rows):
        print('--- ' + horizon + ' : all pairs PENDING (deadline not yet reached) ---')
        print()
        continue
    print('--- ' + horizon + ' ---')
    header = 'PAIR'.ljust(9) + 'FORECAST'.ljust(12) + 'ACTUAL'.ljust(10) + 'ERROR'.ljust(10) + 'DIR'
    print(header)
    for pair, c in rows:
        disp = PAIR_DISPLAY[pair]
        if c['status'] == 'PENDING':
            print(disp.ljust(9) + 'PENDING'.ljust(12) + '-'.ljust(10) + '-'.ljust(10) + '-')
            continue
        if c['status'] == 'DATA_UNAVAILABLE':
            median_disp = fmt(c['forecast']['median'], pair)
            print(disp.ljust(9) + median_disp.ljust(12) + 'DATA_UNAVAILABLE'.ljust(10) + '-'.ljust(10) + '-')
            continue
        forecast_v = fmt(c['forecast']['median'], pair)
        actual_v = fmt(c['actual'], pair)
        err_v = f"{c['percentage_error']:.2f}%"
        dir_v = '✓' if c['direction_correct'] else '✗'
        print(disp.ljust(9) + forecast_v.ljust(12) + actual_v.ljust(10) + err_v.ljust(10) + dir_v)
    print()

print('=== Accuracy by horizon ===')
for horizon in ['24H', '1W', '1M']:
    s = summary[horizon]
    if s['pairs_evaluated'] == 0:
        print(horizon + ': no evaluated pairs yet')
    else:
        print(f"{horizon}: {s['pairs_evaluated']} pair(s) evaluated, mean error {s['mean_percentage_error']:.2f}%, direction accuracy {s['direction_accuracy_pct']:.1f}%")
PYEOF
