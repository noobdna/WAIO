#!/bin/bash
set -uo pipefail

# fx_validation/save_forecast_snapshot.sh -- Step 1 of the FX Forecast
# Validation Engine (see ARCHITECTURE.md's "WAIO FX Forecast Validation
# Engine" phase entry for the full design rationale).
#
# Freezes one WAIO Quantitative FX Scenario Report (the analyst-modeled
# scenario JSON produced for USD/JPY, EUR/USD, AUD/USD, GBP/USD,
# USD/CNY across 24H/1W/1M) into an immutable snapshot under
# results/fx-scenarios/snapshots/. A snapshot carries exactly what a
# later validation run needs and nothing else: per pair/horizon
# base_range, upside_range, downside_range, median, confidence, the
# forecast_timestamp itself, each horizon's computed deadline, and a
# source pointer back to the original report file.
#
# Immutability is enforced two ways, matching this codebase's existing
# "tamper-evidence, not tamper-prevention" posture (see security/lib.sh's
# hash-chained audit_log): (1) this script refuses outright to overwrite
# an existing snapshot file -- re-running with the same forecast
# timestamp is a no-op error, never a silent replace; (2) the written
# file is chmod'd to 444 (read-only) so an accidental later `>` redirect
# by some other script fails at the filesystem level instead of
# corrupting history. A snapshot's own sha256 is recorded inside it so
# any future tampering is at least detectable.
#
# Usage:
#   fx_validation/save_forecast_snapshot.sh <source_report.json> [forecast_timestamp_iso8601]
#
# forecast_timestamp defaults to the source report's own "generated_at"
# field (midnight JST if that field is date-only, as WAIO's FX scenario
# reports currently are).

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"
source security/lib.sh

SOURCE_REPORT="${1:-}"
FORECAST_TS_OVERRIDE="${2:-}"

if [ -z "$SOURCE_REPORT" ]; then
  echo "[FX SNAPSHOT] ERROR: source report path required"
  echo "[FX SNAPSHOT] usage: $0 <source_report.json> [forecast_timestamp_iso8601]"
  exit 1
fi

if [ ! -f "$SOURCE_REPORT" ]; then
  echo "[FX SNAPSHOT] ERROR: source report not found: $SOURCE_REPORT"
  exit 1
fi

SNAPSHOT_DIR="${WAIO_FX_SNAPSHOT_DIR:-results/fx-scenarios/snapshots}"
mkdir -p "$SNAPSHOT_DIR"

# Single python3 pass: read the source report, resolve forecast_timestamp,
# compute each horizon's deadline, build the normalized snapshot object,
# and print "<forecast_id>\t<snapshot_json>" on stdout. Kept as one pass
# (rather than shelling out per field) for the same reason
# weather_agent.sh's merge step is one pass -- no partial/half-built
# state is ever visible to the filesystem.
SNAPSHOT_BUILD="$(python3 - "$SOURCE_REPORT" "$FORECAST_TS_OVERRIDE" <<'PYEOF'
import json, sys, datetime

source_path, ts_override = sys.argv[1], sys.argv[2]

with open(source_path) as f:
    report = json.load(f)

if ts_override:
    ts_raw = ts_override
else:
    ts_raw = report.get("generated_at") or report.get("data_asof")
    if not ts_raw:
        print("ERROR\tsource report has no generated_at/data_asof field and no override was given", file=sys.stderr)
        sys.exit(1)
    if len(ts_raw) == 10:  # date-only, e.g. "2026-09-21"
        ts_raw = ts_raw + "T00:00:00+09:00"

try:
    forecast_dt = datetime.datetime.fromisoformat(ts_raw)
except ValueError as e:
    print(f"ERROR\tunparseable forecast_timestamp '{ts_raw}': {e}", file=sys.stderr)
    sys.exit(1)

if forecast_dt.tzinfo is None:
    forecast_dt = forecast_dt.replace(tzinfo=datetime.timezone(datetime.timedelta(hours=9)))

HORIZON_DELTAS = {
    "24H": datetime.timedelta(hours=24),
    "1W": datetime.timedelta(days=7),
    "1M": datetime.timedelta(days=30),
}
# the source report's own horizon keys are lowercase ("24h"/"1w"/"1m");
# the validation engine's public schema uses uppercase throughout.
SOURCE_KEY_MAP = {"24H": "24h", "1W": "1w", "1M": "1m"}

REQUIRED_PAIRS = ["USDJPY", "EURUSD", "AUDUSD", "GBPUSD", "USDCNY"]

pairs_in = report.get("pairs")
if isinstance(pairs_in, list):
    pairs_by_name = {p["pair"]: p for p in pairs_in}
elif isinstance(pairs_in, dict):
    pairs_by_name = pairs_in
else:
    print("ERROR\tsource report has no usable 'pairs' section", file=sys.stderr)
    sys.exit(1)

out_pairs = {}
missing = []
for pair_name in REQUIRED_PAIRS:
    p = pairs_by_name.get(pair_name)
    if p is None:
        missing.append(pair_name)
        continue
    current = p.get("current")
    horizons_in = p.get("horizons", {})
    out_horizons = {}
    for h_out, h_in_key in SOURCE_KEY_MAP.items():
        h = horizons_in.get(h_in_key) or horizons_in.get(h_out)
        if h is None:
            missing.append(f"{pair_name}.{h_out}")
            continue
        deadline = (forecast_dt + HORIZON_DELTAS[h_out]).isoformat()
        out_horizons[h_out] = {
            "base_range": h.get("base_range"),
            "upside_range": h.get("upside_range"),
            "downside_range": h.get("downside_range"),
            "median": h.get("median"),
            "confidence": h.get("confidence"),
            "deadline": deadline,
        }
    out_pairs[pair_name] = {
        "current_at_forecast": current,
        "horizons": out_horizons,
    }

if missing:
    print("ERROR\tsource report missing required data: " + ", ".join(missing), file=sys.stderr)
    sys.exit(1)

forecast_id = "fx-" + forecast_dt.strftime("%Y%m%dT%H%M%S%z")

snapshot = {
    "forecast_id": forecast_id,
    "forecast_timestamp": forecast_dt.isoformat(),
    "source": source_path,
    "source_report_type": report.get("report_name") or report.get("report_type") or "unknown",
    "immutable": True,
    "snapshot_saved_at": datetime.datetime.now(datetime.timezone.utc).astimezone(forecast_dt.tzinfo).isoformat(),
    "pairs": out_pairs,
}

print(forecast_id + "\t" + json.dumps(snapshot, ensure_ascii=False))
PYEOF
)"

if [[ "$SNAPSHOT_BUILD" == ERROR$'\t'* ]]; then
  echo "[FX SNAPSHOT] $SNAPSHOT_BUILD" | sed 's/^\[FX SNAPSHOT\] ERROR\t/[FX SNAPSHOT] ERROR: /'
  exit 1
fi

FORECAST_ID="${SNAPSHOT_BUILD%%$'\t'*}"
SNAPSHOT_JSON="${SNAPSHOT_BUILD#*$'\t'}"
SNAPSHOT_PATH="$SNAPSHOT_DIR/$FORECAST_ID.json"

if [ -e "$SNAPSHOT_PATH" ]; then
  echo "[FX SNAPSHOT] ERROR: snapshot already exists and is immutable -- refusing to overwrite: $SNAPSHOT_PATH"
  exit 1
fi

# add the snapshot's own content hash last, over everything computed
# above, then write once.
SNAPSHOT_HASH="$(printf '%s' "$SNAPSHOT_JSON" | _sha256)"
FINAL_JSON="$(python3 -c "
import json, sys
snap = json.loads(sys.argv[1])
snap['snapshot_sha256'] = sys.argv[2]
print(json.dumps(snap, indent=2, ensure_ascii=False))
" "$SNAPSHOT_JSON" "$SNAPSHOT_HASH")"

printf '%s\n' "$FINAL_JSON" > "$SNAPSHOT_PATH"
chmod 444 "$SNAPSHOT_PATH"

echo "[FX SNAPSHOT] saved immutable forecast snapshot: $SNAPSHOT_PATH"
echo "[FX SNAPSHOT] forecast_id=$FORECAST_ID sha256=$SNAPSHOT_HASH"
