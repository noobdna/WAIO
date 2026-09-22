#!/bin/bash
set -uo pipefail

# workers/fx_validation_worker.sh -- thin waio.sh dispatch wrapper
# around the FX Forecast Validation Engine (fx_validation/*.sh), same
# layering earthweather_worker.sh uses around earth_weather/
# run_pipeline.sh: this wrapper makes no network call and no DLP/egress
# decision of its own -- fx_validation/fetch_actual_rate.sh does its
# own egress_check immediately before its own curl call.
#
# Two-step pipeline, run in order:
#   1. fx_validation/save_forecast_snapshot.sh -- only if a source
#      report path is given as the request text; freezes a new
#      immutable forecast snapshot. Skipped (not an error) when the
#      request is empty/just "run", so a plain dispatch simply
#      validates whatever snapshot already exists.
#   2. fx_validation/run_validation.sh -- always runs, against the
#      latest snapshot, and prints the WAIO FX FORECAST VALIDATION
#      summary.

REQUEST="${1:-}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"

if [ -n "$REQUEST" ] && [ -f "$REQUEST" ]; then
  echo "[FXVALIDATION WORKER] saving new forecast snapshot from $REQUEST..."
  if ! fx_validation/save_forecast_snapshot.sh "$REQUEST"; then
    echo "[FXVALIDATION WORKER] ERROR: snapshot save failed"
    exit 1
  fi
fi

echo "[FXVALIDATION WORKER] running validation against the latest snapshot..."
fx_validation/run_validation.sh
exit $?
