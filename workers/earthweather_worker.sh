#!/bin/bash
set -uo pipefail

# Earth & Weather Intelligence worker: thin waio.sh dispatch wrapper
# around earth_weather/run_pipeline.sh (Weather Agent -> Earthquake
# Agent -> Data Normalizer -> Correlation Engine -> Intelligence
# Layer). All egress_check/DLP calls happen inside
# earth_weather/weather_agent.sh and earth_weather/earthquake_agent.sh
# themselves, the same layering orchestrate_worker.sh uses for its own
# pipeline stages -- this wrapper makes no network call of its own.
#
# A degraded run (one Agent's API unreachable) is not treated as a
# dispatch failure here -- see run_pipeline.sh's own header for why;
# exit 1 is reserved for "no result was produced at all".

REQUEST="${1:-}"

if [ -z "$REQUEST" ]; then
  echo "[EARTHWEATHER WORKER] ERROR: empty request"
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"

EW_DATA_DIR="${EW_DATA_DIR:-earth_weather/data}"

echo "[EARTHWEATHER WORKER] running Earth & Weather Intelligence pipeline..."
./earth_weather/run_pipeline.sh
PIPELINE_RC=$?

if [ -f "$EW_DATA_DIR/intelligence_summary.txt" ]; then
  echo "[EARTHWEATHER WORKER] summary:"
  cat "$EW_DATA_DIR/intelligence_summary.txt"
  echo "[EARTHWEATHER WORKER] completed"
  exit 0
fi

echo "[EARTHWEATHER WORKER] ERROR: pipeline produced no summary (exit=$PIPELINE_RC) -- see $EW_DATA_DIR/pipeline_run.log"
exit 1
