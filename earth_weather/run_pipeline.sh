#!/bin/bash
set -uo pipefail

# earth_weather/run_pipeline.sh -- Earth & Weather Intelligence PoC,
# full pipeline orchestrator:
#   Weather Agent -> Earthquake Agent -> Data Normalizer
#   -> Correlation Engine -> Intelligence Layer
#
# Requirement #6 (Data integrity) of this PoC: "API障害時はWAIOを停止
# させない". Each stage runs in isolation -- a non-zero exit from
# weather_agent.sh or earthquake_agent.sh (the only two stages that
# make a real network call) is logged and the pipeline continues with
# whatever data already exists on disk from a previous successful run;
# it never aborts the whole run and never propagates a failure that
# would take down waio.sh or any other worker. Local-only stages
# (normalizer/correlation/intelligence) are expected to succeed as
# long as at least one Agent has ever produced data; if neither ever
# has, the normalizer produces an empty timeline and the correlation
# engine reports insufficient_data -- never a crash.
#
# Intended entry points: workers/earthweather_worker.sh (manual,
# through ./waio.sh -w EARTHWEATHER "...") and
# com.waio.earth-weather.plist.example (scheduled, same launchd
# pattern as security/incident_learning/com.waio.incident-learning.plist.example).

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"

EW_DATA_DIR="${EW_DATA_DIR:-earth_weather/data}"
LOG_FILE="${EW_PIPELINE_LOG:-$EW_DATA_DIR/pipeline_run.log}"
mkdir -p "$(dirname "$LOG_FILE")"

log() {
  printf '%s %s\n' "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" "$1" | tee -a "$LOG_FILE"
}

declare -a STAGE_STATUS=()

run_stage() {
  local name="$1" script="$2"
  log "stage start: $name"
  if bash "$script" 2>&1 | tee -a "$LOG_FILE"; then
    log "stage ok: $name"
    STAGE_STATUS+=("$name=ok")
  else
    log "stage FAILED (degraded, continuing): $name"
    STAGE_STATUS+=("$name=failed")
  fi
}

log "=== Earth & Weather Intelligence pipeline run start ==="

run_stage "weather_agent" "earth_weather/weather_agent.sh"
run_stage "earthquake_agent" "earth_weather/earthquake_agent.sh"
run_stage "data_normalizer" "earth_weather/data_normalizer.sh"
run_stage "correlation_engine" "earth_weather/correlation_engine.sh"
run_stage "intelligence_layer" "earth_weather/intelligence_layer.sh"

FAILED_COUNT=0
for s in "${STAGE_STATUS[@]}"; do
  case "$s" in *=failed) FAILED_COUNT=$((FAILED_COUNT + 1)) ;; esac
done

if [ "$FAILED_COUNT" -eq 0 ]; then
  OVERALL="ok"
elif [ -s "$EW_DATA_DIR/intelligence_summary.json" ]; then
  OVERALL="degraded"
else
  OVERALL="failed"
fi

log "=== pipeline run end: overall=$OVERALL (${STAGE_STATUS[*]}) ==="

if [ "$OVERALL" = "failed" ]; then
  exit 1
fi
exit 0
