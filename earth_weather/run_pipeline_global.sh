#!/bin/bash
set -uo pipefail

# earth_weather/run_pipeline_global.sh -- Earth & Weather Intelligence
# PoC, GLOBAL pipeline orchestrator:
#   Weather Agent (multi-station, Open-Meteo) -> Earthquake Agent
#   (worldwide, USGS) -> Data Normalizer -> Correlation Engine
#   (per-station + pooled) -> Intelligence Layer
#
# Same degrade-gracefully contract as run_pipeline.sh: each stage runs
# in isolation, a failure is logged and the run continues with
# whatever data already exists on disk, never aborts the whole run.
#
# NOT wired into workers/registry.conf -- deliberately scoped this
# phase to "test-isolated environment only, no change to the
# production dispatcher or security/egress_allowlist.conf" (see
# ARCHITECTURE.md's "Earth & Weather Intelligence: global expansion"
# phase entry). Run directly, or through
# tests/earth_weather_global_test.sh's fixtures.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"

EW_DATA_DIR="${EW_DATA_DIR:-earth_weather/data}"
LOG_FILE="${EW_PIPELINE_GLOBAL_LOG:-$EW_DATA_DIR/pipeline_global_run.log}"
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

log "=== Earth & Weather Intelligence GLOBAL pipeline run start ==="

run_stage "weather_agent_global" "earth_weather/weather_agent_global.sh"
run_stage "earthquake_agent_global" "earth_weather/earthquake_agent_global.sh"
run_stage "data_normalizer_global" "earth_weather/data_normalizer_global.sh"
run_stage "correlation_engine_global" "earth_weather/correlation_engine_global.sh"
run_stage "intelligence_layer_global" "earth_weather/intelligence_layer_global.sh"

FAILED_COUNT=0
for s in "${STAGE_STATUS[@]}"; do
  case "$s" in *=failed) FAILED_COUNT=$((FAILED_COUNT + 1)) ;; esac
done

if [ "$FAILED_COUNT" -eq 0 ]; then
  OVERALL="ok"
elif [ -s "$EW_DATA_DIR/intelligence_summary_global.json" ]; then
  OVERALL="degraded"
else
  OVERALL="failed"
fi

log "=== pipeline run end: overall=$OVERALL (${STAGE_STATUS[*]}) ==="

if [ "$OVERALL" = "failed" ]; then
  exit 1
fi
exit 0
