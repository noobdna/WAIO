#!/bin/bash
set -uo pipefail

# WAIO Controller: REQUEST -> ROUTE -> EXECUTE -> COLLECT -> RESULT
#
# Reads workers/pipeline.conf for an ordered list of workers/registry.conf
# NAMEs -- the Registry is the single source of truth here. This script
# never hardcodes an Agent/Worker id; it only knows Registry NAMEs and
# dispatches each one through the existing ./waio.sh -w <NAME> path, the
# same entry point a human operator would use. Each stage's output
# (success or failure) is folded into the next stage's input, annotated
# with that stage's outcome, so a failed worker's result is never silently
# dropped -- later stages (or a human reading the log) still see it. Every
# run is logged to logs/ and its final result written to results/
# (pre-existing, gitignored dirs -- reactivating the logging convention
# orchestrator/dispatch.sh used before the registry migration).
#
# Adding a new provider (Claude / OpenAI / Gemini / a local agent) needs no
# change here: register a new worker script + a registry.conf line (and
# optionally add its NAME to pipeline.conf), the same way RESEARCH/
# ANALYSIS/AI/HEALTHCHECK/HOST800 already are.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"

REQUEST="$1"

if [ -z "$REQUEST" ]; then
  echo "[ORCHESTRATE WORKER] ERROR: empty request"
  exit 1
fi

PIPELINE_CONF="workers/pipeline.conf"

if [ ! -f "$PIPELINE_CONF" ]; then
  echo "[ORCHESTRATE WORKER] ERROR: pipeline config not found: $PIPELINE_CONF"
  exit 1
fi

declare -a STAGES=()
while IFS= read -r line; do
  case "$line" in
    ""|\#*) continue ;;
  esac
  STAGES+=("$line")
done < "$PIPELINE_CONF"

if [ "${#STAGES[@]}" -eq 0 ]; then
  echo "[ORCHESTRATE WORKER] ERROR: no stages configured in $PIPELINE_CONF"
  exit 1
fi

for s in "${STAGES[@]}"; do
  if [ "$(printf '%s' "$s" | tr '[:lower:]' '[:upper:]')" = "ORCHESTRATE" ]; then
    echo "[ORCHESTRATE WORKER] ERROR: $PIPELINE_CONF lists ORCHESTRATE itself -- would recurse, refusing to run"
    exit 1
  fi
done

mkdir -p logs results
RUN_ID="$(date +%Y%m%d-%H%M%S)"
LOG="logs/orchestrate-$RUN_ID.log"
RESULT_FILE="results/orchestrate-$RUN_ID.txt"

log() { echo "$1" | tee -a "$LOG"; }

log "[ORCHESTRATE WORKER] run $RUN_ID: pipeline = ${STAGES[*]}"

HISTORY=""
STAGE_RESULT=""
declare -a STAGE_STATUS=()
OVERALL_STATUS="ok"

for i in "${!STAGES[@]}"; do
  NAME="${STAGES[$i]}"
  STEP=$((i + 1))

  if [ "$i" -eq 0 ]; then
    STAGE_INPUT="$REQUEST"
  else
    STAGE_INPUT="Original request: $REQUEST
$HISTORY"
  fi

  log "[ORCHESTRATE WORKER] stage $STEP/${#STAGES[@]}: $NAME (ROUTE+EXECUTE via ./waio.sh -w $NAME)"

  RAW_OUTPUT="$(./waio.sh -w "$NAME" "$STAGE_INPUT" 2>&1)"
  RC=$?

  # COLLECT: every current pipeline-compatible worker ends its real result
  # with a line matching "] response:" -- everything after that marker is
  # the result, everything before it is dispatch/log noise. A worker that
  # errors before reaching that point has no marker, so we fall back to
  # its raw combined output (still useful failure context).
  if printf '%s\n' "$RAW_OUTPUT" | grep -q '\] response:$'; then
    STAGE_RESULT="$(printf '%s\n' "$RAW_OUTPUT" | sed -n '/\] response:$/,$p' | tail -n +2)"
  else
    STAGE_RESULT="$RAW_OUTPUT"
  fi

  if [ "$RC" -eq 0 ]; then
    STATUS_WORD="ok"
    STAGE_STATUS+=("$NAME=ok")
    log "[ORCHESTRATE WORKER] stage $STEP ($NAME) OK"
  else
    STATUS_WORD="FAILED"
    STAGE_STATUS+=("$NAME=failed")
    OVERALL_STATUS="degraded"
    log "[ORCHESTRATE WORKER] stage $STEP ($NAME) FAILED (exit $RC) -- forwarding its output to the next stage anyway"
  fi

  {
    echo "--- stage $STEP: $NAME ($STATUS_WORD) ---"
    echo "$STAGE_RESULT"
  } >> "$LOG"

  HISTORY="$HISTORY

$NAME ($STATUS_WORD):
$STAGE_RESULT"
done

FINAL_RESULT="$STAGE_RESULT"

{
  echo "run_id: $RUN_ID"
  echo "pipeline: ${STAGES[*]}"
  echo "stage_status: ${STAGE_STATUS[*]}"
  echo "overall_status: $OVERALL_STATUS"
  echo "---"
  echo "$FINAL_RESULT"
} > "$RESULT_FILE"

log "[ORCHESTRATE WORKER] run $RUN_ID complete: stage_status=${STAGE_STATUS[*]} overall_status=$OVERALL_STATUS"
log "[ORCHESTRATE WORKER] log: $LOG"
log "[ORCHESTRATE WORKER] result file: $RESULT_FILE"

echo "[ORCHESTRATE WORKER] response:"
echo "$FINAL_RESULT"

[ "$OVERALL_STATUS" = "ok" ]
