#!/bin/bash
set -uo pipefail

# WAIO Controller (formal entry point: ./waio.sh -w ORCHESTRATE "<request>")
#
# Pipeline selection, highest priority first:
#   1. WAIO_PIPELINE env var -- explicit, space-separated list of
#      workers/registry.conf NAMEs, overrides everything else for this one
#      invocation:
#        WAIO_PIPELINE="RESEARCH AI" ./waio.sh -w ORCHESTRATE "<request>"
#   2. Router -- reads every NAME/TYPE pair straight out of
#      workers/registry.conf (skipping ORCHESTRATE itself) and includes a
#      NAME in the pipeline iff its NAME or TYPE appears as a
#      case-insensitive substring of REQUEST -- the exact same matching
#      rule waio.sh's own keyword dispatch already uses, just applied to
#      pick a whole ordered set instead of a single worker. Order = the
#      order those NAMEs appear in registry.conf. No NAME is ever
#      hardcoded here; this loop only ever emits NAMEs it just read from
#      the registry.
#   3. workers/pipeline.conf -- fixed fallback, used only if neither of the
#      above produced any stage (e.g. a request that names no worker at
#      all), so a request that doesn't have a resolvable Router path still
#      behaves exactly as Phase 7-9 did.
# workers/pipeline.conf itself is never modified by any of this.
#
# Execution path, explicit at every stage:
#   REQUEST             - the incoming request text ($1).
#   ROUTER              - match REQUEST against registry.conf NAME/TYPE
#                          (see priority list above).
#   TASK CLASSIFICATION - label what the Router found: "override" (an
#                          explicit WAIO_PIPELINE), "single" (Router
#                          matched exactly one worker), "multi" (Router
#                          matched 2+), or "fallback" (Router matched
#                          nothing, workers/pipeline.conf will be used).
#   PIPELINE SELECTION  - turn that classification into the final STAGES
#                          list (this is where WAIO_PIPELINE / Router
#                          result / pipeline.conf actually gets picked).
#   WORKER EXECUTION    - per stage: ROUTE (resolve the NAME in
#                          registry.conf) -> EXECUTE (./waio.sh -w NAME
#                          "<stage input>", the same entry point a human
#                          operator would use) -> COLLECT (strip that
#                          worker's own dispatch/log lines, keeping only
#                          the content after its "] response:" marker --
#                          a convention every current pipeline-compatible
#                          worker already follows).
#   FAILURE HANDLING    - a failed stage does not abort the run: its
#                          status/output is folded into the next stage's
#                          input (labeled FAILED), so later stages -- or
#                          whoever reads the log/JSON -- still see it.
#   RESULT AGGREGATION  - the last stage's collected content, every
#                          stage's status, and overall_status, written to
#                          a per-run log (logs/), a human-readable result
#                          file, and a machine-readable JSON result file
#                          (both under results/).
#
# overall_status is one of three values, and the process exit code always
# matches it:
#   ok       (exit 0) - every stage succeeded.
#   degraded (exit 1) - at least one stage failed, but the LAST stage in
#                        the pipeline still succeeded, so final_result is
#                        a genuine answer (just produced despite trouble
#                        somewhere upstream).
#   failed   (exit 2) - the LAST stage itself failed, so final_result is
#                        actually that failure's error text, not a
#                        trustworthy answer.
#
# Output contract: human-readable progress/log lines go to stdout as
# "[ORCHESTRATE WORKER] ..." text (for a person running this directly).
# Machine-readable per-stage status lives ONLY in the JSON result file
# (results/orchestrate-<run_id>.json) -- never inlined into the human log
# text -- so a script consuming this run's outcome should read that file,
# not parse stdout.
#
# Adding a new provider (Claude / OpenAI / Gemini / a local agent) needs no
# change here: register a new worker script + a registry.conf line (and
# optionally add its NAME to pipeline.conf), the same way RESEARCH/
# ANALYSIS/AI/HEALTHCHECK/HOST800 already are. This script adds no
# registry.conf entries of its own.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"

REQUEST="$1"

if [ -z "$REQUEST" ]; then
  echo "[ORCHESTRATE WORKER] ERROR: empty request"
  exit 1
fi

PIPELINE_CONF="workers/pipeline.conf"
REGISTRY_CONF="workers/registry.conf"

# ROUTER: read every registered NAME/TYPE straight from registry.conf
# (never hardcoded), skip ORCHESTRATE itself, and include a NAME iff its
# own NAME or TYPE appears as a case-insensitive substring of REQUEST --
# same matching rule waio.sh's single-worker keyword dispatch already
# uses. Preserves registry.conf file order.
route_request() {
  local request_upper name host script type name_upper type_upper
  request_upper="$(printf '%s' "$REQUEST" | tr '[:lower:]' '[:upper:]')"

  if [ ! -f "$REGISTRY_CONF" ]; then
    return 0
  fi

  while IFS='|' read -r name host script type; do
    case "$name" in
      ""|\#*) continue ;;
    esac
    name_upper="$(printf '%s' "$name" | tr '[:lower:]' '[:upper:]')"
    [ "$name_upper" = "ORCHESTRATE" ] && continue
    type_upper="$(printf '%s' "$type" | tr '[:lower:]' '[:upper:]')"
    if [[ "$request_upper" == *"$name_upper"* ]] || { [ -n "$type_upper" ] && [[ "$request_upper" == *"$type_upper"* ]]; }; then
      echo "$name"
    fi
  done < "$REGISTRY_CONF"
}

# TASK CLASSIFICATION
declare -a STAGES=()
if [ -n "${WAIO_PIPELINE:-}" ]; then
  TASK_CLASSIFICATION="override"
else
  declare -a ROUTED_STAGES=()
  while IFS= read -r routed_name; do
    [ -n "$routed_name" ] && ROUTED_STAGES+=("$routed_name")
  done < <(route_request)

  case "${#ROUTED_STAGES[@]}" in
    0) TASK_CLASSIFICATION="fallback" ;;
    1) TASK_CLASSIFICATION="single" ;;
    *) TASK_CLASSIFICATION="multi" ;;
  esac
fi

# PIPELINE SELECTION
case "$TASK_CLASSIFICATION" in
  override)
    PIPELINE_SOURCE="env:WAIO_PIPELINE"
    read -ra STAGES <<< "$WAIO_PIPELINE"
    ;;
  single|multi)
    PIPELINE_SOURCE="router"
    STAGES=("${ROUTED_STAGES[@]}")
    ;;
  fallback)
    PIPELINE_SOURCE="$PIPELINE_CONF"
    if [ ! -f "$PIPELINE_CONF" ]; then
      echo "[ORCHESTRATE WORKER] ERROR: pipeline config not found: $PIPELINE_CONF"
      exit 1
    fi
    while IFS= read -r line; do
      case "$line" in
        ""|\#*) continue ;;
      esac
      STAGES+=("$line")
    done < "$PIPELINE_CONF"
    ;;
esac

if [ "${#STAGES[@]}" -eq 0 ]; then
  echo "[ORCHESTRATE WORKER] ERROR: no stages configured (source: $PIPELINE_SOURCE)"
  exit 1
fi

for s in "${STAGES[@]}"; do
  if [ "$(printf '%s' "$s" | tr '[:lower:]' '[:upper:]')" = "ORCHESTRATE" ]; then
    echo "[ORCHESTRATE WORKER] ERROR: pipeline (source: $PIPELINE_SOURCE) lists ORCHESTRATE itself -- would recurse, refusing to run"
    exit 1
  fi
done

mkdir -p logs results
RUN_ID="$(date +%Y%m%d-%H%M%S)"
LOG="logs/orchestrate-$RUN_ID.log"
RESULT_TXT="results/orchestrate-$RUN_ID.txt"
RESULT_JSON="results/orchestrate-$RUN_ID.json"
STAGES_JSONL="$(mktemp)"
trap 'rm -f "$STAGES_JSONL"' EXIT

log() { echo "$1" | tee -a "$LOG"; }

log "[ORCHESTRATE WORKER] REQUEST run=$RUN_ID"
log "[ORCHESTRATE WORKER] TASK CLASSIFICATION: $TASK_CLASSIFICATION"
log "[ORCHESTRATE WORKER] PIPELINE SELECTION: pipeline=${STAGES[*]} pipeline_source=$PIPELINE_SOURCE"

HISTORY=""
STAGE_RESULT=""
declare -a STAGE_STATUS=()
ANY_STAGE_FAILED="false"

for i in "${!STAGES[@]}"; do
  NAME="${STAGES[$i]}"
  STEP=$((i + 1))

  if [ "$i" -eq 0 ]; then
    STAGE_INPUT="$REQUEST"
  else
    STAGE_INPUT="Original request: $REQUEST
$HISTORY"
  fi

  log "[ORCHESTRATE WORKER] ROUTE stage $STEP/${#STAGES[@]}: $NAME (resolved via workers/registry.conf)"
  log "[ORCHESTRATE WORKER] EXECUTE ./waio.sh -w $NAME"

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
    log "[ORCHESTRATE WORKER] COLLECT stage $STEP ($NAME) status=ok"
  else
    STATUS_WORD="FAILED"
    STAGE_STATUS+=("$NAME=failed")
    ANY_STAGE_FAILED="true"
    log "[ORCHESTRATE WORKER] COLLECT stage $STEP ($NAME) status=failed exit=$RC"
    log "[ORCHESTRATE WORKER] FAILURE HANDLING: forwarding stage $STEP ($NAME) failure into the next stage's input instead of aborting"
  fi

  {
    echo "--- stage $STEP: $NAME ($STATUS_WORD) ---"
    echo "$STAGE_RESULT"
  } >> "$LOG"

  # machine-readable per-stage record (one JSON object per line); combined
  # into RESULT_JSON below once every stage has run.
  python3 -c "
import json, sys
name, status, exit_code, result = sys.argv[1:5]
print(json.dumps({'name': name, 'status': status, 'exit_code': int(exit_code), 'result': result}))
" "$NAME" "$([ "$RC" -eq 0 ] && echo ok || echo failed)" "$RC" "$STAGE_RESULT" >> "$STAGES_JSONL"

  HISTORY="$HISTORY

$NAME ($STATUS_WORD):
$STAGE_RESULT"
done

FINAL_RESULT="$STAGE_RESULT"

# RESULT AGGREGATION: three-way overall_status. "failed" means the LAST
# stage itself failed (final_result is that failure's error text, not a
# trustworthy answer); "degraded" means some earlier stage failed but the
# last stage still produced a genuine result; "ok" means nothing failed.
if [ "$ANY_STAGE_FAILED" = "false" ]; then
  OVERALL_STATUS="ok"
elif [ "$RC" -eq 0 ]; then
  OVERALL_STATUS="degraded"
else
  OVERALL_STATUS="failed"
fi

# RESULT (human-readable)
{
  echo "run_id: $RUN_ID"
  echo "pipeline: ${STAGES[*]}"
  echo "pipeline_source: $PIPELINE_SOURCE"
  echo "task_classification: $TASK_CLASSIFICATION"
  echo "stage_status: ${STAGE_STATUS[*]}"
  echo "overall_status: $OVERALL_STATUS"
  echo "---"
  echo "$FINAL_RESULT"
} > "$RESULT_TXT"

# RESULT (machine-readable) -- the only place per-stage status is emitted
# as structured data; stdout stays human-readable text (see header comment).
python3 -c "
import json, sys
run_id, pipeline_str, pipeline_source, task_classification, overall_status, final_result, log_path, result_txt_path, stages_jsonl = sys.argv[1:10]
stages = []
with open(stages_jsonl) as f:
    for line in f:
        line = line.strip()
        if line:
            stages.append(json.loads(line))
out = {
    'run_id': run_id,
    'pipeline': pipeline_str.split(),
    'pipeline_source': pipeline_source,
    'task_classification': task_classification,
    'stages': stages,
    'overall_status': overall_status,
    'final_result': final_result,
    'log_path': log_path,
    'result_txt_path': result_txt_path,
}
print(json.dumps(out, indent=2))
" "$RUN_ID" "${STAGES[*]}" "$PIPELINE_SOURCE" "$TASK_CLASSIFICATION" "$OVERALL_STATUS" "$FINAL_RESULT" "$LOG" "$RESULT_TXT" "$STAGES_JSONL" > "$RESULT_JSON"

log "[ORCHESTRATE WORKER] RESULT AGGREGATION run=$RUN_ID stage_status=${STAGE_STATUS[*]} overall_status=$OVERALL_STATUS"
log "[ORCHESTRATE WORKER] log: $LOG"
log "[ORCHESTRATE WORKER] result (human): $RESULT_TXT"
log "[ORCHESTRATE WORKER] result (machine/json): $RESULT_JSON"

echo "[ORCHESTRATE WORKER] response:"
echo "$FINAL_RESULT"

case "$OVERALL_STATUS" in
  ok) exit 0 ;;
  degraded) exit 1 ;;
  *) exit 2 ;;
esac
