#!/bin/bash
set -uo pipefail

# WAIO Controller (formal entry point: ./waio.sh -w ORCHESTRATE "<request>")
#
# Pipeline selection: by default the ordered stage list comes from
# workers/pipeline.conf. A single invocation may override it for that
# request only by setting WAIO_PIPELINE to a space-separated list of
# workers/registry.conf NAMEs, e.g.:
#   WAIO_PIPELINE="RESEARCH AI" ./waio.sh -w ORCHESTRATE "<request>"
# pipeline.conf itself is never modified by this -- it is a one-off,
# per-request override, not a way to edit the default.
#
# Execution path, explicit at every stage:
#   REQUEST  - the incoming request text ($1).
#   ROUTE    - look up the next pipeline NAME (from WAIO_PIPELINE if set,
#              else workers/pipeline.conf) in workers/registry.conf (the
#              single source of truth for which Agent/Worker exists; this
#              script never hardcodes one).
#   EXECUTE  - ./waio.sh -w <NAME> "<stage input>", the same entry point a
#              human operator would use.
#   COLLECT  - strip that worker's own dispatch/log lines, keeping only the
#              content after its "] response:" marker (a convention every
#              current pipeline-compatible worker already follows).
#   RESULT   - the last stage's collected content, plus a per-run log
#              (logs/), a human-readable result file, and a machine-readable
#              JSON result file (both under results/).
#
# A failed stage does not abort the run: its status/output is folded into
# the next stage's input (labeled FAILED), so later stages -- or whoever
# reads the log/JSON -- still see it. overall_status is "degraded" if any
# stage failed, "ok" otherwise, and the process exit code matches (0 iff
# every stage was ok) -- unchanged from Phase 7.
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

declare -a STAGES=()
if [ -n "${WAIO_PIPELINE:-}" ]; then
  PIPELINE_SOURCE="env:WAIO_PIPELINE"
  read -ra STAGES <<< "$WAIO_PIPELINE"
else
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
fi

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

log "[ORCHESTRATE WORKER] REQUEST run=$RUN_ID pipeline=${STAGES[*]} pipeline_source=$PIPELINE_SOURCE"

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
    OVERALL_STATUS="degraded"
    log "[ORCHESTRATE WORKER] COLLECT stage $STEP ($NAME) status=failed exit=$RC -- forwarding its output to the next stage anyway"
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

# RESULT (human-readable)
{
  echo "run_id: $RUN_ID"
  echo "pipeline: ${STAGES[*]}"
  echo "pipeline_source: $PIPELINE_SOURCE"
  echo "stage_status: ${STAGE_STATUS[*]}"
  echo "overall_status: $OVERALL_STATUS"
  echo "---"
  echo "$FINAL_RESULT"
} > "$RESULT_TXT"

# RESULT (machine-readable) -- the only place per-stage status is emitted
# as structured data; stdout stays human-readable text (see header comment).
python3 -c "
import json, sys
run_id, pipeline_str, pipeline_source, overall_status, final_result, log_path, result_txt_path, stages_jsonl = sys.argv[1:9]
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
    'stages': stages,
    'overall_status': overall_status,
    'final_result': final_result,
    'log_path': log_path,
    'result_txt_path': result_txt_path,
}
print(json.dumps(out, indent=2))
" "$RUN_ID" "${STAGES[*]}" "$PIPELINE_SOURCE" "$OVERALL_STATUS" "$FINAL_RESULT" "$LOG" "$RESULT_TXT" "$STAGES_JSONL" > "$RESULT_JSON"

log "[ORCHESTRATE WORKER] RESULT run=$RUN_ID stage_status=${STAGE_STATUS[*]} overall_status=$OVERALL_STATUS"
log "[ORCHESTRATE WORKER] log: $LOG"
log "[ORCHESTRATE WORKER] result (human): $RESULT_TXT"
log "[ORCHESTRATE WORKER] result (machine/json): $RESULT_JSON"

echo "[ORCHESTRATE WORKER] response:"
echo "$FINAL_RESULT"

[ "$OVERALL_STATUS" = "ok" ]
