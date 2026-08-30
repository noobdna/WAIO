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
#      the registry. The Router never produces a parallel group (see
#      below); it only ever emits one NAME per matched worker.
#   3. workers/pipeline.conf -- fixed fallback, used only if neither of the
#      above produced any stage (e.g. a request that names no worker at
#      all), so a request that doesn't have a resolvable Router path still
#      behaves exactly as Phase 7-9 did.
# workers/pipeline.conf itself is never modified by any of this.
#
# Parallel stages (Phase 13): a stage token (one WAIO_PIPELINE word, or one
# pipeline.conf line) may be a "+"-joined group of NAMEs, e.g.
# "RESEARCH+ANALYSIS", meaning both run concurrently against the same
# stage input and their results are merged before the next stage runs. A
# token with no "+" is a group of exactly one NAME -- the ordinary
# sequential case, byte-identical to Phase 7-12 behavior. Groups are only
# ever produced by an explicit "+" in WAIO_PIPELINE/pipeline.conf; the
# Router (step 2 above) and TASK CLASSIFICATION are unchanged and never
# emit a group themselves.
#
# Concurrency cap (Phase 15): WAIO_MAX_PARALLEL, an optional positive
# integer env var, caps how many members of a single group run at once.
# Unset (the default) means uncapped -- every member of a group launches
# together, byte-identical to Phase 13 behavior. When set, a group larger
# than the cap runs in sequential batches of at most that many members;
# batch order follows group-token order (same determinism guarantee
# Phase 13 already made for merge order), and a group at or under the cap
# is unaffected either way.
#
# Branching (Phase 16): a stage token in WAIO_PIPELINE/pipeline.conf may
# be prefixed "?ok:" or "?fail:" (case-insensitive), e.g. "?fail:ECHO" or
# "?ok:RESEARCH+ANALYSIS" (composes with "+" groups -- the prefix applies
# to the whole group, not per member). The condition is checked against
# whether the most recently EXECUTED stage (skips don't count, see below)
# had every member succeed: "?ok:" runs only if it did, "?fail:" only if
# it did not. Before any stage has executed, the baseline is "ok" (so a
# "?ok:" first stage runs, a "?fail:" first stage is skipped). A token
# with no "?" prefix is unconditional -- always runs -- exactly like
# every stage before this phase. This is deliberately scoped to
# success/failure only; branching on a stage's actual output content is
# a separate, unstarted feature. The Router never emits a "?"-prefixed
# token; branching, like "+" groups, is opt-in only via
# WAIO_PIPELINE/pipeline.conf.
#
# A skipped stage runs nothing: no EXECUTE, no COLLECT, it contributes no
# text to HISTORY/FINAL_RESULT, and it does not move
# ANY_STAGE_FAILED/LAST_EXECUTED_GROUP_ALL_OK -- the next conditional
# stage still checks the last stage that actually ran, skipping straight
# over it. Each of its members is still recorded, with status "skipped"
# (exit_code null, empty result), in stage_status and the JSON stages
# array, so a skip is always visible after the fact. If EVERY stage in a
# run is skipped, that is treated as a configuration error (nothing ran,
# nothing to report) and the run exits 1 before writing any result files.
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
#   BRANCH              - for a "?ok:"/"?fail:"-prefixed stage only:
#                          decide whether to run it at all, per the
#                          Branching section above. An unconditional
#                          stage has no BRANCH step, same as before this
#                          phase.
#   WORKER EXECUTION    - per stage (a group of one or more NAMEs, see
#                          above): ROUTE (resolve each NAME in
#                          registry.conf) -> EXECUTE (./waio.sh -w NAME
#                          "<stage input>" per group member, concurrently
#                          when the group has more than one member) ->
#                          COLLECT (strip each member's own dispatch/log
#                          lines, keeping only the content after its
#                          "] response:" marker -- a convention every
#                          current pipeline-compatible worker already
#                          follows).
#   FAILURE HANDLING    - a failed group member does not abort the run:
#                          its status/output is folded into the next
#                          stage's input (labeled FAILED), so later
#                          stages -- or whoever reads the log/JSON --
#                          still see it. The rest of that member's group
#                          still runs to completion.
#   RESULT AGGREGATION  - the last stage's collected content (every
#                          member's, labeled, if the last stage was a
#                          group of more than one), every member's
#                          status, and overall_status, written to a
#                          per-run log (logs/), a human-readable result
#                          file, and a machine-readable JSON result file
#                          (both under results/).
#
# overall_status is one of three values, and the process exit code always
# matches it:
#   ok       (exit 0) - every stage succeeded.
#   degraded (exit 1) - at least one stage failed, but every member of the
#                        LAST stage in the pipeline still succeeded, so
#                        final_result is a genuine answer (just produced
#                        despite trouble somewhere upstream).
#   failed   (exit 2) - at least one member of the LAST stage itself
#                        failed, so final_result includes that failure's
#                        error text, not (only) a trustworthy answer.
#
# Output contract: human-readable progress/log lines go to stdout as
# "[ORCHESTRATE WORKER] ..." text (for a person running this directly).
# Machine-readable per-stage status lives ONLY in the JSON result file
# (results/orchestrate-<run_id>.json) -- never inlined into the human log
# text -- so a script consuming this run's outcome should read that file,
# not parse stdout. Each JSON stage entry keeps the same four fields as
# Phase 8 (name/status/exit_code/result) plus one new additive field,
# "step" -- entries sharing the same step number ran in the same
# (possibly parallel) group. A consumer that only reads the original four
# fields is unaffected. Phase 16 adds one new possible "status" value,
# "skipped" (exit_code null, empty result) for a branch-skipped member --
# a consumer that only expects "ok"/"failed" should be updated to also
# handle it, same kind of note Phase 11 made when it added "failed" to
# overall_status.
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
# uses. Preserves registry.conf file order. Never emits a "+" group.
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

# WAIO_MAX_PARALLEL validation: optional, must be a positive integer when
# set. Validated once up front, before any stage runs -- same "fail fast,
# no partial run" style as the self-reference guard below.
if [ -n "${WAIO_MAX_PARALLEL:-}" ]; then
  case "$WAIO_MAX_PARALLEL" in
    *[!0-9]*|'')
      echo "[ORCHESTRATE WORKER] ERROR: WAIO_MAX_PARALLEL must be a positive integer, got '$WAIO_MAX_PARALLEL'"
      exit 1
      ;;
  esac
  if [ "$WAIO_MAX_PARALLEL" -lt 1 ]; then
    echo "[ORCHESTRATE WORKER] ERROR: WAIO_MAX_PARALLEL must be a positive integer, got '$WAIO_MAX_PARALLEL'"
    exit 1
  fi
fi

# BRANCH prefix parsing + self-reference guard, one pass, up front (fail
# fast, no partial run): strip an optional "?ok:"/"?fail:" condition
# prefix from each stage token first, so the "+" split and the
# self-reference check below both operate on the actual NAME(s), not the
# condition syntax. STAGE_TOKENS/STAGE_CONDITIONS stay aligned with
# STAGES by index and are what the main loop below actually uses.
declare -a STAGE_TOKENS=()
declare -a STAGE_CONDITIONS=()
for s in "${STAGES[@]}"; do
  s_upper="$(printf '%s' "$s" | tr '[:lower:]' '[:upper:]')"
  cond=""
  tok="$s"
  case "$s_upper" in
    \?OK:*) cond="ok"; tok="${s#*:}" ;;
    \?FAIL:*) cond="fail"; tok="${s#*:}" ;;
    \?*)
      echo "[ORCHESTRATE WORKER] ERROR: pipeline (source: $PIPELINE_SOURCE) has an unknown condition prefix in '$s' -- supported: ?ok: ?fail:"
      exit 1
      ;;
  esac
  if [ -z "$tok" ]; then
    echo "[ORCHESTRATE WORKER] ERROR: pipeline (source: $PIPELINE_SOURCE) has an empty stage after its condition prefix in '$s'"
    exit 1
  fi
  STAGE_CONDITIONS+=("$cond")
  STAGE_TOKENS+=("$tok")

  # self-reference guard: split on "+" first, so a group like
  # "ECHO+ORCHESTRATE" is caught too, not just a bare "ORCHESTRATE".
  IFS='+' read -ra GUARD_MEMBERS <<< "$tok"
  for gm in "${GUARD_MEMBERS[@]}"; do
    if [ "$(printf '%s' "$gm" | tr '[:lower:]' '[:upper:]')" = "ORCHESTRATE" ]; then
      echo "[ORCHESTRATE WORKER] ERROR: pipeline (source: $PIPELINE_SOURCE) lists ORCHESTRATE itself -- would recurse, refusing to run"
      exit 1
    fi
  done
done

mkdir -p logs results
RUN_ID="$(date +%Y%m%d-%H%M%S)"
LOG="logs/orchestrate-$RUN_ID.log"
RESULT_TXT="results/orchestrate-$RUN_ID.txt"
RESULT_JSON="results/orchestrate-$RUN_ID.json"
STAGES_JSONL="$(mktemp)"
RUN_TMP_DIR="$(mktemp -d)"
trap 'rm -f "$STAGES_JSONL"; rm -rf "$RUN_TMP_DIR"' EXIT

log() { echo "$1" | tee -a "$LOG"; }

log "[ORCHESTRATE WORKER] REQUEST run=$RUN_ID"
log "[ORCHESTRATE WORKER] TASK CLASSIFICATION: $TASK_CLASSIFICATION"
log "[ORCHESTRATE WORKER] PIPELINE SELECTION: pipeline=${STAGES[*]} pipeline_source=$PIPELINE_SOURCE"

HISTORY=""
FINAL_RESULT=""
declare -a STAGE_STATUS=()
ANY_STAGE_FAILED="false"
LAST_EXECUTED_GROUP_ALL_OK="true"
EXECUTED_COUNT=0

for i in "${!STAGES[@]}"; do
  TOKEN="${STAGE_TOKENS[$i]}"
  COND="${STAGE_CONDITIONS[$i]}"
  STEP=$((i + 1))
  IFS='+' read -ra MEMBERS <<< "$TOKEN"

  # BRANCH: only for a "?ok:"/"?fail:"-prefixed stage. Checks the last
  # EXECUTED stage's outcome (skips don't move
  # LAST_EXECUTED_GROUP_ALL_OK, so this correctly looks past any
  # already-skipped stages to the last one that actually ran).
  if [ -n "$COND" ]; then
    PREV_LABEL="ok"
    [ "$LAST_EXECUTED_GROUP_ALL_OK" = "true" ] || PREV_LABEL="failed"

    SKIP="false"
    if [ "$COND" = "ok" ] && [ "$LAST_EXECUTED_GROUP_ALL_OK" != "true" ]; then
      SKIP="true"
    elif [ "$COND" = "fail" ] && [ "$LAST_EXECUTED_GROUP_ALL_OK" = "true" ]; then
      SKIP="true"
    fi

    if [ "$SKIP" = "true" ]; then
      log "[ORCHESTRATE WORKER] BRANCH stage $STEP/${#STAGES[@]}: $TOKEN skipped (condition=?$COND, previous stage=$PREV_LABEL)"
      for m in "${MEMBERS[@]}"; do
        STAGE_STATUS+=("$m=skipped")
        python3 -c "
import json, sys
name, step = sys.argv[1:3]
print(json.dumps({'name': name, 'status': 'skipped', 'exit_code': None, 'step': int(step), 'result': ''}))
" "$m" "$STEP" >> "$STAGES_JSONL"
      done
      continue
    fi

    log "[ORCHESTRATE WORKER] BRANCH stage $STEP/${#STAGES[@]}: $TOKEN condition met (condition=?$COND, previous stage=$PREV_LABEL), proceeding"
  fi

  if [ "$EXECUTED_COUNT" -eq 0 ]; then
    STAGE_INPUT="$REQUEST"
  else
    STAGE_INPUT="Original request: $REQUEST
$HISTORY"
  fi

  GROUP_SIZE="${#MEMBERS[@]}"
  if [ -n "${WAIO_MAX_PARALLEL:-}" ] && [ "$WAIO_MAX_PARALLEL" -lt "$GROUP_SIZE" ]; then
    BATCH_CAP="$WAIO_MAX_PARALLEL"
  else
    BATCH_CAP="$GROUP_SIZE"
  fi

  if [ "$GROUP_SIZE" -gt 1 ] && [ "$BATCH_CAP" -lt "$GROUP_SIZE" ]; then
    log "[ORCHESTRATE WORKER] ROUTE stage $STEP/${#STAGES[@]}: $TOKEN (parallel group, $GROUP_SIZE members, max $BATCH_CAP concurrent)"
  elif [ "$GROUP_SIZE" -gt 1 ]; then
    log "[ORCHESTRATE WORKER] ROUTE stage $STEP/${#STAGES[@]}: $TOKEN (parallel group, $GROUP_SIZE members)"
  else
    log "[ORCHESTRATE WORKER] ROUTE stage $STEP/${#STAGES[@]}: $TOKEN (resolved via workers/registry.conf)"
  fi

  declare -a MEMBER_OUTFILES=()
  declare -a MEMBER_RCS=()
  BATCH_START=0
  while [ "$BATCH_START" -lt "$GROUP_SIZE" ]; do
    BATCH_END=$((BATCH_START + BATCH_CAP))
    [ "$BATCH_END" -gt "$GROUP_SIZE" ] && BATCH_END="$GROUP_SIZE"

    declare -a BATCH_PIDS=()
    for ((j = BATCH_START; j < BATCH_END; j++)); do
      m="${MEMBERS[$j]}"
      OUTFILE="$RUN_TMP_DIR/stage${STEP}-${m}.out"
      MEMBER_OUTFILES+=("$OUTFILE")
      log "[ORCHESTRATE WORKER] EXECUTE ./waio.sh -w $m"
      ./waio.sh -w "$m" "$STAGE_INPUT" > "$OUTFILE" 2>&1 &
      BATCH_PIDS+=("$!")
    done

    for pid in "${BATCH_PIDS[@]}"; do
      wait "$pid"
      MEMBER_RCS+=("$?")
    done

    BATCH_START="$BATCH_END"
  done

  declare -a MEMBER_LABELED=()
  declare -a MEMBER_RAW=()
  GROUP_ANY_FAILED="false"
  for idx in "${!MEMBERS[@]}"; do
    m="${MEMBERS[$idx]}"
    RC="${MEMBER_RCS[$idx]}"
    RAW_OUTPUT="$(cat "${MEMBER_OUTFILES[$idx]}")"

    # COLLECT: every current pipeline-compatible worker ends its real
    # result with a line matching "] response:" -- everything after that
    # marker is the result, everything before it is dispatch/log noise.
    # A worker that errors before reaching that point has no marker, so
    # we fall back to its raw combined output (still useful context).
    if printf '%s\n' "$RAW_OUTPUT" | grep -q '\] response:$'; then
      M_RESULT="$(printf '%s\n' "$RAW_OUTPUT" | sed -n '/\] response:$/,$p' | tail -n +2)"
    else
      M_RESULT="$RAW_OUTPUT"
    fi
    MEMBER_RAW+=("$M_RESULT")

    if [ "$RC" -eq 0 ]; then
      STATUS_WORD="ok"
      STAGE_STATUS+=("$m=ok")
      log "[ORCHESTRATE WORKER] COLLECT stage $STEP ($m) status=ok"
    else
      STATUS_WORD="FAILED"
      STAGE_STATUS+=("$m=failed")
      ANY_STAGE_FAILED="true"
      GROUP_ANY_FAILED="true"
      log "[ORCHESTRATE WORKER] COLLECT stage $STEP ($m) status=failed exit=$RC"
      log "[ORCHESTRATE WORKER] FAILURE HANDLING: forwarding stage $STEP ($m) failure into the next stage's input instead of aborting"
    fi

    {
      echo "--- stage $STEP: $m ($STATUS_WORD) ---"
      echo "$M_RESULT"
    } >> "$LOG"

    python3 -c "
import json, sys
name, status, exit_code, result, step = sys.argv[1:6]
print(json.dumps({'name': name, 'status': status, 'exit_code': int(exit_code), 'step': int(step), 'result': result}))
" "$m" "$([ "$RC" -eq 0 ] && echo ok || echo failed)" "$RC" "$M_RESULT" "$STEP" >> "$STAGES_JSONL"

    MEMBER_LABELED+=("$m ($STATUS_WORD):
$M_RESULT")
  done

  GROUP_RESULT=""
  for idx in "${!MEMBER_LABELED[@]}"; do
    if [ "$idx" -eq 0 ]; then
      GROUP_RESULT="${MEMBER_LABELED[$idx]}"
    else
      GROUP_RESULT="$GROUP_RESULT

${MEMBER_LABELED[$idx]}"
    fi
  done

  HISTORY="$HISTORY

$GROUP_RESULT"

  if [ "${#MEMBERS[@]}" -eq 1 ]; then
    FINAL_RESULT="${MEMBER_RAW[0]}"
  else
    FINAL_RESULT="$GROUP_RESULT"
  fi

  if [ "$GROUP_ANY_FAILED" = "true" ]; then
    LAST_EXECUTED_GROUP_ALL_OK="false"
  else
    LAST_EXECUTED_GROUP_ALL_OK="true"
  fi
  EXECUTED_COUNT=$((EXECUTED_COUNT + 1))
done

if [ "$EXECUTED_COUNT" -eq 0 ]; then
  echo "[ORCHESTRATE WORKER] ERROR: every stage was skipped (source: $PIPELINE_SOURCE) -- no stage ever executed, nothing to report"
  exit 1
fi

# RESULT AGGREGATION: three-way overall_status. "failed" means at least
# one member of the LAST stage itself failed (final_result includes that
# failure's error text, not only a trustworthy answer); "degraded" means
# some earlier stage/member failed but every member of the last stage
# still produced a genuine result; "ok" means nothing failed.
if [ "$ANY_STAGE_FAILED" = "false" ]; then
  OVERALL_STATUS="ok"
elif [ "$LAST_EXECUTED_GROUP_ALL_OK" = "true" ]; then
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
