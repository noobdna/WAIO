#!/bin/bash
set -uo pipefail

# Minimal multi-agent orchestration: chains the existing waio-research,
# waio-analysis, and waio-ai Takomachi agents for a single incoming
# request, feeding each stage's result into the next stage's payload.
# Reuses the same submit/poll contract as research_worker.sh /
# analysis_worker.sh / ai_worker.sh (POST /tasks, GET /tasks/:id) --
# no Takomachi-side schema or endpoint changes.

REQUEST="$1"

if [ -z "$REQUEST" ]; then
  echo "[ORCHESTRATE WORKER] ERROR: empty request"
  exit 1
fi

BASE_URL="http://localhost:3000"

TAKOMACHI_API_KEY="$(security find-generic-password -a "$(whoami)" -s "com.takomachi.api-key" -w)"
if [ -z "$TAKOMACHI_API_KEY" ]; then
  echo "[ORCHESTRATE WORKER] ERROR: could not retrieve TAKOMACHI_API_KEY from Keychain"
  exit 1
fi

TMP_BODY="$(mktemp)"
trap 'rm -f "$TMP_BODY"' EXIT

# http_call METHOD PATH [JSON_BODY] -> prints HTTP status to stdout, body left in $TMP_BODY
http_call() {
  local method="$1" path="$2" body="${3:-}"
  if [ -n "$body" ]; then
    curl -s -o "$TMP_BODY" -w "%{http_code}" -X "$method" "$BASE_URL$path" \
      -H "Authorization: Bearer $TAKOMACHI_API_KEY" -H "Content-Type: application/json" -d "$body"
  else
    curl -s -o "$TMP_BODY" -w "%{http_code}" -X "$method" "$BASE_URL$path" \
      -H "Authorization: Bearer $TAKOMACHI_API_KEY"
  fi
}

# run_stage AGENT_ID MESSAGE_TEXT -> submits a task to AGENT_ID, polls up to
# 90s, prints result.content to stdout on success. Errors go to stderr and
# the function returns non-zero (never prints key/Authorization material).
run_stage() {
  local agent_id="$1" message="$2"
  local message_json status task_id deadline task_status

  message_json="$(python3 -c 'import json,sys; print(json.dumps(sys.argv[1]))' "$message")"

  status="$(http_call POST "/tasks" "{\"target_agent_id\":\"$agent_id\",\"payload\":{\"messages\":[{\"role\":\"user\",\"content\":$message_json}]}}")"
  if [ "$status" != "201" ]; then
    echo "[ORCHESTRATE WORKER] ERROR: task submission to $agent_id failed (HTTP $status)" >&2
    return 1
  fi
  task_id="$(python3 -c "import json; print(json.load(open('$TMP_BODY'))['id'])")"

  deadline=$((SECONDS + 90))
  task_status=""
  while [ "$SECONDS" -lt "$deadline" ]; do
    status="$(http_call GET "/tasks/$task_id")"
    if [ "$status" != "200" ]; then
      echo "[ORCHESTRATE WORKER] ERROR: task fetch failed for $agent_id (HTTP $status)" >&2
      return 1
    fi
    task_status="$(python3 -c "import json; print(json.load(open('$TMP_BODY'))['status'])")"
    if [ "$task_status" = "completed" ] || [ "$task_status" = "failed" ]; then
      break
    fi
    sleep 1
  done

  if [ "$task_status" != "completed" ]; then
    echo "[ORCHESTRATE WORKER] ERROR: $agent_id task did not complete in time (status=${task_status:-timeout})" >&2
    return 1
  fi

  python3 -c "import json; print((json.load(open('$TMP_BODY')).get('result') or {}).get('content'))"
}

echo "[ORCHESTRATE WORKER] stage 1/3: research (waio-research)..."
RESEARCH_RESULT="$(run_stage "waio-research" "$REQUEST")" || exit 1

echo "[ORCHESTRATE WORKER] stage 2/3: analysis (waio-analysis)..."
ANALYSIS_INPUT="Original request: $REQUEST

Research findings:
$RESEARCH_RESULT"
ANALYSIS_RESULT="$(run_stage "waio-analysis" "$ANALYSIS_INPUT")" || exit 1

echo "[ORCHESTRATE WORKER] stage 3/3: ai (waio-ai)..."
AI_INPUT="Original request: $REQUEST

Research findings:
$RESEARCH_RESULT

Analysis:
$ANALYSIS_RESULT"
AI_RESULT="$(run_stage "waio-ai" "$AI_INPUT")" || exit 1

echo "[ORCHESTRATE WORKER] response:"
echo "$AI_RESULT"
