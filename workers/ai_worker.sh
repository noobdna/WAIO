#!/bin/bash
set -uo pipefail

REQUEST="$1"

if [ -z "$REQUEST" ]; then
  echo "[AI WORKER] ERROR: empty request"
  exit 1
fi

AGENT_ID="waio-ai"
BASE_URL="http://localhost:3000"

TAKOMACHI_API_KEY="$(security find-generic-password -a "$(whoami)" -s "com.takomachi.api-key" -w)"
if [ -z "$TAKOMACHI_API_KEY" ]; then
  echo "[AI WORKER] ERROR: could not retrieve TAKOMACHI_API_KEY from Keychain"
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

REQUEST_JSON="$(python3 -c 'import json,sys; print(json.dumps(sys.argv[1]))' "$REQUEST")"

status="$(http_call POST "/tasks" "{\"target_agent_id\":\"$AGENT_ID\",\"payload\":{\"messages\":[{\"role\":\"user\",\"content\":$REQUEST_JSON}]}}")"
if [ "$status" != "201" ]; then
  echo "[AI WORKER] ERROR: task submission failed (HTTP $status)"
  exit 1
fi
TASK_ID="$(python3 -c "import json; print(json.load(open('$TMP_BODY'))['id'])")"

DEADLINE=$((SECONDS + 90))
TASK_STATUS=""
while [ "$SECONDS" -lt "$DEADLINE" ]; do
  status="$(http_call GET "/tasks/$TASK_ID")"
  if [ "$status" != "200" ]; then
    echo "[AI WORKER] ERROR: task fetch failed (HTTP $status)"
    exit 1
  fi
  TASK_STATUS="$(python3 -c "import json; print(json.load(open('$TMP_BODY'))['status'])")"
  if [ "$TASK_STATUS" = "completed" ] || [ "$TASK_STATUS" = "failed" ]; then
    break
  fi
  sleep 1
done

if [ "$TASK_STATUS" != "completed" ]; then
  echo "[AI WORKER] ERROR: task did not complete in time (status=${TASK_STATUS:-timeout})"
  exit 1
fi

echo "[AI WORKER] response:"
python3 -c "import json; print((json.load(open('$TMP_BODY')).get('result') or {}).get('content'))"
