#!/bin/bash
set -uo pipefail

# Health-check worker: queries Takomachi's own existing GET /health endpoint
# (src/api-gateway/server.ts, auth applied the same as every other route)
# and reports agent_manager/task_queue/plugin_system status. No new
# Takomachi-side endpoint or schema; reuses the same Keychain credential
# lookup as every other WAIO worker.

REQUEST="${1:-}"

if [ -z "$REQUEST" ]; then
  echo "[HEALTHCHECK WORKER] ERROR: empty request"
  exit 1
fi

BASE_URL="http://localhost:3000"

TAKOMACHI_API_KEY="$(security find-generic-password -a "$(whoami)" -s "com.takomachi.api-key" -w)"
if [ -z "$TAKOMACHI_API_KEY" ]; then
  echo "[HEALTHCHECK WORKER] ERROR: could not retrieve TAKOMACHI_API_KEY from Keychain"
  exit 1
fi

TMP_BODY="$(mktemp)"
trap 'rm -f "$TMP_BODY"' EXIT

status="$(curl -s -o "$TMP_BODY" -w "%{http_code}" -X GET "$BASE_URL/health" \
  -H "Authorization: Bearer $TAKOMACHI_API_KEY")"

if [ "$status" != "200" ]; then
  echo "[HEALTHCHECK WORKER] ERROR: GET /health failed (HTTP $status)"
  exit 1
fi

echo "[HEALTHCHECK WORKER] response:"
python3 -c "
import json
body = json.load(open('$TMP_BODY'))
am = body.get('agent_manager', {})
tq = body.get('task_queue', {})
ps = body.get('plugin_system', {})
print(f\"agent_manager: {am.get('status')} (counts={am.get('agent_counts')})\")
print(f\"task_queue: {tq.get('status')} (queue_depth={tq.get('queue_depth')}, in_flight={tq.get('in_flight')})\")
print(f\"plugin_system: {ps.get('status')} (enabled_plugin_count={ps.get('enabled_plugin_count')})\")
print(f\"checked_at: {body.get('checked_at')}\")
if am.get('status') != 'ok':
    print('[HEALTHCHECK WORKER] WARNING: agent_manager reports degraded status')
"

echo "[HEALTHCHECK WORKER] completed"
