#!/bin/bash
set -uo pipefail

# workers/register_takomachi_agents.sh -- idempotent Takomachi agent
# provisioning from the single source of truth, workers/takomachi_agents.conf.
#
# Replaces the original one-time, never-committed provisioning step
# (Takomachi repo's own `scripts/register-waio-agents.sh`, referenced in
# ARCHITECTURE.md's Takomachi integration phase but absent from that
# repo's `git log --all` -- it never actually existed as version-controlled
# code). Takomachi's own takomachi.sqlite is gitignored, pure local runtime
# state; when it was later rebuilt the waio-research/waio-analysis/waio-ai
# registrations were lost with no reproducible way to redo them. See
# ARCHITECTURE.md's "Takomachi agent registration" phase entry for the full
# investigation.
#
# Idempotent by construction: for each row in workers/takomachi_agents.conf,
# GET /agents/<id> first and only POST /agents when that GET comes back 404.
# An already-registered agent is left untouched -- this script never PATCHes
# or overwrites an existing agent's definition, run it as many times as you
# like.
#
# Credential: TAKOMACHI_API_KEY from this shell's own environment if already
# set, otherwise macOS Keychain (`security find-generic-password -a
# "$(whoami)" -s "com.takomachi.api-key" -w`) -- same lookup/order every
# other Takomachi-calling worker and dashboard/collect_takomachi_status.sh
# already use. Never printed, logged, or included in any error message.
#
# DLP: this performs a real mutating call to Takomachi, so (unlike
# dashboard/collect_takomachi_status.sh's own passive read-only collector,
# which deliberately bypasses the DLP gate) it goes through the same
# security/lib.sh egress_check/payload_size_check gate every other
# Takomachi-writing worker (research_worker.sh, analysis_worker.sh,
# ai_worker.sh) already uses.
#
# Exit code: 0 iff every row in the conf ends the run either
# already-registered or newly-registered; 1 if any row fails (missing
# credential, network error, schema/validation failure). One failing row
# does not stop the rest from being attempted -- every row's own outcome is
# printed, never silently swallowed.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"

CONF="workers/takomachi_agents.conf"
BASE_URL="${TAKOMACHI_API_URL:-http://localhost:3000}"

if [ ! -f "$CONF" ]; then
  echo "[REGISTER TAKOMACHI AGENTS] ERROR: $CONF not found"
  exit 1
fi

if [ -z "${TAKOMACHI_API_KEY:-}" ]; then
  if command -v security >/dev/null 2>&1; then
    TAKOMACHI_API_KEY="$(security find-generic-password -a "$(whoami)" -s "com.takomachi.api-key" -w 2>/dev/null || true)"
  fi
fi
if [ -z "${TAKOMACHI_API_KEY:-}" ]; then
  echo "[REGISTER TAKOMACHI AGENTS] ERROR: could not retrieve TAKOMACHI_API_KEY (not set in environment, and Keychain lookup found none or is unavailable in this context)"
  exit 1
fi

# DLP / Emergency Shutdown layer: same destination + payload checks every
# other Takomachi-writing worker runs before its own network calls. Host/port
# are parsed out of BASE_URL (not hardcoded "localhost"/"3000" the way
# research_worker.sh/analysis_worker.sh/ai_worker.sh can, since those never
# support a TAKOMACHI_API_URL override) so the DLP check always matches the
# real destination this script is about to contact, in production and under
# test alike.
EGRESS_HOST="$(python3 -c "import sys, urllib.parse as u; p = u.urlparse(sys.argv[1]); print(p.hostname or '')" "$BASE_URL")"
EGRESS_PORT="$(python3 -c "import sys, urllib.parse as u; p = u.urlparse(sys.argv[1]); print(p.port or (443 if p.scheme == 'https' else 80))" "$BASE_URL")"
if [ -z "$EGRESS_HOST" ]; then
  echo "[REGISTER TAKOMACHI AGENTS] ERROR: could not parse host from TAKOMACHI_API_URL/BASE_URL '$BASE_URL'"
  exit 1
fi

source security/lib.sh
if ! egress_check "$EGRESS_HOST" "$EGRESS_PORT" "" "" "REGISTER_TAKOMACHI_AGENTS"; then
  echo "[REGISTER TAKOMACHI AGENTS] ERROR: egress denied by DLP guard, emergency shutdown triggered -- no request sent"
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

TOTAL=0
FAILED=0

while IFS='|' read -r agent_id provider model capability_tag persona_name; do
  case "$agent_id" in
    ""|\#*) continue ;;
  esac
  TOTAL=$((TOTAL + 1))

  status="$(http_call GET "/agents/$agent_id")"
  if [ "$status" = "200" ]; then
    echo "[REGISTER TAKOMACHI AGENTS] $agent_id: already registered, skipping"
    continue
  fi
  if [ "$status" != "404" ]; then
    echo "[REGISTER TAKOMACHI AGENTS] $agent_id: ERROR: unexpected GET /agents/$agent_id response (HTTP $status)"
    FAILED=$((FAILED + 1))
    continue
  fi

  DEFINITION_JSON="$(python3 -c '
import json, sys
agent_id, provider, model, capability_tag, persona_name = sys.argv[1:6]
definition = {
    "id": agent_id,
    "provider": provider,
    "model": model,
    "persona": {
        "name": persona_name,
        "description": "WAIO " + capability_tag + " worker agent -- registered via workers/register_takomachi_agents.sh from workers/takomachi_agents.conf.",
        "system_prompt": "You are the WAIO " + capability_tag + " agent, dispatched by WAIO (github.com/noobdna/WAIO) via Takomachi. Respond helpfully and concisely to the task you are given.",
    },
    "capability_tags": [capability_tag],
    "tool_permissions": [],
}
print(json.dumps(definition))
' "$agent_id" "$provider" "$model" "$capability_tag" "$persona_name")"

  if ! payload_size_check "$DEFINITION_JSON" "" "" "REGISTER_TAKOMACHI_AGENTS" "$EGRESS_HOST:$EGRESS_PORT"; then
    echo "[REGISTER TAKOMACHI AGENTS] $agent_id: ERROR: payload size anomaly detected by DLP guard, emergency shutdown triggered -- request not sent"
    FAILED=$((FAILED + 1))
    continue
  fi

  status="$(http_call POST "/agents" "$DEFINITION_JSON")"
  if [ "$status" = "201" ]; then
    echo "[REGISTER TAKOMACHI AGENTS] $agent_id: registered (provider=$provider model=$model capability=$capability_tag)"
  else
    echo "[REGISTER TAKOMACHI AGENTS] $agent_id: ERROR: registration failed (HTTP $status)"
    FAILED=$((FAILED + 1))
  fi
done < "$CONF"

echo "[REGISTER TAKOMACHI AGENTS] done: $((TOTAL - FAILED))/$TOTAL agent(s) registered-or-already-registered"
if [ "$FAILED" -gt 0 ]; then
  exit 1
fi
exit 0
