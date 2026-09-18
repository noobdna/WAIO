#!/bin/bash
set -uo pipefail

# dashboard/collect_takomachi_status.sh -- Phase 76: read-only data
# collector for the WAIO Dashboard, querying Takomachi's own existing
# GET /health, GET /agents, GET /tasks endpoints (same routes
# workers/healthcheck_worker.sh already calls for /health; no new
# Takomachi-side endpoint or schema).
#
# DELIBERATELY DOES NOT source security/lib.sh and NEVER calls
# egress_check/trigger_shutdown -- unlike every WAIO worker
# (workers/healthcheck_worker.sh, ai_worker.sh, research_worker.sh,
# analysis_worker.sh), which all route their own Takomachi calls
# through the DuCoPA DLP egress gate. That gate's trigger_shutdown()
# writes security/state/SHUTDOWN.lock and contains the entire system
# on an unexpected/unlisted destination -- an appropriate blast radius
# for a WAIO worker's own dispatch path, but not for a passive,
# manually-run dashboard display refresh. A misconfigured
# TAKOMACHI_API_URL, an unreachable Takomachi, or a missing API key
# must only ever make THIS panel say "unavailable" -- never trip a
# system-wide shutdown. See dashboard/collect_snd_status.sh for the
# same posture applied to SND_HOME.
#
# Real external communication/execution workers (workers/*.sh) keep
# their own existing egress_check()/DLP gate entirely unchanged --
# this file does not touch, wrap, or replace that gate in any way.
#
# Manual/on-demand only -- NOT called by dashboard/refresh_dashboard_cron.sh
# (see that file's own Phase 76 note): the first dashboard collector to
# make a real network call, so it deliberately stays off the automated
# schedule.
#
# Credential: TAKOMACHI_API_KEY from this shell's own environment if
# already set (the test-friendly path, and also how a future non-
# interactive scheduling context could supply it); otherwise this
# machine's own macOS Keychain (`security find-generic-password -a
# "$(whoami)" -s "com.takomachi.api-key" -w`), same lookup every
# Takomachi-calling worker already uses -- per the Takomachi
# integration phase's own documented finding (still true, see
# tests/orchestrate_worker_test.sh's own header), Keychain access only
# succeeds from an interactive GUI Terminal session, so this script
# reports "unavailable: no TAKOMACHI_API_KEY" rather than erroring when
# neither source has it (e.g. cron, CI, a non-interactive shell).
#
# Output: logs/takomachi-status-latest.json (logs/ already gitignored).
# Always written, even when Takomachi is fully unreachable -- the JSON
# itself carries "available": false and a human-readable "reason"
# rather than leaving the file stale/absent or exiting non-zero for a
# condition this script fully expects and handles.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"

TAKOMACHI_API_URL="${TAKOMACHI_API_URL:-http://localhost:3000}"

now_iso() { python3 -c 'import datetime; print(datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="milliseconds"))'; }
GENERATED_AT="$(now_iso)"

mkdir -p logs
OUT_PATH="logs/takomachi-status-latest.json"

write_unavailable() {
  python3 -c '
import json, sys
generated_at, api_url, reason = sys.argv[1:4]
data = {
    "generated_at": generated_at,
    "note": "Display layer only, see dashboard/collect_takomachi_status.sh. Deliberately bypasses security/lib.sh egress_check/trigger_shutdown -- a passive dashboard read never triggers a system-wide shutdown. Manual/on-demand only, not on the automated dashboard-refresh schedule.",
    "available": False,
    "reason": reason,
    "api_url": api_url,
    "health": None,
    "agents": None,
    "tasks": None,
}
with open("logs/takomachi-status-latest.json", "w") as f:
    json.dump(data, f, indent=2, ensure_ascii=False)
    f.write("\n")
' "$GENERATED_AT" "$TAKOMACHI_API_URL" "$1"
  echo "[COLLECT TAKOMACHI STATUS] unavailable: $1"
  echo "[COLLECT TAKOMACHI STATUS] Written to $OUT_PATH"
}

if [ -z "${TAKOMACHI_API_KEY:-}" ]; then
  if command -v security >/dev/null 2>&1; then
    TAKOMACHI_API_KEY="$(security find-generic-password -a "$(whoami)" -s "com.takomachi.api-key" -w 2>/dev/null || true)"
  fi
fi
if [ -z "${TAKOMACHI_API_KEY:-}" ]; then
  write_unavailable "no TAKOMACHI_API_KEY (not set in environment, and Keychain lookup found none or is unavailable in this non-interactive context)"
  exit 0
fi

curl_get() {
  # curl_get PATH -- prints "HTTP_CODE\nBODY". 3s hard timeout, no
  # redirects followed, no retries -- "unavailable this cycle, not an
  # automatic retry loop", same posture as security/recovery_engine.sh.
  local path="$1" tmp status
  tmp="$(mktemp)"
  status="$(curl -s --max-time 3 --no-buffer -o "$tmp" -w "%{http_code}" -X GET "$TAKOMACHI_API_URL$path" \
    -H "Authorization: Bearer $TAKOMACHI_API_KEY" 2>/dev/null)"
  printf '%s\n' "${status:-000}"
  cat "$tmp" 2>/dev/null
  rm -f "$tmp"
}

HEALTH_RESULT="$(curl_get /health)"
HEALTH_STATUS="$(echo "$HEALTH_RESULT" | head -1)"
HEALTH_BODY="$(echo "$HEALTH_RESULT" | tail -n +2)"

if [ "$HEALTH_STATUS" != "200" ]; then
  write_unavailable "GET /health failed (HTTP ${HEALTH_STATUS:-000}) against $TAKOMACHI_API_URL"
  exit 0
fi

AGENTS_RESULT="$(curl_get /agents)"
AGENTS_STATUS="$(echo "$AGENTS_RESULT" | head -1)"
AGENTS_BODY="$(echo "$AGENTS_RESULT" | tail -n +2)"
[ "$AGENTS_STATUS" = "200" ] || AGENTS_BODY="[]"

TASKS_RESULT="$(curl_get /tasks)"
TASKS_STATUS="$(echo "$TASKS_RESULT" | head -1)"
TASKS_BODY="$(echo "$TASKS_RESULT" | tail -n +2)"
[ "$TASKS_STATUS" = "200" ] || TASKS_BODY="[]"

python3 -c '
import json, sys

generated_at, api_url, health_json, agents_json, agents_ok, tasks_json, tasks_ok = sys.argv[1:8]

def safe_load(s, default):
    try:
        return json.loads(s)
    except Exception:
        return default

health = safe_load(health_json, {})
agents = safe_load(agents_json, []) if agents_ok == "true" else []
tasks = safe_load(tasks_json, []) if tasks_ok == "true" else []

def counts_by(items, key="status"):
    c = {}
    for it in items:
        if isinstance(it, dict):
            k = it.get(key, "unknown")
            c[k] = c.get(k, 0) + 1
    return c

data = {
    "generated_at": generated_at,
    "note": "Display layer only, see dashboard/collect_takomachi_status.sh. Deliberately bypasses security/lib.sh egress_check/trigger_shutdown -- a passive dashboard read never triggers a system-wide shutdown. Manual/on-demand only, not on the automated dashboard-refresh schedule.",
    "available": True,
    "reason": None,
    "api_url": api_url,
    "health": health,
    "agents": {
        "available": agents_ok == "true",
        "count": len(agents) if isinstance(agents, list) else None,
        "by_status": counts_by(agents) if isinstance(agents, list) else {},
        "list": (agents[:20] if isinstance(agents, list) else []),
    },
    "tasks": {
        "available": tasks_ok == "true",
        "count": len(tasks) if isinstance(tasks, list) else None,
        "by_status": counts_by(tasks) if isinstance(tasks, list) else {},
        "list": (tasks[:20] if isinstance(tasks, list) else []),
    },
}
with open("logs/takomachi-status-latest.json", "w") as f:
    json.dump(data, f, indent=2, ensure_ascii=False)
    f.write("\n")
' "$GENERATED_AT" "$TAKOMACHI_API_URL" "$HEALTH_BODY" "$AGENTS_BODY" \
  "$([ "$AGENTS_STATUS" = "200" ] && echo true || echo false)" \
  "$TASKS_BODY" "$([ "$TASKS_STATUS" = "200" ] && echo true || echo false)"

echo "[COLLECT TAKOMACHI STATUS] available (health=$HEALTH_STATUS agents=$AGENTS_STATUS tasks=$TASKS_STATUS)"
echo "[COLLECT TAKOMACHI STATUS] Written to $OUT_PATH"
