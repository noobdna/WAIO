#!/bin/bash
set -uo pipefail

# dashboard/collect_snd_status.sh -- Phase 76: read-only data collector
# for the WAIO Dashboard, optionally querying SND_HOME's own existing
# GET /api/lan/status, GET /api/system/latest, GET /api/alerts/active,
# GET /api/lan/terminals endpoints (confirmed by reading SND_HOME's own
# middleware/auth.js and routes/*.js during Phase 53's investigation;
# every GET route there is unauthenticated by design unless SND_HOME's
# own API_KEY is set -- routes/lan.js is the one deliberate exception,
# wiring requireAuth across its whole router, GETs included, since a
# LAN device list is sensitive; this script's existing Bearer-token
# handling below already covers that case unchanged).
#
# GET /api/lan/terminals (added this phase, reusing the existing SND_HOME
# endpoint as-is -- no new/duplicate API): SND_HOME's own MAC-primary /
# IP-current-address device model (lan/deviceStore.js's own header:
# "MACアドレスを安定識別子として使う(IPアドレスはDHCPで再割当てされうる
# ため...不適切)"), aggregated per physical terminal
# (lan/deviceStore.js's listTerminals(), LAN_TERMINAL_AGGREGATION_PLAN.md).
# Each entry: {terminalId, displayIp, online, macs, nickname, firstSeenAt,
# lastSeenAt}. `nickname` is operator-set (PATCH /devices/:mac) -- a null
# nickname means no operator has confirmed/identified this terminal yet;
# the dashboard renders that state explicitly (see dashboard/index.html's
# renderSnd()) rather than treating an unconfirmed terminal as normal.
#
# ARCHITECTURE DECISION, this phase (per explicit instruction): WAIO
# stays a CONSUMER of SND_HOME's own JSON/API only, never merges code
# with it -- SND_HOME's own CLAUDE.md is explicit ("他の一切の
# プロジェクトとは無関係であり、混在させません"). A separate, dedicated
# project (~/lan-dashboard-gateway) already exists to aggregate
# WAIO + Takomachi + SND_HOME; this collector does not replace or
# duplicate that project's role -- it only gives THIS dashboard its own
# optional, always-gracefully-degrading view of SND_HOME, off by
# default. As of Phase 76's own investigation, neither SND_HOME nor
# ~/lan-dashboard-gateway is present on this machine (only a backup
# copy of SND_HOME exists, on an external volume) -- so with no
# SND_HOME_API_URL configured, this panel always reports
# "not configured", by design, not as an error.
#
# DELIBERATELY DOES NOT source security/lib.sh and NEVER calls
# egress_check/trigger_shutdown -- same reasoning as
# dashboard/collect_takomachi_status.sh's own header: a misconfigured
# or absent SND_HOME_API_URL must only ever make this panel say
# "not configured"/"unavailable", never trip a system-wide shutdown.
# See that file's header for the fuller rationale; not restated here.
#
# SND_HOME_API_URL/SND_HOME_API_TOKEN are both OPTIONAL and UNSET by
# default -- zero network attempts of any kind happen unless
# SND_HOME_API_URL is explicitly set (in this shell's environment or
# ~/.waio.env, same convention dashboard/collect_status.sh's own
# WAIO_AUTO_NOTIFY check uses). SND_HOME_API_TOKEN is only sent as a
# Bearer header when both are set -- SND_HOME's GET routes work
# unauthenticated today (Phase 53's own finding), but a future
# deployment may set API_KEY on SND_HOME's own side.
#
# Manual/on-demand only -- NOT called by dashboard/refresh_dashboard_cron.sh,
# same reasoning as the Takomachi collector (the first two dashboard
# collectors to make a real network call both stay off the automated
# schedule).
#
# Output: logs/snd-status-latest.json (logs/ already gitignored).

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"

SND_HOME_API_URL="${SND_HOME_API_URL:-}"
if [ -z "$SND_HOME_API_URL" ] && [ -f "$HOME/.waio.env" ]; then
  SND_HOME_API_URL="$(sed -n 's/^\s*export\s\+SND_HOME_API_URL=//p' "$HOME/.waio.env" | tail -1)"
fi
SND_HOME_API_TOKEN="${SND_HOME_API_TOKEN:-}"

now_iso() { python3 -c 'import datetime; print(datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="milliseconds"))'; }
GENERATED_AT="$(now_iso)"

mkdir -p logs
OUT_PATH="logs/snd-status-latest.json"

write_status() {
  # write_status AVAILABLE REASON [LAN_JSON] [SYSTEM_JSON] [ALERTS_JSON] [TERMINALS_JSON]
  local available="$1" reason="$2" lan_json="${3:-null}" system_json="${4:-null}" alerts_json="${5:-null}" terminals_json="${6:-null}"
  python3 -c '
import json, sys
generated_at, api_url, available, reason, lan_json, system_json, alerts_json, terminals_json = sys.argv[1:9]

def safe_load(s):
    try:
        return json.loads(s)
    except Exception:
        return None

data = {
    "generated_at": generated_at,
    "note": "Display layer only, see dashboard/collect_snd_status.sh. WAIO consumes SND_HOME'"'"'s own JSON/API only, per its own CLAUDE.md (never merges code); a dedicated separate project, ~/lan-dashboard-gateway, is the primary WAIO+Takomachi+SND_HOME aggregator -- this panel is this dashboard'"'"'s own optional, additional view, off (\"not configured\") unless SND_HOME_API_URL is explicitly set. Deliberately bypasses security/lib.sh egress_check/trigger_shutdown -- a passive dashboard read never triggers a system-wide shutdown. Manual/on-demand only, not on the automated dashboard-refresh schedule.",
    "configured": bool(api_url),
    "available": available == "true",
    "reason": reason if reason else None,
    "api_url": api_url or None,
    "lan_status": safe_load(lan_json),
    "system_status": safe_load(system_json),
    "active_alerts": safe_load(alerts_json),
    "terminals": safe_load(terminals_json),
}
with open("logs/snd-status-latest.json", "w") as f:
    json.dump(data, f, indent=2, ensure_ascii=False)
    f.write("\n")
' "$GENERATED_AT" "$SND_HOME_API_URL" "$available" "$reason" "$lan_json" "$system_json" "$alerts_json" "$terminals_json"
  echo "[COLLECT SND STATUS] available=$available reason=${reason:-none}"
  echo "[COLLECT SND STATUS] Written to $OUT_PATH"
}

if [ -z "$SND_HOME_API_URL" ]; then
  write_status "false" "not configured (SND_HOME_API_URL not set -- this dashboard's SND panel is opt-in; see this script's own header)"
  exit 0
fi

curl_get() {
  # curl_get PATH -- prints "HTTP_CODE\nBODY". 3s hard timeout, no
  # redirects, no retries -- same posture as collect_takomachi_status.sh.
  # Deliberately two separate curl invocations (not a bash array for the
  # optional -H flag) -- this repo targets macOS's own default bash 3.2,
  # where "${arr[@]}" on an empty array trips "unbound variable" under
  # this file's own `set -uo pipefail`.
  local path="$1" tmp status
  tmp="$(mktemp)"
  if [ -n "$SND_HOME_API_TOKEN" ]; then
    status="$(curl -s --max-time 3 --no-buffer -o "$tmp" -w "%{http_code}" -X GET "$SND_HOME_API_URL$path" \
      -H "Authorization: Bearer $SND_HOME_API_TOKEN" 2>/dev/null)"
  else
    status="$(curl -s --max-time 3 --no-buffer -o "$tmp" -w "%{http_code}" -X GET "$SND_HOME_API_URL$path" 2>/dev/null)"
  fi
  printf '%s\n' "${status:-000}"
  cat "$tmp" 2>/dev/null
  rm -f "$tmp"
}

LAN_RESULT="$(curl_get /api/lan/status)"
LAN_STATUS="$(echo "$LAN_RESULT" | head -1)"
LAN_BODY="$(echo "$LAN_RESULT" | tail -n +2)"

if [ "$LAN_STATUS" != "200" ]; then
  write_status "false" "GET /api/lan/status failed (HTTP ${LAN_STATUS:-000}) against $SND_HOME_API_URL"
  exit 0
fi

SYSTEM_RESULT="$(curl_get /api/system/latest)"
SYSTEM_STATUS="$(echo "$SYSTEM_RESULT" | head -1)"
SYSTEM_BODY="$(echo "$SYSTEM_RESULT" | tail -n +2)"
[ "$SYSTEM_STATUS" = "200" ] || SYSTEM_BODY="null"

ALERTS_RESULT="$(curl_get /api/alerts/active)"
ALERTS_STATUS="$(echo "$ALERTS_RESULT" | head -1)"
ALERTS_BODY="$(echo "$ALERTS_RESULT" | tail -n +2)"
[ "$ALERTS_STATUS" = "200" ] || ALERTS_BODY="null"

# GET /api/lan/terminals: existing SND_HOME endpoint (routes/lan.js),
# same MAC-primary/IP-current device ledger the existing /api/lan/status
# call above already summarizes, just per-terminal instead of aggregate
# counts. Envelope response ({status, data}, unlike /api/lan/status'
# own un-enveloped shape) -- unwrap .data here so collect_takomachi_status.sh's
# own agents-array precedent (a plain list in the output JSON) stays the
# convention, not a second envelope layer.
TERMINALS_RESULT="$(curl_get /api/lan/terminals)"
TERMINALS_STATUS="$(echo "$TERMINALS_RESULT" | head -1)"
TERMINALS_BODY="$(echo "$TERMINALS_RESULT" | tail -n +2)"
if [ "$TERMINALS_STATUS" = "200" ]; then
  TERMINALS_BODY="$(python3 -c '
import json, sys
try:
    body = json.loads(sys.stdin.read())
    data = body.get("data") if isinstance(body, dict) else None
    print(json.dumps(data if isinstance(data, list) else []))
except Exception:
    print("[]")
' <<< "$TERMINALS_BODY")"
else
  TERMINALS_BODY="null"
fi

write_status "true" "" "$LAN_BODY" "$SYSTEM_BODY" "$ALERTS_BODY" "$TERMINALS_BODY"
