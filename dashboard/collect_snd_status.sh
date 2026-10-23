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

# validate_api_url URL -- prints two lines: a display form of URL that
# is safe to write to the dashboard JSON and stdout (userinfo masked,
# query/fragment dropped), then an error message, empty when URL is
# usable. Only plain http(s)://host[:port][/path] is accepted: the URL
# goes straight to curl, so another scheme (file://, gopher://, dict://)
# would make this "read-only dashboard" talk some other protocol, and
# credentials embedded in it would land in curl's argv (ps), the output
# JSON and the log. A token belongs in SND_HOME_API_TOKEN instead.
validate_api_url() {
  python3 -c '
import sys
from urllib.parse import urlsplit, urlunsplit
url = sys.argv[1]
err = ""
try:
    u = urlsplit(url)
    host_part = u.netloc.rsplit("@", 1)[-1]
    display = urlunsplit((u.scheme, ("***@" if "@" in u.netloc else "") + host_part, u.path, "", ""))
    if any(ord(c) < 33 or ord(c) == 127 for c in url):
        err = "contains whitespace or control characters"
    elif u.scheme not in ("http", "https"):
        err = "scheme must be http or https"
    elif "@" in u.netloc:
        err = "credentials in the URL are not supported (use SND_HOME_API_TOKEN)"
    elif not u.hostname:
        err = "missing host"
    elif u.query or u.fragment or "?" in url or "#" in url:
        err = "must not contain a query string or fragment"
    else:
        u.port  # raises ValueError on a malformed port
except ValueError:
    display, err = "<unparseable>", "malformed host or port"
print(display.replace("\n", " "))
print(err)
' "$1"
}

now_iso() { python3 -c 'import datetime; print(datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="milliseconds"))'; }
GENERATED_AT="$(now_iso)"

mkdir -p logs
OUT_PATH="logs/snd-status-latest.json"

write_status() {
  # write_status AVAILABLE REASON [LAN_JSON] [SYSTEM_JSON] [ALERTS_JSON] [TERMINALS_JSON]
  # Bodies reach python3 through files written by the printf builtin,
  # never through argv: four responses together easily exceed macOS's
  # 1 MiB ARG_MAX, python3 then fails to start ("Argument list too
  # long"), and the PREVIOUS run's output stays on the dashboard.
  local available="$1" reason="$2" body_dir rc
  body_dir="$(mktemp -d)"
  printf '%s' "${3:-null}" > "$body_dir/lan"
  printf '%s' "${4:-null}" > "$body_dir/system"
  printf '%s' "${5:-null}" > "$body_dir/alerts"
  printf '%s' "${6:-null}" > "$body_dir/terminals"
  python3 -c '
import json, os, sys
generated_at, api_url, available, reason, body_dir = sys.argv[1:6]

def body(name):
    with open(os.path.join(body_dir, name), encoding="utf-8", errors="replace") as f:
        return f.read()
lan_json, system_json, alerts_json, terminals_json = (body(n) for n in ("lan", "system", "alerts", "terminals"))

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
tmp_path = "logs/snd-status-latest.json.tmp"
with open(tmp_path, "w") as f:
    json.dump(data, f, indent=2, ensure_ascii=False)
    f.write("\n")
os.replace(tmp_path, "logs/snd-status-latest.json")
' "$GENERATED_AT" "$SND_HOME_API_URL_DISPLAY" "$available" "$reason" "$body_dir"
  rc=$?
  rm -rf "$body_dir"
  if [ "$rc" -ne 0 ]; then
    echo "[COLLECT SND STATUS] ERROR: failed to write $OUT_PATH (python3 exit $rc)" >&2
    exit 1
  fi
  echo "[COLLECT SND STATUS] available=$available reason=${reason:-none}"
  echo "[COLLECT SND STATUS] Written to $OUT_PATH"
}

SND_HOME_API_URL_DISPLAY=""
if [ -z "$SND_HOME_API_URL" ]; then
  write_status "false" "not configured (SND_HOME_API_URL not set -- this dashboard's SND panel is opt-in; see this script's own header)"
  exit 0
fi

URL_CHECK="$(validate_api_url "$SND_HOME_API_URL")"
SND_HOME_API_URL_DISPLAY="$(printf '%s\n' "$URL_CHECK" | sed -n 1p)"
URL_ERROR="$(printf '%s\n' "$URL_CHECK" | sed -n 2p)"
[ -n "$SND_HOME_API_URL_DISPLAY" ] || SND_HOME_API_URL_DISPLAY="<invalid>"
if [ -n "$URL_ERROR" ]; then
  write_status "false" "invalid SND_HOME_API_URL ($URL_ERROR): $SND_HOME_API_URL_DISPLAY -- no request was made"
  exit 0
fi

# Per-response cap. curl exits 63 when a response exceeds it, which
# curl_get() reports as a failure. Real SND_HOME payloads are a few KB;
# the cap keeps a misbehaving server from filling this nearly-full disk
# through mktemp.
MAX_RESPONSE_BYTES=1048576

curl_get() {
  # curl_get PATH -- prints "HTTP_CODE\nBODY". 3s hard timeout, no
  # redirects, no retries -- same posture as collect_takomachi_status.sh.
  # Deliberately two separate curl invocations (not a bash array for the
  # optional -H flag) -- this repo targets macOS's own default bash 3.2,
  # where "${arr[@]}" on an empty array trips "unbound variable" under
  # this file's own `set -uo pipefail`.
  # The Authorization header goes in on stdin (-H @-, written by the
  # printf builtin), never as an argument: curl's argv is visible to
  # every local user in ps (same fix as collect_ducopa_control_status.sh).
  local path="$1" tmp status rc
  tmp="$(mktemp)"
  if [ -n "$SND_HOME_API_TOKEN" ]; then
    status="$(printf 'Authorization: Bearer %s\n' "$SND_HOME_API_TOKEN" |
      curl -s --proto =http,https --max-time 3 --max-filesize "$MAX_RESPONSE_BYTES" --no-buffer -o "$tmp" -w "%{http_code}" -X GET "$SND_HOME_API_URL$path" \
      -H @- 2>/dev/null)"
  else
    status="$(curl -s --proto =http,https --max-time 3 --max-filesize "$MAX_RESPONSE_BYTES" --no-buffer -o "$tmp" -w "%{http_code}" -X GET "$SND_HOME_API_URL$path" 2>/dev/null)"
  fi
  rc=$?
  # A non-zero curl exit (timeout mid-body, reset, size cap) after the
  # headers arrived still leaves %{http_code}=200; never let that pass
  # as success -- the status line becomes e.g. "200, curl exit 28".
  if [ "$rc" -ne 0 ]; then
    printf '%s, curl exit %s\n' "${status:-000}" "$rc"
  else
    printf '%s\n' "${status:-000}"
  fi
  cat "$tmp" 2>/dev/null
  rm -f "$tmp"
}

# is_json_object -- exit 0 iff stdin parses as a JSON object. A 200 from
# the primary endpoint only proves *something* answered on that port (a
# captive portal, another web app, a proxy error page); without this
# check that something was rendered as a green AVAILABLE badge.
is_json_object() {
  python3 -c '
import json, sys
try:
    sys.exit(0 if isinstance(json.loads(sys.stdin.read()), dict) else 1)
except Exception:
    sys.exit(1)
'
}

LAN_RESULT="$(curl_get /api/lan/status)"
LAN_STATUS="$(echo "$LAN_RESULT" | head -1)"
LAN_BODY="$(echo "$LAN_RESULT" | tail -n +2)"

if [ "$LAN_STATUS" != "200" ]; then
  write_status "false" "GET /api/lan/status failed (HTTP ${LAN_STATUS:-000}) against $SND_HOME_API_URL_DISPLAY"
  exit 0
fi
if ! printf '%s' "$LAN_BODY" | is_json_object; then
  write_status "false" "GET /api/lan/status returned HTTP 200 but the body is not a JSON object (not SND_HOME?) at $SND_HOME_API_URL_DISPLAY"
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
