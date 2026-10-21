#!/bin/bash
set -uo pipefail

# dashboard/collect_ducopa_control_status.sh -- read-only DETECT bridge
# from WAIO to Takomachi's DuCoPA control plane (Takomachi
# interfaces/dual-control-plane.md: GET /control/heartbeat, GET
# /control/lockdown). Reports Takomachi's own dispatch_state
# (running/paused/lockdown) and its active lockdown episode, if any, so
# WAIO can see the other control plane's state.
#
# READ ONLY, by construction: only GET requests, and only those two
# paths. It never pauses, resumes, enters or exits anything -- WAIO's
# CONTAIN/RECOVER side of the channel is a separate, later decision
# (see the design note in ~/waio-ops/OPERATIONS_RESPONSIBILITY.md, not
# part of this repo), and recovery stays human-only on both planes.
#
# Same posture as dashboard/collect_takomachi_status.sh: DELIBERATELY
# DOES NOT source security/lib.sh and NEVER calls
# egress_check/trigger_shutdown. Takomachi being down, a missing key, or
# a disabled control channel must only make this panel say
# "unavailable" -- never trip a system-wide shutdown.
#
# Fail closed: "available": true is reported only for an HTTP 200
# heartbeat whose body carries the required fields with a dispatch_state
# from the contract's enum. Anything else (unreachable, 401, 404, a
# malformed body, an unknown state) is "available": false with a reason,
# never a guessed "running".
#
# Credential: TAKOMACHI_CONTROL_READ_KEY from this shell's environment
# only. No Keychain lookup: no Keychain service name has been decided
# for the control keys yet, and inventing one here would quietly create
# that decision. Unset -> "unavailable: no TAKOMACHI_CONTROL_READ_KEY".
#
# How Takomachi answers (its src/api-gateway/server.ts): with the
# control channel enabled, a wrong key gets 401. With it disabled (no
# control keys configured there), /control/* falls through to the normal
# API handler: 401 unless the bearer happens to be the plain API key,
# then 404. So a 401 here means "wrong key OR channel disabled" --
# indistinguishable from outside by Takomachi's design, and reported as
# exactly that.
#
# Output: ${WAIO_DUCOPA_CONTROL_STATUS_OUT:-logs/ducopa-control-status-latest.json}
# (logs/ already gitignored). Always written; exits 0 for every
# condition above. Manual/on-demand only, not on any schedule.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"

TAKOMACHI_API_URL="${TAKOMACHI_API_URL:-http://localhost:3000}"
OUT_PATH="${WAIO_DUCOPA_CONTROL_STATUS_OUT:-logs/ducopa-control-status-latest.json}"
mkdir -p "$(dirname "$OUT_PATH")"

now_iso() { python3 -c 'import datetime; print(datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="milliseconds"))'; }
GENERATED_AT="$(now_iso)"

NOTE="Display layer only, see dashboard/collect_ducopa_control_status.sh. GET-only read of Takomachi's DuCoPA control plane; never pauses/resumes/locks anything. Deliberately bypasses security/lib.sh egress_check/trigger_shutdown. Manual/on-demand only."

write_unavailable() {
  python3 -c '
import json, sys
out, generated_at, api_url, note, reason, http_status = sys.argv[1:7]
data = {
    "generated_at": generated_at,
    "note": note,
    "available": False,
    "reason": reason,
    "http_status": http_status or None,
    "api_url": api_url,
    "dispatch_state": None,
    "heartbeat": None,
    "lockdown": None,
}
with open(out, "w") as f:
    json.dump(data, f, indent=2, ensure_ascii=False)
    f.write("\n")
' "$OUT_PATH" "$GENERATED_AT" "$TAKOMACHI_API_URL" "$NOTE" "$1" "${2:-}"
  echo "[COLLECT DUCOPA CONTROL STATUS] unavailable: $1"
  echo "[COLLECT DUCOPA CONTROL STATUS] Written to $OUT_PATH"
}

if [ -z "${TAKOMACHI_CONTROL_READ_KEY:-}" ]; then
  write_unavailable "no TAKOMACHI_CONTROL_READ_KEY in the environment (no Keychain lookup by design, see header)"
  exit 0
fi

curl_get() {
  # curl_get PATH -- prints "HTTP_CODE\nBODY". 3s hard timeout, no
  # redirects, no retries, GET only.
  local path="$1" tmp status
  tmp="$(mktemp)"
  status="$(curl -s --max-time 3 -o "$tmp" -w "%{http_code}" -X GET "$TAKOMACHI_API_URL$path" \
    -H "Authorization: Bearer $TAKOMACHI_CONTROL_READ_KEY" 2>/dev/null)"
  printf '%s\n' "${status:-000}"
  cat "$tmp" 2>/dev/null
  rm -f "$tmp"
}

HB_RESULT="$(curl_get /control/heartbeat)"
HB_STATUS="$(echo "$HB_RESULT" | head -1)"
HB_BODY="$(echo "$HB_RESULT" | tail -n +2)"

case "$HB_STATUS" in
  200) ;;
  000)
    write_unavailable "Takomachi unreachable or timed out at $TAKOMACHI_API_URL (GET /control/heartbeat)" "$HB_STATUS"
    exit 0 ;;
  401)
    write_unavailable "GET /control/heartbeat 401: wrong TAKOMACHI_CONTROL_READ_KEY, or the control channel is disabled on Takomachi (indistinguishable from outside by design)" "$HB_STATUS"
    exit 0 ;;
  404)
    write_unavailable "GET /control/heartbeat 404: Takomachi's control channel is disabled (no control keys configured there)" "$HB_STATUS"
    exit 0 ;;
  *)
    write_unavailable "GET /control/heartbeat failed (HTTP $HB_STATUS)" "$HB_STATUS"
    exit 0 ;;
esac

LD_RESULT="$(curl_get /control/lockdown)"
LD_STATUS="$(echo "$LD_RESULT" | head -1)"
LD_BODY="$(echo "$LD_RESULT" | tail -n +2)"

python3 -c '
import json, sys

out, generated_at, api_url, note, hb_json, ld_status, ld_json = sys.argv[1:8]
DISPATCH_STATES = ("running", "paused", "lockdown")

def unavailable(reason):
    data = {"generated_at": generated_at, "note": note, "available": False, "reason": reason,
            "http_status": "200", "api_url": api_url, "dispatch_state": None, "heartbeat": None, "lockdown": None}
    with open(out, "w") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.write("\n")
    print("[COLLECT DUCOPA CONTROL STATUS] unavailable: " + reason)

try:
    hb = json.loads(hb_json)
except Exception:
    unavailable("heartbeat body is not JSON")
    sys.exit(0)
if not isinstance(hb, dict) or any(k not in hb for k in ("checked_at", "dispatch_state", "system_health")):
    unavailable("heartbeat body lacks a required field (checked_at, dispatch_state, system_health)")
    sys.exit(0)
if hb["dispatch_state"] not in DISPATCH_STATES:
    unavailable("heartbeat dispatch_state %r is not one of %s" % (hb["dispatch_state"], "/".join(DISPATCH_STATES)))
    sys.exit(0)

# GET /control/lockdown answers the current episode or null. It is
# reported as unknown (not "no lockdown") unless it answered 200.
lockdown = {"available": False, "active": None, "episode": None}
if ld_status == "200":
    try:
        ep = json.loads(ld_json)
        if ep is None:
            lockdown = {"available": True, "active": False, "episode": None}
        elif isinstance(ep, dict):
            lockdown = {"available": True, "active": ep.get("status") == "active", "episode": {
                k: ep.get(k) for k in ("id", "status", "entered_reason", "trigger_category", "entered_by", "entered_via", "entered_at")}}
    except Exception:
        pass

data = {
    "generated_at": generated_at,
    "note": note,
    "available": True,
    "reason": None,
    "http_status": "200",
    "api_url": api_url,
    "dispatch_state": hb["dispatch_state"],
    "heartbeat": {"checked_at": hb.get("checked_at"), "system_health": hb.get("system_health")},
    "lockdown": lockdown,
}
with open(out, "w") as f:
    json.dump(data, f, indent=2, ensure_ascii=False)
    f.write("\n")
print("[COLLECT DUCOPA CONTROL STATUS] available (dispatch_state=%s lockdown_active=%s)" % (hb["dispatch_state"], lockdown["active"]))
' "$OUT_PATH" "$GENERATED_AT" "$TAKOMACHI_API_URL" "$NOTE" "$HB_BODY" "$LD_STATUS" "$LD_BODY"
echo "[COLLECT DUCOPA CONTROL STATUS] Written to $OUT_PATH"
