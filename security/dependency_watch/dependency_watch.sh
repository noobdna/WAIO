#!/bin/bash
set -uo pipefail

# security/dependency_watch/dependency_watch.sh -- W-1 Dependency Notice
# Watch runner. Fetches the official status feeds listed in
# sources.conf, one request per source, and hands each saved feed to
# dependency_watch_lib.py. Design: security/dependency_watch/DESIGN.md.
#
# NOT scheduled, and NOT runnable in production until a human approves
# the egress allowlist entries. Gates, in order, per source:
#   1. shutdown already active            -> run nothing
#   2. egress allowlist pre-check, READ ONLY. egress_check() calls
#      trigger_shutdown (a WAIO-wide stop) for an unlisted destination,
#      so this script never calls egress_check for a host it has not
#      first found in the allowlist. A missing allowlist file -> run
#      nothing.
#   3. HFR Source Registry: status must be ALLOWED
#      (hfr_lib.Registry.check_capture(source_id, "feed")).
#   4. egress_check HOST 443 (audit-logged)
#   5. curl over https only, no redirects (--max-redirs 0, never -L),
#      size and time limits, no credentials.
# It never blocks, revokes or reconfigures anything, and never sends
# notifications. New security-category notices are printed as W-3
# escalation candidates for a human to register (or not).

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$SCRIPT_DIR" || exit 1
# shellcheck source=security/lib.sh
source security/lib.sh

DW_DIR="security/dependency_watch"
SOURCES_CONF="${DEPENDENCY_WATCH_SOURCES:-$DW_DIR/sources.conf}"
STATE_DIR="${DEPENDENCY_WATCH_STATE_DIR:-security/state/dependency_watch}"
HFR_HOME="${HFR_HOME:-$HOME/waio-ops/hunt-for-red}"
NOTICES="$STATE_DIR/notices.jsonl"
RUNS="$STATE_DIR/runs.jsonl"
RAW_DIR="$STATE_DIR/raw"
LOCK="$STATE_DIR/.run.lock"
MAX_BYTES=5242880
UA="WAIO-dependency-watch/0.1"
export HFR_HOME

log() { echo "[DEPENDENCY WATCH] $*"; }

run_log() { # source_id result detail
  python3 -I -c '
import json, sys, datetime
ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
with open(sys.argv[1], "a") as f:
    f.write(json.dumps({"ts": ts, "source_id": sys.argv[2], "result": sys.argv[3], "detail": sys.argv[4]}) + "\n")
' "$RUNS" "$1" "$2" "$3"
}

mkdir -p "$STATE_DIR" "$RAW_DIR" || exit 1

# Single run at a time: O_EXCL create via noclobber (not mkdir; see #226).
take_lock() {
  if ( set -o noclobber; echo "$$" > "$LOCK" ) 2>/dev/null; then return 0; fi
  local pid; pid="$(cat "$LOCK" 2>/dev/null || true)"
  if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then return 1; fi
  rm -f "$LOCK"
  ( set -o noclobber; echo "$$" > "$LOCK" ) 2>/dev/null
}
if ! take_lock; then log "another run holds $LOCK -- exiting"; exit 0; fi
trap 'rm -f "$LOCK"' EXIT

if is_shutdown_active; then
  log "shutdown is active -- nothing fetched"
  exit 0
fi
if [ ! -f "$EGRESS_ALLOWLIST" ]; then
  log "egress allowlist not found ($EGRESS_ALLOWLIST) -- nothing fetched (egress_check NOT called)"
  exit 0
fi
if [ ! -f "$SOURCES_CONF" ]; then
  log "sources file not found: $SOURCES_CONF"
  exit 1
fi

allowlisted() { # host -> 0 if "host|443|..." or "host|*|..." is present (read only)
  local a_host a_port _rest
  while IFS='|' read -r a_host a_port _rest; do
    case "$a_host" in ""|\#*) continue ;; esac
    if [ "$a_host" = "$1" ] && { [ "$a_port" = "443" ] || [ "$a_port" = "*" ]; }; then return 0; fi
  done < "$EGRESS_ALLOWLIST"
  return 1
}

registry_allows() { # source_id -> 0 if the HFR registry lets it be captured as a feed
  python3 -I - "$SCRIPT_DIR/security/hunt_for_red" "$HFR_HOME/registry/sources.json" "$1" <<'EOF'
import sys
sys.path.insert(0, sys.argv[1])
import hfr_lib as hl
try:
    hl.Registry(sys.argv[2]).check_capture(sys.argv[3], "feed")
except hl.HFRError as e:
    sys.stderr.write(str(e) + "\n")
    sys.exit(1)
EOF
}

TMP="$(mktemp "$STATE_DIR/.fetch.XXXXXX")"
trap 'rm -f "$LOCK" "$TMP"' EXIT

fetched=0; skipped=0; candidates=0
while IFS='|' read -r sid host path _rest; do
  case "$sid" in ""|\#*) continue ;; esac
  if ! [[ "$host" =~ ^[A-Za-z0-9.-]+$ ]] || ! [[ "$path" =~ ^/[A-Za-z0-9._/-]*$ ]]; then
    log "$sid: invalid host/path in $SOURCES_CONF -- skipped"; run_log "$sid" "skipped" "invalid host/path"; skipped=$((skipped+1)); continue
  fi
  if ! allowlisted "$host"; then
    log "$sid: $host is not in the egress allowlist -- not fetched (egress_check NOT called)"
    run_log "$sid" "skipped" "host not allowlisted"; skipped=$((skipped+1)); continue
  fi
  if ! reason="$(registry_allows "$sid" 2>&1)"; then
    log "$sid: registry refused -- $reason"
    run_log "$sid" "skipped" "registry: $reason"; skipped=$((skipped+1)); continue
  fi
  if ! egress_check "$host" "443" "" "" "DEPENDENCY_WATCH"; then
    log "$sid: egress_check denied -- not fetched"
    run_log "$sid" "denied" "egress_check"; skipped=$((skipped+1)); continue
  fi
  fetched_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  code="$(curl -sS --proto '=https' --max-redirs 0 --max-time 20 --max-filesize "$MAX_BYTES" \
            -A "$UA" -o "$TMP" -w '%{http_code}' "https://$host$path" 2>/dev/null || echo "000")"
  if [ "$code" != "200" ]; then
    log "$sid: HTTP $code (redirects are not followed) -- nothing recorded"
    run_log "$sid" "http_error" "$code"; skipped=$((skipped+1)); continue
  fi
  digest="$(shasum -a 256 "$TMP" | awk '{print $1}')"
  raw="$RAW_DIR/$digest.atom"
  if [ ! -e "$raw" ]; then cp "$TMP" "$raw" && chmod 0444 "$raw"; fi
  if ! summary="$(python3 -I "$DW_DIR/dependency_watch_lib.py" process "$sid" "$raw" "$NOTICES" "$fetched_at")"; then
    run_log "$sid" "parse_error" "$digest"; skipped=$((skipped+1)); continue
  fi
  run_log "$sid" "ok" "$summary"
  fetched=$((fetched+1))
  n="$(python3 -I -c 'import json,sys; print(len(json.loads(sys.argv[1])["security_new"]))' "$summary")"
  if [ "$n" -gt 0 ]; then
    candidates=$((candidates+n))
    python3 -I -c 'import json,sys; [print("[DEPENDENCY WATCH] W-3 candidate (security notice):", i) for i in json.loads(sys.argv[1])["security_new"]]' "$summary"
  fi
done < "$SOURCES_CONF"

log "done: fetched=$fetched skipped=$skipped w3_candidates=$candidates"
exit 0
