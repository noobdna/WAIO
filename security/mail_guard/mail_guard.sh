#!/bin/bash
set -uo pipefail

# security/mail_guard/mail_guard.sh -- the only path from 800 to Cloudflare
# for MAIL GUARD (P2). Two network actions:
#
#   mail_guard.sh pull                       R2 events -> security/state/mail_guard/
#   mail_guard.sh publish N --allowed-signers F
#                                            signed policy vN -> Workers KV
#
# Egress posture (design v0.1 §1.5, risk K12):
#   * the destination host is derived from config (R2: <account-id>.r2.
#     cloudflarestorage.com, KV: api.cloudflare.com) -- never from an
#     argument or an event
#   * PRE-CHECK, read-only: if Emergency Shutdown is active, the allowlist
#     file is missing, or the host is not listed, the action is reported
#     "unavailable" and nothing is sent. This pre-check never calls
#     trigger_shutdown: a not-yet-approved allowlist line must only make
#     the MAIL GUARD panel say "unavailable", never contain the system
#     (same posture as dashboard/collect_takomachi_status.sh)
#   * only then the real DuCoPA egress_check (audit-chained allow decision)
#     runs immediately before the Python call, which itself refuses any
#     host other than the one checked here (--expect-host)
#
# Credentials are read by the Python side from the environment or the
# login Keychain and are never put on a command line or printed.
# Nothing here is scheduled; see com.waio.mail-guard-pull.plist.example.

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_DIR" || exit 2
# shellcheck source=../lib.sh
source security/lib.sh

PY=(python3 -I "$REPO_DIR/security/mail_guard/mail_guard.py")
cmd="${1:-}"
shift || true

case "$cmd" in
  pull) target=r2; worker=MAIL_GUARD_PULL ;;
  publish) target=kv; worker=MAIL_GUARD_PUBLISH ;;
  *) echo "usage: $0 pull | publish VERSION --allowed-signers FILE" >&2; exit 2 ;;
esac

unavailable() {
  echo "[MAIL GUARD] unavailable: $1" >&2
  if [ "$cmd" = pull ]; then "${PY[@]}" pull-failed --reason "$1" || true; fi
  exit 3
}

host="$("${PY[@]}" host "$target" 2>/dev/null)" || unavailable "not configured (config.json missing or invalid)"
case "$host" in
  *[!a-z0-9.-]*|"") unavailable "configured host is malformed" ;;
esac

if is_shutdown_active; then unavailable "Emergency Shutdown is active"; fi
[ -f "$EGRESS_ALLOWLIST" ] || unavailable "egress allowlist missing"

listed=false
while IFS='|' read -r a_host a_port _; do
  case "$a_host" in ""|\#*) continue ;; esac
  if [ "$a_host" = "$host" ] && { [ "$a_port" = 443 ] || [ "$a_port" = "*" ]; }; then listed=true; break; fi
done < "$EGRESS_ALLOWLIST"
[ "$listed" = true ] || unavailable "$host:443 is not in the egress allowlist (adding it needs approval)"

run_id="mailguard-$(date -u +%Y%m%dT%H%M%SZ)-$$"
egress_check "$host" 443 "$run_id" "mail_guard" "$worker" || exit 2

if [ "$cmd" = pull ]; then
  exec "${PY[@]}" pull --expect-host "$host"
fi
version="${1:-}"
case "$version" in ''|*[!0-9]*) echo "publish needs a numeric VERSION" >&2; exit 2 ;; esac
shift
exec "${PY[@]}" policy-publish --version "$version" --execute --expect-host "$host" "$@"
