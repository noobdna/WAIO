#!/bin/bash
set -uo pipefail

# security/corporate_intel/ci_fetch.sh -- the ONLY network exit of the
# WAIO Corporate Intelligence module. Read-only HTTPS GET of one public
# feed, gated by security/lib.sh's egress_check() (an unlisted host
# trips Emergency Shutdown -- the existing fail-closed contract, not a
# new one).
#
# usage: WAIO_CI_ONLINE=1 ci_fetch.sh {kev|nvd|epss} OUTFILE [CVE-ID ...]
#   kev   no ids
#   nvd   exactly one id   (NVD CVE API 2.0, keyless)
#   epss  1-100 ids        (FIRST EPSS API v1)
# stdout: the HTTP status code. exit 0 only on HTTP 200.
#
# Hard rules (tests/corporate_intel_fetch_test.sh):
#   - refuses unless WAIO_CI_ONLINE=1 (ci.py sets it only for `fetch --online`)
#   - host and URL path are fixed here; ids are validated against a strict
#     CVE regex, so no caller input can change the destination
#   - https only, no redirects, 20 s timeout, 20 MB cap, no retries
#   - never sends credentials: P1 is keyless; NVD_API_KEY is ignored

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$SCRIPT_DIR" || exit 2

if [ "${WAIO_CI_ONLINE:-}" != "1" ]; then
  echo "[CORPORATE INTEL FETCH] refused: offline mode (WAIO_CI_ONLINE!=1)" >&2
  exit 3
fi

if [ "$#" -lt 2 ]; then
  echo "[CORPORATE INTEL FETCH] usage: ci_fetch.sh {kev|nvd|epss} OUTFILE [CVE-ID ...]" >&2
  exit 2
fi
SOURCE="$1"
OUT="$2"
shift 2

OUT_DIR="$(dirname "$OUT")"
if [ ! -d "$OUT_DIR" ]; then
  echo "[CORPORATE INTEL FETCH] refused: output directory does not exist" >&2
  exit 2
fi

for id in "$@"; do
  if ! [[ "$id" =~ ^CVE-[0-9]{4}-[0-9]{4,7}$ ]]; then
    echo "[CORPORATE INTEL FETCH] refused: invalid CVE id" >&2
    exit 2
  fi
done

case "$SOURCE" in
  kev)
    [ "$#" -eq 0 ] || { echo "[CORPORATE INTEL FETCH] kev takes no ids" >&2; exit 2; }
    HOST="www.cisa.gov"
    URL="https://$HOST/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    ;;
  nvd)
    [ "$#" -eq 1 ] || { echo "[CORPORATE INTEL FETCH] nvd takes exactly one id" >&2; exit 2; }
    HOST="services.nvd.nist.gov"
    URL="https://$HOST/rest/json/cves/2.0?cveId=$1"
    ;;
  epss)
    { [ "$#" -ge 1 ] && [ "$#" -le 100 ]; } || { echo "[CORPORATE INTEL FETCH] epss takes 1-100 ids" >&2; exit 2; }
    HOST="api.first.org"
    IDS="$(IFS=,; echo "$*")"
    URL="https://$HOST/data/v1/epss?cve=$IDS"
    ;;
  *)
    echo "[CORPORATE INTEL FETCH] refused: unknown source" >&2
    exit 2
    ;;
esac

# shellcheck source=security/lib.sh
source security/lib.sh

WORKER="CORPORATE_INTEL_$(printf '%s' "$SOURCE" | tr '[:lower:]' '[:upper:]')"
if ! egress_check "$HOST" "443" "" "" "$WORKER"; then
  echo "[CORPORATE INTEL FETCH] ERROR: egress denied by DLP guard -- request not sent" >&2
  exit 1
fi

STATUS="$(curl -sS --proto '=https' --max-time 20 --max-filesize 20971520 \
  -H 'Accept: application/json' -o "$OUT" -w '%{http_code}' "$URL" 2>/dev/null)"
CURL_RC=$?
STATUS="${STATUS:-000}"
printf '%s\n' "$STATUS"
# curl's own exit code matters even with HTTP 200: a timeout or the
# --max-filesize cap (rc 28/63) can leave a truncated body behind.
if [ "$CURL_RC" -ne 0 ] || [ "$STATUS" != "200" ]; then
  rm -f "$OUT"
  echo "[CORPORATE INTEL FETCH] ERROR: $SOURCE fetch failed (HTTP $STATUS, curl rc $CURL_RC)" >&2
  exit 1
fi
exit 0
