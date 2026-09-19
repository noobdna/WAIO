#!/bin/bash
set -uo pipefail

# security/incident_learning/collectors/cisa_kev_collector.sh -- Phase
# 81: the first REAL (non-mock) Collector, per the Collector contract
# mock_collector.sh's own header documents. Fetches CISA's own public
# Known Exploited Vulnerabilities (KEV) catalog
# (https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
# -- no authentication required, stable JSON schema, confirmed by
# fetching it directly during design: 1700+ entries, fields cveID/
# vendorProject/product/vulnerabilityName/dateAdded/shortDescription/
# requiredAction/knownRansomwareCampaignUse/notes/cwes) and emits one
# RawIncident JSONL record per entry added to the catalog within the
# last CISA_KEV_LOOKBACK_DAYS days (default 7), capped at
# CISA_KEV_MAX_RECORDS (default 25) -- NOT the whole historical catalog
# every run: an id is stable across runs (incident_normalizer.sh's own
# "already exists" handling makes re-feeding it a no-op), so
# re-emitting 1700+ old entries on every scheduled run would only add
# load, never new information.
#
# ARCHITECTURE DECISION (explicit, reviewed): this is the ONE file in
# security/incident_learning/ that sources security/lib.sh and calls
# egress_check() -- every other file in this domain's own "DuCoPA
# alignment" claim (never touches the Main/Guardian Control Plane)
# remains completely true and unbroken; only this collector is the
# reviewed exception. This performs a genuine automated, scheduled
# outbound fetch (incident_learning_cron.sh's own launchd schedule) --
# exactly the class of action egress_check() exists to gate, unlike a
# passive dashboard read (see dashboard/collect_takomachi_status.sh's
# own header for why THAT collector deliberately bypasses this same
# gate -- a different risk class, a considered choice on both sides,
# not a contradiction). Requires `www.cisa.gov|443` in
# security/egress_allowlist.conf (see that file's own .example
# template); if missing, egress_check() denies and trips a real
# Emergency Shutdown -- the exact same fail-closed contract every other
# WAIO worker with a real network call already has, not a new one
# invented for this file.
#
# Collector contract compliance (see mock_collector.sh's own header):
#   - id: "KEV-<cveID>" -- stable/collision-resistant across runs
#   - source: "cisa_kev_collector"
#   - source_type: "cert" -- CISA is the US cybersecurity agency
#     (CERT-class authority), not a product vendor;
#     incident_confidence.sh's own WEIGHTS table only recognizes
#     vendor_advisory/cert/news/unknown -- an invented label like
#     "government_advisory" would silently fall to the lowest
#     (unknown) weight, badly under-scoring a genuinely authoritative
#     source
#   - source_url: the CVE's own NVD detail page -- always resolvable
#     for any real CVE id, unlike parsing KEV's own free-text "notes"
#     field for a URL that may or may not actually be present
#   - collected_at: the KEV catalog's own "dateAdded" (when CISA
#     confirmed active exploitation), not "now" -- makes
#     incident_evidence.sh's own freshness/staleness scoring meaningful
#     instead of every entry looking artificially fresh just because
#     this collector happened to poll today
#   - raw_text: synthesized from vulnerabilityName/shortDescription/
#     requiredAction/vendorProject/product, in the same
#     "Mitigation:"-prefixed-sentence style mock_collector.sh's own
#     samples already use, so incident_normalizer.sh's existing
#     keyword-based mitigation extraction picks it up unmodified;
#     deliberately never uses phrasing like "unverified"/"single
#     source"/"no corroboration" (incident_evidence.sh's own
#     self-reported-uncorroborated keyword scan), since a KEV entry is
#     never any of those things
#   - corroborating_sources: deliberately omitted -- KEV is a single
#     authoritative source per entry; fabricating a second source would
#     violate the contract's own "never fabricates" rule
#   - never reports knownRansomwareCampaignUse/CWE/etc. as a
#     verification claim -- CISA's own metadata, copied through as
#     descriptive text only, same as every other field here
#
# 20s overall timeout (matching earth_weather/weather_agent.sh's own
# convention for a similarly-sized public feed), no retries --
# "unavailable this cycle, not an automatic retry loop", same posture
# as every other real-network WAIO caller.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$SCRIPT_DIR"
source security/lib.sh

HOST="www.cisa.gov"
PORT="443"
URL="https://$HOST/sites/default/files/feeds/known_exploited_vulnerabilities.json"
LOOKBACK_DAYS="${CISA_KEV_LOOKBACK_DAYS:-7}"
MAX_RECORDS="${CISA_KEV_MAX_RECORDS:-25}"

if ! egress_check "$HOST" "$PORT" "" "" "CISA_KEV_COLLECTOR"; then
  echo "[CISA KEV COLLECTOR] ERROR: egress denied by DLP guard -- request not sent" >&2
  exit 1
fi

TMP_BODY="$(mktemp)"
trap 'rm -f "$TMP_BODY"' EXIT

STATUS="$(curl -s --max-time 20 -o "$TMP_BODY" -w "%{http_code}" "$URL" 2>/dev/null || echo "000")"
if [ "$STATUS" != "200" ]; then
  echo "[CISA KEV COLLECTOR] ERROR: GET $URL failed (HTTP $STATUS)" >&2
  exit 1
fi

python3 -c "
import json, sys
from datetime import datetime, timezone, timedelta

lookback_days = int(sys.argv[1])
max_records = int(sys.argv[2])
body_path = sys.argv[3]

try:
    data = json.load(open(body_path))
except Exception as e:
    print(f'[CISA KEV COLLECTOR] ERROR: response is not valid JSON: {e}', file=sys.stderr)
    sys.exit(1)

vulns = data.get('vulnerabilities', [])
cutoff = datetime.now(timezone.utc) - timedelta(days=lookback_days)

def parse_date(s):
    try:
        return datetime.strptime(s, '%Y-%m-%d').replace(tzinfo=timezone.utc)
    except Exception:
        return None

recent = []
for v in vulns:
    d = parse_date(v.get('dateAdded', ''))
    if d is not None and d >= cutoff:
        recent.append((d, v))

recent.sort(key=lambda t: t[0], reverse=True)
recent = recent[:max_records]

emitted = 0
for d, v in recent:
    cve_id = v.get('cveID', '')
    if not cve_id:
        continue
    name = v.get('vulnerabilityName', '')
    vendor = v.get('vendorProject', '')
    product = v.get('product', '')
    desc = v.get('shortDescription', '')
    action = v.get('requiredAction', '')
    ransomware = v.get('knownRansomwareCampaignUse', 'Unknown')
    date_added = v.get('dateAdded', 'unknown date')

    raw_text_parts = []
    if name:
        raw_text_parts.append(f'{name} ({cve_id}) affects {vendor} {product}.'.strip())
    if desc:
        raw_text_parts.append(desc)
    if action:
        raw_text_parts.append(f'Mitigation: {action}')
    raw_text_parts.append(
        f'CISA Known Exploited Vulnerabilities catalog: confirmed active exploitation, '
        f'added {date_added}. Known ransomware campaign use: {ransomware}.'
    )
    raw_text = ' '.join(p for p in raw_text_parts if p)

    record = {
        'id': f'KEV-{cve_id}',
        'source': 'cisa_kev_collector',
        'source_type': 'cert',
        'source_url': f'https://nvd.nist.gov/vuln/detail/{cve_id}',
        'collected_at': d.strftime('%Y-%m-%dT00:00:00Z'),
        'raw_text': raw_text,
    }
    print(json.dumps(record, ensure_ascii=False))
    emitted += 1

print(f'[CISA KEV COLLECTOR] emitted {emitted} record(s) added to the KEV catalog in the last {lookback_days} day(s) (of {len(vulns)} total catalog entries)', file=sys.stderr)
" "$LOOKBACK_DAYS" "$MAX_RECORDS" "$TMP_BODY"
