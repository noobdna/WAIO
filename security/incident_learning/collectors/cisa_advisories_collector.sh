#!/bin/bash
set -uo pipefail

# security/incident_learning/collectors/cisa_advisories_collector.sh --
# Phase 99 (international real-source expansion): a THIRD real
# Collector, distinct from cisa_kev_collector.sh (Phase 81). Fetches
# CISA's own public "Cybersecurity Advisories" RSS feed
# (https://www.cisa.gov/cybersecurity-advisories/all.xml -- no
# authentication required, confirmed live during design: RSS 2.0,
# title/link/description(full HTML advisory body)/pubDate/dc:creator/
# guid per item), NOT the KEV catalog JSON cisa_kev_collector.sh
# already covers -- this is CISA's broader advisory stream (ICS/ICS-
# Medical vendor advisories and joint alerts), a different real
# document set from the same agency, kept as its own Collector/source/
# id-namespace so the two never collide or double-count the same
# underlying advisory.
#
# Same host as cisa_kev_collector.sh (www.cisa.gov) -- already present
# in security/egress_allowlist.conf since Phase 81, so this Collector
# requires NO new allowlist entry.
#
# Content reality (confirmed live during design, documented honestly
# rather than assumed): every sampled item is an ICS/vendor-patch-style
# advisory citing specific CVEs, not a company/public-breach-style
# report -- this will classify as incident_type=vulnerability_disclosure
# via incident_normalizer.sh's existing cve_list fallback (see that
# file's own header, and tests/incident_learning_classification_test.sh's
# C6 case), the same shape cisa_kev_collector.sh/ghsa_collector.sh
# already produce. It is a legitimate, suitable Collector contract
# source for this pipeline, but it will mostly exercise the
# vulnerability_disclosure/CVE-correlation path, not the Phase 98
# breach-style categories (data_breach/account_takeover/etc.) --
# cert_ee_collector.sh is the one of this phase's three real Collectors
# expected to exercise that path.
#
# ARCHITECTURE DECISION (same posture as cisa_kev_collector.sh/
# ghsa_collector.sh's own headers): this is now the THIRD file in
# security/incident_learning/ that sources security/lib.sh and calls
# egress_check() -- a genuine automated, scheduled outbound fetch,
# exactly what egress_check() exists to gate.
#
# Collector contract compliance (see mock_collector.sh's own header):
#   - id: "CISAADV-<slug>", where slug is the advisory's own final URL
#     path segment (e.g. "icsa-26-279-05") -- CISA's own stable
#     identifier for the advisory, already unique/collision-resistant
#     by construction, so no hash is needed; sanitized to
#     [A-Za-z0-9-] only before use.
#   - source: "cisa_advisories_collector" -- deliberately distinct from
#     cisa_kev_collector.sh's "cisa_kev_collector", so the two real
#     CISA sources are never confused with each other downstream.
#   - source_type: "cert" -- same reasoning as cisa_kev_collector.sh's
#     own header (CISA is a CERT-class government authority, not a
#     product vendor; incident_confidence.sh's WEIGHTS table only
#     recognizes vendor_advisory/cert/news/unknown).
#   - source_url: the advisory's own cisa.gov page (the <link> itself)
#     -- unlike cisa_kev_collector.sh's NVD-detail-page choice, CISA's
#     own advisory page here already IS the authoritative source.
#   - collected_at AND published_at: both set to the feed's own pubDate
#     -- deliberately identical. collected_at carries this value (not
#     "now") for the same freshness/staleness-scoring reason
#     cisa_kev_collector.sh's own header gives; published_at exists
#     specifically to record "when the source published it," which is
#     also exactly this value -- no information is lost by them
#     matching here, and incident_evidence.sh's own age scoring stays
#     meaningful.
#   - raw_text: title + the HTML <description> body with tags stripped
#     and entities unescaped (plain text), so incident_normalizer.sh's
#     existing CVE/mitigation/keyword extraction runs over real prose,
#     not escaped markup; deliberately never synthesizes
#     "unverified"/"single source"/"no corroboration" phrasing
#     (incident_evidence.sh's own self-reported-uncorroborated scan),
#     since a CISA advisory is never any of those things.
#   - corroborating_sources: deliberately omitted, same reasoning as
#     cisa_kev_collector.sh.
#   - country="US", region="NA", language="en": Collector-supplied
#     explicit metadata (Phase 98 contract), not left to
#     incident_normalizer.sh's own JA/EN-presence heuristic.
#
# 20s overall timeout, no retries -- same convention as
# cisa_kev_collector.sh.
#
# ENTITY-EXPANSION GUARD (post-implementation review fix): the fetched
# body is rejected outright if it contains a literal `<!DOCTYPE` or
# `<!ENTITY` substring, BEFORE any XML parsing is attempted --
# `xml.etree.ElementTree` expands internal DTD entities by default
# (verified during review: a small handful of nested entity
# definitions inflates to kilobytes-to-gigabytes in memory, the
# classic "billion laughs" class of attack), and this is the first
# Collector in this domain to parse XML at all (cisa_kev_collector.sh/
# ghsa_collector.sh both parse JSON, which has no such surface). The
# real CISA advisories feed never declares a DOCTYPE/ENTITY (confirmed
# live during design), so this costs nothing against the real source
# and closes the attack class entirely -- a stdlib-only, auditable
# substring check, deliberately not a new `defusedxml` pip dependency
# (this repo has no requirements.txt/pyproject.toml at all; every
# other Collector/stage in this domain is stdlib-only by convention).

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$SCRIPT_DIR"
source security/lib.sh

HOST="www.cisa.gov"
PORT="443"
URL="https://$HOST/cybersecurity-advisories/all.xml"
LOOKBACK_DAYS="${CISA_ADVISORIES_LOOKBACK_DAYS:-7}"
MAX_RECORDS="${CISA_ADVISORIES_MAX_RECORDS:-25}"

if ! egress_check "$HOST" "$PORT" "" "" "CISA_ADVISORIES_COLLECTOR"; then
  echo "[CISA ADVISORIES COLLECTOR] ERROR: egress denied by DLP guard -- request not sent" >&2
  exit 1
fi

TMP_BODY="$(mktemp)"
trap 'rm -f "$TMP_BODY"' EXIT

STATUS="$(curl -s --max-time 20 -o "$TMP_BODY" -w "%{http_code}" "$URL" 2>/dev/null || echo "000")"
if [ "$STATUS" != "200" ]; then
  echo "[CISA ADVISORIES COLLECTOR] ERROR: GET $URL failed (HTTP $STATUS)" >&2
  exit 1
fi

python3 -c "
import html, json, re, sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone, timedelta
from email.utils import parsedate_to_datetime

lookback_days = int(sys.argv[1])
max_records = int(sys.argv[2])
body_path = sys.argv[3]

try:
    with open(body_path, 'rb') as f:
        raw_body = f.read()
except Exception as e:
    print(f'[CISA ADVISORIES COLLECTOR] ERROR: could not read response body: {e}', file=sys.stderr)
    sys.exit(1)

if b'<!DOCTYPE' in raw_body or b'<!ENTITY' in raw_body:
    print('[CISA ADVISORIES COLLECTOR] ERROR: response contains a DOCTYPE/ENTITY declaration -- refusing to parse (entity-expansion guard; the real CISA advisories feed never declares one)', file=sys.stderr)
    sys.exit(1)

try:
    root = ET.fromstring(raw_body)
except Exception as e:
    print(f'[CISA ADVISORIES COLLECTOR] ERROR: response is not valid XML: {e}', file=sys.stderr)
    sys.exit(1)

def local(tag):
    return tag.split('}')[-1] if '}' in tag else tag

def child_text(item, *names):
    wanted = {n.lower() for n in names}
    for child in item:
        if local(child.tag).lower() in wanted and child.text:
            return child.text.strip()
    return ''

def strip_html(s):
    s = html.unescape(s or '')
    s = re.sub(r'<[^>]+>', ' ', s)
    return ' '.join(s.split())

def slug_from_link(link):
    seg = link.rstrip('/').rsplit('/', 1)[-1] if link else ''
    seg = re.sub(r'[^A-Za-z0-9-]', '', seg)
    return seg

def parse_pubdate(s):
    try:
        d = parsedate_to_datetime(s)
        if d.tzinfo is None:
            d = d.replace(tzinfo=timezone.utc)
        return d.astimezone(timezone.utc)
    except Exception:
        return None

cutoff = datetime.now(timezone.utc) - timedelta(days=lookback_days)

items = [e for e in root.iter() if local(e.tag) == 'item']

parsed = []
for item in items:
    title = child_text(item, 'title')
    link = child_text(item, 'link')
    description = child_text(item, 'description')
    pubdate_raw = child_text(item, 'pubDate', 'pubdate')
    d = parse_pubdate(pubdate_raw)
    if d is None or d < cutoff:
        continue
    slug = slug_from_link(link)
    if not slug:
        continue
    parsed.append((d, slug, title, link, description))

parsed.sort(key=lambda t: t[0], reverse=True)
parsed = parsed[:max_records]

emitted = 0
for d, slug, title, link, description in parsed:
    body = strip_html(description)
    raw_text_parts = []
    if title:
        raw_text_parts.append(title + '.')
    if body:
        raw_text_parts.append(body)
    raw_text = ' '.join(p for p in raw_text_parts if p)
    if not raw_text:
        continue

    ts = d.strftime('%Y-%m-%dT%H:%M:%SZ')
    record = {
        'id': f'CISAADV-{slug}',
        'source': 'cisa_advisories_collector',
        'source_type': 'cert',
        'source_url': link,
        'collected_at': ts,
        'published_at': ts,
        'country': 'US',
        'region': 'NA',
        'language': 'en',
        'raw_text': raw_text,
    }
    print(json.dumps(record, ensure_ascii=False))
    emitted += 1

print(f'[CISA ADVISORIES COLLECTOR] emitted {emitted} record(s) published in the last {lookback_days} day(s) (of {len(items)} total feed items)', file=sys.stderr)
" "$LOOKBACK_DAYS" "$MAX_RECORDS" "$TMP_BODY"
