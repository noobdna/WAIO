#!/bin/bash
set -uo pipefail

# security/incident_learning/collectors/jpcert_collector.sh -- Phase 99
# (international real-source expansion): the Japan real Collector.
# Fetches JPCERT/CC's own official public RSS feed
# (https://www.jpcert.or.jp/english/rss/jpcert-en.rdf -- no
# authentication required, confirmed live during design: RDF 1.0,
# channel identifies itself as "JPCERT/CC RSS Feed" / publisher
# "JPCERT/CC" / webmaster@jpcert.or.jp).
#
# KNOWN, DOCUMENTED LIMITATION (confirmed live during design, not
# discovered later): every <item> in this feed carries ONLY <title>/
# <link>/<dc:date> -- there is no <description> or body text at all,
# unlike cisa_advisories_collector.sh's/cert_ee_collector.sh's own
# feeds. raw_text below is therefore the title alone (e.g. "Security
# Alert: Alert Regarding Vulnerabilities in Adobe Acrobat and Reader
# (APSB26-141)"), which is too short and too generic for
# incident_normalizer.sh's affected_sector/claimed_impact extraction to
# find anything, and will usually NOT contain a literal CVE id either
# (JPCERT/CC alert titles reference vendor bulletin ids like
# "APSB26-141", not "CVE-YYYY-NNNNN") -- so most records from this
# Collector land on incident_type=unclassified, not even the
# vulnerability_disclosure fallback cisa_kev_collector.sh/
# cisa_advisories_collector.sh/ghsa_collector.sh all reach. This is a
# deliberate, accepted trade-off for this phase (an honest, title-only
# Collector today, matching this feed's real content) rather than
# silently fetching each item's own linked advisory page for a fuller
# body -- that would be a second network call per item against the
# same host, a real added complexity explicitly deferred rather than
# built speculatively; a future phase MAY add it if deeper JPCERT/CC
# coverage is wanted. Still a legitimate, correctly-functioning
# Collector in the meantime: it corroborates CISA KEV/GHSA-style
# vulnerability_disclosure candidates whenever a title DOES happen to
# contain its own CVE id, and it keeps a live, auditable JP-origin feed
# wired into the pipeline for whenever JPCERT/CC's own titles do carry
# enough signal.
#
# Requires `www.jpcert.or.jp|443` in security/egress_allowlist.conf
# (new entry, Phase 99 -- see that file's own .example template); if
# missing, egress_check() denies and trips a real Emergency Shutdown,
# the same fail-closed contract every other real-network Collector in
# this domain already has.
#
# ARCHITECTURE DECISION (same posture as cisa_kev_collector.sh/
# ghsa_collector.sh/cisa_advisories_collector.sh's own headers): this
# is now the FOURTH file in security/incident_learning/ that sources
# security/lib.sh and calls egress_check().
#
# Collector contract compliance (see mock_collector.sh's own header):
#   - id: "JPCERT-<slug>", where slug is the advisory page's own
#     filename without extension (e.g. link ".../at/2026/at260026.html"
#     -> "at260026") -- JPCERT/CC's own stable identifier, already
#     unique/collision-resistant by construction; sanitized to
#     [A-Za-z0-9-] only before use.
#   - source: "jpcert_collector"
#   - source_type: "cert" -- JPCERT/CC is Japan's national CERT-class
#     coordination authority, not a product vendor; same reasoning as
#     cisa_kev_collector.sh's own header.
#   - source_url: the item's own <link> (JPCERT/CC's own advisory
#     page).
#   - collected_at AND published_at: both set to the feed's own
#     <dc:date> -- deliberately identical, same reasoning as
#     cisa_advisories_collector.sh's own header (freshness-scoring
#     correctness and published_at's own meaning coincide here).
#   - raw_text: the title alone (see limitation above); never
#     synthesizes "unverified"/"single source"/"no corroboration"
#     phrasing (incident_evidence.sh's own self-reported-uncorroborated
#     scan), since a JPCERT/CC alert is never any of those things.
#   - corroborating_sources: deliberately omitted, same reasoning as
#     every other real Collector in this domain.
#   - country="JP", region="APAC", language="en" (this is the
#     English-language JPCERT/CC feed): Collector-supplied explicit
#     metadata (Phase 98 contract), not left to
#     incident_normalizer.sh's own JA/EN-presence heuristic.
#
# 20s overall timeout, no retries -- same convention as every other
# real Collector in this domain.
#
# ENTITY-EXPANSION GUARD (post-implementation review fix): the fetched
# body is rejected outright if it contains a literal `<!DOCTYPE` or
# `<!ENTITY` substring, BEFORE any XML parsing is attempted -- see
# cisa_advisories_collector.sh's own header for the full rationale
# (xml.etree.ElementTree expands internal DTD entities by default, a
# "billion laughs"-class DoS risk no JSON-based Collector in this
# domain has). The real JPCERT/CC feed never declares a
# DOCTYPE/ENTITY (confirmed live during design).

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$SCRIPT_DIR"
source security/lib.sh

HOST="www.jpcert.or.jp"
PORT="443"
URL="https://$HOST/english/rss/jpcert-en.rdf"
LOOKBACK_DAYS="${JPCERT_LOOKBACK_DAYS:-7}"
MAX_RECORDS="${JPCERT_MAX_RECORDS:-25}"

if ! egress_check "$HOST" "$PORT" "" "" "JPCERT_COLLECTOR"; then
  echo "[JPCERT COLLECTOR] ERROR: egress denied by DLP guard -- request not sent" >&2
  exit 1
fi

TMP_BODY="$(mktemp)"
trap 'rm -f "$TMP_BODY"' EXIT

STATUS="$(curl -s --max-time 20 -o "$TMP_BODY" -w "%{http_code}" "$URL" 2>/dev/null || echo "000")"
if [ "$STATUS" != "200" ]; then
  echo "[JPCERT COLLECTOR] ERROR: GET $URL failed (HTTP $STATUS)" >&2
  exit 1
fi

python3 -c "
import json, re, sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone, timedelta

lookback_days = int(sys.argv[1])
max_records = int(sys.argv[2])
body_path = sys.argv[3]

try:
    with open(body_path, 'rb') as f:
        raw_body = f.read()
except Exception as e:
    print(f'[JPCERT COLLECTOR] ERROR: could not read response body: {e}', file=sys.stderr)
    sys.exit(1)

if b'<!DOCTYPE' in raw_body or b'<!ENTITY' in raw_body:
    print('[JPCERT COLLECTOR] ERROR: response contains a DOCTYPE/ENTITY declaration -- refusing to parse (entity-expansion guard; the real JPCERT/CC feed never declares one)', file=sys.stderr)
    sys.exit(1)

try:
    root = ET.fromstring(raw_body)
except Exception as e:
    print(f'[JPCERT COLLECTOR] ERROR: response is not valid XML: {e}', file=sys.stderr)
    sys.exit(1)

def local(tag):
    return tag.split('}')[-1] if '}' in tag else tag

def child_text(item, *names):
    wanted = {n.lower() for n in names}
    for child in item:
        if local(child.tag).lower() in wanted and child.text:
            return child.text.strip()
    return ''

def slug_from_link(link):
    seg = link.rstrip('/').rsplit('/', 1)[-1] if link else ''
    seg = seg.rsplit('.', 1)[0] if '.' in seg else seg
    seg = re.sub(r'[^A-Za-z0-9-]', '', seg)
    return seg

def parse_dcdate(s):
    # JPCERT/CC's own dc:date shape: '2026-09-09T11:36+09:00' (no
    # seconds). Try with and without seconds, with and without a ':' in
    # the UTC offset, before giving up -- never crash on an unexpected
    # variant, just skip that one item.
    for fmt in ('%Y-%m-%dT%H:%M:%S%z', '%Y-%m-%dT%H:%M%z'):
        try:
            normalized = re.sub(r'([+-]\d{2}):(\d{2})\$', r'\1\2', s)
            return datetime.strptime(normalized, fmt).astimezone(timezone.utc)
        except Exception:
            continue
    return None

cutoff = datetime.now(timezone.utc) - timedelta(days=lookback_days)

items = [e for e in root.iter() if local(e.tag) == 'item']

parsed = []
for item in items:
    title = child_text(item, 'title')
    link = child_text(item, 'link')
    date_raw = child_text(item, 'date')
    d = parse_dcdate(date_raw)
    if d is None or d < cutoff:
        continue
    slug = slug_from_link(link)
    if not slug or not title:
        continue
    parsed.append((d, slug, title, link))

parsed.sort(key=lambda t: t[0], reverse=True)
parsed = parsed[:max_records]

emitted = 0
for d, slug, title, link in parsed:
    ts = d.strftime('%Y-%m-%dT%H:%M:%SZ')
    record = {
        'id': f'JPCERT-{slug}',
        'source': 'jpcert_collector',
        'source_type': 'cert',
        'source_url': link,
        'collected_at': ts,
        'published_at': ts,
        'country': 'JP',
        'region': 'APAC',
        'language': 'en',
        'raw_text': title,
    }
    print(json.dumps(record, ensure_ascii=False))
    emitted += 1

print(f'[JPCERT COLLECTOR] emitted {emitted} record(s) published in the last {lookback_days} day(s) (of {len(items)} total feed items)', file=sys.stderr)
" "$LOOKBACK_DAYS" "$MAX_RECORDS" "$TMP_BODY"
