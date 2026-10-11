#!/bin/bash
set -uo pipefail

# security/incident_learning/collectors/cert_ee_collector.sh -- Phase
# 99 (international real-source expansion): the Estonia real
# Collector. Fetches RIA's (Riigi Infosysteemi Amet / Estonian
# Information System Authority -- CERT-EE's own parent agency) public
# English-language news feed
# (https://www.ria.ee/en/news-feed/all/feed -- no authentication
# required, confirmed live during design: RSS 2.0, title/link/
# description(2-sentence teaser)/pubDate/dc:creator/guid per item).
# There is no dedicated CERT-EE-only incident API; this is RIA's
# general news feed, which happens to include CERT-EE's own monthly
# cyberspace-incident summaries alongside unrelated government-IT
# announcements (ID-card software updates, policy notices, etc).
#
# PRE-FILTER (the one thing that makes a GENERAL news feed usable as
# an Incident Learning Collector source): INCIDENT_CUES below gates
# every item on title+description before it is ever emitted -- an item
# matching none of these cues is simply never emitted, not
# "classified unclassified downstream." This keeps non-incident RIA
# announcements out of the pipeline entirely, entirely inside this one
# Collector script -- incident_normalizer.sh's own classification
# tables are untouched and never see a filtered-out item at all.
#
# Content reality (confirmed live during design): sampled items
# include genuine breach/incident-shaped prose in English, e.g. "data
# breaches affecting the dental care information system and the
# University of Tartu's online bookshop, denial-of-service attacks,
# and repeated disruptions to the state's authentication services" --
# this is expected to be the one of this phase's three real Collectors
# that actually exercises incident_type=data_breach/ddos and the
# Correlate step's breach-style attack_pattern matching (see
# cisa_advisories_collector.sh's/jpcert_collector.sh's own headers for
# why those two mostly land on vulnerability_disclosure instead).
# Description is a short (~2 sentence) teaser, not a full article body
# -- claimed_impact extraction will often legitimately come back empty
# (no sentence happens to contain one of incident_normalizer.sh's own
# claimed-impact cue phrases), same "absent finding is not a failure"
# contract as every other field in this pipeline.
#
# Requires `www.ria.ee|443` in security/egress_allowlist.conf (new
# entry, Phase 99 -- see that file's own .example template); if
# missing, egress_check() denies and trips a real Emergency Shutdown,
# the same fail-closed contract every other real-network Collector in
# this domain already has.
#
# ARCHITECTURE DECISION (same posture as cisa_kev_collector.sh/
# ghsa_collector.sh/cisa_advisories_collector.sh/jpcert_collector.sh's
# own headers): this is now the FIFTH file in security/incident_learning/
# that sources security/lib.sh and calls egress_check().
#
# Collector contract compliance (see mock_collector.sh's own header):
#   - id: "CERTEE-<nid>", where nid is the numeric node id RIA's own
#     Drupal-shaped <guid> carries (e.g. guid "4389 at
#     https://www.ria.ee/en" -> nid "4389") -- RIA's own stable
#     identifier, already unique/collision-resistant by construction;
#     falls back to a sanitized slug of the item's own <link> if a
#     <guid> is ever missing or not in this exact shape, rather than
#     skipping the item outright.
#   - source: "cert_ee_collector"
#   - source_type: "cert" -- RIA/CERT-EE is Estonia's national CERT-
#     class authority, not a product vendor; same reasoning as every
#     other real Collector in this domain.
#   - source_url: the item's own <link> (RIA's own news page).
#   - collected_at AND published_at: both set to the feed's own
#     pubDate -- deliberately identical, same reasoning as
#     cisa_advisories_collector.sh's own header.
#   - raw_text: title + description (the teaser), concatenated --
#     deliberately never synthesizes "unverified"/"single source"/
#     "no corroboration" phrasing (incident_evidence.sh's own
#     self-reported-uncorroborated scan), since a RIA news item is
#     never any of those things.
#   - corroborating_sources: deliberately omitted, same reasoning as
#     every other real Collector in this domain.
#   - country="EE", region="EU", language="en" (this is the
#     English-language RIA feed): Collector-supplied explicit metadata
#     (Phase 98 contract), not left to incident_normalizer.sh's own
#     JA/EN-presence heuristic.
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
# domain has). The real RIA feed never declares a DOCTYPE/ENTITY
# (confirmed live during design).

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$SCRIPT_DIR"
source security/lib.sh

HOST="www.ria.ee"
PORT="443"
URL="https://$HOST/en/news-feed/all/feed"
LOOKBACK_DAYS="${CERT_EE_LOOKBACK_DAYS:-7}"
MAX_RECORDS="${CERT_EE_MAX_RECORDS:-25}"

if ! egress_check "$HOST" "$PORT" "" "" "CERT_EE_COLLECTOR"; then
  echo "[CERT-EE COLLECTOR] ERROR: egress denied by DLP guard -- request not sent" >&2
  exit 1
fi

TMP_BODY="$(mktemp)"
trap 'rm -f "$TMP_BODY"' EXIT

STATUS="$(curl -s --max-time 20 -o "$TMP_BODY" -w "%{http_code}" "$URL" 2>/dev/null || echo "000")"
if [ "$STATUS" != "200" ]; then
  echo "[CERT-EE COLLECTOR] ERROR: GET $URL failed (HTTP $STATUS)" >&2
  exit 1
fi

python3 -c "
import json, re, sys
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
    print(f'[CERT-EE COLLECTOR] ERROR: could not read response body: {e}', file=sys.stderr)
    sys.exit(1)

if b'<!DOCTYPE' in raw_body or b'<!ENTITY' in raw_body:
    print('[CERT-EE COLLECTOR] ERROR: response contains a DOCTYPE/ENTITY declaration -- refusing to parse (entity-expansion guard; the real RIA feed never declares one)', file=sys.stderr)
    sys.exit(1)

try:
    root = ET.fromstring(raw_body)
except Exception as e:
    print(f'[CERT-EE COLLECTOR] ERROR: response is not valid XML: {e}', file=sys.stderr)
    sys.exit(1)

def local(tag):
    return tag.split('}')[-1] if '}' in tag else tag

def child_text(item, *names):
    wanted = {n.lower() for n in names}
    for child in item:
        if local(child.tag).lower() in wanted and child.text:
            return child.text.strip()
    return ''

# INCIDENT_CUES: the pre-filter gate -- see this file's own header for
# why a GENERAL RIA news feed needs one at all. Deliberately plain
# English substring cues, same 'fixed keyword, no NLP' posture as
# incident_normalizer.sh's own classification tables.
INCIDENT_CUES = [
    'incident', 'breach', 'attack', 'denial-of-service', 'denial of service',
    'ddos', 'disruption', 'leak', 'leaked', 'phishing', 'ransomware',
    'vulnerability', 'cyber', 'malware', 'compromise', 'compromised',
    'hack', 'hacked', 'exploit', 'intrusion',
]

def is_incident_relevant(title, description):
    text = (title + ' ' + description).lower()
    return any(cue in text for cue in INCIDENT_CUES)

def id_from_guid_or_link(guid, link):
    m = re.match(r'^(\d+)\s+at\s+', guid or '')
    if m:
        return m.group(1)
    seg = (link or '').rstrip('/').rsplit('/', 1)[-1]
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
skipped_irrelevant = 0
for item in items:
    title = child_text(item, 'title')
    link = child_text(item, 'link')
    description = child_text(item, 'description')
    guid = child_text(item, 'guid')
    pubdate_raw = child_text(item, 'pubDate', 'pubdate')
    d = parse_pubdate(pubdate_raw)
    if d is None or d < cutoff:
        continue
    if not is_incident_relevant(title, description):
        skipped_irrelevant += 1
        continue
    rid = id_from_guid_or_link(guid, link)
    if not rid or not title:
        continue
    parsed.append((d, rid, title, link, description))

parsed.sort(key=lambda t: t[0], reverse=True)
parsed = parsed[:max_records]

emitted = 0
for d, rid, title, link, description in parsed:
    raw_text_parts = [p for p in (title, description) if p]
    raw_text = ' '.join(raw_text_parts)
    if not raw_text:
        continue

    ts = d.strftime('%Y-%m-%dT%H:%M:%SZ')
    record = {
        'id': f'CERTEE-{rid}',
        'source': 'cert_ee_collector',
        'source_type': 'cert',
        'source_url': link,
        'collected_at': ts,
        'published_at': ts,
        'country': 'EE',
        'region': 'EU',
        'language': 'en',
        'raw_text': raw_text,
    }
    print(json.dumps(record, ensure_ascii=False))
    emitted += 1

print(f'[CERT-EE COLLECTOR] emitted {emitted} record(s) published in the last {lookback_days} day(s) ({skipped_irrelevant} filtered out as not incident-relevant, of {len(items)} total feed items)', file=sys.stderr)
" "$LOOKBACK_DAYS" "$MAX_RECORDS" "$TMP_BODY"
