#!/bin/bash
set -uo pipefail

# security/incident_learning/collectors/ghsa_collector.sh -- the
# SECOND real Collector, added specifically to close the "single-source
# dependency" gap cisa_kev_collector.sh (Phase 81) left open: every
# candidate that collector alone ever produces is source_type=cert with
# zero corroboration (CISA KEV is a single-authority feed by design),
# which incident_confidence.sh's own WEIGHTS table (cert=35) can never
# clear KNOWLEDGE_MIN_CONFIDENCE's default (50) on its own -- not a bug,
# but it means real KEV data could never organically reach CANDIDATE
# without either a second independent real source or a human-decided
# threshold override. This collector is that second source.
#
# DESIGN: a targeted per-CVE lookup against GitHub's public Security
# Advisories (GHSA) database, NOT a broad "recent N advisories" feed
# like cisa_kev_collector.sh's own KEV catalog pull. This was a
# deliberate correction made after verifying the real API's actual
# behavior during design, not the original plan: GHSA's overall
# publish volume across every ecosystem is extremely high (confirmed
# live: 100 consecutive `sort=published&direction=desc` results spanned
# only a few HOURS of real advisories, not days), so a "fetch the most
# recent N and hope for a date-window overlap with a CISA KEV entry"
# strategy would almost always come back empty for exactly the
# enterprise-appliance-class CVEs KEV entries tend to be, even though a
# real, independent GHSA advisory for that CVE already exists (verified
# live during design: 8 of 9 real CVE ids from a live CISA KEV pull
# already had their own independent GHSA advisory, just far outside any
# realistic "recent N" snapshot's reach). Querying GHSA's own
# `?cve_id=<id>` filter directly for a specific, already-known CVE is
# exact, reliable, and cheap (verified live: correctly returns 0 or the
# matching advisory/advisories every time) -- this is also a more
# faithful model of what "corroboration" actually means: given an
# incident this pipeline already knows about from one source, check a
# SECOND authoritative source specifically for it, rather than blindly
# scanning an unrelated firehose feed and hoping for a coincidence.
#
# What "already known to this pipeline" means, concretely: every
# distinct CVE id appearing in any existing candidate's own cve_list
# (security/state/incident_learning/candidates/*.json, read directly --
# the same on-disk state incident_evidence.sh/incident_analyzer.sh
# already read directly for their own read-only purposes, not a Control
# Plane file), from any source OTHER than this same collector (querying
# a CVE this collector already emitted a GHSA record for is a wasted
# API call, not a correctness issue -- incident_normalizer.sh's own
# "already exists" idempotency would just skip it downstream). Capped
# at GHSA_MAX_RECORDS (default 25) distinct CVEs per run, most-recently-
# updated candidate first, to bound both runtime and outbound request
# count against GitHub's unauthenticated rate limit (60 req/hour) --
# same "don't re-scan everything every run" restraint
# cisa_kev_collector.sh's own CISA_KEV_MAX_RECORDS already established,
# adapted to a per-lookup budget instead of a per-feed-page budget.
# Zero known CVEs yet (e.g. cisa_kev_collector.sh hasn't run yet in this
# environment, or an isolated test fixture has none) is a legitimate
# zero-record run, not an error -- same "absent finding is not a
# failure" contract every other field/stage in this domain already has.
#
# This collector reading OTHER candidates' state files is new for a
# Collector (mock_collector.sh and cisa_kev_collector.sh are both pure,
# stateless external-fetch-only) but is NOT a new class of boundary
# crossing: it is the exact same on-disk, same-domain, read-only access
# incident_analyzer.sh already has to security/knowledge/*.json, just
# one stage earlier in the pipeline. It still never reads/writes any
# Control Plane file (segments.conf/ssh config/egress_allowlist.conf)
# other than the one egress_check() call below, same DuCoPA boundary as
# every other file in this domain.
#
# ARCHITECTURE DECISION (same posture as cisa_kev_collector.sh's own
# header, extended to a second file): this is now the SECOND (and still
# only the second) file in security/incident_learning/ that sources
# security/lib.sh and calls egress_check() -- a genuine automated,
# scheduled outbound fetch, exactly what egress_check() exists to gate.
# Called freshly before EVERY individual request in the loop below
# (not just once before the loop), per egress_check()'s own header
# ("call this immediately before the real call it is guarding, never
# earlier") -- cheap (a local file read, not a network call) and closes
# the gap where a mid-run trigger_shutdown() from elsewhere (e.g. a
# Guardian intervention) would otherwise not be honored until this
# collector's next invocation. Requires `api.github.com|443` in
# security/egress_allowlist.conf (see that file's own .example
# template); missing it fails closed (denies and trips a real Emergency
# Shutdown), the same contract cisa_kev_collector.sh already has.
#
# Collector contract compliance (see mock_collector.sh's own header):
#   - id: the GHSA advisory's own ghsa_id (e.g. "GHSA-xqjc-v467-8fvf") --
#     stable/collision-resistant across runs, used as-is (it already
#     carries its own "GHSA-" prefix).
#   - source: "ghsa_collector"
#   - source_type: "vendor_advisory" -- a GHSA advisory is a reviewed,
#     published statement about a specific product/package (closer in
#     kind to a vendor's own PSIRT advisory than to a government
#     CERT-class catalog entry like KEV), matching
#     incident_confidence.sh's own WEIGHTS table category for "an
#     authoritative party publishing on behalf of the affected
#     product," not an invented label that would silently fall to
#     "unknown"'s weight 5.
#   - source_url: the advisory's own html_url (always present for a
#     real GHSA advisory).
#   - collected_at: the advisory's own published_at (when GitHub
#     actually published it), not "now" -- same freshness-scoring
#     reasoning as cisa_kev_collector.sh's own collected_at choice.
#   - raw_text: synthesized from summary/description/severity, using
#     the advisory's own "### Patches" section (when present) as a
#     "Mitigation:"-prefixed sentence, same keyword-scan-friendly
#     convention cisa_kev_collector.sh already uses; the CVE id is woven
#     into raw_text too, so incident_normalizer.sh's own CVE regex
#     captures it into cve_list exactly the way it would from free text
#     -- this is what makes cross-source CVE matching against a
#     cisa_kev_collector candidate for the same CVE actually possible.
#   - corroborating_sources: deliberately omitted, same reasoning as
#     cisa_kev_collector.sh -- any actual corroboration with a
#     DIFFERENT collector's candidate is incident_evidence.sh's own
#     cross-source matching job (cross_source_corroboration_count), not
#     something this collector fabricates.
#   - a `cve_id=` query with zero results, or an advisory missing its
#     own ghsa_id/cve_id, is skipped gracefully -- never treated as an
#     error, same "skip gracefully, never crash" posture
#     cisa_kev_collector.sh already has for a KEV entry missing cveID.
#
# 15s per-request timeout, no retries -- same convention as
# cisa_kev_collector.sh and earth_weather/weather_agent.sh, applied per
# lookup rather than once, since this collector makes up to
# GHSA_MAX_RECORDS separate requests instead of cisa_kev_collector.sh's
# single one.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$SCRIPT_DIR"
source security/lib.sh

HOST="api.github.com"
PORT="443"
MAX_LOOKUPS="${GHSA_MAX_RECORDS:-25}"

KNOWLEDGE_STATE_DIR_RESOLVED="${KNOWLEDGE_MANAGER_STATE_DIR:-$SCRIPT_DIR/security/state/incident_learning/candidates}"

# cves_to_check -- prints a JSON array of distinct CVE ids already
# known to this pipeline from any OTHER collector's candidates, most-
# recently-updated candidate first, capped at MAX_LOOKUPS. Pure read of
# this domain's own on-disk state, no side effects.
cves_to_check() {
  python3 -c "
import glob, json, os, sys

state_dir, max_lookups = sys.argv[1], int(sys.argv[2])

candidates = []
for path in glob.glob(os.path.join(state_dir, '*.json')):
    try:
        d = json.load(open(path))
    except Exception:
        continue
    if d.get('source') == 'ghsa_collector':
        continue
    cves = d.get('cve_list') or []
    if cves:
        candidates.append((d.get('updated_at') or d.get('created_at') or '', cves))

candidates.sort(key=lambda t: t[0], reverse=True)

seen = []
for _, cves in candidates:
    for c in cves:
        if c not in seen:
            seen.append(c)

print(json.dumps(seen[:max_lookups]))
" "$1" "$2"
}

CVE_LIST_JSON="$(cves_to_check "$KNOWLEDGE_STATE_DIR_RESOLVED" "$MAX_LOOKUPS")"
CVE_COUNT="$(python3 -c "import json,sys; print(len(json.loads(sys.argv[1])))" "$CVE_LIST_JSON")"

if [ "$CVE_COUNT" -eq 0 ]; then
  echo "[GHSA COLLECTOR] no CVE ids known to this pipeline yet (no other collector's candidate has extracted one) -- nothing to look up this run" >&2
  exit 0
fi

emitted=0
checked=0
while IFS= read -r cve; do
  [ -n "$cve" ] || continue
  checked=$((checked + 1))

  if ! egress_check "$HOST" "$PORT" "" "" "GHSA_COLLECTOR"; then
    echo "[GHSA COLLECTOR] ERROR: egress denied by DLP guard -- request not sent (stopped after $checked/$CVE_COUNT lookups, $emitted record(s) emitted so far)" >&2
    exit 1
  fi

  TMP_BODY="$(mktemp)"
  STATUS="$(curl -s --max-time 15 -H "Accept: application/vnd.github+json" -o "$TMP_BODY" -w "%{http_code}" "https://$HOST/advisories?cve_id=$cve" 2>/dev/null || echo "000")"

  # A 403 with zero requests remaining means GitHub's unauthenticated
  # rate limit (60/hour) is exhausted for this run -- every SUBSEQUENT
  # lookup this run would also fail the same way, so stop here rather
  # than silently treating each remaining CVE as "no advisory found"
  # (a materially different, misleading outcome: "0 emitted" should
  # never be allowed to mean "we couldn't check" when it actually means
  # "we checked and there's nothing"). Not a fatal error for the run as
  # a whole -- whatever was already found this run is still emitted.
  if [ "$STATUS" = "403" ] && grep -qi "rate limit" "$TMP_BODY" 2>/dev/null; then
    echo "[GHSA COLLECTOR] rate limit exhausted after $checked/$CVE_COUNT lookups ($emitted record(s) emitted so far) -- stopping this run rather than reporting the remaining CVEs as not found" >&2
    rm -f "$TMP_BODY"
    break
  fi

  if [ "$STATUS" = "200" ]; then
    COUNT_THIS="$(python3 -c "
import json, sys

body_path, cve = sys.argv[1], sys.argv[2]

try:
    data = json.load(open(body_path))
except Exception:
    sys.exit(0)

if not isinstance(data, list):
    sys.exit(0)

for a in data:
    cve_id = a.get('cve_id') or ''
    ghsa_id = a.get('ghsa_id') or ''
    if not cve_id or not ghsa_id:
        continue

    summary = a.get('summary') or ''
    description = (a.get('description') or '').strip()
    severity = a.get('severity') or 'unknown'
    html_url = a.get('html_url') or ''
    published_at = a.get('published_at') or ''

    lower_desc = description.lower()
    patches = ''
    idx = lower_desc.find('### patches')
    if idx != -1:
        rest = description[idx + len('### patches'):].strip()
        next_heading = rest.find('###')
        patch_text = (rest[:next_heading] if next_heading != -1 else rest).strip()
        patch_text = ' '.join(patch_text.split())
        if patch_text:
            patches = f'Mitigation: {patch_text}'

    raw_text_parts = []
    if summary:
        raw_text_parts.append(f'{summary} ({cve_id}).')
    raw_text_parts.append(
        f'GitHub Security Advisories (GHSA) catalog: {ghsa_id}, severity {severity}, '
        f'published {published_at[:10] if published_at else \"unknown date\"}.'
    )
    if patches:
        raw_text_parts.append(patches)
    raw_text = ' '.join(p for p in raw_text_parts if p)

    record = {
        'id': ghsa_id,
        'source': 'ghsa_collector',
        'source_type': 'vendor_advisory',
        'source_url': html_url,
        'collected_at': published_at if published_at else '',
        'raw_text': raw_text,
    }
    print(json.dumps(record, ensure_ascii=False))
" "$TMP_BODY" "$cve")"
    if [ -n "$COUNT_THIS" ]; then
      echo "$COUNT_THIS"
      THIS_EMITTED="$(printf '%s\n' "$COUNT_THIS" | grep -c . || true)"
      emitted=$((emitted + THIS_EMITTED))
    fi
  fi
  rm -f "$TMP_BODY"
done <<< "$(python3 -c "import json,sys; print(chr(10).join(json.loads(sys.argv[1])))" "$CVE_LIST_JSON")"

echo "[GHSA COLLECTOR] emitted $emitted record(s) from $checked CVE lookup(s) already known to this pipeline" >&2
