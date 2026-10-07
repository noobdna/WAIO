#!/bin/bash
set -uo pipefail

# security/incident_learning/incident_normalizer.sh -- Incident
# Learning Engine, Step 2: COLLECTED -> NORMALIZED.
#
# Reads RawIncident JSONL (a Collector's own stdout -- see
# collectors/mock_collector.sh's header for the shape contract) from
# stdin or a file argument. For each record:
#   1. creates a Knowledge Candidate via knowledge_manager.sh if this
#      id hasn't been seen before (idempotent: re-feeding the same
#      RawIncident is a no-op for an id that already exists, never a
#      duplicate/overwritten candidate)
#   2. only acts on candidates currently at COLLECTED -- anything
#      already further along the pipeline is left untouched (skipped,
#      logged), never re-normalized
#   3. extracts a small, deliberately simple set of structured fields
#      via pattern matching -- CVE ids, IPv4-shaped strings as
#      candidate IOCs, a fixed detection-point/mitigation keyword scan,
#      and (added alongside cross-source corroboration) a fixed
#      attack-vector/impact keyword scan plus a MITRE ATT&CK technique
#      id regex -- NOT real NLP, same posture as every other field here.
#      This is intentionally conservative: a later step
#      (incident_evidence.sh) is what actually establishes trust in any
#      of this, so over-engineering extraction here would be effort
#      spent before the safety-relevant part of the pipeline even runs.
#      attack_vector_list/impact_list/ttp_list are always present
#      (possibly empty) on every NORMALIZED candidate, same "absent
#      finding is not a failure" contract cve_list/ioc_list already
#      have -- most real-world raw_text (e.g. a CISA KEV entry) never
#      contains a literal ATT&CK technique id, so an empty ttp_list is
#      the expected common case, not a bug.
#      Phase 98 (Global Incident Intelligence & Auto-Learning) adds a
#      second, bilingual (English/Japanese) classification layer on
#      top of the same posture: incident_type/affected_sector (single
#      primary category each)/claimed_impact (verbatim claim
#      sentences, never treated as fact)/attack_pattern (a
#      deterministic correlation key consumed by the new
#      incident_correlator.sh, Step "Correlate") -- see extract_fields'
#      own INCIDENT_TYPE_KEYWORDS/AFFECTED_SECTOR_KEYWORDS/
#      CLAIMED_IMPACT_CUES tables below for the exact cues. This phase
#      also threads four new OPTIONAL Collector-supplied metadata
#      fields (published_at/country/region/language) straight onto the
#      candidate at creation time, same "Collector reports what it saw/
#      where, this file never infers it" posture as source_type/
#      source_url -- with one narrow exception: language falls back to
#      a cheap Hiragana/Katakana-presence heuristic when a Collector
#      doesn't supply it, since most Collectors won't know their own
#      source's language in advance.
#   4. advances the candidate to NORMALIZED, attaching the extracted
#      fields, via knowledge_manager.sh advance's own KEY=VALUE
#      mechanism -- never any other status. incident_type/
#      affected_sector/claimed_impact/attack_pattern are reserved
#      fields (Phase 98 hardening) and go through the separate
#      `classify` verb instead, right after the advance call -- see
#      that verb's own header for why.
#
# This file never reads/writes any Control Plane file (same DuCoPA
# boundary as knowledge_manager.sh itself) and makes no network call.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$SCRIPT_DIR"
KM_SCRIPT="security/incident_learning/knowledge_manager.sh"
km() { bash "$KM_SCRIPT" "$@"; }

INPUT="${1:-/dev/stdin}"

# extract_fields RAW_TEXT -- prints one JSON object with cve_list,
# ioc_list, detection_points, mitigations -- all arrays, all possibly
# empty. Pure function of the input text, no side effects.
extract_fields() {
  python3 -c "
import json, re, sys

raw = sys.argv[1]
raw_lower = raw.lower()

cves = sorted(set(re.findall(r'CVE-\d{4}-\d{4,7}', raw)))
iocs = sorted(set(re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', raw)))

detection_points = []
for sentence in re.split(r'(?<=[.])\s+', raw):
    if sentence.strip().lower().startswith('detection point'):
        detection_points.append(sentence.strip())

mitigations = []
for sentence in re.split(r'(?<=[.])\s+', raw):
    s = sentence.strip()
    if s.lower().startswith('mitigation') or s.lower().startswith('recommended mitigation'):
        mitigations.append(s)

# Attack Vector: a small, fixed keyword -> category table (first match
# per category wins, a raw_text can match several categories). Ordered
# so a more specific phrase is checked before a more generic one that
# would otherwise also match (e.g. 'command injection' before a bare
# 'injection').
ATTACK_VECTOR_KEYWORDS = [
    ('remote_code_execution', ['remote code execution', 'arbitrary code execution']),
    ('command_injection', ['command injection', 'execute arbitrary commands']),
    ('sql_injection', ['sql injection']),
    ('cross_site_scripting', ['cross-site scripting', ' xss ']),
    ('path_traversal', ['path traversal']),
    ('remote_file_inclusion', ['remote file inclusion']),
    ('arbitrary_file_upload', ['unrestricted file upload', 'arbitrary file upload']),
    ('authentication_bypass', ['authentication bypass', 'unauthenticated']),
    ('privilege_escalation', ['privilege escalation', 'elevated access', 'elevated privileges']),
    ('memory_corruption', ['buffer overflow', 'out-of-bounds write', 'out-of-bounds read', 'use-after-free']),
    ('improper_input_validation', ['improper input validation', 'improper encoding', 'hex encoding']),
    ('denial_of_service', ['denial of service']),
]
attack_vector_list = sorted({
    label for label, phrases in ATTACK_VECTOR_KEYWORDS if any(p in raw_lower for p in phrases)
})

# Impact: same fixed-keyword approach, a separate table from Attack
# Vector on purpose -- 'how the attacker got in' and 'what actually
# happens as a result' are different questions, so 'remote code
# execution' correctly contributes to BOTH (attack_vector AND impact),
# not a shared/merged list.
IMPACT_KEYWORDS = [
    ('code_execution', ['remote code execution', 'arbitrary code execution', 'execute arbitrary commands']),
    ('availability_loss', ['denial of service']),
    ('unauthorized_access', ['elevated access', 'elevated privileges', 'privileges of the admin user', 'gain access']),
    ('data_exposure', ['sensitive resources', 'data exposure', 'exfiltrat', 'disclose']),
]
impact_list = sorted({
    label for label, phrases in IMPACT_KEYWORDS if any(p in raw_lower for p in phrases)
})

# TTP: MITRE ATT&CK technique ids (e.g. T1190, T1059.001), if the
# source text happens to cite one directly. Deliberately just a regex,
# same 'report what's literally there, never infer' posture as cve_list
# -- this pipeline does not attempt to MAP attack-vector keywords to an
# ATT&CK id itself (that mapping is not 1:1 or reliable enough to do
# via keyword matching without risking a wrong/fabricated technique id).
ttp_list = sorted(set(re.findall(r'\bT\d{4}(?:\.\d{3})?\b', raw)))

# Identity Exposure classification (added alongside this phase's own
# milestone): a fixed-keyword classification LAYER, same posture as
# Attack Vector/Impact above -- it reports which abstract categories of
# exposed-identity-data a public incident DESCRIBES, never the actual
# PII/document/financial values themselves. raw_text is CISA
# KEV/GHSA/vendor-advisory/news prose describing a public incident, not
# a real victim's data; this classifier only ever sees and stores
# category labels (e.g. 'identity_document', 'drivers_license') derived
# from that prose, never a real name/number/photo. A raw_text with none
# of these phrases (the overwhelming majority of KEV/GHSA entries, which
# describe a vulnerability, not a data breach) classifies to all-empty
# lists, same 'absent finding is not a failure' contract as cve_list.
#
# IDENTITY_DOCUMENT_KEYWORDS: phrases naming a specific identity
# document TYPE exposed/compromised in an incident (driver license,
# passport) or, failing a specific type, some other government-issued
# identity document -- including the images/scans collected for
# identity-verification (KYC) flows, since a breach of those photos
# carries the same downstream impersonation risk as the physical
# document itself.
IDENTITY_DOCUMENT_KEYWORDS = [
    ('drivers_license', ['driver\'s license', 'drivers license', 'driver license', 'driving licence', 'driving license']),
    ('passport', ['passport']),
    ('other_identity_document', [
        'national id card', 'identity card', 'id card', 'government-issued id',
        'government-issued identification', 'national identity number', 'social security card',
        'identification document', 'id document', 'verification photo', 'selfie photo',
        'kyc document', 'proof of identity',
    ]),
]
identity_document_types = sorted({
    label for label, phrases in IDENTITY_DOCUMENT_KEYWORDS if any(p in raw_lower for p in phrases)
})

# PII_KEYWORDS: phrases describing exposed personal-identifying data
# (name/address/date of birth/phone/email), scoped to breach-disclosure
# phrasing (e.g. 'email addresses', 'dates of birth') rather than a bare
# word like 'name' or 'email' alone -- a bare word is far too common in
# ordinary vulnerability prose (product names, an email-based attack
# vector) to use as a reliable signal without flooding this category
# with false positives; these subtypes decide only whether 'pii' is
# added to exposure_categories below, they are not a separate output
# field (same minimal-schema posture as the rest of this phase).
PII_KEYWORDS = [
    ('name', ['full names', 'full name and', 'names and addresses', 'customers\' names', 'customer names']),
    ('address', ['home address', 'home addresses', 'mailing address', 'residential address', 'postal address']),
    ('date_of_birth', ['date of birth', 'dates of birth', 'birth date', 'birth dates']),
    ('phone', ['phone number', 'phone numbers', 'telephone number', 'telephone numbers']),
    ('email', ['email address', 'email addresses']),
]
pii_types = sorted({
    label for label, phrases in PII_KEYWORDS if any(p in raw_lower for p in phrases)
})

# FINANCIAL_DATA_KEYWORDS: payment/financial data exposed in an
# incident -- deliberately narrow (card/payment phrasing only, never a
# bare 'payment' or 'financial'), same false-positive discipline as PII
# above.
FINANCIAL_DATA_KEYWORDS = [
    ('payment_information', [
        'credit card number', 'credit card numbers', 'debit card number', 'debit card numbers',
        'payment card', 'cardholder data', 'payment information', 'card verification value',
    ]),
]
financial_data_types = sorted({
    label for label, phrases in FINANCIAL_DATA_KEYWORDS if any(p in raw_lower for p in phrases)
})

exposure_categories = []
if identity_document_types:
    exposure_categories.append('identity_document')
if pii_types:
    exposure_categories.append('pii')
if financial_data_types:
    exposure_categories.append('financial_data')
exposure_categories = sorted(exposure_categories)

# ABUSE_PATH / DEFENSIVE_PRIORITY: the ABUSE_PATH taxonomy
# (IDENTITY_EXPOSURE -> identity_impersonation -> {account_takeover,
# fraudulent_verification, social_engineering} -> {financial_fraud,
# unauthorized_service_use}) kept DELIBERATELY as abstract, defensive-
# purpose TTP labels, never a concrete attack recipe -- same posture as
# attack_vector_list/impact_list above, applied to this new domain. Each
# exposure category contributes a fixed set of downstream abuse paths
# and defensive priorities it specifically motivates; a raw_text with no
# identity-exposure category present contributes nothing (both lists
# empty), so this never fires on an ordinary CVE/vulnerability record.
ABUSE_PATH_BY_CATEGORY = {
    'identity_document': ['identity_impersonation', 'fraudulent_verification'],
    'pii': ['identity_impersonation', 'account_takeover', 'social_engineering'],
    'financial_data': ['financial_fraud', 'unauthorized_service_use'],
}
potential_abuse_paths = sorted({
    path for cat in exposure_categories for path in ABUSE_PATH_BY_CATEGORY.get(cat, [])
})

DEFENSIVE_PRIORITY_BY_CATEGORY = {
    'identity_document': ['identity_verification_review'],
    'pii': ['credential_reset', 'phishing_detection'],
    'financial_data': ['fraud_monitoring'],
}
defensive_priorities = sorted({
    p for cat in exposure_categories for p in DEFENSIVE_PRIORITY_BY_CATEGORY.get(cat, [])
})

# INCIDENT_TYPE / AFFECTED_SECTOR / CLAIMED_IMPACT / ATTACK_PATTERN:
# Phase 98 addition (Global Incident Intelligence & Auto-Learning --
# generalizes this pipeline, previously CVE/vulnerability-feed-shaped
# only, to also classify a company/public-breach-style incident
# report, JP or overseas, WITHOUT hardcoding any real company/
# organization name anywhere in this file). Same fixed-keyword,
# first-match-in-priority-order, 'report what is literally cued in the
# text, never infer beyond it' posture as every other classifier
# above, extended to bilingual (English/Japanese) cues since a real JP
# news report is the primary new input shape this phase targets.
#
# incident_type: a SINGLE primary category (unlike attack_vector_list,
# which can hold several) -- ordered most-specific-first so e.g. a
# ransomware note naming a CVE still classifies as ransomware, not
# vulnerability_disclosure. 'vulnerability_disclosure' falls back to
# 'a CVE id is present in this raw_text' (reusing the cves list already
# computed above) when no more specific phrase matched -- this is what
# keeps every existing CISA KEV/GHSA candidate classifying exactly the
# way it always has (cve_list non-empty, no breach-style phrasing) once
# this phase ships. 'unclassified' is the expected common case for a
# raw_text with none of these cues, same 'absent finding is not a
# failure' contract as cve_list/ioc_list/exposure_categories above.
INCIDENT_TYPE_KEYWORDS = [
    ('ransomware', ['ransomware', 'ランサムウェア']),
    ('phishing', ['phishing', 'フィッシング', 'phishing campaign']),
    ('account_takeover', [
        'account takeover', 'credential stuffing', 'unauthorized login',
        'アカウント乗っ取り', '不正ログイン', 'なりすましログイン', 'クレデンシャルスタッフィング',
    ]),
    ('data_breach', [
        'data breach', 'data leak', 'information leak', 'exposed database', 'leaked database',
        'member information', 'customer information', 'personal information of',
        '情報漏洩', '情報漏えい', '会員情報', '顧客情報', '個人情報', '流出',
    ]),
    ('ddos', ['denial of service', 'ddos', 'ddos攻撃']),
]
incident_type = next(
    (label for label, phrases in INCIDENT_TYPE_KEYWORDS if any(p in raw_lower for p in phrases)),
    None,
)
if incident_type is None:
    incident_type = 'vulnerability_disclosure' if cves else 'unclassified'

# affected_sector: same single-primary-category, ordered-priority
# approach, deliberately bilingual and company-name-agnostic -- these
# are GENERIC industry cues, never a specific organization's name, so
# the exact same keyword table applies equally to a JP carsharing
# incident, a JP restaurant-chain incident, or an overseas retailer
# incident without any per-incident special-casing.
AFFECTED_SECTOR_KEYWORDS = [
    ('automotive_carsharing', [
        'car sharing', 'carsharing', 'car-sharing', 'car rental', 'ride sharing', 'ride-share',
        'カーシェア', 'カーシェアリング', 'レンタカー',
    ]),
    ('food_service', [
        'restaurant chain', 'restaurant', 'dining chain', 'food chain',
        '焼肉', '飲食店', 'レストラン', '居酒屋',
    ]),
    ('retail_ecommerce', [
        'e-commerce', 'ecommerce', 'online retailer', 'online store', 'retailer', 'retail chain',
        'membership program', 'loyalty program',
        'ポイントプログラム', '会員制サイト', 'ネット通販', '通販サイト', 'オンラインストア',
    ]),
    ('finance', [
        'bank', 'banking', 'payment processor', 'credit card issuer',
        '銀行', '決済事業者', 'クレジットカード会社', 'フィンテック',
    ]),
    ('healthcare', ['hospital', 'clinic', 'healthcare provider', '病院', '医療機関', 'クリニック']),
    ('government', [
        'government agency', 'municipal government', 'ministry',
        '自治体', '省庁', '官公庁',
    ]),
    ('telecom', ['telecom operator', 'mobile carrier', 'isp', '通信事業者', '携帯キャリア']),
    ('technology', ['software vendor', 'cloud provider', 'saas provider', 'クラウドサービス']),
]
affected_sector = next(
    (label for label, phrases in AFFECTED_SECTOR_KEYWORDS if any(p in raw_lower for p in phrases)),
    'unknown',
)

# claimed_impact: sentence-level extraction, same re.split sentence
# approach detection_points/mitigations already use above, but
# CONTAINS-matched (not startswith) since real news prose never opens
# a sentence with a fixed marker word the way this pipeline's own
# synthetic Collector text does for Mitigation/Detection Point. The
# field name itself -- CLAIMED impact, never just 'impact' -- is the
# point: this is verbatim text attributing a scale/scope claim to the
# SOURCE, stored for a human to weigh, never treated by any code in
# this pipeline as a confirmed fact (a report is not a fact).  Capped
# at 5 sentences to keep the field bounded.
CLAIMED_IMPACT_CUES = [
    'were affected', 'were exposed', 'were compromised', 'were leaked', 'were stolen',
    'customer records', 'personal information of', 'data of approximately', 'affected customers',
    'affected users', 'number of affected',
    '会員情報', '顧客情報', '個人情報', '情報が流出', '情報を不正', '不正に販売', '不正に取得',
    '流出した', '漏えいした', '漏洩した', '被害に遭った', '不正アクセスを受け', '疑いがある',
]
claimed_impact = []
for sentence in re.split(r'(?<=[.。])\s*', raw):
    s = sentence.strip()
    if not s:
        continue
    s_lower = s.lower()
    if any(cue in s_lower or cue in s for cue in CLAIMED_IMPACT_CUES):
        claimed_impact.append(s)
    if len(claimed_impact) >= 5:
        break

# attack_pattern: a single deterministic string combining incident_type
# with this candidate's own attack_vector_list (falling back to
# ttp_list when attack_vector_list is empty) -- used purely as a
# CORRELATION KEY by incident_correlator.sh (Phase 98) to find other
# candidates/knowledge entries describing the same kind of attack
# across different sources/companies/countries. 'unclassified' alone
# (incident_type unclassified AND no attack_vector_list/ttp_list) is a
# deliberate sentinel meaning 'nothing specific enough to correlate
# on' -- incident_correlator.sh skips this value rather than treating
# every uncategorized incident as related to every other one.
if attack_vector_list:
    attack_pattern = incident_type + ':' + '+'.join(attack_vector_list)
elif ttp_list:
    attack_pattern = incident_type + ':' + '+'.join(ttp_list)
else:
    attack_pattern = incident_type

print(json.dumps({
    'cve_list': cves,
    'ioc_list': iocs,
    'detection_points': detection_points,
    'mitigations': mitigations,
    'attack_vector_list': attack_vector_list,
    'impact_list': impact_list,
    'ttp_list': ttp_list,
    'exposure_categories': exposure_categories,
    'identity_document_types': identity_document_types,
    'potential_abuse_paths': potential_abuse_paths,
    'defensive_priorities': defensive_priorities,
    'incident_type': incident_type,
    'affected_sector': affected_sector,
    'claimed_impact': claimed_impact,
    'attack_pattern': attack_pattern,
}))
" "$1"
}

while IFS= read -r line; do
  [ -n "$line" ] || continue

  id="$(python3 -c "import json,sys; print(json.loads(sys.argv[1])['id'])" "$line")"
  source_name="$(python3 -c "import json,sys; print(json.loads(sys.argv[1])['source'])" "$line")"
  source_type="$(python3 -c "import json,sys; print(json.loads(sys.argv[1]).get('source_type','unknown'))" "$line")"
  source_url="$(python3 -c "import json,sys; print(json.loads(sys.argv[1]).get('source_url',''))" "$line")"
  raw_text="$(python3 -c "import json,sys; print(json.loads(sys.argv[1]).get('raw_text',''))" "$line")"
  collected_at="$(python3 -c "import json,sys; print(json.loads(sys.argv[1]).get('collected_at',''))" "$line")"
  corroborating_sources="$(python3 -c "import json,sys; print(json.dumps(json.loads(sys.argv[1]).get('corroborating_sources', [])))" "$line")"

  # Phase 98 addition: published_at/country/region/language are all
  # OPTIONAL Collector-supplied metadata (same "Collector reports what
  # it saw/where, this file never infers geography/publish-time from
  # free text" posture as source_type/source_url above) -- absent on
  # every existing real Collector (cisa_kev_collector.sh/
  # ghsa_collector.sh/mock_collector.sh), which is why every one of
  # them defaults cleanly to 'unknown' (or, for published_at, to an
  # empty string meaning "same as collected_at") rather than breaking.
  # language is the one exception with a computed fallback: a cheap,
  # deterministic, auditable heuristic (Hiragana/Katakana presence),
  # never a full language-detection model -- same "simple, auditable,
  # no NLP" discipline as the rest of this file's own extraction.
  published_at="$(python3 -c "import json,sys; print(json.loads(sys.argv[1]).get('published_at',''))" "$line")"
  country="$(python3 -c "import json,sys; print(json.loads(sys.argv[1]).get('country','unknown'))" "$line")"
  region="$(python3 -c "import json,sys; print(json.loads(sys.argv[1]).get('region','unknown'))" "$line")"
  language="$(python3 -c "import json,sys; print(json.loads(sys.argv[1]).get('language',''))" "$line")"
  if [ -z "$language" ]; then
    language="$(python3 -c "
import re, sys
raw = sys.argv[1]
print('ja' if re.search(r'[぀-ヿ]', raw) else 'en')
" "$raw_text")"
  fi

  if ! km status "$id" >/dev/null 2>&1; then
    # Each of these values (source_type, a URL, a free-text sentence)
    # is passed as-is: none of them are valid JSON syntax on their own,
    # so _km_parse_extras' own try/json.loads-else-string fallback
    # stores them as plain strings automatically -- no manual
    # JSON-quoting needed (and manually wrapping in literal quotes here
    # would break the moment raw_text itself ever contains a `"`).
    # collected_at/corroborating_sources are threaded through here too
    # (rather than left to default on the candidate's own created_at /
    # an absent field) so incident_evidence.sh's age/corroboration
    # computations reflect what the Collector actually reported, not
    # "now" and "none".
    km create "$id" "$source_name" "source_type=$source_type" "source_url=$source_url" "raw_text=$raw_text" \
      "collected_at=$collected_at" "corroborating_sources=$corroborating_sources" \
      "published_at=$published_at" "country=$country" "region=$region" "language=$language" >/dev/null
    echo "[NORMALIZER] $id: new candidate created (COLLECTED)"
  fi

  current="$(km status "$id" 2>/dev/null)"
  if [ "$current" != "COLLECTED" ]; then
    echo "[NORMALIZER] $id: skipping (status=$current, not COLLECTED)"
    continue
  fi

  fields_json="$(extract_fields "$raw_text")"
  cve_list="$(python3 -c "import json,sys; print(json.dumps(json.loads(sys.argv[1])['cve_list']))" "$fields_json")"
  ioc_list="$(python3 -c "import json,sys; print(json.dumps(json.loads(sys.argv[1])['ioc_list']))" "$fields_json")"
  detection_points="$(python3 -c "import json,sys; print(json.dumps(json.loads(sys.argv[1])['detection_points']))" "$fields_json")"
  mitigations="$(python3 -c "import json,sys; print(json.dumps(json.loads(sys.argv[1])['mitigations']))" "$fields_json")"
  attack_vector_list="$(python3 -c "import json,sys; print(json.dumps(json.loads(sys.argv[1])['attack_vector_list']))" "$fields_json")"
  impact_list="$(python3 -c "import json,sys; print(json.dumps(json.loads(sys.argv[1])['impact_list']))" "$fields_json")"
  ttp_list="$(python3 -c "import json,sys; print(json.dumps(json.loads(sys.argv[1])['ttp_list']))" "$fields_json")"
  exposure_categories="$(python3 -c "import json,sys; print(json.dumps(json.loads(sys.argv[1])['exposure_categories']))" "$fields_json")"
  identity_document_types="$(python3 -c "import json,sys; print(json.dumps(json.loads(sys.argv[1])['identity_document_types']))" "$fields_json")"
  potential_abuse_paths="$(python3 -c "import json,sys; print(json.dumps(json.loads(sys.argv[1])['potential_abuse_paths']))" "$fields_json")"
  defensive_priorities="$(python3 -c "import json,sys; print(json.dumps(json.loads(sys.argv[1])['defensive_priorities']))" "$fields_json")"
  incident_type="$(python3 -c "import json,sys; print(json.loads(sys.argv[1])['incident_type'])" "$fields_json")"
  affected_sector="$(python3 -c "import json,sys; print(json.loads(sys.argv[1])['affected_sector'])" "$fields_json")"
  claimed_impact="$(python3 -c "import json,sys; print(json.dumps(json.loads(sys.argv[1])['claimed_impact']))" "$fields_json")"
  attack_pattern="$(python3 -c "import json,sys; print(json.loads(sys.argv[1])['attack_pattern'])" "$fields_json")"

  cve_count="$(python3 -c "import json,sys; print(len(json.loads(sys.argv[1])))" "$cve_list")"
  ioc_count="$(python3 -c "import json,sys; print(len(json.loads(sys.argv[1])))" "$ioc_list")"
  av_count="$(python3 -c "import json,sys; print(len(json.loads(sys.argv[1])))" "$attack_vector_list")"
  exposure_count="$(python3 -c "import json,sys; print(len(json.loads(sys.argv[1])))" "$exposure_categories")"
  reason="normalized: $cve_count CVE(s), $ioc_count IOC(s), $av_count attack vector(s), $exposure_count identity-exposure categor(y/ies) extracted; incident_type=$incident_type, affected_sector=$affected_sector, attack_pattern=$attack_pattern"

  km advance "$id" NORMALIZED "$reason" \
    "cve_list=$cve_list" "ioc_list=$ioc_list" \
    "detection_points=$detection_points" "mitigations=$mitigations" \
    "attack_vector_list=$attack_vector_list" "impact_list=$impact_list" "ttp_list=$ttp_list" \
    "exposure_categories=$exposure_categories" "identity_document_types=$identity_document_types" \
    "potential_abuse_paths=$potential_abuse_paths" "defensive_priorities=$defensive_priorities" >/dev/null
  # incident_type/affected_sector/claimed_impact/attack_pattern are
  # reserved fields (knowledge_manager.sh's own
  # _km_reserved_field_violation) and cannot be set via advance's
  # extras above -- they go through the dedicated `classify` verb
  # instead, the same separation record-evidence/evidence_* and
  # annotate/related_incidents already established, so no Collector or
  # other pipeline stage can forge a classification via a plain
  # create/advance extra.
  km classify "$id" "$reason" \
    "incident_type=$incident_type" "affected_sector=$affected_sector" \
    "claimed_impact=$claimed_impact" "attack_pattern=$attack_pattern" >/dev/null
  echo "[NORMALIZER] $id: NORMALIZED ($reason)"
done < "$INPUT"
