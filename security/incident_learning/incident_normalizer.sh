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
#   4. advances the candidate to NORMALIZED, attaching the extracted
#      fields, via knowledge_manager.sh advance's own KEY=VALUE
#      mechanism -- never any other status.
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
      "collected_at=$collected_at" "corroborating_sources=$corroborating_sources" >/dev/null
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

  cve_count="$(python3 -c "import json,sys; print(len(json.loads(sys.argv[1])))" "$cve_list")"
  ioc_count="$(python3 -c "import json,sys; print(len(json.loads(sys.argv[1])))" "$ioc_list")"
  av_count="$(python3 -c "import json,sys; print(len(json.loads(sys.argv[1])))" "$attack_vector_list")"
  exposure_count="$(python3 -c "import json,sys; print(len(json.loads(sys.argv[1])))" "$exposure_categories")"
  reason="normalized: $cve_count CVE(s), $ioc_count IOC(s), $av_count attack vector(s), $exposure_count identity-exposure categor(y/ies) extracted"

  km advance "$id" NORMALIZED "$reason" \
    "cve_list=$cve_list" "ioc_list=$ioc_list" \
    "detection_points=$detection_points" "mitigations=$mitigations" \
    "attack_vector_list=$attack_vector_list" "impact_list=$impact_list" "ttp_list=$ttp_list" \
    "exposure_categories=$exposure_categories" "identity_document_types=$identity_document_types" \
    "potential_abuse_paths=$potential_abuse_paths" "defensive_priorities=$defensive_priorities" >/dev/null
  echo "[NORMALIZER] $id: NORMALIZED ($reason)"
done < "$INPUT"
