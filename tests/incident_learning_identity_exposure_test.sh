#!/bin/bash
set -uo pipefail

# tests/incident_learning_identity_exposure_test.sh -- regression suite
# for the Identity Exposure / Abuse Path classification layer added to
# Incident Learning Engine Step 2 (security/incident_learning/
# incident_normalizer.sh's extract_fields()).
#
# Scope: this classifier reports which ABSTRACT categories of exposed
# identity-related data a PUBLIC incident report DESCRIBES (identity
# document / pii / financial_data), plus the defensive-purpose abuse
# paths and priorities those categories motivate -- it never collects,
# stores, or processes any real identity document, PII, photo, or
# payment data. Every fixture below is entirely fictional narrative
# text (no real person, no real document, no real card number) that
# merely DESCRIBES a hypothetical breach disclosure, same posture as
# mock_collector.sh's own fabricated CVE/IOC samples.
#
# Runs against scratch fixtures under a temp dir via
# KNOWLEDGE_MANAGER_STATE_DIR/KNOWLEDGE_MANAGER_AUDIT_LOG/
# KNOWLEDGE_MANAGER_KNOWLEDGE_DIR overrides (same convention as every
# other Incident Learning suite) -- never touches this deployment's
# real security/state/incident_learning/, logs/incident-learning-
# audit.jsonl, or security/knowledge/, and makes no network call.
#
# This suite deliberately stops at CANDIDATE (Step 1-3 of the pipeline:
# NORMALIZED -> VERIFIED -> ANALYZED -> SCORED -> CANDIDATE) -- it never
# calls approve/reject/hold/release/promote (the Human Gate / Step 4-5),
# matching this milestone's own scope: an E2E dry-run up to Knowledge
# Candidate generation, never production promotion.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"

PASS=0
FAIL=0
declare -a FAILURES=()

assert_eq() {
  local label="$1" expected="$2" actual="$3"
  if [ "$expected" = "$actual" ]; then
    PASS=$((PASS + 1)); echo "  PASS: $label"
  else
    FAIL=$((FAIL + 1)); FAILURES+=("$label (expected='$expected' actual='$actual')")
    echo "  FAIL: $label (expected='$expected' actual='$actual')"
  fi
}

assert_contains() {
  local label="$1" haystack="$2" needle="$3"
  if [[ "$haystack" == *"$needle"* ]]; then
    PASS=$((PASS + 1)); echo "  PASS: $label"
  else
    FAIL=$((FAIL + 1)); FAILURES+=("$label (expected to contain '$needle')")
    echo "  FAIL: $label (expected to contain '$needle', got: $haystack)"
  fi
}

FIXTURE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/waio-incident-identity-exposure-test.XXXXXX")"
trap 'rm -rf "$FIXTURE_DIR"; true' EXIT

mkdir -p "$FIXTURE_DIR/candidates" "$FIXTURE_DIR/knowledge"
export KNOWLEDGE_MANAGER_STATE_DIR="$FIXTURE_DIR/candidates"
export KNOWLEDGE_MANAGER_AUDIT_LOG="$FIXTURE_DIR/incident-learning-audit.jsonl"
export KNOWLEDGE_MANAGER_KNOWLEDGE_DIR="$FIXTURE_DIR/knowledge"

km() { bash security/incident_learning/knowledge_manager.sh "$@"; }
normalize() { bash security/incident_learning/incident_normalizer.sh; }
evidence() { bash security/incident_learning/incident_evidence.sh "$1"; }
analyze() { bash security/incident_learning/incident_analyzer.sh "$1"; }
confidence() { bash security/incident_learning/incident_confidence.sh "$1"; }
field_json() { python3 -c "import json; print(json.dumps(json.load(open('$FIXTURE_DIR/candidates/$1.json')).get('$2', None)))"; }

feed() {
  # feed ID SOURCE_TYPE RAW_TEXT [CORROBORATING_SOURCES_JSON] -- emits
  # one Collector-contract JSONL record (fictional source_url,
  # collected_at = now, so incident_evidence.sh's staleness penalty
  # never fires on these fixtures) through the normalizer, same shape
  # mock_collector.sh's own records use.
  local id="$1" source_type="$2" raw_text="$3" corrob="${4:-[]}"
  local now
  now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  python3 -c "
import json, sys
d = {
    'id': sys.argv[1],
    'source': 'identity_exposure_fixture',
    'source_type': sys.argv[2],
    'source_url': 'https://example.invalid/breach-notice/' + sys.argv[1],
    'collected_at': sys.argv[3],
    'raw_text': sys.argv[4],
    'corroborating_sources': json.loads(sys.argv[5]),
}
print(json.dumps(d, ensure_ascii=False))
" "$id" "$source_type" "$now" "$raw_text" "$corrob" | normalize >/dev/null
}

echo "=== Incident Learning Engine (Identity Exposure classification layer) regression suite ==="

echo ""
echo "[IE1] fixture: PII only -- names/addresses/DOB/phone/email, no identity document, no payment data"
echo "      (carries one corroborating source so the later Evidence/Confidence E2E check in [C1] actually clears the threshold -- see that section's own header)"
feed "IE-PII-ONLY" "vendor_advisory" \
"A breach at ExampleCorp exposed customer full names, home addresses, dates of birth, phone numbers, and email addresses for approximately 1.2 million users. No financial account numbers or official identification records were involved." \
'["https://example.invalid/cert-advisory/pii-only"]'
assert_eq "IE1 status NORMALIZED" "NORMALIZED" "$(km status IE-PII-ONLY)"
assert_eq "IE1 exposure_categories" '["pii"]' "$(field_json IE-PII-ONLY exposure_categories)"
assert_eq "IE1 identity_document_types empty" "[]" "$(field_json IE-PII-ONLY identity_document_types)"
assert_eq "IE1 potential_abuse_paths" '["account_takeover", "identity_impersonation", "social_engineering"]' "$(field_json IE-PII-ONLY potential_abuse_paths)"
assert_eq "IE1 defensive_priorities" '["credential_reset", "phishing_detection"]' "$(field_json IE-PII-ONLY defensive_priorities)"

echo ""
echo "[IE2] fixture: identity document images only (driver's license + passport scans + selfie/KYC photos), no PII phrases, no financial data"
feed "IE-IDDOC-IMAGE-ONLY" "news" \
"An identity-verification vendor disclosed a breach exposing scanned images of driver's licenses and passports, plus selfie photos submitted by applicants for KYC verification. No other personal records or financial account data were part of the exposed dataset."
assert_eq "IE2 status NORMALIZED" "NORMALIZED" "$(km status IE-IDDOC-IMAGE-ONLY)"
assert_eq "IE2 exposure_categories" '["identity_document"]' "$(field_json IE-IDDOC-IMAGE-ONLY exposure_categories)"
assert_eq "IE2 identity_document_types" '["drivers_license", "other_identity_document", "passport"]' "$(field_json IE-IDDOC-IMAGE-ONLY identity_document_types)"
assert_eq "IE2 potential_abuse_paths" '["fraudulent_verification", "identity_impersonation"]' "$(field_json IE-IDDOC-IMAGE-ONLY potential_abuse_paths)"
assert_eq "IE2 defensive_priorities" '["identity_verification_review"]' "$(field_json IE-IDDOC-IMAGE-ONLY defensive_priorities)"

echo ""
echo "[IE3] fixture: identity document + PII combined"
feed "IE-IDDOC-PII" "vendor_advisory" \
"A cloud storage misconfiguration exposed government-issued identification images, including driver's license photos, together with customers' full names, home addresses, and email addresses for approximately 80,000 applicants of a rental-screening service."
assert_eq "IE3 status NORMALIZED" "NORMALIZED" "$(km status IE-IDDOC-PII)"
assert_eq "IE3 exposure_categories" '["identity_document", "pii"]' "$(field_json IE-IDDOC-PII exposure_categories)"
assert_eq "IE3 identity_document_types" '["drivers_license", "other_identity_document"]' "$(field_json IE-IDDOC-PII identity_document_types)"
assert_eq "IE3 potential_abuse_paths" '["account_takeover", "fraudulent_verification", "identity_impersonation", "social_engineering"]' "$(field_json IE-IDDOC-PII potential_abuse_paths)"
assert_eq "IE3 defensive_priorities" '["credential_reset", "identity_verification_review", "phishing_detection"]' "$(field_json IE-IDDOC-PII defensive_priorities)"

echo ""
echo "[IE4] fixture: PII + financial information combined"
feed "IE-PII-FINANCIAL" "vendor_advisory" \
"An e-commerce platform disclosed a database breach exposing customers' full names, email addresses, and credit card numbers for approximately 250,000 transactions. Cardholder data was reportedly stored without proper encryption."
assert_eq "IE4 status NORMALIZED" "NORMALIZED" "$(km status IE-PII-FINANCIAL)"
assert_eq "IE4 exposure_categories" '["financial_data", "pii"]' "$(field_json IE-PII-FINANCIAL exposure_categories)"
assert_eq "IE4 identity_document_types empty" "[]" "$(field_json IE-PII-FINANCIAL identity_document_types)"
assert_eq "IE4 potential_abuse_paths" '["account_takeover", "financial_fraud", "identity_impersonation", "social_engineering", "unauthorized_service_use"]' "$(field_json IE-PII-FINANCIAL potential_abuse_paths)"
assert_eq "IE4 defensive_priorities" '["credential_reset", "fraud_monitoring", "phishing_detection"]' "$(field_json IE-PII-FINANCIAL defensive_priorities)"

echo ""
echo "[IE5] fixture: financial/payment data only -- no PII phrasing, no identity document"
feed "IE-FINANCIAL-ONLY" "vendor_advisory" \
"A payment processor disclosed a breach exposing payment card numbers and cardholder data for approximately 500,000 transactions handled by its point-of-sale terminals. No other personal records were part of the exposed dataset."
assert_eq "IE5 status NORMALIZED" "NORMALIZED" "$(km status IE-FINANCIAL-ONLY)"
assert_eq "IE5 exposure_categories" '["financial_data"]' "$(field_json IE-FINANCIAL-ONLY exposure_categories)"
assert_eq "IE5 identity_document_types empty" "[]" "$(field_json IE-FINANCIAL-ONLY identity_document_types)"
assert_eq "IE5 potential_abuse_paths" '["financial_fraud", "unauthorized_service_use"]' "$(field_json IE-FINANCIAL-ONLY potential_abuse_paths)"
assert_eq "IE5 defensive_priorities" '["fraud_monitoring"]' "$(field_json IE-FINANCIAL-ONLY defensive_priorities)"

echo ""
echo "[IE6] fixture: all three categories combined -- identity document + pii + financial_data"
feed "IE-TRIPLE" "vendor_advisory" \
"A background-check vendor disclosed a breach exposing scanned driver's license images, together with customers' email addresses and dates of birth, as well as credit card numbers used for subscription billing, for approximately 45,000 users."
assert_eq "IE6 status NORMALIZED" "NORMALIZED" "$(km status IE-TRIPLE)"
assert_eq "IE6 exposure_categories" '["financial_data", "identity_document", "pii"]' "$(field_json IE-TRIPLE exposure_categories)"
assert_eq "IE6 identity_document_types" '["drivers_license"]' "$(field_json IE-TRIPLE identity_document_types)"
assert_eq "IE6 potential_abuse_paths" '["account_takeover", "financial_fraud", "fraudulent_verification", "identity_impersonation", "social_engineering", "unauthorized_service_use"]' "$(field_json IE-TRIPLE potential_abuse_paths)"
assert_eq "IE6 defensive_priorities" '["credential_reset", "fraud_monitoring", "identity_verification_review", "phishing_detection"]' "$(field_json IE-TRIPLE defensive_priorities)"

echo ""
echo "=== False-positive guards: ordinary vulnerability/phishing prose must classify to all-empty lists ==="

echo ""
echo "[FP1] a plain CVE/RCE advisory (no breach, no identity data at all) must not trigger any exposure category"
feed "IE-FP-CVE-RCE" "cert" \
"Citrix NetScaler Improper Input Validation Vulnerability (CVE-2026-88771) affects Citrix NetScaler ADC and NetScaler Gateway, allowing an unauthenticated attacker to execute arbitrary commands. Apply vendor patch 4.2.1."
assert_eq "FP1 exposure_categories empty" "[]" "$(field_json IE-FP-CVE-RCE exposure_categories)"
assert_eq "FP1 identity_document_types empty" "[]" "$(field_json IE-FP-CVE-RCE identity_document_types)"
assert_eq "FP1 potential_abuse_paths empty" "[]" "$(field_json IE-FP-CVE-RCE potential_abuse_paths)"
assert_eq "FP1 defensive_priorities empty" "[]" "$(field_json IE-FP-CVE-RCE defensive_priorities)"

echo ""
echo "[FP2] a phishing campaign report with no exposed-PII phrasing must not trigger any exposure category"
feed "IE-FP-PHISHING" "news" \
"Widespread phishing campaign impersonating shipping notifications observed delivering malicious macro-enabled documents. Indicator: sender domain notify-shipping-example.invalid. Mitigation: disable Office macros from internet-sourced documents by default."
assert_eq "FP2 exposure_categories empty" "[]" "$(field_json IE-FP-PHISHING exposure_categories)"

echo ""
echo "[FP3] bare generic words (name/address/email/id) used in ordinary vulnerability prose, none of them in an exposed-data phrase, must not trigger any exposure category"
feed "IE-FP-BARE-WORDS" "vendor_advisory" \
"The vulnerability allows an attacker to execute arbitrary code using a crafted IP address and a malicious file name delivered via email. WidgetCorp ID Verification Suite 2.1 is affected; the product name itself is unrelated to any identity document."
assert_eq "FP3 exposure_categories empty" "[]" "$(field_json IE-FP-BARE-WORDS exposure_categories)"
assert_eq "FP3 identity_document_types empty" "[]" "$(field_json IE-FP-BARE-WORDS identity_document_types)"

echo ""
echo "[FP4] 'Identity and Access Management (IAM)' product prose must not be classified as identity_document exposure"
feed "IE-FP-IAM" "vendor_advisory" \
"An Identity and Access Management (IAM) platform contains a privilege escalation vulnerability that could allow an authenticated low-privilege user to gain administrative access."
assert_eq "FP4 exposure_categories empty" "[]" "$(field_json IE-FP-IAM exposure_categories)"

echo ""
echo "=== Schema / pipeline compatibility: existing Confidence/Candidate logic is unaffected ==="

echo ""
echo "[C1] Evidence -> Analyzer -> Confidence still compute from evidence_*/cve_list/ioc_list only -- an identity-exposure candidate with a strong source reaches CANDIDATE exactly like any other"
evidence "IE-PII-ONLY" >/dev/null
assert_eq "C1 VERIFIED" "VERIFIED" "$(km status IE-PII-ONLY)"
analyze "IE-PII-ONLY" >/dev/null
assert_eq "C1 ANALYZED" "ANALYZED" "$(km status IE-PII-ONLY)"
confidence "IE-PII-ONLY" >/dev/null
assert_eq "C1 reaches CANDIDATE (E2E dry-run, Human Gate/Promote never invoked)" "CANDIDATE" "$(km status IE-PII-ONLY)"
assert_eq "C1 exposure_categories still intact after Evidence/Analyzer/Confidence" '["pii"]' "$(field_json IE-PII-ONLY exposure_categories)"
assert_eq "C1 confidence_score computed normally (unaffected by new fields)" "true" "$(python3 -c "import json; d=json.load(open('$FIXTURE_DIR/candidates/IE-PII-ONLY.json')); print('true' if isinstance(d.get('confidence_score'), int) else 'false')")"

echo ""
echo "[C2] an uncorroborated vendor_advisory candidate (base weight 40, no corroboration -> below the 50 threshold) is still auto-rejected on the SAME unmodified threshold logic, never auto-promoted just because it carries exposure fields"
evidence "IE-FP-BARE-WORDS" >/dev/null
analyze "IE-FP-BARE-WORDS" >/dev/null
confidence "IE-FP-BARE-WORDS" >/dev/null
assert_eq "C2 status REJECTED (40 < 50 threshold, exactly as a non-exposure candidate with the same source profile would be)" "REJECTED" "$(km status IE-FP-BARE-WORDS)"

echo ""
echo "[C3] the Human Gate / promotion flow was never invoked by this suite (no APPROVED/PROMOTED candidate exists anywhere in this fixture dir)"
promoted_or_approved="$(km list | grep -cE '\|(APPROVED|PROMOTED)\|' || true)"
assert_eq "C3 zero APPROVED/PROMOTED candidates" "0" "$promoted_or_approved"

echo ""
echo "[C4] security/knowledge/ (real) was never written to by this suite -- real entries are gitignored and would show as untracked ('??'); a tracked *.example doc file (e.g. this phase's own schema-doc update) legitimately shows as modified and is not what this guards against"
assert_eq "C4 no new untracked (real) files under security/knowledge/" "" "$(git status --porcelain security/knowledge/ 2>/dev/null | awk '$1 == "??"')"

echo ""
echo "[C5] no real Control Plane file was touched by this suite (DuCoPA boundary)"
for real_file in security/egress_allowlist.conf security/segments.conf security/ssh_management_allowlist.conf; do
  if [ -f "$real_file" ]; then
    assert_eq "C5 $real_file unchanged" "" "$(git diff --name-only -- "$real_file" 2>/dev/null)"
  fi
done

echo ""
echo "[C6] no real PII/identity-document/payment data is ever collected, stored, or logged by this classifier -- static guard: no fixture raw_text or state file contains anything resembling a real SSN/card-number/license-number pattern, only category labels"
leaked=0
for f in "$FIXTURE_DIR/candidates"/*.json; do
  python3 -c "
import json, re, sys
d = json.load(open(sys.argv[1]))
blob = json.dumps(d)
# A real-looking SSN (###-##-####) or a 13-19 digit payment-card-shaped
# run of digits should never appear anywhere on any candidate this
# suite produced -- this classifier only ever stores category labels
# (e.g. 'drivers_license', 'payment_information'), never a value.
if re.search(r'\b\d{3}-\d{2}-\d{4}\b', blob) or re.search(r'\b\d{13,19}\b', blob):
    sys.exit(1)
" "$f" || leaked=$((leaked+1))
done
assert_eq "C6 zero candidates contain anything resembling a real identity-document/SSN/card number" "0" "$leaked"

echo ""
echo "=== Summary: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
  echo "Failures:"
  printf '  - %s\n' "${FAILURES[@]}"
  exit 1
fi
exit 0
