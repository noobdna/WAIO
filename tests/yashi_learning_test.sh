#!/bin/bash
set -uo pipefail

# tests/yashi_learning_test.sh -- regression suite for the YASHI Defense
# Learning Mode (security/yashi/yashi_lib.py + yashi_learn.sh).
#
#   C-series: CLASSIFY -- keyword / ATT&CK-id matching, exclusions
#     (CWE-290 "authentication bypass by spoofing" is not mail spoofing).
#   L-series: learn() -- dedupe, status and mock-source filtering, the
#     seven case sections, provenance, source reliability, proposals.
#   V-series: VALIDATE -- every synthetic fixture run through the REAL
#     mail_forensics detector; a deliberately broken expectation must
#     surface as FAIL / FIX_DETECTOR, not be hidden.
#   I-series: yashi_learn.sh CLI against a temp candidates dir and temp
#     state dir -- never this deployment's security/state/.
#   D-series: static guards for "no network, no attribution, no
#     automatic action, no Control Plane writes".
#
# All candidate records below are synthetic (example.invalid URLs).

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

LIB="security/yashi/yashi_lib.py"
CLI="security/yashi/yashi_learn.sh"
FIXTURE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/yashi-test.XXXXXX")"
trap 'rm -rf "$FIXTURE_DIR"' EXIT
REAL_STATE_BEFORE="not_present"
[ -d security/state/yashi ] && REAL_STATE_BEFORE="$(find security/state/yashi -type f -exec shasum -a 256 {} + 2>/dev/null | sort)"

py() { python3 -I -c "import sys, json; sys.path.insert(0, 'security/yashi'); import yashi_lib as y; $1"; }
techs() { py "print(' '.join(m['technique'] for m in y.classify(json.loads(sys.argv[1]))))" "$1"; }

echo "[C1] classify"
assert_eq "C1 email spoofing + DMARC" "YT-SPOOF-AUTH" "$(py "print(' '.join(m['technique'] for m in y.classify({'raw_text': 'Attackers sent spoofed email; the domain had no DMARC policy.'})))")"
assert_eq "C1 CWE-290 'bypass by spoofing' is NOT mail spoofing" "" "$(py "print(' '.join(m['technique'] for m in y.classify({'raw_text': 'Authentication Bypass by Spoofing Vulnerability in Remote Support.'})))")"
assert_eq "C1 Japanese PII keyword" "YT-PII-EXPOSURE" "$(py "print(' '.join(m['technique'] for m in y.classify({'raw_text': '会員の個人情報が漏えいした可能性'})))")"
assert_eq "C1 ATT&CK id in ttp_list matches without keywords" "YT-MAL-ATTACH" "$(py "print(' '.join(m['technique'] for m in y.classify(dict(raw_text='see report', ttp_list=['T1566.001']))))")"
assert_eq "C1 plain vulnerability text -> no scam technique" "" "$(py "print(' '.join(m['technique'] for m in y.classify({'raw_text': 'Heap overflow in image parser allows code execution.'})))")"
assert_contains "C1 evidence snippet kept" "$(py "print(y.classify({'raw_text': 'A deepfake voice call impersonated the CFO.'})[0]['evidence'])")" "deepfake"

# --- synthetic candidate records --------------------------------------
CAND="$FIXTURE_DIR/candidates"; mkdir -p "$CAND"
mk() { # id status source source_type cve updated_at raw_text
  python3 -I -c "
import json, sys
i, st, src, stype, cve, upd, txt = sys.argv[1:8]
json.dump({'id': i, 'status': st, 'source': src, 'source_type': stype, 'source_url': 'https://example.invalid/' + i,
           'raw_text': txt, 'cve_list': [cve] if cve else [], 'updated_at': upd, 'collected_at': upd,
           'confidence_score': 60, 'corroborating_sources': [], 'occurred_at': '不明'}, open(sys.argv[8], 'w'), ensure_ascii=False)
" "$@" "$CAND/$1.json"
}
mk A1 CANDIDATE cisa_advisories_collector cert "" 2026-10-18T00:00:00Z "Phishing campaign with spoofed email sender and a malicious attachment (.lnk)."
mk A2-old CANDIDATE ghsa_collector vendor_advisory CVE-2026-0001 2026-10-10T00:00:00Z "Credential stuffing led to account takeover."
mk A2-new CANDIDATE cisa_kev_collector cert CVE-2026-0001 2026-10-17T00:00:00Z "Credential stuffing led to account takeover (updated)."
mk A3 REJECTED news news "" 2026-10-18T00:00:00Z "Phishing kit sold on forums."
mk A4 CANDIDATE mock_collector unknown "" 2026-10-18T00:00:00Z "Phishing mock record."
mk A5 CANDIDATE claude_research_2026-10-06 news "" 2026-10-18T00:00:00Z "Deepfake video call scam; voice cloning of an executive."
mk A6 CANDIDATE cisa_kev_collector cert CVE-2026-0002 2026-10-18T00:00:00Z "Buffer overflow in VPN appliance."
CAND_SUMS_BEFORE="$(shasum -a 256 "$CAND"/*.json | sort)"

LEARN="$FIXTURE_DIR/learn.json"
python3 -I -c "
import glob, hashlib, json, sys
sys.path.insert(0, 'security/yashi'); import yashi_lib as y
recs = [(json.load(open(p)), hashlib.sha256(open(p, 'rb').read()).hexdigest()) for p in sorted(glob.glob(sys.argv[1] + '/*.json'))]
json.dump(y.learn(recs), open(sys.argv[2], 'w'), ensure_ascii=False)
" "$CAND" "$LEARN"
q() { python3 -I -c "import json, sys; r = json.load(open(sys.argv[1])); print($1)" "$LEARN"; }

echo "[L1] filtering and dedupe"
assert_eq "L1 input counted" "7" "$(q "r['input_records']")"
assert_eq "L1 mock source excluded" "1" "$(q "r['excluded_mock']")"
assert_eq "L1 eligible = 6 non-mock, non-REJECTED minus 1 CVE duplicate" "4" "$(q "r['eligible_after_dedupe']")"
assert_eq "L1 cases only for classified incidents (A1, A2-new, A5)" "YASHI-A1 YASHI-A2-new YASHI-A5" "$(q "' '.join(sorted(c['case_id'] for c in r['cases']))")"
assert_eq "L1 newest duplicate kept" "2026-10-17T00:00:00Z" "$(q "[c for c in r['cases'] if c['dedupe_key'] == 'cve:CVE-2026-0001'][0]['1_summary_and_source']['provenance']['last_verified_at']")"

echo "[L2] case structure"
assert_eq "L2 seven sections" "1_summary_and_source 2_technique_and_assets 3_indicators_and_detection 4_defensive_rules_and_responses 5_false_positive_risk_and_confidence 6_tests 7_lessons_and_uncertainties" "$(q "' '.join(sorted(k for k in r['cases'][0] if k[0].isdigit()))")"
assert_eq "L2 A1 techniques" "YT-PHISH-LINK YT-SPOOF-AUTH YT-MAL-ATTACH" "$(q "' '.join(h['technique'] for h in [c for c in r['cases'] if c['case_id'] == 'YASHI-A1'][0]['2_technique_and_assets']['hypotheses'])")"
assert_eq "L2 provenance: record hash recorded" "64" "$(q "len(r['cases'][0]['1_summary_and_source']['provenance']['record_sha256'])")"
assert_eq "L2 catalog not claimed verified" "False" "$(q "r['cases'][0]['1_summary_and_source']['provenance']['catalog_reference_verified']")"
assert_eq "L2 AI-compiled research marked SECONDARY" "SECONDARY" "$(q "[c for c in r['cases'] if c['case_id'] == 'YASHI-A5'][0]['1_summary_and_source']['source_reliability']")"
assert_eq "L2 cert source HIGH" "HIGH" "$(q "[c for c in r['cases'] if c['case_id'] == 'YASHI-A1'][0]['1_summary_and_source']['source_reliability']")"
assert_eq "L2 response is human review, never automatic blocking" "HUMAN_REVIEW False" "$(q "' '.join(sorted({c['4_defensive_rules_and_responses']['recommended_response'] + ' ' + str(c['4_defensive_rules_and_responses']['automatic_blocking']) for c in r['cases']}))")"
assert_eq "L2 keyword-only classification is LOW confidence" "LOW" "$(q "[c for c in r['cases'] if c['case_id'] == 'YASHI-A5'][0]['5_false_positive_risk_and_confidence']['classification_confidence']")"
assert_contains "L2 uncertainties say classification is a hypothesis" "$(q "r['cases'][0]['7_lessons_and_uncertainties']['uncertainties']")" "hypothesis"
assert_eq "L2 AI-scam recorded as a detection gap" "['YT-AI-SCAM']" "$(q "[c for c in r['cases'] if c['case_id'] == 'YASHI-A5'][0]['3_indicators_and_detection']['detection_gaps']")"
assert_eq "L2 first run: everything newly observed" "newly_observed" "$(q "' '.join(sorted({h['novelty'] for c in r['cases'] for h in c['2_technique_and_assets']['hypotheses']}))")"

echo "[L3] proposals"
assert_eq "L3 every proposal requires human approval" "PROPOSED_REQUIRES_HUMAN_APPROVAL" "$(q "' '.join(sorted({p['status'] for p in r['proposals']}))")"
assert_eq "L3 AI scam -> GAP" "GAP" "$(q "[p for p in r['proposals'] if p['technique'] == 'YT-AI-SCAM'][0]['kind']")"
assert_eq "L3 validated mail technique -> EXTEND" "EXTEND PASS" "$(q "' '.join([(p['kind'], p['validation']) for p in r['proposals'] if p['technique'] == 'YT-MAL-ATTACH'][0])")"

echo "[V1] validate fixtures with the real detector"
assert_eq "V1 all mail fixtures PASS" "PASS PASS PASS PASS PASS PASS" "$(q "' '.join(v['status'] for k, v in sorted(r['validations'].items()) if v['status'] != 'NO_FIXTURE')")"
assert_eq "V1 techniques without a detector have NO_FIXTURE, not a fake PASS" "YT-AI-SCAM YT-CRED-ATO YT-MFA-FATIGUE YT-PII-EXPOSURE" "$(q "' '.join(k for k, v in sorted(r['validations'].items()) if v['status'] == 'NO_FIXTURE')")"
assert_eq "V1 negatives raise none of the expected codes" "0" "$(q "sum(len(v.get('raised_on_negative', [])) for v in r['validations'].values())")"
V2_OUT="$(python3 -I - <<'PY'
import sys
sys.path.insert(0, 'security/yashi')
import yashi_lib as y
y.TECHNIQUES['YT-MAL-ATTACH']['expect'] = ['NO_SUCH_CODE']
v = y.validate_technique('YT-MAL-ATTACH')
case = {'case_id': 'X', '2_technique_and_assets': {'hypotheses': [{'technique': 'YT-MAL-ATTACH'}]}}
print(v['status'], y.propose([case], {'YT-MAL-ATTACH': v})[0]['kind'])
PY
)"
assert_eq "V2 broken expectation surfaces as FAIL -> FIX_DETECTOR" "FAIL FIX_DETECTOR" "$V2_OUT"

echo "[I1] CLI first run"
STATE="$FIXTURE_DIR/state"
OUT1="$(YASHI_CANDIDATES_DIR="$CAND" YASHI_STATE_DIR="$STATE" bash "$CLI")"; RC1=$?
assert_eq "I1 exit 0" "0" "$RC1"
assert_contains "I1 summary line" "$OUT1" "input=7 unreadable=0 mock_excluded=1 eligible=4 cases=3"
assert_eq "I1 outputs written" "cases.jsonl knowledge_index.json proposals.json run.log validations.json" "$(ls "$STATE" | tr '\n' ' ' | sed 's/ $//')"
assert_eq "I1 cases.jsonl has 3 lines" "3" "$(wc -l < "$STATE/cases.jsonl" | tr -d ' ')"
assert_eq "I1 candidates never modified" "$CAND_SUMS_BEFORE" "$(shasum -a 256 "$CAND"/*.json | sort)"

echo "[I2] CLI second run: known vs new"
OUT2="$(YASHI_CANDIDATES_DIR="$CAND" YASHI_STATE_DIR="$STATE" bash "$CLI")"
assert_contains "I2 nothing newly observed on re-run" "$OUT2" "new_techniques=-"
assert_eq "I2 cases now previously_known" "previously_known" "$(python3 -I -c "import json, sys; print(' '.join(sorted({h['novelty'] for l in open(sys.argv[1]) for h in json.loads(l)['2_technique_and_assets']['hypotheses']})))" "$STATE/cases.jsonl")"
assert_eq "I2 run.log appended, not overwritten" "2" "$(wc -l < "$STATE/run.log" | tr -d ' ')"

echo "[I3] CLI refusals and bad input"
YASHI_CANDIDATES_DIR="$FIXTURE_DIR/nope" YASHI_STATE_DIR="$STATE" bash "$CLI" >/dev/null 2>&1; assert_eq "I3 missing candidates dir -> exit 2" "2" "$?"
echo "{not json" > "$CAND/broken.json"
assert_contains "I3 unreadable record counted, run continues" "$(YASHI_CANDIDATES_DIR="$CAND" YASHI_STATE_DIR="$STATE" bash "$CLI")" "unreadable=1"
rm -f "$CAND/broken.json"

echo "[I4] valid JSON that is not an object"
echo '[]' > "$CAND/list.json"; echo '"text"' > "$CAND/string.json"
I4_OUT="$(YASHI_CANDIDATES_DIR="$CAND" YASHI_STATE_DIR="$STATE" bash "$CLI" 2>&1)"; I4_RC=$?
assert_contains "I4 non-object candidates counted unreadable, run continues" "$I4_OUT" "unreadable=2"
assert_eq "I4 no traceback" "0" "$(printf '%s' "$I4_OUT" | grep -c Traceback)"
assert_eq "I4 exit 0" "0" "$I4_RC"
rm -f "$CAND/list.json" "$CAND/string.json"
cp "$STATE/knowledge_index.json" "$FIXTURE_DIR/idx.bak"; echo '[1, 2]' > "$STATE/knowledge_index.json"
I4_OUT="$(YASHI_CANDIDATES_DIR="$CAND" YASHI_STATE_DIR="$STATE" bash "$CLI" 2>&1)"; I4_RC=$?
assert_eq "I4 non-object knowledge_index treated as empty, exit 0" "0" "$I4_RC"
assert_contains "I4 index rebuilt as an object" "$(python3 -I -c "import json, sys; print(type(json.load(open(sys.argv[1]))['techniques']).__name__)" "$STATE/knowledge_index.json" 2>&1)" "dict"
cp "$FIXTURE_DIR/idx.bak" "$STATE/knowledge_index.json"

echo "[D1] static safety guards"
assert_eq "D1 no network/subprocess imports in lib" "0" "$(grep -cE '^\s*(import|from)\s+(socket|ssl|urllib|http|requests|subprocess)\b' "$LIB")"
assert_eq "D1 no eval/exec/os.system in lib" "0" "$(grep -cE '\b(eval|exec|os\.system|os\.popen)\s*\(' "$LIB")"
assert_eq "D1 lib opens no files at all" "0" "$(grep -cE '\bopen\(' "$LIB")"
assert_eq "D1 no attribution field in lib output" "0" "$(grep -ciE '\"(actor|perpetrator|attribution|threat_actor)\"' "$LIB")"
assert_eq "D1 no Control Plane / containment reference in CLI or lib" "0" "$(cat "$LIB" "$CLI" | grep -vE '^\s*#' | grep -cE 'egress_allowlist|segments\.conf|guardian\.sh|ducopa\.sh|trigger_shutdown')"
assert_eq "D1 this deployment's real security/state/yashi untouched" "$REAL_STATE_BEFORE" "$( [ -d security/state/yashi ] && find security/state/yashi -type f -exec shasum -a 256 {} + 2>/dev/null | sort || echo not_present)"

echo ""
echo "=== Summary: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
  echo "Failures:"
  for f in "${FAILURES[@]}"; do echo "  - $f"; done
  exit 1
fi
exit 0
