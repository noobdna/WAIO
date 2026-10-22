#!/bin/bash
set -uo pipefail

# tests/incident_learning_classification_test.sh -- regression suite
# for Phase 98 (Global Incident Intelligence & Auto-Learning)'s
# classification additions to security/incident_learning/
# incident_normalizer.sh's extract_fields(): incident_type/
# affected_sector/claimed_impact/attack_pattern, plus the four new
# OPTIONAL Collector-supplied metadata fields threaded through at
# create time (published_at/country/region/language, with a
# Hiragana/Katakana-presence fallback for language when a Collector
# omits it).
#
# Every raw_text fixture below is entirely fictional (example.invalid
# domains, invented company names) -- same posture as mock_collector.sh
# and mock_global_incident_collector.sh's own fabricated samples; no
# real organization is ever named here.
#
# Same fixture-sandbox pattern as every other
# tests/incident_learning_*_test.sh: KNOWLEDGE_MANAGER_STATE_DIR/
# KNOWLEDGE_MANAGER_AUDIT_LOG/KNOWLEDGE_MANAGER_KNOWLEDGE_DIR overrides
# mean this suite never touches this deployment's real
# security/state/incident_learning/ or security/knowledge/, and makes
# no network call.

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

FIXTURE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/waio-incident-classification-test.XXXXXX")"
trap 'rm -rf "$FIXTURE_DIR"; true' EXIT

mkdir -p "$FIXTURE_DIR/candidates" "$FIXTURE_DIR/knowledge"
export KNOWLEDGE_MANAGER_STATE_DIR="$FIXTURE_DIR/candidates"
export KNOWLEDGE_MANAGER_AUDIT_LOG="$FIXTURE_DIR/incident-learning-audit.jsonl"
export KNOWLEDGE_MANAGER_KNOWLEDGE_DIR="$FIXTURE_DIR/knowledge"

km() { bash security/incident_learning/knowledge_manager.sh "$@"; }
normalize() { bash security/incident_learning/incident_normalizer.sh; }
field() { python3 -c "import json; print(json.load(open('$FIXTURE_DIR/candidates/$1.json')).get('$2',''))"; }

emit_raw() {
  python3 -c "
import json, sys
d = {'id': sys.argv[1], 'source': 'test_fixture', 'source_type': sys.argv[2], 'source_url': sys.argv[3], 'collected_at': sys.argv[4], 'raw_text': sys.argv[5]}
extra = sys.argv[6]
if extra:
    d.update(json.loads(extra))
print(json.dumps(d, ensure_ascii=False))
" "$@"
}

echo "=== Incident Learning Engine Phase 98: classification regression suite ==="

echo ""
echo "[C1] Japanese data-breach prose classifies incident_type=data_breach, affected_sector=automotive_carsharing, extracts a claimed_impact sentence"
emit_raw C1 news https://example.invalid/c1 "2026-10-01T00:00:00Z" \
  "Example CarShare JP社は、カーシェアリングサービスの会員情報が不正アクセスにより流出した疑いがあると発表した。被害に遭った会員は数百名規模とみられる。" \
  '{"country":"JP","region":"APAC","language":"ja","published_at":"2026-09-30T00:00:00Z"}' \
  | normalize >/dev/null
assert_eq "C1 incident_type" "data_breach" "$(field C1 incident_type)"
assert_eq "C1 affected_sector" "automotive_carsharing" "$(field C1 affected_sector)"
assert_contains "C1 claimed_impact extracted a scope-claim sentence" "$(field C1 claimed_impact)" "数百名規模"
assert_eq "C1 attack_pattern" "data_breach" "$(field C1 attack_pattern)"
assert_eq "C1 country threaded through from Collector" "JP" "$(field C1 country)"
assert_eq "C1 region threaded through from Collector" "APAC" "$(field C1 region)"
assert_eq "C1 language threaded through from Collector" "ja" "$(field C1 language)"
assert_eq "C1 published_at threaded through from Collector" "2026-09-30T00:00:00Z" "$(field C1 published_at)"

echo ""
echo "[C2] English account-takeover prose classifies incident_type=account_takeover, affected_sector=retail_ecommerce"
emit_raw C2 news https://example.invalid/c2 "2026-10-01T00:00:00Z" \
  "Example MegaRetail Global, a major online retailer, disclosed that customer accounts were compromised via credential stuffing. Affected customers were notified." \
  '{"country":"US","region":"NA"}' \
  | normalize >/dev/null
assert_eq "C2 incident_type" "account_takeover" "$(field C2 incident_type)"
assert_eq "C2 affected_sector" "retail_ecommerce" "$(field C2 affected_sector)"
assert_contains "C2 claimed_impact extracted the affected-customers sentence" "$(field C2 claimed_impact)" "Affected customers were notified"

echo ""
echo "[C3] language falls back to 'en' via the Hiragana/Katakana-presence heuristic when a Collector omits it, for ASCII-only raw_text"
emit_raw C3 news https://example.invalid/c3 "2026-10-01T00:00:00Z" \
  "Example EU HealthNet confirmed personal information of patients was exposed." \
  '{"country":"DE"}' \
  | normalize >/dev/null
assert_eq "C3 language fallback is 'en' for ASCII-only text" "en" "$(field C3 language)"

echo ""
echo "[C4] language falls back to 'ja' via the same heuristic when raw_text itself contains Hiragana/Katakana, even with no Collector-supplied language"
emit_raw C4 news https://example.invalid/c4 "2026-10-01T00:00:00Z" \
  "焼肉チェーンの顧客情報が不正に販売されていた疑いがあることが判明した。" \
  '{}' \
  | normalize >/dev/null
assert_eq "C4 language fallback is 'ja' for Japanese text" "ja" "$(field C4 language)"
assert_eq "C4 affected_sector" "food_service" "$(field C4 affected_sector)"

echo ""
echo "[C5] country/region default to 'unknown' and published_at to empty when a Collector supplies neither"
emit_raw C5 news https://example.invalid/c5 "2026-10-01T00:00:00Z" "A generic unrelated report with no geography cues." '{}' | normalize >/dev/null
assert_eq "C5 country defaults to unknown" "unknown" "$(field C5 country)"
assert_eq "C5 region defaults to unknown" "unknown" "$(field C5 region)"
assert_eq "C5 published_at defaults to empty" "" "$(field C5 published_at)"
assert_eq "C5 incident_type defaults to unclassified" "unclassified" "$(field C5 incident_type)"
assert_eq "C5 affected_sector defaults to unknown" "unknown" "$(field C5 affected_sector)"
assert_eq "C5 attack_pattern is the bare 'unclassified' sentinel" "unclassified" "$(field C5 attack_pattern)"

echo ""
echo "[C6] a pre-existing CVE/vulnerability-shaped record (no breach-style phrasing) still classifies incident_type=vulnerability_disclosure -- Phase 98 does not change existing CISA KEV/GHSA-style behavior"
emit_raw C6 cert https://example.invalid/c6 "2026-10-01T00:00:00Z" \
  "Example Vendor VPN Remote Code Execution (CVE-2026-10001) affects ExampleCorp VPN appliance. Mitigation: apply vendor patch 4.2.1." \
  '{}' \
  | normalize >/dev/null
assert_eq "C6 incident_type falls back to vulnerability_disclosure (cve_list non-empty)" "vulnerability_disclosure" "$(field C6 incident_type)"
assert_eq "C6 affected_sector defaults to unknown (no sector cue present)" "unknown" "$(field C6 affected_sector)"
assert_contains "C6 attack_pattern combines incident_type with its own attack_vector_list" "$(field C6 attack_pattern)" "vulnerability_disclosure:remote_code_execution"
assert_contains "C6 cve_list extraction still works unmodified" "$(field C6 cve_list)" "CVE-2026-10001"

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
  printf '  - %s\n' "${FAILURES[@]}"
  exit 1
fi
exit 0
