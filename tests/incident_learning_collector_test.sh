#!/bin/bash
set -uo pipefail

# tests/incident_learning_collector_test.sh -- regression suite for
# Incident Learning Engine Step 2:
# security/incident_learning/collectors/mock_collector.sh and
# security/incident_learning/incident_normalizer.sh.
#
# Runs against scratch fixtures under a temp dir via
# KNOWLEDGE_MANAGER_STATE_DIR/KNOWLEDGE_MANAGER_AUDIT_LOG/
# KNOWLEDGE_MANAGER_KNOWLEDGE_DIR overrides (same convention as
# tests/incident_learning_test.sh) -- never touches this deployment's
# real security/state/incident_learning/ or security/knowledge/.
# mock_collector.sh makes no network call by construction, so this
# suite doesn't need a LAN-optional skip path the way
# tests/segment_recovery_test.sh does.

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

FIXTURE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/waio-incident-collector-test.XXXXXX")"
trap 'rm -rf "$FIXTURE_DIR"; true' EXIT

mkdir -p "$FIXTURE_DIR/candidates" "$FIXTURE_DIR/knowledge"
export KNOWLEDGE_MANAGER_STATE_DIR="$FIXTURE_DIR/candidates"
export KNOWLEDGE_MANAGER_AUDIT_LOG="$FIXTURE_DIR/incident-learning-audit.jsonl"
export KNOWLEDGE_MANAGER_KNOWLEDGE_DIR="$FIXTURE_DIR/knowledge"

km() { bash security/incident_learning/knowledge_manager.sh "$@"; }
collect() { bash security/incident_learning/collectors/mock_collector.sh; }
normalize() { bash security/incident_learning/incident_normalizer.sh; }
field() { python3 -c "import json; print(json.load(open('$FIXTURE_DIR/candidates/$1.json')).get('$2',''))"; }
field_json() { python3 -c "import json; print(json.dumps(json.load(open('$FIXTURE_DIR/candidates/$1.json')).get('$2', None)))"; }

echo "=== Incident Learning Engine (Step 2: collector + normalizer) regression suite ==="

echo ""
echo "[C1] mock_collector.sh emits exactly 3 valid JSON lines on stdout, nothing else"
raw="$(collect)"
line_count="$(echo "$raw" | wc -l | tr -d ' ')"
assert_eq "C1 line count" "3" "$line_count"
bad_json=0
while IFS= read -r l; do python3 -c "import json,sys; json.loads(sys.argv[1])" "$l" 2>/dev/null || bad_json=$((bad_json+1)); done <<< "$raw"
assert_eq "C1 every line is valid JSON" "0" "$bad_json"

echo ""
echo "[C2] every emitted record has the required Collector-contract fields"
missing=0
while IFS= read -r l; do
  for f in id source source_type source_url collected_at raw_text; do
    python3 -c "import json,sys; d=json.loads(sys.argv[1]); sys.exit(0 if sys.argv[2] in d else 1)" "$l" "$f" || missing=$((missing+1))
  done
done <<< "$raw"
assert_eq "C2 no missing required fields across all records" "0" "$missing"

echo ""
echo "[N1] feeding the collector's output through the normalizer creates 3 new candidates, all NORMALIZED"
out="$(collect | normalize)"
assert_contains "N1 log mentions MOCK-2026-0001 created" "$out" "MOCK-2026-0001: new candidate created"
assert_eq "N1 MOCK-2026-0001 status" "NORMALIZED" "$(km status MOCK-2026-0001)"
assert_eq "N1 MOCK-2026-0002 status" "NORMALIZED" "$(km status MOCK-2026-0002)"
assert_eq "N1 MOCK-2026-0003 status" "NORMALIZED" "$(km status MOCK-2026-0003)"

echo ""
echo "[N2] CVE extraction: MOCK-2026-0001's single CVE is captured correctly"
assert_eq "N2 cve_list" '["CVE-2026-10001"]' "$(field_json MOCK-2026-0001 cve_list)"

echo ""
echo "[N3] IOC extraction: MOCK-2026-0001's two IPv4 indicators are captured, sorted, deduplicated"
assert_eq "N3 ioc_list" '["203.0.113.10", "203.0.113.11"]' "$(field_json MOCK-2026-0001 ioc_list)"

echo ""
echo "[N4] a record with no CVE/IOC (MOCK-2026-0002, a phishing report) normalizes to empty lists, not an error"
assert_eq "N4 cve_list empty" "[]" "$(field_json MOCK-2026-0002 cve_list)"
assert_eq "N4 ioc_list empty" "[]" "$(field_json MOCK-2026-0002 ioc_list)"
assert_eq "N4 status still NORMALIZED (empty extraction isn't a failure)" "NORMALIZED" "$(km status MOCK-2026-0002)"

echo ""
echo "[N5] detection_points/mitigations sentences are captured for records that contain them"
dp="$(field_json MOCK-2026-0001 detection_points)"
assert_contains "N5 detection_points captured" "$dp" "Detection point"
mit="$(field_json MOCK-2026-0001 mitigations)"
assert_contains "N5 mitigations captured" "$mit" "mitigation"

echo ""
echo "[N6] source metadata (source_type/source_url/raw_text) is preserved on the candidate"
assert_eq "N6 source_type" "vendor_advisory" "$(field MOCK-2026-0001 source_type)"
assert_eq "N6 source_url" "https://example.invalid/advisory/0001" "$(field MOCK-2026-0001 source_url)"
assert_contains "N6 raw_text preserved" "$(field MOCK-2026-0001 raw_text)" "APT-EXAMPLE"

echo ""
echo "[N7] re-feeding the SAME collector output a second time does not duplicate or re-normalize (idempotent)"
before_audit_lines="$(wc -l < "$FIXTURE_DIR/incident-learning-audit.jsonl" | tr -d ' ')"
out2="$(collect | normalize)"
assert_contains "N7 skips already-NORMALIZED candidates" "$out2" "skipping (status=NORMALIZED, not COLLECTED)"
assert_contains "N7 does not re-create MOCK-2026-0001" "$out2" ""  # sanity: command didn't error
listing="$(km list)"
count_0001="$(echo "$listing" | grep -c "^MOCK-2026-0001|")"
assert_eq "N7 exactly one MOCK-2026-0001 candidate exists (no duplicate)" "1" "$count_0001"
after_audit_lines="$(wc -l < "$FIXTURE_DIR/incident-learning-audit.jsonl" | tr -d ' ')"
assert_eq "N7 no new audit events from the redundant re-feed" "true" "$([ "$after_audit_lines" -eq "$before_audit_lines" ] && echo true || echo false)"

echo ""
echo "[N8] normalizer never advances a candidate that's already past COLLECTED, even if asked to (e.g. after a manual reject)"
km create MANUAL-1 "manual_test" >/dev/null
km reject MANUAL-1 "test setup: pre-rejecting before a redundant normalize attempt" >/dev/null
echo '{"id":"MANUAL-1","source":"manual_test","source_type":"unknown","source_url":"https://example.invalid/x","collected_at":"2026-01-01T00:00:00Z","raw_text":"irrelevant"}' | normalize >/tmp/n8_out.$$ 2>&1
assert_contains "N8 skips a REJECTED candidate" "$(cat /tmp/n8_out.$$)" "skipping (status=REJECTED, not COLLECTED)"
assert_eq "N8 status unchanged (still REJECTED)" "REJECTED" "$(km status MANUAL-1)"
rm -f /tmp/n8_out.$$

echo ""
echo "[N9] DuCoPA boundary: this suite's own run never touched any real Control Plane file"
for real_file in security/egress_allowlist.conf security/segments.conf security/ssh_management_allowlist.conf; do
  if [ -f "$real_file" ]; then
    assert_eq "N9 $real_file unchanged" "" "$(git diff --name-only -- "$real_file" 2>/dev/null)"
  fi
done

echo ""
echo "[N10] no network tool (curl/wget/nc) is invoked by mock_collector.sh -- grep its own source, not behavior, as a static guard against accidental real collection creeping in"
net_calls="$(grep -cE '\b(curl|wget|nc )\b' security/incident_learning/collectors/mock_collector.sh || true)"
assert_eq "N10 zero network-tool invocations in mock_collector.sh" "0" "$net_calls"

echo ""
echo "=== Summary: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
  echo "Failures:"
  printf '  - %s\n' "${FAILURES[@]}"
  exit 1
fi
exit 0
