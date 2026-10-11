#!/bin/bash
set -uo pipefail

# tests/incident_learning_global_incident_collector_test.sh --
# regression suite for Phase 98's new fixture Collector:
# security/incident_learning/collectors/mock_global_incident_collector.sh.
#
# Covers two things: (1) Collector-contract conformance (one JSON
# object per stdout line, every required field present, only
# example.invalid URLs, zero network calls -- same checks
# tests/incident_learning_collector_test.sh already runs against
# mock_collector.sh, applied here to the new fixture file), and (2) a
# true end-to-end run through the full pipeline (collect -> normalize
# -> evidence -> analyze -> correlate -> confidence) confirming the
# cross-country correlation and the UNVERIFIED-but-still-correlated
# case this fixture set was specifically built to demonstrate.
#
# Same fixture-sandbox pattern as every other
# tests/incident_learning_*_test.sh: KNOWLEDGE_MANAGER_STATE_DIR/
# KNOWLEDGE_MANAGER_AUDIT_LOG/KNOWLEDGE_MANAGER_KNOWLEDGE_DIR overrides
# mean this suite never touches this deployment's real
# security/state/incident_learning/ or security/knowledge/, and makes
# no network call (mock_global_incident_collector.sh itself is a pure,
# no-network fixture, same as mock_collector.sh).

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

COLLECTOR="security/incident_learning/collectors/mock_global_incident_collector.sh"

echo "=== Phase 98: mock_global_incident_collector.sh regression suite ==="

echo ""
echo "[G1] Collector contract: every stdout line is valid JSON with the required base fields"
OUTPUT="$(bash "$COLLECTOR" 2>/dev/null)"
CONTRACT_CHECK="$(python3 -c "
import json, sys
ok = True
count = 0
for line in sys.argv[1].splitlines():
    line = line.strip()
    if not line:
        continue
    count += 1
    try:
        d = json.loads(line)
    except Exception as e:
        print(f'invalid JSON: {e}'); ok = False; continue
    for k in ('id', 'source', 'source_type', 'source_url', 'collected_at', 'raw_text'):
        if k not in d:
            print(f'{d.get(\"id\", \"?\")}: missing required field {k}'); ok = False
    if d.get('source_url') and not d['source_url'].startswith('https://example.invalid/'):
        print(f'{d[\"id\"]}: source_url is not example.invalid: {d[\"source_url\"]}'); ok = False
print(f'OK count={count}' if ok else 'FAIL')
" "$OUTPUT")"
assert_contains "G1 every record is valid JSON with required fields and example.invalid URLs" "$CONTRACT_CHECK" "OK count=5"

echo ""
echo "[G2] ids are stable/collision-resistant (five distinct GLOBAL-MOCK-* ids)"
ID_COUNT="$(echo "$OUTPUT" | python3 -c "import json,sys; print(len({json.loads(l)['id'] for l in sys.stdin if l.strip()}))")"
assert_eq "G2 five distinct ids" "5" "$ID_COUNT"

echo ""
echo "[G3] re-running the Collector is idempotent at the raw-output level (same ids every run)"
OUTPUT2="$(bash "$COLLECTOR" 2>/dev/null)"
IDS1="$(echo "$OUTPUT" | python3 -c "import json,sys; print(sorted(json.loads(l)['id'] for l in sys.stdin if l.strip()))")"
IDS2="$(echo "$OUTPUT2" | python3 -c "import json,sys; print(sorted(json.loads(l)['id'] for l in sys.stdin if l.strip()))")"
assert_eq "G3 same ids across two runs" "$IDS1" "$IDS2"

echo ""
echo "[G4] at least one record demonstrates the new optional language field present, and at least one deliberately omits it (to exercise the normalizer's own fallback)"
LANG_PRESENT="$(echo "$OUTPUT" | python3 -c "import json,sys; print(sum(1 for l in sys.stdin if l.strip() and 'language' in json.loads(l)))")"
LANG_ABSENT="$(echo "$OUTPUT" | python3 -c "import json,sys; print(sum(1 for l in sys.stdin if l.strip() and 'language' not in json.loads(l)))")"
assert_eq "G4 at least one record has language set" "true" "$([ "$LANG_PRESENT" -ge 1 ] && echo true || echo false)"
assert_eq "G4 at least one record omits language" "true" "$([ "$LANG_ABSENT" -ge 1 ] && echo true || echo false)"

FIXTURE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/waio-global-collector-test.XXXXXX")"
trap 'rm -rf "$FIXTURE_DIR"; true' EXIT
mkdir -p "$FIXTURE_DIR/candidates" "$FIXTURE_DIR/knowledge"
export KNOWLEDGE_MANAGER_STATE_DIR="$FIXTURE_DIR/candidates"
export KNOWLEDGE_MANAGER_AUDIT_LOG="$FIXTURE_DIR/incident-learning-audit.jsonl"
export KNOWLEDGE_MANAGER_KNOWLEDGE_DIR="$FIXTURE_DIR/knowledge"

km() { bash security/incident_learning/knowledge_manager.sh "$@"; }
field() { python3 -c "import json; print(json.load(open('$FIXTURE_DIR/candidates/$1.json')).get('$2',''))"; }

echo ""
echo "[G5] end-to-end: the full pipeline (collect -> normalize -> evidence -> analyze -> correlate -> confidence) correlates the two JP incidents with their overseas counterparts sharing the same attack_pattern"
bash "$COLLECTOR" | bash security/incident_learning/incident_normalizer.sh >/dev/null
bash security/incident_learning/incident_evidence.sh >/dev/null
bash security/incident_learning/incident_analyzer.sh >/dev/null
bash security/incident_learning/incident_correlator.sh >/dev/null
bash security/incident_learning/incident_confidence.sh >/dev/null

assert_contains "G5 JP account_takeover (0001) correlates with US account_takeover (0003)" "$(field GLOBAL-MOCK-0001 related_incidents)" "GLOBAL-MOCK-0003"
assert_contains "G5 JP data_breach (0002) correlates with DE data_breach (0004)" "$(field GLOBAL-MOCK-0002 related_incidents)" "GLOBAL-MOCK-0004"

echo ""
echo "[G6] the unverified single-source allegation (0005) still correlates by pattern, despite scoring UNVERIFIED"
assert_eq "G6 level(0005) is UNVERIFIED or LOW" "true" "$(python3 -c "
import subprocess
lvl = subprocess.run(['bash','security/incident_learning/knowledge_manager.sh','level','GLOBAL-MOCK-0005'], capture_output=True, text=True).stdout.strip()
print('true' if lvl in ('UNVERIFIED', 'LOW') else 'false')
")"
assert_contains "G6 0005 still appears in 0002's related_incidents (pattern, not trust)" "$(field GLOBAL-MOCK-0002 related_incidents)" "GLOBAL-MOCK-0005"

echo ""
echo "[G7] nothing in this run ever reached the Human Gate or Promote (same safety boundary as the cron wrapper)"
PROMOTED_COUNT="$(km list | grep -c '|PROMOTED|' || true)"
assert_eq "G7 zero candidates reached PROMOTED" "0" "$PROMOTED_COUNT"

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
  printf '  - %s\n' "${FAILURES[@]}"
  exit 1
fi
exit 0
