#!/bin/bash
set -uo pipefail

# tests/incident_learning_annotate_level_test.sh -- regression suite
# for Phase 98 (Global Incident Intelligence & Auto-Learning)'s two
# additions to security/incident_learning/knowledge_manager.sh:
#   - `annotate` (candidate_annotate): the only path that writes
#     related_incidents, deliberately with NO status transition.
#   - `level` (candidate_confidence_level): read-only derivation of
#     UNVERIFIED/LOW/MEDIUM/HIGH/CONFIRMED from confidence_score+status.
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

FIXTURE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/waio-incident-annotate-level-test.XXXXXX")"
trap 'rm -rf "$FIXTURE_DIR"; true' EXIT

mkdir -p "$FIXTURE_DIR/candidates" "$FIXTURE_DIR/knowledge"
export KNOWLEDGE_MANAGER_STATE_DIR="$FIXTURE_DIR/candidates"
export KNOWLEDGE_MANAGER_AUDIT_LOG="$FIXTURE_DIR/incident-learning-audit.jsonl"
export KNOWLEDGE_MANAGER_KNOWLEDGE_DIR="$FIXTURE_DIR/knowledge"

km() { bash security/incident_learning/knowledge_manager.sh "$@"; }
field() { python3 -c "import json; print(json.load(open('$FIXTURE_DIR/candidates/$1.json')).get('$2',''))"; }
audit_events_for() { grep "\"candidate_id\": \"$1\"" "$FIXTURE_DIR/incident-learning-audit.jsonl" | python3 -c "import json,sys; [print(json.loads(l)['event']) for l in sys.stdin]"; }
audit_count() { wc -l < "$FIXTURE_DIR/incident-learning-audit.jsonl" | tr -d ' '; }

echo "=== Incident Learning Engine Phase 98: annotate/level regression suite ==="

echo ""
echo "[N1] annotate sets related_incidents without changing status"
km create N1 mock_global_incident_collector "source_type=news" "source_url=https://example.invalid/n1" "raw_text=t" >/dev/null
assert_eq "N1 precondition: COLLECTED" "COLLECTED" "$(km status N1)"
out="$(km annotate N1 "correlated: 1 related incident(s)" 'related_incidents=["N2"]')"
assert_contains "N1 annotate reports success" "$out" "annotated"
assert_eq "N1 status unchanged after annotate" "COLLECTED" "$(km status N1)"
assert_eq "N1 related_incidents recorded" "['N2']" "$(field N1 related_incidents)"

echo ""
echo "[N2] annotate is re-runnable (overwrites related_incidents, not append-only)"
km annotate N1 "re-correlated: now 0 related" 'related_incidents=[]' >/dev/null
assert_eq "N2 related_incidents replaced with empty list" "[]" "$(field N1 related_incidents)"

echo ""
echo "[N3] annotate refuses a non-whitelisted field"
out="$(km annotate N1 "trying to forge" 'confidence_score=99' 2>&1)"; rc=$?
assert_eq "N3 annotate with forbidden field exits non-zero" "1" "$rc"
assert_contains "N3 error names the rejected field" "$out" "confidence_score"
assert_contains "N3 error says not annotatable" "$out" "not an annotatable field"

echo ""
echo "[N4] annotate refuses a terminal (REJECTED) candidate"
km create N4 mock_global_incident_collector "source_type=news" "source_url=https://example.invalid/n4" "raw_text=t" >/dev/null
km advance N4 NORMALIZED "t" >/dev/null
km advance N4 REJECTED "no usable evidence" >/dev/null
assert_eq "N4 precondition: REJECTED" "REJECTED" "$(km status N4)"
out="$(km annotate N4 "trying anyway" 'related_incidents=["N1"]' 2>&1)"; rc=$?
assert_eq "N4 annotate on REJECTED exits non-zero" "1" "$rc"
assert_contains "N4 error cites terminal status" "$out" "terminal candidate"

echo ""
echo "[N5] annotate refuses a terminal (PROMOTED) candidate"
km create N5 mock_global_incident_collector "source_type=vendor_advisory" "source_url=https://example.invalid/n5" "raw_text=t" "collected_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)" >/dev/null
km advance N5 NORMALIZED "t" >/dev/null
bash security/incident_learning/incident_evidence.sh N5 >/dev/null
km advance N5 ANALYZED "t" >/dev/null
km score N5 90 >/dev/null
km approve N5 "approved for test" >/dev/null
km promote N5 >/dev/null
assert_eq "N5 precondition: PROMOTED" "PROMOTED" "$(km status N5)"
out="$(km annotate N5 "trying anyway" 'related_incidents=["N1"]' 2>&1)"; rc=$?
assert_eq "N5 annotate on PROMOTED exits non-zero" "1" "$rc"
assert_contains "N5 error cites terminal status" "$out" "terminal candidate"

echo ""
echo "[N6] related_incidents is a reserved field: cannot be forged via create"
out="$(km create N6 mock_global_incident_collector 'related_incidents=["N1"]' 2>&1)"; rc=$?
assert_eq "N6 create with related_incidents exits non-zero" "1" "$rc"
assert_contains "N6 error names the reserved field" "$out" "related_incidents"

echo ""
echo "[N7] related_incidents is a reserved field: cannot be forged via advance"
km create N7 mock_global_incident_collector "source_type=news" "source_url=https://example.invalid/n7" "raw_text=t" >/dev/null
out="$(km advance N7 NORMALIZED "t" 'related_incidents=["N1"]' 2>&1)"; rc=$?
assert_eq "N7 advance with related_incidents exits non-zero" "1" "$rc"
assert_contains "N7 error names the reserved field" "$out" "related_incidents"
assert_eq "N7 status unchanged (rejected before any write)" "COLLECTED" "$(km status N7)"

echo ""
echo "[N8] classify sets incident_type/affected_sector/claimed_impact/attack_pattern without changing status"
km create N8 mock_global_incident_collector "source_type=news" "source_url=https://example.invalid/n8" "raw_text=t" >/dev/null
assert_eq "N8 precondition: COLLECTED" "COLLECTED" "$(km status N8)"
out="$(km classify N8 "classified" "incident_type=data_breach" "affected_sector=retail_ecommerce" "claimed_impact=[\"x\"]" "attack_pattern=data_breach")"
assert_contains "N8 classify reports success" "$out" "classified"
assert_eq "N8 status unchanged after classify" "COLLECTED" "$(km status N8)"
assert_eq "N8 incident_type recorded" "data_breach" "$(field N8 incident_type)"
assert_eq "N8 affected_sector recorded" "retail_ecommerce" "$(field N8 affected_sector)"
assert_eq "N8 attack_pattern recorded" "data_breach" "$(field N8 attack_pattern)"

echo ""
echo "[N9] classify refuses a non-whitelisted field"
out="$(km classify N8 "trying to forge" 'confidence_score=99' 2>&1)"; rc=$?
assert_eq "N9 classify with forbidden field exits non-zero" "1" "$rc"
assert_contains "N9 error names the rejected field" "$out" "confidence_score"
assert_contains "N9 error says not a classifiable field" "$out" "not a classifiable field"

echo ""
echo "[N10] classify refuses a terminal (PROMOTED) candidate"
out="$(km classify N5 "trying anyway" "incident_type=ransomware" 2>&1)"; rc=$?
assert_eq "N10 classify on PROMOTED exits non-zero" "1" "$rc"
assert_contains "N10 error cites terminal status" "$out" "terminal candidate"

echo ""
echo "[N11] incident_type/affected_sector/claimed_impact/attack_pattern are reserved fields: cannot be forged via create or advance"
out="$(km create N11 mock_global_incident_collector 'attack_pattern=ransomware' 2>&1)"; rc=$?
assert_eq "N11 create with attack_pattern exits non-zero" "1" "$rc"
assert_contains "N11 error names the reserved field" "$out" "attack_pattern"
km create N11 mock_global_incident_collector "source_type=news" "source_url=https://example.invalid/n11" "raw_text=t" >/dev/null
out="$(km advance N11 NORMALIZED "t" 'incident_type=ransomware' 2>&1)"; rc=$?
assert_eq "N11 advance with incident_type exits non-zero" "1" "$rc"
assert_contains "N11 error names the reserved field" "$out" "incident_type"
assert_eq "N11 status unchanged (rejected before any write)" "COLLECTED" "$(km status N11)"

echo ""
echo "[L1] level: a freshly-created candidate (no confidence_score yet) is UNVERIFIED"
km create L1 mock_global_incident_collector "source_type=news" "source_url=https://example.invalid/l1" "raw_text=t" >/dev/null
assert_eq "L1 level UNVERIFIED with no score" "UNVERIFIED" "$(km level L1)"

echo ""
echo "[L2] level: score bands map correctly (LOW/MEDIUM/HIGH), never CONFIRMED pre-promotion"
km advance L1 NORMALIZED "t" >/dev/null
bash security/incident_learning/incident_evidence.sh L1 >/dev/null
km advance L1 ANALYZED "t" >/dev/null
km score L1 35 >/dev/null
assert_eq "L2 score=35 (REJECTED, below floor) -> LOW" "LOW" "$(km level L1)"

km create L2 mock_global_incident_collector "source_type=vendor_advisory" "source_url=https://example.invalid/l2" "raw_text=t" "collected_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)" >/dev/null
km advance L2 NORMALIZED "t" >/dev/null
bash security/incident_learning/incident_evidence.sh L2 >/dev/null
km advance L2 ANALYZED "t" >/dev/null
km score L2 55 >/dev/null
assert_eq "L2 score=55 (CANDIDATE) -> MEDIUM" "MEDIUM" "$(km level L2)"

km create L3 mock_global_incident_collector "source_type=vendor_advisory" "source_url=https://example.invalid/l3" "raw_text=t" "collected_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)" >/dev/null
km advance L3 NORMALIZED "t" >/dev/null
bash security/incident_learning/incident_evidence.sh L3 >/dev/null
km advance L3 ANALYZED "t" >/dev/null
km score L3 90 >/dev/null
assert_eq "L3 score=90 (CANDIDATE, very high) -> HIGH, never CONFIRMED pre-promotion" "HIGH" "$(km level L3)"

echo ""
echo "[L4] level: CONFIRMED is reached ONLY via PROMOTED, regardless of score"
km approve L3 "approved for test" >/dev/null
km promote L3 >/dev/null
assert_eq "L4 precondition: L3 is PROMOTED" "PROMOTED" "$(km status L3)"
assert_eq "L4 PROMOTED candidate is CONFIRMED" "CONFIRMED" "$(km level L3)"

echo ""
echo "[L5] level: unknown id is a clean error, not a crash"
out="$(km level NOPE_DOES_NOT_EXIST 2>&1)"; rc=$?
assert_eq "L5 unknown id exits non-zero" "1" "$rc"
assert_contains "L5 error names the unknown id" "$out" "unknown candidate"

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
  printf '  - %s\n' "${FAILURES[@]}"
  exit 1
fi
exit 0
