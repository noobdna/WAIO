#!/bin/bash
set -uo pipefail

# tests/incident_learning_correlator_test.sh -- regression suite for
# Phase 98 (Global Incident Intelligence & Auto-Learning)'s Correlate
# step: security/incident_learning/incident_correlator.sh.
#
# Scope: matches candidates (and already-PROMOTED knowledge entries)
# sharing the exact same attack_pattern, excluding self-matches, the
# generic 'unclassified' sentinel, and a same-source+same-source_url
# re-collection of the same record (incident_analyzer.sh's own
# duplicate-detection job, not this file's). Writes related_incidents
# via knowledge_manager.sh's new `annotate` verb, which never changes
# status -- see that command's own header.
#
# Same fixture-sandbox pattern as every other
# tests/incident_learning_*_test.sh: KNOWLEDGE_MANAGER_STATE_DIR/
# KNOWLEDGE_MANAGER_AUDIT_LOG/KNOWLEDGE_MANAGER_KNOWLEDGE_DIR overrides
# mean this suite never touches this deployment's real
# security/state/incident_learning/ or security/knowledge/, and makes
# no network call. Every raw_text/company name used below is entirely
# fictional, same posture as every other fixture in this domain.

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

FIXTURE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/waio-incident-correlator-test.XXXXXX")"
trap 'rm -rf "$FIXTURE_DIR"; true' EXIT

mkdir -p "$FIXTURE_DIR/candidates" "$FIXTURE_DIR/knowledge"
export KNOWLEDGE_MANAGER_STATE_DIR="$FIXTURE_DIR/candidates"
export KNOWLEDGE_MANAGER_AUDIT_LOG="$FIXTURE_DIR/incident-learning-audit.jsonl"
export KNOWLEDGE_MANAGER_KNOWLEDGE_DIR="$FIXTURE_DIR/knowledge"

km() { bash security/incident_learning/knowledge_manager.sh "$@"; }
correlator() { bash security/incident_learning/incident_correlator.sh "$@"; }
field() { python3 -c "import json; print(json.load(open('$FIXTURE_DIR/candidates/$1.json')).get('$2',''))"; }

write_knowledge() {
  local id="$1"; shift
  python3 -c "
import json, sys
d = {'id': sys.argv[1]}
for kv in sys.argv[2:]:
    k, _, v = kv.partition('=')
    try:
        d[k] = json.loads(v)
    except (json.JSONDecodeError, ValueError):
        d[k] = v
json.dump(d, open('$FIXTURE_DIR/knowledge/' + sys.argv[1] + '.json', 'w'))
" "$id" "$@"
}

echo "=== Incident Learning Engine Phase 98: incident_correlator.sh regression suite ==="

echo ""
echo "[R1] two candidates sharing the same attack_pattern, different sources, correlate with each other (symmetric)"
km create R1_A src_a "source_type=news" "source_url=https://example.invalid/r1-a" "raw_text=t" >/dev/null
km advance R1_A NORMALIZED "t" >/dev/null
km classify R1_A "t" "attack_pattern=data_breach" >/dev/null
km create R1_B src_b "source_type=vendor_advisory" "source_url=https://example.invalid/r1-b" "raw_text=t" >/dev/null
km advance R1_B NORMALIZED "t" >/dev/null
km classify R1_B "t" "attack_pattern=data_breach" >/dev/null
correlator R1_A >/dev/null
correlator R1_B >/dev/null
assert_eq "R1 A correlates to B" "['R1_B']" "$(field R1_A related_incidents)"
assert_eq "R1 B correlates to A" "['R1_A']" "$(field R1_B related_incidents)"
assert_eq "R1 A status unchanged by correlation" "NORMALIZED" "$(km status R1_A)"

echo ""
echo "[R2] a candidate with a different attack_pattern does NOT correlate"
km create R2_C src_c "source_type=news" "source_url=https://example.invalid/r2-c" "raw_text=t" >/dev/null
km advance R2_C NORMALIZED "t" >/dev/null
km classify R2_C "t" "attack_pattern=phishing" >/dev/null
out="$(correlator R2_C)"
assert_contains "R2 no related incidents found" "$out" "no related incidents found"
assert_eq "R2 related_incidents not set (no annotate call made)" "" "$(field R2_C related_incidents)"

echo ""
echo "[R3] the bare 'unclassified' sentinel never correlates, even against another 'unclassified' candidate"
km create R3_D src_d "source_type=news" "source_url=https://example.invalid/r3-d" "raw_text=t" >/dev/null
km advance R3_D NORMALIZED "t" >/dev/null
km classify R3_D "t" "attack_pattern=unclassified" >/dev/null
km create R3_E src_e "source_type=news" "source_url=https://example.invalid/r3-e" "raw_text=t" >/dev/null
km advance R3_E NORMALIZED "t" >/dev/null
km classify R3_E "t" "attack_pattern=unclassified" >/dev/null
out="$(correlator R3_D)"
assert_contains "R3 unclassified sentinel is never a correlation key" "$out" "no related incidents found"

echo ""
echo "[R4] a same-source, same-source_url re-collection of the same record is excluded (that is incident_analyzer.sh's duplicate, not a correlation)"
km create R4_F src_f "source_type=news" "source_url=https://example.invalid/r4-shared" "raw_text=t" >/dev/null
km advance R4_F NORMALIZED "t" >/dev/null
km classify R4_F "t" "attack_pattern=ransomware" >/dev/null
km create R4_G src_f "source_type=news" "source_url=https://example.invalid/r4-shared" "raw_text=t2" >/dev/null
km advance R4_G NORMALIZED "t" >/dev/null
km classify R4_G "t" "attack_pattern=ransomware" >/dev/null
out="$(correlator R4_F)"
assert_contains "R4 same-source/same-url re-collection excluded" "$out" "no related incidents found"

echo ""
echo "[R5] a candidate correlates against an already-PROMOTED knowledge entry sharing its attack_pattern, not just other in-flight candidates"
write_knowledge R5_KNOWLEDGE 'attack_pattern=account_takeover' 'source=src_h' 'source_url=https://example.invalid/r5-knowledge'
km create R5_I src_i "source_type=news" "source_url=https://example.invalid/r5-i" "raw_text=t" >/dev/null
km advance R5_I NORMALIZED "t" >/dev/null
km classify R5_I "t" "attack_pattern=account_takeover" >/dev/null
out="$(correlator R5_I)"
assert_contains "R5 correlates against the promoted knowledge entry" "$out" "R5_KNOWLEDGE"
assert_eq "R5 related_incidents includes the knowledge entry id" "['R5_KNOWLEDGE']" "$(field R5_I related_incidents)"

echo ""
echo "[R6] a PROMOTED candidate is skipped entirely (terminal, not annotatable) -- never an error"
km create R6_J src_j "source_type=vendor_advisory" "source_url=https://example.invalid/r6-j" "raw_text=t" "collected_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)" >/dev/null
km advance R6_J NORMALIZED "t" >/dev/null
km classify R6_J "t" "attack_pattern=ddos" >/dev/null
bash security/incident_learning/incident_evidence.sh R6_J >/dev/null
km advance R6_J ANALYZED "t" >/dev/null
km score R6_J 90 >/dev/null
km approve R6_J "approved for test" >/dev/null
km promote R6_J >/dev/null
out="$(correlator R6_J)"; rc=$?
assert_eq "R6 exits zero for a PROMOTED candidate" "0" "$rc"
assert_contains "R6 logs a clean skip, not an error" "$out" "skipping (status=PROMOTED, terminal"

echo ""
echo "[R7] a REJECTED candidate is likewise skipped, never an error"
km create R7_K src_k "source_type=news" "source_url=https://example.invalid/r7-k" "raw_text=t" >/dev/null
km advance R7_K NORMALIZED "t" >/dev/null
km classify R7_K "t" "attack_pattern=ddos" >/dev/null
km advance R7_K REJECTED "no usable evidence" >/dev/null
out="$(correlator R7_K)"; rc=$?
assert_eq "R7 exits zero for a REJECTED candidate" "0" "$rc"
assert_contains "R7 logs a clean skip, not an error" "$out" "skipping (status=REJECTED, terminal"

echo ""
echo "[R8] re-running the correlator refreshes related_incidents rather than failing or appending duplicates -- a new matching candidate added after the first run is picked up on the second"
km create R8_L src_l "source_type=news" "source_url=https://example.invalid/r8-l" "raw_text=t" >/dev/null
km advance R8_L NORMALIZED "t" >/dev/null
km classify R8_L "t" "attack_pattern=supply_chain_demo" >/dev/null
km create R8_M src_m "source_type=news" "source_url=https://example.invalid/r8-m" "raw_text=t" >/dev/null
km advance R8_M NORMALIZED "t" >/dev/null
km classify R8_M "t" "attack_pattern=supply_chain_demo" >/dev/null
correlator R8_L >/dev/null
assert_eq "R8 first run finds R8_M" "['R8_M']" "$(field R8_L related_incidents)"
km create R8_N src_n "source_type=news" "source_url=https://example.invalid/r8-n" "raw_text=t" >/dev/null
km advance R8_N NORMALIZED "t" >/dev/null
km classify R8_N "t" "attack_pattern=supply_chain_demo" >/dev/null
correlator R8_L >/dev/null
assert_eq "R8 second run finds both M and N" "['R8_M', 'R8_N']" "$(field R8_L related_incidents)"

echo ""
echo "[R9] unknown id is a clean error, not a crash"
out="$(correlator NOPE_DOES_NOT_EXIST 2>&1)"; rc=$?
assert_eq "R9 unknown id exits non-zero" "1" "$rc"
assert_contains "R9 error names the unknown id" "$out" "unknown candidate"

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
  printf '  - %s\n' "${FAILURES[@]}"
  exit 1
fi
exit 0
