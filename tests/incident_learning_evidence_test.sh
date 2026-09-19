#!/bin/bash
set -uo pipefail

# tests/incident_learning_evidence_test.sh -- regression suite for
# Incident Learning Engine Step 3:
# security/incident_learning/incident_evidence.sh (NORMALIZED->VERIFIED)
# and security/incident_learning/incident_confidence.sh (ANALYZED->SCORED->CANDIDATE/REJECTED).
#
# Phase 75: incident_evidence.sh's own job now stops at VERIFIED --
# VERIFIED->ANALYZED moved to security/incident_learning/incident_analyzer.sh's
# own dedicated suite (tests/incident_learning_analyzer_test.sh). This
# suite bridges VERIFIED->ANALYZED via a plain `analyzer()` call
# wherever a downstream confidence assertion needs a candidate at
# ANALYZED -- it does not re-test analyzer.sh's own duplicate-detection
# logic (see that dedicated suite instead).
#
# Runs against scratch fixtures under a temp dir via
# KNOWLEDGE_MANAGER_STATE_DIR/KNOWLEDGE_MANAGER_AUDIT_LOG/
# KNOWLEDGE_MANAGER_KNOWLEDGE_DIR overrides (same convention as
# tests/incident_learning_test.sh and
# tests/incident_learning_collector_test.sh) -- never touches this
# deployment's real security/state/incident_learning/ or
# security/knowledge/. Candidates are built directly via `km create`/
# `km advance` fixtures rather than going through mock_collector.sh, so
# this suite is independent of that file's own sample data.

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

FIXTURE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/waio-incident-evidence-test.XXXXXX")"
trap 'rm -rf "$FIXTURE_DIR"; true' EXIT

mkdir -p "$FIXTURE_DIR/candidates" "$FIXTURE_DIR/knowledge"
export KNOWLEDGE_MANAGER_STATE_DIR="$FIXTURE_DIR/candidates"
export KNOWLEDGE_MANAGER_AUDIT_LOG="$FIXTURE_DIR/incident-learning-audit.jsonl"
export KNOWLEDGE_MANAGER_KNOWLEDGE_DIR="$FIXTURE_DIR/knowledge"

km() { bash security/incident_learning/knowledge_manager.sh "$@"; }
evidence() { bash security/incident_learning/incident_evidence.sh "$@"; }
analyzer() { bash security/incident_learning/incident_analyzer.sh "$@"; }
confidence() { bash security/incident_learning/incident_confidence.sh "$@"; }
field() { python3 -c "import json; print(json.load(open('$FIXTURE_DIR/candidates/$1.json')).get('$2',''))"; }

echo "=== Incident Learning Engine (Step 3: evidence + confidence) regression suite ==="

echo ""
echo "[E1] a well-corroborated, fresh vendor_advisory candidate reaches NORMALIZED->VERIFIED with correct evidence fields, then ANALYZED via incident_analyzer.sh"
km create E1 mock_collector \
  "source_type=vendor_advisory" "source_url=https://example.invalid/a" \
  "raw_text=Fully corroborated report." \
  "collected_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  'corroborating_sources=["https://example.invalid/b"]' >/dev/null
km advance E1 NORMALIZED "test setup" >/dev/null
out="$(evidence E1)"
assert_contains "E1 log reports NORMALIZED -> VERIFIED" "$out" "NORMALIZED -> VERIFIED"
assert_eq "E1 status VERIFIED" "VERIFIED" "$(km status E1)"
assert_eq "E1 evidence_source_type" "vendor_advisory" "$(field E1 evidence_source_type)"
assert_eq "E1 evidence_corroborating_count" "1" "$(field E1 evidence_corroborating_count)"
assert_eq "E1 evidence_age_days" "0" "$(field E1 evidence_age_days)"
assert_eq "E1 evidence_self_reported_uncorroborated" "False" "$(field E1 evidence_self_reported_uncorroborated)"
analyzer E1 >/dev/null
assert_eq "E1 final status ANALYZED (via incident_analyzer.sh, empty knowledge dir)" "ANALYZED" "$(km status E1)"

echo ""
echo "[E2] a candidate with no source_url is rejected outright (no usable evidence), never reaches ANALYZED"
km create E2 mock_collector "source_type=vendor_advisory" "source_url=" "raw_text=no source" >/dev/null
km advance E2 NORMALIZED "test setup" >/dev/null
out="$(evidence E2)"
assert_contains "E2 log reports REJECTED" "$out" "REJECTED (no source_url)"
assert_eq "E2 final status REJECTED" "REJECTED" "$(km status E2)"

echo ""
echo "[E3] a stale candidate (collected_at long ago) gets a real, large evidence_age_days"
km create E3 mock_collector \
  "source_type=vendor_advisory" "source_url=https://example.invalid/c" \
  "raw_text=Old advisory." "collected_at=2020-01-01T00:00:00Z" >/dev/null
km advance E3 NORMALIZED "test setup" >/dev/null
evidence E3 >/dev/null
age="$(field E3 evidence_age_days)"
assert_eq "E3 age_days is large (>1000)" "true" "$([ "$age" -gt 1000 ] && echo true || echo false)"
assert_eq "E3 evidence_corroborating_count defaults to 0 when absent" "0" "$(field E3 evidence_corroborating_count)"
analyzer E3 >/dev/null
assert_eq "E3 reaches ANALYZED via incident_analyzer.sh" "ANALYZED" "$(km status E3)"

echo ""
echo "[E4] self-reported-uncorroborated keyword detection fires on flagged raw_text"
km create E4 mock_collector \
  "source_type=unknown" "source_url=https://example.invalid/d" \
  "raw_text=Single source. No corroboration found." >/dev/null
km advance E4 NORMALIZED "test setup" >/dev/null
evidence E4 >/dev/null
assert_eq "E4 evidence_self_reported_uncorroborated True" "True" "$(field E4 evidence_self_reported_uncorroborated)"
analyzer E4 >/dev/null
assert_eq "E4 reaches ANALYZED via incident_analyzer.sh" "ANALYZED" "$(km status E4)"

echo ""
echo "[E5] incident_evidence.sh skips (no-op) a candidate not currently at NORMALIZED"
out="$(evidence E2)"
assert_contains "E5 skips an already-REJECTED candidate" "$out" "skipping (status=REJECTED, not NORMALIZED)"
assert_eq "E5 status unchanged" "REJECTED" "$(km status E2)"

echo ""
echo "[C1] a strong candidate (E1: vendor_advisory + 1 corroboration, fresh) scores above threshold and reaches CANDIDATE"
out="$(confidence E1)"
assert_contains "C1 log reports score" "$out" "score=55"
assert_eq "C1 final status CANDIDATE" "CANDIDATE" "$(km status E1)"
assert_eq "C1 confidence_score persisted" "55" "$(field E1 confidence_score)"

echo ""
echo "[C2] a weak, self-reported-uncorroborated candidate (E4: unknown source, no corroboration, flagged) scores at/near zero and is auto-rejected"
# E4 was already advanced to ANALYZED via evidence()+analyzer() in the
# [E4] block above -- no extra setup needed here.
assert_eq "C2 precondition: E4 is ANALYZED" "ANALYZED" "$(km status E4)"
out="$(confidence E4)"
assert_contains "C2 log reports low score" "$out" "score=0"
assert_eq "C2 final status REJECTED" "REJECTED" "$(km status E4)"

echo ""
echo "[C3] a stale-but-credible candidate (E3: vendor_advisory, no corroboration, very old) gets the staleness penalty and is auto-rejected"
assert_eq "C3 precondition: E3 is ANALYZED" "ANALYZED" "$(km status E3)"
out="$(confidence E3)"
assert_contains "C3 log reports penalized score" "$out" "score=15"
assert_eq "C3 final status REJECTED (below threshold)" "REJECTED" "$(km status E3)"

echo ""
echo "[C4] incident_confidence.sh skips (no-op) a candidate not currently at ANALYZED"
out="$(confidence E2)"
assert_contains "C4 skips an already-REJECTED candidate" "$out" "skipping (status=REJECTED, not ANALYZED/SCORED)"

echo ""
echo "[C5] re-running confidence on an already-SCORED/CANDIDATE candidate does not reprocess it"
out="$(confidence E1)"
assert_contains "C5 skips an already-CANDIDATE candidate" "$out" "skipping (status=CANDIDATE, not ANALYZED/SCORED)"
assert_eq "C5 status unchanged" "CANDIDATE" "$(km status E1)"

echo ""
echo "[D1] DuCoPA boundary: this suite's own run never touched any real Control Plane file"
for real_file in security/egress_allowlist.conf security/segments.conf security/ssh_management_allowlist.conf; do
  if [ -f "$real_file" ]; then
    assert_eq "D1 $real_file unchanged" "" "$(git diff --name-only -- "$real_file" 2>/dev/null)"
  fi
done

echo ""
echo "[D2] neither incident_evidence.sh nor incident_confidence.sh makes a network call (static guard)"
net_calls=0
for f in security/incident_learning/incident_evidence.sh security/incident_learning/incident_confidence.sh; do
  net_calls=$((net_calls + $(grep -cE '\b(curl|wget|nc )\b' "$f" || true)))
done
assert_eq "D2 zero network-tool invocations" "0" "$net_calls"

echo ""
echo "=== Summary: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
  echo "Failures:"
  printf '  - %s\n' "${FAILURES[@]}"
  exit 1
fi
exit 0
