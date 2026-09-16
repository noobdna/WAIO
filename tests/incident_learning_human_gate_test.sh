#!/bin/bash
set -uo pipefail

# tests/incident_learning_human_gate_test.sh -- regression suite for
# Incident Learning Engine Step 4: the Human Gate / Approval flow
# (security/incident_learning/incident_human_gate.sh, plus the new
# HOLD state and hold/release CLI commands added to
# security/incident_learning/knowledge_manager.sh).
#
# Runs against scratch fixtures under a temp dir via
# KNOWLEDGE_MANAGER_STATE_DIR/KNOWLEDGE_MANAGER_AUDIT_LOG/
# KNOWLEDGE_MANAGER_KNOWLEDGE_DIR overrides (same convention as every
# other tests/incident_learning_*_test.sh) -- never touches this
# deployment's real security/state/incident_learning/ or
# security/knowledge/. Candidates are driven straight to CANDIDATE via
# `km create`/`km advance`/`km score` fixtures, independent of
# mock_collector.sh's own sample data.

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

assert_ne() {
  local label="$1" not_expected="$2" actual="$3"
  if [ "$not_expected" != "$actual" ]; then
    PASS=$((PASS + 1)); echo "  PASS: $label"
  else
    FAIL=$((FAIL + 1)); FAILURES+=("$label (expected NOT '$not_expected')")
    echo "  FAIL: $label (expected NOT '$not_expected')"
  fi
}

FIXTURE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/waio-incident-human-gate-test.XXXXXX")"
trap 'rm -rf "$FIXTURE_DIR"; true' EXIT

mkdir -p "$FIXTURE_DIR/candidates" "$FIXTURE_DIR/knowledge"
export KNOWLEDGE_MANAGER_STATE_DIR="$FIXTURE_DIR/candidates"
export KNOWLEDGE_MANAGER_AUDIT_LOG="$FIXTURE_DIR/incident-learning-audit.jsonl"
export KNOWLEDGE_MANAGER_KNOWLEDGE_DIR="$FIXTURE_DIR/knowledge"

km() { bash security/incident_learning/knowledge_manager.sh "$@"; }
hg() { bash security/incident_learning/incident_human_gate.sh "$@"; }
field() { python3 -c "import json; print(json.load(open('$FIXTURE_DIR/candidates/$1.json')).get('$2',''))"; }
audit_events_for() { grep "\"candidate_id\": \"$1\"" "$FIXTURE_DIR/incident-learning-audit.jsonl" | python3 -c "import json,sys; [print(json.loads(l)['event']) for l in sys.stdin]"; }

# make_candidate ID SCORE -- drives a fresh candidate straight to
# CANDIDATE (SCORE>=50) or REJECTED (SCORE<50) via the real pipeline
# primitives, with a fixed evidence fingerprint, so every test below
# starts from a known, realistic state.
make_candidate() {
  local id="$1" score="$2"
  km create "$id" mock_collector "source_type=vendor_advisory" "source_url=https://example.invalid/$id" "raw_text=test incident $id" >/dev/null
  km advance "$id" NORMALIZED "t" >/dev/null
  km record-evidence "$id" "t" \
    "evidence_source_type=vendor_advisory" "evidence_corroborating_count=1" \
    "evidence_age_days=0" "evidence_self_reported_uncorroborated=false" >/dev/null
  km advance "$id" ANALYZED "t" >/dev/null
  km score "$id" "$score" >/dev/null
}

echo "=== Incident Learning Engine (Step 4: human gate / approval) regression suite ==="

echo ""
echo "[H1] CANDIDATE is never auto-reflected into security/knowledge/ -- reaching CANDIDATE alone writes nothing there"
make_candidate H1 55
assert_eq "H1 status is CANDIDATE" "CANDIDATE" "$(km status H1)"
assert_eq "H1 knowledge dir still empty after reaching CANDIDATE" "" "$(ls "$FIXTURE_DIR/knowledge" 2>/dev/null)"

echo ""
echo "[H2] review is read-only: does not change status or write to security/knowledge/"
out="$(hg review H1)"
assert_contains "H2 review shows evidence_source_type" "$out" "evidence_source_type:              vendor_advisory"
assert_contains "H2 review shows confidence_score" "$out" "confidence_score:                  55"
assert_contains "H2 review shows awaiting-decision hint" "$out" "awaiting human decision"
assert_eq "H2 status unchanged by review" "CANDIDATE" "$(km status H1)"
assert_eq "H2 knowledge dir still empty after review" "" "$(ls "$FIXTURE_DIR/knowledge" 2>/dev/null)"

echo ""
echo "[H3] approve requires a non-empty reason, refuses otherwise (human gate cannot be silently bypassed)"
out="$(bash security/incident_learning/incident_human_gate.sh approve H1 2>&1)"; rc=$?
assert_ne "H3 exits non-zero without a reason" "0" "$rc"
assert_eq "H3 status unchanged" "CANDIDATE" "$(km status H1)"

echo ""
echo "[H4] approve embeds the Evidence/Confidence basis into the audit reason, then transitions to APPROVED"
out="$(hg approve H1 "solid single-source corroborated advisory")"
assert_contains "H4 log reports CANDIDATE -> APPROVED" "$out" "CANDIDATE -> APPROVED"
assert_eq "H4 status is APPROVED" "APPROVED" "$(km status H1)"
audit_line="$(grep '"candidate_id": "H1"' "$FIXTURE_DIR/incident-learning-audit.jsonl" | grep human_approved)"
assert_contains "H4 audit reason contains human's own reason text" "$audit_line" "solid single-source corroborated advisory"
assert_contains "H4 audit reason contains evidence_source_type basis" "$audit_line" "evidence: source_type=vendor_advisory"
assert_contains "H4 audit reason contains confidence_score basis" "$audit_line" "confidence_score=55"

echo ""
echo "[H5] APPROVED is still not enough to reach security/knowledge/ -- promote is a distinct, separate step"
assert_eq "H5 knowledge dir still empty after approve alone" "" "$(ls "$FIXTURE_DIR/knowledge" 2>/dev/null)"
km promote H1 >/dev/null
assert_eq "H5 knowledge dir has the entry only after an explicit promote" "H1.json" "$(ls "$FIXTURE_DIR/knowledge" 2>/dev/null)"

echo ""
echo "[H6] REJECTED never advances toward learning: reject is terminal, promote refuses, no further human-gate action is legal"
make_candidate H6 55
hg reject H6 "duplicate of a known false-positive pattern" >/dev/null
assert_eq "H6 status is REJECTED" "REJECTED" "$(km status H6)"
promote_out="$(km promote H6 2>&1)"; promote_rc=$?
assert_ne "H6 promote exits non-zero" "0" "$promote_rc"
assert_contains "H6 promote refuses a non-APPROVED candidate" "$promote_out" "not 'APPROVED'"
assert_eq "H6 knowledge dir unaffected" "" "$(ls "$FIXTURE_DIR/knowledge" 2>/dev/null | grep H6 || true)"
approve_out="$(hg approve H6 "trying to approve after reject" 2>&1)"; approve_rc=$?
assert_ne "H6 approve after reject exits non-zero (REJECTED is terminal)" "0" "$approve_rc"
assert_eq "H6 status still REJECTED" "REJECTED" "$(km status H6)"

echo ""
echo "[H7] a low-confidence candidate that auto-rejected at the SCORED stage never even reaches the human gate, and hg approve refuses it"
make_candidate H7 10
assert_eq "H7 auto-rejected before CANDIDATE" "REJECTED" "$(km status H7)"
out="$(hg approve H7 "trying anyway" 2>&1)"; rc=$?
assert_ne "H7 hg approve exits non-zero" "0" "$rc"
assert_contains "H7 hg approve names the actual status" "$out" "is 'REJECTED'"

echo ""
echo "[H8] hold records a distinct held audit event (neither approved nor rejected), and blocks promote"
make_candidate H8 55
out="$(hg hold H8 "need a second opinion before deciding")"
assert_contains "H8 log reports CANDIDATE -> HOLD" "$out" "CANDIDATE -> HOLD"
assert_eq "H8 status is HOLD" "HOLD" "$(km status H8)"
audit_line="$(grep '"candidate_id": "H8"' "$FIXTURE_DIR/incident-learning-audit.jsonl" | grep human_held)"
assert_contains "H8 audit event is human_held (not approved/rejected)" "$audit_line" "\"event\": \"human_held\""
assert_contains "H8 held audit reason also carries evidence basis" "$audit_line" "evidence: source_type="
promote_out="$(km promote H8 2>&1)"; promote_rc=$?
assert_ne "H8 promote of a HELD candidate exits non-zero" "0" "$promote_rc"

echo ""
echo "[H9] a held candidate can still be approved or rejected directly (hold is not a dead end)"
out="$(hg approve H8 "second opinion came back positive")"
assert_contains "H9 log reports HOLD -> APPROVED" "$out" "HOLD -> APPROVED"
assert_eq "H9 status is APPROVED" "APPROVED" "$(km status H8)"

echo ""
echo "[H10] release sends a held candidate back to CANDIDATE, and it still requires a fresh explicit decision (not auto-approved by release)"
make_candidate H10 55
hg hold H10 "pending review" >/dev/null
out="$(hg release H10 "review complete, back on the queue")"
assert_contains "H10 log reports HOLD -> CANDIDATE" "$out" "HOLD -> CANDIDATE"
assert_eq "H10 status is CANDIDATE again, not APPROVED" "CANDIDATE" "$(km status H10)"
assert_eq "H10 knowledge dir unaffected by release alone" "" "$(ls "$FIXTURE_DIR/knowledge" 2>/dev/null | grep H10 || true)"

echo ""
echo "[H11] hold/release/approve/reject all refuse a candidate in the wrong status (e.g. release on a non-HOLD candidate)"
make_candidate H11 55
out="$(hg release H11 "not actually on hold" 2>&1)"; rc=$?
assert_ne "H11 release on a CANDIDATE (not HOLD) exits non-zero" "0" "$rc"
assert_contains "H11 names the actual status" "$out" "is 'CANDIDATE'"
assert_eq "H11 status unchanged" "CANDIDATE" "$(km status H11)"

echo ""
echo "[H12] every human-gate outcome (approved/rejected/held/released) leaves its own distinct audit event -- no outcome is silently missing"
events="$(audit_events_for H8)"
assert_contains "H12 H8 audit trail includes human_held" "$events" "human_held"
assert_contains "H12 H8 audit trail includes human_approved" "$events" "human_approved"
events10="$(audit_events_for H10)"
assert_contains "H12 H10 audit trail includes human_hold_released" "$events10" "human_hold_released"
events6="$(audit_events_for H6)"
assert_contains "H12 H6 audit trail includes human_rejected" "$events6" "human_rejected"

echo ""
echo "[D1] DuCoPA boundary: this suite's own run never touched any real Control Plane file"
for real_file in security/egress_allowlist.conf security/segments.conf security/ssh_management_allowlist.conf; do
  if [ -f "$real_file" ]; then
    assert_eq "D1 $real_file unchanged" "" "$(git diff --name-only -- "$real_file" 2>/dev/null)"
  fi
done

echo ""
echo "[D2] neither incident_human_gate.sh makes a network call (static guard)"
net_calls="$(grep -cE '\b(curl|wget|nc )\b' security/incident_learning/incident_human_gate.sh || true)"
assert_eq "D2 zero network-tool invocations" "0" "$net_calls"

echo ""
echo "=== Summary: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
  echo "Failures:"
  printf '  - %s\n' "${FAILURES[@]}"
  exit 1
fi
exit 0
