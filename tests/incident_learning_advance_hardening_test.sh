#!/bin/bash
set -uo pipefail

# tests/incident_learning_advance_hardening_test.sh -- regression suite
# for Incident Learning Engine Step 7: closing the Human Gate / Promote
# bypasses a full audit of Steps 1-6 found and demonstrated:
#
#   (a) `create ID SOURCE status=APPROVED` (or status=PROMOTED, or any
#       other reserved field) fabricated a candidate directly at an
#       arbitrary status, skipping the entire pipeline, Evidence,
#       Confidence, and the Human Gate in one call.
#   (b) `advance ID APPROVED "reason"` reached the human gate's own
#       state without ever calling the `approve` command (wrong audit
#       event: advanced/pipeline instead of human_approved/human_gate).
#   (b2) `advance ID PROMOTED "reason"` (from APPROVED) marked a
#       candidate PROMOTED WITHOUT ever running knowledge_promote()'s
#       actual write -- no file landed in security/knowledge/, and
#       promote()'s own idempotency check then treated the candidate as
#       "already done", permanently blocking a real promotion.
#   (c) `advance ID <legal pipeline target> "reason" confidence_score=N`
#       forged a confidence score via KEY=VALUE extras that
#       candidate_transition never protected (unlike status/
#       previous_status/updated_at/reason, which it always re-asserts
#       after merging extras).
#   (d) `advance ID REJECTED "reason"` from CANDIDATE/HOLD rejected a
#       candidate that had already reached the human gate, without
#       going through the `reject` command (wrong audit event, and no
#       accountable human reason on record).
#
# The fix (knowledge_manager.sh): a new _km_reserved_field_violation()
# guard applied to `create`'s extras (all reserved fields refused), and
# to `advance`'s target status (whitelisted to
# NORMALIZED/VERIFIED/ANALYZED/REJECTED only, with REJECTED additionally
# refused from CANDIDATE/HOLD) and its own extras (reserved fields
# refused there too). No state-machine edge was removed and no
# legitimate pipeline call (incident_normalizer.sh/incident_evidence.sh/
# incident_confidence.sh, all of which only ever call advance with
# NORMALIZED/VERIFIED/ANALYZED/REJECTED-from-NORMALIZED) is affected --
# see tests/incident_learning_collector_test.sh/
# incident_learning_evidence_test.sh/incident_learning_cron_test.sh for
# that continued coverage; this suite only covers the NEW refusals.
#
# Same fixture-sandbox pattern as every other
# tests/incident_learning_*_test.sh: KNOWLEDGE_MANAGER_STATE_DIR/
# KNOWLEDGE_MANAGER_AUDIT_LOG/KNOWLEDGE_MANAGER_KNOWLEDGE_DIR overrides
# mean this suite never reads or writes this deployment's real
# security/state/incident_learning/ or security/knowledge/.

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

FIXTURE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/waio-incident-hardening-test.XXXXXX")"
trap 'rm -rf "$FIXTURE_DIR"; true' EXIT

mkdir -p "$FIXTURE_DIR/candidates" "$FIXTURE_DIR/knowledge"
export KNOWLEDGE_MANAGER_STATE_DIR="$FIXTURE_DIR/candidates"
export KNOWLEDGE_MANAGER_AUDIT_LOG="$FIXTURE_DIR/incident-learning-audit.jsonl"
export KNOWLEDGE_MANAGER_KNOWLEDGE_DIR="$FIXTURE_DIR/knowledge"

km() { bash security/incident_learning/knowledge_manager.sh "$@"; }
knowledge_count() { ls "$FIXTURE_DIR/knowledge" 2>/dev/null | wc -l | tr -d ' '; }

make_to_candidate() {
  local id="$1" score="$2"
  km create "$id" mock_collector "source_type=vendor_advisory" "source_url=https://example.invalid/$id" "raw_text=t" >/dev/null
  km advance "$id" NORMALIZED "t" >/dev/null
  km record-evidence "$id" "t" "evidence_source_type=vendor_advisory" "evidence_corroborating_count=1" "evidence_age_days=0" "evidence_self_reported_uncorroborated=false" >/dev/null
  km advance "$id" ANALYZED "t" >/dev/null
  km score "$id" "$score" >/dev/null
}

echo "=== Incident Learning Engine (Step 7: Human Gate bypass hardening) regression suite ==="

echo ""
echo "[A1] (a) create refuses a status= override -- candidate is never created at all"
out="$(km create A1FORGED mock status=APPROVED source_type=vendor_advisory source_url=https://example.invalid/a1 raw_text=fab 2>&1)"; rc=$?
assert_eq "A1 exit code" "1" "$rc"
assert_contains "A1 error names the reserved field" "$out" "'status' is a reserved field"
out2="$(km status A1FORGED 2>&1)"; rc2=$?
assert_eq "A1 candidate was never created" "1" "$rc2"
assert_contains "A1 status lookup fails as unknown" "$out2" "unknown candidate"

echo ""
echo "[A2] (a) create refuses status=PROMOTED the same way, and every other reserved field too"
for field in status previous_status confidence_score reason created_at updated_at id; do
  out="$(km create "A2_$field" mock "$field=whatever" 2>&1)"; rc=$?
  assert_eq "A2 create refuses reserved field '$field' (exit 1)" "1" "$rc"
  assert_contains "A2 error names '$field'" "$out" "'$field' is a reserved field"
done
assert_eq "A2 knowledge dir untouched" "0" "$(knowledge_count)"

echo ""
echo "[A3] (a) creation_rejected is itself audited (nothing silently disappears)"
audit_line="$(grep '"candidate_id": "A1FORGED"' "$FIXTURE_DIR/incident-learning-audit.jsonl" || true)"
assert_contains "A3 audit event is creation_rejected" "$audit_line" "\"event\": \"creation_rejected\""
assert_contains "A3 audit reason names the reserved field" "$audit_line" "reserved field 'status'"

echo ""
echo "[B1] (b) advance cannot reach APPROVED -- the human gate's own state is off-limits to the pipeline verb"
make_to_candidate B1 55
assert_eq "B1 precondition: reached CANDIDATE" "CANDIDATE" "$(km status B1)"
out="$(km advance B1 APPROVED "trying to skip the human gate" 2>&1)"; rc=$?
assert_eq "B1 exit code" "1" "$rc"
assert_contains "B1 error names the out-of-scope target" "$out" "does not permit target status 'APPROVED'"
assert_eq "B1 status unchanged" "CANDIDATE" "$(km status B1)"

echo ""
echo "[B2] (b) advance cannot reach HOLD either"
out="$(km advance B1 HOLD "trying to fake a hold" 2>&1)"; rc=$?
assert_eq "B2 exit code" "1" "$rc"
assert_contains "B2 error names the out-of-scope target" "$out" "does not permit target status 'HOLD'"
assert_eq "B2 status unchanged" "CANDIDATE" "$(km status B1)"

echo ""
echo "[B3] (b2) advance cannot fake-promote: APPROVED -> PROMOTED via advance is refused, and the real promote() path still works afterward"
km approve B1 "legitimate human approval for this test" >/dev/null
assert_eq "B3 precondition: APPROVED" "APPROVED" "$(km status B1)"
out="$(km advance B1 PROMOTED "trying to fake-promote" 2>&1)"; rc=$?
assert_eq "B3 exit code" "1" "$rc"
assert_contains "B3 error names the out-of-scope target" "$out" "does not permit target status 'PROMOTED'"
assert_eq "B3 status still APPROVED (not falsely PROMOTED)" "APPROVED" "$(km status B1)"
assert_eq "B3 knowledge dir still empty" "0" "$(knowledge_count)"
km promote B1 >/dev/null
assert_eq "B3 real promote succeeds afterward" "PROMOTED" "$(km status B1)"
assert_eq "B3 knowledge entry now exists exactly once" "1" "$(knowledge_count)"

echo ""
echo "[B4] every advance scope violation is itself audited as advance_scope_violation"
events="$(grep '"candidate_id": "B1"' "$FIXTURE_DIR/incident-learning-audit.jsonl" | python3 -c "import json,sys; [print(json.loads(l)['event']) for l in sys.stdin]")"
violation_count="$(echo "$events" | grep -c '^advance_scope_violation$')"
assert_eq "B4 at least 3 advance_scope_violation events for B1 (APPROVED, HOLD, PROMOTED attempts)" "true" "$([ "$violation_count" -ge 3 ] && echo true || echo false)"

echo ""
echo "[C1] (c) advance cannot forge confidence_score via extras, even for a legal pipeline target"
km create C1 mock_collector "source_type=unknown" "source_url=https://example.invalid/c1" "raw_text=t" >/dev/null
out="$(km advance C1 NORMALIZED "t" confidence_score=999 2>&1)"; rc=$?
assert_eq "C1 exit code" "1" "$rc"
assert_contains "C1 error names confidence_score" "$out" "'confidence_score' is a reserved field"
assert_eq "C1 status unchanged (still COLLECTED, the advance never happened)" "COLLECTED" "$(km status C1)"
assert_eq "C1 confidence_score field untouched (null)" "None" "$(python3 -c "import json; print(json.load(open('$FIXTURE_DIR/candidates/C1.json')).get('confidence_score'))")"

echo ""
echo "[C2] legitimate advance (no forged extras) for the same candidate still works normally afterward"
out="$(km advance C1 NORMALIZED "real normalize")"; rc=$?
assert_eq "C2 exit code 0" "0" "$rc"
assert_eq "C2 status is NORMALIZED" "NORMALIZED" "$(km status C1)"

echo ""
echo "[D1] (d) advance cannot reject a CANDIDATE -- rejecting a human-gate candidate is the 'reject' command's job"
make_to_candidate D1 55
assert_eq "D1 precondition: CANDIDATE" "CANDIDATE" "$(km status D1)"
out="$(km advance D1 REJECTED "auto-reject bypassing the human gate" 2>&1)"; rc=$?
assert_eq "D1 exit code" "1" "$rc"
assert_contains "D1 error names the human-gate status" "$out" "cannot reject 'D1' from 'CANDIDATE'"
assert_eq "D1 status unchanged" "CANDIDATE" "$(km status D1)"

echo ""
echo "[D2] (d) advance cannot reject a HOLD candidate either"
bash security/incident_learning/incident_human_gate.sh hold D1 "pending review" >/dev/null
assert_eq "D2 precondition: HOLD" "HOLD" "$(km status D1)"
out="$(km advance D1 REJECTED "auto-reject from hold" 2>&1)"; rc=$?
assert_eq "D2 exit code" "1" "$rc"
assert_contains "D2 error names the human-gate status" "$out" "cannot reject 'D1' from 'HOLD'"
assert_eq "D2 status unchanged" "HOLD" "$(km status D1)"

echo ""
echo "[D3] the real 'reject' command still works normally on CANDIDATE/HOLD (only the advance-shaped bypass is blocked)"
out="$(km reject D1 "legitimate human rejection: duplicate report")"; rc=$?
assert_eq "D3 exit code 0" "0" "$rc"
assert_eq "D3 status REJECTED via the real command" "REJECTED" "$(km status D1)"

echo ""
echo "[E1] legitimate pipeline advances are completely unaffected: the full COLLECTED->CANDIDATE path still works end to end"
make_to_candidate E1 60
assert_eq "E1 full pipeline still reaches CANDIDATE" "CANDIDATE" "$(km status E1)"
make_to_candidate E2 10
assert_eq "E2 low-confidence path still auto-rejects (SCORED->REJECTED via 'score', not 'advance')" "REJECTED" "$(km status E2)"

echo ""
echo "[E2] incident_evidence.sh's own automated no-source-url rejection (advance ... REJECTED from NORMALIZED) still works"
km create E3 mock_collector "source_type=vendor_advisory" "source_url=" "raw_text=no url" >/dev/null
km advance E3 NORMALIZED "t" >/dev/null
out="$(bash security/incident_learning/incident_evidence.sh E3)"
assert_contains "E2 evidence.sh still auto-rejects a missing source_url" "$out" "REJECTED (no source_url)"
assert_eq "E2 status REJECTED" "REJECTED" "$(km status E3)"

echo ""
echo "=== Final-audit fix: Evidence forgery via 'advance ... VERIFIED ...' (evidence_* fields were not reserved) ==="
echo ""
echo "[G1] advance can no longer reach VERIFIED at all, even with no extras -- NORMALIZED->VERIFIED now requires 'record-evidence'"
km create G1 mock_collector "source_type=unknown" "source_url=https://example.invalid/g1" "raw_text=single source, no corroboration" >/dev/null
km advance G1 NORMALIZED "t" >/dev/null
out="$(km advance G1 VERIFIED "trying to skip record-evidence" 2>&1)"; rc=$?
assert_eq "G1 exit code" "1" "$rc"
assert_contains "G1 error names the out-of-scope target and points at record-evidence" "$out" "requires 'record-evidence'"
assert_eq "G1 status unchanged (still NORMALIZED)" "NORMALIZED" "$(km status G1)"

echo ""
echo "[G2] the exact forgery the final audit demonstrated is refused: 'advance ... VERIFIED ... evidence_corroborating_count=5' can no longer fabricate high-trust evidence for a single-source, uncorroborated report"
out="$(km advance G1 VERIFIED "forged evidence, not computed by incident_evidence.sh" evidence_source_type=vendor_advisory evidence_corroborating_count=5 evidence_age_days=0 evidence_self_reported_uncorroborated=false 2>&1)"; rc=$?
assert_eq "G2 exit code" "1" "$rc"
assert_eq "G2 status still NORMALIZED (forgery did not land)" "NORMALIZED" "$(km status G1)"
assert_eq "G2 no evidence_* fields were written" "" "$(python3 -c "import json; d=json.load(open('$FIXTURE_DIR/candidates/G1.json')); print(d.get('evidence_source_type',''))")"
events="$(grep '"candidate_id": "G1"' "$FIXTURE_DIR/incident-learning-audit.jsonl" | python3 -c "import json,sys; [print(json.loads(l)['event']) for l in sys.stdin]")"
assert_contains "G2 both attempts are audited as advance_scope_violation" "$events" "advance_scope_violation"

echo ""
echo "[G3] the legitimate replacement, 'record-evidence', works end to end and produces the same confidence outcome incident_evidence.sh itself would"
out="$(km record-evidence G1 "real evidence recorded" evidence_source_type=unknown evidence_corroborating_count=0 evidence_age_days=0 evidence_self_reported_uncorroborated=true)"; rc=$?
assert_eq "G3 exit code 0" "0" "$rc"
assert_eq "G3 status is VERIFIED" "VERIFIED" "$(km status G1)"
assert_eq "G3 evidence_source_type honestly recorded as unknown (not the earlier forged vendor_advisory)" "unknown" "$(python3 -c "import json; print(json.load(open('$FIXTURE_DIR/candidates/G1.json'))['evidence_source_type'])")"
km advance G1 ANALYZED "t" >/dev/null
out="$(bash security/incident_learning/incident_confidence.sh G1)"
assert_contains "G3 confidence.sh scores this the same way it would any weak, self-reported-uncorroborated candidate (low score)" "$out" "score=0"
assert_eq "G3 auto-rejected, never reaches the human gate (the property the forgery was defeating)" "REJECTED" "$(km status G1)"

echo ""
echo "[G4] record-evidence itself refuses any key outside the four recognized evidence fields (whitelist, not a blacklist -- closing the door to a new backdoor)"
km create G4 mock_collector "source_type=vendor_advisory" "source_url=https://example.invalid/g4" "raw_text=t" >/dev/null
km advance G4 NORMALIZED "t" >/dev/null
out="$(km record-evidence G4 "t" evidence_source_type=vendor_advisory some_other_field=whatever 2>&1)"; rc=$?
assert_eq "G4 exit code" "1" "$rc"
assert_contains "G4 error names the rejected field" "$out" "'some_other_field' is not a recognized evidence field"
assert_eq "G4 status unchanged (still NORMALIZED, no partial write)" "NORMALIZED" "$(km status G4)"
events4="$(grep '"candidate_id": "G4"' "$FIXTURE_DIR/incident-learning-audit.jsonl" | python3 -c "import json,sys; [print(json.loads(l)['event']) for l in sys.stdin]")"
assert_contains "G4 audited as evidence_scope_violation" "$events4" "evidence_scope_violation"

echo ""
echo "[G5] record-evidence also refuses a reserved field (e.g. confidence_score) smuggled in under its own name"
out="$(km record-evidence G4 "t" confidence_score=999 2>&1)"; rc=$?
assert_eq "G5 exit code" "1" "$rc"
assert_eq "G5 status unchanged" "NORMALIZED" "$(km status G4)"

echo ""
echo "[G6] record-evidence still honors the state machine: refused on a candidate not currently at NORMALIZED"
out="$(km record-evidence G4 "already past this stage" evidence_source_type=vendor_advisory 2>&1)"; rc=$?
km record-evidence G4 "real" evidence_source_type=vendor_advisory evidence_corroborating_count=1 evidence_age_days=0 evidence_self_reported_uncorroborated=false >/dev/null
assert_eq "G6 precondition: G4 now VERIFIED" "VERIFIED" "$(km status G4)"
out2="$(km record-evidence G4 "trying again on an already-VERIFIED candidate" evidence_source_type=cert 2>&1)"; rc2=$?
assert_eq "G6 second record-evidence exits non-zero" "true" "$([ "$rc2" != "0" ] && echo true || echo false)"
assert_eq "G6 status unchanged (still VERIFIED, not silently re-recorded)" "VERIFIED" "$(km status G4)"

echo ""
echo "[F1] the full pipeline end-to-end (collector -> normalizer -> evidence -> confidence -> cron) is unaffected by the hardening"
export INCIDENT_LEARNING_CRON_LOG="$FIXTURE_DIR/cron.log"
bash security/incident_learning/incident_learning_cron.sh >/dev/null
CRON_RC=$?
assert_eq "F1 cron wrapper still exits 0" "0" "$CRON_RC"
listing="$(km list)"
assert_contains "F1 mock collector's strong record still reaches CANDIDATE" "$listing" "MOCK-2026-0001|CANDIDATE"

echo ""
echo "[D1-boundary] DuCoPA boundary: this suite's own run never touched any real Control Plane file"
for real_file in security/egress_allowlist.conf security/segments.conf security/ssh_management_allowlist.conf; do
  if [ -f "$real_file" ]; then
    assert_eq "D1-boundary $real_file unchanged" "" "$(git diff --name-only -- "$real_file" 2>/dev/null)"
  fi
done

echo ""
echo "=== Summary: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
  echo "Failures:"
  printf '  - %s\n' "${FAILURES[@]}"
  exit 1
fi
exit 0
