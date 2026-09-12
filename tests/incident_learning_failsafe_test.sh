#!/bin/bash
set -uo pipefail

# tests/incident_learning_failsafe_test.sh -- regression suite for
# Incident Learning Engine Step 8: Fail-safe / Recovery / Idempotency
# Hardening.
#
# Context: an audit of the current working tree (before this suite was
# written) found that knowledge_manager.sh, incident_evidence.sh, and
# incident_confidence.sh already carry "Step 8 crash-recovery" code --
# knowledge_promote()'s idempotent no-op + reconciliation branch, `km
# score`'s SCORED-resume branch, and incident_evidence.sh's
# VERIFIED-resume branch -- but NONE of the three had a test that
# actually exercises the crash-recovery branch itself (as opposed to
# the ordinary happy path or the fully-already-PROMOTED no-op, both
# already covered elsewhere -- see
# tests/incident_learning_promote_test.sh's P8/P10). This suite closes
# that gap: every test below manually reproduces the exact on-disk
# state a kill/crash at a specific point would leave, then asserts the
# resume behaves correctly -- no recompute, no duplicate write, no
# silent loss, no acceptance of a caller-supplied value that would
# override what was already safely persisted.
#
# Also covers: incident_normalizer.sh resuming a candidate crash-
# stranded at COLLECTED (create succeeded, advance never ran), and a
# Human Gate action (approve) re-run after it already succeeded once
# (the caller retrying because it didn't see the first success) being
# refused cleanly rather than double-recorded.
#
# Explicitly OUT of scope for this suite (see the audit report handed
# back to the user alongside this suite, not restated here):
#   - semantic duplicate-incident detection (VERIFIED->ANALYZED is
#     still incident_analyzer.sh's own not-yet-implemented placeholder
#     -- a pre-existing, documented gap, not a Step 8 concern)
#   - true concurrent-process locking (two invocations racing at the
#     exact same instant, as opposed to a sequential crash-then-rerun)
#     -- this codebase has no file-locking precedent anywhere
#     (segment_manager.sh included), so introducing one here alone
#     would be a new, inconsistent pattern, not a hardening of an
#     existing one
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

assert_ne() {
  local label="$1" not_expected="$2" actual="$3"
  if [ "$not_expected" != "$actual" ]; then
    PASS=$((PASS + 1)); echo "  PASS: $label"
  else
    FAIL=$((FAIL + 1)); FAILURES+=("$label (expected NOT '$not_expected')")
    echo "  FAIL: $label (expected NOT '$not_expected')"
  fi
}

FIXTURE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/waio-incident-failsafe-test.XXXXXX")"
trap 'rm -rf "$FIXTURE_DIR"; true' EXIT

mkdir -p "$FIXTURE_DIR/candidates" "$FIXTURE_DIR/knowledge"
export KNOWLEDGE_MANAGER_STATE_DIR="$FIXTURE_DIR/candidates"
export KNOWLEDGE_MANAGER_AUDIT_LOG="$FIXTURE_DIR/incident-learning-audit.jsonl"
export KNOWLEDGE_MANAGER_KNOWLEDGE_DIR="$FIXTURE_DIR/knowledge"

km() { bash security/incident_learning/knowledge_manager.sh "$@"; }
hg() { bash security/incident_learning/incident_human_gate.sh "$@"; }
evidence() { bash security/incident_learning/incident_evidence.sh "$@"; }
confidence() { bash security/incident_learning/incident_confidence.sh "$@"; }
normalize() { bash security/incident_learning/incident_normalizer.sh; }
field() { python3 -c "import json; print(json.load(open('$FIXTURE_DIR/candidates/$1.json')).get('$2',''))"; }
kfield() { python3 -c "import json; print(json.load(open('$FIXTURE_DIR/knowledge/$1.json')).get('$2',''))"; }
audit_events_for() { grep "\"candidate_id\": \"$1\"" "$FIXTURE_DIR/incident-learning-audit.jsonl" | python3 -c "import json,sys; [print(json.loads(l)['event']) for l in sys.stdin]"; }
audit_count() { wc -l < "$FIXTURE_DIR/incident-learning-audit.jsonl" | tr -d ' '; }
mtime() { python3 -c "import os; print(os.path.getmtime('$1'))"; }

# force_status ID STATUS PREV [KEY=VALUE ...] -- test-only helper that
# hand-edits a candidate's state file directly, bypassing
# knowledge_manager.sh's own CLI entirely. This is deliberately NOT
# something any real code path in this domain ever does (every real
# writer goes through candidate_transition's tmp+mv) -- it exists here
# only to reproduce, byte-for-byte, the exact on-disk state a
# kill/crash at one specific instant would leave, which cannot
# otherwise be reproduced deterministically in a test.
force_status() {
  local id="$1" status="$2"
  local path="$FIXTURE_DIR/candidates/$id.json"
  python3 -c "
import json, sys
p = sys.argv[1]
d = json.load(open(p))
d['status'] = sys.argv[2]
extra = json.loads(sys.argv[3])
d.update(extra)
json.dump(d, open(p, 'w'), ensure_ascii=False, indent=2)
" "$path" "$status" "$(_extras_json "${@:3}")"
}

_extras_json() {
  python3 -c "
import json, sys
d = {}
for kv in sys.argv[1:]:
    k, _, v = kv.partition('=')
    try:
        d[k] = json.loads(v)
    except (json.JSONDecodeError, ValueError):
        d[k] = v
print(json.dumps(d))
" "$@"
}

echo "=== Incident Learning Engine (Step 8: fail-safe / recovery / idempotency hardening) regression suite ==="

echo ""
echo "--- Promote crash-recovery: kill between the knowledge-file mv and the PROMOTED transition ---"

echo ""
echo "[R1] a genuine crash-recovery scenario: candidate is APPROVED, a matching knowledge file already sits at the real path (as knowledge_promote's own atomic mv would leave it), but the candidate's own status was never advanced past APPROVED -- promote must reconcile, not error and not rewrite"
km create R1 mock_collector "source_type=vendor_advisory" "source_url=https://example.invalid/R1" "raw_text=test incident R1" "cve_list=[\"CVE-2026-9001\"]" >/dev/null
km advance R1 NORMALIZED "t" >/dev/null
km record-evidence R1 "t" "evidence_source_type=vendor_advisory" "evidence_corroborating_count=2" "evidence_age_days=1" "evidence_self_reported_uncorroborated=false" >/dev/null
km advance R1 ANALYZED "t" >/dev/null
km score R1 60 >/dev/null
hg approve R1 "reviewed: matches known pattern" >/dev/null
pre_promote_updated_at="$(field R1 updated_at)"
km promote R1 >/dev/null
assert_eq "R1 precondition: full real promote succeeded first" "PROMOTED" "$(km status R1)"
kpath_mtime_before="$(mtime "$FIXTURE_DIR/knowledge/R1.json")"
# Simulate the crash: roll the candidate's own state file back to
# exactly what it was the instant before knowledge_promote()'s own
# candidate_transition call -- the knowledge file itself (already
# written by the real promote() above) is left untouched, exactly as
# a kill between the `mv -f "$tmp" "$kpath"` and the candidate_transition
# call below it would leave things.
force_status R1 APPROVED "previous_status=CANDIDATE" "updated_at=$pre_promote_updated_at"
assert_eq "R1 simulated crash state: candidate rolled back to APPROVED" "APPROVED" "$(km status R1)"
before_count="$(audit_count)"
out="$(km promote R1)"; rc=$?
assert_eq "R1 reconciling promote exits zero" "0" "$rc"
assert_contains "R1 log reports crash-recovery reconciliation" "$out" "crash-recovery"
assert_eq "R1 status is PROMOTED again after reconciliation" "PROMOTED" "$(km status R1)"
kpath_mtime_after="$(mtime "$FIXTURE_DIR/knowledge/R1.json")"
assert_eq "R1 knowledge file was NOT rewritten (mtime unchanged)" "$kpath_mtime_before" "$kpath_mtime_after"
assert_eq "R1 still exactly one knowledge entry for R1" "1" "$(ls "$FIXTURE_DIR/knowledge" | grep -c '^R1\.json$')"
events="$(audit_events_for R1)"
assert_contains "R1 audit trail records promotion_reconciled" "$events" "promotion_reconciled"
after_count="$(audit_count)"
assert_eq "R1 reconciliation adds exactly 2 audit lines (reconciled + promoted), not a rebuild" "true" "$([ "$((after_count - before_count))" -eq 2 ] && echo true || echo false)"

echo ""
echo "[R2] reconciliation still refuses a knowledge file that does not actually match (defense-in-depth kept even with the new reconcile path)"
km create R2 mock_collector "source_type=vendor_advisory" "source_url=https://example.invalid/R2" "raw_text=test incident R2" >/dev/null
km advance R2 NORMALIZED "t" >/dev/null
km record-evidence R2 "t" "evidence_source_type=vendor_advisory" "evidence_corroborating_count=1" "evidence_age_days=0" "evidence_self_reported_uncorroborated=false" >/dev/null
km advance R2 ANALYZED "t" >/dev/null
km score R2 60 >/dev/null
hg approve R2 "ok" >/dev/null
mkdir -p "$FIXTURE_DIR/knowledge"
echo '{"source_candidate_id": "R2", "status": "APPROVED", "approved_at": "1999-01-01T00:00:00.000Z"}' > "$FIXTURE_DIR/knowledge/R2.json"
out="$(km promote R2 2>&1)"; rc=$?
assert_ne "R2 mismatched pre-existing file is refused" "0" "$rc"
assert_contains "R2 error mentions the pre-existing file, not a silent reconcile" "$out" "does not match"
assert_eq "R2 status remains APPROVED (not falsely marked PROMOTED)" "APPROVED" "$(km status R2)"

echo ""
echo "--- Evidence crash-recovery: kill between NORMALIZED->VERIFIED and VERIFIED->ANALYZED ---"

echo ""
echo "[R3] a candidate crash-stranded at VERIFIED (evidence fields already recorded, the ANALYZED write never happened) resumes without recomputing evidence"
km create R3 mock_collector "source_type=vendor_advisory" "source_url=https://example.invalid/R3" "raw_text=test incident R3" "collected_at=2026-09-01T00:00:00Z" >/dev/null
km advance R3 NORMALIZED "t" >/dev/null
km record-evidence R3 "evidence recorded: source_type=vendor_advisory, corroborating=3, age_days=11, self_reported_uncorroborated=false" \
  "evidence_source_type=vendor_advisory" "evidence_corroborating_count=3" "evidence_age_days=11" "evidence_self_reported_uncorroborated=false" >/dev/null
assert_eq "R3 simulated crash state: VERIFIED" "VERIFIED" "$(km status R3)"
before_count="$(audit_count)"
out="$(evidence R3)"
assert_contains "R3 log reports resuming from VERIFIED" "$out" "resuming from VERIFIED"
assert_eq "R3 final status ANALYZED" "ANALYZED" "$(km status R3)"
assert_eq "R3 evidence_corroborating_count preserved from the interrupted run, not recomputed" "3" "$(field R3 evidence_corroborating_count)"
assert_eq "R3 evidence_age_days preserved from the interrupted run, not recomputed" "11" "$(field R3 evidence_age_days)"
after_count="$(audit_count)"
assert_eq "R3 resume adds exactly one audit line (the ANALYZED advance), no duplicate VERIFIED write" "true" "$([ "$((after_count - before_count))" -eq 1 ] && echo true || echo false)"

echo ""
echo "[R4] re-running incident_evidence.sh's own full loop over a mix of fresh and crash-stranded candidates handles both correctly in one pass"
km create R4A mock_collector "source_type=vendor_advisory" "source_url=https://example.invalid/R4A" "raw_text=fresh candidate" "collected_at=2026-09-10T00:00:00Z" >/dev/null
km advance R4A NORMALIZED "t" >/dev/null
km create R4B mock_collector "source_type=cert" "source_url=https://example.invalid/R4B" "raw_text=stranded candidate" "collected_at=2026-09-05T00:00:00Z" >/dev/null
km advance R4B NORMALIZED "t" >/dev/null
km record-evidence R4B "t" "evidence_source_type=cert" "evidence_corroborating_count=0" "evidence_age_days=7" "evidence_self_reported_uncorroborated=false" >/dev/null
bash security/incident_learning/incident_evidence.sh >/dev/null
assert_eq "R4 fresh candidate reaches ANALYZED" "ANALYZED" "$(km status R4A)"
assert_eq "R4 stranded candidate also reaches ANALYZED via the same full-loop invocation" "ANALYZED" "$(km status R4B)"

echo ""
echo "--- Confidence/score crash-recovery: kill between ANALYZED->SCORED and SCORED->CANDIDATE/REJECTED ---"

echo ""
echo "[R5] 'km score' resumes a candidate crash-stranded at SCORED using the ALREADY-PERSISTED confidence_score, ignoring a different caller-supplied value"
km create R5 mock_collector "source_type=vendor_advisory" "source_url=https://example.invalid/R5" "raw_text=t" >/dev/null
km advance R5 NORMALIZED "t" >/dev/null
km record-evidence R5 "t" "evidence_source_type=vendor_advisory" "evidence_corroborating_count=1" "evidence_age_days=0" "evidence_self_reported_uncorroborated=false" >/dev/null
km advance R5 ANALYZED "t" >/dev/null
force_status R5 SCORED "previous_status=ANALYZED" "confidence_score=77"
assert_eq "R5 simulated crash state: SCORED with confidence_score=77 persisted" "SCORED" "$(km status R5)"
out="$(km score R5 999)"; rc=$?
assert_eq "R5 resumed score exits zero" "0" "$rc"
assert_contains "R5 log reports resuming from SCORED with the persisted value" "$out" "resuming from SCORED (confidence_score=77"
assert_eq "R5 final status uses the PERSISTED score (77 >= 50 -> CANDIDATE), not the caller's bogus 999" "CANDIDATE" "$(km status R5)"
assert_eq "R5 confidence_score on record is still 77, never overwritten by the caller's 999" "77" "$(field R5 confidence_score)"
events="$(audit_events_for R5)"
assert_contains "R5 audit trail records score_resumed" "$events" "score_resumed"

echo ""
echo "[R6] the same crash-stranded-at-SCORED resume also works end-to-end through incident_confidence.sh's own entry point, and correctly resolves to REJECTED when the persisted score is below threshold"
km create R6 mock_collector "source_type=unknown" "source_url=https://example.invalid/R6" "raw_text=t" >/dev/null
km advance R6 NORMALIZED "t" >/dev/null
km record-evidence R6 "t" "evidence_source_type=unknown" "evidence_corroborating_count=0" "evidence_age_days=0" "evidence_self_reported_uncorroborated=false" >/dev/null
km advance R6 ANALYZED "t" >/dev/null
force_status R6 SCORED "previous_status=ANALYZED" "confidence_score=5"
out="$(confidence R6)"
assert_contains "R6 incident_confidence.sh reports the persisted low score" "$out" "score=5"
assert_eq "R6 resolves to REJECTED using the persisted score" "REJECTED" "$(km status R6)"

echo ""
echo "--- Normalizer crash-recovery: kill between candidate_create (COLLECTED) and the NORMALIZED advance ---"

echo ""
echo "[R7] a candidate crash-stranded at COLLECTED (create already ran, the id already exists) is picked back up by a re-run of the SAME raw record, not treated as a duplicate creation"
km create R7 mock_collector "source_type=vendor_advisory" "source_url=https://example.invalid/R7" "raw_text=CVE-2026-77777 present. Detection point: unusual traffic." "collected_at=2026-09-11T00:00:00Z" >/dev/null
assert_eq "R7 simulated crash state: COLLECTED (create ran, advance never did)" "COLLECTED" "$(km status R7)"
before_collected_events="$(audit_events_for R7 | grep -c '^collected$')"
raw_line='{"id":"R7","source":"mock_collector","source_type":"vendor_advisory","source_url":"https://example.invalid/R7","collected_at":"2026-09-11T00:00:00Z","raw_text":"CVE-2026-77777 present. Detection point: unusual traffic."}'
out="$(echo "$raw_line" | normalize)"
assert_contains "R7 does not re-announce a new candidate creation" "$out" "NORMALIZED"
assert_eq "R7 status is now NORMALIZED" "NORMALIZED" "$(km status R7)"
assert_eq "R7 CVE still correctly extracted on the resumed run" '["CVE-2026-77777"]' "$(python3 -c "import json; print(json.dumps(json.load(open('$FIXTURE_DIR/candidates/R7.json'))['cve_list']))")"
after_collected_events="$(audit_events_for R7 | grep -c '^collected$')"
assert_eq "R7 no second 'collected' (creation) audit event from the resumed run" "$before_collected_events" "$after_collected_events"

echo ""
echo "--- Human Gate re-run: retrying an action that already succeeded must not double-record or corrupt state ---"

echo ""
echo "[R8] re-running 'approve' on a candidate that is already APPROVED (caller retrying after not seeing the first success) is refused cleanly, not double-recorded"
km create R8 mock_collector "source_type=vendor_advisory" "source_url=https://example.invalid/R8" "raw_text=t" >/dev/null
km advance R8 NORMALIZED "t" >/dev/null
km record-evidence R8 "t" "evidence_source_type=vendor_advisory" "evidence_corroborating_count=1" "evidence_age_days=0" "evidence_self_reported_uncorroborated=false" >/dev/null
km advance R8 ANALYZED "t" >/dev/null
km score R8 60 >/dev/null
hg approve R8 "first approval" >/dev/null
assert_eq "R8 precondition: APPROVED" "APPROVED" "$(km status R8)"
out="$(hg approve R8 "retry: I don't think the first one went through" 2>&1)"; rc=$?
assert_ne "R8 re-approve exits non-zero" "0" "$rc"
assert_contains "R8 names the actual (already-APPROVED) status" "$out" "is 'APPROVED'"
assert_eq "R8 status unchanged (still APPROVED, not corrupted)" "APPROVED" "$(km status R8)"
events="$(audit_events_for R8 | grep -c '^human_approved$')"
assert_eq "R8 exactly one human_approved event on record, the retry was not double-recorded" "1" "$events"

echo ""
echo "[R9] re-running 'promote' after a fully successful promote (the ordinary already-PROMOTED case) remains a safe no-op alongside the new reconcile path (no regression from R1's change)"
km create R9 mock_collector "source_type=vendor_advisory" "source_url=https://example.invalid/R9" "raw_text=t" >/dev/null
km advance R9 NORMALIZED "t" >/dev/null
km record-evidence R9 "t" "evidence_source_type=vendor_advisory" "evidence_corroborating_count=1" "evidence_age_days=0" "evidence_self_reported_uncorroborated=false" >/dev/null
km advance R9 ANALYZED "t" >/dev/null
km score R9 60 >/dev/null
hg approve R9 "ok" >/dev/null
km promote R9 >/dev/null
assert_eq "R9 precondition: PROMOTED" "PROMOTED" "$(km status R9)"
out="$(km promote R9)"; rc=$?
assert_eq "R9 second promote exits zero (no-op)" "0" "$rc"
assert_contains "R9 log reports already PROMOTED" "$out" "already PROMOTED"
assert_eq "R9 still exactly one knowledge entry" "1" "$(ls "$FIXTURE_DIR/knowledge" | grep -c '^R9\.json$')"

echo ""
echo "--- Traceability survives crash-recovery ---"

echo ""
echo "[R10] the reconciled candidate's audit trail (R1) still carries the full chain end to end, including the recovery step itself"
events="$(audit_events_for R1)"
assert_contains "R10 audit trail includes collected" "$events" "collected"
assert_contains "R10 audit trail includes human_approved" "$events" "human_approved"
assert_contains "R10 audit trail includes promotion_reconciled" "$events" "promotion_reconciled"
assert_contains "R10 audit trail includes a terminal promoted event" "$events" "promoted"
assert_eq "R10 knowledge entry itself still names its source candidate" "R1" "$(kfield R1 source_candidate_id)"

echo ""
echo "--- DuCoPA / Control Plane boundary ---"

echo ""
echo "[D1] DuCoPA boundary: this suite's own run never touched any real Control Plane file"
for real_file in security/egress_allowlist.conf security/segments.conf security/ssh_management_allowlist.conf; do
  if [ -f "$real_file" ]; then
    assert_eq "D1 $real_file unchanged" "" "$(git diff --name-only -- "$real_file" 2>/dev/null)"
  fi
done

echo ""
echo "[D2] no network tool is invoked anywhere in the files this suite exercises (static guard)"
net_calls=0
for f in security/incident_learning/knowledge_manager.sh security/incident_learning/incident_evidence.sh security/incident_learning/incident_confidence.sh security/incident_learning/incident_normalizer.sh security/incident_learning/incident_human_gate.sh; do
  net_calls=$((net_calls + $(grep -cE '\b(curl|wget|nc )\b' "$f" || true)))
done
assert_eq "D2 zero network-tool invocations" "0" "$net_calls"

echo ""
echo "[D3] this suite's own test-only force_status helper never touched a Control Plane path (static guard on the helper itself)"
force_status_fn_body="$(sed -n '/^force_status() {/,/^}/p' "$0")"
assert_eq "D3 force_status has no egress_allowlist reference" "" "$(echo "$force_status_fn_body" | grep -o 'egress_allowlist' || true)"
assert_eq "D3 force_status has no segments.conf reference" "" "$(echo "$force_status_fn_body" | grep -o 'segments\.conf' || true)"

echo ""
echo "=== Summary: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
  echo "Failures:"
  printf '  - %s\n' "${FAILURES[@]}"
  exit 1
fi
exit 0
