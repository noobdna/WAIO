#!/bin/bash
set -uo pipefail

# tests/incident_learning_promote_test.sh -- regression suite for
# Incident Learning Engine Step 5: the Promote flow
# (knowledge_manager.sh's knowledge_promote(), invoked only via its own
# `promote` CLI command), built on top of Step 4's Human Gate
# (security/incident_learning/incident_human_gate.sh).
#
# Runs against scratch fixtures under a temp dir via
# KNOWLEDGE_MANAGER_STATE_DIR/KNOWLEDGE_MANAGER_AUDIT_LOG/
# KNOWLEDGE_MANAGER_KNOWLEDGE_DIR overrides (same convention as every
# other tests/incident_learning_*_test.sh) -- never touches this
# deployment's real security/state/incident_learning/ or
# security/knowledge/.

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

FIXTURE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/waio-incident-promote-test.XXXXXX")"
trap 'rm -rf "$FIXTURE_DIR"; true' EXIT

mkdir -p "$FIXTURE_DIR/candidates" "$FIXTURE_DIR/knowledge"
export KNOWLEDGE_MANAGER_STATE_DIR="$FIXTURE_DIR/candidates"
export KNOWLEDGE_MANAGER_AUDIT_LOG="$FIXTURE_DIR/incident-learning-audit.jsonl"
export KNOWLEDGE_MANAGER_KNOWLEDGE_DIR="$FIXTURE_DIR/knowledge"

km() { bash security/incident_learning/knowledge_manager.sh "$@"; }
hg() { bash security/incident_learning/incident_human_gate.sh "$@"; }
kfield() { python3 -c "import json; print(json.load(open('$FIXTURE_DIR/knowledge/$1.json')).get('$2',''))"; }
kfield_json() { python3 -c "import json; print(json.dumps(json.load(open('$FIXTURE_DIR/knowledge/$1.json')).get('$2', None)))"; }
audit_events_for() { grep "\"candidate_id\": \"$1\"" "$FIXTURE_DIR/incident-learning-audit.jsonl" | python3 -c "import json,sys; [print(json.loads(l)['event']) for l in sys.stdin]"; }
knowledge_count() { ls "$FIXTURE_DIR/knowledge" 2>/dev/null | wc -l | tr -d ' '; }

# make_candidate ID SCORE -- drives a fresh candidate through the real
# pipeline primitives up to SCORED->CANDIDATE/REJECTED, with a fixed
# evidence fingerprint (mirrors the fixture used by
# tests/incident_learning_human_gate_test.sh).
make_candidate() {
  local id="$1" score="$2"
  km create "$id" mock_collector \
    "source_type=vendor_advisory" "source_url=https://example.invalid/$id" \
    "raw_text=test incident $id" "cve_list=[\"CVE-2026-9$id\"]" >/dev/null
  km advance "$id" NORMALIZED "t" >/dev/null
  km record-evidence "$id" "t" \
    "evidence_source_type=vendor_advisory" "evidence_corroborating_count=2" \
    "evidence_age_days=1" "evidence_self_reported_uncorroborated=false" >/dev/null
  km advance "$id" ANALYZED "t" >/dev/null
  km score "$id" "$score" >/dev/null
}

echo "=== Incident Learning Engine (Step 5: promote flow) regression suite ==="

echo ""
echo "[P1] CANDIDATE -> APPROVED -> PROMOTED is the only path that ever writes into security/knowledge/"
make_candidate P1 60
assert_eq "P1 knowledge dir empty at CANDIDATE" "0" "$(knowledge_count)"
hg approve P1 "clear vendor advisory, corroborated" >/dev/null
assert_eq "P1 knowledge dir still empty at APPROVED" "0" "$(knowledge_count)"
km promote P1 >/dev/null
assert_eq "P1 status PROMOTED" "PROMOTED" "$(km status P1)"
assert_eq "P1 knowledge dir has exactly the one entry" "1" "$(knowledge_count)"

echo ""
echo "[P2] REJECTED cannot be promoted"
make_candidate P2 60
hg reject P2 "duplicate report" >/dev/null
out="$(km promote P2 2>&1)"; rc=$?
assert_ne "P2 promote exits non-zero" "0" "$rc"
assert_contains "P2 error names the actual status" "$out" "is 'REJECTED', not 'APPROVED'"
assert_eq "P2 no knowledge entry created" "" "$(ls "$FIXTURE_DIR/knowledge" 2>/dev/null | grep P2 || true)"

echo ""
echo "[P3] HOLD cannot be promoted"
make_candidate P3 60
hg hold P3 "need a second opinion" >/dev/null
out="$(km promote P3 2>&1)"; rc=$?
assert_ne "P3 promote exits non-zero" "0" "$rc"
assert_contains "P3 error names the actual status" "$out" "is 'HOLD', not 'APPROVED'"
assert_eq "P3 no knowledge entry created" "" "$(ls "$FIXTURE_DIR/knowledge" 2>/dev/null | grep P3 || true)"

echo ""
echo "[P4] a HOLD that was released back to CANDIDATE still cannot be promoted (release is not approval)"
make_candidate P4 60
hg hold P4 "pending" >/dev/null
hg release P4 "review done, back on queue" >/dev/null
assert_eq "P4 status is CANDIDATE after release" "CANDIDATE" "$(km status P4)"
out="$(km promote P4 2>&1)"; rc=$?
assert_ne "P4 promote exits non-zero" "0" "$rc"
assert_contains "P4 error names the actual status" "$out" "is 'CANDIDATE', not 'APPROVED'"
assert_eq "P4 no knowledge entry created" "" "$(ls "$FIXTURE_DIR/knowledge" 2>/dev/null | grep P4 || true)"

echo ""
echo "[P5] a candidate auto-rejected at SCORED (never even reaches CANDIDATE) cannot be promoted"
make_candidate P5 5
assert_eq "P5 auto-rejected" "REJECTED" "$(km status P5)"
out="$(km promote P5 2>&1)"; rc=$?
assert_ne "P5 promote exits non-zero" "0" "$rc"
assert_eq "P5 no knowledge entry created" "" "$(ls "$FIXTURE_DIR/knowledge" 2>/dev/null | grep P5 || true)"

echo ""
echo "[P6] traceability: the promoted knowledge entry carries the original incident, evidence, confidence, AND approval basis"
make_candidate P6 60
hg approve P6 "reviewed: CVE matches known pattern, 2 independent corroborating sources" >/dev/null
km promote P6 >/dev/null
assert_eq "P6 source_type preserved" "vendor_advisory" "$(kfield P6 source_type)"
assert_eq "P6 source_url preserved" "https://example.invalid/P6" "$(kfield P6 source_url)"
assert_contains "P6 raw_text preserved" "$(kfield P6 raw_text)" "test incident P6"
assert_eq "P6 evidence_corroborating_count preserved" "2" "$(kfield P6 evidence_corroborating_count)"
assert_eq "P6 confidence_score preserved" "60" "$(kfield P6 confidence_score)"
assert_eq "P6 source_candidate_id set" "P6" "$(kfield P6 source_candidate_id)"
assert_contains "P6 approval_reason carries the human's own reason text" "$(kfield P6 approval_reason)" "reviewed: CVE matches known pattern"
assert_contains "P6 approval_reason carries the embedded evidence basis" "$(kfield P6 approval_reason)" "evidence: source_type=vendor_advisory"
assert_ne "P6 approved_at is set (non-empty)" "" "$(kfield P6 approved_at)"
assert_ne "P6 promoted_at is set (non-empty)" "" "$(kfield P6 promoted_at)"
assert_eq "P6 status frozen at APPROVED in the knowledge copy (captured before the PROMOTED transition)" "APPROVED" "$(kfield P6 status)"

echo ""
echo "[P7] traceability also survives via the audit log's own full transition history for the same id"
events="$(audit_events_for P6)"
assert_contains "P7 audit trail includes collected" "$events" "collected"
assert_contains "P7 audit trail includes advanced (normalize/evidence/analyze)" "$events" "advanced"
assert_contains "P7 audit trail includes scored" "$events" "scored"
assert_contains "P7 audit trail includes candidate_ready" "$events" "candidate_ready"
assert_contains "P7 audit trail includes human_approved" "$events" "human_approved"
assert_contains "P7 audit trail includes promoted" "$events" "promoted"

echo ""
echo "[P8] idempotency: promoting the same candidate a second time is a safe no-op, not a duplicate/overwrite/error"
before_mtime="$(python3 -c "import os; print(os.path.getmtime('$FIXTURE_DIR/knowledge/P6.json'))")"
before_promoted_at="$(kfield P6 promoted_at)"
sleep 1.1
out="$(km promote P6)"; rc=$?
assert_eq "P8 second promote exits zero (no-op success)" "0" "$rc"
assert_contains "P8 log reports already PROMOTED" "$out" "already PROMOTED"
after_mtime="$(python3 -c "import os; print(os.path.getmtime('$FIXTURE_DIR/knowledge/P6.json'))")"
assert_eq "P8 knowledge file was NOT rewritten (mtime unchanged)" "$before_mtime" "$after_mtime"
assert_eq "P8 promoted_at unchanged" "$before_promoted_at" "$(kfield P6 promoted_at)"
assert_eq "P8 still exactly one knowledge entry for P6" "1" "$(ls "$FIXTURE_DIR/knowledge" | grep -c '^P6\.json$')"

echo ""
echo "[P9] a second, distinct promote attempt is itself audited (idempotent skip is not silent)"
events="$(audit_events_for P6)"
assert_contains "P9 audit trail includes promotion_skipped from the redundant call" "$events" "promotion_skipped"

echo ""
echo "[P10] promote refuses to overwrite a pre-existing knowledge file for a still-APPROVED candidate (defense in depth, not just the status check)"
make_candidate P10 60
hg approve P10 "ok" >/dev/null
mkdir -p "$FIXTURE_DIR/knowledge"
echo '{"tampered": true}' > "$FIXTURE_DIR/knowledge/P10.json"
out="$(km promote P10 2>&1)"; rc=$?
assert_ne "P10 promote refuses" "0" "$rc"
assert_contains "P10 error mentions the pre-existing file" "$out" "already exists"
assert_eq "P10 status remains APPROVED (not falsely marked PROMOTED)" "APPROVED" "$(km status P10)"
assert_eq "P10 the pre-existing (tampered) file is left untouched" "true" "$(python3 -c "import json; print(json.load(open('$FIXTURE_DIR/knowledge/P10.json')).get('tampered'))" | tr '[:upper:]' '[:lower:]')"

echo ""
echo "[P11] a knowledge-entry build failure leaves no partial file at the real path (no half-written knowledge)"
make_candidate P11 60
hg approve P11 "ok" >/dev/null
cpath="$FIXTURE_DIR/candidates/P11.json"
cp "$cpath" "$cpath.bak"
echo 'not valid json{{{' > "$cpath"
out="$(km promote P11 2>&1)"; rc=$?
assert_ne "P11 promote fails when the source state file is unreadable" "0" "$rc"
assert_eq "P11 no knowledge file was created" "" "$(ls "$FIXTURE_DIR/knowledge" 2>/dev/null | grep '^P11\.json$' || true)"
assert_eq "P11 no leftover tmp file in knowledge dir" "" "$(ls "$FIXTURE_DIR/knowledge" 2>/dev/null | grep 'P11.*\.tmp\.' || true)"
mv -f "$cpath.bak" "$cpath"
out2="$(km promote P11)"; rc2=$?
assert_eq "P11 promote succeeds once the state file is restored" "0" "$rc2"
assert_eq "P11 knowledge file now exists" "P11.json" "$(ls "$FIXTURE_DIR/knowledge" | grep '^P11\.json$')"

echo ""
echo "[P12] promote never touches any Control Plane path, even indirectly (static guard: no reference to those paths in knowledge_promote's own code)"
promote_fn_body="$(sed -n '/^knowledge_promote() {/,/^}/p' security/incident_learning/knowledge_manager.sh)"
assert_eq "P12 no egress_allowlist reference" "" "$(echo "$promote_fn_body" | grep -o 'egress_allowlist' || true)"
assert_eq "P12 no segments.conf reference" "" "$(echo "$promote_fn_body" | grep -o 'segments\.conf' || true)"
assert_eq "P12 no sshd_config reference" "" "$(echo "$promote_fn_body" | grep -o 'sshd_config' || true)"

echo ""
echo "[D1] DuCoPA boundary: this suite's own run never touched any real Control Plane file"
for real_file in security/egress_allowlist.conf security/segments.conf security/ssh_management_allowlist.conf; do
  if [ -f "$real_file" ]; then
    assert_eq "D1 $real_file unchanged" "" "$(git diff --name-only -- "$real_file" 2>/dev/null)"
  fi
done

echo ""
echo "[D2] no network tool is invoked by knowledge_manager.sh's promote path (static guard)"
net_calls="$(echo "$promote_fn_body" | grep -cE '\b(curl|wget|nc )\b' || true)"
assert_eq "D2 zero network-tool invocations" "0" "$net_calls"

echo ""
echo "=== Summary: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
  echo "Failures:"
  printf '  - %s\n' "${FAILURES[@]}"
  exit 1
fi
exit 0
