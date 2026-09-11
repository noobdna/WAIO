#!/bin/bash
set -uo pipefail

# tests/incident_learning_test.sh -- regression suite for the Incident
# Learning Engine's Step 1 safety backbone:
# security/incident_learning/knowledge_manager.sh.
#
# Everything here runs against scratch fixtures under a temp dir via
# KNOWLEDGE_MANAGER_STATE_DIR/KNOWLEDGE_MANAGER_AUDIT_LOG/
# KNOWLEDGE_MANAGER_KNOWLEDGE_DIR overrides -- this suite never reads
# or writes this deployment's real security/state/incident_learning/,
# logs/incident-learning-audit.jsonl, or security/knowledge/, and makes
# no network calls of any kind (this step has no collector wired in
# yet).

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

FIXTURE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/waio-incident-learning-test.XXXXXX")"
trap 'rm -rf "$FIXTURE_DIR"; true' EXIT

mkdir -p "$FIXTURE_DIR/candidates" "$FIXTURE_DIR/knowledge"
export KNOWLEDGE_MANAGER_STATE_DIR="$FIXTURE_DIR/candidates"
export KNOWLEDGE_MANAGER_AUDIT_LOG="$FIXTURE_DIR/incident-learning-audit.jsonl"
export KNOWLEDGE_MANAGER_KNOWLEDGE_DIR="$FIXTURE_DIR/knowledge"

km() { bash security/incident_learning/knowledge_manager.sh "$@"; }
field() { python3 -c "import json; print(json.load(open('$FIXTURE_DIR/candidates/$1.json')).get('$2',''))"; }

echo "=== Incident Learning Engine (Step 1: knowledge_manager.sh) regression suite ==="

echo ""
echo "[K1] creating a new candidate starts it at COLLECTED"
km create INC-1 "mock_collector" >/dev/null
assert_eq "K1 status COLLECTED" "COLLECTED" "$(km status INC-1)"

echo ""
echo "[K2] creating a duplicate id is refused, original untouched"
out="$(km create INC-1 "other_source" 2>&1)"; rc=$?
assert_eq "K2 exit code" "1" "$rc"
assert_contains "K2 error message" "$out" "already exists"
assert_eq "K2 status unchanged" "COLLECTED" "$(km status INC-1)"

echo ""
echo "[K3] the full happy-path pipeline: COLLECTED -> ... -> CANDIDATE"
km advance INC-1 NORMALIZED "structured successfully" >/dev/null
assert_eq "K3 NORMALIZED" "NORMALIZED" "$(km status INC-1)"
km advance INC-1 VERIFIED "evidence attached from 2 sources" >/dev/null
assert_eq "K3 VERIFIED" "VERIFIED" "$(km status INC-1)"
km advance INC-1 ANALYZED "checked against existing knowledge, novel pattern" >/dev/null
assert_eq "K3 ANALYZED" "ANALYZED" "$(km status INC-1)"
km score INC-1 82 >/dev/null
assert_eq "K3 CANDIDATE after score" "CANDIDATE" "$(km status INC-1)"
assert_eq "K3 confidence_score recorded" "82" "$(field INC-1 confidence_score)"

echo ""
echo "[K4] CRITICAL: no automatic path ever reaches PROMOTED -- CANDIDATE->PROMOTED is illegal"
out="$(km advance INC-1 PROMOTED "trying to skip the human gate" 2>&1)"; rc=$?
assert_eq "K4 exit code (rejected)" "1" "$rc"
assert_contains "K4 error message" "$out" "not allowed"
assert_eq "K4 status unchanged (still CANDIDATE)" "CANDIDATE" "$(km status INC-1)"

echo ""
echo "[K5] CRITICAL: approve/reject refuse a missing reason (the human gate always requires an explanation)"
out="$(km approve INC-1 2>&1)"; rc=$?
assert_eq "K5 approve without reason: exit code" "1" "$rc"
assert_contains "K5 approve without reason: usage error" "$out" "Usage:"
assert_eq "K5 status unchanged (still CANDIDATE)" "CANDIDATE" "$(km status INC-1)"
out="$(km reject INC-1 2>&1)"; rc=$?
assert_eq "K5 reject without reason: exit code" "1" "$rc"
assert_contains "K5 reject without reason: usage error" "$out" "Usage:"
assert_eq "K5 status still unchanged (still CANDIDATE)" "CANDIDATE" "$(km status INC-1)"

echo ""
echo "[K6] promote refuses unless status is APPROVED"
km create INC-2 "mock_collector" >/dev/null
out="$(km promote INC-2 2>&1)"; rc=$?
assert_eq "K6 exit code" "1" "$rc"
assert_contains "K6 error message" "$out" "not 'APPROVED'"

echo ""
echo "[K7] full path through the human gate: CANDIDATE -> APPROVED -> PROMOTED, and the knowledge file is actually written"
km advance INC-2 NORMALIZED "ok" >/dev/null
km advance INC-2 VERIFIED "ok" >/dev/null
km advance INC-2 ANALYZED "ok" >/dev/null
km score INC-2 91 >/dev/null
km approve INC-2 "reviewed by ops-1: matches known CVE pattern, corroborated by 3 independent sources" >/dev/null
assert_eq "K7 status APPROVED" "APPROVED" "$(km status INC-2)"
km promote INC-2 >/dev/null
assert_eq "K7 status PROMOTED" "PROMOTED" "$(km status INC-2)"
assert_eq "K7 knowledge file exists" "yes" "$([ -f "$FIXTURE_DIR/knowledge/INC-2.json" ] && echo yes || echo no)"

echo ""
echo "[K8] CRITICAL: a low-confidence / rejected candidate can never reach PROMOTED, at any stage"
km create INC-3 "mock_collector" >/dev/null
km advance INC-3 NORMALIZED "ok" >/dev/null
km reject INC-3 "single uncorroborated source, suspected disinformation" >/dev/null
assert_eq "K8 status REJECTED" "REJECTED" "$(km status INC-3)"
out="$(km promote INC-3 2>&1)"; rc=$?
assert_eq "K8 promote refused" "1" "$rc"
out="$(km advance INC-3 APPROVED "trying to resurrect a rejected candidate" 2>&1)"; rc=$?
assert_eq "K8 REJECTED->APPROVED refused" "1" "$rc"
assert_eq "K8 status still REJECTED" "REJECTED" "$(km status INC-3)"

echo ""
echo "[K9] every rejected transition attempt is still recorded in the audit log (nothing silently disappears)"
audit_rejections="$(grep -c "transition_rejected" "$FIXTURE_DIR/incident-learning-audit.jsonl")"
assert_eq "K9 at least 2 transition_rejected events logged" "true" "$([ "$audit_rejections" -ge 2 ] && echo true || echo false)"

echo ""
echo "[K10] list shows every known candidate with its current status"
listing="$(km list)"
assert_contains "K10 lists INC-1" "$listing" "INC-1|CANDIDATE|82|mock_collector"
assert_contains "K10 lists INC-2" "$listing" "INC-2|PROMOTED"
assert_contains "K10 lists INC-3" "$listing" "INC-3|REJECTED"

echo ""
echo "[K11] status on an unknown id fails, does not silently default"
out="$(km status NO-SUCH-ID 2>&1)"; rc=$?
assert_eq "K11 exit code" "1" "$rc"
assert_contains "K11 error message" "$out" "unknown candidate"

echo ""
echo "[K12] DuCoPA boundary: this suite's own fixture run never touched any real Control Plane file"
for real_file in security/egress_allowlist.conf security/segments.conf security/ssh_management_allowlist.conf; do
  if [ -f "$real_file" ]; then
    assert_eq "K12 $real_file unchanged (mtime check via git diff)" "" "$(git diff --name-only -- "$real_file" 2>/dev/null)"
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
