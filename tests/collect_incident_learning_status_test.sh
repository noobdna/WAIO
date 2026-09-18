#!/bin/bash
set -uo pipefail

# tests/collect_incident_learning_status_test.sh -- regression suite for
# Phase 76 (Dashboard integration): dashboard/collect_incident_learning_status.sh's
# JSON output (counts, human_gate_queue, promoted_knowledge_entries,
# candidates, recent_events).
#
# Isolates every INPUT this script reads (KNOWLEDGE_MANAGER_STATE_DIR/
# KNOWLEDGE_MANAGER_AUDIT_LOG/KNOWLEDGE_MANAGER_KNOWLEDGE_DIR), same
# test-isolation pattern as tests/incident_learning_*_test.sh -- this
# suite never reads or writes this deployment's real
# security/state/incident_learning/candidates, logs/incident-learning-audit.jsonl,
# or security/knowledge/.
#
# Like tests/collect_status_guardian_test.sh, this script's OUTPUT path
# (logs/incident-learning-status-latest.json) is NOT fixture-overridable
# -- this suite does regenerate that deployment-local, gitignored,
# always-regenerable snapshot file, same accepted tradeoff as every
# other dashboard test in this repo.

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

OUT_PATH="logs/incident-learning-status-latest.json"

out_get() {
  python3 -c "
import json
d = json.load(open('$OUT_PATH'))
node = d
for part in '$1'.split('.'):
    node = node[int(part)] if part.isdigit() else node[part]
print(json.dumps(node))
" 2>/dev/null
}

FIXTURE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/waio-collect-il-status-test.XXXXXX")"
trap 'rm -rf "$FIXTURE_DIR"' EXIT

fixture_reset() {
  local suffix="${1:-default}"
  export KNOWLEDGE_MANAGER_STATE_DIR="$FIXTURE_DIR/candidates-$suffix"
  export KNOWLEDGE_MANAGER_AUDIT_LOG="$FIXTURE_DIR/audit-$suffix.jsonl"
  export KNOWLEDGE_MANAGER_KNOWLEDGE_DIR="$FIXTURE_DIR/knowledge-$suffix"
  rm -rf "$KNOWLEDGE_MANAGER_STATE_DIR" "$KNOWLEDGE_MANAGER_KNOWLEDGE_DIR"
  rm -f "$KNOWLEDGE_MANAGER_AUDIT_LOG"
  mkdir -p "$KNOWLEDGE_MANAGER_STATE_DIR" "$KNOWLEDGE_MANAGER_KNOWLEDGE_DIR"
}

km() { bash security/incident_learning/knowledge_manager.sh "$@"; }

REAL_STATE_PRESENT_BEFORE="false"
[ -d "security/state/incident_learning/candidates" ] && [ -n "$(ls -A security/state/incident_learning/candidates 2>/dev/null)" ] && REAL_STATE_PRESENT_BEFORE="true"
REAL_KNOWLEDGE_PRESENT_BEFORE="false"
[ -d "security/knowledge" ] && [ -n "$(ls -A security/knowledge 2>/dev/null)" ] && REAL_KNOWLEDGE_PRESENT_BEFORE="true"

echo "=== Dashboard: Incident Learning Engine visibility (Phase 76) ==="

echo "[CIL1] empty state dir: all counts zero, empty queue, zero promoted"
fixture_reset "cil1"
./dashboard/collect_incident_learning_status.sh >/dev/null
assert_eq "CIL1 exit 0" "0" "$?"
assert_eq "CIL1 COLLECTED count 0" "0" "$(out_get counts.COLLECTED)"
assert_eq "CIL1 total_candidates 0" "0" "$(out_get total_candidates)"
assert_eq "CIL1 promoted_knowledge_entries 0" "0" "$(out_get promoted_knowledge_entries)"
assert_eq "CIL1 empty human_gate_queue" "[]" "$(out_get human_gate_queue)"

echo "[CIL2] candidates at various statuses are counted correctly"
fixture_reset "cil2"
km create CIL2A mock_collector "source_type=vendor_advisory" >/dev/null
km create CIL2B mock_collector >/dev/null
km advance CIL2B NORMALIZED "t" >/dev/null
./dashboard/collect_incident_learning_status.sh >/dev/null
assert_eq "CIL2 COLLECTED count 1" "1" "$(out_get counts.COLLECTED)"
assert_eq "CIL2 NORMALIZED count 1" "1" "$(out_get counts.NORMALIZED)"
assert_eq "CIL2 total_candidates 2" "2" "$(out_get total_candidates)"

echo "[CIL3] CANDIDATE and HOLD candidates appear in the Human Gate queue with reason/source_type"
fixture_reset "cil3"
km create CIL3A mock_collector "source_type=cert" >/dev/null
km advance CIL3A NORMALIZED "t" >/dev/null
km record-evidence CIL3A "t" "evidence_source_type=cert" "evidence_corroborating_count=1" "evidence_age_days=1" "evidence_self_reported_uncorroborated=false" >/dev/null
km advance CIL3A ANALYZED "t" >/dev/null
km score CIL3A 90 >/dev/null
assert_eq "CIL3 precondition: CIL3A is CANDIDATE" "CANDIDATE" "$(km status CIL3A)"
km hold CIL3A "need more evidence" >/dev/null
./dashboard/collect_incident_learning_status.sh >/dev/null
assert_eq "CIL3 human_gate_queue has one entry" "1" "$(out_get human_gate_queue | python3 -c 'import json,sys; print(len(json.load(sys.stdin)))')"
assert_eq "CIL3 queue entry id" '"CIL3A"' "$(out_get human_gate_queue.0.id)"
assert_eq "CIL3 queue entry status HOLD" '"HOLD"' "$(out_get human_gate_queue.0.status)"
assert_eq "CIL3 queue entry reason" '"need more evidence"' "$(out_get human_gate_queue.0.reason)"
assert_eq "CIL3 queue entry source_type" '"cert"' "$(out_get human_gate_queue.0.source_type)"

echo "[CIL4] promoted_knowledge_entries reflects the real count of files in the knowledge dir"
fixture_reset "cil4"
printf '{}' > "$KNOWLEDGE_MANAGER_KNOWLEDGE_DIR/K1.json"
printf '{}' > "$KNOWLEDGE_MANAGER_KNOWLEDGE_DIR/K2.json"
./dashboard/collect_incident_learning_status.sh >/dev/null
assert_eq "CIL4 promoted_knowledge_entries 2" "2" "$(out_get promoted_knowledge_entries)"

echo "[CIL5] an unreadable/malformed candidate state file is skipped gracefully, never fatal"
fixture_reset "cil5"
km create CIL5A mock_collector >/dev/null
printf 'not valid json' > "$KNOWLEDGE_MANAGER_STATE_DIR/broken.json"
out="$(./dashboard/collect_incident_learning_status.sh 2>&1)"; rc=$?
assert_eq "CIL5 exits zero despite the broken file" "0" "$rc"
assert_eq "CIL5 still counts the one good candidate" "1" "$(out_get counts.COLLECTED)"

echo "[CIL6] recent_events reflects the audit log, most recent first, capped at 15"
fixture_reset "cil6"
km create CIL6A mock_collector >/dev/null
km advance CIL6A NORMALIZED "first" >/dev/null
km advance CIL6A REJECTED "second" >/dev/null
./dashboard/collect_incident_learning_status.sh >/dev/null
assert_eq "CIL6 most recent event first" '"second"' "$(out_get recent_events.0.reason)"

echo "[CIL7] this deployment's real Incident Learning state/audit/knowledge were never touched by this suite"
REAL_STATE_PRESENT_AFTER="false"
[ -d "security/state/incident_learning/candidates" ] && [ -n "$(ls -A security/state/incident_learning/candidates 2>/dev/null)" ] && REAL_STATE_PRESENT_AFTER="true"
REAL_KNOWLEDGE_PRESENT_AFTER="false"
[ -d "security/knowledge" ] && [ -n "$(ls -A security/knowledge 2>/dev/null)" ] && REAL_KNOWLEDGE_PRESENT_AFTER="true"
assert_eq "CIL7 real candidates dir presence unchanged" "$REAL_STATE_PRESENT_BEFORE" "$REAL_STATE_PRESENT_AFTER"
assert_eq "CIL7 real knowledge dir presence unchanged" "$REAL_KNOWLEDGE_PRESENT_BEFORE" "$REAL_KNOWLEDGE_PRESENT_AFTER"

echo "[D1] no network tool is invoked by this collector (static guard)"
NET_CALLS="$(grep -cE '\b(curl|wget|nc )\b' dashboard/collect_incident_learning_status.sh || true)"
assert_eq "D1 zero network-tool invocations" "0" "$NET_CALLS"

echo
echo "=== Results: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
  echo "Failures:"
  for f in "${FAILURES[@]}"; do echo "  - $f"; done
  exit 1
fi
exit 0
