#!/bin/bash
set -uo pipefail

# tests/incident_learning_cron_test.sh -- regression suite for
# Incident Learning Engine Step 6:
# security/incident_learning/incident_learning_cron.sh.
#
# Same posture as tests/segment_monitor_cron_test.sh (this suite's own
# direct model): the wrapper itself adds no new logic -- it only
# sequences already-tested entry points (every collectors/*.sh piped
# through incident_normalizer.sh, then incident_evidence.sh, then
# incident_analyzer.sh (Phase 75), then incident_confidence.sh) and
# logs when it ran. This suite checks that
# plumbing, not the pipeline stages themselves (already covered by
# tests/incident_learning_collector_test.sh and
# tests/incident_learning_evidence_test.sh) -- with one exception
# (CR6) that is the entire point of Step 6's safety design: this
# wrapper must NEVER reach the Human Gate or Promote.
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

FIXTURE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/waio-incident-cron-test.XXXXXX")"
EXTRA_COLLECTOR="security/incident_learning/collectors/__test_extra_collector.sh"
trap 'rm -rf "$FIXTURE_DIR"; rm -f "$EXTRA_COLLECTOR"; true' EXIT

mkdir -p "$FIXTURE_DIR/candidates" "$FIXTURE_DIR/knowledge"
export KNOWLEDGE_MANAGER_STATE_DIR="$FIXTURE_DIR/candidates"
export KNOWLEDGE_MANAGER_AUDIT_LOG="$FIXTURE_DIR/incident-learning-audit.jsonl"
export KNOWLEDGE_MANAGER_KNOWLEDGE_DIR="$FIXTURE_DIR/knowledge"
export INCIDENT_LEARNING_CRON_LOG="$FIXTURE_DIR/incident-learning-cron.log"

km() { bash security/incident_learning/knowledge_manager.sh "$@"; }

echo "=== Incident Learning Cron (Step 6) regression suite ==="

echo ""
echo "[CR1] wrapper exits 0 on a normal run"
bash security/incident_learning/incident_learning_cron.sh
CR1_RC=$?
assert_eq "CR1 exit code 0" "0" "$CR1_RC"

echo ""
echo "[CR2] wrapper's own run log records start/end and each sub-step result"
CR2_LOG="$(cat "$FIXTURE_DIR/incident-learning-cron.log" 2>/dev/null || true)"
assert_contains "CR2 log has run start" "$CR2_LOG" "run start"
assert_contains "CR2 log has collector/normalizer result" "$CR2_LOG" "mock_collector.sh | incident_normalizer.sh: ok"
assert_contains "CR2 log has incident_evidence.sh result" "$CR2_LOG" "incident_evidence.sh: ok"
assert_contains "CR2 log has incident_analyzer.sh result" "$CR2_LOG" "incident_analyzer.sh: ok"
assert_contains "CR2 log has incident_confidence.sh result" "$CR2_LOG" "incident_confidence.sh: ok"
assert_contains "CR2 log has run end" "$CR2_LOG" "run end"

echo ""
echo "[CR3] the automated pipeline actually ran end to end: mock_collector's 5 fixed records reached CANDIDATE or REJECTED, nothing left earlier in the pipeline"
listing="$(km list)"
stuck=0
for id in MOCK-2026-0001 MOCK-2026-0002 MOCK-2026-0003 MOCK-2026-0004 MOCK-2026-0005; do
  st="$(km status "$id")"
  case "$st" in
    CANDIDATE|REJECTED) ;;
    *) stuck=$((stuck + 1)); echo "    unexpected: $id is $st" ;;
  esac
done
assert_eq "CR3 zero candidates stuck before CANDIDATE/REJECTED" "0" "$stuck"
assert_contains "CR3 MOCK-2026-0001 (strong, corroborated) reached CANDIDATE" "$listing" "MOCK-2026-0001|CANDIDATE"

echo ""
echo "[CR4] running the wrapper a second time is a safe no-op (idempotent): no duplicate candidates, same final statuses"
before_listing="$(km list | sort)"
before_audit_lines="$(wc -l < "$FIXTURE_DIR/incident-learning-audit.jsonl" | tr -d ' ')"
bash security/incident_learning/incident_learning_cron.sh
CR4_RC=$?
assert_eq "CR4 second run exit code 0" "0" "$CR4_RC"
after_listing="$(km list | sort)"
assert_eq "CR4 candidate listing unchanged (no duplicates, no re-processing)" "$before_listing" "$after_listing"
after_audit_lines="$(wc -l < "$FIXTURE_DIR/incident-learning-audit.jsonl" | tr -d ' ')"
assert_eq "CR4 no new audit events from the redundant second run" "true" "$([ "$after_audit_lines" -eq "$before_audit_lines" ] && echo true || echo false)"

echo ""
echo "[CR5] CANDIDATE is never auto-reflected into security/knowledge/ by this schedule -- the knowledge dir stays empty across both runs"
assert_eq "CR5 knowledge dir is empty" "0" "$(ls "$FIXTURE_DIR/knowledge" 2>/dev/null | wc -l | tr -d ' ')"

echo ""
echo "[CR6] CRITICAL: this wrapper never touches the Human Gate or Promote -- no human_approved/human_rejected/human_held/human_hold_released/promoted event exists anywhere in its own audit trail"
gate_events="$(python3 -c "
import json
bad = {'human_approved','human_rejected','human_held','human_hold_released','promoted','promotion_skipped'}
count = 0
with open('$FIXTURE_DIR/incident-learning-audit.jsonl') as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        if json.loads(line).get('event') in bad:
            count += 1
print(count)
")"
assert_eq "CR6 zero human-gate/promote events anywhere in the audit trail" "0" "$gate_events"

echo ""
echo "[CR7] adding a second collector is picked up automatically, with no change to the wrapper itself"
cat > "$EXTRA_COLLECTOR" <<'EOF'
#!/bin/bash
echo '{"id":"CRTEST-0001","source":"test_extra_collector","source_type":"news","source_url":"https://example.invalid/extra","collected_at":"2026-01-01T00:00:00Z","raw_text":"extra collector smoke record"}'
EOF
chmod +x "$EXTRA_COLLECTOR"
bash security/incident_learning/incident_learning_cron.sh
CR7_RC=$?
rm -f "$EXTRA_COLLECTOR"
assert_eq "CR7 exit code 0 with the extra collector present" "0" "$CR7_RC"
assert_eq "CR7 the extra collector's own record was picked up" "true" "$(km status CRTEST-0001 >/dev/null 2>&1 && echo true || echo false)"
CR7_LOG="$(cat "$FIXTURE_DIR/incident-learning-cron.log")"
assert_contains "CR7 log names the extra collector by its own filename" "$CR7_LOG" "__test_extra_collector.sh | incident_normalizer.sh: ok"

echo ""
echo "[CR8] script is executable (as launchd/cron will invoke it directly)"
assert_eq "CR8 executable bit set" "true" "$([ -x security/incident_learning/incident_learning_cron.sh ] && echo true || echo false)"

echo ""
echo "[CR9] runtime-wiring audit: the launchd plist TEMPLATE's ProgramArguments actually points at THIS cron script's real, executable, repo-relative path -- this is the only scheduled entry point into the whole pipeline (no registry/dashboard/other WAIO code path calls into Incident Learning at all; runtime audit 2026-09-12 confirmed zero references outside security/incident_learning/ and tests/incident_learning_*), so a silently-stale template (renamed/moved script, wrong path) would mean the pipeline never runs on any deployment that installs it, with no error anywhere to notice"
PLIST_FILE="security/incident_learning/com.waio.incident-learning.plist.example"
# Plain line-based extraction, not an XML parser: this repo's own
# comment style uses "--" freely inside <!-- --> blocks (technically
# invalid per the XML spec, but accepted by plutil/launchd in
# practice, confirmed via `plutil -lint` returning OK on all three
# *.plist.example files in this repo) -- a strict XML parser chokes on
# that even though the real consumer (launchd) does not, so this test
# reads the same way `plutil -lint` sees it, not the way a
# spec-strict library would.
PLIST_PROGRAM="$(grep -A2 '<key>ProgramArguments</key>' "$PLIST_FILE" | grep '<string>' | sed -E 's#.*<string>(.*)</string>.*#\1#')"
assert_contains "CR9 plist references this exact script" "$PLIST_PROGRAM" "security/incident_learning/incident_learning_cron.sh"
PLIST_REPO_RELATIVE_PATH="${PLIST_PROGRAM#*/WAIO/}"
assert_eq "CR9 the referenced path exists and is executable relative to the repo root" "true" "$([ -x "$PLIST_REPO_RELATIVE_PATH" ] && echo true || echo false)"

echo ""
echo "[D1] DuCoPA boundary: this suite's own run never touched any real Control Plane file"
for real_file in security/egress_allowlist.conf security/segments.conf security/ssh_management_allowlist.conf; do
  if [ -f "$real_file" ]; then
    assert_eq "D1 $real_file unchanged" "" "$(git diff --name-only -- "$real_file" 2>/dev/null)"
  fi
done

echo ""
echo "[D2] no network tool is invoked by incident_learning_cron.sh itself (static guard; individual collectors are checked in their own suites)"
net_calls="$(grep -cE '\b(curl|wget|nc )\b' security/incident_learning/incident_learning_cron.sh || true)"
assert_eq "D2 zero network-tool invocations" "0" "$net_calls"

echo ""
echo "=== Summary: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
  echo "Failures:"
  printf '  - %s\n' "${FAILURES[@]}"
  exit 1
fi
exit 0
