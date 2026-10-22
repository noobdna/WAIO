#!/bin/bash
set -uo pipefail

# tests/global_patrol_cron_test.sh -- regression suite for the WAIO
# Global Cyber Intelligence Patrol's scheduled entry point,
# security/incident_learning/global_patrol_cron.sh (and, by exercising
# it end to end, security/incident_learning/global_patrol_report.py).
#
# Same posture as tests/incident_learning_cron_test.sh (this suite's
# own direct model): the wrapper adds no new collection logic of its
# own -- it only re-invokes the already-tested
# incident_learning_cron.sh, then diffs/reports over its output. This
# suite checks that plumbing (lock independence, failure-does-not-
# block-next-run, new-vs-known diffing, report file contents), not the
# underlying pipeline stages (already covered by
# tests/incident_learning_*_test.sh).
#
# Same fixture-sandbox pattern as every other
# tests/incident_learning_*_test.sh and tests/global_patrol_*_test.sh:
# every KNOWLEDGE_MANAGER_*/INCIDENT_LEARNING_CRON_*/GLOBAL_PATROL_*
# env var is overridden to a throwaway temp dir, so this suite never
# reads or writes this deployment's real security/state/incident_learning/
# or logs/.

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

FIXTURE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/waio-global-patrol-cron-test.XXXXXX")"
trap 'rm -rf "$FIXTURE_DIR"' EXIT

mkdir -p "$FIXTURE_DIR/candidates" "$FIXTURE_DIR/knowledge" "$FIXTURE_DIR/collectors" "$FIXTURE_DIR/patrol" "$FIXTURE_DIR/reports"
cp security/incident_learning/collectors/mock_collector.sh "$FIXTURE_DIR/collectors/mock_collector.sh"

export KNOWLEDGE_MANAGER_STATE_DIR="$FIXTURE_DIR/candidates"
export KNOWLEDGE_MANAGER_AUDIT_LOG="$FIXTURE_DIR/incident-learning-audit.jsonl"
export KNOWLEDGE_MANAGER_KNOWLEDGE_DIR="$FIXTURE_DIR/knowledge"
export INCIDENT_LEARNING_COLLECTORS_DIR="$FIXTURE_DIR/collectors"
export INCIDENT_LEARNING_CRON_LOG="$FIXTURE_DIR/incident-learning-cron.log"
export INCIDENT_LEARNING_CRON_LOCK_DIR="$FIXTURE_DIR/.incident-learning-cron.lock"

export GLOBAL_PATROL_LOG="$FIXTURE_DIR/global-patrol-cron.log"
export GLOBAL_PATROL_LOCK_DIR="$FIXTURE_DIR/.global-patrol-cron.lock"
export GLOBAL_PATROL_STATE_FILE="$FIXTURE_DIR/patrol/last_patrol.json"
export GLOBAL_PATROL_OUTPUT_DIR="$FIXTURE_DIR/reports"

jf() { python3 -c "
import json, sys
d = json.load(open(sys.argv[1]))
for k in sys.argv[2].split('.'):
    d = d[k] if not k.isdigit() else d[int(k)]
print(d)
" "$1" "$2" 2>/dev/null; }

echo "=== WAIO Global Cyber Intelligence Patrol regression suite ==="

echo ""
echo "[G1] first run (manual verification run) exits 0"
bash security/incident_learning/global_patrol_cron.sh
G1_RC=$?
assert_eq "G1 exit code 0" "0" "$G1_RC"

echo ""
echo "[G2] first run produced both timestamped and 'latest' JSON+MD report files"
assert_eq "G2 exactly one timestamped JSON report" "1" "$(find "$FIXTURE_DIR/reports" -maxdepth 1 -name 'global-patrol-report-*.json' ! -name '*latest*' | wc -l | tr -d ' ')"
assert_eq "G2 latest JSON exists" "true" "$([ -f "$FIXTURE_DIR/reports/global-patrol-report-latest.json" ] && echo true || echo false)"
assert_eq "G2 latest MD exists" "true" "$([ -f "$FIXTURE_DIR/reports/global-patrol-report-latest.md" ] && echo true || echo false)"

echo ""
echo "[G3] first run is honestly reported as a first run, with all 5 mock candidates as 'new'"
assert_eq "G3 is_first_run true" "True" "$(jf "$FIXTURE_DIR/reports/global-patrol-report-latest.json" is_first_run)"
assert_eq "G3 new_since_last_patrol == 5" "5" "$(jf "$FIXTURE_DIR/reports/global-patrol-report-latest.json" totals.new_since_last_patrol)"
assert_eq "G3 all_known_candidates == 5" "5" "$(jf "$FIXTURE_DIR/reports/global-patrol-report-latest.json" totals.all_known_candidates)"

echo ""
echo "[G4] last_patrol.json state file was written with the known candidate ids"
STATE_IDS="$(python3 -c "import json; print(sorted(json.load(open('$FIXTURE_DIR/patrol/last_patrol.json'))['known_candidate_ids']))")"
assert_eq "G4 known_candidate_ids == the 5 mock ids" "['MOCK-2026-0001', 'MOCK-2026-0002', 'MOCK-2026-0003', 'MOCK-2026-0004', 'MOCK-2026-0005']" "$STATE_IDS"

echo ""
echo "[G5] run log records start/end and both sub-step results"
G5_LOG="$(cat "$FIXTURE_DIR/global-patrol-cron.log")"
assert_contains "G5 log has run start" "$G5_LOG" "run start"
assert_contains "G5 log names the inner pipeline script by its own path" "$G5_LOG" "security/incident_learning/incident_learning_cron.sh: ok"
assert_contains "G5 log has report-generation result" "$G5_LOG" "global_patrol_report.py: ok"
assert_contains "G5 log has run end" "$G5_LOG" "run end"

echo ""
echo "[G6] second run with no new upstream data reports zero new candidates (diff is honest, not 'everything is always new')"
PREV_TOTAL=0
bash security/incident_learning/global_patrol_cron.sh
G6_RC=$?
assert_eq "G6 exit code 0" "0" "$G6_RC"
assert_eq "G6 is_first_run now false" "False" "$(jf "$FIXTURE_DIR/reports/global-patrol-report-latest.json" is_first_run)"
assert_eq "G6 new_since_last_patrol == 0 on an unchanged pipeline" "0" "$(jf "$FIXTURE_DIR/reports/global-patrol-report-latest.json" totals.new_since_last_patrol)"
assert_eq "G6 all_known_candidates still 5 (no duplicates)" "5" "$(jf "$FIXTURE_DIR/reports/global-patrol-report-latest.json" totals.all_known_candidates)"

echo ""
echo "[G7] a genuinely new collector record between two patrol runs is reported as new ONCE, never again -- this is the 'new info takes priority' diffing contract"
EXTRA_COLLECTOR="$FIXTURE_DIR/collectors/__test_extra_collector.sh"
cat > "$EXTRA_COLLECTOR" <<'EOF'
#!/bin/bash
echo '{"id":"GPTEST-0001","source":"test_extra_collector","source_type":"news","source_url":"https://example.invalid/extra","collected_at":"2026-01-01T00:00:00Z","raw_text":"extra record for Global Patrol diffing test","country":"JP","region":"APAC","incident_type":"data_breach","affected_sector":"retail_ecommerce","attack_pattern":"data_breach"}'
EOF
chmod +x "$EXTRA_COLLECTOR"
bash security/incident_learning/global_patrol_cron.sh
G7_RC=$?
assert_eq "G7 exit code 0" "0" "$G7_RC"
assert_eq "G7 new_since_last_patrol == 1 (only the extra record)" "1" "$(jf "$FIXTURE_DIR/reports/global-patrol-report-latest.json" totals.new_since_last_patrol)"
assert_eq "G7 the new record's own id is the one reported" "GPTEST-0001" "$(jf "$FIXTURE_DIR/reports/global-patrol-report-latest.json" new_incidents.0.id)"
assert_eq "G7 the new record's occurred_at/discovered_at are honestly '不明' (no such field exists upstream)" "不明" "$(jf "$FIXTURE_DIR/reports/global-patrol-report-latest.json" new_incidents.0.occurred_at)"
# Run a FOURTH time with the same collector still present -- the same
# id must NOT be reported as new again.
bash security/incident_learning/global_patrol_cron.sh
assert_eq "G7b the same id is never reported as new twice" "0" "$(jf "$FIXTURE_DIR/reports/global-patrol-report-latest.json" totals.new_since_last_patrol)"
rm -f "$EXTRA_COLLECTOR"

echo ""
echo "[G8] an overlapping run (lock already held) skips cleanly and touches neither the state file nor the latest report"
mkdir -p "$GLOBAL_PATROL_LOCK_DIR"
echo "999999999" > "$GLOBAL_PATROL_LOCK_DIR/holder.pid"
BEFORE_STATE="$(cat "$FIXTURE_DIR/patrol/last_patrol.json")"
BEFORE_REPORT="$(cat "$FIXTURE_DIR/reports/global-patrol-report-latest.json")"
bash security/incident_learning/global_patrol_cron.sh
G8_RC=$?
assert_eq "G8 exit code 0 even though it skipped" "0" "$G8_RC"
G8_LOG="$(cat "$FIXTURE_DIR/global-patrol-cron.log")"
assert_contains "G8 log records the skip" "$G8_LOG" "skipped: another global_patrol_cron.sh run is already in progress"
AFTER_STATE="$(cat "$FIXTURE_DIR/patrol/last_patrol.json")"
AFTER_REPORT="$(cat "$FIXTURE_DIR/reports/global-patrol-report-latest.json")"
assert_eq "G8 state file untouched by the skipped run" "$BEFORE_STATE" "$AFTER_STATE"
assert_eq "G8 latest report untouched by the skipped run" "$BEFORE_REPORT" "$AFTER_REPORT"
# holder.pid points at a non-existent (and definitely not live) PID,
# but the lock is also <5s old -- il_lock_acquire's own stale-lock
# reclaim requires BOTH conditions (dead holder AND >5s old), so a
# plain rm is the correct, intentional cleanup here (this is test
# teardown of a lock THIS SAME TEST manually created above, not a
# simulation of real stale-lock recovery -- that path is already
# covered by lock.sh's own reuse in tests/incident_learning_lock_test.sh).
rm -rf "$GLOBAL_PATROL_LOCK_DIR"

echo ""
echo "[G9] a failure inside the inner collection pipeline is logged, does NOT abort this schedule, and does NOT block the next run"
FAIL_SCRIPT="$FIXTURE_DIR/fail_pipeline.sh"
cat > "$FAIL_SCRIPT" <<'EOF'
#!/bin/bash
echo "simulated pipeline failure" >&2
exit 1
EOF
chmod +x "$FAIL_SCRIPT"
GLOBAL_PATROL_PIPELINE_SCRIPT="$FAIL_SCRIPT" bash security/incident_learning/global_patrol_cron.sh
G9_RC=$?
assert_eq "G9 wrapper itself still exits 0 despite the inner pipeline failing" "0" "$G9_RC"
G9_LOG="$(cat "$FIXTURE_DIR/global-patrol-cron.log")"
assert_contains "G9 log records the degraded collection step" "$G9_LOG" "degraded"
assert_eq "G9 report honestly records pipeline_status=degraded for this cycle" "degraded" "$(jf "$FIXTURE_DIR/reports/global-patrol-report-latest.json" pipeline_status)"
assert_eq "G9 lock was released (not stuck) -- a normal run right after still succeeds" "0" "$(bash security/incident_learning/global_patrol_cron.sh >/dev/null 2>&1; echo $?)"

echo ""
echo "[G10] pending human-gate candidates (CANDIDATE/HOLD) are surfaced in 'next patrol' action items, without this schedule ever advancing them itself"
km() { bash security/incident_learning/knowledge_manager.sh "$@"; }
# At least one of the 5 mock candidates reaches CANDIDATE via the real
# pipeline (tests/incident_learning_cron_test.sh's own CR3 already
# proves MOCK-2026-0001 does); confirm this schedule's own report
# lists it as pending, never silently advancing it.
bash security/incident_learning/global_patrol_cron.sh >/dev/null 2>&1
PENDING="$(python3 -c "
import json
d = json.load(open('$FIXTURE_DIR/reports/global-patrol-report-latest.json'))
print('MOCK-2026-0001' in d['action_items_before_next_patrol']['pending_human_gate'])
")"
assert_eq "G10 MOCK-2026-0001 listed as pending human gate" "True" "$PENDING"
assert_eq "G10 this schedule never itself approved/rejected/held/promoted anything (status still CANDIDATE, untouched since the original pipeline run)" "CANDIDATE" "$(km status MOCK-2026-0001)"

echo ""
echo "[G11] script is executable (as launchd will invoke it directly)"
assert_eq "G11 executable bit set" "true" "$([ -x security/incident_learning/global_patrol_cron.sh ] && echo true || echo false)"

echo ""
echo "[G12] runtime-wiring audit: the 72h plist TEMPLATE's ProgramArguments points at THIS exact, executable, repo-relative script path -- same audit discipline as tests/incident_learning_cron_test.sh's own CR9"
PLIST_FILE="security/incident_learning/com.waio.global-patrol.plist.example"
PLIST_PROGRAM="$(grep -A2 '<key>ProgramArguments</key>' "$PLIST_FILE" | grep '<string>' | sed -E 's#.*<string>(.*)</string>.*#\1#')"
assert_contains "G12 plist references this exact script" "$PLIST_PROGRAM" "security/incident_learning/global_patrol_cron.sh"
PLIST_REPO_RELATIVE_PATH="${PLIST_PROGRAM#*/WAIO/}"
assert_eq "G12 the referenced path exists and is executable relative to the repo root" "true" "$([ -x "$PLIST_REPO_RELATIVE_PATH" ] && echo true || echo false)"
assert_eq "G12 StartInterval is 259200 (72h), not the 1h collection schedule's own 3600" "True" "$(grep -A1 '<key>StartInterval</key>' "$PLIST_FILE" | grep -q '<integer>259200</integer>' && echo True || echo False)"

echo ""
echo "[G13] this 72h schedule's own lock/log/state paths are structurally DISTINCT from the existing 1h schedule's own -- overlapping both schedules can never collide on the same lock"
assert_eq "G13 global patrol lock dir name differs from the incident-learning cron's own" "true" "$([ "$GLOBAL_PATROL_LOCK_DIR" != "$INCIDENT_LEARNING_CRON_LOCK_DIR" ] && echo true || echo false)"
DEFAULT_IL_LOCK="$(grep -oE 'CRON_LOCK_DIR="\$\{INCIDENT_LEARNING_CRON_LOCK_DIR:-[^}]+\}"' security/incident_learning/incident_learning_cron.sh | grep -oE '[^-]+\.cron\.lock')"
DEFAULT_GP_LOCK="$(grep -oE 'LOCK_DIR="\$\{GLOBAL_PATROL_LOCK_DIR:-[^}]+\}"' security/incident_learning/global_patrol_cron.sh | grep -oE '[^-]+global_patrol_cron\.lock')"
assert_eq "G13 the two scripts' own DEFAULT lock paths (unset env var case) are also distinct" "true" "$([ "$DEFAULT_IL_LOCK" != "$DEFAULT_GP_LOCK" ] && echo true || echo false)"

echo ""
echo "[D1] DuCoPA boundary: this suite's own run never touched any real Control Plane file"
for real_file in security/egress_allowlist.conf security/segments.conf security/ssh_management_allowlist.conf; do
  if [ -f "$real_file" ]; then
    assert_eq "D1 $real_file unchanged" "" "$(git diff --name-only -- "$real_file" 2>/dev/null)"
  fi
done

echo ""
echo "[D2] no network tool is invoked by global_patrol_cron.sh itself (static guard; the real network calls only happen inside the already-separately-tested Collectors)"
net_calls="$(grep -cE '\b(curl|wget|nc )\b' security/incident_learning/global_patrol_cron.sh || true)"
assert_eq "D2 zero network-tool invocations" "0" "$net_calls"

echo ""
echo "[D3] *** CRITICAL GUARD *** zero references in global_patrol_cron.sh's own ACTUAL CODE (comments excluded -- same code_only() precedent as tests/decision_engine_test.sh's own D5, whose header explicitly documents this file as free to NAME these tools in its own header comments as a description of what it does NOT call) to any real Guardian / Decision Engine / Human Gate / Recovery tool -- this schedule reports, it never executes containment or auto-approves anything"
code_only() {
  grep -vE '^[[:space:]]*#' "$1"
}
containment_calls=0
for pattern in \
  'guardian\.sh' 'guardian_intervene_wrapper\.sh' 'guardian_intervene_quarantine_wrapper\.sh' \
  'guardian_release_agent\.sh' 'guardian_approve\.sh' 'ducopa\.sh' 'recovery_engine\.sh' \
  '\brecover\.sh' 'incident_human_gate\.sh' 'decision_engine\.sh' 'decision_engine_lib' \
  'guardian_quarantine_agent' 'guardian_dispatch' \
; do
  c="$(code_only security/incident_learning/global_patrol_cron.sh | grep -cE "$pattern" || true)"
  containment_calls=$((containment_calls + c))
done
assert_eq "D3 zero references to any real containment/human-gate tool in global_patrol_cron.sh's actual code" "0" "$containment_calls"
echo "  (global_patrol_report.py is checked separately by its OWN suite's D1: it asserts zero subprocess/os.system/os.popen/socket/http calls at all -- a strictly stronger guarantee than a name-based grep, so its own module docstring is free to name these tools as documentation, same precedent tests/decision_engine_test.sh's own D2b already established for decision_engine_lib.py.)"

echo ""
echo "[D4] this schedule never calls any of knowledge_manager.sh's own mutating human-gate subcommands (approve/reject/hold/release/promote) -- it only sources it for the read-only candidate_confidence_level() derivation"
mutating_calls="$(grep -cE 'knowledge_manager\.sh (approve|reject|hold|release|promote)\b' security/incident_learning/global_patrol_cron.sh || true)"
assert_eq "D4 zero mutating knowledge_manager.sh CLI invocations" "0" "$mutating_calls"

echo ""
echo "=== Summary: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
  echo "Failures:"
  printf '  - %s\n' "${FAILURES[@]}"
  exit 1
fi
exit 0
