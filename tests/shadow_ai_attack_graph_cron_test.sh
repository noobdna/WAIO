#!/bin/bash
set -uo pipefail

# tests/shadow_ai_attack_graph_cron_test.sh -- security/shadow_ai_attack_graph_cron.sh
# with WAIO_PERSIST_SHADOW_AI_FINDINGS (opt-in persistence of the last
# successful scan's findings JSONL).
#
# Runs the REAL cron script and the real lock helper inside a temp copy of
# the repo layout, with stub detectors (no ps/lsof scan, no real state):
#   P1   flag unset: no file, original pipe unchanged
#   P2   flag set: file written atomically, 0600, identical to the scan
#   P3   failed scan never replaces the previous file
#   P4   symlink at the destination refused
#   P5-6 decide mode: persisted after a good scan only
#   P7   custom destination; P8 no temp leftovers; P9 run temp dir removed

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR" || exit 1
# shellcheck source=tests/lib/test_isolation.sh
. tests/lib/test_isolation.sh
waio_test_isolate shadow_ai_attack_graph_cron || exit 3
waio_test_assert_isolated || exit 3
trap waio_test_cleanup EXIT

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

T="$WAIO_TEST_ROOT/sagc"
R="$T/repo"
mkdir -p "$R/security/shadow_ai" "$R/security/attack_graph" "$R/security/intelligence" \
  "$R/security/decision_engine" "$R/security/incident_learning" "$T/tmp"
cp security/shadow_ai_attack_graph_cron.sh "$R/security/"
cp security/incident_learning/lock.sh "$R/security/incident_learning/"

cat > "$R/security/shadow_ai/shadow_ai_monitor.sh" <<'EOF'
#!/bin/bash
# stub: STUB_SCAN=ok prints two findings; STUB_SCAN=fail prints one, then fails
echo '{"id":"SHADOWAI-a","risk":"HIGH","detected_at":"2026-10-27T01:00:00Z"}'
[ "${STUB_SCAN:-ok}" = fail ] && exit 1
echo '{"id":"SHADOWAI-b","risk":"LOW","detected_at":"2026-10-27T01:00:00Z"}'
EOF
cat > "$R/security/attack_graph/attack_graph.sh" <<'EOF'
#!/bin/bash
# stub: build [FILE|-] -> records how many findings it received
in="${2:--}"; n=$(if [ "$in" = "-" ]; then grep -c .; else grep -c . "$in"; fi)
mkdir -p security/state/attack_graph; echo "$n" > security/state/attack_graph/received
echo "stub attack_graph built from $n findings"
EOF
printf '#!/bin/bash\necho "{}"\n' > "$R/security/intelligence/intelligence_layer.sh"
printf '#!/bin/bash\necho "{}"\nmkdir -p security/state; touch security/state/decided\n' > "$R/security/decision_engine/decision_engine.sh"
chmod +x "$R"/security/*/*.sh "$R/security/shadow_ai_attack_graph_cron.sh"

DEST="$R/security/state/shadow_ai/latest_findings.jsonl"
run() {   # run [VAR=VALUE...] -- the real cron script, isolated
  env TMPDIR="$T/tmp" SHADOW_AI_ATTACK_GRAPH_CRON_LOG="$T/cron.log" "$@" \
    bash "$R/security/shadow_ai_attack_graph_cron.sh"; echo $?
}
received() { cat "$R/security/state/attack_graph/received" 2>/dev/null || echo none; }
fresh() { rm -rf "$R/security/state" "$T/cron.log"; }
sha() { shasum -a 256 "$1" | cut -d' ' -f1; }

echo "=== P-series ==="
fresh
assert_eq "P1 flag unset: run ok, no findings file, graph got both findings" "0 absent 2" \
  "$(run) $([ -e "$DEST" ] && echo present || echo absent) $(received)"
assert_eq "P1 the original pipe line is unchanged" "1" \
  "$(grep -c '^  if ./security/shadow_ai/shadow_ai_monitor.sh scan 2>>"\$LOG_FILE" | ./security/attack_graph/attack_graph.sh build >>"\$LOG_FILE" 2>&1; then$' security/shadow_ai_attack_graph_cron.sh)"
fresh
assert_eq "P2 flag set: file written, graph got both findings" "0 present 2" \
  "$(run WAIO_PERSIST_SHADOW_AI_FINDINGS=1) $([ -f "$DEST" ] && echo present || echo absent) $(received)"
assert_eq "P2 content identical to the scan, mode 600" "True 600" "$(python3 -c "
import subprocess
scan = subprocess.run(['bash', '$R/security/shadow_ai/shadow_ai_monitor.sh'], capture_output=True, text=True).stdout
print(open('$DEST').read() == scan)") $(python3 -c "import os,sys; print(format(os.stat(sys.argv[1]).st_mode & 0o777, 'o'))" "$DEST")"
assert_eq "P2 logged with a count" "1" "$(grep -c 'persist findings: wrote .* (2 findings)' "$T/cron.log")"
before=$(sha "$DEST")
assert_eq "P3 failed scan: run still exits 0, file NOT replaced" "0 $before" "$(run WAIO_PERSIST_SHADOW_AI_FINDINGS=1 STUB_SCAN=fail) $(sha "$DEST")"
assert_eq "P3 failure logged, graph not rebuilt from the partial scan" "1 2" "$(grep -c 'exited non-zero' "$T/cron.log") $(received)"
fresh; mkdir -p "$R/security/state/shadow_ai"; printf 'target\n' > "$T/target"; ln -s "$T/target" "$DEST"
assert_eq "P4 symlink at the destination refused, target untouched" "0 target symlink" \
  "$(run WAIO_PERSIST_SHADOW_AI_FINDINGS=1) $(cat "$T/target") $([ -L "$DEST" ] && echo symlink || echo replaced)"
assert_eq "P4 refusal logged" "1" "$(grep -c 'is a symlink; refused' "$T/cron.log")"
fresh
assert_eq "P5 decide mode: persisted and later stages ran" "0 present yes" \
  "$(run WAIO_PERSIST_SHADOW_AI_FINDINGS=1 WAIO_DETECTION_DECIDE=1) $([ -f "$DEST" ] && echo present || echo absent) $([ -e "$R/security/state/decided" ] && echo yes || echo no)"
before=$(sha "$DEST")
assert_eq "P6 decide mode, failed scan: file not replaced" "0 $before" "$(run WAIO_PERSIST_SHADOW_AI_FINDINGS=1 WAIO_DETECTION_DECIDE=1 STUB_SCAN=fail) $(sha "$DEST")"
fresh
assert_eq "P6b decide mode without the flag: nothing persisted" "0 absent" "$(run WAIO_DETECTION_DECIDE=1) $([ -e "$DEST" ] && echo present || echo absent)"
fresh
assert_eq "P7 custom destination honored" "0 present absent" \
  "$(run WAIO_PERSIST_SHADOW_AI_FINDINGS=1 SHADOW_AI_FINDINGS_FILE="$T/custom/findings.jsonl") $([ -f "$T/custom/findings.jsonl" ] && echo present || echo absent) $([ -e "$DEST" ] && echo present || echo absent)"
assert_eq "P8 no temp leftovers next to the destination" "0" "$(ls -A "$R/security/state/shadow_ai" "$T/custom" 2>/dev/null | grep -c '^\.latest_findings\.' || true)"
assert_eq "P9 run temp dirs removed" "0" "$(ls "$T/tmp" | grep -c '^waio-detect\.' || true)"
assert_eq "P10 the real repo's state was not touched" "absent" "$([ -e security/state/shadow_ai/latest_findings.jsonl ] && echo present || echo absent)"
for s in sudo ssh scp curl nc osascript; do
  assert_eq "P11 stub $s never called" "0" "$(waio_test_stub_calls "$s")"
done

echo ""
echo "=== Summary: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
  echo "Failures:"; for f in "${FAILURES[@]}"; do echo "  - $f"; done
  exit 1
fi
exit 0
