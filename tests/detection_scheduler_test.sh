#!/bin/bash
set -uo pipefail

# tests/detection_scheduler_test.sh -- regression suite for the scheduled
# detection entry point, security/shadow_ai_attack_graph_cron.sh (run
# every 300 s by the com.waio.shadow-ai-attack-graph LaunchAgent).
#
# Covers: default mode unchanged; opt-in WAIO_DETECTION_DECIDE=1 adds the
# Intelligence Layer + Decision Engine and stays proposal-only; overlap
# lock (duplicate and concurrent runs); stale lock left by a crashed run;
# a run killed mid-flight; a failing stage releasing the lock and the
# next run recovering; an active emergency shutdown never being touched.
#
# Every state, audit, log and lock path is redirected into a temp dir,
# and ps/lsof are fixture scripts on PATH (same technique as
# tests/shadow_ai_monitor_test.sh) -- this machine's real process table,
# security/state/ and logs/ are never read or written. The only
# processes started are this suite's own children, stopped by PID.

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
code_only() { grep -vE '^[[:space:]]*#' "$1"; }

echo "=== Detection scheduler (security/shadow_ai_attack_graph_cron.sh) suite ==="

F="$(mktemp -d "${TMPDIR:-/tmp}/waio-detect-sched.XXXXXX")"
HOLDER_PID=""
cleanup() {
  if [ -n "$HOLDER_PID" ] && jobs -p | grep -qx "$HOLDER_PID"; then kill "$HOLDER_PID" 2>/dev/null; wait "$HOLDER_PID" 2>/dev/null; fi
  rm -rf "${F:?}"
}
trap cleanup EXIT
mkdir -p "$F/bin" "$F/state"/{shadow_ai,attack_graph,intelligence,decision_engine} "$F/logs" "$F/home"

cat > "$F/signatures.conf" <<'EOF'
process|rogue-agent|ai_agent_framework|CRITICAL|Unapproved autonomous agent (fixture)
port|11434|local_llm_runtime|MEDIUM|Ollama default API port (fixture)
EOF
: > "$F/allowlist.conf"
# PS_DELAY makes the fake ps slow, to hold a run open for the overlap cases.
cat > "$F/bin/ps" <<'EOF'
#!/bin/bash
[ -n "${PS_DELAY:-}" ] && sleep "$PS_DELAY"
cat <<X
   200     1 fixture  rogue-agent      /opt/rogue-agent/run --loop
X
EOF
printf '#!/bin/bash\ncat <<X\nCOMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\nrogue-agent 200 fixture 12u IPv4 0x2 0t0 TCP *:11434 (LISTEN)\nX\n' > "$F/bin/lsof"
chmod +x "$F/bin/ps" "$F/bin/lsof"

export PATH="$F/bin:$PATH" HOME="$F/home"
export SHADOW_AI_SIGNATURES_FILE="$F/signatures.conf" SHADOW_AI_ALLOWLIST_FILE="$F/allowlist.conf"
export SHADOW_AI_STATE_DIR="$F/state/shadow_ai" SHADOW_AI_AUDIT_LOG="$F/logs/shadow-ai-audit.jsonl"
export ATTACK_GRAPH_STATE_DIR="$F/state/attack_graph" ATTACK_GRAPH_AUDIT_LOG="$F/logs/attack-graph-audit.jsonl"
export INTELLIGENCE_STATE_DIR="$F/state/intelligence" INTELLIGENCE_AUDIT_LOG="$F/logs/intelligence-audit.jsonl"
export DECISION_ENGINE_STATE_DIR="$F/state/decision_engine" DECISION_ENGINE_AUDIT_LOG="$F/logs/decision-engine-audit.jsonl"
export SHADOW_AI_ATTACK_GRAPH_CRON_LOG="$F/logs/cron.log"
export SHADOW_AI_ATTACK_GRAPH_CRON_LOCK_DIR="$F/state/shadow_ai/.cron.lock"
export WAIO_SHUTDOWN_LOCK="$F/state/SHUTDOWN.lock" WAIO_GUARDIAN_QUARANTINE_FILE="$F/state/GUARDIAN_QUARANTINE" WAIO_GUARDIAN_STATE_FILE="$F/state/GUARDIAN_STATE"
unset WAIO_DETECTION_DECIDE

CRON=./security/shadow_ai_attack_graph_cron.sh
LOCK="$SHADOW_AI_ATTACK_GRAPH_CRON_LOCK_DIR"
LOG="$SHADOW_AI_ATTACK_GRAPH_CRON_LOG"
count() { grep -c -- "$1" "$LOG" 2>/dev/null || true; }
REAL_STATE_BEFORE="$(ls -la security/state 2>/dev/null | shasum | cut -d' ' -f1)"

echo ""
echo "[T1] default mode (WAIO_DETECTION_DECIDE unset): scan + attack graph only, exactly as before"
$CRON; RC=$?
assert_eq "T1 exit 0" "0" "$RC"
assert_contains "T1 log: scan | build ok" "$(cat "$LOG")" "shadow_ai_monitor.sh scan | attack_graph.sh build: ok"
assert_eq "T1 attack graph state written (fixture dir)" "true" "$([ -f "$ATTACK_GRAPH_STATE_DIR/latest_graph.json" ] && echo true || echo false)"
assert_eq "T1 no decision stage in default mode" "false" "$([ -f "$DECISION_ENGINE_STATE_DIR/latest_decisions.json" ] && echo true || echo false)"
assert_eq "T1 lock released" "false" "$([ -d "$LOCK" ] && echo true || echo false)"

echo ""
echo "[T2] WAIO_DETECTION_DECIDE=1: evidence + decision every run, proposal only -- nothing is contained"
WAIO_DETECTION_DECIDE=1 $CRON; RC=$?
assert_eq "T2 exit 0" "0" "$RC"
for s in "shadow_ai_monitor.sh scan: ok" "attack_graph.sh build: ok" "intelligence_layer.sh ingest: ok" "decision_engine.sh decide (proposal only): ok"; do
  assert_contains "T2 log: $s" "$(cat "$LOG")" "$s"
done
DEC="$(python3 -c 'import json,sys; d=[x for x in json.load(open(sys.argv[1]))["decisions"] if x["entity"]=="rogue-agent"][0]; print(d["recommended_action"], d["requires_human_approval_to_act"])' "$DECISION_ENGINE_STATE_DIR/latest_decisions.json" 2>/dev/null)"
assert_eq "T2 decision persisted: RECOMMEND_CONTAINMENT, still requires human approval" "RECOMMEND_CONTAINMENT True" "$DEC"
assert_eq "T2 no quarantine file" "false" "$([ -e "$WAIO_GUARDIAN_QUARANTINE_FILE" ] && echo true || echo false)"
assert_eq "T2 no shutdown lock" "false" "$([ -e "$WAIO_SHUTDOWN_LOCK" ] && echo true || echo false)"
assert_eq "T2 per-run temp dir removed" "0" "$(ls "${TMPDIR:-/tmp}" | grep -c '^waio-detect\.' || true)"

echo ""
echo "[T3] duplicate job: a run while another live run holds the lock is skipped (exit 0, no scan)"
mkdir "$LOCK"; sleep 120 & HOLDER_PID=$!; printf '%s' "$HOLDER_PID" > "$LOCK/holder.pid"
STARTS="$(count 'run start')"
$CRON; RC=$?
assert_eq "T3 exit 0" "0" "$RC"
assert_contains "T3 logged as skipped" "$(tail -1 "$LOG")" "skipped: another run is already in progress"
assert_eq "T3 no new run start" "$STARTS" "$(count 'run start')"
assert_eq "T3 the other run's lock is left alone" "$HOLDER_PID" "$(cat "$LOCK/holder.pid")"
kill "$HOLDER_PID"; wait "$HOLDER_PID" 2>/dev/null; HOLDER_PID=""
rm -rf "${LOCK:?}"

echo ""
echo "[T4] two runs started at the same moment: exactly one runs, the other is skipped"
: > "$LOG"
PS_DELAY=2 $CRON & A=$!
PS_DELAY=2 $CRON & B=$!
wait "$A"; RA=$?; wait "$B"; RB=$?
assert_eq "T4 both exit 0" "0 0" "$RA $RB"
assert_eq "T4 exactly one run start" "1" "$(count 'run start')"
assert_eq "T4 exactly one skipped" "1" "$(count 'skipped: another run')"
assert_eq "T4 lock released afterwards" "false" "$([ -d "$LOCK" ] && echo true || echo false)"

echo ""
echo "[T5] stale lock from a crashed run (holder PID dead, lock older than 5 s) is reclaimed"
mkdir "$LOCK"; sleep 0 & DEAD=$!; wait "$DEAD"; printf '%s' "$DEAD" > "$LOCK/holder.pid"
python3 -c 'import os,sys,time; t=time.time()-60; os.utime(sys.argv[1], (t, t))' "$LOCK"
: > "$LOG"
$CRON; RC=$?
assert_eq "T5 exit 0" "0" "$RC"
assert_eq "T5 run proceeded" "1" "$(count 'run start')"
assert_eq "T5 lock released" "false" "$([ -d "$LOCK" ] && echo true || echo false)"

echo ""
echo "[T6] run killed mid-flight (SIGKILL, no cleanup): next tick within 5 s skips, a later tick reclaims and runs"
: > "$LOG"
PS_DELAY=30 $CRON & K=$!
for _ in $(seq 50); do [ -f "$LOCK/holder.pid" ] && break; sleep 0.1; done
kill -9 "$K"; wait "$K" 2>/dev/null
assert_eq "T6 killed run left its lock behind" "true" "$([ -d "$LOCK" ] && echo true || echo false)"
$CRON
assert_eq "T6 immediate next run skipped (lock too fresh to judge stale)" "1" "$(count 'skipped: another run')"
python3 -c 'import os,sys,time; t=time.time()-60; os.utime(sys.argv[1], (t, t))' "$LOCK"
$CRON; RC=$?
assert_eq "T6 later run reclaimed the lock and ran" "0 2" "$RC $(count 'run start')"
assert_eq "T6 lock released" "false" "$([ -d "$LOCK" ] && echo true || echo false)"

echo ""
echo "[T7] a failing stage is logged, releases the lock, and the next run recovers"
: > "$LOG"
mv "$SHADOW_AI_SIGNATURES_FILE" "$F/signatures.off"   # the scan now fails closed without signatures
WAIO_DETECTION_DECIDE=1 $CRON; RC=$?
assert_eq "T7 exit 0 even when a stage fails" "0" "$RC"
assert_contains "T7 failure logged and later stages skipped" "$(cat "$LOG")" "later stages skipped this run"
assert_eq "T7 lock released after the failure" "false" "$([ -d "$LOCK" ] && echo true || echo false)"
mv "$F/signatures.off" "$SHADOW_AI_SIGNATURES_FILE"
: > "$LOG"
WAIO_DETECTION_DECIDE=1 $CRON
assert_contains "T7 next run completes every stage" "$(cat "$LOG")" "decision_engine.sh decide (proposal only): ok"

echo ""
echo "[T8] an active emergency shutdown is never touched by detection (detection keeps running read-only)"
printf 'reason: fixture shutdown\n' > "$WAIO_SHUTDOWN_LOCK"; BEFORE="$(shasum "$WAIO_SHUTDOWN_LOCK")"
: > "$LOG"
WAIO_DETECTION_DECIDE=1 $CRON; RC=$?
assert_eq "T8 exit 0" "0" "$RC"
assert_contains "T8 detection still ran" "$(cat "$LOG")" "decision_engine.sh decide (proposal only): ok"
assert_eq "T8 shutdown lock unchanged" "$BEFORE" "$(shasum "$WAIO_SHUTDOWN_LOCK")"

echo ""
echo "[D1] structural: the scheduler never calls a containment, recovery or Guardian tool"
cnt="$(code_only security/shadow_ai_attack_graph_cron.sh | grep -cE 'guardian|recover\.sh|recovery_engine|ducopa|trigger_shutdown|containment|security/lib\.sh|pkill|killall' || true)"
assert_eq "D1 zero references" "0" "$cnt"

echo ""
echo "[D2] this checkout's real security/state/ is unchanged"
assert_eq "D2 real state listing unchanged" "$REAL_STATE_BEFORE" "$(ls -la security/state 2>/dev/null | shasum | cut -d' ' -f1)"

echo ""
echo "=== Summary: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
  echo "Failures:"
  for f in "${FAILURES[@]}"; do echo "  - $f"; done
  exit 1
fi
exit 0
