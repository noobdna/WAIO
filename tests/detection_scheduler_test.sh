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
# next run recovering; an active emergency shutdown never being touched;
# log rotation (threshold, 0600 archives, retention, missing log, rename
# and gzip failures, lock-held runs never rotating, concurrent runs).
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
echo "[R1-R9] log rotation: threshold, archive, permissions, retention, missing file, failures"
RD="$F/rlogs"; mkdir -p "$RD"; RL="$RD/cron.log"
fmode() { stat -f%Lp "$1" 2>/dev/null || stat -c%a "$1" 2>/dev/null; }
narch() { ls "$RL".2*Z* 2>/dev/null | wc -l | tr -d ' '; }
fill() { { echo "MARKER-$2"; head -c "$1" /dev/zero | tr '\0' x; echo; } > "$RL"; }
rcron() { SHADOW_AI_ATTACK_GRAPH_CRON_LOG="$RL" SHADOW_AI_ATTACK_GRAPH_CRON_LOG_MAX_BYTES="${MAXB:-1000}" SHADOW_AI_ATTACK_GRAPH_CRON_LOG_KEEP="${KEEP:-3}" $CRON; }

fill 100 small; rcron; RC=$?
assert_eq "R1 under threshold: exit 0" "0" "$RC"
assert_eq "R1 under threshold: no archive" "0" "$(narch)"
assert_contains "R1 under threshold: log kept and appended" "$(head -1 "$RL")" "MARKER-small"

fill 5000 big; rcron; RC=$?
ARC="$(ls "$RL".2*Z*.gz 2>/dev/null | head -1)"
assert_eq "R2 over threshold: exit 0" "0" "$RC"
assert_eq "R2 one gzip archive" "1" "$(ls "$RL".2*Z*.gz 2>/dev/null | wc -l | tr -d ' ')"
assert_contains "R2 archive holds the old content" "$(gzip -dc "$ARC" | head -1)" "MARKER-big"
assert_eq "R2 archive is 0600" "600" "$(fmode "$ARC")"
assert_eq "R2 fresh log is 0600" "600" "$(fmode "$RL")"
assert_contains "R2 fresh log records the rotation" "$(head -1 "$RL")" "log rotated: previous log ("
assert_contains "R2 detection still ran after rotating" "$(cat "$RL")" "attack_graph.sh build: ok"
assert_eq "R2 old content not in fresh log" "0" "$(grep -c MARKER-big "$RL")"

rm -f "$RL".*
for ts in 20260101T000000Z 20260102T000000Z 20260103T000000Z 20260104T000000Z; do echo "$ts" | gzip > "$RL.$ts.gz"; done
echo "uncompressed" > "$RL.20260105T000000Z"
fill 5000 r3; KEEP=3 rcron; RC=$?
assert_eq "R3 retention: exit 0" "0" "$RC"
assert_eq "R3 retention: exactly KEEP=3 archives" "3" "$(narch)"
assert_eq "R3 oldest three removed" "0" "$(ls "$RL".2026010[123]T* 2>/dev/null | wc -l | tr -d ' ')"
assert_eq "R3 newer ones kept (incl. an uncompressed one)" "2" "$(ls "$RL.20260104T000000Z.gz" "$RL.20260105T000000Z" 2>/dev/null | wc -l | tr -d ' ')"
assert_eq "R3 removals logged" "3" "$(grep -c 'log retention: removed oldest archive' "$RL")"
fill 5000 r3b; KEEP=0 rcron
assert_eq "R3 KEEP=0 keeps no archives" "0" "$(narch)"

rm -f "$RL" "$RL".*; rcron; RC=$?
assert_eq "R4 missing log: exit 0" "0" "$RC"
assert_eq "R4 missing log: created, no archive" "true 0" "$([ -f "$RL" ] && echo true || echo false) $(narch)"
assert_contains "R4 missing log: run recorded" "$(cat "$RL")" "run end"

rm -f "$RL" "$RL".*
if [ "$(id -u)" = "0" ]; then
  echo "  SKIP: R5 (root ignores directory permissions)"
else
  fill 5000 r5; chmod 555 "$RD"; rcron; RC=$?; chmod 755 "$RD"
  assert_eq "R5 rename fails: exit 0" "0" "$RC"
  assert_contains "R5 rename failure logged" "$(cat "$RL")" "log rotation failed: could not rename"
  assert_contains "R5 detection still ran" "$(cat "$RL")" "attack_graph.sh build: ok"
  assert_eq "R5 nothing archived, old content intact" "0 1" "$(narch) $(grep -c MARKER-r5 "$RL")"
fi

rm -f "$RL" "$RL".*
mkdir -p "$F/badgzip"; printf '#!/bin/bash\nexit 1\n' > "$F/badgzip/gzip"; chmod +x "$F/badgzip/gzip"
fill 5000 r6; PATH="$F/badgzip:$PATH" rcron; RC=$?
ARC="$(ls "$RL".2*Z 2>/dev/null | head -1)"
assert_eq "R6 gzip fails: exit 0" "0" "$RC"
assert_contains "R6 gzip failure logged" "$(cat "$RL")" "gzip failed, archive kept uncompressed"
assert_contains "R6 uncompressed archive kept" "$(head -1 "$ARC" 2>/dev/null)" "MARKER-r6"
assert_eq "R6 uncompressed archive is 0600, no partial .gz" "600 0" "$(fmode "$ARC") $(ls "$RL".*.gz 2>/dev/null | wc -l | tr -d ' ')"

rm -f "$RL" "$RL".*
fill 5000 r7; mkdir "$LOCK"; sleep 120 & HOLDER_PID=$!; printf '%s' "$HOLDER_PID" > "$LOCK/holder.pid"
rcron; RC=$?
assert_eq "R7 skipped run never rotates" "0 0 1" "$RC $(narch) $(grep -c MARKER-r7 "$RL")"
kill "$HOLDER_PID"; wait "$HOLDER_PID" 2>/dev/null; HOLDER_PID=""; rm -rf "${LOCK:?}"

rm -f "$RL" "$RL".*
fill 5000 r8; MAXB=abc KEEP=-1 rcron; RC=$?
assert_eq "R8 non-numeric overrides fall back to defaults (5 MiB: no rotation)" "0 0" "$RC $(narch)"

rm -f "$RL" "$RL".*
{ echo MARKER-r9; head -c 5000 /dev/zero | tr '\0' x; } > "$RD/target.log"; ln -s "$RD/target.log" "$RL"
rcron; RC=$?
assert_eq "R9 symlinked log is never renamed" "0 0 true" "$RC $(narch) $([ -L "$RL" ] && echo true || echo false)"
rm -f "$RL" "$RD/target.log"

echo ""
echo "[R10] concurrent runs over the threshold: exactly one rotation, no lost archive"
fill 5000 r10
PS_DELAY=1 rcron & A=$!; PS_DELAY=1 rcron & B=$!
wait "$A"; RA=$?; wait "$B"; RB=$?
assert_eq "R10 both exit 0" "0 0" "$RA $RB"
assert_eq "R10 exactly one archive" "1" "$(narch)"
assert_contains "R10 archive holds the old content" "$(gzip -dc "$RL".2*Z*.gz | head -1)" "MARKER-r10"
assert_eq "R10 exactly one rotation logged across log + archive" "1" "$(cat "$RL" | grep -c 'log rotated')"

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
