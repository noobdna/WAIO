#!/bin/bash
set -uo pipefail

# tests/autopilot_test.sh -- WAIO Autopilot mission engine
# (autopilot/autopilot.py, autopilot_lib.py, autopilot_watchdog.py).
#
# Every mission runs against a throwaway Python project in a temp dir,
# with Guardian state, the shutdown lock and the audit log redirected
# into the fixture (same WAIO_* override pattern as every other suite).
# The real security/state/ is never read for decisions or written.
#   M: one mission, several tasks, dependencies, parallelism -> COMPLETE
#   B: build-test-repair loop (local-AI repair via a deterministic stub)
#   L: repeated identical failure -> STUCK, not an endless loop
#   C: completion is never claimed without passing acceptance
#   P: forbidden commands are never run; mission waits for a human
#   G: Guardian blocking / shutdown lock / corrupt state / watchdog down
#      -> no task starts (fail closed); resume afterwards
#   R: engine killed mid-task -> watchdog reaps the orphan, notifies the
#      Guardian; resume re-runs only what is safe; PASSED work not repeated
#   W: watchdog enforces deadlines on its own, and never stops a reused pgid
#   X: duplicate engine or duplicate watchdog refused; escaped task
#      processes reaped, and they cannot hang the engine
#   S: sandbox (macOS) blocks writes outside the workspace and network
#   E: environment scrubbed, secrets redacted from logs
#   V: mission validation; T: traceability

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

assert_not_contains() {
  local label="$1" haystack="$2" needle="$3"
  if [[ "$haystack" != *"$needle"* ]]; then
    PASS=$((PASS + 1)); echo "  PASS: $label"
  else
    FAIL=$((FAIL + 1)); FAILURES+=("$label (expected NOT to contain '$needle')")
    echo "  FAIL: $label (expected NOT to contain '$needle')"
  fi
}

FIX="$(mktemp -d "${TMPDIR:-/tmp}/autopilot-test.XXXXXX")"
WD_PIDS=()
cleanup() {
  for p in "${WD_PIDS[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null; done
  rm -rf "$FIX"
  [ -n "${PROBE:-}" ] && rm -f "$PROBE"
}
trap cleanup EXIT

# Guardian / shutdown / audit isolation (never the real security/state/)
export WAIO_GUARDIAN_STATE_FILE="$FIX/GUARDIAN_STATE"
export WAIO_GUARDIAN_QUARANTINE_FILE="$FIX/GUARDIAN_QUARANTINE"
export WAIO_GUARDIAN_CRITICAL_EVENTS_FILE="$FIX/GUARDIAN_CRITICAL_EVENTS"
export WAIO_GUARDIAN_STATE_LOCK_DIR="$FIX/guardian.lock"
export WAIO_SHUTDOWN_LOCK="$FIX/SHUTDOWN.lock"
export WAIO_AUDIT_LOG="$FIX/audit.jsonl"
export WAIO_AUDIT_LOG_CHECKPOINT="$FIX/audit-checkpoint"
export WAIO_AUDIT_INTEGRITY_ALERTS="$FIX/audit-alerts.jsonl"
export WAIO_AUDIT_LOG_LOCK_DIR="$FIX/audit.lock"
export WAIO_RECOVER_RECONCILE_MARKER="$FIX/.last_reconciled_trigger"
export AUTOPILOT_ENGINE_HB_MAX_AGE=3
export AUTOPILOT_TERM_GRACE_S=1
REAL_GUARDIAN_BEFORE="$(cat security/state/GUARDIAN_STATE 2>/dev/null || echo __absent__)"

ENGINE="autopilot/autopilot.py"
WATCHDOG="autopilot/autopilot_watchdog.py"

# project <dir> -- a tiny Python project with a deliberate bug in add()
project() {
  mkdir -p "$1"
  printf 'def add(a, b):\n    return a - b\n' > "$1/calc.py"
  cat > "$1/test_calc.py" <<'EOF'
import unittest
from calc import add
class T(unittest.TestCase):
    def test_add(self):
        self.assertEqual(add(2, 3), 5)
if __name__ == "__main__":
    unittest.main()
EOF
}

# deterministic stand-in for the local model: reads the prompt on stdin,
# answers with a corrected file in a fenced block (what the engine parses)
STUB="$FIX/ai_stub.sh"
cat > "$STUB" <<'EOF'
#!/bin/bash
cat >/dev/null
printf 'Here is the fix.\n```python\ndef add(a, b):\n    return a + b\n```\n'
EOF
chmod +x "$STUB"

start_watchdog() { python3 "$WATCHDOG" --state "$1" --interval 0.5 >/dev/null 2>&1 & WD_PIDS+=("$!"); for _ in $(seq 1 40); do [ -f "$1/watchdog.hb" ] && return 0; sleep 0.1; done; }
stop_watchdogs() { for p in "${WD_PIDS[@]:-}"; do [ -n "$p" ] && { kill "$p" 2>/dev/null; wait "$p" 2>/dev/null; }; done; WD_PIDS=(); }
mission() { # mission <file> <json>
  printf '%s\n' "$2" > "$1"
}
st() { python3 -I -c "import json, sys; s = json.load(open(sys.argv[1] + '/state.json')); print($2)" "$1"; }

echo "[M1] one mission -> several tasks (deps + parallel) -> COMPLETE"
W="$FIX/m1"; project "$W/ws"; S="$W/state"; start_watchdog "$S"
mission "$W/mission.json" '{"mission_id": "m1", "goal": "two files and a summary", "workspace": "ws",
 "limits": {"max_parallel": 2, "task_timeout_s": 30},
 "tasks": [
  {"id": "a", "cmd": "echo A > a.txt", "test": "grep -q A a.txt"},
  {"id": "b", "cmd": "echo B > b.txt", "test": "grep -q B b.txt"},
  {"id": "c", "deps": ["a", "b"], "cmd": "cat a.txt b.txt > c.txt", "test": "[ \"$(cat c.txt)\" = \"$(printf \"A\\nB\")\" ]"}],
 "acceptance": [{"id": "files", "cmd": "test -s c.txt", "expect_exit": 0}]}'
OUT="$(python3 "$ENGINE" run --mission "$W/mission.json" --state "$S" 2>&1)"; RC=$?
assert_eq "M1 exit 0" "0" "$RC"
assert_contains "M1 verdict printed" "$OUT" "COMPLETE"
assert_eq "M1 all three PASSED" "PASSED PASSED PASSED" "$(st "$S" "' '.join(s['tasks'][t]['status'] for t in 'abc')")"
assert_eq "M1 report lists changed files" "a.txt b.txt c.txt" "$(python3 -I -c "import json,sys; print(' '.join(json.load(open(sys.argv[1]))['changed_files']))" "$S/report.json")"
M1_ORDER="$(python3 -I - "$S/events.jsonl" <<'PY'
import json, sys
ev = [json.loads(l) for l in open(sys.argv[1])]
idx = dict(((e.get("task"), e.get("to")), i) for i, e in enumerate(ev) if e["event"] == "task_state")
print(idx[("c", "RUNNING")] > idx[("a", "PASSED")] and idx[("c", "RUNNING")] > idx[("b", "PASSED")])
PY
)"
assert_eq "M1 c started only after a and b passed" "True" "$M1_ORDER"
stop_watchdogs

echo "[B1] test fails -> local-AI repair (stub) -> re-test passes"
W="$FIX/b1"; project "$W/ws"; S="$W/state"; start_watchdog "$S"
mission "$W/mission.json" '{"mission_id": "b1", "goal": "fix add()", "workspace": "ws",
 "tasks": [{"id": "fix", "test": "python3 -m unittest -q test_calc",
            "repair": {"kind": "local_ai", "file": "calc.py", "instruction": "add must return the sum"}}],
 "acceptance": [{"id": "unit", "cmd": "python3 -m unittest -q test_calc", "expect_exit": 0}]}'
AUTOPILOT_LOCAL_AI_CMD="$STUB" python3 "$ENGINE" run --mission "$W/mission.json" --state "$S" >/dev/null 2>&1; RC=$?
assert_eq "B1 exit 0 after repair" "0" "$RC"
assert_eq "B1 one failed attempt recorded before the pass" "PASSED 1" "$(st "$S" "s['tasks']['fix']['status'], s['tasks']['fix']['attempts']" | tr -d "(),'")"
assert_contains "B1 repair event names the rewritten file" "$(cat "$S/events.jsonl")" "local_ai_rewrote:calc.py"
assert_contains "B1 the fix is real (file now adds)" "$(cat "$W/ws/calc.py")" "a + b"
assert_eq "B1 tasks do not write bytecode caches" "0" "$(find "$W/ws" -name '*.pyc' | wc -l | tr -d ' ')"
echo "[B2] stale bytecode cannot hide a repair (cache written in the same second as the rewrite)"
# The stub reproduces the CI race deterministically: just before answering
# it stamps calc.py with the current whole second and compiles a cache for
# the BUGGY source at that mtime (where this interpreter looks: in-tree
# __pycache__ on Linux, sys.pycache_prefix on macOS system Python). The
# engine writes the fix microseconds later, same size, same second, so
# without the engine's mtime bump Python would trust the stale cache.
B2_STUB="$FIX/ai_stub_b2.sh"
cat > "$B2_STUB" <<'EOF2'
#!/bin/bash
cat >/dev/null
python3 - "$B2_WS/calc.py" <<'PY' >/dev/null
import importlib.util, os, py_compile, sys, time
src = os.path.realpath(sys.argv[1])  # macOS: /var -> /private/var, as the importer sees it
while time.time() % 1 > 0.3:
    time.sleep(0.05)
t = int(time.time())
os.utime(src, (t, t))
c = importlib.util.cache_from_source(os.path.abspath(src))
py_compile.compile(src, cfile=c)
os.utime(src, (t, t))
print(c)
PY
printf 'fix\n```python\ndef add(a, b):\n    return a + b\n```\n'
EOF2
chmod +x "$B2_STUB"
W="$FIX/b2"; project "$W/ws"; start_watchdog "$W/state"
mission "$W/mission.json" '{"mission_id": "b2", "goal": "fix add()", "workspace": "ws",
 "tasks": [{"id": "fix", "test": "python3 -m unittest -q test_calc", "repair": {"kind": "local_ai", "file": "calc.py", "instruction": "sum"}}],
 "acceptance": [{"id": "unit", "cmd": "python3 -m unittest -q test_calc", "expect_exit": 0}]}'
B2_WS="$W/ws" AUTOPILOT_LOCAL_AI_CMD="$B2_STUB" python3 "$ENGINE" run --mission "$W/mission.json" --state "$W/state" >/dev/null 2>&1
assert_eq "B2 repair seen by the re-test despite a same-second stale cache (exit 0)" "0" "$?"
rm -f "$(cd "$W/ws" && python3 -c "import importlib.util, os; print(importlib.util.cache_from_source(os.path.realpath('calc.py')))")"
stop_watchdogs
stop_watchdogs

echo "[L1] same failure twice -> STUCK, mission not successful"
W="$FIX/l1"; project "$W/ws"; S="$W/state"; start_watchdog "$S"
mission "$W/mission.json" '{"mission_id": "l1", "goal": "x", "workspace": "ws", "limits": {"max_attempts": 9},
 "tasks": [{"id": "fix", "test": "python3 -m unittest -q test_calc", "repair": {"kind": "cmd", "cmd": "true"}}],
 "acceptance": [{"id": "unit", "cmd": "python3 -m unittest -q test_calc", "expect_exit": 0}]}'
python3 "$ENGINE" run --mission "$W/mission.json" --state "$S" >/dev/null 2>&1; RC=$?
assert_eq "L1 exit 1 (INCOMPLETE)" "1" "$RC"
assert_eq "L1 STUCK after 2 attempts, not 9" "STUCK 2" "$(st "$S" "s['tasks']['fix']['status'], s['tasks']['fix']['attempts']" | tr -d "(),'")"
assert_eq "L1 mission status INCOMPLETE" "INCOMPLETE" "$(st "$S" "s['status']")"
stop_watchdogs

echo "[C1] tasks pass but acceptance fails -> never COMPLETE"
W="$FIX/c1"; project "$W/ws"; S="$W/state"; start_watchdog "$S"
mission "$W/mission.json" '{"mission_id": "c1", "goal": "x", "workspace": "ws",
 "tasks": [{"id": "t", "cmd": "echo hi > hi.txt", "test": "test -f hi.txt"}],
 "acceptance": [{"id": "unit", "cmd": "python3 -m unittest -q test_calc", "expect_exit": 0}]}'
OUT="$(python3 "$ENGINE" run --mission "$W/mission.json" --state "$S" 2>&1)"; RC=$?
assert_eq "C1 exit 1" "1" "$RC"
assert_contains "C1 reason names the failed acceptance" "$OUT" "acceptance unit failed"
echo "[C2] a task without a test is rejected at load (cannot be 'passed' by default)"
mission "$W/m2.json" '{"mission_id": "c2", "workspace": "ws", "tasks": [{"id": "t", "cmd": "true"}], "acceptance": [{"id": "a", "cmd": "true"}]}'
python3 "$ENGINE" run --mission "$W/m2.json" --state "$W/s2" >/dev/null 2>&1; assert_eq "C2 exit 2" "2" "$?"
stop_watchdogs

echo "[P1] forbidden operations are never executed; mission waits for a human"
W="$FIX/p1"; project "$W/ws"; S="$W/state"; start_watchdog "$S"
mission "$W/mission.json" '{"mission_id": "p1", "goal": "x", "workspace": "ws",
 "tasks": [
  {"id": "net", "cmd": "touch ran-net && curl -s https://example.invalid", "test": "true"},
  {"id": "push", "cmd": "touch ran-push && git push origin HEAD", "test": "true"},
  {"id": "guard", "cmd": "touch ran-guard && echo NORMAL > ../../../security/state/GUARDIAN_STATE", "test": "true"},
  {"id": "sudo", "cmd": "touch ran-sudo && sudo -n true", "test": "true"},
  {"id": "ok", "cmd": "echo fine > ok.txt", "test": "test -f ok.txt"}],
 "acceptance": [{"id": "a", "cmd": "true"}]}'
python3 "$ENGINE" run --mission "$W/mission.json" --state "$S" >/dev/null 2>&1; RC=$?
assert_eq "P1 exit 3 (AWAITING_HUMAN)" "3" "$RC"
assert_eq "P1 four tasks BLOCKED_POLICY, the safe one PASSED" "BLOCKED_POLICY BLOCKED_POLICY BLOCKED_POLICY BLOCKED_POLICY PASSED" "$(st "$S" "' '.join(s['tasks'][t]['status'] for t in ('net', 'push', 'guard', 'sudo', 'ok'))")"
assert_eq "P1 no part of a blocked command ran" "0" "$(ls "$W/ws" | grep -c '^ran-')"
assert_eq "P1 rules recorded" "network publish control_plane privilege" "$(st "$S" "' '.join(s['tasks'][t]['history'][-1]['rule'] for t in ('net', 'push', 'guard', 'sudo'))")"
stop_watchdogs

echo "[G1] Guardian BLOCKED -> nothing starts; NORMAL again -> resume completes"
W="$FIX/g1"; project "$W/ws"; S="$W/state"; start_watchdog "$S"
mission "$W/mission.json" '{"mission_id": "g1", "goal": "x", "workspace": "ws",
 "tasks": [{"id": "t", "cmd": "echo run >> runs.txt", "test": "test -f runs.txt", "idempotent": true}],
 "acceptance": [{"id": "a", "cmd": "test -f runs.txt"}]}'
echo BLOCKED > "$WAIO_GUARDIAN_STATE_FILE"
OUT="$(python3 "$ENGINE" run --mission "$W/mission.json" --state "$S" 2>&1)"; RC=$?
assert_eq "G1 exit 4 (PAUSED_GUARDIAN)" "4" "$RC"
assert_contains "G1 reason" "$OUT" "guardian_blocking"
assert_eq "G1 task never ran" "false" "$([ -f "$W/ws/runs.txt" ] && echo true || echo false)"
echo NORMAL > "$WAIO_GUARDIAN_STATE_FILE"
python3 "$ENGINE" run --mission "$W/mission.json" --state "$S" >/dev/null 2>&1; RC=$?
assert_eq "G1 resume -> exit 0" "0" "$RC"
assert_eq "G1 ran exactly once" "1" "$(wc -l < "$W/ws/runs.txt" | tr -d ' ')"
echo "[G2] Emergency Shutdown lock -> fail closed"
W2="$FIX/g2"; project "$W2/ws"; cp "$W/mission.json" "$W2/mission.json"; start_watchdog "$W2/state"
touch "$WAIO_SHUTDOWN_LOCK"
OUT="$(python3 "$ENGINE" run --mission "$W2/mission.json" --state "$W2/state" 2>&1)"; RC=$?
assert_eq "G2 exit 4" "4" "$RC"; assert_contains "G2 reason" "$OUT" "shutdown_lock_active"
rm -f "$WAIO_SHUTDOWN_LOCK"
echo "[G3] corrupt Guardian state -> treated as BLOCKED (fail closed)"
W3="$FIX/g3"; project "$W3/ws"; cp "$W/mission.json" "$W3/mission.json"; start_watchdog "$W3/state"
echo "totally-not-a-state" > "$WAIO_GUARDIAN_STATE_FILE"
python3 "$ENGINE" run --mission "$W3/mission.json" --state "$W3/state" >/dev/null 2>&1; assert_eq "G3 exit 4" "4" "$?"
echo NORMAL > "$WAIO_GUARDIAN_STATE_FILE"
stop_watchdogs
echo "[G4] watchdog down -> no new task (missing, then stale heartbeat)"
W4="$FIX/g4"; project "$W4/ws"; cp "$W/mission.json" "$W4/mission.json"
OUT="$(python3 "$ENGINE" run --mission "$W4/mission.json" --state "$W4/state" 2>&1)"; RC=$?
assert_eq "G4 missing heartbeat -> exit 4" "4" "$RC"; assert_contains "G4 reason" "$OUT" "watchdog_heartbeat_missing"
touch -t 202001010000 "$W4/state/watchdog.hb"
OUT="$(python3 "$ENGINE" run --mission "$W4/mission.json" --state "$W4/state" 2>&1)"; RC=$?
assert_eq "G4 stale heartbeat -> exit 4" "4" "$RC"; assert_contains "G4 reason" "$OUT" "watchdog_heartbeat_stale"
assert_eq "G4 task never ran" "false" "$([ -f "$W4/ws/runs.txt" ] && echo true || echo false)"

echo "[R1] engine killed mid-task -> watchdog reaps orphan + notifies Guardian -> resume"
W="$FIX/r1"; project "$W/ws"; S="$W/state"; start_watchdog "$S"
mission "$W/mission.json" '{"mission_id": "r1", "goal": "x", "workspace": "ws", "limits": {"max_parallel": 1, "task_timeout_s": 60},
 "tasks": [
  {"id": "first", "priority": 2, "cmd": "echo once >> first.log", "test": "test -f first.log", "idempotent": true},
  {"id": "slow", "priority": 1, "deps": ["first"], "test": "test -f go || sleep 50; test -f go", "idempotent": true}],
 "acceptance": [{"id": "a", "cmd": "test -f go"}]}'
python3 "$ENGINE" run --mission "$W/mission.json" --state "$S" >/dev/null 2>&1 &
EPID=$!
for _ in $(seq 1 100); do [ "$(st "$S" "s['tasks']['slow'].get('pgid', 0) > 0" 2>/dev/null)" = "True" ] && break; sleep 0.1; done
SLOW_PGID="$(st "$S" "s['tasks']['slow']['pgid']")"
kill -9 "$EPID" 2>/dev/null; wait "$EPID" 2>/dev/null
for _ in $(seq 1 100); do grep -q guardian_notified "$S/watchdog.jsonl" 2>/dev/null && break; sleep 0.1; done
assert_contains "R1 watchdog logged the orphan" "$(cat "$S/watchdog.jsonl" 2>/dev/null)" "orphaned_engine_dead"
assert_eq "R1 orphaned task's process group is gone" "gone" "$(kill -0 -"$SLOW_PGID" 2>/dev/null && echo alive || echo gone)"
assert_eq "R1 Guardian was told (WARNING, non-blocking)" "WARNING" "$(cat "$WAIO_GUARDIAN_STATE_FILE")"
touch "$W/ws/go"
python3 "$ENGINE" run --mission "$W/mission.json" --state "$S" >/dev/null 2>&1; RC=$?
assert_eq "R1 resume -> exit 0" "0" "$RC"
assert_eq "R1 PASSED work was not repeated (first ran once)" "1" "$(wc -l < "$W/ws/first.log" | tr -d ' ')"
assert_contains "R1 resume recorded" "$(cat "$S/events.jsonl")" '"event": "resumed"'
echo NORMAL > "$WAIO_GUARDIAN_STATE_FILE"
stop_watchdogs
echo "[R2] non-idempotent task interrupted -> BLOCKED_RESUME (human decides)"
assert_eq "R2 unit" "BLOCKED_RESUME PENDING" "$(python3 -I -c "
import sys; sys.path.insert(0, 'autopilot'); import autopilot_lib as al
m, _ = al.validate_mission(dict(mission_id='r2', workspace='w', tasks=[dict(id='a', test='true'), dict(id='b', test='true', idempotent=True)], acceptance=[dict(id='x', cmd='true')]))
s = al.initial_state(m); s['tasks']['a']['status'] = s['tasks']['b']['status'] = 'RUNNING'
al.resume_state(s, m); print(s['tasks']['a']['status'], s['tasks']['b']['status'])")"

echo "[W1] watchdog stops an overdue task on its own"
W="$FIX/w1"; mkdir -p "$W"
python3 -I -c "import os, time; os.setsid(); time.sleep(60)" &
SPID=$!
sleep 0.3
python3 -I -c "
import json, sys, time
json.dump({'tasks': {'t': {'status': 'RUNNING', 'pgid': int(sys.argv[2]), 'deadline': time.time() - 1, 'phase': 'test'}}}, open(sys.argv[1] + '/state.json', 'w'))" "$W" "$SPID"
printf '%s %s\n' "$$" "$(date +%s)" > "$W/engine.hb"
python3 "$WATCHDOG" --state "$W" --max-iterations 1 >/dev/null 2>&1
assert_contains "W1 deadline_exceeded logged" "$(cat "$W/watchdog.jsonl" 2>/dev/null)" "deadline_exceeded"
wait "$SPID" 2>/dev/null
assert_eq "W1 process gone" "gone" "$(kill -0 "$SPID" 2>/dev/null && echo alive || echo gone)"
echo NORMAL > "$WAIO_GUARDIAN_STATE_FILE"

echo "[X1] a second engine on the same state dir is refused"
W="$FIX/x1"; project "$W/ws"; S="$W/state"; start_watchdog "$S"
mission "$W/mission.json" '{"mission_id": "x1", "goal": "x", "workspace": "ws", "tasks": [{"id": "t", "test": "test -f go || sleep 20; true", "idempotent": true}], "acceptance": [{"id": "a", "cmd": "true"}]}'
python3 "$ENGINE" run --mission "$W/mission.json" --state "$S" >/dev/null 2>&1 &
E1=$!
for _ in $(seq 1 50); do [ -d "$S/engine.lock" ] && break; sleep 0.1; done
python3 "$ENGINE" run --mission "$W/mission.json" --state "$S" >/dev/null 2>&1; assert_eq "X1 second engine exit 5" "5" "$?"
touch "$W/ws/go"; wait "$E1"; assert_eq "X1 first engine still completes" "0" "$?"
echo "[X2] same state dir with a different mission file is refused"
mission "$W/other.json" '{"mission_id": "x1", "goal": "changed", "workspace": "ws", "tasks": [{"id": "t", "test": "true"}], "acceptance": [{"id": "a", "cmd": "true"}]}'
python3 "$ENGINE" run --mission "$W/other.json" --state "$S" >/dev/null 2>&1; assert_eq "X2 exit 2" "2" "$?"
stop_watchdogs

echo "[X3] a second watchdog on the same state dir is refused; the lock dies with its holder"
S="$FIX/x3/state"; start_watchdog "$S"; WD1="${WD_PIDS[${#WD_PIDS[@]}-1]}"
python3 "$WATCHDOG" --state "$S" --interval 0.5 --max-iterations 1 >/dev/null 2>&1; assert_eq "X3 second watchdog exit 5" "5" "$?"
assert_eq "X3 lock names the first watchdog" "$WD1" "$(tr -d '[:space:]' < "$S/watchdog.lock")"
kill -9 "$WD1"; wait "$WD1" 2>/dev/null; WD_PIDS=()
python3 "$WATCHDOG" --state "$S" --interval 0.5 --max-iterations 1 >/dev/null 2>&1; assert_eq "X3 after kill -9 a new watchdog starts (no stale lock)" "0" "$?"

echo "[X4] a task process that setsid()s out of its group is still reaped, and cannot hang the engine"
# esc.py forks a child that leaves the task's process group (setsid), so
# killpg no longer reaches it. "closed": the child also closes stdio and the
# task returns after 1 s. "open": the child keeps the output pipe and the
# task overruns its 4 s timeout -- before this fix the engine then blocked
# forever waiting for EOF.
W="$FIX/x4"; mkdir -p "$W/ws"
cat > "$W/ws/esc.py" <<'EOF'
import os, sys, time
mode = sys.argv[1]
if os.fork() == 0:
    os.setsid()
    if mode == "closed":
        for fd in (0, 1, 2):
            os.close(fd)
    open("escaped-%s.pid" % mode, "w").write(str(os.getpid()))
    time.sleep(40)
    os._exit(0)
time.sleep(1 if mode == "closed" else 20)
EOF
for mode in closed open; do
  S="$W/state-$mode"; start_watchdog "$S"
  mission "$W/m-$mode.json" "{\"mission_id\": \"x4$mode\", \"goal\": \"x\", \"workspace\": \"ws\", \"limits\": {\"task_timeout_s\": 4}, \"tasks\": [{\"id\": \"t\", \"test\": \"python3 esc.py $mode; true\"}], \"acceptance\": [{\"id\": \"a\", \"cmd\": \"true\"}]}"
  T0=$(date +%s)
  perl -e 'alarm shift; exec @ARGV' 40 python3 "$ENGINE" run --mission "$W/m-$mode.json" --state "$S" >/dev/null 2>&1
  ELAPSED=$(( $(date +%s) - T0 ))
  sleep 0.3
  EP="$(cat "$W/ws/escaped-$mode.pid" 2>/dev/null)"
  assert_eq "X4 $mode: the escaped process was recorded" "yes" "$([ -n "$EP" ] && echo yes || echo no)"
  assert_eq "X4 $mode: the escaped process is gone after the task" "gone" "$(kill -0 "$EP" 2>/dev/null && echo alive || echo gone)"
  assert_contains "X4 $mode: the kill is in the event log" "$(cat "$S/events.jsonl")" "escaped_process_killed"
  [ -n "$EP" ] && kill "$EP" 2>/dev/null
  stop_watchdogs
done
assert_eq "X4 open: the engine finished instead of hanging (timeout 4 s + drain, well under 40 s)" "True" "$(python3 -I -c "print($ELAPSED < 20)")"
assert_contains "X4 open: the abandoned output is recorded" "$(cat "$W/state-open/events.jsonl")" "task_output_abandoned"

echo "[W2] the watchdog never stops a process group whose number was reused (no false stop)"
# A RUNNING task whose engine is dead is an orphan the watchdog reaps. Point
# its recorded pgid at an unrelated live group with a different start time,
# as if the number had been reused: it must be left alone and logged.
W="$FIX/w2"; S="$W/state"; mkdir -p "$S"
python3 -I -c "import os, time; os.setsid(); time.sleep(30)" & BYSTANDER=$!
sleep 0.3
python3 -I -c "
import json, sys, time
pgid, start = int(sys.argv[2]), sys.argv[3]
json.dump({'status': 'RUNNING', 'tasks': {'t': {'status': 'RUNNING', 'pgid': pgid, 'pgid_start': start, 'deadline': time.time() - 1}}}, open(sys.argv[1] + '/state.json', 'w'))
" "$S" "$BYSTANDER" "Thu Jan  1 00:00:00 1970"
python3 "$WATCHDOG" --state "$S" --interval 0.2 --max-iterations 3 >/dev/null 2>&1
assert_eq "W2 reused pgid: bystander still alive" "alive" "$(kill -0 "$BYSTANDER" 2>/dev/null && echo alive || echo gone)"
assert_contains "W2 reused pgid: logged as not_stopped/pgid_reused" "$(cat "$S/watchdog.jsonl" 2>/dev/null)" "pgid_reused"
python3 -I -c "
import json, subprocess, sys, time
pgid = int(sys.argv[2]); start = subprocess.run(['ps', '-o', 'lstart=', '-p', str(pgid)], capture_output=True, text=True).stdout.strip()
json.dump({'status': 'RUNNING', 'tasks': {'t': {'status': 'RUNNING', 'pgid': pgid, 'pgid_start': start, 'deadline': time.time() - 1}}}, open(sys.argv[1] + '/state.json', 'w'))
" "$S" "$BYSTANDER"
python3 "$WATCHDOG" --state "$S" --interval 0.2 --max-iterations 3 >/dev/null 2>&1
wait "$BYSTANDER" 2>/dev/null
assert_eq "W2 matching start time: the overdue group is stopped" "gone" "$(kill -0 "$BYSTANDER" 2>/dev/null && echo alive || echo gone)"

echo "[X5] a double fork that escapes faster than any sample is still reaped; unrelated orphans are not"
# fast.py: the task's process forks, the child setsid()s and forks again,
# and both parents exit at once -- the grandchild is already an orphan
# before the 0.5 s sampler can see it (the previous engine reaped 0 of 5).
# Linux: the engine is a child subreaper. macOS: the orphan still has the
# engine's responsible process and the task sandbox.
# OUTSIDER: an orphan created by this test shell (not by the engine), with
# no sandbox, while the task runs. It must survive.
W="$FIX/x5"; mkdir -p "$W/ws"; S="$W/state"
cat > "$W/ws/fast.py" <<'EOF'
import os, time
if os.fork() == 0:
    os.setsid()
    if os.fork() == 0:
        for fd in (0, 1, 2):
            os.close(fd)
        open("fast.pid", "w").write(str(os.getpid()))
        time.sleep(40)
    os._exit(0)
os._exit(0)
EOF
cat > "$W/outsider.py" <<'EOF'
import os, sys, time
if os.fork() == 0:
    os.setsid()
    if os.fork() == 0:
        for fd in (0, 1, 2):
            os.close(fd)
        open(sys.argv[1], "w").write(str(os.getpid()))
        time.sleep(40)
    os._exit(0)
os._exit(0)
EOF
mission "$W/m.json" '{"mission_id": "x5", "goal": "x", "workspace": "ws", "tasks": [{"id": "t", "test": "python3 fast.py; sleep 1; true"}], "acceptance": [{"id": "a", "cmd": "true"}]}'
start_watchdog "$S"
python3 "$ENGINE" run --mission "$W/m.json" --state "$S" >/dev/null 2>&1 &
X5E=$!
sleep 0.5; python3 "$W/outsider.py" "$W/outsider.pid"
wait "$X5E"
sleep 0.3
FP="$(cat "$W/ws/fast.pid" 2>/dev/null)"; OP="$(cat "$W/outsider.pid" 2>/dev/null)"
assert_eq "X5 the fast escapee existed" "yes" "$([ -n "$FP" ] && echo yes || echo no)"
assert_eq "X5 the fast escapee is gone" "gone" "$(kill -0 "$FP" 2>/dev/null && echo alive || echo gone)"
assert_contains "X5 logged as an orphan kill" "$(cat "$S/events.jsonl")" '"orphans": 1'
assert_eq "X5 an unrelated orphan started during the task is left alone" "alive" "$(kill -0 "$OP" 2>/dev/null && echo alive || echo gone)"
[ -n "$FP" ] && kill "$FP" 2>/dev/null; [ -n "$OP" ] && kill "$OP" 2>/dev/null
stop_watchdogs

echo "[S1] sandbox: writes outside the workspace and network are denied"
if command -v sandbox-exec >/dev/null 2>&1; then
  W="$FIX/s1"; project "$W/ws"; S="$W/state"; start_watchdog "$S"
  PROBE="$HOME/.autopilot-sandbox-probe-$$"
  mission "$W/mission.json" "{\"mission_id\": \"s1\", \"goal\": \"x\", \"workspace\": \"ws\",
   \"tasks\": [
    {\"id\": \"escape\", \"cmd\": \"echo x > $PROBE; echo rc=\$? > escape.rc\", \"test\": \"test -f escape.rc\"},
    {\"id\": \"net\", \"cmd\": \"python3 -c 'import socket; socket.create_connection((\\\"127.0.0.1\\\", 9), 1)' > net.out 2>&1; true\", \"test\": \"test -f net.out\"}],
   \"acceptance\": [{\"id\": \"a\", \"cmd\": \"true\"}]}"
  python3 "$ENGINE" run --mission "$W/mission.json" --state "$S" >/dev/null 2>&1
  assert_eq "S1 write outside workspace did not happen" "false" "$([ -e "$PROBE" ] && echo true || echo false)"
  assert_contains "S1 the write failed inside the task" "$(cat "$W/ws/escape.rc" 2>/dev/null)" "rc=1"
  assert_contains "S1 network denied by the sandbox (not just refused)" "$(cat "$W/ws/net.out" 2>/dev/null)" "Operation not permitted"
  assert_eq "S1 sandbox mode recorded" "macos" "$(st "$S" "s['sandbox']")"
  stop_watchdogs
else
  echo "  SKIP: S1 (no sandbox-exec on this platform; the engine records sandbox=unavailable and relies on the policy)"
fi

echo "[E1] environment scrubbed, secrets redacted"
W="$FIX/e1"; project "$W/ws"; S="$W/state"; start_watchdog "$S"
mission "$W/mission.json" '{"mission_id": "e1", "goal": "x", "workspace": "ws",
 "tasks": [{"id": "t", "cmd": "env > env.txt", "test": "echo token=abc123SECRETVALUE; echo Bearer zzzzLONGTOKENzzzz; exit 1"}],
 "acceptance": [{"id": "a", "cmd": "true"}]}'
AUTOPILOT_SECRET_PROBE=leak-me python3 "$ENGINE" run --mission "$W/mission.json" --state "$S" >/dev/null 2>&1
assert_not_contains "E1 caller env not passed to tasks" "$(cat "$W/ws/env.txt")" "leak-me"
assert_not_contains "E1 token redacted from events" "$(cat "$S/events.jsonl")" "abc123SECRETVALUE"
assert_not_contains "E1 bearer redacted from events" "$(cat "$S/events.jsonl")" "zzzzLONGTOKENzzzz"
assert_not_contains "E1 token redacted from state" "$(cat "$S/state.json")" "abc123SECRETVALUE"
stop_watchdogs

wait_log() { # wait_log <file> <pattern>: the watchdog writes its record after the group is gone
  for _ in $(seq 1 100); do grep -q "$2" "$1" 2>/dev/null && return 0; sleep 0.1; done; return 1
}

wait_running() { # wait_running <state> <task> -> prints pgid once the task's process group is recorded
  for _ in $(seq 1 100); do
    g="$(st "$1" "s['tasks']['$2'].get('pgid', 0)" 2>/dev/null)"
    [ -n "$g" ] && [ "$g" != "0" ] && { echo "$g"; return 0; }
    sleep 0.1
  done
  echo 0
}

echo "[G5] Guardian turns SHUTDOWN mid-task -> watchdog stops running work, attempt not counted, resume completes"
W="$FIX/g5"; project "$W/ws"; S="$W/state"; start_watchdog "$S"
mission "$W/mission.json" '{"mission_id": "g5", "goal": "x", "workspace": "ws", "limits": {"task_timeout_s": 60},
 "tasks": [{"id": "long", "test": "test -f go || sleep 50; test -f go", "idempotent": true}],
 "acceptance": [{"id": "a", "cmd": "test -f go"}]}'
python3 "$ENGINE" run --mission "$W/mission.json" --state "$S" >/dev/null 2>&1 &
EPID=$!
G5_PGID="$(wait_running "$S" long)"
echo SHUTDOWN > "$WAIO_GUARDIAN_STATE_FILE"
wait "$EPID"; RC=$?
assert_eq "G5 engine exits PAUSED_GUARDIAN (4)" "4" "$RC"
assert_eq "G5 the running task's process group is gone" "gone" "$(kill -0 -"$G5_PGID" 2>/dev/null && echo alive || echo gone)"
wait_log "$S/watchdog.jsonl" guardian_SHUTDOWN
assert_contains "G5 watchdog logged why" "$(cat "$S/watchdog.jsonl" 2>/dev/null)" "guardian_SHUTDOWN"
assert_eq "G5 task back to PENDING with 0 attempts (interruption, not failure)" "PENDING 0" "$(st "$S" "s['tasks']['long']['status'], s['tasks']['long']['attempts']" | tr -d "(),'")"
echo NORMAL > "$WAIO_GUARDIAN_STATE_FILE"; touch "$W/ws/go"
python3 "$ENGINE" run --mission "$W/mission.json" --state "$S" >/dev/null 2>&1; assert_eq "G5 resume -> exit 0" "0" "$?"
stop_watchdogs

echo "[O1] operator stop (graceful): running task finishes, nothing new starts; clear-stop resumes"
W="$FIX/o1"; project "$W/ws"; S="$W/state"; start_watchdog "$S"
mission "$W/mission.json" '{"mission_id": "o1", "goal": "x", "workspace": "ws", "limits": {"max_parallel": 1},
 "tasks": [{"id": "one", "priority": 2, "cmd": "sleep 2; echo 1 > one.txt", "test": "test -f one.txt", "idempotent": true},
           {"id": "two", "priority": 1, "cmd": "echo 2 > two.txt", "test": "test -f two.txt", "idempotent": true}],
 "acceptance": [{"id": "a", "cmd": "test -f two.txt"}]}'
python3 "$ENGINE" run --mission "$W/mission.json" --state "$S" >/dev/null 2>&1 &
EPID=$!
wait_running "$S" one >/dev/null
python3 "$ENGINE" stop --state "$S" >/dev/null
wait "$EPID"; RC=$?
assert_eq "O1 exit 6 STOPPED_BY_OPERATOR" "6" "$RC"
assert_eq "O1 running task was allowed to finish; next never started" "PASSED PENDING" "$(st "$S" "s['tasks']['one']['status'], s['tasks']['two']['status']" | tr -d "(),'")"
assert_eq "O1 two.txt not created" "false" "$([ -f "$W/ws/two.txt" ] && echo true || echo false)"
python3 "$ENGINE" run --mission "$W/mission.json" --state "$S" >/dev/null 2>&1; assert_eq "O1 still stopped until cleared (exit 6)" "6" "$?"
python3 "$ENGINE" clear-stop --state "$S" >/dev/null
python3 "$ENGINE" run --mission "$W/mission.json" --state "$S" >/dev/null 2>&1; assert_eq "O1 after clear-stop -> exit 0" "0" "$?"
assert_eq "O1 stop and clear are in the audit trail" "2" "$(grep -cE '"event": "operator_stop_(requested|cleared)"' "$S/events.jsonl")"
stop_watchdogs

echo "[O2] operator stop --now: watchdog stops running work"
W="$FIX/o2"; project "$W/ws"; S="$W/state"; start_watchdog "$S"
mission "$W/mission.json" '{"mission_id": "o2", "goal": "x", "workspace": "ws", "limits": {"task_timeout_s": 60},
 "tasks": [{"id": "long", "test": "sleep 50", "idempotent": true}], "acceptance": [{"id": "a", "cmd": "true"}]}'
python3 "$ENGINE" run --mission "$W/mission.json" --state "$S" >/dev/null 2>&1 &
EPID=$!
O2_PGID="$(wait_running "$S" long)"
python3 "$ENGINE" stop --now --state "$S" >/dev/null
wait "$EPID"; RC=$?
assert_eq "O2 exit 6" "6" "$RC"
assert_eq "O2 process group gone" "gone" "$(kill -0 -"$O2_PGID" 2>/dev/null && echo alive || echo gone)"
wait_log "$S/watchdog.jsonl" operator_stop_now
assert_contains "O2 watchdog reason" "$(cat "$S/watchdog.jsonl" 2>/dev/null)" "operator_stop_now"
assert_eq "O2 attempt not counted" "0" "$(st "$S" "s['tasks']['long']['attempts']")"
stop_watchdogs
echo NORMAL > "$WAIO_GUARDIAN_STATE_FILE"

echo "[R3] damaged state.json -> refuse to resume, file preserved, nothing runs"
W="$FIX/r3"; project "$W/ws"; S="$W/state"; mkdir -p "$S"; start_watchdog "$S"
mission "$W/mission.json" '{"mission_id": "r3", "goal": "x", "workspace": "ws", "tasks": [{"id": "t", "cmd": "touch ran", "test": "test -f ran"}], "acceptance": [{"id": "a", "cmd": "true"}]}'
printf '{"truncated": ' > "$S/state.json"
R3_SUM="$(shasum -a 256 "$S/state.json")"
OUT="$(python3 "$ENGINE" run --mission "$W/mission.json" --state "$S" 2>&1)"; RC=$?
assert_eq "R3 truncated state -> exit 2" "2" "$RC"
assert_contains "R3 says why" "$OUT" "refusing to resume"
assert_not_contains "R3 no traceback" "$OUT" "Traceback"
assert_eq "R3 state file left untouched" "$R3_SUM" "$(shasum -a 256 "$S/state.json")"
assert_eq "R3 nothing ran" "false" "$([ -f "$W/ws/ran" ] && echo true || echo false)"
assert_eq "R3 engine lock released" "false" "$([ -d "$S/engine.lock" ] && echo true || echo false)"
echo '{"mission_id": "r3", "tasks": {"other": {"status": "PASSED"}}}' > "$S/state.json"
python3 "$ENGINE" run --mission "$W/mission.json" --state "$S" >/dev/null 2>&1; assert_eq "R3 state from a different task set -> exit 2" "2" "$?"
stop_watchdogs

echo "[V1] mission validation"
v() { python3 -I -c "import sys, json; sys.path.insert(0, 'autopilot'); import autopilot_lib as al; m, e = al.validate_mission(json.loads(sys.argv[1])); print('OK' if m else e[0])" "$1"; }
assert_contains "V1 cycle rejected" "$(v '{"mission_id":"v","workspace":"w","tasks":[{"id":"a","test":"t","deps":["b"]},{"id":"b","test":"t","deps":["a"]}],"acceptance":[{"id":"x","cmd":"t"}]}')" "cycle"
assert_contains "V1 unknown dep rejected" "$(v '{"mission_id":"v","workspace":"w","tasks":[{"id":"a","test":"t","deps":["zz"]}],"acceptance":[{"id":"x","cmd":"t"}]}')" "unknown task"
assert_contains "V1 no acceptance rejected" "$(v '{"mission_id":"v","workspace":"w","tasks":[{"id":"a","test":"t"}]}')" "acceptance"
assert_eq "V1 limits clamped to hard caps" "3600 10 4" "$(python3 -I -c "
import sys; sys.path.insert(0, 'autopilot'); import autopilot_lib as al
m, e = al.validate_mission(dict(mission_id='v', workspace='w', tasks=[dict(id='a', test='t')], acceptance=[dict(id='x', cmd='t')], limits=dict(task_timeout_s=99999, max_attempts=500, max_parallel=64)))
print(m['limits']['task_timeout_s'], m['limits']['max_attempts'], m['limits']['max_parallel'])")"

echo "[L2] the same failure at a different speed is still the same failure"
sig() { python3 -I -c "import sys; sys.path.insert(0, 'autopilot'); import autopilot_lib as al; print(al.failure_signature(1, sys.argv[1]))" "$1"; }
assert_eq "L2 unittest timing (0.001s vs 0.012s) does not change the signature" "$(sig $'FAIL: test_add\nRan 1 test in 0.001s\nFAILED (failures=1)')" "$(sig $'FAIL: test_add\nRan 1 test in 0.012s\nFAILED (failures=1)')"
assert_eq "L2 millisecond units are normalized too" "$(sig 'timeout after 12ms')" "$(sig 'timeout after 950ms')"
assert_eq "L2 a different failure still differs" "False" "$(python3 -I -c "import sys; sys.path.insert(0, 'autopilot'); import autopilot_lib as al; print(al.failure_signature(1, 'FAIL: test_add') == al.failure_signature(1, 'FAIL: test_sub'))")"

echo "[T1] traceability: every task transition is in the append-only event log"
assert_eq "T1 M1 events cover all tasks" "a b c" "$(python3 -I -c "
import json, sys; print(' '.join(sorted({json.loads(l).get('task') for l in open(sys.argv[1]) if json.loads(l)['event'] == 'task_state'})))" "$FIX/m1/state/events.jsonl")"

echo "[D1] static guards and real-state isolation"
assert_eq "D1 real Guardian state untouched by this suite" "$REAL_GUARDIAN_BEFORE" "$(cat security/state/GUARDIAN_STATE 2>/dev/null || echo __absent__)"
assert_eq "D1 engine and watchdog never write Guardian/DuCoPA files directly" "0" "$(grep -vE '^\s*#' autopilot/*.py | grep -cE "open\([^)]*(GUARDIAN|SHUTDOWN|killswitch|ducopa)")"
assert_eq "D1 lib has no I/O or subprocess" "0" "$(grep -vE '^\s*#' autopilot/autopilot_lib.py | grep -cE '^\s*(import|from)\s+(os|subprocess|socket)\b|\bopen\(')"

if [ "${AUTOPILOT_TEST_REAL_AI:-}" = "1" ]; then
  echo "[A1] OPTIONAL: real local model repairs the bug (llama.cpp, opt-in)"
  W="$FIX/a1"; project "$W/ws"; S="$W/state"; start_watchdog "$S"
  mission "$W/mission.json" '{"mission_id": "a1", "goal": "fix add()", "workspace": "ws", "limits": {"task_timeout_s": 60, "max_attempts": 3},
   "tasks": [{"id": "fix", "test": "python3 -m unittest -q test_calc", "repair": {"kind": "local_ai", "file": "calc.py", "instruction": "add(a, b) must return a + b"}}],
   "acceptance": [{"id": "unit", "cmd": "python3 -m unittest -q test_calc", "expect_exit": 0}]}'
  python3 "$ENGINE" run --mission "$W/mission.json" --state "$S" >/dev/null 2>&1; RC=$?
  assert_eq "A1 real local model fixed it (exit 0)" "0" "$RC"
  stop_watchdogs
fi

echo ""
echo "=== Summary: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
  echo "Failures:"
  for f in "${FAILURES[@]}"; do echo "  - $f"; done
  exit 1
fi
exit 0
