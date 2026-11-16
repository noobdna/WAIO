#!/bin/bash
set -uo pipefail

# tests/wad_runner_test.sh -- WAD PR 2 runner: live execution of
# non-disruptive steps (security/wad/runner/wad_runner.py, `response
# execute --live` / `response rollback --live` in security/wad/wad.py) and
# process-group termination by security/wad/wad_estop.sh.
#
#   C-series: default stays dry run; runner config refused fail-closed.
#   L-series: live observe/notify steps; disruptive steps never run live;
#             Decision Engine consistency (only ledger plan steps run).
#   G-series: timeout and whole-process-group termination (leftover
#             children, a child holding the pipe, noisy output).
#   E-series: emergency stop -- runner poll, wad_estop.sh ending groups of a
#             dead runner, pid-reuse guard, unwritable stop dir.
#   F-series: stop already engaged, SHUTDOWN.lock, unreadable stop path,
#             spawn failure, permission-denied kill (simulated in-process).
#   Q-series: hourly live cap, failure breaker.
#   B-series: live rollback (monitor_restore) needs an allowlisted operator;
#             a failed compensation leaves the step where it was.
#   A-series: audit records and chain integrity.
#   S-series: only the runner spawns; the runner can never name a
#             disruptive action or touch a stop signal.
#
# Every adapter is a test script inside the temp root. Runs inside
# tests/lib/test_isolation.sh (sudo/ssh/scp/curl/nc/osascript are stubs).

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR" || exit 1
# shellcheck source=tests/lib/test_isolation.sh
. tests/lib/test_isolation.sh
waio_test_isolate wad_runner || exit 3
waio_test_assert_isolated || exit 3

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

T="$WAIO_TEST_ROOT/wadx"
mkdir -p "$T/bin"
chmod 700 "$T" "$T/bin"
NOW="2026-10-27T02:00:00Z"
LATER="2026-10-27T03:01:00Z"
GOOD="monitoring restored after review of the alert"
export WAD_STATE_DIR="$T/state"
export WAD_STOP_FILE="$T/STOP"
export WAD_RUNNER_CONFIG="$T/runner.json"
export WAD_SECRET_TEST="must-not-reach-adapter"
unset WAD_LEDGER_HMAC_KEY_FILE WAD_APPROVER_ALLOWLIST WAD_APPROVAL_TTL_S

# Kill anything this suite started, whatever happened.
cleanup() {
  local f p
  for f in "$T"/*.leader "$T"/*.child "$T"/*.pid; do
    [ -f "$f" ] || continue
    p=$(cat "$f" 2>/dev/null)
    [[ "$p" =~ ^[0-9]+$ ]] && [ "$p" -gt 1 ] && kill -9 "$p" 2>/dev/null
  done
  chmod -R u+rwx "$T" 2>/dev/null
  waio_test_cleanup
}
trap cleanup EXIT

wad() { python3 security/wad/wad.py "$@" > "$T/out.json" 2> "$T/err.txt"; echo $?; }
out() { python3 -c "import json,sys; r=json.load(open('$T/out.json')); print($1)"; }
violations() { out "','.join(r.get('violations', []))"; }
alive() { if kill -0 "$1" 2>/dev/null; then echo alive; else echo dead; fi; }
ps_start() { LC_ALL=C ps -o lstart= -p "$1" 2>/dev/null | tr -s ' \t' '  ' | sed 's/^ //; s/ $//'; }
wait_file() { local i; for i in $(seq 1 100); do [ -s "$1" ] && return 0; sleep 0.05; done; return 1; }
calls() { if [ -f "$T/calls" ]; then grep -c . "$T/calls"; else echo 0; fi; }
count_type() { python3 -c "
import json,sys
print(sum(1 for l in open('$WAD_STATE_DIR/ledger.jsonl') if l.strip() and json.loads(l).get('event_type')==sys.argv[1]))" "$1"; }
last_live_result() { python3 -c "
import json
r=[json.loads(l) for l in open('$WAD_STATE_DIR/ledger.jsonl') if l.strip()]
r=[x for x in r if x.get('live') and isinstance(x.get('result'), dict) and x['result'].get('outcome')]
print(r[-1]['result'].get('$1') if r else 'none')"; }
state() { wad response list > /dev/null; out "[s['state'] for s in r if s['step_id']=='$1'][0]"; }
libsh_verify() {
  WAIO_AUDIT_LOG="$WAD_STATE_DIR/ledger.jsonl" WAIO_AUDIT_LOG_CHECKPOINT="$WAD_STATE_DIR/ledger.checkpoint" \
    bash -c '. security/lib.sh; verify_audit_log_integrity'
}

# ---- adapters (paths baked in: the runner gives adapters no inherited env)
mkadapter() {  # mkadapter NAME BODY
  printf '#!/bin/bash\n%s\n' "$2" > "$T/bin/$1"
  chmod 700 "$T/bin/$1"
}
mkadapter ok.sh "printf '%s %s %s %s\n' \"\$WAD_ACTION\" \"\$WAD_ENTITY\" \"\$WAD_STEP_ID\" \"\$WAD_MODE\" >> '$T/calls'
env > '$T/env.'\"\$WAD_ACTION\"
echo done"
mkadapter fail.sh "echo \"\$WAD_ACTION fail\" >> '$T/calls'; echo boom; exit 1"
mkadapter slow.sh "echo \$\$ > '$T/slow.leader'
sleep 30 &
echo \$! > '$T/slow.child'
wait"
mkadapter orphan.sh "( sleep 30 ) > /dev/null 2>&1 < /dev/null &
echo \$! > '$T/orphan.child'
echo \"\$WAD_ACTION orphan\" >> '$T/calls'
exit 0"
mkadapter pipeholder.sh "sleep 30 &
echo \$! > '$T/pipe.child'
echo \"\$WAD_ACTION pipe\" >> '$T/calls'
exit 0"
mkadapter stubborn.sh "trap '' TERM
echo \$\$ > '$T/stub.leader'
sleep 30 &
echo \$! > '$T/stub.child'
wait"
mkadapter noisy.sh "head -c 2000000 /dev/zero | tr '\\\\000' x; echo END"
printf '#!/nonexistent/interpreter\n' > "$T/bin/badinterp.sh"; chmod 700 "$T/bin/badinterp.sh"

cfg() {  # cfg CAP ACTION=ADAPTER:TIMEOUT ... -> writes $WAD_RUNNER_CONFIG (0600)
  local cap="$1"; shift
  python3 - "$WAD_RUNNER_CONFIG" "$cap" "$T/bin" "$@" <<'PY'
import json, os, sys
path, cap, bindir = sys.argv[1], int(sys.argv[2]), sys.argv[3]
adapters = {}
for spec in sys.argv[4:]:
    action, rest = spec.split("=", 1)
    script, timeout = rest.split(":")
    adapters[action] = {"argv": [os.path.join(bindir, script)], "timeout_s": int(timeout)}
with open(path, "w") as f:
    json.dump({"version": 1, "max_live_per_hour": cap, "adapters": adapters}, f)
os.chmod(path, 0o600)
PY
}

mkevents() {  # mkevents FILE ENTITY... -- one local CRITICAL event per entity
  local f="$1" e; shift
  : > "$f"
  for e in "$@"; do
    printf '{"event_id":"ev-%s","source_module":"shadow_ai_monitor","entity":"%s","entity_type":"agent","risk":"CRITICAL","confidence":"HIGH","observed_at":"2026-10-27T01:00:00Z"}\n' "$e" "$e" >> "$f"
  done
}

steps_of() {  # steps_of ENTITY -> "M W R I" step ids in plan order
  wad response list > /dev/null
  out "' '.join(s['step_id'] for s in sorted([s for s in r if s['entity']=='$1'], key=lambda s: s['index']))"
}

fresh() {  # fresh [ENTITY...] -- new state; one L4 decision per entity (default worker-a)
  rm -rf "$WAD_STATE_DIR" "$WAD_STOP_FILE" "$T/calls" "$T"/env.* "$T"/*.leader "$T"/*.child
  rm -f "$WAIO_SHUTDOWN_LOCK"
  mkdir -p "$WAD_STATE_DIR"
  printf 'masa\n' > "$WAD_STATE_DIR/approvers"
  [ $# -gt 0 ] || set -- worker-a
  mkevents "$T/ev.jsonl" "$@"
  wad evaluate --events "$T/ev.jsonl" --now "$NOW" > /dev/null
  read -r M W R I <<< "$(steps_of "$1")"
}

echo "=== C-series: default dry run; runner config fails closed ==="
fresh
rm -f "$WAD_RUNNER_CONFIG"
assert_eq "C1 execute without --live is a dry run" "0 DRY_RUN 0" "$(wad response execute "$M" --now "$NOW") $(python3 -c "
import json
r=[json.loads(l) for l in open('$WAD_STATE_DIR/ledger.jsonl')]
print([x for x in r if x.get('action')=='complete'][-1]['result']['result'])") $(calls)"
fresh
assert_eq "C2 --live with no config refused" "6" "$(wad response execute "$M" --live --now "$NOW")"
assert_eq "C2 violation names the config" "1" "$(violations | grep -c 'runner_config_refused')"
assert_eq "C2 step did not move, adapter not run" "planned 0" "$(state "$M") $(calls)"
assert_eq "C2 refusal recorded" "1" "$(count_type wad_transition_refused)"

refused_cfg() {  # refused_cfg LABEL -- config already written; expects refusal and no call
  fresh
  assert_eq "C3 refused: $1" "6 0" "$(wad response execute "$M" --live --now "$NOW") $(calls)"
}
cfg 10 monitor_increase=ok.sh:5; chmod 644 "$WAD_RUNNER_CONFIG"; chmod g+w "$WAD_RUNNER_CONFIG"; refused_cfg "group-writable config"
cfg 10 monitor_increase=ok.sh:5; mv "$WAD_RUNNER_CONFIG" "$T/real.json"; ln -s "$T/real.json" "$WAD_RUNNER_CONFIG"; refused_cfg "symlinked config"; rm -f "$WAD_RUNNER_CONFIG"
cfg 10 monitor_increase=ok.sh:5 isolate_agent=ok.sh:5; refused_cfg "config naming a disruptive action"
cfg 10 monitor_increase=ok.sh:5 restrict_egress=ok.sh:5; refused_cfg "config naming restrict_egress"
cfg 10 monitor_increase=ok.sh:5 release_isolation=ok.sh:5; refused_cfg "config naming release_isolation"
cfg 10 monitor_increase=ok.sh:0; refused_cfg "timeout 0"
cfg 10 monitor_increase=ok.sh:61; refused_cfg "timeout 61"
cfg 61 monitor_increase=ok.sh:5; refused_cfg "max_live_per_hour 61"
python3 -c "import json,os; json.dump({'version':1,'max_live_per_hour':5,'adapters':{'monitor_increase':{'argv':['bin/ok.sh'],'timeout_s':5}}}, open('$WAD_RUNNER_CONFIG','w')); os.chmod('$WAD_RUNNER_CONFIG',0o600)"; refused_cfg "relative adapter path"
python3 -c "import json,os; json.dump({'version':2,'max_live_per_hour':5,'adapters':{}}, open('$WAD_RUNNER_CONFIG','w')); os.chmod('$WAD_RUNNER_CONFIG',0o600)"; refused_cfg "unknown version"
python3 -c "import json,os; json.dump({'version':1,'max_live_per_hour':5,'adapters':{},'extra':1}, open('$WAD_RUNNER_CONFIG','w')); os.chmod('$WAD_RUNNER_CONFIG',0o600)"; refused_cfg "extra key"
python3 -c "import json,os; json.dump({'version':1,'max_live_per_hour':5,'adapters':{'monitor_increase':{'argv':['$T/bin/ok.sh'],'timeout_s':True}}}, open('$WAD_RUNNER_CONFIG','w')); os.chmod('$WAD_RUNNER_CONFIG',0o600)"; refused_cfg "boolean timeout"
printf '{not json' > "$WAD_RUNNER_CONFIG"; chmod 600 "$WAD_RUNNER_CONFIG"; refused_cfg "non-JSON config"
cp "$T/bin/ok.sh" "$T/bin/noexec.sh"; chmod 600 "$T/bin/noexec.sh"
cfg 10 monitor_increase=noexec.sh:5; refused_cfg "non-executable adapter"
mkdir -p "$T/gw"; cp "$T/bin/ok.sh" "$T/gw/ok.sh"; chmod 777 "$T/gw"
python3 -c "import json,os; json.dump({'version':1,'max_live_per_hour':5,'adapters':{'monitor_increase':{'argv':['$T/gw/ok.sh'],'timeout_s':5}}}, open('$WAD_RUNNER_CONFIG','w')); os.chmod('$WAD_RUNNER_CONFIG',0o600)"; refused_cfg "adapter in a world-writable directory"
chmod 700 "$T/gw"
cfg 10 warn_operator=ok.sh:5; refused_cfg "no adapter for the step's action"

echo ""
echo "=== L-series: live non-disruptive steps; disruptive never live ==="
fresh
cfg 10 monitor_increase=ok.sh:5 warn_operator=ok.sh:5 monitor_restore=ok.sh:5
assert_eq "L1 live monitor_increase rc" "0" "$(wad response execute "$M" --live --now "$NOW")"
assert_eq "L1 step done" "done" "$(state "$M")"
assert_eq "L1 adapter got action/entity/step/mode" "monitor_increase worker-a $M live" "$(cat "$T/calls")"
assert_eq "L1 adapter env has no inherited secret" "0" "$(grep -c WAD_SECRET_TEST "$T/env.monitor_increase")"
assert_eq "L1 adapter PATH is the fixed one" "PATH=/usr/bin:/bin:/usr/sbin:/sbin" "$(grep '^PATH=' "$T/env.monitor_increase")"
assert_eq "L1 ledger result" "ok True" "$(last_live_result outcome) $(last_live_result group_terminated)"
assert_eq "L1 no active record left" "0" "$(find "$WAD_STATE_DIR/runner/active" -type f | grep -c . || true)"
assert_eq "L2 live warn_operator" "0 done" "$(wad response execute "$W" --live --now "$NOW") $(state "$W")"
assert_eq "L3 approved disruptive step: approve ok" "0" "$(wad response approve "$R" --operator masa --reason "egress restriction reviewed and approved" --now "$NOW")"
before=$(calls)
assert_eq "L3 approved restrict_egress refused live" "6" "$(wad response execute "$R" --live --now "$NOW")"
assert_eq "L3 violation names class and action" "1 1" "$(violations | grep -c 'live_not_allowed:restrict_egress') $(violations | grep -c 'live_not_allowed_for_class:disruptive')"
assert_eq "L3 step stays approved, adapter not run" "approved $before" "$(state "$R") $(calls)"
assert_eq "L3 unapproved isolate_agent refused live" "6 awaiting_approval" "$(wad response execute "$I" --live --now "$NOW") $(state "$I")"
assert_eq "L4 a step id not in the ledger is refused" "6" "$(wad response execute 0123456789abcdef --live --now "$NOW")"
assert_eq "L4 malformed step id refused" "1" "$(wad response execute '../../x' --live --now "$NOW")"
assert_eq "L5 repeat execute of a done step refused, adapter not rerun" "6 2" "$(wad response execute "$M" --live --now "$NOW") $(calls)"
assert_eq "L6 executed action equals the Decision Engine plan's action" "monitor_increase" "$(python3 -c "
import json
d=[json.loads(l) for l in open('$WAD_STATE_DIR/ledger.jsonl') if '\"wad_decision\"' in l][0]
print(d['plan']['steps'][0]['action'])")"

echo ""
echo "=== G-series: timeout and process-group termination ==="
fresh
cfg 10 monitor_increase=slow.sh:1
SECONDS=0
wad response execute "$M" --live --now "$NOW" > /dev/null
elapsed=$SECONDS
assert_eq "G1 timeout -> failed" "failed timeout" "$(state "$M") $(last_live_result outcome)"
assert_eq "G1 returned within 6 s" "yes" "$([ "$elapsed" -le 6 ] && echo yes || echo "no ($elapsed s)")"
assert_eq "G1 leader and background child both ended" "dead dead" "$(alive "$(cat "$T/slow.leader")") $(alive "$(cat "$T/slow.child")")"
assert_eq "G1 group confirmed gone" "True" "$(last_live_result group_terminated)"
fresh
cfg 10 monitor_increase=orphan.sh:5
assert_eq "G2 adapter exits 0 leaving a detached child: done" "0 done" "$(wad response execute "$M" --live --now "$NOW") $(state "$M")"
assert_eq "G2 leftover child ended" "dead True" "$(alive "$(cat "$T/orphan.child")") $(last_live_result leftover_processes_terminated)"
fresh
cfg 10 monitor_increase=pipeholder.sh:5
SECONDS=0
wad response execute "$M" --live --now "$NOW" > /dev/null
elapsed=$SECONDS
assert_eq "G3 child holding the pipe does not turn exit 0 into a timeout" "done ok" "$(state "$M") $(last_live_result outcome)"
assert_eq "G3 finished in under 4 s, child ended" "yes dead" "$([ "$elapsed" -le 4 ] && echo yes || echo "no ($elapsed s)") $(alive "$(cat "$T/pipe.child")")"
fresh
cfg 10 monitor_increase=noisy.sh:10
wad response execute "$M" --live --now "$NOW" > /dev/null
assert_eq "G4 2 MB of output: done, tail capped at 512" "done True True" "$(state "$M") $(python3 -c "
import json
r=[json.loads(l) for l in open('$WAD_STATE_DIR/ledger.jsonl') if l.strip()]
x=[e for e in r if e.get('live') and isinstance(e.get('result'),dict) and 'output_tail' in e['result']][-1]['result']
print(len(x['output_tail'])<=512, x['output_bytes']>=2000000)")"

fresh
cfg 10 monitor_increase=stubborn.sh:1
SECONDS=0
wad response execute "$M" --live --now "$NOW" > /dev/null
elapsed=$SECONDS
assert_eq "G5 SIGTERM-ignoring group is SIGKILLed on timeout" "failed timeout dead dead" "$(state "$M") $(last_live_result outcome) $(alive "$(cat "$T/stub.leader")") $(alive "$(cat "$T/stub.child")")"
assert_eq "G5 within 8 s" "yes" "$([ "$elapsed" -le 8 ] && echo yes || echo "no ($elapsed s)")"

echo ""
echo "=== E-series: emergency stop ends the whole managed group ==="
fresh
cfg 10 monitor_increase=slow.sh:20
( wait_file "$T/slow.child" && touch "$WAIO_SHUTDOWN_LOCK" ) &
toucher=$!
SECONDS=0
wad response execute "$M" --live --now "$NOW" > /dev/null
elapsed=$SECONDS
wait "$toucher"
assert_eq "E0 SHUTDOWN.lock alone (no estop) ends a live run via the runner's own check" "failed halted_stop dead dead" "$(state "$M") $(last_live_result outcome) $(alive "$(cat "$T/slow.leader")") $(alive "$(cat "$T/slow.child")")"
assert_eq "E0 within 8 s" "yes" "$([ "$elapsed" -le 8 ] && echo yes || echo "no ($elapsed s)")"
rm -f "$WAIO_SHUTDOWN_LOCK"
fresh
cfg 10 monitor_increase=slow.sh:20
( wait_file "$T/slow.leader" && wait_file "$T/slow.child" && security/wad/wad_estop.sh engage --reason "test stop during live run" > "$T/estop1.out" 2>&1 ) &
stopper=$!
SECONDS=0
wad response execute "$M" --live --now "$NOW" > /dev/null
elapsed=$SECONDS
wait "$stopper"
assert_eq "E1 stop during a live run -> failed, halted_stop" "failed halted_stop" "$(state "$M") $(last_live_result outcome)"
assert_eq "E1 ended within 8 s, leader and child dead" "yes dead dead" "$([ "$elapsed" -le 8 ] && echo yes || echo "no ($elapsed s)") $(alive "$(cat "$T/slow.leader")") $(alive "$(cat "$T/slow.child")")"
assert_eq "E1 breaker not involved, stop still engaged" "engaged" "$([ -e "$WAD_STOP_FILE" ] && echo engaged)"

fresh
cfg 10 monitor_increase=slow.sh:30
python3 security/wad/wad.py response execute "$M" --live --now "$NOW" > /dev/null 2>&1 &
runner=$!
echo "$runner" > "$T/runner.pid"
wait_file "$T/slow.child"
kill -9 "$runner" 2>/dev/null; wait "$runner" 2>/dev/null
assert_eq "E2 runner killed: its adapter group survives on its own" "alive alive" "$(alive "$(cat "$T/slow.leader")") $(alive "$(cat "$T/slow.child")")"
assert_eq "E2 active record present" "1" "$(find "$WAD_STATE_DIR/runner/active" -type f ! -name '*.tmp' | grep -c .)"
assert_eq "E2 wad_estop.sh engage rc 0" "0" "$(security/wad/wad_estop.sh engage --reason "runner is dead" > "$T/estop2.out" 2>&1; echo $?)"
assert_eq "E2 estop reports one group ended" "1" "$(grep -c 'ended=1 ' "$T/estop2.out")"
assert_eq "E2 leader and child ended by estop" "dead dead" "$(alive "$(cat "$T/slow.leader")") $(alive "$(cat "$T/slow.child")")"
assert_eq "E2 active record removed" "0" "$(find "$WAD_STATE_DIR/runner/active" -type f | grep -c . || true)"
security/wad/wad_estop.sh release --operator masa --reason "test release after dead runner" > /dev/null
assert_eq "E2 sweep marks the interrupted step failed" "0 failed" "$(wad response sweep --now "$NOW") $(state "$M")"

fresh
cfg 10 monitor_increase=stubborn.sh:30
python3 security/wad/wad.py response execute "$M" --live --now "$NOW" > /dev/null 2>&1 &
runner=$!
echo "$runner" > "$T/runner2.pid"
wait_file "$T/stub.child"
kill -9 "$runner" 2>/dev/null; wait "$runner" 2>/dev/null
assert_eq "E2b estop SIGKILLs a SIGTERM-ignoring group of a dead runner" "0 dead dead" "$(security/wad/wad_estop.sh engage > /dev/null 2>&1; echo $?) $(alive "$(cat "$T/stub.leader")") $(alive "$(cat "$T/stub.child")")"

fresh
mkdir -p "$WAD_STATE_DIR/runner/active"
victim=$(python3 -c "import subprocess as s; print(s.Popen(['sleep','30'], start_new_session=True, stdin=s.DEVNULL, stdout=s.DEVNULL, stderr=s.DEVNULL).pid)")
echo "$victim" > "$T/victim.pid"
assert_eq "E3 precondition: unrelated process alive" "alive" "$(alive "$victim")"
printf '%s\nMon Jan  1 00:00:00 2001\nfake\n' "$victim" > "$WAD_STATE_DIR/runner/active/$victim"
assert_eq "E3 pid-reuse record: estop rc 0" "0" "$(security/wad/wad_estop.sh engage > "$T/estop3.out" 2>&1; echo $?)"
assert_eq "E3 unrelated group with a reused pid is NOT killed" "alive" "$(alive "$victim")"
assert_eq "E3 record moved to stale/" "1 0" "$(find "$WAD_STATE_DIR/runner/stale" -type f | grep -c .) $(find "$WAD_STATE_DIR/runner/active" -type f | grep -c . || true)"
printf '%s\nunknown\nfake\n' "$victim" > "$WAD_STATE_DIR/runner/active/$victim"
assert_eq "E4 unverifiable start time: not killed, estop rc 3" "3 alive" "$(security/wad/wad_estop.sh engage > /dev/null 2>&1; echo $?) $(alive "$victim")"
kill -9 "$victim" 2>/dev/null

fresh
mkdir -p "$WAD_STATE_DIR/runner/active"
managed=$(python3 -c "import subprocess as s; print(s.Popen(['sleep','30'], start_new_session=True, stdin=s.DEVNULL, stdout=s.DEVNULL, stderr=s.DEVNULL).pid)")
echo "$managed" > "$T/managed.pid"
assert_eq "E5 precondition: managed process alive with a start time" "alive yes" "$(alive "$managed") $([ -n "$(ps_start "$managed")" ] && echo yes)"
printf '%s\n%s\nstep\n' "$managed" "$(ps_start "$managed")" > "$WAD_STATE_DIR/runner/active/$managed"
mkdir -p "$T/ro"; chmod 500 "$T/ro"
if [ "$(id -u)" != "0" ]; then
  assert_eq "E5 stop file cannot be placed: rc 2 but the group is still ended" "2 dead" "$(WAD_STOP_FILE="$T/ro/sub/STOP" security/wad/wad_estop.sh engage > /dev/null 2>&1; echo $?) $(alive "$managed")"
else
  echo "  SKIP: E5 (running as root)"
fi
chmod 700 "$T/ro"; kill -9 "$managed" 2>/dev/null

echo ""
echo "=== F-series: fail closed before spawning ==="
fresh
cfg 10 monitor_increase=ok.sh:5
touch "$WAD_STOP_FILE"
assert_eq "F1 stop engaged: live refused, adapter not run" "6 0 planned" "$(wad response execute "$M" --live --now "$NOW") $(calls) $(state "$M")"
rm -f "$WAD_STOP_FILE"
touch "$WAIO_SHUTDOWN_LOCK"
assert_eq "F2 SHUTDOWN.lock: live refused" "6 0" "$(wad response execute "$M" --live --now "$NOW") $(calls)"
assert_eq "F2 runner never removes SHUTDOWN.lock" "yes" "$([ -e "$WAIO_SHUTDOWN_LOCK" ] && echo yes)"
rm -f "$WAIO_SHUTDOWN_LOCK"
mkdir -p "$T/closed"; chmod 000 "$T/closed"
if [ "$(id -u)" != "0" ]; then
  assert_eq "F3 unreadable stop path counts as engaged" "6 0" "$(WAD_STOP_FILE="$T/closed/STOP" wad response execute "$M" --live --now "$NOW") $(calls)"
else
  echo "  SKIP: F3 (running as root)"
fi
chmod 700 "$T/closed"
fresh
cfg 10 monitor_increase=badinterp.sh:5
assert_eq "F4 adapter cannot be spawned -> failed spawn_failed" "0 failed spawn_failed" "$(wad response execute "$M" --live --now "$NOW") $(state "$M") $(last_live_result outcome)"
assert_eq "F5 kill EPERM (simulated): group not confirmed gone, active record kept" "False True True" "$(python3 - "$T" <<'PY'
import os, sys, subprocess
sys.path.insert(0, "security/wad/runner")
import wad_runner as r
real = os.killpg
def fake(pgid, sig):
    if sig != 0:
        raise PermissionError(1, "Operation not permitted")
    return real(pgid, sig)
d = os.path.join(sys.argv[1], "eperm-active")
p = subprocess.Popen(["sleep", "30"], start_new_session=True)
r.os.killpg = fake
res = r.run_adapter(["/bin/sleep", "30"], "monitor_increase", "w", "s", 1, lambda: False, d)
r.os.killpg = real
kept = len(os.listdir(d)) == 1
for f in os.listdir(d):
    try:
        os.killpg(int(f), 9)
    except OSError:
        pass
p.kill()
print(res["group_terminated"], bool(res.get("kill_errors")), kept)
PY
)"

echo ""
echo "=== Q-series: hourly live cap and failure breaker ==="
fresh worker-a worker-b
cfg 2 monitor_increase=ok.sh:5 warn_operator=ok.sh:5
read -r BM BW _ _ <<< "$(steps_of worker-b)"
wad response execute "$M" --live --now "$NOW" > /dev/null
wad response execute "$W" --live --now "$NOW" > /dev/null
assert_eq "Q1 third live attempt in the hour refused" "6" "$(wad response execute "$BM" --live --now "$NOW")"
assert_eq "Q1 violation names the cap" "1" "$(violations | grep -c 'live_rate_limit:2/2')"
assert_eq "Q1 adapter calls stayed at 2" "2" "$(calls)"
assert_eq "Q2 dry run is not capped" "0" "$(wad response execute "$BM" --now "$NOW")"
assert_eq "Q3 an hour later the cap allows again" "0 done" "$(wad response execute "$BW" --live --now "$LATER") $(state "$BW")"
fresh w1 w2 w3 w4
cfg 60 monitor_increase=fail.sh:5
for e in w1 w2 w3; do
  read -r s _ <<< "$(steps_of "$e")"
  wad response execute "$s" --live --now "$NOW" > /dev/null
done
read -r s4 _ <<< "$(steps_of w4)"
assert_eq "Q4 three live failures open the breaker" "1" "$(count_type wad_breaker_tripped)"
assert_eq "Q4 next execute refused (breaker_open), adapter not run" "6 3" "$(wad response execute "$s4" --live --now "$NOW") $(calls)"

echo ""
echo "=== B-series: live rollback needs a human and can fail safely ==="
fresh
cfg 10 monitor_increase=ok.sh:5 warn_operator=ok.sh:5 monitor_restore=ok.sh:5
wad response execute "$M" --live --now "$NOW" > /dev/null
assert_eq "B1 live rollback without an allowlisted operator refused" "6 1" "$(wad response rollback "$M" --live --operator nobody --reason "$GOOD" --now "$NOW") $(calls)"
assert_eq "B1 automated name refused" "6" "$(wad response rollback "$M" --live --operator claude --reason "$GOOD" --now "$NOW")"
assert_eq "B2 live rollback by masa runs monitor_restore" "0 rolled_back" "$(wad response rollback "$M" --live --operator masa --reason "$GOOD" --now "$NOW") $(state "$M")"
assert_eq "B2 adapter got monitor_restore" "monitor_restore worker-a $M live" "$(tail -1 "$T/calls")"
wad response execute "$W" --live --now "$NOW" > /dev/null
assert_eq "B3 warn_operator has no compensation: live rollback refused" "6" "$(wad response rollback "$W" --live --operator masa --reason "$GOOD" --now "$NOW")"
fresh
cfg 10 monitor_increase=ok.sh:5 monitor_restore=fail.sh:5
wad response execute "$M" --live --now "$NOW" > /dev/null
assert_eq "B4 failed compensation: rc 7, step stays done" "7 done" "$(wad response rollback "$M" --live --operator masa --reason "$GOOD" --now "$NOW") $(state "$M")"
assert_eq "B4 failure recorded" "1" "$(count_type wad_live_rollback_failed)"
touch "$WAD_STOP_FILE"
assert_eq "B5 rollback refused while stop engaged" "6" "$(wad response rollback "$M" --live --operator masa --reason "$GOOD" --now "$NOW")"
rm -f "$WAD_STOP_FILE"

echo ""
echo "=== A-series: audit ==="
assert_eq "A1 wad verify-ledger" "0" "$(wad verify-ledger)"
assert_eq "A1 lib.sh verify_audit_log_integrity" "ok" "$(libsh_verify)"
assert_eq "A2 every live start has a completion record, all marked live/mode=live" "True" "$(python3 -c "
import json
r=[json.loads(l) for l in open('$WAD_STATE_DIR/ledger.jsonl') if l.strip()]
starts=[x['step_id'] for x in r if x.get('action')=='start' and x.get('live')]
ends=set(x['step_id'] for x in r if x.get('action') in ('complete','fail') and x.get('live'))
print(bool(starts) and all(s in ends for s in starts) and all(x['mode']=='live' for x in r if x.get('live')))")"
assert_eq "A3 live records never claim authentication" "0" "$(grep -c '"authenticated": true' "$WAD_STATE_DIR/ledger.jsonl" || true)"

echo ""
echo "=== S-series: only the runner spawns ==="
code_only() { grep -vE '^\s*#' "$@" | python3 -c "
import sys,re
print(re.sub(r'\"\"\"[\s\S]*?\"\"\"', '', sys.stdin.read()))"; }
SPAWN='subprocess|os\.system|os\.exec|os\.spawn|popen|os\.fork|socket|urllib|http\.client'
assert_eq "S1 wad.py, wad_lib.py, wad_response.py never spawn" "0" "$(code_only security/wad/*.py | grep -ciE "$SPAWN" || true)"
assert_eq "S1 the runner does spawn (the check above is meaningful)" "yes" "$([ "$(code_only security/wad/runner/wad_runner.py | grep -cE 'subprocess\.Popen')" -ge 1 ] && echo yes)"
assert_eq "S2 LIVE_ACTIONS is exactly the three non-disruptive actions" "['monitor_increase', 'monitor_restore', 'warn_operator']" "$(python3 -c "
import sys; sys.path.insert(0,'security/wad/runner'); import wad_runner as r; print(sorted(r.LIVE_ACTIONS))")"
assert_eq "S2 no disruptive action name in runner code" "0" "$(code_only security/wad/runner/wad_runner.py | grep -cE 'restrict_egress|isolate_agent|release_|\"recover\"' || true)"
assert_eq "S3 runner never touches stop signals or containment tools" "0" "$(code_only security/wad/runner/wad_runner.py | grep -cE 'SHUTDOWN|STOP|guardian|ducopa|containment|killswitch|pfctl|iptables|sudo' || true)"
assert_eq "S4 adapters run without a shell" "0" "$(code_only security/wad/runner/wad_runner.py | grep -cE 'shell *= *True' || true)"
assert_eq "S5 wad_estop.sh still never runs python" "0" "$(grep -vE '^\s*#' security/wad/wad_estop.sh | grep -c python || true)"
for s in sudo ssh scp curl nc osascript; do
  assert_eq "S6 stub $s never called" "0" "$(waio_test_stub_calls "$s")"
done

echo ""
echo "=== Summary: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
  echo "Failures:"
  for f in "${FAILURES[@]}"; do echo "  - $f"; done
  exit 1
fi
exit 0
