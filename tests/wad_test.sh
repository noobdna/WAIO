#!/bin/bash
set -uo pipefail

# tests/wad_test.sh -- regression + adversarial suite for WAIO Adaptive
# Defense (security/wad/).
#   U-series: wad_lib.py pure functions (policy floors, normalization,
#     assessment caps, planning, diff).
#   I-series: wad.sh CLI against fixture events in a temp dir: dry run
#     vs execute, approval hand-off, duplicates, replay, ordering,
#     freshness, rate limit, circuit breaker, timeouts, partial failure
#     and rollback, emergency stop, audit tamper, corrupt state, policy
#     anti-rollback, recovery, concurrency.
#   D-series: static guards -- WAD never reaches a containment tool, and
#     the emergency stop stays independent of the automated path.
# Every case uses its own WAD_STATE_DIR / WAD_ESTOP_FILE /
# WAIO_SHUTDOWN_LOCK under a temp dir, never security/state/.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR" || exit 1

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
    echo "  FAIL: $label (expected to contain '$needle', got: ${haystack:0:400})"
  fi
}

assert_not_contains() {
  local label="$1" haystack="$2" needle="$3"
  if [[ "$haystack" != *"$needle"* ]]; then
    PASS=$((PASS + 1)); echo "  PASS: $label"
  else
    FAIL=$((FAIL + 1)); FAILURES+=("$label (must not contain '$needle')")
    echo "  FAIL: $label (must not contain '$needle')"
  fi
}

WAD=security/wad/wad.sh
ESTOP=security/wad/wad_estop.sh
POLICY=security/wad/policies/wad_policy.v1.json
T=$(mktemp -d "${TMPDIR:-/tmp}/wad_test.XXXXXX")
trap 'chmod -R u+rwx "$T" 2>/dev/null; rm -rf "$T"' EXIT
NOW=2026-10-27T00:00:00Z

pyval() {
  python3 -I -c "
import sys, json
sys.path.insert(0, 'security/wad')
import wad_lib as L
P = json.load(open('$POLICY'))
$1
"
}

# fresh isolated environment for one case: sets SD, EF, SL
new_env() {
  local d="$T/$1"
  mkdir -p "$d"
  SD="$d/state"; EF="$d/estop/ESTOP"; SL="$d/SHUTDOWN.lock"
}

wad() {
  WAD_STATE_DIR="$SD" WAD_ESTOP_FILE="$EF" WAIO_SHUTDOWN_LOCK="$SL" WAD_FIXTURE_NOW="${FNOW:-$NOW}" \
    WAD_ADAPTER_DIR="${ADIR:-}" "$WAD" "$@"
}

# ev ID ENTITY RISK CONF LOCAL [OBSERVED_AT] [SEQ]
ev() {
  printf '{"schema":"wad-event/1","event_id":"%s","source":"fixture","entity":"%s","entity_type":"host","risk":"%s","confidence":"%s","local":%s,"observed_at":"%s","seq":%s}\n' \
    "$1" "$2" "$3" "$4" "$5" "${6:-2026-10-26T23:50:00Z}" "${7:-0}"
}

jq_py() { python3 -I -c "import json,sys; d=json.load(sys.stdin); print($1)"; }
audit_outcomes() { python3 -I -c "
import json,sys
for l in open(sys.argv[1]):
    e=json.loads(l)
    if e['type']=='event': print(e['outcome'])
" "$SD/audit.jsonl" | tr '\n' ' '; }

echo "== U-series: wad_lib.py"

r=$(pyval "print(L.validate_policy(P))")
assert_eq "U1 shipped policy v1 is valid" "[]" "$r"

r=$(pyval "
q=L.copy_policy(P); q['levels']['L4']['auto_actions'].append('isolate_host')
print(any('may never be automatic' in e for e in L.validate_policy(q)))")
assert_eq "U2 policy marking isolate_host automatic is rejected (floor 2)" "True" "$r"

r=$(pyval "
q=L.copy_policy(P); q['level_rules'].insert(0, {'risk':'HIGH','level':'L4'})
print(any('requires local: true' in e for e in L.validate_policy(q)))")
assert_eq "U3 rule reaching L4 without local:true is rejected (floor 1)" "True" "$r"

r=$(pyval "
q=L.copy_policy(P); q['levels']['L1']['steps'].append('restrict_network')
print(any('below L3' in e for e in L.validate_policy(q)))")
assert_eq "U4 destructive step below L3 is rejected" "True" "$r"

r=$(pyval "
q=L.copy_policy(P); q['levels']['L2']['steps'].append('format_disk')
print(any('unknown action' in e for e in L.validate_policy(q)))")
assert_eq "U5 unknown action rejected" "True" "$r"

r=$(pyval "
q=L.copy_policy(P); q['version']=True; q['step_timeout_seconds']=9999
e=L.validate_policy(q); print(any('version' in x for x in e), any('<= 300' in x for x in e))")
assert_eq "U6 bool version and oversized timeout rejected" "True True" "$r"

r=$(pyval "
ev,err=L.normalize_event({'schema':'wad-event/1','event_id':'a1','source':'s','entity':'h','risk':'HIGH','confidence':'HIGH','local':True,'observed_at':'2026-10-26T00:00:00Z'})
print(err, ev['incomplete'])")
assert_eq "U7 well-formed event normalizes with no errors" "[] False" "$r"

r=$(pyval "
for raw in [None, [], {'schema':'wad-event/1'}, {'schema':'x','event_id':'../../etc','source':'s s','entity':'a\nb','risk':'EXTREME','confidence':'SURE','local':'yes','observed_at':'2026-10-26 00:00','seq':-1}]:
    ev,err=L.normalize_event(raw); print(ev['incomplete'], len(err)>0, end=' ')")
assert_eq "U8 garbage inputs never raise and are marked incomplete" "True True True True True True True True " "$r"

r=$(pyval "
ev,err=L.normalize_event({'schema':'wad-event/1','event_id':'a1','source':'s','entity':'h','risk':'HIGH','confidence':'HIGH','local':True,'observed_at':'2026-10-26T09:00:00+09:00'})
print('observed_at' in ' '.join(err))")
assert_eq "U9 non-UTC offset refused, not guessed" "True" "$r"

r=$(pyval "
def lv(risk,conf,local):
    ev,err=L.normalize_event({'schema':'wad-event/1','event_id':'a','source':'s','entity':'h','risk':risk,'confidence':conf,'local':local,'observed_at':'2026-10-26T00:00:00Z'})
    return L.assess(ev,err,P)['level']
print(lv('CRITICAL','HIGH',True), lv('CRITICAL','HIGH',False), lv('HIGH','HIGH',True), lv('HIGH','MEDIUM',True), lv('MEDIUM','LOW',False), lv('MEDIUM','HIGH',True), lv('LOW','HIGH',True))")
assert_eq "U10 level table incl. non-local CRITICAL capped at L2" "L4 L2 L3 L2 L1 L2 L0" "$r"

r=$(pyval "
q=L.copy_policy(P); q['level_rules'][0]['min_confidence']='LOW'
ev,err=L.normalize_event({'schema':'wad-event/1','event_id':'a','source':'s','entity':'h','risk':'CRITICAL','confidence':'LOW','local':True,'observed_at':'2026-10-26T00:00:00Z'})
a=L.assess(ev,err,q); print(a['level'], a['uncertain'])")
assert_eq "U11 LOW confidence never reaches L3+ even if policy allows (floor 3)" "L2 True" "$r"

r=$(pyval "
ev,err=L.normalize_event({'schema':'wad-event/1','event_id':'a','source':'s','risk':'CRITICAL','confidence':'HIGH','local':True,'observed_at':'2026-10-26T00:00:00Z'})
a=L.assess(ev,err,P); print(a['level'], a['uncertain'], a['confidence'])")
assert_eq "U12 incomplete CRITICAL event -> L2 uncertain, never L4" "L2 True HIGH" "$r"

r=$(pyval "
p=L.plan_for('L4',P); print([(s['action'],s['mode']) for s in p['steps']])")
assert_eq "U13 L4 plan: auto local steps, isolate_host pending approval" "[('monitor_up', 'auto'), ('warn', 'auto'), ('isolate_host', 'pending_approval')]" "$r"

r=$(pyval "
p=L.recovery_plan('L4',P); print([(s['action'],s['mode']) for s in p['steps']])")
assert_eq "U14 recovery of L4: release pending approval, monitor_down auto, reverse order" "[('release_host', 'pending_approval'), ('monitor_down', 'auto')]" "$r"

r=$(pyval "
q=L.copy_policy(P); q['version']=2; q['rate_limits']['auto_actions_per_hour']=10; q['levels']['L1']['steps']=['monitor_up']; q['levels']['L1']['auto_actions']=['monitor_up']
d=L.diff_policies(P,q); print(sorted(x['path'] for x in d))")
assert_eq "U15 policy diff lists exactly the changed paths" "['levels.L1.auto_actions', 'levels.L1.steps', 'rate_limits.auto_actions_per_hour', 'version']" "$r"

r=$(pyval "
for n in ['masa','ops.lead@example','claude','wad-runner','autopilot','root','x y','']:
    print(L.validate_operator(n)['valid'], end=' ')")
assert_eq "U16 operator identity: humans ok, automated actors and bad shapes refused" "True True False False False False False False " "$r"

r=$(pyval "
import datetime
now=L.parse_utc('2026-10-27T00:00:00Z')
mk=lambda t: L.normalize_event({'schema':'wad-event/1','event_id':'a','source':'s','entity':'h','risk':'LOW','confidence':'LOW','local':False,'observed_at':t})[0]
print(L.check_freshness(mk('2026-10-25T23:59:59Z'),now,P) is not None, L.check_freshness(mk('2026-10-26T00:00:00Z'),now,P), L.check_freshness(mk('2026-10-27T00:05:00Z'),now,P), L.check_freshness(mk('2026-10-27T00:05:01Z'),now,P) is not None)")
assert_eq "U17 freshness boundaries: 24h+1s stale, exactly 24h ok, +300s ok, +301s refused" "True None None True" "$r"

echo "== I-series: wad.sh"

new_env i1
{ ev e1 web01 CRITICAL HIGH true; ev e2 web02 MEDIUM LOW false; ev e3 web03 LOW HIGH true; } > "$T/i1.jsonl"
out=$(wad respond --in "$T/i1.jsonl"); rc=$?
assert_eq "I1 dry run exits 0" "0" "$rc"
assert_contains "I1 dry run reports mode" "$out" '"mode": "dryrun"'
assert_eq "I1 dry run wrote no watchlist, alerts or approval requests" "no no no" \
  "$([ -d "$SD/watchlist" ] && echo yes || echo no) $([ -f "$SD/alerts.jsonl" ] && echo yes || echo no) $([ -d "$SD/approval_requests" ] && echo yes || echo no)"
a=$(cat "$SD/audit.jsonl")
assert_contains "I1 audit records reasons, confidence and policy version" "$a" '"reasons":["risk=CRITICAL confidence=HIGH local=True -> L4 (level_rules[0])"]'
assert_contains "I1 audit records the policy digest" "$a" '"sha256":"985cfbb884d623f5245116b70c368c4aa270fcd7b6d6f951fcc70ca078072111"'
assert_contains "I1 isolate_host is a pending approval even in dry run" "$a" '"action":"isolate_host","mode":"pending_approval"'
assert_eq "I1 audit chain verifies" "0" "$(wad audit-verify >/dev/null; echo $?)"

out=$(wad respond --in "$T/i1.jsonl" --execute); rc=$?
assert_eq "I2 execute after dry run is not deduplicated by the dry run (separate state)" "0" "$rc"
assert_contains "I2 execute processed all three" "$out" '"planned": 3'
assert_eq "I2 watchlist has entries for web01/web02 (L4, L1), none for L0 web03" "2" "$(find "$SD/watchlist" -name '*.json' | wc -l | tr -d ' ')"
assert_eq "I2 one alert for the L4 event" "1" "$(wc -l < "$SD/alerts.jsonl" | tr -d ' ')"
req=$(cat "$SD"/approval_requests/*.json)
assert_contains "I2 isolate_host became an approval request hand-off" "$req" '"action": "isolate_host"'
assert_contains "I2 hand-off names the existing approval path" "$req" "containment_approval_gate.sh"

out=$(wad respond --in "$T/i1.jsonl" --execute)
assert_contains "I3 replaying the same batch is fully deduplicated" "$out" '"duplicate_suppressed": 3'

new_env i4
ev e1 web01 HIGH HIGH true > "$T/i4a.jsonl"
ev e1 web01 LOW LOW false > "$T/i4b.jsonl"
wad respond --in "$T/i4a.jsonl" --execute >/dev/null
out=$(wad respond --in "$T/i4b.jsonl" --execute)
assert_contains "I4 same event_id with different content -> replay_conflict" "$out" '"replay_conflict": 1'
assert_eq "I4 replay conflict only warned (no new watchlist level change)" "L3" \
  "$(wad status | jq_py "d['execute']['entities']['web01']['level']")"

new_env i5
{ ev late web01 MEDIUM LOW false 2026-10-26T23:40:00Z; ev early web01 HIGH HIGH true 2026-10-26T23:50:00Z; } > "$T/i5.jsonl"
wad respond --in "$T/i5.jsonl" --execute >/dev/null
assert_eq "I5 batch is ordered by observed_at before processing" "planned planned " "$(audit_outcomes)"
ev older web01 MEDIUM HIGH false 2026-10-26T23:30:00Z > "$T/i5b.jsonl"
FNOW=2026-10-27T01:00:00Z wad respond --in "$T/i5b.jsonl" --execute >/dev/null
assert_contains "I5 an older, lower event after a newer one is superseded" "$(audit_outcomes)" "superseded_out_of_order"
assert_eq "I5 superseded event cannot lower the active level" "L3" \
  "$(wad status | jq_py "d['execute']['entities']['web01']['level']")"

new_env i6
{ ev a1 web01 MEDIUM LOW false 2026-10-26T23:50:00Z; ev a2 web01 MEDIUM LOW false 2026-10-26T23:51:00Z; ev a3 web01 CRITICAL HIGH true 2026-10-26T23:52:00Z; } > "$T/i6.jsonl"
out=$(wad respond --in "$T/i6.jsonl" --execute)
assert_contains "I6 repeated same-level event within cooldown suppressed, escalation still acts" "$(audit_outcomes)" "planned cooldown_suppressed planned"

new_env i7
{ ev s1 web01 HIGH HIGH true 2026-10-25T23:59:59Z; ev f1 web01 HIGH HIGH true 2026-10-27T00:06:00Z; } > "$T/i7.jsonl"
out=$(wad respond --in "$T/i7.jsonl" --execute)
assert_contains "I7 stale and future events are refused" "$out" '"refused_freshness": 2'

new_env i8
{ echo 'not json'; echo '{"schema":"wad-event/1","event_id":"x"}'; printf '%*s\n' 70000 '' | tr ' ' 'a'; ev ok web01 LOW LOW false; } > "$T/i8.jsonl"
out=$(wad respond --in "$T/i8.jsonl" --execute); rc=$?
assert_eq "I8 malformed lines do not abort the batch" "0" "$rc"
assert_contains "I8 malformed lines become uncertain L2 warnings" "$(cat "$SD/audit.jsonl")" '"level":"L2","reasons":["incomplete event: line 1 is not JSON"'
assert_eq "I8 three warnings raised for three malformed lines" "3" "$(wc -l < "$SD/alerts.jsonl" | tr -d ' ')"

new_env i9
cat > "$T/report.json" <<'EOF'
{"generated_at":"2026-10-26T23:55:00Z","decisions":[
 {"entity":"203.0.113.9","entity_type":"ip","risk":"CRITICAL","confidence":"HIGH","source_modules":["global_patrol","critical_infra_watch"],"recommended_action":"ALERT_HUMAN","local_corroboration":{"present":false,"modules":[]}},
 {"entity":"proc:evil","entity_type":"process","risk":"CRITICAL","confidence":"HIGH","source_modules":["shadow_ai_monitor"],"recommended_action":"RECOMMEND_CONTAINMENT","local_corroboration":{"present":true,"modules":["shadow_ai_monitor"]}}]}
EOF
out=$(wad assess --decisions "$T/report.json")
assert_eq "I9 Decision Engine report: global-only CRITICAL -> L2, local CRITICAL -> L4" "L2 L4" \
  "$(echo "$out" | jq_py "' '.join(sorted(x['assessment']['level'] for x in d))")"
wad respond --decisions "$T/report.json" --execute >/dev/null
out=$(wad respond --decisions "$T/report.json" --execute)
assert_contains "I9 decision records get stable ids (re-ingest deduplicated)" "$out" '"duplicate_suppressed": 2'

new_env i10
python3 -I -c "
for i in range(40): print('{\"schema\":\"wad-event/1\",\"event_id\":\"r%d\",\"source\":\"fixture\",\"entity\":\"h%d\",\"risk\":\"HIGH\",\"confidence\":\"LOW\",\"local\":false,\"observed_at\":\"2026-10-26T23:50:00Z\"}' % (i,i))
" > "$T/i10.jsonl"
wad respond --in "$T/i10.jsonl" --execute >/dev/null
n=$(python3 -I -c "
import json
c=0
for l in open('$SD/audit.jsonl'):
    e=json.loads(l)
    c+=sum(1 for s in e.get('steps',[]) if s['status']=='rate_limited')
print(c)")
assert_eq "I10 runaway flood: 40 events x2 auto steps capped at 60/hour (20 rate_limited)" "20" "$n"
assert_eq "I10 alerts capped too" "30" "$(wc -l < "$SD/alerts.jsonl" | tr -d ' ')"

new_env i11
ADIR="$T/adapters11"; mkdir -p "$ADIR"; chmod 755 "$ADIR"
printf '#!/bin/sh\ncat >/dev/null\necho adapter-down >&2\nexit 3\n' > "$ADIR/warn"; chmod 755 "$ADIR/warn"
{ ev b1 h1 HIGH LOW false; ev b2 h2 HIGH LOW false; ev b3 h3 HIGH LOW false; ev b4 h4 HIGH LOW false; } > "$T/i11.jsonl"
out=$(wad respond --in "$T/i11.jsonl" --execute); rc=$?
assert_eq "I11 failing adapter -> exit 1" "1" "$rc"
assert_contains "I11 circuit breaker trips after 3 consecutive failures" "$out" '"tripped": true'
assert_contains "I11 later auto steps are refused while the breaker is open" "$(cat "$SD/audit.jsonl")" '"status":"breaker_open"'
assert_contains "I11 non-atomic plan keeps monitor_up despite warn failing (fail-safe: more monitoring)" "$(cat "$SD/audit.jsonl")" '"action":"monitor_up","detail":"watchlist entry written","mode":"auto","status":"ok"'
r=$(wad breaker-reset --operator claude --reason "adapter fixed and verified" 2>&1); rc=$?
assert_eq "I11 breaker reset refused for an automated identity" "2" "$rc"
wad breaker-reset --operator masa --reason "adapter fixed and verified" >/dev/null; rc=$?
assert_eq "I11 breaker reset by a human operator" "0" "$rc"
assert_contains "I11 reset is audited with operator and reason" "$(tail -1 "$SD/audit.jsonl")" '"operator":"masa"'
ADIR=""

new_env i12
ADIR="$T/adapters12"; mkdir -p "$ADIR"; chmod 755 "$ADIR"
printf '#!/bin/sh\ncat >/dev/null\nsleep 30 &\nsleep 30\n' > "$ADIR/monitor_up"; chmod 755 "$ADIR/monitor_up"
python3 -I -c "import json;p=json.load(open('$POLICY'));p['step_timeout_seconds']=1;json.dump(p,open('$T/p_t1.json','w'))"
ev t1 h1 MEDIUM LOW false > "$T/i12.jsonl"
start=$(date +%s)
out=$(wad respond --in "$T/i12.jsonl" --execute --policy "$T/p_t1.json"); rc=$?
el=$(( $(date +%s) - start ))
assert_eq "I12 hung adapter -> step timeout, exit 1" "1" "$rc"
assert_contains "I12 timeout recorded" "$(cat "$SD/audit.jsonl")" '"status":"timeout"'
assert_eq "I12 run did not wait for the hung adapter (<10s)" "yes" "$([ "$el" -lt 10 ] && echo yes || echo no)"
sleep 1
assert_eq "I12 adapter's whole process group was killed (no orphan sleep 30)" "0" \
  "$(pgrep -f "$ADIR" 2>/dev/null | wc -l | tr -d ' ')"
ADIR=""

new_env i13
ADIR="$T/adapters13"; mkdir -p "$ADIR"; chmod 755 "$ADIR"
printf '#!/bin/sh\ncat >/dev/null\nexit 1\n' > "$ADIR/warn"; chmod 755 "$ADIR/warn"
python3 -I -c "import json;p=json.load(open('$POLICY'));p['levels']['L2']['atomic']=True;json.dump(p,open('$T/p_atomic.json','w'))"
ev x1 h1 HIGH LOW false > "$T/i13.jsonl"
wad respond --in "$T/i13.jsonl" --execute --policy "$T/p_atomic.json" >/dev/null
a=$(tail -2 "$SD/audit.jsonl" | head -1)
assert_contains "I13 atomic plan: partial failure rolls back monitor_up with monitor_down" "$a" '"mode":"rollback","rolls_back":"monitor_up","status":"ok"'
assert_eq "I13 rollback left no active watchlist entry (moved to released/)" "0 1" \
  "$(find "$SD/watchlist" -maxdepth 1 -name '*.json' | wc -l | tr -d ' ') $(find "$SD/watchlist/released" -type f | wc -l | tr -d ' ')"
ADIR=""

new_env i14
WAD_ESTOP_FILE="$EF" "$ESTOP" engage --operator masa --reason "drill" >/dev/null
ev h1 web01 CRITICAL HIGH true > "$T/i14.jsonl"
out=$(wad respond --in "$T/i14.jsonl" --execute 2>&1); rc=$?
assert_eq "I14 emergency stop engaged -> exit 7 before anything runs" "7" "$rc"
assert_eq "I14 no state written while stopped" "no" "$([ -f "$SD/state.execute.json" ] && echo yes || echo no)"
assert_contains "I14 halt is audited" "$(cat "$SD/audit.jsonl")" '"type":"run_halted"'
WAD_ESTOP_FILE="$EF" "$ESTOP" status >/dev/null; rc=$?
assert_eq "I14 estop status exit 10 when engaged" "10" "$rc"
WAD_ESTOP_FILE="$EF" "$ESTOP" release --operator wad-runner --reason "automation wants to resume" >/dev/null 2>&1; rc=$?
assert_eq "I14 release refused for an automated identity" "2" "$rc"
WAD_ESTOP_FILE="$EF" "$ESTOP" release --operator masa --reason "drill complete, verified" >/dev/null; rc=$?
assert_eq "I14 human release succeeds and keeps the file as evidence" "0 1" "$rc $(find "$(dirname "$EF")/released" -type f | wc -l | tr -d ' ')"
out=$(wad respond --in "$T/i14.jsonl" --execute); rc=$?
assert_eq "I14 event held back by the stop is processed after release" "0" "$rc"

new_env i15
ADIR="$T/adapters15"; mkdir -p "$ADIR"; chmod 755 "$ADIR"
printf '#!/bin/sh\ncat >/dev/null\nmkdir -p "%s"\ntouch "%s"\n' "$(dirname "$EF")" "$EF" > "$ADIR/monitor_up"; chmod 755 "$ADIR/monitor_up"
{ ev m1 h1 CRITICAL HIGH true; ev m2 h2 CRITICAL HIGH true; } > "$T/i15.jsonl"
out=$(wad respond --in "$T/i15.jsonl" --execute); rc=$?
assert_eq "I15 stop engaged mid-run -> exit 7" "7" "$rc"
assert_contains "I15 remaining steps of the running plan are halted" "$(cat "$SD/audit.jsonl")" '"action":"warn","mode":"auto","status":"halted_estop"'
assert_contains "I15 later events are not processed" "$out" '"not_processed_estop": 1'
ADIR=""

new_env i16
mkdir -p "$(dirname "$EF")"; chmod 000 "$(dirname "$EF")"
ev u1 web01 LOW LOW false > "$T/i16.jsonl"
out=$(wad respond --in "$T/i16.jsonl" --execute 2>&1); rc=$?
chmod 700 "$(dirname "$EF")"
if [ "$(id -u)" = "0" ]; then
  echo "  SKIP: I16 (root ignores directory permissions)"
else
  assert_eq "I16 unreadable estop dir counts as engaged (fail closed)" "7" "$rc"
fi
touch "$SL"
out=$(wad respond --in "$T/i16.jsonl" --execute 2>&1); rc=$?
assert_eq "I16 WAIO SHUTDOWN.lock also stops WAD" "7" "$rc"
rm -f "$SL"

new_env i17
ev a1 web01 MEDIUM LOW false > "$T/i17.jsonl"
wad respond --in "$T/i17.jsonl" --execute >/dev/null
python3 -I -c "
import sys
p=sys.argv[1]; ls=open(p).read().splitlines(); ls[1]=ls[1].replace('MEDIUM','LOW'); open(p,'w').write('\n'.join(ls)+'\n')" "$SD/audit.jsonl"
assert_eq "I17 edited audit entry detected" "5" "$(wad audit-verify >/dev/null; echo $?)"
ev a2 web02 MEDIUM LOW false > "$T/i17b.jsonl"
wad respond --in "$T/i17b.jsonl" --execute >/dev/null 2>&1; rc=$?
assert_eq "I17 respond refuses to append to a tampered chain" "5" "$rc"

new_env i18
ev c1 web01 MEDIUM LOW false > "$T/i18.jsonl"
mkdir -p "$SD"; echo '{"seen":' > "$SD/state.execute.json"
wad respond --in "$T/i18.jsonl" --execute >/dev/null 2>&1; rc=$?
assert_eq "I18 corrupt state -> exit 4" "4" "$rc"
assert_eq "I18 corrupt state file is not overwritten" '{"seen":' "$(cat "$SD/state.execute.json")"

new_env i19
python3 -I -c "import json;p=json.load(open('$POLICY'));p['version']=2;json.dump(p,open('$T/p_v2.json','w'))"
ev p1 web01 LOW LOW false > "$T/i19.jsonl"
wad respond --in "$T/i19.jsonl" --execute --policy "$T/p_v2.json" >/dev/null
wad respond --in "$T/i19.jsonl" --execute >/dev/null 2>&1; rc=$?
assert_eq "I19 older policy version refused after v2 was applied" "6" "$rc"
wad respond --in "$T/i19.jsonl" --execute --allow-policy-rollback --operator masa --reason "v2 regression, roll back" >/dev/null; rc=$?
assert_eq "I19 explicit operator rollback accepted" "0" "$rc"
assert_contains "I19 rollback acceptance audited" "$(cat "$SD/audit.jsonl")" '"type":"policy_rollback_accepted"'
out=$(wad policy-diff "$POLICY" "$T/p_v2.json")
assert_contains "I19 policy-diff shows the version change" "$out" '"path": "version"'

out=$(WAD_STATE_DIR="" WAD_FIXTURE_NOW=$NOW "$WAD" respond --in "$T/i19.jsonl" 2>&1); rc=$?
assert_eq "I20 fixture clock refused against the default state dir" "2" "$rc"

new_env i21
{ ev r1 web01 MEDIUM LOW false; ev r4 web04 CRITICAL HIGH true; } > "$T/i21.jsonl"
wad respond --in "$T/i21.jsonl" --execute >/dev/null
wad recover --entity web01 --operator claude --reason "false positive confirmed" --execute >/dev/null 2>&1; rc=$?
assert_eq "I21 recovery refused for an automated identity" "2" "$rc"
out=$(wad recover --entity web01 --operator masa --reason "false positive confirmed" --execute)
assert_contains "I21 L1 entity recovered" "$out" '"outcome": "recovered"'
out=$(wad recover --entity web04 --operator masa --reason "host rebuilt and verified" --execute)
assert_contains "I21 L4 recovery waits for approval of release_host" "$out" '"outcome": "recover_pending_approval"'
assert_eq "I21 L4 entity stays active until the release is approved" "L4 True" \
  "$(wad status | jq_py "d['execute']['entities']['web04']['level'], d['execute']['entities']['web04']['recovery_pending']" | tr -d "(),'")"

new_env i22
for j in 1 2 3 4; do
  python3 -I -c "
for i in range(15): print('{\"schema\":\"wad-event/1\",\"event_id\":\"c$j-%d\",\"source\":\"fixture\",\"entity\":\"h$j-%d\",\"risk\":\"MEDIUM\",\"confidence\":\"LOW\",\"local\":false,\"observed_at\":\"2026-10-26T23:50:00Z\"}' % (i,i))
" > "$T/i22_$j.jsonl"
done
for j in 1 2 3 4; do wad respond --in "$T/i22_$j.jsonl" --execute >/dev/null & done
wait
assert_eq "I22 4 concurrent runs: audit chain intact" "0" "$(wad audit-verify >/dev/null; echo $?)"
assert_eq "I22 4 concurrent runs: all 60 events recorded" "60" \
  "$(wad status | jq_py "len(d['execute']['entities'])")"

echo "== D-series: static guards"
# code only: Python comments/docstrings and shell comments stripped, so
# the headers may name the tools WAD must never call.
code=$(python3 -I - security/wad/wad_lib.py security/wad/wad_cli.py <<'PY'
import io, sys, tokenize
for path in sys.argv[1:]:
    prev = tokenize.INDENT
    for tok in tokenize.generate_tokens(io.StringIO(open(path).read()).readline):
        if tok.type == tokenize.COMMENT:
            continue
        if tok.type == tokenize.STRING and prev in (tokenize.INDENT, tokenize.NEWLINE, tokenize.NL, tokenize.DEDENT):
            prev = tok.type
            continue
        if tok.type not in (tokenize.NL, tokenize.NEWLINE, tokenize.INDENT, tokenize.DEDENT):
            print(tok.string, end=" ")
        prev = tok.type
PY
grep -v '^[[:space:]]*#' security/wad/wad.sh)
for forbidden in guardian ducopa killswitch recover.sh recovery_engine launchctl sudo pfctl networksetup curl urllib socket; do
  assert_not_contains "D1 WAD code never references $forbidden" "$code" "$forbidden"
done
r=$(grep -nE 'unlink|remove|rename|replace|open\(' security/wad/wad_cli.py | grep -i 'estop' || true)
assert_eq "D2 wad_cli.py never writes, moves or deletes the stop file" "" "$r"
r=$(grep -v '^[[:space:]]*#' security/wad/wad_estop.sh | grep -nE 'wad_cli|wad_lib|python' || true)
assert_eq "D3 wad_estop.sh shares no code with the automated path" "" "$r"
r=$(grep -c 'source \|^\. ' security/wad/wad_estop.sh security/wad/wad.sh | awk -F: '{s+=$2} END {print s}')
assert_eq "D4 neither WAD shell script sources anything" "0" "$r"

echo
echo "wad_test: $PASS passed, $FAIL failed"
if [ "$FAIL" -gt 0 ]; then
  printf '  - %s\n' "${FAILURES[@]}"
  exit 1
fi
exit 0
