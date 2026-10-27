#!/bin/bash
set -uo pipefail

# tests/wad_engine_test.sh -- regression and adversarial suite for WAIO
# Adaptive Defense (security/wad/wad_lib.py + security/wad/wad.py).
#
#   U-series: pure functions (schema boundaries, false positives/negatives,
#     order independence, duplicates/conflicts, missing information, policy
#     invariants and diff, rate limit, kill switch).
#   I-series: the CLI against a temp state dir (ledger chain checked by
#     security/lib.sh's own verify_audit_log_integrity, replay, tamper,
#     truncation, stop signals, unwritable ledger, concurrency, lock
#     timeout, runaway limit across runs, bad policy/input).
#   S-series: WAD never executes anything and never touches real state.
#
# Runs inside tests/lib/test_isolation.sh: every WAIO_* path points into a
# temp root and sudo/ssh/curl/nc/osascript are recording stubs.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR" || exit 1
# shellcheck source=tests/lib/test_isolation.sh
. tests/lib/test_isolation.sh
waio_test_isolate wad_engine || exit 3
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

T="$WAIO_TEST_ROOT/wad"
mkdir -p "$T"
POLICY="security/wad/policies/wad_policy.json"
NOW="2026-10-27T02:00:00Z"
export WAD_STATE_DIR="$T/state"
export WAD_STOP_FILE="$T/STOP"

# pyval CODE -- runs CODE with wad_lib imported as wl and helpers in scope.
pyval() {
  python3 -c "
import sys, json, copy, datetime, itertools
sys.path.insert(0, 'security/wad')
import wad_lib as wl
NOW = wl.parse_ts('$NOW')
POLICY = json.load(open('$POLICY'))
LIM = POLICY['limits']
def ev(i, entity='worker-a', src='shadow_ai_monitor', risk='HIGH', conf='HIGH', at='2026-10-27T01:00:00Z', etype='agent', **kw):
    d = {'event_id': 'e%s' % i, 'source_module': src, 'entity': entity, 'entity_type': etype,
         'risk': risk, 'confidence': conf, 'observed_at': at}
    d.update(kw)
    return {k: v for k, v in d.items() if v is not None}
def levels(raw):
    s = wl.screen_events(raw, {}, NOW, LIM)
    return {a['entity']: a['threat_level'] for a in wl.assess(s['accepted'], s['conflicts'], NOW)}
def reasons(raw):
    s = wl.normalize_event(raw, NOW, LIM)
    return ','.join(s[1] or ['ok'])
$1
"
}

# wad ARGS... -- runs the CLI; stdout to $T/out.json, rc echoed.
wad() {
  python3 security/wad/wad.py "$@" > "$T/out.json" 2> "$T/err.txt"
  echo $?
}
jq_py() { python3 -c "import json,sys; r=json.load(open('$T/out.json')); print($1)"; }
ledger_count() { python3 -c "
import json,sys
n=0
try:
    for l in open('$WAD_STATE_DIR/ledger.jsonl'):
        if l.strip() and json.loads(l).get('event_type')==sys.argv[1]: n+=1
except FileNotFoundError: pass
print(n)" "$1"; }
reset_state() { rm -rf "$WAD_STATE_DIR" "$WAD_STOP_FILE"; }

write_events() {  # write_events FILE -- JSONL from stdin
  cat > "$1"
}

echo "=== U-series: pure functions ==="

echo "[U1] a valid event normalizes; key and digest are stable"
assert_eq "U1 valid" "ok" "$(pyval "print(reasons(ev(1)))")"
assert_eq "U1 stable digest" "True" "$(pyval "a=wl.normalize_event(ev(1),NOW,LIM)[0]; b=wl.normalize_event(dict(reversed(list(ev(1).items()))),NOW,LIM)[0]; print(a['digest']==b['digest'] and a['key']==b['key'])")"
assert_eq "U1 timestamp normalized to UTC" "2026-10-27T01:00:00Z" "$(pyval "print(wl.normalize_event(ev(1, at='2026-10-27T10:00:00+09:00'),NOW,LIM)[0]['observed_at'])")"

echo "[U2] field boundaries"
assert_eq "U2 entity 256 chars ok" "ok" "$(pyval "print(reasons(ev(1, entity='x'*256)))")"
assert_eq "U2 entity 257 chars rejected" "bad_entity" "$(pyval "print(reasons(ev(1, entity='x'*257)))")"
assert_eq "U2 empty entity rejected" "bad_entity" "$(pyval "print(reasons(ev(1, entity='')))")"
assert_eq "U2 control char in entity rejected" "bad_entity" "$(pyval "print(reasons(ev(1, entity='a\\nb')))")"
assert_eq "U2 event_id 128 ok" "ok" "$(pyval "d=ev(1); d['event_id']='a'*128; print(reasons(d))")"
assert_eq "U2 event_id 129 rejected" "bad_event_id" "$(pyval "d=ev(1); d['event_id']='a'*129; print(reasons(d))")"
assert_eq "U2 event_id with slash rejected" "bad_event_id" "$(pyval "d=ev(1); d['event_id']='../x'; print(reasons(d))")"
assert_eq "U2 summary 1024 ok" "ok" "$(pyval "print(reasons(ev(1, summary='s'*1024)))")"
assert_eq "U2 summary 1025 rejected" "bad_summary" "$(pyval "print(reasons(ev(1, summary='s'*1025)))")"
assert_eq "U2 non-object rejected" "not_an_object" "$(pyval "print(reasons(['x']))")"
assert_eq "U2 numeric entity rejected" "bad_entity" "$(pyval "print(reasons(ev(1, entity=5)))")"

echo "[U3] a present-but-wrong value is rejected, not guessed"
assert_eq "U3 bad risk" "bad_risk" "$(pyval "print(reasons(ev(1, risk='SEVERE')))")"
assert_eq "U3 lowercase confidence" "bad_confidence" "$(pyval "print(reasons(ev(1, conf='high')))")"
assert_eq "U3 bad source module" "bad_source_module" "$(pyval "print(reasons(ev(1, src='Shadow AI')))")"

echo "[U4] clock: naive, future, replay window (boundaries are inclusive)"
assert_eq "U4 naive timestamp rejected" "bad_observed_at" "$(pyval "print(reasons(ev(1, at='2026-10-27T01:00:00')))")"
assert_eq "U4 garbage timestamp rejected" "bad_observed_at" "$(pyval "print(reasons(ev(1, at='yesterday')))")"
assert_eq "U4 future exactly skew ok" "ok" "$(pyval "print(reasons(ev(1, at='2026-10-27T02:05:00Z')))")"
assert_eq "U4 future skew+1s rejected" "observed_in_future" "$(pyval "print(reasons(ev(1, at='2026-10-27T02:05:01Z')))")"
assert_eq "U4 age exactly window ok" "ok" "$(pyval "print(reasons(ev(1, at='2026-10-26T02:00:00Z')))")"
assert_eq "U4 age window+1s rejected" "outside_replay_window" "$(pyval "print(reasons(ev(1, at='2026-10-26T01:59:59Z')))")"

echo "[U5] missing information is kept and flagged, never rejected or assumed"
assert_eq "U5 missing risk accepted as insufficient" "['risk']" "$(pyval "print(wl.normalize_event(ev(1, risk=None),NOW,LIM)[0]['insufficient'])")"
assert_eq "U5 missing all three" "['confidence', 'observed_at', 'risk']" "$(pyval "print(wl.normalize_event(ev(1, risk=None, conf=None, at=None),NOW,LIM)[0]['insufficient'])")"
assert_eq "U5 only-insufficient entity -> UNDETERMINED" "UNDETERMINED" "$(pyval "print(levels([ev(1, risk=None)])['worker-a'])")"
assert_eq "U5 insufficient + LOW evidence -> UNDETERMINED, not L0" "UNDETERMINED" "$(pyval "print(levels([ev(1, risk='LOW'), ev(2, risk=None)])['worker-a'])")"
assert_eq "U5 insufficient + L4 evidence -> L4 stands" "L4" "$(pyval "print(levels([ev(1, risk='CRITICAL'), ev(2, risk=None)])['worker-a'])")"

echo "[U6] false positives: global-only, low or single medium evidence never plans a disruptive step"
assert_eq "U6 global-only CRITICAL capped to L2" "L2" "$(pyval "print(levels([ev(1, src='global_patrol', risk='CRITICAL')])['worker-a'])")"
assert_eq "U6 two global sources CRITICAL still L2" "L2" "$(pyval "print(levels([ev(1, src='global_patrol', risk='CRITICAL'), ev(2, src='critical_infra_watch', risk='CRITICAL')])['worker-a'])")"
assert_eq "U6 snd crossref not local" "L2" "$(pyval "print(levels([ev(1, src='snd_home_crossref', risk='CRITICAL')])['worker-a'])")"
assert_eq "U6 unknown module not local" "L2" "$(pyval "print(levels([ev(1, src='made_up_module', risk='CRITICAL')])['worker-a'])")"
assert_eq "U6 LOW local -> L0" "L0" "$(pyval "print(levels([ev(1, risk='LOW')])['worker-a'])")"
assert_eq "U6 MEDIUM single -> L1" "L1" "$(pyval "print(levels([ev(1, risk='MEDIUM')])['worker-a'])")"
assert_eq "U6 HIGH low-confidence single local -> L2" "L2" "$(pyval "print(levels([ev(1, risk='HIGH', conf='LOW')])['worker-a'])")"

echo "[U7] false negatives: real local evidence is not missed"
assert_eq "U7 local CRITICAL -> L4" "L4" "$(pyval "print(levels([ev(1, risk='CRITICAL', conf='LOW')])['worker-a'])")"
assert_eq "U7 local HIGH+HIGH -> L3" "L3" "$(pyval "print(levels([ev(1)])['worker-a'])")"
assert_eq "U7 local HIGH low-conf + global corroboration -> L3" "L3" "$(pyval "print(levels([ev(1, conf='LOW'), ev(2, src='global_patrol', risk='LOW', conf='LOW')])['worker-a'])")"
assert_eq "U7 saas_ato is local" "L4" "$(pyval "print(levels([ev(1, src='saas_ato', risk='CRITICAL', etype='account')])['worker-a'])")"

echo "[U8] order independence: every permutation of a mixed batch gives the same assessment"
assert_eq "U8 720 permutations identical (incl. differing entity_type)" "1" "$(pyval "
batch=[ev(1, at='2026-10-27T01:10:00Z'), ev(2, src='global_patrol', risk='CRITICAL', etype='host'), ev(6, src='attack_graph', etype='node', at='2026-10-27T00:50:00Z'), ev(3, entity='w2', risk=None),
       ev(4, entity='w2', risk='MEDIUM', at='2026-10-27T00:00:00Z'), ev(5, entity='w3', risk='LOW', at='2026-10-27T01:30:00Z')]
out=set()
for p in itertools.permutations(batch):
    s=wl.screen_events(list(p), {}, NOW, LIM)
    out.add(json.dumps(wl.assess(s['accepted'], s['conflicts'], NOW), sort_keys=True))
print(len(out))")"
assert_eq "U8 differing entity_type is reported, earliest event's type used" "node True" "$(pyval "
s=wl.screen_events([ev(1, etype='agent'), ev(2, src='attack_graph', etype='node', at='2026-10-27T00:00:00Z')], {}, NOW, LIM)
a=wl.assess(s['accepted'], s['conflicts'], NOW)[0]; print(a['entity_type'], any('differing entity_type' in r for r in a['reasons']))")"
assert_eq "U8 late (older) event still raises the level" "L4" "$(pyval "print(levels([ev(1, risk='LOW', at='2026-10-27T01:50:00Z'), ev(2, risk='CRITICAL', at='2026-10-27T00:10:00Z')])['worker-a'])")"

echo "[U9] duplicates and conflicting replays"
assert_eq "U9 in-batch duplicate counted once" "1 1" "$(pyval "s=wl.screen_events([ev(1), ev(1)], {}, NOW, LIM); print(len(s['accepted']), len(s['duplicates']))")"
assert_eq "U9 in-batch conflict taints both copies" "0 2" "$(pyval "s=wl.screen_events([ev(1), ev(1, risk='LOW')], {}, NOW, LIM); print(len(s['accepted']), len(s['conflicts']))")"
assert_eq "U9 conflict-only entity -> UNDETERMINED" "UNDETERMINED" "$(pyval "print(levels([ev(1), ev(1, risk='LOW')])['worker-a'])")"
assert_eq "U9 seen key + same digest -> duplicate" "duplicate" "$(pyval "e=wl.normalize_event(ev(1),NOW,LIM)[0]; s=wl.screen_events([ev(1)], {e['key']: e['digest']}, NOW, LIM); print('duplicate' if s['duplicates'] else 'other')")"
assert_eq "U9 seen key + altered content -> conflict" "conflict" "$(pyval "e=wl.normalize_event(ev(1),NOW,LIM)[0]; s=wl.screen_events([ev(1, risk='LOW')], {e['key']: e['digest']}, NOW, LIM); print('conflict' if s['conflicts'] else 'other')")"
assert_eq "U9 same event_id from another source is distinct" "2" "$(pyval "s=wl.screen_events([ev(1), ev(1, src='attack_graph')], {}, NOW, LIM); print(len(s['accepted']))")"

echo "[U10] policy invariants are enforced in code"
assert_eq "U10 default policy valid" "ok" "$(pyval "wl.validate_policy(POLICY); print('ok')")"
for mut in \
  "p['actions']['isolate_agent']['requires_approval']=False" \
  "p['actions']['restrict_egress']['class']='observe'" \
  "p['actions']['delete_everything']={'class':'observe','requires_approval':False}" \
  "p['levels']['L1'].append('restrict_egress')" \
  "p['levels']['UNDETERMINED'].append('isolate_agent')" \
  "p['levels']['L3'].remove('warn_operator')" \
  "p['levels']['L2'].append('nope')" \
  "p['levels']['L2'].append('warn_operator')" \
  "del p['levels']['L4']" \
  "p['levels']['L5']=[]" \
  "p['limits']['max_disruptive_per_hour']=21" \
  "p['limits']['replay_window_s']=59" \
  "p['limits']['clock_skew_s']=True" \
  "del p['limits']['clock_skew_s']" \
  "p['version']=0" \
  "p['version']=True" \
  "p['policy_id']='Bad Id'"; do
  assert_eq "U10 refused: $mut" "refused" "$(pyval "
p=copy.deepcopy(POLICY); $mut
try:
    wl.validate_policy(p); print('accepted')
except wl.PolicyError: print('refused')")"
done

echo "[U11] policy diff"
assert_eq "U11 identical" "True []" "$(pyval "d=wl.diff_policies(POLICY, copy.deepcopy(POLICY)); print(d['identical'], d['loosening'])")"
assert_eq "U11 removing a response is loosening" "1" "$(pyval "
p=copy.deepcopy(POLICY); p['version']=2; p['levels']['L4'].remove('isolate_agent')
print(len(wl.diff_policies(POLICY, p)['loosening']))")"
assert_eq "U11 raising the rate limit is loosening" "limit max_disruptive_per_hour raised 3 -> 10" "$(pyval "
p=copy.deepcopy(POLICY); p['version']=2; p['limits']['max_disruptive_per_hour']=10
print(wl.diff_policies(POLICY, p)['loosening'][0])")"
assert_eq "U11 content change without version bump flagged" "content changed without a version bump" "$(pyval "
p=copy.deepcopy(POLICY); p['limits']['max_disruptive_per_hour']=2
print(wl.diff_policies(POLICY, p)['loosening'][0])")"
assert_eq "U11 tightening is a change but not loosening" "1 0" "$(pyval "
p=copy.deepcopy(POLICY); p['version']=2; p['levels']['L2'].append('restrict_egress')
d=wl.diff_policies(POLICY, p); print(len(d['changes']), len(d['loosening']))")"
assert_eq "U11 version going backwards flagged" "True" "$(pyval "
p=copy.deepcopy(POLICY); p['version']=5
print(any('backwards' in x for x in wl.diff_policies(p, POLICY)['loosening']))")"

echo "[U12] runaway prevention and kill switch in planning"
assert_eq "U12 budget 3: three L4 entities -> 3 awaiting, 3 suppressed" "3 3" "$(pyval "
a=[dict(entity='w%d'%i, threat_level='L4') for i in range(3)]
pl=wl.plan_responses(a, POLICY, 0, False)
st=[s['status'] for p in pl for s in p['steps'] if s['class']=='disruptive']
print(st.count('AWAITING_APPROVAL'), st.count('SUPPRESSED_RATE_LIMIT'))")"
assert_eq "U12 suppressed plan still warns the operator" "DRY_RUN_PLANNED" "$(pyval "
pl=wl.plan_responses([dict(entity='w', threat_level='L4')], POLICY, 3, False)
print([s['status'] for s in pl[0]['steps'] if s['action']=='warn_operator'][0])")"
assert_eq "U12 limit 0 suppresses every disruptive step" "0" "$(pyval "
p=copy.deepcopy(POLICY); p['limits']['max_disruptive_per_hour']=0
pl=wl.plan_responses([dict(entity='w', threat_level='L4')], p, 0, False); print(wl.count_disruptive(pl[0]))")"
assert_eq "U12 kill switch halts every step" "HALTED_KILLSWITCH" "$(pyval "
pl=wl.plan_responses([dict(entity='w', threat_level='L4')], POLICY, 0, True)
print(','.join(sorted({s['status'] for s in pl[0]['steps']})))")"
assert_eq "U12 every disruptive step requires approval" "True" "$(pyval "
pl=wl.plan_responses([dict(entity='w', threat_level='L4')], POLICY, 0, False)
print(all(s['requires_approval'] for s in pl[0]['steps'] if s['class']=='disruptive'))")"
assert_eq "U12 no step is ever anything but dry_run" "dry_run" "$(pyval "
pl=wl.plan_responses([dict(entity='w'+l, threat_level=l) for l in wl.ALL_LEVELS], POLICY, 0, False)
print(','.join(sorted({s['mode'] for p in pl for s in p['steps']})))")"

echo ""
echo "=== I-series: CLI and ledger ==="
write_events "$T/ev1.jsonl" <<'EOF'
{"event_id":"e1","source_module":"shadow_ai_monitor","entity":"worker-a","entity_type":"agent","risk":"CRITICAL","confidence":"HIGH","observed_at":"2026-10-27T01:00:00Z"}
{"event_id":"e2","source_module":"global_patrol","entity":"203.0.113.9","entity_type":"ip","risk":"CRITICAL","confidence":"HIGH","observed_at":"2026-10-27T01:00:00Z"}
{"event_id":"e3","source_module":"attack_graph","entity":"worker-b","entity_type":"agent","observed_at":"2026-10-27T01:00:00Z"}
this line is not json
EOF

echo "[I1] evaluate writes a chained ledger that security/lib.sh verifies unchanged"
reset_state
assert_eq "I1 rc" "0" "$(wad evaluate --events "$T/ev1.jsonl" --now "$NOW")"
assert_eq "I1 counts" "3 1" "$(jq_py "r['counts']['accepted'], r['counts']['rejected']")"
assert_eq "I1 levels" "worker-a=L4 203.0.113.9=L2 worker-b=UNDETERMINED" "$(jq_py "' '.join(a['entity']+'='+a['threat_level'] for a in r['assessments'])")"
assert_eq "I1 decision lines" "3" "$(ledger_count wad_decision)"
assert_eq "I1 decision records reason, confidence, plan, result" "True" "$(python3 -c "
import json
d=[json.loads(l) for l in open('$WAD_STATE_DIR/ledger.jsonl') if '\"wad_decision\"' in l][0]
print(all(k in d for k in ('reasons','confidence','plan','result','policy','threat_level')) and d['result'].startswith('DRY_RUN:'))")"
assert_eq "I1 wad verify-ledger" "0" "$(wad verify-ledger)"
assert_eq "I1 lib.sh verify_audit_log_integrity on WAD ledger" "ok" "$(WAIO_AUDIT_LOG="$WAD_STATE_DIR/ledger.jsonl" WAIO_AUDIT_LOG_CHECKPOINT="$WAD_STATE_DIR/ledger.checkpoint" bash -c '. security/lib.sh; verify_audit_log_integrity')"
assert_eq "I1 ledger file mode 600" "600" "$(python3 -c "import os,stat;print(oct(stat.S_IMODE(os.stat('$WAD_STATE_DIR/ledger.jsonl').st_mode))[2:])")"

echo "[I2] rerun is idempotent"
assert_eq "I2 rc" "0" "$(wad evaluate --events "$T/ev1.jsonl" --now "2026-10-27T02:01:00Z")"
assert_eq "I2 all duplicates" "0 3" "$(jq_py "r['counts']['accepted'], r['counts']['duplicates']")"
assert_eq "I2 no new decision lines" "3" "$(ledger_count wad_decision)"

echo "[I3] replay with altered content is a conflict, not a fresh event"
write_events "$T/ev_alt.jsonl" <<'EOF'
{"event_id":"e1","source_module":"shadow_ai_monitor","entity":"worker-a","entity_type":"agent","risk":"LOW","confidence":"HIGH","observed_at":"2026-10-27T01:00:00Z"}
EOF
assert_eq "I3 rc" "0" "$(wad evaluate --events "$T/ev_alt.jsonl" --now "2026-10-27T02:02:00Z")"
assert_eq "I3 conflict" "1 0" "$(jq_py "r['counts']['conflicts'], r['counts']['accepted']")"
assert_eq "I3 attacker's LOW does not downgrade: entity UNDETERMINED for human" "UNDETERMINED" "$(jq_py "r['assessments'][0]['threat_level']")"
assert_eq "I3 conflict audited" "1" "$(ledger_count wad_event_conflict)"
assert_eq "I3 replay of an old event outside the window is rejected" "outside_replay_window" "$(wad evaluate --events "$T/ev1.jsonl" --now "2026-10-29T02:00:00Z" >/dev/null; jq_py "r['rejected'][0]['reasons'][0]")"

echo "[I4] tamper: an edited ledger line refuses evaluation and changes nothing"
cp "$WAD_STATE_DIR/ledger.jsonl" "$T/ledger.bak"; cp "$WAD_STATE_DIR/ledger.checkpoint" "$T/cp.bak"
python3 - "$WAD_STATE_DIR/ledger.jsonl" <<'EOF'
import sys
p = sys.argv[1]
s = open(p).read().replace('"threat_level": "L4"', '"threat_level": "L0"', 1)
open(p, "w").write(s)
EOF
sum_before="$(cksum < "$WAD_STATE_DIR/ledger.jsonl")"
assert_eq "I4 verify-ledger rc" "4" "$(wad verify-ledger)"
assert_eq "I4 evaluate refused rc" "4" "$(wad evaluate --events "$T/ev1.jsonl" --now "$NOW")"
assert_eq "I4 ledger untouched by refused run" "$sum_before" "$(cksum < "$WAD_STATE_DIR/ledger.jsonl")"
assert_eq "I4 lib.sh agrees it is broken" "broken" "$(WAIO_AUDIT_LOG="$WAD_STATE_DIR/ledger.jsonl" WAIO_AUDIT_LOG_CHECKPOINT="$WAD_STATE_DIR/ledger.checkpoint" bash -c '. security/lib.sh; verify_audit_log_integrity' | cut -d: -f1)"

echo "[I5] truncation and checkpoint mismatch refuse"
cp "$T/ledger.bak" "$WAD_STATE_DIR/ledger.jsonl"; cp "$T/cp.bak" "$WAD_STATE_DIR/ledger.checkpoint"
assert_eq "I5 restored ledger verifies" "0" "$(wad verify-ledger)"
python3 -c "
p='$WAD_STATE_DIR/ledger.jsonl'; l=open(p).readlines(); open(p,'w').writelines(l[:-1])"
assert_eq "I5 truncated tail refused" "4" "$(wad evaluate --events "$T/ev1.jsonl" --now "$NOW")"
cp "$T/ledger.bak" "$WAD_STATE_DIR/ledger.jsonl"; rm -f "$WAD_STATE_DIR/ledger.checkpoint"
assert_eq "I5 deleted checkpoint refused" "4" "$(wad evaluate --events "$T/ev1.jsonl" --now "$NOW")"

echo "[I6] stop signals are read-only and fail closed"
reset_state
touch "$WAIO_SHUTDOWN_LOCK"
assert_eq "I6 SHUTDOWN.lock halts rc" "0" "$(wad evaluate --events "$T/ev1.jsonl" --now "$NOW")"
assert_eq "I6 SHUTDOWN.lock halts every step" "True HALTED_KILLSWITCH" "$(jq_py "r['killswitch_active'], ','.join(sorted(set(s['status'] for p in r['plans'] for s in p['steps'])))")"
assert_eq "I6 halted run still records decisions" "3" "$(ledger_count wad_decision)"
assert_eq "I6 WAD never removes SHUTDOWN.lock" "yes" "$([ -e "$WAIO_SHUTDOWN_LOCK" ] && echo yes)"
rm -f "$WAIO_SHUTDOWN_LOCK"
reset_state
touch "$WAD_STOP_FILE"
assert_eq "I6 WAD STOP file halts" "True" "$(wad evaluate --events "$T/ev1.jsonl" --now "$NOW" >/dev/null; jq_py "r['killswitch_active']")"
rm -f "$WAD_STOP_FILE"
reset_state
mkdir -p "$T/locked"; chmod 000 "$T/locked"
if [ "$(id -u)" != "0" ]; then
  assert_eq "I6 undeterminable stop path counts as stop" "True" "$(WAD_STOP_FILE="$T/locked/STOP" wad evaluate --events "$T/ev1.jsonl" --now "$NOW" >/dev/null; jq_py "r['killswitch_active']")"
else
  echo "  SKIP: I6 unreadable-path case (running as root)"
fi
chmod 700 "$T/locked"

echo "[I7] unwritable ledger: no decision recorded, events are not lost"
reset_state
mkdir -p "$WAD_STATE_DIR"; : > "$WAD_STATE_DIR/ledger.jsonl"; chmod 400 "$WAD_STATE_DIR/ledger.jsonl"
if [ "$(id -u)" != "0" ]; then
  assert_eq "I7 rc 3" "3" "$(wad evaluate --events "$T/ev1.jsonl" --now "$NOW")"
  assert_eq "I7 no checkpoint written" "no" "$([ -e "$WAD_STATE_DIR/ledger.checkpoint" ] && echo yes || echo no)"
  chmod 600 "$WAD_STATE_DIR/ledger.jsonl"
  assert_eq "I7 after repair the same events are decided (not marked seen)" "0 3" "$(wad evaluate --events "$T/ev1.jsonl" --now "$NOW" >/dev/null; jq_py "r['counts']['duplicates'], r['counts']['accepted']")"
else
  echo "  SKIP: I7 (running as root)"
fi

echo "[I8] concurrent evaluations decide each event exactly once"
reset_state
for i in 1 2 3 4 5 6; do
  python3 security/wad/wad.py evaluate --events "$T/ev1.jsonl" --now "$NOW" > "$T/par$i.json" 2>&1 &
done
wait
assert_eq "I8 exactly one accepted batch" "1" "$(ledger_count wad_events_accepted)"
assert_eq "I8 exactly 3 decisions" "3" "$(ledger_count wad_decision)"
assert_eq "I8 five runs saw duplicates" "15" "$(ledger_count wad_event_duplicate)"
assert_eq "I8 chain intact" "0" "$(wad verify-ledger)"

echo "[I9] lock held elsewhere -> rc 5, nothing written"
python3 -c "
import fcntl,os,time,sys
fd=os.open('$WAD_STATE_DIR/.lock', os.O_RDWR); fcntl.flock(fd, fcntl.LOCK_EX)
open('$T/locked.flag','w').close(); time.sleep(3)" &
holder=$!
for _ in $(seq 1 50); do [ -e "$T/locked.flag" ] && break; python3 -c 'import time; time.sleep(0.05)'; done
before="$(cksum < "$WAD_STATE_DIR/ledger.jsonl")"
assert_eq "I9 rc 5" "5" "$(WAD_LOCK_WAIT_S=0.3 wad evaluate --events "$T/ev1.jsonl" --now "$NOW")"
assert_eq "I9 ledger unchanged" "$before" "$(cksum < "$WAD_STATE_DIR/ledger.jsonl")"
kill "$holder" 2>/dev/null; wait "$holder" 2>/dev/null

echo "[I10] runaway: the disruptive budget holds across runs and recovers after an hour"
reset_state
mkl4() {  # mkl4 FILE N -- one CRITICAL local event for entity wN
  printf '{"event_id":"r%s","source_module":"shadow_ai_monitor","entity":"w%s","entity_type":"agent","risk":"CRITICAL","confidence":"HIGH","observed_at":"2026-10-27T01:00:00Z"}\n' "$2" "$2" > "$1"
}
mkl4 "$T/r1.jsonl" 1; mkl4 "$T/r2.jsonl" 2; mkl4 "$T/r3.jsonl" 3; mkl4 "$T/r4.jsonl" 4
wad evaluate --events "$T/r1.jsonl" --now "2026-10-27T02:00:00Z" >/dev/null
assert_eq "I10 run1 uses 2 of 3" "2" "$(jq_py "sum(1 for s in r['plans'][0]['steps'] if s['status']=='AWAITING_APPROVAL')")"
wad evaluate --events "$T/r2.jsonl" --now "2026-10-27T02:10:00Z" >/dev/null
assert_eq "I10 run2 gets 1, 1 suppressed" "1 1" "$(jq_py "sum(1 for s in r['plans'][0]['steps'] if s['status']=='AWAITING_APPROVAL'), sum(1 for s in r['plans'][0]['steps'] if s['status']=='SUPPRESSED_RATE_LIMIT')")"
wad evaluate --events "$T/r3.jsonl" --now "2026-10-27T02:20:00Z" >/dev/null
assert_eq "I10 run3 fully suppressed but operator still warned" "0 DRY_RUN_PLANNED" "$(jq_py "sum(1 for s in r['plans'][0]['steps'] if s['status']=='AWAITING_APPROVAL'), [s['status'] for s in r['plans'][0]['steps'] if s['action']=='warn_operator'][0]")"
wad evaluate --events "$T/r4.jsonl" --now "2026-10-27T03:10:01Z" >/dev/null
assert_eq "I10 an hour after run1 the budget recovers" "2" "$(jq_py "sum(1 for s in r['plans'][0]['steps'] if s['status']=='AWAITING_APPROVAL')")"

echo "[I11] bad policy or input writes nothing"
reset_state
python3 -c "
import json; p=json.load(open('$POLICY')); p['actions']['isolate_agent']['requires_approval']=False
json.dump(p, open('$T/bad_policy.json','w'))"
assert_eq "I11 unsafe policy refused rc 1" "1" "$(wad evaluate --events "$T/ev1.jsonl" --policy "$T/bad_policy.json" --now "$NOW")"
assert_eq "I11 refusal names the invariant" "1" "$(grep -c 'must require approval' "$T/err.txt")"
ln -sf "$SCRIPT_DIR/$POLICY" "$T/policy_link.json"
assert_eq "I11 symlinked policy refused" "1" "$(wad evaluate --events "$T/ev1.jsonl" --policy "$T/policy_link.json" --now "$NOW")"
echo '{not json' > "$T/broken.json"
assert_eq "I11 non-JSON policy refused" "1" "$(wad evaluate --events "$T/ev1.jsonl" --policy "$T/broken.json" --now "$NOW")"
assert_eq "I11 naive --now refused" "1" "$(wad evaluate --events "$T/ev1.jsonl" --now "2026-10-27T02:00:00")"
python3 -c "
import json; p=json.load(open('$POLICY')); p['limits']['max_events_per_run']=2
json.dump(p, open('$T/small_policy.json','w'))"
assert_eq "I11 too many events refused" "1" "$(wad evaluate --events "$T/ev1.jsonl" --policy "$T/small_policy.json" --now "$NOW")"
assert_eq "I11 nothing written by any refused run" "no" "$([ -e "$WAD_STATE_DIR/ledger.jsonl" ] && echo yes || echo no)"
printf '[{"event_id":"a1","source_module":"attack_graph","entity":"n1","entity_type":"node","risk":"MEDIUM","confidence":"LOW","observed_at":"2026-10-27T01:00:00Z"}]' > "$T/arr.json"
assert_eq "I11 JSON array input accepted" "0 1" "$(wad evaluate --events "$T/arr.json" --now "$NOW" | tr -d '\n'; echo -n ' '; jq_py "r['counts']['accepted']")"
: > "$T/empty.jsonl"
assert_eq "I11 empty input is a clean no-op" "0" "$(wad evaluate --events "$T/empty.jsonl" --now "$NOW")"

echo "[I12] policy-check and policy-diff"
assert_eq "I12 policy-check prints ref" "wad-default 1" "$(wad policy-check "$POLICY" >/dev/null; jq_py "r['policy_id'], r['version']" | tr '\n' ' ' | sed 's/ $//')"
python3 -c "
import json; p=json.load(open('$POLICY')); p['version']=2; p['levels']['L4'].remove('isolate_agent')
json.dump(p, open('$T/v2.json','w'))"
assert_eq "I12 diff reports loosening" "0 ['L4 no longer does isolate_agent']" "$(wad policy-diff "$POLICY" "$T/v2.json" | tr -d '\n'; echo -n ' '; jq_py "r['loosening']")"
assert_eq "I12 diff refuses an invalid side" "1" "$(wad policy-diff "$POLICY" "$T/bad_policy.json")"

echo ""
echo "=== S-series: WAD never executes and never touches real state ==="
code_only() { grep -vE '^\s*#' "$@" | python3 -c "
import sys,re
src=sys.stdin.read()
print(re.sub(r'\"\"\"[\s\S]*?\"\"\"', '', src))"; }
assert_eq "S1 no process/network/containment calls in security/wad code" "0" "$(code_only security/wad/*.py | grep -cE 'subprocess|os\.system|os\.exec|os\.spawn|popen|socket|urllib|http\.client|guardian|ducopa|containment_runner|killswitch_gate|pfctl|iptables|trigger_shutdown' || true)"
assert_eq "S1 no os.remove/unlink of stop files" "0" "$(code_only security/wad/*.py | grep -cE 'os\.(remove|unlink|rmdir)|shutil\.rmtree' || true)"
for s in sudo ssh scp curl nc osascript; do
  assert_eq "S2 stub $s never called" "0" "$(waio_test_stub_calls "$s")"
done
assert_eq "S3 repo security/state/wad not created by this suite" "no" "$([ -e security/state/wad/ledger.jsonl ] && [ "security/state/wad/ledger.jsonl" -nt "$T/ev1.jsonl" ] && echo yes || echo no)"
assert_eq "S4 default policy passes its own invariants" "0" "$(wad policy-check "$POLICY")"

echo ""
echo "=== Summary: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
  echo "Failures:"
  for f in "${FAILURES[@]}"; do echo "  - $f"; done
  exit 1
fi
exit 0
