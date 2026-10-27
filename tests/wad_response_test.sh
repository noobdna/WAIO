#!/bin/bash
set -uo pipefail

# tests/wad_response_test.sh -- WAD PR 2: controlled response workflow
# (security/wad/wad_response.py + the `response` / `repair-checkpoint`
# commands and the optional keyed chain in security/wad/wad.py).
#
#   R-series: pure state machine and operator checks.
#   T-series: invalid transitions.
#   A-series: unauthorized approval attempts (allowlist, automated names,
#             reason, expiry, kill switch). The name is never authenticated.
#   D-series: duplicates (repeat approve/execute/rollback, re-sent events).
#   X-series: dry-run execution, stale approvals, interrupted execution.
#   B-series: rollback (compensation, reverse order, refusals).
#   L-series: log tampering and checkpoint repair (unkeyed).
#   K-series: keyed chain (HMAC) tampering and repair.
#   S-series: nothing executes; nothing claims authentication.
#
# Runs inside tests/lib/test_isolation.sh: every WAIO_* path points into a
# temp root and sudo/ssh/curl/nc/osascript are recording stubs.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR" || exit 1
# shellcheck source=tests/lib/test_isolation.sh
. tests/lib/test_isolation.sh
waio_test_isolate wad_response || exit 3
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

T="$WAIO_TEST_ROOT/wadr"
mkdir -p "$T"
NOW="2026-10-27T02:00:00Z"
T1="2026-10-27T03:00:00Z"
LATE="2026-10-28T03:00:00Z"      # 25 h after the decision / approval
GOOD="contained after review of the shadow ai alert"
export WAD_STATE_DIR="$T/state"
export WAD_STOP_FILE="$T/STOP"
unset WAD_LEDGER_HMAC_KEY_FILE WAD_APPROVER_ALLOWLIST WAD_APPROVAL_TTL_S

cat > "$T/ev.jsonl" <<'EOF'
{"event_id":"e1","source_module":"shadow_ai_monitor","entity":"worker-a","entity_type":"agent","risk":"CRITICAL","confidence":"HIGH","observed_at":"2026-10-27T01:00:00Z"}
EOF

wad() { python3 security/wad/wad.py "$@" > "$T/out.json" 2> "$T/err.txt"; echo $?; }
out() { python3 -c "import json,sys; r=json.load(open('$T/out.json')); print($1)"; }
lines() { if [ -f "$WAD_STATE_DIR/ledger.jsonl" ]; then grep -c . "$WAD_STATE_DIR/ledger.jsonl"; else echo 0; fi; }
count_type() { python3 -c "
import json,sys
print(sum(1 for l in open('$WAD_STATE_DIR/ledger.jsonl') if l.strip() and json.loads(l).get('event_type')==sys.argv[1]))" "$1"; }
state() { wad response list > /dev/null; out "[s['state'] for s in r if s['step_id']=='$1'][0]"; }
violations() { out "','.join(r.get('violations', []))"; }
libsh_verify() {
  WAIO_AUDIT_LOG="$WAD_STATE_DIR/ledger.jsonl" WAIO_AUDIT_LOG_CHECKPOINT="$WAD_STATE_DIR/ledger.checkpoint" \
    bash -c '. security/lib.sh; verify_audit_log_integrity'
}
fresh() {   # new state dir, approvers file, one L4 decision; sets RUN M W R I
  rm -rf "$WAD_STATE_DIR" "$WAD_STOP_FILE"
  mkdir -p "$WAD_STATE_DIR"
  printf '# approvers\nmasa\nclaude\nguardian\n' > "$WAD_STATE_DIR/approvers"
  wad evaluate --events "$T/ev.jsonl" --now "$NOW" > /dev/null
  wad response list > /dev/null
  read -r RUN M W R I <<< "$(out "' '.join([r[0]['run_id']] + [s['step_id'] for s in sorted(r, key=lambda s: s['index'])])")"
}
crash_after_start() {   # appends exactly what `execute` writes before running the executor
  python3 - "$1" <<'PY'
import os, sys
sys.path.insert(0, "security/wad")
import wad, wad_response as wr
L = wad.Ledger(os.environ["WAD_STATE_DIR"], wad.load_key())
entries, count, prev = L.walk()
s = wr.replay_steps(entries)[sys.argv[1]]
L.append([wad.transition({"timestamp": "2026-10-27T03:30:00Z", "run_id": "wad-op-crash", "mode": "dry_run"}, s, "start", "wad")], count, prev)
PY
}

echo "=== R-series: pure state machine ==="
assert_eq "R1 exactly 8 legal edges, every other (state, action) refused" "8 0" "$(python3 -c "
import sys; sys.path.insert(0,'security/wad'); import wad_response as wr
S=['awaiting_approval','planned','approved','rejected','executing','done','failed','rolled_back','suppressed','halted','bogus']
A=['approve','reject','start','complete','fail','rollback','expire','']
legal=[(s,a) for s in S for a in A if wr.next_state(s,a)]
extra=[e for e in legal if e not in wr.TRANSITIONS]
print(len(legal), len(extra))")"
assert_eq "R2 terminal states have no outgoing edge" "0" "$(python3 -c "
import sys; sys.path.insert(0,'security/wad'); import wad_response as wr
print(sum(1 for (s,a) in wr.TRANSITIONS if s in wr.TERMINAL))")"
assert_eq "R3 step ids deterministic and 16 hex" "True True" "$(python3 -c "
import sys; sys.path.insert(0,'security/wad'); import wad_response as wr
a=wr.step_id('r','e',0,'x'); print(a==wr.step_id('r','e',0,'x'), wr.valid_step_id(a))")"
assert_eq "R4 operator checks (none, automated, reserved, real) never authenticate" \
  "no_approver_allowlist_configured automated_identity_refused automated_identity_refused automated_identity_refused present_and_in_allowlist_not_authenticated False" \
  "$(python3 -c "
import sys; sys.path.insert(0,'security/wad'); import wad_response as wr
al=set(['masa','claude-bg','x-bot','guardian'])
r=[wr.check_operator('masa', None)[1], wr.check_operator('claude-bg', al)[1], wr.check_operator('x-bot', al)[1],
   wr.check_operator('guardian', al, reserved=['guardian'])[1], wr.check_operator('masa', al)[1]]
print(' '.join(r), any(wr.check_operator('masa', al)[2].get('authenticated') for _ in [0]))")"
assert_eq "R5 warn_operator and recover have no compensation" "None None" "$(python3 -c "
import sys; sys.path.insert(0,'security/wad'); import wad_response as wr
print(wr.COMPENSATION['warn_operator'], wr.COMPENSATION['recover'])")"

echo ""
echo "=== T-series: invalid transitions ==="
fresh
assert_eq "T0 L4 plan -> planned,planned,awaiting,awaiting" "planned planned awaiting_approval awaiting_approval" \
  "$(out "' '.join(s['state'] for s in sorted(r, key=lambda s: s['index']))")"
n=$(lines)
assert_eq "T1 execute an unapproved disruptive step refused" "6" "$(wad response execute "$R" --now "$T1")"
assert_eq "T1 reason recorded" "illegal_transition:awaiting_approval->start" "$(violations)"
assert_eq "T1 step did not move" "awaiting_approval" "$(state "$R")"
assert_eq "T2 approve a step that needs no approval refused" "6" "$(wad response approve "$M" --operator masa --reason "$GOOD" --now "$T1")"
assert_eq "T3 rollback a step that never ran refused" "6" "$(wad response rollback "$R" --operator masa --reason "$GOOD" --now "$T1")"
assert_eq "T4 reject a planned step refused" "6" "$(wad response reject "$M" --operator masa --reason "$GOOD" --now "$T1")"
assert_eq "T5 unknown (well-formed) step id refused" "6 unknown_step" "$(wad response approve 0123456789abcdef --operator masa --reason "$GOOD" --now "$T1") $(violations)"
m=$(lines)
assert_eq "T6 malformed step id rejected before touching the ledger" "1 $m" "$(wad response approve NOT-A-STEP --operator masa --reason "$GOOD") $(lines)"
assert_eq "T7 each refusal is recorded (5)" "5" "$(( $(lines) - n ))"

echo ""
echo "=== A-series: unauthorized approval attempts ==="
mv "$WAD_STATE_DIR/approvers" "$T/approvers.off"
assert_eq "A1 no allowlist configured -> refused" "6 no_approver_allowlist_configured" "$(wad response approve "$R" --operator masa --reason "$GOOD" --now "$T1") $(violations)"
ln -s "$T/approvers.off" "$WAD_STATE_DIR/approvers"
assert_eq "A2 symlinked allowlist ignored -> refused" "6 no_approver_allowlist_configured" "$(wad response approve "$R" --operator masa --reason "$GOOD" --now "$T1") $(violations)"
rm "$WAD_STATE_DIR/approvers"; mv "$T/approvers.off" "$WAD_STATE_DIR/approvers"
assert_eq "A3 name not on the allowlist" "6 identity_not_in_allowlist" "$(wad response approve "$R" --operator eve --reason "$GOOD" --now "$T1") $(violations)"
assert_eq "A4 automated name refused even if allowlisted" "6 automated_identity_refused" "$(wad response approve "$R" --operator claude --reason "$GOOD" --now "$T1") $(violations)"
assert_eq "A5 component name refused even if allowlisted" "6 automated_identity_refused" "$(wad response approve "$R" --operator guardian --reason "$GOOD" --now "$T1") $(violations)"
assert_eq "A6 empty name" "6 missing_identity" "$(wad response approve "$R" --operator "  " --reason "$GOOD" --now "$T1") $(violations)"
assert_eq "A7 weak reason" "6 reason_too_short" "$(wad response approve "$R" --operator masa --reason "ok" --now "$T1") $(violations)"
assert_eq "A8 approval window (24 h) expired" "6 approval_window_expired" "$(wad response approve "$R" --operator masa --reason "$GOOD" --now "$LATE") $(violations)"
touch "$WAD_STOP_FILE"
assert_eq "A9 kill switch blocks approval" "6 killswitch_active" "$(wad response approve "$R" --operator masa --reason "$GOOD" --now "$T1") $(violations)"
rm -f "$WAD_STOP_FILE"
assert_eq "A10 every gate reported, not just the first" "6 identity_not_in_allowlist,reason_too_short" "$(wad response approve "$R" --operator eve --reason "no" --now "$T1") $(violations)"
assert_eq "A11 after all refusals the step is still awaiting" "awaiting_approval" "$(state "$R")"
assert_eq "A12 every refusal recorded unauthenticated" "0" "$(python3 -c "
import json
print(sum(1 for l in open('$WAD_STATE_DIR/ledger.jsonl') if l.strip() and json.loads(l).get('event_type')=='wad_transition_refused' and json.loads(l).get('authenticated') is not False))")"
assert_eq "A13 a valid approval succeeds" "0 approved" "$(wad response approve "$R" --operator masa --reason "$GOOD" --now "$T1") $(state "$R")"
assert_eq "A14 approval record: not authenticated, bound to the decision digest, expiry set" \
  "False present_and_in_allowlist_not_authenticated True 2026-10-28T03:00:00Z" "$(python3 -c "
import json
r=[json.loads(l) for l in open('$WAD_STATE_DIR/ledger.jsonl') if l.strip() and json.loads(l).get('action')=='approve' and json.loads(l).get('event_type')=='wad_step_transition'][-1]
print(r['authenticated'], r['identity_check'], len(r['decision_digest'])==64, r['approval_expires_at'])")"

echo ""
echo "=== D-series: duplicates ==="
assert_eq "D1 second approval refused" "6 illegal_transition:approved->approve" "$(wad response approve "$R" --operator masa --reason "$GOOD" --now "$T1") $(violations)"
assert_eq "D2 reject after approval refused" "6" "$(wad response reject "$R" --operator masa --reason "$GOOD" --now "$T1")"
assert_eq "D3 re-sent event is a duplicate, no new decision" "0 1 1" "$(wad evaluate --events "$T/ev.jsonl" --now "$T1") $(count_type wad_event_duplicate) $(count_type wad_decision)"
assert_eq "D4 still exactly 4 steps" "4" "$(wad response list > /dev/null; out 'len(r)')"

echo ""
echo "=== X-series: dry-run execution, stale approval, interruption ==="
assert_eq "X1 execute approved step" "0 approved>executing,executing>done done" \
  "$(wad response execute "$R" --now "$T1") $(python3 -c "
import json
t=[json.loads(l) for l in open('$WAD_STATE_DIR/ledger.jsonl') if l.strip() and json.loads(l).get('step_id')=='$R' and json.loads(l).get('event_type')=='wad_step_transition']
print(','.join(x['from']+'>'+x['to'] for x in t[1:]))") $(state "$R")"
assert_eq "X2 the result is a dry run" "DRY_RUN|restrict_egress worker-a" "$(python3 -c "
import json
r=[json.loads(l) for l in open('$WAD_STATE_DIR/ledger.jsonl') if l.strip() and json.loads(l).get('action')=='complete'][-1]
print(r['result']['result']+'|'+r['result']['would'])")"
assert_eq "X3 executing a done step again refused" "6 illegal_transition:done->start" "$(wad response execute "$R" --now "$T1") $(violations)"
assert_eq "X4 an observe step runs without approval" "0 done" "$(wad response execute "$M" --now "$T1") $(state "$M")"
wad response approve "$I" --operator masa --reason "$GOOD" --now "$T1" > /dev/null
assert_eq "X5 approval older than 24 h cannot start" "6 approval_expired_before_start approved" "$(wad response execute "$I" --now "$LATE") $(violations) $(state "$I")"
touch "$WAD_STOP_FILE"
assert_eq "X6 kill switch blocks execution" "6 killswitch_active" "$(wad response execute "$W" --now "$T1") $(violations)"
rm -f "$WAD_STOP_FILE"
crash_after_start "$W"
assert_eq "X7 crash after the start record leaves the step executing" "executing" "$(state "$W")"
assert_eq "X8 interrupted step cannot be started again" "6 illegal_transition:executing->start" "$(wad response execute "$W" --now "$T1") $(violations)"
assert_eq "X9 sweep marks it failed (interrupted)" "0 $W failed" "$(wad response sweep --now "$T1") $(out "' '.join(r['swept'])") $(state "$W")"
assert_eq "X10 second sweep finds nothing" "0 0" "$(wad response sweep --now "$T1") $(out 'len(r["swept"])')"

echo ""
echo "=== B-series: rollback ==="
assert_eq "B1 no compensation for warn_operator" "6 $W:no_compensating_action:warn_operator" "$(wad response rollback "$W" --operator masa --reason "$GOOD" --now "$T1") $(violations)"
assert_eq "B2 unauthorized operator" "6 $R:identity_not_in_allowlist" "$(wad response rollback "$R" --operator eve --reason "$GOOD" --now "$T1") $(violations)"
touch "$WAD_STOP_FILE"
assert_eq "B3 kill switch blocks rollback (it loosens)" "6 $R:killswitch_active" "$(wad response rollback "$R" --operator masa --reason "$GOOD" --now "$T1") $(violations)"
rm -f "$WAD_STOP_FILE"
assert_eq "B4 plan rollback with a non-reversible step refused as a whole" "6 done done" \
  "$(wad response rollback --plan "$RUN" worker-a --operator masa --reason "$GOOD" --now "$T1") $(state "$R") $(state "$M")"
assert_eq "B5 per-step rollback, newest first: monitor then egress" "0 0 monitor_restore,release_egress rolled_back rolled_back" \
  "$(wad response rollback "$M" --operator masa --reason "$GOOD" --now "$T1") $(wad response rollback "$R" --operator masa --reason "$GOOD" --now "$T1") $(python3 -c "
import json
print(','.join(json.loads(l)['compensating_action'] for l in open('$WAD_STATE_DIR/ledger.jsonl') if l.strip() and json.loads(l).get('action')=='rollback' and json.loads(l).get('event_type')=='wad_step_transition'))") $(state "$M") $(state "$R")"
assert_eq "B6 second rollback refused" "6 $R:illegal_transition:rolled_back->rollback" "$(wad response rollback "$R" --operator masa --reason "$GOOD" --now "$T1") $(violations)"
fresh
wad response approve "$R" --operator masa --reason "$GOOD" --now "$T1" > /dev/null
wad response execute "$M" --now "$T1" > /dev/null
wad response execute "$R" --now "$T1" > /dev/null
assert_eq "B7 plan rollback reverses completion order" "0 $R,$M" \
  "$(wad response rollback --plan "$RUN" worker-a --operator masa --reason "$GOOD" --now "$T1") $(out "','.join(t['step_id'] for t in r['transitions'])")"
assert_eq "B8 ledger still verifies with security/lib.sh" "ok" "$(libsh_verify)"

echo ""
echo "=== L-series: tampering and checkpoint repair (unkeyed) ==="
assert_eq "L1 verify-ledger ok, unkeyed mode stated" "0 unkeyed" "$(wad verify-ledger) $(grep -o 'unkeyed' "$T/out.json")"
cp "$WAD_STATE_DIR/ledger.jsonl" "$T/good.jsonl"; cp "$WAD_STATE_DIR/ledger.checkpoint" "$T/good.cp"
python3 - "$WAD_STATE_DIR/ledger.jsonl" <<'PY'
import sys
p = sys.argv[1]; t = open(p).read()
open(p, "w").write(t.replace('"actor": "masa"', '"actor": "mallory"', 1))
PY
n=$(lines)
assert_eq "L2 edited approval detected" "4" "$(wad verify-ledger)"
assert_eq "L2 every response command refuses, nothing written" "4 4 $n" "$(wad response list) $(wad response sweep --now "$T1") $(lines)"
cp "$T/good.jsonl" "$WAD_STATE_DIR/ledger.jsonl"
python3 - "$WAD_STATE_DIR/ledger.jsonl" <<'PY'
import sys
p = sys.argv[1]; ls = open(p).read().splitlines(True)
del ls[3]
open(p, "w").write("".join(ls))
PY
assert_eq "L3 deleted line detected" "4" "$(wad verify-ledger)"
assert_eq "L4 repair refused on a broken chain" "4" "$(wad repair-checkpoint --operator masa --reason "$GOOD")"
cp "$T/good.jsonl" "$WAD_STATE_DIR/ledger.jsonl"; cp "$T/good.cp" "$WAD_STATE_DIR/ledger.checkpoint"
assert_eq "L5 repair is a no-op on a consistent ledger" "0 False" "$(wad repair-checkpoint --operator masa --reason "$GOOD") $(out "r['repaired']")"
fresh
cp "$WAD_STATE_DIR/ledger.checkpoint" "$T/old.cp"
wad response approve "$R" --operator masa --reason "$GOOD" --now "$T1" > /dev/null
cp "$T/old.cp" "$WAD_STATE_DIR/ledger.checkpoint"      # crash: append done, checkpoint not renamed
assert_eq "L6 crash between append and checkpoint refused" "4" "$(wad response list)"
grep -q checkpoint_mismatch "$T/err.txt" && cm=yes || cm=no
assert_eq "L6 reason is checkpoint_mismatch" "yes" "$cm"
assert_eq "L7 repair by a name off the allowlist refused, nothing written" "6 4" "$(wad repair-checkpoint --operator eve --reason "$GOOD") $(wad response list)"
assert_eq "L8 repair by a weak reason refused" "6" "$(wad repair-checkpoint --operator masa --reason "fix")"
assert_eq "L9 repair adopts the 1 unacknowledged record" "0 1 chain-only-unkeyed" \
  "$(wad repair-checkpoint --operator masa --reason "$GOOD" --now "$T1") $(out "r['adopted_records']") $(python3 -c "
import json
print([json.loads(l) for l in open('$WAD_STATE_DIR/ledger.jsonl') if l.strip()][-1]['adopted_authenticity'])")"
assert_eq "L10 after repair: approval kept, ledger verifies (WAD and lib.sh)" "approved 0 ok" "$(state "$R") $(wad verify-ledger) $(libsh_verify)"
printf '999:%s' "$(cut -d: -f2 "$WAD_STATE_DIR/ledger.checkpoint")" > "$WAD_STATE_DIR/ledger.checkpoint"
assert_eq "L11 checkpoint ahead of the ledger (truncation) not repaired" "4" "$(wad repair-checkpoint --operator masa --reason "$GOOD")"
printf '2:%064d' 0 > "$WAD_STATE_DIR/ledger.checkpoint"
assert_eq "L12 checkpoint hash not on the chain not repaired" "4" "$(wad repair-checkpoint --operator masa --reason "$GOOD")"
rm "$WAD_STATE_DIR/ledger.checkpoint"
assert_eq "L13 missing checkpoint not repaired" "4" "$(wad repair-checkpoint --operator masa --reason "$GOOD")"

echo ""
echo "=== K-series: keyed chain ==="
head -c 32 /dev/urandom > "$T/key"; chmod 600 "$T/key"
head -c 32 /dev/urandom > "$T/otherkey"
export WAD_LEDGER_HMAC_KEY_FILE="$T/key"
fresh
wad response approve "$R" --operator masa --reason "$GOOD" --now "$T1" > /dev/null
wad response execute "$R" --now "$T1" > /dev/null
assert_eq "K1 keyed ledger verifies, mode stated" "0 hmac-sha256" "$(wad verify-ledger) $(grep -o 'hmac-sha256' "$T/out.json")"
assert_eq "K2 every record carries a mac; checkpoint mac present" "$(lines) yes" "$(grep -c '"mac": "' "$WAD_STATE_DIR/ledger.jsonl") $([ -s "$WAD_STATE_DIR/ledger.checkpoint.mac" ] && echo yes || echo no)"
assert_eq "K3 security/lib.sh still verifies the keyed chain" "ok" "$(libsh_verify)"
cp "$WAD_STATE_DIR/ledger.jsonl" "$T/k.jsonl"; cp "$WAD_STATE_DIR/ledger.checkpoint" "$T/k.cp"; cp "$WAD_STATE_DIR/ledger.checkpoint.mac" "$T/k.mac"
forge() {   # forge MODE: append a correctly chained record, rewrite the checkpoint like an attacker would
  python3 - "$1" "$T/otherkey" <<'PY'
import hashlib, hmac, json, os, sys
d = os.environ["WAD_STATE_DIR"]; p = os.path.join(d, "ledger.jsonl")
ls = [l for l in open(p).read().splitlines() if l]
prev = hashlib.sha256(ls[-1].encode()).hexdigest()
rec = {"timestamp": "2026-10-27T04:00:00Z", "event_type": "wad_step_transition", "step_id": "forged", "prev_hash": prev}
if sys.argv[1] == "wrongkey":
    key = open(sys.argv[2], "rb").read()
    rec["mac"] = hmac.new(key, json.dumps(rec, sort_keys=True, separators=(",", ":")).encode(), hashlib.sha256).hexdigest()
text = json.dumps(rec)
open(p, "a").write(text + "\n")
open(os.path.join(d, "ledger.checkpoint"), "w").write("%d:%s" % (len(ls) + 1, hashlib.sha256(text.encode()).hexdigest()))
PY
}
forge nomac
assert_eq "K4 forged unkeyed append after keyed records detected" "4 unkeyed_record_after_keyed" "$(wad verify-ledger) $(grep -o 'unkeyed_record_after_keyed' "$T/out.json")"
cp "$T/k.jsonl" "$WAD_STATE_DIR/ledger.jsonl"; cp "$T/k.cp" "$WAD_STATE_DIR/ledger.checkpoint"
forge wrongkey
assert_eq "K5 forged append with another key detected" "4 mac_invalid" "$(wad verify-ledger) $(grep -o 'mac_invalid' "$T/out.json")"
assert_eq "K5 repair refuses it too" "4" "$(wad repair-checkpoint --operator masa --reason "$GOOD")"
cp "$T/k.jsonl" "$WAD_STATE_DIR/ledger.jsonl"; cp "$T/k.cp" "$WAD_STATE_DIR/ledger.checkpoint"
printf '%064d' 0 > "$WAD_STATE_DIR/ledger.checkpoint.mac"
assert_eq "K6 forged checkpoint mac detected" "4 checkpoint_mac_invalid" "$(wad verify-ledger) $(grep -o 'checkpoint_mac_invalid' "$T/out.json")"
cp "$T/k.mac" "$WAD_STATE_DIR/ledger.checkpoint.mac"
assert_eq "K7 restored ledger verifies again" "0" "$(wad verify-ledger)"
assert_eq "K8 keyed ledger read without the key refused" "4" "$(WAD_LEDGER_HMAC_KEY_FILE= wad verify-ledger)"
assert_eq "K8 response refuses without the key" "4" "$(WAD_LEDGER_HMAC_KEY_FILE= wad response list)"
ln -s "$T/key" "$T/keylink"
assert_eq "K9 symlinked key refused" "4" "$(WAD_LEDGER_HMAC_KEY_FILE="$T/keylink" wad response list)"
printf 'short' > "$T/shortkey"
assert_eq "K10 short key refused" "4" "$(WAD_LEDGER_HMAC_KEY_FILE="$T/shortkey" wad response list)"
cp "$WAD_STATE_DIR/ledger.checkpoint" "$T/k.cp"; cp "$WAD_STATE_DIR/ledger.checkpoint.mac" "$T/k.mac"
wad response approve "$I" --operator masa --reason "$GOOD" --now "$T1" > /dev/null
cp "$T/k.cp" "$WAD_STATE_DIR/ledger.checkpoint"; cp "$T/k.mac" "$WAD_STATE_DIR/ledger.checkpoint.mac"
assert_eq "K11 keyed crash refused" "4" "$(wad response list)"
assert_eq "K12 keyed repair adopts hmac-verified records" "0 hmac-verified 0" "$(wad repair-checkpoint --operator masa --reason "$GOOD" --now "$T1") $(python3 -c "
import json
print([json.loads(l) for l in open('$WAD_STATE_DIR/ledger.jsonl') if l.strip()][-1]['adopted_authenticity'])") $(wad verify-ledger)"
unset WAD_LEDGER_HMAC_KEY_FILE

echo ""
echo "=== S-series: nothing executes, nothing claims authentication ==="
code_only() { grep -vE '^\s*#' "$@" | python3 -c "
import sys,re
print(re.sub(r'\"\"\"[\s\S]*?\"\"\"', '', sys.stdin.read()))"; }
assert_eq "S1 no process/network/containment calls in the new module" "0" "$(code_only security/wad/wad_response.py | grep -cE 'subprocess|os\.system|os\.exec|os\.spawn|popen|socket|urllib|http\.client|containment_runner|killswitch_gate|pfctl|iptables|trigger_shutdown' || true)"
assert_eq "S2 no live/execute mode anywhere in security/wad" "0" "$(code_only security/wad/*.py | grep -ciE '"mode": *"live"|mode=.live|--live' || true)"
for s in sudo ssh scp curl nc osascript; do
  assert_eq "S3 stub $s never called" "0" "$(waio_test_stub_calls "$s")"
done
assert_eq "S4 no WAD record anywhere claims authentication" "0" "$(cat "$T"/*.jsonl "$WAD_STATE_DIR"/ledger.jsonl 2>/dev/null | grep -c '"authenticated": true' || true)"
assert_eq "S5 every transition record is a dry run" "0" "$(python3 -c "
import json
print(sum(1 for l in open('$WAD_STATE_DIR/ledger.jsonl') if l.strip() and json.loads(l).get('event_type')=='wad_step_transition' and json.loads(l).get('mode')!='dry_run'))")"
assert_eq "S6 repo security/state/wad untouched by this suite" "no" "$([ -e security/state/wad/ledger.jsonl ] && [ security/state/wad/ledger.jsonl -nt "$T/ev.jsonl" ] && echo yes || echo no)"

echo ""
echo "=== Summary: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
  echo "Failures:"; for f in "${FAILURES[@]}"; do echo "  - $f"; done
  exit 1
fi
exit 0
