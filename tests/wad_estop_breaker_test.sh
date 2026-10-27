#!/bin/bash
set -uo pipefail

# tests/wad_estop_breaker_test.sh -- emergency stop (security/wad/wad_estop.sh,
# ported from #212) and the ledger-derived failure breaker on the #214
# response workflow.
#
#   E-series: engage/release/status, release refusals, evidence kept.
#   H-series: wad.py halts on the stop file / SHUTDOWN.lock / unreadable or
#             symlinked stop path, including a stop engaged between the start
#             record and the executor.
#   P-series: the stop path is independent (no python, no shared code, wad.py
#             never writes it).
#   F-series: breaker trips on 3 consecutive failures of one action, a done
#             resets the count, reset needs an allowlisted operator.
#   S-series: nothing claims authentication; ledger still verifies.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR" || exit 1
# shellcheck source=tests/lib/test_isolation.sh
. tests/lib/test_isolation.sh
waio_test_isolate wad_estop_breaker || exit 3
waio_test_assert_isolated || exit 3
trap 'chmod 700 "$T/estop" 2>/dev/null; waio_test_cleanup' EXIT

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

T="$WAIO_TEST_ROOT/wade"
mkdir -p "$T"
NOW="2026-10-27T02:00:00Z"
T1="2026-10-27T03:00:00Z"
GOOD="contained after review of the shadow ai alert"
ESTOP=security/wad/wad_estop.sh
export WAD_STATE_DIR="$T/state"
export WAD_STOP_FILE="$T/estop/STOP"
export WAIO_SHUTDOWN_LOCK="${WAIO_SHUTDOWN_LOCK:-$T/SHUTDOWN.lock}"
unset WAD_LEDGER_HMAC_KEY_FILE WAD_APPROVER_ALLOWLIST WAD_APPROVAL_TTL_S
rm -f "$WAIO_SHUTDOWN_LOCK"

cat > "$T/ev.jsonl" <<'EOF'
{"event_id":"e1","source_module":"shadow_ai_monitor","entity":"worker-a","entity_type":"agent","risk":"CRITICAL","confidence":"HIGH","observed_at":"2026-10-27T01:00:00Z"}
{"event_id":"e2","source_module":"shadow_ai_monitor","entity":"worker-b","entity_type":"agent","risk":"CRITICAL","confidence":"HIGH","observed_at":"2026-10-27T01:00:00Z"}
{"event_id":"e3","source_module":"shadow_ai_monitor","entity":"worker-c","entity_type":"agent","risk":"CRITICAL","confidence":"HIGH","observed_at":"2026-10-27T01:00:00Z"}
{"event_id":"e4","source_module":"shadow_ai_monitor","entity":"worker-d","entity_type":"agent","risk":"CRITICAL","confidence":"HIGH","observed_at":"2026-10-27T01:00:00Z"}
EOF

wad() { python3 security/wad/wad.py "$@" > "$T/out.json" 2> "$T/err.txt"; echo $?; }
out() { python3 -c "import json,sys; r=json.load(open('$T/out.json')); print($1)"; }
violations() { out "','.join(r.get('violations', []))"; }
estop() { "$ESTOP" "$@" > "$T/estop.out" 2>&1; echo $?; }
count_type() { python3 -c "
import json,sys
print(sum(1 for l in open('$WAD_STATE_DIR/ledger.jsonl') if l.strip() and json.loads(l).get('event_type')==sys.argv[1]))" "$1"; }
step_of() {   # step_of ENTITY ACTION -> step id
  wad response list > /dev/null
  out "[s['step_id'] for s in r if s['entity']=='$1' and s['action']=='$2'][0]"
}
state() { wad response list > /dev/null; out "[s['state'] for s in r if s['step_id']=='$1'][0]"; }
crash_after_start() {
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
fresh() {
  rm -rf "$WAD_STATE_DIR" "$T/estop"
  mkdir -p "$WAD_STATE_DIR"
  printf 'masa\nclaude\n' > "$WAD_STATE_DIR/approvers"
  wad evaluate --events "$T/ev.jsonl" --now "$NOW" > /dev/null
}

echo "=== E-series: emergency stop tool ==="
fresh
assert_eq "E1 status when never engaged" "0" "$(estop status)"
assert_eq "E2 engage needs no identity" "0" "$(estop engage)"
assert_eq "E2 status now engaged (exit 10)" "10" "$(estop status)"
estop engage --operator masa --reason "drill" > /dev/null
assert_eq "E3 engage records who/why when given" "operator=masa" "$(grep -o 'operator=masa' "$WAD_STOP_FILE")"
assert_eq "E4 release without an operator refused" "2" "$(estop release --reason "drill complete, verified")"
for who in claude wad-runner autopilot root my-bot llm-ops; do
  assert_eq "E5 release by automated name '$who' refused" "2" "$(estop release --operator "$who" --reason "drill complete, verified")"
done
assert_eq "E6 release with a short reason refused" "2" "$(estop release --operator masa --reason "ok")"
assert_eq "E7 release with a malformed name refused" "2" "$(estop release --operator "masa;rm" --reason "drill complete, verified")"
assert_eq "E8 still engaged after every refused release" "10" "$(estop status)"
assert_eq "E9 release by a human-looking name" "0" "$(estop release --operator masa --reason "drill complete, verified")"
assert_eq "E9 says the name is not authenticated" "1" "$(grep -c 'not authenticated' "$T/estop.out")"
assert_eq "E10 released file kept as evidence" "1" "$(ls "$T/estop/released" | grep -c '^STOP\.')"
assert_eq "E11 log has 2 engages and 1 release, release marked unauthenticated" "2 1 1" \
  "$(grep -c ' engage ' "$T/estop/estop.log") $(grep -c ' release ' "$T/estop/estop.log") $(grep -c 'authenticated=false' "$T/estop/estop.log")"
assert_eq "E12 release when not engaged is a no-op" "0" "$(estop release --operator masa --reason "drill complete, verified")"
assert_eq "E13 usage error" "2" "$(estop bogus)"

echo ""
echo "=== H-series: wad.py halts on every stop signal ==="
fresh
RA=$(step_of worker-a restrict_egress); MA=$(step_of worker-a monitor_increase)
wad response approve "$RA" --operator masa --reason "$GOOD" --now "$T1" > /dev/null
estop engage --operator masa --reason "incident" > /dev/null
assert_eq "H1 execute refused while the stop is engaged" "6 killswitch_active" "$(wad response execute "$MA" --now "$T1") $(violations)"
assert_eq "H2 approve refused while engaged" "6" "$(wad response approve "$(step_of worker-b restrict_egress)" --operator masa --reason "$GOOD" --now "$T1")"
assert_eq "H3 reject still allowed (conservative)" "0" "$(wad response reject "$(step_of worker-a isolate_agent)" --operator masa --reason "$GOOD" --now "$T1")"
assert_eq "H4 list and sweep still work" "0 0" "$(wad response list) $(wad response sweep --now "$T1")"
estop release --operator masa --reason "incident closed, verified" > /dev/null
assert_eq "H5 after release execution works again" "0 done" "$(wad response execute "$MA" --now "$T1") $(state "$MA")"
touch "$WAIO_SHUTDOWN_LOCK"
assert_eq "H6 WAIO SHUTDOWN.lock halts WAD with the stop released" "6 killswitch_active" "$(wad response execute "$RA" --now "$T1") $(violations)"
rm -f "$WAIO_SHUTDOWN_LOCK"
mkdir -p "$T/estop"; chmod 000 "$T/estop"
assert_eq "H7 unreadable stop dir counts as engaged (wad.py)" "6 killswitch_active" "$(wad response execute "$RA" --now "$T1") $(violations)"
assert_eq "H7 unreadable stop dir counts as engaged (estop status)" "10" "$(estop status)"
chmod 700 "$T/estop"
ln -s /nonexistent/target "$WAD_STOP_FILE"
assert_eq "H8 dangling symlink at the stop path counts as engaged" "6 10" "$(wad response execute "$RA" --now "$T1") $(estop status)"
rm -f "$WAD_STOP_FILE"
assert_eq "H9 stop engaged between start record and executor -> step failed, executor not run" "failed halted: stop engaged before the executor ran 0" \
  "$( (python3 - "$RA" "$T1" <<'PY'
import json, os, sys
sys.path.insert(0, "security/wad")
import wad
calls = {"n": 0}
def fake(path):        # the first two lookups are the pre-start check; later ones see the stop
    calls["n"] += 1
    return calls["n"] > 2
wad.stop_signal = fake
try:
    wad.main(["response", "execute", sys.argv[1], "--now", sys.argv[2]])
except SystemExit:
    pass
recs = [json.loads(l) for l in open(os.path.join(os.environ["WAD_STATE_DIR"], "ledger.jsonl")) if l.strip()]
t = [r for r in recs if r.get("step_id") == sys.argv[1] and r.get("event_type") == "wad_step_transition"]
print(t[-1]["to"], t[-1].get("error"), sum(1 for r in t if r.get("action") == "complete"))
PY
) | tail -1)"

echo ""
echo "=== P-series: the stop path is independent ==="
mkdir -p "$T/bin"
for b in dirname date tr cut mkdir chmod mktemp mv cat ls; do ln -sf "$(command -v "$b")" "$T/bin/$b"; done
assert_eq "P1 no python on the restricted PATH" "missing" "$(env -i PATH="$T/bin" /bin/bash -c 'command -v python3' > /dev/null 2>&1 && echo present || echo missing)"
rm -rf "$T/estop"
assert_eq "P2 engage works with no python available" "0 10" "$(PATH="$T/bin" /bin/bash "$ESTOP" engage --reason "no python" > /dev/null 2>&1; echo $?) $(estop status)"
estop release --operator masa --reason "independence drill done" > /dev/null
assert_eq "P3 wad_estop.sh references no python / WAD module" "0" "$(grep -v '^[[:space:]]*#' "$ESTOP" | grep -cE 'python|wad\.py|wad_lib|wad_response' || true)"
assert_eq "P4 wad_estop.sh sources nothing" "0" "$(grep -cE '^[[:space:]]*(source|\.)[[:space:]]' "$ESTOP" || true)"
assert_eq "P5 wad.py never writes, moves or deletes the stop file" "0" "$(grep -nE 'os\.(remove|unlink|rename|replace)|open\(' security/wad/wad.py | grep -ci 'stop' || true)"

echo ""
echo "=== F-series: failure breaker ==="
fresh
for e in worker-a worker-b; do crash_after_start "$(step_of $e monitor_increase)"; done
wad response sweep --now "$T1" > /dev/null
assert_eq "F1 two failures: breaker closed" "False 2" "$(out "r['breaker']['open']") $(out "r['breaker']['counts']['monitor_increase']")"
rc=$(wad response execute "$(step_of worker-c monitor_increase)" --now "$T1")
wad response sweep --now "$T1" > /dev/null
assert_eq "F2 a done resets the count" "0 0" "$rc $(out "r['breaker']['counts']['monitor_increase']")"
for e in worker-a worker-b worker-c; do crash_after_start "$(step_of $e warn_operator)"; done
assert_eq "F3 third consecutive failure of one action trips it" "0 True warn_operator 1" \
  "$(wad response sweep --now "$T1") $(out "r['breaker']['open']") $(out "r['breaker']['tripped_by']") $(count_type wad_breaker_tripped)"
assert_eq "F4 any execute refused while open" "6 breaker_open" "$(wad response execute "$(step_of worker-d monitor_increase)" --now "$T1") $(violations)"
assert_eq "F5 breaker is derived from the ledger: still open in a new process" "6" "$(wad response execute "$(step_of worker-d warn_operator)" --now "$T1")"
assert_eq "F6 reset by an automated name refused" "6 automated_identity_refused" "$(wad response breaker-reset --operator claude --reason "$GOOD" --now "$T1") $(violations)"
assert_eq "F7 reset by a name off the allowlist refused" "6 identity_not_in_allowlist" "$(wad response breaker-reset --operator eve --reason "$GOOD" --now "$T1") $(violations)"
assert_eq "F8 reset with a weak reason refused" "6 reason_too_short" "$(wad response breaker-reset --operator masa --reason "fixed" --now "$T1") $(violations)"
assert_eq "F9 reset by an allowlisted operator" "0 1" "$(wad response breaker-reset --operator masa --reason "$GOOD" --now "$T1") $(count_type wad_breaker_reset)"
assert_eq "F10 execution works after the reset" "0 done" "$(wad response execute "$(step_of worker-d monitor_increase)" --now "$T1") $(state "$(step_of worker-d monitor_increase)")"
assert_eq "F11 reset when not open refused" "6 breaker_not_open" "$(wad response breaker-reset --operator masa --reason "$GOOD" --now "$T1") $(violations)"

echo ""
echo "=== S-series ==="
assert_eq "S1 no record claims authentication" "0" "$(grep -c '"authenticated": true' "$WAD_STATE_DIR/ledger.jsonl" || true)"
assert_eq "S2 breaker reset recorded unauthenticated" "False" "$(python3 -c "
import json
print([json.loads(l) for l in open('$WAD_STATE_DIR/ledger.jsonl') if l.strip() and json.loads(l).get('event_type')=='wad_breaker_reset'][-1]['authenticated'])")"
assert_eq "S3 ledger verifies (WAD and lib.sh)" "0 ok" "$(wad verify-ledger) $(WAIO_AUDIT_LOG="$WAD_STATE_DIR/ledger.jsonl" WAIO_AUDIT_LOG_CHECKPOINT="$WAD_STATE_DIR/ledger.checkpoint" bash -c '. security/lib.sh; verify_audit_log_integrity')"
for s in sudo ssh scp curl nc osascript; do
  assert_eq "S4 stub $s never called" "0" "$(waio_test_stub_calls "$s")"
done

echo ""
echo "=== Summary: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
  echo "Failures:"; for f in "${FAILURES[@]}"; do echo "  - $f"; done
  exit 1
fi
exit 0
