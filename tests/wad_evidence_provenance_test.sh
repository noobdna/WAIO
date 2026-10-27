#!/bin/bash
set -uo pipefail

# tests/wad_evidence_provenance_test.sh -- evidence provenance on WAD
# decisions and approvals (wad_response.evidence_provenance; wad.py
# wad_decision.evidence_provenance and approve's evidence_at_approval).
#
#   E-series: the pure summary (signature status, time source, derived
#             corroboration, notes).
#   C-series: through the CLI with real-detector fixtures, direct events
#             files, the inventory adapter, signed records and approvals.
#   N-series: visibility only -- levels unchanged, nothing gates on it.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR" || exit 1
# shellcheck source=tests/lib/test_isolation.sh
. tests/lib/test_isolation.sh
waio_test_isolate wad_evidence || exit 3
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

T="$WAIO_TEST_ROOT/wadp"
mkdir -p "$T"
NOW="2026-10-27T02:00:00Z"
TS="2026-10-27T01:00:00Z"
GOOD="contained after review of the shadow ai alert"
export WAD_STATE_DIR="$T/state"
export WAD_STOP_FILE="$T/STOP"
unset WAD_LEDGER_HMAC_KEY_FILE WAD_PRODUCER_KEY_DIR

python3 - "$T" "$TS" <<'PY'
import json, os, sys
D, ts = sys.argv[1:3]
sys.path[:0] = ["security/shadow_ai", "security/attack_graph"]
import shadow_ai_lib as sal, attack_graph_lib as agl
sig = dict(pattern="ollama", risk="CRITICAL", category="local_llm_runtime", label="Ollama")
f = sal.build_finding("process", sig, "exact_comm", False, ts, "ollama runtime running", process=dict(comm="ollama", pid=7))
open(os.path.join(D, "shadow.jsonl"), "w").write(json.dumps(f) + "\n")
fs = agl.parse_findings([json.dumps(f) + "\n"]); g = agl.build_graph(fs)
json.dump(dict(generated_at=ts, findings_processed=1, nodes=g["nodes"], edges=g["edges"], analysis=agl.graph_summary(g)),
          open(os.path.join(D, "graph.json"), "w"))
json.dump(sal.merge_inventory({}, [f], ts), open(os.path.join(D, "inventory.json"), "w"))
e = dict(event_id="d1", source_module="shadow_ai_monitor", entity="ollama", entity_type="process", risk="CRITICAL",
         confidence="HIGH", observed_at=ts)
open(os.path.join(D, "direct.jsonl"), "w").write(json.dumps(e) + "\n")
PY

pe() { python3 -c "
import sys, json; sys.path.insert(0, 'security/wad'); import wad_response as wr
P = lambda **k: dict(signature_status=k.get('s','unsigned'), timestamp_source=k.get('t','detector_record'), **({'detection_time_known': False} if k.get('nodet') else {}))
E = lambda m, **k: dict(source_module=m, provenance=P(**k))
$1"; }
wad() { python3 security/wad/wad.py "$@" > "$T/out.json" 2> "$T/err.txt"; echo $?; }
out() { python3 -c "import json,sys; r=json.load(open('$T/out.json')); print($1)"; }
ev() { out "r['evidence_provenance']['ollama']$1"; }
reset() { rm -rf "$WAD_STATE_DIR"; mkdir -p "$WAD_STATE_DIR"; printf 'masa\n' > "$WAD_STATE_DIR/approvers"; }

echo "=== E-series: pure summary ==="
assert_eq "E1 no events: nothing verified, no notes" "0 False []" "$(pe "r=wr.evidence_provenance([]); print(r['events'], r['all_verified'], r['notes'])")"
assert_eq "E2 direct events file: no provenance, said so" "{'no_provenance_direct_events_file': 1} True" "$(pe "r=wr.evidence_provenance([dict(source_module='saas_ato')]); print(r['signature_status'], 'no supporting event is signature-verified' in r['notes'])")"
assert_eq "E3 shadow_ai + attack_graph: only shadow_ai independent, note says why" "['shadow_ai_monitor'] True" "$(pe "r=wr.evidence_provenance([E('shadow_ai_monitor'), E('attack_graph')]); print(r['independent_source_modules'], any('attack_graph is derived from shadow_ai_monitor' in n for n in r['notes']))")"
assert_eq "E4 attack_graph alone is independent (nothing it derives from present)" "['attack_graph']" "$(pe "print(wr.evidence_provenance([E('attack_graph')])['independent_source_modules'])")"
assert_eq "E5 shadow_ai + saas_ato: both independent, no derived note" "['saas_ato', 'shadow_ai_monitor'] 0" "$(pe "r=wr.evidence_provenance([E('shadow_ai_monitor'), E('saas_ato')]); print(r['independent_source_modules'], sum('derived' in n for n in r['notes']))")"
assert_eq "E6 all verified -> all_verified, no 'not verified' note" "True 0" "$(pe "r=wr.evidence_provenance([E('saas_ato', s='verified'), E('shadow_ai_monitor', s='verified')]); print(r['all_verified'], sum('signature-verified' in n for n in r['notes']))")"
assert_eq "E7 one verified of two -> not all_verified" "False" "$(pe "print(wr.evidence_provenance([E('saas_ato', s='verified'), E('saas_ato')])['all_verified'])")"
assert_eq "E8 scan-time evidence counted and noted" "1 True" "$(pe "r=wr.evidence_provenance([E('shadow_ai_monitor', nodet=True, t='inventory_last_seen_scan_time')]); print(r['detection_time_unknown'], any('scan time' in n for n in r['notes']))")"

echo ""
echo "=== C-series: through the CLI ==="
reset
assert_eq "C1 JSONL + graph: decision carries the summary" "0 ['attack_graph', 'shadow_ai_monitor'] ['shadow_ai_monitor'] {'unsigned': 2}" \
  "$(wad ingest --shadow-ai "$T/shadow.jsonl" --attack-graph "$T/graph.json" --now "$NOW") $(ev "['source_modules']") $(ev "['independent_source_modules']") $(ev "['signature_status']")"
assert_eq "C2 the same summary is in the ledger's wad_decision" "True" "$(python3 -c "
import json
L=[json.loads(l) for l in open('$WAD_STATE_DIR/ledger.jsonl') if l.strip()]
d=[x for x in L if x['event_type']=='wad_decision' and x['entity']=='ollama'][0]
print(d['evidence_provenance']==json.load(open('$T/out.json'))['evidence_provenance']['ollama'])")"
reset
assert_eq "C3 direct events file: marked as having no provenance" "0 {'no_provenance_direct_events_file': 1}" "$(wad evaluate --events "$T/direct.jsonl" --now "$NOW") $(ev "['signature_status']")"
reset
assert_eq "C4 inventory: scan-time evidence counted" "0 1 {'inventory_last_seen_scan_time': 1}" "$(wad ingest --shadow-ai-inventory "$T/inventory.json" --now "$NOW") $(ev "['detection_time_unknown']") $(ev "['timestamp_source']")"
mkdir -p "$T/keys"; head -c 32 /dev/urandom > "$T/keys/shadow_ai.key"
python3 - "$T/shadow.jsonl" "$T/signed.jsonl" "$T/keys/shadow_ai.key" <<'PY'
import hashlib, hmac, json, sys
f = json.loads(open(sys.argv[1]).read()); key = open(sys.argv[3], "rb").read()
f["wad_sig"] = dict(alg="hmac-sha256", key_id="shadow_ai",
                    mac=hmac.new(key, json.dumps(f, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(), hashlib.sha256).hexdigest())
open(sys.argv[2], "w").write(json.dumps(f) + "\n")
PY
reset
assert_eq "C5 verified record + unsigned graph: not all_verified" "0 1 1 False" "$(WAD_PRODUCER_KEY_DIR="$T/keys" wad ingest --shadow-ai "$T/signed.jsonl" --attack-graph "$T/graph.json" --now "$NOW") $(ev "['signature_status'].get('verified')") $(ev "['signature_status'].get('unsigned')") $(ev "['all_verified']")"
reset
wad ingest --shadow-ai "$T/shadow.jsonl" --attack-graph "$T/graph.json" --now "$NOW" > /dev/null
wad response list > /dev/null
SID=$(out "[s['step_id'] for s in r if s['entity']=='ollama' and s['action']=='restrict_egress'][0]")
assert_eq "C6 approval record copies the evidence the approver approved" "0 True" "$(wad response approve "$SID" --operator masa --reason "$GOOD" --now "$NOW") $(python3 -c "
import json
L=[json.loads(l) for l in open('$WAD_STATE_DIR/ledger.jsonl') if l.strip()]
d=[x for x in L if x['event_type']=='wad_decision' and x['entity']=='ollama'][0]
a=[x for x in L if x.get('action')=='approve' and x['event_type']=='wad_step_transition'][0]
print(a['evidence_at_approval']==d['evidence_provenance'])")"
assert_eq "C7 ledger verifies (WAD and lib.sh)" "0 ok" "$(python3 security/wad/wad.py verify-ledger > /dev/null 2>&1; echo $?) $(WAIO_AUDIT_LOG="$WAD_STATE_DIR/ledger.jsonl" WAIO_AUDIT_LOG_CHECKPOINT="$WAD_STATE_DIR/ledger.checkpoint" bash -c '. security/lib.sh; verify_audit_log_integrity')"

echo ""
echo "=== N-series: visibility only ==="
reset
wad ingest --shadow-ai "$T/shadow.jsonl" --attack-graph "$T/graph.json" --now "$NOW" > /dev/null
assert_eq "N1 threat level equals wad_lib's own assessment of the same events" "True" "$(python3 -c "
import json, sys; sys.path.insert(0, 'security/wad'); import wad_adapters as wa, wad_lib as wl
pol = json.load(open('security/wad/policies/wad_policy.json')); now = wl.parse_ts('$NOW')
evs = wa.convert('shadow_ai', '$T/shadow.jsonl', {})['events'] + wa.convert('attack_graph', '$T/graph.json', {})['events']
s = wl.screen_events(evs, dict(), now, pol['limits']); lv = dict((a['entity'], a['threat_level']) for a in wl.assess(s['accepted'], s['conflicts'], now))
r = json.load(open('$T/out.json')); print(lv == dict((a['entity'], a['threat_level']) for a in r['assessments']))")"
# Since the optional approval evidence policy (OFF by default), check_approval
# may read the summary, but only through check_evidence_policy; with no policy
# the summary never refuses anything. The other gates still never read it.
assert_eq "N2 start/rollback/operator gates never read the summary" "0" "$(python3 -c "
import inspect, sys; sys.path.insert(0, 'security/wad'); import wad_response as wr
print(sum('evidence' in inspect.getsource(f) for f in (wr.check_start, wr.check_rollback, wr.check_operator)))")"
assert_eq "N2b with no policy, evidence never refuses an approval (any evidence, disruptive step)" "[] [] []" "$(python3 -c "
import sys; sys.path.insert(0, 'security/wad'); import wad_response as wr
st = dict(state='awaiting_approval', **{'class': 'disruptive'})
print(*[wr.check_evidence_policy(st, ev, None) for ev in (None, dict(all_verified=False, independent_source_modules=[]), dict(all_verified=True))])")"
for s in sudo ssh scp curl nc osascript; do
  assert_eq "N3 stub $s never called" "0" "$(waio_test_stub_calls "$s")"
done

echo ""
echo "=== Summary: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
  echo "Failures:"; for f in "${FAILURES[@]}"; do echo "  - $f"; done
  exit 1
fi
exit 0
