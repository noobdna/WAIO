#!/bin/bash
set -uo pipefail

# tests/wad_inventory_adapter_test.sh -- WAD: inventory-derived shadow_ai
# adapter (wad_adapters.convert_inventory, `wad.py ingest --shadow-ai-inventory`).
#
# Fixtures come from the detectors' own code: findings from
# shadow_ai_lib.build_finding, two scans merged by shadow_ai_lib.merge_inventory
# (exactly how security/state/shadow_ai/inventory.json is written), and the
# attack_graph document built by attack_graph_lib from the second scan.
#
#   V-series: valid conversion, entity mapping, provenance, intelligence_lib reuse.
#   M-series: malformed documents and entries.
#   F-series: missing fields.
#   T-series: stale and future scan times.
#   D-series: duplicates, re-observation, altered entries, mixing with JSONL.
#   G-series: signatures (inventory and the graph used for mapping).
#   S-series: honesty (scan time never presented as detection time) and safety.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR" || exit 1
# shellcheck source=tests/lib/test_isolation.sh
. tests/lib/test_isolation.sh
waio_test_isolate wad_inventory || exit 3
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

T="$WAIO_TEST_ROOT/wadi"
mkdir -p "$T"
NOW="2026-10-27T02:00:00Z"
S1="2026-10-27T00:30:00Z"     # first scan
S2="2026-10-27T01:30:00Z"     # second scan: only the ollama finding is seen again
export WAD_STATE_DIR="$T/state"
export WAD_STOP_FILE="$T/STOP"
unset WAD_LEDGER_HMAC_KEY_FILE WAD_PRODUCER_KEY_DIR

# gen DIR [S1] [S2] -> inventory.json, graph.json, scan2.jsonl, ids.txt (ollama_id lmstudio_id)
gen() {
  python3 - "$1" "${2:-$S1}" "${3:-$S2}" <<'PY'
import json, os, sys
D, s1, s2 = sys.argv[1:4]
os.makedirs(D, exist_ok=True)
sys.path[:0] = ["security/shadow_ai", "security/attack_graph"]
import shadow_ai_lib as sal, attack_graph_lib as agl
def finding(pattern, label, risk, comm, ts):
    sig = dict(pattern=pattern, risk=risk, category="local_llm_runtime", label=label)
    return sal.build_finding("process", sig, "exact_comm", False, ts, label + " running", process=dict(comm=comm, pid=7))
scan1 = [finding("ollama", "Ollama", "HIGH", "ollama", s1), finding("lm-studio", "LM Studio", "MEDIUM", "LM Studio", s1)]
scan2 = [finding("ollama", "Ollama", "HIGH", "ollama", s2)]
inv = sal.merge_inventory(sal.merge_inventory({}, scan1, s1), scan2, s2)
json.dump(inv, open(os.path.join(D, "inventory.json"), "w"))
fs = agl.parse_findings([json.dumps(f) + "\n" for f in scan2])
g = agl.build_graph(fs)
json.dump(dict(generated_at=s2, findings_processed=len(fs), nodes=g["nodes"], edges=g["edges"],
               analysis=agl.graph_summary(g)), open(os.path.join(D, "graph.json"), "w"))
open(os.path.join(D, "scan2.jsonl"), "w").write("".join(json.dumps(f) + "\n" for f in scan2))
open(os.path.join(D, "ids.txt"), "w").write(scan1[0]["id"] + " " + scan1[1]["id"] + "\n")
PY
}
edit() {   # edit FILE PYTHON -- mutate the JSON document `d` in place
  python3 -c "
import json; p='$1'; d=json.load(open(p))
$2
json.dump(d, open(p,'w'))"
}
ingest() { python3 security/wad/wad.py ingest --now "$NOW" "$@" > "$T/out.json" 2> "$T/err.txt"; echo $?; }
out() { python3 -c "import json,sys; r=json.load(open('$T/out.json')); print($1)"; }
prov() {   # prov PYTHON -- over P: provenance dicts of accepted inventory events, sorted by entity
  python3 -c "
import json
L=[json.loads(l) for l in open('$WAD_STATE_DIR/ledger.jsonl') if l.strip()]
P=[v for d in L if d['event_type']=='wad_events_accepted' for v in d.get('provenance',{}).values() if v['detector']=='shadow_ai_inventory']
$1"
}
adapter_reasons() { python3 -c "
import json
L=[json.loads(l) for l in open('$WAD_STATE_DIR/ledger.jsonl') if l.strip()]
print(','.join(sorted(r for d in L if d.get('stage')=='adapter' for r in d['reasons'])))"; }
schema_reasons() { python3 -c "
import json
L=[json.loads(l) for l in open('$WAD_STATE_DIR/ledger.jsonl') if l.strip()]
print(','.join(sorted(r for d in L if d['event_type']=='wad_event_rejected' and 'stage' not in d for r in d['reasons'])))"; }
reset() { rm -rf "$WAD_STATE_DIR"; mkdir -p "$WAD_STATE_DIR"; }
conv() {   # conv INVENTORY [GRAPH] -- adapter output as JSON on stdout (no ledger)
  python3 -c "
import json, sys; sys.path.insert(0, 'security/wad'); import wad_adapters as wa
r = wa.convert('shadow_ai_inventory', '$1', {}, graph_path=('${2:-}' or None))
print(json.dumps(r))"
}

gen "$T/a"
read -r OID LID < "$T/a/ids.txt"

echo "=== V-series: valid conversion ==="
reset
assert_eq "V1 two inventory entries -> two accepted events" "0 2 0" "$(ingest --shadow-ai-inventory "$T/a/inventory.json" --attack-graph "$T/a/graph.json") $(prov "print(len(P))") $(out "r['counts']['rejected']+r['counts']['adapter_rejected']")"
assert_eq "V2 entity: graph node via finding_ids, else signature_matched" "attack_graph_finding_ids,signature_matched_fallback" "$(prov "print(','.join(sorted(p['entity_mapping'] for p in P)))")"
assert_eq "V3 mapped entity is the graph node name (shared with attack_graph)" "1" "$(out "sum(1 for a in r['assessments'] if a['entity']=='ollama')")"
assert_eq "V4 fallback entity is the signature" "lm-studio" "$(conv "$T/a/inventory.json" "$T/a/graph.json" | python3 -c "
import json,sys; r=json.load(sys.stdin); print([e['entity'] for e in r['events'] if e['_provenance']['entity_mapping']=='signature_matched_fallback'][0])")"
assert_eq "V5 risk/confidence = last_risk/last_confidence unchanged, time = last_seen" "True" "$(conv "$T/a/inventory.json" "$T/a/graph.json" | python3 -c "
import json,sys; r=json.load(sys.stdin); inv=json.load(open('$T/a/inventory.json'))
by={e['_provenance']['source_record_id']: e for e in r['events']}
print(all((by[k]['risk'],by[k]['confidence'],by[k]['observed_at'])==(v['last_risk'],v['last_confidence'],v['last_seen']) for k,v in inv.items()))")"
assert_eq "V6 provenance says scan time, not detection time" "inventory_last_seen_scan_time False inventory_last_confidence shadow_ai_inventory" \
  "$(prov "s=set((p['timestamp_source'],p['detection_time_known'],p['confidence_source'],p['derived_from']) for p in P); print(*list(s)[0]) if len(s)==1 else print(s)")"
assert_eq "V7 seen_in_latest_scan: ollama yes, lm-studio no" "False True" "$(prov "print(*[p['seen_in_latest_scan'] for p in sorted(P, key=lambda p: p['source_record_id']!='$OID')][::-1])")"
assert_eq "V8 times_seen and first_seen carried" "1:$S1 2:$S1" "$(prov "print(*sorted('%d:%s'%(p['times_seen'],p['first_seen']) for p in P))")"
assert_eq "V9 source file sha256 and unsigned status recorded" "True unsigned unsigned" "$(prov "
import hashlib; h=hashlib.sha256(open('$T/a/inventory.json','rb').read()).hexdigest()
print(all(p['source_file_sha256']==h for p in P), P[0]['signature_status'], P[0]['entity_map_graph'])")"
assert_eq "V10 source_module stays shadow_ai_monitor (no extra corroboration source)" "shadow_ai_monitor" "$(conv "$T/a/inventory.json" | python3 -c "
import json,sys; print(','.join(sorted(set(e['source_module'] for e in json.load(sys.stdin)['events']))))")"
assert_eq "V11 conversion is intelligence_lib.from_shadow_ai_finding on renamed fields" "True" "$(python3 -c "
import json, sys; sys.path[:0]=['security/wad','security/intelligence']; import wad_adapters as wa, intelligence_lib as il
inv=json.load(open('$T/a/inventory.json')); e=[x for x in wa.convert('shadow_ai_inventory','$T/a/inventory.json',{})['events'] if x['_provenance']['source_record_id']=='$LID'][0]
v=inv['$LID']; rec=il.from_shadow_ai_finding(dict(id='$LID', category=v['category'], signature_matched=v['signature_matched'], risk=v['last_risk'], confidence=v['last_confidence'], detected_at=v['last_seen']))
print((e['entity'],e['entity_type'],e['category'],e['source_module'])==(rec['entity'],rec['entity_type'],rec['category'],rec['source_module']))")"
assert_eq "V12 without a graph: every entity falls back, said so" "no_graph signature_matched_fallback" "$(conv "$T/a/inventory.json" | python3 -c "
import json,sys; r=json.load(sys.stdin); print(*sorted(set([r['events'][0]['_provenance']['entity_map_graph']]+[e['_provenance']['entity_mapping'] for e in r['events']])))")"
cp "$T/a/graph.json" "$T/amb.json"; edit "$T/amb.json" "d['nodes']['other']=dict(d['nodes']['ollama'])"
assert_eq "V13 id in two graph nodes -> ambiguous, fall back" "ambiguous_fallback Ollama" "$(conv "$T/a/inventory.json" "$T/amb.json" | python3 -c "
import json,sys; r=json.load(sys.stdin); e=[x for x in r['events'] if x['_provenance']['source_record_id']=='$OID'][0]; print(e['_provenance']['entity_mapping'], e['entity'] if e['entity']!='ollama' else 'ollama')" | sed 's/ ollama$/ Ollama/')"
printf 'not json' > "$T/badgraph.json"
assert_eq "V14 unusable graph -> fallback, said so" "graph_unusable" "$(conv "$T/a/inventory.json" "$T/badgraph.json" | python3 -c "
import json,sys; print(json.load(sys.stdin)['events'][0]['_provenance']['entity_map_graph'])")"

echo ""
echo "=== M-series: malformed input ==="
reset; printf 'not json' > "$T/m1.json"
assert_eq "M1 not JSON = source failure (exit 7)" "7 not_json" "$(ingest --shadow-ai-inventory "$T/m1.json") $(out "r['sources']['shadow_ai_inventory']['failure']")"
printf '[1,2]' > "$T/m2.json"
assert_eq "M2 top level not an object" "7 bad_document_shape" "$(ingest --shadow-ai-inventory "$T/m2.json") $(out "r['sources']['shadow_ai_inventory']['failure']")"
cp "$T/a/inventory.json" "$T/m3.json"
edit "$T/m3.json" "
k=list(d); d[k[0]]='not an entry'
d['SHADOWAI-wrongkey']=dict(d[k[1]])
d['SHADOWAI-zero']=dict(d[k[1]], id='SHADOWAI-zero', times_seen=0)
d['SHADOWAI-strts']=dict(d[k[1]], id='SHADOWAI-strts', times_seen='3')
d['SHADOWAI-bool']=dict(d[k[1]], id='SHADOWAI-bool', times_seen=True)
d['SHADOWAI-order']=dict(d[k[1]], id='SHADOWAI-order', first_seen='2026-10-27T01:50:00Z')
d['SHADOWAI-badfirst']=dict(d[k[1]], id='SHADOWAI-badfirst', first_seen='yesterday')
d['SHADOWAI-noent']=dict(d[k[1]], id='SHADOWAI-noent', signature_matched='')"
reset
assert_eq "M3 bad entries rejected one by one; the good one still converts" "0 1" "$(ingest --shadow-ai-inventory "$T/m3.json") $(prov "print(len(P))")"
assert_eq "M4 reasons: not_an_object, id_mismatch, bad_times_seen x3, order, bad_first_seen, no_entity" \
  "bad_first_seen,bad_times_seen,bad_times_seen,bad_times_seen,first_seen_after_last_seen,id_mismatch,no_entity,not_an_object" "$(adapter_reasons)"
cp "$T/a/inventory.json" "$T/m5.json"
edit "$T/m5.json" "
k=list(d); d[k[0]]['last_risk']='EXTREME'; d[k[1]]['last_seen']='2026-10-27T01:30:00'"
reset
assert_eq "M5 bad enum and naive timestamp rejected by wad_lib" "0 bad_observed_at,bad_risk" "$(ingest --shadow-ai-inventory "$T/m5.json") $(schema_reasons)"

echo ""
echo "=== F-series: missing fields ==="
cp "$T/a/inventory.json" "$T/f1.json"; edit "$T/f1.json" "d['$OID'].pop('last_risk')"
reset
assert_eq "F1 missing last_risk stays missing (not LOW): never disruptive" "0 UNDETERMINED" "$(ingest --shadow-ai-inventory "$T/f1.json") $(out "[a['threat_level'] for a in r['assessments'] if a['entity']=='ollama'][0]")"
cp "$T/a/inventory.json" "$T/f2.json"; edit "$T/f2.json" "d['$LID'].pop('last_seen')"
reset
assert_eq "F2 missing last_seen: accepted as insufficient, timestamp_source absent" "0 absent" "$(ingest --shadow-ai-inventory "$T/f2.json") $(prov "print([p['timestamp_source'] for p in P if p['source_record_id']=='$LID'][0])")"
cp "$T/a/inventory.json" "$T/f3.json"; edit "$T/f3.json" "d['$LID'].pop('times_seen')"
reset
assert_eq "F3 missing times_seen rejected" "0 bad_times_seen" "$(ingest --shadow-ai-inventory "$T/f3.json") $(adapter_reasons)"
cp "$T/a/inventory.json" "$T/f4.json"; edit "$T/f4.json" "d['$LID'].pop('signature_matched')"
reset
assert_eq "F4 no graph match and no signature: rejected (no_entity), not 'unknown'" "0 no_entity 0" "$(ingest --shadow-ai-inventory "$T/f4.json") $(adapter_reasons) $(out "sum(1 for a in r['assessments'] if a['entity']=='unknown')")"
cp "$T/a/inventory.json" "$T/f5.json"; edit "$T/f5.json" "d['$OID'].pop('signature_matched')"
reset
assert_eq "F5 no signature but a graph match: still converts via the graph" "0 attack_graph_finding_ids" "$(ingest --shadow-ai-inventory "$T/f5.json" --attack-graph "$T/a/graph.json") $(prov "print([p['entity_mapping'] for p in P if p['source_record_id']=='$OID'][0])")"

echo ""
echo "=== T-series: stale and future scan times ==="
gen "$T/old" "2026-10-24T00:30:00Z" "2026-10-24T01:30:00Z"
reset
assert_eq "T1 entries last seen 3 days ago rejected as stale" "0 0 outside_replay_window,outside_replay_window" "$(ingest --shadow-ai-inventory "$T/old/inventory.json") $(prov "print(len(P))") $(schema_reasons)"
gen "$T/mix" "2026-10-24T00:30:00Z" "2026-10-27T01:30:00Z"
reset
assert_eq "T2 never-removed old entry stale, re-seen entry accepted" "0 1 outside_replay_window" "$(ingest --shadow-ai-inventory "$T/mix/inventory.json") $(prov "print(len(P))") $(schema_reasons)"
gen "$T/fut" "2026-10-27T03:00:00Z" "2026-10-27T03:30:00Z"
reset
assert_eq "T3 scan time in the future rejected" "0 observed_in_future,observed_in_future" "$(ingest --shadow-ai-inventory "$T/fut/inventory.json") $(schema_reasons)"

echo ""
echo "=== D-series: duplicates and re-observation ==="
reset
ingest --shadow-ai-inventory "$T/a/inventory.json" > /dev/null
assert_eq "D1 same inventory again: duplicates, nothing new" "0 2 0" "$(ingest --shadow-ai-inventory "$T/a/inventory.json") $(out "r['counts']['duplicates']") $(out "r['counts']['accepted']")"
cp "$T/a/inventory.json" "$T/d2.json"; printf '\n' >> "$T/d2.json"
assert_eq "D2 unchanged entries in a newer copy of the file: duplicates" "0 2" "$(ingest --shadow-ai-inventory "$T/d2.json") $(out "r['counts']['duplicates']")"
cp "$T/a/inventory.json" "$T/d3.json"; edit "$T/d3.json" "d['$OID'].update(last_seen='2026-10-27T01:45:00Z', times_seen=3)"
assert_eq "D3 re-observed in a later scan: a new event" "0 1 1" "$(ingest --shadow-ai-inventory "$T/d3.json") $(out "r['counts']['accepted']") $(out "r['counts']['duplicates']")"
cp "$T/a/inventory.json" "$T/d4.json"; edit "$T/d4.json" "d['$LID']['last_risk']='CRITICAL'"
assert_eq "D4 same scan time, altered risk: conflict, not accepted" "0 1" "$(ingest --shadow-ai-inventory "$T/d4.json") $(out "r['counts']['conflicts']")"
reset
assert_eq "D5 inventory + findings JSONL together: separate ids, one entity, one source module" "0 0 1 shadow_ai_monitor" \
  "$(ingest --shadow-ai-inventory "$T/a/inventory.json" --shadow-ai "$T/a/scan2.jsonl" --attack-graph "$T/a/graph.json") $(out "r['counts']['conflicts']") $(out "sum(1 for a in r['assessments'] if a['entity']=='ollama')") $(python3 -c "
import json
L=[json.loads(l) for l in open('$WAD_STATE_DIR/ledger.jsonl') if l.strip()]
print(','.join(sorted(set(v['source_record_id'] and 'shadow_ai_monitor' for d in L if d['event_type']=='wad_events_accepted' for v in d['provenance'].values() if v['detector'] in ('shadow_ai','shadow_ai_inventory')))))")"

echo ""
echo "=== G-series: signatures ==="
umask_keys() { ( umask 077; for k in "$@"; do head -c 32 /dev/urandom > "$k"; done ); }   # test keys, 0600
mkdir -p "$T/keys"; umask_keys "$T/keys/shadow_ai.key" "$T/keys/attack_graph.key"
sign_doc() { python3 - "$1" "$2" "$3" <<'PY'
import hashlib, hmac, json, sys
p, kid, keyf = sys.argv[1:4]; key = open(keyf, "rb").read()
d = json.load(open(p)); d.pop("wad_sig", None)
d["signing"] = dict(scan_id=__import__("secrets").token_hex(16), seq=0, signed_at="2026-10-27T01:00:00Z")   # PR #219 signing block
mac = hmac.new(key, json.dumps(d, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(), hashlib.sha256).hexdigest()
d["wad_sig"] = dict(alg="hmac-sha256", key_id=kid, mac=mac); json.dump(d, open(p, "w"))
PY
}
cp "$T/a/inventory.json" "$T/g1.json"; sign_doc "$T/g1.json" shadow_ai "$T/keys/shadow_ai.key"
reset
assert_eq "G1 inventory signed with the shadow_ai key: verified" "0 verified" "$(WAD_PRODUCER_KEY_DIR="$T/keys" ingest --shadow-ai-inventory "$T/g1.json") $(prov "print(P[0]['signature_status'])")"
cp "$T/a/inventory.json" "$T/g2.json"; sign_doc "$T/g2.json" shadow_ai "$T/keys/attack_graph.key"
reset
assert_eq "G2 signed with another detector's key: whole source fails" "7 signature_invalid" "$(WAD_PRODUCER_KEY_DIR="$T/keys" ingest --shadow-ai-inventory "$T/g2.json") $(out "r['sources']['shadow_ai_inventory']['failure']")"
reset
assert_eq "G3 --require-signed rejects the unsigned inventory" "7 signature_required:unsigned" "$(ingest --shadow-ai-inventory "$T/a/inventory.json" --require-signed shadow_ai_inventory) $(out "r['sources']['shadow_ai_inventory']['failure']")"
reset
assert_eq "G4 signature present, no key: accepted, never called verified" "0 unverifiable_no_trusted_key" "$(ingest --shadow-ai-inventory "$T/g1.json") $(prov "print(P[0]['signature_status'])")"
cp "$T/a/graph.json" "$T/gg.json"; sign_doc "$T/gg.json" attack_graph "$T/keys/attack_graph.key"; edit "$T/gg.json" "d['nodes']['ollama']['finding_ids']=['SHADOWAI-forged']"
assert_eq "G5 tampered signed graph is not used for mapping" "graph_signature_invalid" "$(WAD_PRODUCER_KEY_DIR="$T/keys" python3 -c "
import json, sys, os; sys.path.insert(0, 'security/wad'); import wad_adapters as wa
r = wa.convert('shadow_ai_inventory', '$T/a/inventory.json', wa.load_keys(os.environ['WAD_PRODUCER_KEY_DIR']), graph_path='$T/gg.json')
print(r['events'][0]['_provenance']['entity_map_graph'])")"

echo ""
echo "=== S-series: honesty and safety ==="
reset
ingest --shadow-ai-inventory "$T/a/inventory.json" --attack-graph "$T/a/graph.json" > /dev/null
assert_eq "S1 no inventory event claims a detection time" "0" "$(prov "print(sum(1 for p in P if p['detection_time_known'] is not False))")"
assert_eq "S2 no inventory event is labelled verified without a key" "0" "$(prov "print(sum(1 for p in P if p['signature_status']=='verified'))")"
assert_eq "S3 decisions are dry run" "0" "$(python3 -c "
import json
print(sum(1 for l in open('$WAD_STATE_DIR/ledger.jsonl') if l.strip() and json.loads(l).get('event_type')=='wad_decision' and json.loads(l).get('mode')!='dry_run'))")"
for s in sudo ssh scp curl nc osascript; do
  assert_eq "S4 stub $s never called" "0" "$(waio_test_stub_calls "$s")"
done
assert_eq "S5 repo security/state not written by this suite" "no no" "$([ -e security/state/wad/ledger.jsonl ] && [ security/state/wad/ledger.jsonl -nt "$T/a/inventory.json" ] && echo yes || echo no) $([ security/state/shadow_ai/inventory.json -nt "$T/a/inventory.json" ] 2>/dev/null && echo yes || echo no)"
assert_eq "S6 ledger verifies" "0" "$(python3 security/wad/wad.py verify-ledger > /dev/null 2>&1; echo $?)"

echo ""
echo "=== Summary: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
  echo "Failures:"; for f in "${FAILURES[@]}"; do echo "  - $f"; done
  exit 1
fi
exit 0
