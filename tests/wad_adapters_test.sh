#!/bin/bash
set -uo pipefail

# tests/wad_adapters_test.sh -- WAD PR 3: detector adapters
# (security/wad/wad_adapters.py + `wad.py ingest`).
#
# Fixtures are produced by the detectors' own libraries (shadow_ai_lib
# build_finding, attack_graph_lib + attack_graph.sh's document wrapper,
# saas_ato_lib's monitor sequence), so these are contract tests against
# what the detectors really emit.
#
#   C-series: contract and provenance (intelligence_lib reused).
#   M-series: malformed records and documents.
#   R-series: replayed and altered events; files cannot claim provenance.
#   G-series: signatures (verified / invalid / missing / untrusted / required).
#   T-series: stale, future and missing timestamps.
#   F-series: detector failures; probe detector blocked (#182).
#   S-series: nothing executes; nothing is labelled signed without a key.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR" || exit 1
# shellcheck source=tests/lib/test_isolation.sh
. tests/lib/test_isolation.sh
waio_test_isolate wad_adapters || exit 3
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

T="$WAIO_TEST_ROOT/wada"
mkdir -p "$T"
NOW="2026-10-27T02:00:00Z"
export WAD_STATE_DIR="$T/state"
export WAD_STOP_FILE="$T/STOP"
unset WAD_LEDGER_HMAC_KEY_FILE WAD_PRODUCER_KEY_DIR

# gen DIR [DETECTED_AT] -- real-detector fixtures: shadow.jsonl graph.json saas.jsonl
gen() {
  python3 - "$1" "${2:-2026-10-27T01:00:00Z}" <<'PY'
import json, os, sys
D, TS = sys.argv[1], sys.argv[2]
os.makedirs(D, exist_ok=True)
sys.path[:0] = ["security/shadow_ai", "security/attack_graph", "security/saas_ato"]
import shadow_ai_lib as sal, attack_graph_lib as agl, saas_ato_lib as sato
sig = dict(pattern="ollama", risk="HIGH", category="local_llm_runtime", label="Ollama")
f1 = sal.build_finding("process", sig, "exact_comm", False, TS, "ollama runtime running", process=dict(comm="ollama", pid=4242))
open(os.path.join(D, "shadow.jsonl"), "w").write(json.dumps(f1) + "\n")
fs = agl.parse_findings([json.dumps(f1) + "\n"])
g = agl.build_graph(fs)
doc = dict(generated_at=TS, findings_processed=len(fs), nodes=g["nodes"], edges=g["edges"], analysis=agl.graph_summary(g))
json.dump(doc, open(os.path.join(D, "graph.json"), "w"))
s = dict(id="s1", source="okta", tenant="t1", account="alice@example.com", signal_type="impossible_travel", detected_at=TS)
risk, conf, basis = sato.classify_signal(s)
classified = [dict(s, risk=risk, confidence=conf, basis=basis)]
corr, _ = sato.compute_correlation(None, TS, set(x["signal_type"] for x in classified))
open(os.path.join(D, "saas.jsonl"), "w").write(json.dumps(sato.build_event("alice@example.com", "t1", TS, classified, corr)) + "\n")
PY
}
# sign FILE DETECTOR KEYFILE [jsonl|doc] -- what a future detector would do
sign() {
  python3 - "$@" <<'PY'
import hashlib, hmac, json, sys
p, det, keyf = sys.argv[1:4]; mode = sys.argv[4] if len(sys.argv) > 4 else "jsonl"
key = open(keyf, "rb").read()
canon = lambda o: json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
SCAN = __import__("secrets").token_hex(16); SEQ = [0]
def s(o):
    o = dict(o); o.pop("wad_sig", None)
    o["signing"] = dict(scan_id=SCAN, seq=SEQ[0], signed_at="2026-10-27T01:00:00Z"); SEQ[0] += 1   # PR #219 signing block
    o["wad_sig"] = dict(alg="hmac-sha256", key_id=det, mac=hmac.new(key, canon(o).encode(), hashlib.sha256).hexdigest())
    return o
if mode == "doc":
    json.dump(s(json.load(open(p))), open(p, "w"))
else:
    lines = [json.dumps(s(json.loads(l))) for l in open(p) if l.strip()]
    open(p, "w").write("\n".join(lines) + "\n")
PY
}
ingest() { python3 security/wad/wad.py ingest --now "$NOW" "$@" > "$T/out.json" 2> "$T/err.txt"; echo $?; }
out() { python3 -c "import json,sys; r=json.load(open('$T/out.json')); print($1)"; }
ledger_py() { python3 -c "
import json
L=[json.loads(l) for l in open('$WAD_STATE_DIR/ledger.jsonl') if l.strip()]
$1"; }   # $1: python statements over L (they print their own result)
reset() { rm -rf "$WAD_STATE_DIR"; mkdir -p "$WAD_STATE_DIR"; }

echo "=== C-series: contract and provenance ==="
reset; gen "$T/a"
assert_eq "C1 three real detector outputs ingested" "0 3 0" "$(ingest --shadow-ai "$T/a/shadow.jsonl" --attack-graph "$T/a/graph.json" --saas-ato "$T/a/saas.jsonl") $(out "r['counts']['accepted']") $(out "r['counts']['rejected']+r['counts']['adapter_rejected']")"
assert_eq "C2 shadow_ai: entity = process comm, risk/confidence carried, time from the finding" \
  "ollama process HIGH MEDIUM 2026-10-27T01:00:00Z detector_record" "$(python3 -c "
import json, sys; sys.path.insert(0, 'security/wad'); import wad_adapters as wa
e = wa.convert('shadow_ai', '$T/a/shadow.jsonl', {})['events'][0]
src = json.loads(open('$T/a/shadow.jsonl').read())
assert (e['risk'], e['confidence'], e['observed_at']) == (src['risk'], src['confidence'], src['detected_at'])
print(e['entity'], e['entity_type'], e['risk'], e['confidence'], e['observed_at'], e['_provenance']['timestamp_source'])")"
assert_eq "C3 attack_graph node uses the document's generated_at, said so" "detector_document_generated_at" \
  "$(ledger_py "[print(v['timestamp_source']) for d in L if d['event_type']=='wad_events_accepted' for v in d['provenance'].values() if v['detector']=='attack_graph']" | head -1)"
assert_eq "C4 node confidence comes from intelligence_lib unchanged" "$(python3 -c "
import json,sys; sys.path.insert(0,'security/intelligence'); import intelligence_lib as il
d=json.load(open('$T/a/graph.json')); print(il.from_attack_graph_node('ollama', d['nodes']['ollama'])['confidence'])")" \
  "$(python3 -c "
import json,sys; sys.path.insert(0,'security/wad'); import wad_adapters as wa
print(wa.convert('attack_graph','$T/a/graph.json',{})['events'][0]['confidence'])")"
assert_eq "C5 saas_ato: account entity" "alice@example.com saas_account" "$(out "' '.join([a['entity'] for a in r['assessments'] if '@' in a['entity']] + ['saas_account'])")"
assert_eq "C6 provenance: adapter version, source file sha256, index" "wad-adapters/1 True 0" "$(ledger_py "
import hashlib
p=[v for d in L if d['event_type']=='wad_events_accepted' for v in d['provenance'].values() if v['detector']=='saas_ato'][0]
print(p['adapter'], p['source_file_sha256']==hashlib.sha256(open('$T/a/saas.jsonl','rb').read()).hexdigest(), p['source_index'])")"
assert_eq "C7 every event unsigned, and the report says so" "unsigned" "$(out "','.join(sorted(set(r['signature_status'].values())))")"
assert_eq "C8 sources summary recorded in the ledger" "1 attack_graph,saas_ato,shadow_ai" "$(ledger_py "s=[d for d in L if d['event_type']=='wad_sources_ingested']; print(len(s), ','.join(sorted(s[0]['sources'])))")"

echo ""
echo "=== M-series: malformed input ==="
reset
python3 - "$T/a/shadow.jsonl" "$T/m.jsonl" <<'PY'
import json, sys
good = json.loads(open(sys.argv[1]).read())
bad_risk = dict(good, id="SHADOWAI-badrisk", risk="EXTREME")
naive = dict(good, id="SHADOWAI-naive", detected_at="2026-10-27T01:00:00")
ctrl = dict(good, id="SHADOWAI-ctrl", process=dict(comm="ev\u0007il", pid=1))
norisk = dict(good, id="SHADOWAI-norisk"); norisk.pop("risk")
lines = ["this is not json", json.dumps([1, 2]), json.dumps(bad_risk), json.dumps(naive), json.dumps(ctrl), json.dumps(norisk)]
open(sys.argv[2], "w").write("\n".join(lines) + "\n")
PY
assert_eq "M1 one file, six bad or incomplete records: nothing crashes" "0" "$(ingest --shadow-ai "$T/m.jsonl")"
assert_eq "M2 adapter rejections: unparseable, not_an_object" "not_an_object,unparseable" "$(ledger_py "print(','.join(sorted(d['reasons'][0] for d in L if d['event_type']=='wad_event_rejected' and d.get('stage')=='adapter')))")"
assert_eq "M3 schema rejections from wad_lib: bad_entity, bad_observed_at, bad_risk" "bad_entity,bad_observed_at,bad_risk" "$(ledger_py "print(','.join(sorted(d['reasons'][0] for d in L if d['event_type']=='wad_event_rejected' and 'stage' not in d)))")"
assert_eq "M4 a missing risk stays missing (not intelligence_lib's LOW default)" "1 UNDETERMINED" "$(out "r['counts']['accepted']") $(out "r['assessments'][0]['threat_level']")"
printf 'not json' > "$T/bad.json"
assert_eq "M5 attack_graph document that is not JSON = source failure" "7 not_json" "$(ingest --attack-graph "$T/bad.json") $(out "r['sources']['attack_graph']['failure']")"
printf '{"generated_at":"%s","edges":[]}' "$NOW" > "$T/nonodes.json"
assert_eq "M6 attack_graph document without nodes = bad_document_shape" "7 bad_document_shape" "$(ingest --attack-graph "$T/nonodes.json") $(out "r['sources']['attack_graph']['failure']")"
printf '{"generated_at":"2026-10-27T01:00:00Z","nodes":{},"analysis":{"attack_paths":[{"path":"a->b","path_risk":"HIGH"}]}}' > "$T/badpath.json"
assert_eq "M7 attack path that is not a list rejected" "0 bad_path" "$(ingest --attack-graph "$T/badpath.json") $(ledger_py "print([d['reasons'][0] for d in L if d.get('stage')=='adapter'][-1])")"

echo ""
echo "=== R-series: replay ==="
reset
ingest --shadow-ai "$T/a/shadow.jsonl" --saas-ato "$T/a/saas.jsonl" > /dev/null
n=$(ledger_py "print(sum(1 for d in L if d['event_type']=='wad_decision'))")
assert_eq "R1 the same files again: duplicates, no new decision" "0 2 0 $n" "$(ingest --shadow-ai "$T/a/shadow.jsonl" --saas-ato "$T/a/saas.jsonl") $(out "r['counts']['duplicates']") $(out "r['counts']['accepted']") $(ledger_py "print(sum(1 for d in L if d['event_type']=='wad_decision'))")"
cp "$T/a/shadow.jsonl" "$T/copy.jsonl"; printf '\n' >> "$T/copy.jsonl"
assert_eq "R2 same finding in a different scan file is still a duplicate" "0 1" "$(ingest --shadow-ai "$T/copy.jsonl") $(out "r['counts']['duplicates']")"
python3 -c "
import json; f=json.loads(open('$T/a/shadow.jsonl').read()); f['risk']='LOW'
open('$T/altered.jsonl','w').write(json.dumps(f)+'\n')"
assert_eq "R3 same finding id and time, altered content = conflict, not accepted" "0 1 0" "$(ingest --shadow-ai "$T/altered.jsonl") $(out "r['counts']['conflicts']") $(out "r['counts']['accepted']")"
reset
python3 -c "
import json
e=dict(event_id='claim1', source_module='shadow_ai_monitor', entity='w', entity_type='process', risk='HIGH', confidence='HIGH', observed_at='2026-10-27T01:00:00Z',
       _provenance=dict(signature_status='verified'), provenance=dict(signature_status='verified'))
open('$T/claim.jsonl','w').write(json.dumps(e)+'\n')"
python3 security/wad/wad.py evaluate --events "$T/claim.jsonl" --now "$NOW" > /dev/null
assert_eq "R4 an --events file cannot claim provenance or a signature" "1 0" "$(ledger_py "a=[d for d in L if d['event_type']=='wad_events_accepted']; print(len(a), sum(1 for d in a if 'provenance' in d))")"

echo ""
echo "=== G-series: signatures ==="
umask_keys() { ( umask 077; for k in "$@"; do head -c 32 /dev/urandom > "$k"; done ); }   # test keys, 0600
mkdir -p "$T/keys"; umask_keys "$T/keys/shadow_ai.key" "$T/keys/attack_graph.key" "$T/keys/saas_ato.key"
gen "$T/g"
cp "$T/g/shadow.jsonl" "$T/g/s_ok.jsonl"; sign "$T/g/s_ok.jsonl" shadow_ai "$T/keys/shadow_ai.key"
reset
assert_eq "G1 detector-signed record verified with its own key" "0 verified" "$(WAD_PRODUCER_KEY_DIR="$T/keys" ingest --shadow-ai "$T/g/s_ok.jsonl") $(out "list(r['signature_status'].values())[0]")"
python3 -c "
import json; f=json.loads(open('$T/g/s_ok.jsonl').read()); f['risk']='CRITICAL'
open('$T/g/s_tamper.jsonl','w').write(json.dumps(f)+'\n')"
reset
assert_eq "G2 record changed after signing: rejected, not accepted" "0 0 signature_invalid" "$(WAD_PRODUCER_KEY_DIR="$T/keys" ingest --shadow-ai "$T/g/s_tamper.jsonl") $(out "r['counts']['accepted']") $(ledger_py "print([d['reasons'][0] for d in L if d.get('stage')=='adapter'][0])")"
cp "$T/g/shadow.jsonl" "$T/g/s_wrongkey.jsonl"; sign "$T/g/s_wrongkey.jsonl" shadow_ai "$T/keys/saas_ato.key"
reset
assert_eq "G3 signed with another detector's key: invalid" "0 0" "$(WAD_PRODUCER_KEY_DIR="$T/keys" ingest --shadow-ai "$T/g/s_wrongkey.jsonl") $(out "r['counts']['accepted']")"
cp "$T/g/shadow.jsonl" "$T/g/s_wrongid.jsonl"; sign "$T/g/s_wrongid.jsonl" saas_ato "$T/keys/saas_ato.key"
reset
assert_eq "G4 key_id naming another detector: invalid even with a valid mac for it" "0 0" "$(WAD_PRODUCER_KEY_DIR="$T/keys" ingest --shadow-ai "$T/g/s_wrongid.jsonl") $(out "r['counts']['accepted']")"
cp "$T/g/shadow.jsonl" "$T/g/s_mislabel.jsonl"; sign "$T/g/s_mislabel.jsonl" saas_ato "$T/keys/shadow_ai.key"
reset
assert_eq "G4b right key but key_id naming another detector: invalid, not verified" "0 0 signature_invalid" "$(WAD_PRODUCER_KEY_DIR="$T/keys" ingest --shadow-ai "$T/g/s_mislabel.jsonl") $(out "r['counts']['accepted']") $(ledger_py "print([d['reasons'][0] for d in L if d.get('stage')=='adapter'][0])")"
python3 -c "
import json; f=json.loads(open('$T/g/s_ok.jsonl').read()); f['wad_sig']['alg']='none'
open('$T/g/s_alg.jsonl','w').write(json.dumps(f)+'\n')"
reset
assert_eq "G5 malformed envelope (alg none): invalid" "0 0" "$(WAD_PRODUCER_KEY_DIR="$T/keys" ingest --shadow-ai "$T/g/s_alg.jsonl") $(out "r['counts']['accepted']")"
reset
assert_eq "G6 signature present but no trusted key: accepted, never called verified" "0 unverifiable_no_trusted_key" "$(ingest --shadow-ai "$T/g/s_ok.jsonl") $(out "list(r['signature_status'].values())[0]")"
mkdir -p "$T/keys2"; ln -s "$T/keys/shadow_ai.key" "$T/keys2/shadow_ai.key"; printf 'short' > "$T/keys2/saas_ato.key"
reset
assert_eq "G7 symlinked or short key is not trusted" "unverifiable_no_trusted_key False False" "$(WAD_PRODUCER_KEY_DIR="$T/keys2" ingest --shadow-ai "$T/g/s_ok.jsonl" > /dev/null; out "list(r['signature_status'].values())[0]") $(out "r['sources']['shadow_ai']['trusted_key_present']") $(python3 -c "
import sys; sys.path.insert(0,'security/wad'); import wad_adapters as wa; print('saas_ato' in wa.load_keys('$T/keys2'))")"
reset
assert_eq "G8 --require-signed rejects a missing signature" "0 0 signature_required:unsigned" "$(ingest --shadow-ai "$T/g/shadow.jsonl" --require-signed shadow_ai) $(out "r['counts']['accepted']") $(ledger_py "print([d['reasons'][0] for d in L if d.get('stage')=='adapter'][0])")"
reset
assert_eq "G9 --require-signed rejects an unverifiable signature" "0 signature_required:unverifiable_no_trusted_key" "$(out "r['counts']['accepted']" > /dev/null; ingest --shadow-ai "$T/g/s_ok.jsonl" --require-signed shadow_ai > /dev/null; out "r['counts']['accepted']") $(ledger_py "print([d['reasons'][0] for d in L if d.get('stage')=='adapter'][0])")"
reset
assert_eq "G10 --require-signed accepts a verified record" "0 1" "$(WAD_PRODUCER_KEY_DIR="$T/keys" ingest --shadow-ai "$T/g/s_ok.jsonl" --require-signed shadow_ai) $(out "r['counts']['accepted']")"
cp "$T/g/graph.json" "$T/g/g_noinput.json"; sign "$T/g/g_noinput.json" attack_graph "$T/keys/attack_graph.key" doc
python3 -c "
import json; d=json.load(open('$T/g/graph.json')); d['input_integrity']=dict(verified=1, unverified=0, dropped_invalid=0, mode='verified_only', input_key_used=True)
json.dump(d, open('$T/g/g_ok.json','w'))"
sign "$T/g/g_ok.json" attack_graph "$T/keys/attack_graph.key" doc
reset
assert_eq "G11 whole attack_graph document (verified-only input) signed and verified" "0 verified" "$(WAD_PRODUCER_KEY_DIR="$T/keys" ingest --attack-graph "$T/g/g_ok.json") $(out "list(r['signature_status'].values())[0]")"
reset
assert_eq "G11b signed graph without input_integrity is not 'verified' (could launder unsigned input)" "0 verified_unverified_input" "$(WAD_PRODUCER_KEY_DIR="$T/keys" ingest --attack-graph "$T/g/g_noinput.json") $(out "list(r['signature_status'].values())[0]")"
python3 -c "
import json; d=json.load(open('$T/g/g_ok.json')); d['generated_at']='2026-10-27T01:30:00Z'; json.dump(d, open('$T/g/g_tamper.json','w'))"
reset
assert_eq "G12 tampered signed document: whole source fails" "7 signature_invalid 0" "$(WAD_PRODUCER_KEY_DIR="$T/keys" ingest --attack-graph "$T/g/g_tamper.json") $(out "r['sources']['attack_graph']['failure']") $(out "r['counts']['accepted']")"
assert_eq "G13 unknown detector in --require-signed refused" "1" "$(ingest --shadow-ai "$T/g/shadow.jsonl" --require-signed bogus)"

echo ""
echo "=== T-series: timestamps ==="
reset; gen "$T/old" "2026-10-25T01:00:00Z"
assert_eq "T1 stale (older than the 24 h replay window) rejected" "0 0 outside_replay_window" "$(ingest --shadow-ai "$T/old/shadow.jsonl") $(out "r['counts']['accepted']") $(out "r['rejected'][0]['reasons'][0]")"
reset; gen "$T/fut" "2026-10-27T03:00:00Z"
assert_eq "T2 an hour in the future rejected" "0 observed_in_future" "$(ingest --shadow-ai "$T/fut/shadow.jsonl") $(out "r['rejected'][0]['reasons'][0]")"
reset
python3 -c "
import json; f=json.loads(open('$T/a/shadow.jsonl').read()); f.pop('detected_at')
open('$T/notime.jsonl','w').write(json.dumps(f)+'\n')"
assert_eq "T3 no detector time: accepted as insufficient, timestamp_source absent" "0 observed_at absent" "$(ingest --shadow-ai "$T/notime.jsonl") $(ledger_py "
import sys
print('observed_at', [v['timestamp_source'] for d in L if d['event_type']=='wad_events_accepted' for v in d['provenance'].values()][0])")"
reset
python3 -c "
import json; d=json.load(open('$T/a/graph.json')); d.pop('generated_at'); json.dump(d, open('$T/nogen.json','w'))"
assert_eq "T4 attack_graph without generated_at: timestamp_source absent, never disruptive" "0 absent UNDETERMINED" "$(ingest --attack-graph "$T/nogen.json") $(ledger_py "print([v['timestamp_source'] for d in L if d['event_type']=='wad_events_accepted' for v in d['provenance'].values()][0])") $(out "r['assessments'][0]['threat_level']")"

echo ""
echo "=== F-series: detector failures ==="
reset
assert_eq "F1 missing file: recorded failure, exit 7, other sources still processed" "7 1 1" "$(ingest --shadow-ai "$T/nope.jsonl" --saas-ato "$T/a/saas.jsonl") $(ledger_py "print(sum(1 for d in L if d['event_type']=='wad_source_failed'))") $(out "r['counts']['accepted']")"
ln -s "$T/a/shadow.jsonl" "$T/link.jsonl"
assert_eq "F2 symlinked detector file refused" "7 unreadable_or_symlink" "$(ingest --shadow-ai "$T/link.jsonl") $(out "r['sources']['shadow_ai']['failure'].split(':')[0]")"
dd if=/dev/zero of="$T/big.jsonl" bs=1048576 count=17 2> /dev/null
assert_eq "F3 oversized file refused" "7 too_large" "$(ingest --shadow-ai "$T/big.jsonl") $(out "r['sources']['shadow_ai']['failure']")"
printf '\xff\xfe{}\n' > "$T/latin.jsonl"
assert_eq "F4 non-UTF-8 file refused" "7 not_utf8" "$(ingest --shadow-ai "$T/latin.jsonl") $(out "r['sources']['shadow_ai']['failure']")"
n=$(grep -c . "$WAD_STATE_DIR/ledger.jsonl")
assert_eq "F5 probe detector blocked until #182, nothing written" "1 $n" "$(ingest --probe-detector "$T/a/shadow.jsonl") $(grep -c . "$WAD_STATE_DIR/ledger.jsonl")"
grep -q '#182' "$T/err.txt" && pr=yes || pr=no
assert_eq "F5 says why (#182)" "yes" "$pr"
assert_eq "F6 no source given" "1" "$(ingest)"
assert_eq "F7 ledger still verifies after every failure" "0" "$(python3 security/wad/wad.py verify-ledger > /dev/null 2>&1; echo $?)"

echo ""
echo "=== S-series ==="
code_only() { grep -vE '^\s*#' "$@" | python3 -c "
import sys,re
print(re.sub(r'\"\"\"[\s\S]*?\"\"\"', '', sys.stdin.read()))"; }
assert_eq "S1 adapters never execute or reach the network" "0" "$(code_only security/wad/wad_adapters.py | grep -cE 'subprocess|os\.system|os\.exec|os\.spawn|popen|socket|urllib|http\.client' || true)"
assert_eq "S2 adapters never create a signature (no wad_sig written)" "0" "$(code_only security/wad/wad_adapters.py | grep -cE '\[SIG_FIELD\] *=|\"wad_sig\" *:' || true)"
assert_eq "S3 one hmac.new in adapters, used only for verification" "1" "$(code_only security/wad/wad_adapters.py | grep -c 'hmac.new' || true)"
for s in sudo ssh scp curl nc osascript; do
  assert_eq "S4 stub $s never called" "0" "$(waio_test_stub_calls "$s")"
done
assert_eq "S5 decisions are dry run" "0" "$(ledger_py "print(sum(1 for d in L if d['event_type']=='wad_decision' and d.get('mode')!='dry_run'))")"
assert_eq "S6 repo security/state/wad not written by this suite" "no" "$([ -e security/state/wad/ledger.jsonl ] && [ security/state/wad/ledger.jsonl -nt "$T/a/shadow.jsonl" ] && echo yes || echo no)"

echo ""
echo "=== Summary: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
  echo "Failures:"; for f in "${FAILURES[@]}"; do echo "  - $f"; done
  exit 1
fi
exit 0
