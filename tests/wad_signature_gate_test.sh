#!/bin/bash
set -uo pipefail

# tests/wad_signature_gate_test.sh -- default-deny signature gate for
# disruptive WAD steps (wad_adapters signing-block verification,
# wad_response.check_signature_gate, wad.py approve/execute).
#
#   V-series: valid detector signatures authorize (dry run only).
#   T-series: tampering and wrong keys are rejected.
#   M-series: missing / malformed signing fields -> unverified, denied.
#   F-series: stale and future signatures.
#   R-series: replay (sig id reuse) vs byte-identical duplicates.
#   E-series: verifier failure and untrusted keys.
#   D-series: default deny, diagnostics kept, gate at start too.
#   W-series: a WAD-made signature or claim never counts.
#   S-series: safety.
# Fixtures are real shadow_ai_lib findings signed the way PR #219's
# detector signs (signing block inside the mac) with per-run TEST keys.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR" || exit 1
# shellcheck source=tests/lib/test_isolation.sh
. tests/lib/test_isolation.sh
waio_test_isolate wad_signature_gate || exit 3
waio_test_assert_isolated || exit 3
trap 'chmod 700 "$T/keys" 2>/dev/null; waio_test_cleanup' EXIT

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

T="$WAIO_TEST_ROOT/wadsg"
mkdir -p "$T/keys"
( umask 077; head -c 32 /dev/urandom > "$T/keys/shadow_ai.key"; head -c 32 /dev/urandom > "$T/other.key" )
NOW="2026-10-27T02:00:00Z"
GOOD="contained after review of the shadow ai alert"
export WAD_STATE_DIR="$T/state"
export WAD_STOP_FILE="$T/STOP"
export WAD_PRODUCER_KEY_DIR="$T/keys"
unset WAD_LEDGER_HMAC_KEY_FILE WAD_APPROVAL_POLICY

# mk OUT KEYFILE [MUTATION] -- one real CRITICAL ollama finding, signed like PR #219.
# MUTATION: none|nosigning|badscan|boolseq|badts|stale|future|tamper|reuse:<file>|keyid
mk() {
  python3 - "$1" "$2" "${3:-none}" <<'PY'
import hashlib, hmac, json, secrets, sys
out, keyf, mut = sys.argv[1:4]
sys.path[:0] = ["security/shadow_ai"]
import shadow_ai_lib as sal
f = sal.build_finding("process", dict(pattern="ollama", risk="CRITICAL", category="local_llm_runtime", label="Ollama"),
                      "exact_comm", False, "2026-10-27T01:00:00Z", "ollama running", process=dict(comm="ollama", pid=7))
signing = dict(scan_id=secrets.token_hex(16), seq=0, signed_at="2026-10-27T01:00:00Z")
if mut.startswith("reuse:"):
    prev = json.loads(open(mut[6:]).readline()); signing = prev["signing"]; f["reason"] = "different content, same sig id"
if mut == "badscan": signing["scan_id"] = "zz"
if mut == "boolseq": signing["seq"] = True
if mut == "badts": signing["signed_at"] = "yesterday"
if mut == "stale": signing["signed_at"] = "2026-10-25T23:00:00Z"
if mut == "future": signing["signed_at"] = "2026-10-27T03:00:00Z"
if mut != "nosigning": f["signing"] = signing
key = open(keyf, "rb").read()
canon = json.dumps(f, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
f["wad_sig"] = dict(alg="hmac-sha256", key_id="attack_graph" if mut == "keyid" else "shadow_ai",
                    mac=hmac.new(key, canon, hashlib.sha256).hexdigest())
if mut == "tamper": f["risk"] = "LOW"
open(out, "w").write(json.dumps(f) + "\n")
PY
}
wad() { python3 security/wad/wad.py "$@" > "$T/out.json" 2> "$T/err.txt"; echo $?; }
out() { python3 -c "import json,sys; r=json.load(open('$T/out.json')); print($1)"; }
violations() { out "','.join(r.get('violations', []))"; }
reset() { rm -rf "$WAD_STATE_DIR"; mkdir -p "$WAD_STATE_DIR"; printf 'masa\n' > "$WAD_STATE_DIR/approvers"; }
ingest() { wad ingest --now "$NOW" --shadow-ai "$1"; }
sid() { wad response list > /dev/null; out "[s['step_id'] for s in r if s['entity']=='ollama' and s['action']=='$1'][0]"; }
state() { wad response list > /dev/null; out "[s['state'] for s in r if s['step_id']=='$1'][0]"; }
status_of() { out "list(r['signature_status'].values())[0] if r.get('signature_status') else 'none'"; }
approve() { wad response approve "$1" --operator masa --reason "$GOOD" --now "$NOW"; }
adapter_reason() { python3 -c "
import json
L=[json.loads(l) for l in open('$WAD_STATE_DIR/ledger.jsonl') if l.strip()]
print(','.join(r for d in L if d.get('stage')=='adapter' for r in d['reasons']) or 'none')"; }

echo "=== V-series: valid detector signature ==="
reset; mk "$T/ok.jsonl" "$T/keys/shadow_ai.key"
assert_eq "V1 signed with the detector's own key, fresh signing block: verified" "0 verified" "$(ingest "$T/ok.jsonl") $(status_of)"
R=$(sid restrict_egress)
assert_eq "V2 disruptive approval allowed on verified evidence" "0 approved" "$(approve "$R") $(state "$R")"
assert_eq "V3 disruptive start allowed, and still a dry run" "0 done DRY_RUN" "$(wad response execute "$R" --now "$NOW") $(state "$R") $(python3 -c "
import json; print([json.loads(l) for l in open('$WAD_STATE_DIR/ledger.jsonl') if l.strip() and json.loads(l).get('action')=='complete'][-1]['result']['result'])")"
assert_eq "V4 provenance carries sig_id and sig_mac" "True" "$(python3 -c "
import json
L=[json.loads(l) for l in open('$WAD_STATE_DIR/ledger.jsonl') if l.strip()]
p=[v for d in L if d['event_type']=='wad_events_accepted' for v in d['provenance'].values()][0]
print(bool(p['sig_id']) and len(p['sig_mac'])==64)")"

echo ""
echo "=== T-series: tampering and wrong keys ==="
reset; mk "$T/tamper.jsonl" "$T/keys/shadow_ai.key" tamper
assert_eq "T1 changed after signing: rejected, no decision" "0 signature_invalid 0" "$(ingest "$T/tamper.jsonl") $(adapter_reason) $(out "len(r['assessments'])")"
reset; mk "$T/wrongkey.jsonl" "$T/other.key"
assert_eq "T2 signed with an untrusted key: rejected" "0 signature_invalid" "$(ingest "$T/wrongkey.jsonl") $(adapter_reason)"
reset; mk "$T/keyid.jsonl" "$T/keys/shadow_ai.key" keyid
assert_eq "T3 right key, key_id naming another detector: rejected" "0 signature_invalid" "$(ingest "$T/keyid.jsonl") $(adapter_reason)"

echo ""
echo "=== M-series: missing or malformed signing fields ==="
for m in nosigning badscan boolseq badts; do
  reset; mk "$T/$m.jsonl" "$T/keys/shadow_ai.key" "$m"
  ingest "$T/$m.jsonl" > /dev/null; st=$(status_of); R=$(sid restrict_egress)
  assert_eq "M-$m: mac valid but signing block unusable -> unverified, disruptive approval denied" \
    "missing_signing_block 6 unverified_evidence:missing_signing_block=1" "$st $(approve "$R") $(violations)"
done

echo ""
echo "=== F-series: stale and future signatures ==="
reset; mk "$T/stale.jsonl" "$T/keys/shadow_ai.key" stale
ingest "$T/stale.jsonl" > /dev/null; st=$(status_of); R=$(sid restrict_egress)
assert_eq "F1 signed 27 h before ingest: stale_signature, denied" "stale_signature 6 unverified_evidence:stale_signature=1" "$st $(approve "$R") $(violations)"
reset; mk "$T/future.jsonl" "$T/keys/shadow_ai.key" future
ingest "$T/future.jsonl" > /dev/null; st=$(status_of); R=$(sid restrict_egress)
assert_eq "F2 signed an hour in the future: stale_signature, denied" "stale_signature 6" "$st $(approve "$R")"

echo ""
echo "=== R-series: replay vs duplicate ==="
reset; mk "$T/r1.jsonl" "$T/keys/shadow_ai.key"
ingest "$T/r1.jsonl" > /dev/null
assert_eq "R1 byte-identical resend: a duplicate, not an error" "0 1 none" "$(ingest "$T/r1.jsonl") $(out "r['counts']['duplicates']") $(adapter_reason)"
mk "$T/r2.jsonl" "$T/keys/shadow_ai.key" "reuse:$T/r1.jsonl"
assert_eq "R2 same scan_id:seq, different content (across runs): signature_id_reuse, rejected" "0 signature_id_reuse 0" "$(ingest "$T/r2.jsonl") $(adapter_reason) $(out "r['counts']['accepted']")"
reset; cat "$T/r1.jsonl" "$T/r2.jsonl" > "$T/r12.jsonl"
assert_eq "R3 reuse within one batch: second rejected" "0 1 signature_id_reuse" "$(ingest "$T/r12.jsonl") $(out "r['counts']['accepted']") $(adapter_reason)"

echo ""
echo "=== E-series: verifier failure and untrusted keys ==="
reset; mk "$T/e.jsonl" "$T/keys/shadow_ai.key"
chmod 000 "$T/keys"
ingest "$T/e.jsonl" > /dev/null; st=$(status_of); R=$(sid restrict_egress)
assert_eq "E1 key dir unreadable: unverifiable, denied (fail closed)" "unverifiable_no_trusted_key 6" "$st $(approve "$R")"
chmod 700 "$T/keys"
chmod 644 "$T/keys/shadow_ai.key"; reset
ingest "$T/e.jsonl" > /dev/null; st=$(status_of); R=$(sid restrict_egress)
assert_eq "E2 group/world-readable key not trusted: denied, reason reported" "unverifiable_no_trusted_key 6 accessible to group/others" "$st $(approve "$R") $(python3 -c "
import json
L=[json.loads(l) for l in open('$WAD_STATE_DIR/ledger.jsonl') if l.strip()]
print([d for d in L if d['event_type']=='wad_sources_ingested'][0]['sources']['shadow_ai']['key_problem'])")"
chmod 600 "$T/keys/shadow_ai.key"
assert_eq "E3 a verifier exception is reported as verifier_error, never verified" "verifier_error" "$(python3 -c "
import sys, json; sys.path.insert(0, 'security/wad'); import wad_adapters as wa
o = json.loads(open('$T/e.jsonl').readline())
print(wa.signature_status(o, 'shadow_ai', {'shadow_ai': object()})[0])")"

echo ""
echo "=== D-series: default deny, diagnostics kept ==="
reset
python3 -c "
import json; f=json.loads(open('$T/ok.jsonl').readline()); f.pop('wad_sig'); f.pop('signing')
open('$T/unsigned.jsonl','w').write(json.dumps(f)+'\n')"
ingest "$T/unsigned.jsonl" > /dev/null; lvl=$(out "r['assessments'][0]['threat_level']"); st=$(status_of)
R=$(sid restrict_egress); M=$(sid monitor_increase); W=$(sid warn_operator)
assert_eq "D1 unsigned evidence is still assessed (diagnostics)" "L4 unsigned" "$lvl $st"
assert_eq "D2 no policy file: disruptive approval denied by default" "6 unverified_evidence:unsigned=1 awaiting_approval" "$(approve "$R") $(violations) $(state "$R")"
assert_eq "D3 non-disruptive steps still run on unsigned evidence" "0 0 done done" "$(wad response execute "$M" --now "$NOW") $(wad response execute "$W" --now "$NOW") $(state "$M") $(state "$W")"
printf '{"version":1,"signature_gate":"unenforced"}' > "$WAD_STATE_DIR/approval_policy.json"
assert_eq "D4 explicit unenforced policy: approval allowed and recorded as such" "0 unenforced" "$(approve "$R") $(python3 -c "
import json
a=[json.loads(l) for l in open('$WAD_STATE_DIR/ledger.jsonl') if l.strip() and json.loads(l).get('action')=='approve' and json.loads(l).get('event_type')=='wad_step_transition'][-1]
print(a['signature_gate'])")"
rm "$WAD_STATE_DIR/approval_policy.json"
assert_eq "D5 gate also enforced at start: approved-but-unverified step cannot start" "6 unverified_evidence:unsigned=1 approved" "$(wad response execute "$R" --now "$NOW") $(violations) $(state "$R")"
printf '{"version":1,"signature_gate":"unenforced","bogus":1}' > "$WAD_STATE_DIR/approval_policy.json"
assert_eq "D6 invalid policy cannot relax the gate (start still denied)" "6 unverified_evidence:unsigned=1" "$(wad response execute "$R" --now "$NOW") $(violations)"
printf '{"version":1,"signature_gate":"off"}' > "$WAD_STATE_DIR/approval_policy.json"
assert_eq "D7 unknown gate mode is invalid, not 'off'" "6" "$(wad response execute "$R" --now "$NOW")"
rm "$WAD_STATE_DIR/approval_policy.json"

echo ""
echo "=== W-series: no WAD-made signature or claim counts ==="
reset
python3 -c "
import json
e=dict(event_id='w1', source_module='shadow_ai_monitor', entity='ollama', entity_type='process', risk='CRITICAL', confidence='HIGH',
       observed_at='2026-10-27T01:00:00Z', _provenance=dict(signature_status='verified'), provenance=dict(signature_status='verified'))
open('$T/claim.jsonl','w').write(json.dumps(e)+'\n')"
wad evaluate --events "$T/claim.jsonl" --now "$NOW" > /dev/null; R=$(sid restrict_egress)
assert_eq "W1 an events file claiming 'verified' is not verified: denied" "6 unverified_evidence:no_provenance_direct_events_file=1" "$(approve "$R") $(violations)"
reset; cp "$T/keys/shadow_ai.key" "$T/ledger.key"; chmod 600 "$T/ledger.key"
ingest_w() { WAD_LEDGER_HMAC_KEY_FILE="$T/ledger.key" python3 security/wad/wad.py ingest --now "$NOW" --shadow-ai "$1" > "$T/out.json" 2> "$T/err.txt"; echo $?; }
assert_eq "W2 a detector key identical to WAD's own ledger key is refused" "0 unverifiable_no_trusted_key" "$(ingest_w "$T/ok.jsonl") $(status_of)"
assert_eq "W2 refusal reason recorded" "identical to WAD's own ledger key" "$(WAD_LEDGER_HMAC_KEY_FILE="$T/ledger.key" python3 -c "
import sys; sys.path.insert(0, 'security/wad'); import wad_adapters as wa
print(wa.load_keys_checked('$T/keys')[1]['shadow_ai'])")"
assert_eq "W3 adapters never create a wad_sig" "0" "$(grep -vE '^\s*#' security/wad/wad_adapters.py | grep -cE '\[SIG_FIELD\] *=|\"wad_sig\" *:' || true)"

echo ""
echo "=== S-series ==="
for s in sudo ssh scp curl nc osascript; do
  assert_eq "S1 stub $s never called" "0" "$(waio_test_stub_calls "$s")"
done
assert_eq "S2 test key bytes never in ledger/output" "0" "$(python3 -c "
k=open('$T/keys/shadow_ai.key','rb').read()
print(sum(1 for p in ('$WAD_STATE_DIR/ledger.jsonl','$T/out.json','$T/err.txt') if k in open(p,'rb').read() or k.hex().encode() in open(p,'rb').read()))")"
assert_eq "S3 no record claims authentication" "0" "$(grep -c '\"authenticated\": true' "$WAD_STATE_DIR/ledger.jsonl" || true)"

echo ""
echo "=== Summary: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
  echo "Failures:"; for f in "${FAILURES[@]}"; do echo "  - $f"; done
  exit 1
fi
exit 0
