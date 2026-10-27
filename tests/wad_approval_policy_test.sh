#!/bin/bash
set -uo pipefail

# tests/wad_approval_policy_test.sh -- optional evidence policy for
# disruptive approvals (wad_response.parse_approval_policy /
# check_evidence_policy, wad.py load_approval_policy). OFF by default.
#
#   D-series: default off -- no file, behaviour unchanged.
#   O-series: explicit opt-in -- all_verified, min_independent_sources.
#   I-series: invalid configuration fails closed (every approval refused).
#   U-series: unauthorized approval attempts are still refused; the policy
#             never stands in for identity and nothing claims authentication.
# The signing key here is a per-run TEST key under the temp root.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR" || exit 1
# shellcheck source=tests/lib/test_isolation.sh
. tests/lib/test_isolation.sh
waio_test_isolate wad_approval_policy || exit 3
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

T="$WAIO_TEST_ROOT/wadap"
mkdir -p "$T/keys"
NOW="2026-10-27T02:00:00Z"
TS="2026-10-27T01:00:00Z"
GOOD="contained after review of the shadow ai alert"
export WAD_STATE_DIR="$T/state"
export WAD_STOP_FILE="$T/STOP"
unset WAD_LEDGER_HMAC_KEY_FILE WAD_APPROVAL_POLICY
( umask 077; head -c 32 /dev/urandom > "$T/keys/shadow_ai.key" )
# signatures are verified at ingest: trust the per-run TEST key for every run
export WAD_PRODUCER_KEY_DIR="$T/keys"

python3 - "$T" "$TS" <<'PY'
import hashlib, hmac, json, os, sys
D, ts = sys.argv[1:3]
sys.path[:0] = ["security/shadow_ai", "security/attack_graph"]
import shadow_ai_lib as sal, attack_graph_lib as agl
f = sal.build_finding("process", dict(pattern="ollama", risk="CRITICAL", category="local_llm_runtime", label="Ollama"),
                      "exact_comm", False, ts, "ollama running", process=dict(comm="ollama", pid=7))
open(os.path.join(D, "shadow.jsonl"), "w").write(json.dumps(f) + "\n")
fs = agl.parse_findings([json.dumps(f) + "\n"]); g = agl.build_graph(fs)
json.dump(dict(generated_at=ts, findings_processed=1, nodes=g["nodes"], edges=g["edges"], analysis=agl.graph_summary(g)),
          open(os.path.join(D, "graph.json"), "w"))
key = open(os.path.join(D, "keys", "shadow_ai.key"), "rb").read()
f = dict(f, signing=dict(scan_id=__import__("secrets").token_hex(16), seq=0, signed_at="2026-10-27T01:00:00Z"))   # PR #219 signing block
s = dict(f); s["wad_sig"] = dict(alg="hmac-sha256", key_id="shadow_ai",
         mac=hmac.new(key, json.dumps(f, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(), hashlib.sha256).hexdigest())
open(os.path.join(D, "signed.jsonl"), "w").write(json.dumps(s) + "\n")
ev = lambda i, m, et: dict(event_id="d%d" % i, source_module=m, entity="ollama", entity_type=et, risk="CRITICAL", confidence="HIGH", observed_at=ts)
open(os.path.join(D, "two_sources.jsonl"), "w").write(json.dumps(ev(1, "shadow_ai_monitor", "process")) + "\n" + json.dumps(ev(2, "saas_ato", "process")) + "\n")
PY

wad() { python3 security/wad/wad.py "$@" > "$T/out.json" 2> "$T/err.txt"; echo $?; }
out() { python3 -c "import json,sys; r=json.load(open('$T/out.json')); print($1)"; }
violations() { out "','.join(r.get('violations', []))"; }
setup() {   # setup INGEST-ARGS...: fresh state, approver list, one L4 decision; sets SID (restrict_egress)
  rm -rf "$WAD_STATE_DIR"; mkdir -p "$WAD_STATE_DIR"; printf 'masa\nclaude\n' > "$WAD_STATE_DIR/approvers"
  if [ "$1" = evaluate ]; then shift; wad evaluate --now "$NOW" "$@" > /dev/null; else wad ingest --now "$NOW" "$@" > /dev/null; fi
  wad response list > /dev/null
  SID=$(out "[s['step_id'] for s in r if s['entity']=='ollama' and s['action']=='restrict_egress'][0]")
}
state() { wad response list > /dev/null; out "[s['state'] for s in r if s['step_id']=='$SID'][0]"; }
policy() { printf '%s' "$1" > "$WAD_STATE_DIR/approval_policy.json"; }
approve() { wad response approve "$SID" --operator "${1:-masa}" --reason "$GOOD" --now "$NOW"; }
last_approval() { python3 -c "
import json
L=[json.loads(l) for l in open('$WAD_STATE_DIR/ledger.jsonl') if l.strip()]
a=[x for x in L if x.get('event_type')=='wad_step_transition' and x.get('action')=='approve'][-1]
print($1)"; }

echo "=== D-series: no policy file ==="
setup --shadow-ai "$T/shadow.jsonl" --attack-graph "$T/graph.json"
assert_eq "D1 no policy file: unsigned evidence REFUSED by the default signature gate" "6 unverified_evidence:unsigned=2 awaiting_approval" "$(approve) $(violations) $(state)"
setup --shadow-ai "$T/signed.jsonl"
assert_eq "D1b no policy file: all-verified evidence is approvable" "0 approved" "$(approve) $(state)"
assert_eq "D2 the approval records no optional policy and an enforced gate" "off enforce" "$(last_approval "a['approval_policy']['mode'], a['signature_gate']" | tr -d "(),'")"
assert_eq "D3 the evidence summary is still recorded" "True" "$(last_approval "a['evidence_at_approval']['all_verified']")"

echo ""
echo "=== O-series: explicit opt-in ==="
setup --shadow-ai "$T/shadow.jsonl" --attack-graph "$T/graph.json"
policy '{"version":1,"signature_gate":"unenforced","disruptive_requires":{"all_verified":true}}'
assert_eq "O1 all_verified required, evidence unsigned: refused, step unmoved" "6 evidence_not_all_verified awaiting_approval" "$(approve) $(violations) $(state)"
setup --shadow-ai "$T/signed.jsonl"
policy '{"version":1,"disruptive_requires":{"all_verified":true}}'
assert_eq "O2 all_verified required, every event verified: approved" "0 approved" "$(WAD_PRODUCER_KEY_DIR="$T/keys" approve) $(state)"
assert_eq "O2 the record names the policy and its sha256" "on True" "$(last_approval "a['approval_policy']['mode'], a['approval_policy']['sha256']==__import__('hashlib').sha256(open('$WAD_STATE_DIR/approval_policy.json','rb').read()).hexdigest()" | tr -d "(),'")"
setup --shadow-ai "$T/shadow.jsonl" --attack-graph "$T/graph.json"
policy '{"version":1,"signature_gate":"unenforced","disruptive_requires":{"min_independent_sources":2}}'
assert_eq "O3 two independent sources required; shadow_ai + derived attack_graph is one" "6 independent_sources_below_min:1<2" "$(approve) $(violations)"
setup evaluate --events "$T/two_sources.jsonl"
policy '{"version":1,"signature_gate":"unenforced","disruptive_requires":{"min_independent_sources":2}}'
assert_eq "O4 shadow_ai + saas_ato are two independent sources: approved" "0 approved" "$(approve) $(state)"
setup --shadow-ai "$T/shadow.jsonl" --attack-graph "$T/graph.json"
policy '{"version":1,"signature_gate":"unenforced","disruptive_requires":{"all_verified":true,"min_independent_sources":2}}'
assert_eq "O5 both rules failing: both reported" "6 evidence_not_all_verified,independent_sources_below_min:1<2" "$(approve) $(violations)"
assert_eq "O6 only disruptive steps are subject to it" "[] ['evidence_not_all_verified']" "$(python3 -c "
import sys; sys.path.insert(0, 'security/wad'); import wad_response as wr
p = wr.parse_approval_policy(dict(version=1, disruptive_requires=dict(all_verified=True)))
ev = dict(all_verified=False, independent_source_modules=['x'])
print(wr.check_evidence_policy({'class': 'notify'}, ev, p), wr.check_evidence_policy({'class': 'disruptive'}, ev, p))")"
assert_eq "O7 a decision with no evidence summary cannot satisfy an active policy" "['evidence_unknown:decision has no evidence_provenance']" "$(python3 -c "
import sys; sys.path.insert(0, 'security/wad'); import wad_response as wr
print(wr.check_evidence_policy({'class': 'disruptive'}, None, wr.parse_approval_policy(dict(version=1, disruptive_requires=dict(min_independent_sources=2)))))")"

echo ""
echo "=== I-series: invalid configuration fails closed ==="
bad() {   # bad LABEL POLICY-TEXT -- a valid approval refused with approval_policy_invalid, step unmoved
  setup --shadow-ai "$T/signed.jsonl"
  policy "$2"
  local rc v
  rc=$(WAD_PRODUCER_KEY_DIR="$T/keys" approve); v=$(violations)
  assert_eq "$1" "6 approval_policy_invalid awaiting_approval" "$rc $(printf '%s' "$v" | cut -d: -f1) $(state)"
}
bad "I1 unknown top-level key"           '{"version":1,"disruptive_requires":{"all_verified":true},"enforce":false}'
bad "I2 wrong version"                   '{"version":2,"disruptive_requires":{"all_verified":true}}'
bad "I3 unknown rule"                    '{"version":1,"disruptive_requires":{"all_verified":true,"skip_for":"masa"}}'
bad "I4 all_verified not a boolean"      '{"version":1,"disruptive_requires":{"all_verified":"yes"}}'
bad "I5 min_independent_sources 0"       '{"version":1,"disruptive_requires":{"min_independent_sources":0}}'
bad "I6 min_independent_sources 6"       '{"version":1,"disruptive_requires":{"min_independent_sources":6}}'
bad "I7 min_independent_sources a string" '{"version":1,"disruptive_requires":{"min_independent_sources":"2"}}'
bad "I8 min_independent_sources true"    '{"version":1,"disruptive_requires":{"min_independent_sources":true}}'
bad "I8b min true alongside a real rule"  '{"version":1,"disruptive_requires":{"all_verified":true,"min_independent_sources":true}}'
bad "I9 empty rules"                     '{"version":1,"disruptive_requires":{}}'
bad "I10 a policy that requires nothing" '{"version":1,"disruptive_requires":{"all_verified":false,"min_independent_sources":1}}'
bad "I11 not JSON"                       'all_verified: true'
setup --shadow-ai "$T/signed.jsonl"
printf '{"version":1,"disruptive_requires":{"all_verified":true}}' > "$T/real_policy.json"; ln -s "$T/real_policy.json" "$WAD_STATE_DIR/approval_policy.json"
assert_eq "I12 symlinked policy file refused" "6 approval_policy_invalid" "$(WAD_PRODUCER_KEY_DIR="$T/keys" approve) $(violations | cut -d: -f1)"
setup --shadow-ai "$T/signed.jsonl"
assert_eq "I13 explicitly configured policy file missing: refused (not off)" "6 approval_policy_invalid:configured policy file is missing" "$(WAD_PRODUCER_KEY_DIR="$T/keys" WAD_APPROVAL_POLICY="$T/nope.json" approve) $(violations)"
python3 -c "print('{\"version\":1,\"disruptive_requires\":{\"all_verified\":true},\"pad\":\"' + 'x'*70000 + '\"}')" > "$WAD_STATE_DIR/approval_policy.json"
assert_eq "I14 oversized policy refused" "6 approval_policy_invalid:policy larger than 64 KiB" "$(WAD_PRODUCER_KEY_DIR="$T/keys" approve) $(violations)"
rm -f "$WAD_STATE_DIR/approval_policy.json"
assert_eq "I15 every refusal is recorded unauthenticated" "0" "$(python3 -c "
import json
print(sum(1 for l in open('$WAD_STATE_DIR/ledger.jsonl') if l.strip() and json.loads(l).get('event_type')=='wad_transition_refused' and json.loads(l).get('authenticated') is not False))")"

echo ""
echo "=== U-series: unauthorized approval attempts ==="
setup --shadow-ai "$T/signed.jsonl"
policy '{"version":1,"disruptive_requires":{"all_verified":true}}'
assert_eq "U1 policy satisfied, name not on the allowlist: refused" "6 identity_not_in_allowlist" "$(WAD_PRODUCER_KEY_DIR="$T/keys" approve eve) $(violations)"
assert_eq "U2 policy satisfied, automated name: refused" "6 automated_identity_refused" "$(WAD_PRODUCER_KEY_DIR="$T/keys" approve claude) $(violations)"
mv "$WAD_STATE_DIR/approvers" "$T/approvers.off"
assert_eq "U3 policy satisfied, no allowlist: refused" "6 no_approver_allowlist_configured" "$(WAD_PRODUCER_KEY_DIR="$T/keys" approve) $(violations)"
mv "$T/approvers.off" "$WAD_STATE_DIR/approvers"
policy '{"version":1,"disruptive_requires":{"min_independent_sources":2}}'
assert_eq "U4 policy failing AND unauthorized name: both reported" "6 independent_sources_below_min:1<2,identity_not_in_allowlist" "$(WAD_PRODUCER_KEY_DIR="$T/keys" approve eve) $(violations)"
assert_eq "U5 there is no command-line switch to skip the policy" "2" "$(wad response approve "$SID" --operator masa --reason "$GOOD" --now "$NOW" --no-policy)"
policy '{"version":1,"disruptive_requires":{"all_verified":true}}'
WAD_PRODUCER_KEY_DIR="$T/keys" approve > /dev/null
assert_eq "U6 an approval under a policy is still not authentication" "False present_and_in_allowlist_not_authenticated" "$(last_approval "a['authenticated'], a['identity_check']" | tr -d "(),'")"
assert_eq "U7 no record anywhere claims authentication" "0" "$(grep -c '"authenticated": true' "$WAD_STATE_DIR/ledger.jsonl" || true)"
assert_eq "U8 test key bytes never appear in the ledger, output or error text" "0" "$(python3 -c "
key = open('$T/keys/shadow_ai.key','rb').read()
blobs = [open(p,'rb').read() for p in ('$WAD_STATE_DIR/ledger.jsonl', '$T/out.json', '$T/err.txt')]
print(sum(1 for b in blobs if key in b or key.hex().encode() in b))")"
for s in sudo ssh scp curl nc osascript; do
  assert_eq "U9 stub $s never called" "0" "$(waio_test_stub_calls "$s")"
done
assert_eq "U10 ledger verifies (WAD and lib.sh)" "0 ok" "$(python3 security/wad/wad.py verify-ledger > /dev/null 2>&1; echo $?) $(WAIO_AUDIT_LOG="$WAD_STATE_DIR/ledger.jsonl" WAIO_AUDIT_LOG_CHECKPOINT="$WAD_STATE_DIR/ledger.checkpoint" bash -c '. security/lib.sh; verify_audit_log_integrity')"

echo ""
echo "=== Summary: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
  echo "Failures:"; for f in "${FAILURES[@]}"; do echo "  - $f"; done
  exit 1
fi
exit 0
