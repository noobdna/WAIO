#!/bin/bash
set -uo pipefail

# tests/attack_graph_signing_test.sh -- opt-in integrity for attack_graph.sh
# (security/signing/detector_signing.py shared with shadow_ai).
#
#   B-series: backward compatibility -- no variables, output unchanged.
#   S-series: document signing -- valid, tampered, wrong key/key_id, missing.
#   P-series: signature/payload substitution, malformed envelopes and signing
#             blocks, freshness, replay, key rotation.
#   K-series: key errors -- unsigned fallback with warning, or abort when required.
#   I-series: input integrity -- shadow_ai findings verified before the graph is
#             built; tampered/replayed dropped; verified-only mode; recorded
#             inside the signature so a signed graph cannot launder unsigned input.
#   M-series: malformed input.
# Per-run TEST keys only.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR" || exit 1
# shellcheck source=tests/lib/test_isolation.sh
. tests/lib/test_isolation.sh
waio_test_isolate attack_graph_signing || exit 3
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

T="$WAIO_TEST_ROOT/ags"
mkdir -p "$T/keys"
( umask 077; head -c 32 /dev/urandom > "$T/keys/attack_graph.key"; head -c 32 /dev/urandom > "$T/keys/shadow_ai.key"
  head -c 32 /dev/urandom > "$T/keys/other.key" )
cp "$T/keys/attack_graph.key" "$T/keys/grp.key"; chmod 640 "$T/keys/grp.key"

# findings: two real shadow_ai findings, written unsigned / signed / mixed
python3 - "$T" <<'PY'
import datetime, json, sys
T = sys.argv[1]
sys.path[:0] = ["security/shadow_ai"]
import shadow_ai_lib as sal
now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
mk = lambda p, comm, risk: sal.build_finding("process", dict(pattern=p, risk=risk, category="local_llm_runtime", label=p),
                                              "exact_comm", False, now, p + " running", process=dict(comm=comm, pid=7))
a, b = mk("ollama", "ollama", "HIGH"), mk("autogpt", "autogpt", "MEDIUM")
key = open(T + "/keys/shadow_ai.key", "rb").read(); sid = sal.new_scan_id()
sa, sb = sal.sign_finding(a, key, sid, 0, now), sal.sign_finding(b, key, sid, 1, now)
w = lambda name, objs: open(T + "/" + name, "w").write("".join(json.dumps(o) + "\n" for o in objs))
w("unsigned.jsonl", [a, b])
w("signed.jsonl", [sa, sb])
w("mixed.jsonl", [sa, b])                                   # one verified, one unsigned
t = dict(sb); t["risk"] = "CRITICAL"; w("tampered.jsonl", [sa, t])
w("replay.jsonl", [sa, sa])
open(T + "/malformed.jsonl", "w").write("not json\n" + json.dumps(sa) + "\n[1,2]\n")
PY

build() {   # build INPUT [VAR=VALUE...] -> rc; stdout/stderr in $T/out.json / $T/err.txt
  local in=$1; shift
  env ATTACK_GRAPH_STATE_DIR="$T/state" ATTACK_GRAPH_AUDIT_LOG="$T/audit.jsonl" "$@" \
    bash security/attack_graph/attack_graph.sh build "$in" > "$T/out.json" 2> "$T/err.txt"; echo $?
}
G="$T/state/latest_graph.json"
ver() {   # ver KEYFILE KEY_ID [FILE] -> detector_signing.verify status
  python3 -c "
import datetime, json, sys; sys.path.insert(0, 'security/signing'); import detector_signing as ds
d = json.load(open('${3:-$G}')); k = open('$1','rb').read()
print(ds.verify(d, k, '$2', datetime.datetime.now(datetime.timezone.utc))[0])"
}
jq_g() { python3 -c "import json; d=json.load(open('$G')); print($1)"; }
SIGN=(ATTACK_GRAPH_SIGN=1 ATTACK_GRAPH_SIGNING_KEY_FILE="$T/keys/attack_graph.key")

echo "=== B-series: backward compatibility ==="
assert_eq "B1 no variables: exit 0, original top-level keys only" "0 analysis,edges,findings_processed,generated_at,nodes" "$(build "$T/unsigned.jsonl") $(jq_g "','.join(sorted(d))")"
assert_eq "B2 signed input findings still build the same graph when nothing is configured" "0 autogpt,ollama" "$(build "$T/signed.jsonl") $(jq_g "','.join(sorted(d['nodes']))")"
assert_eq "B3 stdout equals the persisted document" "True" "$(python3 -c "import json; print(json.load(open('$T/out.json'))==json.load(open('$G')))")"

echo ""
echo "=== S-series: document signing ==="
assert_eq "S1 signed with the attack_graph key: verifies" "0 verified" "$(build "$T/unsigned.jsonl" "${SIGN[@]}") $(ver "$T/keys/attack_graph.key" attack_graph)"
assert_eq "S2 key_id attack_graph, signed_at = generated_at, stdout = file" "attack_graph True True" "$(jq_g "d['wad_sig']['key_id'], d['signing']['signed_at']==d['generated_at'], d==json.load(open('$T/out.json'))" | tr -d "(),'")"
python3 -c "import json; d=json.load(open('$G')); d['nodes']['ollama']['highest_risk']='LOW'; json.dump(d, open('$T/tampered_graph.json','w'))"
assert_eq "S3 node changed after signing: invalid" "invalid" "$(ver "$T/keys/attack_graph.key" attack_graph "$T/tampered_graph.json")"
assert_eq "S4 verified with another key: invalid" "invalid" "$(ver "$T/keys/other.key" attack_graph)"
assert_eq "S5 checked as a shadow_ai signature (wrong key_id): invalid" "invalid" "$(ver "$T/keys/attack_graph.key" shadow_ai)"
build "$T/unsigned.jsonl" > /dev/null
assert_eq "S6 unsigned document: missing" "missing" "$(ver "$T/keys/attack_graph.key" attack_graph)"

echo ""
echo "=== P-series: substitution, malformed envelopes, freshness, replay, rotation ==="
build "$T/unsigned.jsonl" "${SIGN[@]}" > /dev/null; cp "$G" "$T/ga.json"
build "$T/mixed.jsonl" ATTACK_GRAPH_INPUT_KEY_FILE="$T/keys/shadow_ai.key" "${SIGN[@]}" > /dev/null; cp "$G" "$T/gb.json"
pchk() {   # pchk KEYFILE PYTHON-EXPR -> space-separated statuses; ga/gb/k/ds/v/w/now/dt available
  python3 -c "
import copy, datetime as dt, json, sys; sys.path.insert(0, 'security/signing'); import detector_signing as ds
ga = json.load(open('$T/ga.json')); gb = json.load(open('$T/gb.json')); k = open('$1','rb').read()
now = dt.datetime.now(dt.timezone.utc)
def v(d, when=None, seen=None): return ds.verify(d, k, 'attack_graph', when or now, seen=seen)[0]
def w(d, **kw): d = copy.deepcopy(d); d.update(kw); return d
print(' '.join($2))"
}
K="$T/keys/attack_graph.key"
assert_eq "P1 both graphs verify on their own" "verified verified" "$(pchk "$K" "[v(ga), v(gb)]")"
assert_eq "P2 signature from graph A moved onto graph B: invalid" "invalid" "$(pchk "$K" "[v(w(gb, wad_sig=ga['wad_sig']))]")"
assert_eq "P3 signing block from B substituted into A: invalid" "invalid" "$(pchk "$K" "[v(w(ga, signing=gb['signing']))]")"
assert_eq "P4 malformed envelopes (string, non-hex mac, short mac, wrong alg, no key_id): all invalid" \
  "invalid invalid invalid invalid invalid" \
  "$(pchk "$K" "[v(w(ga, wad_sig='x')), v(w(ga, wad_sig=dict(ga['wad_sig'], mac='z'*64))), v(w(ga, wad_sig=dict(ga['wad_sig'], mac=ga['wad_sig']['mac'][:32]))), v(w(ga, wad_sig=dict(ga['wad_sig'], alg='none'))), v(w(ga, wad_sig=dict((x, y) for x, y in ga['wad_sig'].items() if x != 'key_id')))]")"
assert_eq "P5 valid mac over a malformed signing block (seq -1, short scan_id, bool seq, bad signed_at): all invalid" \
  "invalid invalid invalid invalid" \
  "$(pchk "$K" "[v(ds.sign(dict((x, y) for x, y in ga.items() if x not in ('wad_sig', 'signing')), k, 'attack_graph', s, q, t)) for s, q, t in ((ga['signing']['scan_id'], -1, ga['signing']['signed_at']), ('ab', 0, ga['signing']['signed_at']), (ga['signing']['scan_id'], True, ga['signing']['signed_at']), (ga['signing']['scan_id'], 0, 'yesterday'))]")"
assert_eq "P6 freshness: 2 days later stale, 1 hour before signing stale (clock skew), now verified" "stale stale verified" \
  "$(pchk "$K" "[v(ga, now + dt.timedelta(days=2)), v(ga, now - dt.timedelta(hours=1)), v(ga)]")"
assert_eq "P7 the same signed graph presented twice to one verifier: replay" "verified replay" \
  "$(pchk "$K" "(lambda s: [v(ga, seen=s), v(ga, seen=s)])(set())")"
( umask 077; head -c 32 /dev/urandom > "$T/keys/attack_graph.rotated.key" )
assert_eq "P8 key rotated: graphs signed with the old key are invalid under the new one" "invalid invalid" "$(pchk "$T/keys/attack_graph.rotated.key" "[v(ga), v(gb)]")"
assert_eq "P9 key rotated: a rebuild with the new key verifies" "0 verified" \
  "$(build "$T/unsigned.jsonl" ATTACK_GRAPH_SIGN=1 ATTACK_GRAPH_SIGNING_KEY_FILE="$T/keys/attack_graph.rotated.key") $(ver "$T/keys/attack_graph.rotated.key" attack_graph)"

echo ""
echo "=== K-series: key errors ==="
assert_eq "K1 signing requested, key missing: written UNSIGNED, warning, audited" "0 False 1 1" \
  "$(build "$T/unsigned.jsonl" ATTACK_GRAPH_SIGN=1 ATTACK_GRAPH_SIGNING_KEY_FILE="$T/keys/nope.key") $(jq_g "'wad_sig' in d") $(grep -c 'WARNING: signing requested but' "$T/err.txt") $(grep -c 'signing=FAILED' "$T/audit.jsonl")"
assert_eq "K2 group-readable key refused the same way" "0 False" "$(build "$T/unsigned.jsonl" ATTACK_GRAPH_SIGN=1 ATTACK_GRAPH_SIGNING_KEY_FILE="$T/keys/grp.key") $(jq_g "'wad_sig' in d")"
build "$T/unsigned.jsonl" "${SIGN[@]}" > /dev/null; before=$(shasum -a 256 "$G" | cut -d' ' -f1)
assert_eq "K3 signing REQUIRED, key unusable: exit 3, nothing written" "3 $before 1" \
  "$(build "$T/signed.jsonl" ATTACK_GRAPH_SIGN_REQUIRED=1 ATTACK_GRAPH_SIGNING_KEY_FILE="$T/keys/grp.key") $(shasum -a 256 "$G" | cut -d' ' -f1) $(grep -c 'nothing written' "$T/err.txt")"
assert_eq "K4 SIGN_REQUIRED alone (no key file) also aborts" "3" "$(build "$T/unsigned.jsonl" ATTACK_GRAPH_SIGN_REQUIRED=1)"
assert_eq "K5 a key without ATTACK_GRAPH_SIGN does nothing" "0 False" "$(build "$T/unsigned.jsonl" ATTACK_GRAPH_SIGNING_KEY_FILE="$T/keys/attack_graph.key") $(jq_g "'wad_sig' in d")"

echo ""
echo "=== I-series: input integrity ==="
IN=(ATTACK_GRAPH_INPUT_KEY_FILE="$T/keys/shadow_ai.key")
assert_eq "I1 mixed input, counts only: 1 verified, 1 unverified, both used" "0 1 1 0 2 all_with_counts" \
  "$(build "$T/mixed.jsonl" "${IN[@]}") $(jq_g "d['input_integrity']['verified'], d['input_integrity']['unverified'], d['input_integrity']['dropped_invalid'], d['findings_processed'], d['input_integrity']['mode']" | tr -d "(),'")"
assert_eq "I2 verified-only: the unverified finding is excluded from the graph" "0 1 ollama verified_only" \
  "$(build "$T/mixed.jsonl" "${IN[@]}" ATTACK_GRAPH_REQUIRE_SIGNED_INPUT=1) $(jq_g "d['findings_processed'], ','.join(d['nodes']), d['input_integrity']['mode']" | tr -d "(),'")"
assert_eq "I3 tampered input finding always dropped" "0 1 1" "$(build "$T/tampered.jsonl" "${IN[@]}") $(jq_g "d['input_integrity']['dropped_invalid'], d['findings_processed']" | tr -d "(),'")"
assert_eq "I4 replayed input line (same scan_id/seq) dropped" "0 1 1" "$(build "$T/replay.jsonl" "${IN[@]}") $(jq_g "d['input_integrity']['dropped_invalid'], d['findings_processed']" | tr -d "(),'")"
assert_eq "I5 verified-only with an unusable input key: exit 3, nothing written" "3" "$(build "$T/signed.jsonl" ATTACK_GRAPH_REQUIRE_SIGNED_INPUT=1 ATTACK_GRAPH_INPUT_KEY_FILE="$T/keys/grp.key")"
assert_eq "I6 input key unusable, not required: warning, counted as unverified" "0 1 2 False" \
  "$(build "$T/signed.jsonl" ATTACK_GRAPH_INPUT_KEY_FILE="$T/keys/grp.key") $(grep -c 'input findings NOT verified' "$T/err.txt") $(jq_g "d['input_integrity']['unverified'], d['input_integrity']['input_key_used']" | tr -d "(),'")"
build "$T/mixed.jsonl" "${IN[@]}" "${SIGN[@]}" > /dev/null
assert_eq "I7 signed graph carries input_integrity inside the mac" "verified 1" "$(ver "$T/keys/attack_graph.key" attack_graph) $(jq_g "d['input_integrity']['unverified']")"
python3 -c "import json; d=json.load(open('$G')); d['input_integrity']['unverified']=0; json.dump(d, open('$T/launder.json','w'))"
assert_eq "I8 hiding unverified input in a signed graph breaks the signature" "invalid" "$(ver "$T/keys/attack_graph.key" attack_graph "$T/launder.json")"
assert_eq "I9 fully verified input + signing: verified, 0 unverified" "0 verified 0 2" \
  "$(build "$T/signed.jsonl" "${IN[@]}" ATTACK_GRAPH_REQUIRE_SIGNED_INPUT=1 "${SIGN[@]}") $(ver "$T/keys/attack_graph.key" attack_graph) $(jq_g "d['input_integrity']['unverified'], d['input_integrity']['verified']" | tr -d "(),'")"

echo ""
echo "=== M-series: malformed input ==="
assert_eq "M1 non-JSON and non-object lines skipped, the signed finding used" "0 1 1" "$(build "$T/malformed.jsonl" "${IN[@]}") $(jq_g "d['findings_processed'], d['input_integrity']['verified']" | tr -d "(),'")"
assert_eq "M2 no variables: a non-object JSON line no longer crashes the build (pre-existing bug)" "0 1" "$(build "$T/malformed.jsonl") $(jq_g "d['findings_processed']")"
for s in sudo ssh scp curl nc osascript; do
  assert_eq "X1 stub $s never called" "0" "$(waio_test_stub_calls "$s")"
done
assert_eq "X2 test key bytes never in outputs" "0" "$(python3 -c "
ks=[open('$T/keys/'+n,'rb').read() for n in ('attack_graph.key','shadow_ai.key','attack_graph.rotated.key')]
print(sum(1 for p in ('$G','$T/out.json','$T/err.txt','$T/audit.jsonl') for k in ks if k in open(p,'rb').read() or k.hex().encode() in open(p,'rb').read()))")"
assert_eq "X3 repo state not written" "absent" "$([ security/state/attack_graph/latest_graph.json -nt "$T/keys/attack_graph.key" ] 2>/dev/null && echo written || echo absent)"
# A module directly in security/ gets its bytecode in security/__pycache__ (Linux CI), which
# changes security/'s mtime -- the '..' entry e2e_pipeline_test.sh D3 hashes. Keep libs in subdirs.
assert_eq "X4 no Python module directly under security/" "" "$(ls security/*.py 2>/dev/null)"

echo ""
echo "=== Summary: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
  echo "Failures:"; for f in "${FAILURES[@]}"; do echo "  - $f"; done
  exit 1
fi
exit 0
