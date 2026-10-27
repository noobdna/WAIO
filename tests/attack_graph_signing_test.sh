#!/bin/bash
set -uo pipefail

# tests/attack_graph_signing_test.sh -- opt-in integrity for attack_graph.sh
# (security/detector_signing.py shared with shadow_ai).
#
#   B-series: backward compatibility -- no variables, output unchanged.
#   S-series: document signing -- valid, tampered, wrong key/key_id, missing.
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
import datetime, json, sys; sys.path.insert(0, 'security'); import detector_signing as ds
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
ks=[open('$T/keys/'+n,'rb').read() for n in ('attack_graph.key','shadow_ai.key')]
print(sum(1 for p in ('$G','$T/out.json','$T/err.txt','$T/audit.jsonl') for k in ks if k in open(p,'rb').read() or k.hex().encode() in open(p,'rb').read()))")"
assert_eq "X3 repo state not written" "absent" "$([ security/state/attack_graph/latest_graph.json -nt "$T/keys/attack_graph.key" ] 2>/dev/null && echo written || echo absent)"

echo ""
echo "=== Summary: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
  echo "Failures:"; for f in "${FAILURES[@]}"; do echo "  - $f"; done
  exit 1
fi
exit 0
