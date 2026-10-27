#!/bin/bash
set -uo pipefail

# tests/shadow_ai_signing_test.sh -- opt-in detector-side signing of Shadow
# AI findings (shadow_ai_lib sign_finding/verify_finding/load_signing_key,
# shadow_ai_monitor.sh SHADOW_AI_SIGN).
#
#   L-series: library -- valid, tampered, missing, invalid, stale/future,
#             replay, key-file checks.
#   W-series: the envelope matches the format WAD's adapters verify
#             (independent re-implementation of that check).
#   M-series: the monitor end to end with ps/lsof shadowed on PATH --
#             off by default, on with a good key, unsigned + warning with a
#             bad key, inventory unchanged.
#   R-series: replay across scans.
# Test keys are generated per run under the temp root; no real key is used.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR" || exit 1
# shellcheck source=tests/lib/test_isolation.sh
. tests/lib/test_isolation.sh
waio_test_isolate shadow_ai_signing || exit 3
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

T="$WAIO_TEST_ROOT/sig"
mkdir -p "$T/bin" "$T/state"
( umask 077; head -c 32 /dev/urandom > "$T/key"; head -c 32 /dev/urandom > "$T/otherkey" )

py() { python3 -c "
import sys, json, datetime, copy
sys.path.insert(0, 'security/shadow_ai'); import shadow_ai_lib as sal
KEY = open('$T/key','rb').read(); OTHER = open('$T/otherkey','rb').read()
NOW = datetime.datetime(2026, 10, 27, 2, 0, 0, tzinfo=datetime.timezone.utc)
F = sal.build_finding('process', dict(pattern='ollama', risk='HIGH', category='local_llm_runtime', label='Ollama'),
                      'exact_comm', False, '2026-10-27T01:00:00Z', 'ollama été running', process=dict(comm='ollama', pid=7))
S = sal.sign_finding(F, KEY, 'a'*32, 0, '2026-10-27T01:00:00Z')
V = lambda o, **k: sal.verify_finding(o, KEY, NOW, **k)[0]
$1"; }

echo "=== L-series: library ==="
assert_eq "L1 signed finding verifies" "verified" "$(py "print(V(S))")"
assert_eq "L2 signing does not mutate the finding" "False" "$(py "print('wad_sig' in F or 'signing' in F)")"
assert_eq "L3 tampered field (risk) -> invalid" "invalid" "$(py "x=copy.deepcopy(S); x['risk']='LOW'; print(V(x))")"
assert_eq "L4 tampered signed_at (try to freshen) -> invalid" "invalid" "$(py "x=copy.deepcopy(S); x['signing']['signed_at']='2026-10-27T01:59:00Z'; print(V(x))")"
assert_eq "L5 tampered scan_id/seq (try to dodge replay) -> invalid" "invalid invalid" "$(py "x=copy.deepcopy(S); x['signing']['scan_id']='b'*32; y=copy.deepcopy(S); y['signing']['seq']=9; print(V(x), V(y))")"
assert_eq "L6 extra field added after signing -> invalid" "invalid" "$(py "x=copy.deepcopy(S); x['note']='injected'; print(V(x))")"
assert_eq "L7 missing signature -> missing" "missing" "$(py "print(V(F))")"
assert_eq "L8 signed with another key -> invalid" "invalid" "$(py "print(V(sal.sign_finding(F, OTHER, 'a'*32, 0, '2026-10-27T01:00:00Z')))")"
assert_eq "L9 wrong key_id / alg none / bad mac hex -> invalid" "invalid invalid invalid" "$(py "
a=copy.deepcopy(S); a['wad_sig']['key_id']='attack_graph'
b=copy.deepcopy(S); b['wad_sig']['alg']='none'
c=copy.deepcopy(S); c['wad_sig']['mac']='zz'
print(V(a), V(b), V(c))")"
assert_eq "L10 valid mac but no signing block -> invalid" "invalid" "$(py "
import hmac, hashlib
x=dict(F); x['wad_sig']=dict(alg='hmac-sha256', key_id='shadow_ai', mac=hmac.new(KEY, sal.canonical(F), hashlib.sha256).hexdigest())
print(V(x))")"
assert_eq "L11 stale (signed 25 h before now) -> stale" "stale" "$(py "print(V(sal.sign_finding(F, KEY, 'a'*32, 0, '2026-10-26T01:00:00Z')))")"
assert_eq "L12 signed in the future beyond skew -> stale" "stale" "$(py "print(V(sal.sign_finding(F, KEY, 'a'*32, 0, '2026-10-27T03:00:00Z')))")"
assert_eq "L13 exact replay with a seen-set -> replay" "verified replay" "$(py "s=set(); print(V(S, seen=s), V(copy.deepcopy(S), seen=s))")"
assert_eq "L14 same finding, new scan -> verified again" "verified verified" "$(py "s=set(); print(V(S, seen=s), V(sal.sign_finding(F, KEY, 'c'*32, 0, '2026-10-27T01:30:00Z'), seen=s))")"
assert_eq "L15 a refused (invalid) finding is not added to the seen-set" "invalid verified" "$(py "s=set(); x=copy.deepcopy(S); x['risk']='LOW'; print(V(x, seen=s), V(S, seen=s))")"
assert_eq "L16 non-ASCII text survives the monitor's ensure_ascii=False output" "verified" "$(py "print(V(json.loads(json.dumps(S, ensure_ascii=False))))")"
assert_eq "L17 new_scan_id is 128-bit hex and differs per call" "32 True" "$(py "a,b=sal.new_scan_id(),sal.new_scan_id(); print(len(a), a!=b)")"
keyerr() { python3 -c "
import sys; sys.path.insert(0, 'security/shadow_ai'); import shadow_ai_lib as sal
try:
    sal.load_signing_key('$1'); print('loaded')
except sal.SigningKeyError as e:
    print('refused')"; }
( umask 077; head -c 16 /dev/urandom > "$T/short" ); cp "$T/key" "$T/grp"; chmod 640 "$T/grp"; ln -s "$T/key" "$T/link"; mkdir -p "$T/dir.key"
assert_eq "L18 key file checks: good, missing, short, group-readable, symlink, directory" "loaded refused refused refused refused refused" \
  "$(keyerr "$T/key") $(keyerr "$T/nope") $(keyerr "$T/short") $(keyerr "$T/grp") $(keyerr "$T/link") $(keyerr "$T/dir.key")"

echo ""
echo "=== W-series: envelope matches what WAD's adapters verify ==="
assert_eq "W1 independent re-implementation of the WAD check accepts it" "True" "$(py "
import hmac, hashlib
sig = S['wad_sig']; body = dict((k, v) for k, v in S.items() if k != 'wad_sig')
canon = json.dumps(body, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('utf-8')
print(sig['alg']=='hmac-sha256' and sig['key_id']=='shadow_ai' and hmac.compare_digest(hmac.new(KEY, canon, hashlib.sha256).hexdigest(), sig['mac']))")"
assert_eq "W2 the signed finding keeps every field consumers read" "True" "$(py "print(all(S[k]==F[k] for k in F))")"

echo ""
echo "=== M-series: shadow_ai_monitor.sh end to end (ps/lsof shadowed) ==="
cat > "$T/bin/ps" <<'EOF'
#!/bin/bash
cat <<'P'
   300     1 masa     ollama           /usr/local/bin/ollama serve
   200     1 masa     autogpt          /usr/bin/python3 /opt/autogpt/main.py
P
EOF
cat > "$T/bin/lsof" <<'EOF'
#!/bin/bash
cat <<'L'
COMMAND   PID  USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
ollama    300  masa   10u  IPv4 0x1        0t0  TCP  *:11434 (LISTEN)
autogpt   200  masa   12u  IPv4 0x2        0t0  TCP  127.0.0.1:54321->127.0.0.1:11434 (ESTABLISHED)
L
EOF
chmod +x "$T/bin/ps" "$T/bin/lsof"
printf 'process|ollama|local_llm_runtime|MEDIUM|Ollama\nprocess|autogpt|ai_agent_framework|HIGH|AutoGPT\nport|11434|local_llm_runtime|MEDIUM|Ollama port\n' > "$T/sigs.conf"
: > "$T/allow.conf"
scan() {   # scan OUTFILE [VAR=VALUE...]
  local o=$1; shift
  env PATH="$T/bin:$PATH" SHADOW_AI_SIGNATURES_FILE="$T/sigs.conf" SHADOW_AI_ALLOWLIST_FILE="$T/allow.conf" \
    SHADOW_AI_STATE_DIR="$T/state" SHADOW_AI_AUDIT_LOG="$T/audit.jsonl" "$@" \
    bash security/shadow_ai/shadow_ai_monitor.sh scan > "$o" 2> "$o.err"; echo $?
}
vfile() {   # vfile FILE -> statuses of every line, verified with the test key
  python3 -c "
import sys, json, datetime; sys.path.insert(0, 'security/shadow_ai'); import shadow_ai_lib as sal
key = open('$T/key','rb').read(); now = datetime.datetime.now(datetime.timezone.utc); seen = set()
print(' '.join(sal.verify_finding(json.loads(l), key, now, seen=seen)[0] for l in open('$1') if l.strip()))"
}
assert_eq "M1 flag unset: scan ok, no wad_sig/signing on any line" "0 0 off" "$(scan "$T/off.jsonl") $(grep -c -e wad_sig -e '\"signing\"' "$T/off.jsonl") $(grep -o 'signing=off' "$T/off.jsonl.err" | head -1 | cut -d= -f2)"
n=$(grep -c . "$T/off.jsonl")
assert_eq "M2 flag + good key: every line verified" "0 $(printf 'verified %.0s' $(seq "$n") | sed 's/ $//')" "$(scan "$T/on.jsonl" SHADOW_AI_SIGN=1 SHADOW_AI_SIGNING_KEY_FILE="$T/key") $(vfile "$T/on.jsonl")"
assert_eq "M3 one scan_id per scan, seq 0..n-1" "1 $(seq 0 $((n - 1)) | tr '\n' ' ' | sed 's/ $//')" "$(python3 -c "
import json; L=[json.loads(l) for l in open('$T/on.jsonl') if l.strip()]
print(len(set(x['signing']['scan_id'] for x in L)), ' '.join(str(x['signing']['seq']) for x in L))")"
assert_eq "M4 summary says signing=on" "1" "$(grep -c 'signing=on' "$T/on.jsonl.err")"
assert_eq "M5 inventory never stores signatures" "0" "$(grep -c -e wad_sig -e '\"signing\"' "$T/state/inventory.json")"
assert_eq "M6 flag + group-readable key: still exit 0, lines UNSIGNED, warning" "0 0 1" "$(scan "$T/bad.jsonl" SHADOW_AI_SIGN=1 SHADOW_AI_SIGNING_KEY_FILE="$T/grp") $(grep -c wad_sig "$T/bad.jsonl") $(grep -c 'WARNING: signing requested but' "$T/bad.jsonl.err")"
assert_eq "M7 the failure reaches the audit log" "1" "$(grep -c 'FAILED (key is accessible to group/others' "$T/audit.jsonl")"
assert_eq "M8 flag + missing key path: unsigned, warning" "0 0 1" "$(scan "$T/miss.jsonl" SHADOW_AI_SIGN=1 SHADOW_AI_SIGNING_KEY_FILE="$T/nope") $(grep -c wad_sig "$T/miss.jsonl") $(grep -c 'WARNING: signing requested but' "$T/miss.jsonl.err")"
assert_eq "M9 a key without the flag does nothing" "0 0" "$(scan "$T/noflag.jsonl" SHADOW_AI_SIGNING_KEY_FILE="$T/key") $(grep -c wad_sig "$T/noflag.jsonl")"
assert_eq "M10 signed lines still parse for attack_graph (same node count)" "True" "$(python3 -c "
import sys; sys.path.insert(0,'security/attack_graph'); import attack_graph_lib as agl
a=agl.build_graph(agl.parse_findings(open('$T/off.jsonl').readlines())); b=agl.build_graph(agl.parse_findings(open('$T/on.jsonl').readlines()))
print(sorted(a['nodes'])==sorted(b['nodes']))")"

echo ""
echo "=== R-series: replay across scans ==="
scan "$T/on2.jsonl" SHADOW_AI_SIGN=1 SHADOW_AI_SIGNING_KEY_FILE="$T/key" > /dev/null
assert_eq "R1 two scans have different scan_ids" "True" "$(python3 -c "
import json; a=json.loads(open('$T/on.jsonl').readline()); b=json.loads(open('$T/on2.jsonl').readline()); print(a['signing']['scan_id']!=b['signing']['scan_id'])")"
assert_eq "R2 replaying scan 1's first line after scan 1 was consumed -> replay" "replay" "$(python3 -c "
import sys, json, datetime; sys.path.insert(0, 'security/shadow_ai'); import shadow_ai_lib as sal
key=open('$T/key','rb').read(); now=datetime.datetime.now(datetime.timezone.utc); seen=set()
L=[json.loads(l) for l in open('$T/on.jsonl') if l.strip()]
[sal.verify_finding(x, key, now, seen=seen) for x in L]
print(sal.verify_finding(L[0], key, now, seen=seen)[0])")"
assert_eq "R3 the same line a day later -> stale" "stale" "$(python3 -c "
import sys, json, datetime; sys.path.insert(0, 'security/shadow_ai'); import shadow_ai_lib as sal
key=open('$T/key','rb').read(); later=datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(hours=25)
print(sal.verify_finding(json.loads(open('$T/on.jsonl').readline()), key, later)[0])")"
for s in sudo ssh scp curl nc osascript; do
  assert_eq "S1 stub $s never called" "0" "$(waio_test_stub_calls "$s")"
done
assert_eq "S2 the real repo state was not touched" "absent" "$([ security/state/shadow_ai/inventory.json -nt "$T/key" ] 2>/dev/null && echo touched || echo absent)"

echo ""
echo "=== Summary: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
  echo "Failures:"; for f in "${FAILURES[@]}"; do echo "  - $f"; done
  exit 1
fi
exit 0
