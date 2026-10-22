#!/bin/bash
set -uo pipefail

# tests/snd_behavior_test.sh -- SND@ID / SND@HOME behavior monitoring
# (security/snd_behavior/). Synthetic data from snd_id_mock.py only;
# fixture-only under mktemp.
#
#   B1      baseline from 30 days of mock history
#   B2      attacks: each scenario raises HIGH/CRITICAL with the right rule
#   B3      false-positive evaluation: benign scenarios with and without
#           operator-declared context (shift change, trip, emergency)
#   B4      record shape: id, time, reason, confidence, risk, recommended
#           action, DRY_RUN / NOT_EXECUTED
#   B5      data minimization: IP, user agent, tokens, bodies dropped
#   B6      determinism + idempotent re-run
#   B7      a detection fed to killswitch evaluate-event is advisory only
#   B8      static: no containment/network code path in the module

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"
export PYTHONDONTWRITEBYTECODE=1
PASS=0
FAIL=0
declare -a FAILURES=()
assert_eq() {
  local label="$1" expected="$2" actual="$3"
  if [ "$expected" = "$actual" ]; then PASS=$((PASS + 1)); echo "  PASS: $label"
  else FAIL=$((FAIL + 1)); FAILURES+=("$label (expected='$expected' actual='$actual')"); echo "  FAIL: $label (expected='$expected' actual='$actual')"; fi
}
jget() { python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print($2)" <<<"$1" 2>/dev/null; }

M=security/snd_behavior
TMP="$(mktemp -d "${TMPDIR:-/tmp}/snd-behavior-test.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT
mon() { python3 $M/behavior_monitor.py "$@"; }
cat > "$TMP/ctx.json" <<'EOF'
[{"context_id":"SC-001","principal":"bob","kind":"schedule_change","start":"2026-10-01T00:00:00Z","end":"2026-10-31T00:00:00Z","hours":[22,6],"approved_by":"manager","reason":"night shift rotation"},
 {"context_id":"TN-001","principal":"alice","kind":"travel","start":"2026-10-13T00:00:00Z","end":"2026-10-14T00:00:00Z","regions":["SG"],"approved_by":"manager","reason":"Singapore customer visit"},
 {"context_id":"EM-001","principal":"carol","kind":"emergency_change","start":"2026-10-13T17:00:00Z","end":"2026-10-13T20:00:00Z","approved_by":"oncall","reason":"incident hotfix window"}]
EOF
printf '{"alice":"test-session-001","bob":"test-session-002","carol":"test-session-003"}\n' > "$TMP/targets.json"

echo "[B1] baseline"
python3 $M/snd_id_mock.py history 7 30 "$TMP/history.jsonl" >/dev/null
OUT="$(mon baseline "$TMP/history.jsonl" "$TMP/baseline.json")"
assert_eq "B1 3 principals, 0 rejected" "3|0" "$(jget "$OUT" "str(d['principals'])+'|'+str(d['rejected'])")"
assert_eq "B1 baseline knows alice's home region" "['JP-13']" "$(jget "$(cat "$TMP/baseline.json")" "d['principals']['alice']['regions']")"

detect() {  # detect SCENARIO [--context] -> sets OUT; records in $TMP/out-SCENARIO[-ctx]
  local sc="$1" suffix="" extra=()
  python3 $M/snd_id_mock.py scenario "$sc" "$TMP/$sc.jsonl" >/dev/null
  if [ "${2:-}" = "--context" ]; then suffix="-ctx"; extra=(--context "$TMP/ctx.json"); fi
  OUT="$(mon detect "$TMP/baseline.json" "$TMP/$sc.jsonl" "$TMP/out-$sc$suffix" --targets "$TMP/targets.json" ${extra[@]+"${extra[@]}"})"
}
max_risk() { jget "$OUT" "max([['LOW','MEDIUM','HIGH','CRITICAL'].index(k) for k in d['by_risk']] or [-1])"; }

echo "[B2] attack scenarios are detected at HIGH/CRITICAL"
for pair in credential_stuffing:auth_failure_burst token_theft_travel:impossible_travel insider_exfil:bulk_data_access \
            priv_escalation:privilege_escalation mfa_reset_attack:mfa_change_unfamiliar; do
  sc="${pair%%:*}" rule="${pair#*:}"
  detect "$sc" --context
  assert_eq "B2 $sc -> rule $rule present" "True" "$(jget "$OUT" "'$rule' in d['rules']")"
  [ "$(max_risk)" -ge 2 ] && r=True || r=False
  assert_eq "B2 $sc max risk >= HIGH even with every context loaded" "True" "$r"
done
detect credential_stuffing
assert_eq "B2 success right after a failure burst is CRITICAL" "True" "$(jget "$OUT" "'CRITICAL' in d['by_risk']")"

echo "[B3] false-positive evaluation on benign scenarios"
FP_NOCTX=0 FP_CTX=0 N_BENIGN=0
for sc in normal_day shift_change business_trip emergency_work; do
  N_BENIGN=$((N_BENIGN + 1))
  detect "$sc"; r0="$(max_risk)"
  detect "$sc" --context; r1="$(max_risk)"
  [ "$r0" -ge 2 ] && FP_NOCTX=$((FP_NOCTX + 1))
  [ "$r1" -ge 2 ] && FP_CTX=$((FP_CTX + 1))
  echo "    $sc: max risk without context=$r0, with context=$r1 (-1 none, 0 LOW .. 3 CRITICAL)"
  [ "$r1" -lt 2 ] && ok=True || ok=False
  assert_eq "B3 $sc with declared context stays below HIGH" "True" "$ok"
done
detect normal_day
assert_eq "B3 a normal day raises nothing at all" "0" "$(jget "$OUT" "d['detections']")"
echo "    FP rate (benign scenarios reaching HIGH+): without context $FP_NOCTX/$N_BENIGN, with context $FP_CTX/$N_BENIGN"
assert_eq "B3 FP with context = 0" "0" "$FP_CTX"
assert_eq "B3 without context, undeclared travel/emergency DO surface (documented, not hidden)" "2" "$FP_NOCTX"
detect business_trip --context
assert_eq "B3 context downgrade is recorded, not silent" "TN-001" "$(python3 -c "import json,glob,sys; print(sorted({json.load(open(f))['context_applied'] for f in glob.glob(sys.argv[1]+'/*.json')})[-1])" "$TMP/out-business_trip-ctx")"
detect credential_stuffing --context
python3 - "$TMP/ctx.json" <<'EOF'
import json, sys
c = json.load(open(sys.argv[1])); c.append({"context_id": "TN-ALICE-RU", "principal": "alice", "kind": "travel",
 "start": "2026-10-15T00:00:00Z", "end": "2026-10-17T00:00:00Z", "regions": ["RU"], "approved_by": "x", "reason": "y"})
json.dump(c, open(sys.argv[1] + ".2", "w"))
EOF
OUT="$(mon detect "$TMP/baseline.json" "$TMP/credential_stuffing.jsonl" "$TMP/out-cs2" --context "$TMP/ctx.json.2")"
assert_eq "B3 no context can downgrade a failed-login burst" "True" "$(jget "$OUT" "d['by_risk'].get('CRITICAL',0) >= 1")"

echo "[B4] detection record shape"
detect token_theft_travel
REC="$(cat "$(ls "$TMP"/out-token_theft_travel/*.json | head -1)")"
for k in event_id observed_at detection_reason confidence risk recommended_action evidence_event_ids; do
  assert_eq "B4 record has $k" "True" "$(jget "$REC" "'$k' in d and d['$k'] not in ('', None, [])")"
done
assert_eq "B4 DRY_RUN / read_only / NOT_EXECUTED" "DRY_RUN|True|NOT_EXECUTED" "$(jget "$REC" "d['mode']+'|'+str(d['read_only'])+'|'+d['execution_result']")"
assert_eq "B4 HIGH maps to a test-only recommendation" "revoke_test_session|test-session-002" \
  "$(python3 -c "import json,glob,sys; r=[json.load(open(f)) for f in glob.glob(sys.argv[1]+'/*.json')]; h=[x for x in r if x['rule']=='impossible_travel'][0]; print(h['recommended_action']+'|'+h['target_ref'])" "$TMP/out-token_theft_travel")"
assert_eq "B4 file mode 0600" "600" "$(python3 -c "import os,sys; print('%o' % (os.stat(sys.argv[1]).st_mode & 0o777))" "$(ls "$TMP"/out-token_theft_travel/*.json | head -1)")"

echo "[B5] data minimization"
cat > "$TMP/leaky.jsonl" <<'EOF'
{"source":"snd_id","event_id":"l-1","ts":"2026-10-16T01:00:00Z","principal":"alice","action":"mfa_change","region":"NG","device_id":"mock-x","ip":"203.0.113.7","user_agent":"curl/8.0","token":"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig","body":"password=hunter2hunter2"}
{"source":"other","event_id":"l-2","ts":"2026-10-16T01:00:00Z","principal":"alice","action":"login_success","region":"JP","device_id":"d"}
{"source":"snd_id","event_id":"../etc","ts":"2026-10-16T01:00:00Z","principal":"alice","action":"login_success","region":"JP","device_id":"d"}
not json
EOF
OUT="$(mon detect "$TMP/baseline.json" "$TMP/leaky.jsonl" "$TMP/out-leaky")"
assert_eq "B5 bad source / traversal id / non-JSON rejected" "3" "$(jget "$OUT" "d['rejected']")"
ALL="$(cat "$TMP"/out-leaky/*.json)"
for s in 203.0.113.7 curl/8.0 eyJhbGci hunter2 user_agent '"ip"'; do
  [[ "$ALL" != *"$s"* ]] && ok=True || ok=False
  assert_eq "B5 stored record omits '$s'" "True" "$ok"
done

echo "[B6] determinism and idempotent re-run"
OUT1="$(mon detect "$TMP/baseline.json" "$TMP/insider_exfil.jsonl" "$TMP/out-det")"
OUT2="$(mon detect "$TMP/baseline.json" "$TMP/insider_exfil.jsonl" "$TMP/out-det")"
assert_eq "B6 re-run writes nothing new" "0" "$(jget "$OUT2" "d['written']")"
assert_eq "B6 same detection count" "$(jget "$OUT1" "d['detections']")" "$(jget "$OUT2" "d['detections']")"

echo "[B7] hand-off to the kill switch is advisory only"
export KILLSWITCH_STATE_DIR="$TMP/ks/state" KILLSWITCH_CONFIG_DIR="$TMP/ks/config" KILLSWITCH_KEYRING_DIR="$TMP/ks/config/keys"
export KILLSWITCH_AUDIT_LOG="$TMP/ks/audit.jsonl" KILLSWITCH_AUDIT_CHECKPOINT="$TMP/ks/state/.cp" KILLSWITCH_TEST_ENV="$TMP/ks/testenv"
mkdir -p "$TMP/ks/config/keys" "$TMP/ks/testenv"; printf 'environment=test\n' > "$TMP/ks/testenv/.killswitch-test-env"
(umask 077; cp security/killswitch/targets.conf.example "$TMP/ks/config/targets.conf"; cp security/killswitch/authz.conf.example "$TMP/ks/config/authz.conf")
det="$(python3 -c "import json,glob,sys; r=[f for f in glob.glob(sys.argv[1]+'/*.json') if json.load(open(f))['rule']=='impossible_travel']; print(r[0])" "$TMP/out-token_theft_travel")"
OUT="$(security/killswitch/killswitch_gate.sh evaluate-event "$det")"
assert_eq "B7 kill switch accepts the detection format" "True" "$(jget "$OUT" "d['ok']")"
assert_eq "B7 ... and only recommends (DRY_RUN, NOT_EXECUTED)" "revoke_test_session|DRY_RUN|NOT_EXECUTED" \
  "$(jget "$OUT" "d['record']['recommended_action']+'|'+d['record']['mode']+'|'+d['record']['execution_result']")"
assert_eq "B7 nothing contained" "0" "$(find "$TMP/ks/testenv" -name '*.contained' | wc -l | tr -d ' ')"

echo "[B8] static: detection never contains"
for f in $M/behavior_lib.py $M/behavior_monitor.py $M/snd_id_mock.py; do
  assert_eq "B8 $f imports/calls no kill-switch, network or process module (AST)" "" "$(python3 - "$f" <<'EOF'
import ast, sys
bad = {"subprocess", "socket", "urllib", "http", "killswitch_lib", "killswitch_io", "killswitch_policy", "ctypes"}
tree = ast.parse(open(sys.argv[1]).read())
hits = []
for n in ast.walk(tree):
    if isinstance(n, ast.Import):
        hits += [a.name for a in n.names if a.name.split(".")[0] in bad]
    elif isinstance(n, ast.ImportFrom) and (n.module or "").split(".")[0] in bad:
        hits.append(n.module)
    elif isinstance(n, ast.Attribute) and n.attr in ("system", "popen", "execv", "execvp", "spawnv"):
        hits.append(n.attr)
print(",".join(hits))
EOF
)"
done
assert_eq "B8 no __pycache__ left" "" "$(find $M -name __pycache__)"

echo
echo "=== Summary: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then printf '  - %s\n' "${FAILURES[@]}"; exit 1; fi
exit 0
