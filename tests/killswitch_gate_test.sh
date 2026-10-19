#!/bin/bash
set -uo pipefail

# tests/killswitch_gate_test.sh -- regression suite for the DuCoPA
# Independent Kill Switch (security/killswitch/). Every case runs
# against fixtures under a fresh mktemp directory OUTSIDE this
# repository: its own state/config/keyring/audit log and its own test
# environment. This deployment's real security/state/ and logs/ are
# never read or written (K40 checks that directly).
#
#   K1-K3    normal path: default DRY-RUN, --enforce-test, all 3 actions
#   K4-K7    authentication (signature, tampering, unknown issuer/key)
#   K8-K13   authorization / policy (authz, allowlists, production, AI origin)
#   K14-K17  input validation and freshness
#   K18-K19  duplicate commands, including a concurrent burst
#   K20-K24  failure handling: timeout, write failure, audit unavailable,
#            missing/invalid test environment, invalid configuration
#   K25-K28  independence: static guards, gate copied away from WAIO with
#            a fixture shutdown lock active, control plane removed after
#            containment, enforcement point fail-closed reads
#   K29-K35  SND@HOME/SND@ID events: DRY-RUN only, data minimization,
#            duplicates, rejection, no path into execution
#   K36-K40  audit chain, secrets absent from records, status, isolation

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"
export PYTHONDONTWRITEBYTECODE=1

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

assert_contains() {
  local label="$1" haystack="$2" needle="$3"
  if [[ "$haystack" == *"$needle"* ]]; then
    PASS=$((PASS + 1)); echo "  PASS: $label"
  else
    FAIL=$((FAIL + 1)); FAILURES+=("$label (expected to contain '$needle')")
    echo "  FAIL: $label (expected to contain '$needle', got: $haystack)"
  fi
}

assert_not_contains() {
  local label="$1" haystack="$2" needle="$3"
  if [[ "$haystack" != *"$needle"* ]]; then
    PASS=$((PASS + 1)); echo "  PASS: $label"
  else
    FAIL=$((FAIL + 1)); FAILURES+=("$label (must not contain '$needle')")
    echo "  FAIL: $label (must not contain '$needle')"
  fi
}

jget() { python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print($2)" <<<"$1" 2>/dev/null; }
code_only() { grep -vE '^[[:space:]]*#' "$1"; }

GATE="$SCRIPT_DIR/security/killswitch/killswitch_gate.sh"
SIGN="$SCRIPT_DIR/security/killswitch/killswitch_sign.py"
ENFORCE="$SCRIPT_DIR/security/killswitch/killswitch_enforce.py"

REAL_STATE_BEFORE="$( [ -e security/state/killswitch ] && echo present || echo absent ):$( [ -e logs/killswitch-audit.jsonl ] && echo present || echo absent )"

TMP="$(mktemp -d "${TMPDIR:-/tmp}/killswitch-test.XXXXXX")"
trap 'chmod -R u+rwx "$TMP" 2>/dev/null; rm -rf "$TMP"' EXIT

export KILLSWITCH_STATE_DIR="$TMP/state"
export KILLSWITCH_CONFIG_DIR="$TMP/config"
export KILLSWITCH_KEYRING_DIR="$TMP/config/keys"
export KILLSWITCH_AUDIT_LOG="$TMP/audit.jsonl"
export KILLSWITCH_AUDIT_CHECKPOINT="$TMP/state/.audit_checkpoint"
export KILLSWITCH_TEST_ENV="$TMP/testenv"
export WAIO_KILLSWITCH_NOW="2026-10-17T12:00:00Z"
ISSUED="2026-10-17T11:59:00Z"

mkdir -p "$TMP/config/keys" "$TMP/testenv" "$TMP/cmds"
printf 'environment=test\n' > "$TMP/testenv/.killswitch-test-env"
umask 077
cp security/killswitch/targets.conf.example "$TMP/config/targets.conf"
cp security/killswitch/authz.conf.example "$TMP/config/authz.conf"
chmod 600 "$TMP/config/targets.conf" "$TMP/config/authz.conf"
for k in operator-masa guardian-800 intruder; do
  python3 -c "import os,sys; open(sys.argv[1],'wb').write(os.urandom(32))" "$TMP/config/keys/$k.key"
  chmod 600 "$TMP/config/keys/$k.key"
done
OPKEY="$TMP/config/keys/operator-masa.key"
GOOD_REASON="test session shows a hijacked token; revoke it for the drill"

# sign NAME [extra signer args...] -- writes $TMP/cmds/NAME.json
sign() {
  local name="$1"; shift
  python3 "$SIGN" --issuer operator-masa --key-file "$OPKEY" --action revoke_test_session \
    --target test-session-001 --reason "$GOOD_REASON" --issued-at "$ISSUED" --command-id "$name" "$@" \
    > "$TMP/cmds/$name.json"
}
# run ARGS... -- sets OUT and RC
run() { OUT="$("$GATE" "$@" 2>/dev/null)"; RC=$?; }
check() { python3 "$ENFORCE" check "$1" "$2" "${3:-$TMP/testenv}" | python3 -c "import json,sys; print(json.load(sys.stdin)['verdict'])"; }
# redefines a key on the operator-masa signer for one command: sign_as ISSUER KEYFILE NAME [args...]
sign_as() {
  local issuer="$1" key="$2" name="$3"; shift 3
  python3 "$SIGN" --issuer "$issuer" --key-file "$key" --action revoke_test_session \
    --target test-session-001 --reason "$GOOD_REASON" --issued-at "$ISSUED" --command-id "$name" "$@" \
    > "$TMP/cmds/$name.json"
}

echo "[K1] default mode is DRY-RUN: a fully valid command executes nothing"
sign k1
run execute "$TMP/cmds/k1.json"
assert_eq "K1 exit 0" "0" "$RC"
assert_eq "K1 result DRY_RUN_NOT_EXECUTED" "DRY_RUN_NOT_EXECUTED" "$(jget "$OUT" "d['execution_result']")"
assert_eq "K1 mode DRY_RUN" "DRY_RUN" "$(jget "$OUT" "d['mode']")"
assert_eq "K1 no marker written" "false" "$([ -e "$TMP/testenv/sessions/test-session-001.contained" ] && echo true || echo false)"
assert_eq "K1 enforcement point still ALLOWs" "ALLOW" "$(check session test-session-001)"

echo "[K2] --enforce-test executes the same command on the test environment"
run execute "$TMP/cmds/k1.json" --enforce-test
assert_eq "K2 exit 0" "0" "$RC"
assert_eq "K2 result EXECUTED" "EXECUTED" "$(jget "$OUT" "d['execution_result']")"
assert_eq "K2 marker exists" "true" "$([ -f "$TMP/testenv/sessions/test-session-001.contained" ] && echo true || echo false)"
assert_eq "K2 enforcement point DENYs the revoked session" "DENY" "$(check session test-session-001)"
assert_eq "K2 an unrelated session is still allowed" "ALLOW" "$(check session test-session-002)"
for f in detection_reason event_id risk recommended_action execution_result decision code issuer origin; do
  assert_eq "K2 record has field $f" "True" "$(jget "$OUT" "'$f' in d")"
done
assert_eq "K2 record persisted under results/" "true" "$([ -f "$TMP/state/results/k1.json" ] && echo true || echo false)"

echo "[K3] the other two actions (block endpoint, isolate worker by the guardian issuer)"
sign k3a --action block_test_endpoint --target test-endpoint-api
run execute "$TMP/cmds/k3a.json" --enforce-test
assert_eq "K3a block_test_endpoint EXECUTED" "EXECUTED" "$(jget "$OUT" "d['execution_result']")"
assert_eq "K3a endpoint DENY" "DENY" "$(check endpoint test-endpoint-api)"
sign_as guardian-800 "$TMP/config/keys/guardian-800.key" k3b --action isolate_test_worker --target test-worker-echo --origin guardian
run execute "$TMP/cmds/k3b.json" --enforce-test
assert_eq "K3b isolate_test_worker by guardian EXECUTED" "EXECUTED" "$(jget "$OUT" "d['execution_result']")"
assert_eq "K3b worker DENY" "DENY" "$(check worker test-worker-echo)"

echo "[K4-K7] unauthenticated commands are refused before any policy check"
sign k4
python3 -c "import json,sys; p=sys.argv[1]; d=json.load(open(p)); d['signature']='0'*64; json.dump(d,open(p,'w'))" "$TMP/cmds/k4.json"
run execute "$TMP/cmds/k4.json" --enforce-test
assert_eq "K4 forged signature exit 2" "2" "$RC"
assert_eq "K4 DENIED_UNAUTHENTICATED" "DENIED_UNAUTHENTICATED" "$(jget "$OUT" "d['code']")"
sign k5 --target test-session-001
python3 -c "import json,sys; p=sys.argv[1]; d=json.load(open(p)); d['target_id']='test-session-002'; json.dump(d,open(p,'w'))" "$TMP/cmds/k5.json"
run execute "$TMP/cmds/k5.json" --enforce-test
assert_eq "K5 field changed after signing -> DENIED_UNAUTHENTICATED" "DENIED_UNAUTHENTICATED" "$(jget "$OUT" "d['code']")"
assert_eq "K5 nothing contained for the substituted target" "ALLOW" "$(check session test-session-002)"
sign_as nobody "$OPKEY" k6
run execute "$TMP/cmds/k6.json" --enforce-test
assert_eq "K6 issuer with no key -> DENIED_UNAUTHENTICATED" "DENIED_UNAUTHENTICATED" "$(jget "$OUT" "d['code']")"
sign_as guardian-800 "$OPKEY" k7 --action isolate_test_worker --target test-worker-echo
run execute "$TMP/cmds/k7.json" --enforce-test
assert_eq "K7 signed with another issuer's key -> DENIED_UNAUTHENTICATED" "DENIED_UNAUTHENTICATED" "$(jget "$OUT" "d['code']")"

echo "[K8-K13] authorization and policy"
sign_as guardian-800 "$TMP/config/keys/guardian-800.key" k8
run execute "$TMP/cmds/k8.json" --enforce-test
assert_eq "K8 issuer not authorized for the action -> DENIED_UNAUTHORIZED" "DENIED_UNAUTHORIZED" "$(jget "$OUT" "d['code']")"
sign_as intruder "$TMP/config/keys/intruder.key" k9
run execute "$TMP/cmds/k9.json" --enforce-test
assert_eq "K9 valid key without any authz line -> DENIED_UNAUTHORIZED" "DENIED_UNAUTHORIZED" "$(jget "$OUT" "d['code']")"
sign k10 --target test-session-999
run execute "$TMP/cmds/k10.json" --enforce-test
assert_eq "K10 target not allowlisted" "DENIED_TARGET_NOT_ALLOWLISTED" "$(jget "$OUT" "d['code']")"
for a in shutdown_waio block_production_traffic rotate_keys cloudflare_dns_change exec_shell; do
  sign "k11-$a" --action "$a"
  run execute "$TMP/cmds/k11-$a.json" --enforce-test
  assert_eq "K11 dangerous/unknown action '$a' refused" "DENIED_ACTION_NOT_ALLOWLISTED" "$(jget "$OUT" "d['code']")"
done
for e in production prod staging; do
  sign "k12-$e" --environment "$e"
  run execute "$TMP/cmds/k12-$e.json" --enforce-test
  assert_eq "K12 environment '$e' refused" "DENIED_PRODUCTION" "$(jget "$OUT" "d['code']")"
done
for o in ai decision_engine waio_ai llm; do
  sign "k13-$o" --origin "$o"
  run execute "$TMP/cmds/k13-$o.json" --enforce-test
  assert_eq "K13 AI-originated command ('$o') refused" "DENIED_AI_ORIGIN" "$(jget "$OUT" "d['code']")"
done
sign k13-other --origin "random_script"
run execute "$TMP/cmds/k13-other.json" --enforce-test
assert_eq "K13 unknown origin refused" "DENIED_ORIGIN" "$(jget "$OUT" "d['code']")"
assert_eq "K8-K13 no endpoint/worker/session marker was added by any refused command" "3" "$(find "$TMP/testenv" -name '*.contained' | wc -l | tr -d ' ')"

echo "[K14-K17] input validation and freshness"
sign k14a --target "../../etc/passwd"
run execute "$TMP/cmds/k14a.json" --enforce-test
assert_eq "K14 path traversal target -> DENIED_INVALID_INPUT" "DENIED_INVALID_INPUT" "$(jget "$OUT" "d['code']")"
sign k14b --target 'x;rm -rf /'
run execute "$TMP/cmds/k14b.json" --enforce-test
assert_eq "K14 shell metacharacters -> DENIED_INVALID_INPUT" "DENIED_INVALID_INPUT" "$(jget "$OUT" "d['code']")"
sign k15a
python3 -c "import json,sys; p=sys.argv[1]; d=json.load(open(p)); d['run']='rm -rf /'; json.dump(d,open(p,'w'))" "$TMP/cmds/k15a.json"
run execute "$TMP/cmds/k15a.json" --enforce-test
assert_eq "K15 extra field -> DENIED_INVALID_INPUT" "DENIED_INVALID_INPUT" "$(jget "$OUT" "d['code']")"
printf 'not json' > "$TMP/cmds/k15b.json"
run execute "$TMP/cmds/k15b.json" --enforce-test
assert_eq "K15 non-JSON -> DENIED_INVALID_INPUT" "DENIED_INVALID_INPUT" "$(jget "$OUT" "d['code']")"
python3 -c "import sys; open(sys.argv[1],'w').write('{\"a\":\"' + 'x'*9000 + '\"}')" "$TMP/cmds/k15c.json"
run execute "$TMP/cmds/k15c.json" --enforce-test
assert_eq "K15 oversize command -> DENIED_INVALID_INPUT" "DENIED_INVALID_INPUT" "$(jget "$OUT" "d['code']")"
run execute "$TMP/cmds/does-not-exist.json" --enforce-test
assert_eq "K15 missing command file -> exit 2" "2" "$RC"
sign k16 --reason "aaaaaaaaaaaaaaaaaaaaaaaaa"
run execute "$TMP/cmds/k16.json" --enforce-test
assert_eq "K16 low-variety reason -> DENIED_INVALID_INPUT" "DENIED_INVALID_INPUT" "$(jget "$OUT" "d['code']")"
sign k17a --issued-at "2026-10-17T11:00:00Z"
run execute "$TMP/cmds/k17a.json" --enforce-test
assert_eq "K17 1h-old command -> DENIED_STALE" "DENIED_STALE" "$(jget "$OUT" "d['code']")"
sign k17b --issued-at "2026-10-17T12:30:00Z"
run execute "$TMP/cmds/k17b.json" --enforce-test
assert_eq "K17 future-dated command -> DENIED_STALE" "DENIED_STALE" "$(jget "$OUT" "d['code']")"

echo "[K18] a duplicate command is never executed twice"
before="$(cat "$TMP/testenv/sessions/test-session-001.contained")"
run execute "$TMP/cmds/k1.json" --enforce-test
assert_eq "K18 exit 0 (idempotent)" "0" "$RC"
assert_eq "K18 DUPLICATE_IGNORED" "DUPLICATE_IGNORED" "$(jget "$OUT" "d['execution_result']")"
assert_eq "K18 marker untouched" "$before" "$(cat "$TMP/testenv/sessions/test-session-001.contained")"
assert_contains "K18 duplicate audited" "$(cat "$TMP/audit.jsonl")" "killswitch_command_duplicate"
cp "$TMP/cmds/k1.json" "$TMP/cmds/k18b.json"
python3 -c "import json,sys; p=sys.argv[1]; d=json.load(open(p)); d['signature']='f'*64; json.dump(d,open(p,'w'))" "$TMP/cmds/k18b.json"
run execute "$TMP/cmds/k18b.json" --enforce-test
assert_eq "K18b forged command reusing an executed id is DENIED" "DENIED_UNAUTHENTICATED" "$(jget "$OUT" "d['code']")"
assert_eq "K18b ...and cannot overwrite the real result record" "EXECUTED" "$(jget "$(cat "$TMP/state/results/k1.json")" "d['execution_result']")"

echo "[K19] concurrent burst of the same new command: exactly one execution"
printf 'revoke_test_session|test-session-burst|test\n' >> "$TMP/config/targets.conf"
sign k19 --target test-session-burst
for i in 1 2 3 4 5 6; do "$GATE" execute "$TMP/cmds/k19.json" --enforce-test > "$TMP/k19.$i.out" 2>/dev/null & done
wait
executed="$(cat "$TMP"/k19.*.out | grep -c '"execution_result": "EXECUTED"')"
dups="$(cat "$TMP"/k19.*.out | grep -c '"execution_result": "DUPLICATE_IGNORED"')"
assert_eq "K19 exactly one EXECUTED" "1" "$executed"
assert_eq "K19 the other five DUPLICATE_IGNORED" "5" "$dups"

echo "[K20] containment that does not complete in time is FAILED_TIMEOUT, never success"
printf 'block_test_endpoint|test-endpoint-hang|test\n' >> "$TMP/config/targets.conf"
mkfifo "$TMP/testenv/endpoints/.test-endpoint-hang.tmp"
sign k20 --action block_test_endpoint --target test-endpoint-hang
OUT="$(KILLSWITCH_ACTION_TIMEOUT=2 "$GATE" execute "$TMP/cmds/k20.json" --enforce-test 2>/dev/null)"; RC=$?
assert_eq "K20 exit 1" "1" "$RC"
assert_eq "K20 FAILED_TIMEOUT" "FAILED_TIMEOUT" "$(jget "$OUT" "d['execution_result']")"
assert_eq "K20 no marker claimed" "false" "$([ -e "$TMP/testenv/endpoints/test-endpoint-hang.contained" ] && echo true || echo false)"
run execute "$TMP/cmds/k20.json" --enforce-test
assert_eq "K20 re-sending the same id is not re-executed (replay safe)" "DUPLICATE_IGNORED" "$(jget "$OUT" "d['execution_result']")"
rm -f "$TMP/testenv/endpoints/.test-endpoint-hang.tmp"

echo "[K21] a failed marker write is FAILED with exit 1"
printf 'isolate_test_worker|test-worker-ro|test\n' >> "$TMP/config/targets.conf"
chmod 500 "$TMP/testenv/workers"
sign k21 --action isolate_test_worker --target test-worker-ro
run execute "$TMP/cmds/k21.json" --enforce-test
assert_eq "K21 exit 1" "1" "$RC"
assert_eq "K21 FAILED" "FAILED" "$(jget "$OUT" "d['execution_result']")"
chmod 700 "$TMP/testenv/workers"
run status
assert_contains "K21 status lists the failed containment" "$(jget "$OUT" "d['containment_failed']")" "test-worker-ro"
assert_contains "K20 status lists the timed-out containment" "$(jget "$OUT" "d['containment_failed']")" "FAILED_TIMEOUT"

echo "[K22] audit log unavailable before an action: not executed"
printf 'revoke_test_session|test-session-noaudit|test\n' >> "$TMP/config/targets.conf"
mkdir -p "$TMP/audit-is-a-dir"
sign k22 --target test-session-noaudit
OUT="$(KILLSWITCH_AUDIT_LOG="$TMP/audit-is-a-dir" "$GATE" execute "$TMP/cmds/k22.json" --enforce-test 2>/dev/null)"; RC=$?
assert_eq "K22 exit 1" "1" "$RC"
assert_eq "K22 FAILED_NO_PERSISTENCE" "FAILED_NO_PERSISTENCE" "$(jget "$OUT" "d['execution_result']")"
assert_eq "K22 no marker" "ALLOW" "$(check session test-session-noaudit)"

echo "[K23] test environment must be declared, marked and outside the repo"
sign k23
OUT="$(KILLSWITCH_TEST_ENV= "$GATE" execute "$TMP/cmds/k23.json" --enforce-test 2>/dev/null)"
assert_eq "K23 unset test env -> DENIED_NO_TEST_ENV" "DENIED_NO_TEST_ENV" "$(jget "$OUT" "d['code']")"
mkdir -p "$TMP/unmarked"
OUT="$(KILLSWITCH_TEST_ENV="$TMP/unmarked" "$GATE" execute "$TMP/cmds/k23.json" --enforce-test 2>/dev/null)"
assert_eq "K23 unmarked dir -> DENIED_NO_TEST_ENV" "DENIED_NO_TEST_ENV" "$(jget "$OUT" "d['code']")"
OUT="$(KILLSWITCH_TEST_ENV="$SCRIPT_DIR/security" "$GATE" execute "$TMP/cmds/k23.json" --enforce-test 2>/dev/null)"
assert_eq "K23 dir inside the repo -> DENIED_NO_TEST_ENV" "DENIED_NO_TEST_ENV" "$(jget "$OUT" "d['code']")"
assert_contains "K23 reason names the repository" "$(jget "$OUT" "d['detail']")" "outside the WAIO repository"

echo "[K24] configuration problems refuse everything"
OUT="$(KILLSWITCH_CONFIG_DIR="$TMP/empty-config" "$GATE" execute "$TMP/cmds/k23.json" --enforce-test 2>/dev/null)"
assert_eq "K24 no config -> DENIED_NOT_CONFIGURED" "DENIED_NOT_CONFIGURED" "$(jget "$OUT" "d['code']")"
mkdir -p "$TMP/badcfg"; cp "$TMP/config/authz.conf" "$TMP/badcfg/"
printf 'revoke_test_session|test-session-001|test\nblock_test_endpoint|prod-api|production\n' > "$TMP/badcfg/targets.conf"
chmod 600 "$TMP/badcfg/"*
OUT="$(KILLSWITCH_CONFIG_DIR="$TMP/badcfg" "$GATE" execute "$TMP/cmds/k23.json" --enforce-test 2>/dev/null)"
assert_eq "K24 a production line poisons the whole allowlist" "DENIED_CONFIG_INVALID" "$(jget "$OUT" "d['code']")"
chmod 644 "$TMP/config/targets.conf"
run execute "$TMP/cmds/k23.json" --enforce-test
assert_eq "K24 world-readable config refused" "DENIED_CONFIG_INVALID" "$(jget "$OUT" "d['code']")"
chmod 600 "$TMP/config/targets.conf"
chmod 644 "$OPKEY"
run execute "$TMP/cmds/k23.json" --enforce-test
assert_eq "K24 world-readable key refused" "DENIED_KEY_INSECURE" "$(jget "$OUT" "d['code']")"
chmod 600 "$OPKEY"

echo "[K25] static independence guards (code lines only)"
for f in security/killswitch/killswitch_gate.sh security/killswitch/killswitch_io.py security/killswitch/killswitch_lib.py security/killswitch/killswitch_enforce.py; do
  assert_eq "K25 $f references no WAIO control-plane file/state" "" \
    "$(code_only "$f" | grep -nE '(^|[^a-z])lib\.sh|guardian[a-z_]*\.sh|GUARDIAN_STATE|ducopa\.sh|DUCOPA_STATE|decision_engine(\.sh|_lib|/)|waio\.sh|recover\.sh|SHUTDOWN\.lock|WAIO_SHUTDOWN_LOCK|orchestrate_worker|registry\.conf')"
  assert_eq "K25 $f uses no network/system-control tool" "" \
    "$(code_only "$f" | grep -nE '\b(curl|wget|scp|cloudflared|pfctl|networksetup|launchctl|osascript|sudo)\b|\bssh[[:space:]]|\bnc[[:space:]]|urllib|http\.client|socket')"
done
assert_eq "K25 the gate sources nothing" "" "$(code_only security/killswitch/killswitch_gate.sh | grep -nE '^[[:space:]]*(source|\.)[[:space:]]')"
assert_eq "K25 enforcement point imports no kill-switch module" "" "$(code_only security/killswitch/killswitch_enforce.py | grep -nE 'import killswitch|from killswitch')"

echo "[K26] the gate works with WAIO absent and stopped (directory copied away, fixture shutdown lock active)"
mkdir -p "$TMP/iso/security"
cp -R security/killswitch "$TMP/iso/security/killswitch"
printf 'revoke_test_session|test-session-iso|test\n' >> "$TMP/config/targets.conf"
printf 'triggered_at: fixture\n' > "$TMP/fixture-SHUTDOWN.lock"
printf 'SHUTDOWN\n' > "$TMP/fixture-GUARDIAN_STATE"
sign k26 --target test-session-iso
OUT="$(WAIO_SHUTDOWN_LOCK="$TMP/fixture-SHUTDOWN.lock" WAIO_GUARDIAN_STATE_FILE="$TMP/fixture-GUARDIAN_STATE" \
  "$TMP/iso/security/killswitch/killswitch_gate.sh" execute "$TMP/cmds/k26.json" --enforce-test 2>/dev/null)"; RC=$?
assert_eq "K26 isolated copy has no waio.sh/lib.sh/guardian.sh next to it" "0" "$(find "$TMP/iso" -name 'waio.sh' -o -name 'lib.sh' -o -name 'guardian.sh' | wc -l | tr -d ' ')"
assert_eq "K26 EXECUTED with WAIO stopped" "EXECUTED" "$(jget "$OUT" "d['execution_result']")"
assert_eq "K26 exit 0" "0" "$RC"

echo "[K27] control plane removed after containment: containment stays in force"
mkdir -p "$TMP/pep"; cp "$TMP/iso/security/killswitch/killswitch_enforce.py" "$TMP/pep/"
rm -rf "$TMP/iso"
assert_eq "K27 gate gone" "false" "$([ -e "$TMP/iso" ] && echo true || echo false)"
assert_eq "K27 contained session still DENY via the standalone enforcement point" "DENY" \
  "$(python3 "$TMP/pep/killswitch_enforce.py" check session test-session-iso "$TMP/testenv" | python3 -c "import json,sys; print(json.load(sys.stdin)['verdict'])")"

echo "[K28] enforcement point fails closed on unreadable/corrupt state"
mkdir -p "$TMP/env2/sessions"; printf 'environment=test\n' > "$TMP/env2/.killswitch-test-env"
printf '{broken' > "$TMP/env2/sessions/s1.contained"
assert_eq "K28 corrupt marker -> DENY" "DENY" "$(check session s1 "$TMP/env2")"
printf '{"target_id": "other"}' > "$TMP/env2/sessions/s2.contained"
assert_eq "K28 marker for another id -> DENY" "DENY" "$(check session s2 "$TMP/env2")"
mkdir -p "$TMP/env2/endpoints"; chmod 000 "$TMP/env2/endpoints"
assert_eq "K28 unreadable state dir -> DENY" "DENY" "$(check endpoint e1 "$TMP/env2")"
chmod 700 "$TMP/env2/endpoints"
printf 'x' > "$TMP/env2/workers"
assert_eq "K28 state path not a directory -> DENY" "DENY" "$(check worker w1 "$TMP/env2")"
assert_eq "K28 invalid id -> DENY" "DENY" "$(check session '../x' "$TMP/env2")"
rm -f "$TMP/env2/.killswitch-test-env"
assert_eq "K28 not a declared test env -> DENY" "DENY" "$(check session s9 "$TMP/env2")"
assert_eq "K28 clean session in a valid env -> ALLOW" "ALLOW" "$(check session clean-1)"

echo "[K29] SND@HOME event -> recommendation only (DRY-RUN), nothing contained"
printf 'revoke_test_session|test-session-snd|test\n' >> "$TMP/config/targets.conf"
cat > "$TMP/ev1.json" <<'EOF'
{"source": "snd_home", "event_id": "snd-evt-0001", "type": "session_hijack", "severity": "critical",
 "target_ref": "test-session-snd", "observed_at": "2026-10-17T11:58:00Z", "message": "token reuse from two locations"}
EOF
markers_before="$(find "$TMP/testenv" -name '*.contained' | sort)"
run evaluate-event "$TMP/ev1.json"
assert_eq "K29 exit 0" "0" "$RC"
assert_eq "K29 recommended revoke_test_session" "revoke_test_session" "$(jget "$OUT" "d['record']['recommended_action']")"
assert_eq "K29 risk CRITICAL" "CRITICAL" "$(jget "$OUT" "d['record']['risk']")"
assert_eq "K29 mode DRY_RUN" "DRY_RUN" "$(jget "$OUT" "d['record']['mode']")"
assert_eq "K29 execution_result NOT_EXECUTED" "NOT_EXECUTED" "$(jget "$OUT" "d['record']['execution_result']")"
assert_eq "K29 target recognized as allowlisted" "True" "$(jget "$OUT" "d['record']['target_allowlisted']")"
for f in detection_reason event_id risk recommended_action execution_result; do
  assert_eq "K29 record has field $f" "True" "$(jget "$OUT" "'$f' in d['record']")"
done
assert_eq "K29 no marker created by detection" "$markers_before" "$(find "$TMP/testenv" -name '*.contained' | sort)"
assert_eq "K29 the session is still allowed" "ALLOW" "$(check session test-session-snd)"

echo "[K30] data minimization: secrets, addresses and extra fields are not kept"
cat > "$TMP/ev2.json" <<'EOF'
{"source": "snd_home", "id": "snd-evt-0002", "category": "c2_beacon", "level": "high",
 "message": "beacon from 192.168.1.77 aa:bb:cc:dd:ee:ff password=hunter2hunter2 AKIAABCDEFGHIJKLMNOP",
 "headers": {"Authorization": "Bearer SECRETBEARERTOKEN123"}, "payload": "raw-packet-bytes"}
EOF
run evaluate-event "$TMP/ev2.json"
rec="$(jget "$OUT" "d['record']")"
assert_eq "K30 alias fields normalized (category -> recommended block)" "block_test_endpoint" "$(jget "$OUT" "d['record']['recommended_action']")"
for needle in 192.168.1.77 aa:bb:cc:dd:ee:ff hunter2hunter2 AKIAABCDEFGHIJKLMNOP SECRETBEARERTOKEN123 raw-packet-bytes Authorization; do
  assert_not_contains "K30 record omits '$needle'" "$rec" "$needle"
  assert_not_contains "K30 audit log omits '$needle'" "$(cat "$TMP/audit.jsonl")" "$needle"
  assert_not_contains "K30 stored event omits '$needle'" "$(cat "$TMP/state/events/snd-evt-0002/record.json")" "$needle"
done

echo "[K31-K34] event duplicates, rejection, low risk, SND@ID"
run evaluate-event "$TMP/ev1.json"
assert_eq "K31 same event id again -> duplicate true" "True" "$(jget "$OUT" "d['duplicate']")"
printf '{"source": "unknown_feed", "event_id": "x1", "type": "c2_beacon", "severity": "critical"}' > "$TMP/ev3.json"
run evaluate-event "$TMP/ev3.json"
assert_eq "K32 unknown source -> exit 2" "2" "$RC"
printf '{"source": "snd_home", "event_id": "../../x", "type": "c2_beacon"}' > "$TMP/ev4.json"
run evaluate-event "$TMP/ev4.json"
assert_eq "K32 invalid event id -> exit 2" "2" "$RC"
printf '{"source": "snd_home", "event_id": "snd-evt-low", "type": "c2_beacon", "severity": "low"}' > "$TMP/ev5.json"
run evaluate-event "$TMP/ev5.json"
assert_eq "K33 low severity -> MONITOR" "MONITOR" "$(jget "$OUT" "d['record']['recommended_action']")"
printf '{"source": "snd_id", "alertId": "sndid-77", "event_type": "impossible_travel", "severity": "high", "test_target": "test-session-001"}' > "$TMP/ev6.json"
run evaluate-event "$TMP/ev6.json"
assert_eq "K34 SND@ID event normalized" "snd_id|sndid-77|revoke_test_session|HIGH" \
  "$(jget "$OUT" "'|'.join([d['record']['source'], d['record']['event_id'], d['record']['recommended_action'], d['record']['risk']])")"

echo "[K35] structural: the event path has no route into execution"
body="$(sed -n '/^ks_evaluate_event() {/,/^}/p' security/killswitch/killswitch_gate.sh)"
assert_not_contains "K35 evaluate-event never calls effect" "$body" "effect"
assert_not_contains "K35 evaluate-event never calls ks_execute" "$body" "ks_execute"
assert_eq "K35 lib has no event->command converter (evaluate_event output carries no signature)" "False" \
  "$(jget "$(cat "$TMP/state/events/snd-evt-0001/record.json")" "'signature' in d")"

echo "[K36-K37] audit chain and secrecy of keys/signatures"
run verify-audit
assert_eq "K36 audit chain verifies" "ok" "$OUT"
sig="$(jget "$(cat "$TMP/cmds/k1.json")" "d['signature']")"
keyhex="$(python3 -c "import sys; print(open(sys.argv[1],'rb').read().hex())" "$OPKEY")"
assert_not_contains "K37 audit log never contains a command signature" "$(cat "$TMP/audit.jsonl")" "$sig"
assert_not_contains "K37 audit log never contains key material" "$(cat "$TMP/audit.jsonl")" "$keyhex"
assert_not_contains "K37 results never contain a command signature" "$(cat "$TMP"/state/results/*.json)" "$sig"
cp "$TMP/audit.jsonl" "$TMP/audit.bak"; cp "$TMP/state/.audit_checkpoint" "$TMP/cp.bak"
sed -i.sed 's/EXECUTED/EXECUTEX/' "$TMP/audit.jsonl"
run verify-audit
assert_contains "K36 tampering detected" "$OUT" "broken:"
cp "$TMP/audit.bak" "$TMP/audit.jsonl"; cp "$TMP/cp.bak" "$TMP/state/.audit_checkpoint"

echo "[K38-K39] status and usage"
run status
assert_eq "K38 default mode reported DRY_RUN" "DRY_RUN" "$(jget "$OUT" "d['default_mode']")"
assert_eq "K38 configured" "True" "$(jget "$OUT" "d['configured']")"
assert_eq "K38 audit integrity ok" "ok" "$(jget "$OUT" "d['audit_integrity']")"
run bogus-verb
assert_eq "K39 unknown verb exit 2" "2" "$RC"

echo "[K40] this deployment's real state was never touched"
REAL_STATE_AFTER="$( [ -e security/state/killswitch ] && echo present || echo absent ):$( [ -e logs/killswitch-audit.jsonl ] && echo present || echo absent )"
assert_eq "K40 real security/state/killswitch and logs/killswitch-audit.jsonl unchanged" "$REAL_STATE_BEFORE" "$REAL_STATE_AFTER"
assert_eq "K40 no __pycache__ left in the module dir" "false" "$([ -d security/killswitch/__pycache__ ] && echo true || echo false)"

echo ""
echo "=== Summary: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
  echo "Failures:"
  for f in "${FAILURES[@]}"; do echo "  - $f"; done
  exit 1
fi
exit 0
