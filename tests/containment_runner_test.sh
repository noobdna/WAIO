#!/bin/bash
# tests/containment_runner_test.sh -- regression suite for
# security/containment_runner/containment_runner.sh (quarantine-only,
# dry run by default, not wired into any LaunchAgent).
#
# Runs entirely inside an e2e sandbox (tests/e2e/lib_env.sh): the REAL
# Shadow AI -> Attack Graph -> Intelligence -> Decision Engine chain on
# fixture telemetry produces the decision report, and every Guardian,
# audit, lock and runner path is redirected into the sandbox. This
# machine's real security/state/ and logs/ are never touched; the only
# processes started are this suite's own children.
#
# Series:
#   M  modes: dry run is the default; --execute without the env opt-in is refused
#   X  execution: contained + verified; repeat is a no-op
#   U  unauthorized actions refused: no rule, bad signature, expired, shutdown,
#      unregistered target, policy/key file permissions, malformed inputs
#   B  repeated alerts are bounded: per-rule budget, global hourly limit
#   G  guard rails: kill switch, overlap lock, bounded action (timeout)
#   S  static: not wired into production, never calls a shutdown path
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR" || exit 1
RUNNER=./security/containment_runner/containment_runner.sh

PASS=0; FAIL=0; FAILURES=()
assert_eq() { if [ "$2" = "$3" ]; then PASS=$((PASS + 1)); echo "  PASS: $1"; else FAIL=$((FAIL + 1)); FAILURES+=("$1 (expected='$2' actual='$3')"); echo "  FAIL: $1 (expected='$2' actual='$3')"; fi; }
assert_contains() { case "$2" in *"$3"*) PASS=$((PASS + 1)); echo "  PASS: $1" ;; *) FAIL=$((FAIL + 1)); FAILURES+=("$1 (missing '$3')"); echo "  FAIL: $1 (missing '$3' in: $(printf '%s' "$2" | head -c 300))" ;; esac; }

ROOT="$(mktemp -d "${TMPDIR:-/tmp}/waio-runner-test.XXXXXX")"
trap 'rm -rf "${ROOT:?}"' EXIT
D="$ROOT/sb"; mkdir -p "$D"
REAL_HOME="$HOME"   # lib_env points HOME at the sandbox; S1 checks the real LaunchAgents dir
# shellcheck source=tests/e2e/lib_env.sh
source tests/e2e/lib_env.sh
e2e_sandbox_init "$D" && e2e_write_detection_fixture "$D" anomaly || { echo "sandbox setup failed"; exit 1; }
e2e_detect_to_decision "$D" || { echo "detect -> decide failed"; cat "$D/run/stderr.log"; exit 1; }
REPORT="$D/run/decisions.json"
# Operator key pair: the PRIVATE key stays in $ROOT/operator (outside the
# sandbox the runner sees); the runner only gets the PUBLIC key.
mkdir -p "$ROOT/operator"; chmod 700 "$ROOT/operator"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$ROOT/operator/signing.pem" 2>/dev/null
openssl pkey -in "$ROOT/operator/signing.pem" -pubout -out "$D/keys/policy.pub.pem" 2>/dev/null
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$ROOT/operator/other.pem" 2>/dev/null
export WAIO_CONTAINMENT_POLICY_PUBKEY="$D/keys/policy.pub.pem"
FUTURE="$(python3 -c 'import datetime; print((datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"))')"
PAST="2020-01-01T00:00:00Z"

assert_eq "setup: the real decision chain recommends containment for rogue-agent" "RECOMMEND_CONTAINMENT" \
  "$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(next(x["recommended_action"] for x in d["decisions"] if x["entity"]=="rogue-agent"))' "$REPORT")"

# fresh NAME -- a clean runner state dir and quarantine list for one scenario.
fresh() {
  export WAIO_CONTAINMENT_RUNNER_STATE_DIR="$D/state/runner-$1"
  export WAIO_GUARDIAN_QUARANTINE_FILE="$D/state/QUARANTINE-$1"
  rm -rf "$WAIO_CONTAINMENT_RUNNER_STATE_DIR" "$WAIO_GUARDIAN_QUARANTINE_FILE"
  unset WAIO_CONTAINMENT_RUNNER_EXECUTE WAIO_CONTAINMENT_RUNNER_MAX_PER_HOUR WAIO_CONTAINMENT_RUNNER_ACTION_TIMEOUT
}
# policy FILE ACTION EXPIRES [MAX] [RULE_ID] [ENTITY] [PRIVATE_KEY] -- a one-rule
# policy signed with openssl directly (any action, so U4 can prove the
# runner itself refuses a validly signed shutdown rule), mode 0600.
policy() {
  python3 - "$1" "$2" "$3" "${4:-1000}" "${5:-rule-test}" "${6:-rogue-agent}" "${7:-$ROOT/operator/signing.pem}" <<'PYEOF'
import base64, json, os, subprocess, sys
path, action, expires, max_exec, rule_id, entity, priv = sys.argv[1:8]
rule = {"rule_id": rule_id, "entity": entity, "action": action, "approved_by": "test-operator (fixture)",
        "reason": "pre-approved narrow test rule", "expires_at": expires, "max_executions": int(max_exec)}
sig = subprocess.run(["openssl", "dgst", "-sha256", "-sign", priv], input=json.dumps(rule, sort_keys=True).encode(), capture_output=True, check=True).stdout
rule["signature"] = "rsa-sha256:" + base64.b64encode(sig).decode()
json.dump({"version": 2, "rules": [rule]}, open(path, "w"))
PYEOF
  chmod 600 "$1"
}
quarantined() { [ -f "$WAIO_GUARDIAN_QUARANTINE_FILE" ] && grep -Fxq "$1" "$WAIO_GUARDIAN_QUARANTINE_FILE" && echo yes || echo no; }
variant() {  # variant N -> a copy of the report with a different hash (a new alert for the same entity)
  python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); d["alert_seq"]=int(sys.argv[2]); json.dump(d, open(sys.argv[3],"w"))' "$REPORT" "$1" "$D/run/decisions-$1.json"
  echo "$D/run/decisions-$1.json"
}
POL="$D/fixtures/policy.json"

echo "[M1] default is a dry run: the recommendation is authorized and planned, nothing changes, the plan is audited"
fresh m1; policy "$POL" quarantine_agent:ECHO "$FUTURE"
OUT="$($RUNNER run --report "$REPORT" --policy "$POL")"; RC=$?
assert_eq "M1 exit 0" "0" "$RC"
assert_contains "M1 outcome planned" "$OUT" '"outcome": "planned"'
assert_contains "M1 mode dry_run" "$OUT" '"mode": "dry_run"'
assert_eq "M1 ECHO not quarantined" "no" "$(quarantined ECHO)"
assert_contains "M1 dry run audited" "$(cat "$WAIO_AUDIT_LOG")" "containment_runner_dry_run"

echo "[M2] --execute without WAIO_CONTAINMENT_RUNNER_EXECUTE=1 is refused (exit 2) and does nothing"
fresh m2; policy "$POL" quarantine_agent:ECHO "$FUTURE"
$RUNNER run --report "$REPORT" --policy "$POL" --execute >/dev/null 2>&1; RC=$?
assert_eq "M2 exit 2" "2" "$RC"
assert_eq "M2 ECHO not quarantined" "no" "$(quarantined ECHO)"

echo "[X1] execute with both opt-ins and a valid signed rule: ECHO quarantined, verified, audited, budgets counted"
fresh x1; policy "$POL" quarantine_agent:ECHO "$FUTURE"
OUT="$(WAIO_CONTAINMENT_RUNNER_EXECUTE=1 $RUNNER run --report "$REPORT" --policy "$POL" --execute)"; RC=$?
assert_eq "X1 exit 0" "0" "$RC"
assert_contains "X1 outcome contained" "$OUT" '"outcome": "contained"'
assert_eq "X1 ECHO quarantined" "yes" "$(quarantined ECHO)"
assert_contains "X1 output names the human release command" "$OUT" "guardian_release_agent.sh ECHO --confirm"
assert_eq "X1 rule ledger 1" "1" "$(cat "$WAIO_CONTAINMENT_RUNNER_STATE_DIR/ledger/rule-test")"
assert_eq "X1 one execution logged" "1" "$(wc -l < "$WAIO_CONTAINMENT_RUNNER_STATE_DIR/executions.log" | tr -d ' ')"
assert_contains "X1 contained audited" "$(cat "$WAIO_AUDIT_LOG")" "containment_runner_contained"

echo "[X2] the same report again is a no-op (idempotent): no second execution"
OUT="$(WAIO_CONTAINMENT_RUNNER_EXECUTE=1 $RUNNER run --report "$REPORT" --policy "$POL" --execute)"; RC=$?
assert_eq "X2 exit 0" "0" "$RC"
assert_contains "X2 outcome duplicate" "$OUT" '"outcome": "duplicate"'
assert_eq "X2 still one execution logged" "1" "$(wc -l < "$WAIO_CONTAINMENT_RUNNER_STATE_DIR/executions.log" | tr -d ' ')"

echo "[X3] recovery stays human: guardian_release_agent.sh with a confirmation reason releases ECHO"
./security/guardian_release_agent.sh ECHO --confirm "containment runner test: fixture quarantine released after verification" >/dev/null 2>&1; RC=$?
assert_eq "X3 release exit 0" "0" "$RC"
assert_eq "X3 ECHO no longer quarantined" "no" "$(quarantined ECHO)"

# run_refused NAME -> runs execute mode against $POL and asserts refusal + nothing quarantined
run_refused() {
  local name="$1" want="$2" out rc
  out="$(WAIO_CONTAINMENT_RUNNER_EXECUTE=1 $RUNNER run --report "${3:-$REPORT}" --policy "$POL" --execute)"; rc=$?
  assert_eq "$name exit 3" "3" "$rc"
  assert_contains "$name outcome refused" "$out" '"outcome": "refused"'
  assert_contains "$name reason" "$out" "$want"
  assert_eq "$name nothing quarantined" "no" "$(quarantined ECHO)"
  [ -e "$WAIO_SHUTDOWN_LOCK" ] && assert_eq "$name no shutdown lock" "absent" "present"
  return 0
}

echo "[U1] no rule for this exact entity -> refused"
fresh u1; policy "$POL" quarantine_agent:ECHO "$FUTURE" 1000 rule-other some-other-agent
run_refused U1 "no pre-approved policy rule"

echo "[U2] rule tampered after signing (action changed) -> signature invalid"
fresh u2; policy "$POL" quarantine_agent:ECHO "$FUTURE"
python3 -c 'import json,sys; p=json.load(open(sys.argv[1])); p["rules"][0]["action"]="quarantine_agent:ANALYSIS"; json.dump(p, open(sys.argv[1],"w"))' "$POL"
run_refused U2 "signature invalid"

echo "[U3] expired rule -> refused"
fresh u3; policy "$POL" quarantine_agent:ECHO "$PAST"
run_refused U3 "expired"

echo "[U4] *** NEVER SHUTDOWN *** a correctly signed emergency_shutdown rule is refused; no SHUTDOWN.lock"
fresh u4; policy "$POL" emergency_shutdown "$FUTURE"
run_refused U4 "may only quarantine one registered agent"
assert_eq "U4 no SHUTDOWN.lock" "absent" "$([ -e "$WAIO_SHUTDOWN_LOCK" ] && echo present || echo absent)"

echo "[U5] quarantine target that is not a registered worker -> refused"
fresh u5; policy "$POL" quarantine_agent:NOT_A_WORKER "$FUTURE"
run_refused U5 "not a registered worker"

echo "[U6] policy file writable by group/other -> refused"
fresh u6; policy "$POL" quarantine_agent:ECHO "$FUTURE"; chmod 664 "$POL"
run_refused U6 "policy file must be a regular file owned by this user"

echo "[U7] public key writable by group/other (could be swapped) -> refused"
fresh u7; policy "$POL" quarantine_agent:ECHO "$FUTURE"; chmod 664 "$WAIO_CONTAINMENT_POLICY_PUBKEY"
run_refused U7 "policy public key must be a regular file owned by this user"
chmod 644 "$WAIO_CONTAINMENT_POLICY_PUBKEY"

echo "[U7b] a rule signed with a different private key -> signature invalid"
fresh u7b; policy "$POL" quarantine_agent:ECHO "$FUTURE" 1000 rule-test rogue-agent "$ROOT/operator/other.pem"
run_refused U7b "signature invalid"

echo "[U7c] *** NO SHARED-SECRET SIGNATURES *** an HMAC-signed rule (the e2e harness format, signable by anything that can read a shared key) -> signature invalid"
fresh u7c; e2e_write_policy "$POL" rogue-agent quarantine_agent:ECHO "$FUTURE" 1000 rule-test; chmod 600 "$POL"
run_refused U7c "signature invalid"

echo "[U7d] the runner never reads the private key: its code path names only the public key"
assert_eq "U7d no private-key or shared-key reference in security/containment_runner/" "" "$(grep -n -E 'signing\.pem|-sign |E2E_POLICY_KEY_FILE|policy\.key|hmac' security/containment_runner/*.sh security/containment_runner/*.py | grep -v -E ':[0-9]+:\s*#')"

echo "[U7e] operator signer: refuses to sign a non-quarantine action; a signed rule it writes (0600) is accepted by the runner"
fresh u7e
python3 scripts/containment_policy_sign.py --private-key "$ROOT/operator/signing.pem" --policy "$D/fixtures/signed.json" --entity rogue-agent --action emergency_shutdown --expires-at "$FUTURE" --max-executions 1 --rule-id rule-sd --approved-by test --reason "should be refused" >/dev/null 2>&1; RC=$?
assert_eq "U7e signer refuses emergency_shutdown (non-zero, no file)" "1 absent" "$RC $([ -e "$D/fixtures/signed.json" ] && echo present || echo absent)"
python3 scripts/containment_policy_sign.py --private-key "$ROOT/operator/signing.pem" --policy "$D/fixtures/signed.json" --entity rogue-agent --action quarantine_agent:ECHO --expires-at "$FUTURE" --max-executions 2 --rule-id rule-u7e --approved-by test-operator --reason "signer round trip" >/dev/null
assert_eq "U7e signer wrote the policy 0600" "600" "$(stat -f %Lp "$D/fixtures/signed.json" 2>/dev/null || stat -c %a "$D/fixtures/signed.json")"
OUT="$($RUNNER run --report "$REPORT" --policy "$D/fixtures/signed.json")"
assert_contains "U7e runner plans the signer's rule (dry run)" "$OUT" '"outcome": "planned"'

echo "[U8] malformed decision report -> refused, nothing done"
fresh u8; policy "$POL" quarantine_agent:ECHO "$FUTURE"; printf '{not json' > "$D/run/bad.json"
run_refused U8 "unreadable/malformed" "$D/run/bad.json"

echo "[U9] a report with no containment recommendation -> exit 0, no output, nothing done"
fresh u9; policy "$POL" quarantine_agent:ECHO "$FUTURE"
python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); [x.update(recommended_action="MONITOR") for x in d["decisions"]]; json.dump(d, open(sys.argv[2],"w"))' "$REPORT" "$D/run/monitor.json"
OUT="$(WAIO_CONTAINMENT_RUNNER_EXECUTE=1 $RUNNER run --report "$D/run/monitor.json" --policy "$POL" --execute)"; RC=$?
assert_eq "U9 exit 0" "0" "$RC"
assert_eq "U9 no output" "" "$OUT"
assert_eq "U9 nothing quarantined" "no" "$(quarantined ECHO)"

echo "[U10] unsafe --run-id is refused before anything runs"
fresh u10
$RUNNER run --report "$REPORT" --policy "$POL" --run-id 'x;rm -rf /' >/dev/null 2>&1; RC=$?
assert_eq "U10 exit 2" "2" "$RC"

echo "[B1] *** REPEATED ALERTS *** per-rule budget: max_executions=1, three new alerts for the same entity -> exactly one execution"
fresh b1; policy "$POL" quarantine_agent:ECHO "$FUTURE" 1 rule-b1
for i in 1 2 3; do WAIO_CONTAINMENT_RUNNER_EXECUTE=1 $RUNNER run --report "$(variant "$i")" --policy "$POL" --execute > "$D/run/b1-$i.out" 2>&1; done
assert_eq "B1 exactly one execution logged" "1" "$(wc -l < "$WAIO_CONTAINMENT_RUNNER_STATE_DIR/executions.log" | tr -d ' ')"
assert_contains "B1 later alerts refused: budget exhausted" "$(cat "$D/run/b1-2.out" "$D/run/b1-3.out")" "execution budget exhausted (1/1)"

echo "[B2] *** DETECTION STORM *** global limit: MAX_PER_HOUR=2, five new alerts under a large rule budget -> exactly two executions, the rest rate-limited"
fresh b2; policy "$POL" quarantine_agent:ECHO "$FUTURE" 1000 rule-b2
for i in 11 12 13 14 15; do WAIO_CONTAINMENT_RUNNER_MAX_PER_HOUR=2 WAIO_CONTAINMENT_RUNNER_EXECUTE=1 $RUNNER run --report "$(variant "$i")" --policy "$POL" --execute > "$D/run/b2-$i.out" 2>&1; done
assert_eq "B2 exactly two executions logged" "2" "$(wc -l < "$WAIO_CONTAINMENT_RUNNER_STATE_DIR/executions.log" | tr -d ' ')"
assert_eq "B2 three alerts rate-limited" "3" "$(cat "$D"/run/b2-1[345].out | grep -c '"outcome": "rate_limited"')"
assert_contains "B2 rate limit audited" "$(cat "$WAIO_AUDIT_LOG")" "containment_runner_rate_limited"

echo "[G1] kill switch: DISABLED present -> exit 6, nothing evaluated or done"
fresh g1; policy "$POL" quarantine_agent:ECHO "$FUTURE"; mkdir -p "$WAIO_CONTAINMENT_RUNNER_STATE_DIR"; touch "$WAIO_CONTAINMENT_RUNNER_STATE_DIR/DISABLED"
OUT="$(WAIO_CONTAINMENT_RUNNER_EXECUTE=1 $RUNNER run --report "$REPORT" --policy "$POL" --execute)"; RC=$?
assert_eq "G1 exit 6" "6" "$RC"
assert_contains "G1 outcome disabled" "$OUT" '"outcome":"disabled"'
assert_eq "G1 nothing quarantined" "no" "$(quarantined ECHO)"

echo "[G2] overlap lock: a live holder -> exit 7, nothing done"
fresh g2; policy "$POL" quarantine_agent:ECHO "$FUTURE"; mkdir -p "$WAIO_CONTAINMENT_RUNNER_STATE_DIR/.runner.lock"; echo "$$" > "$WAIO_CONTAINMENT_RUNNER_STATE_DIR/.runner.lock/holder.pid"
OUT="$(WAIO_CONTAINMENT_RUNNER_EXECUTE=1 $RUNNER run --report "$REPORT" --policy "$POL" --execute)"; RC=$?
assert_eq "G2 exit 7" "7" "$RC"
assert_eq "G2 nothing quarantined" "no" "$(quarantined ECHO)"
assert_eq "G2 the other holder's lock is left alone" "yes" "$([ -d "$WAIO_CONTAINMENT_RUNNER_STATE_DIR/.runner.lock" ] && echo yes || echo no)"

echo "[G3] bounded action: a quarantine that blocks (list is a FIFO nobody reads) is cut off by the timeout -> unverified, exit 4, attempt counted"
fresh g3; policy "$POL" quarantine_agent:ECHO "$FUTURE"; mkfifo "$WAIO_GUARDIAN_QUARANTINE_FILE"
T0=$(date +%s)
OUT="$(WAIO_CONTAINMENT_RUNNER_ACTION_TIMEOUT=2 WAIO_CONTAINMENT_RUNNER_EXECUTE=1 $RUNNER run --report "$REPORT" --policy "$POL" --execute)"; RC=$?
T=$(( $(date +%s) - T0 ))
assert_eq "G3 exit 4" "4" "$RC"
assert_contains "G3 outcome unverified" "$OUT" '"outcome": "unverified"'
assert_eq "G3 returned within timeout + slack (<= 10 s)" "yes" "$([ "$T" -le 10 ] && echo yes || echo "no ($T s)")"
assert_eq "G3 the attempt counts against the budget" "1" "$(wc -l < "$WAIO_CONTAINMENT_RUNNER_STATE_DIR/executions.log" | tr -d ' ')"
assert_eq "G3 no done marker (a retry is not silently skipped)" "0" "$(ls "$WAIO_CONTAINMENT_RUNNER_STATE_DIR/done" | wc -l | tr -d ' ')"
rm -f "$WAIO_GUARDIAN_QUARANTINE_FILE"

echo "[G4] the sandbox audit chain still verifies after every scenario above"
assert_eq "G4 audit chain intact" "0" "$(bash -c 'source security/lib.sh && verify_audit_log_integrity' >/dev/null 2>&1; echo $?)"

echo "[S1] not wired into production: no LaunchAgent template, cron script or worker references the runner"
assert_eq "S1 no production location (security/ workers/ waio.sh dashboard/ scripts/launchd/ plists) references the runner outside its own dir" "" "$(grep -rl 'containment_runner' security workers waio.sh dashboard scripts/launchd 2>/dev/null | grep -v '^security/containment_runner/'; grep -l 'containment_runner' "$REAL_HOME"/Library/LaunchAgents/*.plist 2>/dev/null)"
echo "[S2] the runner never calls a shutdown path"
assert_eq "S2 no trigger_shutdown / guardian_request_waio_shutdown / emergency_shutdown execution in the runner" "" \
  "$(grep -n -E 'trigger_shutdown|guardian_request_waio_shutdown|guardian_set_state' security/containment_runner/containment_runner.sh security/containment_runner/runner_lib.py | grep -v -E '^\S+:[0-9]+:\s*#')"
echo "[S3] real state untouched: no runner state dir in this checkout's security/state/"
assert_eq "S3 security/state/containment_runner absent" "absent" "$([ -e security/state/containment_runner ] && echo present || echo absent)"

echo ""
echo "=== Summary: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
  echo "Failures:"
  for f in "${FAILURES[@]}"; do echo "  - $f"; done
  exit 1
fi
exit 0
