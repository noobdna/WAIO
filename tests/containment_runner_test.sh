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
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$ROOT/operator/other.pem" 2>/dev/null
# Trusted key directory: <key_id>.pub.pem (key_id = first 16 hex of SHA-256 over the DER public key).
kid_of() { openssl pkey -in "$1" -pubout -outform DER 2>/dev/null | shasum -a 256 | cut -c1-16; }
KID="$(kid_of "$ROOT/operator/signing.pem")"; OTHER_KID="$(kid_of "$ROOT/operator/other.pem")"
mkdir -p "$D/keys/trusted"
openssl pkey -in "$ROOT/operator/signing.pem" -pubout -out "$D/keys/trusted/$KID.pub.pem" 2>/dev/null
export WAIO_CONTAINMENT_POLICY_KEYDIR="$D/keys/trusted"
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
# policy FILE ACTION EXPIRES [MAX] [RULE_ID] [ENTITY] [PRIVATE_KEY] -- a v3 policy
# with one rule, the whole document signed with openssl directly (any action,
# so U4 can prove the runner itself refuses a validly signed shutdown rule),
# mode 0600. Knobs (env): P_SERIAL (1), P_ISSUED (rule issued_at, default now-60 s),
# P_POL_ISSUED (policy issued_at, default now), P_KEYID (claimed key_id),
# P_EXTRA_RULE (JSON object appended), P_MAXLIFE, P_SIG (replaces the signature).
policy() {
  python3 - "$1" "$2" "$3" "${4:-1000}" "${5:-rule-test}" "${6:-rogue-agent}" "${7:-$ROOT/operator/signing.pem}" <<'PYEOF'
import base64, datetime, hashlib, json, os, subprocess, sys
path, action, expires, max_exec, rule_id, entity, priv = sys.argv[1:8]
now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
f = lambda t: t.strftime("%Y-%m-%dT%H:%M:%SZ")
der = subprocess.run(["openssl", "pkey", "-in", priv, "-pubout", "-outform", "DER"], capture_output=True, check=True).stdout
rule = {"rule_id": rule_id, "entity": entity, "action": action, "approved_by": "test-operator (fixture)",
        "reason": "pre-approved narrow test rule", "issued_at": os.environ.get("P_ISSUED") or f(now),
        "expires_at": expires, "max_executions": int(max_exec)}
rules = [rule] + ([json.loads(os.environ["P_EXTRA_RULE"])] if os.environ.get("P_EXTRA_RULE") else [])
doc = {"version": 3, "policy_serial": int(os.environ.get("P_SERIAL", "1")), "issued_at": os.environ.get("P_POL_ISSUED") or f(now),
       "key_id": os.environ.get("P_KEYID") or hashlib.sha256(der).hexdigest()[:16], "rules": rules}
if os.environ.get("P_MAXLIFE"):
    doc["max_rule_lifetime_s"] = int(os.environ["P_MAXLIFE"])
data = json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
sig = subprocess.run(["openssl", "dgst", "-sha256", "-sign", priv], input=data, capture_output=True, check=True).stdout
doc["signature"] = os.environ.get("P_SIG") or "rsa-sha256:" + base64.b64encode(sig).decode()
json.dump(doc, open(path, "w"))
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
fresh u3; P_ISSUED=2019-12-31T00:00:00Z policy "$POL" quarantine_agent:ECHO "$PAST"
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
fresh u7; policy "$POL" quarantine_agent:ECHO "$FUTURE"; chmod 664 "$D/keys/trusted/$KID.pub.pem"
run_refused U7 "trusted key $KID must be a regular file owned by this user"
chmod 644 "$D/keys/trusted/$KID.pub.pem"

echo "[U7b] a policy signed with an untrusted key (its own key_id) -> no such trusted key; claiming the trusted key_id -> signature invalid"
fresh u7b; policy "$POL" quarantine_agent:ECHO "$FUTURE" 1000 rule-test rogue-agent "$ROOT/operator/other.pem"
run_refused U7b "trusted key $OTHER_KID unreadable"
fresh u7b2; P_KEYID="$KID" policy "$POL" quarantine_agent:ECHO "$FUTURE" 1000 rule-test rogue-agent "$ROOT/operator/other.pem"
run_refused U7b2 "policy signature invalid"

echo "[U7c] *** NO SHARED-SECRET SIGNATURES *** an HMAC-signed rule (the e2e harness format, signable by anything that can read a shared key) -> signature invalid"
fresh u7c; e2e_write_policy "$POL" rogue-agent quarantine_agent:ECHO "$FUTURE" 1000 rule-test; chmod 600 "$POL"
run_refused U7c "policy version 2 refused"
fresh u7c2; P_SIG="hmac-sha256:00ff" policy "$POL" quarantine_agent:ECHO "$FUTURE"
run_refused U7c2 "policy signature invalid"

echo "[U7d] the runner never reads the private key: its code path names only the public key"
assert_eq "U7d no private-key or shared-key reference in security/containment_runner/" "" "$(grep -n -E 'signing\.pem|-sign |E2E_POLICY_KEY_FILE|policy\.key|hmac' security/containment_runner/*.sh security/containment_runner/*.py | grep -v -E ':[0-9]+:\s*#')"

echo "[U7e] operator signer (v3): refuses a non-quarantine action, an over-long lifetime and a non-increasing serial; its 0600 output is accepted by the runner"
fresh u7e
SIGN=(python3 scripts/containment_policy_sign.py --private-key "$ROOT/operator/signing.pem" --policy "$D/fixtures/signed.json")
printf '[{"rule_id":"rule-sd","entity":"rogue-agent","action":"emergency_shutdown","approved_by":"t","reason":"should be refused","expires_at":"%s","max_executions":1}]' "$FUTURE" > "$D/fixtures/r-sd.json"
"${SIGN[@]}" --serial 1 --rules "$D/fixtures/r-sd.json" >/dev/null 2>&1; RC=$?
assert_eq "U7e signer refuses emergency_shutdown (non-zero, no file)" "1 absent" "$RC $([ -e "$D/fixtures/signed.json" ] && echo present || echo absent)"
LONG="$(python3 -c 'import datetime; print((datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(days=8)).strftime("%Y-%m-%dT%H:%M:%SZ"))')"
printf '[{"rule_id":"rule-long","entity":"rogue-agent","action":"quarantine_agent:ECHO","approved_by":"t","reason":"8 days","expires_at":"%s","max_executions":1}]' "$LONG" > "$D/fixtures/r-long.json"
"${SIGN[@]}" --serial 1 --rules "$D/fixtures/r-long.json" >/dev/null 2>&1; RC=$?
assert_eq "U7e signer refuses an 8-day rule (default limit 7 days)" "1" "$RC"
printf '[{"rule_id":"rule-u7e","entity":"rogue-agent","action":"quarantine_agent:ECHO","approved_by":"test-operator","reason":"signer round trip","expires_at":"%s","max_executions":2}]' "$FUTURE" > "$D/fixtures/r-ok.json"
"${SIGN[@]}" --serial 3 --rules "$D/fixtures/r-ok.json" >/dev/null
assert_eq "U7e signer wrote the policy 0600" "600" "$(python3 -c 'import os, sys; print(format(os.stat(sys.argv[1]).st_mode & 0o777, "o"))' "$D/fixtures/signed.json")"
"${SIGN[@]}" --serial 3 --rules "$D/fixtures/r-ok.json" >/dev/null 2>&1; RC=$?
assert_eq "U7e signer refuses a serial that does not supersede the existing policy" "1" "$RC"
assert_eq "U7e signer --print-key-id matches the trusted key file name" "$KID" "$(python3 scripts/containment_policy_sign.py --private-key "$ROOT/operator/signing.pem" --print-key-id)"
OUT="$($RUNNER run --report "$REPORT" --policy "$D/fixtures/signed.json")"
assert_contains "U7e runner plans the signer's policy (dry run)" "$OUT" '"outcome": "planned"'

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

echo "[G3b] an unverified quarantine (exit 4, needs a human) is not downgraded to exit 3 by a later refused recommendation"
fresh g3b; policy "$POL" quarantine_agent:ECHO "$FUTURE"; mkfifo "$WAIO_GUARDIAN_QUARANTINE_FILE"
python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); d["decisions"].append({"entity": "no-rule-entity", "recommended_action": "RECOMMEND_CONTAINMENT", "local_corroboration": {"present": True}}); json.dump(d, open(sys.argv[2],"w"))' "$REPORT" "$D/run/g3b.json"
OUT="$(WAIO_CONTAINMENT_RUNNER_ACTION_TIMEOUT=2 WAIO_CONTAINMENT_RUNNER_EXECUTE=1 $RUNNER run --report "$D/run/g3b.json" --policy "$POL" --execute)"; RC=$?
assert_contains "G3b first recommendation unverified" "$OUT" '"outcome": "unverified"'
assert_contains "G3b second recommendation refused" "$OUT" '"outcome": "refused"'
assert_eq "G3b exit stays 4" "4" "$RC"
rm -f "$WAIO_GUARDIAN_QUARANTINE_FILE"

echo "[H1] *** PATH HIJACK *** a fake openssl that accepts every signature, first on PATH -> a forged rule is still refused"
fresh h1; P_KEYID="$KID" policy "$POL" quarantine_agent:ECHO "$FUTURE" 1000 rule-test rogue-agent "$ROOT/operator/other.pem"
mkdir -p "$D/fakebin"; printf '#!/bin/sh\necho "Verified OK"\nexit 0\n' > "$D/fakebin/openssl"; chmod +x "$D/fakebin/openssl"
OUT="$(PATH="$D/fakebin:$PATH" WAIO_CONTAINMENT_RUNNER_EXECUTE=1 $RUNNER run --report "$REPORT" --policy "$POL" --execute)"; RC=$?
assert_eq "H1 exit 3" "3" "$RC"
assert_contains "H1 signature invalid despite the fake openssl" "$OUT" "signature invalid"
assert_eq "H1 nothing quarantined" "no" "$(quarantined ECHO)"

echo "[H2] *** SYMLINKS *** a symlinked policy file or public key is refused (no check-then-open swap)"
fresh h2; policy "$D/fixtures/real-policy.json" quarantine_agent:ECHO "$FUTURE"; rm -f "$POL"; ln -s "$D/fixtures/real-policy.json" "$POL"
run_refused H2a "policy file unreadable or a symlink"
rm -f "$POL"; policy "$POL" quarantine_agent:ECHO "$FUTURE"
mkdir -p "$D/keys/linkdir"; ln -s "$D/keys/trusted/$KID.pub.pem" "$D/keys/linkdir/$KID.pub.pem"
OUT="$(WAIO_CONTAINMENT_POLICY_KEYDIR="$D/keys/linkdir" WAIO_CONTAINMENT_RUNNER_EXECUTE=1 $RUNNER run --report "$REPORT" --policy "$POL" --execute)"; RC=$?
assert_eq "H2b symlinked public key: exit 3" "3" "$RC"
assert_contains "H2b reason" "$OUT" "trusted key $KID unreadable or a symlink"
assert_eq "H2b nothing quarantined" "no" "$(quarantined ECHO)"

echo "[H3] *** AMBIGUOUS POLICY *** two validly signed rules for the same entity -> refused, nothing done"
fresh h3; P_EXTRA_RULE="{\"rule_id\":\"rule-b\",\"entity\":\"rogue-agent\",\"action\":\"quarantine_agent:ECHO\",\"approved_by\":\"t\",\"reason\":\"second\",\"issued_at\":\"$(python3 -c 'import datetime; print((datetime.datetime.now(datetime.timezone.utc)-datetime.timedelta(seconds=60)).strftime("%Y-%m-%dT%H:%M:%SZ"))')\",\"expires_at\":\"$FUTURE\",\"max_executions\":1000}" policy "$POL" quarantine_agent:ECHO "$FUTURE" 1000 rule-a
run_refused H3 "more than one policy rule"

echo "[H4] missing public key, unsigned rule -> refused (fail closed)"
fresh h4; policy "$POL" quarantine_agent:ECHO "$FUTURE"
mkdir -p "$D/keys/empty"
OUT="$(WAIO_CONTAINMENT_POLICY_KEYDIR="$D/keys/empty" WAIO_CONTAINMENT_RUNNER_EXECUTE=1 $RUNNER run --report "$REPORT" --policy "$POL" --execute)"; RC=$?
assert_eq "H4a missing public key: exit 3, nothing quarantined" "3 no" "$RC $(quarantined ECHO)"
python3 -c 'import json,sys; p=json.load(open(sys.argv[1])); del p["signature"]; json.dump(p, open(sys.argv[1],"w"))' "$POL"
run_refused H4b "policy signature invalid"

echo "[H5] *** OVERSIZED INPUT *** a decision report over 8 MiB and a policy over 1 MiB are refused without parsing"
fresh h5; policy "$POL" quarantine_agent:ECHO "$FUTURE"
python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); d["padding"]="x"*(9*1024*1024); json.dump(d, open(sys.argv[2],"w"))' "$REPORT" "$D/run/huge.json"
run_refused H5a "too large" "$D/run/huge.json"
python3 -c 'import json,sys; p=json.load(open(sys.argv[1])); p["padding"]="x"*(2*1024*1024); json.dump(p, open(sys.argv[1],"w"))' "$POL"
run_refused H5b "too large"

echo "[H6] runner state is private: state dir and files are not readable by group/other"
fresh h6; policy "$POL" quarantine_agent:ECHO "$FUTURE"
WAIO_CONTAINMENT_RUNNER_EXECUTE=1 $RUNNER run --report "$REPORT" --policy "$POL" --execute >/dev/null 2>&1
assert_eq "H6 no group/other permission bits on any runner state file" "" "$(find "$WAIO_CONTAINMENT_RUNNER_STATE_DIR" -perm -004 -o -perm -040 2>/dev/null | head -3)"

echo "[H7] hostile entity name (newline, quote, control chars) in the decision report cannot break the audit chain or the output"
fresh h7; policy "$POL" quarantine_agent:ECHO "$FUTURE"
python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); d["decisions"].append({"entity": "evil\n\"}{\u0007", "recommended_action": "RECOMMEND_CONTAINMENT", "local_corroboration": {"present": True}}); json.dump(d, open(sys.argv[2],"w"))' "$REPORT" "$D/run/hostile.json"
OUT="$($RUNNER run --report "$D/run/hostile.json" --policy "$POL")"
assert_eq "H7 every output line is valid JSON" "ok" "$(printf '%s\n' "$OUT" | python3 -c 'import json,sys; [json.loads(l) for l in sys.stdin if l.strip()]; print("ok")' 2>&1)"
assert_contains "H7 hostile entity refused (no rule)" "$OUT" "no pre-approved policy rule"

echo "[H8] *** TRUST ANCHOR FROM THE ENVIRONMENT *** test overrides (public key, state dir, Guardian/audit paths) are honored only inside a marked e2e sandbox"
fresh h8
mkdir -p "$ROOT/attacker"; openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$ROOT/attacker/priv.pem" 2>/dev/null
mkdir -p "$ROOT/attacker/keys"; openssl pkey -in "$ROOT/attacker/priv.pem" -pubout -out "$ROOT/attacker/keys/$(kid_of "$ROOT/attacker/priv.pem").pub.pem" 2>/dev/null
policy "$ROOT/attacker/policy.json" quarantine_agent:ECHO "$FUTURE" 1000 rule-evil rogue-agent "$ROOT/attacker/priv.pem"
OUT="$(env -u E2E_SANDBOX WAIO_CONTAINMENT_POLICY_KEYDIR="$ROOT/attacker/keys" WAIO_CONTAINMENT_RUNNER_EXECUTE=1 $RUNNER run --report "$REPORT" --policy "$ROOT/attacker/policy.json" --execute 2>&1)"; RC=$?
assert_eq "H8a attacker key via env, no sandbox: exit 2" "2" "$RC"
assert_contains "H8a reason names the sandbox rule" "$OUT" "outside an e2e sandbox"
assert_eq "H8a nothing quarantined" "no" "$(quarantined ECHO)"
OUT="$(WAIO_CONTAINMENT_POLICY_KEYDIR="$ROOT/attacker/keys" WAIO_CONTAINMENT_RUNNER_EXECUTE=1 $RUNNER run --report "$REPORT" --policy "$ROOT/attacker/policy.json" --execute 2>&1)"; RC=$?
assert_eq "H8b inside the sandbox but the key path is outside it: exit 2" "2" "$RC"
assert_contains "H8b reason" "$OUT" "outside the e2e sandbox"
assert_eq "H8b nothing quarantined" "no" "$(quarantined ECHO)"
OUT="$(env -u E2E_SANDBOX -u WAIO_CONTAINMENT_POLICY_KEYDIR -u WAIO_CONTAINMENT_RUNNER_STATE_DIR $RUNNER run --report "$REPORT" --policy "$POL" 2>&1)"; RC=$?
assert_eq "H8c no sandbox but Guardian/audit paths redirected by env: exit 2 (a production run must act on the real Guardian state)" "2" "$RC"
OUT="$(env -u WAIO_GUARDIAN_QUARANTINE_FILE $RUNNER run --report "$REPORT" --policy "$POL" 2>&1)"; RC=$?
assert_eq "H8d inside the sandbox with the Guardian quarantine path NOT redirected: exit 2 (a sandbox key must never reach the real Guardian list)" "2" "$RC"
assert_contains "H8d reason names the missing override" "$OUT" "requires WAIO_GUARDIAN_QUARANTINE_FILE"
assert_eq "H8 real security/state/containment_runner never created" "absent" "$([ -e security/state/containment_runner ] && echo present || echo absent)"

t_in() { python3 -c 'import datetime,sys; print((datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(seconds=int(sys.argv[1]))).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ"))' "$1"; }
planned_ok() {  # planned_ok NAME -> dry run must plan (exit 0, outcome planned)
  local out rc; out="$($RUNNER run --report "${2:-$REPORT}" --policy "$POL")"; rc=$?
  assert_eq "$1 exit 0" "0" "$rc"; assert_contains "$1 planned" "$out" '"outcome": "planned"'
}

echo "[L1] *** RULE LIFETIME *** default maximum 7 days: 7 d - 1 min accepted, 7 d + 1 h refused; expires_at not after issued_at refused"
fresh l1; P_ISSUED="$(t_in 0)" policy "$POL" quarantine_agent:ECHO "$(t_in $((7*86400 - 120)))"; planned_ok L1a
fresh l1b; P_ISSUED="$(t_in 0)" policy "$POL" quarantine_agent:ECHO "$(t_in $((7*86400 + 3600)))"; run_refused L1b "lifetime exceeds 604800 s"
fresh l1c; P_ISSUED="$(t_in 30)" policy "$POL" quarantine_agent:ECHO "$(t_in 30)"; run_refused L1c "expires_at is not after issued_at"
echo "[L2] a signed policy may set max_rule_lifetime_s up to the 30-day hard cap, never above"
fresh l2; P_MAXLIFE=$((20*86400)) P_ISSUED="$(t_in 0)" policy "$POL" quarantine_agent:ECHO "$(t_in $((14*86400)))"; planned_ok L2a
fresh l2b; P_MAXLIFE=$((31*86400)) policy "$POL" quarantine_agent:ECHO "$FUTURE"; run_refused L2b "max_rule_lifetime_s must be an integer"
fresh l2c; P_MAXLIFE=3600 P_ISSUED="$(t_in 0)" policy "$POL" quarantine_agent:ECHO "$(t_in 7200)"; run_refused L2c "lifetime exceeds 3600 s"
echo "[L3] *** CLOCK EDGES *** rule issued_at 60 s ahead (inside the 300 s skew) accepted; 1 h ahead refused; policy issued_at 1 h ahead refused; malformed timestamp refused"
fresh l3; P_ISSUED="$(t_in 60)" policy "$POL" quarantine_agent:ECHO "$FUTURE"; planned_ok L3a
fresh l3b; P_ISSUED="$(t_in 3600)" policy "$POL" quarantine_agent:ECHO "$(t_in 7200)"; run_refused L3b "rule issued_at is in the future"
fresh l3c; P_POL_ISSUED="$(t_in 3600)" policy "$POL" quarantine_agent:ECHO "$FUTURE"; run_refused L3c "policy issued_at is in the future"
fresh l3d; P_ISSUED="2026-13-40T99:00:00Z" policy "$POL" quarantine_agent:ECHO "$FUTURE"; run_refused L3d "issued_at/expires_at malformed"

echo "[V1] *** ANTI-ROLLBACK *** serial 5 accepted and recorded (even in a dry run); 4 refused; 5 again accepted; 6 accepted and recorded"
fresh v1
P_SERIAL=5 policy "$POL" quarantine_agent:ECHO "$FUTURE"; planned_ok V1a
assert_eq "V1 highest accepted serial recorded" "5" "$(cat "$WAIO_CONTAINMENT_RUNNER_STATE_DIR/policy_serial")"
P_SERIAL=4 policy "$POL" quarantine_agent:ECHO "$FUTURE"; run_refused V1b "rollback refused"
P_SERIAL=5 policy "$POL" quarantine_agent:ECHO "$FUTURE"; planned_ok V1c
P_SERIAL=6 policy "$POL" quarantine_agent:ECHO "$FUTURE"; planned_ok V1d
assert_eq "V1 recorded serial advanced to 6" "6" "$(cat "$WAIO_CONTAINMENT_RUNNER_STATE_DIR/policy_serial")"
echo "[V2] *** REVOCATION + COPIED OLD POLICY *** serial 7 grants rogue-agent; serial 8 drops it (revocation); a saved copy of serial 7 replayed later is refused"
fresh v2
P_SERIAL=7 policy "$D/fixtures/saved-serial7.json" quarantine_agent:ECHO "$FUTURE"
cp "$D/fixtures/saved-serial7.json" "$POL"; chmod 600 "$POL"; planned_ok V2a
P_SERIAL=8 policy "$POL" quarantine_agent:ECHO "$FUTURE" 1000 rule-other some-other-agent; run_refused V2b "no pre-approved policy rule"
cp "$D/fixtures/saved-serial7.json" "$POL"; chmod 600 "$POL"; run_refused V2c "policy_serial 7 is lower than the highest accepted (8): rollback refused"
echo "[V3] malformed serial (0, string, bool) refused"
fresh v3; P_SERIAL=0 policy "$POL" quarantine_agent:ECHO "$FUTURE"; run_refused V3 "policy_serial missing or not a positive integer"

echo "[K1] *** KEY ROTATION *** a second trusted key works by its own key_id; removing the first key file retires it"
fresh k1
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$ROOT/operator/rotated.pem" 2>/dev/null
RKID="$(kid_of "$ROOT/operator/rotated.pem")"
openssl pkey -in "$ROOT/operator/rotated.pem" -pubout -out "$D/keys/trusted/$RKID.pub.pem" 2>/dev/null
policy "$POL" quarantine_agent:ECHO "$FUTURE" 1000 rule-test rogue-agent "$ROOT/operator/rotated.pem"; planned_ok K1a
mv "$D/keys/trusted/$KID.pub.pem" "$ROOT/operator/retired.pub.pem"
fresh k1b; policy "$POL" quarantine_agent:ECHO "$FUTURE"; run_refused K1b "trusted key $KID unreadable"
mv "$ROOT/operator/retired.pub.pem" "$D/keys/trusted/$KID.pub.pem"
echo "[K2] a key file whose content does not match its key_id name is refused"
fresh k2; cp "$D/keys/trusted/$RKID.pub.pem" "$D/keys/trusted/$KID.pub.pem.bak"; mv "$D/keys/trusted/$KID.pub.pem" "$ROOT/operator/kid.keep"; cp "$D/keys/trusted/$RKID.pub.pem" "$D/keys/trusted/$KID.pub.pem"; chmod 644 "$D/keys/trusted/$KID.pub.pem"
policy "$POL" quarantine_agent:ECHO "$FUTURE"; run_refused K2 "does not match its key_id"
mv -f "$ROOT/operator/kid.keep" "$D/keys/trusted/$KID.pub.pem"; rm -f "$D/keys/trusted/$KID.pub.pem.bak" "$D/keys/trusted/$RKID.pub.pem"

echo "[P1] *** FIXED POLICY PATH *** outside an e2e sandbox --policy is refused (exit 2) before anything is read or written"
OUT="$(env -i HOME="$REAL_HOME" PATH=/usr/bin:/bin "$SCRIPT_DIR/security/containment_runner/containment_runner.sh" run --report "$REPORT" --policy "$POL" 2>&1)"; RC=$?
assert_eq "P1 exit 2" "2" "$RC"
assert_contains "P1 reason" "$OUT" "--policy is honored only inside an e2e sandbox"
assert_eq "P1 no state dir created in this checkout" "absent" "$([ -e security/state/containment_runner ] && echo present || echo absent)"

echo "[R1] *** RE-QUARANTINE AFTER HUMAN RELEASE *** contained -> released -> a new alert under the same rule is refused; a rule issued after the release is accepted"
fresh r1; policy "$POL" quarantine_agent:ECHO "$FUTURE"
OUT="$(WAIO_CONTAINMENT_RUNNER_EXECUTE=1 $RUNNER run --report "$REPORT" --policy "$POL" --execute)"
assert_contains "R1 first alert contained" "$OUT" '"outcome": "contained"'
./security/guardian_release_agent.sh ECHO --confirm "containment runner test: human release before the re-quarantine check" >/dev/null 2>&1
assert_eq "R1 released" "no" "$(quarantined ECHO)"
RA="$(variant 31)"
OUT="$(WAIO_CONTAINMENT_RUNNER_EXECUTE=1 $RUNNER run --report "$RA" --policy "$POL" --execute)"; RC=$?
assert_eq "R1 new alert under the old rule: exit 3" "3" "$RC"
assert_contains "R1 reason" "$OUT" "released by a human at or after this rule was issued"
assert_eq "R1 not re-quarantined" "no" "$(quarantined ECHO)"
REL="$(python3 -c 'import json,sys; print(max(json.loads(l)["timestamp"] for l in open(sys.argv[1]) if "guardian_agent_released" in l))' "$WAIO_AUDIT_LOG")"
echo "[R2] equal-second edge: a rule issued in the same second as the release is still refused"
P_SERIAL=2 P_ISSUED="$REL" policy "$POL" quarantine_agent:ECHO "$FUTURE" 1000 rule-r2
OUT="$(WAIO_CONTAINMENT_RUNNER_EXECUTE=1 $RUNNER run --report "$(variant 32)" --policy "$POL" --execute)"; RC=$?
assert_eq "R2 issued_at == release time: exit 3" "3" "$RC"
echo "[R3] a rule issued strictly after the release (new serial) authorizes containment again"
P_SERIAL=3 P_ISSUED="$(python3 -c 'import datetime,sys; t=datetime.datetime.strptime(sys.argv[1],"%Y-%m-%dT%H:%M:%SZ")+datetime.timedelta(seconds=1); print(t.strftime("%Y-%m-%dT%H:%M:%SZ"))' "$REL")" policy "$POL" quarantine_agent:ECHO "$FUTURE" 1000 rule-r3
OUT="$(WAIO_CONTAINMENT_RUNNER_EXECUTE=1 $RUNNER run --report "$(variant 33)" --policy "$POL" --execute)"; RC=$?
assert_eq "R3 exit 0" "0" "$RC"
assert_contains "R3 contained" "$OUT" '"outcome": "contained"'
./security/guardian_release_agent.sh ECHO --confirm "containment runner test: cleanup release after R3 verification" >/dev/null 2>&1

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
