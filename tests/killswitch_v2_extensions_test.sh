#!/bin/bash
set -uo pipefail

# tests/killswitch_v2_extensions_test.sh -- WAIO v2 additions to the
# DuCoPA Independent Kill Switch: Recover (signed release), pre-approved
# policies (execute-policy) and evidence preservation. Fixture-only under
# mktemp, same isolation as tests/killswitch_gate_test.sh.
#
#   X1-X3   release: authz, allowlist, dry-run, evidence kept
#   X4-X6   execute-policy: dry-run, enforce, replay, max_executions
#   X7-X10  execute-policy refusals: forged/tampered/untrusted events,
#           bad policies, stale/low/unmatched events, unsigned detections
#   X11     evidence bundle: preserve, verify, tamper/missing detection,
#           no overwrite, keyed manifest vs. attacker without the key
#   X12     static guards on the new module files
#   X13     this deployment's real state untouched

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
assert_contains() {
  local label="$1" haystack="$2" needle="$3"
  if [[ "$haystack" == *"$needle"* ]]; then PASS=$((PASS + 1)); echo "  PASS: $label"
  else FAIL=$((FAIL + 1)); FAILURES+=("$label (missing '$needle')"); echo "  FAIL: $label (expected to contain '$needle', got: $haystack)"; fi
}
jget() { python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print($2)" <<<"$1" 2>/dev/null; }
code_only() { grep -vE '^[[:space:]]*#' "$1"; }

KS=security/killswitch
GATE="$SCRIPT_DIR/$KS/killswitch_gate.sh"
SIGN="$SCRIPT_DIR/$KS/killswitch_sign.py"
PSIGN="$SCRIPT_DIR/$KS/killswitch_sign_policy.py"
ENFORCE="$SCRIPT_DIR/$KS/killswitch_enforce.py"
REAL_BEFORE="$(ls -la security/state/killswitch logs/killswitch-audit.jsonl 2>&1 | cksum)"

TMP="$(mktemp -d "${TMPDIR:-/tmp}/ks-v2-test.XXXXXX")"
trap 'chmod -R u+rwx "$TMP" 2>/dev/null; rm -rf "$TMP"' EXIT
export KILLSWITCH_STATE_DIR="$TMP/state" KILLSWITCH_CONFIG_DIR="$TMP/config" KILLSWITCH_KEYRING_DIR="$TMP/config/keys"
export KILLSWITCH_AUDIT_LOG="$TMP/audit.jsonl" KILLSWITCH_AUDIT_CHECKPOINT="$TMP/state/.audit_checkpoint"
export KILLSWITCH_TEST_ENV="$TMP/testenv" KILLSWITCH_EVIDENCE_DIR="$TMP/evidence"
export WAIO_KILLSWITCH_NOW="2026-10-17T12:00:00Z"
ISSUED="2026-10-17T11:59:00Z"
umask 077
mkdir -p "$TMP/config/keys" "$TMP/testenv" "$TMP/c"
printf 'environment=test\n' > "$TMP/testenv/.killswitch-test-env"
cp $KS/targets.conf.example "$TMP/config/targets.conf"
printf 'operator-masa|revoke_test_session,block_test_endpoint,isolate_test_worker\nguardian-800|isolate_test_worker\nintruder|release_test_session\n' > "$TMP/config/authz.conf"
for k in operator-masa guardian-800 intruder decoy-sensor-01 rogue-sensor; do
  python3 -c "import os,sys; open(sys.argv[1],'wb').write(os.urandom(32))" "$TMP/config/keys/$k.key"
done
chmod 600 "$TMP"/config/*.conf "$TMP"/config/keys/*.key
OPKEY="$TMP/config/keys/operator-masa.key"
REASON="drill: contain the test target after a confirmed decoy hit"

run() { OUT="$("$GATE" "$@" 2>/dev/null)"; RC=$?; }
check() { python3 "$ENFORCE" check "$1" "$2" "$TMP/testenv" | python3 -c "import json,sys; print(json.load(sys.stdin)['verdict'])"; }
cmd() {  # cmd NAME ACTION TARGET [signer args...]
  local name="$1" action="$2" target="$3"; shift 3
  python3 "$SIGN" --issuer operator-masa --key-file "$OPKEY" --action "$action" --target "$target" \
    --reason "$REASON" --issued-at "$ISSUED" --command-id "$name" "$@" > "$TMP/c/$name.json"
}
# policy NAME [python dict-update expression] -- signed by KEY (default operator)
policy() {
  local name="$1" upd="${2:-}" key="${3:-$OPKEY}"
  [ -n "$upd" ] || upd='{}'
  python3 - "$TMP/c/$name.unsigned" "$upd" <<'EOF'
import json, sys
p = {"schema": "waio.killswitch.policy.v1", "policy_id": "pol-decoy-01", "issuer": "operator-masa",
     "issued_at": "2026-10-17T00:00:00Z", "expires_at": "2026-10-18T00:00:00Z", "environment": "test",
     "sensor_ids": ["decoy-sensor-01"], "max_executions": 2,
     "rules": [{"source": "snd_home", "event_type": "decoy_access", "action": "block_test_endpoint", "target_id": "test-endpoint-api"}],
     "reason": "pre-approved: any decoy hit blocks the test API endpoint"}
p.update(eval(sys.argv[2]))
json.dump(p, open(sys.argv[1], "w"))
EOF
  python3 "$PSIGN" --key-file "$key" "$TMP/c/$name.unsigned" > "$TMP/c/$name.json"
}
# sensor_event NAME EVENT_ID [update-expr] [sensor key]
sensor_event() {
  local name="$1" eid="$2" upd="${3:-}" key="${4:-$TMP/config/keys/decoy-sensor-01.key}"
  [ -n "$upd" ] || upd='{}'
  python3 - "$TMP/c/$name.unsigned" "$eid" "$upd" <<'EOF'
import json, sys
e = {"schema": "waio.killswitch.sensor_event.v1", "event_id": sys.argv[2], "sensor_id": "decoy-sensor-01",
     "source": "snd_home", "type": "decoy_access", "severity": "critical", "target_ref": "test-endpoint-api",
     "observed_at": "2026-10-17T11:59:30Z", "summary": "decoy route admin_login accessed with POST"}
e.update(eval(sys.argv[3]))
json.dump(e, open(sys.argv[1], "w"))
EOF
  python3 "$PSIGN" --key-file "$key" "$TMP/c/$name.unsigned" > "$TMP/c/$name.json"
}

echo "[X1] Recover: a signed release needs its own authz line, then lifts containment and keeps evidence"
cmd x1-contain revoke_test_session test-session-001
run execute "$TMP/c/x1-contain.json" --enforce-test
assert_eq "X1 containment executed" "EXECUTED" "$(jget "$OUT" "d['execution_result']")"
assert_eq "X1 enforcement denies the contained session" "DENY" "$(check session test-session-001)"
cmd x1-rel-noauth release_test_session test-session-001
run execute "$TMP/c/x1-rel-noauth.json" --enforce-test
assert_eq "X1 release without a release authz line -> DENIED_UNAUTHORIZED" "DENIED_UNAUTHORIZED" "$(jget "$OUT" "d['code']")"
assert_eq "X1 still contained after refused release" "DENY" "$(check session test-session-001)"
printf 'operator-masa|release_test_session,unblock_test_endpoint,release_test_worker\n' >> "$TMP/config/authz.conf"
cmd x1-rel-dry release_test_session test-session-001
run execute "$TMP/c/x1-rel-dry.json"
assert_eq "X1 release in DRY-RUN does nothing" "DRY_RUN_NOT_EXECUTED|DENY" "$(jget "$OUT" "d['execution_result']")|$(check session test-session-001)"
cmd x1-rel release_test_session test-session-001
run execute "$TMP/c/x1-rel.json" --enforce-test
assert_eq "X1 release executed" "EXECUTED" "$(jget "$OUT" "d['execution_result']")"
assert_eq "X1 enforcement allows the released session" "ALLOW" "$(check session test-session-001)"
assert_eq "X1 containment record kept under released/" "1" "$(find "$TMP/testenv/sessions/released" -name 'test-session-001.x1-rel.released' | wc -l | tr -d ' ')"
cmd x1-recontain revoke_test_session test-session-001
run execute "$TMP/c/x1-recontain.json" --enforce-test
assert_eq "X1 re-containment after recovery works (new command id)" "EXECUTED|DENY" "$(jget "$OUT" "d['execution_result']")|$(check session test-session-001)"

echo "[X2-X3] release refusals"
cmd x2 release_test_session test-session-999
run execute "$TMP/c/x2.json" --enforce-test
assert_eq "X2 release of a non-allowlisted target refused" "DENIED_TARGET_NOT_ALLOWLISTED" "$(jget "$OUT" "d['code']")"
python3 "$SIGN" --issuer intruder --key-file "$TMP/config/keys/intruder.key" --action release_test_session --target test-session-001 \
  --reason "$REASON" --issued-at "$ISSUED" --command-id x3 --origin llm > "$TMP/c/x3.json"
run execute "$TMP/c/x3.json" --enforce-test
assert_eq "X3 AI-origin release refused even when authorized" "DENIED_AI_ORIGIN" "$(jget "$OUT" "d['code']")"
assert_eq "X3 session stays contained" "DENY" "$(check session test-session-001)"

echo "[X4-X6] execute-policy: pre-approved, sensor-signed, bounded"
policy pol
sensor_event ev1 decoy-evt-0001
run execute-policy "$TMP/c/pol.json" "$TMP/c/ev1.json"
assert_eq "X4 default DRY-RUN" "DRY_RUN_NOT_EXECUTED" "$(jget "$OUT" "d['execution_result']")"
assert_eq "X4 dry-run contains nothing" "ALLOW" "$(check endpoint test-endpoint-api)"
run execute-policy "$TMP/c/pol.json" "$TMP/c/ev1.json" --enforce-test
assert_eq "X4 enforce: executed" "EXECUTED" "$(jget "$OUT" "d['execution_result']")"
assert_eq "X4 origin recorded as preapproved_policy" "preapproved_policy" "$(jget "$OUT" "d['origin']")"
assert_eq "X4 record names the policy and event" "pol-decoy-01|decoy-evt-0001" "$(jget "$OUT" "d['policy_id']+'|'+d['event_id']")"
assert_eq "X4 risk POLICY_TRIGGERED" "POLICY_TRIGGERED" "$(jget "$OUT" "d['risk']")"
assert_eq "X4 endpoint now blocked" "DENY" "$(check endpoint test-endpoint-api)"
run execute-policy "$TMP/c/pol.json" "$TMP/c/ev1.json" --enforce-test
assert_eq "X5 replayed event -> DUPLICATE_IGNORED" "DUPLICATE_IGNORED" "$(jget "$OUT" "d['execution_result']")"
sensor_event ev2 decoy-evt-0002
sensor_event ev3 decoy-evt-0003
run execute-policy "$TMP/c/pol.json" "$TMP/c/ev2.json" --enforce-test
assert_eq "X6 second distinct event uses the second slot" "EXECUTED" "$(jget "$OUT" "d['execution_result']")"
run execute-policy "$TMP/c/pol.json" "$TMP/c/ev3.json" --enforce-test
assert_eq "X6 third event exceeds max_executions=2" "DENIED_POLICY_EXHAUSTED" "$(jget "$OUT" "d['code']")"

echo "[X7] forged / tampered / untrusted events"
sensor_event x7a decoy-evt-x7a "{}" "$TMP/config/keys/rogue-sensor.key"
run execute-policy "$TMP/c/pol.json" "$TMP/c/x7a.json" --enforce-test
assert_eq "X7 event signed with the wrong key" "DENIED_UNAUTHENTICATED" "$(jget "$OUT" "d['code']")"
sensor_event x7b decoy-evt-x7b
python3 -c "import json,sys; e=json.load(open(sys.argv[1])); e['target_ref']='test-session-001'; json.dump(e,open(sys.argv[1],'w'))" "$TMP/c/x7b.json"
run execute-policy "$TMP/c/pol.json" "$TMP/c/x7b.json" --enforce-test
assert_eq "X7 event modified after signing" "DENIED_UNAUTHENTICATED" "$(jget "$OUT" "d['code']")"
sensor_event x7c decoy-evt-x7c "{'sensor_id': 'rogue-sensor'}" "$TMP/config/keys/rogue-sensor.key"
run execute-policy "$TMP/c/pol.json" "$TMP/c/x7c.json" --enforce-test
assert_eq "X7 validly-signed event from a sensor the policy does not name" "DENIED_SENSOR_NOT_TRUSTED" "$(jget "$OUT" "d['code']")"
python3 -c "import json,sys; e=json.load(open(sys.argv[1])); e.pop('signature'); json.dump(e,open(sys.argv[2],'w'))" "$TMP/c/ev3.json" "$TMP/c/x7d.json"
run execute-policy "$TMP/c/pol.json" "$TMP/c/x7d.json" --enforce-test
assert_eq "X7 unsigned event refused" "DENIED_INVALID_INPUT" "$(jget "$OUT" "d['code']")"

echo "[X8] bad policies"
sensor_event x8ev decoy-evt-x8
policy x8a
python3 -c "import json,sys; p=json.load(open(sys.argv[1])); p['max_executions']=20; json.dump(p,open(sys.argv[1],'w'))" "$TMP/c/x8a.json"
run execute-policy "$TMP/c/x8a.json" "$TMP/c/x8ev.json" --enforce-test
assert_eq "X8 policy tampered after signing" "DENIED_UNAUTHENTICATED" "$(jget "$OUT" "d['code']")"
policy x8b "{'issuer': 'intruder'}" "$TMP/config/keys/intruder.key"
run execute-policy "$TMP/c/x8b.json" "$TMP/c/x8ev.json" --enforce-test
assert_eq "X8 validly-signed policy from an issuer not authorized for the action" "DENIED_UNAUTHORIZED" "$(jget "$OUT" "d['code']")"
policy x8c "{'policy_id': 'pol-x8c', 'expires_at': '2026-10-17T11:00:00Z'}"
run execute-policy "$TMP/c/x8c.json" "$TMP/c/x8ev.json" --enforce-test
assert_eq "X8 expired policy" "DENIED_POLICY_EXPIRED" "$(jget "$OUT" "d['code']")"
policy x8d "{'policy_id': 'pol-x8d', 'expires_at': '2026-10-30T00:00:00Z'}"
run execute-policy "$TMP/c/x8d.json" "$TMP/c/x8ev.json" --enforce-test
assert_eq "X8 lifetime over 7 days" "DENIED_POLICY_INVALID" "$(jget "$OUT" "d['code']")"
policy x8e "{'policy_id': 'pol-x8e', 'environment': 'production'}"
run execute-policy "$TMP/c/x8e.json" "$TMP/c/x8ev.json" --enforce-test
assert_eq "X8 production policy" "DENIED_PRODUCTION" "$(jget "$OUT" "d['code']")"
for a in unblock_test_endpoint rotate_keys cloudflare_dns_change; do
  policy "x8f-$a" "{'policy_id': 'pol-x8f', 'rules': [{'source': 'snd_home', 'event_type': 'decoy_access', 'action': '$a', 'target_id': 'test-endpoint-api'}]}"
  run execute-policy "$TMP/c/x8f-$a.json" "$TMP/c/x8ev.json" --enforce-test
  assert_eq "X8 policy rule action '$a' refused" "DENIED_ACTION_NOT_ALLOWLISTED" "$(jget "$OUT" "d['code']")"
done
policy x8g "{'policy_id': 'pol-x8g', 'rules': [{'source': 'snd_home', 'event_type': 'decoy_access', 'action': 'block_test_endpoint', 'target_id': 'prod-api'}]}"
run execute-policy "$TMP/c/x8g.json" "$TMP/c/x8ev.json" --enforce-test
assert_eq "X8 policy target not allowlisted" "DENIED_TARGET_NOT_ALLOWLISTED" "$(jget "$OUT" "d['code']")"

echo "[X9-X10] stale / low / unmatched / unsigned detection records"
policy x9pol "{'policy_id': 'pol-x9'}"
sensor_event x9a decoy-evt-x9a "{'observed_at': '2026-10-17T11:00:00Z'}"
run execute-policy "$TMP/c/x9pol.json" "$TMP/c/x9a.json" --enforce-test
assert_eq "X9 stale event" "DENIED_STALE" "$(jget "$OUT" "d['code']")"
sensor_event x9b decoy-evt-x9b "{'severity': 'low'}"
run execute-policy "$TMP/c/x9pol.json" "$TMP/c/x9b.json" --enforce-test
assert_eq "X9 low-severity event does not trigger" "DENIED_POLICY_NO_MATCH" "$(jget "$OUT" "d['code']")"
sensor_event x9c decoy-evt-x9c "{'type': 'c2_beacon'}"
run execute-policy "$TMP/c/x9pol.json" "$TMP/c/x9c.json" --enforce-test
assert_eq "X9 event type not in the policy" "DENIED_POLICY_NO_MATCH" "$(jget "$OUT" "d['code']")"
printf '%s\n' '{"schema":"waio.snd.detection.v1","event_id":"det-1","source":"snd_id","type":"bulk_data_access","severity":"critical","target_ref":"test-session-001","observed_at":"2026-10-17T11:59:00Z","summary":"x","mode":"DRY_RUN"}' > "$TMP/c/x10.json"
run execute-policy "$TMP/c/x9pol.json" "$TMP/c/x10.json" --enforce-test
assert_eq "X10 an (unsigned) SND detection record can never trigger a policy" "DENIED_INVALID_INPUT" "$(jget "$OUT" "d['code']")"
assert_eq "X7-X10 no refused request added a marker (1 session + 1 endpoint)" "2" "$(find "$TMP/testenv" -name '*.contained' | wc -l | tr -d ' ')"

echo "[X11] evidence preservation and tamper detection"
PCID="$(jget "$(cat "$TMP/state/results/"pol-*.json | head -1)" "d['command_id']")"
run preserve-evidence INC-001 --command-id x1-contain --command-id x1-rel --command-id "$PCID" --event-id decoy-evt-0001
assert_eq "X11 bundle created" "true" "$(jget "$OUT" "str(d['ok']).lower()")"
B="$TMP/evidence/INC-001"
assert_eq "X11 mode recorded (unkeyed)" "sha256-unkeyed" "$(jget "$OUT" "d['mac_mode']")"
for f in MANIFEST.json timeline.json scope.json recovery.md audit/killswitch-audit.jsonl commands/x1-contain.json; do
  assert_eq "X11 bundle has $f" "yes" "$([ -f "$B/$f" ] && echo yes || echo no)"
done
assert_eq "X11 files are read-only" "" "$(python3 -c "import os,sys; print(' '.join(os.path.join(r,n) for r,_,ns in os.walk(sys.argv[1]) for n in ns if os.stat(os.path.join(r,n)).st_mode & 0o222))" "$B")"
assert_contains "X11 timeline covers execution" "$(cat "$B/timeline.json")" "killswitch_command_executed"
assert_contains "X11 recovery steps name the release action" "$(cat "$B/recovery.md")" "release_test_session"
assert_contains "X11 released marker preserved" "$(ls "$B/containment/sessions")" "test-session-001.x1-rel.released"
assert_eq "X11 verify: intact" "ok" "$(jget "$("$GATE" verify-evidence "$B")" "d['verdict']")"
assert_eq "X11 audit chain recorded as ok at preservation" "ok" "$(tr -d '\n' < "$B/audit/integrity_at_preservation.txt")"
chmod u+w "$B/commands/x1-contain.json"; printf ' ' >> "$B/commands/x1-contain.json"
V="$("$GATE" verify-evidence "$B")"
assert_eq "X11 modified file detected" "tampered|['commands/x1-contain.json']" "$(jget "$V" "d['verdict']+'|'+str(d['modified'])")"
chmod u+w "$B/scope.json" "$B"; rm -f "$B/scope.json"
assert_contains "X11 deleted file detected" "$("$GATE" verify-evidence "$B")" '"missing": ["scope.json"]'
run preserve-evidence INC-001 --command-id x1-contain
assert_eq "X11 an existing bundle is never overwritten" "1" "$RC"
export KILLSWITCH_AUDIT_HMAC_KEY_FILE="$TMP/config/keys/audit-hmac.key"
python3 -c "import os,sys; open(sys.argv[1],'wb').write(os.urandom(32))" "$KILLSWITCH_AUDIT_HMAC_KEY_FILE"
rm -f "$TMP/audit.jsonl" "$KILLSWITCH_AUDIT_CHECKPOINT"   # fresh keyed chain for the keyed bundle
run preserve-evidence INC-002 --command-id x1-contain
assert_eq "X11 keyed bundle" "hmac-sha256" "$(jget "$OUT" "d['mac_mode']")"
B2="$TMP/evidence/INC-002"
assert_eq "X11 keyed verify: intact" "ok" "$(jget "$("$GATE" verify-evidence "$B2")" "d['verdict']")"
chmod -R u+w "$B2"
printf '{"forged": true}\n' > "$B2/commands/x1-contain.json"
python3 - "$B2" <<'EOF'
import hashlib, json, os, sys
b = sys.argv[1]; m = json.load(open(os.path.join(b, "MANIFEST.json")))
m["files"]["commands/x1-contain.json"] = hashlib.sha256(open(os.path.join(b, "commands/x1-contain.json"), "rb").read()).hexdigest()
json.dump(m, open(os.path.join(b, "MANIFEST.json"), "w"))
EOF
V="$("$GATE" verify-evidence "$B2")"
assert_eq "X11 attacker rewrote file AND manifest hash without the key -> detected" "tampered|False" "$(jget "$V" "d['verdict']+'|'+str(d['manifest_mac_valid'])")"
unset KILLSWITCH_AUDIT_HMAC_KEY_FILE

echo "[X12] static guards on the new kill-switch files"
for f in $KS/killswitch_policy.py $KS/killswitch_evidence.py $KS/killswitch_sign_policy.py; do
  assert_eq "X12 $f references no WAIO control-plane file/state" "" \
    "$(code_only "$f" | grep -nE '(^|[^a-z])lib\.sh|guardian[a-z_]*\.sh|GUARDIAN_STATE|ducopa\.sh|decision_engine|waio\.sh|recover\.sh|SHUTDOWN\.lock')"
  assert_eq "X12 $f uses no network/system-control tool" "" \
    "$(code_only "$f" | grep -nE '\b(curl|wget|scp|cloudflared|pfctl|networksetup|launchctl|osascript|sudo|subprocess)\b|\bssh[[:space:]]|urllib|http\.client|socket')"
done
assert_eq "X12 gate still has no signing code path" "" "$(code_only $KS/killswitch_gate.sh | grep -nE 'sign_policy|killswitch_sign|\.sign\(')"

echo "[X13] real state untouched"
assert_eq "X13 real security/state/killswitch and logs/killswitch-audit.jsonl unchanged" "$REAL_BEFORE" "$(ls -la security/state/killswitch logs/killswitch-audit.jsonl 2>&1 | cksum)"
assert_eq "X13 no __pycache__ in module dir" "" "$(find $KS -name __pycache__)"

echo
echo "=== Summary: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then printf '  - %s\n' "${FAILURES[@]}"; exit 1; fi
exit 0
