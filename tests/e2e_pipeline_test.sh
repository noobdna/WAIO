#!/bin/bash
set -uo pipefail

# tests/e2e_pipeline_test.sh -- isolated end-to-end harness for the WAIO
# defense pipeline:
#
#   anomaly detection   security/shadow_ai/shadow_ai_monitor.sh (fixture ps/lsof)
#   evidence            security/attack_graph/attack_graph.sh
#                       security/intelligence/intelligence_layer.sh
#   policy decision     security/decision_engine/decision_engine.sh
#   approval            security/red_alert/containment_approval_gate.sh (real)
#                       or a narrow pre-approved policy rule
#   containment         security/guardian.sh via tests/e2e/containment_bridge.sh
#                       (TEST-ONLY bridge -- production has no executor, by design)
#   Guardian validation tests/e2e/guardian_validator.sh (effect via ./waio.sh)
#   recovery            security/guardian_release_agent.sh / security/recover.sh
#   offline fallback    security/continuity.sh (PDC) + workers/orchestrate_worker.sh
#
# Every state path, audit log and lock is redirected into a temp sandbox
# (tests/e2e/lib_env.sh); the only processes started are this suite's
# own children (a loopback listener for the PDC section, tracked by
# PID). No production service, real network device, or real Guardian
# SSH path is touched. S = scenarios, F = failure modes, G = Guardian
# independence, P = PDC / disconnection, D = structural guards.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"

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

code_only() { grep -vE '^[[:space:]]*#' "$1"; }
jfield() { python3 -c 'import json,sys; d=json.loads(sys.argv[1]); print(d.get(sys.argv[2]))' "$1" "$2" 2>/dev/null; }

source tests/e2e/lib_env.sh

ROOT="$(mktemp -d "${TMPDIR:-/tmp}/waio-e2e-test.XXXXXX")"
LISTENER_PID=""
cleanup() {
  # Only this suite's own tracked child; never by name or pattern.
  if [ -n "$LISTENER_PID" ] && jobs -p | grep -qx "$LISTENER_PID"; then
    kill "$LISTENER_PID" 2>/dev/null; wait "$LISTENER_PID" 2>/dev/null
  fi
  rm -rf "${ROOT:?}"
}
trap cleanup EXIT

VALIDATOR_SUM_BEFORE="$(shasum -a 256 tests/e2e/guardian_validator.sh | cut -d' ' -f1)"
REAL_STATE_BEFORE="$(ls -la security/state 2>/dev/null | md5 2>/dev/null || ls -la security/state 2>/dev/null | md5sum)"
orch_count() { ls logs/orchestrate-* results/orchestrate-* 2>/dev/null | wc -l | tr -d ' '; }
REAL_ORCH_BEFORE="$(orch_count)"

# new_sandbox NAME SCENARIO -> fresh isolated sandbox, env exported, fixture written
new_sandbox() {
  local d="$ROOT/$1"
  mkdir -p "$d"
  e2e_sandbox_init "$d" && e2e_write_detection_fixture "$d" "$2"
  SB="$d"
}
future() { python3 -c 'import datetime,sys; print((datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(seconds=int(sys.argv[1]))).strftime("%Y-%m-%dT%H:%M:%SZ"))' "$1"; }
write_policy() { e2e_write_policy "$@"; }   # FILE ENTITY ACTION EXPIRES_AT [MAX_EXECUTIONS] [RULE_ID] -- signed
bridge() { ./tests/e2e/containment_bridge.sh execute "$@"; }
validate() { ./tests/e2e/guardian_validator.sh verify --expect "$1" --target "$2" >/dev/null 2>&1 && echo CONFIRMED || echo NOT_CONFIRMED; }
quarantined() { [ -f "$WAIO_GUARDIAN_QUARANTINE_FILE" ] && grep -Fxq "$1" "$WAIO_GUARDIAN_QUARANTINE_FILE" && echo true || echo false; }
audit_has() { grep -c "\"event_type\": \"$1\"" "$WAIO_AUDIT_LOG" 2>/dev/null || true; }
gstate() { bash -c 'source security/lib.sh; guardian_get_state' 2>/dev/null; }
audit_ok() { bash -c 'source security/lib.sh; verify_audit_log_integrity' 2>/dev/null; }

GP_FIXTURE='{"new_incidents": [{"id": "rogue-agent", "source": "e2e_fixture", "source_url": "https://example.invalid/e2e", "country": "JP", "incident_type": "ai_agent_abuse", "attack_pattern": "autonomous_agent_exfiltration", "confidence_level": "HIGH", "published_at": "2026-10-18T00:00:00Z"}]}'
gate() { ./security/red_alert/containment_approval_gate.sh "$@" 2>/dev/null; }
red_alert_case() {  # red_alert_case NAME -> sandbox whose decision report is RED ALERT-scoped
  new_sandbox "$1" anomaly
  printf '%s\n' "$GP_FIXTURE" > "$SB/fixtures/global_patrol.json"
  e2e_detect_to_decision "$SB" --global-patrol-report "$SB/fixtures/global_patrol.json"
  REP="$SB/run/decisions.json"
}
req() { local who="e2e-analyst"; [ $# -ge 1 ] && who="$1"; gate request "$REP" rogue-agent "$who" --target-type agent --target-id ECHO --proposed-tool "quarantine_agent:ECHO" --rollback-tool "security/guardian_release_agent.sh ECHO --confirm"; }
# approved_shutdown NAME -> RED ALERT sandbox with an APPROVED emergency_shutdown request; sets AID
approved_shutdown() {
  red_alert_case "$1"
  AID="$(jfield "$(gate request "$REP" rogue-agent e2e-analyst --target-type waio --target-id all --proposed-tool emergency_shutdown --rollback-tool "security/recover.sh --confirm")" approval_id)"
  gate approve "$AID" "e2e-approver (fixture human)" "reviewed fixture evidence: CRITICAL agent, whole-WAIO stop approved" >/dev/null
}

echo "=== WAIO isolated end-to-end pipeline harness ==="

echo ""
echo "=== S-series: scenarios ==="

echo ""
echo "[S1] negative control: benign telemetry -> no containment recommendation, bridge refuses, nothing contained"
new_sandbox s1 benign
e2e_detect_to_decision "$SB"; assert_eq "S1 pipeline ran" "0" "$?"
assert_eq "S1 zero RECOMMEND_CONTAINMENT decisions" "0" "$(python3 -c 'import json,sys; print(sum(1 for d in json.load(open(sys.argv[1]))["decisions"] if d["recommended_action"]=="RECOMMEND_CONTAINMENT"))' "$SB/run/decisions.json")"
write_policy "$SB/fixtures/policy.json" rogue-agent "quarantine_agent:ECHO" "$(future 3600)"
OUT="$(bridge --report "$SB/run/decisions.json" --entity rogue-agent --policy "$SB/fixtures/policy.json")"; RC=$?
assert_eq "S1 bridge refuses (exit 3)" "3" "$RC"
assert_eq "S1 ECHO not quarantined" "false" "$(quarantined ECHO)"
assert_eq "S1 validator: dispatch is clear" "CONFIRMED" "$(validate clear ECHO)"

echo ""
echo "[S2] pre-approved policy path: detect -> decide -> quarantine -> independent confirmation -> human release -> confirmed recovery"
new_sandbox s2 anomaly
e2e_detect_to_decision "$SB"; assert_eq "S2 pipeline ran" "0" "$?"
DEC="$(python3 -c 'import json,sys; d=[x for x in json.load(open(sys.argv[1]))["decisions"] if x["entity"]=="rogue-agent"][0]; print(d["recommended_action"], d["risk"], d["local_corroboration"]["present"], d["requires_human_approval_to_act"])' "$SB/run/decisions.json")"
assert_eq "S2 decision: RECOMMEND_CONTAINMENT CRITICAL, locally corroborated, still flags human approval" "RECOMMEND_CONTAINMENT CRITICAL True True" "$DEC"
write_policy "$SB/fixtures/policy.json" rogue-agent "quarantine_agent:ECHO" "$(future 3600)"
OUT="$(bridge --report "$SB/run/decisions.json" --entity rogue-agent --policy "$SB/fixtures/policy.json" --run-id s2)"; RC=$?
assert_eq "S2 bridge exit 0" "0" "$RC"
assert_eq "S2 outcome contained" "contained" "$(jfield "$OUT" outcome)"
assert_eq "S2 validator verdict CONFIRMED" "CONFIRMED" "$(jfield "$OUT" validator_verdict)"
P_OUT="$(./waio.sh -w ECHO "s2 probe" 2>&1)"; P_RC=$?
assert_eq "S2 real dispatch to ECHO refused" "1" "$P_RC"
assert_contains "S2 refusal names quarantine" "$P_OUT" "quarantined"
assert_eq "S2 audit: e2e_bridge_contained" "1" "$(audit_has e2e_bridge_contained)"
assert_eq "S2 audit: e2e_bridge_verified" "1" "$(audit_has e2e_bridge_verified)"
REL="$(./security/guardian_release_agent.sh ECHO 2>&1)"; REL_RC=$?
assert_eq "S2 release without a reason refused (recovery needs a human reason)" "1" "$REL_RC"
assert_eq "S2 still quarantined after refused release" "CONFIRMED" "$(validate quarantined ECHO)"
./security/guardian_release_agent.sh ECHO --confirm "s2: fixture rogue-agent investigated, ECHO verified safe to release" >/dev/null 2>&1
assert_eq "S2 validator confirms recovery (dispatch works again)" "CONFIRMED" "$(validate released ECHO)"
assert_eq "S2 audit chain intact" "ok" "$(audit_ok)"

echo ""
echo "[S3] human approval path through the REAL RED ALERT gate"
new_sandbox s3 anomaly
e2e_detect_to_decision "$SB"
REQ="$(./security/red_alert/containment_approval_gate.sh request "$SB/run/decisions.json" rogue-agent e2e-analyst --target-type agent --target-id ECHO --proposed-tool "quarantine_agent:ECHO" --rollback-tool "security/guardian_release_agent.sh ECHO --confirm" 2>/dev/null)"
assert_contains "S3 a purely LOCAL detection is out of the gate's scope (documented gap: no approval path for local-only containment)" "$REQ" "out_of_scope"
cat > "$SB/fixtures/global_patrol.json" <<'EOF'
{"new_incidents": [{"id": "rogue-agent", "source": "e2e_fixture", "source_url": "https://example.invalid/e2e", "country": "JP", "incident_type": "ai_agent_abuse", "attack_pattern": "autonomous_agent_exfiltration", "confidence_level": "HIGH", "published_at": "2026-10-18T00:00:00Z"}]}
EOF
rm -rf "${SB:?}/run"; e2e_detect_to_decision "$SB" --global-patrol-report "$SB/fixtures/global_patrol.json"
REQ="$(./security/red_alert/containment_approval_gate.sh request "$SB/run/decisions.json" rogue-agent e2e-analyst --target-type agent --target-id ECHO --proposed-tool "quarantine_agent:ECHO" --rollback-tool "security/guardian_release_agent.sh ECHO --confirm" 2>/dev/null)"
AID="$(jfield "$REQ" approval_id)"
assert_eq "S3 RED ALERT + local corroboration: request accepted as PENDING" "PENDING" "$(jfield "$REQ" effective_status)"
OUT="$(bridge --report "$SB/run/decisions.json" --entity rogue-agent --approval-id "$AID")"; RC=$?
assert_eq "S3 bridge refuses a PENDING approval (exit 3)" "3" "$RC"
assert_eq "S3 nothing contained before approval" "false" "$(quarantined ECHO)"
./security/red_alert/containment_approval_gate.sh approve "$AID" "e2e-approver (fixture human)" "reviewed fixture evidence: rogue-agent CRITICAL with local corroboration" >/dev/null 2>&1
cp "$SB/run/decisions.json" "$SB/run/tampered.json"
python3 -c 'import json,sys; p=sys.argv[1]; d=json.load(open(p)); d["decisions"][0]["reasoning"]="tampered after approval"; json.dump(d, open(p,"w"))' "$SB/run/tampered.json"
OUT="$(bridge --report "$SB/run/tampered.json" --entity rogue-agent --approval-id "$AID")"; RC=$?
assert_eq "S3 approval cannot be replayed against a modified report (exit 3)" "3" "$RC"
assert_contains "S3 refusal names the hash mismatch" "$(jfield "$OUT" detail)" "hash mismatch"
OUT="$(bridge --report "$SB/run/decisions.json" --entity rogue-agent --approval-id "$AID" --run-id s3)"; RC=$?
assert_eq "S3 APPROVED -> contained, exit 0" "0" "$RC"
assert_contains "S3 result records who approved" "$(jfield "$OUT" detail)" "e2e-approver"
assert_eq "S3 validator CONFIRMED" "CONFIRMED" "$(jfield "$OUT" validator_verdict)"
REQ2="$(./security/red_alert/containment_approval_gate.sh request "$SB/run/tampered.json" rogue-agent e2e-analyst --target-type agent --target-id ECHO --proposed-tool "quarantine_agent:ECHO" --rollback-tool "x" 2>/dev/null)"
AID2="$(jfield "$REQ2" approval_id)"
./security/red_alert/containment_approval_gate.sh reject "$AID2" "e2e-approver (fixture human)" "rejected: report was edited by hand, not trusted evidence" >/dev/null 2>&1
OUT="$(bridge --report "$SB/run/tampered.json" --entity rogue-agent --approval-id "$AID2")"; RC=$?
assert_eq "S3 REJECTED approval -> refused" "3" "$RC"

echo ""
echo "[S4] emergency_shutdown (human-approved through the gate): whole-WAIO stop, Guardian mirrors it, weak recovery reason refused, real recovery confirmed"
approved_shutdown s4
OUT="$(bridge --report "$REP" --entity rogue-agent --approval-id "$AID" --run-id s4)"; RC=$?
assert_eq "S4 bridge exit 0" "0" "$RC"
assert_eq "S4 validator CONFIRMED shutdown" "CONFIRMED" "$(jfield "$OUT" validator_verdict)"
assert_eq "S4 Guardian state mirrors SHUTDOWN" "SHUTDOWN" "$(gstate)"
./security/recover.sh --confirm "ok ok ok" >/dev/null 2>&1; RC=$?
assert_eq "S4 recover.sh refuses a weak reason (recovery failure is fail-closed)" "1" "$RC"
assert_eq "S4 still shut down after refused recovery" "CONFIRMED" "$(validate shutdown ECHO)"
./security/recover.sh --confirm "s4: fixture rogue-agent investigated, no real host affected, resuming" >/dev/null 2>&1; RC=$?
assert_eq "S4 recover.sh with a real reason exit 0" "0" "$RC"
assert_eq "S4 validator confirms dispatch clear" "CONFIRMED" "$(validate clear ECHO)"
assert_eq "S4 Guardian state back to NORMAL" "NORMAL" "$(gstate)"
assert_eq "S4 audit chain intact" "ok" "$(audit_ok)"

echo ""
echo "=== F-series: failure modes ==="

new_sandbox f anomaly
e2e_detect_to_decision "$SB"
write_policy "$SB/fixtures/policy.json" rogue-agent "quarantine_agent:ECHO" "$(future 3600)"
POL="$SB/fixtures/policy.json"; REP="$SB/run/decisions.json"

echo ""
echo "[F1] malformed events: unparseable report, missing decisions, unknown entity, non-containment decision -> refused, nothing done"
echo '{not json' > "$SB/run/bad.json"
OUT="$(bridge --report "$SB/run/bad.json" --entity rogue-agent --policy "$POL")"; assert_eq "F1 malformed JSON refused" "3" "$?"
echo '{"decisions": "nope"}' > "$SB/run/bad2.json"
OUT="$(bridge --report "$SB/run/bad2.json" --entity rogue-agent --policy "$POL")"; assert_eq "F1 bad decisions list refused" "3" "$?"
OUT="$(bridge --report "$REP" --entity no-such-entity --policy "$POL")"; assert_eq "F1 unknown entity refused" "3" "$?"
python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); d["decisions"][0]["recommended_action"]="ALERT_HUMAN"; json.dump(d, open(sys.argv[2],"w"))' "$REP" "$SB/run/alert.json"
OUT="$(bridge --report "$SB/run/alert.json" --entity rogue-agent --policy "$POL")"; assert_eq "F1 ALERT_HUMAN decision refused" "3" "$?"
python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); d["decisions"][0]["local_corroboration"]={"present": False, "modules": []}; json.dump(d, open(sys.argv[2],"w"))' "$REP" "$SB/run/nolocal.json"
OUT="$(bridge --report "$SB/run/nolocal.json" --entity rogue-agent --policy "$POL")"; assert_eq "F1 no local corroboration refused" "3" "$?"
printf '{garbage\n' >> "$SB/run/shadow_ai.jsonl"
./security/intelligence/intelligence_layer.sh ingest --shadow-ai "$SB/run/shadow_ai.jsonl" > "$SB/run/intel_garbage.json" 2>/dev/null; RC=$?
assert_eq "F1 intelligence layer survives a malformed evidence line (exit 0)" "0" "$RC"
assert_contains "F1 valid evidence still ingested" "$(cat "$SB/run/intel_garbage.json")" "rogue-agent"
assert_eq "F1 nothing contained by any malformed input" "false" "$(quarantined ECHO)"
assert_eq "F1 every refusal audited" "5" "$(audit_has e2e_bridge_refused)"

echo ""
echo "[F2] policy and action limits: expired rule, wildcard entity, unregistered target, disallowed action text -> refused, never executed"
write_policy "$SB/fixtures/expired.json" rogue-agent "quarantine_agent:ECHO" "2020-01-01T00:00:00Z"
OUT="$(bridge --report "$REP" --entity rogue-agent --policy "$SB/fixtures/expired.json")"; assert_eq "F2 expired rule refused" "3" "$?"
write_policy "$SB/fixtures/wild.json" "*" "quarantine_agent:ECHO" "$(future 3600)"
OUT="$(bridge --report "$REP" --entity rogue-agent --policy "$SB/fixtures/wild.json")"; assert_eq "F2 wildcard entity never matches" "3" "$?"
write_policy "$SB/fixtures/unreg.json" rogue-agent "quarantine_agent:NOT_A_WORKER" "$(future 3600)"
OUT="$(bridge --report "$REP" --entity rogue-agent --policy "$SB/fixtures/unreg.json")"; assert_eq "F2 unregistered target refused" "3" "$?"
write_policy "$SB/fixtures/inject.json" rogue-agent 'quarantine_agent:ECHO; touch '"$SB"'/pwned' "$(future 3600)"
OUT="$(bridge --report "$REP" --entity rogue-agent --policy "$SB/fixtures/inject.json")"; assert_eq "F2 shell text in action refused" "3" "$?"
assert_eq "F2 injected command never ran" "false" "$([ -e "$SB/pwned" ] && echo true || echo false)"
write_policy "$SB/fixtures/other.json" rogue-agent "delete_everything" "$(future 3600)"
OUT="$(bridge --report "$REP" --entity rogue-agent --policy "$SB/fixtures/other.json")"; assert_eq "F2 action outside the allowed set refused" "3" "$?"

echo ""
echo "[F3] duplicate events: the same decision executed twice is contained once"
OUT1="$(bridge --report "$REP" --entity rogue-agent --policy "$POL" --run-id f3a)"; RC1=$?
OUT2="$(bridge --report "$REP" --entity rogue-agent --policy "$POL" --run-id f3b)"; RC2=$?
assert_eq "F3 first run contained" "0 contained" "$RC1 $(jfield "$OUT1" outcome)"
assert_eq "F3 second run is a no-op duplicate" "0 duplicate" "$RC2 $(jfield "$OUT2" outcome)"
assert_eq "F3 quarantine list holds ECHO exactly once" "1" "$(grep -cx ECHO "$WAIO_GUARDIAN_QUARANTINE_FILE")"
assert_eq "F3 one contained event, one duplicate event" "1 1" "$(audit_has e2e_bridge_contained) $(audit_has e2e_bridge_duplicate)"
./security/guardian_release_agent.sh ECHO --confirm "f3: duplicate-event check finished, releasing ECHO" >/dev/null 2>&1

fresh_case() {  # fresh_case NAME -> new sandbox with decisions + policy, sets REP/POL
  new_sandbox "$1" anomaly; e2e_detect_to_decision "$SB"
  write_policy "$SB/fixtures/policy.json" rogue-agent "quarantine_agent:ECHO" "$(future 3600)"
  POL="$SB/fixtures/policy.json"; REP="$SB/run/decisions.json"
}

echo ""
echo "[F4] Guardian validation timeout: bounded, containment kept, escalated to a human"
fresh_case f4
T0="$(e2e_now)"
OUT="$(E2E_VALIDATOR_HANG=8 E2E_VALIDATION_TIMEOUT=1 bridge --report "$REP" --entity rogue-agent --policy "$POL")"; RC=$?
T1="$(e2e_now)"
assert_eq "F4 exit 4 contained_unverified" "4 contained_unverified" "$RC $(jfield "$OUT" outcome)"
assert_eq "F4 bounded: whole call under 5 s despite an 8 s hang" "true" "$(python3 -c "print('true' if $T1-$T0 < 5 else 'false')")"
assert_eq "F4 containment left in place" "true" "$(quarantined ECHO)"
assert_eq "F4 audit: e2e_containment_unverified" "1" "$(audit_has e2e_containment_unverified)"
assert_eq "F4 Guardian state raised to WARNING for human review" "WARNING" "$(gstate)"

echo ""
echo "[F5] Guardian unavailable: containment kept, escalated to a human, never reported as confirmed"
fresh_case f5
OUT="$(E2E_VALIDATOR="$SB/no-such-validator" bridge --report "$REP" --entity rogue-agent --policy "$POL")"; RC=$?
assert_eq "F5 exit 4 contained_unverified" "4 contained_unverified" "$RC $(jfield "$OUT" outcome)"
assert_eq "F5 verdict is not CONFIRMED" "None" "$(jfield "$OUT" validator_verdict)"
assert_eq "F5 containment left in place" "true" "$(quarantined ECHO)"

echo ""
echo "[F6] failed containment: quarantine cannot be written -> fail closed to emergency shutdown, independently confirmed"
fresh_case f6
mkdir -p "$WAIO_GUARDIAN_QUARANTINE_FILE"   # a directory: appending to it fails
OUT="$(bridge --report "$REP" --entity rogue-agent --policy "$POL")"; RC=$?
assert_eq "F6 exit 5 escalated_shutdown" "5 escalated_shutdown" "$RC $(jfield "$OUT" outcome)"
assert_eq "F6 shutdown lock present" "true" "$([ -f "$WAIO_SHUTDOWN_LOCK" ] && echo true || echo false)"
assert_eq "F6 validator CONFIRMED the shutdown" "CONFIRMED" "$(jfield "$OUT" validator_verdict)"
assert_eq "F6 audit: e2e_bridge_containment_failed" "1" "$(audit_has e2e_bridge_containment_failed)"
rmdir "$WAIO_GUARDIAN_QUARANTINE_FILE"

echo ""
echo "[F7] validator says NOT_CONFIRMED -> fail closed to emergency shutdown"
fresh_case f7
printf '#!/bin/bash\necho NOT_CONFIRMED\nexit 1\n' > "$SB/deny-validator"; chmod +x "$SB/deny-validator"
OUT="$(E2E_VALIDATOR="$SB/deny-validator" bridge --report "$REP" --entity rogue-agent --policy "$POL")"; RC=$?
assert_eq "F7 exit 5 escalated_shutdown" "5 escalated_shutdown" "$RC $(jfield "$OUT" outcome)"
assert_eq "F7 shutdown lock present" "true" "$([ -f "$WAIO_SHUTDOWN_LOCK" ] && echo true || echo false)"
fresh_case f7b
printf '#!/bin/bash\necho CONFIRMED-ISH\nexit 0\n' > "$SB/liar-validator"; chmod +x "$SB/liar-validator"
OUT="$(E2E_VALIDATOR="$SB/liar-validator" bridge --report "$REP" --entity rogue-agent --policy "$POL")"; RC=$?
assert_eq "F7 exit 0 without the exact word CONFIRMED is not trusted (escalates)" "5" "$RC"

echo ""
echo "[F8] sandbox guard: the bridge refuses to run against any path outside an e2e sandbox"
OUT="$(env -u E2E_SANDBOX ./tests/e2e/containment_bridge.sh execute --report "$REP" --entity rogue-agent --policy "$POL" 2>&1)"; assert_eq "F8 no sandbox -> exit 2" "2" "$?"
OUT="$(WAIO_SHUTDOWN_LOCK="$SCRIPT_DIR/security/state/SHUTDOWN.lock" ./tests/e2e/containment_bridge.sh execute --report "$REP" --entity rogue-agent --policy "$POL" 2>&1)"; RC=$?
assert_eq "F8 real shutdown-lock path -> exit 2" "2" "$RC"
assert_contains "F8 refusal names the variable" "$OUT" "WAIO_SHUTDOWN_LOCK"
OUT="$(WAIO_GUARDIAN_QUARANTINE_FILE=/tmp/GUARDIAN_QUARANTINE ./tests/e2e/containment_bridge.sh execute --report "$REP" --entity rogue-agent --policy "$POL" 2>&1)"; assert_eq "F8 quarantine file outside sandbox -> exit 2" "2" "$?"

echo ""
echo "=== K-series: local-detection authorization (signed policy, budget, human-only actions) ==="

echo ""
echo "[K1] a policy rule only authorizes if it carries a valid operator signature"
fresh_case k1
python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); del d["rules"][0]["signature"]; json.dump(d, open(sys.argv[2],"w"))' "$POL" "$SB/fixtures/unsigned.json"
OUT="$(bridge --report "$REP" --entity rogue-agent --policy "$SB/fixtures/unsigned.json")"; assert_eq "K1 unsigned rule refused" "3" "$?"
python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); d["rules"][0]["max_executions"]=999999; json.dump(d, open(sys.argv[2],"w"))' "$POL" "$SB/fixtures/tampered.json"
OUT="$(bridge --report "$REP" --entity rogue-agent --policy "$SB/fixtures/tampered.json")"; assert_eq "K1 rule edited after signing refused" "3" "$?"
assert_contains "K1 refusal names the signature" "$(jfield "$OUT" detail)" "signature invalid"
REAL_KEY="$E2E_POLICY_KEY_FILE"
( umask 077; python3 -c 'import secrets; print(secrets.token_hex(32))' > "$SB/keys/other.key" )
E2E_POLICY_KEY_FILE="$SB/keys/other.key" write_policy "$SB/fixtures/otherkey.json" rogue-agent "quarantine_agent:ECHO" "$(future 3600)"
OUT="$(bridge --report "$REP" --entity rogue-agent --policy "$SB/fixtures/otherkey.json")"; assert_eq "K1 rule signed with a different key refused" "3" "$?"
assert_eq "K1 nothing contained by any of these" "false" "$(quarantined ECHO)"

echo ""
echo "[K2] the signing key itself must be present, private and inside the sandbox (fail closed)"
chmod 644 "$REAL_KEY"
OUT="$(bridge --report "$REP" --entity rogue-agent --policy "$POL")"; assert_eq "K2 key mode 0644 -> refused" "3" "$?"
chmod 600 "$REAL_KEY"
OUT="$(E2E_POLICY_KEY_FILE="$SB/keys/missing.key" bridge --report "$REP" --entity rogue-agent --policy "$POL")"; assert_eq "K2 missing key -> refused" "3" "$?"
OUT="$(E2E_POLICY_KEY_FILE=/tmp/waio-e2e-not-a-key bridge --report "$REP" --entity rogue-agent --policy "$POL" 2>/dev/null)"; assert_eq "K2 key path outside the sandbox -> exit 2" "2" "$?"

echo ""
echo "[K3] a signed standing policy can never authorize an emergency shutdown -- that needs a human approval"
write_policy "$SB/fixtures/shutdown.json" rogue-agent "emergency_shutdown" "$(future 3600)"
OUT="$(bridge --report "$REP" --entity rogue-agent --policy "$SB/fixtures/shutdown.json")"; assert_eq "K3 refused" "3" "$?"
assert_contains "K3 refusal says human approval is required" "$(jfield "$OUT" detail)" "requires an explicit human approval"
assert_eq "K3 no shutdown lock" "false" "$([ -f "$WAIO_SHUTDOWN_LOCK" ] && echo true || echo false)"

echo ""
echo "[K4] replay: a rule with max_executions=1 is spent after one containment, even for a NEW detection of the same entity"
write_policy "$SB/fixtures/once.json" rogue-agent "quarantine_agent:ECHO" "$(future 3600)" 1 rule-once
OUT="$(bridge --report "$REP" --entity rogue-agent --policy "$SB/fixtures/once.json")"; assert_eq "K4 first use contained" "0" "$?"
./security/guardian_release_agent.sh ECHO --confirm "k4: first containment reviewed, releasing ECHO for the replay check" >/dev/null 2>&1
sleep 1; rm -rf "${SB:?}/run"; e2e_detect_to_decision "$SB"
OUT="$(bridge --report "$REP" --entity rogue-agent --policy "$SB/fixtures/once.json")"; RC=$?
assert_eq "K4 second use with a fresh report refused" "3" "$RC"
assert_contains "K4 refusal names the exhausted budget" "$(jfield "$OUT" detail)" "budget exhausted"
assert_eq "K4 ECHO not re-quarantined" "false" "$(quarantined ECHO)"

echo ""
echo "[K5] the detection side can never sign: no pipeline module or production file references the policy key"
assert_eq "K5 zero references in security/ workers/ waio.sh dashboard/" "0" "$(grep -rlE 'E2E_POLICY_KEY_FILE|policy\.key' security workers waio.sh dashboard 2>/dev/null | wc -l | tr -d ' ')"
assert_eq "K5 the key never appears in any decision or evidence file" "0" "$(grep -rlF "$(cat "$REAL_KEY")" "$SB/run" "$SB/logs" 2>/dev/null | wc -l | tr -d ' ')"

echo ""
echo "=== G-series: Guardian independence ==="

echo ""
echo "[G1] the validator never sources the WAIO control plane or calls a containment/recovery function"
cnt="$(code_only tests/e2e/guardian_validator.sh | grep -cE 'source |\. security/|guardian_[a-z_]+ *\(|guardian_(quarantine|release|approve|set_state|request)|trigger_shutdown|recover\.sh|ducopa' || true)"
assert_eq "G1 zero control-plane references in validator code" "0" "$cnt"

echo ""
echo "[G2] the bridge never references the validator's state, never kills or edits the validator"
cnt="$(code_only tests/e2e/containment_bridge.sh | grep -cE 'E2E_VALIDATOR_DIR|verdicts\.jsonl|pkill|killall|(^|[;&|(]|[[:space:]])kill +[-%$0-9]|chmod|> *"?\$VALIDATOR|rm .*VALIDATOR' || true)"
assert_eq "G2 zero validator-tampering constructs in bridge code (no shell kill at all)" "0" "$cnt"
assert_eq "G2 the only signals sent are run_bounded's, to the process group of the child it forked itself" "2 2" "$(code_only tests/e2e/containment_bridge.sh | grep -o 'kill "' | wc -l | tr -d ' ') $(code_only tests/e2e/containment_bridge.sh | grep -oE 'kill "(TERM|KILL)", -\$pid' | wc -l | tr -d ' ')"

echo ""
echo "[G3] validator script unchanged by the whole run; every verdict line was written by the validator"
assert_eq "G3 validator checksum unchanged" "$VALIDATOR_SUM_BEFORE" "$(shasum -a 256 tests/e2e/guardian_validator.sh | cut -d' ' -f1)"
bad=0
for f in "$ROOT"/*/validator/verdicts.jsonl; do
  [ -f "$f" ] || continue
  python3 -c 'import json,sys; [json.loads(l) for l in open(sys.argv[1])]' "$f" 2>/dev/null || bad=$((bad + 1))
done
assert_eq "G3 every verdict log parses" "0" "$bad"

echo ""
echo "=== P-series: external dependency / network loss (PDC) ==="

new_sandbox p anomaly
PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')"
start_listener() { python3 -m http.server "$PORT" --bind 127.0.0.1 >/dev/null 2>&1 & LISTENER_PID=$!; for _ in $(seq 30); do nc -z 127.0.0.1 "$PORT" 2>/dev/null && return 0; sleep 0.1; done; return 1; }
stop_listener() { jobs -p | grep -qx "$LISTENER_PID" && { kill "$LISTENER_PID"; wait "$LISTENER_PID" 2>/dev/null; }; LISTENER_PID=""; }
echo "AI-API|127.0.0.1|$PORT|ECHO|mock external AI dependency (e2e fixture)" > "$SEGMENT_MANAGER_CONF"
hc() { bash security/health_checker.sh monitor AI-API >/dev/null 2>&1; }
seg() { bash security/segment_manager.sh status AI-API 2>/dev/null; }
pdc() { bash security/continuity.sh "$@" 2>/dev/null; }

echo ""
echo "[P1] connected: dependency reachable, ORCHESTRATE result cached"
start_listener; assert_eq "P1 mock dependency listening" "0" "$?"
hc; assert_eq "P1 health check keeps segment normal" "normal" "$(seg)"
assert_eq "P1 PDC state CONNECTED" "CONNECTED" "$(pdc update)"
OUT="$(WAIO_PIPELINE="ECHO" WAIO_PDC_CACHE=1 ./waio.sh -w ORCHESTRATE "p1 live request" 2>&1)"
assert_contains "P1 live result" "$OUT" "p1 live request"

echo ""
echo "[P2] disconnect: listener stopped; real TCP health checks detect it (normal -> suspicious -> isolated)"
stop_listener
hc; assert_eq "P2 first failed check -> suspicious" "suspicious" "$(seg)"
hc; assert_eq "P2 second failed check -> isolated" "isolated" "$(seg)"
assert_eq "P2 PDC state OFFLINE (the only registered dependency is down)" "OFFLINE" "$(pdc update)"

echo ""
echo "[P3] during the outage: ORCHESTRATE serves the last known good result, labelled stale with its age"
OUT="$(WAIO_PIPELINE="ECHO" WAIO_PDC_FALLBACK=1 ./waio.sh -w ORCHESTRATE "p3 request during outage" 2>&1)"
assert_contains "P3 PDC FALLBACK used" "$OUT" "PDC FALLBACK"
assert_contains "P3 age reported" "$OUT" "age="
assert_contains "P3 content is the cached P1 result" "$OUT" "p1 live request"
assert_eq "P3 the outage-time request is NOT answered live (unavailable while offline)" "false" "$([[ "$OUT" == *"[ECHO WORKER] response:"*"p3 request during outage"* ]] && echo true || echo false)"
assert_contains "P3 fallback audited" "$(cat "$WAIO_CONTINUITY_AUDIT_LOG")" "pdc_cache_fallback"

echo ""
echo "[P4] during the outage: the whole detect -> contain -> verify -> release chain still runs (no external dependency)"
e2e_detect_to_decision "$SB"; assert_eq "P4 pipeline ran offline" "0" "$?"
write_policy "$SB/fixtures/policy.json" rogue-agent "quarantine_agent:ECHO" "$(future 3600)"
OUT="$(bridge --report "$SB/run/decisions.json" --entity rogue-agent --policy "$SB/fixtures/policy.json" --run-id p4)"; RC=$?
assert_eq "P4 contained and confirmed offline" "0 CONFIRMED" "$RC $(jfield "$OUT" validator_verdict)"
OUT="$(WAIO_PIPELINE="ECHO" WAIO_PDC_FALLBACK=1 ./waio.sh -w ORCHESTRATE "p4 request" 2>&1)"
assert_contains "P4 fallback still serves cache while ECHO is quarantined (never dispatches to it)" "$OUT" "PDC FALLBACK"
./security/guardian_release_agent.sh ECHO --confirm "p4: offline containment drill finished, releasing ECHO" >/dev/null 2>&1
assert_eq "P4 release confirmed offline" "CONFIRMED" "$(validate released ECHO)"
printf '(version 1)\n(allow default)\n(deny network*)\n' > "$SB/nonet.sb"
if command -v sandbox-exec >/dev/null 2>&1 && sandbox-exec -f "$SB/nonet.sb" true 2>/dev/null; then
  rm -rf "${SB:?}/run"
  sandbox-exec -f "$SB/nonet.sb" bash -c 'source tests/e2e/lib_env.sh; e2e_detect_to_decision "$1"' _ "$SB"; RC=$?
  assert_eq "P4 decision chain completes with ALL networking denied by the OS sandbox" "0" "$RC"
else
  echo "  SKIP: P4 no-network OS sandbox (sandbox-exec unavailable, or already inside a sandbox that forbids nesting) -- tests/e2e/kill60_bench.sh --no-network covers this outside a sandbox"
fi

echo ""
echo "[P5] no cache for a dependency -> PDC cannot help: falls through to live dispatch (not a silent fake answer)"
rm -f "$WAIO_CONTINUITY_CACHE_DIR"/* 2>/dev/null
OUT="$(WAIO_PIPELINE="ECHO" WAIO_PDC_FALLBACK=1 ./waio.sh -w ORCHESTRATE "p5 request" 2>&1)"
assert_contains "P5 logged: no cached result available" "$OUT" "no cached result available"

echo ""
echo "[P6] restore: dependency back, recovery engine reconnects, PDC resyncs; outage evidence retained"
start_listener
bash -c 'source security/health_checker.sh; source security/recovery_engine.sh; load_segments; recover_segment AI-API reconnect --execute' >/dev/null 2>&1
assert_eq "P6 segment recovered" "recovered" "$(seg)"
bash security/segment_manager.sh set AI-API normal "p6 incident closed" >/dev/null 2>&1
assert_eq "P6 PDC state CONNECTED" "CONNECTED" "$(pdc update)"
assert_contains "P6 continuity_resync logged" "$(cat "$WAIO_CONTINUITY_AUDIT_LOG")" "continuity_resync"
assert_contains "P6 outage-time fallback evidence still in the audit log" "$(cat "$WAIO_CONTINUITY_AUDIT_LOG")" "pdc_cache_fallback"
assert_eq "P6 security audit chain intact across the outage" "ok" "$(audit_ok)"
OUT="$(WAIO_PIPELINE="ECHO" WAIO_PDC_CACHE=1 WAIO_PDC_FALLBACK=1 ./waio.sh -w ORCHESTRATE "p6 live again" 2>&1)"
assert_contains "P6 live dispatch again" "$OUT" "p6 live again"
assert_contains "P6 conflict rule observed: newest live result replaces the cache (last writer wins)" "$(pdc cache-get ECHO)" "p6 live again"
stop_listener

echo ""
echo "[P7] PDC does not replay requests skipped during the outage (documented MVP limit, checked in code)"
assert_eq "P7 no replay/queue construct in continuity.sh" "0" "$(code_only security/continuity.sh | grep -ciE 'replay_|requeue|pending_requests' || true)"

echo ""
echo "[P8] recovery records: every outage/recovery transition is in the segment and PDC audit logs, with its reason"
SEGLOG="$(cat "$SEGMENT_MANAGER_AUDIT_LOG" 2>/dev/null)"
for e in anomaly_detected failure_confirmed recovery_started recovery_succeeded; do assert_contains "P8 segment audit records $e" "$SEGLOG" "\"event\": \"$e\""; done
assert_contains "P8 segment audit records the failed health check reason" "$SEGLOG" "health check failed"
PDCLOG="$(cat "$WAIO_CONTINUITY_AUDIT_LOG")"
assert_contains "P8 PDC audit: CONNECTED -> OFFLINE recorded" "$PDCLOG" "CONNECTED -> OFFLINE"
assert_contains "P8 PDC audit: OFFLINE -> CONNECTED recorded as resync" "$PDCLOG" "OFFLINE -> CONNECTED"

echo ""
echo "[P9] stale-cache age: a 2-hour-old cache entry is served with its real age, never presented as fresh"
CACHE_FILE="$(bash -c 'source security/continuity.sh; continuity_cache_path ECHO' 2>/dev/null)"
hc; hc; assert_eq "P9 dependency down again (listener stopped)" "isolated" "$(seg)"
python3 -c 'import json,sys,datetime; p=sys.argv[1]; d=json.load(open(p)); d["cached_at"]=(datetime.datetime.now(datetime.timezone.utc)-datetime.timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ"); json.dump(d, open(p,"w"))' "$CACHE_FILE"
OUT="$(WAIO_PIPELINE="ECHO" WAIO_PDC_FALLBACK=1 ./waio.sh -w ORCHESTRATE "p9 request" 2>&1)"
AGE="$(printf '%s' "$OUT" | sed -n 's/.*age=\([0-9]*\)s.*/\1/p' | head -1)"
assert_eq "P9 reported age is 2 h (7200-7260 s)" "true" "$([ -n "$AGE" ] && [ "$AGE" -ge 7200 ] && [ "$AGE" -le 7260 ] && echo true || echo false)"
assert_contains "P9 the same age is in the audit record" "$(tail -3 "$WAIO_CONTINUITY_AUDIT_LOG")" "age=${AGE}s"

echo ""
echo "[P10] corrupted cache: never served; treated exactly like a missing cache"
echo '{"worker": "ECHO", "cached_at": ' > "$CACHE_FILE"
OUT="$(WAIO_PIPELINE="ECHO" WAIO_PDC_FALLBACK=1 ./waio.sh -w ORCHESTRATE "p10 request" 2>&1)"
assert_contains "P10 corrupt cache -> no cached result available" "$OUT" "no cached result available"
assert_eq "P10 no fallback line served from garbage" "false" "$([[ "$OUT" == *"serving cached result"* ]] && echo true || echo false)"

echo ""
echo "[P11] synchronization conflict: two concurrent live results -> the cache holds exactly one of them, intact (atomic replace, last writer wins)"
start_listener
bash -c 'source security/health_checker.sh; source security/recovery_engine.sh; load_segments; recover_segment AI-API reconnect --execute' >/dev/null 2>&1
bash security/segment_manager.sh set AI-API normal "p11 back to normal" >/dev/null 2>&1
( WAIO_PIPELINE="ECHO" WAIO_PDC_CACHE=1 ./waio.sh -w ORCHESTRATE "p11 writer A" >/dev/null 2>&1 ) & WA=$!
( WAIO_PIPELINE="ECHO" WAIO_PDC_CACHE=1 ./waio.sh -w ORCHESTRATE "p11 writer B" >/dev/null 2>&1 ) & WB=$!
wait "$WA"; wait "$WB"
C="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["content"])' "$CACHE_FILE" 2>/dev/null)"
assert_eq "P11 cache file is valid JSON" "true" "$([ -n "$C" ] && echo true || echo false)"
assert_eq "P11 cache holds exactly one writer's result" "1" "$( { [[ "$C" == *"p11 writer A"* ]] && echo A; [[ "$C" == *"p11 writer B"* ]] && echo B; } | wc -l | tr -d ' ')"
assert_eq "P11 no temp file left behind" "0" "$(ls "$WAIO_CONTINUITY_CACHE_DIR" | grep -c '\.tmp\.' || true)"
stop_listener

echo ""
echo "[P12] credential-shaped output is never cached (and trips the sandbox's own Emergency Shutdown, by design)"
new_sandbox p12 anomaly
PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')"
echo "AI-API|127.0.0.1|$PORT|ECHO|mock external AI dependency (e2e fixture)" > "$SEGMENT_MANAGER_CONF"
FAKE_KEY="sk-$(printf 'E2EFIXTURE%.0s' 1 2 3)"
OUT="$(WAIO_PIPELINE="ECHO" WAIO_PDC_CACHE=1 ./waio.sh -w ORCHESTRATE "p12 $FAKE_KEY" 2>&1)"
assert_eq "P12 credential-shaped string not in any cache file" "0" "$(cat "$WAIO_CONTINUITY_CACHE_DIR"/* 2>/dev/null | grep -c "$FAKE_KEY" || true)"
assert_eq "P12 sandbox shutdown lock created by secret_leak_check" "true" "$([ -f "$WAIO_SHUTDOWN_LOCK" ] && echo true || echo false)"

echo ""
echo "=== A-series: approval gate and Guardian edge cases ==="


echo ""
echo "[A1] invalid requester identity -> request refused, nothing recorded"
red_alert_case a1
OUT="$(req "")"
assert_eq "A1 empty requested_by refused" "invalid_requested_by" "$(jfield "$OUT" error)"
OUT="$(req "   ")"
assert_eq "A1 whitespace requested_by refused" "invalid_requested_by" "$(jfield "$OUT" error)"
assert_eq "A1 no approval record written" "0" "$(ls "$CONTAINMENT_APPROVAL_STATE_DIR/approvals" 2>/dev/null | wc -l | tr -d ' ')"

echo ""
echo "[A2] invalid approver identity -> approval refused, stays PENDING, bridge refuses"
AID="$(jfield "$(req)" approval_id)"
gate approve "$AID" "" "reviewed fixture evidence carefully before approving" >/dev/null; RC1=$?
gate approve "$AID" "   " "reviewed fixture evidence carefully before approving" >/dev/null; RC2=$?
assert_eq "A2 empty and whitespace approver both refused (non-zero)" "true" "$([ "$RC1" -ne 0 ] && [ "$RC2" -ne 0 ] && echo true || echo false)"
assert_eq "A2 still PENDING" "PENDING" "$(jfield "$(gate status "$AID")" effective_status)"
OUT="$(bridge --report "$REP" --entity rogue-agent --approval-id "$AID")"; assert_eq "A2 bridge refuses" "3" "$?"
gate approve "$AID" "e2e-approver" "ok" >/dev/null; RC=$?
assert_eq "A2 a too-short approval reason is refused too" "true" "$([ "$RC" -ne 0 ] && echo true || echo false)"

echo ""
echo "[A3] an approval cannot be reused for a different entity"
python3 -c 'import json,sys,copy; d=json.load(open(sys.argv[1])); r=copy.deepcopy(d["decisions"][0]); r["entity"]="other-agent"; d["decisions"].append(r); json.dump(d, open(sys.argv[2],"w"))' "$REP" "$SB/run/two.json"
gate approve "$AID" "e2e-approver (fixture human)" "reviewed fixture evidence: rogue-agent CRITICAL with local corroboration" >/dev/null
OUT="$(bridge --report "$SB/run/two.json" --entity other-agent --approval-id "$AID")"; RC=$?
assert_eq "A3 refused" "3" "$RC"
assert_contains "A3 refusal names the entity mismatch" "$(jfield "$OUT" detail)" "different entity"

echo ""
echo "[A4] an APPROVED record past its expires_at is refused by the bridge"
red_alert_case a4
# TTL 10 s, not 2: on a loaded runner request -> approve -> status took
# over 2 s, so approve hit an already-expired record (flake). Then sleep
# until just past the record's own expires_at instead of a fixed 3 s.
# (status keeps an APPROVED record APPROVED after expires_at -- only a
# PENDING one turns EXPIRED -- so the bridge's own expiry check is what
# is tested here.)
AID="$(jfield "$(CONTAINMENT_APPROVAL_TTL_SECONDS=10 req)" approval_id)"
gate approve "$AID" "e2e-approver (fixture human)" "reviewed fixture evidence: rogue-agent CRITICAL with local corroboration" >/dev/null
A4_STATUS="$(gate status "$AID")"
assert_eq "A4 approved" "APPROVED" "$(jfield "$A4_STATUS" effective_status)"
A4_WAIT="$(python3 -c 'import json, sys, datetime as d
e = d.datetime.strptime(json.loads(sys.argv[1])["record"]["expires_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=d.timezone.utc)
print(max(0, int((e - d.datetime.now(d.timezone.utc)).total_seconds()) + 2))' "$A4_STATUS" 2>/dev/null)"
assert_eq "A4 expiry is within the 10 s TTL" "yes" "$( [ -n "$A4_WAIT" ] && [ "$A4_WAIT" -le 12 ] && echo yes || echo "no ($A4_WAIT)")"
sleep "${A4_WAIT:-12}"
OUT="$(bridge --report "$REP" --entity rogue-agent --approval-id "$AID")"; RC=$?
assert_eq "A4 expired approval refused" "3" "$RC"
assert_contains "A4 refusal says expired" "$(jfield "$OUT" detail)" "expired"
assert_eq "A4 nothing contained" "false" "$(quarantined ECHO)"

echo ""
echo "[A5] malformed approval id (path traversal) -> refused by the gate and the bridge"
OUT="$(bridge --report "$REP" --entity rogue-agent --approval-id "../../../etc/passwd")"; RC=$?
assert_eq "A5 refused" "3" "$RC"
assert_contains "A5 refusal comes from the gate's own id validation" "$(jfield "$OUT" detail)" "approval gate:"

echo ""
echo "[A6] Guardian bookkeeping unavailable: emergency shutdown still takes effect (the lock does not depend on Guardian state)"
approved_shutdown a6
mkdir -p "$WAIO_GUARDIAN_STATE_FILE"   # Guardian state file is a directory -> its writes fail
OUT="$(bridge --report "$REP" --entity rogue-agent --approval-id "$AID")"; RC=$?
assert_eq "A6 contained and confirmed despite broken Guardian state" "0 CONFIRMED" "$RC $(jfield "$OUT" validator_verdict)"
assert_eq "A6 shutdown lock present" "true" "$([ -f "$WAIO_SHUTDOWN_LOCK" ] && echo true || echo false)"
rmdir "$WAIO_GUARDIAN_STATE_FILE"

echo ""
echo "[A7] containment action hangs -> bounded by E2E_ACTION_TIMEOUT, then fail-closed to emergency shutdown"
fresh_case a7
mkfifo "$WAIO_GUARDIAN_QUARANTINE_FILE"   # appending to a FIFO with no reader blocks forever
T0="$(e2e_now)"
OUT="$(E2E_ACTION_TIMEOUT=1 bridge --report "$REP" --entity rogue-agent --policy "$POL")"; RC=$?
T1="$(e2e_now)"
assert_eq "A7 escalated to shutdown (exit 5)" "5 escalated_shutdown" "$RC $(jfield "$OUT" outcome)"
assert_eq "A7 bounded: under 8 s" "true" "$(python3 -c "print('true' if $T1-$T0 < 8 else 'false')")"
assert_eq "A7 validator confirmed the shutdown" "CONFIRMED" "$(jfield "$OUT" validator_verdict)"
rm -f "$WAIO_GUARDIAN_QUARANTINE_FILE"

echo ""
echo "[A8] every containment path fails -> reported as containment_failed (exit 5), never as contained"
fresh_case a8
mkdir -p "$WAIO_GUARDIAN_QUARANTINE_FILE" "$SB/state/ro"
chmod 500 "$SB/state/ro"
OUT="$(WAIO_SHUTDOWN_LOCK="$SB/state/ro/SHUTDOWN.lock" bridge --report "$REP" --entity rogue-agent --policy "$POL")"; RC=$?
chmod 700 "$SB/state/ro"
assert_eq "A8 containment_failed, exit 5" "5 containment_failed" "$RC $(jfield "$OUT" outcome)"
assert_eq "A8 no confirmation claimed" "None" "$(jfield "$OUT" validator_verdict)"
assert_eq "A8 both failures audited" "2" "$(audit_has e2e_bridge_containment_failed)"
rmdir "$WAIO_GUARDIAN_QUARANTINE_FILE"

echo ""
echo "=== M-series: mocked Takomachi and SND@HOME (loopback mock, temp copy of the tree, Keychain stubbed) ==="

# Both collectors write fixed logs/*.json paths relative to the tree they
# run in, so they run in a temp copy -- never this checkout's logs/.
TC="$ROOT/treecopy"; mkdir -p "$TC"
git ls-files -z --cached --others --exclude-standard | xargs -0 tar cf - 2>/dev/null | (cd "$TC" && tar xf -)
mkdir -p "$TC/logs" "$TC/security/state"
new_sandbox m anomaly
printf '#!/bin/bash\necho "security $*" >> "%s/keychain.calls"\nexit 44\n' "$SB" > "$SB/bin/security"; chmod +x "$SB/bin/security"
CHECKOUT_LOGS_BEFORE="$(for f in logs/takomachi-status-latest.json logs/snd-status-latest.json; do [ -f "$f" ] && shasum -a 256 "$f" || echo "absent $f"; done)"
MPORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')"
start_mock() { python3 tests/e2e/mock_services.py "$MPORT" >/dev/null 2>&1 & LISTENER_PID=$!; for _ in $(seq 30); do nc -z 127.0.0.1 "$MPORT" 2>/dev/null && return 0; sleep 0.1; done; return 1; }
in_copy() { (cd "$TC" && "$@"); }
tk_field() { python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get(sys.argv[2]))' "$TC/logs/takomachi-status-latest.json" "$1" 2>/dev/null; }

echo ""
echo "[M1] Takomachi reachable (mock), fixture API key in env -> collector reports available, Keychain never consulted"
start_mock; assert_eq "M1 mock listening on loopback" "0" "$?"
in_copy env TAKOMACHI_API_URL="http://127.0.0.1:$MPORT" TAKOMACHI_API_KEY="e2e-fixture-not-a-real-key" dashboard/collect_takomachi_status.sh >/dev/null 2>&1; RC=$?
assert_eq "M1 collector exit 0" "0" "$RC"
assert_eq "M1 available true" "True" "$(tk_field available)"
assert_eq "M1 Keychain stub never called" "false" "$([ -f "$SB/keychain.calls" ] && echo true || echo false)"

echo ""
echo "[M2] Takomachi API key absent -> Keychain lookup attempted (stub fails), reported unavailable, no crash"
in_copy env -u TAKOMACHI_API_KEY TAKOMACHI_API_URL="http://127.0.0.1:$MPORT" dashboard/collect_takomachi_status.sh >/dev/null 2>&1; RC=$?
assert_eq "M2 collector exit 0" "0" "$RC"
assert_eq "M2 available false" "False" "$(tk_field available)"
assert_eq "M2 lookup went to the stub only" "true" "$(grep -q 'find-generic-password' "$SB/keychain.calls" 2>/dev/null && echo true || echo false)"

echo ""
echo "[M3] SND@HOME reachable (mock) -> PDC snapshot written with its cache time"
in_copy env SND_HOME_API_URL="http://127.0.0.1:$MPORT" bash security/continuity.sh snd-snapshot >/dev/null 2>&1; RC=$?
assert_eq "M3 snd-snapshot exit 0" "0" "$RC"
SNAP="$(in_copy bash security/continuity.sh snd-get 2>/dev/null)"
assert_contains "M3 snapshot carries pdc_cached_at" "$SNAP" "pdc_cached_at"
assert_contains "M3 snapshot carries the mock alert" "$SNAP" "ransomware beacon"
SNAP_AT="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["pdc_cached_at"])' "$SNAP" 2>/dev/null)"

echo ""
echo "[M4] SND + Global Patrol evidence alone can never drive containment: capped to ALERT_HUMAN, bridge refuses"
printf '%s\n' "$SNAP" > "$SB/fixtures/snd_snapshot.json"
cat > "$SB/fixtures/gp_snd.json" <<'EOF'
{"new_incidents": [{"id": "KEV-E2E-1", "source": "e2e_fixture", "source_url": "https://example.invalid/e2e2", "country": "US", "incident_type": "vulnerability", "attack_pattern": "ransomware", "confidence_level": "CONFIRMED", "published_at": "2026-10-18T00:00:00Z"}]}
EOF
in_copy ./security/intelligence/intelligence_layer.sh ingest --global-patrol-report "$SB/fixtures/gp_snd.json" --snd-snapshot "$SB/fixtures/snd_snapshot.json" > "$SB/run_m_intel.json" 2>/dev/null
assert_eq "M4 SND cross-reference produced at least one record" "true" "$(python3 -c 'import json,sys; print("true" if json.load(open(sys.argv[1]))["sources_ingested"]["snd_crossref"] >= 1 else "false")' "$SB/run_m_intel.json")"
mkdir -p "$SB/run"; in_copy ./security/decision_engine/decision_engine.sh decide "$SB/run_m_intel.json" > "$SB/run/decisions.json" 2>/dev/null
DEC="$(python3 -c 'import json,sys; d=[x for x in json.load(open(sys.argv[1]))["decisions"] if x["entity"]=="KEV-E2E-1"][0]; print(d["recommended_action"], d["capped_from_recommend_containment"], d["local_corroboration"]["present"])' "$SB/run/decisions.json")"
assert_eq "M4 decision ALERT_HUMAN, capped from containment, no local corroboration" "ALERT_HUMAN True False" "$DEC"
write_policy "$SB/fixtures/policy.json" KEV-E2E-1 "quarantine_agent:ECHO" "$(future 3600)"
OUT="$(bridge --report "$SB/run/decisions.json" --entity KEV-E2E-1 --policy "$SB/fixtures/policy.json")"; assert_eq "M4 bridge refuses even with a matching signed policy rule" "3" "$?"
assert_contains "M4 refusal is about the decision itself" "$(jfield "$OUT" detail)" "not RECOMMEND_CONTAINMENT"

echo ""
echo "[M5] SND@HOME and Takomachi go down -> PDC keeps the last known good SND snapshot; Takomachi reported unavailable"
stop_listener
in_copy env SND_HOME_API_URL="http://127.0.0.1:$MPORT" bash security/continuity.sh snd-snapshot >/dev/null 2>&1; RC=$?
assert_eq "M5 refresh reports failure (non-zero)" "true" "$([ "$RC" -ne 0 ] && echo true || echo false)"
assert_contains "M5 skip audited" "$(cat "$WAIO_CONTINUITY_AUDIT_LOG")" "pdc_snd_snapshot_refresh_skipped"
assert_eq "M5 last known good snapshot preserved (same pdc_cached_at)" "$SNAP_AT" "$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["pdc_cached_at"])' "$(in_copy bash security/continuity.sh snd-get 2>/dev/null)" 2>/dev/null)"
in_copy env TAKOMACHI_API_URL="http://127.0.0.1:$MPORT" TAKOMACHI_API_KEY="e2e-fixture-not-a-real-key" dashboard/collect_takomachi_status.sh >/dev/null 2>&1; RC=$?
assert_eq "M5 Takomachi collector exit 0 while down" "0" "$RC"
assert_eq "M5 Takomachi available false" "False" "$(tk_field available)"

echo ""
echo "[M6] this checkout's own logs/ snapshots were never written by the M-series"
assert_eq "M6 checkout logs unchanged" "$CHECKOUT_LOGS_BEFORE" "$(for f in logs/takomachi-status-latest.json logs/snd-status-latest.json; do [ -f "$f" ] && shasum -a 256 "$f" || echo "absent $f"; done)"

echo ""
echo "=== D-series: structural guards ==="

echo ""
echo "[D1] production modules are unchanged by this harness: decision engine still never names a containment tool"
cnt="$(code_only security/decision_engine/decision_engine.sh | grep -cE 'guardian\.sh|guardian_quarantine_agent|recover\.sh|containment_bridge' || true)"
assert_eq "D1 decision_engine.sh has no containment call" "0" "$cnt"
assert_eq "D1 no production file sources the test bridge" "0" "$(grep -rl 'containment_bridge' security workers waio.sh dashboard 2>/dev/null | wc -l | tr -d ' ')"

echo ""
echo "[D2] no test script here kills by name or pattern"
cnt=0
for f in tests/e2e_pipeline_test.sh tests/e2e/*.sh; do
  c="$(code_only "$f" | grep -cE '(^|[;&|(`]|[[:space:]])(pkill|killall)[[:space:]]' || true)"; cnt=$((cnt + c))
done
assert_eq "D2 zero pkill/killall" "0" "$cnt"

echo ""
echo "[D4] a hostile ~/.waio.env in the caller's HOME is never honoured inside a sandbox"
mkdir -p "$ROOT/hostile_home"; echo "untouched" > "$ROOT/sentinel.lock"
printf 'export WAIO_SHUTDOWN_LOCK="%s"\nexport WAIO_AUTO_NOTIFY=1\n' "$ROOT/sentinel.lock" > "$ROOT/hostile_home/.waio.env"
HOME="$ROOT/hostile_home"; export HOME
new_sandbox d4 anomaly
assert_eq "D4 HOME now points inside the sandbox" "$SB/home" "$HOME"
OUT="$(./waio.sh -w ECHO "d4 probe" 2>&1)"; RC=$?
assert_eq "D4 dispatch works (the hostile lock path was not picked up)" "0" "$RC"
assert_eq "D4 sentinel untouched" "untouched" "$(cat "$ROOT/sentinel.lock")"

echo ""
echo "[D5] ORCHESTRATE runs here write their log/result files inside the sandbox, never this checkout's logs/ or results/"
assert_eq "D5 no new orchestrate-* file in real logs/ or results/" "$REAL_ORCH_BEFORE" "$(orch_count)"

echo ""
echo "[D3] this deployment's real security/state/ listing is unchanged"
assert_eq "D3 real state dir untouched" "$REAL_STATE_BEFORE" "$(ls -la security/state 2>/dev/null | md5 2>/dev/null || ls -la security/state 2>/dev/null | md5sum)"

echo ""
echo "=== Summary: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
  echo "Failures:"
  for f in "${FAILURES[@]}"; do echo "  - $f"; done
  exit 1
fi
exit 0
