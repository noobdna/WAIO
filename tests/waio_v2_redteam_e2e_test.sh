#!/bin/bash
set -uo pipefail

# tests/waio_v2_redteam_e2e_test.sh -- WAIO v2 End-to-End Red Team
# Validation (Detect -> Decide -> Contain -> Preserve Evidence ->
# Recover -> Re-verify), entirely inside a mktemp test environment.
# Live parts: the decoy service really listens on 127.0.0.1 (ephemeral
# port) and is really attacked over loopback; the network blackout in
# R5 is a real macOS sandbox-exec deny-network profile. Nothing leaves
# this machine; no production state, Cloudflare, key or DNS is touched.
#
#   R1  legitimate access is preserved throughout
#   R2  abnormal behaviour is detected (SND@ID mock)
#   R3  unauthorized kill commands are refused
#   R4  the independent gate works with WAIO's main control plane absent
#   R5  emergency channel cut / full network blackout: containment holds
#   R6  revoked sessions and keys cannot be reused
#   R7  decoy access -> signed audit event -> pre-approved containment
#   R8  evidence / audit tampering is detected
#   R9  an AI misjudgment never becomes an unapproved operation
#   R10 recovery, then the whole check set re-runs green

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"
export PYTHONDONTWRITEBYTECODE=1
PASS=0
FAIL=0
SKIP=0
declare -a FAILURES=()
assert_eq() {
  local label="$1" expected="$2" actual="$3"
  if [ "$expected" = "$actual" ]; then PASS=$((PASS + 1)); echo "  PASS: $label"
  else FAIL=$((FAIL + 1)); FAILURES+=("$label (expected='$expected' actual='$actual')"); echo "  FAIL: $label (expected='$expected' actual='$actual')"; fi
}
skip() { SKIP=$((SKIP + 1)); echo "  SKIP: $1"; }
jget() { python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print($2)" <<<"$1" 2>/dev/null; }

KS="$SCRIPT_DIR/security/killswitch"
GATE="$KS/killswitch_gate.sh"
REAL_BEFORE="$(ls -la security/state/killswitch logs/killswitch-audit.jsonl security/state/SHUTDOWN.lock 2>&1 | cksum)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/waio-v2-e2e.XXXXXX")"
DECOY_PID=""
cleanup() {
  [ -n "$DECOY_PID" ] && kill "$DECOY_PID" 2>/dev/null
  [ -n "${RELAY_PID:-}" ] && kill "$RELAY_PID" 2>/dev/null
  chmod -R u+rwx "$TMP" 2>/dev/null; rm -rf "$TMP"
}
trap cleanup EXIT
umask 077
export KILLSWITCH_STATE_DIR="$TMP/ks/state" KILLSWITCH_CONFIG_DIR="$TMP/ks/config" KILLSWITCH_KEYRING_DIR="$TMP/ks/config/keys"
export KILLSWITCH_AUDIT_LOG="$TMP/ks/audit.jsonl" KILLSWITCH_AUDIT_CHECKPOINT="$TMP/ks/state/.cp"
export KILLSWITCH_TEST_ENV="$TMP/testenv" KILLSWITCH_EVIDENCE_DIR="$TMP/evidence"
export KILLSWITCH_AUDIT_HMAC_KEY_FILE="$TMP/ks/config/keys/audit-hmac.key"
NOW="$(date -u +%Y-%m-%dT%H:%M:%SZ)"   # real clock: the decoy stamps real time
mkdir -p "$TMP/ks/config/keys" "$TMP/testenv" "$TMP/c"
printf 'environment=test\n' > "$TMP/testenv/.killswitch-test-env"
cat > "$TMP/ks/config/targets.conf" <<'EOF'
revoke_test_session|test-session-002|test
block_test_endpoint|test-endpoint-api|test
isolate_test_worker|test-worker-echo|test
EOF
cat > "$TMP/ks/config/authz.conf" <<'EOF'
operator-masa|revoke_test_session,block_test_endpoint,isolate_test_worker,release_test_session,unblock_test_endpoint,release_test_worker
EOF
for k in operator-masa decoy-sensor-01 audit-hmac; do
  python3 -c "import os,sys; open(sys.argv[1],'wb').write(os.urandom(32))" "$TMP/ks/config/keys/$k.key"
done
chmod 600 "$TMP"/ks/config/*.conf "$TMP"/ks/config/keys/*.key
OPKEY="$TMP/ks/config/keys/operator-masa.key"
check() { python3 "$KS/killswitch_enforce.py" check "$1" "$2" "$TMP/testenv" | python3 -c "import json,sys; print(json.load(sys.stdin)['verdict'])"; }
sign() {  # sign NAME ACTION TARGET [extra]
  local n="$1" a="$2" t="$3"; shift 3
  python3 "$KS/killswitch_sign.py" --issuer operator-masa --key-file "$OPKEY" --action "$a" --target "$t" \
    --reason "red team drill: operator-confirmed containment step" --command-id "$n" "$@" > "$TMP/c/$n.json"
}
gate() { OUT="$("$GATE" "$@" 2>/dev/null)"; RC=$?; }

legit_access_ok() {   # the legitimate session/worker are never collateral damage
  [ "$(check session test-session-001)" = ALLOW ] && [ "$(check worker test-worker-echo)" = ALLOW ] && echo True || echo False
}

# ------------------------------------------------------------------
echo "[R1] legitimate access preserved (baseline)"
assert_eq "R1 legit session + worker allowed before the incident" "True" "$(legit_access_ok)"
python3 security/snd_behavior/snd_id_mock.py history 7 30 "$TMP/hist.jsonl" >/dev/null
python3 security/snd_behavior/behavior_monitor.py baseline "$TMP/hist.jsonl" "$TMP/base.json" >/dev/null
python3 security/snd_behavior/snd_id_mock.py scenario normal_day "$TMP/normal.jsonl" >/dev/null
OUT="$(python3 security/snd_behavior/behavior_monitor.py detect "$TMP/base.json" "$TMP/normal.jsonl" "$TMP/det-normal")"
assert_eq "R1 a normal working day raises no detection" "0" "$(jget "$OUT" "d['detections']")"

# ------------------------------------------------------------------
echo "[R2] abnormal behaviour detected"
printf '{"bob":"test-session-002"}\n' > "$TMP/targets.json"
python3 security/snd_behavior/snd_id_mock.py scenario token_theft_travel "$TMP/theft.jsonl" >/dev/null
OUT="$(python3 security/snd_behavior/behavior_monitor.py detect "$TMP/base.json" "$TMP/theft.jsonl" "$TMP/det-theft" --targets "$TMP/targets.json")"
assert_eq "R2 impossible travel detected at HIGH" "True" "$(jget "$OUT" "'impossible_travel' in d['rules'] and d['by_risk'].get('HIGH',0) >= 1")"
DET="$(grep -l impossible_travel "$TMP"/det-theft/*.json | head -1)"
gate evaluate-event "$DET"
assert_eq "R2 kill switch turns it into a recommendation only" "revoke_test_session|NOT_EXECUTED" "$(jget "$OUT" "d['record']['recommended_action']+'|'+d['record']['execution_result']")"
assert_eq "R2 detection alone contained nothing" "ALLOW" "$(check session test-session-002)"
# operator decides: signs the containment
sign r2-contain revoke_test_session test-session-002 --event-ref "$(jget "$(cat "$DET")" "d['event_id']")"
gate execute "$TMP/c/r2-contain.json" --enforce-test
assert_eq "R2 operator-signed containment executed" "EXECUTED" "$(jget "$OUT" "d['execution_result']")"
assert_eq "R2 compromised session now denied" "DENY" "$(check session test-session-002)"
assert_eq "R2 legit access unaffected" "True" "$(legit_access_ok)"

# ------------------------------------------------------------------
redteam_commands() {   # R3 body, reused by R10
  local tag="$1"
  python3 -c "import os,sys; open(sys.argv[1],'wb').write(os.urandom(32))" "$TMP/c/attacker.key"; chmod 600 "$TMP/c/attacker.key"
  python3 "$KS/killswitch_sign.py" --issuer operator-masa --key-file "$TMP/c/attacker.key" --action isolate_test_worker \
    --target test-worker-echo --reason "attacker wants the legit worker isolated" --command-id "$tag-forged" > "$TMP/c/$tag-forged.json"
  gate execute "$TMP/c/$tag-forged.json" --enforce-test
  assert_eq "$tag forged signature refused" "DENIED_UNAUTHENTICATED" "$(jget "$OUT" "d['code']")"
  sign "$tag-ai" isolate_test_worker test-worker-echo --origin decision_engine
  gate execute "$TMP/c/$tag-ai.json" --enforce-test
  assert_eq "$tag AI-originated command refused" "DENIED_AI_ORIGIN" "$(jget "$OUT" "d['code']")"
  sign "$tag-prod" block_test_endpoint test-endpoint-api --environment production
  gate execute "$TMP/c/$tag-prod.json" --enforce-test
  assert_eq "$tag production command refused" "DENIED_PRODUCTION" "$(jget "$OUT" "d['code']")"
  sign "$tag-rot" rotate_keys test-endpoint-api
  gate execute "$TMP/c/$tag-rot.json" --enforce-test
  assert_eq "$tag non-allowlisted action refused" "DENIED_ACTION_NOT_ALLOWLISTED" "$(jget "$OUT" "d['code']")"
  sign "$tag-stale" isolate_test_worker test-worker-echo --issued-at "2026-01-01T00:00:00Z"
  gate execute "$TMP/c/$tag-stale.json" --enforce-test
  assert_eq "$tag expired command refused" "DENIED_STALE" "$(jget "$OUT" "d['code']")"
  gate execute "$TMP/c/r2-contain.json" --enforce-test
  assert_eq "$tag replay of an executed command ignored" "DUPLICATE_IGNORED" "$(jget "$OUT" "d['execution_result']")"
  printf 'isolate the echo worker now please\n' > "$TMP/c/$tag-nl.txt"
  gate execute "$TMP/c/$tag-nl.txt" --enforce-test
  assert_eq "$tag natural-language instruction refused" "DENIED_INVALID_INPUT" "$(jget "$OUT" "d['code']")"
  assert_eq "$tag legit worker never isolated by any refused command" "ALLOW" "$(check worker test-worker-echo)"
}
echo "[R3] unauthorized kill commands refused"
redteam_commands R3

# ------------------------------------------------------------------
echo "[R4] independent gate with WAIO's control plane absent"
ISO="$TMP/isolated"
mkdir -p "$ISO/security"
cp -R "$KS" "$ISO/security/killswitch"
printf 'redteam e2e fixture lock\n' > "$ISO/SHUTDOWN.lock"
sign r4 isolate_test_worker test-worker-echo
OUT="$(cd "$ISO" && WAIO_SHUTDOWN_LOCK="$ISO/SHUTDOWN.lock" "$ISO/security/killswitch/killswitch_gate.sh" execute "$TMP/c/r4.json" 2>/dev/null)"
assert_eq "R4 gate copied away from WAIO (no waio.sh, lib.sh, guardian) still decides" "DRY_RUN_NOT_EXECUTED" "$(jget "$OUT" "d['execution_result']")"
assert_eq "R4 the isolated copy contains no WAIO control-plane file" "0" "$(find "$ISO" -name 'waio.sh' -o -name 'lib.sh' -o -name 'guardian*.sh' | wc -l | tr -d ' ')"
gate status
assert_eq "R4 status: configured, DRY_RUN default" "True|DRY_RUN" "$(jget "$OUT" "str(d['configured'])+'|'+d['default_mode']")"

# ------------------------------------------------------------------
echo "[R5] emergency channel cut / network blackout"
# emergency channel stand-in: a loopback relay that would carry signed commands
python3 -c "import socket,time; s=socket.socket(); s.bind(('127.0.0.1',0)); s.listen(1); print(s.getsockname()[1], flush=True); time.sleep(300)" > "$TMP/relay.port" &
RELAY_PID=$!
for _ in 1 2 3 4 5 6 7 8 9 10; do [ -s "$TMP/relay.port" ] && break; sleep 0.2; done
kill "$RELAY_PID" 2>/dev/null; wait "$RELAY_PID" 2>/dev/null; RELAY_PID=""
CUT="$(python3 -c "import socket,sys; s=socket.socket(); s.settimeout(1)
try: s.connect(('127.0.0.1', int(sys.argv[1]))); print('up')
except OSError: print('down')" "$(cat "$TMP/relay.port")")"
assert_eq "R5 emergency channel is really down" "down" "$CUT"
assert_eq "R5 containment still enforced after the channel cut" "DENY" "$(check session test-session-002)"
printf '(version 1)\n(allow default)\n(deny network*)\n' > "$TMP/no-net.sb"
if sandbox-exec -f "$TMP/no-net.sb" true 2>/dev/null; then
  NET="$(sandbox-exec -f "$TMP/no-net.sb" python3 -c "import socket; s=socket.socket(); s.settimeout(1)
try: s.connect(('127.0.0.1', 9)); print('net')
except PermissionError: print('blocked')
except OSError: print('net')")"
  assert_eq "R5 sandbox really blocks all network (incl. loopback)" "blocked" "$NET"
  V="$(sandbox-exec -f "$TMP/no-net.sb" python3 "$KS/killswitch_enforce.py" check session test-session-002 "$TMP/testenv" | python3 -c "import json,sys; print(json.load(sys.stdin)['verdict'])")"
  assert_eq "R5 enforcement under full network blackout: still DENY" "DENY" "$V"
  sign r5-local isolate_test_worker test-worker-echo
  OUT="$(sandbox-exec -f "$TMP/no-net.sb" "$GATE" execute "$TMP/c/r5-local.json" --enforce-test 2>/dev/null)"
  assert_eq "R5 local operator can still contain with no network at all" "EXECUTED" "$(jget "$OUT" "d['execution_result']")"
  assert_eq "R5 worker isolated" "DENY" "$(check worker test-worker-echo)"
else
  skip "R5 sandbox-exec unavailable (non-macOS): network-blackout proof not run; local containment checked without it"
  sign r5-local isolate_test_worker test-worker-echo
  gate execute "$TMP/c/r5-local.json" --enforce-test
  assert_eq "R5 local operator can still contain after the channel cut" "EXECUTED" "$(jget "$OUT" "d['execution_result']")"
  assert_eq "R5 worker isolated" "DENY" "$(check worker test-worker-echo)"
fi

# ------------------------------------------------------------------
echo "[R6] revoked sessions and keys cannot be reused"
gate execute "$TMP/c/r5-local.json" --enforce-test
assert_eq "R6 used command id cannot be replayed" "DUPLICATE_IGNORED" "$(jget "$OUT" "d['execution_result']")"
ZOUT="$(python3 - <<'EOF'
import sys; sys.path.insert(0, "security/zkeys")
import zkeys_lib as z
T = 1_800_000_000; srv = z.ZServer()
a = z.Party("ops", srv.enroll("ops", T)); b = z.Party("guardian", srv.enroll("guardian", T)); a.new_dh(); b.new_dh()
for p in (a, b): srv.register_public(p.request("register_public", T, dh_pub=p.pub), T)
tk = srv.issue_ticket(a.request("issue_ticket", T, peer_id="guardian"), T)
sa, sb = a.open_session(tk, srv.ticket_status, T), b.open_session(tk, srv.ticket_status, T)
m = sa.seal(b"x", T); srv.revoke_ticket(tk["body"]["ticket_id"])
res = []
for fn in (lambda: sb.open(m, T + 1), lambda: b.open_session(tk, srv.ticket_status, T + 1).open(m, T + 1)):
    try: fn(); res.append("reused")
    except z.ZError as e: res.append(e.code)
old = a.mac_key; srv.rotate_enrollment("ops", T + 2)
stale = z.Party("ops", {"key_id": "ops-k1", "mac_key": old}); stale.pub = a.pub
try: srv.issue_ticket(stale.request("issue_ticket", T + 3, peer_id="guardian"), T + 3); res.append("reused")
except z.ZError as e: res.append(e.code)
print("|".join(res))
EOF
)"
assert_eq "R6 revoked Z session, revoked ticket, rotated-out key all refused" "SESSION_NOT_VALID|SESSION_NOT_VALID|UNAUTHENTICATED" "$ZOUT"

# ------------------------------------------------------------------
echo "[R7] decoy access -> signed SND event -> pre-approved containment"
python3 security/deception/decoy_service.py --test-env "$SCRIPT_DIR" --sensor-id decoy-sensor-01 \
  --sensor-key "$TMP/ks/config/keys/decoy-sensor-01.key" --target-ref test-endpoint-api > "$TMP/decoy-bad.out" 2>&1
assert_eq "R7 decoy refuses to run inside the repository" "False" "$(jget "$(cat "$TMP/decoy-bad.out")" "d['ok']")"
python3 security/deception/decoy_service.py --test-env "$TMP/testenv" --sensor-id decoy-sensor-01 \
  --sensor-key "$TMP/ks/config/keys/decoy-sensor-01.key" --target-ref test-endpoint-api > "$TMP/decoy.out" 2>&1 &
DECOY_PID=$!
for _ in $(seq 1 50); do [ -s "$TMP/testenv/decoy/port" ] && break; sleep 0.1; done
PORT="$(cat "$TMP/testenv/decoy/port" 2>/dev/null)"
assert_eq "R7 decoy bound to loopback only" "127.0.0.1" "$(jget "$(head -1 "$TMP/decoy.out")" "d['bind']")"
RESP="$(python3 - "$PORT" <<'EOF'
import sys, urllib.request
port = sys.argv[1]
out = []
for path, data in (("/.env", None), ("/admin/login", b"u=admin&p=hunter2hunter2")):
    try:
        r = urllib.request.urlopen(urllib.request.Request("http://127.0.0.1:%s%s" % (port, path), data=data,
                                   headers={"User-Agent": "redteam-scanner/1.0", "X-Api-Key": "attacker-secret-header"}), timeout=3)
        out.append(r.read().decode())
    except urllib.error.HTTPError as e:
        out.append("HTTP%d" % e.code)
print("\n".join(out))
EOF
)"
assert_eq "R7 attacker got only a synthetic canary" "True" "$([[ "$RESP" == *WAIO-CANARY-dotenv-* ]] && echo True || echo False)"
assert_eq "R7 fake login refused" "True" "$([[ "$RESP" == *HTTP401* ]] && echo True || echo False)"
sleep 0.3
EVENTS=("$TMP"/testenv/decoy/spool/*.json)
assert_eq "R7 each decoy access became one event" "2" "${#EVENTS[@]}"
EV1="$(cat "${EVENTS[0]}")"
assert_eq "R7 event is high-risk SND format" "snd_home|decoy_access|critical" "$(jget "$EV1" "d['source']+'|'+d['type']+'|'+d['severity']")"
ALLEV="$(cat "$TMP"/testenv/decoy/spool/*.json)"
for s in hunter2hunter2 redteam-scanner attacker-secret-header 127.0.0.1 /.env; do
  [[ "$ALLEV" != *"$s"* ]] && ok=True || ok=False
  assert_eq "R7 event omits '$s' (route name only, no body/headers/address/raw path)" "True" "$ok"
done
gate evaluate-event "${EVENTS[0]}"
assert_eq "R7 decoy event also accepted by the SND advisory path" "block_test_endpoint" "$(jget "$OUT" "d['record']['recommended_action']")"
python3 - "$TMP/c/pol.unsigned" <<EOF
import json, sys
json.dump({"schema": "waio.killswitch.policy.v1", "policy_id": "pol-e2e-decoy", "issuer": "operator-masa",
  "issued_at": "$NOW", "expires_at": "2099-01-01T00:00:00Z", "environment": "test", "sensor_ids": ["decoy-sensor-01"],
  "max_executions": 1, "reason": "pre-approved: a decoy hit blocks the test API endpoint",
  "rules": [{"source": "snd_home", "event_type": "decoy_access", "action": "block_test_endpoint", "target_id": "test-endpoint-api"}]},
  open(sys.argv[1], "w"))
EOF
python3 "$KS/killswitch_sign_policy.py" --key-file "$OPKEY" "$TMP/c/pol.unsigned" > "$TMP/c/pol-long.json"
gate execute-policy "$TMP/c/pol-long.json" "${EVENTS[0]}" --enforce-test
assert_eq "R7 a policy with lifetime > 7 days is refused" "DENIED_POLICY_INVALID" "$(jget "$OUT" "d['code']")"
python3 -c "import json,sys,datetime as d; p=json.load(open(sys.argv[1])); p['expires_at']=(d.datetime.utcnow()+d.timedelta(hours=1)).strftime('%Y-%m-%dT%H:%M:%SZ'); json.dump(p,open(sys.argv[1],'w'))" "$TMP/c/pol.unsigned"
python3 "$KS/killswitch_sign_policy.py" --key-file "$OPKEY" "$TMP/c/pol.unsigned" > "$TMP/c/pol.json"
RES="$(security/deception/decoy_responder.sh "$TMP/testenv/decoy/spool" "$TMP/c/pol.json" --enforce-test)"
assert_eq "R7 responder handled both events" "2|ENFORCE_TEST" "$(jget "$RES" "str(d['handled'])+'|'+d['mode']")"
RESULTS="$(cat "$TMP/testenv/decoy/responder-results.jsonl")"
assert_eq "R7 first hit executed, second refused by max_executions=1" "EXECUTED,DENIED" \
  "$(python3 -c "import json,sys; print(','.join(json.loads(l)['execution_result'] for l in sys.stdin))" <<<"$RESULTS")"
assert_eq "R7 attacker-facing endpoint blocked" "DENY" "$(check endpoint test-endpoint-api)"
assert_eq "R7 audit log records preapproved_policy execution" "1" "$(grep killswitch_command_executed "$KILLSWITCH_AUDIT_LOG" | grep -c preapproved_policy | tr -d ' ')"
assert_eq "R7 legit session still allowed" "ALLOW" "$(check session test-session-001)"
kill "$DECOY_PID" 2>/dev/null; wait "$DECOY_PID" 2>/dev/null; DECOY_PID=""

# ------------------------------------------------------------------
echo "[R8] evidence and audit tampering detected"
PCID="$(python3 -c "import json,sys; print([json.loads(l)['command_id'] for l in sys.stdin if json.loads(l)['execution_result']=='EXECUTED'][0])" <<<"$RESULTS")"
DECOY_EID="$(python3 -c "import json,sys; print([json.loads(l)['event_id'] for l in sys.stdin if json.loads(l)['execution_result']=='EXECUTED'][0])" <<<"$RESULTS")"
gate preserve-evidence INC-E2E-001 --command-id r2-contain --command-id r5-local --command-id "$PCID"
assert_eq "R8 evidence bundle preserved with keyed manifest" "True|hmac-sha256" "$(jget "$OUT" "str(d['ok'])+'|'+d['mac_mode']")"
B="$TMP/evidence/INC-E2E-001"
assert_eq "R8 bundle verifies" "ok" "$(jget "$("$GATE" verify-evidence "$B")" "d['verdict']")"
assert_eq "R8 audit chain verifies before tampering" "ok" "$("$GATE" verify-audit)"
cp "$KILLSWITCH_AUDIT_LOG" "$TMP/audit.bak"
python3 - "$KILLSWITCH_AUDIT_LOG" <<'EOF'
import sys
lines = open(sys.argv[1]).read().splitlines(True)
lines[3] = lines[3].replace('"timestamp": "2', '"timestamp": "1', 1)   # backdate one entry
open(sys.argv[1], "w").writelines(lines)
EOF
assert_eq "R8 edited audit line detected" "True" "$([[ "$("$GATE" verify-audit)" == broken* ]] && echo True || echo False)"
sed '$d' "$TMP/audit.bak" > "$KILLSWITCH_AUDIT_LOG"
assert_eq "R8 truncated audit log detected" "True" "$([[ "$("$GATE" verify-audit)" == broken* ]] && echo True || echo False)"
cp "$TMP/audit.bak" "$KILLSWITCH_AUDIT_LOG"
assert_eq "R8 restored log verifies again" "ok" "$("$GATE" verify-audit)"
chmod -R u+w "$B"; printf '{"execution_result": "DENIED"}\n' > "$B/commands/r2-contain.json"
assert_eq "R8 rewritten evidence detected" "tampered" "$(jget "$("$GATE" verify-evidence "$B")" "d['verdict']")"

# ------------------------------------------------------------------
echo "[R9] an AI misjudgment never becomes an unapproved operation"
cat > "$TMP/bad_llm.sh" <<EOF
#!/bin/bash
cat >/dev/null
echo '{"summary":"everything is compromised","recommended_actions":[{"action":"service_shutdown"},{"action":"production_deploy"},{"action":"rotate_production_keys"},{"action":"cloudflare_dns_change"},{"action":"isolate_test_worker"}],"command":"touch $TMP/AI_EXECUTED"}'
EOF
chmod +x "$TMP/bad_llm.sh"
OUT="$(AI_DEFENSE_LLM_CMD="$TMP/bad_llm.sh" python3 security/ai_defense/ai_defense_loop.py analyze "$TMP/ai.json" --input "$TMP/det-theft" --input "$TMP/testenv/decoy/spool" --backend command)"
AI="$(cat "$TMP/ai.json")"
assert_eq "R9 all 5 AI-requested operations rejected, none executed" "5|0" "$(jget "$AI" "str(len(d['rejected_actions']))+'|'+str(len(d['recommended_actions']))")"
assert_eq "R9 AI's embedded command never ran" "absent" "$([ -e "$TMP/AI_EXECUTED" ] && echo present || echo absent)"
python3 -c "import json,sys; json.dump({'schema':'waio.killswitch.command.v1','command_id':'ai-1','action':'isolate_test_worker','target_id':'test-session-001','environment':'test','issued_at':'$NOW','origin':'human_operator','issuer':'operator-masa','reason':'AI says the legit session is compromised','event_ref':'','signature':'0'*64}, open(sys.argv[1],'w'))" "$TMP/c/ai-forged.json"
gate execute "$TMP/c/ai-forged.json" --enforce-test
assert_eq "R9 AI-authored command (no key) refused even claiming human origin" "DENIED_UNAUTHENTICATED" "$(jget "$OUT" "d['code']")"
assert_eq "R9 legit access unaffected by the AI misjudgment" "ALLOW" "$(check session test-session-001)"

# ------------------------------------------------------------------
echo "[R10] recovery, then full re-verification"
sign r10-rel-s release_test_session test-session-002
sign r10-rel-e unblock_test_endpoint test-endpoint-api
sign r10-rel-w release_test_worker test-worker-echo
for n in r10-rel-s r10-rel-e r10-rel-w; do
  gate execute "$TMP/c/$n.json" --enforce-test
  assert_eq "R10 $n executed" "EXECUTED" "$(jget "$OUT" "d['execution_result']")"
done
assert_eq "R10 all targets released" "ALLOW|ALLOW|ALLOW" "$(check session test-session-002)|$(check endpoint test-endpoint-api)|$(check worker test-worker-echo)"
assert_eq "R10 containment history kept as evidence" "3" "$(find "$TMP/testenv" -path '*/released/*.released' | wc -l | tr -d ' ')"
echo "  -- re-test after recovery --"
assert_eq "R10/R1 legit access" "True" "$(legit_access_ok)"
rm -rf "$TMP/det-theft2"
OUT="$(python3 security/snd_behavior/behavior_monitor.py detect "$TMP/base.json" "$TMP/theft.jsonl" "$TMP/det-theft2" --targets "$TMP/targets.json")"
assert_eq "R10/R2 detection still works" "True" "$(jget "$OUT" "'impossible_travel' in d['rules']")"
redteam_commands R10-R3
if sandbox-exec -f "$TMP/no-net.sb" true 2>/dev/null; then
  assert_eq "R10/R5 enforcement point still independent of the network" "ALLOW" "$(sandbox-exec -f "$TMP/no-net.sb" python3 "$KS/killswitch_enforce.py" check session test-session-002 "$TMP/testenv" | python3 -c "import json,sys; print(json.load(sys.stdin)['verdict'])")"
else
  skip "R10/R5 network-blackout re-check (sandbox-exec unavailable)"
fi
sign r10-recontain revoke_test_session test-session-002
gate execute "$TMP/c/r10-recontain.json" --enforce-test
assert_eq "R10 containment usable again after recovery" "EXECUTED|DENY" "$(jget "$OUT" "d['execution_result']")|$(check session test-session-002)"
assert_eq "R10 audit chain intact at the end" "ok" "$("$GATE" verify-audit)"
gate status
assert_eq "R10 no containment reported FAILED" "[]" "$(jget "$OUT" "d['containment_failed']")"

echo "[--] isolation"
assert_eq "real security/state, killswitch audit log and SHUTDOWN.lock untouched" "$REAL_BEFORE" \
  "$(ls -la security/state/killswitch logs/killswitch-audit.jsonl security/state/SHUTDOWN.lock 2>&1 | cksum)"
assert_eq "decoy process stopped" "" "$(pgrep -f "decoy_service.py --test-env $TMP" || true)"

echo
echo "=== Summary: $PASS passed, $FAIL failed, $SKIP skipped ==="
if [ "$FAIL" -gt 0 ]; then printf '  - %s\n' "${FAILURES[@]}"; exit 1; fi
exit 0
