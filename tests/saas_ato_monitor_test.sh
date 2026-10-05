#!/bin/bash
set -uo pipefail

# tests/saas_ato_monitor_test.sh -- regression suite for the SaaS
# Account Takeover (ATO) Monitor (security/saas_ato/saas_ato_lib.py +
# security/saas_ato/saas_ato_monitor.sh +
# security/saas_ato/collectors/*.sh).
#
# Same three-layer convention as tests/ssh_exposure_monitor_test.sh /
# tests/decision_engine_test.sh:
#   U-series: unit tests against saas_ato_lib.py's pure functions,
#     called directly via `python3 -c "sys.path.insert(0,
#     'security/saas_ato'); import saas_ato_lib as sal"` -- no CLI, no
#     file I/O involved at all.
#   I-series: integration tests against saas_ato_monitor.sh's own CLI,
#     fed hand-written RawSignal JSONL fixtures (no mock collector
#     invoked -- same "fixed fixtures prove the CLI, not the mock
#     sample data" discipline tests/decision_engine_test.sh already
#     uses for the Intelligence Layer report shape). Every case runs
#     against an isolated SAAS_ATO_STATE_DIR/SAAS_ATO_AUDIT_LOG, never
#     this deployment's real security/state/saas_ato/.
#   D-series: static structural guards proving this module's own
#     "read-only, no network, no credential, never contains" claims
#     are true in the code, not just asserted in comments -- same
#     posture as tests/decision_engine_test.sh's own D5 (THE critical
#     guard in that suite) applied here to a module one stage further
#     upstream.

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

assert_not_contains() {
  local label="$1" haystack="$2" needle="$3"
  if [[ "$haystack" != *"$needle"* ]]; then
    PASS=$((PASS + 1)); echo "  PASS: $label"
  else
    FAIL=$((FAIL + 1)); FAILURES+=("$label (expected NOT to contain '$needle')")
    echo "  FAIL: $label (expected NOT to contain '$needle', got: $haystack)"
  fi
}

pyval() {
  python3 -c "
import sys
sys.path.insert(0, 'security/saas_ato')
import saas_ato_lib as sal
$1
"
}

echo "=== SaaS ATO Monitor regression suite ==="

echo ""
echo "=== U-series: saas_ato_lib.py unit tests (pure functions, no CLI/file I/O) ==="

echo ""
echo "[U1] parse_signal_line parses a well-formed RawSignal line"
out="$(pyval "
line = '{\"id\":\"x\",\"source\":\"s\",\"tenant\":\"t\",\"account\":\"a@b.com\",\"signal_type\":\"mass_send\",\"detected_at\":\"now\",\"recipient_count\":5}'
r = sal.parse_signal_line(line)
print(r['account'], r['recipient_count'])
")"
assert_eq "U1 valid line parsed" "a@b.com 5" "$out"

echo ""
echo "[U2] parse_signal_line returns None for blank/malformed/missing-required-field lines"
out="$(pyval "
print(sal.parse_signal_line(''))
print(sal.parse_signal_line('not json'))
print(sal.parse_signal_line('{\"id\":\"x\"}'))
")"
assert_eq "U2 all three rejected as None" "$(printf 'None\nNone\nNone')" "$out"

echo ""
echo "[U3] classify_signal mass_send: 9000 recipients -> CRITICAL/HIGH (the 9000-malicious-email scenario)"
out="$(pyval "
risk, conf, basis = sal.classify_signal({'signal_type':'mass_send','recipient_count':9000})
print(risk, conf)
")"
assert_eq "U3 9000 recipients classifies CRITICAL/HIGH" "CRITICAL HIGH" "$out"

echo ""
echo "[U4] classify_signal mass_send: threshold boundaries (499->HIGH, 500->CRITICAL; 19->LOW, 20->MEDIUM; 99->MEDIUM, 100->HIGH)"
out="$(pyval "
for n in (19, 20, 99, 100, 499, 500):
    risk, _, _ = sal.classify_signal({'signal_type':'mass_send','recipient_count':n})
    print(n, risk)
")"
assert_eq "U4 exact boundary values" "$(printf '19 LOW\n20 MEDIUM\n99 MEDIUM\n100 HIGH\n499 HIGH\n500 CRITICAL')" "$out"

echo ""
echo "[U5] classify_signal mass_send: a small, ordinary internal mailing stays LOW (negative control)"
out="$(pyval "
risk, conf, _ = sal.classify_signal({'signal_type':'mass_send','recipient_count':12})
print(risk, conf)
")"
assert_eq "U5 12 recipients is LOW, never CRITICAL" "LOW HIGH" "$out"

echo ""
echo "[U6] classify_signal impossible_travel_signin: fixed HIGH/MEDIUM"
out="$(pyval "
risk, conf, _ = sal.classify_signal({'signal_type':'impossible_travel_signin','location_from':'Tokyo','location_to':'Warsaw','minutes_between':11})
print(risk, conf)
")"
assert_eq "U6 impossible travel is HIGH/MEDIUM" "HIGH MEDIUM" "$out"

echo ""
echo "[U7] classify_signal new_forwarding_rule: external domain -> HIGH/HIGH, internal domain -> MEDIUM/MEDIUM"
out="$(pyval "
r1, c1, _ = sal.classify_signal({'signal_type':'new_forwarding_rule','account':'bob@fabrikam.example.invalid','forwards_to':'x@external.example.invalid'})
r2, c2, _ = sal.classify_signal({'signal_type':'new_forwarding_rule','account':'bob@fabrikam.example.invalid','forwards_to':'archive@fabrikam.example.invalid'})
print(r1, c1)
print(r2, c2)
")"
assert_eq "U7 external HIGH/HIGH, internal MEDIUM/MEDIUM" "$(printf 'HIGH HIGH\nMEDIUM MEDIUM')" "$out"

echo ""
echo "[U8] classify_signal oauth_grant: sensitive scope -> HIGH/MEDIUM, benign scope -> LOW/LOW"
out="$(pyval "
r1, c1, _ = sal.classify_signal({'signal_type':'oauth_grant','app_name':'x','scopes':['Mail.Send']})
r2, c2, _ = sal.classify_signal({'signal_type':'oauth_grant','app_name':'x','scopes':['User.Read']})
print(r1, c1)
print(r2, c2)
")"
assert_eq "U8 sensitive scope HIGH/MEDIUM, benign scope LOW/LOW" "$(printf 'HIGH MEDIUM\nLOW LOW')" "$out"

echo ""
echo "[U9] classify_signal never silently drops or defaults-safe an unrecognized signal_type -- fails closed to MEDIUM/LOW"
out="$(pyval "
risk, conf, basis = sal.classify_signal({'signal_type':'totally_unknown_type'})
print(risk, conf)
print('totally_unknown_type' in basis)
")"
assert_eq "U9 unknown type is MEDIUM/LOW, basis names it" "$(printf 'MEDIUM LOW\nTrue')" "$out"

echo ""
echo "[U10] account_risk_confidence: two or more DISTINCT signal_types for the same account bump confidence to HIGH"
out="$(pyval "
single = [{'signal_type':'oauth_grant','risk':'LOW','confidence':'LOW'}]
multi = [{'signal_type':'oauth_grant','risk':'LOW','confidence':'LOW'}, {'signal_type':'new_forwarding_rule','risk':'MEDIUM','confidence':'MEDIUM'}]
print(sal.account_risk_confidence(single))
print(sal.account_risk_confidence(multi))
")"
assert_eq "U10 single-type keeps its own confidence, multi-type bumps to HIGH" "$(printf "('LOW', 'LOW')\n('MEDIUM', 'HIGH')")" "$out"

echo ""
echo "[U11] compute_correlation: a first-ever scan for an account (prev_account_state=None) produces ZERO events, never a false candidate_incident"
out="$(pyval "
corr, state = sal.compute_correlation(None, '2026-01-01T00:00:00Z', {'mass_send', 'oauth_grant'})
print(corr['events'], corr['candidate_incident'])
print(sorted(state['signal_types'].keys()))
")"
assert_eq "U11 first scan: zero events, state still records current types" "$(printf "[] False\n['mass_send', 'oauth_grant']")" "$out"

echo ""
echo "[U12] compute_correlation: TWO distinct signal_types newly appearing (vs. the previous scan) in the same cycle -> candidate_incident=True"
out="$(pyval "
prev = {'signal_types': {'mass_send': '2026-01-01T00:00:00Z'}, 'last_scan_at': '2026-01-01T00:00:00Z'}
corr, state = sal.compute_correlation(prev, '2026-01-01T00:05:00Z', {'mass_send', 'new_forwarding_rule', 'impossible_travel_signin'})
print(sorted(e['type'] for e in corr['events']))
print(corr['candidate_incident'])
")"
assert_eq "U12 two newly-appeared types trigger candidate_incident" "$(printf "['impossible_travel_signin_appeared', 'new_forwarding_rule_appeared']\nTrue")" "$out"

echo ""
echo "[U13] compute_correlation: only ONE new signal_type appearing -> candidate_incident stays False"
out="$(pyval "
prev = {'signal_types': {'mass_send': '2026-01-01T00:00:00Z'}, 'last_scan_at': '2026-01-01T00:00:00Z'}
corr, _ = sal.compute_correlation(prev, '2026-01-01T00:05:00Z', {'mass_send', 'new_forwarding_rule'})
print(len(corr['events']), corr['candidate_incident'])
")"
assert_eq "U13 one new type is not enough on its own" "1 False" "$out"

echo ""
echo "[U14] compute_correlation: a signal_type already seen stops being 'new' on a repeat scan (no re-trigger from the same ongoing situation)"
out="$(pyval "
prev = {'signal_types': {'mass_send': '2026-01-01T00:00:00Z'}, 'last_scan_at': '2026-01-01T00:00:00Z'}
corr, _ = sal.compute_correlation(prev, '2026-01-01T00:05:00Z', {'mass_send'})
print(corr['events'])
")"
assert_eq "U14 no new events for an already-seen type" "[]" "$out"

echo ""
echo "[U15] build_evidence never emits a bare score -- always names the account, every signal's own basis string, and the correlation verdict"
out="$(pyval "
classified = [{'id':'s1','source':'m365','signal_type':'mass_send','basis':'mass_send: recipient_count=9000 -> CRITICAL'}]
corr = {'window_seconds':300,'events':[],'candidate_incident':False}
ev = sal.build_evidence('alice@contoso.example.invalid', classified, corr)
print(any('alice@contoso.example.invalid' in e for e in ev))
print(any('recipient_count=9000' in e for e in ev))
print(any('candidate_incident' in e for e in ev))
")"
assert_eq "U15 evidence names account, signal basis, and correlation verdict" "$(printf 'True\nTrue\nTrue')" "$out"

echo ""
echo "=== I-series: saas_ato_monitor.sh CLI integration tests (fixed RawSignal fixtures, no mock collector/network) ==="

FIXTURE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/waio-saas-ato-test.XXXXXX")"
trap 'rm -rf "$FIXTURE_DIR"' EXIT
mkdir -p "$FIXTURE_DIR/state"

export SAAS_ATO_STATE_DIR="$FIXTURE_DIR/state"
export SAAS_ATO_AUDIT_LOG="$FIXTURE_DIR/audit.jsonl"

echo ""
echo "[I1] a single mass_send signal with 9000 recipients is detected as CRITICAL on the FIRST scan -- no second cycle needed to confirm it"
echo '{"id":"BURST-1","source":"mock_m365_collector","tenant":"contoso.example.invalid","account":"alice@contoso.example.invalid","signal_type":"mass_send","detected_at":"2026-01-01T00:00:00Z","recipient_count":9000,"window_minutes":5}' > "$FIXTURE_DIR/burst.jsonl"
I1_OUT="$(./security/saas_ato/saas_ato_monitor.sh scan "$FIXTURE_DIR/burst.jsonl" 2>/dev/null)"
assert_eq "I1 risk is CRITICAL" "CRITICAL" "$(echo "$I1_OUT" | python3 -c "import json,sys; print(json.loads(sys.stdin.readline())['risk'])")"
assert_eq "I1 account is alice" "alice@contoso.example.invalid" "$(echo "$I1_OUT" | python3 -c "import json,sys; print(json.loads(sys.stdin.readline())['account'])")"

echo ""
echo "[I2] Negative Control: a benign, small internal mailing list send must NOT classify as CRITICAL or HIGH"
echo '{"id":"NEG-1","source":"mock_m365_collector","tenant":"contoso.example.invalid","account":"newsletter@contoso.example.invalid","signal_type":"mass_send","detected_at":"2026-01-01T00:00:00Z","recipient_count":12,"window_minutes":10}' > "$FIXTURE_DIR/negative.jsonl"
I2_OUT="$(./security/saas_ato/saas_ato_monitor.sh scan "$FIXTURE_DIR/negative.jsonl" 2>/dev/null)"
I2_RISK="$(echo "$I2_OUT" | python3 -c "import json,sys; print(json.loads(sys.stdin.readline())['risk'])")"
assert_eq "I2 negative control stays LOW" "LOW" "$I2_RISK"

echo ""
echo "[I3] a two-scan sequence -- a benign baseline signal type, then a burst PLUS a new external forwarding rule (two BRAND NEW signal types vs. that baseline) for the same account -- trips candidate_incident on the second scan"
rm -f "$FIXTURE_DIR/state/state.json"
printf '{"id":"SEQ-1","source":"mock_m365_collector","tenant":"contoso.example.invalid","account":"carol@contoso.example.invalid","signal_type":"oauth_grant","detected_at":"2026-01-01T00:00:00Z","app_name":"Calendar Sync","scopes":["Calendars.Read"]}\n' > "$FIXTURE_DIR/seq1.jsonl"
./security/saas_ato/saas_ato_monitor.sh scan "$FIXTURE_DIR/seq1.jsonl" >/dev/null 2>/dev/null
printf '%s\n%s\n' \
  '{"id":"SEQ-2","source":"mock_m365_collector","tenant":"contoso.example.invalid","account":"carol@contoso.example.invalid","signal_type":"mass_send","detected_at":"2026-01-01T00:10:00Z","recipient_count":9000,"window_minutes":5}' \
  '{"id":"SEQ-3","source":"mock_m365_collector","tenant":"contoso.example.invalid","account":"carol@contoso.example.invalid","signal_type":"new_forwarding_rule","detected_at":"2026-01-01T00:10:00Z","forwards_to":"x@external.example.invalid"}' \
  > "$FIXTURE_DIR/seq2.jsonl"
I3_OUT="$(./security/saas_ato/saas_ato_monitor.sh scan "$FIXTURE_DIR/seq2.jsonl" 2>/dev/null)"
assert_eq "I3 second scan risk is CRITICAL" "CRITICAL" "$(echo "$I3_OUT" | python3 -c "import json,sys; print(json.loads(sys.stdin.readline())['risk'])")"
assert_eq "I3 second scan candidate_incident is True" "True" "$(echo "$I3_OUT" | python3 -c "import json,sys; print(json.loads(sys.stdin.readline())['correlation']['candidate_incident'])")"

echo ""
echo "[I4] running the SAME scan twice in a row does not spuriously re-trigger candidate_incident for an already-known, ongoing situation"
I4_OUT="$(./security/saas_ato/saas_ato_monitor.sh scan "$FIXTURE_DIR/seq2.jsonl" 2>/dev/null)"
assert_eq "I4 repeat scan candidate_incident is False (nothing NEW appeared)" "False" "$(echo "$I4_OUT" | python3 -c "import json,sys; print(json.loads(sys.stdin.readline())['correlation']['candidate_incident'])")"

echo ""
echo "[I5] malformed/blank lines in the input are skipped gracefully, never crash the scan"
printf 'not valid json\n\n{"id":"OK-1","source":"m365","tenant":"t","account":"ok@contoso.example.invalid","signal_type":"mass_send","detected_at":"2026-01-01T00:00:00Z","recipient_count":5}\n' > "$FIXTURE_DIR/malformed.jsonl"
I5_OUT="$(./security/saas_ato/saas_ato_monitor.sh scan "$FIXTURE_DIR/malformed.jsonl" 2>/dev/null)"
I5_RC=$?
assert_eq "I5 exit code 0 despite malformed lines" "0" "$I5_RC"
assert_contains "I5 the one valid signal still produced a finding" "$I5_OUT" "ok@contoso.example.invalid"

echo ""
echo "[I6] 'status' prints a read-only summary without error, even before any scan has ever run (fresh state dir)"
FRESH_STATE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/waio-saas-ato-fresh.XXXXXX")"
I6_OUT="$(SAAS_ATO_STATE_DIR="$FRESH_STATE_DIR" SAAS_ATO_AUDIT_LOG="$FRESH_STATE_DIR/audit.jsonl" ./security/saas_ato/saas_ato_monitor.sh status)"
assert_contains "I6 fresh status reports no scan yet" "$I6_OUT" "no scan has been run yet"
rm -rf "$FRESH_STATE_DIR"

echo ""
echo "[I7] 'status' after a real scan lists the account and its observed signal_types"
I7_OUT="$(./security/saas_ato/saas_ato_monitor.sh status)"
assert_contains "I7 status lists carol" "$I7_OUT" "carol@contoso.example.invalid"
assert_contains "I7 status lists her signal_types" "$I7_OUT" "mass_send"

echo ""
echo "[I8] this deployment's own real security/state/saas_ato/ was never touched by any case above (every case ran under SAAS_ATO_STATE_DIR override)"
assert_eq "I8 real state dir untouched" "" "$(git status --porcelain security/state/saas_ato/ 2>/dev/null)"

echo ""
echo "=== D-series: structural read-only / no-network / no-credential / NEVER-CONTAINS guards ==="

code_only() {
  grep -vE '^[[:space:]]*#' "$1"
}

echo ""
echo "[D1] this module never sources security/lib.sh and never calls egress_check/audit_log/trigger_shutdown in actual code"
for f in security/saas_ato/saas_ato_monitor.sh security/saas_ato/collectors/mock_m365_collector.sh security/saas_ato/collectors/mock_google_workspace_collector.sh; do
  for pattern in 'source security/lib\.sh' 'egress_check' 'trigger_shutdown' '\baudit_log\('; do
    cnt="$(code_only "$f" | grep -cE "$pattern" || true)"
    assert_eq "D1 $f: zero code occurrences of '$pattern'" "0" "$cnt"
  done
done

echo ""
echo "[D2] zero network tools (curl/wget/nc/ssh) anywhere in the monitor, collectors, or lib's actual code -- this phase makes no real M365/Google Workspace connection at all"
bad_calls=0
for pattern in '\b(curl|wget|nc |ssh )\b'; do
  for f in security/saas_ato/saas_ato_monitor.sh security/saas_ato/collectors/mock_m365_collector.sh security/saas_ato/collectors/mock_google_workspace_collector.sh; do
    c="$(code_only "$f" | grep -cE "$pattern" || true)"
    bad_calls=$((bad_calls + c))
  done
done
assert_eq "D2 zero network invocations" "0" "$bad_calls"

echo ""
echo "[D2b] saas_ato_lib.py never shells out (no subprocess/os.system/os.popen/exec) and makes no network call of its own (no socket/urllib/requests/http.client)"
assert_eq "D2b zero subprocess/os.system/os.popen/os.exec calls" "0" "$(grep -cE '\b(subprocess|os\.system|os\.popen|os\.exec\w*)\b' security/saas_ato/saas_ato_lib.py || true)"
assert_eq "D2b zero socket/urllib/requests/http.client imports" "0" "$(grep -cE '^\s*(import|from)\s+(socket|urllib|requests|http\.client)\b' security/saas_ato/saas_ato_lib.py || true)"

echo ""
echo "[D3] zero hardcoded credentials/tokens/API keys anywhere in the module, and zero references to a real M365/Google Workspace hostname -- proving the 'no network, no credential' scope claim in code, not just in comments"
cred_hits=0
for f in security/saas_ato/saas_ato_lib.py security/saas_ato/saas_ato_monitor.sh security/saas_ato/collectors/mock_m365_collector.sh security/saas_ato/collectors/mock_google_workspace_collector.sh; do
  c="$(code_only "$f" | grep -ciE '(client_secret|api[_-]?key|bearer\s+[A-Za-z0-9]|graph\.microsoft\.com|admin\.googleapis\.com|login\.microsoftonline\.com)' || true)"
  cred_hits=$((cred_hits + c))
done
assert_eq "D3 zero credential-shaped strings or real tenant hostnames" "0" "$cred_hits"

echo ""
echo "[D4] this deployment's real Control Plane conf files were never touched by this suite"
for real_file in security/egress_allowlist.conf security/segments.conf security/ssh_management_allowlist.conf; do
  if [ -f "$real_file" ]; then
    assert_eq "D4 $real_file unchanged" "" "$(git diff --name-only -- "$real_file" 2>/dev/null)"
  fi
done

echo ""
echo "[D5] *** THE CRITICAL GUARD *** zero calls anywhere in saas_ato_monitor.sh's actual code to ANY real WAIO containment/human-gate tool -- this module detects, it never contains. (saas_ato_lib.py is checked separately by D2b: it has no subprocess/os.system/os.popen/exec at all, which already proves it cannot invoke ANY external tool by any name -- a strictly stronger guarantee than a name-based grep, same precedent as the Decision Engine/Intelligence Layer suites' own D2b.)"
containment_calls=0
for pattern in \
  'guardian\.sh' 'guardian_intervene_wrapper\.sh' 'guardian_intervene_quarantine_wrapper\.sh' \
  'guardian_release_agent\.sh' 'guardian_approve\.sh' 'ducopa\.sh' 'recovery_engine\.sh' \
  '\brecover\.sh' 'knowledge_manager\.sh' 'incident_human_gate\.sh' \
  'guardian_quarantine_agent' 'guardian_dispatch' \
; do
  c="$(code_only security/saas_ato/saas_ato_monitor.sh | grep -cE "$pattern" || true)"
  containment_calls=$((containment_calls + c))
done
assert_eq "D5 zero references to any real containment/human-gate tool in saas_ato_monitor.sh's actual code" "0" "$containment_calls"

echo ""
echo "[D6] this module never imports/calls shadow_ai_lib, attack_graph_lib, decision_engine_lib, or intelligence_lib directly -- loose coupling via documented schema only, same discipline as every prior phase"
assert_eq "D6 zero 'import shadow_ai'/'import attack_graph'/'import intelligence_lib'/'import decision_engine_lib' statements" "0" "$(grep -cE '^\s*(import|from)\s+(shadow_ai|attack_graph|intelligence_lib|decision_engine_lib)' security/saas_ato/saas_ato_lib.py || true)"
assert_eq "D6 zero calls to any sibling module's own CLI in actual code" "0" "$(code_only security/saas_ato/saas_ato_monitor.sh | grep -cE 'shadow_ai_monitor\.sh|attack_graph\.sh|intelligence_layer\.sh|decision_engine\.sh' || true)"

echo ""
echo "[D7] the mock collectors never fabricate a risk/confidence verdict themselves -- only saas_ato_lib.py's own classify_signal() is allowed to assign risk/confidence"
assert_not_contains "D7 mock_m365_collector.sh never emits a 'risk' field" "$(code_only security/saas_ato/collectors/mock_m365_collector.sh)" '"risk"'
assert_not_contains "D7 mock_google_workspace_collector.sh never emits a 'risk' field" "$(code_only security/saas_ato/collectors/mock_google_workspace_collector.sh)" '"risk"'

echo ""
echo "=== Summary: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
  echo "Failures:"
  for f in "${FAILURES[@]}"; do echo "  - $f"; done
  exit 1
fi
exit 0
