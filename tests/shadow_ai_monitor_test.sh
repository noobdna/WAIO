#!/bin/bash
set -uo pipefail

# tests/shadow_ai_monitor_test.sh -- regression suite for the Shadow AI
# Monitor (security/shadow_ai/shadow_ai_lib.py +
# security/shadow_ai/shadow_ai_monitor.sh).
#
# Two layers, same convention as tests/fx_validation_test.sh's own
# split:
#   U-series: unit tests against shadow_ai_lib.py's pure functions,
#     called directly via `python3 -c "sys.path.insert(0,
#     'security/shadow_ai'); import shadow_ai_lib as sal"` -- no ps/lsof
#     involved at all.
#   I-series: integration tests against shadow_ai_monitor.sh's own CLI,
#     with `ps` and `lsof` shadowed on PATH by fixture scripts emitting
#     fixed, deterministic output -- same "shadow a binary on PATH"
#     idiom tests/incident_learning_cisa_kev_collector_test.sh's own
#     fake curl already uses. NO REAL process/network state is ever
#     inspected by this suite.
#   D-series: static structural guards proving the module's own
#     "read-only, no network, no Control Plane writes" claims are true
#     in the code, not just asserted in comments.
#
# Every case runs against an isolated SHADOW_AI_SIGNATURES_FILE/
# SHADOW_AI_ALLOWLIST_FILE/SHADOW_AI_STATE_DIR/SHADOW_AI_AUDIT_LOG,
# never this deployment's real security/shadow_ai/known_ai_allowlist.conf
# or security/state/shadow_ai/.

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
  # pyval CODE -- runs CODE with shadow_ai_lib already imported as sal,
  # prints whatever CODE prints. Shared by every U-series case below.
  python3 -c "
import sys
sys.path.insert(0, 'security/shadow_ai')
import shadow_ai_lib as sal
$1
"
}

echo "=== Shadow AI Monitor regression suite ==="

echo ""
echo "=== U-series: shadow_ai_lib.py unit tests (pure functions, no ps/lsof) ==="

echo ""
echo "[U1] redact_args masks known secret shapes, leaves ordinary text alone"
out="$(pyval "print(sal.redact_args('--api-key=sk-FAKE1234567890ABCDEFGH --verbose /opt/app'))")"
assert_not_contains "U1 raw OpenAI-style key not present" "$out" "sk-FAKE1234567890ABCDEFGH"
assert_contains "U1 redaction marker present" "$out" "[REDACTED]"
assert_contains "U1 ordinary flag preserved" "$out" "--verbose"

echo ""
echo "[U2] redact_args masks an Anthropic-style key and a generic token= pattern"
out="$(pyval "print(sal.redact_args('run.sh --key sk-ant-FAKEFAKEFAKEFAKE token=abcdef123456'))")"
assert_not_contains "U2 raw Anthropic-style key not present" "$out" "sk-ant-FAKEFAKEFAKEFAKE"
assert_not_contains "U2 raw token value not present" "$out" "abcdef123456"

echo ""
echo "[U3] redact_args truncates very long strings"
out="$(pyval "print(len(sal.redact_args('x' * 1000)))")"
assert_eq "U3 truncated length is bounded" "true" "$([ "$out" -le 320 ] && echo true || echo false)"

echo ""
echo "[U4] redact_args handles None/empty safely"
out="$(pyval "print(repr(sal.redact_args(None)))")"
assert_eq "U4 None input returns empty string" "''" "$out"

echo ""
echo "[U5] parse_ps_line parses a well-formed line into pid/ppid/user/comm/args"
out="$(pyval "
r = sal.parse_ps_line('  123     1 masa     claude           claude --flag')
print(r['pid'], r['ppid'], r['user'], r['comm'], r['args'])
")"
assert_eq "U5 fields parsed correctly" "123 1 masa claude claude --flag" "$out"

echo ""
echo "[U6] parse_ps_line returns None for a malformed line"
out="$(pyval "print(sal.parse_ps_line('not a valid ps line'))")"
assert_eq "U6 malformed line yields None" "None" "$out"

echo ""
echo "[U7] parse_lsof_line parses a LISTEN line"
out="$(pyval "
r = sal.parse_lsof_line('ollama    300  masa   10u  IPv4 0x1        0t0  TCP  *:11434 (LISTEN)')
print(r['state'], r['local_port'], r['remote_host'], r['pid'], r['command'])
")"
assert_eq "U7 LISTEN parsed correctly" "LISTEN 11434 None 300 ollama" "$out"

echo ""
echo "[U8] parse_lsof_line parses an ESTABLISHED line"
out="$(pyval "
r = sal.parse_lsof_line('python3  456  masa   12u  IPv4 0x2        0t0  TCP  192.168.1.5:54321->140.82.112.3:443 (ESTABLISHED)')
print(r['state'], r['local_port'], r['remote_host'], r['remote_port'])
")"
assert_eq "U8 ESTABLISHED parsed correctly" "ESTABLISHED 54321 140.82.112.3 443" "$out"

echo ""
echo "[U9] parse_lsof_line returns None for an unrelated line (e.g. UDP, no state)"
out="$(pyval "print(sal.parse_lsof_line('sshd  1  root  3u  IPv4 0x0  0t0  UDP  *:68'))")"
assert_eq "U9 unrelated socket line yields None" "None" "$out"

echo ""
echo "[U10] match_process_signatures: process_name match takes precedence, args-only match is reported distinctly"
out="$(pyval "
sigs = [{'type':'process','pattern':'ollama','category':'x','risk':'MEDIUM','label':'l'}]
hits = sal.match_process_signatures('ollama', 'serve', sigs)
print(hits[0][1])
hits2 = sal.match_process_signatures('python3', 'run ollama-wrapper.py', sigs)
print(hits2[0][1])
")"
assert_eq "U10 comm match is process_name, args match is args_substring" "$(printf 'process_name\nargs_substring')" "$out"

echo ""
echo "[U11] match_port_signature is an EXACT match, never a substring"
out="$(pyval "
sigs = [{'type':'port','pattern':'8000','category':'x','risk':'LOW','label':'l'}]
print(sal.match_port_signature(8000, sigs) is not None)
print(sal.match_port_signature(80001, sigs) is None)
print(sal.match_port_signature(800, sigs) is None)
")"
assert_eq "U11 exact match true, near-miss numbers false" "$(printf 'True\nTrue\nTrue')" "$out"

echo ""
echo "[U12] match_domain_in_text matches a domain signature only inside the given text"
out="$(pyval "
sigs = [{'type':'domain','pattern':'api.openai.com','category':'x','risk':'MEDIUM','label':'l'}]
print(len(sal.match_domain_in_text('--base-url https://api.openai.com/v1', sigs)))
print(len(sal.match_domain_in_text('--base-url https://example.invalid', sigs)))
")"
assert_eq "U12 one match, then zero" "$(printf '1\n0')" "$out"

echo ""
echo "[U13] is_allowlisted requires an exact (type, pattern) match"
out="$(pyval "
allow = [{'type':'process','pattern':'claude','label':'l'}]
print(sal.is_allowlisted(allow, 'process', 'claude'))
print(sal.is_allowlisted(allow, 'process', 'ollama'))
print(sal.is_allowlisted(allow, 'port', 'claude'))
")"
assert_eq "U13 exact match true, different pattern/type false" "$(printf 'True\nFalse\nFalse')" "$out"

echo ""
echo "[U14] classify_risk: allowlisted is always LOW regardless of base risk or finding type"
out="$(pyval "print(sal.classify_risk('HIGH', True, 'agent_to_agent'))")"
assert_eq "U14 allowlisted HIGH-base agent_to_agent still LOW" "LOW" "$out"

echo ""
echo "[U15] classify_risk: not allowlisted keeps base risk for a plain process/outbound finding"
out="$(pyval "print(sal.classify_risk('MEDIUM', False, 'process'))")"
assert_eq "U15 unescalated base risk preserved" "MEDIUM" "$out"

echo ""
echo "[U16] classify_risk: not allowlisted escalates ONE step for listening_port and agent_to_agent, capped at CRITICAL"
out="$(pyval "
print(sal.classify_risk('MEDIUM', False, 'listening_port'))
print(sal.classify_risk('HIGH', False, 'agent_to_agent'))
print(sal.classify_risk('CRITICAL', False, 'agent_to_agent'))
")"
assert_eq "U16 escalates by one, caps at CRITICAL" "$(printf 'HIGH\nCRITICAL\nCRITICAL')" "$out"

echo ""
echo "[U17] classify_confidence: stated table, unknown match_kind defaults to MEDIUM (never HIGH by accident)"
out="$(pyval "
print(sal.classify_confidence('exact_port'))
print(sal.classify_confidence('process_name'))
print(sal.classify_confidence('args_substring'))
print(sal.classify_confidence('domain_in_args'))
print(sal.classify_confidence('some_future_unlisted_kind'))
")"
assert_eq "U17 confidence table matches spec" "$(printf 'HIGH\nHIGH\nMEDIUM\nMEDIUM\nMEDIUM')" "$out"

echo ""
echo "[U18] stable_identity is deterministic and input-sensitive (same inputs -> same id, different inputs -> different id)"
out="$(pyval "
a = sal.stable_identity('process', 'ollama', 'ollama')
b = sal.stable_identity('process', 'ollama', 'ollama')
c = sal.stable_identity('process', 'ollama', 'other')
print(a == b)
print(a != c)
print(a.startswith('SHADOWAI-'))
")"
assert_eq "U18 deterministic, sensitive to extra, correctly prefixed" "$(printf 'True\nTrue\nTrue')" "$out"

echo ""
echo "[U19] find_agent_links flags a loopback connection between two DIFFERENT AI-signature-matched processes, never a self-connection or a non-AI pair"
out="$(pyval "
sigs = [{'type':'process','pattern':'ollama','category':'local_llm_runtime','risk':'MEDIUM','label':'l'},
        {'type':'process','pattern':'autogpt','category':'ai_agent_framework','risk':'HIGH','label':'l'}]
ps_records = [
    {'pid': 300, 'ppid': 1, 'user': 'masa', 'comm': 'ollama', 'args': 'serve'},
    {'pid': 200, 'ppid': 1, 'user': 'masa', 'comm': 'autogpt', 'args': 'run'},
    {'pid': 400, 'ppid': 1, 'user': 'masa', 'comm': 'finder', 'args': ''},
]
lsof_records = [
    {'command':'ollama','pid':300,'user':'masa','state':'LISTEN','local_host':'*','local_port':11434,'remote_host':None,'remote_port':None},
    {'command':'autogpt','pid':200,'user':'masa','state':'ESTABLISHED','local_host':'127.0.0.1','local_port':54321,'remote_host':'127.0.0.1','remote_port':11434},
    {'command':'finder','pid':400,'user':'masa','state':'ESTABLISHED','local_host':'127.0.0.1','local_port':55555,'remote_host':'127.0.0.1','remote_port':9999},
]
links = sal.find_agent_links(ps_records, lsof_records, sigs)
print(len(links))
client_rec, client_sig, listener_pid, listener_command, port = links[0]
print(client_rec['comm'], listener_pid, listener_command, port)
")"
assert_eq "U19 exactly one link found, correctly identifying both sides" "$(printf '1\nautogpt 300 ollama 11434')" "$out"

echo ""
echo "[U20] find_agent_links does not flag a NON-loopback established connection, even between two AI-flagged processes"
out="$(pyval "
sigs = [{'type':'process','pattern':'ollama','category':'local_llm_runtime','risk':'MEDIUM','label':'l'}]
ps_records = [{'pid': 300, 'ppid': 1, 'user': 'masa', 'comm': 'ollama', 'args': ''}]
lsof_records = [
    {'command':'ollama','pid':300,'user':'masa','state':'LISTEN','local_host':'*','local_port':11434,'remote_host':None,'remote_port':None},
    {'command':'ollama','pid':300,'user':'masa','state':'ESTABLISHED','local_host':'10.0.0.5','local_port':54321,'remote_host':'203.0.113.9','remote_port':11434},
]
print(len(sal.find_agent_links(ps_records, lsof_records, sigs)))
")"
assert_eq "U20 zero links for a non-loopback remote host" "0" "$out"

echo ""
echo "[U21] merge_inventory: a new finding gets first_seen=now; a repeat finding keeps its original first_seen and increments times_seen; an absent-this-scan entry is left untouched (no silent disappearance)"
out="$(pyval "
existing = {'SHADOWAI-old': {'id': 'SHADOWAI-old', 'first_seen': '2020-01-01T00:00:00Z', 'last_seen': '2020-01-01T00:00:00Z', 'times_seen': 5, 'finding_type':'x','category':'x','signature_matched':'x','signature_label':'x','allowlisted':False,'last_risk':'LOW','last_confidence':'LOW'}}
findings = [{'id': 'SHADOWAI-old', 'finding_type':'x','category':'x','signature_matched':'x','signature_label':'x','allowlisted':False,'risk':'MEDIUM','confidence':'HIGH'},
            {'id': 'SHADOWAI-new', 'finding_type':'y','category':'y','signature_matched':'y','signature_label':'y','allowlisted':False,'risk':'HIGH','confidence':'HIGH'}]
merged = sal.merge_inventory(existing, findings, '2026-01-01T00:00:00Z')
print(merged['SHADOWAI-old']['first_seen'])
print(merged['SHADOWAI-old']['times_seen'])
print(merged['SHADOWAI-old']['last_risk'])
print(merged['SHADOWAI-new']['first_seen'])
print(merged['SHADOWAI-new']['times_seen'])
")"
assert_eq "U21 first_seen preserved, times_seen incremented, new entry correct" "$(printf '2020-01-01T00:00:00Z\n6\nMEDIUM\n2026-01-01T00:00:00Z\n1')" "$out"

echo ""
echo "=== I-series: shadow_ai_monitor.sh CLI integration tests (ps/lsof shadowed on PATH) ==="

FIXTURE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/waio-shadow-ai-test.XXXXXX")"
trap 'rm -rf "$FIXTURE_DIR"' EXIT
mkdir -p "$FIXTURE_DIR/bin" "$FIXTURE_DIR/state"

cat > "$FIXTURE_DIR/signatures.conf" <<'EOF'
process|ollama|local_llm_runtime|MEDIUM|Ollama local LLM runtime
process|autogpt|ai_agent_framework|HIGH|AutoGPT autonomous agent
process|claude|ai_desktop_app|LOW|Claude desktop/CLI process
port|11434|local_llm_runtime|MEDIUM|Ollama default API port
domain|api.openai.com|cloud_ai_api|MEDIUM|OpenAI API
EOF

cat > "$FIXTURE_DIR/allowlist.conf" <<'EOF'
process|claude|Claude Code CLI -- reviewed and approved
EOF

# --- fake ps: fixed, deterministic process table -----------------------
cat > "$FIXTURE_DIR/bin/ps" <<'FAKEPS'
#!/bin/bash
cat <<'PSOUT'
   300     1 masa     ollama           /usr/local/bin/ollama serve
   200     1 masa     autogpt          /usr/bin/python3 /opt/autogpt/main.py --api-key=sk-FAKEFAKEFAKEFAKEFAKE12345
   150     1 masa     claude           claude
   400     1 masa     finder           /System/Library/CoreServices/Finder.app/Contents/MacOS/Finder
   500     1 masa     curl-caller      /usr/bin/python3 caller.py --base-url https://api.openai.com/v1
PSOUT
FAKEPS
chmod +x "$FIXTURE_DIR/bin/ps"

# --- fake lsof: fixed, deterministic socket table -----------------------
cat > "$FIXTURE_DIR/bin/lsof" <<'FAKELSOF'
#!/bin/bash
cat <<'LSOFOUT'
COMMAND   PID  USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
ollama    300  masa   10u  IPv4 0x1        0t0  TCP  *:11434 (LISTEN)
autogpt   200  masa   12u  IPv4 0x2        0t0  TCP  127.0.0.1:54321->127.0.0.1:11434 (ESTABLISHED)
finder    400  masa   14u  IPv4 0x3        0t0  TCP  127.0.0.1:55555->127.0.0.1:9999 (ESTABLISHED)
sshd      999  root   16u  IPv4 0x4        0t0  TCP  *:22 (LISTEN)
LSOFOUT
FAKELSOF
chmod +x "$FIXTURE_DIR/bin/lsof"

export PATH="$FIXTURE_DIR/bin:$PATH"
export SHADOW_AI_SIGNATURES_FILE="$FIXTURE_DIR/signatures.conf"
export SHADOW_AI_ALLOWLIST_FILE="$FIXTURE_DIR/allowlist.conf"
export SHADOW_AI_STATE_DIR="$FIXTURE_DIR/state"
export SHADOW_AI_AUDIT_LOG="$FIXTURE_DIR/audit.jsonl"

REAL_STATE_BEFORE="not_present"
[ -d security/state/shadow_ai ] && REAL_STATE_BEFORE="$(find security/state/shadow_ai -type f 2>/dev/null | sort | tr '\n' ',')"

echo ""
echo "[I1] scan emits valid JSONL, one line per finding, nothing else on stdout"
OUT="$(./security/shadow_ai/shadow_ai_monitor.sh scan 2>/tmp/waio-shadow-ai-i1-stderr.log)"
RC=$?
assert_eq "I1 exit code 0" "0" "$RC"
bad_json=0
while IFS= read -r l; do [ -n "$l" ] || continue; python3 -c "import json,sys; json.loads(sys.argv[1])" "$l" 2>/dev/null || bad_json=$((bad_json+1)); done <<< "$OUT"
assert_eq "I1 every stdout line is valid JSON" "0" "$bad_json"

echo ""
echo "[I2] an un-allowlisted process match (ollama) is reported at its base risk, HIGH confidence (matched by comm)"
OLLAMA_LINE="$(echo "$OUT" | grep '"signature_matched": "ollama"')"
assert_contains "I2 ollama process finding present" "$OUT" '"signature_matched": "ollama"'
assert_contains "I2 risk MEDIUM (base, not allowlisted)" "$OLLAMA_LINE" '"risk": "MEDIUM"'
assert_contains "I2 confidence HIGH (comm match)" "$OLLAMA_LINE" '"confidence": "HIGH"'
assert_contains "I2 allowlisted false" "$OLLAMA_LINE" '"allowlisted": false'

echo ""
echo "[I3] an ALLOWLISTED process match (claude) is reported at LOW risk regardless of base"
CLAUDE_LINE="$(echo "$OUT" | grep '"signature_matched": "claude"')"
assert_contains "I3 claude process finding present" "$OUT" '"signature_matched": "claude"'
assert_contains "I3 risk LOW (allowlisted)" "$CLAUDE_LINE" '"risk": "LOW"'
assert_contains "I3 allowlisted true" "$CLAUDE_LINE" '"allowlisted": true'

echo ""
echo "[I4] a LISTENING port match (ollama:11434) is reported as listening_port, risk escalated one step above base (MEDIUM->HIGH)"
LISTEN_LINE="$(echo "$OUT" | grep '"finding_type": "listening_port"')"
assert_contains "I4 listening_port finding present" "$OUT" '"finding_type": "listening_port"'
assert_contains "I4 risk escalated to HIGH" "$LISTEN_LINE" '"risk": "HIGH"'

echo ""
echo "[I5] an OUTBOUND connection to a known AI port (autogpt -> 127.0.0.1:11434) is reported as outbound_connection using the REMOTE port, not autogpt's own ephemeral local port"
OUTBOUND_LINE="$(echo "$OUT" | grep '"finding_type": "outbound_connection"')"
assert_contains "I5 outbound_connection finding present" "$OUT" '"finding_type": "outbound_connection"'
assert_contains "I5 remote_port 11434 recorded" "$OUTBOUND_LINE" '"remote_port": 11434'
assert_not_contains "I5 does NOT key off the ephemeral local port 54321" "$OUTBOUND_LINE" '"signature_matched": "54321"'

echo ""
echo "[I6] agent-to-agent: autogpt (client) <-> ollama (listener) over loopback is flagged, with both sides' identity in the finding"
AGENT_LINE="$(echo "$OUT" | grep '"finding_type": "agent_to_agent"')"
assert_contains "I6 agent_to_agent finding present" "$OUT" '"finding_type": "agent_to_agent"'
assert_contains "I6 client process is autogpt" "$AGENT_LINE" '"comm": "autogpt"'
assert_contains "I6 listener_command is ollama" "$AGENT_LINE" '"listener_command": "ollama"'
assert_contains "I6 risk escalated to CRITICAL (HIGH base + agent_to_agent escalation)" "$AGENT_LINE" '"risk": "CRITICAL"'

echo ""
echo "[I7] the finder<->9999 loopback pair (neither side AI-flagged) produces NO agent_to_agent finding, and sshd:22 produces no finding at all (no matching signature)"
agent_count="$(echo "$OUT" | grep -c '"finding_type": "agent_to_agent"' || true)"
assert_eq "I7 exactly one agent_to_agent finding (not from finder/sshd)" "1" "$agent_count"
assert_not_contains "I7 sshd never appears in any finding" "$OUT" "sshd"

echo ""
echo "[I8] a domain signature referenced in a process's OWN args (api.openai.com) is reported, never via DNS/connection resolution"
DOMAIN_LINE="$(echo "$OUT" | grep '"match_kind": "domain_in_args"')"
assert_contains "I8 domain_in_args finding present" "$OUT" '"match_kind": "domain_in_args"'
assert_contains "I8 correct process identified" "$DOMAIN_LINE" '"comm": "curl-caller"'

echo ""
echo "[I9] NO secret ever reaches stdout: autogpt's fake embedded API key is redacted in the process finding's own args field"
AUTOGPT_PROC_LINE="$(echo "$OUT" | grep '"comm": "autogpt"' | grep '"finding_type": "process"' | head -1)"
assert_not_contains "I9 raw fake API key absent from stdout entirely" "$OUT" "sk-FAKEFAKEFAKEFAKEFAKE12345"
assert_contains "I9 redaction marker present in autogpt's own finding" "$AUTOGPT_PROC_LINE" "[REDACTED]"

echo ""
echo "[I10] finder (a non-AI process) never appears as the subject of any process/domain finding"
finder_subject_count="$(echo "$OUT" | grep -c '"comm": "finder"' || true)"
assert_eq "I10 finder never flagged" "0" "$finder_subject_count"

echo ""
echo "[I11] the scan summary is logged to stderr, never mixed into stdout's JSONL stream"
assert_contains "I11 stderr has the summary" "$(cat /tmp/waio-shadow-ai-i1-stderr.log)" "findings="
stdout_summary_lines="$(echo "$OUT" | grep -c 'SHADOW AI' || true)"
assert_eq "I11 stdout carries zero non-JSON lines" "0" "$stdout_summary_lines"

echo ""
echo "[I12] inventory persists across two scan runs: first_seen stable, times_seen increments, last_seen advances"
INV_AFTER_1="$(./security/shadow_ai/shadow_ai_monitor.sh inventory)"
OLLAMA_ID="$(python3 -c "
import json,sys
inv = json.loads(sys.argv[1])
for k, v in inv.items():
    if v['signature_matched'] == 'ollama' and v['finding_type'] == 'process':
        print(k)
        break
" "$INV_AFTER_1")"
FIRST_SEEN_1="$(python3 -c "import json,sys; print(json.loads(sys.argv[1])[sys.argv[2]]['first_seen'])" "$INV_AFTER_1" "$OLLAMA_ID")"
TIMES_SEEN_1="$(python3 -c "import json,sys; print(json.loads(sys.argv[1])[sys.argv[2]]['times_seen'])" "$INV_AFTER_1" "$OLLAMA_ID")"
./security/shadow_ai/shadow_ai_monitor.sh scan >/dev/null 2>&1
INV_AFTER_2="$(./security/shadow_ai/shadow_ai_monitor.sh inventory)"
FIRST_SEEN_2="$(python3 -c "import json,sys; print(json.loads(sys.argv[1])[sys.argv[2]]['first_seen'])" "$INV_AFTER_2" "$OLLAMA_ID")"
TIMES_SEEN_2="$(python3 -c "import json,sys; print(json.loads(sys.argv[1])[sys.argv[2]]['times_seen'])" "$INV_AFTER_2" "$OLLAMA_ID")"
assert_eq "I12 first_seen unchanged across the second scan" "$FIRST_SEEN_1" "$FIRST_SEEN_2"
assert_eq "I12 times_seen incremented by exactly 1" "$((TIMES_SEEN_1 + 1))" "$TIMES_SEEN_2"

echo ""
echo "[I13] 'status' prints a read-only risk-count summary without error"
STATUS_OUT="$(./security/shadow_ai/shadow_ai_monitor.sh status)"
assert_contains "I13 status mentions known entries" "$STATUS_OUT" "known entr"

echo ""
echo "[I14] scan-processes / scan-connections / scan-agents each run independently without error"
assert_eq "I14 scan-processes exit 0" "0" "$(./security/shadow_ai/shadow_ai_monitor.sh scan-processes >/dev/null 2>&1; echo $?)"
assert_eq "I14 scan-connections exit 0" "0" "$(./security/shadow_ai/shadow_ai_monitor.sh scan-connections >/dev/null 2>&1; echo $?)"
assert_eq "I14 scan-agents exit 0" "0" "$(./security/shadow_ai/shadow_ai_monitor.sh scan-agents >/dev/null 2>&1; echo $?)"

echo ""
echo "[I15] a missing allowlist file is handled gracefully (nothing pre-approved, not an error)"
NOFILE_OUT="$(SHADOW_AI_ALLOWLIST_FILE="$FIXTURE_DIR/does-not-exist.conf" ./security/shadow_ai/shadow_ai_monitor.sh scan-processes 2>&1)"
NOFILE_RC=$?
assert_eq "I15 exit code 0 even with a missing allowlist" "0" "$NOFILE_RC"
CLAUDE_LINE_NOFILE="$(echo "$NOFILE_OUT" | grep '"signature_matched": "claude"')"
assert_contains "I15 claude now reported as NOT allowlisted (nothing pre-approved)" "$CLAUDE_LINE_NOFILE" '"allowlisted": false'

echo ""
echo "=== D-series: structural read-only / no-network / no-Control-Plane guards ==="

# code_only FILE -- strips full-line comments (lines whose first
# non-whitespace character is '#') before a static grep guard below, so
# these guards check actual CODE, never this module's own extensive
# header prose that (deliberately, for documentation) NAMES the exact
# tools/functions it does NOT use, by way of contrast with
# security/incident_learning/'s real collectors.
code_only() {
  grep -vE '^[[:space:]]*#' "$1"
}

echo ""
echo "[D1] this module never sources security/lib.sh and never calls egress_check/audit_log/trigger_shutdown in actual code -- it has no gating authority and makes no outbound network call of its own"
for pattern in 'source security/lib\.sh' 'egress_check' 'trigger_shutdown' '\baudit_log\('; do
  cnt="$(code_only security/shadow_ai/shadow_ai_monitor.sh | grep -cE "$pattern" || true)"
  assert_eq "D1 zero code occurrences of '$pattern'" "0" "$cnt"
done

echo ""
echo "[D2] zero network tools (curl/wget/nc) invoked anywhere in the module's actual code -- pure local observation only"
net_calls=0
for f in security/shadow_ai/shadow_ai_monitor.sh security/shadow_ai/shadow_ai_lib.py; do
  c="$(code_only "$f" | grep -cE '\b(curl|wget|nc )\b' || true)"
  net_calls=$((net_calls + c))
done
assert_eq "D2 zero network-tool invocations" "0" "$net_calls"

echo ""
echo "[D3] zero process/firewall/routing-modifying commands invoked anywhere in the module's actual code (structural proof of read-only mode, not just a comment claim)"
mod_calls=0
for pattern in '\bkill\b' '\bkillall\b' '\bpfctl\b' '\broute\b' '\bifconfig\b' 'launchctl (unload|stop|kickstart)' '\bnetworksetup\b'; do
  for f in security/shadow_ai/shadow_ai_monitor.sh security/shadow_ai/shadow_ai_lib.py; do
    c="$(code_only "$f" | grep -cE "$pattern" || true)"
    mod_calls=$((mod_calls + c))
  done
done
assert_eq "D3 zero modifying-command invocations" "0" "$mod_calls"

echo ""
echo "[D4] this deployment's real Control Plane conf files were never touched by this suite"
for real_file in security/egress_allowlist.conf security/segments.conf security/ssh_management_allowlist.conf; do
  if [ -f "$real_file" ]; then
    assert_eq "D4 $real_file unchanged" "" "$(git diff --name-only -- "$real_file" 2>/dev/null)"
  fi
done

echo ""
echo "[D5] this deployment's real security/state/shadow_ai/ was never touched by this suite (SHADOW_AI_STATE_DIR override used throughout)"
REAL_STATE_AFTER="not_present"
[ -d security/state/shadow_ai ] && REAL_STATE_AFTER="$(find security/state/shadow_ai -type f 2>/dev/null | sort | tr '\n' ',')"
assert_eq "D5 real state directory contents unchanged" "$REAL_STATE_BEFORE" "$REAL_STATE_AFTER"

echo ""
echo "[D6] ps and lsof are called by bare name only (never a hardcoded absolute path) -- required for this suite's own PATH-shadowing to actually work, and for portability"
assert_eq "D6 no hardcoded /bin/ps or /usr/sbin/lsof path" "0" "$(grep -cE '/(bin|usr/sbin)/(ps|lsof)\b' security/shadow_ai/shadow_ai_monitor.sh)"

echo ""
echo "=== Summary: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
  echo "Failures:"
  for f in "${FAILURES[@]}"; do echo "  - $f"; done
  exit 1
fi
exit 0
