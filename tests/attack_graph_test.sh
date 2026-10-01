#!/bin/bash
set -uo pipefail

# tests/attack_graph_test.sh -- regression suite for the AI Agent
# Attack Graph module (security/attack_graph/attack_graph_lib.py +
# security/attack_graph/attack_graph.sh).
#
# Same two-layer convention as tests/shadow_ai_monitor_test.sh:
#   U-series: unit tests against attack_graph_lib.py's pure functions,
#     called directly via `python3 -c "sys.path.insert(0,
#     'security/attack_graph'); import attack_graph_lib as agl"`.
#   I-series: integration tests against attack_graph.sh's own CLI, fed
#     fixed JSONL finding fixtures via stdin/a file -- no Shadow AI
#     Monitor, no ps/lsof, no live process state involved at all. This
#     module is coupled to Shadow AI Monitor only via the documented
#     JSON finding schema, so these fixtures are hand-written JSONL
#     matching that schema directly, proving the two modules are
#     genuinely decoupled (a schema-compatible fixture is enough, no
#     shared code needed).
#   D-series: static structural guards (read-only, no network, no
#     Control Plane writes).
#
# Every case runs against an isolated ATTACK_GRAPH_STATE_DIR/
# ATTACK_GRAPH_AUDIT_LOG, never this deployment's real
# security/state/attack_graph/.

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

pyval() {
  python3 -c "
import sys
sys.path.insert(0, 'security/attack_graph')
import attack_graph_lib as agl
$1
"
}

echo "=== AI Agent Attack Graph regression suite ==="

echo ""
echo "=== U-series: attack_graph_lib.py unit tests (pure functions) ==="

echo ""
echo "[U1] parse_findings skips blank and malformed lines, keeps valid ones"
out="$(pyval "
lines = ['', '   ', 'not json', '{\"a\": 1}', '{\"b\": 2}']
fs = agl.parse_findings(lines)
print(len(fs))
print(fs[0]['a'], fs[1]['b'])
")"
assert_eq "U1 two valid findings parsed, junk skipped" "$(printf '2\n1 2')" "$out"

echo ""
echo "[U2] build_graph: a lone 'process' finding creates one node with no edges"
out="$(pyval "
findings = [{'id':'F1','finding_type':'process','category':'ai_desktop_app','risk':'LOW','process':{'comm':'claude','pid':1}}]
g = agl.build_graph(findings)
print(list(g['nodes'].keys()))
print(g['nodes']['claude']['highest_risk'])
print(g['nodes']['claude']['category'])
print(len(g['edges']))
")"
assert_eq "U2 one node, LOW risk, category set, zero edges" "$(printf "['claude']\nLOW\nai_desktop_app\n0")" "$out"

echo ""
echo "[U3] build_graph: a 'listening_port' finding adds an exposure to its node, not an edge"
out="$(pyval "
findings = [{'id':'F1','finding_type':'listening_port','category':'local_llm_runtime','risk':'HIGH','process':{'comm':'ollama','pid':1},'network':{'local_port':11434,'remote_port':None}}]
g = agl.build_graph(findings)
print(len(g['edges']))
print(g['nodes']['ollama']['exposures'][0]['port'])
print(g['nodes']['ollama']['exposures'][0]['type'])
")"
assert_eq "U3 zero edges, one exposure recorded with correct port/type" "$(printf '0\n11434\nlistening_port')" "$out"

echo ""
echo "[U4] build_graph: an 'agent_to_agent' finding creates a directed edge and both endpoint nodes"
out="$(pyval "
findings = [{'id':'F1','finding_type':'agent_to_agent','category':'ai_agent_framework','risk':'CRITICAL','confidence':'HIGH','process':{'comm':'autogpt','pid':1},'network':{'listener_command':'ollama','listener_pid':2,'remote_port':11434}}]
g = agl.build_graph(findings)
print(sorted(g['nodes'].keys()))
print(len(g['edges']))
e = g['edges'][0]
print(e['from'], e['to'], e['risk'], e['port'])
print(g['nodes']['autogpt']['highest_risk'], g['nodes']['ollama']['highest_risk'])
")"
assert_eq "U4 both nodes created, one directed edge, both nodes inherit the edge's risk" \
  "$(printf "['autogpt', 'ollama']\n1\nautogpt ollama CRITICAL 11434\nCRITICAL CRITICAL")" "$out"

echo ""
echo "[U5] build_graph: a finding with no usable process context is skipped, never crashes"
out="$(pyval "
findings = [{'id':'F1','finding_type':'listening_port','category':'x','risk':'HIGH','process':None,'network':{'local_port':9999}}]
g = agl.build_graph(findings)
print(len(g['nodes']), len(g['edges']))
")"
assert_eq "U5 zero nodes, zero edges, no crash" "0 0" "$out"

echo ""
echo "[U6] build_graph: empty findings list produces an empty graph"
out="$(pyval "
g = agl.build_graph([])
print(len(g['nodes']), len(g['edges']))
")"
assert_eq "U6 empty graph for empty input" "0 0" "$out"

echo ""
echo "[U7] detect_cycles finds a 2-node feedback loop (ping->pong->ping), reports none for an acyclic chain"
out="$(pyval "
cyclic_edges = [{'from':'ping','to':'pong'}, {'from':'pong','to':'ping'}]
print(len(agl.detect_cycles(cyclic_edges)) > 0)
acyclic_edges = [{'from':'a','to':'b'}, {'from':'b','to':'c'}]
print(len(agl.detect_cycles(acyclic_edges)))
")"
assert_eq "U7 cycle detected in the loop, none in the chain" "$(printf 'True\n0')" "$out"

echo ""
echo "[U8] find_attack_paths finds a path from a low-risk node through an escalated intermediate to a critical target, and does not report a path where no low-risk starting node exists"
out="$(pyval "
nodes = {
    'scanner': {'category':'x','highest_risk':'MEDIUM','finding_ids':[],'exposures':[]},
    'autogpt': {'category':'x','highest_risk':'CRITICAL','finding_ids':[],'exposures':[]},
    'ollama':  {'category':'x','highest_risk':'CRITICAL','finding_ids':[],'exposures':[]},
}
edges = [
    {'from':'scanner','to':'autogpt','risk':'MEDIUM'},
    {'from':'autogpt','to':'ollama','risk':'CRITICAL'},
]
paths = agl.find_attack_paths(nodes, edges)
print(len(paths))
full = [p for p in paths if p['path'] == ['scanner','autogpt','ollama']]
print(len(full) == 1)
print(full[0]['path_risk'])
# no low-risk node at all -> zero paths, never an error
nodes2 = {'a': {'category':'x','highest_risk':'CRITICAL','finding_ids':[],'exposures':[]}}
print(len(agl.find_attack_paths(nodes2, [])))
")"
assert_eq "U8 two paths found (direct + full chain), correct path_risk, zero when no low-risk node exists" \
  "$(printf '2\nTrue\nCRITICAL\n0')" "$out"

echo ""
echo "[U9] highest_risk_node returns the single highest-risk node, or None for an empty graph"
out="$(pyval "
nodes = {'a': {'highest_risk':'LOW'}, 'b': {'highest_risk':'HIGH'}, 'c': {'highest_risk':'MEDIUM'}}
r = agl.highest_risk_node(nodes)
print(r['name'], r['risk'])
print(agl.highest_risk_node({}))
")"
assert_eq "U9 correctly picks the HIGH node, None for empty" "$(printf 'b HIGH\nNone')" "$out"

echo ""
echo "[U10] graph_summary assembles counts, cycles, attack_paths, and highest_risk_node together"
out="$(pyval "
findings = [
    {'id':'F1','finding_type':'agent_to_agent','category':'x','risk':'HIGH','confidence':'HIGH','process':{'comm':'a','pid':1},'network':{'listener_command':'b','listener_pid':2,'remote_port':1}},
]
g = agl.build_graph(findings)
s = agl.graph_summary(g)
print(s['node_count'], s['edge_count'])
print(s['highest_risk_node']['name'])
")"
assert_eq "U10 summary reflects the built graph" "$(printf '2 1\na')" "$out"

echo ""
echo "=== I-series: attack_graph.sh CLI integration tests (fixed JSONL fixtures, no live scan) ==="

FIXTURE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/waio-attack-graph-test.XXXXXX")"
trap 'rm -rf "$FIXTURE_DIR"' EXIT
mkdir -p "$FIXTURE_DIR/state"

export ATTACK_GRAPH_STATE_DIR="$FIXTURE_DIR/state"
export ATTACK_GRAPH_AUDIT_LOG="$FIXTURE_DIR/audit.jsonl"

# A three-node chain (scanner -[MEDIUM]-> autogpt -[CRITICAL]-> ollama),
# matching Shadow AI Monitor's own real finding schema exactly (same
# field names/shapes shadow_ai_monitor.sh actually emits).
cat > "$FIXTURE_DIR/findings.jsonl" <<'EOF'
{"id": "SHADOWAI-scanner", "detected_at": "2026-01-01T00:00:00Z", "finding_type": "process", "category": "ai_agent_framework", "signature_matched": "scanner-agent", "signature_label": "test fixture", "match_kind": "process_name", "process": {"pid": 100, "ppid": 1, "user": "masa", "comm": "scanner", "args": "scanner --scan"}, "network": null, "allowlisted": false, "risk": "LOW", "confidence": "HIGH", "reason": "fixture"}
{"id": "SHADOWAI-link1", "detected_at": "2026-01-01T00:00:00Z", "finding_type": "agent_to_agent", "category": "ai_agent_framework", "signature_matched": "scanner-agent", "signature_label": "test fixture", "match_kind": "process_name", "process": {"pid": 100, "ppid": 1, "user": "masa", "comm": "scanner", "args": "scanner --scan"}, "network": {"local_port": null, "remote_host": "127.0.0.1", "remote_port": 9001, "listener_pid": 200, "listener_command": "autogpt"}, "allowlisted": false, "risk": "MEDIUM", "confidence": "HIGH", "reason": "fixture"}
{"id": "SHADOWAI-link2", "detected_at": "2026-01-01T00:00:00Z", "finding_type": "agent_to_agent", "category": "ai_agent_framework", "signature_matched": "autogpt", "signature_label": "test fixture", "match_kind": "process_name", "process": {"pid": 200, "ppid": 1, "user": "masa", "comm": "autogpt", "args": "autogpt run"}, "network": {"local_port": null, "remote_host": "127.0.0.1", "remote_port": 11434, "listener_pid": 300, "listener_command": "ollama"}, "allowlisted": false, "risk": "CRITICAL", "confidence": "HIGH", "reason": "fixture"}
EOF

echo ""
echo "[I1] build (reading a FILE argument) exits 0 and emits valid JSON to stdout"
OUT="$(./security/attack_graph/attack_graph.sh build "$FIXTURE_DIR/findings.jsonl" 2>/tmp/waio-attack-graph-i1-stderr.log)"
RC=$?
assert_eq "I1 exit code 0" "0" "$RC"
assert_eq "I1 stdout is valid JSON" "true" "$(echo "$OUT" | python3 -c "import json,sys; json.load(sys.stdin); print('true')" 2>/dev/null || echo false)"

echo ""
echo "[I2] the built graph has exactly 3 nodes and 2 edges"
assert_eq "I2 node_count 3" "3" "$(echo "$OUT" | python3 -c "import json,sys; print(json.load(sys.stdin)['analysis']['node_count'])")"
assert_eq "I2 edge_count 2" "2" "$(echo "$OUT" | python3 -c "import json,sys; print(json.load(sys.stdin)['analysis']['edge_count'])")"

echo ""
echo "[I3] the highest-risk node is CRITICAL (both autogpt and ollama inherit CRITICAL from the link2 edge; highest_risk_node's own documented tie-break picks the first one built, autogpt -- see U9/highest_risk_node's own header on ties)"
assert_eq "I3 highest_risk_node is autogpt (first-built of the two CRITICAL nodes)" "autogpt" "$(echo "$OUT" | python3 -c "import json,sys; print(json.load(sys.stdin)['analysis']['highest_risk_node']['name'])")"
assert_eq "I3 highest_risk_node risk is CRITICAL" "CRITICAL" "$(echo "$OUT" | python3 -c "import json,sys; print(json.load(sys.stdin)['analysis']['highest_risk_node']['risk'])")"
assert_eq "I3 ollama ALSO reached CRITICAL (both ends of the CRITICAL edge inherit it)" "CRITICAL" "$(echo "$OUT" | python3 -c "import json,sys; print(json.load(sys.stdin)['nodes']['ollama']['highest_risk'])")"

echo ""
echo "[I4] an attack path from scanner (LOW-ish, MEDIUM after edge participation) to ollama (CRITICAL) is reported"
FULL_PATH_COUNT="$(echo "$OUT" | python3 -c "
import json, sys
a = json.load(sys.stdin)['analysis']
print(sum(1 for p in a['attack_paths'] if p['path'] == ['scanner', 'autogpt', 'ollama']))
")"
assert_eq "I4 full scanner->autogpt->ollama path present" "1" "$FULL_PATH_COUNT"

echo ""
echo "[I5] no cycle is reported for this acyclic chain"
assert_eq "I5 zero cycles" "0" "$(echo "$OUT" | python3 -c "import json,sys; print(len(json.load(sys.stdin)['analysis']['cycles']))")"

echo ""
echo "[I6] the graph is persisted and readable via 'show', identical to the build output's own graph content"
SHOW_OUT="$(./security/attack_graph/attack_graph.sh show)"
assert_eq "I6 persisted node_count matches" "3" "$(echo "$SHOW_OUT" | python3 -c "import json,sys; print(json.load(sys.stdin)['analysis']['node_count'])")"

echo ""
echo "[I7] 'status' prints a read-only human-readable summary without error"
STATUS_OUT="$(./security/attack_graph/attack_graph.sh status)"
assert_contains "I7 status mentions nodes/edges" "$STATUS_OUT" "nodes:"
assert_contains "I7 status names the highest-risk node" "$STATUS_OUT" "autogpt"

echo ""
echo "[I8] build also works reading from STDIN (the real Collector|Normalizer-style pipe usage: shadow_ai_monitor.sh scan | attack_graph.sh build)"
STDIN_OUT="$(cat "$FIXTURE_DIR/findings.jsonl" | ./security/attack_graph/attack_graph.sh build -)"
assert_eq "I8 stdin-fed build produces the same node_count" "3" "$(echo "$STDIN_OUT" | python3 -c "import json,sys; print(json.load(sys.stdin)['analysis']['node_count'])")"
assert_eq "I8 stdin-fed build produces the same node_count when no arg given (default is stdin)" "3" "$(cat "$FIXTURE_DIR/findings.jsonl" | ./security/attack_graph/attack_graph.sh build | python3 -c "import json,sys; print(json.load(sys.stdin)['analysis']['node_count'])")"

echo ""
echo "[I9] an empty findings file produces a valid, empty graph -- never an error"
: > "$FIXTURE_DIR/empty.jsonl"
EMPTY_OUT="$(./security/attack_graph/attack_graph.sh build "$FIXTURE_DIR/empty.jsonl" 2>/dev/null)"
EMPTY_RC=$?
assert_eq "I9 exit code 0 for empty input" "0" "$EMPTY_RC"
assert_eq "I9 node_count 0" "0" "$(echo "$EMPTY_OUT" | python3 -c "import json,sys; print(json.load(sys.stdin)['analysis']['node_count'])")"

echo ""
echo "[I10] a malformed line in the findings file is skipped gracefully, valid lines still processed"
cat > "$FIXTURE_DIR/malformed.jsonl" <<'EOF'
not valid json at all
{"id": "SHADOWAI-x", "finding_type": "process", "category": "ai_desktop_app", "risk": "LOW", "process": {"comm": "claude", "pid": 1}}
EOF
MALFORMED_OUT="$(./security/attack_graph/attack_graph.sh build "$FIXTURE_DIR/malformed.jsonl" 2>/dev/null)"
MALFORMED_RC=$?
assert_eq "I10 exit code 0 despite a malformed line" "0" "$MALFORMED_RC"
assert_eq "I10 the one valid finding still produced a node" "1" "$(echo "$MALFORMED_OUT" | python3 -c "import json,sys; print(json.load(sys.stdin)['analysis']['node_count'])")"

echo ""
echo "[I11] the build summary is logged to stderr, never mixed into stdout's JSON"
assert_contains "I11 stderr has the summary" "$(cat /tmp/waio-attack-graph-i1-stderr.log)" "nodes="

echo ""
echo "=== D-series: structural read-only / no-network / no-Control-Plane guards ==="

code_only() {
  grep -vE '^[[:space:]]*#' "$1"
}

echo ""
echo "[D1] this module never sources security/lib.sh and never calls egress_check/audit_log/trigger_shutdown in actual code"
for pattern in 'source security/lib\.sh' 'egress_check' 'trigger_shutdown' '\baudit_log\('; do
  cnt="$(code_only security/attack_graph/attack_graph.sh | grep -cE "$pattern" || true)"
  assert_eq "D1 zero code occurrences of '$pattern'" "0" "$cnt"
done

echo ""
echo "[D2] zero network tools (curl/wget/nc) and zero ps/lsof calls anywhere in attack_graph.sh's actual code -- this module only ever reads text handed to it"
bad_calls=0
for pattern in '\b(curl|wget|nc )\b' '\bps\b' '\blsof\b'; do
  c="$(code_only security/attack_graph/attack_graph.sh | grep -cE "$pattern" || true)"
  bad_calls=$((bad_calls + c))
done
assert_eq "D2 zero network/ps/lsof invocations in the shell wrapper" "0" "$bad_calls"

echo ""
echo "[D2b] attack_graph_lib.py never shells out at all (no subprocess/os.system/os.popen/exec) -- python-appropriate equivalent of D2, since '#'-based comment-stripping doesn't apply to a Python docstring"
assert_eq "D2b zero subprocess/os.system/os.popen/os.exec calls" "0" "$(grep -cE '\b(subprocess|os\.system|os\.popen|os\.exec\w*)\b' security/attack_graph/attack_graph_lib.py || true)"

echo ""
echo "[D3] zero process/firewall/routing-modifying commands anywhere in the module's actual code"
mod_calls=0
for pattern in '\bkill\b' '\bkillall\b' '\bpfctl\b' '\broute\b' '\bifconfig\b' 'launchctl (unload|stop|kickstart)' '\bnetworksetup\b'; do
  for f in security/attack_graph/attack_graph.sh security/attack_graph/attack_graph_lib.py; do
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
echo "[D5] this module never IMPORTS shadow_ai_lib or CALLS shadow_ai_monitor.sh -- coupling is via the JSON schema only, never shared code (mentioning shadow_ai in documentation/comments, which both files do extensively, is fine and expected -- this checks actual import/call statements only)"
assert_eq "D5 zero 'import shadow_ai'/'from shadow_ai' statements in attack_graph_lib.py" "0" "$(grep -cE '^\s*(import|from)\s+shadow_ai' security/attack_graph/attack_graph_lib.py || true)"
assert_eq "D5 zero calls to shadow_ai_monitor.sh in attack_graph.sh's actual code" "0" "$(code_only security/attack_graph/attack_graph.sh | grep -c "shadow_ai_monitor.sh" || true)"

echo ""
echo "=== Summary: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
  echo "Failures:"
  for f in "${FAILURES[@]}"; do echo "  - $f"; done
  exit 1
fi
exit 0
