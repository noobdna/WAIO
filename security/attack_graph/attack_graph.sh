#!/bin/bash
set -uo pipefail

# security/attack_graph/attack_graph.sh -- AI Agent Attack Graph
# module: builds a directed graph of local AI-agent-to-AI-agent
# connectivity from Shadow AI Monitor's own JSONL evidence stream, and
# runs a small set of deliberately simple graph queries over it
# (cycles, lateral-movement paths from a low-risk node to a high-risk
# one, the single highest-risk node).
#
# This is the promised consumer of
# security/shadow_ai/shadow_ai_monitor.sh's own "integration point for
# a future module" (see that file's Phase 90 header): every
# agent_to_agent finding it emits already carries the stable id +
# complete edge data (client process identity + listener pid/command/
# port) this module needs. Coupling is DELIBERATELY loose -- this file
# never imports anything from security/shadow_ai/ and never invokes
# shadow_ai_monitor.sh itself; it only reads whatever JSONL findings
# are handed to it (stdin, or a file argument), matching the exact
# documented finding schema (see attack_graph_lib.py's own
# parse_findings() header). The intended real-world invocation is the
# same Collector|Normalizer pipe idiom
# security/incident_learning/incident_learning_cron.sh already
# establishes for a different domain:
#     security/shadow_ai/shadow_ai_monitor.sh scan | security/attack_graph/attack_graph.sh build
# but any JSONL source matching the schema works -- this module has no
# code path that knows or cares where its input came from.
#
# Scope (same "detection/evidence only" posture Shadow AI Monitor's own
# header establishes, extended to a second module):
#   - READ-ONLY. Never modifies a process, a firewall/routing rule, or
#     any Control Plane file. Never sources security/lib.sh, never
#     calls egress_check()/audit_log()/trigger_shutdown(), makes no
#     network call and no ps/lsof call of its own -- it only reads
#     text handed to it and its own small state file.
#   - NOT wired into DuCoPA/Guardian/any containment action. Matches
#     the requested pipeline shape
#     (Shadow AI Monitor -> WAIO Intelligence/Evidence Layer -> WAIO
#     Decision Engine -> DuCoPA -> Contain/Recover): this module is
#     still upstream of "Decision Engine," producing structured
#     evidence (the graph + its analysis), never deciding or acting on
#     anything. Nothing here promotes, quarantines, or contains.
#   - Deliberately simple graph analysis (BFS reachability, DFS cycle
#     detection, a highest-risk-node lookup) -- no MITRE ATT&CK
#     technique mapping, no probability/likelihood scoring. Every
#     result traces back to the specific finding id(s) that produced it
#     (see attack_graph_lib.py's own node/edge shape), never a bare
#     verdict with no basis.
#
# Independently testable: state dir and audit log are both overridable
# via env var, same convention as every other domain in this repo; the
# CLI reads JSONL from stdin/a file argument, so
# tests/attack_graph_test.sh needs no ps/lsof/shadow_ai fixture at all
# -- just a fixed JSONL findings file, matching Shadow AI Monitor's own
# real output shape.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$SCRIPT_DIR"

STATE_DIR="${ATTACK_GRAPH_STATE_DIR:-$SCRIPT_DIR/security/state/attack_graph}"
AUDIT_LOG="${ATTACK_GRAPH_AUDIT_LOG:-$SCRIPT_DIR/logs/attack-graph-audit.jsonl}"
GRAPH_FILE="$STATE_DIR/latest_graph.json"

mkdir -p "$STATE_DIR" "$(dirname "$AUDIT_LOG")" 2>/dev/null || true

audit_build_log() {
  local summary="$1"
  python3 -c "
import json, sys
print(json.dumps({
    'timestamp': sys.argv[1],
    'summary': sys.argv[2],
}, ensure_ascii=False))
" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$summary" >> "$AUDIT_LOG"
}

# build_graph [FILE] -- reads JSONL findings from FILE, or stdin if no
# FILE argument (or FILE is '-'). Emits the full graph+analysis JSON to
# stdout, persists it to GRAPH_FILE (atomic tmp+mv, same convention as
# every other state writer in this repo), and logs a one-line summary
# to the audit log.
build_graph() {
  local input="${1:--}"
  local src
  if [ "$input" = "-" ]; then
    src="$(mktemp)"
    cat > "$src"
  else
    src="$input"
  fi

  local stderr_tmp
  stderr_tmp="$(mktemp)"
  python3 - "$src" "$GRAPH_FILE" 2>"$stderr_tmp" <<'PYEOF'
import datetime, json, os, sys

src_path, graph_path = sys.argv[1], sys.argv[2]

sys.path.insert(0, os.path.join(os.getcwd(), "security", "attack_graph"))
import attack_graph_lib as agl

with open(src_path) as f:
    findings = agl.parse_findings(f.readlines())

graph = agl.build_graph(findings)
analysis = agl.graph_summary(graph)

output = {
    "generated_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "findings_processed": len(findings),
    "nodes": graph["nodes"],
    "edges": graph["edges"],
    "analysis": analysis,
}

print(json.dumps(output, ensure_ascii=False, indent=2))

tmp_path = f"{graph_path}.tmp.{os.getpid()}"
with open(tmp_path, "w") as f:
    json.dump(output, f, ensure_ascii=False, indent=2, sort_keys=True)
os.replace(tmp_path, graph_path)

print(
    f"findings={len(findings)} nodes={analysis['node_count']} edges={analysis['edge_count']} "
    f"cycles={len(analysis['cycles'])} attack_paths={len(analysis['attack_paths'])} "
    f"highest_risk_node={analysis['highest_risk_node']}",
    file=sys.stderr,
)
PYEOF
  local rc=$?

  if [ "$input" = "-" ]; then
    rm -f "$src"
  fi

  local summary
  summary="$(cat "$stderr_tmp")"
  rm -f "$stderr_tmp"
  if [ -n "$summary" ]; then
    echo "[ATTACK GRAPH] $summary" >&2
  fi
  audit_build_log "$summary"
  return "$rc"
}

# print_graph -- read-only dump of the last persisted graph+analysis.
print_graph() {
  if [ ! -f "$GRAPH_FILE" ]; then
    echo "{}"
    return 0
  fi
  cat "$GRAPH_FILE"
}

# print_status -- short human-readable summary of the last persisted
# graph. Read-only.
print_status() {
  python3 -c "
import json, sys
path = sys.argv[1]
try:
    with open(path) as f:
        g = json.load(f)
except Exception:
    print('Attack Graph: no graph built yet')
    sys.exit(0)
a = g.get('analysis', {})
print(f\"Attack Graph (generated {g.get('generated_at', '?')}):\")
print(f\"  nodes: {a.get('node_count', 0)}  edges: {a.get('edge_count', 0)}\")
print(f\"  cycles: {len(a.get('cycles', []))}\")
print(f\"  attack paths (low-risk -> high-risk): {len(a.get('attack_paths', []))}\")
hr = a.get('highest_risk_node')
if hr:
    print(f\"  highest-risk node: {hr['name']} ({hr['risk']})\")
" "$GRAPH_FILE"
}

if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
  case "${1:-build}" in
    build)
      build_graph "${2:--}"
      ;;
    show)
      print_graph
      ;;
    status)
      print_status
      ;;
    *)
      echo "Usage: $0 {build [FILE|-]|show|status}" >&2
      exit 1
      ;;
  esac
fi
