#!/bin/bash
set -uo pipefail

# tests/collect_decision_status_test.sh -- regression suite for the
# WAIO integrated dashboard's new Decision Engine panel:
# dashboard/collect_decision_status.sh's JSON output.
#
# Isolates every INPUT this script reads (SHADOW_AI_STATE_DIR/
# ATTACK_GRAPH_STATE_DIR/INTELLIGENCE_STATE_DIR/
# DECISION_ENGINE_STATE_DIR -- same override env vars each of the four
# underlying modules already defines for itself), same test-isolation
# pattern as tests/collect_incident_learning_status_test.sh -- this
# suite never reads or writes this deployment's real
# security/state/{shadow_ai,attack_graph,intelligence,decision_engine}.
#
# Like tests/collect_incident_learning_status_test.sh, this script's
# OUTPUT path (logs/decision-status-latest.json) is NOT
# fixture-overridable -- this suite does regenerate that
# deployment-local, gitignored, always-regenerable snapshot file, same
# accepted tradeoff as every other dashboard collector test in this
# repo.

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

OUT_PATH="logs/decision-status-latest.json"

out_get() {
  python3 -c "
import json
d = json.load(open('$OUT_PATH'))
node = d
for part in '$1'.split('.'):
    node = node[int(part)] if part.isdigit() else node[part]
print(json.dumps(node))
" 2>/dev/null
}

FIXTURE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/waio-collect-decision-status-test.XXXXXX")"
trap 'rm -rf "$FIXTURE_DIR"' EXIT

fixture_reset() {
  local suffix="${1:-default}"
  export SHADOW_AI_STATE_DIR="$FIXTURE_DIR/shadow_ai-$suffix"
  export ATTACK_GRAPH_STATE_DIR="$FIXTURE_DIR/attack_graph-$suffix"
  export INTELLIGENCE_STATE_DIR="$FIXTURE_DIR/intelligence-$suffix"
  export DECISION_ENGINE_STATE_DIR="$FIXTURE_DIR/decision_engine-$suffix"
  rm -rf "$SHADOW_AI_STATE_DIR" "$ATTACK_GRAPH_STATE_DIR" "$INTELLIGENCE_STATE_DIR" "$DECISION_ENGINE_STATE_DIR"
}

REAL_SHADOW_AI_PRESENT_BEFORE="false"
[ -f "security/state/shadow_ai/inventory.json" ] && REAL_SHADOW_AI_PRESENT_BEFORE="true"
REAL_DECISION_PRESENT_BEFORE="false"
[ -f "security/state/decision_engine/latest_decisions.json" ] && REAL_DECISION_PRESENT_BEFORE="true"

echo "=== Dashboard: Decision Engine panel (Shadow AI / Attack Graph / Intelligence / Decision Engine) ==="

echo "[DC1] none of the four modules have ever run: every section reports available=false, nothing fabricated"
fixture_reset "dc1"
./dashboard/collect_decision_status.sh >/dev/null
assert_eq "DC1 exit 0" "0" "$?"
assert_eq "DC1 shadow_ai.available false" "false" "$(out_get shadow_ai.available)"
assert_eq "DC1 shadow_ai.total_findings null" "null" "$(out_get shadow_ai.total_findings)"
assert_eq "DC1 attack_graph.available false" "false" "$(out_get attack_graph.available)"
assert_eq "DC1 intelligence_layer.available false" "false" "$(out_get intelligence_layer.available)"
assert_eq "DC1 decision_engine.available false" "false" "$(out_get decision_engine.available)"
assert_eq "DC1 decision_engine.pending_human_approval empty" "[]" "$(out_get decision_engine.pending_human_approval)"

echo "[DC2] shadow_ai inventory present: total_findings and risk_counts computed correctly from the flat {id: entry} dict"
fixture_reset "dc2"
mkdir -p "$SHADOW_AI_STATE_DIR"
cat > "$SHADOW_AI_STATE_DIR/inventory.json" <<'EOF'
{
  "SHADOWAI-aaa": {"id": "SHADOWAI-aaa", "last_risk": "LOW"},
  "SHADOWAI-bbb": {"id": "SHADOWAI-bbb", "last_risk": "MEDIUM"},
  "SHADOWAI-ccc": {"id": "SHADOWAI-ccc", "last_risk": "MEDIUM"},
  "SHADOWAI-ddd": {"id": "SHADOWAI-ddd", "last_risk": "CRITICAL"}
}
EOF
./dashboard/collect_decision_status.sh >/dev/null
assert_eq "DC2 shadow_ai.available true" "true" "$(out_get shadow_ai.available)"
assert_eq "DC2 total_findings 4" "4" "$(out_get shadow_ai.total_findings)"
assert_eq "DC2 risk_counts.MEDIUM 2" "2" "$(out_get shadow_ai.risk_counts.MEDIUM)"
assert_eq "DC2 risk_counts.CRITICAL 1" "1" "$(out_get shadow_ai.risk_counts.CRITICAL)"
assert_eq "DC2 risk_counts.LOW 1" "1" "$(out_get shadow_ai.risk_counts.LOW)"

echo "[DC3] attack_graph latest_graph.json present: analysis fields surfaced, cycles/attack_paths reported as counts"
fixture_reset "dc3"
mkdir -p "$ATTACK_GRAPH_STATE_DIR"
cat > "$ATTACK_GRAPH_STATE_DIR/latest_graph.json" <<'EOF'
{
  "generated_at": "2026-01-01T00:00:00Z",
  "findings_processed": 5,
  "nodes": {"a": {}, "b": {}},
  "edges": [{"from": "a", "to": "b"}],
  "analysis": {
    "node_count": 2, "edge_count": 1,
    "cycles": [["a", "b", "a"]],
    "attack_paths": [{"from": "a", "to": "b"}],
    "highest_risk_node": {"name": "b", "risk": "HIGH"}
  }
}
EOF
./dashboard/collect_decision_status.sh >/dev/null
assert_eq "DC3 attack_graph.available true" "true" "$(out_get attack_graph.available)"
assert_eq "DC3 node_count 2" "2" "$(out_get attack_graph.node_count)"
assert_eq "DC3 cycle_count 1" "1" "$(out_get attack_graph.cycle_count)"
assert_eq "DC3 attack_path_count 1" "1" "$(out_get attack_graph.attack_path_count)"
assert_eq "DC3 highest_risk_node.name" '"b"' "$(out_get attack_graph.highest_risk_node.name)"

echo "[DC4] intelligence_layer latest_report.json present: summary fields surfaced as-is"
fixture_reset "dc4"
mkdir -p "$INTELLIGENCE_STATE_DIR"
cat > "$INTELLIGENCE_STATE_DIR/latest_report.json" <<'EOF'
{
  "generated_at": "2026-01-01T00:00:00Z",
  "sources_ingested": {"shadow_ai": 2, "attack_graph": 1, "incident_learning": 0},
  "entities": {},
  "summary": {
    "entity_count": 3, "multi_source_entity_count": 1,
    "risk_counts": {"LOW": 1, "MEDIUM": 1, "HIGH": 1, "CRITICAL": 0},
    "top_entities": [{"entity": "x", "entity_type": "process", "risk": "HIGH", "confidence": "HIGH", "source_modules": ["shadow_ai_monitor"]}]
  }
}
EOF
./dashboard/collect_decision_status.sh >/dev/null
assert_eq "DC4 intelligence_layer.available true" "true" "$(out_get intelligence_layer.available)"
assert_eq "DC4 entity_count 3" "3" "$(out_get intelligence_layer.entity_count)"
assert_eq "DC4 multi_source_entity_count 1" "1" "$(out_get intelligence_layer.multi_source_entity_count)"
assert_eq "DC4 top_entities length 1" "1" "$(out_get intelligence_layer.top_entities | python3 -c 'import json,sys; print(len(json.load(sys.stdin)))')"

echo "[DC5] decision_engine latest_decisions.json present: decision_count/action_counts/pending_human_approval surfaced as-is"
fixture_reset "dc5"
mkdir -p "$DECISION_ENGINE_STATE_DIR"
cat > "$DECISION_ENGINE_STATE_DIR/latest_decisions.json" <<'EOF'
{
  "generated_at": "2026-01-01T00:00:00Z",
  "intelligence_report_generated_at": "2026-01-01T00:00:00Z",
  "decisions": [],
  "summary": {
    "decision_count": 2,
    "action_counts": {"NO_ACTION": 0, "MONITOR": 0, "ALERT_HUMAN": 1, "RECOMMEND_CONTAINMENT": 1},
    "pending_human_approval": ["evil.example.com"]
  }
}
EOF
./dashboard/collect_decision_status.sh >/dev/null
assert_eq "DC5 decision_engine.available true" "true" "$(out_get decision_engine.available)"
assert_eq "DC5 decision_count 2" "2" "$(out_get decision_engine.decision_count)"
assert_eq "DC5 pending_human_approval has one entry" '["evil.example.com"]' "$(out_get decision_engine.pending_human_approval)"

echo "[DC6] a malformed/unparseable state file in any of the four is skipped gracefully (available=false), never fatal"
fixture_reset "dc6"
mkdir -p "$DECISION_ENGINE_STATE_DIR"
printf 'not valid json' > "$DECISION_ENGINE_STATE_DIR/latest_decisions.json"
out="$(./dashboard/collect_decision_status.sh 2>&1)"; rc=$?
assert_eq "DC6 exits zero despite the broken file" "0" "$rc"
assert_eq "DC6 decision_engine.available false" "false" "$(out_get decision_engine.available)"

echo "[DC7] all four present simultaneously: every section available, no cross-contamination between sections"
fixture_reset "dc7"
mkdir -p "$SHADOW_AI_STATE_DIR" "$ATTACK_GRAPH_STATE_DIR" "$INTELLIGENCE_STATE_DIR" "$DECISION_ENGINE_STATE_DIR"
echo '{"X": {"last_risk": "LOW"}}' > "$SHADOW_AI_STATE_DIR/inventory.json"
echo '{"generated_at": "t", "analysis": {"node_count": 1, "edge_count": 0, "cycles": [], "attack_paths": [], "highest_risk_node": null}}' > "$ATTACK_GRAPH_STATE_DIR/latest_graph.json"
echo '{"generated_at": "t", "sources_ingested": {}, "summary": {"entity_count": 1, "multi_source_entity_count": 0, "risk_counts": {}, "top_entities": []}}' > "$INTELLIGENCE_STATE_DIR/latest_report.json"
echo '{"generated_at": "t", "summary": {"decision_count": 1, "action_counts": {}, "pending_human_approval": []}}' > "$DECISION_ENGINE_STATE_DIR/latest_decisions.json"
./dashboard/collect_decision_status.sh >/dev/null
assert_eq "DC7 shadow_ai.available true" "true" "$(out_get shadow_ai.available)"
assert_eq "DC7 attack_graph.available true" "true" "$(out_get attack_graph.available)"
assert_eq "DC7 intelligence_layer.available true" "true" "$(out_get intelligence_layer.available)"
assert_eq "DC7 decision_engine.available true" "true" "$(out_get decision_engine.available)"

echo "[DC8] this deployment's real state files were never touched by this suite"
REAL_SHADOW_AI_PRESENT_AFTER="false"
[ -f "security/state/shadow_ai/inventory.json" ] && REAL_SHADOW_AI_PRESENT_AFTER="true"
REAL_DECISION_PRESENT_AFTER="false"
[ -f "security/state/decision_engine/latest_decisions.json" ] && REAL_DECISION_PRESENT_AFTER="true"
assert_eq "DC8 real shadow_ai inventory presence unchanged" "$REAL_SHADOW_AI_PRESENT_BEFORE" "$REAL_SHADOW_AI_PRESENT_AFTER"
assert_eq "DC8 real decision_engine state presence unchanged" "$REAL_DECISION_PRESENT_BEFORE" "$REAL_DECISION_PRESENT_AFTER"

echo "[D1] no network tool is invoked by this collector (static guard)"
NET_CALLS="$(grep -cE '\b(curl|wget|nc )\b' dashboard/collect_decision_status.sh || true)"
assert_eq "D1 zero network-tool invocations" "0" "$NET_CALLS"

echo "[D2] this collector never calls into any of the four modules' own CLI (decide/ingest/build/scan) -- read-only file access only"
cnt="$(grep -cE 'decision_engine\.sh (decide|show|status)|intelligence_layer\.sh (ingest|show|status)|attack_graph\.sh (build|show|status)|shadow_ai_monitor\.sh (scan|inventory|status)' dashboard/collect_decision_status.sh || true)"
assert_eq "D2 zero CLI invocations" "0" "$cnt"

echo
echo "=== Results: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
  echo "Failures:"
  for f in "${FAILURES[@]}"; do echo "  - $f"; done
  exit 1
fi
exit 0
