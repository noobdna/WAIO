#!/bin/bash
set -uo pipefail

# dashboard/collect_decision_status.sh -- read-only data collector for
# the WAIO Dashboard's new "Decision Engine" panel. Reads the four
# already-persisted state files the Shadow AI Monitor / Attack Graph /
# Intelligence Layer / Decision Engine pipeline (Phase 90-93) writes on
# every run of its own:
#   security/state/shadow_ai/inventory.json
#   security/state/attack_graph/latest_graph.json
#   security/state/intelligence/latest_report.json
#   security/state/decision_engine/latest_decisions.json
# and merges them into one summary JSON for the dashboard. Mirrors
# dashboard/collect_incident_learning_status.sh's own conventions
# exactly (same header shape, same "read state files directly off
# disk, never call the module's own CLI" posture, same output
# location pattern).
#
# ZERO network calls, ZERO calls into any of the four modules' own CLI
# (decision_engine.sh/intelligence_layer.sh/attack_graph.sh/
# shadow_ai_monitor.sh) -- this script only reads already-existing
# local files and never advances, scans, builds, ingests, or decides
# anything. Display layer only, same posture as every other
# dashboard/collect_*.sh.
#
# Deliberately does NOT `source` any of the four modules' own .sh
# files to obtain their state-file paths (unlike
# dashboard/collect_incident_learning_status.sh's one-file `source
# security/incident_learning/knowledge_manager.sh`) -- sourcing four
# separate modules would also pull in their own same-named functions
# (all four independently define a `print_status`, for instance),
# which this script never needs and would rather not risk silently
# shadowing. Instead, this script duplicates only each module's own
# documented PATH CONSTRUCTION (one line each, matching that module's
# own STATE_DIR override env var and default), never its code -- same
# loose-coupling discipline security/attack_graph/attack_graph_lib.py's
# own header already states for a different module pair ("depend only
# on the documented schema, never the sibling module's code").
#
# Each of the four sections is independently optional: a module that
# has never been run yet (no state file present, or present but not
# valid JSON) is reported with "available": false and every other
# field null/empty -- never fabricated, never treated as an error (a
# brand-new WAIO deployment that has never run any of these four
# modules is an expected, valid state, not a collector failure).
#
# Output: logs/decision-status-latest.json (logs/ already gitignored).

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"

SHADOW_AI_INVENTORY_FILE="${SHADOW_AI_STATE_DIR:-$SCRIPT_DIR/security/state/shadow_ai}/inventory.json"
ATTACK_GRAPH_FILE="${ATTACK_GRAPH_STATE_DIR:-$SCRIPT_DIR/security/state/attack_graph}/latest_graph.json"
INTELLIGENCE_REPORT_FILE="${INTELLIGENCE_STATE_DIR:-$SCRIPT_DIR/security/state/intelligence}/latest_report.json"
DECISION_ENGINE_FILE="${DECISION_ENGINE_STATE_DIR:-$SCRIPT_DIR/security/state/decision_engine}/latest_decisions.json"

now_iso() { python3 -c 'import datetime; print(datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="milliseconds"))'; }

GENERATED_AT="$(now_iso)"

mkdir -p logs
python3 -c '
import json, sys

shadow_ai_path, attack_graph_path, intelligence_path, decision_path, generated_at = sys.argv[1:6]


def safe_load(path):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return None


# --- Shadow AI Monitor (inventory.json is a flat {id: entry} dict, no
# envelope/generated_at/summary of its own -- counts computed here) ---
shadow_ai_inv = safe_load(shadow_ai_path)
if isinstance(shadow_ai_inv, dict):
    risk_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    for entry in shadow_ai_inv.values():
        r = entry.get("last_risk", "LOW") if isinstance(entry, dict) else "LOW"
        risk_counts[r] = risk_counts.get(r, 0) + 1
    shadow_ai = {
        "available": True,
        "total_findings": len(shadow_ai_inv),
        "risk_counts": risk_counts,
    }
else:
    shadow_ai = {"available": False, "total_findings": None, "risk_counts": {}}

# --- Attack Graph ------------------------------------------------------
graph = safe_load(attack_graph_path)
if isinstance(graph, dict) and isinstance(graph.get("analysis"), dict):
    a = graph["analysis"]
    attack_graph = {
        "available": True,
        "generated_at": graph.get("generated_at"),
        "node_count": a.get("node_count", 0),
        "edge_count": a.get("edge_count", 0),
        "cycle_count": len(a.get("cycles") or []),
        "attack_path_count": len(a.get("attack_paths") or []),
        "highest_risk_node": a.get("highest_risk_node"),
    }
else:
    attack_graph = {
        "available": False, "generated_at": None, "node_count": None,
        "edge_count": None, "cycle_count": None, "attack_path_count": None,
        "highest_risk_node": None,
    }

# --- Intelligence / Evidence Layer -------------------------------------
report = safe_load(intelligence_path)
if isinstance(report, dict) and isinstance(report.get("summary"), dict):
    s = report["summary"]
    intelligence_layer = {
        "available": True,
        "generated_at": report.get("generated_at"),
        "sources_ingested": report.get("sources_ingested") or {},
        "entity_count": s.get("entity_count", 0),
        "multi_source_entity_count": s.get("multi_source_entity_count", 0),
        "risk_counts": s.get("risk_counts") or {},
        "top_entities": s.get("top_entities") or [],
    }
else:
    intelligence_layer = {
        "available": False, "generated_at": None, "sources_ingested": {},
        "entity_count": None, "multi_source_entity_count": None,
        "risk_counts": {}, "top_entities": [],
    }

# --- Decision Engine ----------------------------------------------------
decisions_doc = safe_load(decision_path)
if isinstance(decisions_doc, dict) and isinstance(decisions_doc.get("summary"), dict):
    s = decisions_doc["summary"]
    decision_engine = {
        "available": True,
        "generated_at": decisions_doc.get("generated_at"),
        "intelligence_report_generated_at": decisions_doc.get("intelligence_report_generated_at"),
        "decision_count": s.get("decision_count", 0),
        "action_counts": s.get("action_counts") or {},
        "pending_human_approval": s.get("pending_human_approval") or [],
    }
else:
    decision_engine = {
        "available": False, "generated_at": None,
        "intelligence_report_generated_at": None, "decision_count": None,
        "action_counts": {}, "pending_human_approval": [],
    }

data = {
    "generated_at": generated_at,
    "note": (
        "Display layer only, see dashboard/collect_decision_status.sh. Read-only: "
        "reads security/state/{shadow_ai,attack_graph,intelligence,decision_engine} "
        "directly off disk, never calls into any of those four modules own CLI. "
        "This is the Shadow AI Monitor -> Attack Graph -> Intelligence Layer -> "
        "Decision Engine pipeline (Phase 90-93) -- a SEPARATE, independent "
        "pipeline from the DLP/Emergency Shutdown layer the Incident Timeline "
        "panel above tracks. Every decision shown here is a RECOMMENDATION "
        "ONLY: WAIO never auto-executes containment from this pipeline -- a "
        "human reviews pending_human_approval and then, separately, by hand, "
        "chooses whether to run one of WAIO existing containment tools."
    ),
    "shadow_ai": shadow_ai,
    "attack_graph": attack_graph,
    "intelligence_layer": intelligence_layer,
    "decision_engine": decision_engine,
}
with open("logs/decision-status-latest.json", "w") as f:
    json.dump(data, f, indent=2, ensure_ascii=False)
    f.write("\n")
' "$SHADOW_AI_INVENTORY_FILE" "$ATTACK_GRAPH_FILE" "$INTELLIGENCE_REPORT_FILE" "$DECISION_ENGINE_FILE" "$GENERATED_AT"

echo "[COLLECT DECISION STATUS] Written to logs/decision-status-latest.json"
