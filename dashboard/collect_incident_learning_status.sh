#!/bin/bash
set -uo pipefail

# dashboard/collect_incident_learning_status.sh -- Phase 76: read-only
# data collector for the WAIO Dashboard, mirroring
# dashboard/collect_segment_status.sh's own conventions exactly. Reads
# the Incident Learning Engine's own state files
# (security/incident_learning/knowledge_manager.sh's
# KNOWLEDGE_MANAGER_STATE_DIR, one JSON per candidate) and its audit
# log (KNOWLEDGE_MANAGER_AUDIT_LOG) directly off disk. Zero network
# calls, zero calls into knowledge_manager.sh's own CLI -- this script
# only sources it for its path variables (KNOWLEDGE_STATE_DIR/
# KNOWLEDGE_AUDIT_LOG/KNOWLEDGE_BASE_DIR), never candidate_transition/
# candidate_create/knowledge_promote. It never advances a candidate's
# status and never writes into security/knowledge/ -- display layer
# only, same posture as every other dashboard/collect_*.sh.
#
# Output: logs/incident-learning-status-latest.json (logs/ already
# gitignored).

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"
source security/incident_learning/knowledge_manager.sh

now_iso() { python3 -c 'import datetime; print(datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="milliseconds"))'; }

GENERATED_AT="$(now_iso)"

mkdir -p logs
python3 -c '
import glob, json, os, sys

state_dir, audit_log, knowledge_dir, generated_at = sys.argv[1:5]

STATUSES = ["COLLECTED", "NORMALIZED", "VERIFIED", "ANALYZED", "SCORED",
            "CANDIDATE", "APPROVED", "PROMOTED", "REJECTED", "HOLD"]
counts = {s: 0 for s in STATUSES}
candidates = []
human_gate = []

for path in sorted(glob.glob(os.path.join(state_dir, "*.json"))):
    try:
        d = json.load(open(path))
    except Exception:
        continue
    st = d.get("status")
    counts[st] = counts.get(st, 0) + 1
    entry = {
        "id": d.get("id"),
        "status": st,
        "confidence_score": d.get("confidence_score"),
        "source": d.get("source"),
        "updated_at": d.get("updated_at"),
    }
    candidates.append(entry)
    if st in ("CANDIDATE", "HOLD"):
        human_gate.append({
            **entry,
            "source_type": d.get("source_type"),
            "reason": d.get("reason"),
        })

human_gate.sort(key=lambda c: c.get("updated_at") or "")

promoted_count = len(glob.glob(os.path.join(knowledge_dir, "*.json")))

recent_events = []
if os.path.isfile(audit_log):
    with open(audit_log) as f:
        lines = [l.strip() for l in f if l.strip()]
    for l in reversed(lines[-15:]):
        try:
            recent_events.append(json.loads(l))
        except Exception:
            pass

data = {
    "generated_at": generated_at,
    "note": "Display layer only, see dashboard/collect_incident_learning_status.sh. Read-only: reads security/incident_learning state and audit files, never advances a candidate or writes to security/knowledge/.",
    "counts": counts,
    "total_candidates": len(candidates),
    "promoted_knowledge_entries": promoted_count,
    "human_gate_queue": human_gate,
    "candidates": candidates,
    "recent_events": recent_events,
}
with open("logs/incident-learning-status-latest.json", "w") as f:
    json.dump(data, f, indent=2, ensure_ascii=False)
    f.write("\n")
' "$KNOWLEDGE_STATE_DIR" "$KNOWLEDGE_AUDIT_LOG" "$KNOWLEDGE_BASE_DIR" "$GENERATED_AT"

echo "[COLLECT INCIDENT LEARNING STATUS] Written to logs/incident-learning-status-latest.json"
