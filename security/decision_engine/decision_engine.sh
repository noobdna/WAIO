#!/bin/bash
set -uo pipefail

# security/decision_engine/decision_engine.sh -- WAIO Decision Engine:
# turns the WAIO Intelligence/Evidence Layer's own ranked entity
# profiles into recommended response decisions, per the requested
# pipeline shape:
#
#     Shadow AI Monitor -\
#     Attack Graph        -> WAIO Intelligence/Evidence Layer -> WAIO Decision Engine -> DuCoPA -> Contain/Recover
#     Incident Learning  -/
#
# ============================================================
# CRITICAL SAFETY BOUNDARY -- read before touching this file
# ============================================================
# This file PROPOSES, IT NEVER DISPOSES. It is the first module in
# this pipeline whose job is to recommend a RESPONSE, not just report
# evidence -- which makes it tempting to also have it ACT. It does
# not, and must never be changed to. This file:
#   - never calls security/guardian.sh,
#     security/guardian_intervene_wrapper.sh,
#     security/guardian_intervene_quarantine_wrapper.sh,
#     security/guardian_release_agent.sh, security/guardian_approve.sh,
#     security/ducopa.sh, security/recovery_engine.sh,
#     security/recover.sh, or any `knowledge_manager.sh
#     approve|reject|hold|promote` call.
#   - never sources security/lib.sh and never calls
#     egress_check()/audit_log()/trigger_shutdown() (same posture as
#     Phase 90/91/92's own modules).
#   - makes no network call, modifies no process/firewall/routing rule,
#     and writes to nothing outside its own
#     security/state/decision_engine/ state dir.
# A RECOMMEND_CONTAINMENT decision in this file's own output is a
# human reading that output and THEN, separately, by hand, choosing to
# run one of WAIO's existing containment tools. This file does not
# queue an auto-execute path to them, does not shortcut
# incident_human_gate.sh's own approve/reject flow, and does not
# shortcut Guardian's own intervention wrappers. See
# decision_engine_lib.py's own header for the full reasoning; see
# tests/decision_engine_test.sh's own D-series for the static guards
# that keep this true in code, not just in this comment.
#
# This module's own INPUT is deliberately narrow: ONLY the WAIO
# Intelligence/Evidence Layer's own report JSON (file or stdin) -- same
# one-stage-consumes-only-the-stage-before-it discipline
# security/attack_graph/attack_graph.sh and
# security/intelligence/intelligence_layer.sh already established. The
# real intended usage is the full pipe:
#     security/shadow_ai/shadow_ai_monitor.sh scan \
#       | security/attack_graph/attack_graph.sh build \
#       | security/intelligence/intelligence_layer.sh ingest --shadow-ai - \
#       | security/decision_engine/decision_engine.sh decide
# (illustrative -- intelligence_layer.sh's own `ingest` currently reads
# named flags per source, not a single combined stdin stream; chaining
# it for real means writing each stage's output to a file first, same
# as this repo's own existing multi-stage pipelines already do when a
# stage needs more than one upstream input).
#
# Independently testable: state dir and audit log are both overridable
# via env var, same convention as every other domain in this repo; the
# CLI reads JSON from stdin/a file argument, so
# tests/decision_engine_test.sh needs no shadow_ai/attack_graph/
# intelligence fixture at all -- just a fixed Intelligence Layer report
# JSON, matching that module's own real output shape.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$SCRIPT_DIR"

STATE_DIR="${DECISION_ENGINE_STATE_DIR:-$SCRIPT_DIR/security/state/decision_engine}"
AUDIT_LOG="${DECISION_ENGINE_AUDIT_LOG:-$SCRIPT_DIR/logs/decision-engine-audit.jsonl}"
DECISIONS_FILE="$STATE_DIR/latest_decisions.json"

mkdir -p "$STATE_DIR" "$(dirname "$AUDIT_LOG")" 2>/dev/null || true

audit_decide_log() {
  local summary="$1"
  python3 -c "
import json, sys
print(json.dumps({
    'timestamp': sys.argv[1],
    'summary': sys.argv[2],
}, ensure_ascii=False))
" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$summary" >> "$AUDIT_LOG"
}

# decide [FILE|-] -- reads an Intelligence Layer report (default
# stdin), produces one Decision Record per entity, ranks them
# most-urgent-first, emits the full decision report JSON to stdout,
# persists it, logs a one-line summary. NEVER calls anything beyond
# this file's own state dir -- see this file's own header.
decide() {
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
  python3 - "$src" "$DECISIONS_FILE" 2>"$stderr_tmp" <<'PYEOF'
import datetime, json, os, sys

src_path, decisions_path = sys.argv[1], sys.argv[2]

sys.path.insert(0, os.path.join(os.getcwd(), "security", "decision_engine"))
import decision_engine_lib as del_

with open(src_path) as f:
    report = json.load(f)

entities = report.get("entities") or {}
decisions = del_.decide_all(entities)
ranked = del_.rank_decisions(decisions)
summary = del_.decision_summary(ranked)

output = {
    "generated_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "intelligence_report_generated_at": report.get("generated_at"),
    "decisions": ranked,
    "summary": summary,
}

print(json.dumps(output, ensure_ascii=False, indent=2))

tmp_path = f"{decisions_path}.tmp.{os.getpid()}"
with open(tmp_path, "w") as f:
    json.dump(output, f, ensure_ascii=False, indent=2, sort_keys=True)
os.replace(tmp_path, decisions_path)

print(
    f"decisions={summary['decision_count']} action_counts={summary['action_counts']} "
    f"pending_human_approval={summary['pending_human_approval']}",
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
    echo "[DECISION ENGINE] $summary" >&2
  fi
  audit_decide_log "$summary"
  return "$rc"
}

print_decisions() {
  if [ ! -f "$DECISIONS_FILE" ]; then
    echo "{}"
    return 0
  fi
  cat "$DECISIONS_FILE"
}

# print_status -- read-only summary, PLUS the explicit reminder this
# module never executes: every status print restates that acting on a
# pending decision is a separate, manual, human-run step.
print_status() {
  python3 -c "
import json, sys
path = sys.argv[1]
try:
    with open(path) as f:
        d = json.load(f)
except Exception:
    print('Decision Engine: no decisions generated yet')
    sys.exit(0)
s = d.get('summary', {})
print(f\"Decision Engine (generated {d.get('generated_at', '?')}):\")
print(f\"  decisions: {s.get('decision_count', 0)}\")
print(f\"  action counts: {s.get('action_counts', {})}\")
pending = s.get('pending_human_approval', [])
print(f\"  pending human approval to act ({len(pending)}): {pending}\")
if pending:
    print(
        '  NOTE: this is a RECOMMENDATION list only -- this module never '
        'acts on it. Review each entity, then act (if you agree) using '
        \"WAIO's existing containment tools by hand.\"
    )
" "$DECISIONS_FILE"
}

if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
  case "${1:-decide}" in
    decide)
      decide "${2:--}"
      ;;
    show)
      print_decisions
      ;;
    status)
      print_status
      ;;
    *)
      echo "Usage: $0 {decide [FILE|-]|show|status}" >&2
      exit 1
      ;;
  esac
fi
