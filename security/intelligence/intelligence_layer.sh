#!/bin/bash
set -uo pipefail

# security/intelligence/intelligence_layer.sh -- WAIO Intelligence /
# Evidence Layer: normalizes and aggregates evidence from multiple
# WAIO evidence-producing modules into one common schema, per the
# requested pipeline shape:
#
#     Shadow AI Monitor  -\
#     Attack Graph         -> WAIO Intelligence/Evidence Layer -> WAIO Decision Engine -> DuCoPA -> Contain/Recover
#     Incident Learning   -/
#     SaaS ATO Monitor    -/
#
# This file DECIDES NOTHING and ACTS ON NOTHING -- same "detection/
# evidence only" scope as security/shadow_ai/shadow_ai_monitor.sh,
# security/attack_graph/attack_graph.sh (Phase 90/91), and
# security/saas_ato/saas_ato_monitor.sh. It has no risk-escalation
# authority beyond rolling up each source's own already-computed
# risk/confidence to the highest observed value per entity (see
# intelligence_lib.py's own aggregate_by_entity() header). Nothing
# here is wired into security/guardian.sh, security/ducopa.sh, or any
# containment action -- it is still upstream of "WAIO Decision Engine"
# in the diagram above.
#
# Coupling is DELIBERATELY loose, same discipline
# security/attack_graph/attack_graph.sh already established: this file
# never imports/sources anything from security/shadow_ai/,
# security/attack_graph/, or security/saas_ato/, and never calls any
# of those modules' own CLI. It only reads whatever file paths are
# explicitly handed to it on the command line -- see `ingest`'s own
# usage below. The one exception, clearly scoped: `--incident-learning-dir` reads
# security/incident_learning/'s own candidate state files DIRECTLY off
# disk (the exact same read-only, same-repo, cross-domain access
# security/incident_learning/incident_analyzer.sh already has to
# security/knowledge/*.json -- not a new class of boundary crossing).
# This file never writes into that directory and never calls
# knowledge_manager.sh -- read-only, full stop.
#
# Only CANDIDATE/HOLD/APPROVED/PROMOTED-status candidates are ingested
# from Incident Learning (see ingest_incident_learning()'s own
# comment): these are the ones that actually reached a real
# confidence_score and human-gate relevance; an earlier-stage
# (COLLECTED/NORMALIZED/VERIFIED/ANALYZED/SCORED-and-rejected)
# candidate has nothing yet worth surfacing to a Decision Engine.
#
# WAIO GLOBAL RED ALERT Phase A (optional, this phase): `--global-patrol-report FILE`
# and `--snd-snapshot FILE` add two more optional sources, both read-only
# file arguments, same discipline as every flag above. Unlike the
# shadow_ai/attack_graph/saas_ato loose-coupling rule above (never import
# that SOURCE's own lib), security/red_alert/red_alert_adapter.py and
# snd_crossref.py are themselves an adapter layer explicitly designed to
# be reused unchanged here -- see red_alert_adapter.py's own header
# ("this file plays the same architectural role... that intelligence_
# layer.sh's own ingest() function already plays"). This phase ONLY adds
# these two flags to `ingest`; it never touches security/decision_engine/,
# security/guardian.sh, security/ducopa.sh, any cron wrapper, or any
# launchd plist -- security/red_alert/'s own D6/D7/D8 structural guards
# (tests/red_alert_test.sh) remain true after this change, confirmed by
# this file's own new D7 guard below.
#   --global-patrol-report FILE reads a file shaped like
#     logs/global-patrol-report-latest.json (global_patrol_report.py's own
#     real output): `new_incidents` (source_module="global_patrol") and
#     `critical_infrastructure_watch.confirmed_activity`
#     (source_module="critical_infra_watch") each go through
#     red_alert_adapter.from_global_patrol_entity(); `critical_infrastructure_watch.precursor_hypotheses`
#     goes through red_alert_adapter.from_precursor_hypothesis(). Entries
#     missing their own `id` (or, for a hypothesis, `attack_pattern`) are
#     skipped, never guessed.
#   --snd-snapshot FILE reads the `{"pdc_cached_at","snd_status"}`
#     envelope `security/continuity.sh snd-get` itself prints (or its
#     backing file, security/state/continuity/snd_snapshot.json) --
#     unwraps `snd_status` and runs it through
#     snd_crossref.build_crossref_signals() against whichever
#     --global-patrol-report entities were ingested in the SAME call
#     (never against this deployment's own live state unless the caller
#     explicitly passes that path). Every resulting signal is adapted via
#     red_alert_adapter.from_snd_crossref_signal(), which carries its own
#     mandatory, non-empty confidence_caveat straight into the record's
#     summary. Given alone (no --global-patrol-report in the same call),
#     there are no entities to cross-reference against, so this
#     contributes zero records -- not an error.
#   Both are validated defensively: a missing file, a file that is not
#     valid JSON, or JSON that is not the expected shape (not an object,
#     or `new_incidents`/`precursor_hypotheses` not a list) is logged to
#     stderr and treated as "this source contributed nothing" -- it never
#     raises, never crashes the rest of `ingest`, and never executes,
#     evaluates, or shells out on any string value found inside the file
#     (same posture as every other source above).
#
# Independently testable: every input is an explicit file/directory
# argument (never a default pointing at this deployment's own real
# security/state/..., so a plain `ingest` with no flags ingests
# nothing from anywhere -- the empty report, not a surprise live read).
# State dir and audit log are both overridable via env var, same
# convention as every other domain in this repo.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$SCRIPT_DIR"

STATE_DIR="${INTELLIGENCE_STATE_DIR:-$SCRIPT_DIR/security/state/intelligence}"
AUDIT_LOG="${INTELLIGENCE_AUDIT_LOG:-$SCRIPT_DIR/logs/intelligence-layer-audit.jsonl}"
REPORT_FILE="$STATE_DIR/latest_report.json"

mkdir -p "$STATE_DIR" "$(dirname "$AUDIT_LOG")" 2>/dev/null || true

audit_ingest_log() {
  local summary="$1"
  python3 -c "
import json, sys
print(json.dumps({
    'timestamp': sys.argv[1],
    'summary': sys.argv[2],
}, ensure_ascii=False))
" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$summary" >> "$AUDIT_LOG"
}

# ingest -- parses --shadow-ai/--attack-graph/--incident-learning-dir
# flags (any subset, each optional), normalizes+aggregates+ranks, emits
# the full report JSON to stdout, persists it, logs a summary.
ingest() {
  local shadow_ai_file="" attack_graph_file="" incident_learning_dir="" saas_ato_file=""
  local global_patrol_report_file="" snd_snapshot_file=""

  while [ $# -gt 0 ]; do
    case "$1" in
      --shadow-ai) shadow_ai_file="$2"; shift 2 ;;
      --attack-graph) attack_graph_file="$2"; shift 2 ;;
      --incident-learning-dir) incident_learning_dir="$2"; shift 2 ;;
      --saas-ato) saas_ato_file="$2"; shift 2 ;;
      --global-patrol-report) global_patrol_report_file="$2"; shift 2 ;;
      --snd-snapshot) snd_snapshot_file="$2"; shift 2 ;;
      *) echo "Usage: $0 ingest [--shadow-ai FILE] [--attack-graph FILE] [--incident-learning-dir DIR] [--saas-ato FILE] [--global-patrol-report FILE] [--snd-snapshot FILE]" >&2; return 1 ;;
    esac
  done

  local stderr_tmp
  stderr_tmp="$(mktemp)"
  python3 - "$shadow_ai_file" "$attack_graph_file" "$incident_learning_dir" "$saas_ato_file" "$global_patrol_report_file" "$snd_snapshot_file" "$REPORT_FILE" 2>"$stderr_tmp" <<'PYEOF'
import datetime, glob, json, os, sys

(shadow_ai_file, attack_graph_file, incident_learning_dir, saas_ato_file,
 global_patrol_report_file, snd_snapshot_file, report_path) = sys.argv[1:8]

sys.path.insert(0, os.path.join(os.getcwd(), "security", "intelligence"))
import intelligence_lib as il
sys.path.insert(0, os.path.join(os.getcwd(), "security", "red_alert"))
import red_alert_adapter as ra
import snd_crossref as sc

records = []
counts = {
    "shadow_ai": 0, "attack_graph": 0, "incident_learning": 0, "saas_ato": 0,
    "global_patrol": 0, "critical_infra_watch": 0, "snd_crossref": 0,
}
crossref_entities = []

if shadow_ai_file:
    with open(shadow_ai_file) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                finding = json.loads(line)
            except (json.JSONDecodeError, TypeError):
                continue
            records.append(il.from_shadow_ai_finding(finding))
            counts["shadow_ai"] += 1

if attack_graph_file:
    with open(attack_graph_file) as f:
        graph_doc = json.load(f)
    for name, node in (graph_doc.get("nodes") or {}).items():
        records.append(il.from_attack_graph_node(name, node))
        counts["attack_graph"] += 1
    for path in (graph_doc.get("analysis") or {}).get("attack_paths", []):
        records.append(il.from_attack_graph_path(path))
        counts["attack_graph"] += 1

if incident_learning_dir:
    # Only these four statuses carry real, scored, human-gate-relevant
    # intelligence -- see this file's own header for why earlier/
    # rejected stages are skipped.
    relevant_statuses = {"CANDIDATE", "HOLD", "APPROVED", "PROMOTED"}
    for path in glob.glob(os.path.join(incident_learning_dir, "*.json")):
        try:
            with open(path) as f:
                candidate = json.load(f)
        except Exception:
            continue
        if candidate.get("status") not in relevant_statuses:
            continue
        records.append(il.from_incident_learning_candidate(candidate))
        counts["incident_learning"] += 1

if saas_ato_file:
    with open(saas_ato_file) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                finding = json.loads(line)
            except (json.JSONDecodeError, TypeError):
                continue
            records.append(il.from_saas_ato_finding(finding))
            counts["saas_ato"] += 1

# --global-patrol-report: a WHOLE-FILE JSON read (same shape class as
# --attack-graph above), but wrapped in try/except -- unlike
# attack_graph_file above, malformed/unexpected content here is logged
# and skipped, never allowed to crash the rest of this ingest call (see
# this file's own header for why this source gets that extra safety).
# Nothing read from this file is ever executed, evaluated, or passed to
# a shell -- every field is read via plain dict/list .get() access only,
# same as every other source in this function.
gp_report = {}
if global_patrol_report_file:
    try:
        with open(global_patrol_report_file) as f:
            gp_report = json.load(f)
        if not isinstance(gp_report, dict):
            raise ValueError("top-level JSON is not an object")
    except Exception as e:
        print(f"[global-patrol-report] skipped ({e})", file=sys.stderr)
        gp_report = {}

new_incidents = gp_report.get("new_incidents")
if not isinstance(new_incidents, list):
    new_incidents = []
for entry in new_incidents:
    if not isinstance(entry, dict) or not entry.get("id"):
        continue
    records.append(ra.from_global_patrol_entity(entry, "global_patrol"))
    counts["global_patrol"] += 1
    crossref_entities.append(entry)

critical_infra_watch_section = gp_report.get("critical_infrastructure_watch")
if not isinstance(critical_infra_watch_section, dict):
    critical_infra_watch_section = {}

confirmed_activity = critical_infra_watch_section.get("confirmed_activity")
if not isinstance(confirmed_activity, list):
    confirmed_activity = []
for entry in confirmed_activity:
    if not isinstance(entry, dict) or not entry.get("id"):
        continue
    records.append(ra.from_global_patrol_entity(entry, "critical_infra_watch"))
    counts["critical_infra_watch"] += 1
    crossref_entities.append(entry)

precursor_hypotheses = critical_infra_watch_section.get("precursor_hypotheses")
if not isinstance(precursor_hypotheses, list):
    precursor_hypotheses = []
for hypothesis in precursor_hypotheses:
    if not isinstance(hypothesis, dict) or not hypothesis.get("attack_pattern"):
        continue
    records.append(ra.from_precursor_hypothesis(hypothesis))
    counts["critical_infra_watch"] += 1

# --snd-snapshot: unwraps continuity.sh's own {"pdc_cached_at",
# "snd_status"} envelope and cross-references it against whichever
# --global-patrol-report entities were ingested above in this SAME
# call -- never against this deployment's own live PDC state unless
# the caller explicitly passed that path. Given with no
# --global-patrol-report (crossref_entities empty), this safely
# contributes zero records, not an error.
snd_status = None
if snd_snapshot_file:
    try:
        with open(snd_snapshot_file) as f:
            snd_envelope = json.load(f)
        if not isinstance(snd_envelope, dict):
            raise ValueError("top-level JSON is not an object")
        snd_status = snd_envelope.get("snd_status")
    except Exception as e:
        print(f"[snd-snapshot] skipped ({e})", file=sys.stderr)
        snd_status = None

if snd_status is not None and crossref_entities:
    for signal in sc.build_crossref_signals(snd_status, crossref_entities):
        records.append(ra.from_snd_crossref_signal(signal))
        counts["snd_crossref"] += 1

profiles = il.aggregate_by_entity(records)
ranked = il.rank_profiles(profiles)
summary = il.report_summary(ranked)

output = {
    "generated_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "sources_ingested": counts,
    "records_total": len(records),
    "entities": {p["entity"]: p for p in ranked},
    "ranked_entities": [p["entity"] for p in ranked],
    "summary": summary,
}

print(json.dumps(output, ensure_ascii=False, indent=2))

tmp_path = f"{report_path}.tmp.{os.getpid()}"
with open(tmp_path, "w") as f:
    json.dump(output, f, ensure_ascii=False, indent=2, sort_keys=True)
os.replace(tmp_path, report_path)

print(
    f"sources={counts} records_total={len(records)} entities={summary['entity_count']} "
    f"risk_counts={summary['risk_counts']} multi_source={summary['multi_source_entity_count']}",
    file=sys.stderr,
)
PYEOF
  local rc=$?
  local summary
  summary="$(cat "$stderr_tmp")"
  rm -f "$stderr_tmp"
  if [ -n "$summary" ]; then
    echo "[INTELLIGENCE LAYER] $summary" >&2
  fi
  audit_ingest_log "$summary"
  return "$rc"
}

print_report() {
  if [ ! -f "$REPORT_FILE" ]; then
    echo "{}"
    return 0
  fi
  cat "$REPORT_FILE"
}

print_status() {
  python3 -c "
import json, sys
path = sys.argv[1]
try:
    with open(path) as f:
        r = json.load(f)
except Exception:
    print('Intelligence Layer: no report built yet')
    sys.exit(0)
s = r.get('summary', {})
print(f\"Intelligence Layer (generated {r.get('generated_at', '?')}):\")
print(f\"  sources ingested: {r.get('sources_ingested', {})}\")
print(f\"  entities: {s.get('entity_count', 0)}  multi-source: {s.get('multi_source_entity_count', 0)}\")
print(f\"  risk counts: {s.get('risk_counts', {})}\")
print('  top entities:')
for e in s.get('top_entities', []):
    print(f\"    {e['entity']} ({e['entity_type']}): {e['risk']}/{e['confidence']} via {e['source_modules']}\")
" "$REPORT_FILE"
}

if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
  case "${1:-}" in
    ingest)
      shift
      ingest "$@"
      ;;
    show)
      print_report
      ;;
    status)
      print_status
      ;;
    *)
      echo "Usage: $0 {ingest [--shadow-ai FILE] [--attack-graph FILE] [--incident-learning-dir DIR] [--saas-ato FILE] [--global-patrol-report FILE] [--snd-snapshot FILE]|show|status}" >&2
      exit 1
      ;;
  esac
fi
