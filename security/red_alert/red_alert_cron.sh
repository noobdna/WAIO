#!/bin/bash
set -uo pipefail

# security/red_alert/red_alert_cron.sh -- WAIO GLOBAL RED ALERT Phase B:
# a manual-invocation-only, READ-ONLY prototype entry point that feeds
# Phase A's new security/intelligence/intelligence_layer.sh `ingest`
# flags (--global-patrol-report/--snd-snapshot, added for exactly this
# purpose) from whatever real Global Patrol report and SND@HOME
# snapshot ALREADY EXIST on disk.
#
# ============================================================
# SCOPE, STATED NARROWLY -- read before touching this file
# ============================================================
# This file does exactly three things:
#   1. Resolves the two real, already-documented file paths
#      (logs/global-patrol-report-latest.json,
#      security/state/continuity/snd_snapshot.json -- same env-var
#      override names global_patrol_report.py/continuity.sh themselves
#      already use, see below).
#   2. Validates each path/file (exists, readable, valid JSON, top-level
#      a JSON object) BEFORE ever handing it to `intelligence_layer.sh
#      ingest` -- a missing or invalid input is logged and OMITTED from
#      the ingest call entirely, never guessed, never substituted with
#      an empty/placeholder object presented as if it were real data.
#      This file never reads a single field out of either report itself
#      -- field-level parsing is `intelligence_layer.sh ingest`'s own
#      job (Phase A), already covered by its own regression suite
#      (tests/intelligence_layer_global_patrol_test.sh), including that
#      suite's own injection-safety case (I17).
#   3. Invokes `security/intelligence/intelligence_layer.sh ingest` with
#      only the flags whose input validated, and propagates its real
#      exit code -- nothing here forces exit 0 over a genuine failure.
#
# NEVER calls, by name, anywhere in this file: security/decision_engine/
# decision_engine.sh, security/decision_engine/decision_engine_lib.py,
# security/guardian.sh, security/guardian_intervene_wrapper.sh,
# security/guardian_intervene_quarantine_wrapper.sh,
# security/guardian_release_agent.sh, security/guardian_approve.sh,
# security/ducopa.sh, security/recovery_engine.sh, security/recover.sh,
# security/incident_learning/knowledge_manager.sh's own
# approve/reject/hold/promote verbs, or
# security/incident_learning/incident_human_gate.sh. Never sources
# security/lib.sh (no egress_check()/audit_log()/trigger_shutdown()),
# never makes a network call of its own, never scans or touches any
# third-party/external system, and never performs a containment or
# recovery action of any kind. tests/red_alert_cron_test.sh's own
# D-series proves every one of these claims structurally, not just in
# this comment.
#
# NOT SCHEDULED, NOT INSTALLED (explicit, this phase): no launchd plist
# exists for this file, it is not referenced from any
# security/incident_learning/*.sh cron wrapper, it does not register
# itself with launchctl/crontab/cron in any way, and nothing in this
# repo currently calls it automatically -- running it is exactly as
# consequential as a human typing the equivalent
# `intelligence_layer.sh ingest --global-patrol-report ... --snd-snapshot
# ...` command by hand, nothing more. Whether/when to schedule this is
# an explicit, separate, later decision (same inspect->validate->
# dry-run->explicit-approval->install sequence every other scheduled
# job in this repo went through) -- not made by this file's existence.
#
# WHY THE DEFAULT PATHS ARE THE REAL ONES: reading real, already-
# existing output from already-approved, already-scheduled modules
# (global_patrol_cron.sh's own `-latest.json`, continuity.sh's own
# read-only snd-get cache) is the entire point of this prototype -- it
# is meant to be run, by hand, against whatever a real deployment
# already has on disk, to see what Phase A's ingest would actually
# produce from real data today. Both paths are fully overridable via
# env var for testing, same convention as every other file in this
# domain:
#   GLOBAL_PATROL_OUTPUT_DIR (same variable name
#     global_patrol_cron.sh/global_patrol_report.py already use,
#     default "logs") -> "$GLOBAL_PATROL_OUTPUT_DIR/global-patrol-report-latest.json"
#   WAIO_CONTINUITY_STATE_DIR / WAIO_CONTINUITY_SND_SNAPSHOT_FILE (same
#     variable names security/continuity.sh already uses) -> the exact
#     same resolved path continuity.sh's own CONTINUITY_SND_SNAPSHOT_FILE
#     would resolve to, computed independently here (this file never
#     sources continuity.sh itself, to avoid pulling in its own
#     `source security/lib.sh`/`source security/segment_manager.sh` --
#     see "NEVER calls" above).
# Neither default existing on a given machine (e.g. SND_HOME not
# configured at all) is a normal, expected, NON-error state -- see
# validate_json_object_file()'s own callers below.
#
# This file's own log (RED_ALERT_CRON_LOG, default
# logs/red-alert-cron.log) records only: which of the two inputs were
# found/valid, the counts intelligence_layer.sh ingest itself reports
# (sources_ingested/records_total/entities), and the final exit code --
# never the report content itself (untrusted data, never echoed back
# into this file's own log line by line).

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$SCRIPT_DIR"

LOG_FILE="${RED_ALERT_CRON_LOG:-logs/red-alert-cron.log}"
mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true

log() {
  printf '%s %s\n' "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" "$1" >>"$LOG_FILE"
}

# validate_json_object_file PATH -- 0 (valid) only if PATH exists, is a
# regular file, is readable, and its content parses as JSON whose
# top-level value is a JSON object ({...}, not a list/string/number).
# Never prints the file's own content anywhere (stdout, stderr, or the
# log) -- this function's only output is its exit code. Parsing only,
# via Python's json module (same as every JSON read elsewhere in this
# pipeline) -- never eval/exec, never a shell interpretation of
# anything inside the file.
validate_json_object_file() {
  local path="$1"
  [ -n "$path" ] || return 1
  [ -f "$path" ] || return 1
  [ -r "$path" ] || return 1
  python3 -c "
import json, sys
try:
    with open(sys.argv[1]) as f:
        doc = json.load(f)
except Exception:
    sys.exit(1)
sys.exit(0 if isinstance(doc, dict) else 1)
" "$path" 2>/dev/null
}

GLOBAL_PATROL_REPORT_FILE="${GLOBAL_PATROL_OUTPUT_DIR:-logs}/global-patrol-report-latest.json"
SND_SNAPSHOT_FILE="${WAIO_CONTINUITY_SND_SNAPSHOT_FILE:-${WAIO_CONTINUITY_STATE_DIR:-security/state/continuity}/snd_snapshot.json}"

INGEST_ARGS=()

if validate_json_object_file "$GLOBAL_PATROL_REPORT_FILE"; then
  log "global-patrol-report: found and structurally valid ($GLOBAL_PATROL_REPORT_FILE)"
  INGEST_ARGS+=(--global-patrol-report "$GLOBAL_PATROL_REPORT_FILE")
else
  if [ -e "$GLOBAL_PATROL_REPORT_FILE" ]; then
    log "global-patrol-report: present but not valid JSON object, SKIPPED ($GLOBAL_PATROL_REPORT_FILE) -- treating this cycle as having NO new Global Patrol intelligence, never inventing data"
  else
    log "global-patrol-report: absent, SKIPPED ($GLOBAL_PATROL_REPORT_FILE) -- treating this cycle as having NO new Global Patrol intelligence, never inventing data"
  fi
fi

if validate_json_object_file "$SND_SNAPSHOT_FILE"; then
  log "snd-snapshot: found and structurally valid ($SND_SNAPSHOT_FILE)"
  INGEST_ARGS+=(--snd-snapshot "$SND_SNAPSHOT_FILE")
else
  if [ -e "$SND_SNAPSHOT_FILE" ]; then
    log "snd-snapshot: present but not valid JSON object, SKIPPED ($SND_SNAPSHOT_FILE) -- treating this cycle as having NO SND@HOME snapshot, never inventing one"
  else
    log "snd-snapshot: absent, SKIPPED ($SND_SNAPSHOT_FILE) -- treating this cycle as having NO SND@HOME snapshot, never inventing one"
  fi
fi

OUT="$(./security/intelligence/intelligence_layer.sh ingest "${INGEST_ARGS[@]+"${INGEST_ARGS[@]}"}" 2>>"$LOG_FILE")"
RC=$?

SUMMARY="$(python3 -c "
import json, sys
try:
    d = json.loads(sys.argv[1])
except Exception:
    print('ingest produced no parseable JSON output')
    sys.exit(0)
s = d.get('summary', {})
print(
    f\"sources_ingested={d.get('sources_ingested', {})} \"
    f\"records_total={d.get('records_total', 0)} \"
    f\"entity_count={s.get('entity_count', 0)} \"
    f\"multi_source={s.get('multi_source_entity_count', 0)} \"
    f\"risk_counts={s.get('risk_counts', {})}\"
)
" "$OUT" 2>/dev/null || echo "ingest produced no parseable JSON output")"

log "ingest exit_code=$RC $SUMMARY"
echo "$OUT"
exit "$RC"
