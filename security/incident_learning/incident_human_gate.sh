#!/bin/bash
set -uo pipefail

# security/incident_learning/incident_human_gate.sh -- Incident
# Learning Engine, Step 4: the Human Gate / Approval flow between
# CANDIDATE and PROMOTED.
#
# This file adds NO new state-machine edge and NO new write path into
# security/knowledge/ beyond what knowledge_manager.sh already defines
# (CANDIDATE/HOLD -> APPROVED/REJECTED via its own `approve`/`reject`/
# `hold`/`release` CLI commands, APPROVED -> PROMOTED via its own
# `promote`). This file is a thin, human-facing layer in front of
# those same primitives, for two reasons only:
#
#   1. review ID -- read-only. Prints the Evidence (incident_evidence.sh)
#      and Confidence (incident_confidence.sh) fields already recorded
#      on the candidate's own state file, so a human can see the actual
#      basis for the pipeline's score BEFORE deciding, without having
#      to know the state file's JSON shape. Never mutates state, never
#      writes anywhere. Design requirement 4 ("Evidence / Confidenceの
#      根拠をApproval時に参照可能にする") is satisfied by making this
#      the command a reviewer runs immediately before approve/reject/
#      hold -- see the CLI usage note below.
#
#   2. approve/reject/hold/release ID "reason" -- thin wrappers around
#      knowledge_manager.sh's own commands of the same name, with two
#      differences: (a) they refuse to run at all if the candidate
#      isn't currently in a state where that action is legal, with a
#      clear human-facing message, rather than only surfacing
#      knowledge_manager.sh's own lower-level "not allowed" error; (b)
#      they fold the same Evidence/Confidence summary review() prints
#      into the audit reason string itself, so the audit log entry for
#      every human decision permanently records what evidence was in
#      front of the human when they made it -- not just the decision.
#
# Neither of these adds a shortcut: every knowledge_manager.sh-side
# safety property (non-empty reason required, illegal transitions
# refused and logged, PROMOTED only reachable from APPROVED via a
# separate explicit `promote` call) still applies unchanged underneath.
#
# DuCoPA alignment (explicit, load-bearing, same as every other file in
# this domain): this file never reads or writes
# security/egress_allowlist.conf, security/segments.conf,
# sshd_config, or any other Control Plane file, and makes no network
# call. It also never calls `promote` itself -- promotion into
# security/knowledge/ remains a distinct, separate human action taken
# directly via knowledge_manager.sh, deliberately not folded into
# `approve` here, so "approved" and "actually written into the
# knowledge base" are never the same keystroke.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$SCRIPT_DIR"
KM_SCRIPT="security/incident_learning/knowledge_manager.sh"
km() { bash "$KM_SCRIPT" "$@"; }

KNOWLEDGE_STATE_DIR_RESOLVED="${KNOWLEDGE_MANAGER_STATE_DIR:-$SCRIPT_DIR/security/state/incident_learning/candidates}"

# evidence_summary ID -- prints a human-readable, multi-line summary of
# every Evidence/Confidence field already recorded on the candidate's
# state file (absent fields print as blank, never as an error -- a
# candidate that hasn't reached evidence/confidence yet still has a
# reviewable summary, just a sparser one). Pure read, no side effects.
evidence_summary() {
  local id="$1" state_file="$KNOWLEDGE_STATE_DIR_RESOLVED/$1.json"
  [ -f "$state_file" ] || { echo "[HUMAN-GATE] ERROR: unknown candidate '$id'" >&2; return 1; }
  python3 -c "
import json
d = json.load(open('$state_file'))
def g(k, default=''):
    v = d.get(k, default)
    return default if v is None else v
print(f\"  id:                                {g('id')}\")
print(f\"  status:                            {g('status')}\")
print(f\"  source / source_type:              {g('source')} / {g('source_type')}\")
print(f\"  source_url:                        {g('source_url')}\")
print(f\"  collected_at:                      {g('collected_at')}\")
print(f\"  raw_text:                          {g('raw_text')}\")
print(f\"  cve_list:                          {g('cve_list', [])}\")
print(f\"  ioc_list:                          {g('ioc_list', [])}\")
print(f\"  detection_points:                  {g('detection_points', [])}\")
print(f\"  mitigations:                       {g('mitigations', [])}\")
print(f\"  --- evidence (incident_evidence.sh) ---\")
print(f\"  evidence_source_type:              {g('evidence_source_type')}\")
print(f\"  evidence_corroborating_count:      {g('evidence_corroborating_count')}\")
print(f\"  evidence_age_days:                 {g('evidence_age_days')}\")
print(f\"  evidence_self_reported_uncorroborated: {g('evidence_self_reported_uncorroborated')}\")
print(f\"  --- confidence (incident_confidence.sh) ---\")
print(f\"  confidence_score:                  {g('confidence_score')}\")
"
}

# evidence_summary_oneline ID -- the same fields, collapsed to a single
# line, meant to be folded into an audit reason string (audit log lines
# are themselves single JSON objects -- see candidate_audit_log in
# knowledge_manager.sh -- so the reason recorded there must stay
# one-line plain text, never the multi-line report() above).
evidence_summary_oneline() {
  local id="$1" state_file="$KNOWLEDGE_STATE_DIR_RESOLVED/$1.json"
  [ -f "$state_file" ] || return 1
  python3 -c "
import json
d = json.load(open('$state_file'))
def g(k, default=''):
    v = d.get(k, default)
    return default if v is None else v
print(
    f\"evidence: source_type={g('evidence_source_type', g('source_type'))}, \"
    f\"corroborating={g('evidence_corroborating_count', 0)}, \"
    f\"age_days={g('evidence_age_days', 0)}, \"
    f\"self_reported_uncorroborated={g('evidence_self_reported_uncorroborated', False)}, \"
    f\"confidence_score={g('confidence_score')}\"
)
"
}

# review ID -- read-only human-facing report. Works at any status (a
# reviewer may want to look at a REJECTED or PROMOTED candidate too),
# but flags plainly when the candidate isn't currently awaiting a
# decision, so this can't be mistaken for "action needed".
review() {
  local id="$1" current
  current="$(km status "$id" 2>/dev/null)" || { echo "[HUMAN-GATE] ERROR: unknown candidate '$id'" >&2; return 1; }
  echo "=== Human Gate review: $id ==="
  evidence_summary "$id"
  case "$current" in
    CANDIDATE) echo "  (awaiting human decision: approve / reject / hold)" ;;
    HOLD) echo "  (on hold: approve / reject / release)" ;;
    *) echo "  (status=$current -- not currently awaiting a human-gate decision)" ;;
  esac
}

# require_status ID STATUS... -- returns 0 if the candidate's current
# status is one of STATUS..., else prints a clear human-facing error
# and returns 1. This exists purely for a friendlier, action-specific
# message than knowledge_manager.sh's own generic "not allowed" --
# knowledge_manager.sh's own transition_allowed() is still the actual
# enforcement point underneath (see this file's own header).
require_status() {
  local id="$1" current; shift
  current="$(km status "$id" 2>/dev/null)" || { echo "[HUMAN-GATE] ERROR: unknown candidate '$id'" >&2; return 1; }
  local want
  for want in "$@"; do
    [ "$current" = "$want" ] && return 0
  done
  echo "[HUMAN-GATE] ERROR: '$id' is '$current' -- this action requires one of: $* " >&2
  return 1
}

hg_approve() {
  local id="$1" reason="$2"
  require_status "$id" CANDIDATE HOLD || return 1
  local ev; ev="$(evidence_summary_oneline "$id")"
  km approve "$id" "$reason | $ev"
}

hg_reject() {
  local id="$1" reason="$2"
  require_status "$id" CANDIDATE HOLD || return 1
  local ev; ev="$(evidence_summary_oneline "$id")"
  km reject "$id" "$reason | $ev"
}

hg_hold() {
  local id="$1" reason="$2"
  require_status "$id" CANDIDATE || return 1
  local ev; ev="$(evidence_summary_oneline "$id")"
  km hold "$id" "$reason | $ev"
}

hg_release() {
  local id="$1" reason="$2"
  require_status "$id" HOLD || return 1
  km release "$id" "$reason"
}

if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
  case "${1:-}" in
    review)
      [ -n "${2:-}" ] || { echo "Usage: $0 review ID" >&2; exit 1; }
      review "$2"
      ;;
    approve)
      [ -n "${2:-}" ] && [ -n "${3:-}" ] || { echo "Usage: $0 approve ID \"reason\"" >&2; exit 1; }
      hg_approve "$2" "$3"
      ;;
    reject)
      [ -n "${2:-}" ] && [ -n "${3:-}" ] || { echo "Usage: $0 reject ID \"reason\"" >&2; exit 1; }
      hg_reject "$2" "$3"
      ;;
    hold)
      [ -n "${2:-}" ] && [ -n "${3:-}" ] || { echo "Usage: $0 hold ID \"reason\"" >&2; exit 1; }
      hg_hold "$2" "$3"
      ;;
    release)
      [ -n "${2:-}" ] && [ -n "${3:-}" ] || { echo "Usage: $0 release ID \"reason\"" >&2; exit 1; }
      hg_release "$2" "$3"
      ;;
    *)
      echo "Usage: $0 {review ID|approve ID \"reason\"|reject ID \"reason\"|hold ID \"reason\"|release ID \"reason\"}" >&2
      exit 1
      ;;
  esac
fi
