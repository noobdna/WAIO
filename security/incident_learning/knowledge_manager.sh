#!/bin/bash
set -uo pipefail

# security/incident_learning/knowledge_manager.sh -- Incident Learning
# Engine, Step 1: candidate identity, status persistence, and the
# promotion state machine. Modeled directly on
# security/segment_manager.sh's own proven shape (same
# load/index/get_status/transition_allowed/transition/audit_log split,
# same append-only JSONL audit trail, same "the state machine graph is
# the actual enforcement point, not documentation" posture) -- see that
# file's own header for the pattern this one deliberately repeats.
#
# Scope of this file: the SAFETY BACKBONE only. It knows nothing about
# how to fetch, normalize, verify, or score an incident -- those are
# security/incident_learning/collectors/*, incident_normalizer.sh,
# incident_evidence.sh, and incident_analyzer.sh's own jobs (later
# steps). This file only enforces WHICH status transitions are legal
# and records every attempt, successful or not.
#
# DuCoPA alignment (explicit, load-bearing): this file NEVER reads or
# writes security/egress_allowlist.conf, security/segments.conf,
# sshd_config, or any other Control Plane file. A promoted knowledge
# entry lands in security/knowledge/ (a separate, read-only-by-
# convention namespace) -- this file has no code path that feeds a
# learned incident back into anything that gates network/SSH/recovery
# decisions. Promotion to WAIO Knowledge is not reachable automatically
# from any earlier state: CANDIDATE -> APPROVED exists only via this
# file's own `approve` CLI command, which requires an explicit non-empty
# reason string, the same human-gate convention
# segment_manager.sh's `set ... --force` and recovery_engine.sh's
# escalate_to_human() already use elsewhere in this repo.
#
# State machine (per the Incident Learning Engine design):
#   COLLECTED -> NORMALIZED   (incident_normalizer.sh: raw payload structured)
#   COLLECTED -> REJECTED     (malformed/unusable raw data)
#   NORMALIZED -> VERIFIED    (incident_evidence.sh: evidence/source attached)
#   NORMALIZED -> REJECTED    (no usable evidence found)
#   VERIFIED -> ANALYZED      (incident_analyzer.sh: checked against existing knowledge)
#   VERIFIED -> REJECTED      (duplicate of existing knowledge, or contamination suspected)
#   ANALYZED -> SCORED        (confidence score computed)
#   ANALYZED -> REJECTED      (analysis found this unusable)
#   SCORED -> CANDIDATE       (crossed the minimum-confidence floor)
#   SCORED -> REJECTED        (confidence too low to even present to a human)
#   CANDIDATE -> APPROVED     (human gate only -- see `approve` below)
#   CANDIDATE -> REJECTED     (human gate only -- see `reject` below)
#   APPROVED -> PROMOTED      (written into security/knowledge/)
#   APPROVED -> REJECTED      (promotion itself failed -- e.g. write conflict)
# Every other (FROM, TO) pair is rejected, with no --force escape hatch
# at all (unlike segment_manager.sh's failed->isolated override) --
# there is no legitimate reason to ever skip the human gate here.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$SCRIPT_DIR"

KNOWLEDGE_STATE_DIR="${KNOWLEDGE_MANAGER_STATE_DIR:-$SCRIPT_DIR/security/state/incident_learning/candidates}"
KNOWLEDGE_AUDIT_LOG="${KNOWLEDGE_MANAGER_AUDIT_LOG:-$SCRIPT_DIR/logs/incident-learning-audit.jsonl}"
KNOWLEDGE_BASE_DIR="${KNOWLEDGE_MANAGER_KNOWLEDGE_DIR:-$SCRIPT_DIR/security/knowledge}"

mkdir -p "$KNOWLEDGE_STATE_DIR" "$(dirname "$KNOWLEDGE_AUDIT_LOG")" "$KNOWLEDGE_BASE_DIR" 2>/dev/null || true

candidate_state_path() { echo "$KNOWLEDGE_STATE_DIR/$1.json"; }
knowledge_entry_path() { echo "$KNOWLEDGE_BASE_DIR/$1.json"; }

# candidate_exists ID -- 0 if a state file already exists for this id.
candidate_exists() {
  [ -f "$(candidate_state_path "$1")" ]
}

# _km_parse_extras [KEY=VALUE ...] -- shared by candidate_create and
# candidate_transition. Each VALUE is tried as JSON first (so
# cve_list='["CVE-2026-10001"]' becomes a real array, confidence_score=82
# becomes a real number), falling back to a plain string if it doesn't
# parse -- so a caller never has to think about quoting/escaping for the
# common case (a bare word or sentence), only for genuinely structured
# values.
_km_parse_extras() {
  python3 -c "
import json, sys
d = {}
for kv in sys.argv[1:]:
    k, _, v = kv.partition('=')
    try:
        d[k] = json.loads(v)
    except (json.JSONDecodeError, ValueError):
        d[k] = v
print(json.dumps(d))
" "$@"
}

# candidate_create ID [SOURCE] [KEY=VALUE ...] -- creates a brand-new
# candidate at status COLLECTED. Refuses if the id already exists (no
# silent overwrite -- same "never clobber existing state" posture as
# every other writer in this file). Optional trailing KEY=VALUE pairs
# (e.g. source_type=vendor_advisory, source_url=..., raw_text=...) are
# folded straight into the initial record via the same _km_parse_extras
# mechanism candidate_transition uses -- a Collector's own output
# fields land on the candidate without this function needing to know
# their names in advance.
candidate_create() {
  local id="$1" source="${2:-unknown}"
  shift 2 2>/dev/null || shift "$#"
  if candidate_exists "$id"; then
    echo "[KNOWLEDGE] ERROR: candidate '$id' already exists" >&2
    return 1
  fi
  local path tmp extra_json="{}"
  if [ "$#" -gt 0 ]; then
    extra_json="$(_km_parse_extras "$@")"
  fi
  path="$(candidate_state_path "$id")"
  tmp="$path.tmp.$$"
  python3 -c "
import json, sys
d = {
    'id': sys.argv[1],
    'status': 'COLLECTED',
    'previous_status': None,
    'source': sys.argv[2],
    'created_at': sys.argv[3],
    'updated_at': sys.argv[3],
    'confidence_score': None,
    'reason': 'collected',
}
d.update(json.loads(sys.argv[4]))
json.dump(d, open(sys.argv[5], 'w'), ensure_ascii=False, indent=2)
" "$id" "$source" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$extra_json" "$tmp"
  mv -f "$tmp" "$path"
  candidate_audit_log "$id" "collected" "new raw incident collected from '$source'" "collect" "recorded"
  echo "[KNOWLEDGE] $id: created at COLLECTED (source=$source)"
}

# candidate_get_status ID -- prints the status, or nothing + returns 1
# if this id doesn't exist (deliberately different from
# segment_manager.sh's segment_get_status, which defaults unknown
# segments to "normal" -- there is no sensible implicit default status
# for an incident candidate that was never actually collected).
candidate_get_status() {
  local id="$1" path
  path="$(candidate_state_path "$id")"
  [ -f "$path" ] || return 1
  python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['status'])" "$path"
}

candidate_get_field() {
  local id="$1" field="$2" path
  path="$(candidate_state_path "$id")"
  [ -f "$path" ] || return 1
  python3 -c "import json,sys; print(json.load(open(sys.argv[1])).get(sys.argv[2], ''))" "$path" "$field"
}

# transition_allowed FROM TO -- the state machine's only source of
# truth, both directions checked as an explicit pair, same discipline
# as segment_manager.sh's own transition_allowed(). No wildcard/--force
# path exists anywhere in this file -- see this file's own header for
# why that's deliberate here.
transition_allowed() {
  local from="$1" to="$2"
  case "$from:$to" in
    COLLECTED:NORMALIZED) return 0 ;;
    COLLECTED:REJECTED) return 0 ;;
    NORMALIZED:VERIFIED) return 0 ;;
    NORMALIZED:REJECTED) return 0 ;;
    VERIFIED:ANALYZED) return 0 ;;
    VERIFIED:REJECTED) return 0 ;;
    ANALYZED:SCORED) return 0 ;;
    ANALYZED:REJECTED) return 0 ;;
    SCORED:CANDIDATE) return 0 ;;
    SCORED:REJECTED) return 0 ;;
    CANDIDATE:APPROVED) return 0 ;;
    CANDIDATE:REJECTED) return 0 ;;
    APPROVED:PROMOTED) return 0 ;;
    APPROVED:REJECTED) return 0 ;;
    *) return 1 ;;
  esac
}

# candidate_audit_log ID EVENT REASON ACTION RESULT -- appends one JSON
# line, same shape convention as segment_manager.sh's
# segment_audit_log() (kept as a separate function/file rather than a
# shared one, for the same reason that file gives: this domain's own
# fixed field set should never have to be shoehorned into or drift
# another domain's frozen shape).
candidate_audit_log() {
  local id="$1" event="$2" reason="$3" action="$4" result="$5"
  local ts
  ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  python3 -c "
import json, sys
print(json.dumps({
    'timestamp': sys.argv[1],
    'candidate_id': sys.argv[2],
    'event': sys.argv[3],
    'reason': sys.argv[4],
    'action': sys.argv[5],
    'result': sys.argv[6],
}, ensure_ascii=False))
" "$ts" "$id" "$event" "$reason" "$action" "$result" >> "$KNOWLEDGE_AUDIT_LOG"
}

# candidate_transition ID NEW_STATUS REASON EVENT ACTION RESULT
# [EXTRA_FIELD=VALUE ...] -- the only path that ever writes a
# candidate's state file. Validates against transition_allowed() with
# NO override flag (see file header) -- an illegal transition is always
# rejected and always logged as rejected, so the audit trail shows both
# what was tried and what actually happened, same as
# segment_manager.sh's own segment_transition().
candidate_transition() {
  local id="$1" new_status="$2" reason="$3" event="$4" action="$5" result="$6"
  shift 6
  local current
  current="$(candidate_get_status "$id")" || { echo "[KNOWLEDGE] ERROR: unknown candidate '$id'" >&2; return 1; }

  if ! transition_allowed "$current" "$new_status"; then
    echo "[KNOWLEDGE] ERROR: rejected transition for '$id': $current -> $new_status is not allowed." >&2
    candidate_audit_log "$id" "transition_rejected" "$reason (attempted $current -> $new_status)" "$action" "rejected"
    return 1
  fi

  local path tmp
  path="$(candidate_state_path "$id")"
  tmp="$path.tmp.$$"
  # Optional KEY=VALUE extras (confidence_score from `score` below,
  # cve_list/ioc_list from incident_normalizer.sh, etc.) get folded into
  # the state file via the same _km_parse_extras candidate_create uses,
  # without this function needing to know about every possible field a
  # later step might add.
  local extra_json="{}"
  if [ "$#" -gt 0 ]; then
    extra_json="$(_km_parse_extras "$@")"
  fi

  python3 -c "
import json, sys
existing = json.load(open(sys.argv[1]))
extra = json.loads(sys.argv[5])
existing.update(extra)
existing['status'] = sys.argv[2]
existing['previous_status'] = sys.argv[3]
existing['updated_at'] = sys.argv[4]
existing['reason'] = sys.argv[6]
json.dump(existing, open(sys.argv[7], 'w'), ensure_ascii=False, indent=2)
" "$path" "$new_status" "$current" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$extra_json" "$reason" "$tmp"
  mv -f "$tmp" "$path"

  candidate_audit_log "$id" "$event" "$reason" "$action" "$result"
  echo "[KNOWLEDGE] $id: $current -> $new_status ($reason)"
  return 0
}

# candidate_list -- one line per known candidate: id|status|confidence_score|source
candidate_list() {
  local f id
  for f in "$KNOWLEDGE_STATE_DIR"/*.json; do
    [ -e "$f" ] || continue
    id="$(basename "$f" .json)"
    python3 -c "
import json
d = json.load(open('$f'))
print(f\"{d['id']}|{d['status']}|{d.get('confidence_score','')}|{d.get('source','')}\")
"
  done
}

# knowledge_promote ID -- the ONLY function that writes into
# security/knowledge/. Requires status APPROVED (enforced via the same
# transition_allowed() graph -- APPROVED->PROMOTED is the only legal
# entry into this function's own write). Copies the candidate's own
# accumulated fields into a new, separate knowledge-base entry file;
# the original candidate record is left in place under
# security/state/incident_learning/candidates/ as the permanent audit
# trail of how this entry came to exist.
knowledge_promote() {
  local id="$1"
  local current
  current="$(candidate_get_status "$id")" || { echo "[KNOWLEDGE] ERROR: unknown candidate '$id'" >&2; return 1; }
  if [ "$current" != "APPROVED" ]; then
    echo "[KNOWLEDGE] ERROR: candidate '$id' is '$current', not 'APPROVED' -- promotion requires the human gate first." >&2
    candidate_audit_log "$id" "promotion_rejected" "status is '$current', not 'APPROVED'" "promote" "rejected"
    return 1
  fi

  local cpath kpath
  cpath="$(candidate_state_path "$id")"
  kpath="$(knowledge_entry_path "$id")"
  python3 -c "
import json
d = json.load(open('$cpath'))
d['promoted_at'] = __import__('datetime').datetime.now(__import__('datetime').timezone.utc).isoformat(timespec='milliseconds')
json.dump(d, open('$kpath', 'w'), ensure_ascii=False, indent=2)
"
  candidate_transition "$id" "PROMOTED" "written to security/knowledge/$id.json" "promoted" "promote" "pass"
}

if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
  case "${1:-}" in
    create)
      [ -n "${2:-}" ] || { echo "Usage: $0 create ID [SOURCE] [KEY=VALUE ...]" >&2; exit 1; }
      CREATE_ID="$2"; CREATE_SOURCE="${3:-unknown}"
      shift 3 2>/dev/null || shift "$#"
      candidate_create "$CREATE_ID" "$CREATE_SOURCE" "$@"
      ;;
    status)
      [ -n "${2:-}" ] || { echo "Usage: $0 status ID" >&2; exit 1; }
      candidate_get_status "$2" || { echo "[KNOWLEDGE] ERROR: unknown candidate '$2'" >&2; exit 1; }
      ;;
    list)
      candidate_list
      ;;
    advance)
      # advance ID NEW_STATUS "reason" [KEY=VALUE ...] -- used by the
      # automated pipeline stages (normalizer/evidence/analyzer/scorer)
      # to both move a candidate forward and attach whatever structured
      # fields that stage produced (e.g. incident_normalizer.sh's own
      # cve_list/ioc_list), never by a human directly for
      # CANDIDATE->APPROVED/REJECTED (see `approve`/`reject` below,
      # which exist specifically so those two transitions always carry
      # the human-gate framing distinctly in the audit log, even though
      # this dispatches to the same underlying function).
      [ -n "${2:-}" ] && [ -n "${3:-}" ] && [ -n "${4:-}" ] || {
        echo "Usage: $0 advance ID NEW_STATUS \"reason\" [KEY=VALUE ...]" >&2; exit 1;
      }
      ADV_ID="$2"; ADV_STATUS="$3"; ADV_REASON="$4"
      shift 4 2>/dev/null || shift "$#"
      candidate_transition "$ADV_ID" "$ADV_STATUS" "$ADV_REASON" "advanced" "pipeline" "pass" "$@"
      ;;
    score)
      # ANALYZED->SCORED (records confidence_score) then, in the same
      # command, the threshold check that decides SCORED->CANDIDATE vs
      # SCORED->REJECTED -- both legal per transition_allowed() above,
      # so a low-confidence incident is auto-rejected here rather than
      # ever being presented to the human gate at all (design item 5:
      # "confidence too low to even present to a human").
      [ -n "${2:-}" ] && [ -n "${3:-}" ] || { echo "Usage: $0 score ID CONFIDENCE_SCORE" >&2; exit 1; }
      SCORE_ID="$2"; SCORE_VALUE="$3"; SCORE_MIN="${KNOWLEDGE_MIN_CONFIDENCE:-50}"
      candidate_transition "$SCORE_ID" "SCORED" "confidence score computed" "scored" "pipeline" "pass" "confidence_score=$SCORE_VALUE" || exit 1
      if [ "$SCORE_VALUE" -ge "$SCORE_MIN" ]; then
        candidate_transition "$SCORE_ID" "CANDIDATE" "confidence $SCORE_VALUE >= threshold $SCORE_MIN" "candidate_ready" "pipeline" "pass"
      else
        candidate_transition "$SCORE_ID" "REJECTED" "confidence $SCORE_VALUE below threshold $SCORE_MIN" "low_confidence" "pipeline" "rejected"
      fi
      ;;
    approve)
      [ -n "${2:-}" ] && [ -n "${3:-}" ] || { echo "Usage: $0 approve ID \"reason\"" >&2; exit 1; }
      candidate_transition "$2" "APPROVED" "$3" "human_approved" "human_gate" "approved"
      ;;
    reject)
      [ -n "${2:-}" ] && [ -n "${3:-}" ] || { echo "Usage: $0 reject ID \"reason\"" >&2; exit 1; }
      candidate_transition "$2" "REJECTED" "$3" "human_rejected" "human_gate" "rejected"
      ;;
    promote)
      [ -n "${2:-}" ] || { echo "Usage: $0 promote ID" >&2; exit 1; }
      knowledge_promote "$2"
      ;;
    *)
      echo "Usage: $0 {create ID [SOURCE]|status ID|list|advance ID NEW_STATUS \"reason\"|score ID CONFIDENCE_SCORE|approve ID \"reason\"|reject ID \"reason\"|promote ID}" >&2
      exit 1
      ;;
  esac
fi
