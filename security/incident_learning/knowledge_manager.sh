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
#   CANDIDATE -> HOLD         (human gate only -- see `hold` below: reviewer
#                              wants more time/evidence, not a decision yet)
#   HOLD -> APPROVED          (human gate only -- see `approve` below)
#   HOLD -> REJECTED          (human gate only -- see `reject` below)
#   HOLD -> CANDIDATE         (human gate only -- see `release` below: back
#                              onto the queue, still requires an explicit
#                              approve/reject/hold later, never auto-decided)
#   APPROVED -> PROMOTED      (written into security/knowledge/)
#   APPROVED -> REJECTED      (promotion itself failed -- e.g. write conflict)
# Every other (FROM, TO) pair is rejected, with no --force escape hatch
# at all (unlike segment_manager.sh's failed->isolated override) --
# there is no legitimate reason to ever skip the human gate here.
#
# Step 4 (Human Gate / Approval flow, security/incident_learning/
# incident_human_gate.sh) adds no new state-machine edge beyond HOLD
# above and no new write path into security/knowledge/ -- `approve`,
# `reject`, `hold`, and `release` below remain the only way any of
# CANDIDATE/HOLD/APPROVED/REJECTED is ever reached, all human-gate CLI
# commands, all requiring a non-empty reason, all logged. Reaching
# CANDIDATE is never sufficient on its own to reach PROMOTED: that
# still requires an explicit `approve` (human_gate) followed by an
# explicit `promote` (a second, separate human action) -- nothing in
# this file auto-chains CANDIDATE -> APPROVED -> PROMOTED.

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

# _km_reserved_field_violation [KEY=VALUE ...] -- Step 7 hardening,
# extended by the final-audit fix below. Prints the first reserved
# field name found among the given KEY=VALUE extras and returns 0
# (violation found); returns 1 (clean) if none. Reserved fields are
# this file's own control fields -- status, previous_status, id,
# created_at, updated_at, confidence_score, reason, and the four
# evidence_* fields -- every one of them is meant to be set ONLY by
# candidate_create/candidate_transition/knowledge_promote/
# record_evidence's own explicit code, NEVER by a caller-supplied
# extra. Without this check, a bare `create ID SOURCE status=APPROVED`
# or `advance ID NORMALIZED "reason" confidence_score=999` could
# silently forge a candidate's own control state.
#
# Final-audit fix: the original Step 7 list protected confidence_score
# itself but NOT the four evidence_* fields confidence_score is
# computed FROM (evidence_source_type/evidence_corroborating_count/
# evidence_age_days/evidence_self_reported_uncorroborated) -- so
# `advance ID VERIFIED "reason" evidence_corroborating_count=99` could
# forge Evidence's own output, completely bypassing
# incident_evidence.sh's real computation, and from there
# incident_confidence.sh would compute a fully "legitimate" high
# confidence_score from forged inputs -- confidence_score's own
# reservation was never actually load-bearing against this route. The
# fix mirrors `score`'s existing separation from `advance`: these four
# fields are now reserved here (blocking them from `create`/`advance`
# entirely) and are settable only via the new `record-evidence` CLI
# command below, which owns NORMALIZED->VERIFIED exactly as `score`
# owns ANALYZED->SCORED->CANDIDATE/REJECTED.
#
# Used by `create` (all reserved fields) and `advance` (same list --
# `score`'s own internal candidate_transition call sets
# confidence_score directly in code, and `record_evidence`'s own
# internal candidate_transition call likewise sets the evidence_*
# fields directly in code, neither ever through this caller-facing
# check, so legitimate scoring/evidence-recording is unaffected).
_km_reserved_field_violation() {
  local kv key
  for kv in "$@"; do
    key="${kv%%=*}"
    case "$key" in
      status|previous_status|id|created_at|updated_at|confidence_score|reason| \
      evidence_source_type|evidence_corroborating_count|evidence_age_days|evidence_self_reported_uncorroborated)
        echo "$key"
        return 0
        ;;
    esac
  done
  return 1
}

# candidate_create ID [SOURCE] [KEY=VALUE ...] -- creates a brand-new
# candidate at status COLLECTED. Refuses if the id already exists (no
# silent overwrite -- same "never clobber existing state" posture as
# every other writer in this file). Optional trailing KEY=VALUE pairs
# (e.g. source_type=vendor_advisory, source_url=..., raw_text=...) are
# folded straight into the initial record via the same _km_parse_extras
# mechanism candidate_transition uses -- a Collector's own output
# fields land on the candidate without this function needing to know
# their names in advance. Reserved fields (status, previous_status,
# id, created_at, updated_at, confidence_score, reason) are refused
# outright -- see _km_reserved_field_violation's own header for why: a
# candidate must always start life at COLLECTED, never fabricated
# directly at APPROVED/PROMOTED/any other status via a KEY=VALUE extra.
candidate_create() {
  local id="$1" source="${2:-unknown}"
  shift 2 2>/dev/null || shift "$#"
  if candidate_exists "$id"; then
    echo "[KNOWLEDGE] ERROR: candidate '$id' already exists" >&2
    return 1
  fi
  local violation
  if violation="$(_km_reserved_field_violation "$@")"; then
    echo "[KNOWLEDGE] ERROR: refusing to create '$id': '$violation' is a reserved field and cannot be set via create's KEY=VALUE extras (candidate_create always assigns it itself; every new candidate starts at COLLECTED)." >&2
    candidate_audit_log "$id" "creation_rejected" "attempted to set reserved field '$violation' via create extras" "create" "rejected"
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
    CANDIDATE:HOLD) return 0 ;;
    HOLD:APPROVED) return 0 ;;
    HOLD:REJECTED) return 0 ;;
    HOLD:CANDIDATE) return 0 ;;
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
# security/knowledge/ (Step 5: Promote flow). Requires status APPROVED
# (enforced via the same transition_allowed() graph -- APPROVED->PROMOTED
# is the only legal entry into this function's own write; REJECTED, HOLD,
# and CANDIDATE-after-a-HOLD-release are all just "not APPROVED" here,
# refused the same way). Copies the candidate's own accumulated fields
# (source/source_type/source_url/raw_text/cve_list/ioc_list/
# evidence_*/confidence_score, plus the exact approval reason and
# timestamp that were on the record at the moment of copy -- see
# approval_reason/approved_at below) into a new, separate knowledge-base
# entry file. The original candidate record is left in place under
# security/state/incident_learning/candidates/ as the permanent,
# independent audit trail of how this entry came to exist; the audit
# log additionally has every intermediate transition (collect -> ...
# -> human_approved -> promoted), so traceability from a promoted
# knowledge entry back to its original incident, its evidence, its
# confidence score, and its human approval never depends on this one
# file alone.
#
# Idempotency / no-partial-write guarantees:
#   - an already-PROMOTED candidate is a no-op success (not an error --
#     re-running a promote step, e.g. from a future cron wrapper, must
#     never be treated as a failure just because it already happened)
#   - the knowledge entry is built into a temp file and only made
#     visible via `mv -f` (atomic rename), matching every other writer
#     in this codebase (segment_manager.sh, candidate_transition above)
#     -- a crash or error mid-build leaves no partial file at the real
#     path, ever
#   - Step 8 crash-recovery: if a file already sits at the real path
#     while the candidate is still APPROVED (not yet PROMOTED), that is
#     exactly the state a crash/kill between the `mv -f` above and the
#     candidate_transition below would leave -- and, since Step 7's
#     hardening closed every other way to write into $kpath, it is now
#     the ONLY way this situation can arise. Rather than requiring
#     manual intervention, promote reconciles automatically: it
#     verifies the existing file was actually produced FROM this exact
#     candidate's current approval (source_candidate_id/approved_at/
#     status match) before completing the transition -- never
#     rewriting the file, only catching the candidate's own state up to
#     match what is already safely on disk. A file that does NOT match
#     (wrong id, foreign content, a stale/tampered write) is still
#     refused outright, exactly as before.
knowledge_promote() {
  local id="$1"
  local current
  current="$(candidate_get_status "$id")" || { echo "[KNOWLEDGE] ERROR: unknown candidate '$id'" >&2; return 1; }

  if [ "$current" = "PROMOTED" ]; then
    echo "[KNOWLEDGE] $id: already PROMOTED (no-op, not re-written)"
    candidate_audit_log "$id" "promotion_skipped" "already PROMOTED, promote is idempotent" "promote" "skipped"
    return 0
  fi

  if [ "$current" != "APPROVED" ]; then
    echo "[KNOWLEDGE] ERROR: candidate '$id' is '$current', not 'APPROVED' -- promotion requires the human gate first." >&2
    candidate_audit_log "$id" "promotion_rejected" "status is '$current', not 'APPROVED'" "promote" "rejected"
    return 1
  fi

  local cpath kpath tmp
  cpath="$(candidate_state_path "$id")"
  kpath="$(knowledge_entry_path "$id")"

  if [ -e "$kpath" ]; then
    local reconcile_ok
    reconcile_ok="$(python3 -c "
import json, sys
try:
    k = json.load(open(sys.argv[1]))
    c = json.load(open(sys.argv[2]))
except Exception:
    print('false'); sys.exit(0)
ok = (
    k.get('source_candidate_id') == sys.argv[3]
    and k.get('status') == 'APPROVED'
    and k.get('approved_at') == c.get('updated_at')
)
print('true' if ok else 'false')
" "$kpath" "$cpath" "$id")"

    if [ "$reconcile_ok" = "true" ]; then
      echo "[KNOWLEDGE] $id: knowledge entry already exists and matches the current approval (crash-recovery) -- completing the interrupted PROMOTED transition, not rewriting the file."
      candidate_audit_log "$id" "promotion_reconciled" "knowledge entry already existed at $kpath and matches the current approval -- completed the interrupted transition without rewriting" "promote" "reconciled"
      candidate_transition "$id" "PROMOTED" "reconciled: knowledge entry already existed from an interrupted promote" "promoted" "promote" "pass"
      return $?
    fi

    echo "[KNOWLEDGE] ERROR: a knowledge entry already exists at '$kpath' but does not match '$id''s current approval -- refusing to overwrite; investigate manually." >&2
    candidate_audit_log "$id" "promotion_rejected" "knowledge entry already exists at $kpath and does not match the current approval" "promote" "rejected"
    return 1
  fi

  tmp="$kpath.tmp.$$"
  if ! python3 -c "
import json, datetime
d = json.load(open('$cpath'))
d['source_candidate_id'] = d.get('id')
d['approval_reason'] = d.get('reason')
d['approved_at'] = d.get('updated_at')
d['promoted_at'] = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='milliseconds')
json.dump(d, open('$tmp', 'w'), ensure_ascii=False, indent=2)
"; then
    rm -f "$tmp"
    echo "[KNOWLEDGE] ERROR: failed to build knowledge entry for '$id' -- nothing written." >&2
    candidate_audit_log "$id" "promotion_rejected" "failed to build knowledge entry (build error)" "promote" "rejected"
    return 1
  fi

  if ! mv -f "$tmp" "$kpath"; then
    rm -f "$tmp"
    echo "[KNOWLEDGE] ERROR: failed to finalize knowledge entry for '$id' -- nothing written." >&2
    candidate_audit_log "$id" "promotion_rejected" "failed to finalize knowledge entry (rename error)" "promote" "rejected"
    return 1
  fi

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
      #
      # Step 7 hardening (this scope restriction is enforced in CODE,
      # not just in the comment above -- see the audit that found
      # `advance ID APPROVED ...` / `advance ID PROMOTED ...` could
      # reach the human gate's own states, or PROMOTED without ever
      # running knowledge_promote()'s actual write):
      #   - NEW_STATUS must be one of NORMALIZED/ANALYZED/REJECTED --
      #     APPROVED/HOLD/PROMOTED, and CANDIDATE (reached only via
      #     `score`'s own internal call), are never legal advance
      #     targets, regardless of what transition_allowed() itself
      #     would otherwise permit.
      #   - VERIFIED is likewise never a legal advance target (final-
      #     audit fix -- see _km_reserved_field_violation's own header):
      #     NORMALIZED->VERIFIED must carry the evidence_* fields, and
      #     those are reserved, so `advance` could only ever reach
      #     VERIFIED with them silently absent (null) -- a corrupted
      #     "verified but with no evidence recorded" state that's worse
      #     than not allowing the transition at all. Use `record-evidence`
      #     below instead.
      #   - REJECTED specifically is refused if the candidate is
      #     currently CANDIDATE or HOLD: rejecting a candidate that has
      #     already reached the human gate is `reject`'s job, not an
      #     automated pipeline stage's.
      #   - KEY=VALUE extras may never set a reserved field (see
      #     _km_reserved_field_violation) -- most importantly
      #     confidence_score and the four evidence_* fields, which are
      #     `score`'s and `record-evidence`'s own job alone,
      #     respectively.
      [ -n "${2:-}" ] && [ -n "${3:-}" ] && [ -n "${4:-}" ] || {
        echo "Usage: $0 advance ID NEW_STATUS \"reason\" [KEY=VALUE ...]" >&2; exit 1;
      }
      ADV_ID="$2"; ADV_STATUS="$3"; ADV_REASON="$4"
      shift 4 2>/dev/null || shift "$#"
      case "$ADV_STATUS" in
        NORMALIZED|ANALYZED) ;;
        REJECTED)
          ADV_CURRENT="$(candidate_get_status "$ADV_ID" 2>/dev/null || true)"
          case "$ADV_CURRENT" in
            CANDIDATE|HOLD)
              echo "[KNOWLEDGE] ERROR: 'advance' cannot reject '$ADV_ID' from '$ADV_CURRENT' -- rejecting a candidate that has already reached the human gate requires the 'reject' command." >&2
              candidate_audit_log "$ADV_ID" "advance_scope_violation" "attempted advance-reject from human-gate status '$ADV_CURRENT'" "advance" "rejected"
              exit 1
              ;;
          esac
          ;;
        *)
          echo "[KNOWLEDGE] ERROR: 'advance' does not permit target status '$ADV_STATUS' -- pipeline-only targets are NORMALIZED/ANALYZED/REJECTED (VERIFIED requires 'record-evidence'); APPROVED/HOLD/PROMOTED/CANDIDATE require approve/reject/hold/release/promote (the human gate)." >&2
          candidate_audit_log "$ADV_ID" "advance_scope_violation" "attempted advance to out-of-scope target '$ADV_STATUS'" "advance" "rejected"
          exit 1
          ;;
      esac
      if ADV_VIOLATION="$(_km_reserved_field_violation "$@")"; then
        echo "[KNOWLEDGE] ERROR: refusing advance for '$ADV_ID': '$ADV_VIOLATION' is a reserved field and cannot be set via advance's KEY=VALUE extras." >&2
        candidate_audit_log "$ADV_ID" "advance_scope_violation" "attempted to set reserved field '$ADV_VIOLATION' via advance extras" "advance" "rejected"
        exit 1
      fi
      candidate_transition "$ADV_ID" "$ADV_STATUS" "$ADV_REASON" "advanced" "pipeline" "pass" "$@"
      ;;
    record-evidence)
      # record-evidence ID "reason" [evidence_source_type=... evidence_corroborating_count=...
      #   evidence_age_days=... evidence_self_reported_uncorroborated=...]
      # -- the ONLY path that ever writes the evidence_* fields
      # (NORMALIZED -> VERIFIED), mirroring `score`'s own separation of
      # confidence_score from `advance`'s generic extras. Added by the
      # final-audit fix (see _km_reserved_field_violation's own header
      # for the forgery this closes): incident_evidence.sh calls this
      # instead of `advance ... VERIFIED ...`. Only the four evidence_*
      # keys are accepted as extras here -- anything else (including an
      # attempt to sneak a reserved field in under this command instead)
      # is refused and audited, the same defense-in-depth posture as
      # every other writer in this file.
      [ -n "${2:-}" ] && [ -n "${3:-}" ] || {
        echo "Usage: $0 record-evidence ID \"reason\" [evidence_source_type=... evidence_corroborating_count=... evidence_age_days=... evidence_self_reported_uncorroborated=...]" >&2; exit 1;
      }
      RE_ID="$2"; RE_REASON="$3"
      shift 3 2>/dev/null || shift "$#"
      for RE_KV in "$@"; do
        RE_KEY="${RE_KV%%=*}"
        case "$RE_KEY" in
          evidence_source_type|evidence_corroborating_count|evidence_age_days|evidence_self_reported_uncorroborated) ;;
          *)
            echo "[KNOWLEDGE] ERROR: refusing record-evidence for '$RE_ID': '$RE_KEY' is not a recognized evidence field -- only evidence_source_type/evidence_corroborating_count/evidence_age_days/evidence_self_reported_uncorroborated are accepted here." >&2
            candidate_audit_log "$RE_ID" "evidence_scope_violation" "attempted to set non-evidence field '$RE_KEY' via record-evidence extras" "record-evidence" "rejected"
            exit 1
            ;;
        esac
      done
      candidate_transition "$RE_ID" "VERIFIED" "$RE_REASON" "advanced" "pipeline" "pass" "$@"
      ;;
    score)
      # ANALYZED->SCORED (records confidence_score) then, in the same
      # command, the threshold check that decides SCORED->CANDIDATE vs
      # SCORED->REJECTED -- both legal per transition_allowed() above,
      # so a low-confidence incident is auto-rejected here rather than
      # ever being presented to the human gate at all (design item 5:
      # "confidence too low to even present to a human").
      #
      # Step 8 crash-recovery: these are two separate writes. A crash
      # between them used to strand a candidate at SCORED forever --
      # incident_confidence.sh only ever re-submits ANALYZED candidates,
      # so nothing would ever revisit it. `score` is now resumable: if
      # called while the candidate is already SCORED (not ANALYZED),
      # it skips re-recording confidence_score (the caller-supplied
      # value is ignored in favor of the one already persisted --
      # trusting a second, possibly different, caller-supplied number
      # for a decision that's already half-committed would itself be a
      # new integrity gap) and completes only the threshold decision.
      [ -n "${2:-}" ] && [ -n "${3:-}" ] || { echo "Usage: $0 score ID CONFIDENCE_SCORE" >&2; exit 1; }
      SCORE_ID="$2"; SCORE_VALUE="$3"; SCORE_MIN="${KNOWLEDGE_MIN_CONFIDENCE:-50}"
      SCORE_CURRENT="$(candidate_get_status "$SCORE_ID" 2>/dev/null)" || { echo "[KNOWLEDGE] ERROR: unknown candidate '$SCORE_ID'" >&2; exit 1; }
      case "$SCORE_CURRENT" in
        ANALYZED)
          candidate_transition "$SCORE_ID" "SCORED" "confidence score computed" "scored" "pipeline" "pass" "confidence_score=$SCORE_VALUE" || exit 1
          ;;
        SCORED)
          SCORE_VALUE="$(candidate_get_field "$SCORE_ID" confidence_score)"
          echo "[KNOWLEDGE] $SCORE_ID: resuming from SCORED (confidence_score=$SCORE_VALUE already recorded) -- completing the interrupted threshold decision"
          candidate_audit_log "$SCORE_ID" "score_resumed" "resuming an interrupted score: confidence_score=$SCORE_VALUE already recorded" "score" "resumed"
          ;;
        *)
          echo "[KNOWLEDGE] ERROR: candidate '$SCORE_ID' is '$SCORE_CURRENT', not 'ANALYZED' (or 'SCORED' to resume an interrupted score)." >&2
          candidate_audit_log "$SCORE_ID" "score_rejected" "status is '$SCORE_CURRENT', not 'ANALYZED'/'SCORED'" "score" "rejected"
          exit 1
          ;;
      esac
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
    hold)
      # CANDIDATE -> HOLD: reviewer wants more time/evidence before
      # deciding -- deliberately NOT a decision (see `approve`/`reject`
      # above), just as loud an audit event as either of them, so a
      # human gate that never says yes or no still leaves a visible
      # trail rather than the candidate silently sitting untouched.
      [ -n "${2:-}" ] && [ -n "${3:-}" ] || { echo "Usage: $0 hold ID \"reason\"" >&2; exit 1; }
      candidate_transition "$2" "HOLD" "$3" "human_held" "human_gate" "held"
      ;;
    release)
      # HOLD -> CANDIDATE: back onto the queue. Still requires a later
      # explicit approve/reject/hold -- this never auto-decides.
      [ -n "${2:-}" ] && [ -n "${3:-}" ] || { echo "Usage: $0 release ID \"reason\"" >&2; exit 1; }
      candidate_transition "$2" "CANDIDATE" "$3" "human_hold_released" "human_gate" "released"
      ;;
    promote)
      [ -n "${2:-}" ] || { echo "Usage: $0 promote ID" >&2; exit 1; }
      knowledge_promote "$2"
      ;;
    *)
      echo "Usage: $0 {create ID [SOURCE]|status ID|list|advance ID NEW_STATUS \"reason\"|record-evidence ID \"reason\"|score ID CONFIDENCE_SCORE|approve ID \"reason\"|reject ID \"reason\"|hold ID \"reason\"|release ID \"reason\"|promote ID}" >&2
      exit 1
      ;;
  esac
fi
