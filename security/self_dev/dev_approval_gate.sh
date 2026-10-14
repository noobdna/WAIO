#!/bin/bash
set -uo pipefail

# security/self_dev/dev_approval_gate.sh -- WAIO Self-Development
# Engine Human Approval Gate: the audit-log-backed CLI wrapper around
# security/self_dev/dev_approval_lib.py's pure library. Implements
# exactly five verbs: propose | approve | reject | status | list.
# NEVER executes, invokes, or queues a merge, deploy, shutdown,
# containment action, or any other privileged operation -- every
# result below answers "may a human record this approval decision" or
# "what is already known about this proposal", nothing here is capable
# of acting on either answer.
#
# ============================================================
# SCOPE, STATED NARROWLY -- read before touching this file
# ============================================================
# This file's own architectural sibling is
# security/red_alert/containment_approval_gate.sh -- same lock
# algorithm, same hash-chained audit log, same hardened APPROVAL_ID
# validation (reused verbatim, not re-derived, specifically to avoid
# reintroducing the path-traversal class of bug that file's own
# commit 7983f08 found and fixed). This file is independent of that
# one: it never sources it, never calls it, and is never called by it
# -- two separate approval domains (containment recommendations vs.
# self-development operations), same loose-coupling discipline as
# every other sibling pair in this repository.
#
# WHY THIS FILE DOES NOT `source security/lib.sh`: identical reasoning
# to containment_approval_gate.sh's own header -- security/lib.sh
# sources security/guardian.sh at its own top level, and pulling that
# in here would violate this phase's explicit "do not connect
# Guardian" requirement merely by existing in this process. This file
# carries its own standalone copy of the same proven mkdir-lock and
# hash-chained-audit-log algorithms.
#
# NO PRIVILEGED OPERATION IS EVER EXECUTED, QUEUED, OR INVOKED BY THIS
# FILE -- not `git merge`, not `git push`, not `gh pr merge`, not a
# deploy script, not any WAIO containment/Guardian/DuCoPA tool. An
# APPROVED record is a human reading this gate's own `status` output
# and THEN, separately, by hand, performing the privileged action.
# tests/dev_approval_gate_test.sh's own D-series exists specifically
# to keep this true in code, not just in this comment.
#
# SELF-APPROVAL IS STRUCTURALLY IMPOSSIBLE: `propose` and `approve`
# are entirely separate verbs below with no call from one into the
# other -- a proposal-generation step (an AI agent calling `propose`)
# has no code path by which it could also call `approve` on the same
# invocation or any other. See dev_approval_lib.py's own header,
# Section 3, for the full reasoning, including the honest limits of
# the identity-denylist check this relies on.
#
# APPROVER IDENTITY IS NOT AUTHENTICATION (restated here, load-bearing):
# every `--identity`/approver string below is passed straight through
# to dev_approval_lib.validate_approver_identity(), which checks
# PRESENCE and NON-MEMBERSHIP in a small denylist of obviously-non-human
# strings only. Every approval/rejection record this file writes
# carries `decided_by` as a plain recorded claim, never a proven
# identity.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$SCRIPT_DIR"

STATE_DIR="${DEV_APPROVAL_STATE_DIR:-$SCRIPT_DIR/security/state/self_dev}"
PROPOSALS_DIR="$STATE_DIR/proposals"
LOCKS_DIR="$STATE_DIR/.locks"
AUDIT_LOG="${DEV_APPROVAL_AUDIT_LOG:-$SCRIPT_DIR/logs/self-dev-approval-audit.jsonl}"
AUDIT_CHECKPOINT="${DEV_APPROVAL_AUDIT_CHECKPOINT:-$STATE_DIR/.audit_checkpoint}"
AUDIT_LOCK_DIR="$STATE_DIR/.audit_lock"
TTL_SECONDS="${DEV_APPROVAL_TTL_SECONDS:-86400}"
PYLIB="security/self_dev/dev_approval_lib.py"

# Safe persistence, checked explicitly, same convention as
# containment_approval_gate.sh: refuse cleanly rather than silently
# writing nowhere or crashing with a raw traceback.
if ! mkdir -p "$PROPOSALS_DIR" "$LOCKS_DIR" "$(dirname "$AUDIT_LOG")" 2>/dev/null; then
  echo "[SELF-DEV APPROVAL] ERROR: cannot create required state directories under '$STATE_DIR' / '$(dirname "$AUDIT_LOG")' -- refusing to proceed without safe persistence." >&2
  exit 1
fi

# ------------------------------------------------------------------
# Standalone mkdir-based lock -- algorithm reused verbatim from
# security/red_alert/containment_approval_gate.sh's own
# _cag_lock_acquire/_cag_lock_release (itself reused from
# security/incident_learning/lock.sh). See this file's own header for
# why this is a reimplementation, not a `source` of either.
# ------------------------------------------------------------------

_sda_lock_acquire() {
  local lock_dir="$1" max_wait="$2" waited=0
  while ! mkdir "$lock_dir" 2>/dev/null; do
    if [ -d "$lock_dir" ]; then
      local lock_mtime now age
      lock_mtime="$(stat -f %m "$lock_dir" 2>/dev/null)"
      case "$lock_mtime" in
        ''|*[!0-9]*) lock_mtime="$(stat -c %Y "$lock_dir" 2>/dev/null)" ;;
      esac
      case "$lock_mtime" in
        ''|*[!0-9]*) lock_mtime=0 ;;
      esac
      now="$(date +%s)" || now=0
      age=$((now - lock_mtime))
      if [ "$age" -gt 5 ]; then
        local holder_pid=""
        holder_pid="$(cat "$lock_dir/holder.pid" 2>/dev/null)" || holder_pid=""
        case "$holder_pid" in
          ''|*[!0-9]*) holder_pid="" ;;
        esac
        if [ -z "$holder_pid" ] || ! kill -0 "$holder_pid" 2>/dev/null; then
          rm -rf "$lock_dir" 2>/dev/null || true
          continue
        fi
      fi
    fi
    waited=$((waited + 1))
    [ "$waited" -gt "$max_wait" ] && return 1
    sleep 0.1
  done
  printf '%s' "$$" > "$lock_dir/holder.pid" 2>/dev/null || true
  return 0
}

_sda_lock_release() {
  rm -rf "$1" 2>/dev/null || true
}

_sda_sanitize_id() {
  python3 -c "
import sys
text = sys.argv[1]
print(''.join(ch if (ch.isalnum() or ch in '-_.') else '_' for ch in text))
" "$1"
}

# ------------------------------------------------------------------
# APPROVAL_ID format gate -- identical convention to
# containment_approval_gate.sh's own _cag_validate_approval_id, reused
# from the start here rather than re-discovered after an audit.
# ------------------------------------------------------------------

_sda_validate_approval_id() {
  python3 -c "
import sys, os
sys.path.insert(0, os.path.join(os.getcwd(), 'security', 'self_dev'))
import dev_approval_lib as dal
sys.exit(0 if dal.validate_approval_id_format(sys.argv[1]) else 1)
" "$1"
}

_sda_invalid_approval_id_json() {
  python3 -c "
import json, sys
print(json.dumps({
    'ok': False,
    'error': 'invalid_approval_id',
    'approval_id': sys.argv[1],
    'detail': 'approval_id must be a non-empty string of at most 200 characters composed only of letters, digits, \'-\', \'_\', \'.\' (no path separators) -- see dev_approval_lib.validate_approval_id_format',
}, ensure_ascii=False))
" "$1"
}

_sda_now() {
  if [ -n "${WAIO_SELF_DEV_APPROVAL_NOW:-}" ]; then
    printf '%s' "$WAIO_SELF_DEV_APPROVAL_NOW"
  else
    date -u +%Y-%m-%dT%H:%M:%SZ
  fi
}

# ------------------------------------------------------------------
# Standalone hash-chained audit log -- identical algorithm to
# containment_approval_gate.sh's own _cag_audit_log. Fail-OPEN on lock
# contention (logging must never block the gate itself), but every
# write failure is still reported to stderr, never silently swallowed.
# ------------------------------------------------------------------

_sda_sha256() {
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 | awk '{print $1}'
  else
    sha256sum | awk '{print $1}'
  fi
}

_sda_audit_log() {
  local event_type="$1" approval_id="$2" actor="$3" detail_json="$4"
  local ts; ts="$(_sda_now)"
  local lock_held=1
  _sda_lock_acquire "$AUDIT_LOCK_DIR" 50 && lock_held=0

  local checkpoint_content="" checkpoint_count=0 prev_hash="genesis"
  if [ -f "$AUDIT_CHECKPOINT" ]; then
    checkpoint_content="$(cat "$AUDIT_CHECKPOINT" 2>/dev/null)" || checkpoint_content=""
  fi
  checkpoint_count="${checkpoint_content%%:*}"
  case "$checkpoint_count" in
    ''|*[!0-9]*) checkpoint_count=0 ;;
    *) prev_hash="${checkpoint_content#*:}" ;;
  esac

  local line
  line="$(python3 -c "
import json, sys
detail_raw = sys.argv[5]
try:
    detail = json.loads(detail_raw) if detail_raw else None
except Exception:
    detail = {'unparsed_detail': detail_raw}
print(json.dumps({
    'timestamp': sys.argv[1],
    'event_type': sys.argv[2],
    'approval_id': sys.argv[3],
    'actor': sys.argv[4],
    'detail': detail,
    'prev_hash': sys.argv[6],
}, ensure_ascii=False))
" "$ts" "$event_type" "$approval_id" "$actor" "$detail_json" "$prev_hash")" || line=""

  if [ -n "$line" ] && printf '%s\n' "$line" >> "$AUDIT_LOG" 2>/dev/null; then
    local new_hash new_count=$((checkpoint_count + 1))
    new_hash="$(printf '%s' "$line" | _sda_sha256)" || new_hash=""
    [ -n "$new_hash" ] && printf '%s:%s' "$new_count" "$new_hash" > "$AUDIT_CHECKPOINT" 2>/dev/null
  else
    echo "[SELF-DEV APPROVAL] WARNING: failed to write audit log entry (event_type=$event_type approval_id=$approval_id) -- the audit trail is incomplete" >&2
  fi

  [ "$lock_held" -eq 0 ] && _sda_lock_release "$AUDIT_LOCK_DIR"
}

# ==================================================================
# propose OPERATION TARGET_BRANCH HEAD_REF PROPOSED_BY
#         [--path PATH]... [--diff-file FILE]
# ==================================================================
# Classifies the proposed operation (dev_approval_lib.classify_operation),
# computes a change-set hash binding this EXACT operation/branch/path-
# list/diff together, and writes a record: PENDING (needs a human
# approve/reject) if PRIVILEGED, AUTO_CLEARED (no approval needed, but
# still logged) if AUTOMATIC. Never executes the operation itself --
# this verb only ever writes a JSON record describing it.
sda_propose() {
  if [ $# -lt 4 ]; then
    echo "Usage: $0 propose OPERATION TARGET_BRANCH HEAD_REF PROPOSED_BY [--path PATH]... [--diff-file FILE]" >&2
    return 1
  fi
  local operation="$1" target_branch="$2" head_ref="$3" proposed_by="$4"
  shift 4
  local -a paths=()
  local diff_file=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --path) paths+=("$2"); shift 2 ;;
      --diff-file) diff_file="$2"; shift 2 ;;
      *) echo "Usage: $0 propose OPERATION TARGET_BRANCH HEAD_REF PROPOSED_BY [--path PATH]... [--diff-file FILE]" >&2; return 1 ;;
    esac
  done

  local diff_hash="sha256:empty"
  if [ -n "$diff_file" ]; then
    if [ ! -f "$diff_file" ]; then
      python3 -c "import json; print(json.dumps({'ok': False, 'error': 'diff_file_not_found', 'detail': '$diff_file'}))"
      return 2
    fi
    diff_hash="sha256:$(_sda_sha256 < "$diff_file")"
  fi

  local lock_key lock_dir
  lock_key="$(_sda_sanitize_id "${operation}-${head_ref}")"
  lock_dir="$LOCKS_DIR/propose-${lock_key}.lock"
  if ! _sda_lock_acquire "$lock_dir" 50; then
    echo "[SELF-DEV APPROVAL] ERROR: could not acquire propose lock for '$operation/$head_ref' (contended) -- try again" >&2
    return 1
  fi

  local paths_json="[]"
  if [ "${#paths[@]}" -gt 0 ]; then
    paths_json="$(printf '%s\n' "${paths[@]}" | python3 -c "import json,sys; print(json.dumps([l.rstrip(chr(10)) for l in sys.stdin if l.rstrip(chr(10))]))")"
  fi

  local out rc
  out="$(python3 - "$operation" "$target_branch" "$head_ref" "$proposed_by" "$paths_json" "$diff_hash" "$PROPOSALS_DIR" "$(_sda_now)" "$TTL_SECONDS" <<'PYEOF'
import datetime, json, os, sys
sys.path.insert(0, os.path.join(os.getcwd(), "security", "self_dev"))
import dev_approval_lib as dal

(operation, target_branch, head_ref, proposed_by, paths_json, diff_hash,
 proposals_dir, now_text, ttl_text) = sys.argv[1:10]

try:
    touched_paths = json.loads(paths_json)
    if not isinstance(touched_paths, list):
        touched_paths = []
except Exception:
    touched_paths = []
touched_paths = sorted(touched_paths)

classification = dal.classify_operation(operation, target_branch=target_branch, touched_paths=touched_paths)
risk_tier = classification["risk_tier"]

change_set = {
    "operation": operation,
    "target_branch": target_branch,
    "head_ref": head_ref,
    "touched_paths": touched_paths,
    "diff_hash": diff_hash,
    "risk_tier": risk_tier,
}
change_hash = dal.compute_change_hash(change_set)

safe_ref = "".join(ch if (ch.isalnum() or ch in "-_.") else "_" for ch in head_ref)
safe_op = "".join(ch if (ch.isalnum() or ch in "-_.") else "_" for ch in operation)
approval_id = f"SDA-{safe_op}-{safe_ref}-{change_hash.split(':', 1)[1][:12]}"
proposal_path = os.path.join(proposals_dir, f"{approval_id}.json")

now_dt = dal.parse_utc_timestamp(now_text)

if os.path.exists(proposal_path):
    try:
        with open(proposal_path) as f:
            existing = json.load(f)
    except Exception as e:
        print(json.dumps({"ok": False, "error": "existing_record_corrupt", "detail": str(e), "approval_id": approval_id}))
        sys.exit(4)
    print(json.dumps({"ok": True, "duplicate": True, "approval_id": approval_id, "status": existing.get("status"), "record": existing}, ensure_ascii=False))
    sys.exit(0)

try:
    ttl_seconds = int(ttl_text)
except ValueError:
    ttl_seconds = dal.DEFAULT_APPROVAL_TTL_SECONDS
requires_approval = dal.requires_human_approval(risk_tier)
expires_dt = dal.compute_expiry(now_dt, ttl_seconds=ttl_seconds) if requires_approval else None

record = {
    "approval_id": approval_id,
    "status": "PENDING" if requires_approval else "AUTO_CLEARED",
    "operation": operation,
    "target_branch": target_branch,
    "head_ref": head_ref,
    "touched_paths": touched_paths,
    "diff_hash": diff_hash,
    "risk_tier": risk_tier,
    "classification_reasons": classification["reasons"],
    "requires_human_approval": requires_approval,
    "change_hash": change_hash,
    "proposed_at": now_text,
    "proposed_by": proposed_by,
    "expires_at": dal.format_utc_timestamp(expires_dt) if expires_dt else None,
    "decision": {"outcome": None, "decided_at": None, "decided_by": None, "reason": None},
}

tmp_path = f"{proposal_path}.tmp.{os.getpid()}"
try:
    with open(tmp_path, "w") as f:
        json.dump(record, f, ensure_ascii=False, indent=2, sort_keys=True)
    os.replace(tmp_path, proposal_path)
except Exception as e:
    try:
        os.remove(tmp_path)
    except OSError:
        pass
    print(json.dumps({"ok": False, "error": "persistence_failed", "detail": str(e)}))
    sys.exit(1)

print(json.dumps({"ok": True, "duplicate": False, "approval_id": approval_id, "status": record["status"], "record": record}, ensure_ascii=False))
PYEOF
)"
  rc=$?
  echo "$out"
  _sda_lock_release "$lock_dir"

  local aid status
  aid="$(_sda_extract_json_field "$out" "approval_id")"
  status="$(_sda_extract_json_field "$out" "status")"
  _sda_audit_log "proposed" "$aid" "$proposed_by" "$(python3 -c "import json,sys; print(json.dumps({'operation': sys.argv[1], 'status': sys.argv[2]}))" "$operation" "$status")"
  return "$rc"
}

_sda_extract_json_field() {
  python3 -c "
import json, sys
try:
    d = json.loads(sys.argv[1])
except Exception:
    print('')
    sys.exit(0)
v = d.get(sys.argv[2])
print('' if v is None else v)
" "$1" "$2" 2>/dev/null
}

# ==================================================================
# approve APPROVAL_ID APPROVER_IDENTITY REASON
# ==================================================================
sda_approve() {
  if [ $# -lt 3 ]; then
    echo "Usage: $0 approve APPROVAL_ID APPROVER_IDENTITY REASON" >&2
    return 1
  fi
  local approval_id="$1" approver_identity="$2" reason="$3"

  if ! _sda_validate_approval_id "$approval_id"; then
    local out; out="$(_sda_invalid_approval_id_json "$approval_id")"
    echo "$out"
    _sda_audit_log "approval_refused:invalid_approval_id" "$approval_id" "$approver_identity" "$out"
    return 10
  fi

  local lock_dir="$LOCKS_DIR/${approval_id}.lock"
  if ! _sda_lock_acquire "$lock_dir" 50; then
    echo "[SELF-DEV APPROVAL] ERROR: could not acquire lock for '$approval_id' (contended) -- try again" >&2
    return 1
  fi

  local out rc
  out="$(python3 - "$approval_id" "$approver_identity" "$reason" "$PROPOSALS_DIR" "$(_sda_now)" <<'PYEOF'
import json, os, sys
sys.path.insert(0, os.path.join(os.getcwd(), "security", "self_dev"))
import dev_approval_lib as dal

approval_id, approver_identity, reason, proposals_dir, now_text = sys.argv[1:6]

proposal_path = os.path.join(proposals_dir, f"{approval_id}.json")
# Defense-in-depth (same convention as containment_approval_gate.sh):
# the bash-layer _sda_validate_approval_id above already rejected any
# approval_id containing "/" before this python block ran, so
# proposal_path can only ever be a direct child of proposals_dir by
# construction. This second, independent check additionally resolves
# any symlink that might exist AT proposal_path itself and confirms
# the fully-resolved path still lands directly inside proposals_dir.
real_proposals_dir = os.path.realpath(proposals_dir)
real_proposal_path = os.path.realpath(proposal_path)
if os.path.dirname(real_proposal_path) != real_proposals_dir:
    print(json.dumps({"ok": False, "error": "invalid_approval_id", "detail": "resolved path escapes proposals_dir", "approval_id": approval_id}, ensure_ascii=False))
    sys.exit(10)
if not os.path.isfile(proposal_path):
    print(json.dumps({"ok": False, "error": "proposal_not_found", "approval_id": approval_id}))
    sys.exit(2)
try:
    with open(proposal_path) as f:
        record = json.load(f)
except Exception as e:
    print(json.dumps({"ok": False, "error": "record_corrupt", "detail": str(e), "approval_id": approval_id}))
    sys.exit(4)

now_dt = dal.parse_utc_timestamp(now_text)
expires_dt = dal.parse_utc_timestamp(record.get("expires_at")) if record.get("expires_at") else None
stored_status = record.get("status")
effective_status = stored_status
if stored_status == "PENDING" and expires_dt is not None and dal.is_expired(expires_dt, now_dt):
    effective_status = "EXPIRED"
    record["status"] = "EXPIRED"
    tmp_path = f"{proposal_path}.tmp.{os.getpid()}"
    try:
        with open(tmp_path, "w") as f:
            json.dump(record, f, ensure_ascii=False, indent=2, sort_keys=True)
        os.replace(tmp_path, proposal_path)
    except Exception:
        pass

if not dal.can_transition(effective_status, "approve"):
    print(json.dumps({"ok": False, "error": "illegal_transition", "current_status": effective_status, "approval_id": approval_id}))
    sys.exit(6)

change_set = {
    "operation": record.get("operation"),
    "target_branch": record.get("target_branch"),
    "head_ref": record.get("head_ref"),
    "touched_paths": record.get("touched_paths"),
    "diff_hash": record.get("diff_hash"),
    "risk_tier": record.get("risk_tier"),
}

evaluation = dal.evaluate_approval(
    change_set,
    record.get("change_hash"),
    approver_identity,
    now_dt,
    expires_dt,
    approval_reason=reason,
)

if not evaluation["allowed"]:
    print(json.dumps({"ok": False, "error": "gate_refused", "violations": evaluation["violations"], "approval_id": approval_id}, ensure_ascii=False))
    sys.exit(7)

record["status"] = "APPROVED"
record["decision"] = {
    "outcome": "APPROVED",
    "decided_at": now_text,
    "decided_by": approver_identity,
    "reason": evaluation["checks"]["reason"]["normalized"],
}

tmp_path = f"{proposal_path}.tmp.{os.getpid()}"
try:
    with open(tmp_path, "w") as f:
        json.dump(record, f, ensure_ascii=False, indent=2, sort_keys=True)
    os.replace(tmp_path, proposal_path)
except Exception as e:
    try:
        os.remove(tmp_path)
    except OSError:
        pass
    print(json.dumps({"ok": False, "error": "persistence_failed", "detail": str(e), "approval_id": approval_id}))
    sys.exit(1)

print(json.dumps({"ok": True, "approval_id": approval_id, "status": "APPROVED", "record": record}, ensure_ascii=False))
PYEOF
)"
  rc=$?
  echo "$out"
  _sda_lock_release "$lock_dir"
  _sda_audit_log "approval_decided:$([ "$rc" -eq 0 ] && echo approved || echo refused)" "$approval_id" "$approver_identity" "$out"
  return "$rc"
}

# ==================================================================
# reject APPROVAL_ID APPROVER_IDENTITY REASON
# ==================================================================
sda_reject() {
  if [ $# -lt 3 ]; then
    echo "Usage: $0 reject APPROVAL_ID APPROVER_IDENTITY REASON" >&2
    return 1
  fi
  local approval_id="$1" approver_identity="$2" reason="$3"

  if ! _sda_validate_approval_id "$approval_id"; then
    local out; out="$(_sda_invalid_approval_id_json "$approval_id")"
    echo "$out"
    _sda_audit_log "rejection_refused:invalid_approval_id" "$approval_id" "$approver_identity" "$out"
    return 10
  fi

  local lock_dir="$LOCKS_DIR/${approval_id}.lock"
  if ! _sda_lock_acquire "$lock_dir" 50; then
    echo "[SELF-DEV APPROVAL] ERROR: could not acquire lock for '$approval_id' (contended) -- try again" >&2
    return 1
  fi

  local out rc
  out="$(python3 - "$approval_id" "$approver_identity" "$reason" "$PROPOSALS_DIR" "$(_sda_now)" <<'PYEOF'
import json, os, sys
sys.path.insert(0, os.path.join(os.getcwd(), "security", "self_dev"))
import dev_approval_lib as dal

approval_id, approver_identity, reason, proposals_dir, now_text = sys.argv[1:6]

proposal_path = os.path.join(proposals_dir, f"{approval_id}.json")
real_proposals_dir = os.path.realpath(proposals_dir)
real_proposal_path = os.path.realpath(proposal_path)
if os.path.dirname(real_proposal_path) != real_proposals_dir:
    print(json.dumps({"ok": False, "error": "invalid_approval_id", "detail": "resolved path escapes proposals_dir", "approval_id": approval_id}, ensure_ascii=False))
    sys.exit(10)
if not os.path.isfile(proposal_path):
    print(json.dumps({"ok": False, "error": "proposal_not_found", "approval_id": approval_id}))
    sys.exit(2)
try:
    with open(proposal_path) as f:
        record = json.load(f)
except Exception as e:
    print(json.dumps({"ok": False, "error": "record_corrupt", "detail": str(e), "approval_id": approval_id}))
    sys.exit(4)

if not dal.can_transition(record.get("status"), "reject"):
    print(json.dumps({"ok": False, "error": "illegal_transition", "current_status": record.get("status"), "approval_id": approval_id}))
    sys.exit(6)

identity_check = dal.validate_approver_identity(approver_identity)
reason_check = dal.validate_reason(reason)
violations = []
if not identity_check["valid"]:
    violations.append(identity_check["reason"])
if reason_check["status"] != "OK":
    violations.append(f"reason_{reason_check['status'].lower()}")
if violations:
    print(json.dumps({"ok": False, "error": "gate_refused", "violations": violations, "approval_id": approval_id}, ensure_ascii=False))
    sys.exit(7)

record["status"] = "REJECTED"
record["decision"] = {
    "outcome": "REJECTED",
    "decided_at": now_text,
    "decided_by": approver_identity,
    "reason": reason_check["normalized"],
}

tmp_path = f"{proposal_path}.tmp.{os.getpid()}"
try:
    with open(tmp_path, "w") as f:
        json.dump(record, f, ensure_ascii=False, indent=2, sort_keys=True)
    os.replace(tmp_path, proposal_path)
except Exception as e:
    try:
        os.remove(tmp_path)
    except OSError:
        pass
    print(json.dumps({"ok": False, "error": "persistence_failed", "detail": str(e), "approval_id": approval_id}))
    sys.exit(1)

print(json.dumps({"ok": True, "approval_id": approval_id, "status": "REJECTED", "record": record}, ensure_ascii=False))
PYEOF
)"
  rc=$?
  echo "$out"
  _sda_lock_release "$lock_dir"
  _sda_audit_log "rejection_decided:$([ "$rc" -eq 0 ] && echo rejected || echo refused)" "$approval_id" "$approver_identity" "$out"
  return "$rc"
}

# ==================================================================
# status APPROVAL_ID -- read-only, EXPIRED-on-access side effect only
# ==================================================================
sda_status() {
  if [ $# -lt 1 ]; then
    echo "Usage: $0 status APPROVAL_ID" >&2
    return 1
  fi
  local approval_id="$1"

  if ! _sda_validate_approval_id "$approval_id"; then
    _sda_invalid_approval_id_json "$approval_id"
    return 10
  fi

  python3 -c "
import json, os, sys
sys.path.insert(0, os.path.join(os.getcwd(), 'security', 'self_dev'))
import dev_approval_lib as dal

approval_id, proposals_dir, now_text = sys.argv[1], sys.argv[2], sys.argv[3]
proposal_path = os.path.join(proposals_dir, f'{approval_id}.json')
real_proposals_dir = os.path.realpath(proposals_dir)
real_proposal_path = os.path.realpath(proposal_path)
if os.path.dirname(real_proposal_path) != real_proposals_dir:
    print(json.dumps({'ok': False, 'error': 'invalid_approval_id', 'detail': 'resolved path escapes proposals_dir', 'approval_id': approval_id}, ensure_ascii=False))
    sys.exit(10)
if not os.path.isfile(proposal_path):
    print(json.dumps({'ok': False, 'error': 'proposal_not_found', 'approval_id': approval_id}))
    sys.exit(2)
try:
    with open(proposal_path) as f:
        record = json.load(f)
except Exception as e:
    print(json.dumps({'ok': False, 'error': 'record_corrupt', 'detail': str(e), 'approval_id': approval_id}))
    sys.exit(4)

now_dt = dal.parse_utc_timestamp(now_text)
expires_dt = dal.parse_utc_timestamp(record.get('expires_at')) if record.get('expires_at') else None
effective_status = record.get('status')
if effective_status == 'PENDING' and expires_dt is not None and dal.is_expired(expires_dt, now_dt):
    effective_status = 'EXPIRED'
    record['status'] = 'EXPIRED'
    tmp_path = f'{proposal_path}.tmp.{os.getpid()}'
    try:
        with open(tmp_path, 'w') as f:
            json.dump(record, f, ensure_ascii=False, indent=2, sort_keys=True)
        os.replace(tmp_path, proposal_path)
    except Exception:
        pass

print(json.dumps({'ok': True, 'approval_id': approval_id, 'effective_status': effective_status, 'record': record}, ensure_ascii=False))
" "$approval_id" "$PROPOSALS_DIR" "$(_sda_now)"
}

# ==================================================================
# list [--status STATUS]
# ==================================================================
sda_list() {
  local status_filter=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --status) status_filter="$2"; shift 2 ;;
      *) echo "Usage: $0 list [--status STATUS]" >&2; return 1 ;;
    esac
  done

  python3 -c "
import json, os, sys
proposals_dir, status_filter = sys.argv[1], sys.argv[2]
entries = []
corrupt = []
if os.path.isdir(proposals_dir):
    for name in sorted(os.listdir(proposals_dir)):
        if not name.endswith('.json') or name.endswith('.tmp'):
            continue
        path = os.path.join(proposals_dir, name)
        try:
            with open(path) as f:
                record = json.load(f)
        except Exception as e:
            corrupt.append({'path': path, 'detail': str(e)})
            continue
        if status_filter and record.get('status') != status_filter:
            continue
        entries.append({
            'approval_id': record.get('approval_id'),
            'operation': record.get('operation'),
            'target_branch': record.get('target_branch'),
            'risk_tier': record.get('risk_tier'),
            'status': record.get('status'),
            'proposed_by': record.get('proposed_by'),
            'proposed_at': record.get('proposed_at'),
        })
print(json.dumps({'ok': True, 'entries': entries, 'corrupt': corrupt}, ensure_ascii=False))
" "$PROPOSALS_DIR" "$status_filter"
}

if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
  case "${1:-}" in
    propose) shift; sda_propose "$@" ;;
    approve) shift; sda_approve "$@" ;;
    reject)  shift; sda_reject "$@" ;;
    status)  shift; sda_status "$@" ;;
    list)    shift; sda_list "$@" ;;
    *)
      echo "Usage: $0 {propose|approve|reject|status|list} ..." >&2
      exit 1
      ;;
  esac
fi
