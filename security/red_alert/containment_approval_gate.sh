#!/bin/bash
set -uo pipefail

# security/red_alert/containment_approval_gate.sh -- WAIO GLOBAL
# RED ALERT Phase E: the audit-log-backed CLI wrapper around Phase D's
# pure library (security/red_alert/containment_approval_lib.py).
# Deliberately placed alongside that library, not under
# security/decision_engine/, so this entire approval-gate effort stays
# self-contained under security/red_alert/ -- this file never modifies,
# sources, or is sourced by decision_engine.sh/decision_engine_lib.py;
# it only ever reads a Decision Engine report FILE a human already
# produced, same as every other file in this domain.
# Implements exactly five verbs: request | approve | reject | status |
# list. NEVER executes, invokes, or queues a containment action --
# every result below answers "may a human record this decision",
# nothing here is capable of acting on it.
#
# ============================================================
# SCOPE, STATED NARROWLY -- read before touching this file
# ============================================================
# Scoped to WAIO GLOBAL RED ALERT Decision Records ONLY (reuses
# containment_approval_lib.is_red_alert_scoped() -- the same three
# source_module values security/red_alert/red_alert_adapter.py
# actually emits). A Decision Record sourced purely from Shadow AI /
# Attack Graph / SaaS ATO / plain Incident Learning is refused at
# `request` time (error "out_of_scope") -- this file never touches
# any other Decision Engine recommendation.
#
# WHY THIS FILE DOES NOT `source security/lib.sh` (explicit, load-
# bearing, same reasoning security/incident_learning/lock.sh's own
# header already states for itself): security/lib.sh's own audit_log()
# would be the obvious thing to reuse here, but security/lib.sh itself
# does `source "$SECURITY_LIB_DIR/guardian.sh"` at its own top level --
# sourcing it here would pull in the entire Guardian Control Plane as
# an unavoidable side effect, directly violating this phase's explicit
# "do not connect Guardian" requirement, merely by existing in this
# file's own process, never mind calling anything. This file instead
# carries its OWN standalone copy of the exact same proven mkdir-based
# lock algorithm (security/lib.sh's own _waio_mkdir_lock_acquire/
# _waio_mkdir_lock_release, Phase 65/67/70 hardening: PID-liveness-
# gated stale-lock steal, never age alone) and its OWN standalone
# hash-chained audit log (security/lib.sh's own audit_log() algorithm:
# a JSONL line per event, each carrying the SHA-256 of the immediately
# preceding line, with the running checkpoint in a separate small
# file) -- reused verbatim as algorithms, reimplemented here under
# different function names specifically so no future reader could
# mistake this file's own lock/audit primitives for the real
# Main-Control-Plane ones. Nothing in this file calls
# security/guardian.sh, security/ducopa.sh,
# security/guardian_intervene_wrapper.sh,
# security/guardian_intervene_quarantine_wrapper.sh,
# security/guardian_release_agent.sh, security/guardian_approve.sh,
# security/recovery_engine.sh, security/recover.sh,
# security/incident_learning/knowledge_manager.sh's own
# approve/reject/hold/promote verbs, or decision_engine.sh/
# decision_engine_lib.py -- it only ever READS a Decision Engine
# report FILE a human already produced by hand (same one-way,
# file-based, one-stage-consumes-only-the-file-handed-to-it discipline
# every prior stage in this pipeline already uses), it never calls
# decision_engine.sh itself.
#
# APPROVER IDENTITY IS NOT AUTHENTICATION (restated here, load-bearing,
# never diluted): every `--identity`/approver string below is passed
# straight through to containment_approval_lib.validate_approver_identity(),
# which checks PRESENCE only (optionally membership in an explicitly-
# supplied allowlist -- not wired up by any caller in this file this
# phase). Every approval/rejection record this file writes carries
# `decided_by` as a plain recorded claim, never a proven identity.
#
# NO CONTAINMENT ACTION IS EVER EXECUTED, QUEUED, OR INVOKED BY THIS
# FILE. `proposed_tool`/`rollback_tool` are free-text fields a human
# supplies and a human later reads -- this file never shells out on
# either value, by construction (see tests/containment_approval_gate_test.sh's
# own D-series for the structural proof).

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$SCRIPT_DIR"

STATE_DIR="${CONTAINMENT_APPROVAL_STATE_DIR:-$SCRIPT_DIR/security/state/containment_approval}"
APPROVALS_DIR="$STATE_DIR/approvals"
LOCKS_DIR="$STATE_DIR/.locks"
AUDIT_LOG="${CONTAINMENT_APPROVAL_AUDIT_LOG:-$SCRIPT_DIR/logs/containment-approval-audit.jsonl}"
AUDIT_CHECKPOINT="${CONTAINMENT_APPROVAL_AUDIT_CHECKPOINT:-$STATE_DIR/.audit_checkpoint}"
AUDIT_LOCK_DIR="$STATE_DIR/.audit_lock"
TTL_SECONDS="${CONTAINMENT_APPROVAL_TTL_SECONDS:-86400}"

# Safe persistence, checked explicitly (not the usual repo-wide
# "mkdir -p ... || true" best-effort pattern): if this deployment
# cannot create its own state directories, every verb below must
# refuse cleanly rather than silently writing nowhere or crashing with
# a raw traceback.
if ! mkdir -p "$APPROVALS_DIR" "$LOCKS_DIR" "$(dirname "$AUDIT_LOG")" 2>/dev/null; then
  echo "[CONTAINMENT APPROVAL] ERROR: cannot create required state directories under '$STATE_DIR' / '$(dirname "$AUDIT_LOG")' -- refusing to proceed without safe persistence." >&2
  exit 1
fi

# ------------------------------------------------------------------
# Standalone mkdir-based lock -- see module header for why this is a
# reimplementation, not a `source security/lib.sh` call. Algorithm
# reused verbatim from security/incident_learning/lock.sh's own
# il_lock_acquire/il_lock_release (itself a standalone copy of
# security/lib.sh's _waio_mkdir_lock_acquire/_waio_mkdir_lock_release).
# ------------------------------------------------------------------

_cag_lock_acquire() {
  local lock_dir="$1" max_wait="$2" waited=0
  while ! mkdir "$lock_dir" 2>/dev/null; do
    if [ -d "$lock_dir" ]; then
      local lock_mtime now age
      now="$(date +%s)" || now=0
      lock_mtime="$(stat -f %m "$lock_dir" 2>/dev/null)"
      case "$lock_mtime" in
        ''|*[!0-9]*) lock_mtime="$(stat -c %Y "$lock_dir" 2>/dev/null)" ;;
      esac
      # Unreadable mtime (typically: the directory vanished between the
      # -d test and stat, i.e. the previous holder just released) means
      # staleness cannot be established -- treat it as fresh. Falling
      # back to 0 made age "seconds since 1970", so a lock that a third
      # process had just re-acquired, before writing holder.pid, was
      # deleted and taken: two holders at once.
      # (tests/mkdir_lock_unreadable_mtime_test.sh)
      case "$lock_mtime" in
        ''|*[!0-9]*) lock_mtime="$now" ;;
      esac
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

_cag_lock_release() {
  rm -rf "$1" 2>/dev/null || true
}

_cag_sanitize_id() {
  python3 -c "
import sys
text = sys.argv[1]
print(''.join(ch if (ch.isalnum() or ch in '-_.') else '_' for ch in text))
" "$1"
}

# ------------------------------------------------------------------
# APPROVAL_ID format gate (SECURITY FIX, post-audit) -- every
# caller-supplied APPROVAL_ID (approve/reject/status) MUST pass this
# BEFORE it is used to build ANY filesystem path (lock_dir below, or
# approval_path inside each verb's own python block). Unlike `request`'s
# entity (already sanitized into safe_entity before any path is built --
# see cag_request below), approve/reject/status previously used their
# own APPROVAL_ID argument completely unvalidated: a caller-supplied id
# containing "/" could escape APPROVALS_DIR/LOCKS_DIR entirely (read via
# `status`, conditional overwrite via `approve`/`reject`, and -- via
# _cag_lock_acquire's own stale-lock reap below -- `rm -rf` of an
# arbitrary pre-existing directory outside LOCKS_DIR). See
# containment_approval_lib.validate_approval_id_format() for the exact
# rule (charset-only allowlist, "/" excluded, which alone makes
# traversal unrepresentable) and tests/containment_approval_gate_test.sh's
# own H-series for the regression coverage. Every approval_id this
# file's own cag_request ever generates already satisfies this check,
# so normal request -> approve/reject -> status flows are unaffected.
# ------------------------------------------------------------------

_cag_validate_approval_id() {
  python3 -c "
import sys, os
sys.path.insert(0, os.path.join(os.getcwd(), 'security', 'red_alert'))
import containment_approval_lib as cal
sys.exit(0 if cal.validate_approval_id_format(sys.argv[1]) else 1)
" "$1"
}

_cag_invalid_approval_id_json() {
  python3 -c "
import json, sys
print(json.dumps({
    'ok': False,
    'error': 'invalid_approval_id',
    'approval_id': sys.argv[1],
    'detail': 'approval_id must be a non-empty string of at most 200 characters composed only of letters, digits, \'-\', \'_\', \'.\' (no path separators) -- see containment_approval_lib.validate_approval_id_format',
}, ensure_ascii=False))
" "$1"
}

# ------------------------------------------------------------------
# Clock -- always real UTC time, UNLESS the test-only override
# WAIO_CONTAINMENT_APPROVAL_NOW is set (same "override via env var for
# test isolation only, a real deployment never sets it" convention as
# every other file in this pipeline).
# ------------------------------------------------------------------

_cag_now() {
  if [ -n "${WAIO_CONTAINMENT_APPROVAL_NOW:-}" ]; then
    printf '%s' "$WAIO_CONTAINMENT_APPROVAL_NOW"
  else
    date -u +%Y-%m-%dT%H:%M:%SZ
  fi
}

# ------------------------------------------------------------------
# Standalone hash-chained audit log -- see module header. Fail-OPEN on
# lock contention (same posture security/lib.sh's own audit_log()
# documents for itself: "logging must never block a real dispatch"),
# but every write failure is still reported to stderr, never silently
# swallowed.
# ------------------------------------------------------------------

_cag_sha256() {
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 | awk '{print $1}'
  else
    sha256sum | awk '{print $1}'
  fi
}

_cag_audit_log() {
  local event_type="$1" approval_id="$2" actor="$3" detail_json="$4"
  local ts; ts="$(_cag_now)"
  local lock_held=1
  _cag_lock_acquire "$AUDIT_LOCK_DIR" 50 && lock_held=0

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
    new_hash="$(printf '%s' "$line" | _cag_sha256)" || new_hash=""
    [ -n "$new_hash" ] && printf '%s:%s' "$new_count" "$new_hash" > "$AUDIT_CHECKPOINT" 2>/dev/null
  else
    echo "[CONTAINMENT APPROVAL] WARNING: failed to write audit log entry (event_type=$event_type approval_id=$approval_id) -- the audit trail is incomplete" >&2
  fi

  [ "$lock_held" -eq 0 ] && _cag_lock_release "$AUDIT_LOCK_DIR"
}

# _cag_verify_audit_integrity -- walks the WHOLE audit log and
# recomputes its hash chain from genesis, same algorithm as
# security/lib.sh's own verify_audit_log_integrity(). Prints one of:
# "ok" | "ok:no_checkpoint" | "missing" | "broken:<lineno>" |
# "broken:checkpoint_mismatch(...)" . Not wired to any CLI verb this
# phase (outside the explicitly scoped five) -- sourced and called
# directly by tests/containment_approval_gate_test.sh's own
# audit-corruption cases, same convention
# tests/incident_learning_lock_test.sh already uses to call
# il_lock_acquire directly by sourcing lock.sh.
_cag_verify_audit_integrity() {
  if [ ! -f "$AUDIT_LOG" ]; then
    if [ -f "$AUDIT_CHECKPOINT" ]; then echo "missing"; else echo "ok"; fi
    return 0
  fi
  if [ ! -f "$AUDIT_CHECKPOINT" ]; then
    echo "ok:no_checkpoint"
    return 0
  fi
  local checkpoint_content checkpoint_count checkpoint_hash
  checkpoint_content="$(cat "$AUDIT_CHECKPOINT" 2>/dev/null)" || checkpoint_content=""
  checkpoint_count="${checkpoint_content%%:*}"
  checkpoint_hash="${checkpoint_content#*:}"
  case "$checkpoint_count" in
    ''|*[!0-9]*) echo "ok:no_checkpoint"; return 0 ;;
  esac
  python3 -c "
import hashlib, json, sys
log_path, expected_count, expected_hash = sys.argv[1], int(sys.argv[2]), sys.argv[3]
prev_hash = 'genesis'
count = 0
broken_at = None
with open(log_path) as f:
    for lineno, raw in enumerate(f, start=1):
        text = raw.rstrip('\n')
        if not text:
            continue
        try:
            obj = json.loads(text)
        except Exception:
            broken_at = lineno
            break
        if obj.get('prev_hash') != prev_hash:
            broken_at = lineno
            break
        count += 1
        prev_hash = hashlib.sha256(text.encode('utf-8')).hexdigest()
if broken_at is not None:
    print(f'broken:{broken_at}')
elif count != expected_count or prev_hash != expected_hash:
    print(f'broken:checkpoint_mismatch(count={count},expected={expected_count})')
else:
    print('ok')
" "$AUDIT_LOG" "$checkpoint_count" "$checkpoint_hash"
}

_cag_extract_json_field() {
  # _cag_extract_json_field JSON_TEXT FIELD_NAME -- prints the named
  # top-level field (as its own str()), or empty string if absent/the
  # input is not valid JSON. Used only to pull a couple of fields out
  # of a verb's own JSON result for the audit-log call below -- never
  # used for anything that affects an approval decision itself.
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
# request DECISION_REPORT_FILE ENTITY REQUESTED_BY [--target-type T]
#         [--target-id ID] [--proposed-tool TOOL] [--rollback-tool TOOL]
# ==================================================================
cag_request() {
  if [ $# -lt 3 ]; then
    echo "Usage: $0 request DECISION_REPORT_FILE ENTITY REQUESTED_BY [--target-type TYPE] [--target-id ID] [--proposed-tool TOOL] [--rollback-tool TOOL]" >&2
    return 1
  fi
  local report_file="$1" entity="$2" requested_by="$3"
  shift 3
  local target_type="none" target_id="" proposed_tool="" rollback_tool=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --target-type) target_type="$2"; shift 2 ;;
      --target-id) target_id="$2"; shift 2 ;;
      --proposed-tool) proposed_tool="$2"; shift 2 ;;
      --rollback-tool) rollback_tool="$2"; shift 2 ;;
      *) echo "Usage: $0 request DECISION_REPORT_FILE ENTITY REQUESTED_BY [--target-type TYPE] [--target-id ID] [--proposed-tool TOOL] [--rollback-tool TOOL]" >&2; return 1 ;;
    esac
  done

  local lock_key lock_dir
  lock_key="$(_cag_sanitize_id "$entity")"
  lock_dir="$LOCKS_DIR/request-${lock_key}.lock"
  if ! _cag_lock_acquire "$lock_dir" 50; then
    echo "[CONTAINMENT APPROVAL] ERROR: could not acquire request lock for entity '$entity' (contended) -- try again" >&2
    return 1
  fi

  local out rc
  out="$(python3 - "$report_file" "$entity" "$requested_by" "$target_type" "$target_id" "$proposed_tool" "$rollback_tool" "$APPROVALS_DIR" "$(_cag_now)" "$TTL_SECONDS" <<'PYEOF'
import json, os, sys
sys.path.insert(0, os.path.join(os.getcwd(), "security", "red_alert"))
import containment_approval_lib as cal

(report_file, entity, requested_by, target_type, target_id, proposed_tool,
 rollback_tool, approvals_dir, now_text, ttl_text) = sys.argv[1:11]

if not os.path.isfile(report_file):
    print(json.dumps({"ok": False, "error": "decision_report_not_found", "detail": report_file}))
    sys.exit(2)
try:
    with open(report_file) as f:
        report = json.load(f)
except Exception as e:
    print(json.dumps({"ok": False, "error": "decision_report_malformed", "detail": str(e)}))
    sys.exit(2)
if not isinstance(report, dict):
    print(json.dumps({"ok": False, "error": "decision_report_shape_invalid", "detail": "top-level JSON is not an object"}))
    sys.exit(2)

decisions = report.get("decisions")
if not isinstance(decisions, list):
    print(json.dumps({"ok": False, "error": "decision_report_shape_invalid", "detail": "missing/invalid decisions list"}))
    sys.exit(2)

decision_record = None
for d in decisions:
    if isinstance(d, dict) and d.get("entity") == entity:
        decision_record = d
        break
if decision_record is None:
    print(json.dumps({"ok": False, "error": "entity_not_found", "detail": entity}))
    sys.exit(2)

if not cal.is_red_alert_scoped(decision_record):
    print(json.dumps({"ok": False, "error": "out_of_scope", "detail": "this gate only handles WAIO GLOBAL RED ALERT source_modules", "entity": entity}))
    sys.exit(3)

identity_check = cal.validate_approver_identity(requested_by)
if not identity_check["valid"]:
    print(json.dumps({"ok": False, "error": "invalid_requested_by", "detail": identity_check["reason"]}))
    sys.exit(5)

report_hash = cal.compute_decision_report_hash(report)
safe_entity = "".join(ch if (ch.isalnum() or ch in "-_.") else "_" for ch in entity)
approval_id = f"CAG-{safe_entity}-{report_hash.split(':', 1)[1][:12]}"
approval_path = os.path.join(approvals_dir, f"{approval_id}.json")

now_dt = cal.parse_utc_timestamp(now_text)

if os.path.exists(approval_path):
    try:
        with open(approval_path) as f:
            existing = json.load(f)
    except Exception as e:
        print(json.dumps({"ok": False, "error": "existing_record_corrupt", "detail": str(e), "approval_id": approval_id}))
        sys.exit(4)
    expires_at = cal.parse_utc_timestamp(existing.get("expires_at"))
    effective = existing.get("status")
    if effective == "PENDING" and cal.is_expired(expires_at, now_dt):
        effective = "EXPIRED"
    print(json.dumps({"ok": True, "duplicate": True, "approval_id": approval_id, "effective_status": effective, "record": existing}, ensure_ascii=False))
    sys.exit(0)

try:
    ttl_seconds = int(ttl_text)
except ValueError:
    ttl_seconds = cal.DEFAULT_APPROVAL_TTL_SECONDS
expires_dt = cal.compute_expiry(now_dt, ttl_seconds=ttl_seconds)

record = {
    "approval_id": approval_id,
    "status": "PENDING",
    "decision_record_ref": {
        "entity": decision_record.get("entity"),
        "entity_type": decision_record.get("entity_type"),
        "risk": decision_record.get("risk"),
        "confidence": decision_record.get("confidence"),
        "source_modules": decision_record.get("source_modules"),
        "recommended_action": decision_record.get("recommended_action"),
        "decision_report_generated_at": report.get("generated_at"),
        "decision_report_path": os.path.abspath(report_file),
        "decision_report_hash": report_hash,
    },
    "evidence_summary": decision_record.get("reasoning", ""),
    "corroboration": {
        "multi_source": cal.has_multi_source_corroboration(decision_record),
        "trusted_local_corroboration": cal.has_trusted_local_corroboration(decision_record),
        "source_modules_count": len(decision_record.get("source_modules") or []),
        "exception_reason": None,
    },
    "proposed_scope": {
        "target_type": target_type or "none",
        "target_id": target_id or None,
        "proposed_tool": proposed_tool or None,
    },
    "requested_at": now_text,
    "requested_by": requested_by,
    "expires_at": cal.format_utc_timestamp(expires_dt),
    "decision": {"outcome": None, "decided_at": None, "decided_by": None, "reason": None},
    "rollback": {
        "required": cal.is_high_impact(decision_record),
        "rollback_tool": rollback_tool or None,
        "rollback_confirmed_at": None,
    },
}

tmp_path = f"{approval_path}.tmp.{os.getpid()}"
try:
    with open(tmp_path, "w") as f:
        json.dump(record, f, ensure_ascii=False, indent=2, sort_keys=True)
    os.replace(tmp_path, approval_path)
except Exception as e:
    try:
        os.remove(tmp_path)
    except OSError:
        pass
    print(json.dumps({"ok": False, "error": "persistence_failed", "detail": str(e)}))
    sys.exit(1)

print(json.dumps({"ok": True, "duplicate": False, "approval_id": approval_id, "effective_status": "PENDING", "record": record}, ensure_ascii=False))
PYEOF
)"
  rc=$?
  echo "$out"

  local approval_id_out event_type
  approval_id_out="$(_cag_extract_json_field "$out" approval_id)"
  if [ "$rc" -eq 0 ]; then
    local dup; dup="$(_cag_extract_json_field "$out" duplicate)"
    [ "$dup" = "True" ] && event_type="duplicate_request_detected" || event_type="approval_requested"
  else
    local err; err="$(_cag_extract_json_field "$out" error)"
    event_type="request_refused:${err:-unknown}"
  fi
  _cag_audit_log "$event_type" "${approval_id_out:-unknown}" "$requested_by" "$out"

  _cag_lock_release "$lock_dir"
  return "$rc"
}

# ==================================================================
# approve APPROVAL_ID APPROVER_IDENTITY REASON [EXCEPTION_REASON]
# ==================================================================
cag_approve() {
  if [ $# -lt 3 ]; then
    echo "Usage: $0 approve APPROVAL_ID APPROVER_IDENTITY REASON [EXCEPTION_REASON]" >&2
    return 1
  fi
  local approval_id="$1" approver_identity="$2" reason="$3" exception_reason="${4:-}"

  if ! _cag_validate_approval_id "$approval_id"; then
    local out; out="$(_cag_invalid_approval_id_json "$approval_id")"
    echo "$out"
    _cag_audit_log "approval_refused:invalid_approval_id" "$approval_id" "$approver_identity" "$out"
    return 10
  fi

  local lock_dir="$LOCKS_DIR/${approval_id}.lock"
  if ! _cag_lock_acquire "$lock_dir" 50; then
    echo "[CONTAINMENT APPROVAL] ERROR: could not acquire lock for '$approval_id' (contended) -- try again" >&2
    return 1
  fi

  local out rc
  out="$(python3 - "$approval_id" "$approver_identity" "$reason" "$exception_reason" "$APPROVALS_DIR" "$(_cag_now)" <<'PYEOF'
import json, os, sys
sys.path.insert(0, os.path.join(os.getcwd(), "security", "red_alert"))
import containment_approval_lib as cal

approval_id, approver_identity, reason, exception_reason, approvals_dir, now_text = sys.argv[1:7]
exception_reason = exception_reason if exception_reason else None

approval_path = os.path.join(approvals_dir, f"{approval_id}.json")
# Defense-in-depth (SECURITY FIX, post-audit): the bash-layer
# _cag_validate_approval_id above already rejected any approval_id
# containing "/" before this python block ever ran, so approval_path
# can only ever be a direct child of approvals_dir by construction.
# This second, independent check additionally resolves any symlink
# that might exist AT approval_path itself (e.g. one planted inside
# approvals_dir by some other means) and confirms the fully-resolved
# path still lands directly inside approvals_dir -- never trusts the
# unresolved path alone.
real_approvals_dir = os.path.realpath(approvals_dir)
real_approval_path = os.path.realpath(approval_path)
if os.path.dirname(real_approval_path) != real_approvals_dir:
    print(json.dumps({"ok": False, "error": "invalid_approval_id", "detail": "resolved path escapes approvals_dir", "approval_id": approval_id}, ensure_ascii=False))
    sys.exit(10)
if not os.path.isfile(approval_path):
    print(json.dumps({"ok": False, "error": "approval_not_found", "approval_id": approval_id}))
    sys.exit(2)
try:
    with open(approval_path) as f:
        record = json.load(f)
except Exception as e:
    print(json.dumps({"ok": False, "error": "record_corrupt", "detail": str(e), "approval_id": approval_id}))
    sys.exit(4)

now_dt = cal.parse_utc_timestamp(now_text)
expires_dt = cal.parse_utc_timestamp(record.get("expires_at"))
stored_status = record.get("status")
effective_status = stored_status
if stored_status == "PENDING" and cal.is_expired(expires_dt, now_dt):
    effective_status = "EXPIRED"
    record["status"] = "EXPIRED"
    tmp_path = f"{approval_path}.tmp.{os.getpid()}"
    try:
        with open(tmp_path, "w") as f:
            json.dump(record, f, ensure_ascii=False, indent=2, sort_keys=True)
        os.replace(tmp_path, approval_path)
    except Exception:
        pass

if not cal.can_transition(effective_status, "approve"):
    print(json.dumps({"ok": False, "error": "illegal_transition", "current_status": effective_status, "approval_id": approval_id}))
    sys.exit(6)

decision_record_ref = record.get("decision_record_ref") or {}
report_path = decision_record_ref.get("decision_report_path")
current_report = {}
if report_path and os.path.isfile(report_path):
    try:
        with open(report_path) as f:
            current_report = json.load(f)
    except Exception:
        current_report = {}

evaluation = cal.evaluate_approval(
    decision_record_ref,
    current_report,
    decision_record_ref.get("decision_report_hash"),
    approver_identity,
    now_dt,
    expires_dt,
    approval_reason=reason,
    exception_reason=exception_reason,
    rollback=record.get("rollback"),
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
if exception_reason:
    # Store the ORIGINAL readable text, not the validator own stripped
    # form (validate_exception_reason removes ALL internal whitespace
    # for its own check only -- persisting that stripped form here
    # would turn a readable sentence into an unreadable run of
    # characters in the audit trail).
    record["corroboration"]["exception_reason"] = exception_reason

tmp_path = f"{approval_path}.tmp.{os.getpid()}"
try:
    with open(tmp_path, "w") as f:
        json.dump(record, f, ensure_ascii=False, indent=2, sort_keys=True)
    os.replace(tmp_path, approval_path)
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

  local event_type
  if [ "$rc" -eq 0 ]; then
    event_type="approval_granted"
  else
    local err; err="$(_cag_extract_json_field "$out" error)"
    event_type="approval_refused:${err:-unknown}"
  fi
  _cag_audit_log "$event_type" "$approval_id" "$approver_identity" "$out"

  _cag_lock_release "$lock_dir"
  return "$rc"
}

# ==================================================================
# reject APPROVAL_ID APPROVER_IDENTITY REASON
# ==================================================================
cag_reject() {
  if [ $# -lt 3 ]; then
    echo "Usage: $0 reject APPROVAL_ID APPROVER_IDENTITY REASON" >&2
    return 1
  fi
  local approval_id="$1" approver_identity="$2" reason="$3"

  if ! _cag_validate_approval_id "$approval_id"; then
    local out; out="$(_cag_invalid_approval_id_json "$approval_id")"
    echo "$out"
    _cag_audit_log "rejection_refused:invalid_approval_id" "$approval_id" "$approver_identity" "$out"
    return 10
  fi

  local lock_dir="$LOCKS_DIR/${approval_id}.lock"
  if ! _cag_lock_acquire "$lock_dir" 50; then
    echo "[CONTAINMENT APPROVAL] ERROR: could not acquire lock for '$approval_id' (contended) -- try again" >&2
    return 1
  fi

  local out rc
  out="$(python3 - "$approval_id" "$approver_identity" "$reason" "$APPROVALS_DIR" "$(_cag_now)" <<'PYEOF'
import json, os, sys
sys.path.insert(0, os.path.join(os.getcwd(), "security", "red_alert"))
import containment_approval_lib as cal

approval_id, approver_identity, reason, approvals_dir, now_text = sys.argv[1:6]
approval_path = os.path.join(approvals_dir, f"{approval_id}.json")
# Defense-in-depth (SECURITY FIX, post-audit) -- see the cag_approve
# python block above for the full rationale; same independent
# symlink-aware containment check, repeated here for reject.
real_approvals_dir = os.path.realpath(approvals_dir)
real_approval_path = os.path.realpath(approval_path)
if os.path.dirname(real_approval_path) != real_approvals_dir:
    print(json.dumps({"ok": False, "error": "invalid_approval_id", "detail": "resolved path escapes approvals_dir", "approval_id": approval_id}, ensure_ascii=False))
    sys.exit(10)
if not os.path.isfile(approval_path):
    print(json.dumps({"ok": False, "error": "approval_not_found", "approval_id": approval_id}))
    sys.exit(2)
try:
    with open(approval_path) as f:
        record = json.load(f)
except Exception as e:
    print(json.dumps({"ok": False, "error": "record_corrupt", "detail": str(e), "approval_id": approval_id}))
    sys.exit(4)

now_dt = cal.parse_utc_timestamp(now_text)
expires_dt = cal.parse_utc_timestamp(record.get("expires_at"))
stored_status = record.get("status")
effective_status = stored_status
if stored_status == "PENDING" and cal.is_expired(expires_dt, now_dt):
    effective_status = "EXPIRED"
    record["status"] = "EXPIRED"
    tmp_path = f"{approval_path}.tmp.{os.getpid()}"
    try:
        with open(tmp_path, "w") as f:
            json.dump(record, f, ensure_ascii=False, indent=2, sort_keys=True)
        os.replace(tmp_path, approval_path)
    except Exception:
        pass

if not cal.can_transition(effective_status, "reject"):
    print(json.dumps({"ok": False, "error": "illegal_transition", "current_status": effective_status, "approval_id": approval_id}))
    sys.exit(6)

identity_check = cal.validate_approver_identity(approver_identity)
if not identity_check["valid"]:
    print(json.dumps({"ok": False, "error": "invalid_identity", "detail": identity_check["reason"], "approval_id": approval_id}))
    sys.exit(5)

reason_check = cal.validate_reason(reason)
if reason_check["status"] != "OK":
    print(json.dumps({"ok": False, "error": "invalid_reason", "detail": reason_check, "approval_id": approval_id}))
    sys.exit(8)

record["status"] = "REJECTED"
record["decision"] = {"outcome": "REJECTED", "decided_at": now_text, "decided_by": approver_identity, "reason": reason_check["normalized"]}

tmp_path = f"{approval_path}.tmp.{os.getpid()}"
try:
    with open(tmp_path, "w") as f:
        json.dump(record, f, ensure_ascii=False, indent=2, sort_keys=True)
    os.replace(tmp_path, approval_path)
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

  local event_type
  if [ "$rc" -eq 0 ]; then
    event_type="approval_rejected"
  else
    local err; err="$(_cag_extract_json_field "$out" error)"
    event_type="rejection_refused:${err:-unknown}"
  fi
  _cag_audit_log "$event_type" "$approval_id" "$approver_identity" "$out"

  _cag_lock_release "$lock_dir"
  return "$rc"
}

# ==================================================================
# status APPROVAL_ID -- read-only, never mutates, never locks.
# ==================================================================
cag_status() {
  if [ $# -lt 1 ]; then
    echo "Usage: $0 status APPROVAL_ID" >&2
    return 1
  fi
  local approval_id="$1"

  if ! _cag_validate_approval_id "$approval_id"; then
    _cag_invalid_approval_id_json "$approval_id"
    return 10
  fi

  python3 - "$approval_id" "$APPROVALS_DIR" "$(_cag_now)" <<'PYEOF'
import json, os, sys
sys.path.insert(0, os.path.join(os.getcwd(), "security", "red_alert"))
import containment_approval_lib as cal

approval_id, approvals_dir, now_text = sys.argv[1:4]
approval_path = os.path.join(approvals_dir, f"{approval_id}.json")
# Defense-in-depth (SECURITY FIX, post-audit) -- see the cag_approve
# python block for the full rationale; status is read-only but must
# never read THROUGH a symlink planted at approval_path either.
real_approvals_dir = os.path.realpath(approvals_dir)
real_approval_path = os.path.realpath(approval_path)
if os.path.dirname(real_approval_path) != real_approvals_dir:
    print(json.dumps({"ok": False, "error": "invalid_approval_id", "detail": "resolved path escapes approvals_dir", "approval_id": approval_id}, ensure_ascii=False))
    sys.exit(10)
if not os.path.isfile(approval_path):
    print(json.dumps({"ok": False, "error": "approval_not_found", "approval_id": approval_id}))
    sys.exit(2)
try:
    with open(approval_path) as f:
        record = json.load(f)
except Exception as e:
    print(json.dumps({"ok": False, "error": "record_corrupt", "detail": str(e), "approval_id": approval_id}))
    sys.exit(4)

now_dt = cal.parse_utc_timestamp(now_text)
expires_dt = cal.parse_utc_timestamp(record.get("expires_at"))
stored_status = record.get("status")
effective_status = stored_status
if stored_status == "PENDING" and cal.is_expired(expires_dt, now_dt):
    effective_status = "EXPIRED"

print(json.dumps({"ok": True, "approval_id": approval_id, "stored_status": stored_status, "effective_status": effective_status, "record": record}, ensure_ascii=False))
PYEOF
}

# ==================================================================
# list [--status PENDING|APPROVED|REJECTED|EXPIRED] -- read-only.
# ==================================================================
cag_list() {
  local filter_status=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --status) filter_status="$2"; shift 2 ;;
      *) echo "Usage: $0 list [--status PENDING|APPROVED|REJECTED|EXPIRED]" >&2; return 1 ;;
    esac
  done
  python3 - "$APPROVALS_DIR" "$(_cag_now)" "$filter_status" <<'PYEOF'
import glob, json, os, sys
sys.path.insert(0, os.path.join(os.getcwd(), "security", "red_alert"))
import containment_approval_lib as cal

approvals_dir, now_text, filter_status = sys.argv[1:4]
now_dt = cal.parse_utc_timestamp(now_text)

entries = []
corrupt = []
for path in sorted(glob.glob(os.path.join(approvals_dir, "*.json"))):
    try:
        with open(path) as f:
            record = json.load(f)
    except Exception as e:
        corrupt.append({"path": os.path.basename(path), "error": str(e)})
        continue
    stored_status = record.get("status")
    effective_status = stored_status
    expires_dt = cal.parse_utc_timestamp(record.get("expires_at"))
    if stored_status == "PENDING" and cal.is_expired(expires_dt, now_dt):
        effective_status = "EXPIRED"
    if filter_status and effective_status != filter_status:
        continue
    entries.append({
        "approval_id": record.get("approval_id"),
        "effective_status": effective_status,
        "entity": (record.get("decision_record_ref") or {}).get("entity"),
        "requested_at": record.get("requested_at"),
        "expires_at": record.get("expires_at"),
    })

print(json.dumps({"ok": True, "count": len(entries), "entries": entries, "corrupt": corrupt}, ensure_ascii=False))
PYEOF
}

if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
  case "${1:-}" in
    request)
      shift
      cag_request "$@"
      ;;
    approve)
      shift
      cag_approve "$@"
      ;;
    reject)
      shift
      cag_reject "$@"
      ;;
    status)
      shift
      cag_status "$@"
      ;;
    list)
      shift
      cag_list "$@"
      ;;
    *)
      echo "Usage: $0 {request DECISION_REPORT_FILE ENTITY REQUESTED_BY [--target-type TYPE] [--target-id ID] [--proposed-tool TOOL] [--rollback-tool TOOL]|approve APPROVAL_ID APPROVER_IDENTITY REASON [EXCEPTION_REASON]|reject APPROVAL_ID APPROVER_IDENTITY REASON|status APPROVAL_ID|list [--status STATUS]}" >&2
      exit 1
      ;;
  esac
fi
