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

# Owner-token release and mutex-serialized stale steal: identical to
# security/lib.sh's _waio_mkdir_lock_acquire, see its header
# (tests/mkdir_lock_ownership_test.sh).
_sda_lock_acquire() {
  local lock_dir="$1" max_wait="$2" waited=0
  local token_var="_WAIO_LOCK_TOKEN_${lock_dir//[!A-Za-z0-9]/_}"
  while ! mkdir "$lock_dir" 2>/dev/null; do
    if [ -d "$lock_dir" ] && _sda_lock_is_stale "$lock_dir"; then
      if mkdir "$lock_dir.steal" 2>/dev/null; then
        _sda_lock_is_stale "$lock_dir" && { rm -rf "$lock_dir" 2>/dev/null || true; }
        rmdir "$lock_dir.steal" 2>/dev/null || true
        continue
      elif [ "$(_sda_lock_age "$lock_dir.steal")" -gt 5 ]; then
        rmdir "$lock_dir.steal" 2>/dev/null || true
        continue
      fi
    fi
    waited=$((waited + 1))
    if [ "$waited" -gt "$max_wait" ]; then
      printf -v "$token_var" '%s' "-"
      return 1
    fi
    sleep 0.1
  done
  printf '%s' "$$" > "$lock_dir/holder.pid" 2>/dev/null || true
  local token=""
  token="$(od -An -N8 -tx1 /dev/urandom 2>/dev/null)" || token=""
  token="$$.${token//[!0-9a-f]/}.$RANDOM"
  printf '%s' "$token" > "$lock_dir/owner" 2>/dev/null || true
  printf -v "$token_var" '%s' "$token"
  return 0
}

_sda_lock_release() {
  local lock_dir="$1" mine owner=""
  local token_var="_WAIO_LOCK_TOKEN_${lock_dir//[!A-Za-z0-9]/_}"
  mine="${!token_var:-}"
  unset "$token_var"
  if [ -n "$mine" ]; then
    { IFS= read -r owner < "$lock_dir/owner"; } 2>/dev/null || true
    [ "$owner" = "$mine" ] || return 0
  fi
  rm -rf "$lock_dir" 2>/dev/null || true
}

# _sda_lock_age DIR -- seconds since DIR's mtime; 0 when the mtime
# cannot be read (see the unreadable-mtime note below).
_sda_lock_age() {
  local lock_dir="$1" lock_mtime now
  # stat -f means "print mtime with this format" on macOS/BSD, but
  # "print FILESYSTEM status" (entirely different, and takes no %m
  # format spec) on Linux/GNU -- it does not error there, it just
  # silently succeeds with unrelated multi-line output, so the
  # naive `stat -f ... || stat -c ...` fallback never triggers on
  # Linux (confirmed in CI, 2026-09-16: this broke stale-lock
  # detection under real concurrent writers -- only 1 of 12 landed).
  # Try BSD form, then GNU form, and validate each result is
  # actually a bare integer before trusting it.
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
  echo $((now - lock_mtime))
}

# _sda_lock_is_stale LOCK_DIR -- 0 if LOCK_DIR is older than 5s
# AND its recorded holder is missing or no longer alive (age alone is
# never enough, Phase 65).
_sda_lock_is_stale() {
  local lock_dir="$1" holder_pid=""
  [ "$(_sda_lock_age "$lock_dir")" -gt 5 ] || return 1
  holder_pid="$(cat "$lock_dir/holder.pid" 2>/dev/null)" || holder_pid=""
  case "$holder_pid" in
    ''|*[!0-9]*) holder_pid="" ;;
  esac
  [ -z "$holder_pid" ] || ! kill -0 "$holder_pid" 2>/dev/null
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

# _sda_hash_line TEXT -- hashes one audit-log line for the hash chain.
# Plain SHA-256 by default (identical algorithm to this file's own
# sibling, containment_approval_gate.sh). If
# DEV_APPROVAL_AUDIT_HMAC_KEY_FILE names a file this process can read,
# uses HMAC-SHA256 keyed with that file's raw bytes instead -- closing
# half of this module's own documented residual risk (ARCHITECTURE.md:
# "by a keyed/signed hash, or both"). The key is read directly from
# disk by Python, never placed on argv or in any env var value itself,
# so it never appears in a process listing. This does NOT by itself
# provide OS-level write isolation -- an attacker who can both write
# security/state/self_dev/ AND read the key file can still forge a
# self-consistent chain; the key file's own permissions/placement
# (e.g. root-owned, 0400, outside this OS user's read access) is what
# makes that infeasible, and remains the operator's responsibility.
_sda_hash_line() {
  python3 -c "
import hashlib, hmac, os, sys
text = sys.argv[1]
key_path = os.environ.get('DEV_APPROVAL_AUDIT_HMAC_KEY_FILE', '')
if key_path and os.path.isfile(key_path) and os.access(key_path, os.R_OK):
    with open(key_path, 'rb') as f:
        key = f.read()
    print(hmac.new(key, text.encode('utf-8'), hashlib.sha256).hexdigest())
else:
    print(hashlib.sha256(text.encode('utf-8')).hexdigest())
" "$1"
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
    new_hash="$(_sda_hash_line "$line")" || new_hash=""
    [ -n "$new_hash" ] && printf '%s:%s' "$new_count" "$new_hash" > "$AUDIT_CHECKPOINT" 2>/dev/null
  else
    echo "[SELF-DEV APPROVAL] WARNING: failed to write audit log entry (event_type=$event_type approval_id=$approval_id) -- the audit trail is incomplete" >&2
  fi

  [ "$lock_held" -eq 0 ] && _sda_lock_release "$AUDIT_LOCK_DIR"
}

# _sda_verify_audit_integrity -- walks the WHOLE audit log and
# recomputes its hash chain from genesis, same algorithm as this file's
# own architectural sibling, security/red_alert/
# containment_approval_gate.sh's own _cag_verify_audit_integrity (see
# that file for the original -- this copy additionally honors
# DEV_APPROVAL_AUDIT_HMAC_KEY_FILE, same key-aware hashing as
# _sda_hash_line above, so a chain written under a key can only be
# confirmed "ok" by a verifier that also holds that key; without it,
# recomputing with plain SHA-256 will not match and the chain reads
# "broken" -- fail-closed, never a false "ok"). Prints one of: "ok" |
# "ok:no_checkpoint" | "missing" | "broken:<lineno>" |
# "broken:checkpoint_mismatch(...)". Not wired to any CLI verb (outside
# the explicitly scoped five: propose|approve|reject|status|list), same
# scope discipline as the sibling this was ported from -- sourced and
# called directly by tests/dev_approval_gate_test.sh's own
# audit-corruption cases.
_sda_verify_audit_integrity() {
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
import hashlib, hmac, json, os, sys
log_path, expected_count, expected_hash = sys.argv[1], int(sys.argv[2]), sys.argv[3]

def hash_line(text):
    key_path = os.environ.get('DEV_APPROVAL_AUDIT_HMAC_KEY_FILE', '')
    if key_path and os.path.isfile(key_path) and os.access(key_path, os.R_OK):
        with open(key_path, 'rb') as f:
            key = f.read()
        return hmac.new(key, text.encode('utf-8'), hashlib.sha256).hexdigest()
    return hashlib.sha256(text.encode('utf-8')).hexdigest()

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
        prev_hash = hash_line(text)
if broken_at is not None:
    print(f'broken:{broken_at}')
elif count != expected_count or prev_hash != expected_hash:
    print(f'broken:checkpoint_mismatch(count={count},expected={expected_count})')
else:
    print('ok')
" "$AUDIT_LOG" "$checkpoint_count" "$checkpoint_hash"
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

  local aid status detail_json
  aid="$(_sda_extract_json_field "$out" "approval_id")"
  status="$(_sda_extract_json_field "$out" "status")"
  # Computed into a variable FIRST, then passed as a plain "$detail_json"
  # argument -- NOT inlined as a nested "$(...)" argument to
  # _sda_audit_log directly. A dict-literal python -c argument embedded
  # that way is textually exposed to bash's own brace expansion when it
  # sits inside a multi-argument command invocation (confirmed: it
  # silently split json.dumps({'operation':..., 'status':...}) into two
  # broken invocations at the comma, corrupting detail to empty and
  # printing two stray SyntaxErrors on every propose call). Plain
  # assignment first is the same safe convention sda_approve/sda_reject
  # already use for their own "$out" -- see this file's history.
  detail_json="$(python3 -c "import json,sys; print(json.dumps({'operation': sys.argv[1], 'status': sys.argv[2]}))" "$operation" "$status")"
  _sda_audit_log "proposed" "$aid" "$proposed_by" "$detail_json"
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

# FAIL-CLOSED GUARD. No apostrophes anywhere in this comment block,
# deliberately, same convention as the symlink-defense comment above
# in this same heredoc: an unbalanced single quote inside a heredoc
# body nested in a $(...) command substitution confuses the quote-depth
# tracking bash uses for the enclosing substitution, not just this
# comment. A stored record only ever reaches status PENDING when it
# was classified PRIVILEGED at propose time (see sda_propose). If
# evaluate_approval() now RE-classifies the SAME stored
# operation/target_branch/touched_paths as AUTOMATIC -- the documented
# "not-privileged short circuit" in dev_approval_lib.evaluate_approval(),
# returning allowed=True with no identity/evidence/expiry/reason gate
# evaluated at all -- that can only mean the record fields drifted
# from what propose() originally saw (on-disk tampering, or a
# classify_operation() rule change between propose and approve).
# Either way this is the same "any material change invalidates the
# previous approval" class of problem change_intact() exists to
# catch, so it is refused here, fail-closed, with an explicit
# violation code -- NEVER treated as "no approval needed, mark it
# APPROVED anyway" (which would skip every other check in this gate),
# and never allowed to reach the dict access below, where "reason" is
# only ever absent in exactly this one short-circuited branch.
if evaluation["checks"].get("scope", {}).get("basis") == "not_privileged":
    print(json.dumps({
        "ok": False,
        "error": "gate_refused",
        "violations": ["classification_drift_since_proposal"],
        "approval_id": approval_id,
    }, ensure_ascii=False))
    sys.exit(7)

if not evaluation["allowed"]:
    print(json.dumps({"ok": False, "error": "gate_refused", "violations": evaluation["violations"], "approval_id": approval_id}, ensure_ascii=False))
    sys.exit(7)

record["status"] = "APPROVED"
record["decision"] = {
    "outcome": "APPROVED",
    "decided_at": now_text,
    "decided_by": approver_identity,
    "reason": evaluation["checks"].get("reason", {}).get("normalized"),
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
