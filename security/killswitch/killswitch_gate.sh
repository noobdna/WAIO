#!/bin/bash
set -uo pipefail

# security/killswitch/killswitch_gate.sh -- DuCoPA Independent Kill
# Switch: the least-privilege containment gate for the TEST environment.
# Verbs:
#   execute COMMAND_FILE [--enforce-test]  -- verify a signed command
#                                             (containment or release);
#                                             DRY-RUN unless --enforce-test
#   execute-policy POLICY EVENT [--enforce-test]
#                                          -- operator-signed pre-approved
#                                             policy + sensor-signed event
#                                             (killswitch_policy.py)
#   evaluate-event EVENT_FILE              -- SND@HOME/SND@ID event ->
#                                             recommendation (always DRY-RUN)
#   preserve-evidence INCIDENT_ID [--command-id ID]... [--event-id ID]...
#   verify-evidence BUNDLE_DIR             -- killswitch_evidence.py
#   status                                 -- configuration/result summary
#   verify-audit                           -- recompute the audit hash chain
#
# ============================================================
# SCOPE, STATED NARROWLY -- read before touching this file
# ============================================================
# INDEPENDENT OF WAIO'S OWN JUDGMENT: this file does not source the
# main security library, and never reads or calls the Guardian Control
# Plane, the DuCoPA prototype, the Decision Engine, the main dispatcher
# or any worker (tests/killswitch_gate_test.sh's K-series proves this
# with a grep, and runs this directory alone, copied away from the rest
# of the repository, with a fixture emergency-shutdown lock active).
# It works when WAIO is stopped because it needs nothing from WAIO.
#
# THE ONLY SIDE EFFECT is killswitch_io.py's `effect`: one marker file
# inside a declared test-environment directory (KILLSWITCH_TEST_ENV,
# which must be outside this repository and carry a
# `.killswitch-test-env` file declaring `environment=test`). The
# enforcement point a test service consults is killswitch_enforce.py.
# No production traffic, firewall, Cloudflare, SSH, credential or
# WAIO state is ever touched.
#
# AI-GENERATED INSTRUCTIONS ARE NEVER EXECUTED UNCONDITIONALLY: the only
# executable input is a command signed by an issuer key from the
# keyring, authorized for that action, aimed at an allowlisted test
# target, with a human_operator/guardian origin and a fresh timestamp.
# `evaluate-event` has no path into `execute` -- detection alone never
# contains anything.
#
# FAILURE BEHAVIOUR (fail closed, never reported as success):
#   - audit log cannot be written before an action -> not executed
#   - marker write fails / exceeds KILLSWITCH_ACTION_TIMEOUT -> FAILED /
#     FAILED_TIMEOUT, exit 1; the command id stays consumed (replay
#     safe); the operator re-issues with a new command id
#   - duplicate command id -> DUPLICATE_IGNORED, never executed twice
#   - control plane (this gate / WAIO / the link to it) down -> existing
#     markers stay in force; the enforcement point never auto-releases
#
# AUTHENTICATION IS KEY POSSESSION, NOT HUMAN IDENTITY: anyone who can
# read an issuer key can sign. Keep keys off the hosts where WAIO's AI
# processes run (see ARCHITECTURE.md, Phase 106).
#
# WHY NO `source` OF THE MAIN SECURITY LIBRARY: same reasoning as
# security/red_alert/containment_approval_gate.sh -- that library pulls
# in the Guardian Control Plane at load time. This file carries its own
# copy of the repository's mkdir lock and hash-chained audit log
# algorithms, with one deliberate difference: an audit write failure
# before an action is FAIL-CLOSED here (the action does not run).

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
KS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KS_IO="$KS_DIR/killswitch_io.py"

STATE_DIR="${KILLSWITCH_STATE_DIR:-$SCRIPT_DIR/security/state/killswitch}"
CONFIG_DIR="${KILLSWITCH_CONFIG_DIR:-$STATE_DIR/config}"
KEYRING_DIR="${KILLSWITCH_KEYRING_DIR:-$CONFIG_DIR/keys}"
AUDIT_LOG="${KILLSWITCH_AUDIT_LOG:-$SCRIPT_DIR/logs/killswitch-audit.jsonl}"
AUDIT_CHECKPOINT="${KILLSWITCH_AUDIT_CHECKPOINT:-$STATE_DIR/.audit_checkpoint}"
AUDIT_LOCK_DIR="$STATE_DIR/.audit_lock"
SEEN_DIR="$STATE_DIR/seen"
RESULTS_DIR="$STATE_DIR/results"
EVENTS_DIR="$STATE_DIR/events"
POLICY_USES_DIR="$STATE_DIR/policy_uses"
EVIDENCE_DIR="${KILLSWITCH_EVIDENCE_DIR:-$STATE_DIR/evidence}"
TEST_ENV="${KILLSWITCH_TEST_ENV:-}"
ACTION_TIMEOUT="${KILLSWITCH_ACTION_TIMEOUT:-5}"
case "$ACTION_TIMEOUT" in ''|*[!0-9]*|0) ACTION_TIMEOUT=5 ;; esac

export PYTHONDONTWRITEBYTECODE=1   # never leave __pycache__ inside the repo
export KS_CONFIG_DIR="$CONFIG_DIR" KS_KEYRING_DIR="$KEYRING_DIR" KS_REPO_DIR="$SCRIPT_DIR"
export KS_NOW="${WAIO_KILLSWITCH_NOW:-}"
export KS_FRESHNESS_SECONDS="${KILLSWITCH_FRESHNESS_SECONDS:-300}"

_ks_now() {
  if [ -n "${WAIO_KILLSWITCH_NOW:-}" ]; then printf '%s' "$WAIO_KILLSWITCH_NOW"; else date -u +%Y-%m-%dT%H:%M:%SZ; fi
}

# _ks_json JSON PY_EXPR -- prints PY_EXPR evaluated against parsed JSON `d`
_ks_json() {
  python3 -c "import json,sys; d=json.loads(sys.argv[1]); v=($2); print(v if isinstance(v,str) else json.dumps(v,sort_keys=True))" "$1" 2>/dev/null
}

# ------------------------------------------------------------------
# Standalone mkdir lock (same algorithm as containment_approval_gate.sh:
# PID-liveness-gated stale-lock steal, never age alone).
# ------------------------------------------------------------------
_ks_lock_acquire() {
  local lock_dir="$1" max_wait="$2" waited=0
  while ! mkdir "$lock_dir" 2>/dev/null; do
    if [ -d "$lock_dir" ]; then
      local lock_mtime now age holder_pid=""
      lock_mtime="$(stat -f %m "$lock_dir" 2>/dev/null)"
      case "$lock_mtime" in ''|*[!0-9]*) lock_mtime="$(stat -c %Y "$lock_dir" 2>/dev/null)" ;; esac
      case "$lock_mtime" in ''|*[!0-9]*) lock_mtime=0 ;; esac
      now="$(date +%s)" || now=0
      age=$((now - lock_mtime))
      if [ "$age" -gt 5 ]; then
        holder_pid="$(cat "$lock_dir/holder.pid" 2>/dev/null)" || holder_pid=""
        case "$holder_pid" in ''|*[!0-9]*) holder_pid="" ;; esac
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

_ks_lock_release() { rm -rf "$1" 2>/dev/null || true; }

# ------------------------------------------------------------------
# Standalone hash-chained audit log (same algorithm as
# containment_approval_gate.sh; optional HMAC key via
# KILLSWITCH_AUDIT_HMAC_KEY_FILE, read by Python from disk, never on
# argv). Returns 1 if the line could not be written -- callers that are
# about to act treat that as "do not act".
# ------------------------------------------------------------------
_ks_hash_line() {
  python3 -c "
import hashlib, hmac, os, sys
text = sys.argv[1]
key_path = os.environ.get('KILLSWITCH_AUDIT_HMAC_KEY_FILE', '')
if key_path and os.path.isfile(key_path) and os.access(key_path, os.R_OK):
    with open(key_path, 'rb') as f:
        key = f.read()
    print(hmac.new(key, text.encode('utf-8'), hashlib.sha256).hexdigest())
else:
    print(hashlib.sha256(text.encode('utf-8')).hexdigest())
" "$1"
}

_ks_audit_log() {
  local event_type="$1" ref_id="$2" detail_json="$3"
  local ts; ts="$(_ks_now)"
  _ks_lock_acquire "$AUDIT_LOCK_DIR" 50 || {
    echo "[KILLSWITCH] ERROR: audit lock unavailable (event_type=$event_type)" >&2
    return 1
  }
  local checkpoint_content="" checkpoint_count=0 prev_hash="genesis" rc=1
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
try:
    detail = json.loads(sys.argv[4]) if sys.argv[4] else None
except Exception:
    detail = {'unparsed_detail': sys.argv[4][:400]}
print(json.dumps({'timestamp': sys.argv[1], 'event_type': sys.argv[2], 'ref_id': sys.argv[3],
                  'detail': detail, 'prev_hash': sys.argv[5]}, ensure_ascii=False, sort_keys=True))
" "$ts" "$event_type" "$ref_id" "$detail_json" "$prev_hash")" || line=""
  if [ -n "$line" ] && printf '%s\n' "$line" >> "$AUDIT_LOG" 2>/dev/null; then
    local new_hash
    new_hash="$(_ks_hash_line "$line")" || new_hash=""
    if [ -n "$new_hash" ] && printf '%s:%s' "$((checkpoint_count + 1))" "$new_hash" > "$AUDIT_CHECKPOINT" 2>/dev/null; then
      rc=0
    fi
  fi
  [ "$rc" -eq 0 ] || echo "[KILLSWITCH] ERROR: failed to write audit log entry (event_type=$event_type ref=$ref_id)" >&2
  _ks_lock_release "$AUDIT_LOCK_DIR"
  return "$rc"
}

# _ks_verify_audit -- prints ok | ok:no_checkpoint | missing |
# broken:<lineno> | broken:checkpoint_mismatch(...)
_ks_verify_audit() {
  if [ ! -f "$AUDIT_LOG" ]; then
    if [ -f "$AUDIT_CHECKPOINT" ]; then echo "missing"; else echo "ok"; fi
    return 0
  fi
  [ -f "$AUDIT_CHECKPOINT" ] || { echo "ok:no_checkpoint"; return 0; }
  local cp; cp="$(cat "$AUDIT_CHECKPOINT" 2>/dev/null)" || cp=""
  case "${cp%%:*}" in ''|*[!0-9]*) echo "ok:no_checkpoint"; return 0 ;; esac
  python3 -c "
import hashlib, hmac, json, os, sys
log_path, expected_count, expected_hash = sys.argv[1], int(sys.argv[2]), sys.argv[3]
def hash_line(text):
    key_path = os.environ.get('KILLSWITCH_AUDIT_HMAC_KEY_FILE', '')
    if key_path and os.path.isfile(key_path) and os.access(key_path, os.R_OK):
        with open(key_path, 'rb') as f:
            return hmac.new(f.read(), text.encode('utf-8'), hashlib.sha256).hexdigest()
    return hashlib.sha256(text.encode('utf-8')).hexdigest()
prev, count, broken = 'genesis', 0, None
with open(log_path) as f:
    for lineno, raw in enumerate(f, start=1):
        text = raw.rstrip('\n')
        if not text:
            continue
        try:
            obj = json.loads(text)
        except Exception:
            broken = lineno; break
        if obj.get('prev_hash') != prev:
            broken = lineno; break
        count += 1
        prev = hash_line(text)
if broken is not None:
    print('broken:%d' % broken)
elif count != expected_count or prev != expected_hash:
    print('broken:checkpoint_mismatch(count=%d,expected=%d)' % (count, expected_count))
else:
    print('ok')
" "$AUDIT_LOG" "${cp%%:*}" "${cp#*:}"
}

# Set to 1 only by the process whose own mkdir claimed seen/<id>. A
# result file is written ONLY by that process, so a forged/denied
# command reusing an executed command's id can never overwrite the
# real result record.
KS_OWNS_ID=0

# _ks_finish CMD_JSON DECISION CODE DETAIL MODE RESULT EXIT_CODE AUDIT_EVENT
# builds the structured record, persists it (results/<id>.json, owner
# of the id only), audits it, prints it, exits.
_ks_finish() {
  local cmd_json="$1" decision="$2" code="$3" detail="$4" mode="$5" result="$6" rc="$7" audit_event="$8"
  local record cid
  record="$(KS_REC_COMMAND="$cmd_json" KS_REC_DECISION="$decision" KS_REC_CODE="$code" \
    KS_REC_DETAIL="$detail" KS_REC_MODE="$mode" KS_REC_RESULT="$result" python3 "$KS_IO" record)"
  cid="$(_ks_json "$record" "d['command_id']")"
  if [ "$KS_OWNS_ID" -eq 1 ] && [ -n "$cid" ]; then
    printf '%s\n' "$record" > "$RESULTS_DIR/$cid.json" 2>/dev/null || true
  fi
  _ks_audit_log "$audit_event" "${cid:-invalid}" "$record" || true
  printf '%s\n' "$record"
  exit "$rc"
}

ks_execute() {
  local cmd_file="${1:-}" enforce=0
  [ "${2:-}" = "--enforce-test" ] && enforce=1
  if [ -z "$cmd_file" ] || [ ! -f "$cmd_file" ]; then
    _ks_finish "{}" DENY DENIED_INVALID_INPUT "command file not found" NONE DENIED 2 killswitch_command_denied
  fi
  local decision_json decision code detail cmd_json mode=DRY_RUN
  [ "$enforce" -eq 1 ] && mode=ENFORCE_TEST
  decision_json="$(python3 "$KS_IO" decide "$cmd_file")" || decision_json=""
  decision="$(_ks_json "$decision_json" "d['decision']")"
  code="$(_ks_json "$decision_json" "d['code']")"
  detail="$(_ks_json "$decision_json" "d['detail']")"
  cmd_json="$(_ks_json "$decision_json" "d['command']")"
  [ -n "$cmd_json" ] || cmd_json="{}"
  if [ "$decision" != "ALLOW" ]; then
    _ks_finish "$cmd_json" DENY "${code:-DENIED_INTERNAL}" "${detail:-decision helper failed}" "$mode" DENIED 2 killswitch_command_denied
  fi
  _ks_act "$cmd_json" "$enforce" "$mode"
}

ks_execute_policy() {
  local pol_file="${1:-}" ev_file="${2:-}" enforce=0 mode=DRY_RUN
  [ "${3:-}" = "--enforce-test" ] && { enforce=1; mode=ENFORCE_TEST; }
  if [ -z "$pol_file" ] || [ ! -f "$pol_file" ] || [ -z "$ev_file" ] || [ ! -f "$ev_file" ]; then
    _ks_finish "{}" DENY DENIED_INVALID_INPUT "policy or event file not found" NONE DENIED 2 killswitch_policy_denied
  fi
  local decision_json decision cmd_json
  decision_json="$(python3 "$KS_IO" policy-decide "$pol_file" "$ev_file")" || decision_json=""
  decision="$(_ks_json "$decision_json" "d['decision']")"
  cmd_json="$(_ks_json "$decision_json" "d['command']")"
  [ -n "$cmd_json" ] || cmd_json="{}"
  if [ "$decision" != "ALLOW" ]; then
    _ks_finish "$cmd_json" DENY "$(_ks_json "$decision_json" "d['code']")" "$(_ks_json "$decision_json" "d['detail']")" \
      "$mode" DENIED 2 killswitch_policy_denied
  fi
  _ks_act "$cmd_json" "$enforce" "$mode"
}

# _ks_act CMD_JSON ENFORCE MODE -- shared tail of execute/execute-policy
# for a command that already passed every policy check.
_ks_act() {
  local cmd_json="$1" enforce="$2" mode="$3"
  local cid action target testenv_json policy_id
  cid="$(_ks_json "$cmd_json" "d['command_id']")"
  action="$(_ks_json "$cmd_json" "d['action']")"
  target="$(_ks_json "$cmd_json" "d['target_id']")"
  testenv_json="$(python3 "$KS_IO" testenv "$TEST_ENV")"
  if [ "$(_ks_json "$testenv_json" "d['ok']")" != "true" ]; then
    _ks_finish "$cmd_json" DENY DENIED_NO_TEST_ENV "$(_ks_json "$testenv_json" "d['detail']")" "$mode" DENIED 2 killswitch_command_denied
  fi
  if [ "$enforce" -ne 1 ]; then
    _ks_finish "$cmd_json" ALLOW ALLOWED "dry-run: all checks passed, nothing executed (pass --enforce-test to act on the test environment)" \
      DRY_RUN DRY_RUN_NOT_EXECUTED 0 killswitch_command_dry_run
  fi

  # single execution per command id (atomic)
  if ! mkdir "$SEEN_DIR/$cid" 2>/dev/null; then
    if [ -d "$SEEN_DIR/$cid" ]; then
      _ks_audit_log killswitch_command_duplicate "$cid" "$cmd_json" || true
      python3 -c "import json,sys; print(json.dumps({'record_type':'command','command_id':sys.argv[1],'execution_result':'DUPLICATE_IGNORED','detail':'command id already used; not executed again'}))" "$cid"
      exit 0
    fi
    _ks_finish "$cmd_json" ALLOW ALLOWED "cannot record command id" "$mode" FAILED_NO_PERSISTENCE 1 killswitch_command_failed
  fi
  KS_OWNS_ID=1
  policy_id="$(_ks_json "$cmd_json" "d.get('policy_id') or ''")"
  if [ -n "$policy_id" ]; then
    # max_executions: claim one numbered slot atomically, or refuse
    local max_n slot=0 n
    max_n="$(_ks_json "$cmd_json" "str(d.get('max_executions') or 0)")"
    case "$max_n" in ''|*[!0-9]*) max_n=0 ;; esac
    mkdir -p "$POLICY_USES_DIR/$policy_id" 2>/dev/null || true
    n=1
    while [ "$n" -le "$max_n" ]; do
      if mkdir "$POLICY_USES_DIR/$policy_id/$n" 2>/dev/null; then slot="$n"; break; fi
      n=$((n + 1))
    done
    if [ "$slot" -eq 0 ]; then
      _ks_finish "$cmd_json" DENY DENIED_POLICY_EXHAUSTED "policy $policy_id already used $max_n time(s)" "$mode" DENIED 2 killswitch_policy_denied
    fi
  fi
  if ! _ks_audit_log killswitch_command_attempt "$cid" "$cmd_json"; then
    _ks_finish "$cmd_json" ALLOW ALLOWED "audit log unavailable before action; not executed" "$mode" FAILED_NO_PERSISTENCE 1 killswitch_command_failed
  fi

  local effect_json="" effect_rc=0
  effect_json="$(/usr/bin/perl -e 'alarm shift; exec @ARGV' "$ACTION_TIMEOUT" \
    python3 "$KS_IO" effect "$action" "$target" "$TEST_ENV" "$cid")" || effect_rc=$?
  if [ "$effect_rc" -eq 142 ]; then
    _ks_finish "$cmd_json" ALLOW ALLOWED "containment did not complete within ${ACTION_TIMEOUT}s" "$mode" FAILED_TIMEOUT 1 killswitch_command_failed
  fi
  if [ "$effect_rc" -ne 0 ] || [ "$(_ks_json "$effect_json" "d['ok']")" != "true" ]; then
    _ks_finish "$cmd_json" ALLOW ALLOWED "$(_ks_json "$effect_json" "d['detail']") (rc=$effect_rc)" "$mode" FAILED 1 killswitch_command_failed
  fi
  _ks_finish "$cmd_json" ALLOW ALLOWED "$(_ks_json "$effect_json" "d['marker']")" "$mode" EXECUTED 0 killswitch_command_executed
}

ks_evaluate_event() {
  local ev_file="${1:-}" out eid dup=false record
  if [ -z "$ev_file" ] || [ ! -f "$ev_file" ]; then
    echo '{"ok": false, "error": "invalid_event", "detail": "event file not found"}'; exit 2
  fi
  out="$(python3 "$KS_IO" event "$ev_file")" || out=""
  if [ "$(_ks_json "$out" "d['ok']")" != "true" ]; then
    [ -n "$out" ] || out='{"ok": false, "error": "invalid_event", "detail": "event helper failed"}'
    _ks_audit_log killswitch_event_rejected "invalid" "$out" || true
    printf '%s\n' "$out"; exit 2
  fi
  record="$(_ks_json "$out" "d['record']")"
  eid="$(_ks_json "$record" "d['event_id']")"
  if mkdir "$EVENTS_DIR/$eid" 2>/dev/null; then
    printf '%s\n' "$record" > "$EVENTS_DIR/$eid/record.json" 2>/dev/null || true
    _ks_audit_log killswitch_event_evaluated "$eid" "$record" || true
  else
    dup=true
    _ks_audit_log killswitch_event_duplicate "$eid" "$record" || true
  fi
  python3 -c "import json,sys; print(json.dumps({'ok': True, 'duplicate': sys.argv[1]=='true', 'record': json.loads(sys.argv[2])}, sort_keys=True))" "$dup" "$record"
  exit 0
}

ks_status() {
  python3 - "$RESULTS_DIR" "$EVENTS_DIR" "$(python3 "$KS_IO" testenv "$TEST_ENV")" "$(_ks_verify_audit)" \
    "$([ -f "$CONFIG_DIR/targets.conf" ] && [ -f "$CONFIG_DIR/authz.conf" ] && echo true || echo false)" <<'EOF'
import json, os, sys
results_dir, events_dir, testenv, audit, configured = sys.argv[1:6]
counts, failed = {}, []
for name in sorted(os.listdir(results_dir)) if os.path.isdir(results_dir) else []:
    try:
        with open(os.path.join(results_dir, name)) as f:
            r = json.load(f)
    except Exception:
        counts["UNREADABLE"] = counts.get("UNREADABLE", 0) + 1
        continue
    res = r.get("execution_result", "UNKNOWN")
    counts[res] = counts.get(res, 0) + 1
    if res.startswith("FAILED"):
        failed.append({"command_id": r.get("command_id"), "target_id": r.get("target_id"), "result": res})
print(json.dumps({
    "default_mode": "DRY_RUN",
    "configured": configured == "true",
    "test_env": json.loads(testenv),
    "results": counts,
    "containment_failed": failed,
    "events_recorded": len(os.listdir(events_dir)) if os.path.isdir(events_dir) else 0,
    "audit_integrity": audit,
}, sort_keys=True))
EOF
}

if ! mkdir -p "$SEEN_DIR" "$RESULTS_DIR" "$EVENTS_DIR" "$(dirname "$AUDIT_LOG")" 2>/dev/null; then
  echo '{"record_type": "command", "execution_result": "FAILED_NO_PERSISTENCE", "detail": "cannot create state directories; refusing to act without safe persistence"}'
  exit 1
fi

case "${1:-}" in
  execute) shift; ks_execute "$@" ;;
  evaluate-event) shift; ks_evaluate_event "$@" ;;
  execute-policy) shift; ks_execute_policy "$@" ;;
  preserve-evidence)
    shift
    export KS_STATE_DIR="$STATE_DIR" KS_AUDIT_LOG="$AUDIT_LOG" KS_AUDIT_CHECKPOINT="$AUDIT_CHECKPOINT" KS_TEST_ENV="$TEST_ENV"
    KS_AUDIT_INTEGRITY="$(_ks_verify_audit)"; export KS_AUDIT_INTEGRITY
    ev_out="$(python3 "$KS_DIR/killswitch_evidence.py" preserve "${1:-}" "$EVIDENCE_DIR" "${@:2}")"
    _ks_audit_log killswitch_evidence_preserved "${1:-invalid}" "$ev_out" || true
    printf '%s\n' "$ev_out"
    [ "$(_ks_json "$ev_out" "d['ok']")" = "true" ] || exit 1 ;;
  verify-evidence) shift; python3 "$KS_DIR/killswitch_evidence.py" verify "${1:-}" ;;
  status) ks_status ;;
  verify-audit) _ks_verify_audit ;;
  *)
    echo "usage: $0 execute COMMAND_FILE [--enforce-test] | execute-policy POLICY EVENT [--enforce-test] | evaluate-event EVENT_FILE | preserve-evidence INCIDENT_ID [--command-id ID]... [--event-id ID]... | verify-evidence BUNDLE | status | verify-audit" >&2
    exit 2 ;;
esac
