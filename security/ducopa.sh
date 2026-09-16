#!/bin/bash
# security/ducopa.sh -- DuCoPA (Dual Control Plane Architecture) minimal
# control-plane prototype: state machine + severity ranking + fail-closed
# reads + explicit human-approval gate, ONLY.
#
# DELIBERATELY STANDALONE, and deliberately worded below without naming
# this repo's other control-plane files directly, so a plain `grep` of
# this one file for those exact names -- the check tests/ducopa_core_test.sh
# runs as its very first case -- proves the isolation instead of just
# asserting it in prose. This file is not sourced by, and does not read,
# write, or call anything belonging to: the existing DLP/emergency-stop
# library every worker already sources, that library's real persisted
# lock file, the script that clears that lock, the already-integrated
# Guardian control-plane module (sourced from that library and wired into
# the main dispatcher's own gate), or that dispatcher itself.
#
# Its "shutdown" severity only ever sets this module's OWN local state
# file to SHUTDOWN; it never touches any real, already-integrated
# shutdown/recovery state anywhere else in this repo.
#
# This is intentional scope, per the instruction that created it: build
# and prove out the DuCoPA state machine in isolation first, wire it to
# any real production path (a dispatch gate, the real shutdown lock, an
# SSH-authenticated Guardian channel) only as an explicit, separate,
# later decision. Nothing in this file is called by any existing script
# today.
#
# Five states, ordered by severity (ducopa_state_rank below):
#   NORMAL(0)                   -- ordinary operation
#   WARNING(1)                  -- noteworthy, logged, non-blocking
#   BLOCKED(2)                  -- blocking (per ducopa_is_blocking)
#   HUMAN_APPROVAL_REQUIRED(3)  -- blocking; cleared only via
#                                  ducopa_approve with an explicit reason
#   SHUTDOWN(4)                 -- blocking; this module's own local
#                                  mirror only -- cleared only via
#                                  ducopa_approve, same as
#                                  HUMAN_APPROVAL_REQUIRED (this standalone
#                                  module has no separate recovery script
#                                  of its own -- see header above)
#
# Severity never auto-downgrades: ducopa_notify_event only ever raises
# the current state's rank, never lowers it (ducopa_state_rank compare).
# The only way a state's rank ever decreases is the explicit
# ducopa_approve path, which always requires a non-empty reason.
#
# Fail-closed reads (ducopa_get_state): an absent state file reads as
# NORMAL (a fresh checkout must not start pre-blocked); a present file
# whose content is not one of the five names above reads as BLOCKED,
# never silently as NORMAL.

DUCOPA_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DUCOPA_STATE_FILE="${WAIO_DUCOPA_STATE_FILE:-$DUCOPA_LIB_DIR/state/DUCOPA_STATE}"
DUCOPA_AUDIT_LOG="${WAIO_DUCOPA_AUDIT_LOG:-$DUCOPA_LIB_DIR/state/ducopa/audit.jsonl}"
mkdir -p "$(dirname "$DUCOPA_STATE_FILE")" "$(dirname "$DUCOPA_AUDIT_LOG")" 2>/dev/null || true

# _ducopa_log EVENT_TYPE FROM_STATE TO_STATE ACTOR DETAIL -- appends one
# JSON line to this module's OWN audit log -- entirely separate from the
# repo's real production audit trail and its logging function, so this
# module's activity is trivially distinguishable from real production
# audit events. Never fails the caller.
_ducopa_log() {
  local event_type="$1" from_state="$2" to_state="$3" actor="${4:-unknown}" detail="${5:-}"
  local ts
  ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  python3 -c "
import json, sys
print(json.dumps({
    'timestamp': sys.argv[1],
    'event_type': sys.argv[2],
    'from_state': sys.argv[3],
    'to_state': sys.argv[4],
    'actor': sys.argv[5],
    'detail': sys.argv[6],
}))
" "$ts" "$event_type" "$from_state" "$to_state" "$actor" "$detail" >> "$DUCOPA_AUDIT_LOG" 2>/dev/null || true
  return 0
}

# ducopa_state_rank STATE -- integer severity rank, higher = more
# restrictive. -1 for anything not one of the five known states.
ducopa_state_rank() {
  case "$1" in
    NORMAL) echo 0 ;;
    WARNING) echo 1 ;;
    BLOCKED) echo 2 ;;
    HUMAN_APPROVAL_REQUIRED) echo 3 ;;
    SHUTDOWN) echo 4 ;;
    *) echo -1 ;;
  esac
}

# ducopa_valid_state STATE -- true (exit 0) iff STATE is one of the five
# known states.
ducopa_valid_state() {
  [ "$(ducopa_state_rank "$1")" -ge 0 ]
}

# ducopa_get_state -- prints the current state. Absent file -> NORMAL.
# Present-but-invalid content -> BLOCKED (fail closed), with a stderr
# warning so the corruption is never silent.
ducopa_get_state() {
  if [ ! -f "$DUCOPA_STATE_FILE" ]; then
    echo "NORMAL"
    return 0
  fi
  local content=""
  content="$(cat "$DUCOPA_STATE_FILE" 2>/dev/null)" || content=""
  content="$(printf '%s' "$content" | tr -d '[:space:]')"
  if [ -z "$content" ]; then
    echo "NORMAL"
    return 0
  fi
  if ducopa_valid_state "$content"; then
    echo "$content"
  else
    echo "[DuCoPA] WARNING: $DUCOPA_STATE_FILE contains an unrecognized state ('$content') -- treating as BLOCKED (fail closed)." >&2 || true
    echo "BLOCKED"
  fi
  return 0
}

# ducopa_set_state NEW_STATE REASON [ACTOR] -- pure state transition:
# validates NEW_STATE, writes it, logs a ducopa_state_changed event to
# this module's own audit log. Never calls any real shutdown/recovery
# code -- this only ever writes DUCOPA_STATE_FILE.
ducopa_set_state() {
  local new_state="$1" reason="${2:-no reason given}" actor="${3:-unknown}"
  if ! ducopa_valid_state "$new_state"; then
    echo "[DuCoPA] ERROR: refusing to set unknown state '$new_state'" >&2 || true
    return 1
  fi
  local old_state=""
  old_state="$(ducopa_get_state)"
  printf '%s\n' "$new_state" > "$DUCOPA_STATE_FILE"
  _ducopa_log "ducopa_state_changed" "$old_state" "$new_state" "$actor" "$reason"
  return 0
}

# ducopa_is_blocking -- true (exit 0) iff the current state is
# BLOCKED, HUMAN_APPROVAL_REQUIRED, or SHUTDOWN. Not wired to any real
# dispatch path today -- a future caller would check this the same way
# the main dispatcher already gates on the integrated Guardian module's
# equivalent function, but no such call site exists for this module yet.
ducopa_is_blocking() {
  case "$(ducopa_get_state)" in
    BLOCKED|HUMAN_APPROVAL_REQUIRED|SHUTDOWN) return 0 ;;
    *) return 1 ;;
  esac
}

# ducopa_notify_event EVENT_NAME SEVERITY DETAIL [ACTOR] -- the
# notify-only interface. SEVERITY: info (logged only, never changes
# state) / warning (escalates to at least WARNING) / critical
# (escalates to at least BLOCKED) / shutdown (escalates to SHUTDOWN --
# this module's own local state ONLY; never calls any real production
# shutdown code or touches any real production lock file). Escalation
# only ever raises rank, never lowers it.
ducopa_notify_event() {
  local event_name="$1" severity="${2:-info}" detail="${3:-}" actor="${4:-unknown}"
  local current=""
  current="$(ducopa_get_state)"
  _ducopa_log "ducopa_event_notified" "$current" "$current" "$actor" "severity=$severity $event_name: $detail"

  local target=""
  case "$severity" in
    warning) target="WARNING" ;;
    critical) target="BLOCKED" ;;
    shutdown) target="SHUTDOWN" ;;
    *) return 0 ;;
  esac

  if [ "$(ducopa_state_rank "$target")" -gt "$(ducopa_state_rank "$current")" ]; then
    ducopa_set_state "$target" "auto-escalated by event '$event_name' (severity=$severity): $detail" "$actor"
  fi
  return 0
}

# ducopa_require_human_approval REASON [ACTOR] -- explicitly transitions
# to HUMAN_APPROVAL_REQUIRED. Not reachable via ducopa_notify_event's
# severity levels (mirrors the already-integrated Guardian module's own
# separation between automatic severity escalation and this explicit
# call).
ducopa_require_human_approval() {
  local reason="$1" actor="${2:-unknown}"
  ducopa_set_state "HUMAN_APPROVAL_REQUIRED" "$reason" "$actor"
}

# ducopa_approve REASON [ACTOR] -- the ONLY way any non-NORMAL state
# (WARNING/BLOCKED/HUMAN_APPROVAL_REQUIRED/SHUTDOWN) clears back to
# NORMAL. Requires a non-empty reason. Since this module never calls any
# real production shutdown/recovery code, SHUTDOWN here is cleared the
# exact same way as every other state -- there is no separate recovery
# script for a purely local, unwired mirror.
ducopa_approve() {
  local reason="$1" actor="${2:-operator}"
  local current=""
  current="$(ducopa_get_state)"
  if [ "$current" = "NORMAL" ]; then
    echo "[DuCoPA] Already NORMAL. Nothing to do."
    return 0
  fi
  if [ -z "$reason" ]; then
    echo "[DuCoPA] ERROR: refusing to clear state '$current' without a reason." >&2 || true
    return 1
  fi
  ducopa_set_state "NORMAL" "$reason" "$actor"
  _ducopa_log "ducopa_approval_granted" "$current" "NORMAL" "$actor" "$reason"
  return 0
}
