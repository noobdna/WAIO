#!/bin/bash
set -uo pipefail

# security/recovery_engine.sh -- Phase 49 (Segment Recovery MVP):
# the isolated -> recovering -> {recovered, failed} edges.
#
# Safety posture (matches ARCHITECTURE.md Phase 40-A's conclusion that
# an automated component must never confirm its own recovery without
# genuine verification, and this repo's existing dry-run/--apply
# asymmetry in security/generate_ssh_guardian_config.sh):
#   - Only two whitelisted actions exist, each a named function below.
#     There is no eval, no `bash -c "$string"`, no way to pass an
#     arbitrary command through this file -- adding a new action means
#     writing a new function and adding it to ALLOWED_ACTIONS, not
#     configuring one.
#   - Neither action reaches out and mutates anything on the remote
#     host. WAIO's own dispatch (waio.sh) already opens a fresh SSH
#     connection per call rather than holding a persistent one, so
#     there is no real remote session to "restart"; both actions are
#     scoped to this side: a fresh reachability probe, or clearing this
#     segment's own local recovery bookkeeping before that probe. This
#     is a deliberate MVP boundary, not an oversight -- it is why this
#     file never touches sshd_config, authorized_keys, firewall rules,
#     or anything resembling real network isolation. See this repo's
#     own README/ARCHITECTURE.md for how a future phase could extend
#     this safely if a concrete need for real remote intervention shows
#     up (the same judgment call Phase 40-A made and documented).
#   - Dry-run is the default. Real execution requires the explicit
#     --execute flag on every invocation -- there is no "remember my
#     choice" state.
#   - A failed recovery transitions to `failed` and escalates to a
#     human (segment_manager.sh's state machine only allows
#     failed->isolated via a human's explicit --force override, see
#     segment_manager.sh); this file never re-attempts on its own, so
#     there is no automatic retry loop by construction, not just by
#     convention.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"
source security/health_checker.sh

ALLOWED_ACTIONS="reconnect restart_worker_session"

action_allowed() {
  local action="$1" a
  for a in $ALLOWED_ACTIONS; do
    [ "$a" = "$action" ] && return 0
  done
  return 1
}

# action_reconnect SEGMENT_ID -- a fresh reachability probe, nothing
# else. Exists as its own named action (rather than folding into the
# post-action re-check every recovery already does) so the audit trail
# distinguishes "operator asked to just retry" from "the mandatory
# post-recovery verification".
action_reconnect() {
  local id="$1"
  health_check_segment "$id"
}

# action_restart_worker_session SEGMENT_ID -- clears this segment's own
# local recovery-attempt bookkeeping (RECOVERY_STATE_DIR/<id>.attempt,
# a timestamp marker only) before the same reachability probe
# action_reconnect does. WAIO holds no persistent remote session to
# actually restart (see file header) -- this is the safe, local
# equivalent, scoped to this side of the connection only.
RECOVERY_STATE_DIR="${RECOVERY_ENGINE_STATE_DIR:-$SECURITY_LIB_DIR/state/recovery}"
mkdir -p "$RECOVERY_STATE_DIR" 2>/dev/null || true

action_restart_worker_session() {
  local id="$1"
  date -u +%Y-%m-%dT%H:%M:%SZ > "$RECOVERY_STATE_DIR/$id.attempt"
  health_check_segment "$id"
}

run_action() {
  local action="$1" id="$2"
  case "$action" in
    reconnect) action_reconnect "$id" ;;
    restart_worker_session) action_restart_worker_session "$id" ;;
    *) echo "[RECOVERY] ERROR: '$action' is not a recognized action (this should be unreachable -- action_allowed should have caught it)" >&2; return 1 ;;
  esac
}

# escalate_to_human SEGMENT_ID REASON -- logs the escalation and makes
# a best-effort local notification (same osascript pattern as
# security/notify_shutdown.sh, Phase 40-B-1: fixed script text, the
# reason passed only via an environment variable read at AppleScript
# runtime, never interpolated into the script source -- reason text can
# carry attacker-influenced content the same way a shutdown reason can).
# Never fails the overall recovery flow if osascript is unavailable.
escalate_to_human() {
  local id="$1" reason="$2"
  segment_audit_log "$id" "human_escalation_required" "$reason" "escalate" "pending"
  echo "[RECOVERY] *** HUMAN ESCALATION REQUIRED for segment '$id': $reason ***"
  echo "[RECOVERY] Investigate, then manually clear with:"
  echo "[RECOVERY]   ./security/segment_manager.sh set $id isolated \"<what you found>\" --force"

  if command -v osascript >/dev/null 2>&1; then
    WAIO_RECOVERY_TITLE="WAIO Segment Recovery Failed"
    WAIO_RECOVERY_MSG="$id: $reason"
    export WAIO_RECOVERY_TITLE WAIO_RECOVERY_MSG
    osascript <<'APPLESCRIPT' >/dev/null 2>&1 || true
display notification (system attribute "WAIO_RECOVERY_MSG") with title (system attribute "WAIO_RECOVERY_TITLE")
APPLESCRIPT
  fi
}

# recover_segment SEGMENT_ID ACTION [--execute]
# Dry-run (no --execute): validates preconditions, reports what would
# happen, logs a recovery_dry_run audit event, changes nothing.
# Real (with --execute): isolated -> recovering -> {recovered, failed},
# with a mandatory post-action health check as the only source of
# truth for recovered vs. failed (the action's own exit status is not
# treated as proof of recovery by itself).
recover_segment() {
  local id="$1" action="$2" mode="${3:-}"
  local execute="false"
  [ "$mode" = "--execute" ] && execute="true"

  if ! action_allowed "$action"; then
    echo "[RECOVERY] ERROR: '$action' is not an allowed action. Allowed: $ALLOWED_ACTIONS" >&2
    segment_audit_log "$id" "recovery_rejected" "action not in whitelist: $action" "$action" "rejected"
    return 1
  fi

  local current
  current="$(segment_get_status "$id")"
  if [ "$current" != "isolated" ]; then
    echo "[RECOVERY] ERROR: segment '$id' is '$current', not 'isolated' -- recovery only runs on isolated segments." >&2
    segment_audit_log "$id" "recovery_rejected" "segment status is '$current', not 'isolated'" "$action" "rejected"
    return 1
  fi

  if [ "$execute" != "true" ]; then
    echo "[RECOVERY] DRY RUN: would run action '$action' on segment '$id' (currently isolated), then re-verify with a health check."
    echo "[RECOVERY] DRY RUN: no state change, no action executed. Re-run with --execute to actually perform this."
    segment_audit_log "$id" "recovery_dry_run" "dry-run requested for action '$action'" "$action" "simulated"
    return 0
  fi

  segment_transition "$id" "recovering" "recovery attempt started" "recovery_started" "$action" "in_progress" || return 1

  if run_action "$action" "$id"; then
    segment_transition "$id" "recovered" "action '$action' succeeded and post-recovery health check passed" "recovery_succeeded" "$action" "pass"
    return 0
  else
    segment_transition "$id" "failed" "action '$action' did not restore reachability" "recovery_failed" "$action" "fail"
    escalate_to_human "$id" "recovery action '$action' failed post-action health check"
    return 1
  fi
}

if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
  load_segments || exit 1
  [ -n "${1:-}" ] && [ -n "${2:-}" ] || {
    echo "Usage: $0 SEGMENT_ID ACTION [--execute]" >&2
    echo "  Allowed actions: $ALLOWED_ACTIONS" >&2
    echo "  Without --execute: dry-run only (default, safe)." >&2
    exit 1
  }
  segment_index "$1" >/dev/null || { echo "[RECOVERY] ERROR: unknown segment '$1'" >&2; exit 1; }
  recover_segment "$1" "$2" "${3:-}"
fi
