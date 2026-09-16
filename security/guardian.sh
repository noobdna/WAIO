#!/bin/bash
# security/guardian.sh -- DuCoPA (Dual Control Plane Architecture) Guardian
# Control Plane. Sourced by security/lib.sh, so every existing call site
# that already does `source security/lib.sh` (waio.sh, every worker) gets
# this for free -- no new source line needed at any of those 8 sites.
#
# WAIO's normal orchestration (Router, TASK CLASSIFICATION, pipeline
# execution, result aggregation, and the DLP/Emergency Shutdown layer in
# this same directory) is the Main Control Plane. This file is the
# Guardian / Rescue plane's WAIO-side half: a state machine WAIO can be
# told about (guardian_notify_event) and gated on (guardian_is_blocking /
# guardian_is_quarantined), plus the primitives a Guardian-side decision
# would use to intervene (block new tasks, quarantine an agent, force a
# real WAIO shutdown, or require a human to explicitly approve resuming).
#
# Explicitly NOT attempted here (see ARCHITECTURE.md Phase 30-39, the
# Guardian Recovery Protocol work this builds on): no new authentication
# mechanism, no claim that this alone gives Takomachi authority WAIO's own
# operator doesn't already have while both run as the same local user on
# the same machine. That separation (Option D: a physically separate
# machine, 800号機, SSH-key authenticated) already exists for the
# *recovery* direction -- security/recover.sh --guardian-confirm,
# security/guardian_recover_wrapper.sh, security/guardian_recover_trigger.sh.
# This file adds the *detection/intervention* direction WAIO can drive
# locally today (matching Phase 39's lowest-risk option (a): notify and
# gate, never grant new authority) -- a real Takomachi process across that
# same separated channel can drive it exactly the same way a future phase
# chooses to wire it up; nothing here assumes that wiring exists yet.
#
# Five states, ordered by severity (guardian_state_rank below):
#   NORMAL                   -- ordinary operation, nothing gated
#   WARNING                  -- something noteworthy happened; logged, not
#                               yet blocking new dispatch
#   BLOCKED                  -- new task dispatch refused (waio.sh gates on
#                               guardian_is_blocking before every dispatch)
#   HUMAN_APPROVAL_REQUIRED  -- same gate as BLOCKED, but framed as
#                               "needs an explicit human decision", cleared
#                               only via security/guardian_approve.sh
#   SHUTDOWN                 -- the Guardian's own mirror of a real WAIO
#                               Emergency Shutdown (security/lib.sh's
#                               existing SHUTDOWN_LOCK/trigger_shutdown --
#                               reused here, never replaced or duplicated).
#                               Only clearable via security/recover.sh,
#                               same as the real lock it mirrors.
#
# Fail-closed, matching this codebase's existing DLP philosophy: an absent
# state file means NORMAL (nothing has ever happened -- a fresh checkout,
# or a fresh deployment, must not start pre-blocked), but a *present* file
# whose content is not one of the five names above is treated as BLOCKED,
# never as NORMAL -- a corrupted or truncated state file must never be
# silently read as "everything is fine".

GUARDIAN_STATE_FILE="${WAIO_GUARDIAN_STATE_FILE:-$SECURITY_LIB_DIR/state/GUARDIAN_STATE}"
GUARDIAN_QUARANTINE_FILE="${WAIO_GUARDIAN_QUARANTINE_FILE:-$SECURITY_LIB_DIR/state/GUARDIAN_QUARANTINE}"
mkdir -p "$(dirname "$GUARDIAN_STATE_FILE")" "$(dirname "$GUARDIAN_QUARANTINE_FILE")" 2>/dev/null || true

# guardian_state_rank STATE -- prints an integer severity rank, higher =
# more restrictive. Used so automatic escalation (guardian_notify_event)
# can never silently *downgrade* an already-more-severe state.
guardian_state_rank() {
  case "$1" in
    NORMAL) echo 0 ;;
    WARNING) echo 1 ;;
    BLOCKED) echo 2 ;;
    HUMAN_APPROVAL_REQUIRED) echo 3 ;;
    SHUTDOWN) echo 4 ;;
    *) echo -1 ;;
  esac
}

# guardian_valid_state STATE -- true (exit 0) iff STATE is one of the five
# known states.
guardian_valid_state() {
  [ "$(guardian_state_rank "$1")" -ge 0 ]
}

# guardian_get_state -- prints the current Guardian state. Absent file ->
# NORMAL. Present-but-invalid content -> BLOCKED (fail closed), with a
# stderr warning so the corruption isn't silent.
guardian_get_state() {
  if [ ! -f "$GUARDIAN_STATE_FILE" ]; then
    echo "NORMAL"
    return 0
  fi
  local content=""
  content="$(cat "$GUARDIAN_STATE_FILE" 2>/dev/null)" || content=""
  content="$(printf '%s' "$content" | tr -d '[:space:]')"
  if [ -z "$content" ]; then
    echo "NORMAL"
    return 0
  fi
  if guardian_valid_state "$content"; then
    echo "$content"
  else
    echo "[WAIO GUARDIAN] WARNING: $GUARDIAN_STATE_FILE contains an unrecognized state ('$content') -- treating as BLOCKED (fail closed)." >&2 || true
    echo "BLOCKED"
  fi
  return 0
}

# guardian_set_state NEW_STATE REASON [RUN_ID] [ACTOR] -- pure state
# transition: validates NEW_STATE, writes it, and records a
# guardian_state_changed audit event. Never itself touches SHUTDOWN_LOCK
# (see guardian_request_waio_shutdown for the one function that does) --
# keeps this the single place state is written, and keeps "mirror the
# Guardian's own state" and "actually stop WAIO" as two explicit, separate
# actions per requirement 7 (reuse SHUTDOWN.lock, don't fold new behavior
# silently into it).
guardian_set_state() {
  local new_state="$1" reason="${2:-no reason given}" run_id="${3:-unknown}" actor="${4:-unknown}"
  if ! guardian_valid_state "$new_state"; then
    echo "[WAIO GUARDIAN] ERROR: refusing to set unknown Guardian state '$new_state'" >&2 || true
    return 1
  fi
  local old_state=""
  old_state="$(guardian_get_state)"
  printf '%s\n' "$new_state" > "$GUARDIAN_STATE_FILE"
  audit_log "guardian_state_changed" "$run_id" "guardian" "$actor" "n/a" "$new_state" "$old_state -> $new_state: $reason"
  return 0
}

# guardian_is_blocking -- true (exit 0) iff the current state means new
# task dispatch must be refused (BLOCKED, HUMAN_APPROVAL_REQUIRED, or
# SHUTDOWN). WARNING is deliberately non-blocking -- it is a caution
# signal, not a stop signal; is_shutdown_active (security/lib.sh's own
# real lock) is checked separately by every existing call site and is
# unaffected by this function either way.
guardian_is_blocking() {
  case "$(guardian_get_state)" in
    BLOCKED|HUMAN_APPROVAL_REQUIRED|SHUTDOWN) return 0 ;;
    *) return 1 ;;
  esac
}

# guardian_notify_event EVENT_NAME SEVERITY DETAIL [RUN_ID] [WORKER] --
# the WAIO -> Guardian interface (requirement 5). Any WAIO-side code can
# call this to tell the Guardian plane something happened, without itself
# having to know about state machines or thresholds.
#
# SEVERITY is one of: info (logged only, never changes state),
# warning (escalates to at least WARNING), critical (escalates to at
# least BLOCKED), shutdown (escalates to SHUTDOWN AND forces a real WAIO
# shutdown via guardian_request_waio_shutdown -- use only for a genuine
# "stop everything" signal). Escalation only ever raises the state's rank,
# never lowers it -- a WARNING-severity event arriving while already
# BLOCKED leaves BLOCKED in place.
guardian_notify_event() {
  local event_name="$1" severity="${2:-info}" detail="${3:-}" run_id="${4:-unknown}" worker="${5:-unknown}"
  audit_log "guardian_event_notified" "$run_id" "guardian" "$worker" "n/a" "$severity" "$event_name: $detail"

  local target=""
  case "$severity" in
    warning) target="WARNING" ;;
    critical) target="BLOCKED" ;;
    shutdown)
      guardian_request_waio_shutdown "$event_name: $detail" "$run_id" "guardian-notify" "$worker" "n/a"
      return 0
      ;;
    *) return 0 ;;
  esac

  local current=""
  current="$(guardian_get_state)"
  if [ "$(guardian_state_rank "$target")" -gt "$(guardian_state_rank "$current")" ]; then
    guardian_set_state "$target" "auto-escalated by event '$event_name': $detail" "$run_id" "waio-auto"
  fi
  return 0
}

# guardian_request_waio_shutdown REASON [RUN_ID] [STAGE] [WORKER] [DESTINATION]
# -- requirement 6's "必要に応じてWAIO停止要求": sets the Guardian's own
# state to SHUTDOWN AND reuses security/lib.sh's existing trigger_shutdown
# to trip the real SHUTDOWN_LOCK -- the actual production safety
# mechanism, not a parallel one. Recovery for a Guardian-triggered
# shutdown goes through the exact same security/recover.sh
# ([--guardian-]confirm) as any other shutdown; recover.sh also resets the
# Guardian state back to NORMAL when it clears a lock that got here via
# this path (see security/recover.sh).
guardian_request_waio_shutdown() {
  local reason="$1" run_id="${2:-unknown}" stage="${3:-guardian}" worker="${4:-guardian}" destination="${5:-n/a}"
  guardian_set_state "SHUTDOWN" "$reason" "$run_id" "guardian"
  trigger_shutdown "$reason" "$run_id" "$stage" "$worker" "$destination"
}

# guardian_require_human_approval REASON [RUN_ID] -- requirement 6's
# "人間承認待ちに遷移". Softer than SHUTDOWN: blocks new dispatch
# (guardian_is_blocking) without touching the real SHUTDOWN_LOCK. Cleared
# only via security/guardian_approve.sh, mirroring security/recover.sh's
# explicit-human-confirmation pattern for the real shutdown lock.
guardian_require_human_approval() {
  local reason="$1" run_id="${2:-unknown}"
  guardian_set_state "HUMAN_APPROVAL_REQUIRED" "$reason" "$run_id" "guardian"
}

# guardian_approve REASON [RUN_ID] [ACTOR] -- the human-confirmation path
# back to NORMAL from WARNING/BLOCKED/HUMAN_APPROVAL_REQUIRED. Refuses on
# SHUTDOWN (that state mirrors the real SHUTDOWN_LOCK and must be cleared
# via security/recover.sh, so the two recovery paths never diverge) and
# refuses without a non-empty reason, matching security/recover.sh's own
# require-a-reason discipline. See security/guardian_approve.sh for the
# CLI wrapper around this.
guardian_approve() {
  local reason="$1" run_id="${2:-unknown}" actor="${3:-operator}"
  local current=""
  current="$(guardian_get_state)"
  if [ "$current" = "SHUTDOWN" ]; then
    echo "[WAIO GUARDIAN] ERROR: state is SHUTDOWN -- that mirrors the real Emergency Shutdown lock; clear it with security/recover.sh (--confirm or --guardian-confirm), not this command." >&2 || true
    return 1
  fi
  if [ "$current" = "NORMAL" ]; then
    echo "[WAIO GUARDIAN] Already NORMAL. Nothing to do."
    return 0
  fi
  if [ -z "$reason" ]; then
    echo "[WAIO GUARDIAN] ERROR: refusing to clear Guardian state '$current' without a reason." >&2 || true
    return 1
  fi
  guardian_set_state "NORMAL" "$reason" "$run_id" "$actor"
  audit_log "guardian_approval_granted" "$run_id" "guardian" "$actor" "n/a" "cleared" "$reason (was $current)"
  return 0
}

# guardian_quarantine_agent AGENT REASON [RUN_ID] -- requirement 6's
# "対象エージェント隔離". AGENT is a worker/registry NAME (see
# workers/registry.conf); waio.sh refuses to dispatch to a quarantined
# name before it ever runs the worker script. Dedup: quarantining an
# already-quarantined agent is a harmless no-op (idempotent, like
# trigger_shutdown).
guardian_quarantine_agent() {
  local agent="$1" reason="${2:-no reason given}" run_id="${3:-unknown}"
  if [ -f "$GUARDIAN_QUARANTINE_FILE" ] && grep -Fxq "$agent" "$GUARDIAN_QUARANTINE_FILE" 2>/dev/null; then
    return 0
  fi
  printf '%s\n' "$agent" >> "$GUARDIAN_QUARANTINE_FILE"
  audit_log "guardian_agent_quarantined" "$run_id" "guardian" "$agent" "n/a" "quarantined" "$reason"
  return 0
}

# guardian_release_agent AGENT REASON [RUN_ID] -- the reverse of
# guardian_quarantine_agent. No-op (exit 0) if AGENT was never
# quarantined.
guardian_release_agent() {
  local agent="$1" reason="${2:-no reason given}" run_id="${3:-unknown}"
  if [ ! -f "$GUARDIAN_QUARANTINE_FILE" ] || ! grep -Fxq "$agent" "$GUARDIAN_QUARANTINE_FILE" 2>/dev/null; then
    return 0
  fi
  local tmp="$GUARDIAN_QUARANTINE_FILE.tmp.$$"
  grep -Fxv "$agent" "$GUARDIAN_QUARANTINE_FILE" > "$tmp" 2>/dev/null || : > "$tmp"
  mv -f "$tmp" "$GUARDIAN_QUARANTINE_FILE"
  audit_log "guardian_agent_released" "$run_id" "guardian" "$agent" "n/a" "released" "$reason"
  return 0
}

# guardian_is_quarantined AGENT -- true (exit 0) iff AGENT is on the
# Guardian quarantine list.
guardian_is_quarantined() {
  [ -f "$GUARDIAN_QUARANTINE_FILE" ] && grep -Fxq "$1" "$GUARDIAN_QUARANTINE_FILE" 2>/dev/null
}
