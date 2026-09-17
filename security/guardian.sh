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
# Quarantine is available both as an explicit, manual action (see
# guardian_quarantine_agent/guardian_release_agent and their CLI wrappers)
# and, opt-in only, as an automatic policy driven by repeated critical
# events (see "Automatic quarantine policy" below, near
# _guardian_maybe_auto_quarantine) -- the automatic path only ever calls
# the same guardian_quarantine_agent function, never a second mechanism.
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
# GUARDIAN_CRITICAL_EVENTS_FILE: per-worker cumulative count of
# critical-severity guardian_notify_event calls, used only by the
# opt-in automatic quarantine policy below (_guardian_maybe_auto_quarantine).
# Same test-isolation override pattern as every other file in this
# module.
GUARDIAN_CRITICAL_EVENTS_FILE="${WAIO_GUARDIAN_CRITICAL_EVENTS_FILE:-$SECURITY_LIB_DIR/state/GUARDIAN_CRITICAL_EVENTS}"
mkdir -p "$(dirname "$GUARDIAN_STATE_FILE")" "$(dirname "$GUARDIAN_QUARANTINE_FILE")" "$(dirname "$GUARDIAN_CRITICAL_EVENTS_FILE")" 2>/dev/null || true

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
    critical)
      target="BLOCKED"
      _guardian_maybe_auto_quarantine "$worker" "$event_name" "$detail" "$run_id"
      ;;
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

# --- Automatic quarantine policy (opt-in, safe-by-default) ---------------
#
# Requirement: an automatic trigger policy for agent quarantine, without
# touching the real SHUTDOWN mechanism, any waio.sh dispatch gate, or the
# existing manual/CLI quarantine path (guardian_quarantine_agent/
# guardian_release_agent, and their CLI wrappers, are entirely unchanged
# in behavior -- this policy only ever *calls* guardian_quarantine_agent,
# the exact same function a human operator's future CLI action would
# call, never a parallel quarantine mechanism).
#
# Off by default (WAIO_GUARDIAN_AUTO_QUARANTINE unset): guardian_notify_event
# behaves exactly as before this policy existed -- zero behavior change,
# same as every other opt-in flag in this codebase (WAIO_AUTO_NOTIFY,
# WAIO_AUTO_DASHBOARD_REFRESH, WAIO_AUTO_GUARDIAN_NOTIFY).
#
# When on (WAIO_GUARDIAN_AUTO_QUARANTINE=1): counts critical-severity
# guardian_notify_event calls attributed to one specific, known worker
# (never "unknown"/empty -- guessing which agent to punish for an
# unattributed event is exactly the false-quarantine risk this policy
# must avoid) in GUARDIAN_CRITICAL_EVENTS_FILE. Only "critical" severity
# counts -- deliberately not "warning" (too noisy for an
# irreversible-until-released action) and not "shutdown" (that severity
# already forces a real WAIO shutdown via guardian_request_waio_shutdown,
# a stronger, already-existing response this policy must not duplicate
# or race with). Once a worker's count reaches
# WAIO_GUARDIAN_AUTO_QUARANTINE_THRESHOLD (default 3 -- a single
# anomalous critical event is deliberately NOT enough on its own, to stay
# safe against a one-off false positive), that one worker is quarantined.
#
# Cumulative, not time-windowed, by deliberate choice: the counter never
# decays on its own and is reset only by an explicit release
# (guardian_release_agent, see below) or by firing the auto-quarantine
# itself. A time-windowed counter could be gamed by spacing events out to
# always stay under threshold; a cumulative one cannot -- the safety
# trade-off is that an old, otherwise-forgotten critical event still
# counts toward the total until an operator actually reviews and
# releases the agent, which this codebase's own "no auto-recovery,
# recovery is manual and explicit" philosophy already treats as the
# correct default (see security/recover.sh's own header).

# _guardian_critical_event_count AGENT -- prints AGENT's current
# cumulative critical-event count (0 if AGENT has no recorded count yet).
# Uses awk's exact first-field match (not grep -F substring match) so one
# agent name being a substring of another (e.g. "ECHO" / "EXTRA_ECHO")
# can never cross-contaminate counts.
_guardian_critical_event_count() {
  local agent="$1"
  [ -f "$GUARDIAN_CRITICAL_EVENTS_FILE" ] || { echo 0; return 0; }
  awk -F'|' -v a="$agent" '$1 == a { c = $2 } END { print (c == "" ? 0 : c) }' "$GUARDIAN_CRITICAL_EVENTS_FILE" 2>/dev/null || echo 0
}

# _guardian_critical_event_set AGENT COUNT -- rewrites AGENT's counter
# line (dropping any prior line for the same agent first -- one line per
# agent, no unbounded growth).
_guardian_critical_event_set() {
  local agent="$1" count="$2" tmp
  tmp="$GUARDIAN_CRITICAL_EVENTS_FILE.tmp.$$"
  if [ -f "$GUARDIAN_CRITICAL_EVENTS_FILE" ]; then
    awk -F'|' -v a="$agent" '$1 != a' "$GUARDIAN_CRITICAL_EVENTS_FILE" > "$tmp" 2>/dev/null || : > "$tmp"
  else
    : > "$tmp"
  fi
  printf '%s|%s\n' "$agent" "$count" >> "$tmp"
  mv -f "$tmp" "$GUARDIAN_CRITICAL_EVENTS_FILE"
}

# guardian_reset_critical_events AGENT -- clears AGENT's counter back to
# zero (removes its line entirely; _guardian_critical_event_count then
# reads it as 0 again). Called from guardian_release_agent below so a
# resolved incident's history never counts toward a future, unrelated
# one -- a released-and-later-re-offending agent must rebuild the full
# threshold from scratch, not resume from where it left off.
guardian_reset_critical_events() {
  local agent="$1" tmp
  [ -f "$GUARDIAN_CRITICAL_EVENTS_FILE" ] || return 0
  tmp="$GUARDIAN_CRITICAL_EVENTS_FILE.tmp.$$"
  awk -F'|' -v a="$agent" '$1 != a' "$GUARDIAN_CRITICAL_EVENTS_FILE" > "$tmp" 2>/dev/null || : > "$tmp"
  mv -f "$tmp" "$GUARDIAN_CRITICAL_EVENTS_FILE"
  return 0
}

# _guardian_maybe_auto_quarantine WORKER EVENT_NAME DETAIL RUN_ID --
# called only from guardian_notify_event's "critical" branch above. See
# the policy header above for the full rationale; this is the mechanism:
# no-op unless opted in; no-op for an unattributed worker; increments and
# persists the counter; once it reaches the threshold, resets the counter
# to 0 and -- only if the worker isn't already quarantined (avoids a
# misleading duplicate audit event for an agent a human already
# quarantined manually) -- quarantines it via the existing
# guardian_quarantine_agent and logs one additional, clearly-labeled
# audit event (guardian_auto_quarantine_triggered) so the trail can tell
# an automatic decision apart from a manual one. Never touches
# SHUTDOWN_LOCK, trigger_shutdown, or any dispatch gate.
_guardian_maybe_auto_quarantine() {
  local worker="$1" event_name="$2" detail="$3" run_id="${4:-unknown}"
  [ "${WAIO_GUARDIAN_AUTO_QUARANTINE:-}" = "1" ] || return 0
  case "$worker" in ""|unknown) return 0 ;; esac

  local threshold="${WAIO_GUARDIAN_AUTO_QUARANTINE_THRESHOLD:-3}"
  local count=0
  count="$(_guardian_critical_event_count "$worker")"
  case "$count" in ''|*[!0-9]*) count=0 ;; esac
  count=$((count + 1))

  if [ "$count" -ge "$threshold" ]; then
    _guardian_critical_event_set "$worker" 0
    if ! guardian_is_quarantined "$worker"; then
      guardian_quarantine_agent "$worker" "auto-quarantined: $count cumulative critical-severity events reached threshold=$threshold, latest: $event_name: $detail" "$run_id"
      audit_log "guardian_auto_quarantine_triggered" "$run_id" "guardian" "$worker" "n/a" "quarantined" "count=$count threshold=$threshold latest_event=$event_name: $detail"
    fi
  else
    _guardian_critical_event_set "$worker" "$count"
  fi
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
  guardian_reset_critical_events "$agent"
  audit_log "guardian_agent_released" "$run_id" "guardian" "$agent" "n/a" "released" "$reason"
  return 0
}

# guardian_is_quarantined AGENT -- true (exit 0) iff AGENT is on the
# Guardian quarantine list.
guardian_is_quarantined() {
  [ -f "$GUARDIAN_QUARANTINE_FILE" ] && grep -Fxq "$1" "$GUARDIAN_QUARANTINE_FILE" 2>/dev/null
}
