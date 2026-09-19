#!/bin/bash
# security/incident_learning/lock.sh -- Phase 78: portable (macOS/Linux,
# no `flock` dependency) mutual-exclusion lock for the Incident
# Learning Engine's own automated entry point
# (incident_learning_cron.sh, Step 6), closing the "overlapping cron
# runs / a manual run racing the scheduled one" gap Phase 75/76 both
# left explicitly open. Not executable on its own -- sourced only.
#
# DELIBERATELY a standalone copy of security/lib.sh's own
# _waio_mkdir_lock_acquire/_waio_mkdir_lock_release (Phase 65/67/70
# hardening: portable `mkdir`-based mutual exclusion, Phase 65's
# PID-liveness-gated stale-lock steal -- age alone is never enough --
# Phase 67's widened, caller-supplied retry budget), NOT a
# `source security/lib.sh` call. Every file in this domain explicitly
# never touches the Main/Guardian Control Plane (see
# knowledge_manager.sh's own header, "DuCoPA alignment, explicit,
# load-bearing") -- sourcing security/lib.sh here would pull in
# SHUTDOWN_LOCK/egress_check/guardian_* and their own state as a side
# effect, entangling two subsystems this domain's own design
# deliberately keeps apart. The algorithm itself is proven (three
# hardening phases, tests/audit_log_integrity_test.sh's own I10
# 12-way-concurrency case, and security/guardian.sh's own reuse of the
# exact same primitive) -- reused verbatim here, not reinvented; only
# the function names differ, to avoid any confusion with the
# Main-Control-Plane version if a future file in this domain were ever
# (mistakenly) to source both.
#
# UNLIKE security/lib.sh's own version's most common caller
# (audit_log()): this lock is meant to be used FAIL-CLOSED, not
# fail-open, on a caller-supplied retry-budget exhaustion.
# audit_log()'s own lock lets its caller proceed WITHOUT the lock after
# giving up, because logging must never block a real dispatch. Here,
# the entire point of this lock is to stop two full pipeline runs from
# processing the same candidates at once -- proceeding anyway after
# failing to acquire would defeat the only reason this file exists.
# incident_learning_cron.sh's own caller of il_lock_acquire treats a
# non-zero return as "another run is genuinely still in progress, skip
# this trigger entirely, log it, exit 0" -- never as permission to
# proceed unprotected. This is a caller-side contract (this file's own
# functions are unopinionated about it), so it is documented here for
# whoever reads this file next, not enforced by the functions below.

# il_lock_acquire LOCK_DIR MAX_WAIT_ITERATIONS -- 0 once acquired (the
# caller's own PID recorded at LOCK_DIR/holder.pid), 1 if it gave up
# waiting on a lock it correctly declined to steal (still genuinely
# held by a live process). A stale lock (its holder process is no
# longer alive) is reclaimed once it is more than 5s old, regardless of
# MAX_WAIT_ITERATIONS -- age alone only ever triggers the liveness
# check, never an unconditional steal (Phase 65's own fix, reused
# verbatim).
il_lock_acquire() {
  local lock_dir="$1" max_wait="$2" waited=0
  while ! mkdir "$lock_dir" 2>/dev/null; do
    if [ -d "$lock_dir" ]; then
      local lock_mtime now age
      # stat -f means "print mtime with this format" on macOS/BSD, but
      # "print FILESYSTEM status" (entirely different, and takes no %m
      # format spec) on Linux/GNU -- it does not error there, it just
      # silently succeeds with unrelated multi-line output, so a naive
      # `stat -f ... || stat -c ...` fallback would never trigger on
      # Linux (the exact bug security/lib.sh's own version fixed after
      # it broke stale-lock detection under real concurrent writers in
      # CI). Try BSD form, then GNU form, and validate each result is
      # actually a bare integer before trusting it.
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

# il_lock_release LOCK_DIR -- releases a lock this process holds.
il_lock_release() {
  rm -rf "$1" 2>/dev/null || true
}
