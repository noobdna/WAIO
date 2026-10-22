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
# Owner-token release and mutex-serialized stale steal: identical to
# security/lib.sh's _waio_mkdir_lock_acquire, see its header
# (tests/mkdir_lock_ownership_test.sh).
il_lock_acquire() {
  local lock_dir="$1" max_wait="$2" waited=0
  local token_var="_WAIO_LOCK_TOKEN_${lock_dir//[!A-Za-z0-9]/_}"
  while ! mkdir "$lock_dir" 2>/dev/null; do
    if [ -d "$lock_dir" ] && il_lock_is_stale "$lock_dir"; then
      if mkdir "$lock_dir.steal" 2>/dev/null; then
        il_lock_is_stale "$lock_dir" && { rm -rf "$lock_dir" 2>/dev/null || true; }
        rmdir "$lock_dir.steal" 2>/dev/null || true
        continue
      elif [ "$(il_lock_age "$lock_dir.steal")" -gt 5 ]; then
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

# il_lock_release LOCK_DIR -- releases a lock this process holds.
il_lock_release() {
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

# il_lock_age DIR -- seconds since DIR's mtime; 0 when the mtime
# cannot be read (see the unreadable-mtime note below).
il_lock_age() {
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

# il_lock_is_stale LOCK_DIR -- 0 if LOCK_DIR is older than 5s
# AND its recorded holder is missing or no longer alive (age alone is
# never enough, Phase 65).
il_lock_is_stale() {
  local lock_dir="$1" holder_pid=""
  [ "$(il_lock_age "$lock_dir")" -gt 5 ] || return 1
  holder_pid="$(cat "$lock_dir/holder.pid" 2>/dev/null)" || holder_pid=""
  case "$holder_pid" in
    ''|*[!0-9]*) holder_pid="" ;;
  esac
  [ -z "$holder_pid" ] || ! kill -0 "$holder_pid" 2>/dev/null
}
