#!/bin/bash
set -uo pipefail

# security/health_checker.sh -- Phase 49 (Segment Recovery MVP):
# timeout+retry TCP reachability checks, and the detection side of the
# Incident State Machine (normal <-> suspicious <-> isolated).
#
# Deliberately a raw TCP connect (`nc -z`), not a dispatch through
# waio.sh/a worker script: a worker dispatch (e.g. HOST800's "system
# check") opens a real SSH session and runs a remote command every
# time it's called, which is too heavy/intrusive to run on a health
# check's own timeout+retry loop. A TCP-level check answers "is this
# segment reachable at all" -- the right question for detecting an
# outage -- without repeatedly exercising SSH auth against real
# devices. Deeper (auth-level) health checking, if ever needed, should
# reuse workers/registry.conf's WORKER_NAME field this file already
# cross-references, as a later phase.
#
# health_check_and_transition() is the only function here that writes
# segment state, and it only ever drives the detection edges
# (normal->suspicious->isolated, or suspicious->normal on recovery of
# the underlying signal). It never touches recovering/recovered/failed
# -- those belong to security/recovery_engine.sh.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"
source security/segment_manager.sh

HEALTH_CHECK_TIMEOUT="${HEALTH_CHECK_TIMEOUT:-3}"
HEALTH_CHECK_RETRIES="${HEALTH_CHECK_RETRIES:-3}"
HEALTH_CHECK_RETRY_DELAY="${HEALTH_CHECK_RETRY_DELAY:-1}"

# health_check_segment SEGMENT_ID [TIMEOUT] [RETRIES] -- up to RETRIES
# TCP connect attempts, TIMEOUT seconds each, a fixed (not exponential,
# not unbounded) HEALTH_CHECK_RETRY_DELAY between attempts. Returns 0
# on the first success, 1 if every attempt failed. Always logs exactly
# one segment_audit_log event per call, win or lose.
health_check_segment() {
  local id="$1" timeout="${2:-$HEALTH_CHECK_TIMEOUT}" retries="${3:-$HEALTH_CHECK_RETRIES}"
  local host port attempt=1 ok="false"

  host="$(segment_host "$id")" || { echo "[HEALTH] ERROR: unknown segment '$id'" >&2; return 1; }
  port="$(segment_port "$id")"

  while [ "$attempt" -le "$retries" ]; do
    if nc -z -w "$timeout" "$host" "$port" >/dev/null 2>&1; then
      ok="true"
      break
    fi
    [ "$attempt" -lt "$retries" ] && sleep "$HEALTH_CHECK_RETRY_DELAY"
    attempt=$((attempt + 1))
  done

  if [ "$ok" = "true" ]; then
    segment_audit_log "$id" "health_check" "TCP connect succeeded on attempt $attempt/$retries (timeout=${timeout}s)" "tcp_connect" "pass"
    return 0
  else
    segment_audit_log "$id" "health_check" "TCP connect failed after $retries/$retries attempts (timeout=${timeout}s each)" "tcp_connect" "fail"
    return 1
  fi
}

# health_check_and_transition SEGMENT_ID [TIMEOUT] [RETRIES] -- runs
# health_check_segment, then drives at most one state-machine edge
# based on (current status, pass/fail):
#   normal      + fail -> suspicious   (first sign of trouble)
#   suspicious  + fail -> isolated     (confirmed on a second check cycle)
#   suspicious  + pass -> normal       (false alarm, signal recovered on its own)
#   normal      + pass -> no-op (already healthy)
#   isolated/recovering/recovered/failed -> no-op regardless of the
#     check result; those statuses are recovery_engine.sh's to manage,
#     this function only ever observes them.
# Never called automatically/on a timer by this file itself -- a human
# or a future scheduled invocation decides when to check.
health_check_and_transition() {
  local id="$1" timeout="${2:-$HEALTH_CHECK_TIMEOUT}" retries="${3:-$HEALTH_CHECK_RETRIES}"
  local current passed="false"

  current="$(segment_get_status "$id")"
  if health_check_segment "$id" "$timeout" "$retries"; then
    passed="true"
  fi

  case "$current:$passed" in
    normal:false)
      segment_transition "$id" "suspicious" "health check failed" "anomaly_detected" "health_check" "fail"
      ;;
    suspicious:false)
      segment_transition "$id" "isolated" "health check failed again (confirmed)" "failure_confirmed" "health_check" "fail"
      ;;
    suspicious:true)
      segment_transition "$id" "normal" "health check recovered on its own" "false_alarm_cleared" "health_check" "pass"
      ;;
    *)
      # normal:true (already healthy), or isolated/recovering/recovered/
      # failed regardless of result: no state-machine action here.
      return 0
      ;;
  esac
}

if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
  load_segments || exit 1
  case "${1:-}" in
    check)
      [ -n "${2:-}" ] || { echo "Usage: $0 check SEGMENT_ID [TIMEOUT] [RETRIES]" >&2; exit 1; }
      health_check_segment "$2" "${3:-}" "${4:-}"
      ;;
    check-all)
      rc=0
      for id in "${SEG_IDS[@]}"; do
        health_check_segment "$id" || rc=1
      done
      exit "$rc"
      ;;
    monitor)
      [ -n "${2:-}" ] || { echo "Usage: $0 monitor SEGMENT_ID [TIMEOUT] [RETRIES]" >&2; exit 1; }
      health_check_and_transition "$2" "${3:-}" "${4:-}"
      ;;
    monitor-all)
      for id in "${SEG_IDS[@]}"; do
        health_check_and_transition "$id"
      done
      ;;
    *)
      echo "Usage: $0 {check SEGMENT_ID [TIMEOUT] [RETRIES]|check-all|monitor SEGMENT_ID [TIMEOUT] [RETRIES]|monitor-all}" >&2
      exit 1
      ;;
  esac
fi
