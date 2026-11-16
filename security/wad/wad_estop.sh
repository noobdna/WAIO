#!/bin/bash
set -uo pipefail
# security/wad/wad_estop.sh -- emergency stop for WAIO Adaptive Defense.
#
# Ported from #212 (feat/wad-adaptive-defense-core) onto the #213/#214 stop
# file: the same path wad.py reads, WAD_STOP_FILE, or $WAD_STATE_DIR/STOP
# (default security/state/wad/STOP).
#
# Deliberately independent of the automated path: plain bash, sources
# nothing, never runs python or wad.py, and is the only WAD code that
# creates or releases the stop file. wad.py only reads it (lstat, before
# every command and again right before an executor would run) and treats an
# unreadable path as engaged. Engaging needs no identity, so anyone at the
# console can stop WAD. Releasing needs an operator name and a reason; the
# name is checked for shape and refused if it names an automated actor, but
# it is NOT authenticated. The released file is kept as evidence, never
# deleted. WAIO's SHUTDOWN.lock stops WAD independently of this file.
#
# engage also ends every process group the live runner
# (runner/wad_runner.py) recorded in $WAD_STATE_DIR/runner/active/<pgid>:
# SIGTERM to the whole group, then SIGKILL. This works even if the runner is
# hung or dead. A record whose leader is alive with a different start time
# (pid reused) is never killed; it is moved to runner/stale/. A record whose
# leader is gone still ends any remaining members of that group.
#
#   wad_estop.sh engage  [--operator NAME] [--reason TEXT]
#   wad_estop.sh release --operator NAME --reason TEXT
#   wad_estop.sh status
#
# Exit codes: status 0 = not engaged, 10 = engaged; 2 usage/refused/failed;
# engage 3 = stop file placed but a managed process group could not be
# confirmed ended (see estop.log).
STATE_DEFAULT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/state/wad"
STOP_FILE="${WAD_STOP_FILE:-${WAD_STATE_DIR:-$STATE_DEFAULT}/STOP}"
STOP_DIR="$(dirname "$STOP_FILE")"
LOG="$STOP_DIR/estop.log"
RUNNER_DIR="${WAD_STATE_DIR:-$STATE_DEFAULT}/runner"

die() { echo "wad_estop: $*" >&2; exit 2; }
now() { date -u +%Y-%m-%dT%H:%M:%SZ; }
clean() { printf '%s' "$1" | tr -d '\000-\037\177' | cut -c1-300; }

ps_start() {  # ps_start PID -- the same `ps -o lstart=` text the runner recorded
  local ps
  for ps in /bin/ps /usr/bin/ps; do
    if [ -x "$ps" ]; then
      LC_ALL=C "$ps" -o lstart= -p "$1" 2>/dev/null | tr -s ' \t' '  ' | sed 's/^ //; s/ $//'
      return 0
    fi
  done
  return 1
}

group_state() {  # group_state PGID -> alive | eperm | gone
  local out
  if out=$(kill -0 -- "-$1" 2>&1); then echo alive; return; fi
  case "$out" in *ermitted*) echo eperm ;; *) echo gone ;; esac
}

wait_gone() {  # wait_gone PGID -- up to 2 s
  local i
  for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
    [ "$(group_state "$1")" = gone ] && return 0
    sleep 0.1
  done
  [ "$(group_state "$1")" = gone ]
}

end_managed_groups() {  # prints a summary; returns 1 if any group may survive
  local f pgid recorded current own ended=0 failed=0 stale=0
  [ -d "$RUNNER_DIR/active" ] || { echo "managed process groups: none"; return 0; }
  own=$(ps -o pgid= -p $$ 2>/dev/null | tr -d ' ')
  for f in "$RUNNER_DIR/active"/*; do
    [ -f "$f" ] || continue
    case "$f" in *.tmp) continue ;; esac
    pgid=$(sed -n 1p "$f"); recorded=$(sed -n 2p "$f")
    if ! [[ "$pgid" =~ ^[0-9]+$ ]] || [ "$pgid" -le 1 ] || [ "$pgid" = "$own" ]; then
      mkdir -p "$RUNNER_DIR/stale" && mv -f "$f" "$RUNNER_DIR/stale/" 2>/dev/null
      stale=$((stale + 1)); continue
    fi
    if ! current=$(ps_start "$pgid"); then
      # No ps: a reused pid cannot be told apart, so never kill blind.
      printf '%s engage group=%s NOT ended: ps unavailable\n' "$(now)" "$pgid" >> "$LOG" 2>/dev/null
      failed=$((failed + 1)); continue
    fi
    if [ -n "$current" ] && { [ "$recorded" = unknown ] || [ "$current" != "$recorded" ]; }; then
      if [ "$recorded" = unknown ]; then
        # Cannot tell our group from a reused pid: do not kill, report.
        printf '%s engage group=%s NOT ended: start time was not recorded\n' "$(now)" "$pgid" >> "$LOG" 2>/dev/null
        failed=$((failed + 1)); continue
      fi
      mkdir -p "$RUNNER_DIR/stale" && mv -f "$f" "$RUNNER_DIR/stale/" 2>/dev/null
      printf '%s engage group=%s skipped: pid reused (recorded "%s", now "%s")\n' "$(now)" "$pgid" "$recorded" "$current" >> "$LOG" 2>/dev/null
      stale=$((stale + 1)); continue
    fi
    if [ "$(group_state "$pgid")" = gone ]; then
      rm -f "$f"; continue
    fi
    kill -TERM -- "-$pgid" 2>/dev/null
    if ! wait_gone "$pgid"; then
      kill -KILL -- "-$pgid" 2>/dev/null
      wait_gone "$pgid"
    fi
    if [ "$(group_state "$pgid")" = gone ]; then
      rm -f "$f"; ended=$((ended + 1))
      printf '%s engage group=%s ended\n' "$(now)" "$pgid" >> "$LOG" 2>/dev/null
    else
      failed=$((failed + 1))
      printf '%s engage group=%s NOT ended (%s)\n' "$(now)" "$pgid" "$(group_state "$pgid")" >> "$LOG" 2>/dev/null
    fi
  done
  echo "managed process groups: ended=$ended stale_records=$stale not_ended=$failed"
  [ "$failed" -eq 0 ]
}

cmd=${1:-}; [ $# -gt 0 ] && shift
operator=""; reason=""
while [ $# -gt 0 ]; do
  case "$1" in
    --operator) [ $# -ge 2 ] || die "--operator needs a value"; operator=$2; shift 2 ;;
    --reason) [ $# -ge 2 ] || die "--reason needs a value"; reason=$2; shift 2 ;;
    *) die "unknown argument: $1" ;;
  esac
done

case "$cmd" in
  engage)
    # Ending the managed groups does not depend on placing the stop file:
    # an unwritable state dir must not leave a live adapter running.
    placed=false
    if mkdir -p "$STOP_DIR" 2>/dev/null; then
      chmod 700 "$STOP_DIR" 2>/dev/null || true
      if tmp=$(mktemp "$STOP_DIR/.stop.XXXXXX" 2>/dev/null) \
        && printf 'engaged_at=%s\noperator=%s\nreason=%s\n' "$(now)" "$(clean "${operator:-unspecified}")" \
             "$(clean "${reason:-unspecified}")" > "$tmp" \
        && mv -f "$tmp" "$STOP_FILE"; then
        placed=true
      fi
    fi
    if $placed; then
      printf '%s engage operator=%s reason=%s\n' "$(now)" "$(clean "${operator:-unspecified}")" \
        "$(clean "${reason:-unspecified}")" >> "$LOG" 2>/dev/null || true
      echo "WAD emergency stop ENGAGED: $STOP_FILE"
    else
      echo "wad_estop: could not place $STOP_FILE; ending managed process groups anyway" >&2
    fi
    groups_ok=true
    end_managed_groups || groups_ok=false
    $placed || exit 2
    if ! $groups_ok; then
      echo "wad_estop: WARNING: stop is engaged but a managed process group may still be running (see $LOG)" >&2
      exit 3
    fi
    ;;
  release)
    [[ "$operator" =~ ^[A-Za-z0-9._@-]{1,64}$ ]] || die "release needs --operator NAME"
    shopt -s nocasematch
    case "$operator" in
      *claude*|*anthropic*|*openai*|*gpt*|*llm*|*bot*|*agent*|*autopilot*|*wad*|*automation*|*cron*|*launchd*|*daemon*|*system*|*root*)
        die "release refused: operator names an automated actor" ;;
    esac
    shopt -u nocasematch
    r=$(clean "$reason"); [ "${#r}" -ge 10 ] || die "release needs --reason of at least 10 characters"
    [ -e "$STOP_FILE" ] || [ -L "$STOP_FILE" ] || { echo "WAD emergency stop is not engaged"; exit 0; }
    mkdir -p "$STOP_DIR/released" || die "cannot create released/"
    dest="$STOP_DIR/released/STOP.$(date -u +%Y%m%dT%H%M%SZ).$$"
    mv "$STOP_FILE" "$dest" || die "cannot move $STOP_FILE"
    printf '%s release operator=%s reason=%s kept=%s authenticated=false\n' "$(now)" "$operator" "$r" "$dest" >> "$LOG"
    echo "WAD emergency stop released by $operator (not authenticated; kept as $dest)"
    ;;
  status)
    if [ -e "$STOP_FILE" ] || [ -L "$STOP_FILE" ]; then
      echo "ENGAGED: $STOP_FILE"; cat "$STOP_FILE" 2>/dev/null; exit 10
    fi
    if [ -d "$STOP_DIR" ] && ! ls "$STOP_DIR" > /dev/null 2>&1; then
      echo "ENGAGED (unreadable): $STOP_DIR"; exit 10
    fi
    echo "not engaged"
    ;;
  *) die "usage: wad_estop.sh engage|release|status [--operator NAME] [--reason TEXT]" ;;
esac
