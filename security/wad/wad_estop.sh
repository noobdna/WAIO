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
#   wad_estop.sh engage  [--operator NAME] [--reason TEXT]
#   wad_estop.sh release --operator NAME --reason TEXT
#   wad_estop.sh status
#
# Exit codes: status 0 = not engaged, 10 = engaged; 2 usage/refused/failed.
STATE_DEFAULT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/state/wad"
STOP_FILE="${WAD_STOP_FILE:-${WAD_STATE_DIR:-$STATE_DEFAULT}/STOP}"
STOP_DIR="$(dirname "$STOP_FILE")"
LOG="$STOP_DIR/estop.log"

die() { echo "wad_estop: $*" >&2; exit 2; }
now() { date -u +%Y-%m-%dT%H:%M:%SZ; }
clean() { printf '%s' "$1" | tr -d '\000-\037\177' | cut -c1-300; }

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
    mkdir -p "$STOP_DIR" || die "cannot create $STOP_DIR"
    chmod 700 "$STOP_DIR" 2>/dev/null || true
    tmp=$(mktemp "$STOP_DIR/.stop.XXXXXX") || die "cannot write in $STOP_DIR"
    printf 'engaged_at=%s\noperator=%s\nreason=%s\n' "$(now)" "$(clean "${operator:-unspecified}")" \
      "$(clean "${reason:-unspecified}")" > "$tmp" || die "cannot write $tmp"
    mv -f "$tmp" "$STOP_FILE" || die "cannot place $STOP_FILE"
    printf '%s engage operator=%s reason=%s\n' "$(now)" "$(clean "${operator:-unspecified}")" \
      "$(clean "${reason:-unspecified}")" >> "$LOG" 2>/dev/null || true
    echo "WAD emergency stop ENGAGED: $STOP_FILE"
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
