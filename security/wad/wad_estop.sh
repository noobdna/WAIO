#!/bin/bash
set -uo pipefail
# security/wad/wad_estop.sh -- emergency stop for WAIO Adaptive Defense.
#
# Deliberately independent of the automated path: plain bash, sources
# nothing, imports nothing from wad_cli.py/wad_lib.py, and is the only
# code that creates or releases the ESTOP file. wad_cli.py only reads
# it (before a run and before every step), and treats an unreadable
# path as engaged. Engaging needs no identity, so anyone at the console
# can stop WAD; releasing needs an operator name and a reason, and the
# released file is kept as evidence, never deleted.
#
#   wad_estop.sh engage  [--operator NAME] [--reason TEXT]
#   wad_estop.sh release --operator NAME --reason TEXT
#   wad_estop.sh status
#
# Exit codes: status 0 = not engaged, 10 = engaged; 2 usage/refused.
ESTOP_DIR_DEFAULT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/state/wad_estop"
ESTOP_FILE="${WAD_ESTOP_FILE:-$ESTOP_DIR_DEFAULT/ESTOP}"
ESTOP_DIR="$(dirname "$ESTOP_FILE")"
LOG="$ESTOP_DIR/estop.log"

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
    mkdir -p "$ESTOP_DIR" || die "cannot create $ESTOP_DIR"
    chmod 700 "$ESTOP_DIR" 2>/dev/null || true
    tmp=$(mktemp "$ESTOP_DIR/.estop.XXXXXX") || die "cannot write in $ESTOP_DIR"
    printf 'engaged_at=%s\noperator=%s\nreason=%s\n' "$(now)" "$(clean "${operator:-unspecified}")" \
      "$(clean "${reason:-unspecified}")" > "$tmp"
    mv -f "$tmp" "$ESTOP_FILE" || die "cannot place $ESTOP_FILE"
    printf '%s engage operator=%s reason=%s\n' "$(now)" "$(clean "${operator:-unspecified}")" \
      "$(clean "${reason:-unspecified}")" >> "$LOG"
    echo "WAD emergency stop ENGAGED: $ESTOP_FILE"
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
    [ -e "$ESTOP_FILE" ] || [ -L "$ESTOP_FILE" ] || { echo "WAD emergency stop is not engaged"; exit 0; }
    mkdir -p "$ESTOP_DIR/released" || die "cannot create released/"
    dest="$ESTOP_DIR/released/ESTOP.$(date -u +%Y%m%dT%H%M%SZ).$$"
    mv "$ESTOP_FILE" "$dest" || die "cannot move $ESTOP_FILE"
    printf '%s release operator=%s reason=%s kept=%s\n' "$(now)" "$operator" "$r" "$dest" >> "$LOG"
    echo "WAD emergency stop released by $operator (kept as $dest)"
    ;;
  status)
    if [ -e "$ESTOP_FILE" ] || [ -L "$ESTOP_FILE" ]; then
      echo "ENGAGED: $ESTOP_FILE"; cat "$ESTOP_FILE" 2>/dev/null; exit 10
    fi
    if ! ls "$ESTOP_DIR" >/dev/null 2>&1 && [ -d "$ESTOP_DIR" ]; then
      echo "ENGAGED (unreadable): $ESTOP_DIR"; exit 10
    fi
    echo "not engaged"
    ;;
  *) die "usage: wad_estop.sh engage|release|status [--operator NAME] [--reason TEXT]" ;;
esac
