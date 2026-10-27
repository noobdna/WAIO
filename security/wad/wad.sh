#!/bin/bash
set -uo pipefail
# security/wad/wad.sh -- CLI for WAIO Adaptive Defense (WAD).
# All logic lives in wad_cli.py / wad_lib.py; see their headers for the
# safety boundary. Default mode is dry run; --execute runs only the
# automatic local actions (observe, monitor_up, monitor_down, warn).
# Destructive actions are written out as approval requests, never run.
#
#   wad.sh assess        --in EVENTS.jsonl | --decisions REPORT.json [--policy F]
#   wad.sh respond       --in ... | --decisions ... [--execute] [--policy F]
#   wad.sh recover       --entity E --operator NAME --reason TEXT [--execute]
#   wad.sh breaker-reset --operator NAME --reason TEXT
#   wad.sh policy-check FILE | policy-diff OLD NEW | audit-verify | status
#
# Emergency stop: security/wad/wad_estop.sh (independent of this CLI).
WAD_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export PYTHONDONTWRITEBYTECODE=1
exec python3 -I "$WAD_DIR/wad_cli.py" "$@"
