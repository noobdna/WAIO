#!/bin/bash
set -uo pipefail

# jobs/run-job.sh -- ad-hoc SSH diagnostic runner against 800号機, kept
# intentionally standalone and NOT folded into workers/registry.conf/
# waio.sh (see ARCHITECTURE.md's "Deliberately not integrated" section
# -- this fix does not change that decision).
#
# DLP/audit-bypass fix (Red Team finding #4, 2026-09-13): this script
# used to open a real outbound SSH connection with NO egress_check and
# NO audit trail at all -- a complete bypass of the DLP/Emergency
# Shutdown layer every registry-dispatched worker already goes
# through, even while an Emergency Shutdown was active (README's own
# "every real outbound connection any worker makes is checked against
# security/egress_allowlist.conf first" claim was false for this
# file). Fixed by sourcing security/lib.sh and calling egress_check
# immediately before the real ssh call -- the same "last check before
# the real SSH call" placement every other worker already uses.
# egress_check's own existing behavior needed no new code: it already
# denies while a shutdown is active, denies an unlisted destination,
# and always calls audit_log on both the allow and deny path -- this
# fix is wiring only, not new logic. workers/800.json's host is the
# same destination workers/host800_worker.sh already dispatches
# through the registry path, so it is already present in a real
# deployment's security/egress_allowlist.conf -- no new allowlist
# entry is needed for THIS file specifically.
#
# See tests/jobs_taco_control_dlp_test.sh for the regression tests
# (fake ssh on PATH + a fixture workers/800.json, no real network).

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/security/lib.sh"

WORKER=$(python3 -c 'import json; print(json.load(open("workers/800.json"))["host"])')

case "${1:-}" in
  system)
    JOB="system check"
    COMMAND='echo "[HOST] $(hostname)"; echo "[OS] $(sw_vers -productVersion)"; uptime; df -h /'
    ;;
  identity)
    JOB="identity check"
    COMMAND='echo "[HOST] $(hostname)"; scutil --get ComputerName; scutil --get LocalHostName'
    ;;
  *)
    echo "Usage: $0 {system|identity}"
    exit 1
    ;;
esac

echo "=== WAIO JOB ==="
echo "TARGET: $WORKER"
echo "JOB: $JOB"
echo

# DLP / Emergency Shutdown layer: last check before the real SSH call.
if ! egress_check "$WORKER" "22" "" "" "JOBS_RUN_JOB"; then
  echo "ERROR: egress denied by DLP guard, emergency shutdown triggered -- SSH not attempted" >&2
  exit 1
fi

# payload_size_check is not applicable here (security audit finding,
# 2026-09-17): COMMAND is one of two fixed, hardcoded diagnostic
# strings selected by a "$1" keyword match above ({system|identity}) --
# "$1" itself never becomes part of the outbound SSH payload, so there
# is no attacker-influenceable growth vector to check.
RESPONSE="$(ssh "$WORKER" "$COMMAND")"
RC=$?

# secret_leak_check (security audit finding, 2026-09-17): the remote
# diagnostic output was previously streamed straight into results/ and
# stdout, unscanned, until now.
if ! secret_leak_check "$RESPONSE" "" "" "JOBS_RUN_JOB" "$WORKER:22"; then
  echo "ERROR: potential credential leak detected by DLP guard in response, emergency shutdown triggered -- response withheld" >&2
  exit 1
fi

echo "$RESPONSE" | tee "results/$(date +%Y%m%d-%H%M%S)-$1.txt"
exit "$RC"

echo
echo "=== JOB COMPLETE ==="
