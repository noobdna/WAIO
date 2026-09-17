#!/bin/bash
set -uo pipefail

# jobs/test-job.sh -- minimal SSH liveness check against 800号機, kept
# intentionally standalone and NOT folded into workers/registry.conf/
# waio.sh (see ARCHITECTURE.md's "Deliberately not integrated" section,
# and jobs/run-job.sh's own header for the full DLP/audit-bypass fix
# writeup this file shares -- Red Team finding #4, 2026-09-13).

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/security/lib.sh"

WORKER=$(python3 -c 'import json; print(json.load(open("workers/800.json"))["host"])')

# DLP / Emergency Shutdown layer: last check before the real SSH call.
if ! egress_check "$WORKER" "22" "" "" "JOBS_TEST_JOB"; then
  echo "ERROR: egress denied by DLP guard, emergency shutdown triggered -- SSH not attempted" >&2
  exit 1
fi

# payload_size_check is not applicable here (security audit finding,
# 2026-09-17): the remote command below is a fixed, hardcoded string
# with no attacker-influenceable content at all.
RESPONSE="$(ssh "$WORKER" 'echo "WAIO JOB RECEIVED"; hostname; sw_vers -productVersion')"
RC=$?

# secret_leak_check (security audit finding, 2026-09-17): the remote
# diagnostic output was previously streamed straight to stdout,
# unscanned, until now.
if ! secret_leak_check "$RESPONSE" "" "" "JOBS_TEST_JOB" "$WORKER:22"; then
  echo "ERROR: potential credential leak detected by DLP guard in response, emergency shutdown triggered -- response withheld" >&2
  exit 1
fi

echo "$RESPONSE"
exit "$RC"
