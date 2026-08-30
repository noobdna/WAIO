#!/bin/bash
# thin WORKER-contract adapter for 800号機 (workers/800.json).
# self-contained SSH, same pattern as rpi_worker.sh: waio.sh dispatches this
# locally on 750, and this script does the remote hop itself.
# read-only diagnostics only, mirrors jobs/run-job.sh's system/identity checks.
# does not modify jobs/ or 800号機 itself.

REQUEST="$1"

if [ -z "$REQUEST" ]; then
  echo "[HOST800 WORKER] ERROR: empty request"
  exit 1
fi

REQUEST_UPPER="$(printf '%s' "$REQUEST" | tr '[:lower:]' '[:upper:]')"

if [[ "$REQUEST_UPPER" == *"IDENTITY"* ]]; then
  JOB="identity check"
  COMMAND='echo "[HOST] $(hostname)"; scutil --get ComputerName; scutil --get LocalHostName'
elif [[ "$REQUEST_UPPER" == *"SYSTEM"* ]]; then
  JOB="system check"
  COMMAND='echo "[HOST] $(hostname)"; echo "[OS] $(sw_vers -productVersion)"; uptime; df -h /'
else
  echo "[HOST800 WORKER] ERROR: unsupported job type in request. supported: system, identity"
  exit 1
fi

TARGET_HOST="$(python3 -c 'import json; print(json.load(open("workers/800.json"))["host"])')"
TARGET_USER="$(python3 -c 'import json; print(json.load(open("workers/800.json"))["user"])')"

echo "[HOST800 WORKER] job: $JOB"
echo "[HOST800 WORKER] target: ${TARGET_USER}@${TARGET_HOST}"

# DLP / Emergency Shutdown layer: last check before the real SSH call.
source security/lib.sh
if ! egress_check "$TARGET_HOST" "22" "" "" "HOST800"; then
  echo "[HOST800 WORKER] ERROR: egress denied by DLP guard, emergency shutdown triggered -- SSH not attempted"
  exit 1
fi

ssh -o BatchMode=yes "${TARGET_USER}@${TARGET_HOST}" "$COMMAND"

echo "[HOST800 WORKER] completed"
