#!/bin/bash

REQUEST="$1"

if [ -z "$REQUEST" ]; then
  echo "ERROR: empty request"
  exit 1
fi

JOB_ID="$(date +%Y%m%d-%H%M%S)"
LOG="logs/$JOB_ID.log"
RESULT="results/$JOB_ID.txt"

echo "[WAIO] JOB_ID=$JOB_ID" | tee "$LOG"
echo "[WAIO] dispatching request" | tee -a "$LOG"

./orchestrator/router.sh "$REQUEST" | tee "$RESULT" | tee -a "$LOG"

echo "[WAIO] DONE" | tee -a "$LOG"
