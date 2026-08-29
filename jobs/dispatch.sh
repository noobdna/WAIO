#!/bin/bash

WORKER=$(python3 -c 'import json; print(json.load(open("workers/800.json"))["host"])')

echo "=== WAIO DISPATCH ==="
echo "TARGET: $WORKER"
echo "JOB: system check"
echo

ssh "$WORKER" '
echo "[WORKER] $(hostname)"
echo "[OS] $(sw_vers -productVersion)"
echo "[UPTIME]"
uptime
echo "[DISK]"
df -h /
'
