#!/bin/bash

echo "================================"
echo "        WAIO ORCHESTRATOR"echo "        
echo "================================"
echo "Commander : 750"
echo "Worker    : 800"
echo "Status    : ONLINE"
echo
- GPT / Claude / Gemini / OpenRouter の変更"
echo ": system check"
echo

read -p "WAIO> " JOB

echo
echo ">>> 800..."
echo ">>> JOB: $JOB"
echo

WORKER=$(python3 -c 'import json; print(json.load(open("workers/800.json"))["host"])')

ssh "$WORKER" "
echo '[800] JOB RECEIVED'
echo '[800] $JOB'
echo '[800] HOST: '\$(hostname)
echo '[800] OS: '\$(sw_vers -productVersion)
"

echo
echo ">>> JOB COMPLETE"
