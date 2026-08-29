#!/bin/bash

WORKER=$(python3 -c 'import json; print(json.load(open("workers/800.json"))["host"])')

case "$1" in
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

ssh "$WORKER" "$COMMAND" | tee "results/$(date +%Y%m%d-%H%M%S)-$1.txt"

echo
echo "=== JOB COMPLETE ==="
