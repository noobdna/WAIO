#!/bin/bash
REQUEST="$1"

echo "[RPI DISPATCH] sending to Raspberry Pi..."
ssh -o BatchMode=yes masa@192.168.1.150 "~/WAIO-worker/remote_worker.sh \"$REQUEST\""
