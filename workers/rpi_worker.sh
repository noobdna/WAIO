#!/bin/bash
REQUEST="$1"

# DLP / Emergency Shutdown layer: last check before the real SSH call.
source security/lib.sh
if ! egress_check "192.168.1.150" "22" "" "" "RPI"; then
  echo "[RPI DISPATCH] ERROR: egress denied by DLP guard, emergency shutdown triggered -- SSH not attempted"
  exit 1
fi

echo "[RPI DISPATCH] sending to Raspberry Pi..."
ssh -o BatchMode=yes masa@192.168.1.150 "~/WAIO-worker/remote_worker.sh \"$REQUEST\""
