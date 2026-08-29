#!/bin/bash

REQUEST="$1"

if [ -z "$REQUEST" ]; then
  echo "ERROR: empty request"
  exit 1
fi

if [[ "$REQUEST" == *RESEARCH* ]]; then
  WORKER="research_worker"
elif [[ "$REQUEST" == *ANALYSIS* ]]; then
  WORKER="analysis_worker"
elif [[ "$REQUEST" == *RPI* ]]; then
  WORKER="rpi_worker"
elif [[ "$REQUEST" == *AI* ]]; then
  WORKER="ai_worker"
else
  WORKER="echo_worker"
fi

echo "[WAIO ROUTER] request: $REQUEST"
echo "[WAIO ROUTER] selected worker: $WORKER"

./workers/${WORKER}.sh "$REQUEST"
