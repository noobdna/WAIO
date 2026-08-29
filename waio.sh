#!/bin/bash

source ~/.waio.env

REQUEST="$*"

if [ -z "$REQUEST" ]; then
  echo "[WAIO] ERROR: request required"
  exit 1
fi

echo "[WAIO] dispatching to RESEARCH WORKER..."
./workers/research_worker.sh "$REQUEST"
