#!/bin/bash

source ~/.waio.env

REQUEST="$1"

if [ -z "$REQUEST" ]; then
  echo "[RESEARCH WORKER] ERROR: empty request"
  exit 1
fi

python3 - "$REQUEST" <<'PY'
import os
import sys
import json
import urllib.request

request = sys.argv[1]

data = {
    "model": "openai/gpt-4o-mini",
    "messages": [
        {
            "role": "system",
            "content": "You are the RESEARCH worker of WAIO (World AI Orchestrator). WAIO is a distributed AI orchestration system, not a womens organization. Focus on research, facts, evidence, and concise findings."
        },
        {
            "role": "user",
            "content": request
        }
    ]
}

req = urllib.request.Request(
    "https://openrouter.ai/api/v1/chat/completions",
    data=json.dumps(data).encode("utf-8"),
    headers={
        "Authorization": "Bearer " + os.environ["OPENROUTER_API_KEY"],
        "Content-Type": "application/json"
    },
    method="POST"
)

with urllib.request.urlopen(req, timeout=60) as r:
    result = json.load(r)

print("[RESEARCH WORKER] response:")
print(result["choices"][0]["message"]["content"])
PY
