#!/bin/bash

REQUEST="$1"

if [ -z "$REQUEST" ]; then
  echo "[AI WORKER] ERROR: empty request"
  exit 1
fi

source ~/.waio.env

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
            "content": "You are the AI worker of WAIO. Answer concisely."
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

print("[AI WORKER] response:")
print(result["choices"][0]["message"]["content"])
PY
