#!/bin/bash
WORKER=$(python3 -c 'import json; print(json.load(open("workers/800.json"))["host"])')
ssh "$WORKER" 'echo "WAIO JOB RECEIVED"; hostname; sw_vers -productVersion'
