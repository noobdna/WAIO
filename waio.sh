#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

source ~/.waio.env

REGISTRY="workers/registry.conf"
REQUEST="$*"

if [ -z "$REQUEST" ]; then
  echo "[WAIO] ERROR: request required"
  exit 1
fi

if [ ! -f "$REGISTRY" ]; then
  echo "[WAIO] ERROR: registry not found: $REGISTRY"
  exit 1
fi

# see workers/registry.conf for the field spec (NAME|HOST|SCRIPT|TYPE)
declare -a NAMES=() HOSTS=() SCRIPTS=() TYPES=()

while IFS='|' read -r name host script type; do
  case "$name" in
    ""|\#*) continue ;;
  esac
  NAMES+=("$name")
  HOSTS+=("$host")
  SCRIPTS+=("$script")
  TYPES+=("$type")
done < "$REGISTRY"

if [ "${#NAMES[@]}" -eq 0 ]; then
  echo "[WAIO] ERROR: no workers registered in $REGISTRY"
  exit 1
fi

SELECTED=-1
REQUEST_UPPER="$(printf '%s' "$REQUEST" | tr '[:lower:]' '[:upper:]')"
for i in "${!NAMES[@]}"; do
  if [[ "$REQUEST_UPPER" == *"${NAMES[$i]}"* ]]; then
    SELECTED=$i
    break
  fi
done

if [ "$SELECTED" -eq -1 ]; then
  if [ "${#NAMES[@]}" -eq 1 ]; then
    SELECTED=0
  else
    echo "[WAIO] ERROR: no worker keyword matched in request, and multiple workers are registered."
    echo "[WAIO] registered workers: ${NAMES[*]}"
    exit 1
  fi
fi

W_NAME="${NAMES[$SELECTED]}"
W_HOST="${HOSTS[$SELECTED]}"
W_SCRIPT="${SCRIPTS[$SELECTED]}"
W_TYPE="${TYPES[$SELECTED]}"

if [ "$W_HOST" != "750" ]; then
  echo "[WAIO] ERROR: remote execution target '$W_HOST' is not supported yet (local '750' only)."
  exit 1
fi

if [ ! -x "$W_SCRIPT" ]; then
  echo "[WAIO] ERROR: worker script not found or not executable: $W_SCRIPT"
  exit 1
fi

echo "[WAIO] dispatching to $W_NAME WORKER (type=$W_TYPE, host=$W_HOST)..."
exec "$W_SCRIPT" "$REQUEST"
