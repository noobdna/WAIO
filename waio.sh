#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

source ~/.waio.env

REGISTRY="workers/registry.conf"

# optional explicit worker override: -w NAME / --worker NAME / --worker=NAME
# must come before the request text. Bypasses NAME/TYPE keyword matching.
WORKER_OVERRIDE=""
while [ $# -gt 0 ]; do
  case "$1" in
    -w|--worker)
      WORKER_OVERRIDE="$2"
      shift 2
      ;;
    --worker=*)
      WORKER_OVERRIDE="${1#--worker=}"
      shift
      ;;
    --)
      shift
      break
      ;;
    -*)
      echo "[WAIO] ERROR: unknown option: $1"
      exit 1
      ;;
    *)
      break
      ;;
  esac
done

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

# --- worker resolution ---------------------------------------------------
# priority (highest first):
#   1. explicit -w/--worker override -> exact NAME match (case-insensitive)
#   2. NAME-or-TYPE substring match against the request text, in registry
#      file order (the first entry whose NAME or TYPE appears wins)
#   3. if the registry has exactly one entry, use it regardless
#   4. otherwise: error, no silent default
SELECTED=-1
MATCH_MODE=""

if [ -n "$WORKER_OVERRIDE" ]; then
  OVERRIDE_UPPER="$(printf '%s' "$WORKER_OVERRIDE" | tr '[:lower:]' '[:upper:]')"
  for i in "${!NAMES[@]}"; do
    if [ "${NAMES[$i]}" = "$OVERRIDE_UPPER" ]; then
      SELECTED=$i
      MATCH_MODE="explicit"
      break
    fi
  done
  if [ "$SELECTED" -eq -1 ]; then
    echo "[WAIO] ERROR: --worker '$WORKER_OVERRIDE' is not a registered worker."
    echo "[WAIO] registered workers: ${NAMES[*]}"
    exit 1
  fi
else
  REQUEST_UPPER="$(printf '%s' "$REQUEST" | tr '[:lower:]' '[:upper:]')"
  for i in "${!NAMES[@]}"; do
    TYPE_UPPER="$(printf '%s' "${TYPES[$i]}" | tr '[:lower:]' '[:upper:]')"
    if [[ "$REQUEST_UPPER" == *"${NAMES[$i]}"* ]] || [[ -n "$TYPE_UPPER" && "$REQUEST_UPPER" == *"$TYPE_UPPER"* ]]; then
      SELECTED=$i
      MATCH_MODE="keyword"
      break
    fi
  done

  if [ "$SELECTED" -eq -1 ]; then
    if [ "${#NAMES[@]}" -eq 1 ]; then
      SELECTED=0
      MATCH_MODE="sole-default"
    else
      echo "[WAIO] ERROR: no worker NAME/TYPE keyword matched in request, and multiple workers are registered."
      echo "[WAIO] registered workers: ${NAMES[*]}"
      echo "[WAIO] hint: specify explicitly with -w <NAME> / --worker <NAME>"
      exit 1
    fi
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

echo "[WAIO] dispatching to $W_NAME WORKER (type=$W_TYPE, host=$W_HOST, match=$MATCH_MODE)..."
exec "$W_SCRIPT" "$REQUEST"
