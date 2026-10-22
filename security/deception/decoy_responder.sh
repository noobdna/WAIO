#!/bin/bash
set -uo pipefail

# security/deception/decoy_responder.sh -- hands each decoy sensor event
# in SPOOL_DIR to the DuCoPA Independent Kill Switch's execute-policy
# verb, together with an operator-signed pre-approved POLICY_FILE.
#
#   decoy_responder.sh SPOOL_DIR POLICY_FILE [--enforce-test]
#
# This script decides NOTHING: no AI, no heuristics. Every check
# (policy signature, sensor signature, freshness, allowlist, test-only
# environment, one execution per event, max_executions) is the gate's.
# Without --enforce-test the gate runs in DRY-RUN and nothing is
# contained. Each event is moved to SPOOL_DIR/processed/ after one
# attempt (so a replay of the same file is a no-op here, and the gate
# would refuse it as DUPLICATE anyway); the gate's JSON answer for
# every event is appended to SPOOL_DIR/../responder-results.jsonl.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
GATE="${DECOY_RESPONDER_GATE:-$SCRIPT_DIR/security/killswitch/killswitch_gate.sh}"

spool="${1:-}" policy="${2:-}" enforce="${3:-}"
if [ -z "$spool" ] || [ ! -d "$spool" ] || [ -z "$policy" ] || [ ! -f "$policy" ]; then
  echo "usage: $0 SPOOL_DIR POLICY_FILE [--enforce-test]" >&2
  exit 2
fi
mode=DRY_RUN
declare -a extra=()
case "$enforce" in
  "") ;;
  --enforce-test) mode=ENFORCE_TEST; extra=(--enforce-test) ;;
  *) echo "unknown option: $enforce" >&2; exit 2 ;;
esac

results="$(dirname "$spool")/responder-results.jsonl"
mkdir -p "$spool/processed" || exit 1
handled=0
for ev in "$spool"/*.json; do
  [ -f "$ev" ] || continue
  out="$("$GATE" execute-policy "$policy" "$ev" ${extra[@]+"${extra[@]}"} 2>/dev/null)" || true
  [ -n "$out" ] || out='{"execution_result": "GATE_NO_OUTPUT"}'
  printf '%s\n' "$out" >> "$results"
  mv "$ev" "$spool/processed/" || exit 1
  handled=$((handled + 1))
done
echo "{\"handled\": $handled, \"mode\": \"$mode\"}"
