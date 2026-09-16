#!/bin/bash
set -uo pipefail

# security/segment_manager.sh -- Phase 49 (Segment Recovery MVP):
# segment identity, status persistence, and the Incident State Machine
# transition graph. Sourced by security/health_checker.sh and
# security/recovery_engine.sh; also runnable directly for CLI
# inspection/manual override (see the dispatch block at the bottom).
#
# A "segment" here is one entry in security/segments.conf -- currently
# always a single host WAIO already knows about via
# workers/registry.conf (HOST800, RPI). This is deliberately not a
# real L2/L3 network-segmentation concept (no VLAN/switch/firewall
# integration exists in this codebase, and building one is out of
# scope for this MVP) -- it is a monitored unit with its own
# independent incident lifecycle, so the model generalizes cleanly if
# more/different segments are added later.
#
# State machine (six statuses, per the Phase 49 spec):
#   normal -> suspicious                  (health_checker.sh: first failed check)
#   suspicious -> isolated                (health_checker.sh: still failing, confirmed)
#   suspicious -> normal                  (health_checker.sh: false alarm, check passed again)
#   isolated -> recovering                (recovery_engine.sh: a recovery attempt starts)
#   recovering -> recovered               (recovery_engine.sh: action + re-check both succeeded)
#   recovering -> failed                  (recovery_engine.sh: action or re-check failed)
#   recovered -> normal                   (incident closed)
#   failed -> isolated                    (human-forced only, see --force below; never automatic --
#                                          this is the one edge that keeps "no automatic infinite
#                                          retry" true: recovery_engine.sh never performs it itself)
# Every other (FROM, TO) pair is rejected. segment_transition() is the
# only way state files are written -- there is no direct-write path,
# so this graph is the actual enforcement point, not documentation.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"
source security/lib.sh

SEGMENTS_CONF="${SEGMENT_MANAGER_CONF:-$SECURITY_LIB_DIR/segments.conf}"
SEGMENT_STATE_DIR="${SEGMENT_MANAGER_STATE_DIR:-$SECURITY_LIB_DIR/state/segments}"
SEGMENT_AUDIT_LOG="${SEGMENT_MANAGER_AUDIT_LOG:-$SECURITY_LIB_DIR/../logs/segment-audit.jsonl}"

mkdir -p "$SEGMENT_STATE_DIR" "$(dirname "$SEGMENT_AUDIT_LOG")" 2>/dev/null || true

SEG_IDS=()
SEG_HOSTS=()
SEG_PORTS=()
SEG_WORKERS=()
SEG_LABELS=()
SEG_MACS=()

# load_segments -- populate the SEG_* arrays from SEGMENTS_CONF. A
# missing file is an error (not configured yet); an existing file with
# zero valid entries is a valid, safe, empty state (see
# segments.conf.example's header for why this differs from
# egress_allowlist.conf's fail-closed posture -- this file is an
# inventory list, not a security boundary).
#
# MAC (6th field, Phase 50) is OPTIONAL -- a 5-field line (no trailing
# |MAC) is still fully valid: `read` leaves an omitted trailing field
# empty, so `mac` is simply "" for such lines, and the required-field
# check below deliberately does not include it. MAC identity is never
# treated as sole/absolute trust by any consumer of this field.
load_segments() {
  SEG_IDS=(); SEG_HOSTS=(); SEG_PORTS=(); SEG_WORKERS=(); SEG_LABELS=(); SEG_MACS=()
  if [ ! -f "$SEGMENTS_CONF" ]; then
    echo "[SEGMENT] ERROR: segment registry missing: $SEGMENTS_CONF" >&2
    echo "[SEGMENT] Copy security/segments.conf.example and fill in this deployment's segments (see README.md Setup)." >&2
    return 1
  fi

  local id host port worker label mac
  while IFS='|' read -r id host port worker label mac; do
    case "$id" in ""|\#*) continue ;; esac
    if [ -z "$id" ] || [ -z "${host:-}" ] || [ -z "${port:-}" ] || [ -z "${worker:-}" ] || [ -z "${label:-}" ]; then
      echo "[SEGMENT] ERROR: malformed segments.conf line (need SEGMENT_ID|HOST|PORT|WORKER_NAME|LABEL[|MAC]): '$id|${host:-}|${port:-}|${worker:-}|${label:-}|${mac:-}'" >&2
      return 1
    fi
    SEG_IDS+=("$id"); SEG_HOSTS+=("$host"); SEG_PORTS+=("$port"); SEG_WORKERS+=("$worker"); SEG_LABELS+=("$label"); SEG_MACS+=("${mac:-}")
  done < "$SEGMENTS_CONF"
  return 0
}

# segment_index SEGMENT_ID -- prints the array index, or nothing + returns 1
segment_index() {
  local want="$1" i
  for i in "${!SEG_IDS[@]}"; do
    [ "${SEG_IDS[$i]}" = "$want" ] && { echo "$i"; return 0; }
  done
  return 1
}

segment_host() { local i; i="$(segment_index "$1")" && echo "${SEG_HOSTS[$i]}"; }
segment_port() { local i; i="$(segment_index "$1")" && echo "${SEG_PORTS[$i]}"; }
segment_worker() { local i; i="$(segment_index "$1")" && echo "${SEG_WORKERS[$i]}"; }
segment_label() { local i; i="$(segment_index "$1")" && echo "${SEG_LABELS[$i]}"; }
# segment_mac -- prints this segment's configured MAC, or an empty
# string if none is set (5-field legacy line). Never fabricates one.
segment_mac() { local i; i="$(segment_index "$1")" && echo "${SEG_MACS[$i]}"; }

segment_state_path() { echo "$SEGMENT_STATE_DIR/$1.json"; }

# segment_get_status SEGMENT_ID -- "normal" is the implicit initial
# status for any registered segment with no state file yet.
segment_get_status() {
  local id="$1" path
  path="$(segment_state_path "$id")"
  if [ -f "$path" ]; then
    python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['status'])" "$path" 2>/dev/null || echo "normal"
  else
    echo "normal"
  fi
}

# transition_allowed FROM TO -- the state machine's only source of
# truth, both directions checked as an explicit pair (never inferred).
# failed:isolated is deliberately NOT in this normally-allowed graph --
# it is reachable only via segment_transition's --force escape hatch
# (a human's manual CLI override), never automatically. This is the
# actual enforcement point for "no automatic infinite retry": even if
# some future caller mistakenly tried to loop recovery, this function
# itself refuses the failed->isolated step without --force, not just
# recovery_engine.sh's own restraint from never attempting it.
transition_allowed() {
  local from="$1" to="$2"
  case "$from:$to" in
    normal:suspicious) return 0 ;;
    suspicious:isolated) return 0 ;;
    suspicious:normal) return 0 ;;
    isolated:recovering) return 0 ;;
    recovering:recovered) return 0 ;;
    recovering:failed) return 0 ;;
    recovered:normal) return 0 ;;
    *) return 1 ;;
  esac
}

# segment_audit_log SEGMENT_ID EVENT REASON ACTION RESULT -- appends
# one JSON line to SEGMENT_AUDIT_LOG. Same "metadata only, never a
# secret/credential/raw payload" discipline as security/lib.sh's
# audit_log(), and the same append-only JSONL shape -- kept as a
# separate file/function (not a reuse of lib.sh's audit_log) so this
# domain's fixed field set (segment_id/event/reason/action/result,
# exactly what Phase 49 specifies) never has to be shoehorned into or
# drift the existing DLP audit log's own frozen shape.
segment_audit_log() {
  local segment_id="$1" event="$2" reason="$3" action="$4" result="$5"
  local ts
  ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  python3 -c "
import json, sys
print(json.dumps({
    'timestamp': sys.argv[1],
    'segment_id': sys.argv[2],
    'event': sys.argv[3],
    'reason': sys.argv[4],
    'action': sys.argv[5],
    'result': sys.argv[6],
}, ensure_ascii=False))
" "$ts" "$segment_id" "$event" "$reason" "$action" "$result" >> "$SEGMENT_AUDIT_LOG"
}

# segment_transition SEGMENT_ID NEW_STATUS REASON EVENT ACTION RESULT [--force]
# The only path that ever writes a segment's state file. Validates the
# transition against transition_allowed() unless --force is passed
# (reserved for a human operator's manual CLI override -- see the
# dispatch block below; recovery_engine.sh and health_checker.sh never
# pass --force). Every attempt is logged, including rejected ones, so
# the audit trail shows both what was tried and what actually happened.
segment_transition() {
  local id="$1" new_status="$2" reason="$3" event="$4" action="$5" result="$6" force="${7:-}"
  local current
  current="$(segment_get_status "$id")"

  if [ "$force" != "--force" ] && ! transition_allowed "$current" "$new_status"; then
    echo "[SEGMENT] ERROR: rejected transition for '$id': $current -> $new_status is not allowed." >&2
    segment_audit_log "$id" "transition_rejected" "$reason (attempted $current -> $new_status)" "$action" "rejected"
    return 1
  fi

  local path tmp
  path="$(segment_state_path "$id")"
  tmp="$path.tmp.$$"
  python3 -c "
import json, sys
json.dump({
    'segment_id': sys.argv[1],
    'status': sys.argv[2],
    'previous_status': sys.argv[3],
    'updated_at': sys.argv[4],
    'reason': sys.argv[5],
}, open(sys.argv[6], 'w'), ensure_ascii=False)
" "$id" "$new_status" "$current" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$reason" "$tmp"
  mv -f "$tmp" "$path"

  segment_audit_log "$id" "$event" "$reason" "$action" "$result"
  echo "[SEGMENT] $id: $current -> $new_status ($reason)"
  return 0
}

segment_list() {
  local i id
  for i in "${!SEG_IDS[@]}"; do
    id="${SEG_IDS[$i]}"
    echo "$id|$(segment_get_status "$id")|${SEG_HOSTS[$i]}|${SEG_PORTS[$i]}|${SEG_WORKERS[$i]}|${SEG_LABELS[$i]}|${SEG_MACS[$i]}"
  done
}

# Only run the CLI dispatch when executed directly -- health_checker.sh
# and recovery_engine.sh source this file for its functions and never
# reach this block. tests/segment_recovery_test.sh also sources it
# directly (after exporting the SEGMENT_MANAGER_* overrides above) to
# unit-test load_segments/transition_allowed/segment_transition against
# fixtures without ever touching this deployment's real segments.conf.
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
  case "${1:-}" in
    list)
      load_segments || exit 1
      segment_list
      ;;
    status)
      load_segments || exit 1
      [ -n "${2:-}" ] || { echo "Usage: $0 status SEGMENT_ID" >&2; exit 1; }
      segment_index "$2" >/dev/null || { echo "[SEGMENT] ERROR: unknown segment '$2'" >&2; exit 1; }
      segment_get_status "$2"
      ;;
    mac)
      load_segments || exit 1
      [ -n "${2:-}" ] || { echo "Usage: $0 mac SEGMENT_ID" >&2; exit 1; }
      segment_index "$2" >/dev/null || { echo "[SEGMENT] ERROR: unknown segment '$2'" >&2; exit 1; }
      segment_mac "$2"
      ;;
    set)
      # manual human override: $0 set SEGMENT_ID NEW_STATUS "reason" [--force]
      load_segments || exit 1
      [ -n "${2:-}" ] && [ -n "${3:-}" ] && [ -n "${4:-}" ] || { echo "Usage: $0 set SEGMENT_ID NEW_STATUS \"reason\" [--force]" >&2; exit 1; }
      segment_index "$2" >/dev/null || { echo "[SEGMENT] ERROR: unknown segment '$2'" >&2; exit 1; }
      segment_transition "$2" "$3" "$4" "manual_override" "cli_set" "manual" "${5:-}"
      ;;
    *)
      echo "Usage: $0 {list|status SEGMENT_ID|mac SEGMENT_ID|set SEGMENT_ID NEW_STATUS \"reason\" [--force]}" >&2
      exit 1
      ;;
  esac
fi
