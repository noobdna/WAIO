#!/bin/bash
# security/lib.sh -- WAIO Data Loss Prevention / Emergency Shutdown layer.
# Sourced by waio.sh and every worker that makes a real outbound
# connection (SSH or HTTP). Not executable on its own.
#
# Threat model, stated honestly: WAIO is a single-operator local bash
# tool, not a sandboxed multi-tenant system. This layer is a cooperative
# choke point every current outbound call already goes through -- it
# stops an unauthorized destination, an oversized payload, or a
# credential-shaped string in worker output from silently going out
# to the real network. It does not (and cannot, from within bash) stop
# an attacker who has already replaced these library functions
# themselves, or who bypasses this file's call sites entirely; it is
# defense in depth on top of the existing dispatch path, not a sandbox
# or a network-level firewall. See ARCHITECTURE.md's DLP/Emergency
# Shutdown phase entry for the full threat-model discussion.
#
# Fail-closed: any error resolving the allowlist, any destination not
# explicitly listed, any payload/output anomaly -> deny and trip
# Emergency Shutdown. Nothing here ever logs a secret's actual value,
# a credential, or full payload/response content -- only metadata
# (destination, decision, reason, size counts). See audit_log below.

SECURITY_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SHUTDOWN_LOCK="$SECURITY_LIB_DIR/state/SHUTDOWN.lock"
SECURITY_AUDIT_LOG="${WAIO_AUDIT_LOG:-$SECURITY_LIB_DIR/../logs/security-audit.jsonl}"
EGRESS_ALLOWLIST="$SECURITY_LIB_DIR/egress_allowlist.conf"
MAX_PAYLOAD_BYTES="${WAIO_MAX_PAYLOAD_BYTES:-100000}"

mkdir -p "$(dirname "$SHUTDOWN_LOCK")" "$(dirname "$SECURITY_AUDIT_LOG")" 2>/dev/null || true

# audit_log EVENT_TYPE RUN_ID STAGE WORKER DESTINATION DECISION REASON
# Appends one JSON line. Every argument here must be metadata only --
# never a secret value, credential, or raw payload/response body.
audit_log() {
  local event_type="$1" run_id="$2" stage="$3" worker="$4" destination="$5" decision="$6" reason="$7"
  local ts
  ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  python3 -c "
import json, sys
print(json.dumps({
    'timestamp': sys.argv[1],
    'event_type': sys.argv[2],
    'run_id': sys.argv[3],
    'stage': sys.argv[4],
    'worker': sys.argv[5],
    'destination': sys.argv[6],
    'decision': sys.argv[7],
    'reason': sys.argv[8],
}))
" "$ts" "$event_type" "$run_id" "$stage" "$worker" "$destination" "$decision" "$reason" >> "$SECURITY_AUDIT_LOG"
}

# is_shutdown_active -- true (exit 0) iff Emergency Shutdown is tripped.
is_shutdown_active() {
  [ -f "$SHUTDOWN_LOCK" ]
}

# trigger_shutdown REASON [RUN_ID] [STAGE] [WORKER] [DESTINATION]
# Idempotent: the first trip wins, its lock file is never overwritten by
# a later one (so the original cause stays recorded). Always logs an
# audit event, even if shutdown was already active.
#
# Optional auto-notification: if WAIO_AUTO_NOTIFY=1 is set in the
# environment, security/notify_shutdown.sh is fired (backgrounded,
# output discarded) on the first trip only -- never on a redundant
# trigger_shutdown call while already active, matching the idempotent
# semantics above. Unset (the default) is byte-for-byte the same
# behavior this function has always had; every existing test relies on
# that default and none of them set this variable. The backgrounded,
# redirected invocation cannot alter this function's own return value,
# timing, or output, so callers' existing contracts are unaffected
# either way. See ARCHITECTURE.md's notify_shutdown.sh auto-notify
# entry for what was and wasn't verified about this path.
trigger_shutdown() {
  local reason="$1" run_id="${2:-unknown}" stage="${3:-unknown}" worker="${4:-unknown}" destination="${5:-unknown}"
  if [ ! -f "$SHUTDOWN_LOCK" ]; then
    local ts
    ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    {
      echo "reason: $reason"
      echo "run_id: $run_id"
      echo "stage: $stage"
      echo "worker: $worker"
      echo "destination: $destination"
      echo "triggered_at: $ts"
    } > "$SHUTDOWN_LOCK"
    if [ "${WAIO_AUTO_NOTIFY:-}" = "1" ]; then
      ("$SECURITY_LIB_DIR/notify_shutdown.sh" >/dev/null 2>&1 &)
    fi
  fi
  audit_log "shutdown_triggered" "$run_id" "$stage" "$worker" "$destination" "denied" "$reason"
}

# egress_check HOST PORT [RUN_ID] [STAGE] [WORKER]
# Returns 0 (allowed) or 1 (denied -- and trips Emergency Shutdown).
# Call this immediately before the real ssh/curl call it is guarding,
# never earlier -- it must be the last thing that can stop that call.
egress_check() {
  local host="$1" port="$2" run_id="${3:-unknown}" stage="${4:-unknown}" worker="${5:-unknown}"
  local destination="$host:$port"

  if is_shutdown_active; then
    audit_log "egress_denied" "$run_id" "$stage" "$worker" "$destination" "denied" "shutdown already active"
    return 1
  fi

  if [ ! -f "$EGRESS_ALLOWLIST" ]; then
    trigger_shutdown "egress allowlist missing: $EGRESS_ALLOWLIST" "$run_id" "$stage" "$worker" "$destination"
    return 1
  fi

  local allowed="false" a_host a_port a_label
  while IFS='|' read -r a_host a_port a_label; do
    case "$a_host" in ""|\#*) continue ;; esac
    if [ "$a_host" = "$host" ] && { [ "$a_port" = "$port" ] || [ "$a_port" = "*" ]; }; then
      allowed="true"
      break
    fi
  done < "$EGRESS_ALLOWLIST"

  if [ "$allowed" != "true" ]; then
    trigger_shutdown "egress destination not in allowlist: $destination" "$run_id" "$stage" "$worker" "$destination"
    return 1
  fi

  audit_log "egress_allowed" "$run_id" "$stage" "$worker" "$destination" "allowed" "matched egress_allowlist.conf"
  return 0
}

# payload_size_check PAYLOAD [RUN_ID] [STAGE] [WORKER] [DESTINATION]
# Flags an anomalously large outbound payload (a bulk-exfiltration
# shape) before it is sent. Logs only the byte count, never the payload.
payload_size_check() {
  local payload="$1" run_id="${2:-unknown}" stage="${3:-unknown}" worker="${4:-unknown}" destination="${5:-unknown}"
  local size
  size="$(printf '%s' "$payload" | wc -c | tr -d ' ')"
  if [ "$size" -gt "$MAX_PAYLOAD_BYTES" ]; then
    trigger_shutdown "payload size anomaly: ${size} bytes exceeds limit ${MAX_PAYLOAD_BYTES}" "$run_id" "$stage" "$worker" "$destination"
    return 1
  fi
  return 0
}

# secret_leak_check OUTPUT_TEXT [RUN_ID] [STAGE] [WORKER] [DESTINATION]
# Pattern-based (shape, not value) scan for common credential formats in
# worker output before it is printed/forwarded. Never logs the matched
# text -- only that a match occurred.
secret_leak_check() {
  local output="$1" run_id="${2:-unknown}" stage="${3:-unknown}" worker="${4:-unknown}" destination="${5:-unknown}"
  if printf '%s' "$output" | grep -qE '(sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY-----)'; then
    trigger_shutdown "potential credential-shaped string detected in worker output" "$run_id" "$stage" "$worker" "$destination"
    return 1
  fi
  return 0
}
