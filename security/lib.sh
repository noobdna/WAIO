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
# WAIO_SHUTDOWN_LOCK: test-isolation override, same pattern as
# WAIO_AUDIT_LOG below. Unset (the default) resolves to the exact same
# path this has always been -- zero behavior change for any existing
# caller. Added so test fixtures can exercise trigger/recover/
# reconciliation logic against a throwaway lock file without ever
# touching this deployment's real security/state/SHUTDOWN.lock.
SHUTDOWN_LOCK="${WAIO_SHUTDOWN_LOCK:-$SECURITY_LIB_DIR/state/SHUTDOWN.lock}"
SECURITY_AUDIT_LOG="${WAIO_AUDIT_LOG:-$SECURITY_LIB_DIR/../logs/security-audit.jsonl}"
# WAIO_EGRESS_ALLOWLIST: same test-isolation override pattern as
# WAIO_SHUTDOWN_LOCK/WAIO_AUDIT_LOG above -- unset (the default)
# resolves to the exact same path this has always been.
EGRESS_ALLOWLIST="${WAIO_EGRESS_ALLOWLIST:-$SECURITY_LIB_DIR/egress_allowlist.conf}"
MAX_PAYLOAD_BYTES="${WAIO_MAX_PAYLOAD_BYTES:-100000}"
# Audit-log tamper-evidence state (Red Team finding #3, 2026-09-13) --
# see verify_audit_log_integrity() below for what these are used for.
AUDIT_LOG_CHECKPOINT="${WAIO_AUDIT_LOG_CHECKPOINT:-$SECURITY_LIB_DIR/state/.audit_log_chain_checkpoint}"
AUDIT_LOG_INTEGRITY_ALERTS="${WAIO_AUDIT_INTEGRITY_ALERTS:-$SECURITY_LIB_DIR/state/.audit_log_integrity_alerts.jsonl}"
AUDIT_LOG_LOCK_DIR="${WAIO_AUDIT_LOG_LOCK_DIR:-$SECURITY_LIB_DIR/state/.audit_log.lock}"

mkdir -p "$(dirname "$SHUTDOWN_LOCK")" "$(dirname "$SECURITY_AUDIT_LOG")" "$(dirname "$AUDIT_LOG_CHECKPOINT")" 2>/dev/null || true

# DuCoPA (Dual Control Plane Architecture) Guardian Control Plane --
# separate from this file's own Main Control Plane DLP layer above (see
# ARCHITECTURE.md Phase 30-39 and security/guardian.sh's own header for
# the boundary between the two). Sourced here, once, so every existing
# `source security/lib.sh` call site (waio.sh and every worker) gets
# guardian_* functions for free with no other file needing a new source
# line. Depends on audit_log() above, so must be sourced after it.
source "$SECURITY_LIB_DIR/guardian.sh"

# _sha256 -- prints the SHA-256 of stdin as a bare lowercase hex
# digest. macOS (this repo's own dev machine, "750") ships `shasum -a
# 256`; Linux (CI's ubuntu-latest) ships `sha256sum` -- tries the
# former first, falls back to the latter.
_sha256() {
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 | awk '{print $1}'
  else
    sha256sum | awk '{print $1}'
  fi
}

# _audit_log_lock_acquire / _audit_log_lock_release -- a portable
# (works identically on macOS and Linux, no `flock` dependency) mutual-
# exclusion lock around audit_log()'s own read-checkpoint ->
# append-line -> write-checkpoint sequence below. `mkdir` is atomic on
# every POSIX filesystem (fails if the directory already exists) --
# the standard portable shell-scripting lock primitive. Needed because
# workers/orchestrate_worker.sh legitimately runs several worker
# subprocesses concurrently (Phase 13's "+"-joined parallel groups) --
# each is a separate process sourcing this file independently, so two
# audit_log() calls landing at the same moment is a real, expected
# condition here, not a hypothetical. Without this lock, two racing
# callers could both read the same "previous line's hash" and each
# append a line claiming to follow it -- verify_audit_log_integrity()
# below would then (wrongly) report that as a broken/tampered chain. A
# stale lock (its owner crashed mid-update, never released it) is
# stolen after 5s rather than hanging every future dispatch forever.
_audit_log_lock_acquire() {
  local waited=0
  while ! mkdir "$AUDIT_LOG_LOCK_DIR" 2>/dev/null; do
    if [ -d "$AUDIT_LOG_LOCK_DIR" ]; then
      local lock_mtime now age
      lock_mtime="$(stat -f %m "$AUDIT_LOG_LOCK_DIR" 2>/dev/null || stat -c %Y "$AUDIT_LOG_LOCK_DIR" 2>/dev/null || echo 0)"
      now="$(date +%s)" || now=0
      age=$((now - lock_mtime))
      if [ "$age" -gt 5 ]; then
        rmdir "$AUDIT_LOG_LOCK_DIR" 2>/dev/null || true
        continue
      fi
    fi
    waited=$((waited + 1))
    [ "$waited" -gt 50 ] && return 1
    sleep 0.1
  done
  return 0
}

_audit_log_lock_release() {
  rmdir "$AUDIT_LOG_LOCK_DIR" 2>/dev/null || true
}

# audit_log EVENT_TYPE RUN_ID STAGE WORKER DESTINATION DECISION REASON
# Appends one JSON line. Every argument here must be metadata only --
# never a secret value, credential, or raw payload/response body.
#
# Actor attribution (added alongside the recovery-hardening work): every
# call site's own 7-argument signature is unchanged -- these fields are
# captured automatically from the OS environment of whichever process
# calls audit_log, never supplied by the caller, so none of the existing
# 12 call sites (security/lib.sh itself, security/recover.sh,
# security/generate_ssh_guardian_config.sh) needed to change.
#   actor_user            -- OS username of the process writing this event
#   actor_uid              -- its numeric uid
#   actor_tty              -- controlling tty, or "not a tty" (cron/launchd/
#                             a forced SSH command with no pty all land here)
#   actor_ssh_connection   -- $SSH_CONNECTION if this process is running
#                             inside an SSH session, else null. Useful
#                             signal (not proof) for telling a genuine
#                             Guardian SSH recovery apart from a local
#                             operator invoking --guardian-confirm
#                             directly: WAIO and Takomachi run as the
#                             same local user, so actor_user alone can't
#                             distinguish them (see ARCHITECTURE.md Phase
#                             32) -- this field is not a new auth
#                             mechanism, it is only recorded, never
#                             checked/enforced by any gate.
#
# Tamper-evidence chaining (Red Team finding #3, 2026-09-13): each line
# also carries 'prev_hash', the SHA-256 of the immediately preceding
# line's own exact text ('genesis' for the very first line ever
# written). After a successful append, this line's own hash is
# recorded in AUDIT_LOG_CHECKPOINT (a separate small file -- see
# verify_audit_log_integrity() below, which walks the whole log and
# recomputes this chain to detect an edited/deleted/reordered past
# line or a truncated/replaced tail). A failed append (the log file or
# its directory is not writable) is detected and reported here
# synchronously, not inferred later -- see the AUDIT_LOG_INTEGRITY_ALERTS
# side-channel write below, which exists specifically so a report can
# still be made durable even when the main log itself cannot be
# written to.
audit_log() {
  local event_type="$1" run_id="$2" stage="$3" worker="$4" destination="$5" decision="$6" reason="$7"
  local ts actor_user actor_uid actor_tty actor_ssh_connection
  ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  actor_user="$(id -un 2>/dev/null)" || actor_user="unknown"
  actor_uid="$(id -u 2>/dev/null)" || actor_uid="unknown"
  actor_tty="$(tty 2>/dev/null)" || actor_tty="not a tty"
  actor_ssh_connection="${SSH_CONNECTION:-}"

  local lock_held="false"
  _audit_log_lock_acquire && lock_held="true"

  local checkpoint_content="" checkpoint_count=0 prev_hash="genesis"
  if [ -f "$AUDIT_LOG_CHECKPOINT" ]; then
    checkpoint_content="$(cat "$AUDIT_LOG_CHECKPOINT" 2>/dev/null)" || checkpoint_content=""
  fi
  checkpoint_count="${checkpoint_content%%:*}"
  case "$checkpoint_count" in
    ''|*[!0-9]*) checkpoint_count=0 ;;
    *) prev_hash="${checkpoint_content#*:}" ;;
  esac

  local line
  line="$(python3 -c "
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
    'actor_user': sys.argv[9],
    'actor_uid': sys.argv[10],
    'actor_tty': sys.argv[11],
    'actor_ssh_connection': sys.argv[12] or None,
    'prev_hash': sys.argv[13],
}))
" "$ts" "$event_type" "$run_id" "$stage" "$worker" "$destination" "$decision" "$reason" \
    "$actor_user" "$actor_uid" "$actor_tty" "$actor_ssh_connection" "$prev_hash")" || line=""

  if [ -n "$line" ] && printf '%s\n' "$line" >> "$SECURITY_AUDIT_LOG" 2>/dev/null; then
    local new_hash="" new_count=$((checkpoint_count + 1))
    new_hash="$(printf '%s' "$line" | _sha256)" || new_hash=""
    if [ -n "$new_hash" ]; then
      printf '%s:%s' "$new_count" "$new_hash" > "$AUDIT_LOG_CHECKPOINT" 2>/dev/null || true
    fi
  else
    echo "[WAIO] WARNING: failed to write audit log entry to $SECURITY_AUDIT_LOG (event_type=$event_type) -- the audit trail is incomplete, or the log is not writable" >&2 || true
    printf '{"timestamp": "%s", "event_type": "audit_log_write_failed", "attempted_event_type": "%s", "destination": "%s"}\n' \
      "$ts" "$event_type" "$destination" >> "$AUDIT_LOG_INTEGRITY_ALERTS" 2>/dev/null || true
  fi

  [ "$lock_held" = "true" ] && _audit_log_lock_release
  return 0
}

# verify_audit_log_integrity -- walks the entire audit log, recomputing
# the prev_hash chain audit_log() writes above, and compares the final
# state to AUDIT_LOG_CHECKPOINT. Prints exactly one word/token to
# stdout, never fails the calling script:
#   ok                   -- checkpoint (if any) matches the log exactly
#   ok:no_checkpoint      -- a log with content exists, but no
#                            checkpoint to verify it against (e.g. a
#                            log from before this feature existed)
#   missing               -- a checkpoint exists (entries were written)
#                            but the log file itself is now gone
#   unwritable            -- the log file/its directory can't be
#                            written to right now
#   broken:N               -- line N's own prev_hash doesn't match the
#                            hash of line N-1's actual text -- a past
#                            line was edited, deleted, or reordered
#   truncated              -- the file has fewer lines than the
#                            checkpoint recorded
#   checkpoint_mismatch     -- line count matches, or the file is
#                            longer, but the final line's hash doesn't
#                            match what the checkpoint recorded (the
#                            tail was replaced, or lines were appended
#                            outside of audit_log()'s own lock-protected
#                            path)
# This is tamper-EVIDENCE, not tamper-PREVENTION or authentication: an
# attacker with write access to both the log and the checkpoint can, in
# principle, recompute a fully self-consistent fake chain from scratch.
# It raises the bar against exactly the class of bypass Red Team
# finding #3 identified (delete SHUTDOWN.lock, don't touch the audit
# log at all, or edit/remove only the one incriminating line) -- see
# ARCHITECTURE.md for the full discussion of what this does and does
# not prove, and tests/audit_log_integrity_test.sh for the tamper
# scenarios this is verified against.
verify_audit_log_integrity() {
  if [ ! -f "$SECURITY_AUDIT_LOG" ]; then
    if [ -f "$AUDIT_LOG_CHECKPOINT" ]; then echo "missing"; else echo "ok"; fi
    return 0
  fi

  local writable="true"
  if [ ! -w "$SECURITY_AUDIT_LOG" ] || [ ! -w "$(dirname "$SECURITY_AUDIT_LOG")" ]; then
    writable="false"
  fi

  if [ ! -f "$AUDIT_LOG_CHECKPOINT" ]; then
    if [ "$writable" = "false" ]; then echo "unwritable"; else echo "ok:no_checkpoint"; fi
    return 0
  fi

  local checkpoint_content checkpoint_count checkpoint_hash
  checkpoint_content="$(cat "$AUDIT_LOG_CHECKPOINT" 2>/dev/null)" || checkpoint_content=""
  checkpoint_count="${checkpoint_content%%:*}"
  checkpoint_hash="${checkpoint_content#*:}"
  case "$checkpoint_count" in
    ''|*[!0-9]*)
      if [ "$writable" = "false" ]; then echo "unwritable"; else echo "ok:no_checkpoint"; fi
      return 0
      ;;
  esac

  local result="broken:unknown"
  result="$(python3 -c "
import hashlib, json, sys

log_path, expected_count, expected_hash = sys.argv[1], int(sys.argv[2]), sys.argv[3]

prev_hash = 'genesis'
count = 0
with open(log_path, 'r') as f:
    for lineno, raw in enumerate(f, start=1):
        text = raw.rstrip('\n')
        if not text:
            continue
        count += 1
        try:
            obj = json.loads(text)
        except Exception:
            print(f'broken:{lineno}')
            sys.exit(0)
        if obj.get('prev_hash') != prev_hash:
            print(f'broken:{lineno}')
            sys.exit(0)
        prev_hash = hashlib.sha256(text.encode('utf-8')).hexdigest()

if count < expected_count:
    print('truncated')
elif count != expected_count or prev_hash != expected_hash:
    print('checkpoint_mismatch')
else:
    print('ok')
" "$SECURITY_AUDIT_LOG" "$checkpoint_count" "$checkpoint_hash" 2>/dev/null)" || result="broken:unknown"
  [ -n "$result" ] || result="broken:unknown"

  if [ "$writable" = "false" ] && [ "$result" = "ok" ]; then
    echo "unwritable"
  else
    echo "$result"
  fi
}

# _handle_audit_log_integrity_alert -- calls verify_audit_log_integrity()
# and, on anything other than "ok"/"ok:no_checkpoint", raises a loud
# stderr warning and records the alert to AUDIT_LOG_INTEGRITY_ALERTS (a
# small side-channel file, deliberately DISTINCT from the main audit
# log -- chosen specifically so a "the main log is gone/broken/
# unwritable" finding still leaves a durable record even when the main
# log itself cannot be trusted or written to), plus, best-effort, an
# audit_log_integrity_violation event in the main log itself if it is
# currently writable (this permanently marks the point in the chain
# where the violation was noticed, going forward). Purely advisory --
# never blocks or exits, same `|| true` discipline as
# _reconcile_recovery_audit, for the same set -euo pipefail reasons
# (this is called from waio.sh, which runs with -e).
_handle_audit_log_integrity_alert() {
  local result="check_failed"
  result="$(verify_audit_log_integrity)" || result="check_failed"
  case "$result" in
    ok|ok:no_checkpoint) return 0 ;;
  esac

  local ts=""
  ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)" || true
  echo "[WAIO] WARNING: audit log integrity check failed ($result) -- $SECURITY_AUDIT_LOG may have been deleted, modified, truncated, or made unwritable outside of audit_log()'s own path" >&2 || true
  printf '{"timestamp": "%s", "event_type": "audit_log_integrity_violation", "result": "%s"}\n' "$ts" "$result" \
    >> "$AUDIT_LOG_INTEGRITY_ALERTS" 2>/dev/null || true
  audit_log "audit_log_integrity_violation" "n/a" "reconciliation" "n/a" "n/a" "detected" "audit log integrity check result: $result" || true
  return 0
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
#
# Optional auto-dashboard-refresh: same shape, same first-trip-only
# guard, a separate opt-in variable (WAIO_AUTO_DASHBOARD_REFRESH=1).
# When set, dashboard/collect_status.sh and
# dashboard/build_incident_history.sh (both already-existing,
# unmodified, read-only data generators -- reused as-is, not
# reimplemented) are run in one backgrounded subshell, sequentially, so
# the Dashboard's JSON snapshots reflect this real incident without a
# human having to remember to re-run them by hand. Backgrounded and
# fully output-redirected, exactly like the notify path above -- cannot
# alter this function's return value, timing, or output either. Unset
# (the default) is byte-for-byte unchanged from before this addition.
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
    if [ "${WAIO_AUTO_DASHBOARD_REFRESH:-}" = "1" ]; then
      ("$SECURITY_LIB_DIR/../dashboard/collect_status.sh" >/dev/null 2>&1
       "$SECURITY_LIB_DIR/../dashboard/build_incident_history.sh" >/dev/null 2>&1) &
    fi
    # Optional DuCoPA Guardian mirror: same opt-in, first-trip-only shape
    # as the two blocks above -- unset (the default) is byte-for-byte
    # unchanged from before this addition. Sets the Guardian's own state
    # directly (guardian_set_state, not guardian_request_waio_shutdown) --
    # we are already inside trigger_shutdown, which is about to write
    # SHUTDOWN_LOCK itself, so calling guardian_request_waio_shutdown here
    # would call back into trigger_shutdown a second time (harmless, since
    # its own first-trip guard would skip re-writing the lock, but it
    # would still append a second redundant shutdown_triggered audit
    # line). guardian_set_state is the pure setter with no such call-back.
    if [ "${WAIO_AUTO_GUARDIAN_NOTIFY:-}" = "1" ]; then
      guardian_set_state "SHUTDOWN" "mirrors real shutdown: $reason" "$run_id" "waio-dlp" || true
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

# shell_quote VALUE -- prints VALUE wrapped in POSIX single-quotes,
# with every embedded single quote escaped as '\'' -- the one escape
# sequence that round-trips correctly through ANY POSIX-compatible
# shell (bash, dash, zsh, ksh alike), unlike bash's own `printf '%q'`,
# which emits bash-specific $'...' ANSI-C quoting a non-bash remote
# login shell would not understand.
#
# Exists because some workers (workers/rpi_worker.sh) must embed an
# untrusted request string into a command line that is sent over SSH
# and re-parsed by a REMOTE shell: `ssh host arg...` always joins its
# trailing arguments into one string and hands it to the remote user's
# login shell for parsing -- there is no way to avoid that one layer of
# re-parsing while still invoking a named remote script with an
# argument over plain `ssh`. shell_quote makes that one unavoidable
# re-parse safe: however the quoted output is embedded into a larger
# command string, the shell that re-parses it always treats it as one
# inert argument, never as additional shell syntax (Red Team finding
# #1, 2026-09-13 -- see workers/rpi_worker.sh's own header for the
# vulnerability this closes and tests/rpi_command_injection_test.sh for
# the attack-simulation regression tests).
shell_quote() {
  if [ -z "$1" ]; then
    printf "''"
    return 0
  fi
  printf '%s' "$1" | sed "s/'/'\\\\''/g; 1s/^/'/; \$s/\$/'/"
}

# _reconcile_recovery_audit -- recovery-hardening item 3: detect (never
# gate on) a SHUTDOWN.lock that disappeared without a matching
# recovery_confirmed(_guardian) audit event -- i.e. cleared by something
# other than security/recover.sh (a direct `rm`, for instance). Purely
# advisory: logs a "shutdown_lock_bypass_suspected" audit event and a
# stderr warning, never blocks/denies/exits. Called only from the two
# real entry points (waio.sh, security/recover.sh), not from every
# individual worker script, to avoid redundant repeated checks within a
# single ORCHESTRATE pipeline run.
#
# trigger_shutdown() always logs "shutdown_triggered" (even on a
# redundant trip while already active -- see its own header), so any
# period where SHUTDOWN.lock existed has at least one such event on
# record. Reconciliation condition: the lock is currently absent, but
# the most recent shutdown_triggered event is not followed by a
# recovery_confirmed/recovery_confirmed_guardian event -- i.e. an
# incident that, per the audit trail, was never actually resolved via
# recover.sh, yet the lock is gone.
#
# Written defensively against `set -euo pipefail` inherited from every
# caller (waio.sh has -e; a failing `grep`/malformed-JSON `python3` call
# inside a pipeline under `pipefail` would otherwise abort the entire
# calling script) -- every risky pipeline ends in `|| true`, declared on
# its own line (never `local var=$(...)`, which bash-version-dependently
# masks/unmasks the substitution's own exit status), and this function
# always returns 0.
_reconcile_recovery_audit() {
  is_shutdown_active && return 0
  [ -f "$SECURITY_AUDIT_LOG" ] || return 0

  local last_trigger_json=""
  last_trigger_json="$(grep -F '"event_type": "shutdown_triggered"' "$SECURITY_AUDIT_LOG" 2>/dev/null | tail -1)" || true
  [ -n "$last_trigger_json" ] || return 0

  local last_trigger_ts="" last_trigger_run_id="unknown" last_trigger_worker="unknown" last_trigger_dest="unknown"
  last_trigger_ts="$(printf '%s' "$last_trigger_json" | python3 -c "
import json, sys
try:
    print(json.loads(sys.stdin.read()).get('timestamp',''))
except Exception:
    print('')" 2>/dev/null)" || true
  [ -n "$last_trigger_ts" ] || return 0
  last_trigger_run_id="$(printf '%s' "$last_trigger_json" | python3 -c "
import json, sys
try:
    print(json.loads(sys.stdin.read()).get('run_id','unknown'))
except Exception:
    print('unknown')" 2>/dev/null)" || true
  last_trigger_worker="$(printf '%s' "$last_trigger_json" | python3 -c "
import json, sys
try:
    print(json.loads(sys.stdin.read()).get('worker','unknown'))
except Exception:
    print('unknown')" 2>/dev/null)" || true
  last_trigger_dest="$(printf '%s' "$last_trigger_json" | python3 -c "
import json, sys
try:
    print(json.loads(sys.stdin.read()).get('destination','unknown'))
except Exception:
    print('unknown')" 2>/dev/null)" || true

  local last_recovery_ts=""
  last_recovery_ts="$(grep -E '"event_type": "recovery_confirmed(_guardian)?"' "$SECURITY_AUDIT_LOG" 2>/dev/null | tail -1 | python3 -c "
import json, sys
try:
    print(json.loads(sys.stdin.read()).get('timestamp',''))
except Exception:
    print('')" 2>/dev/null)" || true

  # A recovery at or after this trigger's own timestamp means it was
  # properly resolved via recover.sh -- nothing to flag. (Timestamps are
  # this codebase's one fixed %Y-%m-%dT%H:%M:%SZ format throughout, so
  # lexicographic string comparison is chronological comparison.)
  if [ -n "$last_recovery_ts" ] && [[ ! "$last_trigger_ts" > "$last_recovery_ts" ]]; then
    return 0
  fi

  local marker="${WAIO_RECOVER_RECONCILE_MARKER:-$SECURITY_LIB_DIR/state/.last_reconciled_trigger}"
  local already=""
  if [ -f "$marker" ]; then
    already="$(cat "$marker" 2>/dev/null)" || true
  fi
  [ "$already" = "$last_trigger_ts" ] && return 0

  audit_log "shutdown_lock_bypass_suspected" "$last_trigger_run_id" "reconciliation" \
    "$last_trigger_worker" "$last_trigger_dest" "detected" \
    "SHUTDOWN.lock is absent but no recovery_confirmed(_guardian) event follows the shutdown_triggered event at $last_trigger_ts -- likely cleared without security/recover.sh" || true
  echo "[WAIO] WARNING: possible unaudited recovery detected -- see $SECURITY_AUDIT_LOG (shutdown_lock_bypass_suspected)" >&2 || true
  printf '%s' "$last_trigger_ts" > "$marker" 2>/dev/null || true
  return 0
}
