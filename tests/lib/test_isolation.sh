#!/bin/bash
# tests/lib/test_isolation.sh -- shared fail-closed test isolation for
# suites that drive real WAIO security code (security/lib.sh and
# anything that sources it: trigger_shutdown/audit_log/recover.sh/
# guardian_*). Sourced, not executed.
#
# Why (audit finding F-17, 2026-10-18): security/lib.sh resolves every
# lock/audit/Guardian path from a WAIO_* override OR, when unset, the
# real deployment path. A suite that forgets one override silently
# writes the production audit log or trips the real SHUTDOWN.lock --
# which is exactly how tests/ssh_guardian_config_test.sh appended
# fixture events to logs/security-audit.jsonl. This helper makes
# isolation explicit and verified instead of assumed:
#
#   waio_test_isolate NAME   -- refuses a pre-set override that points at
#                               production; creates a private temp root;
#                               exports EVERY path override security/lib.sh,
#                               guardian.sh and ducopa.sh honor into it;
#                               unsets the opt-in side-effect flags; points
#                               HOME at an empty dir (waio.sh sources
#                               ~/.waio.env, which could otherwise re-point
#                               the overrides); puts recording stubs for
#                               sudo/ssh/scp/curl/nc/osascript first on
#                               PATH, each of which fails without acting.
#   waio_test_assert_isolated
#                            -- sources security/lib.sh in a subshell with
#                               the current environment and checks every
#                               path it actually resolves lies inside the
#                               temp root. Callers abort on failure.
#   waio_test_stub_calls NAME
#                            -- prints how many times stub NAME was called.
#   waio_test_cleanup        -- removes the temp root (only ever a path this
#                               helper created).
#
# Exit/return code 3 everywhere below means "isolation could not be
# guaranteed -- refusing to run", distinct from a normal test failure.

WAIO_TEST_REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

_waio_test_realpath() {
  python3 -c 'import os, sys; print(os.path.realpath(sys.argv[1]))' "$1"
}

# Every override security/lib.sh, security/guardian.sh and
# security/ducopa.sh read. Keep in sync with those files.
WAIO_TEST_PATH_VARS="WAIO_SHUTDOWN_LOCK WAIO_AUDIT_LOG WAIO_AUDIT_LOG_CHECKPOINT WAIO_AUDIT_INTEGRITY_ALERTS WAIO_AUDIT_LOG_LOCK_DIR WAIO_RECOVER_RECONCILE_MARKER WAIO_EGRESS_ALLOWLIST WAIO_GUARDIAN_STATE_FILE WAIO_GUARDIAN_QUARANTINE_FILE WAIO_GUARDIAN_CRITICAL_EVENTS_FILE WAIO_GUARDIAN_STATE_LOCK_DIR WAIO_DUCOPA_STATE_FILE WAIO_DUCOPA_AUDIT_LOG"
# Opt-in flags that make trigger_shutdown()/guardian_notify_event() fire
# real side effects (desktop notification, live dashboard regeneration,
# Guardian mirroring, auto-quarantine).
WAIO_TEST_SIDE_EFFECT_FLAGS="WAIO_AUTO_NOTIFY WAIO_AUTO_DASHBOARD_REFRESH WAIO_AUTO_GUARDIAN_NOTIFY WAIO_GUARDIAN_AUTO_QUARANTINE"

# waio_test_is_production_path PATH -- true if PATH is, or is inside, a
# real deployment location this repo's tests must never write.
waio_test_is_production_path() {
  local p rp prod
  p="$1"
  [ -n "$p" ] || return 1
  rp="$(_waio_test_realpath "$p")"
  for prod in "$WAIO_TEST_REPO/security/state" "$WAIO_TEST_REPO/logs" "$WAIO_TEST_REPO/workers" \
              "$WAIO_TEST_REPO/security/egress_allowlist.conf" "$WAIO_TEST_REPO/security/ssh_management_allowlist.conf" \
              "/etc/ssh" "${WAIO_TEST_REAL_HOME:-$HOME}/.ssh" "${WAIO_TEST_REAL_HOME:-$HOME}/.waio.env"; do
    prod="$(_waio_test_realpath "$prod")"
    case "$rp" in
      "$prod"|"$prod"/*) return 0 ;;
    esac
  done
  return 1
}

waio_test_isolate() {
  local name="${1:-suite}" v val
  if [ -n "${WAIO_TEST_ROOT:-}" ]; then
    echo "[TEST ISOLATION] REFUSING: waio_test_isolate called twice (WAIO_TEST_ROOT already set to $WAIO_TEST_ROOT)" >&2
    return 3
  fi
  WAIO_TEST_REAL_HOME="$HOME"
  for v in $WAIO_TEST_PATH_VARS SSH_GUARDIAN_DEPLOYED_CONFIG SSH_GUARDIAN_STATE_DIR SSH_GUARDIAN_BACKUP_DIR SSH_GUARDIAN_ALLOWLIST WAIO_INCIDENT_HISTORY_OUTPUT; do
    val="${!v:-}"
    if [ -n "$val" ] && waio_test_is_production_path "$val"; then
      echo "[TEST ISOLATION] REFUSING: pre-set $v points at a production path ($val)" >&2
      return 3
    fi
  done

  WAIO_TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/waio-test-$name.XXXXXX")" || {
    echo "[TEST ISOLATION] REFUSING: could not create a temp root" >&2
    return 3
  }
  WAIO_TEST_ROOT="$(_waio_test_realpath "$WAIO_TEST_ROOT")"
  mkdir -p "$WAIO_TEST_ROOT/state" "$WAIO_TEST_ROOT/logs" "$WAIO_TEST_ROOT/home" "$WAIO_TEST_ROOT/bin" "$WAIO_TEST_ROOT/stub-calls"
  export WAIO_TEST_ROOT WAIO_TEST_REAL_HOME

  export WAIO_SHUTDOWN_LOCK="$WAIO_TEST_ROOT/state/SHUTDOWN.lock"
  export WAIO_AUDIT_LOG="$WAIO_TEST_ROOT/logs/security-audit.jsonl"
  export WAIO_AUDIT_LOG_CHECKPOINT="$WAIO_TEST_ROOT/state/.audit_log_chain_checkpoint"
  export WAIO_AUDIT_INTEGRITY_ALERTS="$WAIO_TEST_ROOT/state/.audit_log_integrity_alerts.jsonl"
  export WAIO_AUDIT_LOG_LOCK_DIR="$WAIO_TEST_ROOT/state/.audit_log.lock"
  export WAIO_RECOVER_RECONCILE_MARKER="$WAIO_TEST_ROOT/state/.last_reconciled_trigger"
  export WAIO_EGRESS_ALLOWLIST="$WAIO_TEST_ROOT/state/egress_allowlist.conf"
  export WAIO_GUARDIAN_STATE_FILE="$WAIO_TEST_ROOT/state/GUARDIAN_STATE"
  export WAIO_GUARDIAN_QUARANTINE_FILE="$WAIO_TEST_ROOT/state/GUARDIAN_QUARANTINE"
  export WAIO_GUARDIAN_CRITICAL_EVENTS_FILE="$WAIO_TEST_ROOT/state/GUARDIAN_CRITICAL_EVENTS"
  export WAIO_GUARDIAN_STATE_LOCK_DIR="$WAIO_TEST_ROOT/state/.guardian_state.lock"
  export WAIO_DUCOPA_STATE_FILE="$WAIO_TEST_ROOT/state/DUCOPA_STATE"
  export WAIO_DUCOPA_AUDIT_LOG="$WAIO_TEST_ROOT/state/ducopa-audit.jsonl"
  printf 'localhost|3000|test-isolation fixture entry\n' > "$WAIO_EGRESS_ALLOWLIST"

  for v in $WAIO_TEST_SIDE_EFFECT_FLAGS; do unset "$v"; done
  export HOME="$WAIO_TEST_ROOT/home"

  local stub
  for stub in sudo ssh scp curl nc osascript; do
    cat > "$WAIO_TEST_ROOT/bin/$stub" <<EOF
#!/bin/bash
# test-isolation stub: records the call, never acts, always fails.
printf '%s\n' "\$*" >> "$WAIO_TEST_ROOT/stub-calls/$stub"
echo "[TEST ISOLATION] stub '$stub' refused (tests may not run real $stub)" >&2
exit 1
EOF
    chmod +x "$WAIO_TEST_ROOT/bin/$stub"
  done
  export PATH="$WAIO_TEST_ROOT/bin:$PATH"
  return 0
}

waio_test_assert_isolated() {
  if [ -z "${WAIO_TEST_ROOT:-}" ] || [ ! -d "$WAIO_TEST_ROOT" ]; then
    echo "[TEST ISOLATION] REFUSING: waio_test_isolate was not called (no WAIO_TEST_ROOT)" >&2
    return 3
  fi
  if [ -e "$HOME/.waio.env" ] || [ "$(_waio_test_realpath "$HOME")" != "$WAIO_TEST_ROOT/home" ]; then
    echo "[TEST ISOLATION] REFUSING: HOME is not the empty test home ($HOME)" >&2
    return 3
  fi
  local v
  for v in $WAIO_TEST_SIDE_EFFECT_FLAGS; do
    if [ -n "${!v:-}" ]; then
      echo "[TEST ISOLATION] REFUSING: side-effect flag $v is set" >&2
      return 3
    fi
  done
  local resolved bad=0 p
  resolved="$(cd "$WAIO_TEST_REPO" && bash -c 'source security/lib.sh >/dev/null 2>&1 || exit 9
    printf "%s\n" "$SHUTDOWN_LOCK" "$SECURITY_AUDIT_LOG" "$EGRESS_ALLOWLIST" "$AUDIT_LOG_CHECKPOINT" \
      "$AUDIT_LOG_INTEGRITY_ALERTS" "$AUDIT_LOG_LOCK_DIR" "${WAIO_RECOVER_RECONCILE_MARKER:-$SECURITY_LIB_DIR/state/.last_reconciled_trigger}" \
      "$GUARDIAN_STATE_FILE" "$GUARDIAN_QUARANTINE_FILE" "$GUARDIAN_CRITICAL_EVENTS_FILE" "$GUARDIAN_STATE_LOCK_DIR"')" || {
    echo "[TEST ISOLATION] REFUSING: could not resolve security/lib.sh paths" >&2
    return 3
  }
  while IFS= read -r p; do
    [ -n "$p" ] || continue
    case "$(_waio_test_realpath "$p")" in
      "$WAIO_TEST_ROOT"/*) ;;
      *) echo "[TEST ISOLATION] REFUSING: security/lib.sh resolves $p outside the test root" >&2; bad=1 ;;
    esac
    if waio_test_is_production_path "$p"; then
      echo "[TEST ISOLATION] REFUSING: security/lib.sh resolves a production path: $p" >&2
      bad=1
    fi
  done <<< "$resolved"
  [ "$bad" -eq 0 ] || return 3
  return 0
}

waio_test_stub_calls() {
  local f="$WAIO_TEST_ROOT/stub-calls/$1"
  if [ -f "$f" ]; then wc -l < "$f" | tr -d ' '; else echo 0; fi
}

waio_test_cleanup() {
  case "${WAIO_TEST_ROOT:-}" in
    */waio-test-*.*) rm -rf "$WAIO_TEST_ROOT" ;;
  esac
}
