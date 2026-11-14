#!/bin/bash
set -uo pipefail

# tests/audit_log_permissive_gate_test.sh -- when the audit-log lock is
# held by a LIVE process (audit_log gives up and returns 75), permissive
# actions must not happen (fail-closed) and restrictive actions must still
# happen (fail-safe). Each permissive action is also checked to work, and
# to be chained BEFORE it takes effect, once the lock is free.
#   G1 egress_check:          denied (rc 1), no shutdown, allow decision diverted
#   G2 trigger_shutdown:      proceeds, shutdown_triggered diverted (not lost)
#   G3 recover.sh:            refused, SHUTDOWN.lock stays; free -> clears, chained
#   G4 guardian_approve:      refused (intent not chained), state unchanged;
#                             free -> NORMAL, intent then outcome chained
#   G5 guardian_release:      refused, agent stays quarantined; free -> released
#   G6 guardian_quarantine:   proceeds while held (restrictive)
#   G7 ssh_guardian rollback: refused, nothing restored; free -> restored
#   G8 ssh_guardian apply:    refused, nothing installed (needs a local sshd;
#                             SKIP, not counted as pass, when absent)
#   G9 default budget:        with no override, egress_check gives up after
#                             ~15 s (150 x 0.1 s) and is denied
# Isolated via tests/lib/test_isolation.sh; fixtures only, no network.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR" || exit 1
# shellcheck source=tests/lib/test_isolation.sh
source tests/lib/test_isolation.sh
waio_test_isolate audit-permissive-gate || exit 3
LIVE_PID=""
trap '[ -n "$LIVE_PID" ] && kill "$LIVE_PID" 2>/dev/null; waio_test_cleanup' EXIT
waio_test_assert_isolated || exit 3

PASS=0; FAIL=0; SKIP=0
check() { if [ "$2" = "$3" ]; then PASS=$((PASS+1)); echo "  PASS: $1"; else FAIL=$((FAIL+1)); echo "  FAIL: $1 (expected '$2', got '$3')"; fi; }
yes_if() { if "$@"; then echo yes; else echo no; fi; }

sleep 300 & LIVE_PID=$!
fixture() {
  local d="$WAIO_TEST_ROOT/fx/$1"; mkdir -p "$d"
  export WAIO_AUDIT_LOG="$d/audit.jsonl" WAIO_AUDIT_LOG_CHECKPOINT="$d/checkpoint" \
    WAIO_AUDIT_INTEGRITY_ALERTS="$d/alerts.jsonl" WAIO_AUDIT_LOG_LOCK_DIR="$d/lock" \
    WAIO_SHUTDOWN_LOCK="$d/SHUTDOWN.lock" WAIO_GUARDIAN_STATE_FILE="$d/GS" \
    WAIO_GUARDIAN_QUARANTINE_FILE="$d/GQ" WAIO_GUARDIAN_CRITICAL_EVENTS_FILE="$d/GCE" \
    WAIO_GUARDIAN_STATE_LOCK_DIR="$d/gs.lock"
  export WAIO_AUDIT_LOG_LOCK_MAX_WAIT=3   # 0.3 s budget except G9
  printf 'ok.example.invalid|443|test\n' > "$WAIO_EGRESS_ALLOWLIST"
}
hold_lock() { mkdir -p "$WAIO_AUDIT_LOG_LOCK_DIR"; printf 'H-token' > "$WAIO_AUDIT_LOG_LOCK_DIR/owner"; printf '%s' "$LIVE_PID" > "$WAIO_AUDIT_LOG_LOCK_DIR/holder.pid"; }
free_lock() { rm -rf "$WAIO_AUDIT_LOG_LOCK_DIR"; }
lines() { if [ -f "$1" ]; then wc -l < "$1" | tr -d ' '; else echo 0; fi; }
diverted() { grep -q "\"attempted_event_type\": \"$1\"" "$WAIO_AUDIT_INTEGRITY_ALERTS" 2>/dev/null && echo yes || echo no; }
chained() { grep -q "\"event_type\": *\"$1\"" "$WAIO_AUDIT_LOG" 2>/dev/null && echo yes || echo no; }
lib() { bash -c 'source security/lib.sh; '"$1" 2>/dev/null; }

echo "[G1] egress_check while the audit lock is held"
fixture g1; hold_lock
lib 'egress_check ok.example.invalid 443 r s w'; rc=$?
check "G1 denied (rc 1)" 1 "$rc"
check "G1 no SHUTDOWN.lock" no "$(yes_if test -e "$WAIO_SHUTDOWN_LOCK")"
check "G1 chained log untouched" 0 "$(lines "$WAIO_AUDIT_LOG")"
check "G1 allow decision diverted" yes "$(diverted egress_allowed)"
free_lock; lib 'egress_check ok.example.invalid 443 r s w'; rc=$?
check "G1 lock free: allowed (rc 0)" 0 "$rc"
check "G1 lock free: egress_allowed chained" yes "$(chained egress_allowed)"

echo "[G2] trigger_shutdown while held"
fixture g2; hold_lock
lib 'trigger_shutdown "gate test" r s w d'
check "G2 SHUTDOWN.lock created (fail-safe)" yes "$(yes_if test -e "$WAIO_SHUTDOWN_LOCK")"
check "G2 shutdown_triggered diverted, not lost" yes "$(diverted shutdown_triggered)"

echo "[G3] recover.sh while held, then free"
REASON="investigated the permissive gate test scenario carefully"
bash security/recover.sh --confirm "$REASON" >/dev/null 2>&1; rc=$?
check "G3 recovery refused (rc 1)" 1 "$rc"
check "G3 SHUTDOWN.lock still present" yes "$(yes_if test -e "$WAIO_SHUTDOWN_LOCK")"
check "G3 recovery_confirmed diverted" yes "$(diverted recovery_confirmed)"
free_lock; before="$(lines "$WAIO_AUDIT_LOG")"
bash security/recover.sh --confirm "$REASON" >/dev/null 2>&1; rc=$?
check "G3 lock free: recovery succeeds" 0 "$rc"
check "G3 lock free: SHUTDOWN.lock removed" no "$(yes_if test -e "$WAIO_SHUTDOWN_LOCK")"
check "G3 lock free: recovery chained" yes "$(chained recovery_confirmed)"
check "G3 lock free: chained log grew" yes "$(yes_if test "$(lines "$WAIO_AUDIT_LOG")" -gt "$before")"

echo "[G4] guardian_approve while held"
fixture g4
lib 'guardian_set_state HUMAN_APPROVAL_REQUIRED "gate test" r tester' >/dev/null
hold_lock
lib 'guardian_approve "approved by the gate test with a long reason" r tester'; rc=$?
check "G4 approval refused (rc 1)" 1 "$rc"
check "G4 state unchanged" HUMAN_APPROVAL_REQUIRED "$(cat "$WAIO_GUARDIAN_STATE_FILE" 2>/dev/null)"
check "G4 approval intent diverted" yes "$(diverted guardian_approval_started)"
check "G4 no approval_granted outcome while refused" no "$(chained guardian_approval_granted)"
free_lock
lib 'guardian_approve "approved by the gate test with a long reason" r tester'; rc=$?
check "G4 lock free: approval succeeds" 0 "$rc"
check "G4 lock free: state NORMAL" NORMAL "$(cat "$WAIO_GUARDIAN_STATE_FILE" 2>/dev/null)"
check "G4 lock free: intent and outcome chained" yes "$( [ "$(chained guardian_approval_started)" = yes ] && [ "$(chained guardian_approval_granted)" = yes ] && echo yes || echo no)"

echo "[G5] guardian_release_agent while held; [G6] quarantine while held"
fixture g5
lib 'guardian_quarantine_agent AGENT_X "gate test" r' >/dev/null
hold_lock
lib 'guardian_release_agent AGENT_X "release by gate test" r'; rc=$?
check "G5 release refused (rc 1)" 1 "$rc"
check "G5 agent still quarantined" yes "$(yes_if grep -Fxq AGENT_X "$WAIO_GUARDIAN_QUARANTINE_FILE")"
check "G5 release intent diverted" yes "$(diverted guardian_agent_release_started)"
check "G5 no released outcome while refused" no "$(chained guardian_agent_released)"
lib 'guardian_quarantine_agent AGENT_Y "gate test while held" r' >/dev/null
check "G6 quarantine proceeds while held (fail-safe)" yes "$(yes_if grep -Fxq AGENT_Y "$WAIO_GUARDIAN_QUARANTINE_FILE")"
free_lock
lib 'guardian_release_agent AGENT_X "release by gate test" r'; rc=$?
check "G5 lock free: release succeeds" 0 "$rc"
check "G5 lock free: agent released" no "$(yes_if grep -Fxq AGENT_X "$WAIO_GUARDIAN_QUARANTINE_FILE")"
check "G5 lock free: release chained" yes "$(chained guardian_agent_released)"

echo "[G7] ssh_guardian --rollback while held"
fixture g7
SG="$WAIO_TEST_ROOT/sg"; mkdir -p "$SG/state" "$SG/backups"
printf 'ORIGINAL\n' > "$SG/backups/50-waio-guardian.conf.20260101000000.bak"
printf 'CURRENT\n' > "$SG/deployed.conf"
sg() { SSH_GUARDIAN_ALLOWLIST="$SG/allowlist.conf" SSH_GUARDIAN_DEPLOYED_CONFIG="$SG/deployed.conf" \
       SSH_GUARDIAN_STATE_DIR="$SG/state" SSH_GUARDIAN_BACKUP_DIR="$SG/backups" \
       bash security/generate_ssh_guardian_config.sh "$1" >/dev/null 2>&1; }
hold_lock
sg --rollback; rc=$?
check "G7 rollback refused (rc 1)" 1 "$rc"
check "G7 nothing restored" CURRENT "$(cat "$SG/deployed.conf")"
check "G7 rollback intent diverted" yes "$(diverted ssh_guardian_rollback_started)"
free_lock
sg --rollback; rc=$?
check "G7 lock free: rollback succeeds" 0 "$rc"
check "G7 lock free: restored" ORIGINAL "$(cat "$SG/deployed.conf")"
check "G7 lock free: intent chained before outcome" yes "$(chained ssh_guardian_rollback_started)"

echo "[G8] ssh_guardian --apply while held"
if [ -x /usr/sbin/sshd ] || command -v sshd >/dev/null 2>&1; then
  fixture g8
  printf '192.168.1.91|host800\n192.168.1.33|ipad\n' > "$SG/allowlist.conf"
  printf 'CURRENT\n' > "$SG/deployed.conf"
  hold_lock
  sg --apply; rc=$?
  check "G8 apply refused (rc 1)" 1 "$rc"
  check "G8 nothing installed" CURRENT "$(cat "$SG/deployed.conf")"
  check "G8 apply intent diverted" yes "$(diverted ssh_guardian_apply_started)"
  free_lock
else
  SKIP=$((SKIP+1)); echo "  SKIP: G8 (no local sshd binary -- not counted as pass)"
fi

echo "[G9] default wait budget (~15 s) then fail-closed"
fixture g9; unset WAIO_AUDIT_LOG_LOCK_MAX_WAIT; hold_lock
t0="$(date +%s)"; lib 'egress_check ok.example.invalid 443 r s w'; rc=$?; t1="$(date +%s)"
el=$((t1 - t0))
check "G9 denied after the default budget (rc 1)" 1 "$rc"
check "G9 waited roughly 15 s (13-25 s), elapsed=${el}s" yes "$(yes_if test "$el" -ge 13 -a "$el" -le 25)"
check "G9 no shutdown" no "$(yes_if test -e "$WAIO_SHUTDOWN_LOCK")"

echo
echo "=== Summary: $PASS passed, $FAIL failed, $SKIP skipped ==="
[ "$FAIL" -eq 0 ]
