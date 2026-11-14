#!/bin/bash
set -uo pipefail

# tests/audit_log_permissive_gate_test.sh -- when an audit event cannot be
# chained (audit-log lock held by a LIVE process -> audit_log returns 75;
# lock held but the append fails -> 74), permissive actions must not
# happen (fail-closed) and restrictive / recovery actions must still
# happen (fail-safe). Each permissive action is also checked to work, and
# to be chained BEFORE it takes effect, once the lock is free.
#   G1  egress_check:          denied, no shutdown, refusal recorded
#   G2  trigger_shutdown:      proceeds, shutdown_triggered diverted (not lost)
#   G3  recover.sh:            refused, SHUTDOWN.lock stays; free -> cleared
#   G4  guardian_approve:      refused; free -> NORMAL, intent before outcome
#   G5  guardian_release:      refused, agent stays quarantined; free -> released
#   G6  guardian_quarantine:   proceeds while held (restrictive)
#   G7  ssh_guardian rollback: FAIL-SAFE (owner decision 2026-11-15) --
#                              proceeds while held; ordering when free
#   G8  ssh_guardian apply:    refused, nothing installed (needs /usr/sbin/sshd;
#                              SKIP, not counted as pass, when absent)
#   G9  default budget:        ~15 s (150 x 0.1 s) then denied
#   G10 append failure (R1):   unwritable log -> 74 -> permissive refused
#   G11 recover race (R2):     a shutdown triggered during recover's audit
#                              wait is not cleared
#   G12 release race (R3):     a re-quarantine during release's wait wins
#   G13 approve race (R4):     escalation during approve's wait wins; the
#                              transition lock is not held during the wait
#   G14 outcome records (R5):  failed release / recover / apply are recorded
#   G15 bypass marker (R6):    a diverted detection is retried, not marked
# Isolated via tests/lib/test_isolation.sh; fixtures only, no network.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR" || exit 1
# shellcheck source=tests/lib/test_isolation.sh
source tests/lib/test_isolation.sh
waio_test_isolate audit-permissive-gate || exit 3
LIVE_PID=""
cleanup() {
  [ -n "$LIVE_PID" ] && kill "$LIVE_PID" 2>/dev/null
  chmod -R u+w "$WAIO_TEST_ROOT" 2>/dev/null
  waio_test_cleanup
}
trap cleanup EXIT
waio_test_assert_isolated || exit 3

PASS=0; FAIL=0; SKIP=0
check() { if [ "$2" = "$3" ]; then PASS=$((PASS+1)); echo "  PASS: $1"; else FAIL=$((FAIL+1)); echo "  FAIL: $1 (expected '$2', got '$3')"; fi; }
yes_if() { if "$@"; then echo yes; else echo no; fi; }

sleep 300 & LIVE_PID=$!
fixture() {
  local d="$WAIO_TEST_ROOT/fx/$1"; mkdir -p "$d"
  FX="$d"
  export WAIO_AUDIT_LOG="$d/audit.jsonl" WAIO_AUDIT_LOG_CHECKPOINT="$d/checkpoint" \
    WAIO_AUDIT_INTEGRITY_ALERTS="$d/alerts.jsonl" WAIO_AUDIT_LOG_LOCK_DIR="$d/lock" \
    WAIO_SHUTDOWN_LOCK="$d/SHUTDOWN.lock" WAIO_GUARDIAN_STATE_FILE="$d/GS" \
    WAIO_GUARDIAN_QUARANTINE_FILE="$d/GQ" WAIO_GUARDIAN_CRITICAL_EVENTS_FILE="$d/GCE" \
    WAIO_GUARDIAN_STATE_LOCK_DIR="$d/gs.lock" WAIO_RECOVER_RECONCILE_MARKER="$d/reconcile.marker"
  export WAIO_AUDIT_LOG_LOCK_MAX_WAIT=3   # 0.3 s budget except where noted
  printf 'ok.example.invalid|443|test\n' > "$WAIO_EGRESS_ALLOWLIST"
}
hold_lock() { mkdir -p "$WAIO_AUDIT_LOG_LOCK_DIR"; printf 'H-token' > "$WAIO_AUDIT_LOG_LOCK_DIR/owner"; printf '%s' "$LIVE_PID" > "$WAIO_AUDIT_LOG_LOCK_DIR/holder.pid"; }
free_lock() { rm -rf "$WAIO_AUDIT_LOG_LOCK_DIR"; }
lines() { if [ -f "$1" ]; then wc -l < "$1" | tr -d ' '; else echo 0; fi; }
diverted() { grep -q "\"attempted_event_type\": \"$1\"" "$WAIO_AUDIT_INTEGRITY_ALERTS" 2>/dev/null && echo yes || echo no; }
refused() { grep "\"event_type\": \"permissive_action_refused\"" "$WAIO_AUDIT_INTEGRITY_ALERTS" 2>/dev/null | grep -q "\"attempted_event_type\": \"$1\"" && echo yes || echo no; }
chained() { grep -q "\"event_type\": *\"$1\"" "$WAIO_AUDIT_LOG" 2>/dev/null && echo yes || echo no; }
line_of() { grep -n "\"event_type\": *\"$1\"" "$WAIO_AUDIT_LOG" 2>/dev/null | head -1 | cut -d: -f1; }
before_in_log() { local a b; a="$(line_of "$1")"; b="$(line_of "$2")"; [ -n "$a" ] && [ -n "$b" ] && [ "$a" -lt "$b" ] && echo yes || echo no; }
lib() { bash -c 'source security/lib.sh; '"$1" 2>/dev/null; }
wait_for() { local i=0; while [ "$i" -lt 100 ]; do eval "$1" && return 0; sleep 0.1; i=$((i+1)); done; return 1; }
REASON="investigated the permissive gate test scenario carefully"

echo "[G1] egress_check while the audit lock is held"
fixture g1; hold_lock
lib 'egress_check ok.example.invalid 443 r s w'; rc=$?
check "G1 denied (rc 1)" 1 "$rc"
check "G1 no SHUTDOWN.lock" no "$(yes_if test -e "$WAIO_SHUTDOWN_LOCK")"
check "G1 chained log untouched" 0 "$(lines "$WAIO_AUDIT_LOG")"
check "G1 allow decision diverted" yes "$(diverted egress_allowed)"
check "G1 refusal recorded (R7)" yes "$(refused egress_allowed)"
free_lock; lib 'egress_check ok.example.invalid 443 r s w'; rc=$?
check "G1 lock free: allowed (rc 0)" 0 "$rc"
check "G1 lock free: egress_allowed chained" yes "$(chained egress_allowed)"

echo "[G2] trigger_shutdown while held"
fixture g2; hold_lock
lib 'trigger_shutdown "gate test" r s w d'
check "G2 SHUTDOWN.lock created (fail-safe)" yes "$(yes_if test -e "$WAIO_SHUTDOWN_LOCK")"
check "G2 shutdown_triggered diverted, not lost" yes "$(diverted shutdown_triggered)"

echo "[G3] recover.sh while held, then free"
bash security/recover.sh --confirm "$REASON" >/dev/null 2>&1; rc=$?
check "G3 recovery refused (rc 1)" 1 "$rc"
check "G3 SHUTDOWN.lock still present" yes "$(yes_if test -e "$WAIO_SHUTDOWN_LOCK")"
check "G3 refusal recorded (R7)" yes "$(refused recovery_confirmed)"
free_lock
bash security/recover.sh --confirm "$REASON" >/dev/null 2>&1; rc=$?
check "G3 lock free: recovery succeeds" 0 "$rc"
check "G3 lock free: SHUTDOWN.lock removed" no "$(yes_if test -e "$WAIO_SHUTDOWN_LOCK")"
check "G3 lock free: recovery chained" yes "$(chained recovery_confirmed)"

echo "[G4] guardian_approve while held"
fixture g4
lib 'guardian_set_state HUMAN_APPROVAL_REQUIRED "gate test" r tester' >/dev/null
hold_lock
lib 'guardian_approve "approved by the gate test with a long reason" r tester'; rc=$?
check "G4 approval refused (rc 1)" 1 "$rc"
check "G4 state unchanged" HUMAN_APPROVAL_REQUIRED "$(cat "$WAIO_GUARDIAN_STATE_FILE" 2>/dev/null)"
check "G4 no approval_granted outcome while refused" no "$(chained guardian_approval_granted)"
check "G4 refusal recorded (R7)" yes "$(refused guardian_approval_started)"
free_lock
lib 'guardian_approve "approved by the gate test with a long reason" r tester'; rc=$?
check "G4 lock free: approval succeeds" 0 "$rc"
check "G4 lock free: state NORMAL" NORMAL "$(cat "$WAIO_GUARDIAN_STATE_FILE" 2>/dev/null)"
check "G4 lock free: intent chained before outcome" yes "$(before_in_log guardian_approval_started guardian_approval_granted)"

echo "[G5] guardian_release_agent while held; [G6] quarantine while held"
fixture g5
lib 'guardian_quarantine_agent AGENT_X "gate test" r' >/dev/null
hold_lock
lib 'guardian_release_agent AGENT_X "release by gate test" r'; rc=$?
check "G5 release refused (rc 1)" 1 "$rc"
check "G5 agent still quarantined" yes "$(yes_if grep -Fxq AGENT_X "$WAIO_GUARDIAN_QUARANTINE_FILE")"
check "G5 refusal recorded (R7)" yes "$(refused guardian_agent_release_started)"
lib 'guardian_quarantine_agent AGENT_Y "gate test while held" r' >/dev/null
check "G6 quarantine proceeds while held (fail-safe)" yes "$(yes_if grep -Fxq AGENT_Y "$WAIO_GUARDIAN_QUARANTINE_FILE")"
free_lock
lib 'guardian_release_agent AGENT_X "release by gate test" r'; rc=$?
check "G5 lock free: release succeeds" 0 "$rc"
check "G5 lock free: agent released" no "$(yes_if grep -Fxq AGENT_X "$WAIO_GUARDIAN_QUARANTINE_FILE")"
check "G5 lock free: intent chained before outcome" yes "$(before_in_log guardian_agent_release_started guardian_agent_released)"

SG="$WAIO_TEST_ROOT/sg"; mkdir -p "$SG/state" "$SG/backups"
sg() { SSH_GUARDIAN_ALLOWLIST="$SG/allowlist.conf" SSH_GUARDIAN_DEPLOYED_CONFIG="${SG_DEPLOYED:-$SG/deployed.conf}" \
       SSH_GUARDIAN_STATE_DIR="$SG/state" SSH_GUARDIAN_BACKUP_DIR="$SG/backups" \
       bash security/generate_ssh_guardian_config.sh "$1" >/dev/null 2>&1; }

echo "[G7] ssh_guardian --rollback is FAIL-SAFE"
fixture g7
printf 'ORIGINAL\n' > "$SG/backups/50-waio-guardian.conf.20260101000000.bak"
printf 'CURRENT\n' > "$SG/deployed.conf"
hold_lock
sg --rollback; rc=$?
check "G7 rollback proceeds while held (rc 0)" 0 "$rc"
check "G7 restored while held" ORIGINAL "$(cat "$SG/deployed.conf")"
check "G7 rollback intent diverted (best effort)" yes "$(diverted ssh_guardian_rollback_started)"
check "G7 no refusal recorded (not a gate)" no "$(refused ssh_guardian_rollback_started)"
free_lock; printf 'CURRENT\n' > "$SG/deployed.conf"
sg --rollback; rc=$?
check "G7 lock free: rollback succeeds" 0 "$rc"
check "G7 lock free: intent chained before outcome" yes "$(before_in_log ssh_guardian_rollback_started ssh_guardian_rolled_back)"

HAVE_SSHD="no"; [ -x /usr/sbin/sshd ] && HAVE_SSHD="yes"   # sshd_syntax_check uses /usr/sbin/sshd
printf '192.168.1.91|host800\n192.168.1.33|ipad\n' > "$SG/allowlist.conf"
echo "[G8] ssh_guardian --apply while held"
if [ "$HAVE_SSHD" = yes ]; then
  fixture g8; printf 'CURRENT\n' > "$SG/deployed.conf"
  hold_lock
  sg --apply; rc=$?
  check "G8 apply refused (rc 1)" 1 "$rc"
  check "G8 nothing installed" CURRENT "$(cat "$SG/deployed.conf")"
  check "G8 apply intent diverted" yes "$(diverted ssh_guardian_apply_started)"
  check "G8 refusal recorded (R7)" yes "$(refused ssh_guardian_apply_started)"
  free_lock
else
  SKIP=$((SKIP+1)); echo "  SKIP: G8 (no /usr/sbin/sshd -- not counted as pass)"
fi

echo "[G9] default wait budget (~15 s) then fail-closed"
fixture g9; unset WAIO_AUDIT_LOG_LOCK_MAX_WAIT; hold_lock
t0="$(date +%s)"; lib 'egress_check ok.example.invalid 443 r s w'; rc=$?; t1="$(date +%s)"
el=$((t1 - t0))
check "G9 denied after the default budget (rc 1)" 1 "$rc"
check "G9 waited roughly 15 s (13-25 s), elapsed=${el}s" yes "$(yes_if test "$el" -ge 13 -a "$el" -le 25)"
check "G9 no shutdown" no "$(yes_if test -e "$WAIO_SHUTDOWN_LOCK")"

echo "[G10] append failure with the lock free (R1)"
fixture g10
lib 'guardian_set_state BLOCKED "g10" r tester' >/dev/null
chmod 444 "$WAIO_AUDIT_LOG"
lib 'audit_log g10_probe r s w d allowed probe'; rc=$?
check "G10 audit_log returns 74 when the append fails" 74 "$rc"
# egress first, while no shutdown is active, so the denial can only come
# from the new gate (an active shutdown would deny earlier, for another reason)
lib 'egress_check ok.example.invalid 443 r s w'; rc=$?
check "G10 egress denied" 1 "$rc"
check "G10 egress refusal recorded" yes "$(refused egress_allowed)"
check "G10 no shutdown caused by the denial" no "$(yes_if test -e "$WAIO_SHUTDOWN_LOCK")"
lib 'trigger_shutdown "g10 trip" r s w d'
check "G10 shutdown still trips with an unwritable log (fail-safe)" yes "$(yes_if test -e "$WAIO_SHUTDOWN_LOCK")"
bash security/recover.sh --confirm "$REASON" >/dev/null 2>&1; rc=$?
check "G10 recovery refused" 1 "$rc"
check "G10 SHUTDOWN.lock still present" yes "$(yes_if test -e "$WAIO_SHUTDOWN_LOCK")"
lib 'guardian_approve "approved by the gate test with a long reason" r tester'; rc=$?
check "G10 approval refused" 1 "$rc"
check "G10 state still BLOCKED" BLOCKED "$(cat "$WAIO_GUARDIAN_STATE_FILE" 2>/dev/null)"
chmod 644 "$WAIO_AUDIT_LOG"

echo "[G11] a shutdown triggered during recover's audit wait is not cleared (R2)"
fixture g11
lib 'trigger_shutdown "g11 first trip" r1 s w d'
hold_lock
OUT11="$FX/recover.out"
( WAIO_AUDIT_LOG_LOCK_MAX_WAIT=40 bash security/recover.sh --confirm "$REASON" > "$OUT11" 2>&1; echo "rc=$?" >> "$OUT11" ) &
RP=$!
wait_for 'grep -q "Current shutdown record" "$OUT11" 2>/dev/null'
sleep 0.5
WAIO_AUDIT_LOG_LOCK_MAX_WAIT=1 bash -c 'source security/lib.sh; trigger_shutdown "g11 second trip during the wait" r2 s w d' 2>/dev/null
free_lock; wait "$RP"
check "G11 recovery refused" "rc=1" "$(tail -1 "$OUT11")"
check "G11 SHUTDOWN.lock still present" yes "$(yes_if test -e "$WAIO_SHUTDOWN_LOCK")"
check "G11 recovery_aborted chained" yes "$(chained recovery_aborted)"
check "G11 abort explained to the operator" yes "$(yes_if grep -q 'new shutdown was triggered' "$OUT11")"

echo "[G12] a re-quarantine during release's audit wait wins (R3)"
fixture g12
lib 'guardian_quarantine_agent AGENT_Z "g12" r' >/dev/null
hold_lock
( WAIO_AUDIT_LOG_LOCK_MAX_WAIT=30 bash -c 'source security/lib.sh; guardian_release_agent AGENT_Z "g12 release" r' >/dev/null 2>&1; echo "rc=$?" > "$FX/release.rc" ) &
RP=$!
sleep 0.8
bash -c 'source security/lib.sh; guardian_quarantine_agent AGENT_Z "g12 re-quarantine" r2' >/dev/null 2>&1
free_lock; wait "$RP"
check "G12 release refused" "rc=1" "$(cat "$FX/release.rc")"
check "G12 agent still quarantined" yes "$(yes_if grep -Fxq AGENT_Z "$WAIO_GUARDIAN_QUARANTINE_FILE")"
check "G12 guardian_agent_release_aborted chained" yes "$(chained guardian_agent_release_aborted)"

echo "[G13] an escalation during approve's audit wait wins; no transition lock held while waiting (R4)"
fixture g13
lib 'guardian_set_state BLOCKED "g13" r tester' >/dev/null
hold_lock
( WAIO_AUDIT_LOG_LOCK_MAX_WAIT=30 bash -c 'source security/lib.sh; guardian_approve "approved by the gate test with a long reason" r tester' >/dev/null 2>&1; echo "rc=$?" > "$FX/approve.rc" ) &
RP=$!
sleep 0.8
check "G13 transition lock NOT held during the audit wait" no "$(yes_if test -d "$WAIO_GUARDIAN_STATE_LOCK_DIR.transition")"
printf 'HUMAN_APPROVAL_REQUIRED\n' > "$WAIO_GUARDIAN_STATE_FILE"   # simulated concurrent escalation
free_lock; wait "$RP"
check "G13 approval refused" "rc=1" "$(cat "$FX/approve.rc")"
check "G13 escalated state kept" HUMAN_APPROVAL_REQUIRED "$(cat "$WAIO_GUARDIAN_STATE_FILE")"
check "G13 guardian_approval_aborted chained" yes "$(chained guardian_approval_aborted)"
check "G13 no approval_granted outcome" no "$(chained guardian_approval_granted)"

echo "[G14] failed effects after a chained intent get an outcome record (R5)"
fixture g14
mkdir -p "$FX/q"; export WAIO_GUARDIAN_QUARANTINE_FILE="$FX/q/GQ"
lib 'guardian_quarantine_agent AGENT_W "g14" r' >/dev/null
chmod 555 "$FX/q"
lib 'guardian_release_agent AGENT_W "g14 release" r'; rc=$?
chmod 755 "$FX/q"
check "G14 release with an unwritable list fails (rc 1)" 1 "$rc"
check "G14 agent still quarantined" yes "$(yes_if grep -Fxq AGENT_W "$WAIO_GUARDIAN_QUARANTINE_FILE")"
check "G14 guardian_agent_release_failed chained" yes "$(chained guardian_agent_release_failed)"
check "G14 no released outcome" no "$(chained guardian_agent_released)"
mkdir -p "$FX/s"; export WAIO_SHUTDOWN_LOCK="$FX/s/SHUTDOWN.lock"
lib 'trigger_shutdown "g14 trip" r s w d'
chmod 555 "$FX/s"
bash security/recover.sh --confirm "$REASON" >/dev/null 2>&1; rc=$?
chmod 755 "$FX/s"
check "G14 recover with an unremovable lock fails (rc 1)" 1 "$rc"
check "G14 SHUTDOWN.lock still present" yes "$(yes_if test -e "$WAIO_SHUTDOWN_LOCK")"
check "G14 recovery_failed chained" yes "$(chained recovery_failed)"
if [ "$HAVE_SSHD" = yes ]; then
  mkdir -p "$FX/dd"; printf 'CURRENT\n' > "$FX/dd/deployed.conf"; chmod 555 "$FX/dd"
  SG_DEPLOYED="$FX/dd/deployed.conf" sg --apply; rc=$?
  chmod 755 "$FX/dd"
  check "G14 apply with an uninstallable target fails (rc 1)" 1 "$rc"
  check "G14 apply intent chained" yes "$(chained ssh_guardian_apply_started)"
  check "G14 ssh_guardian_apply_failed chained" yes "$(chained ssh_guardian_apply_failed)"
  check "G14 target unchanged" CURRENT "$(cat "$FX/dd/deployed.conf")"
else
  SKIP=$((SKIP+1)); echo "  SKIP: G14 apply part (no /usr/sbin/sshd -- not counted as pass)"
fi

echo "[G15] a diverted bypass detection is retried, not marked done (R6)"
fixture g15
lib 'trigger_shutdown "g15 trip" r s w d'
rm -f "$WAIO_SHUTDOWN_LOCK"   # simulated removal that skipped recover.sh
hold_lock
lib '_reconcile_recovery_audit' >/dev/null
check "G15 bypass detection diverted" yes "$(diverted shutdown_lock_bypass_suspected)"
check "G15 marker NOT written while diverted" no "$(yes_if test -s "$WAIO_RECOVER_RECONCILE_MARKER")"
# waio.sh calls _reconcile_recovery_audit under set -euo pipefail: a
# diverted detection must not abort its caller (M3, fail-safe).
check "G15 a set -euo pipefail caller continues after a diverted detection" "continued" \
  "$(bash -euo pipefail -c 'source security/lib.sh; _reconcile_recovery_audit >/dev/null 2>&1; echo continued' 2>/dev/null)"
free_lock
lib '_reconcile_recovery_audit' >/dev/null
check "G15 retried: bypass detection chained" yes "$(chained shutdown_lock_bypass_suspected)"
check "G15 marker written once chained" yes "$(yes_if test -s "$WAIO_RECOVER_RECONCILE_MARKER")"

echo
echo "=== Summary: $PASS passed, $FAIL failed, $SKIP skipped ==="
[ "$FAIL" -eq 0 ]
