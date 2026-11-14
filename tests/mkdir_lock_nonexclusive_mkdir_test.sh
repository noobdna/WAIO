#!/bin/bash
set -uo pipefail

# tests/mkdir_lock_nonexclusive_mkdir_test.sh -- regression suite for the
# Ubuntu 26.04 lock race. Covers all six mkdir-based lock implementations:
#   security/lib.sh                                  _waio_mkdir_lock_*
#   security/incident_learning/lock.sh               il_lock_*
#   security/red_alert/containment_approval_gate.sh  _cag_lock_*
#   security/self_dev/dev_approval_gate.sh           _sda_lock_*
#   security/killswitch/killswitch_gate.sh           _ks_lock_*
#   security/ducopa.sh                               _ducopa_lock/_ducopa_unlock
#
# Root cause (diagnosed 2026-11-05 on GitHub's ubuntu-26.04 runner): uutils
# coreutils 0.10 `mkdir` (no -p) runs statx() before mkdir(2). When
# mkdir(2) then returns EEXIST because a concurrent caller has just created
# the directory, it sees a directory and exits 0. Two callers are both told
# they created it. Every lock above treated that exit status as exclusive
# ownership, so two processes held the lock at once:
#   - audit-log hash chain broken (audit_log_integrity_test I10)
#   - lost transitions (containment_approval_gate_test I27/I28,
#     incident_learning_lock_test L10)
# GNU and BSD mkdir report EEXIST, so the bug never showed on 24.04 or
# macOS.
#
# The fix: ownership is the O_EXCL (bash noclobber) creation of
# LOCK_DIR/owner, which bash itself performs, not mkdir's exit status. The
# steal mutex is claimed the same way.
#
# This suite needs no 26.04 runner. A `mkdir` shim on PATH reproduces the
# worst case deterministically: it reports success whenever the directory
# exists afterwards, i.e. it never reports EEXIST. Before the fix, N1, N3,
# N5 and N6 fail every time.
#
#   N1  a contender does not acquire a lock already held by a live holder,
#       even though mkdir "succeeds" -- and the holder's owner token is
#       untouched
#   N2  with the shim, an uncontended acquire + release still works
#   N3  a live steal mutex (claimed by another stealer) still blocks
#       stealing, even though mkdir "succeeds" on it
#   N4  with the shim, a genuinely stale lock (dead holder) is still
#       recovered and no steal mutex is left behind
#   N5  ducopa: a contender times out instead of acquiring a held lock
#   N6  ducopa: lock + unlock with the shim leaves no lock directory
#   N7  end to end: 12 concurrent audit_log() writers with the shim on PATH
#       produce a fully valid hash chain (3 rounds)
#
# All fixtures live in a scratch temp dir; nothing under security/state
# or logs/ is touched.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"

PASS=0
FAIL=0
declare -a FAILURES=()

assert_eq() {
  local label="$1" expected="$2" actual="$3"
  if [ "$expected" = "$actual" ]; then
    PASS=$((PASS + 1)); echo "  PASS: $label"
  else
    FAIL=$((FAIL + 1)); FAILURES+=("$label (expected='$expected' actual='$actual')")
    echo "  FAIL: $label (expected='$expected' actual='$actual')"
  fi
}

FIXTURE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/waio-mkdir-nonexclusive-test.XXXXXX")"
LIVE_PID=""
trap '[ -n "$LIVE_PID" ] && kill "$LIVE_PID" 2>/dev/null; rm -rf "$FIXTURE_DIR"' EXIT

sleep 0 & DEAD_PID=$!; wait "$DEAD_PID" 2>/dev/null
sleep 300 & LIVE_PID=$!

# The non-exclusive mkdir: run the real one, then report success if the
# directory exists, whoever created it.
REAL_MKDIR="$(command -v mkdir)"
SHIM="$FIXTURE_DIR/shim"
"$REAL_MKDIR" -p "$SHIM"
cat > "$SHIM/mkdir" <<EOF
#!/bin/bash
"$REAL_MKDIR" "\$@" 2>/dev/null
for a in "\$@"; do case "\$a" in -*) ;; *) [ -d "\$a" ] || exit 1 ;; esac; done
exit 0
EOF
chmod +x "$SHIM/mkdir"

assert_eq "shim sanity: mkdir on an existing directory reports success" "0" \
  "$("$REAL_MKDIR" -p "$FIXTURE_DIR/sanity"; PATH="$SHIM:$PATH" mkdir "$FIXTURE_DIR/sanity"; echo $?)"

# run_impl IMPL SCRIPT -- same loader as tests/mkdir_lock_ownership_test.sh,
# always with the shim first on PATH.
run_impl() {
  local impl="$1" script="$2"
  local load acq rel
  case "$impl" in
    lib) load="security/lib.sh"; acq="_waio_mkdir_lock_acquire"; rel="_waio_mkdir_lock_release" ;;
    il)  load="security/incident_learning/lock.sh"; acq="il_lock_acquire"; rel="il_lock_release" ;;
    cag) load="security/red_alert/containment_approval_gate.sh"; acq="_cag_lock_acquire"; rel="_cag_lock_release" ;;
    sda) load="security/self_dev/dev_approval_gate.sh"; acq="_sda_lock_acquire"; rel="_sda_lock_release" ;;
    ks)  load="$FIXTURE_DIR/ks_lock.sh"; acq="_ks_lock_acquire"; rel="_ks_lock_release"
         awk '/^_ks_lock_[a-z_]*\(\) \{/,/^}/' security/killswitch/killswitch_gate.sh > "$load" ;;
  esac
  CONTAINMENT_APPROVAL_STATE_DIR="$FIXTURE_DIR/state-cag" \
  CONTAINMENT_APPROVAL_AUDIT_LOG="$FIXTURE_DIR/state-cag/audit.jsonl" \
  DEV_APPROVAL_STATE_DIR="$FIXTURE_DIR/state-sda" \
  DEV_APPROVAL_AUDIT_LOG="$FIXTURE_DIR/state-sda/audit.jsonl" \
  WAIO_AUDIT_LOG="$FIXTURE_DIR/lib-audit.jsonl" \
  WAIO_AUDIT_LOG_CHECKPOINT="$FIXTURE_DIR/lib-checkpoint" \
  WAIO_AUDIT_INTEGRITY_ALERTS="$FIXTURE_DIR/lib-alerts.jsonl" \
  WAIO_AUDIT_LOG_LOCK_DIR="$FIXTURE_DIR/lib-lock" \
  WAIO_SHUTDOWN_LOCK="$FIXTURE_DIR/SHUTDOWN.lock" \
  WAIO_GUARDIAN_STATE_FILE="$FIXTURE_DIR/GUARDIAN_STATE" \
  WAIO_GUARDIAN_QUARANTINE_FILE="$FIXTURE_DIR/GUARDIAN_QUARANTINE" \
  WAIO_GUARDIAN_CRITICAL_EVENTS_FILE="$FIXTURE_DIR/GUARDIAN_CRITICAL_EVENTS" \
  WAIO_DUCOPA_STATE_FILE="$FIXTURE_DIR/DUCOPA_STATE" \
  WAIO_DUCOPA_AUDIT_LOG="$FIXTURE_DIR/ducopa-audit.jsonl" \
  ACQ="$acq" REL="$rel" PATH="$SHIM:$PATH" \
    bash -c 'source "$1" >/dev/null 2>&1; eval "$2"' _ "$load" "$script" 2>/dev/null
}

exists() { [ -e "$1" ] && echo true || echo false; }

for impl in lib il cag sda ks; do
  echo ""
  echo "[$impl] N1 a contender does not acquire a held lock, even though mkdir \"succeeds\""
  L="$FIXTURE_DIR/$impl-n1"; "$REAL_MKDIR" "$L"
  printf '%s' "$LIVE_PID" > "$L/holder.pid"; printf 'H-token' > "$L/owner"
  assert_eq "$impl N1 contender gives up (returns 1)" "1" "$(L="$L" run_impl "$impl" '"$ACQ" "$L" 3; echo $?')"
  assert_eq "$impl N1 holder's owner token untouched" "H-token" "$(cat "$L/owner" 2>/dev/null)"
  assert_eq "$impl N1 holder.pid untouched" "$LIVE_PID" "$(cat "$L/holder.pid" 2>/dev/null)"

  echo "[$impl] N2 uncontended acquire + release still works with the shim"
  L="$FIXTURE_DIR/$impl-n2"
  assert_eq "$impl N2 acquire+release rc" "0" "$(L="$L" run_impl "$impl" '"$ACQ" "$L" 3 || exit 9; [ -s "$L/owner" ] || exit 8; "$REL" "$L"; echo $?')"
  assert_eq "$impl N2 lock directory gone" "false" "$(exists "$L")"

  echo "[$impl] N3 a live steal mutex still blocks stealing"
  L="$FIXTURE_DIR/$impl-n3"; "$REAL_MKDIR" "$L"
  # A stale lock as the fixed code leaves one: dead holder plus its owner
  # token, so the contender cannot claim it and must go through the steal
  # path.
  printf '%s' "$DEAD_PID" > "$L/holder.pid"; printf 'D-token' > "$L/owner"; : > "$L/old-was-here"; touch -t 202001010000 "$L"
  "$REAL_MKDIR" "$L.steal"; : > "$L.steal/owner"
  assert_eq "$impl N3 acquire gives up (returns 1)" "1" "$(L="$L" run_impl "$impl" '"$ACQ" "$L" 3; echo $?')"
  assert_eq "$impl N3 lock not stolen while another stealer holds the mutex" "true" "$(exists "$L/old-was-here")"
  assert_eq "$impl N3 the other stealer's mutex untouched" "true" "$(exists "$L.steal/owner")"

  echo "[$impl] N4 a genuinely stale lock is still recovered with the shim"
  L="$FIXTURE_DIR/$impl-n4"; "$REAL_MKDIR" "$L"
  printf '%s' "$DEAD_PID" > "$L/holder.pid"; printf 'D-token' > "$L/owner"; touch -t 202001010000 "$L"
  assert_eq "$impl N4 acquire succeeds (returns 0)" "0" "$(L="$L" run_impl "$impl" '"$ACQ" "$L" 3; echo $?')"
  assert_eq "$impl N4 holder.pid now a live pid, not the dead one" "true" "$(p="$(cat "$L/holder.pid" 2>/dev/null)"; [ -n "$p" ] && [ "$p" != "$DEAD_PID" ] && echo true || echo false)"
  assert_eq "$impl N4 owner is a fresh token, not the dead holder's" "true" "$(o="$(cat "$L/owner" 2>/dev/null)"; [ -n "$o" ] && [ "$o" != "D-token" ] && echo true || echo false)"
  assert_eq "$impl N4 no steal mutex left behind" "false" "$(exists "$L.steal")"
done

echo ""
echo "[ducopa] N5 a contender times out instead of acquiring a held lock"
DL="$FIXTURE_DIR/DUCOPA_STATE.transition.d"; "$REAL_MKDIR" "$DL"; : > "$DL/owner"; : > "$DL/H-was-here"
assert_eq "ducopa N5 _ducopa_lock returns 1" "1" \
  "$(WAIO_DUCOPA_LOCK_WAIT_S=1 run_impl lib 'source security/ducopa.sh >/dev/null 2>&1; _ducopa_lock n5; echo $?' | tail -1)"
assert_eq "ducopa N5 holder's lock untouched" "true" "$(exists "$DL/H-was-here")"
rm -rf "$DL"

echo "[ducopa] N6 lock + unlock with the shim leaves no lock directory"
assert_eq "ducopa N6 lock+unlock rc" "0" \
  "$(run_impl lib 'source security/ducopa.sh >/dev/null 2>&1; _ducopa_lock n6 || exit 9; _ducopa_unlock; echo $?' | tail -1)"
assert_eq "ducopa N6 lock directory gone" "false" "$(exists "$DL")"

echo ""
echo "[audit_log] N7 12 concurrent writers with the shim keep the hash chain valid (3 rounds)"
for round in 1 2 3; do
  R="$FIXTURE_DIR/n7-$round"; "$REAL_MKDIR" -p "$R"
  pids=()
  for ((k = 1; k <= 12; k++)); do
    WAIO_AUDIT_LOG="$R/audit.jsonl" WAIO_AUDIT_LOG_CHECKPOINT="$R/checkpoint" \
    WAIO_AUDIT_INTEGRITY_ALERTS="$R/alerts.jsonl" WAIO_AUDIT_LOG_LOCK_DIR="$R/lock" \
    WAIO_SHUTDOWN_LOCK="$R/SHUTDOWN.lock" WAIO_GUARDIAN_STATE_FILE="$R/GS" \
    WAIO_GUARDIAN_QUARANTINE_FILE="$R/GQ" WAIO_GUARDIAN_CRITICAL_EVENTS_FILE="$R/GCE" \
    PATH="$SHIM:$PATH" \
      bash -c 'source security/lib.sh; audit_log test_event n7 1 "W$1" fixture allowed "concurrent write $1"' _ "$k" &
    pids+=("$!")
  done
  for p in "${pids[@]}"; do wait "$p"; done
  assert_eq "N7 round $round all 12 writes landed" "12" "$(wc -l < "$R/audit.jsonl" | tr -d ' ')"
  assert_eq "N7 round $round chain fully valid" "ok" "$(WAIO_AUDIT_LOG="$R/audit.jsonl" WAIO_AUDIT_LOG_CHECKPOINT="$R/checkpoint" \
    WAIO_AUDIT_INTEGRITY_ALERTS="$R/alerts.jsonl" WAIO_AUDIT_LOG_LOCK_DIR="$R/lock" WAIO_SHUTDOWN_LOCK="$R/SHUTDOWN.lock" \
    WAIO_GUARDIAN_STATE_FILE="$R/GS" WAIO_GUARDIAN_QUARANTINE_FILE="$R/GQ" WAIO_GUARDIAN_CRITICAL_EVENTS_FILE="$R/GCE" \
    bash -c 'source security/lib.sh; verify_audit_log_integrity')"
done

echo ""
echo "=== Summary: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
  echo "Failures:"
  printf '  - %s\n' "${FAILURES[@]}"
  exit 1
fi
exit 0
