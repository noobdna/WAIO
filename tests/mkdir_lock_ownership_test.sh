#!/bin/bash
set -uo pipefail

# tests/mkdir_lock_ownership_test.sh -- regression suite for two more
# races in the mkdir-based lock, after tests/mkdir_lock_unreadable_mtime_test.sh
# closed the first. Covers all four copies of the algorithm:
#   security/lib.sh                                  _waio_mkdir_lock_*
#   security/incident_learning/lock.sh               il_lock_*
#   security/red_alert/containment_approval_gate.sh  _cag_lock_*
#   security/self_dev/dev_approval_gate.sh           _sda_lock_*
#   security/killswitch/killswitch_gate.sh           _ks_lock_* (added later)
#
# Race 1 -- release was not ownership-checked: release removed the lock
# directory unconditionally. A holder whose lock had already been taken
# from it (any wrong steal) then deleted the NEXT holder's lock on its own
# release, so one wrong steal cascaded into further double-holding.
# Race 2 -- stealer vs stealer: two waiters both judged a genuinely stale
# lock (dead holder) stealable. The first removed it and re-acquired; the
# second, still acting on its earlier observation, then removed the first
# one's fresh lock -- two holders. tests/ducopa_guardian_test.sh G62 (40-way
# counter, intermittently losing increments on GitHub Actions) is the
# observed symptom of this family.
#
# Like tests/mkdir_lock_unreadable_mtime_test.sh, this does not attempt a
# real simultaneous race: it hand-crafts the lock-directory state and
# drives the exact interleaving deterministically (a `cat` fixture on PATH
# acts as the competing waiter inside the steal window).
#
# What this suite checks, for each implementation:
#   O1  acquire + release in the same shell still removes the lock
#   O2  acquire records holder.pid (unchanged) and a non-empty owner token
#   O3  a holder whose lock was replaced does NOT remove the new holder's
#       lock on release (race 1)
#   O4  a shell whose acquire gave up (fail-open) does not remove the
#       holder's lock on release
#   O5  a shell that never acquired may still release (cross-process
#       cleanup, as tests and operators use it) -- unchanged
#   O6  two acquire/release cycles in one shell both work
#   T1  stealer vs stealer: the competing waiter's fresh lock survives
#       (race 2), and the fixture really ran inside the steal window
#   T2  genuinely stale lock (dead holder) is still recovered, and no
#       steal mutex is left behind
#   T3  a live steal mutex blocks stealing (lock left intact)
#   T4  a stale steal mutex (stealer died) does not block recovery forever
#
# All fixtures live in a scratch temp dir; nothing under security/state
# is touched.

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

FIXTURE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/waio-mkdir-lock-ownership-test.XXXXXX")"
LIVE_PID=""
trap '[ -n "$LIVE_PID" ] && kill "$LIVE_PID" 2>/dev/null; rm -rf "$FIXTURE_DIR"' EXIT

# A PID that is certainly not running: spawn and reap a short process.
sleep 0 & DEAD_PID=$!; wait "$DEAD_PID" 2>/dev/null
# A PID that certainly is running for the whole suite (stands in for the
# competing holder's process).
sleep 300 & LIVE_PID=$!

REAL_CAT="$(command -v cat)"

# run_impl IMPL SCRIPT [PATH_PREFIX] -- sources IMPL's file in a fresh bash
# and runs SCRIPT with $ACQ / $REL naming that copy's acquire / release.
run_impl() {
  local impl="$1" script="$2" prefix="${3:-}"
  local load acq rel
  case "$impl" in
    lib) load="security/lib.sh"; acq="_waio_mkdir_lock_acquire"; rel="_waio_mkdir_lock_release" ;;
    il)  load="security/incident_learning/lock.sh"; acq="il_lock_acquire"; rel="il_lock_release" ;;
    cag) load="security/red_alert/containment_approval_gate.sh"; acq="_cag_lock_acquire"; rel="_cag_lock_release" ;;
    sda) load="security/self_dev/dev_approval_gate.sh"; acq="_sda_lock_acquire"; rel="_sda_lock_release" ;;
    # killswitch_gate.sh runs its CLI when sourced: load only its lock functions.
    ks)  load="$FIXTURE_DIR/ks_lock.sh"; acq="_ks_lock_acquire"; rel="_ks_lock_release"
         awk '/^_ks_lock_[a-z_]*\(\) \{/,/^}/' security/killswitch/killswitch_gate.sh > "$load" ;;
  esac
  # The two approval gates create their state/audit directories when
  # sourced; point those at the fixture so security/state and logs/
  # are never touched.
  CONTAINMENT_APPROVAL_STATE_DIR="$FIXTURE_DIR/state-cag" \
  CONTAINMENT_APPROVAL_AUDIT_LOG="$FIXTURE_DIR/state-cag/audit.jsonl" \
  DEV_APPROVAL_STATE_DIR="$FIXTURE_DIR/state-sda" \
  DEV_APPROVAL_AUDIT_LOG="$FIXTURE_DIR/state-sda/audit.jsonl" \
  ACQ="$acq" REL="$rel" PATH="${prefix:+$prefix:}$PATH" \
    bash -c 'source "$1" >/dev/null 2>&1; eval "$2"' _ "$load" "$script" 2>/dev/null
}

exists() { [ -e "$1" ] && echo true || echo false; }

for impl in lib il cag sda ks; do
  echo ""
  echo "[$impl] O1 acquire + release in the same shell removes the lock"
  L="$FIXTURE_DIR/$impl-o1"
  assert_eq "$impl O1 acquire+release rc" "0" "$(L="$L" run_impl "$impl" '"$ACQ" "$L" 3 || exit 9; "$REL" "$L"; echo $?')"
  assert_eq "$impl O1 lock directory gone" "false" "$(exists "$L")"

  echo "[$impl] O2 acquire records holder.pid and an owner token"
  L="$FIXTURE_DIR/$impl-o2"
  L="$L" run_impl "$impl" '"$ACQ" "$L" 3' >/dev/null
  assert_eq "$impl O2 holder.pid is a bare pid" "true" "$(grep -qE '^[0-9]+$' "$L/holder.pid" 2>/dev/null && echo true || echo false)"
  assert_eq "$impl O2 owner token is non-empty" "true" "$([ -s "$L/owner" ] && echo true || echo false)"

  echo "[$impl] O3 a holder whose lock was replaced does NOT remove the new holder's lock"
  L="$FIXTURE_DIR/$impl-o3"
  L="$L" LIVE_PID="$LIVE_PID" run_impl "$impl" '
    "$ACQ" "$L" 3 || exit 9
    rm -rf "$L"; mkdir "$L"                      # taken from us; a new holder C acquires
    printf "%s" "$LIVE_PID" > "$L/holder.pid"; printf "C-token" > "$L/owner"; : > "$L/C-was-here"
    "$REL" "$L"' >/dev/null
  assert_eq "$impl O3 new holder's lock still there" "true" "$(exists "$L/C-was-here")"
  assert_eq "$impl O3 new holder's owner token untouched" "C-token" "$("$REAL_CAT" "$L/owner" 2>/dev/null)"

  echo "[$impl] O4 a shell whose acquire gave up does not remove the holder's lock"
  L="$FIXTURE_DIR/$impl-o4"; mkdir "$L"; printf '%s' "$LIVE_PID" > "$L/holder.pid"; : > "$L/H-was-here"
  assert_eq "$impl O4 acquire gives up (returns 1)" "1" "$(L="$L" run_impl "$impl" '"$ACQ" "$L" 3; rc=$?; "$REL" "$L"; echo $rc')"
  assert_eq "$impl O4 holder's lock still there" "true" "$(exists "$L/H-was-here")"

  echo "[$impl] O5 a shell that never acquired may still release (cross-process cleanup)"
  L="$FIXTURE_DIR/$impl-o5"; mkdir "$L"; printf '%s' "$LIVE_PID" > "$L/holder.pid"
  L="$L" run_impl "$impl" '"$REL" "$L"' >/dev/null
  assert_eq "$impl O5 lock directory removed" "false" "$(exists "$L")"

  echo "[$impl] O6 two acquire/release cycles in one shell"
  L="$FIXTURE_DIR/$impl-o6"
  assert_eq "$impl O6 both cycles ok" "ok" "$(L="$L" run_impl "$impl" '
    "$ACQ" "$L" 3 || exit 9; "$REL" "$L"; [ -e "$L" ] && exit 8
    "$ACQ" "$L" 3 || exit 7; "$REL" "$L"; [ -e "$L" ] && exit 6; echo ok')"

  echo "[$impl] T1 stealer vs stealer: the competing waiter's fresh lock survives"
  L="$FIXTURE_DIR/$impl-t1"; mkdir "$L"; printf '%s' "$DEAD_PID" > "$L/holder.pid"; touch -t 202001010000 "$L"
  HOOK="$FIXTURE_DIR/$impl-t1-bin"; mkdir -p "$HOOK"
  # On the first read of holder.pid: report the dead pid (what this waiter
  # observed), then -- inside the window before this waiter acts -- the
  # competing waiter W1 steals the stale lock and acquires it.
  cat > "$HOOK/cat" <<EOF
#!/bin/bash
if [ "\${1:-}" = "$L/holder.pid" ] && [ ! -e "$FIXTURE_DIR/$impl-t1.fired" ]; then
  : > "$FIXTURE_DIR/$impl-t1.fired"
  "$REAL_CAT" "\$1"
  rm -rf "$L"; mkdir "$L"; printf '%s' "$LIVE_PID" > "$L/holder.pid"; : > "$L/W1-was-here"
  exit 0
fi
exec "$REAL_CAT" "\$@"
EOF
  chmod +x "$HOOK/cat"
  assert_eq "$impl T1 this waiter gives up (returns 1)" "1" "$(L="$L" run_impl "$impl" '"$ACQ" "$L" 3; echo $?' "$HOOK")"
  assert_eq "$impl T1 fixture ran inside the steal window" "true" "$(exists "$FIXTURE_DIR/$impl-t1.fired")"
  assert_eq "$impl T1 W1's fresh lock still there" "true" "$(exists "$L/W1-was-here")"

  echo "[$impl] T2 genuinely stale lock (dead holder) is still recovered"
  L="$FIXTURE_DIR/$impl-t2"; mkdir "$L"; printf '%s' "$DEAD_PID" > "$L/holder.pid"; touch -t 202001010000 "$L"
  assert_eq "$impl T2 acquire succeeds (returns 0)" "0" "$(L="$L" run_impl "$impl" '"$ACQ" "$L" 3; echo $?')"
  assert_eq "$impl T2 holder.pid now a live pid, not the dead one" "true" "$(p="$("$REAL_CAT" "$L/holder.pid" 2>/dev/null)"; [ -n "$p" ] && [ "$p" != "$DEAD_PID" ] && echo true || echo false)"
  assert_eq "$impl T2 no steal mutex left behind" "false" "$(exists "$L.steal")"

  echo "[$impl] T3 a live steal mutex blocks stealing"
  # The marker goes in BEFORE the backdating touch: creating a file inside
  # the directory resets its mtime, which would make the lock look fresh.
  L="$FIXTURE_DIR/$impl-t3"; mkdir "$L"; printf '%s' "$DEAD_PID" > "$L/holder.pid"; : > "$L/old-was-here"; touch -t 202001010000 "$L"
  mkdir "$L.steal"
  assert_eq "$impl T3 acquire gives up (returns 1)" "1" "$(L="$L" run_impl "$impl" '"$ACQ" "$L" 3; echo $?')"
  assert_eq "$impl T3 lock not stolen while another stealer holds the mutex" "true" "$(exists "$L/old-was-here")"
  assert_eq "$impl T3 the other stealer's mutex untouched" "true" "$(exists "$L.steal")"

  echo "[$impl] T4 a stale steal mutex (stealer died) does not block recovery forever"
  L="$FIXTURE_DIR/$impl-t4"; mkdir "$L"; printf '%s' "$DEAD_PID" > "$L/holder.pid"; touch -t 202001010000 "$L"
  mkdir "$L.steal"; touch -t 202001010000 "$L.steal"
  assert_eq "$impl T4 acquire succeeds (returns 0)" "0" "$(L="$L" run_impl "$impl" '"$ACQ" "$L" 3; echo $?')"
  assert_eq "$impl T4 stale mutex cleared" "false" "$(exists "$L.steal")"
done

echo ""
echo "=== Summary: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
  echo "Failures:"
  printf '  - %s\n' "${FAILURES[@]}"
  exit 1
fi
exit 0
