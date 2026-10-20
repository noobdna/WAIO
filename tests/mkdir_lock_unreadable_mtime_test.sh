#!/bin/bash
set -uo pipefail

# tests/mkdir_lock_unreadable_mtime_test.sh -- regression suite for the
# mkdir-based lock's stale-steal decision when the lock directory's
# mtime cannot be read. Covers all four copies of the algorithm:
#   security/lib.sh                            _waio_mkdir_lock_acquire
#   security/incident_learning/lock.sh         il_lock_acquire
#   security/red_alert/containment_approval_gate.sh  _cag_lock_acquire
#   security/self_dev/dev_approval_gate.sh     _sda_lock_acquire
#   security/killswitch/killswitch_gate.sh     _ks_lock_acquire (a fifth
#     copy the first pass missed; its audit-chain lock broke K36/K38 on
#     a GitHub Actions run of the 6-way K19 burst)
#
# The bug: an unreadable mtime fell back to 0, so `age` became "seconds
# since 1970" and the lock always looked stale. A live lock whose holder
# had just won mkdir but not yet written holder.pid was then deleted and
# taken by a second process -- two holders inside the critical section.
# In real use the mtime is unreadable exactly when the waiter's `stat`
# lands in the gap after the previous holder's release (the directory
# is momentarily gone); on Linux the BSD-form `stat -f %m` fails first
# and widens that gap. tests/ducopa_guardian_test.sh's own G62 (40-way
# counter, intermittently losing an increment on GitHub Actions) is the
# observed symptom.
#
# Like tests/incident_learning_lock_test.sh, this does not attempt a
# real simultaneous race: it hand-crafts the lock-directory state and
# makes `stat` unavailable via a fixture on PATH, which is the exact
# state the race produces, deterministically.
#
# What this suite checks, for each implementation:
#   U1  unreadable mtime + live lock with no holder.pid yet -> NOT stolen
#   U2  readable, genuinely stale mtime + no holder.pid -> still stolen
#       (the existing dead-holder recovery is unchanged)
#   U3  readable, stale mtime + LIVE holder pid -> not stolen (unchanged)
#   U4  unreadable mtime + dead holder -> not stolen either: staleness
#       cannot be established, so the waiter gives up after its budget
#       and the caller's own existing contract applies (documented
#       trade-off; previously such a lock was always stolen)
#   S1  static: no copy still falls back to lock_mtime=0
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

FIXTURE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/waio-mkdir-lock-mtime-test.XXXXXX")"
trap 'rm -rf "$FIXTURE_DIR"' EXIT

# `stat` that always fails: both the BSD and the GNU form the lock tries.
mkdir -p "$FIXTURE_DIR/nostat"
cat > "$FIXTURE_DIR/nostat/stat" <<'EOF'
#!/bin/bash
exit 1
EOF
chmod +x "$FIXTURE_DIR/nostat/stat"

# A PID that is certainly not running: spawn and reap a short process.
sleep 0 & DEAD_PID=$!; wait "$DEAD_PID" 2>/dev/null

# acquire IMPL LOCK_DIR [PATH_PREFIX] -- runs one acquire attempt with a
# 3-iteration budget in a fresh subshell and prints its exit code.
acquire() {
  local impl="$1" lock="$2" prefix="${3:-}"
  local load fn
  case "$impl" in
    lib) load="security/lib.sh"; fn="_waio_mkdir_lock_acquire" ;;
    il)  load="security/incident_learning/lock.sh"; fn="il_lock_acquire" ;;
    cag) load="security/red_alert/containment_approval_gate.sh"; fn="_cag_lock_acquire" ;;
    sda) load="security/self_dev/dev_approval_gate.sh"; fn="_sda_lock_acquire" ;;
    # killswitch_gate.sh runs its CLI when sourced, so load only the
    # function itself.
    ks)  load="$FIXTURE_DIR/ks_lock.sh"; fn="_ks_lock_acquire"
         sed -n '/^_ks_lock_acquire() {/,/^}/p' security/killswitch/killswitch_gate.sh > "$load" ;;
  esac
  # The two approval gates create their state/audit directories when
  # sourced; point those at the fixture so security/state and logs/
  # are never touched.
  CONTAINMENT_APPROVAL_STATE_DIR="$FIXTURE_DIR/state-cag" \
  CONTAINMENT_APPROVAL_AUDIT_LOG="$FIXTURE_DIR/state-cag/audit.jsonl" \
  DEV_APPROVAL_STATE_DIR="$FIXTURE_DIR/state-sda" \
  DEV_APPROVAL_AUDIT_LOG="$FIXTURE_DIR/state-sda/audit.jsonl" \
  PATH="${prefix:+$prefix:}$PATH" bash -c 'source "$1" >/dev/null 2>&1; "$2" "$3" 3; echo $?' _ "$load" "$fn" "$lock" 2>/dev/null
}

for impl in lib il cag sda ks; do
  echo ""
  echo "[$impl] U1 unreadable mtime + live lock with no holder.pid yet: must NOT be stolen"
  L="$FIXTURE_DIR/$impl-u1"; mkdir "$L"
  assert_eq "$impl U1 acquire gives up (returns 1)" "1" "$(acquire "$impl" "$L" "$FIXTURE_DIR/nostat")"
  assert_eq "$impl U1 the live lock directory is still there" "true" "$([ -d "$L" ] && echo true || echo false)"
  assert_eq "$impl U1 the waiter never wrote its own holder.pid into it" "false" "$([ -f "$L/holder.pid" ] && echo true || echo false)"

  echo "[$impl] U2 readable, genuinely stale mtime + no holder.pid: dead-holder recovery still steals it"
  L="$FIXTURE_DIR/$impl-u2"; mkdir "$L"; touch -t 202001010000 "$L"
  assert_eq "$impl U2 acquire succeeds (returns 0)" "0" "$(acquire "$impl" "$L")"
  assert_eq "$impl U2 new holder.pid recorded" "true" "$(grep -qE '^[0-9]+$' "$L/holder.pid" 2>/dev/null && echo true || echo false)"

  echo "[$impl] U3 readable, stale mtime + LIVE holder: not stolen"
  L="$FIXTURE_DIR/$impl-u3"; mkdir "$L"; printf '%s' "$$" > "$L/holder.pid"; touch -t 202001010000 "$L"
  assert_eq "$impl U3 acquire gives up (returns 1)" "1" "$(acquire "$impl" "$L")"
  assert_eq "$impl U3 live holder's pid untouched" "$$" "$(cat "$L/holder.pid" 2>/dev/null)"

  echo "[$impl] U4 unreadable mtime + dead holder: staleness cannot be established, so not stolen"
  L="$FIXTURE_DIR/$impl-u4"; mkdir "$L"; printf '%s' "$DEAD_PID" > "$L/holder.pid"; touch -t 202001010000 "$L"
  assert_eq "$impl U4 acquire gives up (returns 1)" "1" "$(acquire "$impl" "$L" "$FIXTURE_DIR/nostat")"
  assert_eq "$impl U4 lock directory still there" "true" "$([ -d "$L" ] && echo true || echo false)"
done

echo ""
echo "[S1] static: no copy of the algorithm still falls back to lock_mtime=0"
for f in security/lib.sh security/incident_learning/lock.sh security/red_alert/containment_approval_gate.sh security/self_dev/dev_approval_gate.sh security/killswitch/killswitch_gate.sh; do
  assert_eq "S1 $f has no lock_mtime=0 fallback" "0" "$(grep -vE '^[[:space:]]*#' "$f" | grep -cE 'lock_mtime=0\b' || true)"
done

echo ""
echo "=== Summary: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
  echo "Failures:"
  printf '  - %s\n' "${FAILURES[@]}"
  exit 1
fi
exit 0
