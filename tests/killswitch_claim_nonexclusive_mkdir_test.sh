#!/bin/bash
set -uo pipefail

# tests/killswitch_claim_nonexclusive_mkdir_test.sh -- regression suite for
# the Kill Switch's single-use claims under a non-exclusive mkdir.
#
# Background: #226 (tests/mkdir_lock_nonexclusive_mkdir_test.sh) fixed the
# six mkdir-based LOCK functions for the Ubuntu 26.04 / uutils coreutils
# 0.10 race, where `mkdir` (no -p) can tell two concurrent callers they both
# created the directory. security/killswitch/killswitch_gate.sh also used a
# bare `mkdir DIR` exit status as a single-use claim in three places that
# are not locks:
#   - command id      (replay protection: execute each id once)
#   - policy slot     (max_executions)
#   - event id        (duplicate event detection)
# On master 4e2c416 the CI regression job then failed killswitch_gate_test
# K19 ("exactly one EXECUTED": 2). These claims now go through
# _ks_claim_once (O_EXCL creation of DIR/.claim under bash noclobber).
#
# Like #226's suite, this needs no 26.04 runner: a `mkdir` shim on PATH
# that never reports EEXIST (it reports success whenever the directory
# exists afterwards) reproduces the worst case deterministically.
#
#   C1  _ks_claim_once: first claim succeeds, a second claim of the same
#       DIR fails (with and without the shim)
#   C2  a pre-fix DIR (exists, no .claim) is never claimed
#   C3  16 concurrent claimers, shim on PATH: exactly one wins (20 rounds)
#   C4  the existing killswitch_gate_test.sh passes with the shim on PATH
#       (K18 duplicate, K19 concurrent burst, K31 duplicate event, ...)
#   C5  the existing killswitch_v2_extensions_test.sh passes with the shim
#       on PATH (X6 max_executions)
#   C6  no bare `mkdir DIR` claim is left in killswitch_gate.sh outside
#       the lock functions and _ks_claim_once (static guard)
#
# Fixtures live in a scratch temp dir; the sub-suites use their own
# mktemp fixtures. Nothing under security/state or logs/ is touched.

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

FIXTURE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/waio-ks-claim-test.XXXXXX")"
trap 'rm -rf "$FIXTURE_DIR"' EXIT

GATE_SRC="security/killswitch/killswitch_gate.sh"

# Same shim as tests/mkdir_lock_nonexclusive_mkdir_test.sh.
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

echo "=== Kill Switch single-use claims under a non-exclusive mkdir ==="

assert_eq "shim sanity: mkdir on an existing directory reports success" "0" \
  "$("$REAL_MKDIR" -p "$FIXTURE_DIR/sanity"; PATH="$SHIM:$PATH" mkdir "$FIXTURE_DIR/sanity"; echo $?)"

# Load only _ks_claim_once from the real gate (the gate itself runs a CLI
# on source).
CLAIM_LIB="$FIXTURE_DIR/ks_claim.sh"
awk '/^_ks_claim_once\(\) \{/,/^}/' "$GATE_SRC" > "$CLAIM_LIB"
assert_eq "_ks_claim_once is defined in the gate" "1" "$(grep -c '^_ks_claim_once() {' "$CLAIM_LIB")"

claim() { # claim [shim|real] DIR -> prints 0/1
  local mode="$1" d="$2" p="$PATH"
  [ "$mode" = shim ] && p="$SHIM:$PATH"
  PATH="$p" bash -c 'source "$1"; _ks_claim_once "$2"' _ "$CLAIM_LIB" "$d"; echo $?
}

echo "[C1] first claim wins, a second claim of the same DIR loses"
for mode in real shim; do
  d="$FIXTURE_DIR/c1-$mode"
  assert_eq "C1 ($mode mkdir) first claim" "0" "$(claim "$mode" "$d")"
  assert_eq "C1 ($mode mkdir) .claim created" "true" "$([ -f "$d/.claim" ] && echo true || echo false)"
  assert_eq "C1 ($mode mkdir) second claim refused" "1" "$(claim "$mode" "$d")"
done

echo "[C2] a pre-fix DIR (exists, no .claim) stays used"
"$REAL_MKDIR" "$FIXTURE_DIR/c2-legacy"
assert_eq "C2 (shim) legacy DIR not claimed" "1" "$(claim shim "$FIXTURE_DIR/c2-legacy")"
assert_eq "C2 no .claim written into a legacy DIR" "false" "$([ -e "$FIXTURE_DIR/c2-legacy/.claim" ] && echo true || echo false)"

echo "[C3] 16 concurrent claimers with the shim: exactly one winner (20 rounds)"
bad_rounds=0
for round in $(seq 1 20); do
  d="$FIXTURE_DIR/c3-$round"
  out="$FIXTURE_DIR/c3-$round.out"
  : > "$out"
  for i in $(seq 1 16); do
    ( r="$(claim shim "$d")"; [ "$r" = 0 ] && echo win >> "$out" ) &
  done
  wait
  wins="$(grep -c win "$out" 2>/dev/null || true)"
  [ "$wins" = "1" ] || bad_rounds=$((bad_rounds + 1))
done
assert_eq "C3 rounds without exactly one winner" "0" "$bad_rounds"

run_suite_with_shim() { # label script
  local label="$1" script="$2" log="$FIXTURE_DIR/$(basename "$2").log" rc
  PATH="$SHIM:$PATH" bash "$script" > "$log" 2>&1; rc=$?
  assert_eq "$label exits 0 with the shim on PATH" "0" "$rc"
  if [ "$rc" -ne 0 ]; then
    grep -E '^\s*FAIL:' "$log" | head -10 | sed 's/^/      /'
  fi
  echo "      $(grep -E '=== (Summary|Results)' "$log" | tail -1)"
}

echo "[C4] killswitch_gate_test.sh with the shim (K18 duplicate, K19 burst, K31 duplicate event)"
run_suite_with_shim "C4 killswitch_gate_test.sh" tests/killswitch_gate_test.sh

echo "[C5] killswitch_v2_extensions_test.sh with the shim (X6 max_executions)"
run_suite_with_shim "C5 killswitch_v2_extensions_test.sh" tests/killswitch_v2_extensions_test.sh

echo "[C6] static guard: no bare mkdir claim left outside the lock functions and _ks_claim_once"
leftover="$(awk '
  /^_ks_lock_[a-z_]*\(\) \{/ || /^_ks_claim_once\(\) \{/ { skip=1 }
  skip && /^}/ { skip=0; next }
  !skip && !/^[[:space:]]*#/ && /(if|while|&&|\|\|)[[:space:]]*!?[[:space:]]*mkdir "/ && !/mkdir -p/ { print NR": "$0 }
' "$GATE_SRC")"
assert_eq "C6 bare mkdir claims outside helpers" "" "$leftover"

echo ""
echo "=== Summary: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
  echo "Failures:"
  for f in "${FAILURES[@]}"; do echo "  - $f"; done
  exit 1
fi
exit 0
