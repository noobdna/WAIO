#!/bin/bash
set -uo pipefail

# tests/orchestrate_stage_timeout_test.sh -- WAIO_STAGE_TIMEOUT in
# workers/orchestrate_worker.sh: an opt-in per-batch deadline so a stage
# member that never exits cannot block the run forever.
#
# Runs against a temporary COPY of the tracked tree (fixture workers are
# added to the copy's workers/registry.conf, never to this checkout's),
# with every security/lib.sh path isolated via tests/lib/test_isolation.sh
# sourced from that copy. Only ECHO and fixture workers are dispatched:
# no Keychain, no network.

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

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
assert_contains() {
  local label="$1" haystack="$2" needle="$3"
  case "$haystack" in
    *"$needle"*) PASS=$((PASS + 1)); echo "  PASS: $label" ;;
    *) FAIL=$((FAIL + 1)); FAILURES+=("$label (expected to contain '$needle')"); echo "  FAIL: $label (expected to contain '$needle', got: $haystack)" ;;
  esac
}
assert_le() {
  local label="$1" max="$2" actual="$3"
  if [ "$actual" -le "$max" ]; then
    PASS=$((PASS + 1)); echo "  PASS: $label ($actual <= $max)"
  else
    FAIL=$((FAIL + 1)); FAILURES+=("$label ($actual > $max)"); echo "  FAIL: $label ($actual > $max)"
  fi
}

COPY="$(mktemp -d "${TMPDIR:-/tmp}/waio-stage-timeout.XXXXXX")"
(cd "$SRC_DIR" && git ls-files -z | xargs -0 tar -cf - 2>/dev/null) | (cd "$COPY" && tar -xf -)
cd "$COPY" || exit 3

# Fixture workers. HANG exec's a uniquely-tagged sleep so the test can
# prove nothing is left behind; STUBBORN ignores TERM and needs KILL.
cat > workers/hang_worker.sh <<'EOF'
#!/bin/bash
echo "[HANG WORKER] start"
exec sleep 47.13
EOF
cat > workers/stubborn_worker.sh <<'EOF'
#!/bin/bash
trap '' TERM
echo "[STUBBORN WORKER] start"
while :; do sleep 0.1; done
EOF
chmod +x workers/hang_worker.sh workers/stubborn_worker.sh
printf 'HANG|750|workers/hang_worker.sh|hang\nSTUBBORN|750|workers/stubborn_worker.sh|stubborn\n' >> workers/registry.conf

# shellcheck source=tests/lib/test_isolation.sh
source tests/lib/test_isolation.sh
waio_test_isolate orchestrate-stage-timeout || exit 3
cleanup() { waio_test_cleanup; rm -rf "$COPY"; }  # no pkill: tests never kill by pattern (serve_dashboard_test C1); S1/S4 assert nothing is left
trap cleanup EXIT
waio_test_assert_isolated || { echo "ABORT: test isolation could not be guaranteed" >&2; exit 3; }

run() {  # run PIPELINE [TIMEOUT] -> OUT, RC, DUR
  local start=$SECONDS
  if [ -n "${2:-}" ]; then
    OUT="$(WAIO_PIPELINE="$1" WAIO_STAGE_TIMEOUT="$2" ./waio.sh -w ORCHESTRATE "timeout probe" 2>&1)"
  else
    OUT="$(WAIO_PIPELINE="$1" ./waio.sh -w ORCHESTRATE "timeout probe" 2>&1)"
  fi
  RC=$?
  DUR=$((SECONDS - start))
}

echo "=== orchestrate_worker.sh WAIO_STAGE_TIMEOUT ==="

echo "[S1] a member that never exits is stopped at the deadline and reported failed (exit 124); the run ends"
run "HANG" 2
assert_eq "S1 overall exit 2 (failed: the last stage's member failed)" "2" "$RC"
assert_le "S1 run ends within timeout + grace + slack" 8 "$DUR"
assert_contains "S1 timeout is logged" "$OUT" "TIMEOUT stage 1 (HANG): still running after 2s"
assert_contains "S1 member reported failed with exit 124" "$OUT" "status=failed exit=124"
sleep 0.5
assert_eq "S1 no HANG process left behind" "0" "$(pgrep -f 'sleep 47.13' | wc -l | tr -d ' ')"

echo "[S2] a fast member does not wait for the deadline"
run "ECHO" 20
assert_eq "S2 exit 0" "0" "$RC"
assert_le "S2 finishes well before the 20 s deadline" 8 "$DUR"

echo "[S3] parallel group: the fast member's result is kept, the hung member is stopped"
run "ECHO+HANG" 2
assert_eq "S3 overall exit 2" "2" "$RC"
assert_le "S3 run ends within timeout + grace + slack" 8 "$DUR"
assert_contains "S3 ECHO still ok" "$OUT" "COLLECT stage 1 (ECHO) status=ok"
assert_contains "S3 HANG failed with 124" "$OUT" "COLLECT stage 1 (HANG) status=failed exit=124"

echo "[S4] a member that ignores TERM is KILLed after the grace period"
run "STUBBORN" 2
assert_eq "S4 overall exit 2" "2" "$RC"
assert_le "S4 run ends within timeout + grace + slack" 9 "$DUR"
assert_contains "S4 reported failed with 124" "$OUT" "status=failed exit=124"
sleep 0.3
assert_eq "S4 no STUBBORN worker left" "0" "$(pgrep -f 'workers/stubborn_worker.sh' | wc -l | tr -d ' ')"

echo "[S5] a timed-out stage is folded into the next stage like any failure; the next stage still runs"
run "HANG ECHO" 2
assert_eq "S5 overall exit 1 (degraded: last stage ok)" "1" "$RC"
assert_contains "S5 next stage ran" "$OUT" "COLLECT stage 2 (ECHO) status=ok"

echo "[S6] invalid values are refused before any stage runs"
for bad in abc 0 -1 1.5; do
  run "ECHO" "$bad"
  assert_eq "S6 '$bad' exit 1" "1" "$RC"
  assert_contains "S6 '$bad' error names the variable" "$OUT" "WAIO_STAGE_TIMEOUT must be a positive integer"
done

echo "[S7] unset: unchanged behavior (no deadline applied)"
run "ECHO"
assert_eq "S7 exit 0" "0" "$RC"
assert_eq "S7 no TIMEOUT line" "0" "$(printf '%s' "$OUT" | grep -c 'TIMEOUT stage')"

echo "[S8] isolation held: no privileged/network stub was called"
assert_eq "S8 sudo/ssh/curl/osascript stubs never called" "0:0:0:0" "$(waio_test_stub_calls sudo):$(waio_test_stub_calls ssh):$(waio_test_stub_calls curl):$(waio_test_stub_calls osascript)"

echo ""
echo "=== Summary: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
  echo "Failures:"
  for f in "${FAILURES[@]}"; do echo "  - $f"; done
  exit 1
fi
exit 0
