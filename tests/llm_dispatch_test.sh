#!/bin/bash
set -uo pipefail

# tests/llm_dispatch_test.sh -- Phase 43: OPT-IN, cost-incurring real LLM
# dispatch test for workers/research_worker.sh (representative case; see
# ARCHITECTURE.md Phase 43 for the ANALYSIS/AI expansion note).
#
# NOT wired into .github/workflows/lint.yml's regression job and NOT
# invoked by any other test file -- this is deliberate, file-level
# exclusion from CI, stronger than an in-suite skip check alone. This
# file's mere existence never spends money: nothing here calls a real
# LLM unless a human explicitly sets WAIO_ALLOW_LLM_COST_TESTS=1.
#
# Reuses the exact minimal prompt already verified end-to-end during the
# original Takomachi integration (ARCHITECTURE.md, "Takomachi
# integration Phase 2"): "Reply with exactly one word: ok" -- chosen
# there, and here, to keep token usage (and therefore cost) as small as
# possible. Does not modify workers/research_worker.sh or
# security/lib.sh in any way.
#
# Shutdown/recovery handling, deliberately distinct from
# tests/security_test.sh's G/K-series cases: this test never calls
# trigger_shutdown itself to set up a scenario, so under every expected
# outcome (opt-out, environment-limitation skip, or a genuine success)
# no shutdown lock is ever created by this test. The one case where a
# real lock COULD appear is if the real dispatch below unexpectedly
# trips a real DLP guard (payload_size_check/secret_leak_check) on this
# trivial, benign prompt -- that would be a genuine anomaly, not an
# environment limitation. This test deliberately does NOT call
# security/recover.sh to clear that automatically: doing so would be
# exactly the silent auto-recovery of a real incident this codebase's
# whole Guardian/DLP design (Phase 30/31 onward) exists to prevent. That
# one path is reported as a hard FAILURE instead, with an explicit note
# that a real shutdown lock may now be active and requires manual
# investigation via security/recover.sh -- this is the one path where
# "leave no state behind" is deliberately not honored, because leaving
# it for a human is the correct fail-closed behavior.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"
source security/lib.sh

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
  if [[ "$haystack" == *"$needle"* ]]; then
    PASS=$((PASS + 1)); echo "  PASS: $label"
  else
    FAIL=$((FAIL + 1)); FAILURES+=("$label (expected to contain '$needle')")
    echo "  FAIL: $label (expected to contain '$needle')"
  fi
}

SKIP=0
skip_case() {
  SKIP=$((SKIP + 1))
  echo "  SKIP: $1 ($2)"
}

echo "=== Phase 43: RESEARCH worker real LLM dispatch (opt-in, cost-incurring) ==="

if [ "${WAIO_ALLOW_LLM_COST_TESTS:-}" != "1" ]; then
  skip_case "M1 RESEARCH real dispatch" "opt-in required: set WAIO_ALLOW_LLM_COST_TESTS=1 to run this cost-incurring test"
else
  echo "[M1] RESEARCH worker real dispatch (minimal prompt, matches Phase 2's own verified pattern)"
  OUT_M1="$(./waio.sh -w RESEARCH "Reply with exactly one word: ok" 2>&1)"; RC_M1=$?

  case "$OUT_M1" in
    *"could not retrieve TAKOMACHI_API_KEY"*)
      skip_case "M1 RESEARCH real dispatch" "Keychain credential not retrievable in this execution context"
      ;;
    *"egress denied by DLP guard"*)
      skip_case "M1 RESEARCH real dispatch" "localhost:3000 not in this deployment's egress_allowlist.conf"
      ;;
    *"task submission failed"*|*"task fetch failed"*|*"task did not complete in time"*)
      skip_case "M1 RESEARCH real dispatch" "Takomachi not reachable/agent not responding on localhost:3000"
      ;;
    *"payload size anomaly"*|*"potential credential leak"*)
      # NOT an environment limitation -- a DLP guard actually tripped on
      # this trivial, benign prompt/response. Hard failure, never
      # auto-recovered; a real shutdown lock may now be active.
      FAIL=$((FAIL + 1))
      FAILURES+=("M1 unexpected DLP guard trip on minimal prompt -- investigate manually via security/recover.sh, do NOT auto-recover")
      echo "  FAIL: M1 unexpected DLP guard trip on a trivial prompt -- a real Emergency Shutdown may now be active."
      echo "        This test will NOT clear it automatically. Investigate manually via security/recover.sh."
      ;;
    *)
      assert_eq "M1 exit code" "0" "$RC_M1"
      assert_contains "M1 response present" "$OUT_M1" "RESEARCH WORKER] response:"
      assert_contains "M1 response looks like the expected minimal reply" "$(printf '%s' "$OUT_M1" | tr '[:upper:]' '[:lower:]')" "ok"
      ;;
  esac
fi

echo
echo "=== Summary: $PASS passed, $FAIL failed, $SKIP skipped ==="
if [ "$FAIL" -gt 0 ]; then
  echo "Failures:"
  for f in "${FAILURES[@]}"; do echo "  - $f"; done
  exit 1
fi
exit 0
