#!/bin/bash
set -uo pipefail

# tests/dev_approval_pre_push_hook_test.sh -- regression suite for
# security/self_dev/dev_approval_pre_push_hook.sh: the OPTIONAL,
# OPT-IN per-clone git pre-push hook that blocks a push to a protected
# branch (master/develop) unless an APPROVED self-development approval
# record already exists for the EXACT commit being pushed.
#
# This file is never installed as a real git hook by this suite --
# every case below invokes it directly (piping synthetic pre-push
# stdin lines through it), the same way tests/dev_approval_gate_test.sh
# exercises dev_approval_gate.sh directly. No real `git push` is ever
# attempted; no real .git/hooks/ file is ever touched.

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

assert_contains() {
  local label="$1" haystack="$2" needle="$3"
  if [[ "$haystack" == *"$needle"* ]]; then
    PASS=$((PASS + 1)); echo "  PASS: $label"
  else
    FAIL=$((FAIL + 1)); FAILURES+=("$label (expected to contain '$needle')")
    echo "  FAIL: $label (expected to contain '$needle', got: $haystack)"
  fi
}

code_only() {
  grep -vE '^[[:space:]]*#' "$1"
}

# code_executed -- code_only, further stripping bare `echo "..."` lines.
# This hook deliberately PRINTS human-readable guidance mentioning
# `git push`/`propose`/`approve` by name (telling the operator what to
# run next) without ever EXECUTING any of it -- D1/D2 below check for
# actual invocation syntax, not advisory string literals.
code_executed() {
  code_only "$1" | grep -vE '^[[:space:]]*echo '
}

HOOK=./security/self_dev/dev_approval_pre_push_hook.sh
GATE=./security/self_dev/dev_approval_gate.sh

echo "=== WAIO Self-Development Engine pre-push hook (opt-in) regression suite ==="
echo "    (security/self_dev/dev_approval_pre_push_hook.sh)"

FIXTURE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/waio-sda-hook-test.XXXXXX")"
trap 'rm -rf "$FIXTURE_DIR"' EXIT

export DEV_APPROVAL_STATE_DIR="$FIXTURE_DIR/state"
export DEV_APPROVAL_AUDIT_LOG="$FIXTURE_DIR/audit.jsonl"
export WAIO_SELF_DEV_APPROVAL_NOW="2026-10-15T00:00:00Z"

echo ""
echo "=== I-series: integration tests against the real hook/real CLI ==="

echo ""
echo "[I1] a push to a NON-protected branch (feature/demo) is always allowed, no approval id needed"
OUT="$(printf 'refs/heads/feature/demo abc111 refs/heads/feature/demo abc111\n' | WAIO_SELF_DEV_PUSH_APPROVAL_ID= $HOOK)"
assert_eq "I1 exit code 0" "0" "$?"

echo ""
echo "[I2] a push to 'master' with NO WAIO_SELF_DEV_PUSH_APPROVAL_ID set is blocked"
OUT="$(printf 'refs/heads/master abc222 refs/heads/master abc222\n' | env -u WAIO_SELF_DEV_PUSH_APPROVAL_ID $HOOK 2>&1)"
RC=$?
assert_eq "I2 exit code non-zero" "1" "$RC"
assert_contains "I2 error mentions the missing approval id" "$OUT" "requires WAIO_SELF_DEV_PUSH_APPROVAL_ID"

echo ""
echo "[I3] a push to 'develop' (the OTHER protected branch) with no approval id is ALSO blocked"
OUT="$(printf 'refs/heads/develop abc333 refs/heads/develop abc333\n' | env -u WAIO_SELF_DEV_PUSH_APPROVAL_ID $HOOK 2>&1)"
assert_eq "I3 exit code non-zero" "1" "$?"

echo ""
echo "[I4] a push to 'master' naming an approval id that does not exist is blocked"
OUT="$(printf 'refs/heads/master abc444 refs/heads/master abc444\n' | WAIO_SELF_DEV_PUSH_APPROVAL_ID=NONEXISTENT-ID $HOOK 2>&1)"
assert_eq "I4 exit code non-zero" "1" "$?"
assert_contains "I4 error mentions the status lookup failure" "$OUT" "status lookup"

echo ""
echo "[I5] *** THE GOLDEN PATH *** propose(merge_to_master, master, HEAD=i5head) -> approve -> push with that EXACT commit as local_sha succeeds"
OUT="$($GATE propose merge_to_master master i5head alice --path foo.py)"
ID5="$(python3 -c "import json,sys;print(json.load(sys.stdin)['approval_id'])" <<<"$OUT")"
$GATE approve "$ID5" masa "golden path approval, long enough reason to pass validation" > /dev/null
OUT="$(printf 'refs/heads/master i5head refs/heads/master remotesha\n' | WAIO_SELF_DEV_PUSH_APPROVAL_ID="$ID5" $HOOK 2>&1)"
assert_eq "I5 exit code 0 (push allowed)" "0" "$?"
assert_contains "I5 output confirms OK for this exact commit" "$OUT" "OK: approval id '$ID5' is APPROVED for exactly this commit ('i5head')"

echo ""
echo "[I6] *** APPROVAL-TO-COMMIT BINDING *** the SAME approved id from I5 does NOT authorize pushing a DIFFERENT commit"
OUT="$(printf 'refs/heads/master differentsha refs/heads/master remotesha\n' | WAIO_SELF_DEV_PUSH_APPROVAL_ID="$ID5" $HOOK 2>&1)"
assert_eq "I6 exit code non-zero" "1" "$?"
assert_contains "I6 error names the commit mismatch" "$OUT" "refusing to reuse an approval for a different commit"

echo ""
echo "[I7] *** APPROVAL-TO-BRANCH BINDING *** the SAME approved id from I5 (approved for target_branch master) does NOT authorize pushing to 'develop'"
OUT="$(printf 'refs/heads/develop i5head refs/heads/develop remotesha\n' | WAIO_SELF_DEV_PUSH_APPROVAL_ID="$ID5" $HOOK 2>&1)"
assert_eq "I7 exit code non-zero" "1" "$?"
assert_contains "I7 error names the branch mismatch" "$OUT" "refusing to reuse it for a different branch"

echo ""
echo "[I8] a PENDING (not yet approved) record blocks the push"
OUT="$($GATE propose merge_to_develop develop i8head alice --path foo.py)"
ID8="$(python3 -c "import json,sys;print(json.load(sys.stdin)['approval_id'])" <<<"$OUT")"
OUT="$(printf 'refs/heads/develop i8head refs/heads/develop remotesha\n' | WAIO_SELF_DEV_PUSH_APPROVAL_ID="$ID8" $HOOK 2>&1)"
assert_eq "I8 exit code non-zero" "1" "$?"
assert_contains "I8 error names the non-APPROVED status" "$OUT" "is 'PENDING', not APPROVED"

echo ""
echo "[I9] a REJECTED record blocks the push"
OUT="$($GATE propose merge_to_develop develop i9head alice --path foo.py)"
ID9="$(python3 -c "import json,sys;print(json.load(sys.stdin)['approval_id'])" <<<"$OUT")"
$GATE reject "$ID9" masa "rejected for this regression case, long enough reason" > /dev/null
OUT="$(printf 'refs/heads/develop i9head refs/heads/develop remotesha\n' | WAIO_SELF_DEV_PUSH_APPROVAL_ID="$ID9" $HOOK 2>&1)"
assert_eq "I9 exit code non-zero" "1" "$?"
assert_contains "I9 error names the REJECTED status" "$OUT" "is 'REJECTED', not APPROVED"

echo ""
echo "[I10] a single invocation covering MULTIPLE refs (one unprotected, one protected-and-approved, one protected-and-unapproved) blocks the whole push if ANY line fails, same as a real git pre-push invocation"
OUT="$($GATE propose merge_to_master master i10head alice --path foo.py)"
ID10="$(python3 -c "import json,sys;print(json.load(sys.stdin)['approval_id'])" <<<"$OUT")"
$GATE approve "$ID10" masa "multi-ref case approval, long enough reason" > /dev/null
MULTI_STDIN="refs/heads/feature/demo abc555 refs/heads/feature/demo abc555
refs/heads/master i10head refs/heads/master remotesha
refs/heads/develop unapprovedsha refs/heads/develop remotesha2"
OUT="$(printf '%s\n' "$MULTI_STDIN" | WAIO_SELF_DEV_PUSH_APPROVAL_ID="$ID10" $HOOK 2>&1)"
assert_eq "I10 overall exit code non-zero (the develop line has no matching approval)" "1" "$?"
assert_contains "I10 the master line is still reported OK individually" "$OUT" "OK: approval id '$ID10'"
assert_contains "I10 the develop line is still reported BLOCKED individually (the only id given, ID10, was approved for master -- a branch mismatch for the develop line, not a missing-id case)" "$OUT" "refusing to reuse it for a different branch"

echo ""
echo "=== D-series: structural guards ==="

echo ""
echo "[D1] this hook's ACTUAL EXECUTED CODE (comments and advisory echo/printf strings stripped) never runs git push/merge, gh pr merge, or any deploy/Guardian/DuCoPA tool -- it only reads this gate's own status verb and exits 0/non-zero. (Advisory echo text MAY mention these by name, to tell a blocked operator what to run next -- that is printed guidance, never executed, and is exactly what I2/I4/I8/I9 above already confirm behaviorally.)"
cnt=0
for pattern in '\bgit push\b' '\bgit merge\b' 'gh pr merge' 'guardian\.sh' 'guardian_intervene' 'ducopa\.sh' 'recovery_engine\.sh' '\brecover\.sh' 'decision_engine\.sh'; do
  c="$(code_executed security/self_dev/dev_approval_pre_push_hook.sh | grep -cE "$pattern" || true)"
  cnt=$((cnt + c))
done
assert_eq "D1 zero references to any execution-capable tool by name in executed code" "0" "$cnt"

echo ""
echo "[D2] this hook never EXECUTES 'propose', 'approve', or 'reject' on the gate -- it is READ-ONLY against the approval state (only a quoted \"\$GATE\" status invocation may appear as actually-executed code; advisory echo text may still SUGGEST propose/approve commands to a blocked operator, same caveat as D1)"
cnt="$(code_executed security/self_dev/dev_approval_pre_push_hook.sh | grep -cE '"\$GATE" (propose|approve|reject)' || true)"
assert_eq "D2 zero EXECUTED propose/approve/reject invocations" "0" "$cnt"

echo ""
echo "[D3] zero eval / double-expansion constructs anywhere in actual code"
cnt="$(code_only security/self_dev/dev_approval_pre_push_hook.sh | grep -cE '\beval\b|\$\(\$' || true)"
assert_eq "D3 zero eval constructs" "0" "$cnt"

echo ""
echo "[D4] this file is executable (a hook git invokes directly must have the executable bit, same lesson as this phase's own sibling gate script)"
assert_eq "D4 executable bit set" "true" "$([ -x security/self_dev/dev_approval_pre_push_hook.sh ] && echo true || echo false)"

echo ""
echo "[D5] this phase's own scope stayed entirely under security/self_dev/, tests/, TASKS.md, ARCHITECTURE.md, and one additive regression-step line in .github/workflows/lint.yml -- no OTHER pre-existing sibling file has a working-tree diff"
for f in security/red_alert/containment_approval_gate.sh security/red_alert/containment_approval_lib.py security/self_dev/dev_approval_lib.py security/lib.sh security/guardian.sh security/ducopa.sh; do
  assert_eq "D5 $f has no working-tree diff" "" "$(git diff --name-only -- "$f" 2>/dev/null)"
done

echo ""
echo "[D6] .github/workflows/lint.yml's own diff is a small, purely-additive insertion (this suite's own new regression step) -- no existing line removed, never the option-2 CI-gate design (which remains unimplemented, see TASKS.md)"
LINT_DIFF_STAT="$(git diff --numstat -- .github/workflows/lint.yml 2>/dev/null)"
LINT_REMOVED="$(awk '{print $2}' <<<"$LINT_DIFF_STAT")"
assert_eq "D6 zero lines removed from lint.yml" "0" "${LINT_REMOVED:-0}"
assert_contains "D6 lint.yml's diff adds exactly this suite's own regression step" "$(git diff -- .github/workflows/lint.yml 2>/dev/null)" "dev_approval_pre_push_hook_test.sh"

echo ""
echo "=== Summary: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
  echo "Failures:"
  for f in "${FAILURES[@]}"; do echo "  - $f"; done
  exit 1
fi
exit 0
