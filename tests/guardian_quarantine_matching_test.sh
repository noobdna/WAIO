#!/bin/bash
set -uo pipefail

# tests/guardian_quarantine_matching_test.sh -- the Guardian quarantine
# list must block a worker however its name is spelled, on every dispatch
# path, without blocking unrelated workers, and must only be released
# through the reason-checked release path.
#
# Background (2026-11-05 integration audit): guardian_is_quarantined used
# an exact-case grep -Fx, while waio.sh dispatches by the uppercase
# registry NAME. "echo", "Echo", "ECHO " or a CRLF line quarantined
# nothing (fail open). The SSH intervene wrapper passes the name exactly
# as the remote Guardian typed it.
#
# Fully isolated via tests/lib/test_isolation.sh (temp security/state,
# empty HOME, recording stubs for sudo/ssh/curl/osascript). Dispatches
# only to ECHO (and ORCHESTRATE -> ECHO), which need no Keychain and no
# network. The SSH path is exercised by running the forced-command
# wrapper locally with SSH_ORIGINAL_COMMAND set, exactly as sshd would
# invoke it -- no real SSH connection is made.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"
# shellcheck source=tests/lib/test_isolation.sh
source tests/lib/test_isolation.sh

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

waio_test_isolate guardian-quarantine-matching || exit 3
Q="$WAIO_GUARDIAN_QUARANTINE_FILE"
cleanup() { rm -rf "$Q" "$Q".tmp.* 2>/dev/null; waio_test_cleanup; }
trap cleanup EXIT
waio_test_assert_isolated || { echo "ABORT: test isolation could not be guaranteed" >&2; exit 3; }

reset_q() { rm -rf "$Q"; }
# Each helper is its own process: nothing is cached between calls, so
# every check below also proves the list is re-read from disk.
is_q() { bash -c 'source security/lib.sh; guardian_is_quarantined "$1"' _ "$1" && echo yes || echo no; }
lib() { bash -c 'source security/lib.sh; "$@"' _ "$@"; }
echo_ran() { printf '%s' "$1" | grep -c 'ECHO WORKER\] completed'; }
REASON="observed repeated policy violations from this worker during review"

echo "=== Guardian quarantine: name matching, dispatch paths, release ==="

echo "[M1] spellings in the list that must block ECHO via waio.sh -w ECHO"
for entry in 'ECHO' 'echo' 'Echo' 'eChO' ' ECHO' 'ECHO ' $'\tECHO\t' $'ECHO\r' $'echo\r'; do
  reset_q; printf '%s\n' "$entry" > "$Q"
  OUT="$(./waio.sh -w ECHO "probe" 2>&1)"; RC=$?
  label="$(printf '%q' "$entry")"
  assert_eq "M1 entry $label -> refused (exit 1)" "1" "$RC"
  assert_eq "M1 entry $label -> ECHO never ran" "0" "$(echo_ran "$OUT")"
done

echo "[M2] the dispatcher's own spelling of the target does not matter"
reset_q; printf 'echo\n' > "$Q"
for target in ECHO echo Echo; do
  OUT="$(./waio.sh -w "$target" "probe" 2>&1)"; RC=$?
  assert_eq "M2 -w $target refused" "1" "$RC"
done
OUT="$(./waio.sh "please echo this" 2>&1)"; RC=$?
assert_eq "M2 keyword-routed request to ECHO refused" "1" "$RC"
assert_eq "M2 keyword-routed ECHO never ran" "0" "$(echo_ran "$OUT")"

echo "[M3] ORCHESTRATE stage members are gated too (stages run ./waio.sh -w NAME)"
reset_q; printf 'echo\n' > "$Q"
OUT="$(WAIO_PIPELINE="ECHO" ./waio.sh -w ORCHESTRATE "probe" 2>&1)"
assert_eq "M3 ORCHESTRATE -> ECHO stage refused (ECHO never ran)" "0" "$(echo_ran "$OUT")"
OUT="$(WAIO_PIPELINE="echo" ./waio.sh -w ORCHESTRATE "probe" 2>&1)"
assert_eq "M3 ORCHESTRATE -> lowercase pipeline stage refused" "0" "$(echo_ran "$OUT")"
reset_q
OUT="$(WAIO_PIPELINE="ECHO" ./waio.sh -w ORCHESTRATE "probe" 2>&1)"
assert_eq "M3 baseline: ORCHESTRATE -> ECHO runs when not quarantined" "1" "$(echo_ran "$OUT")"

echo "[M4] no false positives: whole-name match only"
reset_q; printf 'ECH\nECHO2\nXECHO\nEARTH\nAI\n#ECHO\n\n' > "$Q"
OUT="$(./waio.sh -w ECHO "probe" 2>&1)"; RC=$?
assert_eq "M4 ECHO dispatches when only near-miss names are listed" "0" "$RC"
assert_eq "M4 ECHO ran" "1" "$(echo_ran "$OUT")"
assert_eq "M4 EARTH does not block EARTHWEATHER" "no" "$(is_q EARTHWEATHER)"
assert_eq "M4 AI does not block FXVALIDATION" "no" "$(is_q FXVALIDATION)"
assert_eq "M4 AI itself is blocked" "yes" "$(is_q ai)"
reset_q; printf 'echo\n' > "$Q"
for other in ORCHESTRATE RESEARCH ANALYSIS RPI AI HOST800 HEALTHCHECK EARTHWEATHER FXVALIDATION; do
  assert_eq "M4 quarantining ECHO does not block $other" "no" "$(is_q "$other")"
done
assert_eq "M4 empty name never matches (blank lines name no worker)" "no" "$(printf '\n\n' > "$Q"; is_q '')"

echo "[M5] guardian_quarantine_agent writes one canonical line; variants are no-ops"
reset_q
lib guardian_quarantine_agent echo "$REASON" m5
lib guardian_quarantine_agent ' Echo ' "$REASON" m5
lib guardian_quarantine_agent ECHO "$REASON" m5
assert_eq "M5 list holds exactly ECHO" "ECHO" "$(cat "$Q")"
lib guardian_quarantine_agent '' "$REASON" m5; RC=$?
assert_eq "M5 empty name refused (exit 1)" "1" "$RC"
assert_eq "M5 empty name wrote nothing" "ECHO" "$(cat "$Q")"

echo "[M6] release removes every variant of the name and nothing else"
reset_q; printf 'echo\nRESEARCH\nECHO\n Echo \necho\r\nAI\n' > "$Q"
lib guardian_release_agent eChO "$REASON" m6
assert_eq "M6 only unrelated entries remain, in order" "RESEARCH AI" "$(tr '\n' ' ' < "$Q" | sed 's/ $//')"
assert_eq "M6 ECHO no longer quarantined" "no" "$(is_q ECHO)"
OUT="$(./waio.sh -w ECHO "probe" 2>&1)"; RC=$?
assert_eq "M6 ECHO dispatches again after release" "0" "$RC"
assert_eq "M6 release of an agent not listed is a no-op" "RESEARCH AI" "$(lib guardian_release_agent HOST800 "$REASON" m6; tr '\n' ' ' < "$Q" | sed 's/ $//')"

echo "[M7] SSH intervene path (forced-command wrapper, run as sshd would)"
reset_q
OUT="$(SSH_ORIGINAL_COMMAND="echo $REASON" ./security/guardian_intervene_quarantine_wrapper.sh 2>&1)"; RC=$?
assert_eq "M7 lowercase quarantine over SSH accepted" "0" "$RC"
assert_eq "M7 written canonically" "ECHO" "$(cat "$Q" 2>/dev/null)"
OUT="$(./waio.sh -w ECHO "probe" 2>&1)"; RC=$?
assert_eq "M7 ECHO dispatch refused after SSH quarantine" "1" "$RC"
OUT="$(SSH_ORIGINAL_COMMAND="Echo $REASON" ./security/guardian_intervene_quarantine_wrapper.sh 2>&1)"; RC=$?
assert_eq "M7 mixed-case repeat reports already quarantined" "0" "$RC"
assert_eq "M7 repeat said already quarantined" "1" "$(printf '%s' "$OUT" | grep -c 'already quarantined')"
assert_eq "M7 still one line" "1" "$(wc -l < "$Q" | tr -d ' ')"
reset_q
OUT="$(SSH_ORIGINAL_COMMAND="echo too short" ./security/guardian_intervene_quarantine_wrapper.sh 2>&1)"; RC=$?
assert_eq "M7 SSH quarantine without a real reason refused" "1" "$RC"
assert_eq "M7 nothing written" "no" "$( [ -s "$Q" ] && echo yes || echo no)"

echo "[M8] release requires the WAIO-side --confirm path with a real reason"
reset_q; printf 'echo\n' > "$Q"
OUT="$(./security/guardian_release_agent.sh ECHO 2>&1)"; RC=$?
assert_eq "M8 release without --confirm refused" "1" "$RC"
OUT="$(./security/guardian_release_agent.sh ECHO --confirm "ok" 2>&1)"; RC=$?
assert_eq "M8 release with a too-short reason refused" "1" "$RC"
OUT="$(./security/guardian_release_agent.sh ECHO --confirm "aaaaaaaaaaaaaaaaaaaaaaaaa" 2>&1)"; RC=$?
assert_eq "M8 release with a low-variety reason refused" "1" "$RC"
assert_eq "M8 still quarantined after refused releases" "yes" "$(is_q ECHO)"
OUT="$(./security/guardian_release_agent.sh echo --confirm "$REASON" 2>&1)"; RC=$?
assert_eq "M8 release with a real reason accepted (lowercase arg, lowercase entry)" "0" "$RC"
assert_eq "M8 released" "no" "$(is_q ECHO)"
# Code lines only: comments and echo'd usage hints may name the release CLI.
assert_eq "M8 no SSH wrapper invokes a quarantine release" "0" "$(grep -hvE '^[[:space:]]*#|^[[:space:]]*echo ' security/guardian_*_wrapper.sh 2>/dev/null | grep -cE 'guardian_release_agent')"

echo "[M9] persistence: state survives process restarts and lives only in the list file"
reset_q
lib guardian_quarantine_agent research "$REASON" m9
assert_eq "M9 a fresh process sees the quarantine" "yes" "$(env -i PATH="$PATH" HOME="$HOME" WAIO_GUARDIAN_QUARANTINE_FILE="$Q" bash -c 'source security/lib.sh; guardian_is_quarantined RESEARCH && echo yes || echo no')"
assert_eq "M9 list file is the only record needed" "RESEARCH" "$(cat "$Q")"
chmod 000 "$Q"
if [ -r "$Q" ]; then
  echo "  SKIP: M9 unreadable-list cases (running as a user that can read mode-000 files)"
else
  OUT="$(./waio.sh -w ECHO "probe" 2>&1)"; RC=$?
  assert_eq "M9 unreadable list: dispatch still fails closed" "1" "$RC"
  lib guardian_release_agent RESEARCH "$REASON" m9 >/dev/null 2>&1
  chmod 600 "$Q"
  assert_eq "M9 a release that cannot read the list never truncates it" "RESEARCH" "$(cat "$Q")"
fi
chmod 600 "$Q" 2>/dev/null
assert_eq "M9 no temp files left behind" "0" "$(ls "$Q".tmp.* 2>/dev/null | wc -l | tr -d ' ')"

echo "[M10] audit trail records quarantine and release events"
assert_eq "M10 quarantine events audited" "yes" "$(grep -q '"guardian_agent_quarantined"' "$WAIO_AUDIT_LOG" 2>/dev/null && echo yes || echo no)"
assert_eq "M10 release events audited" "yes" "$(grep -q '"guardian_agent_released"' "$WAIO_AUDIT_LOG" 2>/dev/null && echo yes || echo no)"

echo "[M12] the deprecated orchestrator/router.sh (ran workers directly, no gates) now refuses"
reset_q; printf 'ECHO\n' > "$Q"
OUT="$(./orchestrator/router.sh "echo probe" 2>&1)"; RC=$?
assert_eq "M12 router.sh exits 1" "1" "$RC"
assert_eq "M12 router.sh never ran a worker" "0" "$(printf '%s' "$OUT" | grep -c 'WORKER\]')"
assert_eq "M12 router.sh points to ./waio.sh" "1" "$(printf '%s' "$OUT" | grep -c 'use the canonical entry point')"
reset_q

echo "[M11] isolation held: no privileged/network stub was called"
assert_eq "M11 sudo/ssh/curl/osascript stubs never called" "0:0:0:0" "$(waio_test_stub_calls sudo):$(waio_test_stub_calls ssh):$(waio_test_stub_calls curl):$(waio_test_stub_calls osascript)"

echo ""
echo "=== Summary: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
  echo "Failures:"
  for f in "${FAILURES[@]}"; do echo "  - $f"; done
  exit 1
fi
exit 0
