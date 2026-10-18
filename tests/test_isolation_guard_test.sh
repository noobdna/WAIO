#!/bin/bash
set -uo pipefail

# tests/test_isolation_guard_test.sh -- regression suite for
# tests/lib/test_isolation.sh and for the suites converted to it
# (audit finding F-17, 2026-10-18: tests/ssh_guardian_config_test.sh
# wrote fixture events into the real logs/security-audit.jsonl, and
# tests/build_incident_history_test.sh rewrote the live
# logs/incident-history-latest.json).
#
# Everything below runs inside a throwaway COPY of this tree (tracked +
# untracked non-ignored files, so gitignored real configs are never
# copied) whose "production" paths -- security/state/SHUTDOWN.lock,
# Guardian state, logs/security-audit.jsonl and its chain checkpoint,
# workers/registry.conf, logs/incident-history-latest.json -- are seeded
# with SENTINEL content. A guard bug can therefore only ever damage
# those sentinels (which is exactly what the I-series detects), never
# this checkout's real deployment state.
#   G1-G7  the helper refuses unsafe setups (pre-set production
#          overrides, missing isolation, a path re-pointed at production
#          after isolation, side-effect flags, a planted ~/.waio.env) and
#          its stubs refuse to act.
#   I1-I3  the converted suites, run in the copy, pass AND leave every
#          sentinel byte-identical (content, inode, mtime).
#   S1     static: each converted suite asserts isolation before the
#          first command that can write security state.

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

code_only() { grep -vE '^[[:space:]]*#' "$1"; }
fstat() { python3 -c 'import os,sys; s=os.stat(sys.argv[1]); print(s.st_ino, s.st_mtime_ns, s.st_size)' "$1" 2>/dev/null || echo absent; }
fsum() { if [ -f "$1" ]; then shasum -a 256 "$1" | cut -d' ' -f1; else echo absent; fi; }

echo "=== test isolation guard suite ==="

T="$(mktemp -d "${TMPDIR:-/tmp}/waio-isoguard.XXXXXX")" || exit 1
T="$(python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "$T")"
trap 'rm -rf "$T"' EXIT
C="$T/copy"
mkdir -p "$C"
git ls-files -z --cached --others --exclude-standard | xargs -0 tar cf - 2>/dev/null | (cd "$C" && tar xf -)
[ -f "$C/tests/lib/test_isolation.sh" ] || { echo "ABORT: could not build the isolated copy"; exit 1; }
mkdir -p "$C/security/state" "$C/logs" "$C/backups/ssh_guardian"

# Sentinel "production" state inside the copy.
printf 'reason: SENTINEL -- must never be read-cleared or modified\ntriggered_at: 2000-01-01T00:00:00Z\n' > "$C/security/state/SHUTDOWN.lock"
printf 'BLOCKED\n' > "$C/security/state/GUARDIAN_STATE"
printf '{"timestamp": "2000-01-01T00:00:00Z", "event_type": "sentinel", "prev_hash": "genesis"}\n' > "$C/logs/security-audit.jsonl"
printf '1:sentinelhash' > "$C/security/state/.audit_log_chain_checkpoint"
printf '{"sentinel": "live dashboard file"}\n' > "$C/logs/incident-history-latest.json"
printf 'SENTINEL-BACKUP\n' > "$C/backups/ssh_guardian/sentinel.bak"
SENTINELS="security/state/SHUTDOWN.lock security/state/GUARDIAN_STATE logs/security-audit.jsonl security/state/.audit_log_chain_checkpoint logs/incident-history-latest.json workers/registry.conf backups/ssh_guardian/sentinel.bak"
snap() { local f; for f in $SENTINELS; do printf '%s %s %s\n' "$f" "$(fsum "$C/$f")" "$(fstat "$C/$f")"; done; }
SNAP_BEFORE="$(snap)"

# helper NAME BODY -- runs BODY in a fresh bash in the copy with the
# copy's helper sourced; prints the exit code on the last line.
helper() {
  (cd "$C" && env "$@" bash -c 'source tests/lib/test_isolation.sh; '"$HELPER_BODY" >/dev/null 2>&1; echo $?) | tail -1
}

echo ""
echo "[G1] a pre-set override pointing at a production path is refused (exit 3) before anything is created"
HELPER_BODY='waio_test_isolate g1'
assert_eq "G1 WAIO_AUDIT_LOG=<repo>/logs/security-audit.jsonl refused" "3" "$(helper WAIO_AUDIT_LOG="$C/logs/security-audit.jsonl")"
assert_eq "G1 WAIO_SHUTDOWN_LOCK=<repo>/security/state/SHUTDOWN.lock refused" "3" "$(helper WAIO_SHUTDOWN_LOCK="$C/security/state/SHUTDOWN.lock")"
assert_eq "G1 SSH_GUARDIAN_DEPLOYED_CONFIG=/etc/ssh/... refused" "3" "$(helper SSH_GUARDIAN_DEPLOYED_CONFIG=/etc/ssh/sshd_config.d/50-waio-guardian.conf)"
assert_eq "G1 WAIO_INCIDENT_HISTORY_OUTPUT=<repo>/logs/... refused" "3" "$(helper WAIO_INCIDENT_HISTORY_OUTPUT="$C/logs/incident-history-latest.json")"
HELPER_BODY='waio_test_isolate g1b; rc=$?; waio_test_cleanup; exit $rc'
assert_eq "G1 a safe pre-set override is accepted (then replaced)" "0" "$(helper WAIO_AUDIT_LOG="$T/elsewhere.jsonl")"

echo ""
echo "[G2] missing isolation is refused: assert without isolate"
HELPER_BODY='waio_test_assert_isolated'
assert_eq "G2 assert without isolate -> 3" "3" "$(helper)"

echo ""
echo "[G3] isolate + assert succeeds and every resolved lib.sh path is inside the test root"
HELPER_BODY='waio_test_isolate g3 && waio_test_assert_isolated; rc=$?; waio_test_cleanup; exit $rc'
assert_eq "G3 isolate+assert -> 0" "0" "$(helper)"

echo ""
echo "[G4] a path re-pointed at production AFTER isolation is caught by the assertion"
HELPER_BODY='waio_test_isolate g4 || exit 9; unset WAIO_SHUTDOWN_LOCK; waio_test_assert_isolated; rc=$?; waio_test_cleanup; exit $rc'
assert_eq "G4 unset WAIO_SHUTDOWN_LOCK (falls back to real path) -> 3" "3" "$(helper)"
HELPER_BODY='waio_test_isolate g4b || exit 9; export WAIO_AUDIT_LOG="$PWD/logs/security-audit.jsonl"; waio_test_assert_isolated; rc=$?; waio_test_cleanup; exit $rc'
assert_eq "G4 WAIO_AUDIT_LOG re-pointed at the real log -> 3" "3" "$(helper)"
HELPER_BODY='waio_test_isolate g4c || exit 9; unset WAIO_GUARDIAN_STATE_FILE; waio_test_assert_isolated; rc=$?; waio_test_cleanup; exit $rc'
assert_eq "G4 unset WAIO_GUARDIAN_STATE_FILE -> 3" "3" "$(helper)"

echo ""
echo "[G5] side-effect flags are cleared by isolate, and re-setting one is refused"
HELPER_BODY='waio_test_isolate g5 || exit 9; [ -z "${WAIO_AUTO_NOTIFY:-}${WAIO_AUTO_GUARDIAN_NOTIFY:-}${WAIO_GUARDIAN_AUTO_QUARANTINE:-}${WAIO_AUTO_DASHBOARD_REFRESH:-}" ] || exit 8; export WAIO_AUTO_NOTIFY=1; waio_test_assert_isolated; rc=$?; waio_test_cleanup; exit $rc'
assert_eq "G5 inherited flags cleared, re-set flag refused -> 3" "3" "$(helper WAIO_AUTO_NOTIFY=1 WAIO_AUTO_GUARDIAN_NOTIFY=1 WAIO_GUARDIAN_AUTO_QUARANTINE=1)"

echo ""
echo "[G6] HOME is an empty test dir; a planted ~/.waio.env is refused"
HELPER_BODY='waio_test_isolate g6 || exit 9; [ "$HOME" = "$WAIO_TEST_ROOT/home" ] || exit 8; printf "export WAIO_SHUTDOWN_LOCK=/x\n" > "$HOME/.waio.env"; waio_test_assert_isolated; rc=$?; waio_test_cleanup; exit $rc'
assert_eq "G6 planted ~/.waio.env -> 3" "3" "$(helper)"

echo ""
echo "[G7] stubs record and refuse: sudo/ssh/nc/curl/osascript never act"
HELPER_BODY='waio_test_isolate g7 || exit 9; sudo cp /dev/null /etc/ssh/never 2>/dev/null && exit 7; ssh host true 2>/dev/null && exit 7; nc -z 192.0.2.1 22 2>/dev/null && exit 7; curl https://example.invalid 2>/dev/null && exit 7; osascript -e x 2>/dev/null && exit 7; [ "$(waio_test_stub_calls sudo):$(waio_test_stub_calls ssh):$(waio_test_stub_calls nc):$(waio_test_stub_calls curl):$(waio_test_stub_calls osascript)" = "1:1:1:1:1" ] || exit 6; waio_test_cleanup; exit 0'
assert_eq "G7 every stub refused and recorded exactly once" "0" "$(helper)"
assert_eq "G7 cleanup removed every test root created above" "0" "$(find "${TMPDIR:-/tmp}" -maxdepth 1 -name 'waio-test-g[0-9]*' 2>/dev/null | wc -l | tr -d ' ')"

echo ""
echo "[I1] the converted ssh_guardian_config_test.sh passes inside the copy"
OUT_I1="$(cd "$C" && bash tests/ssh_guardian_config_test.sh 2>&1)"; RC_I1=$?
assert_eq "I1 exit 0" "0" "$RC_I1"
assert_eq "I1 its own SG22 isolation checks ran" "true" "$([[ "$OUT_I1" == *"PASS: SG22 sudo was never invoked"* ]] && echo true || echo false)"

echo ""
echo "[I2] the converted build_incident_history_test.sh passes inside the copy"
OUT_I2="$(cd "$C" && bash tests/build_incident_history_test.sh 2>&1)"; RC_I2=$?
assert_eq "I2 exit 0" "0" "$RC_I2"

echo ""
echo "[I3] every sentinel 'production' file in the copy is byte-identical (content, inode, mtime, size)"
SNAP_AFTER="$(snap)"
assert_eq "I3 sentinels unchanged" "$SNAP_BEFORE" "$SNAP_AFTER"
assert_eq "I3 no registry backup left behind" "0" "$(find "$C/workers" -name 'registry.conf.*' | wc -l | tr -d ' ')"
assert_eq "I3 no test root left behind by the converted suites" "0" "$(find "${TMPDIR:-/tmp}" -maxdepth 1 \( -name 'waio-test-ssh-guardian-config.*' -o -name 'waio-test-build-incident-history.*' \) -newer "$C/logs/security-audit.jsonl" 2>/dev/null | wc -l | tr -d ' ')"

echo ""
echo "[S1] static: each converted suite isolates and asserts before its first state-writing command"
for spec in "tests/ssh_guardian_config_test.sh:generate_ssh_guardian_config.sh" "tests/build_incident_history_test.sh:build_incident_history.sh"; do
  f="${spec%%:*}"; target="${spec#*:}"
  assert_line="$(code_only "$f" | grep -n 'waio_test_assert_isolated' | head -1 | cut -d: -f1)"
  first_use="$(code_only "$f" | grep -n "$target" | head -1 | cut -d: -f1)"
  assert_eq "S1 $f asserts isolation before first $target call" "true" \
    "$([ -n "$assert_line" ] && [ -n "$first_use" ] && [ "$assert_line" -lt "$first_use" ] && echo true || echo false)"
  # Process substitution, not `code_only | grep -q`: under pipefail an
  # early-exiting grep -q can SIGPIPE code_only and flip this to false.
  assert_eq "S1 $f aborts (exit 3) if isolation fails" "true" \
    "$(grep -q 'waio_test_assert_isolated || {.*exit 3' <(code_only "$f") && echo true || echo false)"
done

echo ""
echo "=== Summary: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
  echo "Failures:"
  for f in "${FAILURES[@]}"; do echo "  - $f"; done
  exit 1
fi
exit 0
