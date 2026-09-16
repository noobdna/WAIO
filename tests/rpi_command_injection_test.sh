#!/bin/bash
set -uo pipefail

# tests/rpi_command_injection_test.sh -- attack-simulation regression
# suite for Red Team finding #1 (2026-09-13): workers/rpi_worker.sh
# used to embed the raw request string into a remote SSH command line
# with only manual, incomplete quoting ("~/WAIO-worker/remote_worker.sh
# \"$REQUEST\""), letting a `"`, backtick, `$()`, or `;` in the request
# break out and run arbitrary commands on the Raspberry Pi. Fixed by
# security/lib.sh's shell_quote() -- see that function's own header and
# workers/rpi_worker.sh's own header for the full vulnerability/fix
# writeup.
#
# NO REAL NETWORK CALL OF ANY KIND. `ssh` is shadowed on PATH by a
# fixture script that never leaves this machine: it faithfully replays
# what a REAL remote shell would do with the exact command-line string
# real ssh would have sent -- `ssh host arg...` joins its trailing
# arguments and hands the result to the remote login shell via
# `$SHELL -c "..."` (documented OpenSSH behavior) -- by running that
# exact string through `bash -c` locally, with HOME pointed at a
# fixture directory containing a fake `~/WAIO-worker/remote_worker.sh`
# that only records what it received. This is a faithful, safe,
# entirely local simulation of the real remote-shell-parsing step the
# vulnerability lived in, not a mock that assumes the fix works.
#
# workers/rpi_worker.sh itself is exercised unmodified and end-to-end
# (not just shell_quote() in isolation) -- egress_check, the real
# ssh-command construction, everything except the actual network I/O.

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

FIXTURE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/waio-rpi-injection-test.XXXXXX")"
trap 'rm -rf "$FIXTURE_DIR"' EXIT

mkdir -p "$FIXTURE_DIR/bin" "$FIXTURE_DIR/fake_home/WAIO-worker"

# --- fake `ssh`: replays the exact remote-shell-parsing step real SSH
# would trigger, entirely locally. --------------------------------
cat > "$FIXTURE_DIR/bin/ssh" <<'FAKESSH'
#!/bin/bash
# Records every invocation (for the test's own sanity checks), then
# takes the LAST argument -- the one remote command string real `ssh
# host arg...` would have joined and sent -- and runs it exactly the
# way a remote login shell would: `bash -c "$REMOTE_CMD"`, with HOME
# pointed at a fixture "home directory" so `~/WAIO-worker/...` resolves
# to a script this test controls instead of a real path.
REMOTE_CMD="${@: -1}"
{
  echo "--- ssh invocation ---"
  for a in "$@"; do echo "ARG: $a"; done
  echo "REMOTE_CMD: $REMOTE_CMD"
} >> "$FAKE_SSH_LOG"
HOME="$FAKE_SSH_HOME" bash -c "$REMOTE_CMD"
FAKESSH
chmod +x "$FIXTURE_DIR/bin/ssh"

# --- fake remote_worker.sh: records exactly what it received as $1,
# does nothing else. Its OWN presence/absence is not the point of this
# suite -- remote_worker.sh lives on the real Pi, outside this repo --
# it exists here purely so the test can verify round-trip fidelity
# (the request arrives as ONE correctly-reconstructed argument) in
# addition to "no injected command ran". -----------------------------
cat > "$FIXTURE_DIR/fake_home/WAIO-worker/remote_worker.sh" <<'REMOTEWORKER'
#!/bin/bash
{
  echo "ARGC=$#"
  echo "ARG1=$1"
} > "$RPI_TEST_RECEIVED_FILE"
REMOTEWORKER
chmod +x "$FIXTURE_DIR/fake_home/WAIO-worker/remote_worker.sh"

# --- fixture egress allowlist: allows 192.168.1.150:22 without ever
# touching this deployment's real security/egress_allowlist.conf. ----
cat > "$FIXTURE_DIR/egress_allowlist.conf" <<'EOF'
192.168.1.150|22|Raspberry Pi (RPI worker) -- test fixture
EOF

export PATH="$FIXTURE_DIR/bin:$PATH"
export FAKE_SSH_HOME="$FIXTURE_DIR/fake_home"
export WAIO_EGRESS_ALLOWLIST="$FIXTURE_DIR/egress_allowlist.conf"
export WAIO_SHUTDOWN_LOCK="$FIXTURE_DIR/SHUTDOWN.lock"
export WAIO_AUDIT_LOG="$FIXTURE_DIR/audit.jsonl"
export WAIO_AUDIT_LOG_CHECKPOINT="$FIXTURE_DIR/audit_checkpoint"
export WAIO_AUDIT_INTEGRITY_ALERTS="$FIXTURE_DIR/audit_alerts.jsonl"
export WAIO_AUDIT_LOG_LOCK_DIR="$FIXTURE_DIR/audit_lock"

run_rpi_worker() {
  # run_rpi_worker REQUEST MARKER_FILE -- one clean run, fresh fixture
  # state each time, no leftover marker/received files from a previous
  # case.
  local request="$1" marker="$2"
  rm -f "$FIXTURE_DIR/audit.jsonl" "$FIXTURE_DIR/audit_checkpoint" "$FIXTURE_DIR/SHUTDOWN.lock" "$FIXTURE_DIR/log.txt"
  rm -f "$marker" "$FIXTURE_DIR/received.txt"
  export FAKE_SSH_LOG="$FIXTURE_DIR/log.txt"
  export RPI_TEST_RECEIVED_FILE="$FIXTURE_DIR/received.txt"
  ./workers/rpi_worker.sh "$request" > "$FIXTURE_DIR/out.txt" 2>&1
  echo "$?"
}

echo "=== Sanity: a benign request round-trips correctly, no injection framework false-positives ==="
MARKER="$FIXTURE_DIR/PWNED_sanity"
run_rpi_worker "system check please" "$MARKER" > /tmp/waio_rpi_test_rc.$$; RC="$(cat /tmp/waio_rpi_test_rc.$$)"; rm -f /tmp/waio_rpi_test_rc.$$
assert_eq "S1 rpi_worker exit code" "0" "$RC"
assert_eq "S1 no marker created" "false" "$([ -e "$MARKER" ] && echo true || echo false)"
assert_contains "S1 remote script received exactly the original request" "$(cat "$FIXTURE_DIR/received.txt" 2>/dev/null)" "ARG1=system check please"
assert_contains "S1 argc was exactly 1 (single argument, not split on spaces)" "$(cat "$FIXTURE_DIR/received.txt" 2>/dev/null)" "ARGC=1"

echo
echo "=== Attack simulation: each payload must (a) not create its marker file and (b) arrive intact as ARG1 ==="

declare -a PAYLOADS=(
  'foo" ; touch __MARKER__ ; echo "'
  'foo`touch __MARKER__`bar'
  'foo$(touch __MARKER__)bar'
  "it's a test; touch __MARKER__"
  'a && touch __MARKER__ && b'
  'a || touch __MARKER__'
  'a | touch __MARKER__'
  "'; touch __MARKER__ #"
  '"; touch __MARKER__ #'
  "multi''''quote'attempt; touch __MARKER__"
)

i=0
for payload_template in "${PAYLOADS[@]}"; do
  i=$((i + 1))
  MARKER="$FIXTURE_DIR/PWNED_$i"
  PAYLOAD="${payload_template//__MARKER__/$MARKER}"
  RC="$(run_rpi_worker "$PAYLOAD" "$MARKER")"
  assert_eq "A$i exit code (dispatch itself still succeeds)" "0" "$RC"
  assert_eq "A$i injected command did NOT execute (no marker file)" "false" "$([ -e "$MARKER" ] && echo true || echo false)"
  RECEIVED="$(cat "$FIXTURE_DIR/received.txt" 2>/dev/null | sed -n 's/^ARG1=//p')"
  assert_eq "A$i payload arrived intact as the sole argument" "$PAYLOAD" "$RECEIVED"
  assert_contains "A$i argc was exactly 1 (payload's own spaces/semicolons did not split into extra args)" "$(cat "$FIXTURE_DIR/received.txt" 2>/dev/null)" "ARGC=1"
done

echo
echo "=== [E1] egress_check still runs and still gates the SSH call (ordering unaffected by this fix) ==="
rm -f "$FIXTURE_DIR/audit.jsonl" "$FIXTURE_DIR/audit_checkpoint" "$FIXTURE_DIR/SHUTDOWN.lock" "$FIXTURE_DIR/log.txt" "$FIXTURE_DIR/received.txt"
# an allowlist with NO entry for 192.168.1.150 -- egress_check must deny
# before ssh (the fake binary) is ever invoked at all.
cat > "$FIXTURE_DIR/empty_allowlist.conf" <<'EOF'
# no destinations listed
EOF
export FAKE_SSH_LOG="$FIXTURE_DIR/log.txt"
export RPI_TEST_RECEIVED_FILE="$FIXTURE_DIR/received.txt"
OUT_E1="$(WAIO_EGRESS_ALLOWLIST="$FIXTURE_DIR/empty_allowlist.conf" ./workers/rpi_worker.sh "test" 2>&1)"; RC_E1=$?
assert_eq "E1 exit code (denied)" "1" "$RC_E1"
assert_contains "E1 error message" "$OUT_E1" "egress denied by DLP guard"
assert_eq "E1 fake ssh was never invoked" "false" "$([ -f "$FIXTURE_DIR/log.txt" ] && echo true || echo false)"

echo
echo "=== Summary: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
  echo "Failures:"
  for f in "${FAILURES[@]}"; do echo "  - $f"; done
  exit 1
fi
exit 0
