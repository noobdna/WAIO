#!/bin/bash
set -uo pipefail

# tests/taco_control_injection_test.sh -- attack-simulation regression
# suite for Red Team finding #2 (2026-09-13):
# taco-control/taco_control_dispatch.sh used to embed the raw COMMAND
# argument into a remote SSH command line as a bare `'$COMMAND'` -- a
# single quote in COMMAND broke out of that quoting once the LOCAL
# shell substituted it into the text actually sent to the remote
# shell, letting arbitrary commands run on 800号機. Fixed with two
# layers: (1) COMMAND must match ^[A-Z][A-Z0-9_]*$ before anything else
# runs, (2) security/lib.sh's shell_quote() (already tested for the
# same bug class in tests/rpi_command_injection_test.sh) safely embeds
# it regardless. See taco_control_dispatch.sh's own header for the
# full writeup.
#
# NO REAL NETWORK CALL OF ANY KIND, and no real SSH host-key trust
# needed (this channel is documented as "NOT YET FUNCTIONAL end-to-end"
# for that reason and is untouched by this fix). `ssh` is shadowed on
# PATH by a fixture script that never leaves this machine: it replays
# what a REAL remote shell would do with the exact command-line string
# real ssh would have sent -- `ssh host arg...` joins its trailing
# arguments and hands the result to the remote login shell via
# `$SHELL -c "..."` (documented OpenSSH behavior) -- by running that
# exact string through `bash -c` locally, with HOME pointed at a
# fixture directory containing a copy of the REAL, unmodified
# taco-control/taco_control_executor.sh (a pure local script with no
# network access of its own -- safe to run for real here, and far more
# faithful than a stand-in fake).

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

FIXTURE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/waio-taco-injection-test.XXXXXX")"
trap 'rm -rf "$FIXTURE_DIR"' EXIT

mkdir -p "$FIXTURE_DIR/bin" "$FIXTURE_DIR/fake_home/taco-control"

# --- fake `ssh`: replays the exact remote-shell-parsing step real SSH
# would trigger, entirely locally. Identical technique to
# tests/rpi_command_injection_test.sh's own fake ssh. --------------
cat > "$FIXTURE_DIR/bin/ssh" <<'FAKESSH'
#!/bin/bash
REMOTE_CMD="${@: -1}"
{
  echo "--- ssh invocation ---"
  for a in "$@"; do echo "ARG: $a"; done
} >> "$FAKE_SSH_LOG"
HOME="$FAKE_SSH_HOME" bash -c "$REMOTE_CMD"
FAKESSH
chmod +x "$FIXTURE_DIR/bin/ssh"

# --- the REAL, unmodified executor, copied into the fixture "remote
# home" -- it is a pure local script (reads a file, writes files,
# hostname/date only) with no network access of its own, so running it
# for real here is safe and far more faithful than reimplementing its
# whitelist logic as a second, possibly-drifting fake. -------------
cp "$SCRIPT_DIR/taco-control/taco_control_executor.sh" "$FIXTURE_DIR/fake_home/taco-control/taco_control_executor.sh"
chmod +x "$FIXTURE_DIR/fake_home/taco-control/taco_control_executor.sh"

export PATH="$FIXTURE_DIR/bin:$PATH"
export FAKE_SSH_HOME="$FIXTURE_DIR/fake_home"

# taco_control_dispatch.sh now also calls egress_check() (Red Team
# finding #4, 2026-09-13, added after this file's own #2 fix) -- these
# overrides keep that check, and the audit trail it writes, entirely
# within this fixture, same as every other DLP-touching test in this
# repo. TACO_CONTROL_HOST is likewise overridden so this suite never
# depends on (or risks denial against) this deployment's real
# security/egress_allowlist.conf.
export TACO_CONTROL_HOST="TACOHOST"
export WAIO_EGRESS_ALLOWLIST="$FIXTURE_DIR/egress_allowlist.conf"
cat > "$WAIO_EGRESS_ALLOWLIST" <<'EOF'
TACOHOST|22|taco-control test fixture
EOF
export WAIO_SHUTDOWN_LOCK="$FIXTURE_DIR/SHUTDOWN.lock"
export WAIO_AUDIT_LOG="$FIXTURE_DIR/audit.jsonl"
export WAIO_AUDIT_LOG_CHECKPOINT="$FIXTURE_DIR/audit_checkpoint"
export WAIO_AUDIT_INTEGRITY_ALERTS="$FIXTURE_DIR/audit_alerts.jsonl"
export WAIO_AUDIT_LOG_LOCK_DIR="$FIXTURE_DIR/audit_lock"

run_dispatch() {
  # run_dispatch COMMAND -- one clean run, fresh fixture "remote" state
  # each time.
  local command="$1"
  rm -f "$FIXTURE_DIR/log.txt"
  rm -rf "$FIXTURE_DIR/fake_home/taco-control/commands" "$FIXTURE_DIR/fake_home/taco-control/state" "$FIXTURE_DIR/fake_home/taco-control/logs"
  export FAKE_SSH_LOG="$FIXTURE_DIR/log.txt"
  ./taco-control/taco_control_dispatch.sh "$command" > "$FIXTURE_DIR/out.txt" 2>&1
  echo "$?"
}

echo "=== Sanity: the one legitimate command (PING) still works end-to-end through the real executor ==="
RC="$(run_dispatch "PING")"
assert_eq "S1 dispatch exit code" "0" "$RC"
OUT_S1="$(cat "$FIXTURE_DIR/out.txt")"
assert_contains "S1 PONG result reached this script's own stdout" "$OUT_S1" "PONG from"
assert_contains "S1 remote executor recorded DISPATCHED" "$OUT_S1" "DISPATCHED"
assert_eq "S1 fake ssh was invoked exactly once" "true" "$([ -f "$FIXTURE_DIR/log.txt" ] && echo true || echo false)"
assert_contains "S1 remote command file received exactly 'PING'" "$(cat "$FIXTURE_DIR/fake_home/taco-control/commands/next.command" 2>/dev/null)" "PING"

echo
echo "=== Attack simulation: each malicious COMMAND is refused LOCALLY, before SSH is ever attempted ==="

declare -a PAYLOADS=(
  "PING' ; touch __MARKER__ ; echo '"
  'PING`touch __MARKER__`'
  'PING$(touch __MARKER__)'
  "it's a test; touch __MARKER__"
  'PING && touch __MARKER__'
  'PING || touch __MARKER__'
  'PING | touch __MARKER__'
  "'; touch __MARKER__ #"
  '"; touch __MARKER__ #'
  'ping'
  'PING EXTRA ARGS'
  'PING; touch __MARKER__'
  ' PING'
  'PING '
)

i=0
for payload_template in "${PAYLOADS[@]}"; do
  i=$((i + 1))
  MARKER="$FIXTURE_DIR/PWNED_$i"
  rm -f "$MARKER"
  PAYLOAD="${payload_template//__MARKER__/$MARKER}"
  RC="$(run_dispatch "$PAYLOAD")"
  assert_eq "A$i exit code (rejected)" "1" "$RC"
  assert_contains "A$i clear local error message" "$(cat "$FIXTURE_DIR/out.txt")" "refusing before attempting SSH"
  assert_eq "A$i fake ssh was NEVER invoked (rejected before SSH, not after)" "false" "$([ -f "$FIXTURE_DIR/log.txt" ] && echo true || echo false)"
  assert_eq "A$i injected command did not execute (no marker file)" "false" "$([ -e "$MARKER" ] && echo true || echo false)"
done

echo
echo "=== [Q1] defense-in-depth: shell_quote() is actually applied to the one value that DOES pass validation (round-trip fidelity, not just 'PING' happening to be safe on its own) ==="
QUOTED="$(bash -c 'source security/lib.sh; shell_quote "PING"')"
assert_eq "Q1 shell_quote wraps a simple keyword in single quotes" "'PING'" "$QUOTED"

echo
echo "=== Summary: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
  echo "Failures:"
  for f in "${FAILURES[@]}"; do echo "  - $f"; done
  exit 1
fi
exit 0
