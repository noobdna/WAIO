#!/bin/bash
set -uo pipefail

# tests/jobs_taco_control_dlp_test.sh -- regression suite for Red Team
# finding #4 (2026-09-13): jobs/run-job.sh, jobs/dispatch.sh,
# jobs/test-job.sh, and taco-control/taco_control_dispatch.sh each made
# a real outbound SSH connection with NO egress_check and NO audit
# trail at all -- a complete, silent bypass of the DLP/Emergency
# Shutdown layer every registry-dispatched worker already goes
# through, even while an Emergency Shutdown was active. Fixed by
# sourcing security/lib.sh and calling egress_check immediately before
# each script's real ssh call (see each file's own header for the
# per-file writeup). This suite proves, for all four scripts:
#   - an unlisted destination is denied, and ssh is never invoked
#   - an active Emergency Shutdown denies dispatch, and ssh is never
#     invoked (the DLP layer's fail-closed posture now actually
#     applies to this whole class of script, not just registry workers)
#   - an allowed destination with no active shutdown still dispatches
#     normally (the fix does not regress the legitimate path)
#   - every allow/deny decision is recorded in the audit trail with the
#     correct destination and worker label
#
# NO REAL NETWORK CALL OF ANY KIND. `ssh` is shadowed on PATH by the
# same fake-ssh-on-PATH technique as tests/rpi_command_injection_test.sh
# and tests/taco_control_injection_test.sh (replays the exact
# remote-shell-parsing step a real ssh would trigger, entirely
# locally). jobs/*.sh read workers/800.json and write results/ as
# plain CWD-relative paths (an existing, unchanged assumption -- not
# something this fix touches) -- this suite runs them from a fixture
# working directory with its own throwaway workers/800.json instead of
# touching this deployment's real one.

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

assert_not_contains() {
  local label="$1" haystack="$2" needle="$3"
  if [[ "$haystack" != *"$needle"* ]]; then
    PASS=$((PASS + 1)); echo "  PASS: $label"
  else
    FAIL=$((FAIL + 1)); FAILURES+=("$label (expected NOT to contain '$needle')")
    echo "  FAIL: $label (expected NOT to contain '$needle')"
  fi
}

FIXTURE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/waio-jobs-taco-dlp-test.XXXXXX")"
trap 'rm -rf "$FIXTURE_DIR"' EXIT

mkdir -p "$FIXTURE_DIR/bin" "$FIXTURE_DIR/bin_replay" "$FIXTURE_DIR/cwd/workers" "$FIXTURE_DIR/cwd/results" "$FIXTURE_DIR/fake_home"

# workers/host800_worker.sh (added to this suite's own coverage,
# security audit finding, 2026-09-17) sources security/lib.sh via a
# bare, CWD-relative "security/lib.sh" (unlike jobs/*.sh/
# taco_control_dispatch.sh, which anchor it to their own SCRIPT_DIR) --
# symlinked into the fixture cwd so it resolves the same way it would
# from this deployment's real repo root, without ever touching or
# depending on the real one.
ln -s "$SCRIPT_DIR/security" "$FIXTURE_DIR/cwd/security"

# --- fake `ssh` (stub mode, D1-D3 below): this suite is about DLP
# gating (was ssh reached or not, was it audited correctly), not about
# the content of what each script's remote command actually does --
# jobs/*.sh's own remote commands use macOS-only tools (sw_vers,
# scutil), which would make a faithful local replay of them
# environment-dependent (this repo's CI runs on ubuntu-latest) for no
# benefit to what this suite is actually checking. Just records the
# invocation and returns success. -----------------------------------
cat > "$FIXTURE_DIR/bin/ssh" <<'FAKESSH'
#!/bin/bash
{
  echo "--- ssh invocation ---"
  for a in "$@"; do echo "ARG: $a"; done
} >> "$FAKE_SSH_LOG"
echo "FAKE_REMOTE_OUTPUT"
exit 0
FAKESSH
chmod +x "$FIXTURE_DIR/bin/ssh"

# --- fake `ssh` (replay mode, [T1] only): faithfully replays the exact
# remote-shell-parsing step real SSH would trigger -- same technique as
# tests/rpi_command_injection_test.sh / tests/taco_control_injection_test.sh.
# Only taco_control_dispatch.sh's own remote command is
# environment-independent (plain POSIX shell + the real, unmodified
# taco_control_executor.sh), so only its one end-to-end test below uses
# this mode, via its own PATH prefix. -------------------------------
cat > "$FIXTURE_DIR/bin_replay/ssh" <<'FAKESSHREPLAY'
#!/bin/bash
REMOTE_CMD="${@: -1}"
{
  echo "--- ssh invocation ---"
  for a in "$@"; do echo "ARG: $a"; done
} >> "$FAKE_SSH_LOG"
HOME="$FAKE_SSH_HOME" bash -c "$REMOTE_CMD"
FAKESSHREPLAY
chmod +x "$FIXTURE_DIR/bin_replay/ssh"

# --- fixture workers/800.json (jobs/*.sh read this as a bare
# CWD-relative path -- an existing, unchanged assumption). -----------
cat > "$FIXTURE_DIR/cwd/workers/800.json" <<'EOF'
{"host": "TESTHOST800", "user": "testuser"}
EOF

export PATH="$FIXTURE_DIR/bin:$PATH"
export FAKE_SSH_HOME="$FIXTURE_DIR/fake_home"

fixture_reset() {
  local suffix="$1"
  export WAIO_AUDIT_LOG="$FIXTURE_DIR/audit-$suffix.jsonl"
  export WAIO_SHUTDOWN_LOCK="$FIXTURE_DIR/SHUTDOWN-$suffix.lock"
  export WAIO_AUDIT_LOG_CHECKPOINT="$FIXTURE_DIR/checkpoint-$suffix"
  export WAIO_AUDIT_INTEGRITY_ALERTS="$FIXTURE_DIR/alerts-$suffix.jsonl"
  export WAIO_AUDIT_LOG_LOCK_DIR="$FIXTURE_DIR/lock-$suffix"
  export WAIO_EGRESS_ALLOWLIST="$FIXTURE_DIR/egress-$suffix.conf"
  export WAIO_RECOVER_RECONCILE_MARKER="$FIXTURE_DIR/marker-$suffix"
  rm -rf "$WAIO_AUDIT_LOG" "$WAIO_SHUTDOWN_LOCK" "$WAIO_AUDIT_LOG_CHECKPOINT" \
    "$WAIO_AUDIT_INTEGRITY_ALERTS" "$WAIO_AUDIT_LOG_LOCK_DIR" "$WAIO_EGRESS_ALLOWLIST" "$WAIO_RECOVER_RECONCILE_MARKER"
  rm -f "$FIXTURE_DIR/log.txt"
  export FAKE_SSH_LOG="$FIXTURE_DIR/log.txt"
}

count_events() {
  local n
  n="$(grep -c "\"event_type\": \"$2\"" "$1" 2>/dev/null)"
  echo "${n:-0}"
}

# run_target NAME SCRIPT [ARGS...] -- runs one target script from the
# fixture CWD (so workers/800.json resolves to the fixture one, not
# this deployment's real file), returns its exit code.
run_target() {
  local script="$1"; shift
  ( cd "$FIXTURE_DIR/cwd" && bash "$SCRIPT_DIR/$script" "$@" > "$FIXTURE_DIR/out.txt" 2>&1 )
  echo "$?"
}

# --- targets under test: NAME|SCRIPT|EXTRA_ARG|DESTINATION|WORKER_LABEL
declare -a TARGETS=(
  "run-job.sh(system)|jobs/run-job.sh|system|TESTHOST800:22|JOBS_RUN_JOB"
  "run-job.sh(identity)|jobs/run-job.sh|identity|TESTHOST800:22|JOBS_RUN_JOB"
  "dispatch.sh|jobs/dispatch.sh||TESTHOST800:22|JOBS_DISPATCH"
  "test-job.sh|jobs/test-job.sh||TESTHOST800:22|JOBS_TEST_JOB"
  "taco_control_dispatch.sh|taco-control/taco_control_dispatch.sh|PING|TACOHOST:22|TACO_CONTROL"
)

for target in "${TARGETS[@]}"; do
  IFS='|' read -r name script extra_arg destination worker_label <<< "$target"
  dest_host="${destination%%:*}"
  dest_port="${destination##*:}"
  slug="$(echo "$name" | tr -c 'A-Za-z0-9' '_')"

  echo
  echo "=== $name ==="

  echo "[D1] unlisted destination -> denied, ssh never invoked, egress_denied audited"
  fixture_reset "${slug}_d1"
  : > "$WAIO_EGRESS_ALLOWLIST"  # exists, but empty -- no destination allowed
  if [ "$script" = "taco-control/taco_control_dispatch.sh" ]; then
    export TACO_CONTROL_HOST="$dest_host"
  fi
  if [ -n "$extra_arg" ]; then
    RC="$(run_target "$script" "$extra_arg")"
  else
    RC="$(run_target "$script")"
  fi
  assert_eq "$name D1 exit code (denied)" "1" "$RC"
  assert_contains "$name D1 error message" "$(cat "$FIXTURE_DIR/out.txt")" "egress denied by DLP guard"
  assert_eq "$name D1 ssh was NEVER invoked" "false" "$([ -f "$FIXTURE_DIR/log.txt" ] && echo true || echo false)"
  # egress_check()'s own behavior (unchanged by this fix): an unlisted
  # destination doesn't just log a quiet "denied" -- it calls
  # trigger_shutdown(), which logs "shutdown_triggered" (and trips a
  # real Emergency Shutdown for the whole system, same as any other
  # worker's unlisted-destination case). "egress_denied" as its own
  # audit event_type is reserved for the separate "shutdown was
  # ALREADY active" branch -- see D2 below.
  assert_eq "$name D1 shutdown_triggered recorded in audit log" "1" "$(count_events "$WAIO_AUDIT_LOG" shutdown_triggered)"
  assert_contains "$name D1 audit reason mentions the unlisted destination" "$(tail -1 "$WAIO_AUDIT_LOG")" "not in allowlist"
  assert_contains "$name D1 audit log names the correct worker" "$(tail -1 "$WAIO_AUDIT_LOG")" "\"worker\": \"$worker_label\""

  echo "[D2] Emergency Shutdown already active -> denied, ssh never invoked (this is the actual bug: this used to run anyway)"
  fixture_reset "${slug}_d2"
  cat > "$WAIO_EGRESS_ALLOWLIST" <<EOF
$dest_host|$dest_port|test fixture
EOF
  echo "reason: dummy pre-existing shutdown for $name D2" > "$WAIO_SHUTDOWN_LOCK"
  if [ -n "$extra_arg" ]; then
    RC="$(run_target "$script" "$extra_arg")"
  else
    RC="$(run_target "$script")"
  fi
  assert_eq "$name D2 exit code (denied)" "1" "$RC"
  assert_eq "$name D2 ssh was NEVER invoked while shutdown active" "false" "$([ -f "$FIXTURE_DIR/log.txt" ] && echo true || echo false)"
  assert_eq "$name D2 egress_denied recorded (shutdown already active)" "1" "$(count_events "$WAIO_AUDIT_LOG" egress_denied)"
  assert_contains "$name D2 audit reason mentions shutdown already active" "$(tail -1 "$WAIO_AUDIT_LOG")" "shutdown already active"

  echo "[D3] allowed destination, no active shutdown -> dispatch proceeds normally, egress_allowed audited"
  fixture_reset "${slug}_d3"
  cat > "$WAIO_EGRESS_ALLOWLIST" <<EOF
$dest_host|$dest_port|test fixture
EOF
  if [ -n "$extra_arg" ]; then
    RC="$(run_target "$script" "$extra_arg")"
  else
    RC="$(run_target "$script")"
  fi
  assert_eq "$name D3 exit code (allowed, dispatch succeeds)" "0" "$RC"
  assert_eq "$name D3 ssh WAS invoked" "true" "$([ -f "$FIXTURE_DIR/log.txt" ] && echo true || echo false)"
  assert_eq "$name D3 egress_allowed recorded in audit log" "1" "$(count_events "$WAIO_AUDIT_LOG" egress_allowed)"
  assert_contains "$name D3 audit log names the correct worker" "$(grep egress_allowed "$WAIO_AUDIT_LOG")" "\"worker\": \"$worker_label\""
  # security audit finding, 2026-09-17: each script now captures its SSH
  # response (to scan it with secret_leak_check below) instead of
  # streaming it straight through -- this proves that restructuring
  # still actually forwards a legitimate response to stdout/results/.
  assert_contains "$name D3 the remote response actually reached stdout (capture-then-secret_leak_check-then-print did not swallow it)" "$(cat "$FIXTURE_DIR/out.txt")" "FAKE_REMOTE_OUTPUT"

  unset TACO_CONTROL_HOST
done

echo
echo "=== [T1] taco_control_dispatch.sh's PING still reaches the real, unmodified executor end-to-end once allowed (fix does not regress D3's own successful path) ==="
fixture_reset "t1"
cat > "$WAIO_EGRESS_ALLOWLIST" <<EOF
TACOHOST|22|test fixture
EOF
export TACO_CONTROL_HOST="TACOHOST"
mkdir -p "$FIXTURE_DIR/fake_home/taco-control"
cp "$SCRIPT_DIR/taco-control/taco_control_executor.sh" "$FIXTURE_DIR/fake_home/taco-control/taco_control_executor.sh"
chmod +x "$FIXTURE_DIR/fake_home/taco-control/taco_control_executor.sh"
RC="$(PATH="$FIXTURE_DIR/bin_replay:$PATH" run_target "taco-control/taco_control_dispatch.sh" "PING")"
assert_eq "T1 exit code" "0" "$RC"
assert_contains "T1 real executor's PONG reached this script's own stdout" "$(cat "$FIXTURE_DIR/out.txt")" "PONG from"
unset TACO_CONTROL_HOST

echo
echo "=== Host-collision guard (security audit finding, 2026-09-17): taco_control_dispatch.sh must refuse when its destination collides with workers/800.json's own host ==="

echo "[C1] TACO_HOST identical to workers/800.json's host -> refused, ssh never invoked, even though that host IS in the egress allowlist"
fixture_reset "c1"
cat > "$WAIO_EGRESS_ALLOWLIST" <<EOF
TESTHOST800|22|test fixture (deliberately allowed, to prove the collision guard fires independently of egress_check's own allow/deny decision)
EOF
export TACO_CONTROL_HOST="TESTHOST800"
RC="$(run_target "taco-control/taco_control_dispatch.sh" "PING")"
assert_eq "C1 exit code (refused)" "1" "$RC"
assert_contains "C1 error message names the collision" "$(cat "$FIXTURE_DIR/out.txt")" "is identical to workers/800.json's own host"
assert_eq "C1 ssh was NEVER invoked" "false" "$([ -f "$FIXTURE_DIR/log.txt" ] && echo true || echo false)"
assert_eq "C1 collision event audited" "1" "$(count_events "$WAIO_AUDIT_LOG" taco_control_host_collision_detected)"
assert_contains "C1 audit reason names the colliding host" "$(tail -1 "$WAIO_AUDIT_LOG")" "TESTHOST800"
unset TACO_CONTROL_HOST

echo "[C2] TACO_HOST distinct from workers/800.json's host -> no collision, dispatch proceeds normally (the guard does not fire on legitimate, distinct destinations)"
fixture_reset "c2"
cat > "$WAIO_EGRESS_ALLOWLIST" <<EOF
TACOHOST|22|test fixture
EOF
export TACO_CONTROL_HOST="TACOHOST"
RC="$(run_target "taco-control/taco_control_dispatch.sh" "PING")"
assert_eq "C2 exit code (proceeds)" "0" "$RC"
assert_eq "C2 ssh WAS invoked (not blocked by the collision guard)" "true" "$([ -f "$FIXTURE_DIR/log.txt" ] && echo true || echo false)"
assert_eq "C2 no collision event logged" "0" "$(count_events "$WAIO_AUDIT_LOG" taco_control_host_collision_detected)"
unset TACO_CONTROL_HOST

echo "[C3] workers/800.json missing entirely -> collision check skipped safely, dispatch proceeds normally"
fixture_reset "c3"
cat > "$WAIO_EGRESS_ALLOWLIST" <<EOF
TACOHOST|22|test fixture
EOF
export TACO_CONTROL_HOST="TACOHOST"
mv "$FIXTURE_DIR/cwd/workers/800.json" "$FIXTURE_DIR/cwd/workers/800.json.bak"
RC="$(run_target "taco-control/taco_control_dispatch.sh" "PING")"
assert_eq "C3 exit code (proceeds despite missing 800.json)" "0" "$RC"
assert_eq "C3 ssh WAS invoked" "true" "$([ -f "$FIXTURE_DIR/log.txt" ] && echo true || echo false)"
mv "$FIXTURE_DIR/cwd/workers/800.json.bak" "$FIXTURE_DIR/cwd/workers/800.json"
unset TACO_CONTROL_HOST

echo "[C4] workers/800.json malformed JSON -> collision check fails safe (skipped, not blocking), dispatch proceeds normally"
fixture_reset "c4"
cat > "$WAIO_EGRESS_ALLOWLIST" <<EOF
TACOHOST|22|test fixture
EOF
export TACO_CONTROL_HOST="TACOHOST"
cp "$FIXTURE_DIR/cwd/workers/800.json" "$FIXTURE_DIR/cwd/workers/800.json.bak"
printf 'not valid json{{{' > "$FIXTURE_DIR/cwd/workers/800.json"
RC="$(run_target "taco-control/taco_control_dispatch.sh" "PING")"
assert_eq "C4 exit code (proceeds despite malformed 800.json)" "0" "$RC"
assert_eq "C4 ssh WAS invoked" "true" "$([ -f "$FIXTURE_DIR/log.txt" ] && echo true || echo false)"
mv "$FIXTURE_DIR/cwd/workers/800.json.bak" "$FIXTURE_DIR/cwd/workers/800.json"
unset TACO_CONTROL_HOST

echo
echo "=== secret_leak_check (security audit finding, 2026-09-17): every SSH-based dispatch path must scan its response before printing/forwarding it ==="

declare -a SECRET_LEAK_TARGETS=(
  "run-job.sh(system)|jobs/run-job.sh|system|TESTHOST800|JOBS_RUN_JOB"
  "dispatch.sh|jobs/dispatch.sh||TESTHOST800|JOBS_DISPATCH"
  "test-job.sh|jobs/test-job.sh||TESTHOST800|JOBS_TEST_JOB"
  "taco_control_dispatch.sh|taco-control/taco_control_dispatch.sh|PING|TACOHOST|TACO_CONTROL"
  "host800_worker.sh(system)|workers/host800_worker.sh|system|TESTHOST800|HOST800"
)

for target in "${SECRET_LEAK_TARGETS[@]}"; do
  IFS='|' read -r name script extra_arg dest_host worker_label <<< "$target"
  slug="secret_$(echo "$name" | tr -c 'A-Za-z0-9' '_')"

  echo
  echo "--- $name ---"

  echo "[SL1] $name: a credential-shaped SSH response is withheld, not printed, and the dispatch is denied"
  fixture_reset "${slug}_sl1"
  cat > "$WAIO_EGRESS_ALLOWLIST" <<EOF
$dest_host|22|test fixture
EOF
  if [ "$script" = "taco-control/taco_control_dispatch.sh" ]; then
    export TACO_CONTROL_HOST="$dest_host"
  fi
  cat > "$FIXTURE_DIR/bin/ssh" <<'FAKESSHSECRET'
#!/bin/bash
echo "sk-abcdefghijklmnopqrstuvwx1234567890"
FAKESSHSECRET
  chmod +x "$FIXTURE_DIR/bin/ssh"
  if [ -n "$extra_arg" ]; then
    RC="$(run_target "$script" "$extra_arg")"
  else
    RC="$(run_target "$script")"
  fi
  assert_eq "$name SL1 exit code (denied)" "1" "$RC"
  assert_contains "$name SL1 error message" "$(cat "$FIXTURE_DIR/out.txt")" "potential credential leak detected"
  assert_not_contains "$name SL1 the credential-shaped string itself is never printed" "$(cat "$FIXTURE_DIR/out.txt")" "sk-abcdefghijklmnopqrstuvwx1234567890"
  assert_eq "$name SL1 no results/ file left behind with the leaked secret" "0" "$(grep -rl "sk-abcdefghijklmnopqrstuvwx1234567890" "$FIXTURE_DIR/cwd/results/" 2>/dev/null | wc -l | tr -d ' ')"

  # restore the stub ssh (D1-D3's own shared fixture) for any later target/section
  cat > "$FIXTURE_DIR/bin/ssh" <<'FAKESSH'
#!/bin/bash
{
  echo "--- ssh invocation ---"
  for a in "$@"; do echo "ARG: $a"; done
} >> "$FAKE_SSH_LOG"
echo "FAKE_REMOTE_OUTPUT"
exit 0
FAKESSH
  chmod +x "$FIXTURE_DIR/bin/ssh"
  unset TACO_CONTROL_HOST
done

echo
echo "=== payload_size_check (security audit finding, 2026-09-17): taco_control_dispatch.sh's COMMAND has no length cap in its own shape-only regex ==="

echo "[SL2] an oversized (but shape-valid) COMMAND is denied before SSH is ever attempted"
fixture_reset "sl2"
cat > "$WAIO_EGRESS_ALLOWLIST" <<EOF
TACOHOST|22|test fixture
EOF
export TACO_CONTROL_HOST="TACOHOST"
# 105000 bytes: comfortably over WAIO_MAX_PAYLOAD_BYTES's 100000-byte
# default (so payload_size_check reliably trips) while staying well
# under any real OS argv-length limit (ARG_MAX) -- see
# tests/rpi_command_injection_test.sh's own P1 comment for the CI
# failure (Linux "Argument list too long", exit 126) a 200000-byte
# version of this pattern actually caused.
BIG_COMMAND="$(python3 -c "print('A' * 105000)")"
RC="$(run_target "taco-control/taco_control_dispatch.sh" "$BIG_COMMAND")"
assert_eq "SL2 exit code (denied)" "1" "$RC"
assert_contains "SL2 error message" "$(cat "$FIXTURE_DIR/out.txt")" "payload size anomaly detected"
assert_eq "SL2 ssh was NEVER invoked" "false" "$([ -f "$FIXTURE_DIR/log.txt" ] && echo true || echo false)"
unset TACO_CONTROL_HOST

echo
echo "=== Summary: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
  echo "Failures:"
  for f in "${FAILURES[@]}"; do echo "  - $f"; done
  exit 1
fi
exit 0
