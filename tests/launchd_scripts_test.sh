#!/bin/bash
set -uo pipefail

# tests/launchd_scripts_test.sh -- regression suite for the WAIO
# Cloudflare Tunnel's launchd wrappers (scripts/launchd/run-waio-tunnel.sh,
# scripts/launchd/rotate-waio-tunnel-log.sh) and their companion plist
# templates (scripts/launchd/com.waio.cloudflared-tunnel.plist.example,
# scripts/launchd/com.waio.tunnel-log-rotate.plist.example).
#
# Neither wrapper is network-reachable from CI (one execs the real
# `cloudflared` binary, the other calls the real `launchctl`) -- this
# suite never invokes either for real. Both the Keychain lookup
# (`security find-generic-password`) and the eventual `cloudflared`/
# `launchctl` invocations are shadowed via a fixture directory
# prepended to PATH (same PATH-shadowing technique
# tests/incident_learning_cisa_kev_collector_test.sh already uses for
# `curl`) plus two test-only override hooks added to the scripts
# themselves (WAIO_TUNNEL_CLOUDFLARED_BIN, WAIO_TUNNEL_LOG /
# WAIO_TUNNEL_LOG_MAX_BYTES) -- a real deployment never sets any of
# these three and gets byte-for-byte the same hardcoded
# paths/threshold as before this suite existed.
#
# What this suite checks:
#   L1-L2  shell syntax + plist XML well-formedness
#   L3-L4  plist wiring: each plist's own ProgramArguments points at
#          the exact, executable, repo-relative script it is meant to
#          drive, and its own scheduling keys match what that script's
#          own nature requires (KeepAlive for the long-running tunnel
#          process, StartInterval for the periodic rotation pass) --
#          same runtime-wiring audit discipline as
#          tests/incident_learning_cron_test.sh's own CR9 and
#          tests/global_patrol_cron_test.sh's own G12.
#   L5     static guard: TUNNEL_TOKEN is never echoed/printed and
#          `set -x` never appears (which would print it to the log).
#   L6-L7  runtime: Keychain-miss fails closed (non-zero exit, the
#          token never existed so trivially never appears anywhere,
#          and the tunnel binary is never invoked); Keychain-hit
#          exports TUNNEL_TOKEN into the child's ENVIRONMENT only --
#          never as a command-line argument, never in stdout/stderr.
#   L7b    runtime: a missing/non-executable tunnel binary fails
#          closed before the Keychain is ever queried; the default
#          binary path is the official /usr/local/bin install, not the
#          vanished ~/.npm-global prefix.
#   L8-L9  rotate-waio-tunnel-log.sh: under threshold is a no-op
#          (no rename, no launchctl call); over threshold renames+
#          gzips and kicks the tunnel job; retention keeps only the 8
#          newest *.gz files regardless of whether this run itself
#          rotated anything.
#   L10    CI wiring: .github/workflows/lint.yml's own bash -n glob,
#          a dedicated shellcheck step, and the regression job all
#          reference this phase's files -- same self-audit convention
#          as D1-style checks elsewhere in this test suite family.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"

RUN_SCRIPT="scripts/launchd/run-waio-tunnel.sh"
ROTATE_SCRIPT="scripts/launchd/rotate-waio-tunnel-log.sh"
TUNNEL_PLIST="scripts/launchd/com.waio.cloudflared-tunnel.plist.example"
ROTATE_PLIST="scripts/launchd/com.waio.tunnel-log-rotate.plist.example"

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
    echo "  FAIL: $label (expected NOT to contain '$needle', got: $haystack)"
  fi
}

FIXTURE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/waio-launchd-scripts-test.XXXXXX")"
trap 'rm -rf "$FIXTURE_DIR"' EXIT

# ---------------------------------------------------------------------
echo "[L1] bash -n syntax check on both wrapper scripts"
assert_eq "L1 run-waio-tunnel.sh syntax OK" "0" "$(bash -n "$RUN_SCRIPT" 2>/dev/null; echo $?)"
assert_eq "L1 rotate-waio-tunnel-log.sh syntax OK" "0" "$(bash -n "$ROTATE_SCRIPT" 2>/dev/null; echo $?)"
assert_eq "L1 run-waio-tunnel.sh executable bit set" "true" "$([ -x "$RUN_SCRIPT" ] && echo true || echo false)"
assert_eq "L1 rotate-waio-tunnel-log.sh executable bit set" "true" "$([ -x "$ROTATE_SCRIPT" ] && echo true || echo false)"

echo ""
echo "[L2] both plist templates are well-formed XML/plist (plutil -lint, or portable python3 plistlib fallback where plutil is unavailable, e.g. Linux CI)"
lint_plist() {
  if command -v plutil >/dev/null 2>&1; then
    plutil -lint "$1" >/dev/null 2>&1
  else
    python3 -c 'import plistlib,sys; plistlib.load(open(sys.argv[1],"rb"))' "$1" >/dev/null 2>&1
  fi
}
assert_eq "L2 cloudflared-tunnel plist well-formed" "0" "$(lint_plist "$TUNNEL_PLIST"; echo $?)"
assert_eq "L2 tunnel-log-rotate plist well-formed" "0" "$(lint_plist "$ROTATE_PLIST"; echo $?)"

# ---------------------------------------------------------------------
echo ""
echo "[L3] runtime-wiring audit: the tunnel plist's ProgramArguments points at THIS exact, executable, repo-relative script -- and uses RunAtLoad+KeepAlive (a long-running service), never StartInterval (which would race a fresh launch against an already-running tunnel)"
TUNNEL_PLIST_PROGRAM="$(grep -A2 '<key>ProgramArguments</key>' "$TUNNEL_PLIST" | grep '<string>' | sed -E 's#.*<string>(.*)</string>.*#\1#')"
assert_contains "L3 plist references run-waio-tunnel.sh" "$TUNNEL_PLIST_PROGRAM" "scripts/launchd/run-waio-tunnel.sh"
TUNNEL_PLIST_REPO_RELATIVE_PATH="${TUNNEL_PLIST_PROGRAM#*/WAIO/}"
assert_eq "L3 the referenced path exists and is executable relative to the repo root" "true" "$([ -x "$TUNNEL_PLIST_REPO_RELATIVE_PATH" ] && echo true || echo false)"
assert_eq "L3 RunAtLoad is true" "True" "$(grep -A1 '<key>RunAtLoad</key>' "$TUNNEL_PLIST" | grep -q '<true/>' && echo True || echo False)"
assert_eq "L3 KeepAlive is true" "True" "$(grep -A1 '<key>KeepAlive</key>' "$TUNNEL_PLIST" | grep -q '<true/>' && echo True || echo False)"
assert_eq "L3 no StartInterval key (this is a persistent service, not a periodic batch pass)" "0" "$(grep -c '<key>StartInterval</key>' "$TUNNEL_PLIST")"

echo ""
echo "[L4] runtime-wiring audit: the rotation plist's ProgramArguments points at THIS exact, executable, repo-relative script -- and uses StartInterval=604800 (7 days), never RunAtLoad/KeepAlive (a periodic batch pass, not a service)"
ROTATE_PLIST_PROGRAM="$(grep -A2 '<key>ProgramArguments</key>' "$ROTATE_PLIST" | grep '<string>' | sed -E 's#.*<string>(.*)</string>.*#\1#')"
assert_contains "L4 plist references rotate-waio-tunnel-log.sh" "$ROTATE_PLIST_PROGRAM" "scripts/launchd/rotate-waio-tunnel-log.sh"
ROTATE_PLIST_REPO_RELATIVE_PATH="${ROTATE_PLIST_PROGRAM#*/WAIO/}"
assert_eq "L4 the referenced path exists and is executable relative to the repo root" "true" "$([ -x "$ROTATE_PLIST_REPO_RELATIVE_PATH" ] && echo true || echo false)"
assert_eq "L4 StartInterval is 604800 (7 days)" "True" "$(grep -A1 '<key>StartInterval</key>' "$ROTATE_PLIST" | grep -q '<integer>604800</integer>' && echo True || echo False)"
assert_eq "L4 no RunAtLoad key" "0" "$(grep -c '<key>RunAtLoad</key>' "$ROTATE_PLIST")"
assert_eq "L4 no KeepAlive key" "0" "$(grep -c '<key>KeepAlive</key>' "$ROTATE_PLIST")"

# ---------------------------------------------------------------------
echo ""
echo "[L5] static guard: TUNNEL_TOKEN is never echoed/printed, and 'set -x' (which would print it to the log for every subsequent command) never appears -- checked against ACTUAL CODE ONLY (comments excluded, same code_only() precedent tests/decision_engine_test.sh's own D1/D2 already establish, since this script's own header comments deliberately DISCUSS \$TUNNEL_TOKEN/--token as documentation of what it does NOT do)"
code_only() {
  grep -vE '^[[:space:]]*#' "$1"
}
assert_eq "L5 zero echo/printf/print of \$TUNNEL_TOKEN in actual code" "0" "$(code_only "$RUN_SCRIPT" | grep -cE '(echo|printf|print).*TUNNEL_TOKEN' || true)"
assert_eq "L5 zero 'set -x' in run-waio-tunnel.sh's actual code" "0" "$(code_only "$RUN_SCRIPT" | grep -cE '^\s*set\s+-[a-zA-Z]*x' || true)"
assert_eq "L5 TUNNEL_TOKEN never passed as a --token command-line argument in actual code" "0" "$(code_only "$RUN_SCRIPT" | grep -cE -- '--token' || true)"

# ---------------------------------------------------------------------
echo ""
echo "[L6] Keychain miss: fails closed (non-zero exit), never invokes the tunnel binary, and -- since no token exists in this case -- trivially never prints one"
mkdir -p "$FIXTURE_DIR/path_security_empty"
cat > "$FIXTURE_DIR/path_security_empty/security" <<'EOF'
#!/bin/bash
# Fixture stand-in for the real macOS `security` binary: simulates
# "no such Keychain item" by printing nothing and exiting non-zero,
# the same observable behavior the real command has when the item is
# absent.
exit 44
EOF
chmod +x "$FIXTURE_DIR/path_security_empty/security"

L6_ARGV_FILE="$FIXTURE_DIR/l6-cloudflared-argv.txt"
L6_ENV_FILE="$FIXTURE_DIR/l6-cloudflared-env.txt"
cat > "$FIXTURE_DIR/fake-cloudflared" <<EOF
#!/bin/bash
printf '%s\n' "\$@" > "$L6_ARGV_FILE"
env | grep '^TUNNEL_TOKEN=' > "$L6_ENV_FILE" || true
EOF
chmod +x "$FIXTURE_DIR/fake-cloudflared"

L6_OUT="$(PATH="$FIXTURE_DIR/path_security_empty:$PATH" WAIO_TUNNEL_CLOUDFLARED_BIN="$FIXTURE_DIR/fake-cloudflared" "$RUN_SCRIPT" 2>&1)"
L6_RC=$?
assert_eq "L6 exit code non-zero" "true" "$([ "$L6_RC" -ne 0 ] && echo true || echo false)"
assert_contains "L6 error message explains why" "$L6_OUT" "Refusing to start"
assert_eq "L6 cloudflared fixture was never invoked" "false" "$([ -f "$L6_ARGV_FILE" ] && echo true || echo false)"

# ---------------------------------------------------------------------
echo ""
echo "[L7] Keychain hit: TUNNEL_TOKEN reaches the tunnel binary's ENVIRONMENT only -- never its argv, never stdout/stderr"
FAKE_TOKEN="waio-test-token-6f8c9a2b1d"
mkdir -p "$FIXTURE_DIR/path_security_hit"
cat > "$FIXTURE_DIR/path_security_hit/security" <<EOF
#!/bin/bash
# Fixture stand-in for the real macOS \`security\` binary: simulates a
# present Keychain item by printing the fixture token to stdout, the
# same observable behavior \`security find-generic-password -w\` has
# on a real hit.
echo "$FAKE_TOKEN"
EOF
chmod +x "$FIXTURE_DIR/path_security_hit/security"

L7_ARGV_FILE="$FIXTURE_DIR/l7-cloudflared-argv.txt"
L7_ENV_FILE="$FIXTURE_DIR/l7-cloudflared-env.txt"
cat > "$FIXTURE_DIR/fake-cloudflared-2" <<EOF
#!/bin/bash
printf '%s\n' "\$@" > "$L7_ARGV_FILE"
env | grep '^TUNNEL_TOKEN=' > "$L7_ENV_FILE" || true
EOF
chmod +x "$FIXTURE_DIR/fake-cloudflared-2"

L7_OUT="$(PATH="$FIXTURE_DIR/path_security_hit:$PATH" WAIO_TUNNEL_CLOUDFLARED_BIN="$FIXTURE_DIR/fake-cloudflared-2" "$RUN_SCRIPT" 2>&1)"
L7_RC=$?
assert_eq "L7 exit code 0" "0" "$L7_RC"
assert_eq "L7 cloudflared fixture was invoked" "true" "$([ -f "$L7_ARGV_FILE" ] && echo true || echo false)"
assert_eq "L7 argv is exactly 'tunnel run'" "tunnel
run" "$(cat "$L7_ARGV_FILE")"
assert_contains "L7 TUNNEL_TOKEN reached the child's environment" "$(cat "$L7_ENV_FILE" 2>/dev/null)" "TUNNEL_TOKEN=$FAKE_TOKEN"
assert_not_contains "L7 token never appears in the recorded argv" "$(cat "$L7_ARGV_FILE")" "$FAKE_TOKEN"
assert_not_contains "L7 token never appears in this run's own stdout/stderr" "$L7_OUT" "$FAKE_TOKEN"

# ---------------------------------------------------------------------
echo ""
echo "[L7b] Missing tunnel binary: fails closed BEFORE the Keychain is queried, and the default path is the official /usr/local/bin install"
mkdir -p "$FIXTURE_DIR/path_security_spy"
L7B_SECURITY_CALLS="$FIXTURE_DIR/l7b-security-calls.txt"
cat > "$FIXTURE_DIR/path_security_spy/security" <<EOF
#!/bin/bash
# Records that it was called, then behaves like a Keychain hit -- the
# assertion below is that it is never reached at all.
echo called >> "$L7B_SECURITY_CALLS"
echo "$FAKE_TOKEN"
EOF
chmod +x "$FIXTURE_DIR/path_security_spy/security"

L7B_OUT="$(PATH="$FIXTURE_DIR/path_security_spy:$PATH" WAIO_TUNNEL_CLOUDFLARED_BIN="$FIXTURE_DIR/no-such-cloudflared" "$RUN_SCRIPT" 2>&1)"
L7B_RC=$?
assert_eq "L7b exit code non-zero" "true" "$([ "$L7B_RC" -ne 0 ] && echo true || echo false)"
assert_contains "L7b error message names the missing binary" "$L7B_OUT" "cloudflared binary not found"
assert_contains "L7b error message says it refuses to start" "$L7B_OUT" "Refusing to start"
assert_eq "L7b Keychain (security) was never queried" "false" "$([ -f "$L7B_SECURITY_CALLS" ] && echo true || echo false)"
assert_not_contains "L7b token never appears in stdout/stderr" "$L7B_OUT" "$FAKE_TOKEN"
assert_eq "L7b default binary path is the official /usr/local/bin install" "1" "$(code_only "$RUN_SCRIPT" | grep -c 'WAIO_TUNNEL_CLOUDFLARED_BIN:-/usr/local/bin/cloudflared}' || true)"
assert_eq "L7b no code line still references the vanished ~/.npm-global prefix" "0" "$(code_only "$RUN_SCRIPT" | grep -c 'npm-global' || true)"

# ---------------------------------------------------------------------
echo ""
echo "[L8] rotate-waio-tunnel-log.sh: under threshold is a no-op (no rename, no launchctl kickstart)"
mkdir -p "$FIXTURE_DIR/path_launchctl"
L8_LAUNCHCTL_CALLS="$FIXTURE_DIR/l8-launchctl-calls.txt"
cat > "$FIXTURE_DIR/path_launchctl/launchctl" <<EOF
#!/bin/bash
printf '%s\n' "\$*" >> "$L8_LAUNCHCTL_CALLS"
EOF
chmod +x "$FIXTURE_DIR/path_launchctl/launchctl"

L8_LOG="$FIXTURE_DIR/l8-tunnel.log"
printf 'small log, well under threshold\n' > "$L8_LOG"
PATH="$FIXTURE_DIR/path_launchctl:$PATH" WAIO_TUNNEL_LOG="$L8_LOG" WAIO_TUNNEL_LOG_MAX_BYTES=1000000 "$ROTATE_SCRIPT"
L8_RC=$?
assert_eq "L8 exit code 0 with no rotated .gz present yet (nothing to prune is not a failure)" "0" "$L8_RC"
assert_eq "L8 log file untouched (no rotation)" "true" "$([ -f "$L8_LOG" ] && echo true || echo false)"
assert_eq "L8 no rotated .gz file created" "0" "$(find "$FIXTURE_DIR" -maxdepth 1 -name 'l8-tunnel.log.*.gz' | wc -l | tr -d ' ')"
assert_eq "L8 launchctl was never invoked" "false" "$([ -f "$L8_LAUNCHCTL_CALLS" ] && echo true || echo false)"

echo ""
echo "[L9] rotate-waio-tunnel-log.sh: over threshold rotates (rename+gzip), kicks the tunnel job, and retention keeps only the 8 newest *.gz files"
L9_LOG="$FIXTURE_DIR/l9-tunnel.log"
printf '%s' "this line is long enough to exceed a tiny fixture threshold" > "$L9_LOG"
# Pre-seed 9 older rotated logs, all dated in the past (Jan 2026),
# beyond the 8-newest retention this script already enforces
# unconditionally -- with distinct mtimes so `ls -t` has a stable,
# deterministic ordering to prune by. Today's real rotation (below)
# gets today's real UTC date tag, which always sorts newer than any
# of these fixed Jan-2026 tags.
for i in $(seq 1 9); do
  day="$(printf '%02d' "$i")"
  f="$L9_LOG.202601${day}T000000Z.gz"
  printf 'old' | gzip > "$f"
  touch -t "202601${day}0000" "$f" 2>/dev/null || touch "$f"
done
L9_LAUNCHCTL_CALLS="$FIXTURE_DIR/l9-launchctl-calls.txt"
mkdir -p "$FIXTURE_DIR/path_launchctl_l9"
cat > "$FIXTURE_DIR/path_launchctl_l9/launchctl" <<EOF
#!/bin/bash
printf '%s\n' "\$*" >> "$L9_LAUNCHCTL_CALLS"
EOF
chmod +x "$FIXTURE_DIR/path_launchctl_l9/launchctl"

TODAY_TAG="$(date -u +%Y%m%d)"
PATH="$FIXTURE_DIR/path_launchctl_l9:$PATH" WAIO_TUNNEL_LOG="$L9_LOG" WAIO_TUNNEL_LOG_MAX_BYTES=10 "$ROTATE_SCRIPT"
L9_RC=$?
assert_eq "L9 exit code 0 after rotating and pruning" "0" "$L9_RC"
assert_eq "L9 original log path replaced by a fresh rotation (not left as-is)" "false" "$([ -f "$L9_LOG" ] && echo true || echo false)"
assert_eq "L9 exactly one NEW rotated .gz created this run (today's date tag)" "1" "$(find "$FIXTURE_DIR" -maxdepth 1 -name "l9-tunnel.log.${TODAY_TAG}T*.gz" | wc -l | tr -d ' ')"
assert_contains "L9 launchctl kickstart was called for com.waio.cloudflared-tunnel" "$(cat "$L9_LAUNCHCTL_CALLS" 2>/dev/null)" "kickstart"
assert_contains "L9 launchctl kickstart named the right job label" "$(cat "$L9_LAUNCHCTL_CALLS" 2>/dev/null)" "com.waio.cloudflared-tunnel"
assert_eq "L9 retention kept exactly 8 rotated .gz files (newest 8 of the 9 pre-seeded + 1 new = 10, pruned to 8)" "8" "$(find "$FIXTURE_DIR" -maxdepth 1 -name 'l9-tunnel.log.*.gz' | wc -l | tr -d ' ')"

# ---------------------------------------------------------------------
echo ""
echo "[L10] CI wiring: lint.yml's bash -n glob, a dedicated shellcheck step, and the regression job all reference this phase's files -- same self-audit convention as other suites' own D1-style checks"
LINT_YML_CONTENT="$(cat .github/workflows/lint.yml)"
assert_contains "L10 bash -n glob includes scripts/launchd/*.sh" "$LINT_YML_CONTENT" "scripts/launchd/*.sh"
assert_contains "L10 a shellcheck step covers scripts/launchd/*.sh" "$LINT_YML_CONTENT" "shellcheck -S error scripts/launchd/*.sh"
assert_contains "L10 regression job runs this suite" "$LINT_YML_CONTENT" "./tests/launchd_scripts_test.sh"

echo ""
echo "=== Summary: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
  echo "Failures:"
  printf '  - %s\n' "${FAILURES[@]}"
  exit 1
fi
exit 0
