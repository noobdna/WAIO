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
#   L11    runtime: a Keychain value that is not a tunnel token (hex-
#          encoded by `security -w`, the whole install command, a
#          tunnel ID, bad base64, JSON missing a field) fails closed
#          with a named reason, never invokes the binary and never
#          prints the value.
#   L12    runtime: --check reports binary + token format and exits
#          without starting the tunnel.
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
echo "[L2] both plist templates are well-formed XML/plist (python3 plistlib everywhere, plus plutil -lint where available)"
# plistlib (expat) runs on every platform, not only where plutil is
# missing: plutil accepts a "--" inside an XML comment, which expat and
# so Linux CI reject, and that once passed locally and failed in CI.
lint_plist() {
  python3 -c 'import plistlib,sys; plistlib.load(open(sys.argv[1],"rb"))' "$1" >/dev/null 2>&1 || return 1
  if command -v plutil >/dev/null 2>&1; then
    plutil -lint "$1" >/dev/null 2>&1
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
# Same shape as a real run token (base64 of {"a","t","s"} JSON), so it
# passes run-waio-tunnel.sh's own format check; the values are fixtures.
FAKE_TOKEN="$(printf '%s' '{"a":"waio-test-account-tag","t":"6f8c9a2b-1d00-4c00-8000-000000000000","s":"d2Fpby10ZXN0LXNlY3JldA=="}' | base64 | tr -d '\n')"
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
echo "[L11] Malformed Keychain token: fails closed with the reason cloudflared's own 'Provided Tunnel token is not valid.' never gives, never invokes the tunnel binary, never prints the value"
# make_security DIR VALUE -- fixture `security` that prints VALUE (read
# from a file, so no quoting reaches the heredoc) like a Keychain hit.
make_security() {
  mkdir -p "$1"
  printf '%s' "$2" > "$1/value"
  cat > "$1/security" <<EOF
#!/bin/bash
cat "$1/value"; echo
EOF
  chmod +x "$1/security"
}
L11_ARGV_FILE="$FIXTURE_DIR/l11-cloudflared-argv.txt"
cat > "$FIXTURE_DIR/fake-cloudflared-l11" <<EOF
#!/bin/bash
printf '%s\n' "\$@" >> "$L11_ARGV_FILE"
EOF
chmod +x "$FIXTURE_DIR/fake-cloudflared-l11"
# check_malformed ID VALUE EXPECTED_REASON_FRAGMENT
check_malformed() {
  local id="$1" value="$2" reason="$3" out rc
  make_security "$FIXTURE_DIR/path_security_$id" "$value"
  rm -f "$L11_ARGV_FILE"
  out="$(PATH="$FIXTURE_DIR/path_security_$id:$PATH" WAIO_TUNNEL_CLOUDFLARED_BIN="$FIXTURE_DIR/fake-cloudflared-l11" "$RUN_SCRIPT" 2>&1)"
  rc=$?
  assert_eq "L11 $id exit code non-zero" "true" "$([ "$rc" -ne 0 ] && echo true || echo false)"
  assert_contains "L11 $id names the reason" "$out" "$reason"
  assert_contains "L11 $id says it refuses to start" "$out" "Refusing to start"
  assert_eq "L11 $id cloudflared fixture was never invoked" "false" "$([ -f "$L11_ARGV_FILE" ] && echo true || echo false)"
  assert_not_contains "L11 $id the stored value never appears in stdout/stderr" "$out" "$value"
}
# `security -w` hex-encodes an item holding a non-printable byte; this is
# FAKE_TOKEN plus a trailing newline, as `security` would print it.
L11_HEX="$(printf '%s\n' "$FAKE_TOKEN" | od -An -v -tx1 | tr -d ' \n')"
check_malformed hex "$L11_HEX" "hex-encoded"
check_malformed install-command "cloudflared service install $FAKE_TOKEN" "contains whitespace"
check_malformed tunnel-id "6f8c9a2b-1d00-4c00-8000-000000000000" "does not start with 'eyJ'"
check_malformed bad-base64 "eyJhIjoi%%%%" "does not base64-decode"
check_malformed no-secret "$(printf '%s' '{"a":"waio-test-account-tag","t":"6f8c9a2b-1d00-4c00-8000-000000000000"}' | base64 | tr -d '\n')" "field is missing"

# ---------------------------------------------------------------------
echo ""
echo "[L12] --check: validates binary + token format and exits without starting the tunnel, never printing the token"
make_security "$FIXTURE_DIR/path_security_l12_ok" "$FAKE_TOKEN"
rm -f "$L11_ARGV_FILE"
L12_OUT="$(PATH="$FIXTURE_DIR/path_security_l12_ok:$PATH" WAIO_TUNNEL_CLOUDFLARED_BIN="$FIXTURE_DIR/fake-cloudflared-l11" "$RUN_SCRIPT" --check 2>&1)"
L12_RC=$?
assert_eq "L12 valid token + binary: exit code 0" "0" "$L12_RC"
assert_contains "L12 valid token + binary: reports OK" "$L12_OUT" "OK:"
assert_eq "L12 valid token + binary: cloudflared never invoked" "false" "$([ -f "$L11_ARGV_FILE" ] && echo true || echo false)"
assert_not_contains "L12 valid token + binary: token never printed" "$L12_OUT" "$FAKE_TOKEN"

L12B_OUT="$(PATH="$FIXTURE_DIR/path_security_l12_ok:$PATH" WAIO_TUNNEL_CLOUDFLARED_BIN="$FIXTURE_DIR/no-such-cloudflared" "$RUN_SCRIPT" --check 2>&1)"
L12B_RC=$?
assert_eq "L12 missing binary: exit code non-zero" "true" "$([ "$L12B_RC" -ne 0 ] && echo true || echo false)"
assert_contains "L12 missing binary: reported" "$L12B_OUT" "cloudflared binary not found"
assert_not_contains "L12 missing binary: no OK line" "$L12B_OUT" "OK:"
assert_not_contains "L12 missing binary: token never printed" "$L12B_OUT" "$FAKE_TOKEN"

make_security "$FIXTURE_DIR/path_security_l12_bad" "$L11_HEX"
L12C_OUT="$(PATH="$FIXTURE_DIR/path_security_l12_bad:$PATH" WAIO_TUNNEL_CLOUDFLARED_BIN="$FIXTURE_DIR/no-such-cloudflared" "$RUN_SCRIPT" --check 2>&1)"
L12C_RC=$?
assert_eq "L12 missing binary + malformed token: exit code non-zero" "true" "$([ "$L12C_RC" -ne 0 ] && echo true || echo false)"
assert_contains "L12 missing binary + malformed token: both reported (binary)" "$L12C_OUT" "cloudflared binary not found"
assert_contains "L12 missing binary + malformed token: both reported (token)" "$L12C_OUT" "hex-encoded"

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

# ---------------------------------------------------------------------
echo ""
echo "[L13] rotate-waio-tunnel-log.sh: a missing live log (tunnel never started, or booted out after a rotation) is a no-op that still prunes, not a set -e abort"
L13_DIR="$FIXTURE_DIR/l13"
mkdir -p "$L13_DIR"
L13_LOG="$L13_DIR/tunnel.log"
for i in $(seq 1 10); do
  day="$(printf '%02d' "$i")"
  f="$L13_LOG.202601${day}T000000Z.gz"
  printf 'old' | gzip > "$f"
  touch -t "202601${day}0000" "$f" 2>/dev/null || touch "$f"
done
PATH="$FIXTURE_DIR/path_launchctl:$PATH" WAIO_TUNNEL_LOG="$L13_LOG" WAIO_TUNNEL_LOG_MAX_BYTES=10 "$ROTATE_SCRIPT" >/dev/null 2>&1
L13_RC=$?
assert_eq "L13 exit code 0 with no live log" "0" "$L13_RC"
assert_eq "L13 retention still pruned to the 8 newest archives" "8" "$(find "$L13_DIR" -maxdepth 1 -name 'tunnel.log.*.gz' | wc -l | tr -d ' ')"
assert_eq "L13 no log file conjured into existence" "false" "$([ -e "$L13_LOG" ] && echo true || echo false)"

# ---------------------------------------------------------------------
echo ""
echo "[L14] rotate-waio-tunnel-log.sh: a failed kickstart (tunnel job booted out) still prunes, then reports the failure"
L14_DIR="$FIXTURE_DIR/l14"
mkdir -p "$L14_DIR" "$FIXTURE_DIR/path_launchctl_l14"
cat > "$FIXTURE_DIR/path_launchctl_l14/launchctl" <<'EOF'
#!/bin/bash
echo "Could not find service \"com.waio.cloudflared-tunnel\" in domain for user gui" >&2
exit 113
EOF
chmod +x "$FIXTURE_DIR/path_launchctl_l14/launchctl"
L14_LOG="$L14_DIR/tunnel.log"
printf '%s' "this line is long enough to exceed a tiny fixture threshold" > "$L14_LOG"
for i in $(seq 1 9); do
  day="$(printf '%02d' "$i")"
  f="$L14_LOG.202601${day}T000000Z.gz"
  printf 'old' | gzip > "$f"
  touch -t "202601${day}0000" "$f" 2>/dev/null || touch "$f"
done
L14_ERR="$(PATH="$FIXTURE_DIR/path_launchctl_l14:$PATH" WAIO_TUNNEL_LOG="$L14_LOG" WAIO_TUNNEL_LOG_MAX_BYTES=10 "$ROTATE_SCRIPT" 2>&1 >/dev/null)"
L14_RC=$?
assert_eq "L14 exit code non-zero (the failed restart is still surfaced to launchd)" "true" "$([ "$L14_RC" -ne 0 ] && echo true || echo false)"
assert_eq "L14 retention still pruned to the 8 newest archives" "8" "$(find "$L14_DIR" -maxdepth 1 -name 'tunnel.log.*.gz' | wc -l | tr -d ' ')"
assert_contains "L14 failure is named on stderr" "$L14_ERR" "kickstart"

# ---------------------------------------------------------------------
echo ""
echo "[L15] incident_learning_cron.sh (com.waio.incident-learning, hourly): its own log is size-rotated under the lock, archives 0600, retention bounded"
L15_DIR="$FIXTURE_DIR/l15"
mkdir -p "$L15_DIR/collectors" "$L15_DIR/candidates" "$L15_DIR/knowledge"
L15_LOG="$L15_DIR/incident-learning-cron.log"
l15_run() {
  KNOWLEDGE_MANAGER_STATE_DIR="$L15_DIR/candidates" \
  KNOWLEDGE_MANAGER_AUDIT_LOG="$L15_DIR/audit.jsonl" \
  KNOWLEDGE_MANAGER_KNOWLEDGE_DIR="$L15_DIR/knowledge" \
  INCIDENT_LEARNING_COLLECTORS_DIR="$L15_DIR/collectors" \
  INCIDENT_LEARNING_CRON_LOCK_DIR="$L15_DIR/.cron.lock" \
  INCIDENT_LEARNING_CRON_LOG="$L15_LOG" \
  INCIDENT_LEARNING_CRON_LOG_MAX_BYTES=1000 \
  INCIDENT_LEARNING_CRON_LOG_KEEP=2 \
  bash security/incident_learning/incident_learning_cron.sh >/dev/null 2>&1
}
l15_narch() { find "$L15_DIR" -maxdepth 1 -name 'incident-learning-cron.log.2*' | wc -l | tr -d ' '; }
head -c 2000 /dev/zero | tr '\0' 'x' > "$L15_LOG"
printf '\nMARKER-l15\n' >> "$L15_LOG"
l15_run; L15_RC=$?
assert_eq "L15 run exit code 0" "0" "$L15_RC"
assert_eq "L15 an over-threshold log was archived (one archive)" "1" "$(l15_narch)"
assert_eq "L15 fresh live log no longer holds the old content" "0" "$(grep -c MARKER-l15 "$L15_LOG")"
assert_contains "L15 fresh log records the rotation and the run" "$(cat "$L15_LOG")" "run end"
L15_ARC="$(find "$L15_DIR" -maxdepth 1 -name 'incident-learning-cron.log.2*' | head -1)"
assert_eq "L15 archive is 0600" "600" "$(stat -f %Lp "$L15_ARC" 2>/dev/null || stat -c %a "$L15_ARC" 2>/dev/null)"
for i in 1 2 3; do
  head -c 2000 /dev/zero | tr '\0' 'y' >> "$L15_LOG"
  sleep 1
  l15_run
done
assert_eq "L15 retention keeps at most LOG_KEEP=2 archives" "2" "$(l15_narch)"
: > "$L15_LOG"
L15_BEFORE="$(l15_narch)"
l15_run
assert_eq "L15 under-threshold log is not rotated" "$L15_BEFORE" "$(l15_narch)"

echo ""
echo "=== Summary: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
  echo "Failures:"
  printf '  - %s\n' "${FAILURES[@]}"
  exit 1
fi
exit 0
