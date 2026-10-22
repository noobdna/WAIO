#!/bin/bash
set -uo pipefail

# tests/ssh_guardian_config_test.sh -- regression suite for
# security/generate_ssh_guardian_config.sh (the SSH management
# allowlist -> sshd_config.d drop-in generator).
#
# Everything here runs against scratch fixtures under a temp dir via
# the generator's SSH_GUARDIAN_ALLOWLIST/SSH_GUARDIAN_DEPLOYED_CONFIG/
# SSH_GUARDIAN_STATE_DIR/SSH_GUARDIAN_BACKUP_DIR overrides -- this suite
# never reads or writes this deployment's real
# security/ssh_management_allowlist.conf and never touches
# /etc/ssh/sshd_config.d. Config validity is checked with the real
# installed sshd binary (`sshd -T`) using a throwaway ephemeral host
# key generated fresh for each check -- no sudo, no real host key ever
# read. See security/generate_ssh_guardian_config.sh's own header for
# the incident (2026-08-31) this generator and its lockout-detection
# check exist to prevent a repeat of.
#
# Most of this suite (SG1-SG8, SG12-SG14) needs a local sshd binary to
# validate generated config against, matching what the generator itself
# shells out to (/usr/sbin/sshd -- always present on the real macOS
# deployment target, not guaranteed on a bare CI runner). Those cases
# skip cleanly as one block if it's missing, same "skip, don't fail"
# posture as tests/security_test.sh's L1/L2 LAN-dependent cases.
# SG9-SG11 (fail-closed on a missing/empty/malformed allowlist) and
# SG15 (template sanity) never reach sshd_syntax_check, so they always
# run regardless.
#
# Security-state isolation (audit finding F-17, 2026-10-18): the
# generator sources security/lib.sh and calls audit_log(), and this
# suite used to leave WAIO_AUDIT_LOG & co. unset -- every run appended
# ~10 fixture ssh_guardian_* events to the REAL logs/security-audit.jsonl
# (and advanced its real chain checkpoint). It now runs under
# tests/lib/test_isolation.sh: every security/lib.sh path is redirected
# into a private temp root and verified there before any case runs;
# HOME is an empty dir; sudo/ssh/nc/osascript are recording stubs that
# refuse to act (so privileged_cp's `sudo cp` fallback can never reach
# the real /etc/ssh even if a fixture dir were unwritable); the
# generator's SSH_GUARDIAN_* paths default to fixtures for EVERY call,
# not only the ones that pass them explicitly. SG16/SG17 (real LAN TCP
# probes) now run only with WAIO_TEST_ALLOW_LAN=1. SG22 proves the real
# audit log, chain checkpoint, /etc/ssh and the real allowlist/backups
# were not changed by the run.

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

SKIP=0
skip_case() {
  SKIP=$((SKIP + 1))
  echo "  SKIP: $1 ($2)"
}

# --- fixture sandbox: a fresh temp dir per run, removed on exit. Never
# touches the real security/ssh_management_allowlist.conf or the real
# /etc/ssh/sshd_config.d. Explicit XXXXXX template (not `mktemp -d -t
# prefix`): GNU mktemp (Linux CI) and BSD/macOS mktemp disagree on `-t`
# with no XXXXXX in the template -- this form is the one both
# implementations handle identically. ---------------------------------
source tests/lib/test_isolation.sh
# Production snapshot BEFORE isolation changes HOME/PATH (SG22 compares).
_sg_sum() { if [ -e "$1" ]; then shasum -a 256 "$1" | awk '{print $1}'; else echo absent; fi; }
_sg_tree_sum() { find "$1" -type f 2>/dev/null | LC_ALL=C sort | while IFS= read -r f; do printf '%s %s\n' "$f" "$(_sg_sum "$f")"; done | shasum -a 256 | awk '{print $1}'; }
REAL_AUDIT_LOG="logs/security-audit.jsonl"
REAL_AUDIT_SIZE_BEFORE="$([ -f "$REAL_AUDIT_LOG" ] && wc -c < "$REAL_AUDIT_LOG" | tr -d ' ' || echo 0)"
REAL_AUDIT_PREFIX_BEFORE="$([ -f "$REAL_AUDIT_LOG" ] && head -c "$REAL_AUDIT_SIZE_BEFORE" "$REAL_AUDIT_LOG" | shasum -a 256 | awk '{print $1}' || echo absent)"
REAL_STATE_FILES="security/state/SHUTDOWN.lock security/state/GUARDIAN_STATE security/state/GUARDIAN_QUARANTINE security/state/50-waio-guardian.conf.staged security/ssh_management_allowlist.conf"
REAL_STATE_BEFORE="$(for f in $REAL_STATE_FILES; do printf '%s=%s ' "$f" "$(_sg_sum "$f")"; done)"
REAL_ETC_SSH_BEFORE="$(_sg_tree_sum /etc/ssh)"
REAL_BACKUPS_BEFORE="$(_sg_tree_sum backups/ssh_guardian)"

waio_test_isolate ssh-guardian-config || exit 3
trap waio_test_cleanup EXIT
waio_test_assert_isolated || { echo "ABORT: test isolation could not be guaranteed -- refusing to run" >&2; exit 3; }

FIXTURE_DIR="$WAIO_TEST_ROOT/fixtures"
mkdir -p "$FIXTURE_DIR/state" "$FIXTURE_DIR/backups"
# Defaults for EVERY generator invocation in this file -- a call that
# forgets one of these still lands in the fixture dir, never on the
# generator's real defaults (/etc/ssh/sshd_config.d, security/state,
# backups/ssh_guardian, the real allowlist).
export SSH_GUARDIAN_ALLOWLIST="$FIXTURE_DIR/allowlist.conf"
export SSH_GUARDIAN_DEPLOYED_CONFIG="$FIXTURE_DIR/deployed.conf"
export SSH_GUARDIAN_STATE_DIR="$FIXTURE_DIR/state"
export SSH_GUARDIAN_BACKUP_DIR="$FIXTURE_DIR/backups"

# Three real, currently-reachable management clients confirmed by the
# operator (post-incident inventory, 2026-08-31): 800号機, iPad Pro,
# Raspberry Pi. Deliberately the same addresses as the real deployment
# at the time this suite was written, so a passing suite here was
# directly meaningful -- but written only to a fixture allowlist file,
# never the real one, and SG1-SG15 never touch anything outside that
# fixture, so this value staying fixed (even after the real deployment
# moved on) doesn't affect their correctness. SG16's own real
# reachability check below intentionally does NOT use this fixture
# constant -- see its own comment.
HOST800_IP="192.168.1.91"
IPAD_IP="192.168.1.33"
RPI_IP="192.168.1.150"
UNAUTHORIZED_IP="192.168.1.222"

write_fixture_allowlist() {
  # write_fixture_allowlist LINE...
  : > "$FIXTURE_DIR/allowlist.conf"
  local line
  for line in "$@"; do
    echo "$line" >> "$FIXTURE_DIR/allowlist.conf"
  done
}

write_fixture_allowlist \
  "$HOST800_IP|800号機" \
  "$IPAD_IP|iPad Pro" \
  "$RPI_IP|Raspberry Pi"

SSHD_BIN=""
[ -x /usr/sbin/sshd ] && SSHD_BIN=/usr/sbin/sshd

run_generator() {
  # run_generator MODE [DEPLOYED_CONFIG_PATH] -- runs the generator as
  # a subprocess (its own bash -n/exit-code semantics matter here, so
  # invoke rather than source) with all paths pointed at the fixture
  # sandbox.
  local mode="$1" deployed="${2:-$FIXTURE_DIR/deployed.conf}"
  SSH_GUARDIAN_ALLOWLIST="$FIXTURE_DIR/allowlist.conf" \
  SSH_GUARDIAN_DEPLOYED_CONFIG="$deployed" \
  SSH_GUARDIAN_STATE_DIR="$FIXTURE_DIR/state" \
  SSH_GUARDIAN_BACKUP_DIR="$FIXTURE_DIR/backups" \
    bash security/generate_ssh_guardian_config.sh "$mode"
}

# resolve_effective IP DIRECTIVE -- given the currently-staged fixture
# config, ask the REAL sshd binary (via an ephemeral, throwaway host
# key -- never a real one, no sudo) what DIRECTIVE resolves to for a
# connection whose source address is IP. Same `sshd -T -C` mechanism
# the generator's own sshd_syntax_check uses, applied here per-address
# so tests can assert on the actual allow/deny decision sshd would
# make, not just string-match the generated file.
resolve_effective() {
  local ip="$1" directive="$2"
  local staged="$FIXTURE_DIR/state/50-waio-guardian.conf.staged"
  local tmpkey probe
  tmpkey="$(mktemp "${TMPDIR:-/tmp}/sg-test-hostkey.XXXXXX")"; rm -f "$tmpkey"
  ssh-keygen -q -t ed25519 -N "" -f "$tmpkey" >/dev/null 2>&1
  probe="$(mktemp "${TMPDIR:-/tmp}/sg-test-probe.XXXXXX")"
  { echo "Port 22"; echo "HostKey $tmpkey"; cat "$staged"; } > "$probe"
  local out
  out="$("$SSHD_BIN" -T -C "addr=$ip,user=masa,host=750,laddr=192.168.1.116,lport=22" -f "$probe" 2>/dev/null)"
  rm -f "$tmpkey" "$tmpkey.pub" "$probe"
  echo "$out" | grep -i "^$directive " | awk '{print $2}'
}

echo "=== SSH Guardian config generator regression suite ==="
echo

if [ -n "$SSHD_BIN" ]; then

# --- SG1: baseline generation succeeds and stages a config -----------
echo "[SG1] --check with a 3-client allowlist and no prior deployed config succeeds"
OUT1="$(run_generator --check 2>&1)"; RC1=$?
assert_eq "SG1 exit code 0" "0" "$RC1"
assert_contains "SG1 reports OK" "$OUT1" "OK: staged config"
assert_eq "SG1 stages a file" "true" "$([ -f "$FIXTURE_DIR/state/50-waio-guardian.conf.staged" ] && echo true || echo false)"
assert_eq "SG1 --check writes nothing to the deployed path" "false" "$([ -f "$FIXTURE_DIR/deployed.conf" ] && echo true || echo false)"

echo
echo "[SG2] generated config hard-codes PermitRootLogin/PasswordAuthentication/KbdInteractiveAuthentication to no"
STAGED_CONTENT="$(cat "$FIXTURE_DIR/state/50-waio-guardian.conf.staged")"
assert_contains "SG2 PermitRootLogin no" "$STAGED_CONTENT" "PermitRootLogin no"
assert_contains "SG2 PasswordAuthentication no" "$STAGED_CONTENT" "PasswordAuthentication no"
assert_contains "SG2 KbdInteractiveAuthentication no" "$STAGED_CONTENT" "KbdInteractiveAuthentication no"

echo
echo "[SG3] generated config lists all 3 allowlisted IPs in a single Match Address line"
assert_contains "SG3 has $HOST800_IP" "$STAGED_CONTENT" "$HOST800_IP"
assert_contains "SG3 has $IPAD_IP" "$STAGED_CONTENT" "$IPAD_IP"
assert_contains "SG3 has $RPI_IP" "$STAGED_CONTENT" "$RPI_IP"

echo
echo "--- requirement #10 case 1: authorized management client -> SSH allowed ---"
echo "[SG4] 800号機 ($HOST800_IP): PubkeyAuthentication resolves to yes"
assert_eq "SG4 PubkeyAuthentication=yes for $HOST800_IP" "yes" "$(resolve_effective "$HOST800_IP" pubkeyauthentication)"
assert_eq "SG4 PasswordAuthentication stays no for $HOST800_IP" "no" "$(resolve_effective "$HOST800_IP" passwordauthentication)"
assert_eq "SG4 PermitRootLogin stays no for $HOST800_IP" "no" "$(resolve_effective "$HOST800_IP" permitrootlogin)"

echo
echo "--- requirement #10 case 2: unauthorized LAN client -> SSH denied ---"
echo "[SG5] unlisted LAN address ($UNAUTHORIZED_IP): every auth method denied"
assert_eq "SG5 PubkeyAuthentication=no for unlisted address" "no" "$(resolve_effective "$UNAUTHORIZED_IP" pubkeyauthentication)"
assert_eq "SG5 PasswordAuthentication=no for unlisted address" "no" "$(resolve_effective "$UNAUTHORIZED_IP" passwordauthentication)"
assert_eq "SG5 KbdInteractiveAuthentication=no for unlisted address" "no" "$(resolve_effective "$UNAUTHORIZED_IP" kbdinteractiveauthentication)"

echo
echo "--- requirement #10 case 4: multiple management clients -> all allowed ---"
echo "[SG6] all 3 registered clients independently resolve PubkeyAuthentication=yes"
assert_eq "SG6 800号機 allowed" "yes" "$(resolve_effective "$HOST800_IP" pubkeyauthentication)"
assert_eq "SG6 iPad Pro allowed" "yes" "$(resolve_effective "$IPAD_IP" pubkeyauthentication)"
assert_eq "SG6 Raspberry Pi allowed" "yes" "$(resolve_effective "$RPI_IP" pubkeyauthentication)"

echo
echo "--- requirement #10 case 3: current management path removed -> configuration rejected ---"
echo "[SG7] a currently-deployed client dropped from the new allowlist is detected as a lockout, not applied"
cat > "$FIXTURE_DIR/deployed_with_extra.conf" <<EOF
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication no

Match Address $HOST800_IP,$IPAD_IP,$RPI_IP,192.168.1.99
    PubkeyAuthentication yes
EOF
DEPLOYED_BEFORE="$(cat "$FIXTURE_DIR/deployed_with_extra.conf")"
OUT7="$(run_generator --check "$FIXTURE_DIR/deployed_with_extra.conf" 2>&1)"; RC7=$?
assert_eq "SG7 exit code 2 (lockout, not a generic error)" "2" "$RC7"
assert_contains "SG7 stderr says management lockout detected" "$OUT7" "management lockout detected"
assert_contains "SG7 names the address that would be lost" "$OUT7" "192.168.1.99"
DEPLOYED_AFTER="$(cat "$FIXTURE_DIR/deployed_with_extra.conf")"
assert_eq "SG7 currently-deployed fixture left byte-identical (nothing written)" "$DEPLOYED_BEFORE" "$DEPLOYED_AFTER"

echo
echo "[SG8] a same-address regression is NOT flagged as lockout (sanity: SG7 isn't just always failing)"
cat > "$FIXTURE_DIR/deployed_same.conf" <<EOF
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication no

Match Address $HOST800_IP
    PubkeyAuthentication yes
EOF
OUT8="$(run_generator --check "$FIXTURE_DIR/deployed_same.conf" 2>&1)"; RC8=$?
assert_eq "SG8 exit code 0 (no client lost)" "0" "$RC8"

else
  skip_case "SG1-SG8 (generation + real sshd-validated allow/deny checks)" "no /usr/sbin/sshd on this host to validate generated config against"
fi

echo
echo "--- fail-closed on generation itself (never a wide-open fallback) ---"
echo "[SG9] empty allowlist refuses to generate, distinct exit code from lockout"
: > "$FIXTURE_DIR/allowlist_empty.conf"
OUT9="$(SSH_GUARDIAN_ALLOWLIST="$FIXTURE_DIR/allowlist_empty.conf" SSH_GUARDIAN_DEPLOYED_CONFIG="$FIXTURE_DIR/deployed.conf" SSH_GUARDIAN_STATE_DIR="$FIXTURE_DIR/state" SSH_GUARDIAN_BACKUP_DIR="$FIXTURE_DIR/backups" bash security/generate_ssh_guardian_config.sh --check 2>&1)"; RC9=$?
assert_eq "SG9 exit code 1 (generation refused, not lockout's 2)" "1" "$RC9"
assert_contains "SG9 explains empty allowlist" "$OUT9" "allowlist is empty"

echo
echo "[SG10] missing allowlist file refuses to generate (fail closed, same posture as egress_allowlist.conf)"
OUT10="$(SSH_GUARDIAN_ALLOWLIST="$FIXTURE_DIR/does_not_exist.conf" SSH_GUARDIAN_DEPLOYED_CONFIG="$FIXTURE_DIR/deployed.conf" SSH_GUARDIAN_STATE_DIR="$FIXTURE_DIR/state" SSH_GUARDIAN_BACKUP_DIR="$FIXTURE_DIR/backups" bash security/generate_ssh_guardian_config.sh --check 2>&1)"; RC10=$?
assert_eq "SG10 exit code 1" "1" "$RC10"
assert_contains "SG10 explains missing allowlist" "$OUT10" "allowlist missing"

echo
echo "--- malformed allowlist lines are rejected, not silently dropped ---"
echo "[SG11] a line missing its label is rejected"
write_fixture_allowlist "$HOST800_IP|800号機" "192.168.1.50"
OUT11="$(run_generator --check 2>&1)"; RC11=$?
assert_eq "SG11 exit code 1" "1" "$RC11"
assert_contains "SG11 explains malformed line" "$OUT11" "malformed allowlist line"
# restore the 3-client fixture for the remaining cases
write_fixture_allowlist \
  "$HOST800_IP|800号機" \
  "$IPAD_IP|iPad Pro" \
  "$RPI_IP|Raspberry Pi"

echo
echo "--- backup / rollback (fixture paths -- no sudo, real /etc/ssh never touched) ---"
if [ -n "$SSHD_BIN" ]; then

echo "[SG12] --apply backs up an existing deployed fixture before installing the new one"
cat > "$FIXTURE_DIR/deployed.conf" <<EOF
PermitRootLogin no
PasswordAuthentication yes
KbdInteractiveAuthentication yes
PubkeyAuthentication yes
EOF
ORIGINAL_DEPLOYED="$(cat "$FIXTURE_DIR/deployed.conf")"
OUT12="$(run_generator --apply 2>&1)"; RC12=$?
assert_eq "SG12 --apply exit code 0" "0" "$RC12"
BACKUP_FILE="$(ls -1t "$FIXTURE_DIR"/backups/*.bak 2>/dev/null | head -1)"
assert_eq "SG12 a backup file was created" "true" "$([ -n "$BACKUP_FILE" ] && [ -f "$BACKUP_FILE" ] && echo true || echo false)"
assert_eq "SG12 backup content matches the pre-apply deployed fixture" "$ORIGINAL_DEPLOYED" "$([ -n "$BACKUP_FILE" ] && cat "$BACKUP_FILE")"
assert_contains "SG12 deployed fixture now has the new Match Address block" "$(cat "$FIXTURE_DIR/deployed.conf")" "$HOST800_IP"

echo
echo "[SG13] --rollback restores the most recent backup over the deployed fixture"
OUT13="$(SSH_GUARDIAN_ALLOWLIST="$FIXTURE_DIR/allowlist.conf" SSH_GUARDIAN_DEPLOYED_CONFIG="$FIXTURE_DIR/deployed.conf" SSH_GUARDIAN_STATE_DIR="$FIXTURE_DIR/state" SSH_GUARDIAN_BACKUP_DIR="$FIXTURE_DIR/backups" bash security/generate_ssh_guardian_config.sh --rollback 2>&1)"; RC13=$?
assert_eq "SG13 --rollback exit code 0" "0" "$RC13"
assert_eq "SG13 deployed fixture restored to pre-apply content" "$ORIGINAL_DEPLOYED" "$(cat "$FIXTURE_DIR/deployed.conf")"

echo
echo "[SG14] --apply itself refuses (does not install) when the new config would lose a currently-live client"
cat > "$FIXTURE_DIR/deployed_with_extra2.conf" <<EOF
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication no

Match Address $HOST800_IP,192.168.1.77
    PubkeyAuthentication yes
EOF
DEPLOYED_EXTRA2_BEFORE="$(cat "$FIXTURE_DIR/deployed_with_extra2.conf")"
OUT14="$(run_generator --apply "$FIXTURE_DIR/deployed_with_extra2.conf" 2>&1)"; RC14=$?
assert_eq "SG14 exit code 2" "2" "$RC14"
assert_contains "SG14 reports management lockout detected" "$OUT14" "management lockout detected"
assert_eq "SG14 deployed fixture left untouched" "$DEPLOYED_EXTRA2_BEFORE" "$(cat "$FIXTURE_DIR/deployed_with_extra2.conf")"

echo
echo "--- backup_existing() stdout-capture correctness (Phase 71, closes Phase 68 finding 4) ---"
echo "[SG19] backup_existing() stdout is EXACTLY the backup path (no embedded progress text) when an existing deployed config is present"
cat > "$FIXTURE_DIR/deployed_sg19.conf" <<EOF
PermitRootLogin no
PasswordAuthentication yes
KbdInteractiveAuthentication yes
PubkeyAuthentication yes
EOF
BACKUP_OUT19="$(
  SSH_GUARDIAN_ALLOWLIST="$FIXTURE_DIR/allowlist.conf" \
  SSH_GUARDIAN_DEPLOYED_CONFIG="$FIXTURE_DIR/deployed_sg19.conf" \
  SSH_GUARDIAN_STATE_DIR="$FIXTURE_DIR/state" \
  SSH_GUARDIAN_BACKUP_DIR="$FIXTURE_DIR/backups" \
  bash -c 'source security/generate_ssh_guardian_config.sh; backup_existing' 2>/dev/null
)"
LINE_COUNT19="$(printf '%s\n' "$BACKUP_OUT19" | wc -l | tr -d ' ')"
assert_eq "SG19 backup_existing() stdout is a single line" "1" "$LINE_COUNT19"
assert_eq "SG19 stdout is exactly an existing backup file path" "true" "$([ -f "$BACKUP_OUT19" ] && echo true || echo false)"

echo
echo "[SG20] backup_existing() stdout is EMPTY (not a stray message) when there is no existing deployed config"
BACKUP_OUT20="$(
  SSH_GUARDIAN_ALLOWLIST="$FIXTURE_DIR/allowlist.conf" \
  SSH_GUARDIAN_DEPLOYED_CONFIG="$FIXTURE_DIR/deployed_sg20_missing.conf" \
  SSH_GUARDIAN_STATE_DIR="$FIXTURE_DIR/state" \
  SSH_GUARDIAN_BACKUP_DIR="$FIXTURE_DIR/backups" \
  bash -c 'source security/generate_ssh_guardian_config.sh; backup_existing' 2>/dev/null
)"
assert_eq "SG20 stdout empty when nothing to back up" "" "$BACKUP_OUT20"

echo
echo "[SG21] --apply genuinely RESTORES the prior deployed config (not delete-on-failure) when post_install_check fails after a successful backup+install"
cat > "$FIXTURE_DIR/deployed_sg21.conf" <<EOF
PermitRootLogin no
PasswordAuthentication yes
KbdInteractiveAuthentication yes
PubkeyAuthentication yes
EOF
ORIGINAL_SG21="$(cat "$FIXTURE_DIR/deployed_sg21.conf")"
OUT21="$(
  SSH_GUARDIAN_ALLOWLIST="$FIXTURE_DIR/allowlist.conf" \
  SSH_GUARDIAN_DEPLOYED_CONFIG="$FIXTURE_DIR/deployed_sg21.conf" \
  SSH_GUARDIAN_STATE_DIR="$FIXTURE_DIR/state" \
  SSH_GUARDIAN_BACKUP_DIR="$FIXTURE_DIR/backups" \
  bash -c 'source security/generate_ssh_guardian_config.sh; post_install_check() { return 1; }; apply_config' 2>&1
)"
RC21=$?
assert_eq "SG21 apply_config reports failure" "1" "$RC21"
assert_contains "SG21 reports reverting" "$OUT21" "reverting"
assert_eq "SG21 deployed fixture still EXISTS after revert" "true" "$([ -f "$FIXTURE_DIR/deployed_sg21.conf" ] && echo true || echo false)"
assert_eq "SG21 deployed fixture content restored to the ORIGINAL pre-apply config (not deleted, not left as the broken new config)" "$ORIGINAL_SG21" "$([ -f "$FIXTURE_DIR/deployed_sg21.conf" ] && cat "$FIXTURE_DIR/deployed_sg21.conf")"

else
  skip_case "SG12-SG14,SG19-SG21 (--apply/--rollback and backup_existing() correctness against fixtures)" "no /usr/sbin/sshd on this host to validate generated config against"
fi

echo
echo "--- .example template sanity (same convention as security_test.sh's I3 for egress_allowlist.conf.example) ---"
echo "[SG15] security/ssh_management_allowlist.conf.example: every non-comment/non-blank line has a non-empty IP and LABEL"
BAD_LINES=0
while IFS='|' read -r a_ip a_label; do
  case "$a_ip" in ""|\#*) continue ;; esac
  if [ -z "$a_ip" ] || [ -z "$a_label" ]; then
    BAD_LINES=$((BAD_LINES + 1))
  fi
done < security/ssh_management_allowlist.conf.example
assert_eq "SG15 no malformed IP|LABEL lines in the example template" "0" "$BAD_LINES"

echo
echo "--- live LAN reachability sanity (skips cleanly with no LAN access, same pattern as tests/security_test.sh's L1/L2) ---"
# SG16 checks REAL reachability, unlike SG1-SG15's fixture-only
# HOST800_IP above -- so it reads workers/800.json, the same source of
# truth host800_worker.sh itself uses, rather than that fixture
# constant. HOST800_IP was originally used here too, but this
# deployment's real workers/800.json host was reassigned to
# 192.168.1.80 at some point after this suite was written, so the
# fixture's still-192.168.1.91 value silently turned SG16 into a
# perpetual skip (never actually checking the real, current host) --
# harmless (SG16 only ever skips or passes, it never gates a real
# assertion the way tests/security_test.sh's R5 did), but found and
# fixed alongside that same-shaped R5 bug.
# Real network contact is opt-in (WAIO_TEST_ALLOW_LAN=1): `nc` on PATH is
# the isolation stub, so the opt-in path calls the system nc explicitly.
REAL_HOST800_IP="$(python3 -c 'import json; print(json.load(open("workers/800.json"))["host"])' 2>/dev/null)"
if [ "${WAIO_TEST_ALLOW_LAN:-}" != "1" ]; then
  skip_case "SG16 800号機 real reachability" "real LAN probe is opt-in: set WAIO_TEST_ALLOW_LAN=1"
  skip_case "SG17 Raspberry Pi real reachability" "real LAN probe is opt-in: set WAIO_TEST_ALLOW_LAN=1"
else
  if [ -z "$REAL_HOST800_IP" ]; then
    skip_case "SG16 800号機 real reachability" "workers/800.json missing or unreadable"
  elif /usr/bin/nc -z -w 3 "$REAL_HOST800_IP" 22 >/dev/null 2>&1; then
    echo "[SG16] 800号機 ($REAL_HOST800_IP:22) TCP reachable from this host"
    PASS=$((PASS + 1)); echo "  PASS: SG16 800号機 reachable"
  else
    skip_case "SG16 800号機 real reachability" "no LAN access to $REAL_HOST800_IP:22"
  fi
  if /usr/bin/nc -z -w 3 "$RPI_IP" 22 >/dev/null 2>&1; then
    echo "[SG17] Raspberry Pi ($RPI_IP:22) TCP reachable from this host"
    PASS=$((PASS + 1)); echo "  PASS: SG17 Raspberry Pi reachable"
  else
    skip_case "SG17 Raspberry Pi real reachability" "no LAN access to $RPI_IP:22"
  fi
fi
skip_case "SG18 iPad Pro real reachability" "iPad Pro is an SSH client, not a server -- reachability is only observable from the iPad's own connection attempt, not from this host; operator-confirmed reachable out of band"

echo
echo "--- isolation: production security state is unchanged by this run (F-17 regression) ---"
echo "[SG22] audit events went to the test root, never the real audit trail; /etc/ssh, real allowlist/backups/state untouched; no sudo"
assert_eq "SG22 generator audit events landed in the isolated audit log" "true" "$([ -s "$WAIO_AUDIT_LOG" ] && grep -q '"ssh_guardian_' "$WAIO_AUDIT_LOG" && echo true || echo false)"
assert_eq "SG22 real audit log: pre-existing bytes unchanged" "$REAL_AUDIT_PREFIX_BEFORE" "$([ -f "$SCRIPT_DIR/$REAL_AUDIT_LOG" ] && head -c "$REAL_AUDIT_SIZE_BEFORE" "$SCRIPT_DIR/$REAL_AUDIT_LOG" | shasum -a 256 | awk '{print $1}' || echo absent)"
assert_eq "SG22 real audit log: no ssh_guardian_* event appended" "0" "$([ -f "$SCRIPT_DIR/$REAL_AUDIT_LOG" ] && { tail -c +"$((REAL_AUDIT_SIZE_BEFORE + 1))" "$SCRIPT_DIR/$REAL_AUDIT_LOG" | grep -c '"ssh_guardian_' || true; } || echo 0)"
assert_eq "SG22 real shutdown/Guardian/staged/allowlist files unchanged" "$REAL_STATE_BEFORE" "$(for f in $REAL_STATE_FILES; do printf '%s=%s ' "$f" "$(_sg_sum "$f")"; done)"
assert_eq "SG22 /etc/ssh tree unchanged" "$REAL_ETC_SSH_BEFORE" "$(_sg_tree_sum /etc/ssh)"
assert_eq "SG22 real backups/ssh_guardian unchanged" "$REAL_BACKUPS_BEFORE" "$(_sg_tree_sum backups/ssh_guardian)"
assert_eq "SG22 sudo was never invoked (privileged_cp stayed on fixtures)" "0" "$(waio_test_stub_calls sudo)"
assert_eq "SG22 no ssh/nc/osascript invoked" "0:0:0" "$(waio_test_stub_calls ssh):$(waio_test_stub_calls nc):$(waio_test_stub_calls osascript)"

echo
echo "=== Summary: $PASS passed, $FAIL failed, $SKIP skipped ==="
if [ "$FAIL" -gt 0 ]; then
  echo "Failures:"
  for f in "${FAILURES[@]}"; do echo "  - $f"; done
  exit 1
fi
exit 0
