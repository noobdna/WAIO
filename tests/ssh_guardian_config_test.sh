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
FIXTURE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/waio-ssh-guardian-test.XXXXXX")"
trap 'rm -rf "$FIXTURE_DIR"' EXIT

mkdir -p "$FIXTURE_DIR/state" "$FIXTURE_DIR/backups"

# Three real, currently-reachable management clients confirmed by the
# operator (post-incident inventory, 2026-08-31): 800号機, iPad Pro,
# Raspberry Pi. Deliberately the same addresses as the real deployment
# so a passing suite here is directly meaningful, but written to a
# fixture allowlist file -- never the real one.
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

else
  skip_case "SG12-SG14 (--apply/--rollback against fixtures)" "no /usr/sbin/sshd on this host to validate generated config against"
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
if nc -z -w 3 "$HOST800_IP" 22 >/dev/null 2>&1; then
  echo "[SG16] 800号機 ($HOST800_IP:22) TCP reachable from this host"
  PASS=$((PASS + 1)); echo "  PASS: SG16 800号機 reachable"
else
  skip_case "SG16 800号機 real reachability" "no LAN access to $HOST800_IP:22"
fi
if nc -z -w 3 "$RPI_IP" 22 >/dev/null 2>&1; then
  echo "[SG17] Raspberry Pi ($RPI_IP:22) TCP reachable from this host"
  PASS=$((PASS + 1)); echo "  PASS: SG17 Raspberry Pi reachable"
else
  skip_case "SG17 Raspberry Pi real reachability" "no LAN access to $RPI_IP:22"
fi
skip_case "SG18 iPad Pro real reachability" "iPad Pro is an SSH client, not a server -- reachability is only observable from the iPad's own connection attempt, not from this host; operator-confirmed reachable out of band"

echo
echo "=== Summary: $PASS passed, $FAIL failed, $SKIP skipped ==="
if [ "$FAIL" -gt 0 ]; then
  echo "Failures:"
  for f in "${FAILURES[@]}"; do echo "  - $f"; done
  exit 1
fi
exit 0
