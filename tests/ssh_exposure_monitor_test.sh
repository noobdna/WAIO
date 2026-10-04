#!/bin/bash
set -uo pipefail

# tests/ssh_exposure_monitor_test.sh -- regression suite for the SSH
# Exposure Monitor (security/ssh_exposure/ssh_exposure_lib.py +
# security/ssh_exposure/ssh_exposure_monitor.sh +
# security/ssh_exposure/adapters/*.sh).
#
# Same three-layer convention as tests/shadow_ai_monitor_test.sh:
#   U-series: unit tests against ssh_exposure_lib.py's pure functions,
#     called directly via `python3 -c "sys.path.insert(0,
#     'security/ssh_exposure'); import ssh_exposure_lib as sel"` -- no
#     ps/lsof/sshd/firewall involved at all.
#   I-series: integration tests against ssh_exposure_monitor.sh's own
#     CLI, with `ps`, `lsof`, and `hostname` shadowed on PATH by
#     fixture scripts emitting fixed, deterministic output, a fixture
#     sshd_config (SSH_EXPOSURE_SSHD_CONFIG override), and a fixture
#     firewall adapter (SSH_EXPOSURE_FIREWALL_ADAPTER override) -- same
#     "shadow a binary on PATH" / "override every path" idiom used
#     throughout this repo. NO REAL sshd/firewall/process/network state
#     is ever inspected by this suite, and the real
#     /etc/ssh/sshd_config is never read.
#   D-series: static structural guards proving this module's own
#     "read-only, no sudo, no firewall/sshd mutation, no network call"
#     claims are true in the code, not just asserted in comments.

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
    echo "  FAIL: $label (expected NOT to contain '$needle', got: $haystack)"
  fi
}

pyval() {
  python3 -c "
import sys
sys.path.insert(0, 'security/ssh_exposure')
import ssh_exposure_lib as sel
$1
"
}

echo "=== SSH Exposure Monitor regression suite ==="

echo ""
echo "=== U-series: ssh_exposure_lib.py unit tests (pure functions, no ps/lsof/sshd) ==="

echo ""
echo "[U1] parse_ps_line parses a well-formed pid/ppid/comm line"
out="$(pyval "
r = sel.parse_ps_line('  123     1 sshd')
print(r['pid'], r['ppid'], r['comm'])
")"
assert_eq "U1 fields parsed correctly" "123 1 sshd" "$out"

echo ""
echo "[U2] parse_ps_line returns None for a malformed line"
out="$(pyval "print(sel.parse_ps_line('not-a-valid-line'))")"
assert_eq "U2 malformed line yields None" "None" "$out"

echo ""
echo "[U3] parse_lsof_listen_line parses an IPv4 LISTEN line"
out="$(pyval "
r = sel.parse_lsof_listen_line('sshd    900  root  3u  IPv4 0x1  0t0  TCP  *:22 (LISTEN)')
print(r['command'], r['pid'], r['local_host'], r['local_port'])
")"
assert_eq "U3 IPv4 LISTEN parsed" "sshd 900 * 22" "$out"

echo ""
echo "[U4] parse_lsof_listen_line parses a bracketed IPv6 LISTEN line"
out="$(pyval "
r = sel.parse_lsof_listen_line('sshd    900  root  4u  IPv6 0x2  0t0  TCP  [::1]:22 (LISTEN)')
print(r['local_host'], r['local_port'])
")"
assert_eq "U4 IPv6 LISTEN parsed" "::1 22" "$out"

echo ""
echo "[U5] parse_lsof_listen_line returns None for a non-LISTEN (ESTABLISHED) line"
out="$(pyval "print(sel.parse_lsof_listen_line('sshd  900  root  5u  IPv4 0x3  0t0  TCP  10.0.0.5:22->10.0.0.9:51234 (ESTABLISHED)'))")"
assert_eq "U5 ESTABLISHED line yields None" "None" "$out"

echo ""
echo "[U6] is_sshd_process / is_socket_activation_wrapper classify known process names correctly"
out="$(pyval "
print(sel.is_sshd_process('sshd'))
print(sel.is_sshd_process('/usr/sbin/sshd'))
print(sel.is_sshd_process('ssh'))
print(sel.is_socket_activation_wrapper('launchd'))
print(sel.is_socket_activation_wrapper('systemd'))
print(sel.is_socket_activation_wrapper('sshd'))
")"
assert_eq "U6 process-name classification" "$(printf 'True\nTrue\nFalse\nTrue\nTrue\nFalse')" "$out"

echo ""
echo "[U7] find_ssh_listeners: a real sshd LISTEN is kept on ANY port (not hardcoded to 22); a launchd LISTEN is kept only when its port is in the configured set; an unrelated process is dropped"
out="$(pyval "
records = [
    {'command': 'sshd', 'pid': 1, 'local_host': '*', 'local_port': 2222},
    {'command': 'launchd', 'pid': 2, 'local_host': '*', 'local_port': 22},
    {'command': 'launchd', 'pid': 3, 'local_host': '*', 'local_port': 9999},
    {'command': 'nginx', 'pid': 4, 'local_host': '*', 'local_port': 22},
]
hits = sel.find_ssh_listeners(records, [22])
print(len(hits))
print(sorted((h['command'], h['local_port'], h['via']) for h in hits))
")"
assert_eq "U7 sshd (any port) + launchd on configured port kept; nginx and launchd on an unconfigured port dropped" "$(printf "2\n[('launchd', 22, 'socket_activation'), ('sshd', 2222, 'sshd')]")" "$out"

echo ""
echo "[U8] classify_listener_scope: loopback addresses (IPv4 and IPv6)"
out="$(pyval "
print(sel.classify_listener_scope('127.0.0.1'))
print(sel.classify_listener_scope('::1'))
print(sel.classify_listener_scope('localhost'))
")"
assert_eq "U8 loopback classified consistently" "$(printf "('localhost', 'ipv4')\n('localhost', 'ipv6')\n('localhost', 'ipv4')")" "$out"

echo ""
echo "[U9] classify_listener_scope: all-interfaces tokens"
out="$(pyval "
print(sel.classify_listener_scope('*')[0])
print(sel.classify_listener_scope('0.0.0.0')[0])
print(sel.classify_listener_scope('::')[0])
")"
assert_eq "U9 all-interfaces tokens classified" "$(printf 'all_interfaces\nall_interfaces\nall_interfaces')" "$out"

echo ""
echo "[U10] classify_listener_scope: private/LAN addresses (IPv4 RFC1918 and IPv6 unique-local/link-local)"
out="$(pyval "
print(sel.classify_listener_scope('192.168.1.10')[0])
print(sel.classify_listener_scope('10.0.0.5')[0])
print(sel.classify_listener_scope('fd00::1')[0])
print(sel.classify_listener_scope('fe80::1')[0])
")"
assert_eq "U10 private ranges classified as lan" "$(printf 'lan\nlan\nlan\nlan')" "$out"

echo ""
echo "[U11] classify_listener_scope: a directly-bound public address is external_direct, for IPv4 and IPv6"
out="$(pyval "
print(sel.classify_listener_scope('8.8.8.8')[0])
print(sel.classify_listener_scope('2606:4700:4700::1111')[0])
")"
assert_eq "U11 public addresses classified external_direct" "$(printf 'external_direct\nexternal_direct')" "$out"

echo ""
echo "[U12] classify_listener_scope: an unparsable host string is 'unknown', never crashes"
out="$(pyval "print(sel.classify_listener_scope('not-an-ip')[0])")"
assert_eq "U12 unparsable host is unknown" "unknown" "$out"

echo ""
echo "[U13] host_has_public_address: true only when a non-private/non-loopback/non-link-local address is present"
out="$(pyval "
print(sel.host_has_public_address(['127.0.0.1', '192.168.1.5', 'fe80::1']))
print(sel.host_has_public_address(['192.168.1.5', '8.8.4.4']))
")"
assert_eq "U13 private-only false, with-public true" "$(printf 'False\nTrue')" "$out"

echo ""
echo "[U14] overall_exposure: the full scope lattice, including the all_interfaces/external disambiguation by public-address presence"
out="$(pyval "
print(sel.overall_exposure([], False))
print(sel.overall_exposure(['localhost'], False))
print(sel.overall_exposure(['lan'], False))
print(sel.overall_exposure(['all_interfaces'], False))
print(sel.overall_exposure(['all_interfaces'], True))
print(sel.overall_exposure(['external_direct'], False))
print(sel.overall_exposure(['localhost', 'lan'], False))
")"
assert_eq "U14 overall_exposure lattice" "$(printf 'none\nlocalhost\nlan\nall_interfaces_private\nexternal\nexternal\nlan')" "$out"

echo ""
echo "[U15] classify_severity: sshd inactive or no exposure -> informational, regardless of config"
out="$(pyval "
print(sel.classify_severity(False, 'none', 'yes', 'yes'))
print(sel.classify_severity(True, 'none', 'yes', 'yes'))
")"
assert_eq "U15 inactive/no-exposure always informational" "$(printf 'informational\ninformational')" "$out"

echo ""
echo "[U16] classify_severity: localhost-only listener is informational (no network exposure), LAN-only listener is low"
out="$(pyval "
print(sel.classify_severity(True, 'localhost', 'yes', 'yes'))
print(sel.classify_severity(True, 'lan', 'yes', 'yes'))
")"
assert_eq "U16 localhost informational, lan low" "$(printf 'informational\nlow')" "$out"

echo ""
echo "[U17] classify_severity: all_interfaces_private baseline is medium, escalates to high on PasswordAuthentication=yes or root login allowed, but never reaches critical"
out="$(pyval "
print(sel.classify_severity(True, 'all_interfaces_private', 'no', 'no'))
print(sel.classify_severity(True, 'all_interfaces_private', 'yes', 'no'))
print(sel.classify_severity(True, 'all_interfaces_private', 'no', 'yes'))
print(sel.classify_severity(True, 'all_interfaces_private', 'yes', 'yes'))
")"
assert_eq "U17 all_interfaces_private ladder (medium/high only)" "$(printf 'medium\nhigh\nhigh\nhigh')" "$out"

echo ""
echo "[U18] classify_severity: confirmed external exposure + PasswordAuthentication=yes -> high (exact spec example)"
out="$(pyval "print(sel.classify_severity(True, 'external', 'yes', 'no'))")"
assert_eq "U18 external + password auth -> high" "high" "$out"

echo ""
echo "[U19] classify_severity: confirmed external exposure + root login allowed -> critical (exact spec example)"
out="$(pyval "print(sel.classify_severity(True, 'external', 'no', 'yes'))")"
assert_eq "U19 external + root login allowed -> critical" "critical" "$out"

echo ""
echo "[U20] classify_severity: unknown/None config values fail toward MORE scrutiny (documented defaults), never toward false safety"
out="$(pyval "print(sel.classify_severity(True, 'external', None, None))")"
assert_eq "U20 unknown config on external exposure -> critical (defaults treated as enabled/allowed)" "critical" "$out"

echo ""
echo "[U21] collect_config_entries + first_value/all_values: first-wins for a single-value keyword, cumulative for Port"
cat > /tmp/waio-ssh-exp-u21.conf <<'EOF'
Port 22
Port 2222
PasswordAuthentication yes
PasswordAuthentication no
EOF
out="$(pyval "
entries, included, errors = sel.collect_config_entries('/tmp/waio-ssh-exp-u21.conf')
print(sel.all_values(entries, 'port'))
print(sel.first_value(entries, 'passwordauthentication'))
print(errors)
")"
assert_eq "U21 Port cumulative, PasswordAuthentication first-wins, no errors" "$(printf "['22', '2222']\nyes\n[]")" "$out"
rm -f /tmp/waio-ssh-exp-u21.conf

echo ""
echo "[U22] collect_config_entries expands an Include directive inline, in the order encountered"
mkdir -p /tmp/waio-ssh-exp-u22.d
cat > /tmp/waio-ssh-exp-u22.d/sub.conf <<'EOF'
PermitRootLogin yes
EOF
cat > /tmp/waio-ssh-exp-u22-main.conf <<'EOF'
PasswordAuthentication no
Include /tmp/waio-ssh-exp-u22.d/*.conf
EOF
out="$(pyval "
entries, included, errors = sel.collect_config_entries('/tmp/waio-ssh-exp-u22-main.conf')
print(sel.first_value(entries, 'permitrootlogin'))
print(len(included))
")"
assert_eq "U22 Include expanded, PermitRootLogin visible from the sub-file" "$(printf 'yes\n2')" "$out"
rm -rf /tmp/waio-ssh-exp-u22.d /tmp/waio-ssh-exp-u22-main.conf

echo ""
echo "[U23] parse_sshd_config: a missing file degrades to source='unavailable' with safe (non-crashing) defaults, never raises"
out="$(pyval "
c = sel.parse_sshd_config('/tmp/waio-ssh-exp-does-not-exist.conf')
print(c['source'], c['port'], c['password_authentication'], c['permit_root_login'])
")"
assert_eq "U23 missing config file handled gracefully" "unavailable [22] unknown unknown" "$out"

echo ""
echo "[U24] config_fingerprint is deterministic and sensitive to a Port change"
out="$(pyval "
c1 = {'port': [22], 'password_authentication': 'yes', 'permit_root_login': 'yes', 'pubkey_authentication': 'yes', 'listen_address': []}
c2 = dict(c1)
c3 = dict(c1, port=[2222])
print(sel.config_fingerprint(c1) == sel.config_fingerprint(c2))
print(sel.config_fingerprint(c1) == sel.config_fingerprint(c3))
")"
assert_eq "U24 fingerprint stable for identical config, differs when Port changes" "$(printf 'True\nFalse')" "$out"

echo ""
echo "[U25] compute_correlation: no prior state (first-ever scan) produces no 'changed' events and is never a candidate incident"
out="$(pyval "
corr, state = sel.compute_correlation(None, '2026-01-01T00:00:00Z', True, 'HASH1', ['*:22'])
print(corr['events'])
print(corr['candidate_incident'])
")"
assert_eq "U25 first scan is quiet" "$(printf '[]\nFalse')" "$out"

echo ""
echo "[U26] compute_correlation: a config change AND a brand-new listener in the SAME scan cycle is flagged as a candidate incident (two distinct event types)"
out="$(pyval "
prev = {'config_hash': 'HASH1', 'sshd_active': True, 'sshd_active_since': '2026-01-01T00:00:00Z', 'listener_keys': {'*:22': '2026-01-01T00:00:00Z'}, 'last_scan_at': '2026-01-01T00:00:00Z'}
corr, state = sel.compute_correlation(prev, '2026-01-01T00:05:00Z', True, 'HASH2', ['*:22', '*:2222'])
print(sorted(e['type'] for e in corr['events']))
print(corr['candidate_incident'])
")"
assert_eq "U26 config_changed + listener_appeared together -> candidate_incident True" "$(printf "['config_changed', 'listener_appeared']\nTrue")" "$out"

echo ""
echo "[U27] compute_correlation: a single isolated change (no other co-occurring event) is NOT a candidate incident"
out="$(pyval "
prev = {'config_hash': 'HASH1', 'sshd_active': True, 'sshd_active_since': '2026-01-01T00:00:00Z', 'listener_keys': {'*:22': '2026-01-01T00:00:00Z'}, 'last_scan_at': '2026-01-01T00:00:00Z'}
corr, state = sel.compute_correlation(prev, '2026-01-01T00:05:00Z', True, 'HASH2', ['*:22'])
print(len(corr['events']))
print(corr['events'][0]['type'])
print(corr['candidate_incident'])
")"
assert_eq "U27 lone config change is not a candidate incident" "$(printf '1\nconfig_changed\nFalse')" "$out"

echo ""
echo "[U28] compute_correlation: sshd stop->start transition is its own event type, never confused with a listener or config event"
out="$(pyval "
prev = {'config_hash': 'HASH1', 'sshd_active': False, 'sshd_active_since': None, 'listener_keys': {}, 'last_scan_at': '2026-01-01T00:00:00Z'}
corr, state = sel.compute_correlation(prev, '2026-01-01T00:05:00Z', True, 'HASH1', [])
print([e['type'] for e in corr['events']])
print(state['sshd_active_since'])
")"
assert_eq "U28 sshd_started detected, since-timestamp recorded" "$(printf "['sshd_started']\n2026-01-01T00:05:00Z")" "$out"

echo ""
echo "[U29] compute_correlation: an entry absent from this scan's listener_keys is dropped from the NEW state (no stale listeners retained forever), never raises"
out="$(pyval "
prev = {'config_hash': 'HASH1', 'sshd_active': True, 'sshd_active_since': 't0', 'listener_keys': {'*:22': 't0', '*:2222': 't0'}, 'last_scan_at': 't0'}
corr, state = sel.compute_correlation(prev, 't1', True, 'HASH1', ['*:22'])
print(sorted(state['listener_keys'].keys()))
")"
assert_eq "U29 stale listener key dropped from new state" "['*:22']" "$out"

echo ""
echo "[U30] parse_adapter_output: parses PLATFORM/FIREWALL_TOOL/FIREWALL_STATE/FIREWALL_DETAIL and every repeated IFACE_ADDR line, ignoring unknown keys"
out="$(pyval "
text = 'PLATFORM=macos\nFIREWALL_TOOL=socketfilterfw\nFIREWALL_STATE=enabled\nFIREWALL_DETAIL=Firewall is enabled.\nIFACE_ADDR=192.168.1.5\nIFACE_ADDR=::1\nSOME_FUTURE_KEY=ignored\n'
fw, addrs = sel.parse_adapter_output(text)
print(fw['platform'], fw['tool'], fw['state'], fw['detail'])
print(addrs)
")"
assert_eq "U30 adapter output parsed, unknown key ignored, order preserved" "$(printf "macos socketfilterfw enabled Firewall is enabled.\n['192.168.1.5', '::1']")" "$out"

echo ""
echo "=== I-series: ssh_exposure_monitor.sh CLI integration tests (ps/lsof/hostname/firewall-adapter shadowed) ==="

FIXTURE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/waio-ssh-exposure-test.XXXXXX")"
trap 'rm -rf "$FIXTURE_DIR"' EXIT
mkdir -p "$FIXTURE_DIR/bin" "$FIXTURE_DIR/state"

write_ps() { # write_ps "line1" "line2" ...
  : > "$FIXTURE_DIR/bin/ps"
  {
    echo '#!/bin/bash'
    echo 'cat <<"PSOUT"'
    for l in "$@"; do echo "$l"; done
    echo 'PSOUT'
  } > "$FIXTURE_DIR/bin/ps"
  chmod +x "$FIXTURE_DIR/bin/ps"
}

write_lsof() { # write_lsof "line1" "line2" ...
  : > "$FIXTURE_DIR/bin/lsof"
  {
    echo '#!/bin/bash'
    echo 'cat <<"LSOFOUT"'
    echo 'COMMAND   PID  USER   FD   TYPE DEVICE SIZE/OFF NODE NAME'
    for l in "$@"; do echo "$l"; done
    echo 'LSOFOUT'
  } > "$FIXTURE_DIR/bin/lsof"
  chmod +x "$FIXTURE_DIR/bin/lsof"
}

cat > "$FIXTURE_DIR/bin/hostname" <<'FAKEHOST'
#!/bin/bash
echo "waio-test-host"
FAKEHOST
chmod +x "$FIXTURE_DIR/bin/hostname"

cat > "$FIXTURE_DIR/firewall_adapter.sh" <<'FAKEADAPTER'
#!/bin/bash
echo "PLATFORM=fixture"
echo "FIREWALL_TOOL=fixture_fw"
echo "FIREWALL_STATE=enabled"
echo "FIREWALL_DETAIL=fixture firewall enabled"
echo "IFACE_ADDR=192.168.1.20"
FAKEADAPTER
chmod +x "$FIXTURE_DIR/firewall_adapter.sh"

export PATH="$FIXTURE_DIR/bin:$PATH"
export SSH_EXPOSURE_STATE_DIR="$FIXTURE_DIR/state"
export SSH_EXPOSURE_AUDIT_LOG="$FIXTURE_DIR/audit.jsonl"
export SSH_EXPOSURE_FIREWALL_ADAPTER="$FIXTURE_DIR/firewall_adapter.sh"

REAL_STATE_BEFORE="not_present"
[ -d security/state/ssh_exposure ] && REAL_STATE_BEFORE="$(find security/state/ssh_exposure -type f 2>/dev/null | sort | tr '\n' ',')"

cat > "$FIXTURE_DIR/sshd_config_stopped" <<'EOF'
# sshd not running, no listener either
EOF

echo ""
echo "[I1] sshd not running at all -> informational, exposure none, event is valid single-line JSON"
write_ps '  1     0 launchd' '  50    1 Finder'
write_lsof
OUT="$(SSH_EXPOSURE_SSHD_CONFIG="$FIXTURE_DIR/sshd_config_stopped" SSH_EXPOSURE_STATE_DIR="$FIXTURE_DIR/state/i1" ./security/ssh_exposure/ssh_exposure_monitor.sh scan 2>"$FIXTURE_DIR/i1.stderr")"
RC=$?
assert_eq "I1 exit code 0" "0" "$RC"
LINE_COUNT="$(echo "$OUT" | grep -c . || true)"
assert_eq "I1 exactly one line of output" "1" "$LINE_COUNT"
python3 -c "import json,sys; json.loads(sys.argv[1])" "$OUT" 2>/dev/null
assert_eq "I1 output is valid JSON" "0" "$?"
assert_contains "I1 severity informational" "$OUT" '"severity": "informational"'
assert_contains "I1 exposure scope none" "$OUT" '"scope": "none"'
assert_contains "I1 sshd_active false" "$OUT" '"sshd_active": false'
assert_contains "I1 firewall surfaced from adapter" "$OUT" '"tool": "fixture_fw"'

echo ""
echo "[I2] sshd listening on loopback only -> informational, exposure scope localhost"
cat > "$FIXTURE_DIR/sshd_config_localhost" <<'EOF'
Port 22
PasswordAuthentication no
PermitRootLogin no
EOF
write_ps '  900     1 sshd'
write_lsof 'sshd      900  root  3u  IPv4 0x1  0t0  TCP  127.0.0.1:22 (LISTEN)'
OUT="$(SSH_EXPOSURE_SSHD_CONFIG="$FIXTURE_DIR/sshd_config_localhost" SSH_EXPOSURE_STATE_DIR="$FIXTURE_DIR/state/i2" ./security/ssh_exposure/ssh_exposure_monitor.sh scan 2>/dev/null)"
assert_contains "I2 severity informational (loopback only)" "$OUT" '"severity": "informational"'
assert_contains "I2 exposure scope localhost" "$OUT" '"scope": "localhost"'

echo ""
echo "[I3] sshd listening on a specific LAN address -> low"
cat > "$FIXTURE_DIR/sshd_config_lan" <<'EOF'
Port 22
PasswordAuthentication yes
PermitRootLogin yes
EOF
write_ps '  900     1 sshd'
write_lsof 'sshd      900  root  3u  IPv4 0x1  0t0  TCP  192.168.1.10:22 (LISTEN)'
OUT="$(SSH_EXPOSURE_SSHD_CONFIG="$FIXTURE_DIR/sshd_config_lan" SSH_EXPOSURE_STATE_DIR="$FIXTURE_DIR/state/i3" ./security/ssh_exposure/ssh_exposure_monitor.sh scan 2>/dev/null)"
assert_contains "I3 severity low (LAN-only, regardless of permissive auth config)" "$OUT" '"severity": "low"'
assert_contains "I3 exposure scope lan" "$OUT" '"scope": "lan"'

echo ""
echo "[I4] sshd listening on ALL interfaces (0.0.0.0), host has no public address of its own, hardened auth -> medium"
cat > "$FIXTURE_DIR/sshd_config_allif_hardened" <<'EOF'
Port 22
PasswordAuthentication no
PermitRootLogin no
EOF
write_ps '  900     1 sshd'
write_lsof 'sshd      900  root  3u  IPv4 0x1  0t0  TCP  *:22 (LISTEN)'
cat > "$FIXTURE_DIR/adapter_no_public.sh" <<'EOF'
#!/bin/bash
echo "PLATFORM=fixture"
echo "FIREWALL_TOOL=fixture_fw"
echo "FIREWALL_STATE=enabled"
echo "FIREWALL_DETAIL=ok"
echo "IFACE_ADDR=192.168.1.20"
echo "IFACE_ADDR=127.0.0.1"
EOF
chmod +x "$FIXTURE_DIR/adapter_no_public.sh"
OUT="$(SSH_EXPOSURE_SSHD_CONFIG="$FIXTURE_DIR/sshd_config_allif_hardened" SSH_EXPOSURE_STATE_DIR="$FIXTURE_DIR/state/i4" SSH_EXPOSURE_FIREWALL_ADAPTER="$FIXTURE_DIR/adapter_no_public.sh" ./security/ssh_exposure/ssh_exposure_monitor.sh scan 2>/dev/null)"
assert_contains "I4 severity medium (all-interfaces, no public IP, hardened auth)" "$OUT" '"severity": "medium"'
assert_contains "I4 exposure scope all_interfaces_private" "$OUT" '"scope": "all_interfaces_private"'

echo ""
echo "[I5] sshd listening on ALL interfaces, PasswordAuthentication=yes -> high"
cat > "$FIXTURE_DIR/sshd_config_allif_pw" <<'EOF'
Port 22
PasswordAuthentication yes
PermitRootLogin no
EOF
write_ps '  900     1 sshd'
write_lsof 'sshd      900  root  3u  IPv4 0x1  0t0  TCP  *:22 (LISTEN)'
OUT="$(SSH_EXPOSURE_SSHD_CONFIG="$FIXTURE_DIR/sshd_config_allif_pw" SSH_EXPOSURE_STATE_DIR="$FIXTURE_DIR/state/i5" SSH_EXPOSURE_FIREWALL_ADAPTER="$FIXTURE_DIR/adapter_no_public.sh" ./security/ssh_exposure/ssh_exposure_monitor.sh scan 2>/dev/null)"
assert_contains "I5 severity high (all-interfaces + PasswordAuthentication=yes)" "$OUT" '"severity": "high"'

echo ""
echo "[I6] CONFIRMED external exposure (bound directly to this host's own public address) + PasswordAuthentication=yes -> high (exact spec example)"
cat > "$FIXTURE_DIR/sshd_config_ext_pw" <<'EOF'
Port 22
PasswordAuthentication yes
PermitRootLogin no
EOF
write_ps '  900     1 sshd'
write_lsof 'sshd      900  root  3u  IPv4 0x1  0t0  TCP  8.8.8.8:22 (LISTEN)'
OUT="$(SSH_EXPOSURE_SSHD_CONFIG="$FIXTURE_DIR/sshd_config_ext_pw" SSH_EXPOSURE_STATE_DIR="$FIXTURE_DIR/state/i6" ./security/ssh_exposure/ssh_exposure_monitor.sh scan 2>/dev/null)"
assert_contains "I6 severity high (external + password auth)" "$OUT" '"severity": "high"'
assert_contains "I6 exposure scope external" "$OUT" '"scope": "external"'

echo ""
echo "[I7] CONFIRMED external exposure + PermitRootLogin=yes -> critical (exact spec example)"
cat > "$FIXTURE_DIR/sshd_config_ext_root" <<'EOF'
Port 22
PasswordAuthentication no
PermitRootLogin yes
EOF
write_ps '  900     1 sshd'
write_lsof 'sshd      900  root  3u  IPv4 0x1  0t0  TCP  8.8.8.8:22 (LISTEN)'
OUT="$(SSH_EXPOSURE_SSHD_CONFIG="$FIXTURE_DIR/sshd_config_ext_root" SSH_EXPOSURE_STATE_DIR="$FIXTURE_DIR/state/i7" ./security/ssh_exposure/ssh_exposure_monitor.sh scan 2>/dev/null)"
assert_contains "I7 severity critical (external + root login allowed)" "$OUT" '"severity": "critical"'

echo ""
echo "[I8] a non-default Port (2222) is detected correctly -- never hardcoded to 22"
cat > "$FIXTURE_DIR/sshd_config_altport" <<'EOF'
Port 2222
PasswordAuthentication no
PermitRootLogin no
EOF
write_ps '  900     1 sshd'
write_lsof 'sshd      900  root  3u  IPv4 0x1  0t0  TCP  192.168.1.10:2222 (LISTEN)'
OUT="$(SSH_EXPOSURE_SSHD_CONFIG="$FIXTURE_DIR/sshd_config_altport" SSH_EXPOSURE_STATE_DIR="$FIXTURE_DIR/state/i8" ./security/ssh_exposure/ssh_exposure_monitor.sh scan 2>/dev/null)"
assert_contains "I8 listener on port 2222 reported" "$OUT" '"local_port": 2222'
assert_contains "I8 severity low (LAN scope on the alternate port)" "$OUT" '"severity": "low"'

echo ""
echo "[I9] macOS-style on-demand socket activation: NO resident sshd process, but launchd is LISTENing on a port sshd_config actually declares -> still detected, sshd_active true, via=socket_activation"
cat > "$FIXTURE_DIR/sshd_config_launchd" <<'EOF'
Port 22
PasswordAuthentication no
PermitRootLogin no
EOF
write_ps '  1     0 launchd' '  50    1 Finder'
write_lsof 'launchd   1  root  3u  IPv4 0x1  0t0  TCP  *:22 (LISTEN)'
OUT="$(SSH_EXPOSURE_SSHD_CONFIG="$FIXTURE_DIR/sshd_config_launchd" SSH_EXPOSURE_STATE_DIR="$FIXTURE_DIR/state/i9" SSH_EXPOSURE_FIREWALL_ADAPTER="$FIXTURE_DIR/adapter_no_public.sh" ./security/ssh_exposure/ssh_exposure_monitor.sh scan 2>/dev/null)"
assert_contains "I9 sshd_active true via socket activation" "$OUT" '"sshd_active": true'
assert_contains "I9 via socket_activation recorded" "$OUT" '"via": "socket_activation"'
assert_not_contains "I9 Finder never appears anywhere in the event" "$OUT" "Finder"

echo ""
echo "[I10] a Finder-only lsof LISTEN (unrelated service, e.g. AirDrop/Finder-adjacent) on a NON-configured port is never reported as an SSH listener"
write_ps '  1     0 launchd' '  60    1 Finder'
write_lsof 'Finder   60  masa  3u  IPv4 0x1  0t0  TCP  *:5353 (LISTEN)'
OUT="$(SSH_EXPOSURE_SSHD_CONFIG="$FIXTURE_DIR/sshd_config_stopped" SSH_EXPOSURE_STATE_DIR="$FIXTURE_DIR/state/i10" ./security/ssh_exposure/ssh_exposure_monitor.sh scan 2>/dev/null)"
assert_eq "I10 zero listeners reported" "0" "$(echo "$OUT" | python3 -c "import json,sys; print(len(json.loads(sys.stdin.read())['ssh']['listeners']))")"
assert_contains "I10 severity informational (no SSH exposure at all)" "$OUT" '"severity": "informational"'

echo ""
echo "[I11] correlation: a config change AND a brand-new listener appearing in the SAME scan is flagged candidate_incident=true; a quiet repeat scan afterwards is candidate_incident=false"
CORR_STATE="$FIXTURE_DIR/state/i11"
cat > "$FIXTURE_DIR/sshd_config_corr_1" <<'EOF'
Port 22
PasswordAuthentication no
PermitRootLogin no
EOF
write_ps '  900     1 sshd'
write_lsof 'sshd      900  root  3u  IPv4 0x1  0t0  TCP  192.168.1.10:22 (LISTEN)'
SSH_EXPOSURE_SSHD_CONFIG="$FIXTURE_DIR/sshd_config_corr_1" SSH_EXPOSURE_STATE_DIR="$CORR_STATE" ./security/ssh_exposure/ssh_exposure_monitor.sh scan >/dev/null 2>/dev/null

cat > "$FIXTURE_DIR/sshd_config_corr_2" <<'EOF'
Port 22
Port 2222
PasswordAuthentication yes
PermitRootLogin no
EOF
write_ps '  900     1 sshd'
write_lsof 'sshd      900  root  3u  IPv4 0x1  0t0  TCP  192.168.1.10:22 (LISTEN)' \
           'sshd      900  root  4u  IPv4 0x2  0t0  TCP  192.168.1.10:2222 (LISTEN)'
OUT2="$(SSH_EXPOSURE_SSHD_CONFIG="$FIXTURE_DIR/sshd_config_corr_2" SSH_EXPOSURE_STATE_DIR="$CORR_STATE" ./security/ssh_exposure/ssh_exposure_monitor.sh scan 2>/dev/null)"
assert_contains "I11 second scan flagged as a candidate incident" "$OUT2" '"candidate_incident": true'

OUT3="$(SSH_EXPOSURE_SSHD_CONFIG="$FIXTURE_DIR/sshd_config_corr_2" SSH_EXPOSURE_STATE_DIR="$CORR_STATE" ./security/ssh_exposure/ssh_exposure_monitor.sh scan 2>/dev/null)"
assert_contains "I11 third (unchanged) scan is NOT a candidate incident" "$OUT3" '"candidate_incident": false'

echo ""
echo "[I12] 'config' and 'state' subcommands are read-only and never fail"
CFG_OUT="$(SSH_EXPOSURE_SSHD_CONFIG="$FIXTURE_DIR/sshd_config_lan" ./security/ssh_exposure/ssh_exposure_monitor.sh config)"
assert_contains "I12 config subcommand reflects the override path's content" "$CFG_OUT" '"source": "live_config"'
STATE_OUT="$(SSH_EXPOSURE_STATE_DIR="$CORR_STATE" ./security/ssh_exposure/ssh_exposure_monitor.sh state)"
assert_contains "I12 state subcommand reflects persisted correlation state" "$STATE_OUT" "config_hash"

echo ""
echo "[I13] a missing/unreadable sshd_config degrades to config.source=unavailable, severity still computed (fails toward MORE scrutiny), never crashes"
write_ps '  900     1 sshd'
write_lsof 'sshd      900  root  3u  IPv4 0x1  0t0  TCP  8.8.8.8:22 (LISTEN)'
OUT="$(SSH_EXPOSURE_SSHD_CONFIG="$FIXTURE_DIR/does-not-exist.conf" SSH_EXPOSURE_STATE_DIR="$FIXTURE_DIR/state/i13" ./security/ssh_exposure/ssh_exposure_monitor.sh scan 2>/dev/null)"
RC=$?
assert_eq "I13 exit code 0 even with a missing sshd_config" "0" "$RC"
assert_contains "I13 config source unavailable" "$OUT" '"source": "unavailable"'
assert_contains "I13 severity still escalates to critical (unknown auth config treated conservatively, external exposure confirmed)" "$OUT" '"severity": "critical"'

echo ""
echo "[I14] the scan summary is logged to stderr only, never mixed into stdout's single JSON event"
assert_contains "I14 stderr carries the summary" "$(cat "$FIXTURE_DIR/i1.stderr")" "severity="
I1_LINE_COUNT="$(cat "$FIXTURE_DIR/i1.stderr" | grep -c . || true)"
assert_eq "I14 stderr has exactly the wrapped summary line" "1" "$I1_LINE_COUNT"

echo ""
echo "=== D-series: structural read-only / no-sudo / no-mutation / no-network guards ==="

code_only() {
  grep -vE '^[[:space:]]*#' "$1"
}

# Shell files only, for the shell-command keyword guards below --
# code_only()'s '#'-prefixed-line stripping only applies to shell-style
# comments; ssh_exposure_lib.py's own prose lives in Python docstrings
# (not '#' lines), so it is checked separately by D1b (no subprocess/
# os.system/os.popen call of any kind -- a stronger, more precise
# structural proof for a pure-Python file than grepping its prose for
# command-name substrings would be).
SSH_EXP_SHELL_FILES=(
  security/ssh_exposure/ssh_exposure_monitor.sh
  security/ssh_exposure/adapters/firewall_macos.sh
  security/ssh_exposure/adapters/firewall_linux.sh
  security/ssh_exposure/adapters/firewall_unknown.sh
)

echo ""
echo "[D1] zero sudo invocations anywhere in this module's actual shell code"
cnt=0
for f in "${SSH_EXP_SHELL_FILES[@]}"; do
  c="$(code_only "$f" | grep -cE '\bsudo\b' || true)"
  cnt=$((cnt + c))
done
assert_eq "D1 zero sudo occurrences" "0" "$cnt"

echo ""
echo "[D1b] ssh_exposure_lib.py never shells out at all (no subprocess/os.system/os.popen) -- it is a pure parsing/classification core, never an executor"
cnt="$(grep -cE 'import subprocess|subprocess\.|os\.system\(|os\.popen\(' security/ssh_exposure/ssh_exposure_lib.py || true)"
assert_eq "D1b zero subprocess/os.system/os.popen in ssh_exposure_lib.py" "0" "$cnt"

echo ""
echo "[D2] zero firewall/sshd/process-mutating commands anywhere in this module's actual shell code"
mod_calls=0
for pattern in '\bkill\b' '\bkillall\b' '\bpfctl\b' 'socketfilterfw --(setglobalstate|setblockall|setstealthmode)' \
               'systemctl (stop|start|restart|disable|enable)' 'service ssh' 'launchctl (unload|stop|kickstart)' \
               'ufw (enable|disable)' 'firewall-cmd --(add|remove|reload|permanent)' '\biptables -[AIDF]\b' '\bnft add\b' \
               'sshd -t' '>\s*/etc/ssh/sshd_config'; do
  for f in "${SSH_EXP_SHELL_FILES[@]}"; do
    c="$(code_only "$f" | grep -cE "$pattern" || true)"
    mod_calls=$((mod_calls + c))
  done
done
assert_eq "D2 zero mutating-command invocations" "0" "$mod_calls"

echo ""
echo "[D3] zero network-tool invocations (curl/wget/nc) or outbound connectivity tests anywhere in this module's actual shell code"
net_calls=0
for f in "${SSH_EXP_SHELL_FILES[@]}"; do
  c="$(code_only "$f" | grep -cE '\b(curl|wget|nc )\b' || true)"
  net_calls=$((net_calls + c))
done
assert_eq "D3 zero network-tool invocations" "0" "$net_calls"

echo ""
echo "[D4] this module never sources security/lib.sh and never calls egress_check/trigger_shutdown -- it has no gating authority and makes no outbound network call of its own"
cnt=0
for pattern in 'source security/lib\.sh' 'egress_check' 'trigger_shutdown'; do
  c="$(code_only security/ssh_exposure/ssh_exposure_monitor.sh | grep -cE "$pattern" || true)"
  cnt=$((cnt + c))
done
assert_eq "D4 zero code occurrences" "0" "$cnt"

echo ""
echo "[D5] ps/lsof/hostname are called by bare name only (never a hardcoded absolute path) -- required for this suite's own PATH-shadowing to work, and for portability"
assert_eq "D5 no hardcoded /bin/ps, /usr/sbin/lsof, or /bin/hostname path" "0" \
  "$(grep -cE '/(bin|usr/sbin)/(ps|lsof|hostname)\b' security/ssh_exposure/ssh_exposure_monitor.sh)"

echo ""
echo "[D6] the real security/state/ssh_exposure/ directory was never touched by this suite (every scan used an SSH_EXPOSURE_STATE_DIR override)"
REAL_STATE_AFTER="not_present"
[ -d security/state/ssh_exposure ] && REAL_STATE_AFTER="$(find security/state/ssh_exposure -type f 2>/dev/null | sort | tr '\n' ',')"
assert_eq "D6 real state directory contents unchanged" "$REAL_STATE_BEFORE" "$REAL_STATE_AFTER"

echo ""
echo "[D7] the real /etc/ssh/sshd_config was never opened for writing by this module (no open(...,'w')/'a' call targets a path outside this module's own state/audit files)"
cnt="$(code_only security/ssh_exposure/ssh_exposure_lib.py | grep -cE "open\([^)]*['\"]w" || true)"
assert_eq "D7 ssh_exposure_lib.py opens nothing for writing (read-only parsing core)" "0" "$cnt"

echo ""
echo "=== Summary: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
  echo "Failures:"
  for f in "${FAILURES[@]}"; do echo "  - $f"; done
  exit 1
fi
exit 0
