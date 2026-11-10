#!/bin/bash
set -uo pipefail

# tests/weekly_audit_test.sh -- regression suite for the WAIO WEEKLY
# SECURITY AUDIT (security/weekly_audit/).
#
# Every host command the audit runs (arp, ifconfig, netstat, lsof, dscl,
# df, launchctl, softwareupdate, ...) is replaced by a fixture script on
# PATH, so the suite never reads this machine's real LAN/accounts and
# runs the same on macOS and the Linux CI runner. SND_HOME is a local
# mock HTTP server on 127.0.0.1. The audit's output dir and HOME are
# temp dirs; nothing is written into the repo.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$SCRIPT_DIR" || exit 1

PASS=0
FAIL=0
declare -a FAILURES=()
ok() { PASS=$((PASS + 1)); echo "  PASS: $1"; }
ng() { FAIL=$((FAIL + 1)); FAILURES+=("$1"); echo "  FAIL: $1"; }
check() { if eval "$2"; then ok "$1"; else ng "$1"; fi; }

T="$(mktemp -d)"
T="$(cd "$T" && pwd -P)"
MOCK_PID=""
cleanup() {
  [ -n "$MOCK_PID" ] && kill "$MOCK_PID" 2>/dev/null
  rm -rf "$T"
}
trap cleanup EXIT

FIX="$T/fixtures"
BIN="$T/bin"
mkdir -p "$FIX" "$BIN" "$T/home"

# --- fixture commands --------------------------------------------------------
# Each fake prints $FIX/<name>.out (switchable between runs) and logs its argv.
for c in arp ifconfig route ipconfig netstat lsof dscl df vm_stat sysctl uptime launchctl sw_vers softwareupdate tmutil ps hostname; do
  cat >"$BIN/$c" <<EOF
#!/bin/bash
echo "$c \$*" >>"$T/argv.log"
key="$c"
case "$c" in
  dscl) case "\$*" in *Groups/admin*) key=dscl_admin ;; *) key=dscl_users ;; esac ;;
  sysctl) case "\$*" in *memsize*) key=memsize ;; *loadavg*) key=loadavg ;; *ncpu*) key=ncpu ;; esac ;;
esac
cat "$FIX/\$key.out" 2>/dev/null
exit 0
EOF
  chmod +x "$BIN/$c"
done
cat >"$T/fw_adapter.sh" <<'EOF'
#!/bin/bash
echo "PLATFORM=macos"
echo "FIREWALL_TOOL=socketfilterfw"
echo "FIREWALL_STATE=${FAKE_FW_STATE:-enabled}"
echo "FIREWALL_DETAIL=fixture"
EOF
chmod +x "$T/fw_adapter.sh"
printf 'Port 22\nPasswordAuthentication no\n' >"$T/sshd_config"

GW_MAC="02:00:5e:10:00:01"
A_MAC="02:00:5e:10:00:33"
B_MAC="02:00:5e:10:00:75"
NEW_MAC="de:ad:be:ef:00:01"
SELF_MAC="02:00:5e:10:00:80"

base_fixtures() {
  cat >"$FIX/arp.out" <<EOF
? (192.168.1.1) at ${GW_MAC} on en0 ifscope [ethernet]
? (192.168.1.33) at ${A_MAC} on en0 ifscope [ethernet]
? (192.168.1.75) at 02:00:5e:10:00:75 on en0 ifscope [ethernet]
? (192.168.1.99) at (incomplete) on en0 ifscope [ethernet]
? (192.168.1.255) at ff:ff:ff:ff:ff:ff on en0 ifscope [ethernet]
? (224.0.0.251) at 1:0:5e:0:0:fb on en0 ifscope permanent [ethernet]
EOF
  cat >"$FIX/ifconfig.out" <<EOF
lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
	inet 127.0.0.1 netmask 0xff000000
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
	ether ${SELF_MAC}
	inet 192.168.1.80 netmask 0xffffff00 broadcast 192.168.1.255
	status: active
EOF
  printf '   route to: default\n    gateway: 192.168.1.1\n  interface: en0\n' >"$FIX/route.out"
  printf 'op = BOOTREPLY\nyiaddr = 192.168.1.80\nserver_identifier (ip): 192.168.1.1\nlease_time (uint32): 0x15180\nrouter (ip_mult): {192.168.1.1}\ndomain_name_server (ip_mult): {192.168.1.1}\nsubnet_mask (ip): 255.255.255.0\n' >"$FIX/ipconfig.out"
  cat >"$FIX/netstat.out" <<'EOF'
Active Internet connections (including servers)
Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)
tcp4       0      0  *.22                   *.*                    LISTEN
tcp4       0      0  127.0.0.1.8000         *.*                    LISTEN
tcp4       0      0  *.49337                *.*                    LISTEN
tcp4       0      0  192.168.1.80.52000     1.2.3.4.443            ESTABLISHED
EOF
  cat >"$FIX/lsof.out" <<'EOF'
COMMAND   PID USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
Python    527 masa    3u  IPv4 0x1      0t0  TCP 127.0.0.1:8000 (LISTEN)
rapportd  600 masa    4u  IPv4 0x2      0t0  TCP *:49337 (LISTEN)
EOF
  printf 'masa 501\nroot 0\n_www 70\nnobody -2\n' >"$FIX/dscl_users.out"
  printf 'GroupMembership: root masa\n' >"$FIX/dscl_admin.out"
  cat >"$FIX/df.out" <<'EOF'
Filesystem     1024-blocks      Used Available Capacity iused ifree %iused  Mounted on
/dev/disk1s1s1   488245288   9000000 100000000    70%  1  2  0%   /
/dev/disk1s2     488245288 400000000  40000000    90%  1  2  0%   /System/Volumes/Data
/dev/disk1s4     488245288   1000000  40000000     3%  1  2  0%   /System/Volumes/VM
EOF
  printf 'Mach Virtual Memory Statistics: (page size of 4096 bytes)\nPages free: 100000.\nPages inactive: 100000.\nPages speculative: 0.\n' >"$FIX/vm_stat.out"
  echo 8589934592 >"$FIX/memsize.out"
  echo '{ 1.00 1.50 2.00 }' >"$FIX/loadavg.out"
  echo 8 >"$FIX/ncpu.out"
  echo '12:00  up 2 days' >"$FIX/uptime.out"
  printf 'PID\tStatus\tLabel\n527\t0\tcom.waio.dashboard-server\n-\t0\tcom.waio.wsr-backup\n-\t1\tcom.waio.cloudflared-tunnel\n' >"$FIX/launchctl.out"
  printf 'ProductName:\tmacOS\nProductVersion:\t13.7.8\nBuildVersion:\t22H730\n' >"$FIX/sw_vers.out"
  {
    echo 'Display Name                                       Version    Date                  '
    echo '------------                                       -------    ----                  '
    echo "macOS Ventura                                      13.7.8     $(date -v-10d +%Y/%m/%d 2>/dev/null || date -d '10 days ago' +%Y/%m/%d) 1:00:00   "
  } >"$FIX/softwareupdate.out"
  echo '/Volumes/Backup/2026-11-10-113722' >"$FIX/tmutil.out"
  printf '  1     0 /sbin/launchd\n' >"$FIX/ps.out"
  echo fixture-host >"$FIX/hostname.out"
}

WAIO_LOGS="$T/waio-logs"
LA="$T/LaunchAgents"
mkdir -p "$WAIO_LOGS" "$LA"
NOW_HTTP="$(date '+%d/%b/%Y %H:%M:%S')"
printf '127.0.0.1 - - [%s] "GET / HTTP/1.1" 200 -\n127.0.0.1 - - [%s] "GET /x HTTP/1.1" 404 -\n' "$NOW_HTTP" "$NOW_HTTP" >"$WAIO_LOGS/dashboard-server-launchd.log"
printf '%s run start\n%s wsr_backup_create: ok\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >"$WAIO_LOGS/wsr-backup-cron.log"
echo '{}' >"$WAIO_LOGS/global-patrol-report-latest.json"
for l in dashboard-server wsr-backup cloudflared-tunnel; do
  printf '<?xml version="1.0"?><plist version="1.0"><dict><key>Label</key><string>com.waio.%s</string></dict></plist>\n' "$l" >"$LA/com.waio.$l.plist"
done

# --- mock SND_HOME ------------------------------------------------------------
SND_MODE_FILE="$T/snd_mode"
echo open >"$SND_MODE_FILE"
python3 - "$T/snd_port" "$SND_MODE_FILE" >/dev/null 2>&1 <<PYEOF &
import json, sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
port_file, mode_file = sys.argv[1], sys.argv[2]
TERMINALS = [
    {"terminalId": "t1", "displayIp": "192.168.1.33", "online": True, "macs": ["${A_MAC}"], "nickname": "living-tv",
     "firstSeenAt": "2026-10-01T00:00:00Z", "lastSeenAt": "2026-11-10T00:00:00Z"},
    {"terminalId": "t2", "displayIp": "192.168.1.150", "online": True, "macs": ["02:00:5e:10:01:50"], "nickname": None,
     "firstSeenAt": "2026-10-01T00:00:00Z", "lastSeenAt": "2026-11-10T00:00:00Z"},
    {"terminalId": "t3", "displayIp": "192.168.1.60", "online": False, "macs": ["0:11:22:33:44:55"], "nickname": None,
     "firstSeenAt": "2026-06-01T00:00:00Z", "lastSeenAt": "2026-07-01T00:00:00Z"},
]
class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def send(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    def do_GET(self):
        mode = open(mode_file).read().strip()
        if self.path == "/api/lan/status": self.send(200, {"online": 2, "total": 3})
        elif self.path == "/api/lan/terminals":
            if mode == "auth" and not self.headers.get("Authorization"): self.send(401, {"status": "error"})
            else: self.send(200, {"status": "ok", "data": TERMINALS})
        elif self.path == "/api/alerts/active": self.send(200, {"data": []})
        else: self.send(404, {})
    def do_POST(self): self.send(405, {})
s = ThreadingHTTPServer(("127.0.0.1", 0), H)
open(port_file, "w").write(str(s.server_address[1]))
s.serve_forever()
PYEOF
MOCK_PID=$!
for _ in $(seq 1 50); do [ -s "$T/snd_port" ] && break; sleep 0.1; done
SND_URL="http://127.0.0.1:$(cat "$T/snd_port")"

AUD="$T/audit"
run_audit() {
  # run_audit [extra env assignments...]
  env -i HOME="$T/home" PATH="$BIN:/usr/bin:/bin" TZ=Asia/Tokyo \
    WEEKLY_AUDIT_DIR="$AUD" WEEKLY_AUDIT_WAIO_LOG_DIR="$WAIO_LOGS" WEEKLY_AUDIT_LAUNCH_AGENTS="$LA" \
    SSH_EXPOSURE_FIREWALL_ADAPTER="$T/fw_adapter.sh" SSH_EXPOSURE_SSHD_CONFIG="$T/sshd_config" \
    "$@" ./security/weekly_audit/weekly_audit_cron.sh
}
latest_report() { find "$AUD" -maxdepth 1 -name 'WEEKLY_AUDIT_*.md' | sort | tail -1; }
mode_of() { python3 -c 'import os,stat,sys; print(oct(stat.S_IMODE(os.stat(sys.argv[1]).st_mode)))' "$1"; }
report_has() { grep -qF -- "$1" "$(latest_report)"; }
snap_findings() { python3 -c '
import glob, json, sys
p = sorted(glob.glob(sys.argv[1] + "/snapshots/snapshot_*.json"))[-1]
print(" ".join(x["severity"] + ":" + x["id"] for x in json.load(open(p))["findings"]))' "$AUD"; }

REPO_SND_JSON="logs/snd-status-latest.json"
REPO_SND_BEFORE="$(ls -l "$REPO_SND_JSON" 2>/dev/null || echo absent)"

echo "== W1: baseline run (SND open, no API_KEY) =="
base_fixtures
OUT="$(run_audit SND_HOME_API_URL="$SND_URL" 2>&1)"; RC=$?
check "W1a exit 0" '[ "$RC" -eq 0 ]'
R="$(latest_report)"
check "W1b report named WEEKLY_AUDIT_YYYYMMDD.md" '[[ "$(basename "$R")" =~ ^WEEKLY_AUDIT_[0-9]{8}\.md$ ]]'
check "W1c audit dir mode 0700" '[ "$(mode_of "$AUD")" = "0o700" ]'
check "W1d report mode 0600" '[ "$(mode_of "$R")" = "0o600" ]'
check "W1e ledger + snapshot mode 0600" '[ "$(mode_of "$AUD/devices.json")" = "0o600" ] && [ "$(mode_of "$(ls "$AUD"/snapshots/*.json)")" = "0o600" ]'
for s in "## 1. 総合判定" "## 2. 今週の変更点" "## 3. ネットワーク端末一覧" "## 4. セキュリティ異常" "## 5. 未解決リスク" "## 6. 前週比較" "## 7. 改善提案" "## 8. 人間の承認が必要な事項"; do
  check "W1f section present: $s" 'report_has "$s"'
done
F="$(snap_findings)"
check "W1g SND API_KEY unset -> HIGH" '[[ "$F" == *"HIGH:sec.snd_api_key_unset"* ]]'
check "W1h baseline: no 'new unconfirmed' HIGH flood" '[[ "$F" != *"net.new_unconfirmed"* ]]'
check "W1i unconfirmed devices -> MEDIUM" '[[ "$F" == *"MEDIUM:net.unconfirmed_present"* ]]'
check "W1j disk 90% -> MEDIUM, VM volume ignored" '[[ "$F" == *"MEDIUM:sys.disk./System/Volumes/Data"* && "$F" != *"VM"* ]]'
check "W1k failing WAIO agent -> MEDIUM" '[[ "$F" == *"MEDIUM:sys.service.com.waio.cloudflared-tunnel"* ]]'
check "W1l LAN-exposed :22 listed" '[[ "$F" == *"MEDIUM:sec.exposed_services"* ]]'
check "W1m SND nickname confirms device" 'python3 -c "import json,sys; d=json.load(open(\"$AUD/devices.json\")); sys.exit(0 if d[\"$A_MAC\"][\"confirmed\"] else 1)"'
check "W1n SND offline terminal kept in ledger, normalised MAC" 'python3 -c "import json,sys; d=json.load(open(\"$AUD/devices.json\")); sys.exit(0 if \"00:11:22:33:44:55\" in d else 1)"'
check "W1o broadcast/multicast/incomplete ARP rows ignored" '! grep -qE "ff:ff:ff:ff:ff:ff|01:00:5e" "$AUD/devices.json"'
check "W1p dashboard SND file in repo untouched" '[ "$(ls -l "$REPO_SND_JSON" 2>/dev/null || echo absent)" = "$REPO_SND_BEFORE" ]'
check "W1q SND accuracy section" 'report_has "LAN Scan 精度"'

echo "== W2: second run -- new device, disappeared device, admin added, same-day report kept =="
FIRST_REPORT="$R"
FIRST_SUM="$(cksum <"$FIRST_REPORT")"
sed -i.bak "/${B_MAC}/d" "$FIX/arp.out"
echo "? (192.168.1.77) at ${NEW_MAC} on en0 ifscope [ethernet]" >>"$FIX/arp.out"
printf 'GroupMembership: root masa intruder\n' >"$FIX/dscl_admin.out"
printf 'masa 501\nroot 0\nintruder 502\n' >"$FIX/dscl_users.out"
sleep 1
run_audit SND_HOME_API_URL="$SND_URL" >/dev/null 2>&1
F="$(snap_findings)"
check "W2a new unconfirmed device -> HIGH" '[[ "$F" == *"HIGH:net.new_unconfirmed"* ]]'
check "W2b disappeared device -> LOW" '[[ "$F" == *"LOW:net.disappeared"* ]]'
check "W2c disappeared device still in ledger (never deleted)" 'grep -q "$B_MAC" "$AUD/devices.json"'
check "W2d admin added -> CRITICAL" '[[ "$F" == *"CRITICAL:sec.admin_added"* ]]'
check "W2e account added -> HIGH" '[[ "$F" == *"HIGH:sec.account_added"* ]]'
check "W2f earlier same-day report not overwritten" '[ "$(cksum <"$FIRST_REPORT")" = "$FIRST_SUM" ] && [ "$(find "$AUD" -maxdepth 1 -name "WEEKLY_AUDIT_*.md" | wc -l | tr -d " ")" = 2 ]'
check "W2g comparison table rendered" 'report_has "| 重大度 | 前回 | 今回 | 増減 |"'
check "W2h approval list names the admin change" 'report_has "管理者権限の付与に心当たりがあるか即時確認"'
check "W2i first_seen of a persistent finding carried over" 'python3 -c "
import glob,json,sys
s=[json.load(open(p)) for p in sorted(glob.glob(\"$AUD/snapshots/*.json\"))]
a={x[\"id\"]:x[\"first_seen\"] for x in s[0][\"findings\"]}; b={x[\"id\"]:x[\"first_seen\"] for x in s[1][\"findings\"]}
sys.exit(0 if b[\"sec.snd_api_key_unset\"]==a[\"sec.snd_api_key_unset\"] else 1)"'

echo "== W3: known_devices.conf confirms a device =="
printf '%s  test-laptop\n' "$NEW_MAC" >"$AUD/known_devices.conf"
chmod 600 "$AUD/known_devices.conf"
run_audit SND_HOME_API_URL="$SND_URL" >/dev/null 2>&1
check "W3a known device confirmed" 'python3 -c "import json,sys; d=json.load(open(\"$AUD/devices.json\")); sys.exit(0 if d[\"$NEW_MAC\"][\"known_label\"]==\"test-laptop\" else 1)"'

echo "== W4: SND enforces API_KEY (401 without token) -> no HIGH =="
echo auth >"$SND_MODE_FILE"
run_audit SND_HOME_API_URL="$SND_URL" >/dev/null 2>&1
F="$(snap_findings)"
check "W4a no api_key finding when 401" '[[ "$F" != *"sec.snd_api_key_unset"* ]]'

echo "== W5: SND unavailable -> audit continues =="
run_audit SND_HOME_API_URL="http://127.0.0.1:1" >/dev/null 2>&1; RC=$?
F="$(snap_findings)"
check "W5a exit 0" '[ "$RC" -eq 0 ]'
check "W5b snd.unavailable MEDIUM" '[[ "$F" == *"MEDIUM:snd.unavailable"* ]]'
check "W5c network section still produced from ARP" 'report_has "ネットワーク端末一覧" && grep -q "192.168.1.33" "$(latest_report)"'
run_audit >/dev/null 2>&1
check "W5d SND not configured -> MEDIUM, still runs" '[[ "$(snap_findings)" == *"MEDIUM:snd.not_configured"* ]]'

echo "== W6: gateway IP claimed by another host's MAC -> CRITICAL; IP conflict =="
echo "? (192.168.1.33) at ${GW_MAC} on en0 ifscope [ethernet]" >>"$FIX/arp.out"
run_audit >/dev/null 2>&1
F="$(snap_findings)"
check "W6a gateway MAC shared -> CRITICAL" '[[ "$F" == *"CRITICAL:net.gateway_mac_shared"* ]]'
check "W6b IP conflict -> MEDIUM" '[[ "$F" == *"MEDIUM:net.ip_conflict.192.168.1.33"* ]]'
base_fixtures

echo "== W7: firewall disabled -> HIGH; collector failure tolerated =="
cp "$BIN/netstat" "$T/netstat.keep"
printf '#!/bin/bash\nexit 1\n' >"$BIN/netstat"
run_audit FAKE_FW_STATE=disabled >/dev/null 2>&1; RC=$?
F="$(snap_findings)"
check "W7a exit 0 with a missing command" '[ "$RC" -eq 0 ]'
check "W7b firewall disabled -> HIGH" '[[ "$F" == *"HIGH:sec.firewall_disabled"* ]]'
check "W7c collector error surfaced in report" 'report_has "収集時の警告"'
cp "$T/netstat.keep" "$BIN/netstat"

echo "== W8: permissions self-check reports, never fixes =="
chmod 755 "$AUD"
run_audit >/dev/null 2>&1
check "W8a too-open audit dir -> HIGH" '[[ "$(snap_findings)" == *"HIGH:sec.audit_dir_perms"* ]]'
check "W8b mode left as found (no auto-fix)" '[ "$(mode_of "$AUD")" = "0o755" ]'
chmod 700 "$AUD"

echo "== W9: double-start prevention =="
N_BEFORE="$(find "$AUD/snapshots" -name '*.json' | wc -l | tr -d ' ')"
mkdir "$AUD/.weekly_audit.lock"
echo "$$" >"$AUD/.weekly_audit.lock/holder.pid"
OUT="$(run_audit 2>&1)"; RC=$?
check "W9a second run exits 0" '[ "$RC" -eq 0 ]'
check "W9b second run skipped (no new snapshot)" '[ "$(find "$AUD/snapshots" -name "*.json" | wc -l | tr -d " ")" = "$N_BEFORE" ]'
check "W9c skip logged" 'grep -q "skipping this run" "$AUD/weekly-audit.log"'
check "W9d live holder's lock left in place" '[ -d "$AUD/.weekly_audit.lock" ]'
rm -rf "$AUD/.weekly_audit.lock"

echo "== W10: refuses an output dir inside the repository =="
OUT="$(env -i HOME="$T/home" PATH="$BIN:/usr/bin:/bin" WEEKLY_AUDIT_DIR="$SCRIPT_DIR/logs/weekly-audit-should-not-exist" ./security/weekly_audit/weekly_audit_cron.sh 2>&1)"; RC=$?
check "W10a exit 2" '[ "$RC" -eq 2 ]'
check "W10b nothing created in repo" '[ ! -e "$SCRIPT_DIR/logs/weekly-audit-should-not-exist" ]'

echo "== W11: static policy guards =="
SRC="security/weekly_audit/weekly_audit_cron.sh security/weekly_audit/weekly_audit_lib.py"
CODE="$(grep -hvE '^[[:space:]]*#' $SRC)"
check "W11a no sudo" '! grep -qE "\bsudo\b" <<<"$CODE"'
check "W11b no firewall mutation" '! grep -qE "pfctl|socketfilterfw[^\n]*--set|--setglobalstate" <<<"$CODE"'
check "W11c no launchctl load/unload/kickstart/bootout/stop" '! grep -qE "launchctl[[:space:]]+(load|unload|kickstart|bootout|bootstrap|stop|remove)" <<<"$CODE"'
check "W11d no kill/pkill/shutdown/reboot" '! grep -qE "\b(pkill|killall|shutdown|reboot|halt)\b|\bkill[[:space:]]+-" <<<"$CODE"'
check "W11e no rm / unlink / rmtree" '! grep -qE "\brm[[:space:]]|os\.remove|os\.unlink|rmtree" <<<"$CODE"'
check "W11f no active scanners" '! grep -qE "\b(nmap|ping|arping|masscan|nc[[:space:]]+-z)\b" <<<"$CODE"'
check "W11g no chmod call (report, never fix)" '! grep -qE "^[[:space:]]*chmod[[:space:]]|[;&|][[:space:]]*chmod[[:space:]]|os\.chmod|os\.fchmod" <<<"$CODE"'
check "W11h plist example has no real LAN address" '! grep -qE "192\.168\.|10\.[0-9]+\.[0-9]+\.[0-9]+" security/weekly_audit/com.waio.weekly-audit.plist.example'

echo
echo "weekly_audit_test: $PASS passed, $FAIL failed"
if [ "$FAIL" -gt 0 ]; then
  printf '  - %s\n' "${FAILURES[@]}"
  exit 1
fi
exit 0
