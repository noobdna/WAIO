#!/usr/bin/env python3
"""security/weekly_audit/weekly_audit_lib.py -- WAIO weekly security audit:
parse the raw, read-only observations weekly_audit_cron.sh collected,
compare them with the previous audit, grade findings and render
WEEKLY_AUDIT_YYYYMMDD.md.

Policy (enforced by tests/weekly_audit_test.sh's static guards):
  - read-only: this module only reads the work directory the cron
    wrapper filled, the previous snapshot and the device ledger, and
    writes the report, a new snapshot and the updated ledger -- all
    inside the private audit directory (outside the public repo).
  - it never blocks, deletes, restarts, changes a firewall or an
    API key, and never opens a network connection.
  - device records are never deleted: a device that is not seen keeps
    its record and is classified by its last-seen date.

Usage:
  weekly_audit_lib.py run --work DIR --audit-dir DIR --run-id ID
                          --now ISO8601 [--waio-log-dir DIR]
"""

import argparse
import datetime as dt
import glob
import ipaddress
import json
import os
import plistlib
import re
import stat
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "ssh_exposure"))
import ssh_exposure_lib as sel  # noqa: E402  (reused: lsof parsing, scope classification)

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}
JST = dt.timezone(dt.timedelta(hours=9), "JST")

# --- small helpers ---------------------------------------------------------


def read_text(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return None


def read_json(path):
    text = read_text(path)
    if text is None:
        return None
    try:
        return json.loads(text)
    except ValueError:
        return None


def write_private(path, text):
    """Write a 0600 file atomically (umask 077 is also set by the cron wrapper)."""
    tmp = f"{path}.tmp.{os.getpid()}"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)
    os.replace(tmp, path)


def parse_iso(s):
    if not s or not isinstance(s, str):
        return None
    try:
        t = dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None
    if t.tzinfo is None:
        t = t.replace(tzinfo=dt.timezone.utc)
    return t


def norm_mac(mac):
    """'0:1a:2b:3:4:5' -> '00:1a:2b:03:04:05'; None for anything that is not a MAC."""
    if not mac or not isinstance(mac, str):
        return None
    parts = re.split(r"[:\-]", mac.strip().lower())
    if len(parts) != 6 or not all(re.fullmatch(r"[0-9a-f]{1,2}", p) for p in parts):
        return None
    return ":".join(p.zfill(2) for p in parts)


def is_unicast_mac(mac):
    if mac is None or mac == "ff:ff:ff:ff:ff:ff":
        return False
    return int(mac.split(":")[0], 16) & 1 == 0  # multicast bit clear


# --- parsers (one per raw file; each tolerates missing/garbled input) -----

_ARP_RE = re.compile(r"^\S+ \(([^)]+)\) at (\S+) on (\S+)")


def parse_arp(text):
    """`arp -an` -> [{ip, mac, iface}] (incomplete/broadcast/multicast skipped)."""
    out = []
    for line in (text or "").splitlines():
        m = _ARP_RE.match(line.strip())
        if not m:
            continue
        ip, mac, iface = m.groups()
        mac = norm_mac(mac)
        if not is_unicast_mac(mac):
            continue
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if addr.is_multicast or str(addr).endswith(".255"):
            continue
        out.append({"ip": ip, "mac": mac, "iface": iface})
    return out


def parse_ifconfig(text):
    """`ifconfig` -> {iface: {mac, inet: [..], inet6: [..], active}}."""
    ifaces = {}
    cur = None
    for line in (text or "").splitlines():
        m = re.match(r"^([A-Za-z0-9]+): flags=", line)
        if m:
            cur = ifaces.setdefault(m.group(1), {"mac": None, "inet": [], "inet6": [], "active": False})
            continue
        if cur is None:
            continue
        s = line.strip()
        if s.startswith("ether "):
            cur["mac"] = norm_mac(s.split()[1])
        elif s.startswith("inet6 "):
            cur["inet6"].append(s.split()[1].split("%")[0])
        elif s.startswith("inet "):
            cur["inet"].append(s.split()[1])
        elif s.startswith("status: active"):
            cur["active"] = True
    return ifaces


def parse_route_default(text):
    out = {"gateway": None, "interface": None}
    for line in (text or "").splitlines():
        k, _, v = line.strip().partition(":")
        if k in ("gateway", "interface") and v.strip():
            out[k] = v.strip()
    return out


def parse_dhcp_packet(text):
    """`ipconfig getpacket IFACE` -> the handful of fields the audit tracks."""
    want = {
        "yiaddr": "ip", "server_identifier (ip)": "dhcp_server", "lease_time (uint32)": "lease_time",
        "router (ip_mult)": "router", "domain_name_server (ip_mult)": "dns", "subnet_mask (ip)": "subnet_mask",
    }
    out = {}
    for line in (text or "").splitlines():
        k, sep, v = line.strip().partition(":")
        if not sep:
            k, sep, v = line.strip().partition("=")
        k = k.strip()
        if k in want:
            v = v.strip().strip("{}").strip()
            if k == "lease_time (uint32)":
                try:
                    v = int(v, 0)
                except ValueError:
                    pass
            out[want[k]] = v
    return out


def parse_netstat_listen(text):
    """`netstat -an -p tcp` LISTEN rows -> [{proto, host, port}] (system-wide, no root needed)."""
    out = []
    for line in (text or "").splitlines():
        parts = line.split()
        if len(parts) < 6 or parts[-1] != "LISTEN" or not parts[0].startswith("tcp"):
            continue
        host, _, port = parts[3].rpartition(".")
        if not port.isdigit():
            continue
        out.append({"proto": parts[0], "host": host or "*", "port": int(port)})
    return out


def parse_lsof_listen(text):
    recs = []
    for line in (text or "").splitlines():
        if line.startswith("COMMAND"):
            continue
        r = sel.parse_lsof_listen_line(line)
        if r:
            recs.append(r)
    return recs


def build_listeners(netstat_text, lsof_text):
    """Union of netstat (complete, no process names) and lsof (this user's
    processes only, but named). Keyed so that ephemeral/high ports owned by
    the same program do not show up as a 'new port' every week."""
    by_port = {}
    for r in parse_lsof_listen(lsof_text):
        by_port.setdefault(r["local_port"], set()).add(r["command"])
    seen = {}
    for r in parse_netstat_listen(netstat_text):
        scope, family = sel.classify_listener_scope(r["host"])
        cmds = sorted(by_port.get(r["port"], set()))
        command = ",".join(cmds) if cmds else None
        ident = str(r["port"]) if r["port"] < 49152 else (command or "ephemeral")
        key = f"{scope}:{ident}"
        cur = seen.setdefault(key, {"key": key, "scope": scope, "family": set(), "ports": set(),
                                    "command": command, "hosts": set()})
        cur["family"].add(family)
        cur["ports"].add(r["port"])
        cur["hosts"].add(r["host"])
    out = []
    for v in seen.values():
        out.append({"key": v["key"], "scope": v["scope"], "family": sorted(v["family"]),
                    "ports": sorted(v["ports"]), "command": v["command"], "hosts": sorted(v["hosts"])})
    return sorted(out, key=lambda x: (x["scope"], min(x["ports"])))


def parse_users(text):
    """`dscl . -list /Users UniqueID` -> {name: uid} for real accounts (uid 0 or >= 500, no '_' prefix)."""
    out = {}
    for line in (text or "").splitlines():
        parts = line.split()
        if len(parts) != 2 or not parts[1].lstrip("-").isdigit():
            continue
        name, uid = parts[0], int(parts[1])
        if name.startswith("_"):
            continue
        if uid == 0 or uid >= 500:
            out[name] = uid
    return out


def parse_group_membership(text):
    for line in (text or "").splitlines():
        if line.startswith("GroupMembership:"):
            return sorted(line.split(":", 1)[1].split())
    return []


def parse_df(text):
    """`df -kl` -> [{mount, used_pct}]."""
    out = []
    for line in (text or "").splitlines()[1:]:
        parts = line.split()
        if len(parts) < 6:
            continue
        pct = next((p for p in parts if re.fullmatch(r"\d+%", p)), None)
        mount = parts[-1]
        if pct is None or not mount.startswith("/"):
            continue
        if mount.startswith("/System/Volumes/") and mount != "/System/Volumes/Data":
            continue
        out.append({"mount": mount, "used_pct": int(pct[:-1]), "filesystem": parts[0]})
    return out


def parse_memory(vm_stat_text, memsize_text):
    pages = {}
    page_size = 4096
    for line in (vm_stat_text or "").splitlines():
        m = re.search(r"page size of (\d+) bytes", line)
        if m:
            page_size = int(m.group(1))
            continue
        k, _, v = line.partition(":")
        v = v.strip().rstrip(".")
        if v.isdigit():
            pages[k.strip()] = int(v)
    try:
        total = int((memsize_text or "").strip())
    except ValueError:
        total = None
    avail = sum(pages.get(k, 0) for k in ("Pages free", "Pages inactive", "Pages speculative", "Pages purgeable"))
    if not total or not pages:
        return {"total_bytes": total, "used_pct": None}
    used_pct = round(100 * (1 - (avail * page_size) / total), 1)
    return {"total_bytes": total, "used_pct": max(0.0, min(100.0, used_pct))}


def parse_loadavg(text, ncpu_text):
    nums = re.findall(r"\d+(?:\.\d+)?", text or "")
    try:
        ncpu = int((ncpu_text or "").strip())
    except ValueError:
        ncpu = None
    return {"load": [float(x) for x in nums[:3]] if len(nums) >= 3 else None, "ncpu": ncpu}


def parse_launchctl(text, label_prefix="com.waio."):
    """`launchctl list` -> {label: {pid, status}} for WAIO agents."""
    out = {}
    for line in (text or "").splitlines():
        parts = line.split("\t") if "\t" in line else line.split()
        if len(parts) != 3 or not parts[2].startswith(label_prefix):
            continue
        pid, status, label = parts
        out[label] = {"pid": None if pid == "-" else pid, "status": int(status) if status.lstrip("-").isdigit() else status}
    return out


def parse_sw_vers(text):
    out = {}
    for line in (text or "").splitlines():
        k, _, v = line.partition(":")
        if v.strip():
            out[k.strip()] = v.strip()
    return out


def parse_update_history(text):
    """`softwareupdate --history` -> [{name, version, date}] (local install history, no network)."""
    out = []
    for line in (text or "").splitlines():
        m = re.search(r"^(.*?)\s{2,}(\S+)\s+(\d{4}/\d{2}/\d{2}) +(\d{1,2}:\d{2}:\d{2})", line)
        if not m:
            continue
        name, ver, d, t = m.groups()
        try:
            when = dt.datetime.strptime(f"{d} {t}", "%Y/%m/%d %H:%M:%S").replace(tzinfo=JST)
        except ValueError:
            continue
        out.append({"name": name.strip(), "version": ver, "date": when.isoformat()})
    return out


def parse_backup_log(text):
    """logs/wsr-backup-cron.log -> last ok / last failed ISO timestamps."""
    last_ok = last_fail = None
    for line in (text or "").splitlines():
        ts = line.split(" ", 1)[0]
        if "wsr_backup_create: ok" in line:
            last_ok = ts
        elif "wsr_backup_create: FAILED" in line:
            last_fail = ts
    return {"last_ok": last_ok, "last_failed": last_fail}


_HTTP_RE = re.compile(r'^(\S+) \S+ \S+ \[(\d{2}/\w{3}/\d{4} \d{2}:\d{2}:\d{2})\] "[^"]*" (\d{3}) ')


def parse_http_log(text, now, days=7):
    """Dashboard server access log -> status counts for the last `days` days
    (the log's timestamps are this host's local time = JST)."""
    since = now - dt.timedelta(days=days)
    counts = {"200": 0, "401": 0, "403": 0, "404": 0, "other": 0}
    denied_sources = {}
    total = 0
    for line in (text or "").splitlines():
        m = _HTTP_RE.match(line)
        if not m:
            continue
        src, ts, code = m.groups()
        try:
            when = dt.datetime.strptime(ts, "%d/%b/%Y %H:%M:%S").replace(tzinfo=JST)
        except ValueError:
            continue
        if when < since or when > now + dt.timedelta(minutes=5):
            continue
        total += 1
        counts[code if code in counts else "other"] += 1
        if code in ("401", "403"):
            denied_sources[src] = denied_sources.get(src, 0) + 1
    return {"total": total, "counts": counts, "denied_sources": denied_sources}


def count_log_errors(log_dir, now, days=7):
    """Lines starting with an ISO timestamp inside the window that mention an
    error, per WAIO log file. Read-only; files are never rotated or touched."""
    since = now - dt.timedelta(days=days)
    pat = re.compile(r"\b(ERROR|FATAL|FAILED|Traceback)\b")
    out = {}
    for path in sorted(glob.glob(os.path.join(log_dir, "*.log"))):
        try:
            if dt.datetime.fromtimestamp(os.path.getmtime(path), dt.timezone.utc) < since:
                continue
        except OSError:
            continue
        n = 0
        for line in (read_text(path) or "").splitlines():
            ts = parse_iso(line.split(" ", 1)[0]) if line[:2] == "20" else None
            if ts and ts >= since and pat.search(line):
                n += 1
        if n:
            out[os.path.basename(path)] = n
    return out


# --- device model ----------------------------------------------------------


def snd_terminals(snd):
    """SND_HOME ledger -> {mac: {...}}; one terminal may own several MACs."""
    out = {}
    for t in (snd or {}).get("terminals") or []:
        if not isinstance(t, dict):
            continue
        for mac in t.get("macs") or []:
            mac = norm_mac(mac if isinstance(mac, str) else (mac or {}).get("mac"))
            if not mac:
                continue
            out[mac] = {
                "terminal_id": t.get("terminalId"),
                "ip": t.get("displayIp"),
                "online": bool(t.get("online")),
                "nickname": t.get("nickname"),
                "first_seen": t.get("firstSeenAt"),
                "last_seen": t.get("lastSeenAt"),
            }
    return out


def load_known_devices(path):
    """Operator-maintained `MAC label...` lines; '#' comments. Optional."""
    out = {}
    for line in (read_text(path) or "").splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        mac, _, label = line.partition(" ")
        mac = norm_mac(mac)
        if mac:
            out[mac] = label.strip() or "known"
    return out


def age_class(last_seen, now):
    t = parse_iso(last_seen)
    if t is None:
        return "unknown"
    days = (now - t).total_seconds() / 86400
    if days <= 7:
        return "active(<=7d)"
    if days <= 30:
        return "recent(8-30d)"
    if days <= 90:
        return "stale(31-90d)"
    return "dormant(>90d)"


def update_ledger(ledger, arp, snd_map, own_macs, known, now_iso):
    """Merge this run's observations into the device ledger. Never removes a record."""
    ledger = dict(ledger or {})
    present = {}
    for e in arp:
        present.setdefault(e["mac"], {"ips": set(), "sources": set()})
        present[e["mac"]]["ips"].add(e["ip"])
        present[e["mac"]]["sources"].add("arp")
    for mac, t in snd_map.items():
        if t["online"]:
            present.setdefault(mac, {"ips": set(), "sources": set()})
            if t["ip"]:
                present[mac]["ips"].add(t["ip"])
            present[mac]["sources"].add("snd")
    for mac in own_macs:
        present.setdefault(mac, {"ips": set(), "sources": set()})["sources"].add("self")

    new_macs = []
    for mac, p in present.items():
        rec = ledger.get(mac)
        if rec is None:
            rec = {"first_seen": now_iso, "ips_seen": []}
            new_macs.append(mac)
        rec["last_seen"] = now_iso
        rec["last_ips"] = sorted(p["ips"])
        rec["ips_seen"] = sorted(set(rec.get("ips_seen", [])) | p["ips"])
        rec["last_sources"] = sorted(p["sources"])
        ledger[mac] = rec
    for mac, t in snd_map.items():  # SND's own history, even for offline terminals
        rec = ledger.setdefault(mac, {"first_seen": t["first_seen"] or now_iso, "ips_seen": [], "last_seen": t["last_seen"]})
        rec["snd"] = {k: t[k] for k in ("terminal_id", "nickname", "online", "first_seen", "last_seen", "ip")}
        if mac not in present and t["last_seen"]:
            prev = parse_iso(rec.get("last_seen"))
            snd_seen = parse_iso(t["last_seen"])
            if snd_seen and (prev is None or snd_seen > prev):
                rec["last_seen"] = t["last_seen"]
    for mac, rec in ledger.items():
        rec["self"] = mac in own_macs
        rec["known_label"] = known.get(mac)
        nick = (rec.get("snd") or {}).get("nickname")
        rec["confirmed"] = bool(rec["self"] or rec["known_label"] or nick)
    return ledger, present, sorted(new_macs)


# --- findings --------------------------------------------------------------


def finding(fid, sev, area, title, detail="", approval=None, proposal=None):
    return {"id": fid, "severity": sev, "area": area, "title": title, "detail": detail,
            "approval": approval, "proposal": proposal}


def assess(cur, prev, now):
    """All grading rules in one place. `prev` is the previous snapshot or None (baseline run)."""
    f = []
    baseline = prev is None
    net, sec, sysm, snd = cur["network"], cur["security"], cur["system"], cur["snd"]

    # A. network
    # On the baseline run every device is "new"; those are graded as
    # unconfirmed-present (MEDIUM) instead of flooding HIGH.
    unconfirmed_new = [] if baseline else [m for m in net["new_devices"] if not cur["ledger"][m]["confirmed"]]
    if unconfirmed_new:
        f.append(finding("net.new_unconfirmed", "HIGH", "A", f"未確認の新規端末 {len(unconfirmed_new)} 台",
                         ", ".join(f"{m} ({'/'.join(cur['ledger'][m].get('last_ips') or []) or '-'})" for m in unconfirmed_new),
                         approval="新規端末の持ち主を確認し、known_devices.conf か SND の nickname に登録するか判断",
                         proposal="既知端末は known_devices.conf (MAC ラベル) に登録すると次回以降の誤検知が減る"))
    unconfirmed_present = [m for m in net["present_macs"] if not cur["ledger"][m]["confirmed"] and m not in unconfirmed_new]
    if unconfirmed_present:
        f.append(finding("net.unconfirmed_present", "MEDIUM", "A", f"未確認のまま稼働中の端末 {len(unconfirmed_present)} 台",
                         ", ".join(unconfirmed_present),
                         proposal="端末の持ち主を確認し known_devices.conf か SND nickname に登録"))
    for gw_dup in net["arp_multi_ip"]:
        if net["gateway"] and net["gateway"] in gw_dup["ips"]:
            f.append(finding(f"net.gateway_mac_shared.{gw_dup['mac']}", "CRITICAL", "A",
                             "デフォルトゲートウェイの IP を他の IP と同じ MAC が名乗っている (ARP spoofing の兆候)",
                             f"{gw_dup['mac']} -> {', '.join(gw_dup['ips'])}",
                             approval="ネットワークの即時点検 (遮断は自動では行わない)"))
        else:
            f.append(finding(f"net.mac_multi_ip.{gw_dup['mac']}", "LOW", "A", "1 つの MAC が複数 IP を使用",
                             f"{gw_dup['mac']} -> {', '.join(gw_dup['ips'])}"))
    for dup in net["ip_conflicts"]:
        f.append(finding(f"net.ip_conflict.{dup['ip']}", "MEDIUM", "A", f"IP 重複の疑い: {dup['ip']}",
                         "MAC: " + ", ".join(dup["macs"]) + f" (source: {dup['source']})",
                         proposal="ルーターの DHCP 割当表と照合"))
    if not baseline:
        pg = (prev.get("network") or {}).get("gateway_mac")
        if pg and net["gateway_mac"] and pg != net["gateway_mac"]:
            f.append(finding("net.gateway_mac_changed", "HIGH", "A", "デフォルトゲートウェイの MAC が変化",
                             f"{pg} -> {net['gateway_mac']}", approval="ルーター交換などの心当たりがあるか確認"))
        changes = diff_dict(prev.get("network", {}).get("config", {}), net["config"])
        if changes:
            f.append(finding("net.config_changed", "LOW", "A", "ネットワーク構成の変化", "; ".join(changes)))
    if net["disappeared"]:
        f.append(finding("net.disappeared", "LOW", "A", f"前回あって今回見えない端末 {len(net['disappeared'])} 台",
                         ", ".join(net["disappeared"])))

    # B. security
    if snd["available"] and not snd["token_sent"] and str(snd.get("terminals_http_status") or "").startswith("200"):
        f.append(finding("sec.snd_api_key_unset", "HIGH", "B",
                         "SND@HOME の API_KEY が未設定 (LAN 端末台帳が認証なしで読める)",
                         "GET /api/lan/terminals がトークンなしで HTTP 200",
                         approval="SND_HOME 側で API_KEY を設定するか (WAIO からは変更しない)",
                         proposal="API_KEY 設定後は SND_HOME_API_TOKEN を監査 LaunchAgent の環境に追加"))
    fw = sec.get("firewall") or {}
    if fw.get("state") == "disabled":
        f.append(finding("sec.firewall_disabled", "HIGH", "B", "macOS アプリケーションファイアウォールが無効",
                         fw.get("detail") or "", approval="ファイアウォールを有効にするか (自動では変更しない)"))
    elif fw.get("state") in (None, "unknown"):
        f.append(finding("sec.firewall_unknown", "LOW", "B", "ファイアウォール状態を取得できない", fw.get("detail") or ""))
    ssh = sec.get("ssh_exposure") or {}
    ssh_sev = (ssh.get("severity") or "").upper()
    if ssh_sev in ("CRITICAL", "HIGH", "MEDIUM"):
        f.append(finding("sec.ssh_exposure", ssh_sev, "B", f"SSH 露出 (scope={ssh.get('scope')})",
                         "; ".join(ssh.get("evidence") or [])[:500],
                         approval="SSH の待受範囲を絞るか" if ssh_sev != "MEDIUM" else None,
                         proposal="sshd の ListenAddress / パスワード認証を見直す"))
    exposed = [l for l in sec["listeners"] if l["scope"] in ("all_interfaces", "lan", "external_direct")]
    # Inventory of services reachable from the LAN (every run, so the
    # baseline is graded too). Ephemeral-port listeners (>= 49152, e.g.
    # rapportd) are listed in section 4 but not graded here.
    fixed = [l for l in exposed if min(l["ports"]) < 49152]
    if fixed:
        fw_off = (sec.get("firewall") or {}).get("state") == "disabled"
        f.append(finding("sec.exposed_services", "HIGH" if fw_off and any(l["scope"] == "external_direct" for l in fixed) else "MEDIUM",
                         "B", f"LAN から到達可能な待受サービス {len(fixed)} 件" + (" (ファイアウォール無効)" if fw_off else ""),
                         ", ".join(f"{l['scope']}:{'/'.join(map(str, l['ports']))}" + (f"({l['command']})" if l["command"] else "")
                                   for l in fixed),
                         proposal="不要なサービス (共有・画面共有・リモートログイン等) は システム設定 > 一般 > 共有 で無効化を検討"))
    if not baseline:
        prev_keys = {l["key"] for l in (prev.get("security") or {}).get("listeners", [])}
        new_exposed = [l for l in exposed if l["key"] not in prev_keys]
        if new_exposed:
            f.append(finding("sec.new_listener", "HIGH", "B", f"LAN 側に新しい待受 {len(new_exposed)} 件",
                             ", ".join(f"{l['key']} ports={l['ports']} cmd={l['command'] or '?'}" for l in new_exposed),
                             approval="新しい待受サービスが意図したものか確認"))
        pu, cu = (prev.get("security") or {}).get("users", {}), sec["users"]
        added = sorted(set(cu) - set(pu))
        removed = sorted(set(pu) - set(cu))
        if added:
            f.append(finding("sec.account_added", "HIGH", "B", "ローカルアカウントが追加された", ", ".join(added),
                             approval="追加されたアカウントに心当たりがあるか確認"))
        if removed:
            f.append(finding("sec.account_removed", "MEDIUM", "B", "ローカルアカウントが削除された", ", ".join(removed)))
        pa, ca = set((prev.get("security") or {}).get("admins", [])), set(sec["admins"])
        if ca - pa:
            f.append(finding("sec.admin_added", "CRITICAL", "B", "管理者グループにメンバーが追加された",
                             ", ".join(sorted(ca - pa)), approval="管理者権限の付与に心当たりがあるか即時確認"))
        if pa - ca:
            f.append(finding("sec.admin_removed", "MEDIUM", "B", "管理者グループからメンバーが外れた", ", ".join(sorted(pa - ca))))
    http = sec["http"]
    if http is None:
        f.append(finding("sec.http_log_missing", "LOW", "B", "ダッシュボードのアクセスログが読めない (401/403 推移を評価できない)"))
    else:
        denied = http["counts"]["401"] + http["counts"]["403"]
        prev_http = (prev or {}).get("security", {}).get("http") or {}
        prev_denied = sum((prev_http.get("counts") or {}).get(k, 0) for k in ("401", "403"))
        if denied >= 20 and (baseline or denied >= 2 * max(prev_denied, 1)):
            f.append(finding("sec.http_denied_spike", "MEDIUM", "B", f"ダッシュボードの 401/403 が増加 ({prev_denied} -> {denied})",
                             ", ".join(f"{k}:{v}" for k, v in sorted(http["denied_sources"].items(), key=lambda x: -x[1])[:5])))
        remote = {s: n for s, n in http["denied_sources"].items() if s not in ("127.0.0.1", "::1", "localhost")}
        if remote:
            f.append(finding("sec.http_denied_remote", "MEDIUM", "B", "ループバック以外からの 401/403",
                             ", ".join(f"{k}:{v}" for k, v in remote.items())))
    dash = sec.get("dashboard") or {}
    if dash.get("bind") and dash["bind"] not in ("127.0.0.1", "::1", "localhost") and not dash.get("auth_file_set"):
        f.append(finding("sec.dashboard_open", "HIGH", "B", "ダッシュボードが非ループバックで認証ファイル未設定",
                         f"bind={dash['bind']}", approval="バインド先か認証設定の見直し"))
    perm = cur["self_check"]
    if perm["problems"]:
        f.append(finding("sec.audit_dir_perms", "HIGH", "B", "監査ディレクトリ/ファイルの権限が想定より広い",
                         "; ".join(perm["problems"]),
                         approval="chmod 700/600 で権限を絞るか (監査は自動修正しない)"))

    # C. system
    for d in sysm["disks"]:
        if d["used_pct"] >= 95:
            f.append(finding(f"sys.disk.{d['mount']}", "HIGH", "C", f"ディスク使用率 {d['used_pct']}%: {d['mount']}",
                             proposal="不要データの退避先を検討 (監査は削除しない)"))
        elif d["used_pct"] >= 85:
            f.append(finding(f"sys.disk.{d['mount']}", "MEDIUM", "C", f"ディスク使用率 {d['used_pct']}%: {d['mount']}",
                             proposal="容量の推移を監視し、退避計画を立てる"))
    la = sysm["load"]
    if la.get("load") and la.get("ncpu") and la["load"][2] > la["ncpu"]:
        f.append(finding("sys.load", "MEDIUM", "C", f"15 分平均負荷 {la['load'][2]} > CPU {la['ncpu']}"))
    for label, s in sorted(sysm["services"].items()):
        if s["pid"] is None and s["status"] not in (0, "0"):
            f.append(finding(f"sys.service.{label}", "MEDIUM", "C", f"{label} の最終終了ステータスが {s['status']}",
                             proposal="該当ログを確認 (自動再起動はしない)"))
    for label in sysm["agents_not_loaded"]:
        f.append(finding(f"sys.service_unloaded.{label}", "MEDIUM", "C", f"{label} の plist はあるが launchd に未ロード"))
    if sysm["log_errors"]:
        total = sum(sysm["log_errors"].values())
        f.append(finding("sys.log_errors", "LOW", "C", f"直近 7 日の WAIO ログにエラー行 {total} 件",
                         ", ".join(f"{k}:{v}" for k, v in sysm["log_errors"].items())))
    b = sysm["backup"]
    ok = parse_iso(b.get("last_ok"))
    if ok is None:
        f.append(finding("sys.backup_unknown", "MEDIUM", "C", "WSR バックアップの成功記録が見つからない"))
    else:
        age = (now - ok).days
        if age > 8:
            f.append(finding("sys.backup_stale", "MEDIUM", "C", f"WSR バックアップ最終成功から {age} 日"))
    fail = parse_iso(b.get("last_failed"))
    if fail and (ok is None or fail > ok):
        f.append(finding("sys.backup_failed", "MEDIUM", "C", "WSR バックアップの最終実行が失敗", b.get("last_failed")))
    upd = sysm["updates"]
    last = parse_iso(upd.get("last_install"))
    if last is None:
        f.append(finding("sys.updates_unknown", "LOW", "C", "更新履歴を取得できない"))
    else:
        age = (now - last).days
        if age > 90:
            f.append(finding("sys.updates_stale", "HIGH", "C", f"最終ソフトウェア更新から {age} 日",
                             approval="macOS の更新を適用するか (監査は更新しない)"))
        elif age > 30:
            f.append(finding("sys.updates_stale", "MEDIUM", "C", f"最終ソフトウェア更新から {age} 日",
                             "未適用の更新はローカル情報だけでは判定できない",
                             proposal="手動で ソフトウェアアップデート を確認"))

    # D. WAIO / SND@HOME
    if not snd["configured"]:
        f.append(finding("snd.not_configured", "MEDIUM", "D", "SND@HOME 連携が未設定 (SND_HOME_API_URL)",
                         proposal="監査 LaunchAgent の環境に SND_HOME_API_URL を設定"))
    elif not snd["available"]:
        f.append(finding("snd.unavailable", "MEDIUM", "D", "SND@HOME unavailable (監査は継続)", snd.get("reason") or ""))
    acc = snd.get("accuracy")
    if acc and acc["arp_only"]:
        sev = "MEDIUM" if len(acc["arp_only"]) >= 3 else "LOW"
        f.append(finding("snd.scan_gap", sev, "D", f"Mac の ARP に見えて SND がオンライン扱いしない端末 {len(acc['arp_only'])} 台",
                         ", ".join(acc["arp_only"]), proposal="SND の LAN Scan 間隔・対象サブネットを確認"))
    if snd.get("alert_count"):
        f.append(finding("snd.active_alerts", "LOW", "D", f"SND のアクティブアラート {snd['alert_count']} 件"))
    for name, info in cur["waio"]["monitors"].items():
        if info.get("stale"):
            f.append(finding(f"waio.monitor_stale.{name}", "MEDIUM", "D", f"{name} の最終出力が古い ({info.get('age_hours')} 時間前)"))
        elif info.get("missing"):
            f.append(finding(f"waio.monitor_missing.{name}", "LOW", "D", f"{name} の出力が見つからない"))

    # carry first_seen across runs so "unresolved since" is meaningful
    prev_first = {x["id"]: x.get("first_seen") for x in (prev or {}).get("findings", [])}
    for x in f:
        x["first_seen"] = prev_first.get(x["id"]) or cur["generated_at"]
    f.sort(key=lambda x: (SEV_RANK[x["severity"]], x["area"], x["id"]))
    return f


def diff_dict(old, new):
    out = []
    for k in sorted(set(old) | set(new)):
        if old.get(k) != new.get(k):
            out.append(f"{k}: {old.get(k)} -> {new.get(k)}")
    return out


# --- build the current snapshot from the work directory --------------------


def check_permissions(audit_dir):
    problems = []
    for root, dirs, files in os.walk(audit_dir):
        dirs[:] = [d for d in dirs if d != "work"]  # this run's raw dir is checked by the wrapper
        for name, want in [(d, 0o700) for d in dirs] + [(fn, 0o600) for fn in files]:
            p = os.path.join(root, name)
            try:
                mode = stat.S_IMODE(os.lstat(p).st_mode)
            except OSError:
                continue
            if mode & 0o077:
                problems.append(f"{os.path.relpath(p, audit_dir)} mode {oct(mode)} (want {oct(want)})")
    try:
        mode = stat.S_IMODE(os.stat(audit_dir).st_mode)
        if mode & 0o077:
            problems.insert(0, f". mode {oct(mode)} (want 0o700)")
    except OSError as e:
        problems.insert(0, f"cannot stat audit dir: {e}")
    return {"problems": problems[:20]}


def load_dashboard_env(plist_path):
    try:
        with open(plist_path, "rb") as f:
            env = plistlib.load(f).get("EnvironmentVariables", {}) or {}
    except Exception:
        return None
    return {"bind": env.get("WAIO_DASHBOARD_BIND", "127.0.0.1"), "auth_file_set": bool(env.get("WAIO_DASHBOARD_AUTH_FILE"))}


def monitor_age(path, max_hours, now):
    try:
        age_h = (now.timestamp() - os.path.getmtime(path)) / 3600
    except OSError:
        return {"missing": True}
    return {"age_hours": round(age_h, 1), "stale": age_h > max_hours}


def build_current(work, audit_dir, waio_log_dir, launch_agents_dir, now, run_id):
    W = lambda name: read_text(os.path.join(work, name))  # noqa: E731
    gen = now.isoformat(timespec="seconds")

    arp = parse_arp(W("arp.txt"))
    ifaces = parse_ifconfig(W("ifconfig.txt"))
    own_macs = {i["mac"] for i in ifaces.values() if i["mac"] and i["active"]}
    route = parse_route_default(W("route_default.txt"))
    dhcp = parse_dhcp_packet(W("dhcp.txt"))
    primary = ifaces.get(route["interface"] or "", {})

    snd_raw = read_json(os.path.join(work, "snd.json")) or {}
    snd_map = snd_terminals(snd_raw)
    known = load_known_devices(os.path.join(audit_dir, "known_devices.conf"))
    ledger_path = os.path.join(audit_dir, "devices.json")
    old_ledger = read_json(ledger_path) or {}
    ledger, present, new_macs = update_ledger(old_ledger, arp, snd_map, own_macs, known, gen)
    for mac, rec in ledger.items():
        rec["age_class"] = "present" if mac in present else age_class(rec.get("last_seen"), now)

    ip_macs = {}
    mac_ips = {}
    for e in arp:
        ip_macs.setdefault(e["ip"], set()).add(e["mac"])
        mac_ips.setdefault(e["mac"], set()).add(e["ip"])
    conflicts = [{"ip": ip, "macs": sorted(m), "source": "arp"} for ip, m in ip_macs.items() if len(m) > 1]
    snd_ip = {}
    for mac, t in snd_map.items():
        if t["online"] and t["ip"]:
            snd_ip.setdefault(t["ip"], {}).setdefault(t["terminal_id"], set()).add(mac)
    for ip, terms in snd_ip.items():
        if len(terms) > 1:
            conflicts.append({"ip": ip, "macs": sorted(set().union(*terms.values())), "source": "snd"})
    multi = [{"mac": m, "ips": sorted(i)} for m, i in mac_ips.items() if len(i) > 1 and m not in own_macs]
    gw_mac = next((e["mac"] for e in arp if e["ip"] == route["gateway"]), None)

    netcfg = {
        "interface": route["interface"], "gateway": route["gateway"], "own_ipv4": ",".join(primary.get("inet", [])),
        "dhcp_server": dhcp.get("dhcp_server"), "dns": dhcp.get("dns"), "subnet_mask": dhcp.get("subnet_mask"),
    }

    ssh_event = None
    for line in (W("ssh_exposure.json") or "").splitlines():
        try:
            ssh_event = json.loads(line)
            break
        except ValueError:
            continue
    fw = (ssh_event or {}).get("firewall") or {}

    http_text = read_text(os.path.join(waio_log_dir, "dashboard-server-launchd.log"))
    http = parse_http_log(http_text, now) if http_text is not None else None

    disks = parse_df(W("df.txt"))
    history = parse_update_history(W("softwareupdate_history.txt"))
    last_install = max((h["date"] for h in history), default=None)

    services = parse_launchctl(W("launchctl.txt"))
    plists = sorted(os.path.basename(p)[:-6] for p in glob.glob(os.path.join(launch_agents_dir, "com.waio.*.plist")))
    not_loaded = [p for p in plists if p not in services]

    snd_avail = bool(snd_raw.get("available"))
    accuracy = None
    if snd_avail:
        snd_online = {m for m, t in snd_map.items() if t["online"]}
        arp_macs = {e["mac"] for e in arp} - own_macs
        accuracy = {
            "snd_online": len(snd_online), "arp_seen": len(arp_macs), "both": len(snd_online & arp_macs),
            "arp_only": sorted(arp_macs - snd_online), "snd_only": sorted(snd_online - arp_macs),
        }
    alerts = snd_raw.get("active_alerts")
    if isinstance(alerts, dict):
        alerts = alerts.get("data") if isinstance(alerts.get("data"), list) else alerts.get("alerts")
    alert_count = len(alerts) if isinstance(alerts, list) else 0

    cur = {
        "schema": 1,
        "run_id": run_id,
        "generated_at": gen,
        "ledger": ledger,
        "network": {
            "gateway": route["gateway"], "gateway_mac": gw_mac, "config": netcfg, "dhcp": dhcp,
            "arp": arp, "present_macs": sorted(present), "new_devices": new_macs,
            "ip_conflicts": conflicts, "arp_multi_ip": multi, "disappeared": [],
        },
        "security": {
            "firewall": {"state": fw.get("state"), "tool": fw.get("tool"), "detail": fw.get("detail")},
            "ssh_exposure": None if ssh_event is None else {
                "severity": ssh_event.get("severity"), "scope": (ssh_event.get("exposure") or {}).get("scope"),
                "evidence": ssh_event.get("evidence") if isinstance(ssh_event.get("evidence"), list) else
                [json.dumps(ssh_event.get("evidence"), ensure_ascii=False)[:300]],
            },
            "listeners": build_listeners(W("netstat_listen.txt"), W("lsof.txt")),
            "users": parse_users(W("dscl_users.txt")),
            "admins": parse_group_membership(W("dscl_admin.txt")),
            "http": http,
            "dashboard": load_dashboard_env(os.path.join(launch_agents_dir, "com.waio.dashboard-server.plist")),
        },
        "system": {
            "disks": disks,
            "memory": parse_memory(W("vm_stat.txt"), W("memsize.txt")),
            "load": parse_loadavg(W("loadavg.txt"), W("ncpu.txt")),
            "uptime": (W("uptime.txt") or "").strip(),
            "services": services,
            "agents_not_loaded": not_loaded,
            "log_errors": count_log_errors(waio_log_dir, now),
            "backup": parse_backup_log(read_text(os.path.join(waio_log_dir, "wsr-backup-cron.log"))),
            "time_machine": (W("tmutil_latest.txt") or "").strip() or None,
            "updates": {"os": parse_sw_vers(W("sw_vers.txt")), "last_install": last_install,
                        "recent": sorted(history, key=lambda h: h["date"])[-5:]},
        },
        "snd": {
            "configured": bool(snd_raw.get("configured")), "available": snd_avail, "reason": snd_raw.get("reason"),
            "api_url": snd_raw.get("api_url"), "terminals_http_status": snd_raw.get("terminals_http_status"),
            "token_sent": bool(snd_raw.get("token_sent")), "terminal_count": len({t["terminal_id"] for t in snd_map.values()}),
            "online_count": len({t["terminal_id"] for t in snd_map.values() if t["online"]}),
            "accuracy": accuracy, "alert_count": alert_count,
        },
        "waio": {"monitors": {
            "global-patrol": monitor_age(os.path.join(waio_log_dir, "global-patrol-report-latest.json"), 96, now),
            "wsr-backup": monitor_age(os.path.join(waio_log_dir, "wsr-backup-cron.log"), 8 * 24, now),
            "dashboard-refresh": monitor_age(os.path.join(waio_log_dir, "dashboard-refresh-cron.log"), 24, now),
        }},
        "self_check": check_permissions(audit_dir),
        "collector_errors": [ln for ln in (W("collector_errors.txt") or "").splitlines() if ln.strip()],
    }
    return cur, ledger_path


def find_previous_snapshot(snap_dir, run_id):
    snaps = sorted(p for p in glob.glob(os.path.join(snap_dir, "snapshot_*.json"))
                   if os.path.basename(p) != f"snapshot_{run_id}.json")
    for p in reversed(snaps):
        d = read_json(p)
        if isinstance(d, dict) and d.get("schema") == 1:
            return d, p
    return None, None


# --- report ----------------------------------------------------------------


def md_escape(s):
    return str(s).replace("|", "\\|").replace("\n", " ")


def render_report(cur, prev, prev_path, findings, now):
    L = []
    counts = {s: sum(1 for x in findings if x["severity"] == s) for s in SEVERITIES}
    overall = next((s for s in SEVERITIES if counts[s]), "OK")
    prev_f = {x["id"]: x for x in (prev or {}).get("findings", [])}
    cur_ids = {x["id"] for x in findings}
    new_f = [x for x in findings if x["id"] not in prev_f]
    resolved = [x for i, x in prev_f.items() if i not in cur_ids]
    persistent = [x for x in findings if x["id"] in prev_f]
    net, sec, sysm, snd = cur["network"], cur["security"], cur["system"], cur["snd"]

    L.append(f"# WAIO WEEKLY SECURITY AUDIT -- {now.strftime('%Y-%m-%d %H:%M')} JST")
    L.append("")
    L.append(f"- run_id: `{cur['run_id']}` / 前回: `{os.path.basename(prev_path) if prev_path else 'なし (初回ベースライン)'}`")
    L.append("- モード: 読み取り専用 (遮断・削除・再起動・FW/API_KEY 変更・外部スキャンは一切行っていない)")
    if cur["collector_errors"]:
        L.append(f"- 収集時の警告: {md_escape('; '.join(cur['collector_errors'])[:400])}")
    L.append("")

    L.append("## 1. 総合判定")
    L.append("")
    L.append(f"**{overall}** -- CRITICAL {counts['CRITICAL']} / HIGH {counts['HIGH']} / MEDIUM {counts['MEDIUM']} / LOW {counts['LOW']}")
    if counts["CRITICAL"]:
        L.append("")
        L.append("> CRITICAL があります。人間による即時確認が必要です。")
    L.append("")

    L.append("## 2. 今週の変更点")
    L.append("")
    if prev is None:
        L.append("- 初回実行のため、今回の結果をベースラインとして保存した。")
    else:
        ch = []
        ch += [f"新規端末: {m}" for m in net["new_devices"]]
        ch += [f"消失端末: {m}" for m in net["disappeared"]]
        ch += [f"ネットワーク構成: {c}" for c in diff_dict(prev["network"].get("config", {}), net["config"])]
        pk = {l["key"] for l in prev["security"].get("listeners", [])}
        ck = {l["key"] for l in sec["listeners"]}
        ch += [f"待受追加: {k}" for k in sorted(ck - pk)] + [f"待受消滅: {k}" for k in sorted(pk - ck)]
        pf = (prev["security"].get("firewall") or {}).get("state")
        if pf != sec["firewall"]["state"]:
            ch.append(f"ファイアウォール: {pf} -> {sec['firewall']['state']}")
        ch += [f"新規の指摘: [{x['severity']}] {x['title']}" for x in new_f]
        ch += [f"解消: [{x['severity']}] {x['title']}" for x in resolved]
        L += [f"- {md_escape(c)}" for c in ch] or ["- 変更なし"]
    L.append("")

    L.append("## 3. ネットワーク端末一覧")
    L.append("")
    c = net["config"]
    L.append(f"- IF `{c.get('interface')}` / 自IP `{c.get('own_ipv4')}` / GW `{c.get('gateway')}` ({net['gateway_mac'] or 'MAC不明'})"
             f" / DHCP `{c.get('dhcp_server')}` / DNS `{c.get('dns')}`")
    L.append(f"- 今回検出: {len(net['present_macs'])} 台 (ARP {len({e['mac'] for e in net['arp']})}"
             f", SND online {snd['online_count'] if snd['available'] else '-'}) / 台帳累計: {len(cur['ledger'])} 台 (削除しない)")
    L.append("")
    L.append("| 状態 | MAC | IP | 確認 | ラベル/nickname | 初回 | 最終 | 出所 |")
    L.append("|---|---|---|---|---|---|---|---|")
    order = {"present": 0, "active(<=7d)": 1, "recent(8-30d)": 2, "stale(31-90d)": 3, "dormant(>90d)": 4, "unknown": 5}
    for mac, r in sorted(cur["ledger"].items(), key=lambda kv: (order.get(kv[1]["age_class"], 9), kv[0])):
        label = "this host" if r.get("self") else (r.get("known_label") or (r.get("snd") or {}).get("nickname") or "")
        ips = ",".join(r.get("last_ips") or []) or (r.get("snd") or {}).get("ip") or ""
        L.append(f"| {r['age_class']} | `{mac}` | {md_escape(ips)} | {'済' if r['confirmed'] else '**未確認**'} | "
                 f"{md_escape(label)} | {str(r.get('first_seen') or '')[:10]} | {str(r.get('last_seen') or '')[:10]} | "
                 f"{','.join(r.get('last_sources') or ['snd-ledger'])} |")
    L.append("")

    L.append("## 4. セキュリティ異常")
    L.append("")
    fw = sec["firewall"]
    L.append(f"- ファイアウォール: **{fw['state'] or 'unknown'}** ({md_escape(fw.get('detail') or '')})")
    ssh = sec["ssh_exposure"] or {}
    L.append(f"- SSH 露出: severity={ssh.get('severity')} scope={ssh.get('scope')}")
    sndauth = ("未設定 (トークンなしで 200)" if snd["available"] and str(snd.get("terminals_http_status") or "").startswith("200")
               and not snd["token_sent"] else (snd.get("terminals_http_status") or "未確認"))
    L.append(f"- SND API_KEY: {sndauth}")
    d = sec.get("dashboard") or {}
    L.append(f"- WAIO ダッシュボード: bind={d.get('bind')} 認証ファイル={'設定あり' if d.get('auth_file_set') else 'なし'}")
    h = sec["http"]
    if h:
        L.append(f"- HTTP (直近7日): 200={h['counts']['200']} 401={h['counts']['401']} 403={h['counts']['403']} "
                 f"404={h['counts']['404']} other={h['counts']['other']}")
    L.append(f"- 管理者グループ: {', '.join(sec['admins']) or '-'} / アカウント: {', '.join(sorted(sec['users'])) or '-'}")
    L.append("- 待受 (ループバック以外):")
    ex = [l for l in sec["listeners"] if l["scope"] != "localhost"]
    L += [f"  - `{l['key']}` ports={l['ports']} cmd={l['command'] or '? (他ユーザー/root のため不明)'}" for l in ex] or ["  - なし"]
    L.append("")
    L.append("| 重大度 | 区分 | 指摘 | 詳細 |")
    L.append("|---|---|---|---|")
    for x in findings:
        L.append(f"| {x['severity']} | {x['area']} | {md_escape(x['title'])} | {md_escape(x['detail'])[:300]} |")
    if not findings:
        L.append("| - | - | 指摘なし | |")
    L.append("")
    L.append("### システム")
    L.append("")
    mem = sysm["memory"]
    la = sysm["load"]
    L.append(f"- ディスク: " + ", ".join(f"{x['mount']} {x['used_pct']}%" for x in sysm["disks"]))
    L.append(f"- メモリ使用率: {mem.get('used_pct')}% / 負荷: {la.get('load')} (CPU {la.get('ncpu')}) / {md_escape(sysm['uptime'])}")
    L.append(f"- WAIO サービス: " + ", ".join(f"{k.replace('com.waio.', '')}={'run' if v['pid'] else 'exit ' + str(v['status'])}"
                                            for k, v in sorted(sysm["services"].items())))
    L.append(f"- WSR バックアップ最終成功: {sysm['backup'].get('last_ok')} / Time Machine: {md_escape(sysm['time_machine'] or '取得不可')}")
    os_v = sysm["updates"]["os"]
    L.append(f"- OS: {os_v.get('ProductName')} {os_v.get('ProductVersion')} ({os_v.get('BuildVersion')}) / 最終更新: {sysm['updates']['last_install']}")
    L.append("")
    L.append("### WAIO / SND@HOME")
    L.append("")
    L.append(f"- SND: configured={snd['configured']} available={snd['available']} url={snd.get('api_url')} reason={md_escape(snd.get('reason') or '-')}")
    if snd["available"]:
        L.append(f"- SND 台帳: 端末 {snd['terminal_count']} 台 (online {snd['online_count']}) / アクティブアラート {snd['alert_count']}")
    a = snd.get("accuracy")
    if a:
        L.append(f"- LAN Scan 精度 (Mac ARP との突合): 一致 {a['both']} / ARP のみ {len(a['arp_only'])} / SND のみ {len(a['snd_only'])}")
    for name, info in cur["waio"]["monitors"].items():
        L.append(f"- {name}: " + ("出力なし" if info.get("missing") else f"最終出力 {info['age_hours']} 時間前"))
    L.append("")

    L.append("## 5. 未解決リスク")
    L.append("")
    unresolved = [x for x in findings if x["severity"] != "LOW"]
    L += [f"- [{x['severity']}] {md_escape(x['title'])} (初回検出 {str(x['first_seen'])[:10]})" for x in unresolved] or ["- なし"]
    L.append("")

    L.append("## 6. 前週比較")
    L.append("")
    if prev is None:
        L.append("- 前回の監査結果がないため比較なし (今回をベースラインとして保存)。")
    else:
        pc = {s: sum(1 for x in prev.get("findings", []) if x["severity"] == s) for s in SEVERITIES}
        L.append("| 重大度 | 前回 | 今回 | 増減 |")
        L.append("|---|---|---|---|")
        for s in SEVERITIES:
            L.append(f"| {s} | {pc[s]} | {counts[s]} | {counts[s] - pc[s]:+d} |")
        L.append("")
        L.append(f"- 新規発見: {len(new_f)} 件 / 解消: {len(resolved)} 件 / 継続 (未解決): {len(persistent)} 件")
        L.append(f"- 端末: 新規 {len(net['new_devices'])} / 消失 {len(net['disappeared'])} / 現在 {len(net['present_macs'])} "
                 f"(前回 {len(prev['network'].get('present_macs', []))})")
        changed = []
        for mac in net["present_macs"]:
            old = (prev.get("ledger") or {}).get(mac) or {}
            new = cur["ledger"][mac]
            if old.get("last_ips") and new.get("last_ips") and old["last_ips"] != new["last_ips"]:
                changed.append(f"{mac}: {','.join(old['last_ips'])} -> {','.join(new['last_ips'])}")
        L.append(f"- IP 変更: {len(changed)} 件" + ("" if not changed else " -- " + md_escape("; ".join(changed))[:500]))
        ph, ch = (prev["security"].get("http") or {}).get("counts") or {}, (h or {}).get("counts") or {}
        if ph or ch:
            L.append("- HTTP 推移: " + ", ".join(f"{k} {ph.get(k, 0)}->{ch.get(k, 0)}" for k in ("200", "401", "403", "404")))
    L.append("")

    L.append("## 7. 改善提案")
    L.append("")
    props = [x for x in findings if x.get("proposal")]
    L += [f"- [{x['severity']}] {md_escape(x['proposal'])} ({md_escape(x['title'])})" for x in props] or ["- なし"]
    L.append("")

    L.append("## 8. 人間の承認が必要な事項")
    L.append("")
    appr = [x for x in findings if x.get("approval")]
    L += [f"- [ ] [{x['severity']}] {md_escape(x['approval'])} -- {md_escape(x['title'])}" for x in appr] or ["- なし"]
    L.append("")
    L.append("---")
    L.append("このレポートは security/weekly_audit/weekly_audit_cron.sh が自動生成した。監査は読み取り専用で、上記の承認事項はいずれも自動実行されない。")
    L.append("")
    return "\n".join(L), overall, counts


# --- entry point -------------------------------------------------------------


def run(args):
    now = parse_iso(args.now)
    if now is None:
        print("invalid --now", file=sys.stderr)
        return 2
    now = now.astimezone(JST)
    snap_dir = os.path.join(args.audit_dir, "snapshots")
    prev, prev_path = find_previous_snapshot(snap_dir, args.run_id)
    cur, ledger_path = build_current(args.work, args.audit_dir, args.waio_log_dir, args.launch_agents_dir, now, args.run_id)
    if prev:
        cur["network"]["disappeared"] = sorted(set(prev["network"].get("present_macs", [])) - set(cur["network"]["present_macs"]))
    findings = assess(cur, prev, now)
    cur["findings"] = findings
    report, overall, counts = render_report(cur, prev, prev_path, findings, now)

    date = now.strftime("%Y%m%d")
    report_path = os.path.join(args.audit_dir, f"WEEKLY_AUDIT_{date}.md")
    if os.path.exists(report_path):  # never overwrite an earlier report from the same day
        report_path = os.path.join(args.audit_dir, f"WEEKLY_AUDIT_{date}_{now.strftime('%H%M%S')}.md")
    write_private(report_path, report)
    write_private(os.path.join(snap_dir, f"snapshot_{args.run_id}.json"), json.dumps(cur, ensure_ascii=False, indent=1, sort_keys=True))
    write_private(ledger_path, json.dumps(cur["ledger"], ensure_ascii=False, indent=1, sort_keys=True))
    print(json.dumps({"report": report_path, "overall": overall, "counts": counts,
                      "previous": prev_path, "devices_present": len(cur["network"]["present_macs"])}, ensure_ascii=False))
    return 0


def main(argv=None):
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--work", required=True)
    r.add_argument("--audit-dir", required=True)
    r.add_argument("--run-id", required=True)
    r.add_argument("--now", required=True)
    r.add_argument("--waio-log-dir", required=True)
    r.add_argument("--launch-agents-dir", default=os.path.expanduser("~/Library/LaunchAgents"))
    args = p.parse_args(argv)
    return run(args)


if __name__ == "__main__":
    sys.exit(main())
