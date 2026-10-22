#!/bin/bash
set -uo pipefail

# security/ssh_exposure/ssh_exposure_monitor.sh -- SSH Exposure Monitor:
# detects whether SSH has become unintentionally exposed on this host,
# from LOCAL, READ-ONLY telemetry only.
#
# Scope (deliberately narrow, matching the explicit request this module
# implements -- see ARCHITECTURE.md's Phase entry for the full design
# note):
#   - READ-ONLY / observation mode only. This file never modifies
#     sshd's configuration, restarts/stops/starts sshd, changes a
#     firewall rule, opens a port, or runs anything as root. It never
#     calls `sudo` (grep-guarded by this suite's own D-series tests). It
#     makes NO outbound network connection of its own (no connectivity
#     test against this host's own exposed port, no reverse-DNS, no
#     scan of anything) -- "is SSH exposed" is answered entirely from
#     this host's own process table (`ps`), socket table (`lsof -i -P
#     -n`), its own sshd_config file, and a small OS adapter's
#     already-local firewall-state/interface-address query (see
#     adapters/firewall_macos.sh / adapters/firewall_linux.sh /
#     adapters/firewall_unknown.sh -- the ONLY OS-specific code in this
#     module, deliberately isolated there per the request's own "OS依存
#     部分はadapterとして分離する" requirement).
#   - NOT wired into DuCoPA/Guardian/any containment action, and not
#     wired into security/incident_learning/ either, matching this
#     repo's existing "detection/evidence module first, integration
#     later, explicitly" precedent (security/shadow_ai/shadow_ai_monitor.sh,
#     security/attack_graph/attack_graph.sh). This file ONLY produces
#     one structured `ssh_exposure` JSON event per scan on stdout and a
#     small persisted state snapshot
#     (security/state/ssh_exposure/state.json, used solely for this
#     module's own across-scan change correlation -- see
#     ssh_exposure_lib.py's compute_correlation()). Nothing here ever
#     calls guardian.sh/ducopa.sh/recovery_engine.sh, and nothing here
#     decides or acts on anything.
#
# Detection flow (one `scan`, every step read-only):
#   1. `ps -axo pid=,ppid=,comm=` (bare name, shadow-able on PATH, same
#      idiom as shadow_ai_monitor.sh's own `ps` call) -> is there a
#      resident `sshd` process.
#   2. `lsof -i -P -n` (bare name, shadow-able) -> every LISTEN socket;
#      ssh_exposure_lib.find_ssh_listeners() keeps only the ones owned
#      by `sshd` itself (ANY port -- never hardcoded to 22) or by a
#      socket-activation wrapper (`launchd`/`systemd`) on one of the
#      PORTS THIS HOST'S OWN sshd_config ACTUALLY DECLARES (falling
#      back to 22 only as the documented SSH protocol default when no
#      `Port` line exists -- still not a hardcoded assumption about
#      THIS host).
#   3. `sshd_config` (path overridable via SSH_EXPOSURE_SSHD_CONFIG,
#      default /etc/ssh/sshd_config) -- read-only, Include-aware
#      (ssh_exposure_lib.collect_config_entries()) -- PasswordAuthentication/
#      PermitRootLogin/PubkeyAuthentication/Port captured structured.
#      A permission-denied or missing file degrades to
#      config.source="unavailable" (never an error, never sudo).
#   4. OS firewall/interface adapter (dispatched by `uname -s`,
#      overridable via SSH_EXPOSURE_FIREWALL_ADAPTER for tests) -- a
#      read-only firewall-enabled/disabled/unknown state plus this
#      host's own locally-bound interface addresses (used only to tell
#      apart "0.0.0.0 bind on a NAT'd home LAN host" from "0.0.0.0 bind
#      on a host that also has a public IP of its own" -- see
#      ssh_exposure_lib.overall_exposure()'s own header).
#   5. ssh_exposure_lib.py combines all of the above into one
#      `ssh_exposure` event (severity/ssh/firewall/exposure/evidence/
#      correlation), printed as one JSON object on stdout, and updates
#      the persisted state snapshot used for next scan's correlation.
#
# Independently testable: every path (sshd_config, state dir, audit
# log, firewall adapter) is overridable via env var, same convention as
# every other domain in this repo (SHADOW_AI_STATE_DIR,
# KNOWLEDGE_MANAGER_STATE_DIR, etc.), and `ps`/`lsof`/`hostname` are
# called by bare name (never an absolute path), so
# tests/ssh_exposure_monitor_test.sh can shadow all three on PATH with
# fixed, deterministic fixture output -- same "shadow a binary on PATH"
# idiom shadow_ai_monitor.sh's own test suite already uses.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$SCRIPT_DIR"

SSHD_CONFIG="${SSH_EXPOSURE_SSHD_CONFIG:-/etc/ssh/sshd_config}"
STATE_DIR="${SSH_EXPOSURE_STATE_DIR:-$SCRIPT_DIR/security/state/ssh_exposure}"
AUDIT_LOG="${SSH_EXPOSURE_AUDIT_LOG:-$SCRIPT_DIR/logs/ssh-exposure-audit.jsonl}"
STATE_FILE="$STATE_DIR/state.json"
CORRELATION_WINDOW_SECONDS="${SSH_EXPOSURE_CORRELATION_WINDOW_SECONDS:-300}"

mkdir -p "$STATE_DIR" "$(dirname "$AUDIT_LOG")" 2>/dev/null || true

# pick_firewall_adapter -- the ONLY place this module's shell wrapper
# branches on OS. An explicit SSH_EXPOSURE_FIREWALL_ADAPTER override (a
# path to any executable emitting this module's adapter output
# contract -- see adapters/firewall_macos.sh's own header) always wins,
# letting tests supply a deterministic fixture adapter without ever
# touching this host's own real firewall tool.
pick_firewall_adapter() {
  if [ -n "${SSH_EXPOSURE_FIREWALL_ADAPTER:-}" ]; then
    echo "$SSH_EXPOSURE_FIREWALL_ADAPTER"
    return
  fi
  case "$(uname -s)" in
    Darwin) echo "$SCRIPT_DIR/security/ssh_exposure/adapters/firewall_macos.sh" ;;
    Linux) echo "$SCRIPT_DIR/security/ssh_exposure/adapters/firewall_linux.sh" ;;
    *) echo "$SCRIPT_DIR/security/ssh_exposure/adapters/firewall_unknown.sh" ;;
  esac
}

# audit_scan_log SUMMARY -- appends one JSON line recording that a scan
# ran and its top-line verdict (event_type/severity/exposure scope
# only, never the full event) -- same append-only JSONL convention as
# every other domain's own audit log in this repo
# (security/shadow_ai/shadow_ai_monitor.sh's own audit_scan_log(), kept
# as its own small function here rather than security/lib.sh's
# audit_log() for the same reason shadow_ai_monitor.sh gives: this
# module never sources security/lib.sh and has no gating authority to
# exercise.
audit_scan_log() {
  local summary="$1"
  python3 -c "
import json, sys
print(json.dumps({
    'timestamp': sys.argv[1],
    'summary': sys.argv[2],
}, ensure_ascii=False))
" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$summary" >> "$AUDIT_LOG"
}

# run_scan -- the one `scan` entry point. Gathers every read-only input
# listed in this file's own header, hands the raw text to
# ssh_exposure_lib.py, prints exactly one `ssh_exposure` JSON event on
# stdout, persists the updated correlation state, and logs a one-line
# summary to the audit log.
run_scan() {
  local ps_tmp lsof_tmp adapter_tmp adapter_path host
  ps_tmp="$(mktemp)"
  lsof_tmp="$(mktemp)"
  adapter_tmp="$(mktemp)"
  trap 'rm -f "$ps_tmp" "$lsof_tmp" "$adapter_tmp"' RETURN

  ps -axo pid=,ppid=,comm= > "$ps_tmp" 2>/dev/null || true
  lsof -i -P -n > "$lsof_tmp" 2>/dev/null || true

  adapter_path="$(pick_firewall_adapter)"
  if [ -x "$adapter_path" ]; then
    "$adapter_path" > "$adapter_tmp" 2>/dev/null || true
  fi

  host="$(hostname 2>/dev/null || echo unknown-host)"

  local stderr_tmp
  stderr_tmp="$(mktemp)"
  python3 - "$SSHD_CONFIG" "$STATE_FILE" "$ps_tmp" "$lsof_tmp" "$adapter_tmp" "$host" "$CORRELATION_WINDOW_SECONDS" \
    2>"$stderr_tmp" <<'PYEOF'
import datetime, json, os, sys

sshd_config_path, state_path, ps_path, lsof_path, adapter_path, host, window_s = sys.argv[1:8]
window_s = int(window_s)

sys.path.insert(0, os.path.join(os.getcwd(), "security", "ssh_exposure"))
import ssh_exposure_lib as sel

now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

config = sel.parse_sshd_config(sshd_config_path)

ps_records = []
if os.path.exists(ps_path):
    with open(ps_path) as f:
        for line in f:
            rec = sel.parse_ps_line(line.rstrip("\n"))
            if rec:
                ps_records.append(rec)

lsof_listen = []
if os.path.exists(lsof_path):
    with open(lsof_path) as f:
        lines = f.readlines()
    for line in lines:
        line = line.rstrip("\n")
        if line.startswith("COMMAND"):
            continue
        rec = sel.parse_lsof_listen_line(line)
        if rec:
            lsof_listen.append(rec)

sshd_active = any(sel.is_sshd_process(r["comm"]) for r in ps_records)

ssh_listen_records = sel.find_ssh_listeners(lsof_listen, config["port"])
listeners = []
for rec in ssh_listen_records:
    scope, family = sel.classify_listener_scope(rec["local_host"])
    listeners.append({
        "local_host": rec["local_host"],
        "local_port": rec["local_port"],
        "command": rec["command"],
        "via": rec["via"],
        "scope": scope,
        "family": family,
    })
# A listener via a real sshd process (or a socket-activation wrapper
# already proven to be sshd's own by matching a configured port) is
# itself proof sshd is effectively active/reachable, even if `ps`
# found no resident process yet (macOS on-demand launchd activation).
if listeners:
    sshd_active = True

adapter_text = ""
if os.path.exists(adapter_path):
    with open(adapter_path) as f:
        adapter_text = f.read()
firewall, iface_addrs = sel.parse_adapter_output(adapter_text)

prev_state = None
if os.path.exists(state_path):
    try:
        with open(state_path) as f:
            prev_state = json.load(f)
    except Exception:
        prev_state = None

config_hash = sel.config_fingerprint(config)
listener_keys = [sel.listener_key(l) for l in listeners]
correlation, new_state = sel.compute_correlation(
    prev_state, now, sshd_active, config_hash, listener_keys, window_seconds=window_s,
)

event = sel.build_event(host, now, sshd_active, listeners, config, firewall, iface_addrs, correlation)
print(json.dumps(event, ensure_ascii=False))

tmp_path = f"{state_path}.tmp.{os.getpid()}"
with open(tmp_path, "w") as f:
    json.dump(new_state, f, ensure_ascii=False, indent=2, sort_keys=True)
os.replace(tmp_path, state_path)

print(
    f"sshd_active={sshd_active} listeners={len(listeners)} "
    f"severity={event['severity']} exposure={event['exposure']['scope']} "
    f"candidate_incident={correlation['candidate_incident']}",
    file=sys.stderr,
)
PYEOF
  local rc=$?
  local summary
  summary="$(cat "$stderr_tmp")"
  rm -f "$stderr_tmp"
  if [ -n "$summary" ]; then
    echo "[SSH EXPOSURE] $summary" >&2
  fi
  audit_scan_log "$summary"
  return "$rc"
}

# print_state -- read-only dump of the current persisted correlation
# state snapshot.
print_state() {
  if [ ! -f "$STATE_FILE" ]; then
    echo "{}"
    return 0
  fi
  cat "$STATE_FILE"
}

# print_config -- read-only dump of just the parsed sshd_config, for a
# human to sanity-check what this module actually read, independent of
# running a full scan.
print_config() {
  python3 -c "
import json, os, sys
sys.path.insert(0, os.path.join(os.getcwd(), 'security', 'ssh_exposure'))
import ssh_exposure_lib as sel
print(json.dumps(sel.parse_sshd_config(sys.argv[1]), ensure_ascii=False, indent=2, sort_keys=True))
" "$SSHD_CONFIG"
}

if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
  case "${1:-scan}" in
    scan)
      run_scan
      ;;
    state)
      print_state
      ;;
    config)
      print_config
      ;;
    *)
      echo "Usage: $0 {scan|state|config}" >&2
      exit 1
      ;;
  esac
fi
