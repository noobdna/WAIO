#!/bin/bash
set -uo pipefail

# security/shadow_ai/shadow_ai_monitor.sh -- Shadow AI Monitor: detects
# and inventories unauthorized/unexpected AI usage and AI-agent
# connectivity from LOCAL telemetry only.
#
# Scope (deliberately narrow for this first module, per explicit
# design constraints):
#   - READ-ONLY / observation mode only. This file never modifies a
#     process, a firewall/routing rule, or any Control Plane file
#     (security/egress_allowlist.conf, security/segments.conf, sshd
#     config, etc.) -- it has no write path to any of them at all, not
#     even a --force one. It does not source security/lib.sh and does
#     not call egress_check()/trigger_shutdown()/audit_log() -- unlike
#     security/incident_learning/collectors/cisa_kev_collector.sh and
#     ghsa_collector.sh, this module makes NO outbound network call of
#     its own (no DNS resolution either -- see shadow_ai_lib.py's own
#     header on why a "domain" signature only ever matches a process's
#     own argument text, never a live connection's resolved remote
#     name). It only reads: `ps` (running processes), `lsof -i -P -n`
#     (existing local socket state the OS already has), and this
#     module's own two small config files.
#   - NOT wired into DuCoPA/Guardian/any containment action. This is
#     intentional and explicit, matching the requested integration
#     shape:
#         Shadow AI Monitor -> WAIO Intelligence/Evidence Layer
#                            -> WAIO Decision Engine -> DuCoPA
#                            -> Contain/Recover
#     This file is ONLY the first box. It produces evidence (JSONL on
#     stdout, one finding per line, same "stdout is the evidence
#     stream, diagnostics go to stderr" Collector contract
#     security/incident_learning/collectors/mock_collector.sh's own
#     header already establishes for a different domain) and a
#     lightweight local inventory
#     (security/state/shadow_ai/inventory.json). Nothing here ever
#     calls guardian.sh/ducopa.sh/recovery_engine.sh, and nothing here
#     decides anything -- nothing is promoted, quarantined, or acted
#     on automatically. A later "WAIO Intelligence/Evidence Layer"/
#     "Decision Engine" module is the intended consumer of this
#     module's JSONL output; wiring that up is explicitly out of scope
#     here (see "Integration point for a future module" below).
#   - No secrets/PII collected: every process command-line string this
#     module ever touches goes through shadow_ai_lib.py's own
#     redact_args() before it can reach a finding, the inventory, or
#     stdout -- see that function's own header for the exact patterns
#     redacted (a named, auditable list, not a black box).
#
# Detection signals (three independent scans, each also runnable on its
# own -- see the CLI dispatch at the bottom):
#   1. scan-processes: a running process (`ps`) whose command name or
#      (already-redacted) arguments match a known AI-related signature
#      in shadow_ai_signatures.conf ("unknown AI services" / "unknown
#      AI APIs" via a domain reference in its own args).
#   2. scan-connections: an existing local socket (`lsof -i -P -n`,
#      LISTEN or ESTABLISHED) whose LOCAL port matches a known AI
#      service port signature ("unexpected AI-agent processes" exposing
#      a local API). Known, accepted limitation (confirmed live during
#      development, not hypothetical): a port number alone cannot prove
#      what's actually listening on it -- WAIO's own
#      dashboard/index.html dev server (`python3 -m http.server 8000`)
#      was flagged this way purely because 8000 is also a common local
#      LLM server default. classify_confidence()'s own "HIGH" for an
#      exact port match means "confidently matched THIS SIGNATURE
#      PATTERN," never "confidently proven to be AI" -- a human
#      reviewing a listening_port finding still has to look at which
#      process actually owns it (already included in the finding's own
#      `process` field) before treating it as real Shadow AI. Adding
#      this deployment's own known non-AI services on a colliding port
#      to known_ai_allowlist.conf (TYPE=port) reclassifies them at LOW
#      going forward.
#   3. scan-agents: cross-references (1) and (2) to find TWO different
#      locally-running AI-signature-matched processes with an
#      established LOOPBACK connection between them ("suspicious
#      AI-to-AI or agent-to-agent connections") -- see
#      shadow_ai_lib.py's find_agent_links() for exactly how.
# `scan` (the default) runs all three together against one single
# ps/lsof snapshot, so scan-agents' own cross-reference sees the exact
# same process/socket state scan-processes and scan-connections just
# reported on, not a second, possibly-inconsistent later snapshot.
#
# Every finding carries its own risk (LOW/MEDIUM/HIGH/CRITICAL) and
# confidence (LOW/MEDIUM/HIGH) field, computed by shadow_ai_lib.py's
# own classify_risk()/classify_confidence() -- deliberately simple,
# fully auditable rules stated in that file's own header, never a
# black-box score (same posture as
# security/incident_learning/incident_confidence.sh's own formula).
# Matching security/shadow_ai/known_ai_allowlist.conf (this
# deployment's own reviewed/approved AI usage -- see that file's own
# .example template) always classifies a finding at LOW risk
# regardless of its base signature risk.
#
# Integration point for a future module (explicitly left open, not
# built here): this module's own stable per-finding "id"
# (shadow_ai_lib.stable_identity(), derived from finding_type +
# signature + a disambiguator, e.g. a process name or "clientproc->
# listenerproc:port" -- NEVER from a pid or a timestamp, both of which
# change every scan) is designed to double as a graph NODE/EDGE key: an
# "agent_to_agent" finding's own process/network fields already carry
# both endpoints (client process identity + listener pid/command/port),
# which is exactly the edge data a future "AI Agent Attack Graph"
# module would need to build a graph of which local AI processes talk
# to which. That graph-building logic does not exist yet and is
# intentionally not started here -- this module's only commitment to it
# is a stable id scheme and complete edge data in every agent_to_agent
# finding.
#
# Independently testable: every path below (signatures file, allowlist
# file, state dir, audit log) is overridable via env var, same
# convention as every other domain in this repo
# (KNOWLEDGE_MANAGER_STATE_DIR, SEGMENT_MANAGER_CONF, etc.), and `ps`/
# `lsof` are called by bare name (never an absolute path), so
# tests/shadow_ai_monitor_test.sh can shadow both on PATH with fixed,
# deterministic fixture output -- same "shadow a binary on PATH" idiom
# security/incident_learning/collectors/cisa_kev_collector.sh's own test
# suite already uses for `curl`.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$SCRIPT_DIR"

SIGNATURES_FILE="${SHADOW_AI_SIGNATURES_FILE:-$SCRIPT_DIR/security/shadow_ai/shadow_ai_signatures.conf}"
ALLOWLIST_FILE="${SHADOW_AI_ALLOWLIST_FILE:-$SCRIPT_DIR/security/shadow_ai/known_ai_allowlist.conf}"
STATE_DIR="${SHADOW_AI_STATE_DIR:-$SCRIPT_DIR/security/state/shadow_ai}"
AUDIT_LOG="${SHADOW_AI_AUDIT_LOG:-$SCRIPT_DIR/logs/shadow-ai-audit.jsonl}"
INVENTORY_FILE="$STATE_DIR/inventory.json"

mkdir -p "$STATE_DIR" "$(dirname "$AUDIT_LOG")" 2>/dev/null || true

# audit_scan_log MODE SUMMARY -- appends one JSON line recording that a
# scan ran and what it found (counts only, never finding-level detail --
# the JSONL findings themselves, plus the inventory, are the detailed
# record). Same append-only JSONL convention as every other domain's
# own audit log in this repo, kept as its own small function/file
# rather than reusing security/lib.sh's audit_log() -- this module
# deliberately never sources security/lib.sh at all (see this file's
# own header on why).
audit_scan_log() {
  local mode="$1" summary="$2"
  python3 -c "
import json, sys
print(json.dumps({
    'timestamp': sys.argv[1],
    'mode': sys.argv[2],
    'summary': sys.argv[3],
}, ensure_ascii=False))
" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$mode" "$summary" >> "$AUDIT_LOG"
}

# run_scan MODE -- MODE is one of processes|connections|agents|all.
# Runs exactly the ps/lsof calls that mode needs (never both when only
# one is required), hands the raw text to shadow_ai_lib.py for parsing/
# matching/classification, prints JSONL findings to stdout, updates the
# inventory, and logs a one-line summary to the audit log.
run_scan() {
  local mode="$1"
  local ps_tmp lsof_tmp
  ps_tmp="$(mktemp)"
  lsof_tmp="$(mktemp)"
  trap 'rm -f "$ps_tmp" "$lsof_tmp"' RETURN

  case "$mode" in
    processes|agents|all)
      ps -axo pid=,ppid=,user=,comm=,args= > "$ps_tmp" 2>/dev/null || true
      ;;
  esac
  case "$mode" in
    connections|agents|all)
      lsof -i -P -n > "$lsof_tmp" 2>/dev/null || true
      ;;
  esac

  local stderr_tmp
  stderr_tmp="$(mktemp)"
  python3 - "$mode" "$SIGNATURES_FILE" "$ALLOWLIST_FILE" "$INVENTORY_FILE" "$ps_tmp" "$lsof_tmp" 2>"$stderr_tmp" <<'PYEOF'
import datetime, json, os, sys

mode, sig_path, allow_path, inv_path, ps_path, lsof_path = sys.argv[1:7]

sys.path.insert(0, os.path.join(os.getcwd(), "security", "shadow_ai"))
import shadow_ai_lib as sal

now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

signatures = sal.load_signatures(sig_path)
allowlist = sal.load_allowlist(allow_path)

ps_records = []
if os.path.exists(ps_path):
    with open(ps_path) as f:
        for line in f:
            rec = sal.parse_ps_line(line.rstrip("\n"))
            if rec:
                ps_records.append(rec)

lsof_records = []
if os.path.exists(lsof_path):
    with open(lsof_path) as f:
        lines = f.readlines()
    for line in lines:
        line = line.rstrip("\n")
        if line.startswith("COMMAND"):
            continue
        rec = sal.parse_lsof_line(line)
        if rec:
            lsof_records.append(rec)

findings = []

if mode in ("all", "processes", "agents"):
    for rec in ps_records:
        proc_ctx = {
            "pid": rec["pid"], "ppid": rec["ppid"],
            "user": rec["user"], "comm": rec["comm"], "args": rec["args"],
        }
        for sig, match_kind in sal.match_process_signatures(rec["comm"], rec["args"], signatures):
            allowed = sal.is_allowlisted(allowlist, "process", sig["pattern"])
            findings.append(sal.build_finding(
                "process", sig, match_kind, allowed, now,
                reason=(
                    f"process '{rec['comm']}' (pid {rec['pid']}) matched AI signature "
                    f"'{sig['pattern']}' ({sig['label']})"
                ),
                process=proc_ctx, network=None, identity_extra=rec["comm"],
            ))
        for sig in sal.match_domain_in_text(rec["args"], signatures):
            allowed = sal.is_allowlisted(allowlist, "domain", sig["pattern"])
            findings.append(sal.build_finding(
                "process", sig, "domain_in_args", allowed, now,
                reason=(
                    f"process '{rec['comm']}' (pid {rec['pid']}) references known AI domain "
                    f"'{sig['pattern']}' in its own arguments ({sig['label']})"
                ),
                process=proc_ctx, network=None, identity_extra=rec["comm"],
            ))

if mode in ("all", "connections", "agents"):
    ps_by_pid = {r["pid"]: r for r in ps_records}
    for lr in lsof_records:
        # LISTEN: the port THIS process exposes is the local_port --
        # that's what a caller would connect to. ESTABLISHED: this
        # process is the CLIENT of whatever it's connected to, so the
        # meaningful port to check is the REMOTE port (the service it's
        # talking to), never its own ephemeral local_port.
        check_port = lr["local_port"] if lr["state"] == "LISTEN" else lr["remote_port"]
        port_sig = sal.match_port_signature(check_port, signatures)
        if not port_sig:
            continue
        finding_type = "listening_port" if lr["state"] == "LISTEN" else "outbound_connection"
        allowed = sal.is_allowlisted(allowlist, "port", port_sig["pattern"])
        ps_ctx = ps_by_pid.get(lr["pid"])
        process_ctx = None
        if ps_ctx:
            process_ctx = {
                "pid": ps_ctx["pid"], "ppid": ps_ctx["ppid"],
                "user": ps_ctx["user"], "comm": ps_ctx["comm"], "args": ps_ctx["args"],
            }
        network_ctx = {
            "local_host": lr["local_host"], "local_port": lr["local_port"],
            "remote_host": lr["remote_host"], "remote_port": lr["remote_port"],
            "state": lr["state"],
        }
        if lr["state"] == "LISTEN":
            reason = (
                f"{lr['command']} (pid {lr['pid']}) is LISTENING on port {lr['local_port']}, "
                f"matching AI signature ({port_sig['label']})"
            )
        else:
            reason = (
                f"{lr['command']} (pid {lr['pid']}) has an ESTABLISHED connection to remote "
                f"port {lr['remote_port']}, matching AI signature ({port_sig['label']})"
            )
        findings.append(sal.build_finding(
            finding_type, port_sig, "exact_port", allowed, now,
            reason=reason, process=process_ctx, network=network_ctx,
            identity_extra=f"{lr['command']}:{check_port}",
        ))

if mode in ("all", "agents"):
    for client_rec, client_sig, listener_pid, listener_command, port in sal.find_agent_links(
        ps_records, lsof_records, signatures
    ):
        allowed = sal.is_allowlisted(allowlist, "process", client_sig["pattern"])
        reason = (
            f"AI-flagged process '{client_rec['comm']}' (pid {client_rec['pid']}) has an "
            f"established loopback connection to port {port}, which AI-flagged process "
            f"'{listener_command}' (pid {listener_pid}) is listening on -- possible "
            f"agent-to-agent link"
        )
        findings.append(sal.build_finding(
            "agent_to_agent", client_sig, "process_name", allowed, now,
            reason=reason,
            process={
                "pid": client_rec["pid"], "ppid": client_rec["ppid"],
                "user": client_rec["user"], "comm": client_rec["comm"], "args": client_rec["args"],
            },
            network={
                "local_port": None, "remote_host": "127.0.0.1", "remote_port": port,
                "listener_pid": listener_pid, "listener_command": listener_command,
            },
            identity_extra=f"{client_rec['comm']}->{listener_command}:{port}",
        ))

for f in findings:
    print(json.dumps(f, ensure_ascii=False))

existing = {}
if os.path.exists(inv_path):
    try:
        with open(inv_path) as f:
            existing = json.load(f)
    except Exception:
        existing = {}
merged = sal.merge_inventory(existing, findings, now)
tmp_path = f"{inv_path}.tmp.{os.getpid()}"
with open(tmp_path, "w") as f:
    json.dump(merged, f, ensure_ascii=False, indent=2, sort_keys=True)
os.replace(tmp_path, inv_path)

risk_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
for f in findings:
    risk_counts[f["risk"]] = risk_counts.get(f["risk"], 0) + 1
print(
    f"ps_processes={len(ps_records)} lsof_sockets={len(lsof_records)} "
    f"findings={len(findings)} risk={risk_counts}",
    file=sys.stderr,
)
PYEOF
  local rc=$?
  local summary
  summary="$(cat "$stderr_tmp")"
  rm -f "$stderr_tmp"
  if [ -n "$summary" ]; then
    echo "[SHADOW AI] $summary" >&2
  fi
  audit_scan_log "$mode" "$summary"
  return "$rc"
}

# print_inventory -- read-only dump of the current inventory snapshot.
print_inventory() {
  if [ ! -f "$INVENTORY_FILE" ]; then
    echo "{}"
    return 0
  fi
  cat "$INVENTORY_FILE"
}

# print_status -- short human-readable summary of the current inventory
# (counts by last-known risk). Read-only.
print_status() {
  python3 -c "
import json, sys
path = sys.argv[1]
try:
    with open(path) as f:
        inv = json.load(f)
except Exception:
    inv = {}
counts = {'LOW': 0, 'MEDIUM': 0, 'HIGH': 0, 'CRITICAL': 0}
for entry in inv.values():
    counts[entry.get('last_risk', 'LOW')] = counts.get(entry.get('last_risk', 'LOW'), 0) + 1
print(f'Shadow AI inventory: {len(inv)} known entr' + ('y' if len(inv) == 1 else 'ies'))
for risk in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW'):
    print(f'  {risk}: {counts[risk]}')
" "$INVENTORY_FILE"
}

if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
  case "${1:-scan}" in
    scan)
      run_scan all
      ;;
    scan-processes)
      run_scan processes
      ;;
    scan-connections)
      run_scan connections
      ;;
    scan-agents)
      run_scan agents
      ;;
    inventory)
      print_inventory
      ;;
    status)
      print_status
      ;;
    *)
      echo "Usage: $0 {scan|scan-processes|scan-connections|scan-agents|inventory|status}" >&2
      exit 1
      ;;
  esac
fi
