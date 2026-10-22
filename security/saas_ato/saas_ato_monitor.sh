#!/bin/bash
set -uo pipefail

# security/saas_ato/saas_ato_monitor.sh -- WAIO SaaS Account Takeover
# (ATO) Monitor: reads RawSignal JSONL (a Collector's own stdout --
# see security/saas_ato/collectors/mock_m365_collector.sh's own header
# for the shape contract), classifies each signal's risk/confidence via
# security/saas_ato/saas_ato_lib.py, groups by account, correlates
# against the previous scan's own persisted state, and emits one
# `saas_ato` finding event per account. Same fourth-producer position
# in the pipeline as every other Phase 90-94 module:
#
#     Shadow AI Monitor  -\
#     Attack Graph         -> WAIO Intelligence/Evidence Layer -> WAIO Decision Engine -> DuCoPA -> Contain/Recover
#     Incident Learning   -/
#     SaaS ATO Monitor    -/
#
# ============================================================
# CRITICAL SAFETY BOUNDARY -- read before touching this file
# ============================================================
# This file DETECTS, IT NEVER CONTAINS. It:
#   - never sources security/lib.sh and never calls
#     egress_check()/audit_log()/trigger_shutdown() (same posture as
#     Phase 90/91/92/93's own modules).
#   - never calls security/guardian.sh, security/ducopa.sh,
#     security/recover.sh, security/recovery_engine.sh,
#     security/incident_learning/knowledge_manager.sh, or
#     security/incident_human_gate.sh.
#   - makes NO network call and holds NO credential/API key/Keychain
#     entry anywhere -- every "signal" this file's own `scan` command
#     reads is RawSignal JSONL handed to it as a file argument or via
#     stdin, exactly like security/decision_engine/decision_engine.sh's
#     own `decide [FILE|-]`. A REAL Microsoft 365 Graph API / Google
#     Workspace Admin SDK Collector that actually calls those services
#     (with its own credential storage, its own egress_allowlist.conf
#     entry, its own egress_check() call before any request) is a
#     separate, later, deliberately out-of-scope task -- same P1
#     boundary already drawn for SND@HOME/Takomachi's own real-
#     environment connection work. security/saas_ato/collectors/*.sh
#     in this phase are mock collectors only: fixed, entirely
#     fictional signals, same posture as
#     security/incident_learning/collectors/mock_collector.sh.
#   - writes to nothing outside its own security/state/saas_ato/ state
#     dir and its own logs/saas-ato-audit.jsonl audit log.
# A CRITICAL-risk finding from this file is a human reading it (via
# the WAIO Intelligence Layer -> Decision Engine pipeline this file's
# own output feeds into) and THEN, separately, by hand, deciding
# whether to act against the real M365/Google Workspace tenant. See
# security/decision_engine/decision_engine_lib.py's own header for the
# exact same boundary already drawn one stage downstream; see
# tests/saas_ato_monitor_test.sh's own D-series for the static guards
# that keep this true in code, not just in this comment.
#
# Independently testable: state dir and audit log are both overridable
# via env var, same convention as every other domain in this repo; the
# CLI reads RawSignal JSONL from stdin/a file argument, so
# tests/saas_ato_monitor_test.sh needs no real M365/Google Workspace
# connection at all -- just a fixed RawSignal JSONL fixture.
#
# Real intended usage (illustrative -- see
# security/intelligence/intelligence_layer.sh's own header for why
# chaining multi-stage pipelines in this repo means writing each
# stage's output to a file first):
#     security/saas_ato/collectors/mock_m365_collector.sh \
#       | security/saas_ato/saas_ato_monitor.sh scan - \
#       > /tmp/saas_ato_findings.jsonl
#     security/intelligence/intelligence_layer.sh ingest \
#       --saas-ato /tmp/saas_ato_findings.jsonl

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$SCRIPT_DIR"

STATE_DIR="${SAAS_ATO_STATE_DIR:-$SCRIPT_DIR/security/state/saas_ato}"
AUDIT_LOG="${SAAS_ATO_AUDIT_LOG:-$SCRIPT_DIR/logs/saas-ato-audit.jsonl}"
STATE_FILE="$STATE_DIR/state.json"

mkdir -p "$STATE_DIR" "$(dirname "$AUDIT_LOG")" 2>/dev/null || true

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

# scan [FILE|-] -- reads RawSignal JSONL (default stdin), classifies +
# groups + correlates, emits one `saas_ato` finding event per account
# (JSONL) to stdout, persists the updated per-account correlation
# state, logs a one-line summary. NEVER calls anything beyond this
# file's own state dir -- see this file's own header.
scan() {
  local input="${1:--}"
  local src
  if [ "$input" = "-" ]; then
    src="$(mktemp)"
    cat > "$src"
  else
    src="$input"
  fi

  local stderr_tmp
  stderr_tmp="$(mktemp)"
  python3 - "$src" "$STATE_FILE" 2>"$stderr_tmp" <<'PYEOF'
import datetime, json, os, sys

src_path, state_path = sys.argv[1], sys.argv[2]

sys.path.insert(0, os.path.join(os.getcwd(), "security", "saas_ato"))
import saas_ato_lib as sal

signals = []
with open(src_path) as f:
    for line in f:
        parsed = sal.parse_signal_line(line)
        if parsed is not None:
            signals.append(parsed)

now_iso = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

try:
    with open(state_path) as f:
        prev_state = json.load(f)
except Exception:
    prev_state = {}
prev_accounts = prev_state.get("accounts") or {}

by_account = sal.group_by_account(signals)

events = []
new_accounts_state = {}
for account, acct_signals in by_account.items():
    classified = []
    for s in acct_signals:
        risk, confidence, basis = sal.classify_signal(s)
        classified.append(dict(s, risk=risk, confidence=confidence, basis=basis))

    signal_types_this_cycle = {s["signal_type"] for s in classified}
    prev_account_state = prev_accounts.get(account)
    correlation, new_account_state = sal.compute_correlation(
        prev_account_state, now_iso, signal_types_this_cycle
    )

    tenant = classified[0].get("tenant") if classified else None
    event = sal.build_event(account, tenant, now_iso, classified, correlation)
    events.append(event)
    new_accounts_state[account] = new_account_state

# Merge, never replace: an account not mentioned in THIS cycle's
# input (e.g. a different Collector run, or simply a quiet cycle for
# that account) must keep its own previously-persisted correlation
# state, not be silently evicted -- state.json accumulates knowledge
# about every account ever seen, same "state reflects what's known,
# never shrinks just because this particular scan didn't mention it"
# posture every other state file in this repo already has.
merged_accounts = dict(prev_accounts)
merged_accounts.update(new_accounts_state)
new_state = {"accounts": merged_accounts, "last_scan_at": now_iso}
tmp_path = f"{state_path}.tmp.{os.getpid()}"
with open(tmp_path, "w") as f:
    json.dump(new_state, f, ensure_ascii=False, indent=2, sort_keys=True)
os.replace(tmp_path, state_path)

for e in events:
    print(json.dumps(e, ensure_ascii=False))

risk_counts = {}
for e in events:
    risk_counts[e["risk"]] = risk_counts.get(e["risk"], 0) + 1
candidate_incidents = sorted(e["account"] for e in events if e["correlation"]["candidate_incident"])
print(
    f"accounts_scanned={len(events)} risk_counts={risk_counts} "
    f"candidate_incidents={candidate_incidents}",
    file=sys.stderr,
)
PYEOF
  local rc=$?

  if [ "$input" = "-" ]; then
    rm -f "$src"
  fi

  local summary
  summary="$(cat "$stderr_tmp")"
  rm -f "$stderr_tmp"
  if [ -n "$summary" ]; then
    echo "[SAAS ATO MONITOR] $summary" >&2
  fi
  audit_scan_log "$summary"
  return "$rc"
}

# status -- read-only summary of the last persisted state (never
# triggers a new scan). Absent/corrupt state file is reported as "no
# scan yet", never an error -- a brand-new deployment that has never
# run `scan` is an expected, valid state.
print_status() {
  python3 -c "
import json, sys
path = sys.argv[1]
try:
    with open(path) as f:
        d = json.load(f)
except Exception:
    print('SaaS ATO Monitor: no scan has been run yet')
    sys.exit(0)
accounts = d.get('accounts') or {}
print(f\"SaaS ATO Monitor (last scan: {d.get('last_scan_at', '?')}):\")
print(f\"  accounts with recorded state: {len(accounts)}\")
for account, state in sorted(accounts.items()):
    types = sorted((state.get('signal_types') or {}).keys())
    print(f\"    {account}: signal_types={types}\")
" "$STATE_FILE"
}

if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
  case "${1:-scan}" in
    scan)
      scan "${2:--}"
      ;;
    status)
      print_status
      ;;
    *)
      echo "Usage: $0 {scan [FILE|-]|status}" >&2
      exit 1
      ;;
  esac
fi
