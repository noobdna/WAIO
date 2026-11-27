#!/bin/bash
set -uo pipefail

# security/incident_learning/collectors/mail_guard_collector.sh -- Incident
# Learning Engine Collector for WAIO MAIL GUARD (design v0.1 §1.5).
#
# Same Collector contract as collectors/mock_collector.sh (one RawIncident
# JSON object per line on stdout, diagnostics on stderr), so the existing
# incident_normalizer.sh and everything after it are reused unchanged --
# no new pipeline.
#
# Input: security/state/mail_guard/events.jsonl only, the local copy that
# security/mail_guard/mail_guard.sh pull already fetched and sanitised.
# This Collector makes NO network call, so it needs no egress_check. With
# no events file (MAIL GUARD not configured) it emits nothing and exits 0.
#
# One record per (UTC day, sender domain) among messages the Worker put at
# quarantine or block level, over the last 2 days; ids are stable
# (MAILGUARD-<yyyymmdd>-<sha256(domain)[:12]>), so re-runs are idempotent
# from the normalizer's point of view. Records carry only domains,
# indicator names and counts -- never message hashes or addresses.
# source_type=internal_telemetry scores as 'unknown' in
# incident_confidence.sh: a single-host observation never auto-qualifies.

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
STATE_DIR="${MAILGUARD_STATE_DIR:-$REPO_DIR/security/state/mail_guard}"

[ -f "$STATE_DIR/events.jsonl" ] || exit 0
python3 -I "$REPO_DIR/security/mail_guard/mail_guard.py" --state-dir "$STATE_DIR" incidents --days 2
