#!/bin/bash
set -uo pipefail

# dashboard/collect_mail_guard_status.sh -- read-only data collector for
# the WAIO Dashboard's MAIL GUARD panel.
#
# Reads only local state (security/state/mail_guard/: events.jsonl that
# security/mail_guard/mail_guard.sh pull fetched, last_pull.json,
# policy/publish.log.jsonl) and writes logs/mail-guard-status-latest.json.
# Makes NO network call and never calls egress_check/trigger_shutdown.
# Always writes the file: with no data it carries "available": false and a
# reason, so the panel says UNAVAILABLE instead of showing stale numbers.
# Counts, verdicts, indicator names and domains only -- the events never
# contain message text, subjects or addresses.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR" || exit 1
STATE_DIR="${MAILGUARD_STATE_DIR:-$SCRIPT_DIR/security/state/mail_guard}"
OUT="${MAILGUARD_STATUS_OUT:-$SCRIPT_DIR/logs/mail-guard-status-latest.json}"
mkdir -p "$(dirname "$OUT")"
python3 -I "$SCRIPT_DIR/security/mail_guard/mail_guard.py" --state-dir "$STATE_DIR" status --out "$OUT"
