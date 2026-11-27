#!/bin/bash
set -uo pipefail

# tests/mail_guard_test.sh -- WAIO MAIL GUARD (P2) suite.
#
#   1. Python unit tests (tests/mail_guard/test_mail_guard.py): event
#      sanitising, SigV4 (AWS reference vectors), R2 pull against a
#      127.0.0.1 stub, summaries, RawIncident records, policy build /
#      validate / diff, BOZE-signed publish against a fake KV (throwaway keys)
#   2. security/mail_guard/mail_guard.sh egress posture, isolated via
#      WAIO_SHUTDOWN_LOCK / WAIO_AUDIT_LOG / WAIO_EGRESS_ALLOWLIST and a temp
#      MAILGUARD_STATE_DIR: unconfigured, unlisted host, active shutdown and
#      missing allowlist all report "unavailable" (exit 3) and NEVER create
#      SHUTDOWN.lock; a listed host passes egress_check (audit-logged) and
#      then stops at "no credentials" -- no network call is ever made
#   3. collectors: dashboard/collect_mail_guard_status.sh and
#      incident_learning/collectors/mail_guard_collector.sh, the latter fed
#      through the real, unmodified incident_normalizer.sh into a temp
#      knowledge state
# Synthetic data only (example.* / *.invalid).

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_DIR" || exit 1
PASS=0
FAIL=0
ok() { echo "PASS: $1"; PASS=$((PASS + 1)); }
ng() { echo "FAIL: $1"; FAIL=$((FAIL + 1)); }
check() { if eval "$2"; then ok "$1"; else ng "$1"; fi; }

echo "=== MAIL GUARD: Python unit tests"
if python3 -I "$REPO_DIR/tests/mail_guard/test_mail_guard.py"; then ok "python unit tests"; else ng "python unit tests"; fi

T="$(mktemp -d "${TMPDIR:-/tmp}/mail-guard-test.XXXXXX")"
trap 'rm -rf "$T"' EXIT
export WAIO_SHUTDOWN_LOCK="$T/SHUTDOWN.lock"
export WAIO_AUDIT_LOG="$T/audit.jsonl"
export WAIO_AUDIT_LOG_CHECKPOINT="$T/checkpoint"
export WAIO_AUDIT_INTEGRITY_ALERTS="$T/integrity.jsonl"
export WAIO_AUDIT_LOG_LOCK_DIR="$T/audit.lock"
export WAIO_EGRESS_ALLOWLIST="$T/egress_allowlist.conf"
export MAILGUARD_STATE_DIR="$T/state"
unset MAILGUARD_R2_ACCESS_KEY_ID MAILGUARD_R2_SECRET_ACCESS_KEY MAILGUARD_KV_API_TOKEN
# The Keychain is never consulted by this suite.
export MAILGUARD_NO_KEYCHAIN=1
mkdir -p "$MAILGUARD_STATE_DIR"
ACCT="0123456789abcdef0123456789abcdef"
HOST="$ACCT.r2.cloudflarestorage.com"

echo "=== MAIL GUARD: egress wrapper"
out="$(security/mail_guard/mail_guard.sh pull 2>&1)"; rc=$?
check "W1 unconfigured -> exit 3" '[ "$rc" = 3 ]'
check "W1 says not configured" '[[ "$out" == *"not configured"* ]]'

printf '{"account_id":"%s","bucket":"waio-mailguard-events","kv_namespace_id":"%s"}\n' "$ACCT" "$ACCT" > "$MAILGUARD_STATE_DIR/config.json"
printf 'localhost|3000|Takomachi\n' > "$WAIO_EGRESS_ALLOWLIST"
out="$(security/mail_guard/mail_guard.sh pull 2>&1)"; rc=$?
check "W2 host not in allowlist -> exit 3" '[ "$rc" = 3 ]'
check "W2 reason names the allowlist" '[[ "$out" == *"not in the egress allowlist"* ]]'
check "W2 no Emergency Shutdown" '[ ! -e "$WAIO_SHUTDOWN_LOCK" ]'
check "W2 last_pull records the failure" 'python3 -c "import json,sys; d=json.load(open(sys.argv[1])); sys.exit(0 if d[\"ok\"] is False and \"allowlist\" in d[\"reason\"] else 1)" "$MAILGUARD_STATE_DIR/last_pull.json"'
out="$(security/mail_guard/mail_guard.sh publish 1 2>&1)"; rc=$?
check "W3 publish with api.cloudflare.com unlisted -> exit 3, no shutdown" '[ "$rc" = 3 ] && [ ! -e "$WAIO_SHUTDOWN_LOCK" ]'

rm -f "$WAIO_EGRESS_ALLOWLIST"
out="$(security/mail_guard/mail_guard.sh pull 2>&1)"; rc=$?
check "W4 missing allowlist -> exit 3, no shutdown (egress_check would have tripped it)" '[ "$rc" = 3 ] && [ ! -e "$WAIO_SHUTDOWN_LOCK" ]'

printf '%s|443|MAIL GUARD test\napi.cloudflare.com|443|MAIL GUARD test\n' "$HOST" > "$WAIO_EGRESS_ALLOWLIST"
echo "reason: test" > "$WAIO_SHUTDOWN_LOCK"
out="$(security/mail_guard/mail_guard.sh pull 2>&1)"; rc=$?
check "W5 active shutdown -> exit 3" '[ "$rc" = 3 ] && [[ "$out" == *"Shutdown is active"* ]]'
rm -f "$WAIO_SHUTDOWN_LOCK" "$WAIO_SHUTDOWN_LOCK.triggers"

out="$(security/mail_guard/mail_guard.sh pull 2>&1)"; rc=$?
check "W6 listed host passes egress_check, stops at missing credentials (exit 3)" '[ "$rc" = 3 ] && [[ "$out" == *"credentials not available"* ]]'
check "W6 allow decision is in the audit log" 'grep -q "\"egress_allowed\"" "$WAIO_AUDIT_LOG" && grep -q "$HOST:443" "$WAIO_AUDIT_LOG"'
check "W6 no Emergency Shutdown" '[ ! -e "$WAIO_SHUTDOWN_LOCK" ]'
out="$(security/mail_guard/mail_guard.sh publish abc 2>&1)"; rc=$?
check "W7 non-numeric publish version refused" '[ "$rc" = 2 ]'
out="$(security/mail_guard/mail_guard.sh bogus 2>&1)"; rc=$?
check "W8 unknown subcommand refused" '[ "$rc" = 2 ]'
printf '{"account_id":"%s;touch %s/pwn","bucket":"b"}\n' "$ACCT" "$T" > "$MAILGUARD_STATE_DIR/config.json"
out="$(security/mail_guard/mail_guard.sh pull 2>&1)"; rc=$?
check "W9 malformed account id -> unavailable, nothing executed" '[ "$rc" = 3 ] && [ ! -e "$T/pwn" ]'

echo "=== MAIL GUARD: collectors"
rm -f "$MAILGUARD_STATE_DIR/events.jsonl"
out="$(security/incident_learning/collectors/mail_guard_collector.sh)"; rc=$?
check "C1 incident collector with no events: exit 0, no output" '[ "$rc" = 0 ] && [ -z "$out" ]'
MAILGUARD_STATUS_OUT="$T/status.json" dashboard/collect_mail_guard_status.sh
check "C2 dashboard collector without data: available=false" 'python3 -c "import json,sys; d=json.load(open(sys.argv[1])); sys.exit(0 if d[\"available\"] is False and d[\"generated_at\"] else 1)" "$T/status.json"'

python3 - "$MAILGUARD_STATE_DIR/events.jsonl" <<'PY'
import datetime, json, sys
now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
base = {"ts": now, "event": "decision", "mode": "monitor", "level": "allow", "verdict": "pass",
        "hdr_from_domain": "example.org", "indicators": [], "flags": [], "body": {"url_blocklist_hits": []}}
rows = [base, dict(base, level="quarantine", verdict="would-quarantine", hdr_from_domain="evil.invalid",
                   indicators=["DISPLAY_NAME_SPOOF", "URL_USERINFO"], score=6,
                   body={"foreign_url_domains": ["login.evil.invalid"]})]
with open(sys.argv[1], "w") as f:
    for r in rows:
        f.write(json.dumps(r) + "\n")
PY
MAILGUARD_STATUS_OUT="$T/status.json" dashboard/collect_mail_guard_status.sh
check "C3 dashboard collector with data: 2 messages, 1 flagged" 'python3 -c "import json,sys; d=json.load(open(sys.argv[1])); s=d[\"last_24h\"]; sys.exit(0 if d[\"available\"] and s[\"messages\"]==2 and s[\"flagged\"]==1 else 1)" "$T/status.json"'
out="$(security/incident_learning/collectors/mail_guard_collector.sh)"
check "C4 one RawIncident for the flagged sender domain" '[ "$(printf "%s\n" "$out" | grep -c MAILGUARD-)" = 1 ] && [[ "$out" == *"evil.invalid"* ]]'

export KNOWLEDGE_MANAGER_STATE_DIR="$T/il/candidates"
export KNOWLEDGE_MANAGER_AUDIT_LOG="$T/il/audit.jsonl"
export KNOWLEDGE_MANAGER_KNOWLEDGE_DIR="$T/il/knowledge"
mkdir -p "$KNOWLEDGE_MANAGER_STATE_DIR" "$KNOWLEDGE_MANAGER_KNOWLEDGE_DIR"
printf '%s\n' "$out" | bash security/incident_learning/incident_normalizer.sh >"$T/norm.out" 2>&1
check "C5 real incident_normalizer.sh accepts the record -> NORMALIZED" 'grep -rqs "\"status\": *\"NORMALIZED\"" "$KNOWLEDGE_MANAGER_STATE_DIR"'
printf '%s\n' "$out" | bash security/incident_learning/incident_normalizer.sh >>"$T/norm.out" 2>&1
check "C6 re-feeding is idempotent (still one candidate)" '[ "$(find "$KNOWLEDGE_MANAGER_STATE_DIR" -type f -name "MAILGUARD-*" | wc -l | tr -d " ")" = 1 ]'

echo
echo "MAIL GUARD suite: $PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]
