#!/bin/bash
set -uo pipefail

# tests/dependency_watch_test.sh -- W-1 Dependency Notice Watch.
#   U-series: tests/dependency_watch_unittest.py (pure library).
#   I-series: security/dependency_watch/dependency_watch.sh end to end,
#     under tests/lib/test_isolation.sh (temp HOME, temp allowlist,
#     temp SHUTDOWN.lock and audit log). curl is a recording stub that
#     serves a fabricated feed: no real network access.
#   D-series: static guards (no redirects, no network in the parser,
#     no notifications, no Incident Learning write paths).

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR" || exit 1
# shellcheck source=tests/lib/test_isolation.sh
source tests/lib/test_isolation.sh

PASS=0; FAIL=0
ok()  { PASS=$((PASS + 1)); echo "  PASS: $1"; }
bad() { FAIL=$((FAIL + 1)); echo "  FAIL: $1"; }
check() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (expected '$2', got '$3')"; fi; }

echo "== U-series"
if u_out="$(python3 -I -W error::ResourceWarning tests/dependency_watch_unittest.py 2>&1)"; then
  printf '%s\n' "$u_out" | tail -n 3; ok "U-series unittest suite"
else
  printf '%s\n' "$u_out"; bad "U-series unittest suite"
fi

echo "== I-series"
waio_test_isolate dependency-watch || exit 3
trap waio_test_cleanup EXIT
waio_test_assert_isolated || exit 3

T="$WAIO_TEST_ROOT"
export DEPENDENCY_WATCH_STATE_DIR="$T/dw"
export DEPENDENCY_WATCH_SOURCES="$T/sources.conf"
export HFR_HOME="$T/hfr"
mkdir -p "$HFR_HOME/registry"
cat > "$HFR_HOME/registry/sources.json" <<'EOF'
{"registry_version": "test", "sources": [
 {"source_id": "ok-status", "kind": "vendor_status", "status": "ALLOWED", "allowed_uses": {"collect": "yes", "store_raw": "yes"}},
 {"source_id": "unknown-status", "kind": "vendor_status", "status": "UNKNOWN", "allowed_uses": {"collect": "yes", "store_raw": "yes"}}
]}
EOF
printf 'ok-status|ok.example.invalid|/history.atom\nunknown-status|unknown.example.invalid|/history.atom\nunlisted-status|unlisted.example.invalid|/history.atom\n' > "$DEPENDENCY_WATCH_SOURCES"

FIX="$T/fixture.atom"; CODE_FILE="$T/curl_code"
good_feed() {
  printf '%s' '<?xml version="1.0" encoding="UTF-8"?><feed xmlns="http://www.w3.org/2005/Atom"><title>t</title><entry><id>tag:1</id><title>Security incident: unauthorized access</title><link rel="alternate" href="https://example.invalid/i/1"/><updated>2026-01-01T00:00:00Z</updated><content>x</content></entry><entry><id>tag:2</id><title>Scheduled maintenance</title><link rel="alternate" href="https://example.invalid/i/2"/><updated>2026-01-01T00:00:00Z</updated><content>y</content></entry></feed>' > "$FIX"
}
# Recording curl stub: copies $FIX to the -o target and prints the code in $CODE_FILE.
cat > "$T/bin/curl" <<EOF
#!/bin/bash
printf '%s\n' "\$*" >> "$T/stub-calls/curl"
out=""; prev=""
for a in "\$@"; do [ "\$prev" = "-o" ] && out="\$a"; prev="\$a"; done
[ -n "\$out" ] && cp "$FIX" "\$out"
cat "$CODE_FILE"
EOF
chmod +x "$T/bin/curl"
echo 200 > "$CODE_FILE"; good_feed
run() { bash security/dependency_watch/dependency_watch.sh 2>&1; }
curl_calls() { waio_test_stub_calls curl; }
no_shutdown() { [ ! -e "$WAIO_SHUTDOWN_LOCK" ] && echo yes || echo no; }

# I1 allowlist missing -> nothing fetched, egress_check never called, no shutdown
rm -f "$WAIO_EGRESS_ALLOWLIST"
out="$(run)"; rc=$?
check "I1 exit 0 without allowlist" 0 "$rc"
check "I1 curl not called" 0 "$(curl_calls)"
check "I1 no SHUTDOWN.lock" yes "$(no_shutdown)"
case "$out" in *"egress_check NOT called"*) ok "I1 says egress_check not called";; *) bad "I1 message: $out";; esac

# I2 hosts present only for ok/unknown; unlisted host is skipped before egress_check
printf 'ok.example.invalid|443|test\nunknown.example.invalid|443|test\n' > "$WAIO_EGRESS_ALLOWLIST"
out="$(run)"
check "I2 no SHUTDOWN.lock after unlisted host" yes "$(no_shutdown)"
case "$out" in *"unlisted-status: unlisted.example.invalid is not in the egress allowlist"*) ok "I2 unlisted skipped";; *) bad "I2 unlisted message: $out";; esac
# I3 registry UNKNOWN -> not fetched
case "$out" in *"unknown-status: registry refused"*) ok "I3 UNKNOWN refused";; *) bad "I3 message: $out";; esac
# I4 ALLOWED -> exactly one fetch, with the safe curl flags
check "I4 exactly one curl call (ok-status only)" 1 "$(curl_calls)"
args="$(cat "$T/stub-calls/curl")"
case "$args" in *"--max-redirs 0"*) ok "I4 --max-redirs 0";; *) bad "I4 redirects: $args";; esac
case "$args" in *"--proto =https"*) ok "I4 --proto =https";; *) bad "I4 proto: $args";; esac
case " $args " in *" -L "*|*"--location"*) bad "I4 curl got -L";; *) ok "I4 no -L";; esac
case "$args" in *"https://ok.example.invalid/history.atom"*) ok "I4 canonical URL";; *) bad "I4 url: $args";; esac
check "I4 two notices recorded" 2 "$(wc -l < "$DEPENDENCY_WATCH_STATE_DIR/notices.jsonl" | tr -d ' ')"
case "$out" in *"W-3 candidate (security notice): ok-status:"*) ok "I4 W-3 candidate printed";; *) bad "I4 candidate: $out";; esac
raw="$(ls "$DEPENDENCY_WATCH_STATE_DIR/raw/"*.atom | head -1)"
check "I4 raw copy is read-only" 444 "$(stat -f '%Lp' "$raw")"
grep -q '"action":"egress_check"\|egress_allowed\|"destination":"ok.example.invalid:443"' "$WAIO_AUDIT_LOG" && ok "I4 egress_check audit-logged" || bad "I4 no egress audit entry"

# I5 same feed again -> no duplicate lines
run >/dev/null
check "I5 dedupe (still 2 notices)" 2 "$(wc -l < "$DEPENDENCY_WATCH_STATE_DIR/notices.jsonl" | tr -d ' ')"

# I6 redirect (301) is not followed, nothing recorded
echo 301 > "$CODE_FILE"
out="$(run)"
case "$out" in *"ok-status: HTTP 301 (redirects are not followed)"*) ok "I6 301 not followed";; *) bad "I6: $out";; esac
check "I6 still 2 notices" 2 "$(wc -l < "$DEPENDENCY_WATCH_STATE_DIR/notices.jsonl" | tr -d ' ')"

# I7 hostile feed (DOCTYPE/ENTITY) refused, nothing recorded
echo 200 > "$CODE_FILE"
printf '%s' '<?xml version="1.0"?><!DOCTYPE feed [<!ENTITY a "x">]><feed xmlns="http://www.w3.org/2005/Atom">&a;</feed>' > "$FIX"
out="$(run)"
case "$out" in *"feed refused"*) ok "I7 DOCTYPE feed refused";; *) bad "I7: $out";; esac
check "I7 still 2 notices" 2 "$(wc -l < "$DEPENDENCY_WATCH_STATE_DIR/notices.jsonl" | tr -d ' ')"
good_feed

# I8 shutdown already active -> nothing fetched
before="$(curl_calls)"
mkdir -p "$(dirname "$WAIO_SHUTDOWN_LOCK")"; echo test > "$WAIO_SHUTDOWN_LOCK"
out="$(run)"
case "$out" in *"shutdown is active"*) ok "I8 shutdown respected";; *) bad "I8: $out";; esac
check "I8 no new curl call" "$before" "$(curl_calls)"
rm -f "$WAIO_SHUTDOWN_LOCK"

# I9 invalid host in sources.conf is refused before any gate
printf 'evil|bad host;rm|/x\n' > "$DEPENDENCY_WATCH_SOURCES"
out="$(run)"
case "$out" in *"evil: invalid host/path"*) ok "I9 invalid host refused";; *) bad "I9: $out";; esac
check "I9 no SHUTDOWN.lock" yes "$(no_shutdown)"

echo "== D-series"
SH=security/dependency_watch/dependency_watch.sh
PY=security/dependency_watch/dependency_watch_lib.py
if grep -nE '(^|[[:space:]])-L([[:space:]]|$)|--location' "$SH"; then bad "D1 curl redirect flag present"; else ok "D1 no -L/--location"; fi
if grep -nE '^\s*(import|from)\s+(urllib|http|socket|requests|ssl|ftplib|smtplib|asyncio)\b' "$PY"; then bad "D2 network import in parser"; else ok "D2 parser has no network imports"; fi
if grep -nE 'osascript|terminal-notifier|sendmail|mail -s|-X POST|--data|-d @' "$SH" "$PY"; then bad "D3 notification/outbound-post code"; else ok "D3 no notification or POST code"; fi
if grep -nE 'knowledge_manager|incident_human_gate|security/knowledge|candidate_transition' "$SH" "$PY"; then bad "D4 ILE write path referenced"; else ok "D4 no ILE write paths"; fi
if grep -vE '^\s*#|^\s*$' security/dependency_watch/sources.conf | grep -vE '^[a-z-]+\|[a-z0-9.-]+\|/[A-Za-z0-9._/-]*$'; then bad "D5 malformed sources.conf line"; else ok "D5 sources.conf well-formed"; fi
if grep -q 'egress_allowlist' <(git diff --name-only origin/feat/hunt-for-red-p1-ledger 2>/dev/null); then bad "D6 egress allowlist changed on this branch"; else ok "D6 egress allowlist untouched"; fi

echo
echo "dependency_watch_test: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
