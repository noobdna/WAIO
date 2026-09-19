#!/bin/bash
set -uo pipefail

# tests/register_takomachi_agents_test.sh -- regression suite for
# workers/register_takomachi_agents.sh: idempotent (GET-before-POST)
# Takomachi agent provisioning from the single source of truth,
# workers/takomachi_agents.conf. See that conf file's own header, and
# ARCHITECTURE.md's "Takomachi agent registration" phase entry, for why
# this script exists (the original one-time registration was never
# committed and was lost when Takomachi's own takomachi.sqlite was
# rebuilt).
#
# Same conventions as tests/collect_takomachi_status_test.sh: driven
# entirely via TAKOMACHI_API_KEY/TAKOMACHI_API_URL env-var overrides
# against a local, unauthenticated Python http.server fixture standing in
# for Takomachi -- never the real macOS Keychain or a real Takomachi
# instance. Unlike that collector (a passive read that deliberately
# bypasses the DLP gate), this script performs a real mutating POST, so
# it IS expected to go through security/lib.sh's egress_check/
# payload_size_check -- WAIO_EGRESS_ALLOWLIST/WAIO_SHUTDOWN_LOCK/
# WAIO_AUDIT_LOG(+checkpoint/lock-dir) are all pointed at scratch fixture
# paths for the whole suite so the real deployment's security state is
# never read or written.

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
    FAIL=$((FAIL + 1)); FAILURES+=("$label (must NOT contain '$needle')")
    echo "  FAIL: $label (must NOT contain '$needle')"
  fi
}

# --- fixture isolation for the DLP layer (never touches real state) ---
FIXTURE_DIR="$(mktemp -d)"
export WAIO_SHUTDOWN_LOCK="$FIXTURE_DIR/SHUTDOWN.lock"
export WAIO_AUDIT_LOG="$FIXTURE_DIR/security-audit.jsonl"
export WAIO_AUDIT_LOG_CHECKPOINT="$FIXTURE_DIR/.audit_log_chain_checkpoint"
export WAIO_AUDIT_LOG_LOCK_DIR="$FIXTURE_DIR/.audit_log.lock"
export WAIO_EGRESS_ALLOWLIST="$FIXTURE_DIR/egress_allowlist.conf"

cleanup() {
  [ -n "${MOCK_PID:-}" ] && kill "$MOCK_PID" 2>/dev/null
  [ -n "${MOCK_PID:-}" ] && wait "$MOCK_PID" 2>/dev/null
  rm -rf "$FIXTURE_DIR"
}
trap cleanup EXIT

FAKE_API_KEY="test-fixture-key-not-a-real-secret-98765"

BEFORE_LOCK_HASH="not_present"
[ -f security/state/SHUTDOWN.lock ] && BEFORE_LOCK_HASH="$(shasum -a 256 security/state/SHUTDOWN.lock | awk '{print $1}')"

# --- mock Takomachi: stateful, tracks which agent ids have been "created"
# in-process so GET-before-POST idempotency is exercised for real. A
# special path lets the test read back how many POSTs it actually saw. A
# query-string flag (?fail_post=1) makes POST /agents return 500 for one
# chosen id, to exercise the "one row fails, the rest still run" path. ---
start_mock() {
  local port="$1" fail_post_for="${2:-}"
  python3 - "$port" "$fail_post_for" > /dev/null 2>&1 <<'PYEOF' &
import json, sys
from http.server import BaseHTTPRequestHandler, HTTPServer

fail_post_for = sys.argv[2]
created = set()
post_count = {"n": 0}

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/__meta/post_count":
            body = json.dumps({"post_count": post_count["n"]}).encode()
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
            self.wfile.write(body); return
        if self.path.startswith("/agents/"):
            agent_id = self.path[len("/agents/"):]
            if agent_id in created:
                body = json.dumps({"id": agent_id}).encode()
                self.send_response(200)
            else:
                body = json.dumps({"error": "not found"}).encode()
                self.send_response(404)
            self.send_header("Content-Type", "application/json"); self.end_headers()
            self.wfile.write(body); return
        self.send_response(404); self.end_headers()

    def do_POST(self):
        if self.path == "/agents":
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length)
            post_count["n"] += 1
            try:
                agent_id = json.loads(raw).get("id")
            except Exception:
                agent_id = None
            if fail_post_for and agent_id == fail_post_for:
                self.send_response(500)
                self.send_header("Content-Type", "application/json"); self.end_headers()
                self.wfile.write(json.dumps({"error": "injected failure"}).encode())
                return
            if agent_id:
                created.add(agent_id)
            self.send_response(201)
            self.send_header("Content-Type", "application/json"); self.end_headers()
            self.wfile.write(raw)
            return
        self.send_response(404); self.end_headers()

    def log_message(self, *a):
        pass

HTTPServer(("127.0.0.1", int(sys.argv[1])), Handler).serve_forever()
PYEOF
  MOCK_PID=$!
  sleep 0.5
}

stop_mock() {
  [ -n "${MOCK_PID:-}" ] && kill "$MOCK_PID" 2>/dev/null
  [ -n "${MOCK_PID:-}" ] && wait "$MOCK_PID" 2>/dev/null
  MOCK_PID=""
}

allow_only() {
  # Isolated egress allowlist covering only the given host:port -- proves
  # the script's own derived host/port (from BASE_URL, not a hardcoded
  # "localhost"/"3000") is what actually gets checked.
  printf '%s|%s|test fixture Takomachi\n' "$1" "$2" > "$WAIO_EGRESS_ALLOWLIST"
}

echo "=== workers/register_takomachi_agents.sh ==="

echo "[R1] no TAKOMACHI_API_KEY at all: exits 1, clear error, no network call attempted"
unset TAKOMACHI_API_KEY 2>/dev/null || true
allow_only "127.0.0.1" "1"
R1_OUT="$(TAKOMACHI_API_URL="http://127.0.0.1:1" ./workers/register_takomachi_agents.sh 2>&1)"
R1_RC=$?
assert_eq "R1 exit 1" "1" "$R1_RC"
assert_contains "R1 mentions Keychain/env var" "$R1_OUT" "TAKOMACHI_API_KEY"

echo "[R2] egress denied (destination not in the isolated allowlist): exits 1, no crash"
printf '# empty on purpose\n' > "$WAIO_EGRESS_ALLOWLIST"
R2_OUT="$(TAKOMACHI_API_KEY="$FAKE_API_KEY" TAKOMACHI_API_URL="http://127.0.0.1:19999" ./workers/register_takomachi_agents.sh 2>&1)"
R2_RC=$?
assert_eq "R2 exit 1" "1" "$R2_RC"
assert_contains "R2 mentions egress denial" "$R2_OUT" "egress denied"
# R2 deliberately trips the real trigger_shutdown() side effect (same as
# any WAIO worker's egress_check denial) against the fixture lock path --
# clear it before continuing, same between-case convention
# tests/security_test.sh/tests/incident_learning_cisa_kev_collector_test.sh
# already use for their own deliberate trips.
rm -f "$WAIO_SHUTDOWN_LOCK"

MOCK_PORT=18944

echo "[R3] fresh registration: every agent 404s on GET, then POSTs 201 -- all four rows registered, exit 0"
allow_only "127.0.0.1" "$MOCK_PORT"
start_mock "$MOCK_PORT" ""
R3_OUT="$(TAKOMACHI_API_KEY="$FAKE_API_KEY" TAKOMACHI_API_URL="http://127.0.0.1:$MOCK_PORT" ./workers/register_takomachi_agents.sh 2>&1)"
R3_RC=$?
assert_eq "R3 exit 0" "0" "$R3_RC"
assert_contains "R3 registers waio-research" "$R3_OUT" "waio-research: registered"
assert_contains "R3 registers waio-analysis" "$R3_OUT" "waio-analysis: registered"
assert_contains "R3 registers waio-ai" "$R3_OUT" "waio-ai: registered"
assert_contains "R3 registers waio-orchestrate" "$R3_OUT" "waio-orchestrate: registered"
POST_COUNT_AFTER_R3="$(curl -s "http://127.0.0.1:$MOCK_PORT/__meta/post_count" | python3 -c 'import json,sys; print(json.load(sys.stdin)["post_count"])')"
assert_eq "R3 issued exactly 4 POSTs" "4" "$POST_COUNT_AFTER_R3"

echo "[R4] re-running against the SAME mock (now all pre-existing): idempotent -- every row skipped, zero new POSTs, exit 0"
R4_OUT="$(TAKOMACHI_API_KEY="$FAKE_API_KEY" TAKOMACHI_API_URL="http://127.0.0.1:$MOCK_PORT" ./workers/register_takomachi_agents.sh 2>&1)"
R4_RC=$?
assert_eq "R4 exit 0" "0" "$R4_RC"
assert_contains "R4 skips waio-research" "$R4_OUT" "waio-research: already registered, skipping"
assert_contains "R4 skips waio-analysis" "$R4_OUT" "waio-analysis: already registered, skipping"
assert_contains "R4 skips waio-ai" "$R4_OUT" "waio-ai: already registered, skipping"
assert_contains "R4 skips waio-orchestrate" "$R4_OUT" "waio-orchestrate: already registered, skipping"
assert_not_contains "R4 never re-POSTs" "$R4_OUT" ": registered ("
POST_COUNT_AFTER_R4="$(curl -s "http://127.0.0.1:$MOCK_PORT/__meta/post_count" | python3 -c 'import json,sys; print(json.load(sys.stdin)["post_count"])')"
assert_eq "R4 issued zero additional POSTs (still 4 total)" "4" "$POST_COUNT_AFTER_R4"
stop_mock

echo "[R5] one row's POST fails (HTTP 500): that row reported as ERROR, the other three still complete, overall exit 1"
allow_only "127.0.0.1" "$MOCK_PORT"
start_mock "$MOCK_PORT" "waio-ai"
R5_OUT="$(TAKOMACHI_API_KEY="$FAKE_API_KEY" TAKOMACHI_API_URL="http://127.0.0.1:$MOCK_PORT" ./workers/register_takomachi_agents.sh 2>&1)"
R5_RC=$?
stop_mock
assert_eq "R5 exit 1 (one row failed)" "1" "$R5_RC"
assert_contains "R5 reports waio-ai failure" "$R5_OUT" "waio-ai: ERROR: registration failed (HTTP 500)"
assert_contains "R5 still registers waio-research" "$R5_OUT" "waio-research: registered"
assert_contains "R5 still registers waio-analysis" "$R5_OUT" "waio-analysis: registered"
assert_contains "R5 still registers waio-orchestrate" "$R5_OUT" "waio-orchestrate: registered"

echo "[R6] secret hygiene: the fake API key value is never echoed anywhere in this script's stdout/stderr, across every case above"
ALL_OUTPUT="$R1_OUT
$R2_OUT
$R3_OUT
$R4_OUT
$R5_OUT"
assert_not_contains "R6 API key never printed" "$ALL_OUTPUT" "$FAKE_API_KEY"

echo "[D1] this script DOES source security/lib.sh and DOES call egress_check/payload_size_check as real function calls (unlike dashboard/collect_takomachi_status.sh's deliberate bypass) -- static check"
SOURCES_LIB="$(grep -cE '^\s*source security/lib\.sh\b' workers/register_takomachi_agents.sh || true)"
assert_eq "D1 sources security/lib.sh" "1" "$SOURCES_LIB"
CALLS_EGRESS="$(grep -cE '\begress_check\s+"' workers/register_takomachi_agents.sh || true)"
assert_eq "D1 calls egress_check" "1" "$CALLS_EGRESS"
CALLS_PAYLOAD="$(grep -cE '\bpayload_size_check\s+"' workers/register_takomachi_agents.sh || true)"
assert_eq "D1 calls payload_size_check" "1" "$CALLS_PAYLOAD"

echo "[D2] AGENT_ID is not hardcoded in research_worker.sh/analysis_worker.sh/ai_worker.sh anymore -- resolved from workers/takomachi_agents.conf by capability tag"
for pair in "research_worker.sh:research" "analysis_worker.sh:analysis" "ai_worker.sh:ai"; do
  f="workers/${pair%%:*}"
  tag="${pair##*:}"
  HARDCODED="$(grep -cE "AGENT_ID=\"waio-${tag}\"" "$f" || true)"
  assert_eq "D2 $f has no literal AGENT_ID=\"waio-$tag\"" "0" "$HARDCODED"
  READS_CONF="$(grep -cE 'workers/takomachi_agents\.conf' "$f" || true)"
  if [ "$READS_CONF" -lt 1 ]; then READS_CONF=0; else READS_CONF=1; fi
  assert_eq "D2 $f reads workers/takomachi_agents.conf" "1" "$READS_CONF"
done

echo "[D3] this deployment's real security/state/SHUTDOWN.lock (a pre-existing, unrelated fixture) is byte-for-byte unchanged by everything above -- this suite only ever touched WAIO_SHUTDOWN_LOCK's own scratch fixture path"
AFTER_LOCK_HASH="not_present"
[ -f security/state/SHUTDOWN.lock ] && AFTER_LOCK_HASH="$(shasum -a 256 security/state/SHUTDOWN.lock | awk '{print $1}')"
assert_eq "D3 real SHUTDOWN.lock checksum unchanged" "$BEFORE_LOCK_HASH" "$AFTER_LOCK_HASH"

echo
echo "=== Results: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
  echo "Failures:"
  for f in "${FAILURES[@]}"; do echo "  - $f"; done
  exit 1
fi
exit 0
