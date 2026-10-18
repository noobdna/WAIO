#!/bin/bash
set -uo pipefail

# tests/serve_dashboard_test.sh -- regression suite for
# dashboard/serve_dashboard.py: the hardcoded exact-path allowlist HTTP
# server that replaces stock `python3 -m http.server --directory
# dashboard` in com.waio.dashboard-server's own LaunchAgent. Every case
# here runs a real server process against an ISOLATED fixture
# dashboard/logs root on a loopback-only ephemeral port
# (WAIO_DASHBOARD_ROOT/WAIO_DASHBOARD_LOGS_ROOT/WAIO_DASHBOARD_BIND/
# WAIO_DASHBOARD_PORT overrides) -- never the real dashboard/, never
# the real installed LaunchAgent, never port 8000 itself.

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

code_only() {
  grep -vE '^[[:space:]]*#' "$1"
}

echo "=== WAIO Dashboard server (dashboard/serve_dashboard.py) regression suite ==="

FIXTURE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/waio-dashboard-test.XXXXXX")"
FIXTURE_DASHBOARD="$FIXTURE_DIR/dashboard"
FIXTURE_LOGS="$FIXTURE_DIR/logs"
mkdir -p "$FIXTURE_DASHBOARD" "$FIXTURE_LOGS"

# Fixture content -- deliberately distinct strings per file so a
# content-match proves the RIGHT file was served, not just any 200.
echo "<html>FIXTURE-INDEX</html>" > "$FIXTURE_DASHBOARD/index.html"
echo "<html>FIXTURE-EARTHWEATHER</html>" > "$FIXTURE_DASHBOARD/earth_weather.html"
echo '{"fixture": "waio-status-latest"}' > "$FIXTURE_LOGS/waio-status-latest.json"
echo '{"fixture": "response60-latest"}' > "$FIXTURE_LOGS/response60-latest.json"
echo '{"fixture": "incident-history-latest"}' > "$FIXTURE_LOGS/incident-history-latest.json"
echo '{"fixture": "waio-segments-latest"}' > "$FIXTURE_LOGS/waio-segments-latest.json"
echo '{"fixture": "incident-learning-status-latest"}' > "$FIXTURE_LOGS/incident-learning-status-latest.json"
echo '{"fixture": "decision-status-latest"}' > "$FIXTURE_LOGS/decision-status-latest.json"
echo '{"fixture": "takomachi-status-latest"}' > "$FIXTURE_LOGS/takomachi-status-latest.json"
# SND fixture, deliberately present on disk -- proves exclusion is a
# real refusal, not merely "the file doesn't exist so of course it 404s".
echo '{"fixture": "snd-status-latest", "terminals": ["should-never-be-servable"]}' > "$FIXTURE_LOGS/snd-status-latest.json"
# Out-of-allowlist files that DO exist in the fixture dashboard dir,
# same as the real dashboard/ today (collector scripts, plist template)
# -- proves these are no longer servable, a net hardening vs. today.
echo "#!/bin/bash" > "$FIXTURE_DASHBOARD/collect_status.sh"
echo "fake real-looking config" > "$FIXTURE_DIR/workers_800_fixture.json"
mkdir -p "$FIXTURE_DIR/workers"
cp "$FIXTURE_DIR/workers_800_fixture.json" "$FIXTURE_DIR/workers/800.json"
mkdir -p "$FIXTURE_DIR/security/state/self_dev"
echo '{"secret_looking": "should-never-be-servable"}' > "$FIXTURE_DIR/security/state/self_dev/fixture.json"

PORT=18453
export WAIO_DASHBOARD_ROOT="$FIXTURE_DASHBOARD"
export WAIO_DASHBOARD_LOGS_ROOT="$FIXTURE_LOGS"
export WAIO_DASHBOARD_BIND="127.0.0.1"
export WAIO_DASHBOARD_PORT="$PORT"

python3 ./dashboard/serve_dashboard.py > "$FIXTURE_DIR/server.log" 2>&1 &
SERVER_PID=$!
cleanup() {
  kill "$SERVER_PID" 2>/dev/null
  wait "$SERVER_PID" 2>/dev/null
  rm -rf "$FIXTURE_DIR"
}
trap cleanup EXIT

# Wait for the server to actually start listening (up to ~3s), rather
# than a blind sleep.
ready=0
for _ in $(seq 1 30); do
  if curl -s --max-time 1 -o /dev/null "http://127.0.0.1:$PORT/" 2>/dev/null; then
    ready=1
    break
  fi
  sleep 0.1
done
if [ "$ready" -ne 1 ]; then
  echo "FATAL: server did not start listening on 127.0.0.1:$PORT within 3s"
  cat "$FIXTURE_DIR/server.log"
  exit 1
fi

BASE="http://127.0.0.1:$PORT"

echo ""
echo "=== I-series: allowed paths, correct content and content-type ==="

echo ""
echo "[I1] GET / returns the fixture index.html (200, correct body, text/html)"
OUT="$(curl -s -D - -o "$FIXTURE_DIR/body1" --max-time 2 "$BASE/")"
assert_contains "I1 status 200" "$OUT" "200"
assert_contains "I1 content-type text/html" "$OUT" "text/html"
assert_contains "I1 body is the fixture index" "$(cat "$FIXTURE_DIR/body1")" "FIXTURE-INDEX"

echo ""
echo "[I2] GET /index.html (explicit) returns the same fixture index.html"
assert_eq "I2 status 200" "200" "$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 "$BASE/index.html")"

echo ""
echo "[I3] GET /earth_weather.html returns the fixture earth_weather page"
OUT="$(curl -s --max-time 2 "$BASE/earth_weather.html")"
assert_contains "I3 body is the fixture earth_weather page" "$OUT" "FIXTURE-EARTHWEATHER"

echo ""
echo "[I4] all seven approved logs/*.json files: 200, correct content, application/json"
for f in waio-status-latest response60-latest incident-history-latest waio-segments-latest incident-learning-status-latest decision-status-latest takomachi-status-latest; do
  OUT="$(curl -s -D - -o "$FIXTURE_DIR/body_$f" --max-time 2 "$BASE/logs/$f.json")"
  assert_contains "I4 $f.json status 200" "$OUT" "200"
  assert_contains "I4 $f.json content-type application/json" "$OUT" "application/json"
  assert_contains "I4 $f.json body matches fixture" "$(cat "$FIXTURE_DIR/body_$f")" "\"fixture\": \"$f\""
done

echo ""
echo "[I5] cache-busting query strings (exactly what index.html's own fetch() appends) do not break the allowlist match"
assert_eq "I5 status 200 with a ?t=... query string" "200" "$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 "$BASE/logs/waio-status-latest.json?t=1234567890")"

echo ""
echo "=== I-series: denied paths ==="

echo ""
echo "[I6] *** SND EXCLUDED BY DESIGN *** GET /logs/snd-status-latest.json is 404 even though the file genuinely exists on disk in the fixture logs dir"
assert_eq "I6 snd-status-latest.json is 404 (exists on disk but not in the allowlist)" "404" "$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 "$BASE/logs/snd-status-latest.json")"

echo ""
echo "[I7] a collector .sh script that DOES exist in the fixture dashboard dir (same as the real dashboard/ today) is no longer servable -- 404"
assert_eq "I7 collect_status.sh is 404" "404" "$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 "$BASE/collect_status.sh")"

echo ""
echo "[I8] *** NO REPO-ROOT / workers/ / security/state/ EXPOSURE *** every one of these real-shaped-but-out-of-allowlist paths is 404, never 200, regardless of whether the underlying file exists"
for p in "/workers/800.json" "/security/state/self_dev/fixture.json" "/com.waio.dashboard-server.plist.example" "/nonexistent-entirely.json"; do
  assert_eq "I8 $p is 404" "404" "$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 "$BASE$p")"
done

echo ""
echo "[I9] *** PATH TRAVERSAL *** both raw and percent-encoded '../' traversal attempts against the one URL prefix with any path depth (/logs/) are refused -- 404, never 200, never leaking the fixture 'security/state' file placed two directories above logs/"
for p in "/logs/../../security/state/self_dev/fixture.json" "/logs/%2e%2e/%2e%2e/security/state/self_dev/fixture.json" "/../etc/passwd" "/logs/../../../../../../etc/passwd"; do
  CODE="$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 "$BASE$p")"
  if [ "$CODE" = "200" ]; then
    FAIL=$((FAIL + 1)); FAILURES+=("I9 traversal '$p' returned 200 -- MUST NEVER happen")
    echo "  FAIL: I9 traversal '$p' returned 200 -- MUST NEVER happen"
  else
    PASS=$((PASS + 1)); echo "  PASS: I9 traversal '$p' refused (got $CODE, never 200)"
  fi
done

echo ""
echo "=== I-series: HTTP methods ==="

echo ""
echo "[I10] non-GET methods against an otherwise-allowed path are refused with 405, never 200"
for m in POST PUT DELETE HEAD PATCH; do
  CODE="$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 -X "$m" "$BASE/logs/waio-status-latest.json")"
  assert_eq "I10 $m is 405" "405" "$CODE"
done

echo ""
echo "=== D-series: structural guards (actual code, comments stripped) ==="

echo ""
echo "[D1] snd-status-latest.json is not a key in the ALLOWLIST data structure itself -- exclusion is structural (the module docstring above ALLOWLIST does name it, explaining why; that is documentation, not a dict entry, and is correctly NOT what this checks)"
ALLOWLIST_BLOCK="$(python3 -c "
import re
text = open('dashboard/serve_dashboard.py').read()
m = re.search(r'ALLOWLIST = \{.*?\n\}', text, re.S)
print(m.group(0) if m else '')
")"
assert_contains "D1 sanity: ALLOWLIST block was actually found" "$ALLOWLIST_BLOCK" "ALLOWLIST = {"
cnt="$(printf '%s' "$ALLOWLIST_BLOCK" | grep -c "snd-status-latest" || true)"
assert_eq "D1 zero occurrences of snd-status-latest within the ALLOWLIST dict itself" "0" "$cnt"

echo ""
echo "[D2] no directory-listing / os.walk / glob / SimpleHTTPRequestHandler-style generic static-file serving anywhere -- this is an exact allowlist, not a scoped directory server. (send_header -- setting one explicit response header -- is unrelated to SimpleHTTPRequestHandler's own send_head() directory/file dispatcher and is correctly not what this checks)"
cnt=0
for pattern in 'os\.walk' 'glob\.' 'SimpleHTTPRequestHandler' 'send_head\b' 'list_directory' 'os\.listdir'; do
  c="$(code_only dashboard/serve_dashboard.py | grep -cE "$pattern" || true)"
  cnt=$((cnt + c))
done
assert_eq "D2 zero directory-listing/generic-static-serving constructs" "0" "$cnt"

echo ""
echo "[D3] no eval/exec/os.system/subprocess anywhere in actual code"
cnt=0
for pattern in '\beval\(' '\bexec\(' 'os\.system' 'subprocess\.'; do
  c="$(code_only dashboard/serve_dashboard.py | grep -cE "$pattern" || true)"
  cnt=$((cnt + c))
done
assert_eq "D3 zero eval/exec/os.system/subprocess references" "0" "$cnt"

echo ""
echo "[D7] with WAIO_DASHBOARD_BIND unset, the module binds loopback only -- LAN exposure (unauthenticated) must be an explicit opt-in"
DEFAULT_BIND="$(env -u WAIO_DASHBOARD_BIND python3 -c "
import importlib.util
spec = importlib.util.spec_from_file_location('sd', 'dashboard/serve_dashboard.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
print(m.BIND)
")"
assert_eq "D7 default BIND is 127.0.0.1" "127.0.0.1" "$DEFAULT_BIND"
OPTIN_BIND="$(WAIO_DASHBOARD_BIND=0.0.0.0 python3 -c "
import importlib.util
spec = importlib.util.spec_from_file_location('sd', 'dashboard/serve_dashboard.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
print(m.BIND)
")"
assert_eq "D7 explicit WAIO_DASHBOARD_BIND=0.0.0.0 opt-in still honoured" "0.0.0.0" "$OPTIN_BIND"

echo ""
echo "[D4] python3 -m py_compile succeeds"
python3 -m py_compile dashboard/serve_dashboard.py 2>/tmp/waio_dash_pycompile_err
assert_eq "D4 py_compile exit 0" "0" "$?"
rm -f /tmp/waio_dash_pycompile_err

echo ""
echo "[D5] the installed template dashboard/com.waio.dashboard-server.plist.example's actual ProgramArguments array now invokes serve_dashboard.py, not the old generic 'http.server --directory dashboard' (a header comment explaining that history, mentioning --directory by name, is expected and is correctly not what this checks)"
PROGRAM_ARGS_BLOCK="$(python3 -c "
import re
text = open('dashboard/com.waio.dashboard-server.plist.example').read()
m = re.search(r'<key>ProgramArguments</key>\s*<array>.*?</array>', text, re.S)
print(m.group(0) if m else '')
")"
assert_contains "D5 sanity: ProgramArguments block was actually found" "$PROGRAM_ARGS_BLOCK" "ProgramArguments"
assert_contains "D5 ProgramArguments invokes serve_dashboard.py" "$PROGRAM_ARGS_BLOCK" "serve_dashboard.py"
cnt="$(printf '%s' "$PROGRAM_ARGS_BLOCK" | grep -c -- '--directory' || true)"
assert_eq "D5 ProgramArguments no longer passes --directory" "0" "$cnt"

echo ""
echo "[D6] this phase's own scope stayed under dashboard/serve_dashboard.py, dashboard/com.waio.dashboard-server.plist.example, and this test file -- the REAL installed LaunchAgent, dashboard/index.html, and every other pre-existing file have no working-tree diff"
for f in dashboard/index.html dashboard/earth_weather.html dashboard/collect_status.sh dashboard/collect_snd_status.sh dashboard/collect_takomachi_status.sh dashboard/refresh_dashboard_cron.sh dashboard/com.waio.dashboard-refresh.plist.example; do
  assert_eq "D6 $f has no working-tree diff" "" "$(git diff --name-only -- "$f" 2>/dev/null)"
done

echo ""
echo "=== Summary: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
  echo "Failures:"
  for f in "${FAILURES[@]}"; do echo "  - $f"; done
  exit 1
fi
exit 0
