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

# Every test port is a fresh kernel-assigned loopback port (never 8000,
# never a fixed number another run or process could already hold).
# TEST_PORTS records them for the C3 leak check.
free_port() {
  python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()'
}
TEST_PORTS=()
PORT="$(free_port)"; TEST_PORTS+=("$PORT")
export WAIO_DASHBOARD_ROOT="$FIXTURE_DASHBOARD"
export WAIO_DASHBOARD_LOGS_ROOT="$FIXTURE_LOGS"
export WAIO_DASHBOARD_BIND="127.0.0.1"
export WAIO_DASHBOARD_PORT="$PORT"

python3 ./dashboard/serve_dashboard.py > "$FIXTURE_DIR/server.log" 2>&1 &
SERVER_PID=$!
EXTRA_PIDS=()
# Process cleanup is by tracked PID only, and only for a PID that is
# still one of this shell's own background jobs (bash's `jobs -p`) --
# never by name/pattern (pkill -f / killall): the live
# com.waio.dashboard-server LaunchAgent runs this same script path as
# the same user, so a pattern match would kill production. `jobs -p` is
# a builtin, so this also works where /bin/ps is unavailable (e.g.
# under sandbox-exec, where ps is "Operation not permitted" and a
# ps-based check silently skipped every kill, leaking test servers).
# C1/C2 below guard this.
stop_tracked() {
  local pid own
  own=" $(jobs -p | tr '\n' ' ') "
  for pid in "$@"; do
    [ -n "$pid" ] || continue
    case "$own" in *" $pid "*) ;; *) continue ;; esac
    kill "$pid" 2>/dev/null
    wait "$pid" 2>/dev/null
  done
}
cleanup() {
  stop_tracked "$SERVER_PID" "${EXTRA_PIDS[@]}"
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
python3 -m py_compile dashboard/serve_dashboard.py 2>"$FIXTURE_DIR/pycompile_err"
assert_eq "D4 py_compile exit 0" "0" "$?"

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
echo "=== A-series: LAN access policy (non-loopback bind needs Basic auth + a private client allowlist; fail closed) ==="

# Credential fixture via the real helper. The password is a test-only
# literal, never a real credential; the helper stores only a PBKDF2 hash.
AUTH_DIR="$FIXTURE_DIR/authcfg"
TEST_PW="fixture-only-pw-$$-0123"
printf '%s\n' "$TEST_PW" | python3 ./dashboard/set_dashboard_auth.py --user ipad --out "$AUTH_DIR/dashboard-auth" --password-stdin >/dev/null 2>"$FIXTURE_DIR/helper.err"
AUTH_FILE="$AUTH_DIR/dashboard-auth"

echo ""
echo "[A1] helper writes a 0600 file in a 0700 dir holding a pbkdf2 hash, never the password"
file_mode() { python3 -c 'import os, sys; print(format(os.stat(sys.argv[1]).st_mode & 0o777, "o"))' "$1"; }
assert_eq "A1 credential file mode 600" "600" "$(file_mode "$AUTH_FILE")"
assert_eq "A1 credential dir mode 700" "700" "$(file_mode "$AUTH_DIR")"
assert_contains "A1 file holds a pbkdf2_sha256 record" "$(cat "$AUTH_FILE")" "ipad:pbkdf2_sha256\$200000\$"
assert_eq "A1 plaintext password not in the file" "0" "$(grep -c -- "$TEST_PW" "$AUTH_FILE" || true)"
printf 'short\n' | python3 ./dashboard/set_dashboard_auth.py --user ipad --out "$AUTH_DIR/weak" --password-stdin >/dev/null 2>&1
assert_eq "A1 helper refuses a password under 12 chars" "false" "$([ -e "$AUTH_DIR/weak" ] && echo true || echo false)"
printf '%s\n' "$TEST_PW" | python3 ./dashboard/set_dashboard_auth.py --user ipad --out "./dashboard/should-not-exist-auth" --password-stdin >/dev/null 2>&1
assert_eq "A1 helper refuses to write inside the repository" "false" "$([ -e ./dashboard/should-not-exist-auth ] && echo true || echo false)"
rm -f ./dashboard/should-not-exist-auth

# start_policy_server PORT [VAR=VALUE...] -> starts a server with the
# given policy env; prints nothing. Exit status/listening checked by caller.
start_policy_server() {
  local port="$1"; shift
  env WAIO_DASHBOARD_PORT="$port" WAIO_DASHBOARD_AUTH_FILE= WAIO_DASHBOARD_ALLOWED_CLIENTS= "$@" \
    python3 ./dashboard/serve_dashboard.py > "$FIXTURE_DIR/server-$port.log" 2>&1 &
  EXTRA_PIDS+=("$!")
}
# wait_listening PORT -> 0 once something answers on PORT AND the
# server this suite just started is still alive (so a reply can never
# come from some other process that happened to hold the port).
wait_listening() {
  local port="$1" pid="${EXTRA_PIDS[${#EXTRA_PIDS[@]}-1]}"
  for _ in $(seq 1 30); do
    if curl -s --max-time 1 -o /dev/null "http://127.0.0.1:$port/" 2>/dev/null; then
      kill -0 "$pid" 2>/dev/null && return 0
      return 1
    fi
    sleep 0.1
  done
  return 1
}
# refused_rc VAR=VALUE... -> runs the server in the foreground (it must
# exit on its own, never listen) and prints its exit code.
REFUSED_PORT="$(free_port)"; TEST_PORTS+=("$REFUSED_PORT")
refused_rc() {
  env WAIO_DASHBOARD_PORT="$REFUSED_PORT" WAIO_DASHBOARD_AUTH_FILE= WAIO_DASHBOARD_ALLOWED_CLIENTS= "$@" \
    perl -e 'alarm 5; exec @ARGV' python3 ./dashboard/serve_dashboard.py > "$FIXTURE_DIR/refused.log" 2>&1
  echo $?
}

echo ""
echo "[A2] *** FAIL CLOSED *** a non-loopback bind without auth and allowlist never starts (exit 2, never listens)"
assert_eq "A2 0.0.0.0 with neither: exit 2" "2" "$(refused_rc WAIO_DASHBOARD_BIND=0.0.0.0)"
assert_contains "A2 refusal names the missing settings" "$(cat "$FIXTURE_DIR/refused.log")" "requires both WAIO_DASHBOARD_AUTH_FILE and WAIO_DASHBOARD_ALLOWED_CLIENTS"
assert_eq "A2 0.0.0.0 with auth but no allowlist: exit 2" "2" "$(refused_rc WAIO_DASHBOARD_BIND=0.0.0.0 WAIO_DASHBOARD_AUTH_FILE="$AUTH_FILE")"
assert_eq "A2 0.0.0.0 with allowlist but no auth: exit 2" "2" "$(refused_rc WAIO_DASHBOARD_BIND=0.0.0.0 WAIO_DASHBOARD_ALLOWED_CLIENTS=192.168.1.0/24)"
assert_eq "A2 nothing is listening on the refused port" "000" "$(curl -s -o /dev/null -w '%{http_code}' --max-time 1 http://127.0.0.1:$REFUSED_PORT/ 2>/dev/null)"

echo ""
echo "[A3] allowlist entries must be private/loopback; public ranges and catch-alls are refused"
for bad in 8.8.8.0/24 0.0.0.0/0 ::/0 2406:2d40::/32 not-a-cidr; do
  assert_eq "A3 allowlist '$bad' refused (exit 2)" "2" "$(refused_rc WAIO_DASHBOARD_BIND=0.0.0.0 WAIO_DASHBOARD_AUTH_FILE="$AUTH_FILE" WAIO_DASHBOARD_ALLOWED_CLIENTS="$bad")"
done

echo ""
echo "[A4] credential file must be a 0600 regular file owned by this user, with a strong pbkdf2 record"
cp "$AUTH_FILE" "$AUTH_DIR/loose"; chmod 644 "$AUTH_DIR/loose"
assert_eq "A4 mode 644 credential file refused" "2" "$(refused_rc WAIO_DASHBOARD_BIND=0.0.0.0 WAIO_DASHBOARD_AUTH_FILE="$AUTH_DIR/loose" WAIO_DASHBOARD_ALLOWED_CLIENTS=192.168.1.0/24)"
printf 'ipad:plaintext-password\n' > "$AUTH_DIR/plain"; chmod 600 "$AUTH_DIR/plain"
assert_eq "A4 non-pbkdf2 (plaintext) record refused" "2" "$(refused_rc WAIO_DASHBOARD_BIND=0.0.0.0 WAIO_DASHBOARD_AUTH_FILE="$AUTH_DIR/plain" WAIO_DASHBOARD_ALLOWED_CLIENTS=192.168.1.0/24)"
sed 's/\$200000\$/$1000$/' "$AUTH_FILE" > "$AUTH_DIR/weakiter"; chmod 600 "$AUTH_DIR/weakiter"
assert_eq "A4 pbkdf2 under 100000 iterations refused" "2" "$(refused_rc WAIO_DASHBOARD_BIND=0.0.0.0 WAIO_DASHBOARD_AUTH_FILE="$AUTH_DIR/weakiter" WAIO_DASHBOARD_ALLOWED_CLIENTS=192.168.1.0/24)"
assert_eq "A4 missing credential file refused" "2" "$(refused_rc WAIO_DASHBOARD_BIND=0.0.0.0 WAIO_DASHBOARD_AUTH_FILE="$AUTH_DIR/nope" WAIO_DASHBOARD_ALLOWED_CLIENTS=192.168.1.0/24)"

echo ""
echo "[A5] authenticated server (loopback bind, auth + allowlist 127.0.0.1/32): 401 without/with wrong creds, 200 with the right ones"
P5="$(free_port)"; TEST_PORTS+=("$P5")
start_policy_server "$P5" WAIO_DASHBOARD_BIND=127.0.0.1 WAIO_DASHBOARD_AUTH_FILE="$AUTH_FILE" WAIO_DASHBOARD_ALLOWED_CLIENTS=127.0.0.1/32
if wait_listening "$P5"; then
  B5="http://127.0.0.1:$P5"
  assert_eq "A5 no credentials -> 401" "401" "$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "$B5/")"
  assert_contains "A5 401 carries a Basic challenge" "$(curl -s -D - -o /dev/null --max-time 3 "$B5/")" 'WWW-Authenticate: Basic realm="WAIO Dashboard"'
  assert_eq "A5 no credentials on a JSON route -> 401 (data is protected too)" "401" "$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "$B5/logs/waio-status-latest.json")"
  assert_eq "A5 wrong password -> 401" "401" "$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 -u "ipad:wrong-password-xyz" "$B5/")"
  assert_eq "A5 wrong user -> 401" "401" "$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 -u "other:$TEST_PW" "$B5/")"
  assert_contains "A5 right credentials -> fixture index" "$(curl -s --max-time 5 -u "ipad:$TEST_PW" "$B5/")" "FIXTURE-INDEX"
  assert_contains "A5 right credentials -> JSON route served" "$(curl -s --max-time 5 -u "ipad:$TEST_PW" "$B5/logs/waio-status-latest.json?t=1")" "waio-status-latest"
  assert_contains "A5 authenticated response is Cache-Control: no-store" "$(curl -s -D - -o /dev/null --max-time 5 -u "ipad:$TEST_PW" "$B5/")" "Cache-Control: no-store"
  assert_eq "A5 SND exclusion still holds when authenticated -> 404" "404" "$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 -u "ipad:$TEST_PW" "$B5/logs/snd-status-latest.json")"
  assert_eq "A5 POST still 405" "405" "$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 -X POST "$B5/")"
  assert_eq "A5 test password never appears in the server log" "0" "$(grep -c -- "$TEST_PW" "$FIXTURE_DIR/server-$P5.log" || true)"
  assert_contains "A5 startup line reports auth=basic and the client allowlist" "$(cat "$FIXTURE_DIR/server-$P5.log")" "auth=basic clients=127.0.0.1/32"
else
  FAIL=$((FAIL + 1)); FAILURES+=("A5 authenticated server did not start"); echo "  FAIL: A5 server did not start"; cat "$FIXTURE_DIR/server-$P5.log"
fi

echo ""
echo "[A6] brute-force brake: 5 wrong passwords from one client -> 429 even for the right password"
P6="$(free_port)"; TEST_PORTS+=("$P6")
start_policy_server "$P6" WAIO_DASHBOARD_BIND=127.0.0.1 WAIO_DASHBOARD_AUTH_FILE="$AUTH_FILE" WAIO_DASHBOARD_ALLOWED_CLIENTS=127.0.0.1/32
if wait_listening "$P6"; then
  for _ in 1 2 3 4 5; do curl -s -o /dev/null --max-time 3 -u "ipad:wrong-$RANDOM-pw" "http://127.0.0.1:$P6/"; done
  assert_eq "A6 right password during lockout -> 429" "429" "$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 -u "ipad:$TEST_PW" "http://127.0.0.1:$P6/")"
else
  FAIL=$((FAIL + 1)); FAILURES+=("A6 server did not start"); echo "  FAIL: A6 server did not start"
fi

echo ""
echo "[A7] client allowlist is enforced: a loopback client outside WAIO_DASHBOARD_ALLOWED_CLIENTS gets 403 before any auth"
P7="$(free_port)"; TEST_PORTS+=("$P7")
start_policy_server "$P7" WAIO_DASHBOARD_BIND=127.0.0.1 WAIO_DASHBOARD_AUTH_FILE="$AUTH_FILE" WAIO_DASHBOARD_ALLOWED_CLIENTS=192.168.1.0/24
for _ in $(seq 1 30); do
  code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 1 "http://127.0.0.1:$P7/" 2>/dev/null)"
  [ "$code" != "000" ] && break; sleep 0.1
done
assert_eq "A7 127.0.0.1 not in 192.168.1.0/24 -> 403" "403" "$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 -u "ipad:$TEST_PW" "http://127.0.0.1:$P7/")"

echo ""
echo "[A8] policy unit checks (module functions; no socket)"
UNIT="$(python3 - <<'PYEOF'
import importlib.util, ipaddress
spec = importlib.util.spec_from_file_location("sd", "dashboard/serve_dashboard.py")
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
nets = m.parse_allowed_clients("192.168.1.0/24, fd42::/16")
r = []
r.append(m.client_allowed("192.168.1.33", nets))           # iPad-like LAN client
r.append(not m.client_allowed("192.168.2.10", nets))       # other subnet
r.append(m.client_allowed("::ffff:192.168.1.209", nets))   # IPv4-mapped form
r.append(not m.client_allowed("2406:2d40::1", nets))        # public IPv6
r.append(m.is_loopback_bind("127.0.0.1") and m.is_loopback_bind("::1") and m.is_loopback_bind("localhost"))
r.append(not m.is_loopback_bind("0.0.0.0") and not m.is_loopback_bind("192.168.1.80") and not m.is_loopback_bind("example.lan"))
try:
    m.build_policy("192.168.1.80", "", "192.168.1.0/24"); r.append(False)
except m.ConfigError:
    r.append(True)
print(" ".join("ok" if x else "BAD" for x in r))
PYEOF
)"
assert_eq "A8 allowlist matching, mapped IPv4, public IPv6, loopback detection, specific-IP bind also fails closed" "ok ok ok ok ok ok ok" "$UNIT"

echo ""
echo "[A10] every malformed or unusable credential file is refused (exit 2, never listens)"
REC="$(cut -d: -f2- "$AUTH_FILE")"
IT="$(printf '%s' "$REC" | cut -d'$' -f2)"; SALT="$(printf '%s' "$REC" | cut -d'$' -f3)"; DG="$(printf '%s' "$REC" | cut -d'$' -f4)"
bad_auth() {  # bad_auth NAME CONTENT -> exit code of a 0.0.0.0 start with that 0600 file
  printf '%s\n' "$2" > "$AUTH_DIR/$1"; chmod 600 "$AUTH_DIR/$1"
  refused_rc WAIO_DASHBOARD_BIND=0.0.0.0 WAIO_DASHBOARD_AUTH_FILE="$AUTH_DIR/$1" WAIO_DASHBOARD_ALLOWED_CLIENTS=192.168.1.0/24
}
: > "$AUTH_DIR/empty"; chmod 600 "$AUTH_DIR/empty"
assert_eq "A10 empty file refused" "2" "$(refused_rc WAIO_DASHBOARD_BIND=0.0.0.0 WAIO_DASHBOARD_AUTH_FILE="$AUTH_DIR/empty" WAIO_DASHBOARD_ALLOWED_CLIENTS=192.168.1.0/24)"
mkdir -m 700 "$AUTH_DIR/adir"
assert_eq "A10 directory refused" "2" "$(refused_rc WAIO_DASHBOARD_BIND=0.0.0.0 WAIO_DASHBOARD_AUTH_FILE="$AUTH_DIR/adir" WAIO_DASHBOARD_ALLOWED_CLIENTS=192.168.1.0/24)"
cp "$AUTH_FILE" "$AUTH_DIR/unreadable"; chmod 000 "$AUTH_DIR/unreadable"
assert_eq "A10 unreadable (mode 000) file refused" "2" "$(refused_rc WAIO_DASHBOARD_BIND=0.0.0.0 WAIO_DASHBOARD_AUTH_FILE="$AUTH_DIR/unreadable" WAIO_DASHBOARD_ALLOWED_CLIENTS=192.168.1.0/24)"
assert_contains "A10 unreadable file is reported as unreadable, not malformed" "$(cat "$FIXTURE_DIR/refused.log")" "cannot read"
chmod 600 "$AUTH_DIR/unreadable"
assert_eq "A10 invalid base64 salt refused" "2" "$(bad_auth badb64 "ipad:pbkdf2_sha256\$$IT\$!!!\$$DG")"
assert_eq "A10 salt under 16 bytes refused" "2" "$(bad_auth shortsalt "ipad:pbkdf2_sha256\$$IT\$$(printf 'abcd' | base64)\$$DG")"
assert_eq "A10 digest not 32 bytes refused" "2" "$(bad_auth shortdigest "ipad:pbkdf2_sha256\$$IT\$$SALT\$$(printf 'abcd' | base64)")"
assert_eq "A10 empty user refused" "2" "$(bad_auth emptyuser ":pbkdf2_sha256\$$IT\$$SALT\$$DG")"
assert_eq "A10 extra field refused" "2" "$(bad_auth extrafield "ipad:pbkdf2_sha256\$$IT\$$SALT\$$DG\$x")"
assert_eq "A10 other scheme refused" "2" "$(bad_auth sha1 "ipad:pbkdf2_sha1\$$IT\$$SALT\$$DG")"
assert_eq "A10 non-integer iterations refused" "2" "$(bad_auth nonint "ipad:pbkdf2_sha256\$lots\$$SALT\$$DG")"
assert_eq "A10 two records refused" "2" "$(bad_auth tworec "$(cat "$AUTH_FILE")
other:pbkdf2_sha256\$$IT\$$SALT\$$DG")"
assert_eq "A10 no Traceback in any refusal" "0" "$(grep -c Traceback "$FIXTURE_DIR/refused.log" || true)"

echo ""
echo "[A11] malformed or wrong Authorization headers are 401 (never 200, never a crash); the right one still works afterwards"
# Two servers, each kept under the 5-failure lockout, so every answer
# below is the auth decision itself rather than a 429.
P11A="$(free_port)"; TEST_PORTS+=("$P11A")
start_policy_server "$P11A" WAIO_DASHBOARD_BIND=127.0.0.1 WAIO_DASHBOARD_AUTH_FILE="$AUTH_FILE" WAIO_DASHBOARD_ALLOWED_CLIENTS=127.0.0.1/32
P11B="$(free_port)"; TEST_PORTS+=("$P11B")
start_policy_server "$P11B" WAIO_DASHBOARD_BIND=127.0.0.1 WAIO_DASHBOARD_AUTH_FILE="$AUTH_FILE" WAIO_DASHBOARD_ALLOWED_CLIENTS=127.0.0.1/32
hdr_code() { curl -s -o /dev/null -w '%{http_code}' --max-time 3 -H "Authorization: $2" "http://127.0.0.1:$1/"; }
if wait_listening "$P11B" && curl -s -o /dev/null --max-time 2 "http://127.0.0.1:$P11A/"; then
  assert_eq "A11 Bearer scheme -> 401" "401" "$(hdr_code "$P11A" "Bearer abc")"
  assert_eq "A11 'Basic' with no credentials -> 401" "401" "$(hdr_code "$P11A" "Basic")"
  assert_eq "A11 invalid base64 -> 401" "401" "$(hdr_code "$P11A" "Basic !!!")"
  assert_eq "A11 no ':' separator -> 401" "401" "$(hdr_code "$P11A" "Basic $(printf 'ipadonly' | base64)")"
  assert_eq "A11 non-UTF-8 credentials -> 401" "401" "$(hdr_code "$P11B" "Basic $(printf '\377\376:\377' | base64)")"
  assert_eq "A11 empty password -> 401" "401" "$(hdr_code "$P11B" "Basic $(printf 'ipad:' | base64)")"
  assert_eq "A11 lowercase 'basic' scheme is not accepted -> 401" "401" "$(hdr_code "$P11B" "basic $(printf 'ipad:%s' "$TEST_PW" | base64)")"
  assert_eq "A11 correct credentials still -> 200 after malformed ones" "200" "$(hdr_code "$P11B" "Basic $(printf 'ipad:%s' "$TEST_PW" | base64)")"
  assert_eq "A11 no Traceback in either server log" "0" "$(cat "$FIXTURE_DIR/server-$P11A.log" "$FIXTURE_DIR/server-$P11B.log" | grep -c Traceback || true)"
  assert_eq "A11 test password never in either server log" "0" "$(cat "$FIXTURE_DIR/server-$P11A.log" "$FIXTURE_DIR/server-$P11B.log" | grep -c -- "$TEST_PW" || true)"
else
  FAIL=$((FAIL + 1)); FAILURES+=("A11 servers did not start"); echo "  FAIL: A11 servers did not start"
fi

echo ""
echo "[A12] non-GET methods: a client outside the allowlist gets 403 (same as GET), an allowlisted client gets 405 -- never 200, never a body"
if [ -n "${P7:-}" ]; then
  for m in POST PUT DELETE HEAD PATCH OPTIONS; do
    assert_eq "A12 $m from a non-allowlisted client -> 403" "403" "$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 -X "$m" "http://127.0.0.1:$P7/")"
  done
fi
OUT="$(curl -s -D - --max-time 3 -X POST "http://127.0.0.1:$P11B/")"
assert_contains "A12 POST from an allowlisted client -> 405" "$OUT" "405"
assert_contains "A12 405 carries no body" "$OUT" "Content-Length: 0"

echo ""
echo "[A13] allowlist 127.0.0.1/32 on a loopback bind with no auth file: allowlisted client is served without a login; the policy for a valid 0.0.0.0 config is accepted (unit, no socket)"
P13="$(free_port)"; TEST_PORTS+=("$P13")
start_policy_server "$P13" WAIO_DASHBOARD_BIND=127.0.0.1 WAIO_DASHBOARD_ALLOWED_CLIENTS=127.0.0.1/32
if wait_listening "$P13"; then
  assert_eq "A13 allowlist-only loopback server -> 200 without credentials" "200" "$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "http://127.0.0.1:$P13/")"
  assert_contains "A13 startup line shows auth=off" "$(cat "$FIXTURE_DIR/server-$P13.log")" "auth=off clients=127.0.0.1/32"
else
  FAIL=$((FAIL + 1)); FAILURES+=("A13 server did not start"); echo "  FAIL: A13 server did not start"
fi
assert_eq "A13 build_policy accepts 0.0.0.0 + valid auth + LAN allowlist" "ipad 192.168.1.0/24" "$(python3 - "$AUTH_FILE" <<'PYEOF'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("sd", "dashboard/serve_dashboard.py")
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
p = m.build_policy("0.0.0.0", sys.argv[1], "192.168.1.0/24")
print(p["auth"][0], ",".join(str(n) for n in p["clients"]))
PYEOF
)"

echo ""
echo "[A14] credential helper: refuses unsafe usernames and a pre-existing tmp path (no symlink is followed), leaves an existing dir's mode alone, never prints the password"
OUT="$(printf '%s\n' "$TEST_PW" | python3 ./dashboard/set_dashboard_auth.py --user ipad --out "$AUTH_DIR/again" --password-stdin 2>&1)"
assert_eq "A14 helper output never contains the password" "0" "$(printf '%s' "$OUT" | grep -c -- "$TEST_PW" || true)"
printf '%s\n' "$TEST_PW" | python3 ./dashboard/set_dashboard_auth.py --user "$(printf 'ip\nad')" --out "$AUTH_DIR/nluser" --password-stdin >/dev/null 2>&1
assert_eq "A14 username with a newline refused" "false" "$([ -e "$AUTH_DIR/nluser" ] && echo true || echo false)"
printf '%s\n' "$TEST_PW" | python3 ./dashboard/set_dashboard_auth.py --user "ip:ad" --out "$AUTH_DIR/coluser" --password-stdin >/dev/null 2>&1
assert_eq "A14 username with ':' refused" "false" "$([ -e "$AUTH_DIR/coluser" ] && echo true || echo false)"
mkdir -m 700 "$AUTH_DIR/symdir"
echo "victim-content" > "$FIXTURE_DIR/victim"; chmod 644 "$FIXTURE_DIR/victim"
ln -s "$FIXTURE_DIR/victim" "$AUTH_DIR/symdir/auth.tmp"
printf '%s\n' "$TEST_PW" | python3 ./dashboard/set_dashboard_auth.py --user ipad --out "$AUTH_DIR/symdir/auth" --password-stdin >/dev/null 2>&1
assert_eq "A14 planted tmp symlink: helper exits non-zero" "1" "$?"
assert_eq "A14 planted tmp symlink: target content untouched" "victim-content" "$(cat "$FIXTURE_DIR/victim")"
assert_eq "A14 planted tmp symlink: target mode untouched" "644" "$(file_mode "$FIXTURE_DIR/victim")"
assert_eq "A14 planted tmp symlink: no credential file written" "false" "$([ -e "$AUTH_DIR/symdir/auth" ] && echo true || echo false)"
mkdir -m 755 "$AUTH_DIR/opendir"
printf '%s\n' "$TEST_PW" | python3 ./dashboard/set_dashboard_auth.py --user ipad --out "$AUTH_DIR/opendir/auth" --password-stdin >/dev/null 2>&1
assert_eq "A14 existing directory keeps its own mode (documented)" "755" "$(file_mode "$AUTH_DIR/opendir")"
assert_eq "A14 file in an existing directory is still 0600" "600" "$(file_mode "$AUTH_DIR/opendir/auth")"
assert_eq "A14 no tmp file left behind" "false" "$([ -e "$AUTH_DIR/opendir/auth.tmp" ] && echo true || echo false)"

echo ""
echo "[A16] iPad access (docs/IPAD_PRO_ACCESS.md): EVERY allowlisted route, with an iPad Safari user agent -- 401 + Basic challenge without credentials, 200 + no-store with them, never a cookie; and 403 on every route for a client outside the allowlist"
IPAD_UA="Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1"
ROUTES="$(python3 -c 'import sys; sys.path.insert(0, "dashboard"); import serve_dashboard as s; print(" ".join(sorted(s.ALLOWLIST)))')"
assert_eq "A16 route list read from the module's own ALLOWLIST (10 routes)" "10" "$(echo "$ROUTES" | wc -w | tr -d ' ')"
P15="$(free_port)"; TEST_PORTS+=("$P15")
start_policy_server "$P15" WAIO_DASHBOARD_BIND=127.0.0.1 WAIO_DASHBOARD_AUTH_FILE="$AUTH_FILE" WAIO_DASHBOARD_ALLOWED_CLIENTS=127.0.0.1/32
if wait_listening "$P15"; then
  B15="http://127.0.0.1:$P15"
  bad=""; for r in $ROUTES; do
    h="$(curl -s -D - -o /dev/null --max-time 3 -A "$IPAD_UA" "$B15$r")"
    case "$h" in *" 401 "*) ;; *) bad="$bad $r(no401)";; esac
    case "$h" in *'WWW-Authenticate: Basic realm="WAIO Dashboard"'*) ;; *) bad="$bad $r(nochallenge)";; esac
  done
  assert_eq "A16 no credentials: every route 401 with a Basic challenge (what makes Safari prompt)" "" "$bad"
  bad=""; for r in $ROUTES; do
    h="$(curl -s -D - -o /dev/null --max-time 5 -A "$IPAD_UA" -u "ipad:$TEST_PW" "$B15$r?t=1")"
    case "$h" in *" 200 "*) ;; *) bad="$bad $r(no200)";; esac
    case "$h" in *"Cache-Control: no-store"*) ;; *) bad="$bad $r(cacheable)";; esac
  done
  assert_eq "A16 right credentials: every route 200 and Cache-Control: no-store (nothing left in the iPad's cache)" "" "$bad"
  assert_eq "A16 wrong password on a JSON route -> 401" "401" "$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 -A "$IPAD_UA" -u "ipad:not-it" "$B15/logs/decision-status-latest.json")"
  assert_eq "A16 no response sets a cookie (no session token exists to leak or expire)" "0" \
    "$(for r in $ROUTES; do curl -s -D - -o /dev/null --max-time 3 -A "$IPAD_UA" "$B15$r"; curl -s -D - -o /dev/null --max-time 3 -A "$IPAD_UA" -u "ipad:$TEST_PW" "$B15$r"; done | grep -ci '^set-cookie' || true)"
  # 401s carry no Cache-Control; that is safe only because they carry no body
  bad=""; for r in $ROUTES; do
    n="$(curl -s --max-time 3 -A "$IPAD_UA" "$B15$r" | wc -c | tr -d ' ')"
    [ "$n" = "0" ] || bad="$bad $r(${n}B)"
  done
  assert_eq "A16 unauthenticated 401s have an empty body on every route (nothing to cache or leak)" "" "$bad"
  assert_eq "A16 the test password never appears in this server's log" "0" "$(grep -c -- "$TEST_PW" "$FIXTURE_DIR/server-$P15.log" || true)"
else
  FAIL=$((FAIL + 1)); FAILURES+=("A16 server did not start"); echo "  FAIL: A16 server did not start"
fi
P15b="$(free_port)"; TEST_PORTS+=("$P15b")
start_policy_server "$P15b" WAIO_DASHBOARD_BIND=127.0.0.1 WAIO_DASHBOARD_AUTH_FILE="$AUTH_FILE" WAIO_DASHBOARD_ALLOWED_CLIENTS=192.168.1.0/24
sleep 1
bad=""; for r in $ROUTES; do
  c="$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 -A "$IPAD_UA" -u "ipad:$TEST_PW" "http://127.0.0.1:$P15b$r")"
  [ "$c" = "403" ] || bad="$bad $r($c)"
done
assert_eq "A16 client outside the allowlist: every route 403, even with the right password" "" "$bad"
bad=""; for r in $ROUTES; do
  h="$(curl -s -D - -o "$FIXTURE_DIR/a15b-body" --max-time 3 -A "$IPAD_UA" -u "ipad:$TEST_PW" "http://127.0.0.1:$P15b$r")"
  [ -s "$FIXTURE_DIR/a15b-body" ] && bad="$bad $r(body)"
  case "$h" in *[Ss]et-[Cc]ookie*) bad="$bad $r(cookie)";; esac
  case "$h" in *WWW-Authenticate*) bad="$bad $r(challenge)";; esac
done
assert_eq "A16 403s: empty body, no cookie, and no login prompt (the client is refused before auth)" "" "$bad"
assert_eq "A16 the test password never appears in the 403 server's log" "0" "$(grep -c -- "$TEST_PW" "$FIXTURE_DIR/server-$P15b.log" || true)"

echo ""
echo "[A9] default loopback server (no auth configured) still serves loopback clients unchanged -- the I-series above ran against it"
assert_contains "A9 the I-series server's startup line shows auth=off, loopback-only clients" "$(cat "$FIXTURE_DIR/server.log")" "auth=off clients=127.0.0.0/8,::1/128"

echo ""
echo "=== C-series: test cleanup can never terminate the production dashboard ==="

echo ""
echo "[C1] static: no test script kills processes by name or pattern (pkill/killall), anywhere under tests/"
cnt=0
for f in tests/*.sh; do
  c="$(code_only "$f" | grep -cE '(^|[;&|(`]|[[:space:]])(pkill|killall)[[:space:]]+[-"'"'"'$[:alnum:]]' || true)"
  [ "$c" -gt 0 ] && echo "    found in $f"
  cnt=$((cnt + c))
done
assert_eq "C1 zero pkill/killall invocations in tests/*.sh" "0" "$cnt"

echo ""
echo "[C2] dynamic: a decoy whose command line contains 'dashboard/serve_dashboard.py' (exactly what the live LaunchAgent's command line contains) survives stop_tracked, while the tracked test server is stopped"
# The decoy is started in a subshell and disowned from this shell's job
# table, so it is NOT a direct child -- same relationship as the real
# launchd-owned service.
DECOY_MARK="/decoy/WAIO-$$/dashboard/serve_dashboard.py"
DECOY_PID="$( (bash -c 'exec -a "python3 $1" sleep 120' _ "$DECOY_MARK" >/dev/null 2>&1 & echo $!) )"
PC="$(free_port)"; TEST_PORTS+=("$PC")
start_policy_server "$PC" WAIO_DASHBOARD_BIND=127.0.0.1
C2_SERVER_PID="${EXTRA_PIDS[${#EXTRA_PIDS[@]}-1]}"
wait_listening "$PC" || true
PROD_BEFORE="$(lsof -tiTCP:8000 -sTCP:LISTEN 2>/dev/null | head -1)"
assert_contains "C2 sanity: a 'dashboard/serve_dashboard.py' pattern match finds the decoy (as it would the live service)" " $(pgrep -f "$DECOY_MARK" | tr '\n' ' ') " " $DECOY_PID "
stop_tracked "$C2_SERVER_PID" "$DECOY_PID"
assert_eq "C2 tracked test server stopped" "dead" "$(kill -0 "$C2_SERVER_PID" 2>/dev/null && echo alive || echo dead)"
assert_eq "C2 decoy (not a child of this shell) still running" "alive" "$(kill -0 "$DECOY_PID" 2>/dev/null && echo alive || echo dead)"
PROD_AFTER="$(lsof -tiTCP:8000 -sTCP:LISTEN 2>/dev/null | head -1)"
assert_eq "C2 whatever owns port 8000 (the live service, if any) has the same PID before and after" "$PROD_BEFORE" "$PROD_AFTER"
# The decoy is this suite's own process: stop it by its exact PID after
# re-checking that PID still carries this run's unique decoy marker.
case " $(pgrep -f "$DECOY_MARK" | tr '\n' ' ') " in
  *" $DECOY_PID "*) kill "$DECOY_PID" 2>/dev/null ;;
esac

echo ""
echo "[C3] leak check: stop_tracked really stops every server this suite started (a cleanup that silently skips kills -- as a ps-based check did under sandbox-exec -- fails here)"
stop_tracked "$SERVER_PID" "${EXTRA_PIDS[@]}"
alive=0
for pid in "$SERVER_PID" "${EXTRA_PIDS[@]}"; do
  kill -0 "$pid" 2>/dev/null && alive=$((alive + 1))
done
assert_eq "C3 zero suite-started servers still running" "0" "$alive"
open=0
for port in "${TEST_PORTS[@]}"; do
  [ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 1 "http://127.0.0.1:$port/" 2>/dev/null)" != "000" ] && open=$((open + 1))
done
assert_eq "C3 every test port is closed again" "0" "$open"

echo ""
echo "=== Summary: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
  echo "Failures:"
  for f in "${FAILURES[@]}"; do echo "  - $f"; done
  exit 1
fi
exit 0
