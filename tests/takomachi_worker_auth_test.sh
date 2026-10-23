#!/bin/bash
set -uo pipefail

# tests/takomachi_worker_auth_test.sh -- how the four Takomachi workers
# (research/analysis/ai/healthcheck) send TAKOMACHI_API_KEY:
#   W1  the key reaches Takomachi as an Authorization: Bearer header on
#       stdin (-H @-) and never appears in curl's argv (readable by every
#       local user via ps);
#   W2  every curl call is pinned to http/https with redirects disabled;
#   W3  a key containing CR/LF or another control character is refused
#       before any header is built: no curl call, key never echoed.
# Fully isolated via tests/lib/test_isolation.sh: every security/lib.sh
# path is a temp path, HOME is empty, and `security` (Keychain) and
# `curl` are recording stubs -- no real Keychain read, no network.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"
# shellcheck source=tests/lib/test_isolation.sh
source tests/lib/test_isolation.sh

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
assert_not_contains() {
  local label="$1" haystack="$2" needle="$3"
  case "$haystack" in
    *"$needle"*) FAIL=$((FAIL + 1)); FAILURES+=("$label (found '$needle')"); echo "  FAIL: $label (found '$needle')" ;;
    *) PASS=$((PASS + 1)); echo "  PASS: $label" ;;
  esac
}

waio_test_isolate takomachi-worker-auth || exit 3
trap waio_test_cleanup EXIT
waio_test_assert_isolated || { echo "ABORT: test isolation could not be guaranteed" >&2; exit 3; }

STUB="$WAIO_TEST_ROOT/workerstubs"
mkdir -p "$STUB"
# `security find-generic-password ... -w` prints $STUB_KEY (from a file,
# so it may hold CR/LF).
cat > "$STUB/security" <<EOF
#!/bin/bash
cat "$STUB/key"
EOF
# curl stub: records argv (one line per call) and stdin, answers like a
# minimal Takomachi: POST /tasks -> 201 {id}, GET /tasks/ID -> 200
# completed, GET /health -> 200.
cat > "$STUB/curl" <<EOF
#!/bin/bash
printf '%s\n' "\$*" >> "$STUB/argv.log"
cat >> "$STUB/stdin.log"
out="" url="" method="GET"
while [ \$# -gt 0 ]; do
  case "\$1" in
    -o) out="\$2"; shift ;;
    -X) method="\$2"; shift ;;
    http*) url="\$1" ;;
  esac
  shift
done
case "\$method \$url" in
  "POST "*/tasks) printf '{"id":"t1"}' > "\$out"; printf 201 ;;
  "GET "*/tasks/t1) printf '{"status":"completed","result":{"content":"ok"}}' > "\$out"; printf 200 ;;
  "GET "*/health) printf '{"agent_manager":{"status":"ok"}}' > "\$out"; printf 200 ;;
  *) printf 404 ;;
esac
EOF
chmod +x "$STUB/security" "$STUB/curl"
export PATH="$STUB:$PATH"

reset_logs() { : > "$STUB/argv.log"; : > "$STUB/stdin.log"; }

echo "=== Takomachi worker auth suite ==="

for w in research analysis ai healthcheck; do
  echo ""
  echo "[W1/W2] $w worker: key on stdin, not argv; curl pinned to http(s), no redirects"
  printf 'wk-secret-key-123' > "$STUB/key"
  reset_logs
  OUT="$(./workers/${w}_worker.sh "hello" 2>&1)"
  RC=$?
  assert_eq "W1 $w exit 0" "0" "$RC"
  CALLS="$(wc -l < "$STUB/argv.log" | tr -d ' ')"
  [ "$CALLS" -ge 1 ] && assert_eq "W1 $w curl called" "yes" "yes" || assert_eq "W1 $w curl called" "yes" "no"
  assert_not_contains "W1 $w key absent from curl argv" "$(cat "$STUB/argv.log")" "wk-secret-key-123"
  assert_eq "W1 $w every call sent the Bearer header on stdin" "$CALLS" "$(grep -c '^Authorization: Bearer wk-secret-key-123$' "$STUB/stdin.log")"
  assert_eq "W2 $w every call pinned to http/https" "$CALLS" "$(grep -c -- '--proto =http,https' "$STUB/argv.log")"
  assert_eq "W2 $w every call has redirects disabled" "$CALLS" "$(grep -c -- '--max-redirs 0' "$STUB/argv.log")"
  assert_not_contains "W1 $w key absent from output" "$OUT" "wk-secret-key-123"

  echo "[W3] $w worker: a key with CR/LF or TAB is refused before any header is built"
  for k in 'wk-crlf\r\nX-Injected: yes' 'wk-tab\tbad'; do
    printf "$k" > "$STUB/key"
    reset_logs
    OUT="$(./workers/${w}_worker.sh "hello" 2>&1)"
    RC=$?
    assert_eq "W3 $w exit 1" "1" "$RC"
    assert_eq "W3 $w no curl call made" "0" "$(wc -l < "$STUB/argv.log" | tr -d ' ')"
    assert_not_contains "W3 $w key absent from output" "$OUT" "wk-"
  done
done

echo ""
echo "[W4] the suite's own isolation held: no real privileged/network command was reached"
assert_eq "W4 isolation stubs for sudo/ssh/osascript never called" "0:0:0" "$(waio_test_stub_calls sudo):$(waio_test_stub_calls ssh):$(waio_test_stub_calls osascript)"

echo ""
echo "=== Summary: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
  echo "Failures:"
  for f in "${FAILURES[@]}"; do echo "  - $f"; done
  exit 1
fi
exit 0
