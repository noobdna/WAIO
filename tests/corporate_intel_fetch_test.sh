#!/bin/bash
set -uo pipefail

# tests/corporate_intel_fetch_test.sh -- the network boundary of
# security/corporate_intel/: ci_fetch.sh (and ci.py fetch --online on
# top of it).
#
# NO REAL NETWORK CALL: `curl` is a fixture script first on PATH that
# records its argv and serves synthetic bodies; egress_check() runs for
# real against an ISOLATED allowlist / SHUTDOWN.lock / audit log
# (tests/lib/test_isolation.sh), never this deployment's.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR" || exit 3

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
    FAIL=$((FAIL + 1)); FAILURES+=("$label (missing '$needle')")
    echo "  FAIL: $label (missing '$needle' in: $haystack)"
  fi
}

REAL_SHUTDOWN_BEFORE="$([ -f security/state/SHUTDOWN.lock ] && echo present || echo absent)"
REAL_AUDIT_SIZE_BEFORE="$([ -f logs/security-audit.jsonl ] && wc -c < logs/security-audit.jsonl | tr -d ' ' || echo 0)"
REAL_AUDIT_PREFIX_BEFORE="$([ -f logs/security-audit.jsonl ] && head -c "$REAL_AUDIT_SIZE_BEFORE" logs/security-audit.jsonl | shasum -a 256 | awk '{print $1}' || echo absent)"

# shellcheck source=tests/lib/test_isolation.sh
source tests/lib/test_isolation.sh
waio_test_isolate corporate-intel-fetch || exit 3
trap waio_test_cleanup EXIT
waio_test_assert_isolated || { echo "ABORT: test isolation could not be guaranteed" >&2; exit 3; }

M=security/corporate_intel
FX="$SCRIPT_DIR/$M/fixtures"
FAKE_BIN="$WAIO_TEST_ROOT/fakebin"
CURL_LOG="$WAIO_TEST_ROOT/curl-argv.log"
mkdir -p "$FAKE_BIN"
cat > "$FAKE_BIN/curl" <<FAKECURL
#!/bin/bash
printf '%s\n' "\$*" >> "$CURL_LOG"
declare -a A=("\$@"); URL="\${A[\${#A[@]}-1]}"; OUT=""
for i in "\${!A[@]}"; do [ "\${A[\$i]}" = "-o" ] && OUT="\${A[\$((i+1))]}"; done
case "\${FAKE_CURL_MODE:-ok}" in
  http500) echo "oops" > "\$OUT"; printf '500'; exit 0 ;;
  truncated) echo '{"vulnerab' > "\$OUT"; printf '200'; exit 63 ;;
  timeout) printf '000'; exit 28 ;;
esac
case "\$URL" in
  *www.cisa.gov*) cp "$FX/kev.json" "\$OUT" ;;
  *services.nvd.nist.gov*cveId=CVE-2026-1000[1-5]) cp "$FX/nvd/\${URL##*cveId=}.json" "\$OUT" ;;
  *api.first.org*) cp "$FX/epss.json" "\$OUT" ;;
  *) printf '404'; exit 0 ;;
esac
printf '200'
FAKECURL
chmod +x "$FAKE_BIN/curl"
export PATH="$FAKE_BIN:$PATH"
cat > "$WAIO_EGRESS_ALLOWLIST" <<'EOF'
www.cisa.gov|443|test fixture
services.nvd.nist.gov|443|test fixture
api.first.org|443|test fixture
EOF
export WAIO_CI_STATE_DIR="$WAIO_TEST_ROOT/state/corporate_intel"
export WAIO_CI_NVD_INTERVAL_S=0
OUTF="$WAIO_TEST_ROOT/out.json"
curl_calls() { [ -f "$CURL_LOG" ] && wc -l < "$CURL_LOG" | tr -d ' ' || echo 0; }

echo "=== WAIO Corporate Intelligence: fetch boundary suite ==="

echo ""
echo "[F1] offline by default: no WAIO_CI_ONLINE -> refused before any network code"
RC="$(bash $M/ci_fetch.sh kev "$OUTF" >/dev/null 2>&1; echo $?)"
assert_eq "F1 exit 3" "3" "$RC"
assert_eq "F1 curl never called" "0" "$(curl_calls)"

export WAIO_CI_ONLINE=1
echo ""
echo "[F2] input validation: bad ids / unknown source / arity are refused, curl never called"
for args in "nvd $OUTF CVE-2026-1;id" "nvd $OUTF CVE-2026-10001&apiKey=x" "nvd $OUTF ../../etc" \
            "nvd $OUTF" "nvd $OUTF CVE-2026-10001 CVE-2026-10002" "kev $OUTF CVE-2026-10001" \
            "evil $OUTF" "kev /nonexistent-dir/x.json"; do
  # shellcheck disable=SC2086
  RC="$(bash $M/ci_fetch.sh $args >/dev/null 2>&1; echo $?)"
  assert_eq "F2 refused: $args" "2" "$RC"
done
assert_eq "F2 curl never called" "0" "$(curl_calls)"

echo ""
echo "[F3] allowed fetch: fixed https URL, no redirects, no credentials, HTTP 200 -> exit 0"
NVD_API_KEY="CANARY-SECRET-ff00" STATUS="$(bash $M/ci_fetch.sh nvd "$OUTF" CVE-2026-10002 2>/dev/null)"
RC=$?
assert_eq "F3 exit 0" "0" "$RC"
assert_eq "F3 status 200" "200" "$STATUS"
ARGV="$(tail -1 "$CURL_LOG")"
assert_contains "F3 URL fixed" "$ARGV" "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-10002"
assert_contains "F3 https-only" "$ARGV" "--proto =https"
assert_contains "F3 size cap" "$ARGV" "--max-filesize 20971520"
assert_eq "F3 no redirect following" "0" "$(printf '%s' "$ARGV" | grep -cE '(^| )(-L|--location)( |$)' || true)"
assert_eq "F3 api key never sent" "0" "$(grep -c 'CANARY-SECRET-ff00' "$CURL_LOG" || true)"
bash $M/ci_fetch.sh epss "$OUTF" CVE-2026-10001 CVE-2026-10002 >/dev/null 2>&1
assert_contains "F3 epss batch URL" "$(tail -1 "$CURL_LOG")" "https://api.first.org/data/v1/epss?cve=CVE-2026-10001,CVE-2026-10002"

echo ""
echo "[F4] HTTP/curl failures -> exit 1 and no partial body left behind"
for mode in http500 truncated timeout; do
  rm -f "$OUTF"
  RC="$(FAKE_CURL_MODE=$mode bash $M/ci_fetch.sh kev "$OUTF" >/dev/null 2>&1; echo $?)"
  assert_eq "F4 $mode exit 1" "1" "$RC"
  assert_eq "F4 $mode body removed" "absent" "$([ -e "$OUTF" ] && echo present || echo absent)"
done

echo ""
echo "[F5] egress denied for a host missing from the allowlist: request never sent, fail-closed shutdown (isolated lock only)"
printf 'www.cisa.gov|443|test fixture\n' > "$WAIO_EGRESS_ALLOWLIST"
BEFORE="$(curl_calls)"
OUT5="$(bash $M/ci_fetch.sh nvd "$OUTF" CVE-2026-10001 2>&1)"
RC=$?
assert_eq "F5 exit 1" "1" "$RC"
assert_contains "F5 denial message" "$OUT5" "egress denied by DLP guard"
assert_eq "F5 curl not called" "$BEFORE" "$(curl_calls)"
assert_eq "F5 isolated SHUTDOWN.lock tripped" "present" "$([ -f "$WAIO_SHUTDOWN_LOCK" ] && echo present || echo absent)"
rm -f "$WAIO_SHUTDOWN_LOCK"
printf 'www.cisa.gov|443|t\nservices.nvd.nist.gov|443|t\napi.first.org|443|t\n' > "$WAIO_EGRESS_ALLOWLIST"

echo ""
echo "[F6] ci.py fetch --online end to end (fake curl): kev + nvd + epss ingested with provenance"
python3 $M/ci.py fetch --source kev --online 2>/dev/null; assert_eq "F6 kev rc" "0" "$?"
python3 $M/ci.py fetch --source nvd --online --cves-from-kev 3 2>/dev/null
RC=$?
# KEV holds 10001/10004/10006; the fake NVD has no 10006 body -> 404 -> that one id fails, others kept
assert_eq "F6 nvd rc (one id 404)" "2" "$RC"
FAILED_IDS="$(python3 -c 'import json,sys; print(",".join(json.load(open(sys.argv[1]))["failed_ids"]))' "$WAIO_CI_STATE_DIR/status/nvd.json")"
assert_eq "F6 nvd failed id recorded" "CVE-2026-10006" "$FAILED_IDS"
python3 $M/ci.py fetch --source epss --online --cve CVE-2026-10001 --cve CVE-2026-10004 2>/dev/null; assert_eq "F6 epss rc" "0" "$?"
PROV="$(python3 -c '
import json,sys
r=json.load(open(sys.argv[1]))["records"]["CVE-2026-10001"]["provenance"]
print(r["source"], r["identifier"], r["http_status"], bool(r["fetched_at"]), r["source_updated_at"], r["source_url"])' "$WAIO_CI_STATE_DIR/sources/nvd.json")"
assert_eq "F6 nvd provenance" "nvd CVE-2026-10001 200 True 2026-11-04T12:00:00Z https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-10001" "$PROV"

echo ""
echo "[F7] online fetch failure keeps the previous good data and marks the source stale"
SUM_BEFORE="$(shasum -a 256 "$WAIO_CI_STATE_DIR/sources/kev.json" | awk '{print $1}')"
FAKE_CURL_MODE=http500 python3 $M/ci.py fetch --source kev --online 2>/dev/null; RC=$?
assert_eq "F7 rc 2" "2" "$RC"
assert_eq "F7 kev data unchanged" "$SUM_BEFORE" "$(shasum -a 256 "$WAIO_CI_STATE_DIR/sources/kev.json" | awk '{print $1}')"
assert_eq "F7 kev stale" "True" "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["stale"])' "$WAIO_CI_STATE_DIR/status/kev.json")"

echo ""
echo "[F-D] this deployment's real security state untouched"
assert_eq "D1 real SHUTDOWN.lock unchanged" "$REAL_SHUTDOWN_BEFORE" "$([ -f security/state/SHUTDOWN.lock ] && echo present || echo absent)"
REAL_AUDIT_PREFIX_AFTER="$([ -f logs/security-audit.jsonl ] && head -c "$REAL_AUDIT_SIZE_BEFORE" logs/security-audit.jsonl | shasum -a 256 | awk '{print $1}' || echo absent)"
assert_eq "D2 real audit log prefix unchanged" "$REAL_AUDIT_PREFIX_BEFORE" "$REAL_AUDIT_PREFIX_AFTER"
assert_eq "D3 real audit log has no CORPORATE_INTEL entries from this run" "0" \
  "$([ -f logs/security-audit.jsonl ] && tail -c +"$((REAL_AUDIT_SIZE_BEFORE + 1))" logs/security-audit.jsonl | grep -c CORPORATE_INTEL || echo 0)"
assert_eq "D4 isolated audit log recorded the F5 denial" "true" "$(grep -q CORPORATE_INTEL_NVD "$WAIO_AUDIT_LOG" 2>/dev/null && echo true || echo false)"

echo ""
echo "=== Summary: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
  printf '  - %s\n' "${FAILURES[@]}"
  exit 1
fi
exit 0
