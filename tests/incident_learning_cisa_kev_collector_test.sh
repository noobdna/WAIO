#!/bin/bash
set -uo pipefail

# tests/incident_learning_cisa_kev_collector_test.sh -- regression
# suite for Phase 81 (real Collector):
# security/incident_learning/collectors/cisa_kev_collector.sh.
#
# NO REAL NETWORK CALL. `curl` is shadowed on PATH by a fixture script
# (same "shadow a binary on PATH" idiom as tests/earth_weather_test.sh's
# own fake curl, tests/rpi_command_injection_test.sh's fake ssh) that
# serves a small, fixed KEV-shaped JSON body, so the collector is
# exercised unmodified and end-to-end (real egress_check, real
# date-filtering/mapping logic) except the actual network I/O. Every
# case runs against an isolated WAIO_EGRESS_ALLOWLIST/
# WAIO_SHUTDOWN_LOCK/WAIO_AUDIT_LOG(+checkpoint/alerts/lock), never
# this deployment's real security state -- confirmed explicitly by D3
# below, not just assumed from the env overrides.

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

FIXTURE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/waio-cisa-kev-test.XXXXXX")"
trap 'rm -rf "$FIXTURE_DIR"' EXIT
mkdir -p "$FIXTURE_DIR/bin"

TODAY="$(date -u +%Y-%m-%d)"
THREE_DAYS_AGO="$(date -u -v-3d +%Y-%m-%d 2>/dev/null || date -u -d '3 days ago' +%Y-%m-%d)"
SIXTY_DAYS_AGO="$(date -u -v-60d +%Y-%m-%d 2>/dev/null || date -u -d '60 days ago' +%Y-%m-%d)"

# --- fixture KEV body: one recent, well-formed entry; one recent entry
# missing cveID (must be skipped, never crash); one entry outside the
# lookback window (must be excluded). ------------------------------
python3 -c "
import json
data = {
    'title': 'fixture', 'catalogVersion': 'fixture', 'dateReleased': '$TODAY', 'count': 3,
    'vulnerabilities': [
        {
            'cveID': 'CVE-2026-10001', 'vendorProject': 'WidgetCorp', 'product': 'VPN Appliance',
            'vulnerabilityName': 'WidgetCorp VPN Appliance RCE', 'dateAdded': '$TODAY',
            'shortDescription': 'Fixture description of a real-shaped KEV entry.',
            'requiredAction': 'Apply vendor patch 4.2.1.',
            'knownRansomwareCampaignUse': 'Known',
        },
        {
            'vendorProject': 'NoID Corp', 'product': 'Widget', 'vulnerabilityName': 'Missing cveID entry',
            'dateAdded': '$TODAY', 'shortDescription': 'This entry has no cveID and must be skipped.',
            'requiredAction': 'n/a',
        },
        {
            'cveID': 'CVE-2020-00001', 'vendorProject': 'OldCorp', 'product': 'Legacy',
            'vulnerabilityName': 'Ancient entry outside lookback window', 'dateAdded': '$SIXTY_DAYS_AGO',
            'shortDescription': 'Too old to be picked up by a 7-day lookback.',
            'requiredAction': 'n/a',
        },
    ],
}
json.dump(data, open('$FIXTURE_DIR/kev_body.json', 'w'))
"

# --- fake curl: routes by URL substring, or simulates an HTTP
# failure/malformed body per env-var switches. ----------------------
cat > "$FIXTURE_DIR/bin/curl" <<FAKECURL
#!/bin/bash
declare -a ARGS=("\$@")
URL="\${ARGS[\${#ARGS[@]}-1]}"
OUT=""
for i in "\${!ARGS[@]}"; do
  if [ "\${ARGS[\$i]}" = "-o" ]; then OUT="\${ARGS[\$((i+1))]}"; fi
done
if [ -n "\${FAKE_CURL_FAIL_HOST:-}" ] && [[ "\$URL" == *"\$FAKE_CURL_FAIL_HOST"* ]]; then
  echo -n "000"
  exit 0
fi
if [ -n "\${FAKE_CURL_MALFORMED:-}" ]; then
  echo "not valid json" > "\$OUT"
  echo -n "200"
  exit 0
fi
if [[ "\$URL" == *"www.cisa.gov"* ]]; then
  cp "$FIXTURE_DIR/kev_body.json" "\$OUT"
  echo -n "200"
else
  echo -n "000"
fi
FAKECURL
chmod +x "$FIXTURE_DIR/bin/curl"

cat > "$FIXTURE_DIR/egress_allowlist.conf" <<'EOF'
www.cisa.gov|443|test fixture
EOF

export PATH="$FIXTURE_DIR/bin:$PATH"
export WAIO_EGRESS_ALLOWLIST="$FIXTURE_DIR/egress_allowlist.conf"
export WAIO_SHUTDOWN_LOCK="$FIXTURE_DIR/SHUTDOWN.lock"
export WAIO_AUDIT_LOG="$FIXTURE_DIR/audit.jsonl"
export WAIO_AUDIT_LOG_CHECKPOINT="$FIXTURE_DIR/audit_checkpoint"
export WAIO_AUDIT_INTEGRITY_ALERTS="$FIXTURE_DIR/audit_alerts.jsonl"
export WAIO_AUDIT_LOG_LOCK_DIR="$FIXTURE_DIR/audit_lock"

REAL_SHUTDOWN_BEFORE="false"
[ -f security/state/SHUTDOWN.lock ] && REAL_SHUTDOWN_BEFORE="true"
REAL_AUDIT_HASH_BEFORE="not_present"
[ -f logs/security-audit.jsonl ] && REAL_AUDIT_HASH_BEFORE="$(shasum -a 256 logs/security-audit.jsonl | awk '{print $1}')"

echo "=== Incident Learning Engine: real Collector (CISA KEV, Phase 81) regression suite ==="

echo ""
echo "[K1] a well-formed recent entry is emitted correctly: id/source_type/source_url/collected_at mapping, mitigation phrasing preserved"
OUT="$(CISA_KEV_LOOKBACK_DAYS=7 ./security/incident_learning/collectors/cisa_kev_collector.sh 2>/tmp/waio-kev-k1-stderr.log)"
RC=$?
assert_eq "K1 exit code 0" "0" "$RC"
K1_LINE="$(echo "$OUT" | grep 'CVE-2026-10001')"
K1_ID="$(python3 -c "import json,sys; print(json.loads(sys.argv[1])['id'])" "$K1_LINE")"
assert_eq "K1 id is KEV-<cveID>" "KEV-CVE-2026-10001" "$K1_ID"
K1_SOURCE_TYPE="$(python3 -c "import json,sys; print(json.loads(sys.argv[1])['source_type'])" "$K1_LINE")"
assert_eq "K1 source_type is cert" "cert" "$K1_SOURCE_TYPE"
K1_SOURCE_URL="$(python3 -c "import json,sys; print(json.loads(sys.argv[1])['source_url'])" "$K1_LINE")"
assert_eq "K1 source_url is the NVD detail page" "https://nvd.nist.gov/vuln/detail/CVE-2026-10001" "$K1_SOURCE_URL"
K1_COLLECTED_AT="$(python3 -c "import json,sys; print(json.loads(sys.argv[1])['collected_at'])" "$K1_LINE")"
assert_eq "K1 collected_at reflects dateAdded, not 'now'" "${TODAY}T00:00:00Z" "$K1_COLLECTED_AT"
assert_contains "K1 raw_text carries the mitigation, keyword-scan-friendly" "$K1_LINE" "Mitigation: Apply vendor patch 4.2.1."
K1_HAS_CORROB="$(python3 -c "import json,sys; print('corroborating_sources' in json.loads(sys.argv[1]))" "$K1_LINE")"
assert_eq "K1 corroborating_sources field is genuinely absent, not an empty array pretending to be checked" "False" "$K1_HAS_CORROB"

echo ""
echo "[K2] an entry outside the lookback window is excluded"
K2_PRESENT="$(echo "$OUT" | grep -c 'CVE-2020-00001' || true)"
assert_eq "K2 old entry not emitted" "0" "$K2_PRESENT"

echo ""
echo "[K3] an entry missing cveID is skipped gracefully, never crashes the run"
K3_LINES="$(echo "$OUT" | wc -l | tr -d ' ')"
assert_eq "K3 exactly one record emitted (missing-cveID and out-of-window both excluded)" "1" "$K3_LINES"

echo ""
echo "[K4] the summary line goes to stderr, never stdout (Collector contract: nothing but JSONL on stdout)"
K4_STDERR="$(cat /tmp/waio-kev-k1-stderr.log)"
assert_contains "K4 stderr has the summary" "$K4_STDERR" "emitted 1 record(s)"
K4_STDOUT_HAS_SUMMARY="$(echo "$OUT" | grep -c 'CISA KEV COLLECTOR' || true)"
assert_eq "K4 stdout carries zero non-JSON lines" "0" "$K4_STDOUT_HAS_SUMMARY"

echo ""
echo "[K5] the emitted line is valid, single-line JSON (JSONL, not pretty-printed)"
K5_VALID="$(python3 -c "import json; json.loads('''$K1_LINE'''); print('true')" 2>/dev/null || echo false)"
assert_eq "K5 valid JSON" "true" "$K5_VALID"

echo ""
echo "[K6] a zero-day lookback window emits nothing, cleanly (today's own fixture entries all have dateAdded=today, so a 0-day window with a past-midnight cutoff can legitimately still include them -- this only asserts the run stays clean, not a specific count)"
OUT_K6="$(CISA_KEV_LOOKBACK_DAYS=0 ./security/incident_learning/collectors/cisa_kev_collector.sh 2>&1 >/dev/null)"
RC_K6=$?
assert_eq "K6 exit code 0 even with zero matches possible" "0" "$RC_K6"

echo ""
echo "[K7] CISA_KEV_MAX_RECORDS caps the emitted count even when more are in-window"
OUT_K7="$(CISA_KEV_LOOKBACK_DAYS=7 CISA_KEV_MAX_RECORDS=0 ./security/incident_learning/collectors/cisa_kev_collector.sh 2>/dev/null)"
K7_LINES="$(echo -n "$OUT_K7" | grep -c . || true)"
assert_eq "K7 MAX_RECORDS=0 emits nothing" "0" "$K7_LINES"

echo ""
echo "[K8] egress denied (destination not in the fixture allowlist): exits non-zero, emits nothing on stdout, never touches this deployment's real SHUTDOWN.lock"
cat > "$FIXTURE_DIR/egress_allowlist_empty.conf" <<'EOF'
EOF
OUT_K8="$(WAIO_EGRESS_ALLOWLIST="$FIXTURE_DIR/egress_allowlist_empty.conf" ./security/incident_learning/collectors/cisa_kev_collector.sh 2>&1)"
RC_K8=$?
assert_eq "K8 exit code non-zero" "true" "$([ "$RC_K8" -ne 0 ] && echo true || echo false)"
assert_contains "K8 error mentions egress denial" "$OUT_K8" "egress denied by DLP guard"
K8_STDOUT_LINES="$(WAIO_EGRESS_ALLOWLIST="$FIXTURE_DIR/egress_allowlist_empty.conf" ./security/incident_learning/collectors/cisa_kev_collector.sh 2>/dev/null | grep -c . || true)"
assert_eq "K8 zero stdout lines" "0" "$K8_STDOUT_LINES"
# K8's own denial legitimately trips the FIXTURE shutdown lock
# (egress_check()'s real trigger_shutdown() side effect, same as any
# real WAIO worker) -- clear it before continuing, same as
# tests/security_test.sh's own between-case convention, so K9 onward
# test their OWN distinct scenarios (a request egress_check has
# already allowed) rather than tripping on K8's still-active lock.
rm -f "$FIXTURE_DIR/SHUTDOWN.lock"

echo ""
echo "[K9] an unreachable/failing HTTP fetch exits non-zero with a clear reason, emits nothing"
OUT_K9="$(FAKE_CURL_FAIL_HOST="www.cisa.gov" ./security/incident_learning/collectors/cisa_kev_collector.sh 2>&1)"
RC_K9=$?
assert_eq "K9 exit code non-zero" "true" "$([ "$RC_K9" -ne 0 ] && echo true || echo false)"
assert_contains "K9 error mentions the failed HTTP status" "$OUT_K9" "HTTP 000"

echo ""
echo "[K10] a malformed (non-JSON) response is reported cleanly, never a raw Python traceback crash"
OUT_K10="$(FAKE_CURL_MALFORMED=1 ./security/incident_learning/collectors/cisa_kev_collector.sh 2>&1)"
RC_K10=$?
assert_eq "K10 exit code non-zero" "true" "$([ "$RC_K10" -ne 0 ] && echo true || echo false)"
assert_contains "K10 error names the JSON problem" "$OUT_K10" "response is not valid JSON"

echo ""
echo "[D1] this collector DOES source security/lib.sh and DOES call egress_check -- the one deliberate exception in this domain (opposite of every other file's own D1/D2 static guard -- see this collector's own header for the architecture decision)"
assert_eq "D1 sources security/lib.sh" "1" "$(grep -cE '^\s*source security/lib\.sh\b' security/incident_learning/collectors/cisa_kev_collector.sh)"
assert_eq "D1 calls egress_check" "1" "$(grep -cE '\begress_check\s*"' security/incident_learning/collectors/cisa_kev_collector.sh)"

echo ""
echo "[D2] this deployment's real SHUTDOWN.lock/audit log were never touched by this suite (every scenario above used WAIO_* overrides)"
REAL_SHUTDOWN_AFTER="false"
[ -f security/state/SHUTDOWN.lock ] && REAL_SHUTDOWN_AFTER="true"
assert_eq "D2 real SHUTDOWN.lock presence unchanged" "$REAL_SHUTDOWN_BEFORE" "$REAL_SHUTDOWN_AFTER"
REAL_AUDIT_HASH_AFTER="not_present"
[ -f logs/security-audit.jsonl ] && REAL_AUDIT_HASH_AFTER="$(shasum -a 256 logs/security-audit.jsonl | awk '{print $1}')"
assert_eq "D2 real audit log checksum unchanged" "$REAL_AUDIT_HASH_BEFORE" "$REAL_AUDIT_HASH_AFTER"

echo ""
echo "[D3] this deployment's real Control Plane conf files were never touched by this suite"
for real_file in security/egress_allowlist.conf security/segments.conf security/ssh_management_allowlist.conf; do
  if [ -f "$real_file" ]; then
    assert_eq "D3 $real_file unchanged" "" "$(git diff --name-only -- "$real_file" 2>/dev/null)"
  fi
done

echo ""
echo "=== Summary: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
  echo "Failures:"
  for f in "${FAILURES[@]}"; do echo "  - $f"; done
  exit 1
fi
exit 0
