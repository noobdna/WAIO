#!/bin/bash
set -uo pipefail

# tests/incident_learning_cisa_advisories_collector_test.sh --
# regression suite for Phase 99 (real Collector):
# security/incident_learning/collectors/cisa_advisories_collector.sh.
#
# NO REAL NETWORK CALL. `curl` is shadowed on PATH by a fixture script
# (same idiom as tests/incident_learning_cisa_kev_collector_test.sh's
# own fake curl) that serves a small, fixed CISA-advisories-RSS-shaped
# body, so the collector is exercised unmodified and end-to-end (real
# egress_check, real date-filtering/parsing/HTML-stripping logic)
# except the actual network I/O. Every case runs against an isolated
# WAIO_EGRESS_ALLOWLIST/WAIO_SHUTDOWN_LOCK/WAIO_AUDIT_LOG(+checkpoint/
# alerts/lock), never this deployment's real security state --
# confirmed explicitly by D2/D3 below, not just assumed from the env
# overrides.

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

FIXTURE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/waio-cisa-advisories-test.XXXXXX")"
trap 'rm -rf "$FIXTURE_DIR"' EXIT
mkdir -p "$FIXTURE_DIR/bin"

TODAY_RFC="$(date -u +"%a, %d %b %Y %H:%M:%S +0000")"
SIXTY_DAYS_AGO_RFC="$(date -u -v-60d +"%a, %d %b %Y %H:%M:%S +0000" 2>/dev/null || date -u -d '60 days ago' +"%a, %d %b %Y %H:%M:%S +0000")"

# --- fixture CISA advisories RSS body: one recent, well-formed entry
# with a real CVE in its HTML description; one recent entry with an
# empty link (must be skipped, never crash); one entry outside the
# lookback window (must be excluded). -------------------------------
cat > "$FIXTURE_DIR/advisories.xml" <<EOF
<?xml version="1.0" encoding="utf-8"?>
<rss version="2.0"><channel>
<item>
  <title>Fixture Vendor Example Widget</title>
  <link>https://www.cisa.gov/news-events/ics-advisories/icsa-26-111-01</link>
  <description>&lt;p&gt;&lt;strong&gt;Summary&lt;/strong&gt;&lt;/p&gt;&lt;p&gt;Affects CVE-2026-77777 in Example Widget. Mitigation: apply vendor patch 9.9.9.&lt;/p&gt;</description>
  <pubDate>$TODAY_RFC</pubDate>
  <guid isPermaLink="false">/node/11111</guid>
</item>
<item>
  <title>Fixture entry with no link</title>
  <link></link>
  <description>This entry has no link and must be skipped.</description>
  <pubDate>$TODAY_RFC</pubDate>
  <guid isPermaLink="false">/node/22222</guid>
</item>
<item>
  <title>Fixture ancient advisory outside lookback window</title>
  <link>https://www.cisa.gov/news-events/ics-advisories/icsa-20-000-01</link>
  <description>Too old to be picked up by a 7-day lookback.</description>
  <pubDate>$SIXTY_DAYS_AGO_RFC</pubDate>
  <guid isPermaLink="false">/node/33333</guid>
</item>
</channel></rss>
EOF

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
  echo "not valid xml <<<" > "\$OUT"
  echo -n "200"
  exit 0
fi
if [ -n "\${FAKE_CURL_ENTITY_BOMB:-}" ]; then
  printf '%s\n' '<?xml version="1.0"?>' '<!DOCTYPE rss [<!ENTITY a "AAAAAAAAAA"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">]>' '<rss version="2.0"><channel><item><title>&b;</title><link>https://www.cisa.gov/x</link><pubDate>Tue, 06 Oct 26 12:00:00 +0000</pubDate></item></channel></rss>' > "\$OUT"
  echo -n "200"
  exit 0
fi
if [[ "\$URL" == *"www.cisa.gov"* ]]; then
  cp "$FIXTURE_DIR/advisories.xml" "\$OUT"
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

echo "=== Incident Learning Engine: real Collector (CISA Advisories, Phase 99) regression suite ==="

echo ""
echo "[A1] a well-formed recent entry is emitted correctly: id/source/source_type/source_url/collected_at/published_at/country/region/language mapping, HTML stripped from raw_text"
OUT="$(CISA_ADVISORIES_LOOKBACK_DAYS=7 ./security/incident_learning/collectors/cisa_advisories_collector.sh 2>/tmp/waio-cisaadv-a1-stderr.log)"
RC=$?
assert_eq "A1 exit code 0" "0" "$RC"
A1_LINE="$(echo "$OUT" | grep 'icsa-26-111-01')"
assert_eq "A1 id is CISAADV-<slug>" "CISAADV-icsa-26-111-01" "$(python3 -c "import json,sys; print(json.loads(sys.argv[1])['id'])" "$A1_LINE")"
assert_eq "A1 source" "cisa_advisories_collector" "$(python3 -c "import json,sys; print(json.loads(sys.argv[1])['source'])" "$A1_LINE")"
assert_eq "A1 source_type is cert" "cert" "$(python3 -c "import json,sys; print(json.loads(sys.argv[1])['source_type'])" "$A1_LINE")"
assert_eq "A1 source_url is the advisory's own link" "https://www.cisa.gov/news-events/ics-advisories/icsa-26-111-01" "$(python3 -c "import json,sys; print(json.loads(sys.argv[1])['source_url'])" "$A1_LINE")"
assert_eq "A1 country" "US" "$(python3 -c "import json,sys; print(json.loads(sys.argv[1])['country'])" "$A1_LINE")"
assert_eq "A1 region" "NA" "$(python3 -c "import json,sys; print(json.loads(sys.argv[1])['region'])" "$A1_LINE")"
assert_eq "A1 language" "en" "$(python3 -c "import json,sys; print(json.loads(sys.argv[1])['language'])" "$A1_LINE")"
assert_eq "A1 collected_at equals published_at" "true" "$(python3 -c "import json,sys; d=json.loads(sys.argv[1]); print('true' if d['collected_at']==d['published_at'] else 'false')" "$A1_LINE")"
assert_contains "A1 raw_text has HTML tags stripped (no literal '<p>')" "$A1_LINE" "Summary Affects CVE-2026-77777"
A1_HAS_P_TAG="$(echo "$A1_LINE" | grep -c '&lt;p&gt;\|<p>' || true)"
assert_eq "A1 no raw HTML tag survives into raw_text" "0" "$A1_HAS_P_TAG"
assert_contains "A1 CVE id preserved in raw_text for cve_list extraction" "$A1_LINE" "CVE-2026-77777"
A1_HAS_CORROB="$(python3 -c "import json,sys; print('corroborating_sources' in json.loads(sys.argv[1]))" "$A1_LINE")"
assert_eq "A1 corroborating_sources field is genuinely absent" "False" "$A1_HAS_CORROB"

echo ""
echo "[A2] an entry outside the lookback window is excluded"
A2_PRESENT="$(echo "$OUT" | grep -c 'icsa-20-000-01' || true)"
assert_eq "A2 old entry not emitted" "0" "$A2_PRESENT"

echo ""
echo "[A3] an entry with an empty link is skipped gracefully, never crashes the run"
A3_LINES="$(echo "$OUT" | grep -c . || true)"
assert_eq "A3 exactly one record emitted (empty-link and out-of-window both excluded)" "1" "$A3_LINES"

echo ""
echo "[A4] the summary line goes to stderr, never stdout (Collector contract: nothing but JSONL on stdout)"
A4_STDERR="$(cat /tmp/waio-cisaadv-a1-stderr.log)"
assert_contains "A4 stderr has the summary" "$A4_STDERR" "emitted 1 record(s)"
A4_STDOUT_HAS_SUMMARY="$(echo "$OUT" | grep -c 'CISA ADVISORIES COLLECTOR' || true)"
assert_eq "A4 stdout carries zero non-JSON lines" "0" "$A4_STDOUT_HAS_SUMMARY"

echo ""
echo "[A5] the emitted line is valid, single-line JSON (JSONL, not pretty-printed)"
A5_VALID="$(python3 -c "import json; json.loads('''$A1_LINE'''); print('true')" 2>/dev/null || echo false)"
assert_eq "A5 valid JSON" "true" "$A5_VALID"

echo ""
echo "[A6] CISA_ADVISORIES_MAX_RECORDS caps the emitted count even when more are in-window"
OUT_A6="$(CISA_ADVISORIES_LOOKBACK_DAYS=7 CISA_ADVISORIES_MAX_RECORDS=0 ./security/incident_learning/collectors/cisa_advisories_collector.sh 2>/dev/null)"
A6_LINES="$(echo -n "$OUT_A6" | grep -c . || true)"
assert_eq "A6 MAX_RECORDS=0 emits nothing" "0" "$A6_LINES"

echo ""
echo "[A7] egress denied (destination not in the fixture allowlist): exits non-zero, emits nothing on stdout"
cat > "$FIXTURE_DIR/egress_allowlist_empty.conf" <<'EOF'
EOF
OUT_A7="$(WAIO_EGRESS_ALLOWLIST="$FIXTURE_DIR/egress_allowlist_empty.conf" ./security/incident_learning/collectors/cisa_advisories_collector.sh 2>&1)"
RC_A7=$?
assert_eq "A7 exit code non-zero" "true" "$([ "$RC_A7" -ne 0 ] && echo true || echo false)"
assert_contains "A7 error mentions egress denial" "$OUT_A7" "egress denied by DLP guard"
rm -f "$FIXTURE_DIR/SHUTDOWN.lock"

echo ""
echo "[A8] an unreachable/failing HTTP fetch exits non-zero with a clear reason, emits nothing"
OUT_A8="$(FAKE_CURL_FAIL_HOST="www.cisa.gov" ./security/incident_learning/collectors/cisa_advisories_collector.sh 2>&1)"
RC_A8=$?
assert_eq "A8 exit code non-zero" "true" "$([ "$RC_A8" -ne 0 ] && echo true || echo false)"
assert_contains "A8 error mentions the failed HTTP status" "$OUT_A8" "HTTP 000"

echo ""
echo "[A9] a malformed (non-XML) response is reported cleanly, never a raw Python traceback crash"
OUT_A9="$(FAKE_CURL_MALFORMED=1 ./security/incident_learning/collectors/cisa_advisories_collector.sh 2>&1)"
RC_A9=$?
assert_eq "A9 exit code non-zero" "true" "$([ "$RC_A9" -ne 0 ] && echo true || echo false)"
assert_contains "A9 error names the XML problem" "$OUT_A9" "response is not valid XML"

echo ""
echo "[A10] a response containing a DOCTYPE/ENTITY declaration is rejected outright (entity-expansion guard), never parsed, never expanded"
OUT_A10="$(FAKE_CURL_ENTITY_BOMB=1 ./security/incident_learning/collectors/cisa_advisories_collector.sh 2>&1)"
RC_A10=$?
assert_eq "A10 exit code non-zero" "true" "$([ "$RC_A10" -ne 0 ] && echo true || echo false)"
assert_contains "A10 error names the DOCTYPE/ENTITY guard" "$OUT_A10" "DOCTYPE/ENTITY declaration"
A10_STDOUT_LINES="$(FAKE_CURL_ENTITY_BOMB=1 ./security/incident_learning/collectors/cisa_advisories_collector.sh 2>/dev/null | grep -c . || true)"
assert_eq "A10 zero stdout lines (nothing emitted, nothing expanded)" "0" "$A10_STDOUT_LINES"

echo ""
echo "[D1] this collector DOES source security/lib.sh and DOES call egress_check"
assert_eq "D1 sources security/lib.sh" "1" "$(grep -cE '^\s*source security/lib\.sh\b' security/incident_learning/collectors/cisa_advisories_collector.sh)"
assert_eq "D1 calls egress_check" "1" "$(grep -cE '\begress_check\s*"' security/incident_learning/collectors/cisa_advisories_collector.sh)"

echo ""
echo "[D2] this deployment's real SHUTDOWN.lock/audit log were never touched by this suite"
REAL_SHUTDOWN_AFTER="false"
[ -f security/state/SHUTDOWN.lock ] && REAL_SHUTDOWN_AFTER="true"
assert_eq "D2 real SHUTDOWN.lock presence unchanged" "$REAL_SHUTDOWN_BEFORE" "$REAL_SHUTDOWN_AFTER"
REAL_AUDIT_HASH_AFTER="not_present"
[ -f logs/security-audit.jsonl ] && REAL_AUDIT_HASH_AFTER="$(shasum -a 256 logs/security-audit.jsonl | awk '{print $1}')"
assert_eq "D2 real audit log checksum unchanged" "$REAL_AUDIT_HASH_BEFORE" "$REAL_AUDIT_HASH_AFTER"

echo ""
echo "[D3] this deployment's real Control Plane conf files were never touched by this suite"
for real_file in security/segments.conf security/ssh_management_allowlist.conf; do
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
