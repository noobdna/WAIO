#!/bin/bash
set -uo pipefail

# tests/incident_learning_cert_ee_collector_test.sh -- regression
# suite for Phase 99 (real Collector):
# security/incident_learning/collectors/cert_ee_collector.sh.
#
# NO REAL NETWORK CALL. `curl` is shadowed on PATH by a fixture script
# (same idiom as tests/incident_learning_cisa_kev_collector_test.sh's
# own fake curl) that serves a small, fixed RIA-news-RSS-shaped body,
# so the collector is exercised unmodified and end-to-end (real
# egress_check, real date-parsing/pre-filter/mapping logic) except the
# actual network I/O. Every case runs against an isolated
# WAIO_EGRESS_ALLOWLIST/WAIO_SHUTDOWN_LOCK/WAIO_AUDIT_LOG(+checkpoint/
# alerts/lock), never this deployment's real security state.

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

FIXTURE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/waio-cert-ee-test.XXXXXX")"
trap 'rm -rf "$FIXTURE_DIR"' EXIT
mkdir -p "$FIXTURE_DIR/bin"

TODAY_RFC="$(date -u +"%a, %d %b %Y %H:%M:%S +0000")"
SIXTY_DAYS_AGO_RFC="$(date -u -v-60d +"%a, %d %b %Y %H:%M:%S +0000" 2>/dev/null || date -u -d '60 days ago' +"%a, %d %b %Y %H:%M:%S +0000")"

# --- fixture RIA news RSS body: one recent, incident-relevant entry;
# one recent entry with NO incident cue (must be filtered out, the
# whole point of this Collector's own pre-filter); one incident-
# relevant entry outside the lookback window (must be excluded). ----
cat > "$FIXTURE_DIR/ria.xml" <<EOF
<?xml version="1.0"?>
<rss version="2.0"><channel>
<item>
  <title>Fixture: data breach and disruption in September</title>
  <link>https://ria.ee/en/news/fixture-breach</link>
  <description>RIA recorded a data breach affecting an example information system and a denial-of-service attack on a government e-service.</description>
  <pubDate>$TODAY_RFC</pubDate>
  <guid isPermaLink="false">55001 at https://www.ria.ee/en</guid>
</item>
<item>
  <title>Fixture: ID-card software update available</title>
  <link>https://ria.ee/en/news/fixture-id-software</link>
  <description>A routine software update is now available for ID cards, no security content here.</description>
  <pubDate>$TODAY_RFC</pubDate>
  <guid isPermaLink="false">55002 at https://www.ria.ee/en</guid>
</item>
<item>
  <title>Fixture: ancient phishing campaign outside lookback window</title>
  <link>https://ria.ee/en/news/fixture-old-phishing</link>
  <description>A phishing campaign targeting citizens was reported, but this is too old for a 7-day lookback.</description>
  <pubDate>$SIXTY_DAYS_AGO_RFC</pubDate>
  <guid isPermaLink="false">55003 at https://www.ria.ee/en</guid>
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
  printf '%s\n' '<?xml version="1.0"?>' '<!DOCTYPE rss [<!ENTITY a "AAAAAAAAAA"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">]>' '<rss version="2.0"><channel><item><title>&b; incident breach</title><link>https://ria.ee/en/news/x</link><pubDate>Tue, 06 Oct 2026 12:00:00 +0000</pubDate></item></channel></rss>' > "\$OUT"
  echo -n "200"
  exit 0
fi
if [[ "\$URL" == *"www.ria.ee"* ]]; then
  cp "$FIXTURE_DIR/ria.xml" "\$OUT"
  echo -n "200"
else
  echo -n "000"
fi
FAKECURL
chmod +x "$FIXTURE_DIR/bin/curl"

cat > "$FIXTURE_DIR/egress_allowlist.conf" <<'EOF'
www.ria.ee|443|test fixture
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

echo "=== Incident Learning Engine: real Collector (RIA/CERT-EE, Phase 99) regression suite ==="

echo ""
echo "[E1] a well-formed, incident-relevant recent entry is emitted correctly: id/source/source_type/source_url/collected_at/published_at/country/region/language mapping, raw_text is title+description"
OUT="$(CERT_EE_LOOKBACK_DAYS=7 ./security/incident_learning/collectors/cert_ee_collector.sh 2>/tmp/waio-certee-e1-stderr.log)"
RC=$?
assert_eq "E1 exit code 0" "0" "$RC"
E1_LINE="$(echo "$OUT" | grep 'fixture-breach')"
assert_eq "E1 id is CERTEE-<nid> (parsed from the Drupal-shaped guid)" "CERTEE-55001" "$(python3 -c "import json,sys; print(json.loads(sys.argv[1])['id'])" "$E1_LINE")"
assert_eq "E1 source" "cert_ee_collector" "$(python3 -c "import json,sys; print(json.loads(sys.argv[1])['source'])" "$E1_LINE")"
assert_eq "E1 source_type is cert" "cert" "$(python3 -c "import json,sys; print(json.loads(sys.argv[1])['source_type'])" "$E1_LINE")"
assert_eq "E1 source_url is the item's own link" "https://ria.ee/en/news/fixture-breach" "$(python3 -c "import json,sys; print(json.loads(sys.argv[1])['source_url'])" "$E1_LINE")"
assert_eq "E1 country" "EE" "$(python3 -c "import json,sys; print(json.loads(sys.argv[1])['country'])" "$E1_LINE")"
assert_eq "E1 region" "EU" "$(python3 -c "import json,sys; print(json.loads(sys.argv[1])['region'])" "$E1_LINE")"
assert_eq "E1 language" "en" "$(python3 -c "import json,sys; print(json.loads(sys.argv[1])['language'])" "$E1_LINE")"
assert_eq "E1 collected_at equals published_at" "true" "$(python3 -c "import json,sys; d=json.loads(sys.argv[1]); print('true' if d['collected_at']==d['published_at'] else 'false')" "$E1_LINE")"
assert_contains "E1 raw_text includes the title" "$E1_LINE" "Fixture: data breach and disruption"
assert_contains "E1 raw_text includes the description" "$E1_LINE" "denial-of-service attack"
E1_HAS_CORROB="$(python3 -c "import json,sys; print('corroborating_sources' in json.loads(sys.argv[1]))" "$E1_LINE")"
assert_eq "E1 corroborating_sources field is genuinely absent" "False" "$E1_HAS_CORROB"

echo ""
echo "[E2] an item with no incident cue in title or description is filtered out entirely -- the whole point of this Collector's own pre-filter against RIA's general news feed"
E2_PRESENT="$(echo "$OUT" | grep -c 'fixture-id-software' || true)"
assert_eq "E2 non-incident item never emitted" "0" "$E2_PRESENT"
E2_STDERR="$(cat /tmp/waio-certee-e1-stderr.log)"
assert_contains "E2 stderr reports exactly 1 filtered-out item" "$E2_STDERR" "1 filtered out as not incident-relevant"

echo ""
echo "[E3] an incident-relevant entry outside the lookback window is excluded"
E3_PRESENT="$(echo "$OUT" | grep -c 'fixture-old-phishing' || true)"
assert_eq "E3 old entry not emitted" "0" "$E3_PRESENT"

echo ""
echo "[E4] exactly one record emitted overall (non-incident and out-of-window both excluded, leaving only the one relevant/recent item)"
E4_LINES="$(echo "$OUT" | grep -c . || true)"
assert_eq "E4 exactly one record emitted" "1" "$E4_LINES"

echo ""
echo "[E5] the summary line goes to stderr, never stdout (Collector contract: nothing but JSONL on stdout)"
assert_contains "E5 stderr has the summary" "$E2_STDERR" "emitted 1 record(s)"
E5_STDOUT_HAS_SUMMARY="$(echo "$OUT" | grep -c 'CERT-EE COLLECTOR' || true)"
assert_eq "E5 stdout carries zero non-JSON lines" "0" "$E5_STDOUT_HAS_SUMMARY"

echo ""
echo "[E6] the emitted line is valid, single-line JSON (JSONL, not pretty-printed)"
E6_VALID="$(python3 -c "import json; json.loads('''$E1_LINE'''); print('true')" 2>/dev/null || echo false)"
assert_eq "E6 valid JSON" "true" "$E6_VALID"

echo ""
echo "[E7] CERT_EE_MAX_RECORDS caps the emitted count even when more are in-window"
OUT_E7="$(CERT_EE_LOOKBACK_DAYS=7 CERT_EE_MAX_RECORDS=0 ./security/incident_learning/collectors/cert_ee_collector.sh 2>/dev/null)"
E7_LINES="$(echo -n "$OUT_E7" | grep -c . || true)"
assert_eq "E7 MAX_RECORDS=0 emits nothing" "0" "$E7_LINES"

echo ""
echo "[E8] egress denied (destination not in the fixture allowlist): exits non-zero, emits nothing on stdout"
cat > "$FIXTURE_DIR/egress_allowlist_empty.conf" <<'EOF'
EOF
OUT_E8="$(WAIO_EGRESS_ALLOWLIST="$FIXTURE_DIR/egress_allowlist_empty.conf" ./security/incident_learning/collectors/cert_ee_collector.sh 2>&1)"
RC_E8=$?
assert_eq "E8 exit code non-zero" "true" "$([ "$RC_E8" -ne 0 ] && echo true || echo false)"
assert_contains "E8 error mentions egress denial" "$OUT_E8" "egress denied by DLP guard"
rm -f "$FIXTURE_DIR/SHUTDOWN.lock"

echo ""
echo "[E9] an unreachable/failing HTTP fetch exits non-zero with a clear reason, emits nothing"
OUT_E9="$(FAKE_CURL_FAIL_HOST="www.ria.ee" ./security/incident_learning/collectors/cert_ee_collector.sh 2>&1)"
RC_E9=$?
assert_eq "E9 exit code non-zero" "true" "$([ "$RC_E9" -ne 0 ] && echo true || echo false)"
assert_contains "E9 error mentions the failed HTTP status" "$OUT_E9" "HTTP 000"

echo ""
echo "[E10] a malformed (non-XML) response is reported cleanly, never a raw Python traceback crash"
OUT_E10="$(FAKE_CURL_MALFORMED=1 ./security/incident_learning/collectors/cert_ee_collector.sh 2>&1)"
RC_E10=$?
assert_eq "E10 exit code non-zero" "true" "$([ "$RC_E10" -ne 0 ] && echo true || echo false)"
assert_contains "E10 error names the XML problem" "$OUT_E10" "response is not valid XML"

echo ""
echo "[E11] a response containing a DOCTYPE/ENTITY declaration is rejected outright (entity-expansion guard), never parsed, never expanded -- checked even before the incident-relevance pre-filter runs"
OUT_E11="$(FAKE_CURL_ENTITY_BOMB=1 ./security/incident_learning/collectors/cert_ee_collector.sh 2>&1)"
RC_E11=$?
assert_eq "E11 exit code non-zero" "true" "$([ "$RC_E11" -ne 0 ] && echo true || echo false)"
assert_contains "E11 error names the DOCTYPE/ENTITY guard" "$OUT_E11" "DOCTYPE/ENTITY declaration"
E11_STDOUT_LINES="$(FAKE_CURL_ENTITY_BOMB=1 ./security/incident_learning/collectors/cert_ee_collector.sh 2>/dev/null | grep -c . || true)"
assert_eq "E11 zero stdout lines (nothing emitted, nothing expanded)" "0" "$E11_STDOUT_LINES"

echo ""
echo "[D1] this collector DOES source security/lib.sh and DOES call egress_check"
assert_eq "D1 sources security/lib.sh" "1" "$(grep -cE '^\s*source security/lib\.sh\b' security/incident_learning/collectors/cert_ee_collector.sh)"
assert_eq "D1 calls egress_check" "1" "$(grep -cE '\begress_check\s*"' security/incident_learning/collectors/cert_ee_collector.sh)"

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
