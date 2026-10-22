#!/bin/bash
set -uo pipefail

# tests/incident_learning_jpcert_collector_test.sh -- regression suite
# for Phase 99 (real Collector):
# security/incident_learning/collectors/jpcert_collector.sh.
#
# NO REAL NETWORK CALL. `curl` is shadowed on PATH by a fixture script
# (same idiom as tests/incident_learning_cisa_kev_collector_test.sh's
# own fake curl) that serves a small, fixed JPCERT/CC-RDF-shaped body,
# so the collector is exercised unmodified and end-to-end (real
# egress_check, real date-parsing/mapping logic) except the actual
# network I/O. Every case runs against an isolated
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

FIXTURE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/waio-jpcert-test.XXXXXX")"
trap 'rm -rf "$FIXTURE_DIR"' EXIT
mkdir -p "$FIXTURE_DIR/bin"

TODAY_DC="$(date -u +"%Y-%m-%dT%H:%M+00:00")"
SIXTY_DAYS_AGO_DC="$(date -u -v-60d +"%Y-%m-%dT%H:%M+00:00" 2>/dev/null || date -u -d '60 days ago' +"%Y-%m-%dT%H:%M+00:00")"

# --- fixture JPCERT/CC RDF body: one recent, well-formed entry; one
# recent entry with an empty link (must be skipped, never crash); one
# entry outside the lookback window (must be excluded). -------------
cat > "$FIXTURE_DIR/jpcert.rdf" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns="http://purl.org/rss/1.0/">
<item rdf:about="https://www.jpcert.or.jp/english/at/2026/at260111.html">
  <title>Security Alert: Fixture Vulnerability (APSB26-111)</title>
  <link>https://www.jpcert.or.jp/english/at/2026/at260111.html</link>
  <dc:date>$TODAY_DC</dc:date>
</item>
<item rdf:about="https://www.jpcert.or.jp/english/at/2026/empty.html">
  <title>Fixture entry with no link</title>
  <link></link>
  <dc:date>$TODAY_DC</dc:date>
</item>
<item rdf:about="https://www.jpcert.or.jp/english/at/2020/at200000.html">
  <title>Fixture ancient alert outside lookback window</title>
  <link>https://www.jpcert.or.jp/english/at/2020/at200000.html</link>
  <dc:date>$SIXTY_DAYS_AGO_DC</dc:date>
</item>
</rdf:RDF>
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
  printf '%s\n' '<?xml version="1.0"?>' '<!DOCTYPE rdf [<!ENTITY a "AAAAAAAAAA"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">]>' '<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns="http://purl.org/rss/1.0/"><item><title>&b;</title><link>https://www.jpcert.or.jp/x</link><dc:date>2026-10-06T12:00+00:00</dc:date></item></rdf:RDF>' > "\$OUT"
  echo -n "200"
  exit 0
fi
if [[ "\$URL" == *"www.jpcert.or.jp"* ]]; then
  cp "$FIXTURE_DIR/jpcert.rdf" "\$OUT"
  echo -n "200"
else
  echo -n "000"
fi
FAKECURL
chmod +x "$FIXTURE_DIR/bin/curl"

cat > "$FIXTURE_DIR/egress_allowlist.conf" <<'EOF'
www.jpcert.or.jp|443|test fixture
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

echo "=== Incident Learning Engine: real Collector (JPCERT/CC, Phase 99) regression suite ==="

echo ""
echo "[J1] a well-formed recent entry is emitted correctly: id/source/source_type/source_url/collected_at/published_at/country/region/language mapping, raw_text is the title (this feed's own documented title-only limitation)"
OUT="$(JPCERT_LOOKBACK_DAYS=7 ./security/incident_learning/collectors/jpcert_collector.sh 2>/tmp/waio-jpcert-j1-stderr.log)"
RC=$?
assert_eq "J1 exit code 0" "0" "$RC"
J1_LINE="$(echo "$OUT" | grep 'at260111')"
assert_eq "J1 id is JPCERT-<slug>" "JPCERT-at260111" "$(python3 -c "import json,sys; print(json.loads(sys.argv[1])['id'])" "$J1_LINE")"
assert_eq "J1 source" "jpcert_collector" "$(python3 -c "import json,sys; print(json.loads(sys.argv[1])['source'])" "$J1_LINE")"
assert_eq "J1 source_type is cert" "cert" "$(python3 -c "import json,sys; print(json.loads(sys.argv[1])['source_type'])" "$J1_LINE")"
assert_eq "J1 source_url is the item's own link" "https://www.jpcert.or.jp/english/at/2026/at260111.html" "$(python3 -c "import json,sys; print(json.loads(sys.argv[1])['source_url'])" "$J1_LINE")"
assert_eq "J1 country" "JP" "$(python3 -c "import json,sys; print(json.loads(sys.argv[1])['country'])" "$J1_LINE")"
assert_eq "J1 region" "APAC" "$(python3 -c "import json,sys; print(json.loads(sys.argv[1])['region'])" "$J1_LINE")"
assert_eq "J1 language" "en" "$(python3 -c "import json,sys; print(json.loads(sys.argv[1])['language'])" "$J1_LINE")"
assert_eq "J1 collected_at equals published_at" "true" "$(python3 -c "import json,sys; d=json.loads(sys.argv[1]); print('true' if d['collected_at']==d['published_at'] else 'false')" "$J1_LINE")"
assert_eq "J1 raw_text is exactly the title" "Security Alert: Fixture Vulnerability (APSB26-111)" "$(python3 -c "import json,sys; print(json.loads(sys.argv[1])['raw_text'])" "$J1_LINE")"
J1_HAS_CORROB="$(python3 -c "import json,sys; print('corroborating_sources' in json.loads(sys.argv[1]))" "$J1_LINE")"
assert_eq "J1 corroborating_sources field is genuinely absent" "False" "$J1_HAS_CORROB"

echo ""
echo "[J2] an entry outside the lookback window is excluded"
J2_PRESENT="$(echo "$OUT" | grep -c 'at200000' || true)"
assert_eq "J2 old entry not emitted" "0" "$J2_PRESENT"

echo ""
echo "[J3] an entry with an empty link is skipped gracefully, never crashes the run"
J3_LINES="$(echo "$OUT" | grep -c . || true)"
assert_eq "J3 exactly one record emitted (empty-link and out-of-window both excluded)" "1" "$J3_LINES"

echo ""
echo "[J4] the summary line goes to stderr, never stdout (Collector contract: nothing but JSONL on stdout)"
J4_STDERR="$(cat /tmp/waio-jpcert-j1-stderr.log)"
assert_contains "J4 stderr has the summary" "$J4_STDERR" "emitted 1 record(s)"
J4_STDOUT_HAS_SUMMARY="$(echo "$OUT" | grep -c 'JPCERT COLLECTOR' || true)"
assert_eq "J4 stdout carries zero non-JSON lines" "0" "$J4_STDOUT_HAS_SUMMARY"

echo ""
echo "[J5] the emitted line is valid, single-line JSON (JSONL, not pretty-printed)"
J5_VALID="$(python3 -c "import json; json.loads('''$J1_LINE'''); print('true')" 2>/dev/null || echo false)"
assert_eq "J5 valid JSON" "true" "$J5_VALID"

echo ""
echo "[J6] JPCERT_MAX_RECORDS caps the emitted count even when more are in-window"
OUT_J6="$(JPCERT_LOOKBACK_DAYS=7 JPCERT_MAX_RECORDS=0 ./security/incident_learning/collectors/jpcert_collector.sh 2>/dev/null)"
J6_LINES="$(echo -n "$OUT_J6" | grep -c . || true)"
assert_eq "J6 MAX_RECORDS=0 emits nothing" "0" "$J6_LINES"

echo ""
echo "[J7] egress denied (destination not in the fixture allowlist): exits non-zero, emits nothing on stdout"
cat > "$FIXTURE_DIR/egress_allowlist_empty.conf" <<'EOF'
EOF
OUT_J7="$(WAIO_EGRESS_ALLOWLIST="$FIXTURE_DIR/egress_allowlist_empty.conf" ./security/incident_learning/collectors/jpcert_collector.sh 2>&1)"
RC_J7=$?
assert_eq "J7 exit code non-zero" "true" "$([ "$RC_J7" -ne 0 ] && echo true || echo false)"
assert_contains "J7 error mentions egress denial" "$OUT_J7" "egress denied by DLP guard"
rm -f "$FIXTURE_DIR/SHUTDOWN.lock"

echo ""
echo "[J8] an unreachable/failing HTTP fetch exits non-zero with a clear reason, emits nothing"
OUT_J8="$(FAKE_CURL_FAIL_HOST="www.jpcert.or.jp" ./security/incident_learning/collectors/jpcert_collector.sh 2>&1)"
RC_J8=$?
assert_eq "J8 exit code non-zero" "true" "$([ "$RC_J8" -ne 0 ] && echo true || echo false)"
assert_contains "J8 error mentions the failed HTTP status" "$OUT_J8" "HTTP 000"

echo ""
echo "[J9] a malformed (non-XML) response is reported cleanly, never a raw Python traceback crash"
OUT_J9="$(FAKE_CURL_MALFORMED=1 ./security/incident_learning/collectors/jpcert_collector.sh 2>&1)"
RC_J9=$?
assert_eq "J9 exit code non-zero" "true" "$([ "$RC_J9" -ne 0 ] && echo true || echo false)"
assert_contains "J9 error names the XML problem" "$OUT_J9" "response is not valid XML"

echo ""
echo "[J10] a response containing a DOCTYPE/ENTITY declaration is rejected outright (entity-expansion guard), never parsed, never expanded"
OUT_J10="$(FAKE_CURL_ENTITY_BOMB=1 ./security/incident_learning/collectors/jpcert_collector.sh 2>&1)"
RC_J10=$?
assert_eq "J10 exit code non-zero" "true" "$([ "$RC_J10" -ne 0 ] && echo true || echo false)"
assert_contains "J10 error names the DOCTYPE/ENTITY guard" "$OUT_J10" "DOCTYPE/ENTITY declaration"
J10_STDOUT_LINES="$(FAKE_CURL_ENTITY_BOMB=1 ./security/incident_learning/collectors/jpcert_collector.sh 2>/dev/null | grep -c . || true)"
assert_eq "J10 zero stdout lines (nothing emitted, nothing expanded)" "0" "$J10_STDOUT_LINES"

echo ""
echo "[D1] this collector DOES source security/lib.sh and DOES call egress_check"
assert_eq "D1 sources security/lib.sh" "1" "$(grep -cE '^\s*source security/lib\.sh\b' security/incident_learning/collectors/jpcert_collector.sh)"
assert_eq "D1 calls egress_check" "1" "$(grep -cE '\begress_check\s*"' security/incident_learning/collectors/jpcert_collector.sh)"

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
