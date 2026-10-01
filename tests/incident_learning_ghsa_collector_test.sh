#!/bin/bash
set -uo pipefail

# tests/incident_learning_ghsa_collector_test.sh -- regression suite
# for the SECOND real Collector:
# security/incident_learning/collectors/ghsa_collector.sh.
#
# NO REAL NETWORK CALL. `curl` is shadowed on PATH by a fixture script
# (same idiom as tests/incident_learning_cisa_kev_collector_test.sh's
# own fake curl) that routes by the `cve_id=` query string on each
# request -- this collector makes one request PER already-known CVE
# (a targeted lookup, not a single broad feed pull like
# cisa_kev_collector.sh), so the fixture must distinguish requests by
# query string rather than by host alone. Every case runs against an
# isolated WAIO_EGRESS_ALLOWLIST/WAIO_SHUTDOWN_LOCK/WAIO_AUDIT_LOG(+
# checkpoint/alerts/lock) AND an isolated KNOWLEDGE_MANAGER_STATE_DIR
# (this collector reads OTHER candidates' cve_list directly -- see its
# own header), never this deployment's real security state.

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

FIXTURE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/waio-ghsa-test.XXXXXX")"
trap 'rm -rf "$FIXTURE_DIR"' EXIT
mkdir -p "$FIXTURE_DIR/bin" "$FIXTURE_DIR/candidates" "$FIXTURE_DIR/knowledge"

# --- fixture GHSA responses, keyed by cve_id. -----------------------
mkdir -p "$FIXTURE_DIR/responses"
cat > "$FIXTURE_DIR/responses/CVE-2026-10001.json" <<'EOF'
[{"ghsa_id": "GHSA-fixt-ure0-0001", "cve_id": "CVE-2026-10001", "summary": "Fixture GHSA advisory for a matched CVE", "description": "Some description.\n\n### Patches\n\nFixed in 9.9.9.", "severity": "high", "html_url": "https://github.com/advisories/GHSA-fixt-ure0-0001", "published_at": "2026-01-01T00:00:00Z"}]
EOF
echo '[]' > "$FIXTURE_DIR/responses/CVE-2026-99999.json"
cat > "$FIXTURE_DIR/responses/CVE-2026-77777.json" <<'EOF'
[{"ghsa_id": "GHSA-fixt-ure0-0002", "cve_id": "CVE-2026-77777", "summary": "A second fixture match, no CVE regex needed since this is already structured", "description": "No patches section here.", "severity": "critical", "html_url": "https://github.com/advisories/GHSA-fixt-ure0-0002", "published_at": "2026-01-02T00:00:00Z"}]
EOF

QUERY_LOG="$FIXTURE_DIR/queried_cves.log"
: > "$QUERY_LOG"

# --- fake curl: routes by the cve_id= query string on the URL (the
# last argument), or simulates an HTTP failure per env-var switch;
# every queried CVE is appended to QUERY_LOG so a test can assert
# exactly which lookups were (or were not) attempted. -----------------
cat > "$FIXTURE_DIR/bin/curl" <<FAKECURL
#!/bin/bash
declare -a ARGS=("\$@")
URL="\${ARGS[\${#ARGS[@]}-1]}"
OUT=""
for i in "\${!ARGS[@]}"; do
  if [ "\${ARGS[\$i]}" = "-o" ]; then OUT="\${ARGS[\$((i+1))]}"; fi
done
CVE="\$(echo "\$URL" | sed -n 's/.*cve_id=\([^&]*\).*/\1/p')"
echo "\$CVE" >> "$QUERY_LOG"
if [ -n "\${FAKE_CURL_FAIL_HOST:-}" ] && [[ "\$URL" == *"\$FAKE_CURL_FAIL_HOST"* ]]; then
  echo -n "000"
  exit 0
fi
if [ -n "\${FAKE_CURL_MALFORMED:-}" ]; then
  echo "not valid json" > "\$OUT"
  echo -n "200"
  exit 0
fi
if [ -n "\${FAKE_CURL_RATE_LIMIT:-}" ]; then
  echo '{"message": "API rate limit exceeded for 1.2.3.4."}' > "\$OUT"
  echo -n "403"
  exit 0
fi
RESP_FILE="$FIXTURE_DIR/responses/\$CVE.json"
if [[ "\$URL" == *"api.github.com"* ]] && [ -f "\$RESP_FILE" ]; then
  cp "\$RESP_FILE" "\$OUT"
  echo -n "200"
else
  echo '[]' > "\$OUT"
  echo -n "200"
fi
FAKECURL
chmod +x "$FIXTURE_DIR/bin/curl"

cat > "$FIXTURE_DIR/egress_allowlist.conf" <<'EOF'
api.github.com|443|test fixture
EOF

export PATH="$FIXTURE_DIR/bin:$PATH"
export WAIO_EGRESS_ALLOWLIST="$FIXTURE_DIR/egress_allowlist.conf"
export WAIO_SHUTDOWN_LOCK="$FIXTURE_DIR/SHUTDOWN.lock"
export WAIO_AUDIT_LOG="$FIXTURE_DIR/audit.jsonl"
export WAIO_AUDIT_LOG_CHECKPOINT="$FIXTURE_DIR/audit_checkpoint"
export WAIO_AUDIT_INTEGRITY_ALERTS="$FIXTURE_DIR/audit_alerts.jsonl"
export WAIO_AUDIT_LOG_LOCK_DIR="$FIXTURE_DIR/audit_lock"
export KNOWLEDGE_MANAGER_STATE_DIR="$FIXTURE_DIR/candidates"
export KNOWLEDGE_MANAGER_AUDIT_LOG="$FIXTURE_DIR/knowledge-audit.jsonl"
export KNOWLEDGE_MANAGER_KNOWLEDGE_DIR="$FIXTURE_DIR/knowledge"

km() { bash security/incident_learning/knowledge_manager.sh "$@"; }

REAL_SHUTDOWN_BEFORE="false"
[ -f security/state/SHUTDOWN.lock ] && REAL_SHUTDOWN_BEFORE="true"
REAL_AUDIT_HASH_BEFORE="not_present"
[ -f logs/security-audit.jsonl ] && REAL_AUDIT_HASH_BEFORE="$(shasum -a 256 logs/security-audit.jsonl | awk '{print $1}')"

echo "=== Incident Learning Engine: second real Collector (GHSA) regression suite ==="

echo ""
echo "[G1] with no known candidates at all, the collector makes zero requests and exits 0 cleanly"
OUT_G1="$(GHSA_MAX_RECORDS=25 ./security/incident_learning/collectors/ghsa_collector.sh 2>&1 >/dev/null)"
RC_G1=$?
assert_eq "G1 exit code 0" "0" "$RC_G1"
assert_contains "G1 message explains zero-CVE case" "$OUT_G1" "nothing to look up this run"
assert_eq "G1 zero curl requests made" "0" "$([ -s "$QUERY_LOG" ] && wc -l < "$QUERY_LOG" | tr -d ' ' || echo 0)"

echo ""
echo "[G2] seed the pipeline with candidates from OTHER sources (as cisa_kev_collector.sh's own normalizer output would), then run the collector"
km create OTHER-1 "other_collector" "cve_list=[\"CVE-2026-10001\"]" >/dev/null
km create OTHER-2 "other_collector" "cve_list=[\"CVE-2026-99999\"]" >/dev/null
km create OTHER-3 "other_collector" "cve_list=[\"CVE-2026-77777\"]" >/dev/null
: > "$QUERY_LOG"
OUT_G2="$(./security/incident_learning/collectors/ghsa_collector.sh 2>/tmp/waio-ghsa-g2-stderr.log)"
RC_G2=$?
assert_eq "G2 exit code 0" "0" "$RC_G2"
assert_eq "G2 exactly 3 distinct CVEs queried" "3" "$(sort -u "$QUERY_LOG" | grep -c . )"

echo ""
echo "[G3] a CVE with a matching GHSA advisory is emitted correctly: id/source/source_type/source_url/collected_at mapping, Patches section captured as Mitigation"
G3_LINE="$(echo "$OUT_G2" | grep 'GHSA-fixt-ure0-0001')"
assert_contains "G3 a record was emitted for the matched CVE" "$OUT_G2" "GHSA-fixt-ure0-0001"
G3_ID="$(python3 -c "import json,sys; print(json.loads(sys.argv[1])['id'])" "$G3_LINE")"
assert_eq "G3 id is the ghsa_id as-is" "GHSA-fixt-ure0-0001" "$G3_ID"
G3_SOURCE="$(python3 -c "import json,sys; print(json.loads(sys.argv[1])['source'])" "$G3_LINE")"
assert_eq "G3 source is ghsa_collector" "ghsa_collector" "$G3_SOURCE"
G3_SOURCE_TYPE="$(python3 -c "import json,sys; print(json.loads(sys.argv[1])['source_type'])" "$G3_LINE")"
assert_eq "G3 source_type is vendor_advisory" "vendor_advisory" "$G3_SOURCE_TYPE"
G3_URL="$(python3 -c "import json,sys; print(json.loads(sys.argv[1])['source_url'])" "$G3_LINE")"
assert_eq "G3 source_url is the advisory's own html_url" "https://github.com/advisories/GHSA-fixt-ure0-0001" "$G3_URL"
G3_COLLECTED_AT="$(python3 -c "import json,sys; print(json.loads(sys.argv[1])['collected_at'])" "$G3_LINE")"
assert_eq "G3 collected_at reflects published_at, not 'now'" "2026-01-01T00:00:00Z" "$G3_COLLECTED_AT"
assert_contains "G3 raw_text carries the CVE id (so incident_normalizer.sh's regex finds it)" "$G3_LINE" "CVE-2026-10001"
assert_contains "G3 raw_text carries the Patches section as Mitigation" "$G3_LINE" "Mitigation: Fixed in 9.9.9."

echo ""
echo "[G4] a second matched CVE (no Patches section in its description) is emitted without a Mitigation sentence, never an error"
G4_LINE="$(echo "$OUT_G2" | grep 'GHSA-fixt-ure0-0002')"
assert_contains "G4 a record was emitted for the second matched CVE" "$OUT_G2" "GHSA-fixt-ure0-0002"
G4_HAS_MITIGATION="$(echo "$G4_LINE" | grep -c 'Mitigation:' || true)"
assert_eq "G4 no Mitigation sentence fabricated when there's no Patches section" "0" "$G4_HAS_MITIGATION"

echo ""
echo "[G5] a CVE with zero matching GHSA advisories is skipped gracefully -- no record, no error"
G5_COUNT="$(echo "$OUT_G2" | grep -c 'CVE-2026-99999' || true)"
assert_eq "G5 no record emitted for the unmatched CVE" "0" "$G5_COUNT"
assert_eq "G5 exactly 2 records emitted total (of 3 CVEs looked up)" "2" "$(echo "$OUT_G2" | grep -c . || true)"

echo ""
echo "[G6] a candidate whose OWN source is ghsa_collector is excluded from the lookup pool (never re-queries its own past output)"
km create SELF-1 "ghsa_collector" "cve_list=[\"CVE-2026-55555\"]" >/dev/null
: > "$QUERY_LOG"
./security/incident_learning/collectors/ghsa_collector.sh >/dev/null 2>&1
SELF_QUERIED="$(grep -c '^CVE-2026-55555$' "$QUERY_LOG" || true)"
assert_eq "G6 CVE-2026-55555 (from a ghsa_collector-sourced candidate) never queried" "0" "$SELF_QUERIED"

echo ""
echo "[G7] GHSA_MAX_RECORDS caps the number of distinct CVEs looked up per run"
: > "$QUERY_LOG"
GHSA_MAX_RECORDS=1 ./security/incident_learning/collectors/ghsa_collector.sh >/dev/null 2>&1
assert_eq "G7 exactly 1 CVE queried when capped at 1" "1" "$(sort -u "$QUERY_LOG" | grep -c .)"

echo ""
echo "[G8] the summary line goes to stderr, never stdout (Collector contract: nothing but JSONL on stdout)"
G8_STDOUT_HAS_SUMMARY="$(echo "$OUT_G2" | grep -c 'GHSA COLLECTOR' || true)"
assert_eq "G8 stdout carries zero non-JSON lines" "0" "$G8_STDOUT_HAS_SUMMARY"
assert_contains "G8 stderr has the summary" "$(cat /tmp/waio-ghsa-g2-stderr.log)" "emitted 2 record(s) from 3 CVE lookup(s)"

echo ""
echo "[G9] egress denied (destination not in the fixture allowlist): exits non-zero, emits nothing on stdout, never touches this deployment's real SHUTDOWN.lock"
cat > "$FIXTURE_DIR/egress_allowlist_empty.conf" <<'EOF'
EOF
OUT_G9="$(WAIO_EGRESS_ALLOWLIST="$FIXTURE_DIR/egress_allowlist_empty.conf" ./security/incident_learning/collectors/ghsa_collector.sh 2>&1)"
RC_G9=$?
assert_eq "G9 exit code non-zero" "true" "$([ "$RC_G9" -ne 0 ] && echo true || echo false)"
assert_contains "G9 error mentions egress denial" "$OUT_G9" "egress denied by DLP guard"
rm -f "$FIXTURE_DIR/SHUTDOWN.lock"

echo ""
echo "[G10] an unreachable/failing HTTP fetch for one CVE is skipped (HTTP != 200), never crashes the run or emits a record for it"
: > "$QUERY_LOG"
OUT_G10="$(FAKE_CURL_FAIL_HOST="api.github.com" ./security/incident_learning/collectors/ghsa_collector.sh 2>/tmp/waio-ghsa-g10-stderr.log)"
RC_G10=$?
assert_eq "G10 exit code 0 (a per-lookup HTTP failure is not a fatal error)" "0" "$RC_G10"
assert_eq "G10 zero records emitted when every lookup fails" "0" "$(echo -n "$OUT_G10" | grep -c . || true)"

echo ""
echo "[G11] a malformed (non-JSON) response for one CVE is skipped cleanly, never a raw Python traceback crash"
: > "$QUERY_LOG"
OUT_G11="$(FAKE_CURL_MALFORMED=1 ./security/incident_learning/collectors/ghsa_collector.sh 2>&1 >/dev/null)"
RC_G11=$?
assert_eq "G11 exit code 0 (a malformed per-lookup body is not a fatal error)" "0" "$RC_G11"

echo ""
echo "[G12] a 403 rate-limit response stops the run early (not treated as '0 advisories found' for the remaining CVEs), never crashes"
km create RATE-1 "other_collector" "cve_list=[\"CVE-2026-88001\"]" >/dev/null
km create RATE-2 "other_collector" "cve_list=[\"CVE-2026-88002\"]" >/dev/null
: > "$QUERY_LOG"
OUT_G12="$(FAKE_CURL_RATE_LIMIT=1 ./security/incident_learning/collectors/ghsa_collector.sh 2>/tmp/waio-ghsa-g12-stderr.log)"
RC_G12=$?
assert_eq "G12 exit code 0 (rate limit stops the run cleanly, not a fatal error)" "0" "$RC_G12"
assert_eq "G12 zero records emitted" "0" "$(echo -n "$OUT_G12" | grep -c . || true)"
assert_contains "G12 stderr explains the rate-limit stop, distinct from 'not found'" "$(cat /tmp/waio-ghsa-g12-stderr.log)" "rate limit exhausted"
assert_eq "G12 only ONE lookup attempted (stopped immediately on the first 403, never tried the second CVE)" "1" "$(sort -u "$QUERY_LOG" | grep -c .)"

echo ""
echo "[D1] this collector DOES source security/lib.sh and DOES call egress_check -- the second deliberate exception in this domain"
assert_eq "D1 sources security/lib.sh" "1" "$(grep -cE '^\s*source security/lib\.sh\b' security/incident_learning/collectors/ghsa_collector.sh)"
assert_eq "D1 calls egress_check" "1" "$(grep -cE '\begress_check\s+"' security/incident_learning/collectors/ghsa_collector.sh)"

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
echo "[D4] this deployment's real Incident Learning candidate/knowledge state was never touched by this suite (KNOWLEDGE_MANAGER_* overrides used throughout)"
assert_eq "D4 real candidates dir untouched" "" "$(git status --porcelain -- security/state/incident_learning 2>/dev/null)"

echo ""
echo "=== Summary: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
  echo "Failures:"
  for f in "${FAILURES[@]}"; do echo "  - $f"; done
  exit 1
fi
exit 0
