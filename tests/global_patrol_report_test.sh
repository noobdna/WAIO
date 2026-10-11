#!/bin/bash
set -uo pipefail

# tests/global_patrol_report_test.sh -- unit-level regression suite
# for security/incident_learning/global_patrol_report.py, invoked
# directly against hand-built candidate fixtures (bypassing the full
# Collect->Normalize->...->Score pipeline and global_patrol_cron.sh
# entirely) so this suite can assert on diffing/aggregation/rendering
# logic precisely, independent of what any real Collector happens to
# produce. End-to-end wiring through the real pipeline is covered
# separately by tests/global_patrol_cron_test.sh.

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
    echo "  FAIL: $label (expected to contain '$needle')"
  fi
}

FIXTURE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/waio-global-patrol-report-test.XXXXXX")"
trap 'rm -rf "$FIXTURE_DIR"' EXIT

CANDIDATES_DIR="$FIXTURE_DIR/candidates"
STATE_PATH="$FIXTURE_DIR/last_patrol.json"
OUTPUT_DIR="$FIXTURE_DIR/reports"
LEVELS_PATH="$FIXTURE_DIR/levels.json"
mkdir -p "$CANDIDATES_DIR" "$OUTPUT_DIR"

cat > "$CANDIDATES_DIR/GP-A.json" <<'EOF'
{
  "id": "GP-A", "status": "CANDIDATE", "confidence_score": 60,
  "source": "test", "source_type": "news",
  "source_url": "https://example.invalid/a",
  "collected_at": "2026-10-01T00:00:00Z", "published_at": "2026-09-30T00:00:00Z",
  "country": "JP", "region": "APAC", "affected_sector": "finance",
  "incident_type": "account_takeover", "attack_pattern": "account_takeover",
  "claimed_impact": ["about 100 accounts affected"],
  "related_incidents": []
}
EOF
cat > "$CANDIDATES_DIR/GP-B.json" <<'EOF'
{
  "id": "GP-B", "status": "SCORED", "confidence_score": 20,
  "source": "test", "source_type": "news",
  "source_url": "https://example.invalid/b",
  "collected_at": "2026-10-01T00:00:00Z", "published_at": "2026-09-29T00:00:00Z",
  "country": "US", "region": "NA", "affected_sector": "retail_ecommerce",
  "incident_type": "data_breach", "attack_pattern": "data_breach",
  "claimed_impact": [], "related_incidents": []
}
EOF
cat > "$CANDIDATES_DIR/GP-C-malformed.json" <<'EOF'
{ this is not valid json
EOF

cat > "$LEVELS_PATH" <<'EOF'
{"GP-A": "MEDIUM", "GP-B": "UNVERIFIED"}
EOF

jf() { python3 -c "
import json, sys
d = json.load(open(sys.argv[1]))
for k in sys.argv[2].split('.'):
    d = d[k] if not k.isdigit() else d[int(k)]
print(d)
" "$1" "$2" 2>/dev/null; }

run_report() {
  python3 security/incident_learning/global_patrol_report.py \
    "$CANDIDATES_DIR" "$STATE_PATH" "$OUTPUT_DIR" "$1" "$LEVELS_PATH" "${2:-ok}"
}

echo "=== Global Patrol Report generator unit suite ==="

echo ""
echo "[R1] first invocation (no prior state file): is_first_run true, both real candidates reported as new, the malformed file is silently skipped (not a crash)"
R1_RC="$(run_report "2026-10-01T12:00:00Z" >/dev/null 2>"$FIXTURE_DIR/r1.stderr"; echo $?)"
assert_eq "R1 exit code 0 despite one malformed candidate file" "0" "$R1_RC"
LATEST="$OUTPUT_DIR/global-patrol-report-latest.json"
assert_eq "R1 is_first_run true" "True" "$(jf "$LATEST" is_first_run)"
assert_eq "R1 all_known_candidates == 2 (malformed file excluded)" "2" "$(jf "$LATEST" totals.all_known_candidates)"
assert_eq "R1 new_since_last_patrol == 2" "2" "$(jf "$LATEST" totals.new_since_last_patrol)"

echo ""
echo "[R2] date-field honesty: occurred_at/discovered_at are always '不明' (no such field exists upstream); published_at/collected_at are passed through verbatim"
GP_A_ENTRY="$(python3 -c "
import json
d = json.load(open('$LATEST'))
e = [x for x in d['new_incidents'] if x['id'] == 'GP-A'][0]
print(e['occurred_at'], '|', e['discovered_at'], '|', e['published_at'], '|', e['collected_at'])
")"
assert_eq "R2 GP-A date fields" "不明 | 不明 | 2026-09-30T00:00:00Z | 2026-10-01T00:00:00Z" "$GP_A_ENTRY"

echo ""
echo "[R3] confidence_level comes from the precomputed levels map, never re-derived from confidence_score"
assert_eq "R3 GP-A level == MEDIUM (from levels.json, not re-derived from score=60)" "MEDIUM" "$(python3 -c "
import json
d = json.load(open('$LATEST'))
print([x for x in d['new_incidents'] if x['id']=='GP-A'][0]['confidence_level'])
")"

echo ""
echo "[R4] trend aggregation: by_country/by_sector/by_incident_type counts are correct"
assert_eq "R4 by_country JP==1,US==1" "True" "$(python3 -c "
import json
d = json.load(open('$LATEST'))['trends']['by_country']
print(d.get('JP')==1 and d.get('US')==1)
")"
assert_eq "R4 by_sector finance==1,retail_ecommerce==1" "True" "$(python3 -c "
import json
d = json.load(open('$LATEST'))['trends']['by_sector']
print(d.get('finance')==1 and d.get('retail_ecommerce')==1)
")"

echo ""
echo "[R5] second invocation, same candidates, same levels: diff is honest -- zero new, state file's known_candidate_ids now covers both"
R5_RC="$(run_report "2026-10-04T12:00:00Z" >/dev/null 2>&1; echo $?)"
assert_eq "R5 exit code 0" "0" "$R5_RC"
assert_eq "R5 is_first_run now false" "False" "$(jf "$LATEST" is_first_run)"
assert_eq "R5 new_since_last_patrol == 0" "0" "$(jf "$LATEST" totals.new_since_last_patrol)"
assert_eq "R5 previous_run_at carried over from the first run" "2026-10-01T12:00:00Z" "$(jf "$LATEST" previous_run_at)"

echo ""
echo "[R6] attack_method_changes: adding a third candidate with a NEW attack_pattern between two runs shows up as a +1 delta, and an existing pattern's count is unaffected unless it actually changed"
cat > "$CANDIDATES_DIR/GP-D.json" <<'EOF'
{
  "id": "GP-D", "status": "SCORED", "confidence_score": 10,
  "source": "test", "source_type": "news",
  "source_url": "https://example.invalid/d",
  "collected_at": "2026-10-05T00:00:00Z", "published_at": "2026-10-05T00:00:00Z",
  "country": "EE", "region": "EU", "affected_sector": "technology",
  "incident_type": "ddos", "attack_pattern": "ddos",
  "claimed_impact": [], "related_incidents": []
}
EOF
echo '{"GP-A":"MEDIUM","GP-B":"UNVERIFIED","GP-D":"UNVERIFIED"}' > "$LEVELS_PATH"
run_report "2026-10-08T12:00:00Z" >/dev/null 2>&1
DDOS_CHANGE="$(python3 -c "
import json
d = json.load(open('$LATEST'))
rows = [c for c in d['attack_method_changes'] if c['attack_pattern']=='ddos']
print(rows[0]['previous_count'], rows[0]['current_count'], rows[0]['delta'])
")"
assert_eq "R6 ddos attack_pattern went 0 -> 1 (delta +1)" "0 1 1" "$DDOS_CHANGE"
NO_SPURIOUS_CHANGE="$(python3 -c "
import json
d = json.load(open('$LATEST'))
print(any(c['attack_pattern']=='account_takeover' for c in d['attack_method_changes']))
")"
assert_eq "R6 account_takeover (unchanged count) is NOT listed as a change" "False" "$NO_SPURIOUS_CHANGE"

echo ""
echo "[R7] markdown report contains all 6 requested sections plus the data-quality notes section"
MD="$OUTPUT_DIR/global-patrol-report-latest.md"
MD_TEXT="$(cat "$MD")"
assert_contains "R7 section 1 Global Incident Summary" "$MD_TEXT" "## 1. Global Incident Summary"
assert_contains "R7 section 2 new incident list" "$MD_TEXT" "## 2. 新規インシデント一覧"
assert_contains "R7 section 3 country/region/sector trends" "$MD_TEXT" "## 3. 国・地域・業種別の傾向"
assert_contains "R7 section 4 attack method changes" "$MD_TEXT" "## 4. 攻撃手法の変化"
assert_contains "R7 section 5 WAIO improvement proposals" "$MD_TEXT" "## 5. WAIOの検知・封じ込め改善案"
assert_contains "R7 section 6 items before next patrol" "$MD_TEXT" "## 6. 次回巡回までの重要事項"
assert_contains "R7 data quality notes section present" "$MD_TEXT" "データ品質に関する注記"

echo ""
echo "[R8] safety-framing check: the report never states a detection/containment CLAIM, and explicitly disclaims breach-rate estimation"
assert_contains "R8 WAIO section explicitly disclaims this is a desk review, not an actual detection" "$MD_TEXT" "実際に検知・封じ込めが行われたことを意味しません"
assert_contains "R8 data_quality_notes explicitly refuses to estimate an overall breach rate from unknown-population candidate counts" "$MD_TEXT" "侵害率を推定することはしない"
assert_contains "R8 data_quality_notes explicitly states unpublished/undetected incidents are not treated as fact" "$MD_TEXT" "発生した事実として扱っていない"

echo ""
echo "[R9] pipeline_status is threaded through honestly when the caller reports a degraded collection cycle"
run_report "2026-10-09T00:00:00Z" "degraded" >/dev/null 2>&1
assert_eq "R9 pipeline_status == degraded" "degraded" "$(jf "$LATEST" pipeline_status)"

echo ""
echo "[R10] missing/insufficient arguments fail fast with a non-zero exit and write NOTHING (no partial report, no state mutation)"
BEFORE_STATE_MTIME="$(stat -f %m "$STATE_PATH" 2>/dev/null || stat -c %Y "$STATE_PATH" 2>/dev/null)"
R10_RC="$(python3 security/incident_learning/global_patrol_report.py "$CANDIDATES_DIR" "$STATE_PATH" >/dev/null 2>&1; echo $?)"
assert_eq "R10 exit code non-zero on missing arguments" "true" "$([ "$R10_RC" != "0" ] && echo true || echo false)"
AFTER_STATE_MTIME="$(stat -f %m "$STATE_PATH" 2>/dev/null || stat -c %Y "$STATE_PATH" 2>/dev/null)"
assert_eq "R10 state file untouched by the failed invocation" "$BEFORE_STATE_MTIME" "$AFTER_STATE_MTIME"

echo ""
echo "[R11] section 7 (Critical Infrastructure & Military Precursor Watch) is present in both JSON and Markdown, and its own carryover state file is created as a sibling of STATE_PATH with no extra argument needed"
run_report "2026-10-09T06:00:00Z" >/dev/null 2>&1
assert_eq "R11 critical_infrastructure_watch key present in JSON" "True" "$(python3 -c "
import json
d = json.load(open('$LATEST'))
print('critical_infrastructure_watch' in d)
")"
assert_contains "R11 markdown has section 7 header" "$(cat "$MD")" "## 7. Critical Infrastructure & Military Precursor Watch"
assert_eq "R11 carryover file created next to STATE_PATH with no 7th argv" "true" "$([ -f "$FIXTURE_DIR/critical_watch_carryover.json" ] && echo true || echo false)"

echo ""
echo "[D1] *** CRITICAL GUARD *** this module (and the critical_infra_watch module it now imports for section 7) makes zero network calls of its own (no urllib/requests/http/socket/curl/wget anywhere) -- every real fetch already happened inside the Collectors, in a separate process, before this report generator ever runs"
net_refs=0
for f in security/incident_learning/global_patrol_report.py security/incident_learning/critical_infra_watch.py; do
  c="$(grep -ciE 'urllib|requests|http\.client|socket\.|subprocess|os\.system|os\.popen' "$f" || true)"
  net_refs=$((net_refs + c))
done
assert_eq "D1 zero network/subprocess-execution references (both files)" "0" "$net_refs"

echo ""
echo "=== Summary: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
  echo "Failures:"
  printf '  - %s\n' "${FAILURES[@]}"
  exit 1
fi
exit 0
