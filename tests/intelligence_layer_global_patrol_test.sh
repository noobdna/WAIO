#!/bin/bash
set -uo pipefail

# tests/intelligence_layer_global_patrol_test.sh -- regression suite for
# WAIO GLOBAL RED ALERT Phase A: the `--global-patrol-report FILE` and
# `--snd-snapshot FILE` optional flags added to
# security/intelligence/intelligence_layer.sh's own `ingest()`.
#
# Deliberately a SEPARATE suite from tests/intelligence_layer_test.sh
# (which is re-run unmodified, and still passes unmodified, alongside
# this one) rather than appended to it -- this suite exists specifically
# to prove the NEW flags, while tests/intelligence_layer_test.sh keeps
# proving the four pre-existing flags are byte-for-byte unaffected.
#
# Same three-layer convention as the rest of this pipeline's test
# suites:
#   I-series: integration tests against the real CLI, hand-written
#     fixtures shaped exactly like global_patrol_report.py's own real
#     output (logs/global-patrol-report-latest.json) and continuity.sh's
#     own {"pdc_cached_at","snd_status"} envelope -- no live
#     global_patrol_cron.sh/continuity.sh/security/red_alert run
#     invoked at all.
#   D-series: static structural guards -- confirm this change touches
#     ONLY intelligence_layer.sh (never intelligence_lib.py, never
#     decision_engine.sh/decision_engine_lib.py/guardian.sh/ducopa.sh,
#     never any cron wrapper or launchd plist), and that
#     security/red_alert/'s own D6/D7/D8 guards (tests/red_alert_test.sh)
#     still hold after this change.
#
# Every case runs against an isolated INTELLIGENCE_STATE_DIR/
# INTELLIGENCE_AUDIT_LOG, never this deployment's real
# security/state/intelligence/.

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

jget() {
  # jget JSON_STRING PY_EXPR -- tiny helper, same pattern the existing
  # intelligence_layer_test.sh already uses inline everywhere below.
  python3 -c "import json,sys; d=json.load(sys.stdin); print($2)" <<<"$1"
}

code_only() {
  grep -vE '^[[:space:]]*#' "$1"
}

echo "=== WAIO GLOBAL RED ALERT Phase A regression suite ==="
echo "    (intelligence_layer.sh ingest(): --global-patrol-report / --snd-snapshot)"

FIXTURE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/waio-il-global-patrol-test.XXXXXX")"
trap 'rm -rf "$FIXTURE_DIR" /tmp/waio_phaseA_injection_marker*' EXIT
mkdir -p "$FIXTURE_DIR/state"

export INTELLIGENCE_STATE_DIR="$FIXTURE_DIR/state"
export INTELLIGENCE_AUDIT_LOG="$FIXTURE_DIR/audit.jsonl"

# Real-shaped Global Patrol report fixture: one new_incidents entry
# (KEV-RA-1, attack_pattern=ransomware), one confirmed_activity entry
# (CIW-1, attack_pattern=grid_intrusion, critical_sectors=[energy]), one
# precursor_hypothesis sharing CIW-1's own attack_pattern across two
# countries -- field names copied verbatim from
# global_patrol_report.py's own _candidate_summary()/
# critical_infra_watch.py's own build_section() output, confirmed by
# reading both modules directly before writing this fixture.
cat > "$FIXTURE_DIR/gp_report.json" <<'EOF'
{
  "generated_at": "2026-01-01T00:00:00Z",
  "new_incidents": [
    {"id": "KEV-RA-1", "source": "cisa_kev_collector", "source_url": "https://example.invalid/1", "country": "US", "region": "unknown", "affected_sector": "energy", "incident_type": "vulnerability", "attack_pattern": "ransomware", "confidence_level": "HIGH", "published_at": "2026-01-01T00:00:00Z", "collected_at": "2026-01-01T00:00:00Z"}
  ],
  "critical_infrastructure_watch": {
    "confirmed_activity": [
      {"id": "CIW-1", "critical_sectors": ["energy"], "incident_type": "sabotage", "attack_pattern": "grid_intrusion", "country": "JP", "confidence_level": "CONFIRMED", "source_url": "https://example.invalid/2", "source": "jpcert_collector"}
    ],
    "precursor_hypotheses": [
      {"attack_pattern": "grid_intrusion", "member_ids": ["CIW-1", "CIW-2"], "countries_involved": ["JP", "US"], "alternative_explanations": ["coincidence"], "confidence_caveat": "hypothesis only, not a confirmed attack"}
    ]
  }
}
EOF

# SND@HOME snapshot fixture, real envelope shape (continuity.sh snd-get):
# active_alerts text genuinely contains "ransomware" -- a real textual
# overlap with KEV-RA-1's own attack_pattern.
cat > "$FIXTURE_DIR/snd_snapshot.json" <<'EOF'
{"pdc_cached_at": "2026-01-01T00:00:00Z", "snd_status": {"active_alerts": {"alerts": ["RANSOMWARE activity detected on segment 3"]}, "lan_status": null, "system_status": null, "terminals": null}}
EOF

# Negative-control SND@HOME snapshot: genuinely unrelated text, no
# keyword overlap with ransomware/grid_intrusion/energy at all.
cat > "$FIXTURE_DIR/snd_snapshot_no_overlap.json" <<'EOF'
{"pdc_cached_at": "2026-01-01T00:00:00Z", "snd_status": {"active_alerts": {"alerts": ["routine LAN health check, nothing unusual"]}, "lan_status": {"note": "all terminals nominal"}, "system_status": null, "terminals": null}}
EOF

echo ""
echo "=== I-series: --global-patrol-report / --snd-snapshot integration tests ==="

echo ""
echo "[I1] --global-patrol-report alone: new_incidents + confirmed_activity + precursor_hypotheses all ingested, snd_crossref stays 0 (no --snd-snapshot given)"
OUT="$(./security/intelligence/intelligence_layer.sh ingest --global-patrol-report "$FIXTURE_DIR/gp_report.json" 2>/dev/null)"
assert_eq "I1 global_patrol count 1" "1" "$(jget "$OUT" "d['sources_ingested']['global_patrol']")"
assert_eq "I1 critical_infra_watch count 2 (1 confirmed_activity + 1 precursor_hypothesis)" "2" "$(jget "$OUT" "d['sources_ingested']['critical_infra_watch']")"
assert_eq "I1 snd_crossref count 0 (flag not given)" "0" "$(jget "$OUT" "d['sources_ingested']['snd_crossref']")"
assert_eq "I1 entity_count 3 (KEV-RA-1, CIW-1, grid_intrusion hypothesis)" "3" "$(jget "$OUT" "d['summary']['entity_count']")"
assert_eq "I1 CIW-1 entity_type is critical_infra_activity" "critical_infra_activity" "$(jget "$OUT" "d['entities']['CIW-1']['entity_type']")"
assert_eq "I1 grid_intrusion hypothesis entity_type is precursor_hypothesis" "precursor_hypothesis" "$(jget "$OUT" "d['entities']['grid_intrusion']['entity_type']")"

echo ""
echo "[I2] --snd-snapshot alone (no --global-patrol-report in the same call): zero entities to cross-reference against -> 0 records, 0 signals, NOT an error"
OUT="$(./security/intelligence/intelligence_layer.sh ingest --snd-snapshot "$FIXTURE_DIR/snd_snapshot.json" 2>/dev/null)"
RC=$?
assert_eq "I2 exit code 0" "0" "$RC"
assert_eq "I2 records_total 0" "0" "$(jget "$OUT" "d['records_total']")"
assert_eq "I2 snd_crossref count 0" "0" "$(jget "$OUT" "d['sources_ingested']['snd_crossref']")"

echo ""
echo "[I3] *** THE CRITICAL INTEGRATION CASE *** both flags together, real keyword overlap: snd_crossref fires, KEV-RA-1 becomes multi-source (global_patrol + snd_home_crossref), highest_risk stays HIGH (never downgraded by the LOW-risk crossref signal)"
OUT="$(./security/intelligence/intelligence_layer.sh ingest --global-patrol-report "$FIXTURE_DIR/gp_report.json" --snd-snapshot "$FIXTURE_DIR/snd_snapshot.json" 2>/dev/null)"
assert_eq "I3 snd_crossref count 1" "1" "$(jget "$OUT" "d['sources_ingested']['snd_crossref']")"
assert_eq "I3 KEV-RA-1 source_modules has both" "['global_patrol', 'snd_home_crossref']" "$(jget "$OUT" "d['entities']['KEV-RA-1']['source_modules']")"
assert_eq "I3 KEV-RA-1 highest_risk stays HIGH" "HIGH" "$(jget "$OUT" "d['entities']['KEV-RA-1']['highest_risk']")"
assert_eq "I3 KEV-RA-1 record_count 2" "2" "$(jget "$OUT" "d['entities']['KEV-RA-1']['record_count']")"
assert_eq "I3 multi_source_entity_count 1 (only KEV-RA-1; CIW-1/grid_intrusion have no snd overlap keyword of their own in this fixture)" "1" "$(jget "$OUT" "d['summary']['multi_source_entity_count']")"

echo ""
echo "[I4] *** NEGATIVE CONTROL *** both flags together, SND@HOME text has NO genuine keyword overlap with any ingested entity: snd_crossref MUST stay 0, no false-positive multi-source corroboration anywhere"
OUT="$(./security/intelligence/intelligence_layer.sh ingest --global-patrol-report "$FIXTURE_DIR/gp_report.json" --snd-snapshot "$FIXTURE_DIR/snd_snapshot_no_overlap.json" 2>/dev/null)"
assert_eq "I4 snd_crossref count 0 (negative control)" "0" "$(jget "$OUT" "d['sources_ingested']['snd_crossref']")"
assert_eq "I4 multi_source_entity_count 0" "0" "$(jget "$OUT" "d['summary']['multi_source_entity_count']")"
assert_eq "I4 KEV-RA-1 source_modules is global_patrol ONLY (no false crossref corroboration)" "['global_patrol']" "$(jget "$OUT" "d['entities']['KEV-RA-1']['source_modules']")"

echo ""
echo "[I5] missing --global-patrol-report file: skipped gracefully, exit 0, stderr names the skip, never a traceback"
MISSING_ERR="$(mktemp)"
OUT="$(./security/intelligence/intelligence_layer.sh ingest --global-patrol-report "$FIXTURE_DIR/does_not_exist.json" 2>"$MISSING_ERR")"
RC=$?
assert_eq "I5 exit code 0 despite missing file" "0" "$RC"
assert_eq "I5 global_patrol count 0" "0" "$(jget "$OUT" "d['sources_ingested']['global_patrol']")"
assert_contains "I5 stderr names the skip, not a Python traceback" "$(cat "$MISSING_ERR")" "[global-patrol-report] skipped"
assert_eq "I5 stderr is NOT a raw Traceback" "0" "$(grep -c 'Traceback (most recent call last)' "$MISSING_ERR" || true)"
rm -f "$MISSING_ERR"

echo ""
echo "[I6] missing --snd-snapshot file: skipped gracefully, exit 0, stderr names the skip"
MISSING_ERR="$(mktemp)"
OUT="$(./security/intelligence/intelligence_layer.sh ingest --global-patrol-report "$FIXTURE_DIR/gp_report.json" --snd-snapshot "$FIXTURE_DIR/does_not_exist.json" 2>"$MISSING_ERR")"
RC=$?
assert_eq "I6 exit code 0 despite missing snd-snapshot file" "0" "$RC"
assert_eq "I6 snd_crossref count 0" "0" "$(jget "$OUT" "d['sources_ingested']['snd_crossref']")"
assert_contains "I6 stderr names the skip" "$(cat "$MISSING_ERR")" "[snd-snapshot] skipped"
rm -f "$MISSING_ERR"

echo ""
echo "[I7] malformed --global-patrol-report (not valid JSON at all): skipped gracefully, never crashes, other flags in the same call still work"
echo 'this is not json { [ broken' > "$FIXTURE_DIR/malformed_gp.json"
MALFORMED_ERR="$(mktemp)"
OUT="$(./security/intelligence/intelligence_layer.sh ingest --global-patrol-report "$FIXTURE_DIR/malformed_gp.json" --snd-snapshot "$FIXTURE_DIR/snd_snapshot.json" 2>"$MALFORMED_ERR")"
RC=$?
assert_eq "I7 exit code 0 despite malformed JSON" "0" "$RC"
assert_eq "I7 global_patrol count 0" "0" "$(jget "$OUT" "d['sources_ingested']['global_patrol']")"
assert_eq "I7 records_total 0 (no entities to crossref against either)" "0" "$(jget "$OUT" "d['records_total']")"
assert_contains "I7 stderr names the skip" "$(cat "$MALFORMED_ERR")" "[global-patrol-report] skipped"
rm -f "$MALFORMED_ERR"

echo ""
echo "[I8] malformed --global-patrol-report shape (valid JSON, but top-level is a LIST, not an object): skipped gracefully, never crashes"
echo '["not", "an", "object"]' > "$FIXTURE_DIR/list_shaped_gp.json"
OUT="$(./security/intelligence/intelligence_layer.sh ingest --global-patrol-report "$FIXTURE_DIR/list_shaped_gp.json" 2>/dev/null)"
RC=$?
assert_eq "I8 exit code 0 despite list-shaped top level" "0" "$RC"
assert_eq "I8 global_patrol count 0" "0" "$(jget "$OUT" "d['sources_ingested']['global_patrol']")"

echo ""
echo "[I9] new_incidents present but not a list (a string): treated as empty, never crashes"
echo '{"new_incidents": "not-a-list"}' > "$FIXTURE_DIR/bad_new_incidents.json"
OUT="$(./security/intelligence/intelligence_layer.sh ingest --global-patrol-report "$FIXTURE_DIR/bad_new_incidents.json" 2>/dev/null)"
RC=$?
assert_eq "I9 exit code 0 despite non-list new_incidents" "0" "$RC"
assert_eq "I9 global_patrol count 0" "0" "$(jget "$OUT" "d['sources_ingested']['global_patrol']")"

echo ""
echo "[I10] a precursor_hypothesis entry missing attack_pattern is skipped INDIVIDUALLY -- a sibling valid entry in the same file still ingests"
cat > "$FIXTURE_DIR/mixed_hypotheses.json" <<'EOF'
{
  "new_incidents": [],
  "critical_infrastructure_watch": {
    "confirmed_activity": [],
    "precursor_hypotheses": [
      {"member_ids": ["X1", "X2"], "countries_involved": ["JP", "US"]},
      {"attack_pattern": "valid_pattern", "member_ids": ["Y1", "Y2"], "countries_involved": ["JP", "US"], "confidence_caveat": "ok"}
    ]
  }
}
EOF
OUT="$(./security/intelligence/intelligence_layer.sh ingest --global-patrol-report "$FIXTURE_DIR/mixed_hypotheses.json" 2>/dev/null)"
assert_eq "I10 critical_infra_watch count 1 (only the valid hypothesis)" "1" "$(jget "$OUT" "d['sources_ingested']['critical_infra_watch']")"
assert_contains "I10 valid_pattern entity present" "$OUT" "valid_pattern"

echo ""
echo "[I11] a new_incidents / confirmed_activity entry missing its own id is skipped individually, never guessed"
cat > "$FIXTURE_DIR/missing_id.json" <<'EOF'
{
  "new_incidents": [
    {"source": "cisa_kev_collector", "attack_pattern": "ransomware", "confidence_level": "HIGH"},
    {"id": "KEV-HAS-ID", "attack_pattern": "ransomware", "confidence_level": "HIGH"}
  ],
  "critical_infrastructure_watch": {"confirmed_activity": [], "precursor_hypotheses": []}
}
EOF
OUT="$(./security/intelligence/intelligence_layer.sh ingest --global-patrol-report "$FIXTURE_DIR/missing_id.json" 2>/dev/null)"
assert_eq "I11 global_patrol count 1 (only the id-bearing entry)" "1" "$(jget "$OUT" "d['sources_ingested']['global_patrol']")"
assert_contains "I11 KEV-HAS-ID present" "$OUT" "KEV-HAS-ID"

echo ""
echo "[I12] malformed --snd-snapshot (not valid JSON): skipped gracefully, never crashes"
echo 'also not json' > "$FIXTURE_DIR/malformed_snd.json"
OUT="$(./security/intelligence/intelligence_layer.sh ingest --global-patrol-report "$FIXTURE_DIR/gp_report.json" --snd-snapshot "$FIXTURE_DIR/malformed_snd.json" 2>/dev/null)"
RC=$?
assert_eq "I12 exit code 0 despite malformed snd-snapshot" "0" "$RC"
assert_eq "I12 snd_crossref count 0" "0" "$(jget "$OUT" "d['sources_ingested']['snd_crossref']")"

echo ""
echo "[I13] --snd-snapshot envelope missing its own snd_status key entirely: treated the same as 'no snapshot available' (snd_crossref.py's own None contract), never crashes"
echo '{"pdc_cached_at": "2026-01-01T00:00:00Z"}' > "$FIXTURE_DIR/no_snd_status_key.json"
OUT="$(./security/intelligence/intelligence_layer.sh ingest --global-patrol-report "$FIXTURE_DIR/gp_report.json" --snd-snapshot "$FIXTURE_DIR/no_snd_status_key.json" 2>/dev/null)"
RC=$?
assert_eq "I13 exit code 0" "0" "$RC"
assert_eq "I13 snd_crossref count 0" "0" "$(jget "$OUT" "d['sources_ingested']['snd_crossref']")"

echo ""
echo "[I14] *** CONFLICTING / INVALID OPTIONS *** an unrecognized flag mixed in with the two new flags still triggers the SAME Usage error the parser already gave before this change -- the new flags do not swallow or bypass that existing validation"
USAGE_ERR="$(mktemp)"
./security/intelligence/intelligence_layer.sh ingest --global-patrol-report "$FIXTURE_DIR/gp_report.json" --this-flag-does-not-exist whatever >/dev/null 2>"$USAGE_ERR"
RC=$?
assert_eq "I14 exit code 1 on unrecognized flag" "1" "$RC"
assert_contains "I14 stderr shows the Usage message, including both new flags" "$(cat "$USAGE_ERR")" "--global-patrol-report FILE"
assert_contains "I14 Usage message also still lists --snd-snapshot" "$(cat "$USAGE_ERR")" "--snd-snapshot FILE"
rm -f "$USAGE_ERR"

echo ""
echo "[I15] *** LEGACY BEHAVIOR UNCHANGED *** the four pre-existing flags, run through ingest() with this phase's new code present, produce IDENTICAL results to the pre-existing contract (same fixture shapes as tests/intelligence_layer_test.sh's own I1)"
cat > "$FIXTURE_DIR/legacy_shadow_ai.jsonl" <<'EOF'
{"id": "SHADOWAI-1", "detected_at": "2026-01-01T00:00:00Z", "finding_type": "process", "category": "local_llm_runtime", "signature_matched": "ollama", "signature_label": "l", "match_kind": "process_name", "process": {"pid": 1, "ppid": 0, "user": "masa", "comm": "ollama", "args": "ollama serve"}, "network": null, "allowlisted": false, "risk": "MEDIUM", "confidence": "HIGH", "reason": "fixture"}
EOF
OUT="$(./security/intelligence/intelligence_layer.sh ingest --shadow-ai "$FIXTURE_DIR/legacy_shadow_ai.jsonl" 2>/dev/null)"
assert_eq "I15 shadow_ai count 1, exactly as the pre-existing contract always produced" "1" "$(jget "$OUT" "d['sources_ingested']['shadow_ai']")"
assert_eq "I15 new counters exist and are 0 when their flags are absent" "0 0 0" "$(jget "$OUT" "f\"{d['sources_ingested']['global_patrol']} {d['sources_ingested']['critical_infra_watch']} {d['sources_ingested']['snd_crossref']}\"")"
assert_eq "I15 entity_count 1 (ollama only)" "1" "$(jget "$OUT" "d['summary']['entity_count']")"

echo ""
echo "[I16] ingest with NO flags at all: still produces the completely empty report, all seven counters present and zero -- the new counters never change the 'no flags = empty report' contract"
OUT="$(./security/intelligence/intelligence_layer.sh ingest 2>/dev/null)"
RC=$?
assert_eq "I16 exit code 0" "0" "$RC"
assert_eq "I16 records_total 0" "0" "$(jget "$OUT" "d['records_total']")"
assert_eq "I16 all seven source counters are 0" "0 0 0 0 0 0 0" "$(jget "$OUT" "' '.join(str(d['sources_ingested'][k]) for k in ['shadow_ai','attack_graph','incident_learning','saas_ato','global_patrol','critical_infra_watch','snd_crossref'])")"

echo ""
echo "[I17] *** INJECTION SAFETY *** shell-metacharacter-laden strings inside attack_pattern/critical_sectors are NEVER executed -- they appear verbatim as inert text in the output, and no marker file is ever created"
rm -f /tmp/waio_phaseA_injection_marker /tmp/waio_phaseA_injection_marker2
cat > "$FIXTURE_DIR/injection_attempt.json" <<'EOF'
{
  "new_incidents": [
    {"id": "INJ-1", "attack_pattern": "ransomware; touch /tmp/waio_phaseA_injection_marker ; `touch /tmp/waio_phaseA_injection_marker2`", "confidence_level": "HIGH", "source": "fixture"}
  ],
  "critical_infrastructure_watch": {"confirmed_activity": [], "precursor_hypotheses": []}
}
EOF
OUT="$(./security/intelligence/intelligence_layer.sh ingest --global-patrol-report "$FIXTURE_DIR/injection_attempt.json" 2>/dev/null)"
assert_contains "I17 the malicious-looking string is stored verbatim as inert text" "$OUT" 'touch /tmp/waio_phaseA_injection_marker'
assert_eq "I17 no marker file was ever created (never executed)" "absent absent" "$([ -e /tmp/waio_phaseA_injection_marker ] && echo present || echo absent) $([ -e /tmp/waio_phaseA_injection_marker2 ] && echo present || echo absent)"

echo ""
echo "=== D-series: structural guards -- this change touches ONLY intelligence_layer.sh, and security/red_alert/'s own unwired-state guards still hold ==="

echo ""
echo "[D1] intelligence_lib.py is byte-for-byte unmodified by this phase (this phase changes the CLI wrapper only, never the pure library every OTHER caller of aggregate_by_entity/rank_profiles/report_summary also depends on)"
assert_eq "D1 security/intelligence/intelligence_lib.py has no working-tree diff" "" "$(git diff --name-only -- security/intelligence/intelligence_lib.py 2>/dev/null)"

echo ""
echo "[D2] this phase touches NOTHING under security/decision_engine/, security/guardian.sh, security/ducopa.sh, or any cron/launchd wiring -- GLOBAL RED ALERT remains unwired from production exactly as before"
for f in security/decision_engine/decision_engine.sh security/decision_engine/decision_engine_lib.py security/guardian.sh security/ducopa.sh security/incident_learning/global_patrol_cron.sh; do
  assert_eq "D2 $f has no working-tree diff" "" "$(git diff --name-only -- "$f" 2>/dev/null)"
done
assert_eq "D2 zero new *.plist / *.plist.example files introduced" "0" "$(git status --porcelain -- '*.plist*' 2>/dev/null | wc -l | tr -d ' ')"

echo ""
echo "[D3] intelligence_layer.sh's own actual code (comments stripped) still never sources security/lib.sh and never calls egress_check/trigger_shutdown/audit_log -- the new red_alert import does not change this file's own Control-Plane posture"
for pattern in 'source security/lib\.sh' 'egress_check' 'trigger_shutdown' '\baudit_log\('; do
  cnt="$(code_only security/intelligence/intelligence_layer.sh | grep -cE "$pattern" || true)"
  assert_eq "D3 zero code occurrences of '$pattern'" "0" "$cnt"
done

echo ""
echo "[D4] zero network tools (curl/wget/nc) and zero process/firewall-modifying commands anywhere in the file's actual code, including the new flags' own code block"
bad_calls=0
for pattern in '\b(curl|wget|nc )\b' '\bkill\b' '\bkillall\b' '\bpfctl\b' '\bifconfig\b'; do
  c="$(code_only security/intelligence/intelligence_layer.sh | grep -cE "$pattern" || true)"
  bad_calls=$((bad_calls + c))
done
assert_eq "D4 zero network/modifying-command invocations" "0" "$bad_calls"

echo ""
echo "[D5] security/red_alert/'s own D6/D7/D8 unwired-state guards (tests/red_alert_test.sh) still hold after this phase: zero references to red_alert/snd_crossref in decision_engine.sh/decision_engine_lib.py/guardian.sh/ducopa.sh, no *red*alert* launchd plist. UPDATED BY PHASE B: red_alert_cron.sh now deliberately exists (tests/red_alert_cron_test.sh) -- still not scheduled or wired anywhere, see that suite's own D-series for the direct proof."
cnt=0
for f in security/decision_engine/decision_engine.sh security/decision_engine/decision_engine_lib.py security/guardian.sh security/ducopa.sh; do
  c="$(grep -cE 'red_alert|snd_crossref' "$f" 2>/dev/null || true)"
  cnt=$((cnt + c))
done
assert_eq "D5 zero red_alert/snd_crossref references outside intelligence_layer.sh and security/red_alert/ itself" "0" "$cnt"
assert_eq "D5 no *red*alert* launchd plist anywhere" "0" "$(find . -iname '*red*alert*.plist*' -not -path './logs/*' -not -path './results/*' 2>/dev/null | wc -l | tr -d ' ')"

echo ""
echo "[D6] the new red_alert import lines are exactly two sys.path.insert + two import statements -- intelligence_layer.sh does not import shadow_ai_lib/attack_graph_lib/saas_ato_lib (the pre-existing loose-coupling rule, unaffected by this phase)"
assert_eq "D6 zero 'import shadow_ai'/'import attack_graph'/'import saas_ato' in the python heredoc" "0" "$(code_only security/intelligence/intelligence_layer.sh | grep -cE 'import (shadow_ai|attack_graph|saas_ato)' || true)"
assert_contains "D6 the file DOES import red_alert_adapter, as designed" "$(code_only security/intelligence/intelligence_layer.sh)" "import red_alert_adapter as ra"
assert_contains "D6 the file DOES import snd_crossref, as designed" "$(code_only security/intelligence/intelligence_layer.sh)" "import snd_crossref as sc"

echo ""
echo "=== Summary: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
  echo "Failures:"
  for f in "${FAILURES[@]}"; do echo "  - $f"; done
  exit 1
fi
exit 0
