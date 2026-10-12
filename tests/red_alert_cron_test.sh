#!/bin/bash
set -uo pipefail

# tests/red_alert_cron_test.sh -- regression suite for WAIO GLOBAL RED
# ALERT Phase B: security/red_alert/red_alert_cron.sh, the manual-
# invocation-only, read-only prototype that feeds Phase A's
# intelligence_layer.sh ingest --global-patrol-report/--snd-snapshot
# flags from whatever real Global Patrol report / SND@HOME snapshot
# already exist on disk.
#
# Same three-layer convention as the rest of this pipeline's suites:
#   I-series: integration tests against the real script, with
#     hand-written fixtures shaped like the real producers' own output
#     (same fixture shapes tests/intelligence_layer_global_patrol_test.sh
#     already verified against the real producer modules) -- no live
#     global_patrol_cron.sh/continuity.sh run invoked at all.
#   D-series: static structural guards -- this file never references
#     the Decision Engine, Guardian, DuCoPA, recovery/promotion tools,
#     never sources security/lib.sh, never schedules/installs itself,
#     and security/red_alert/'s own pure modules remain byte-identical.
#
# Every case runs against an isolated INTELLIGENCE_STATE_DIR/
# INTELLIGENCE_AUDIT_LOG/RED_ALERT_CRON_LOG/GLOBAL_PATROL_OUTPUT_DIR/
# WAIO_CONTINUITY_STATE_DIR -- never this deployment's real
# logs/global-patrol-report-latest.json or
# security/state/continuity/snd_snapshot.json paths, and never this
# deployment's real security/state/intelligence/.

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

assert_not_contains() {
  local label="$1" haystack="$2" needle="$3"
  if [[ "$haystack" != *"$needle"* ]]; then
    PASS=$((PASS + 1)); echo "  PASS: $label"
  else
    FAIL=$((FAIL + 1)); FAILURES+=("$label (expected NOT to contain '$needle')")
    echo "  FAIL: $label (expected NOT to contain '$needle')"
  fi
}

jget() {
  python3 -c "import json,sys; d=json.load(sys.stdin); print($2)" <<<"$1"
}

code_only() {
  grep -vE '^[[:space:]]*#' "$1"
}

echo "=== WAIO GLOBAL RED ALERT Phase B regression suite ==="
echo "    (security/red_alert/red_alert_cron.sh)"

FIXTURE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/waio-red-alert-cron-test.XXXXXX")"
trap 'rm -rf "$FIXTURE_DIR" /tmp/waio_phaseB_injection_marker*' EXIT
mkdir -p "$FIXTURE_DIR/state" "$FIXTURE_DIR/logs" "$FIXTURE_DIR/continuity"

export INTELLIGENCE_STATE_DIR="$FIXTURE_DIR/state"
export INTELLIGENCE_AUDIT_LOG="$FIXTURE_DIR/audit.jsonl"
export RED_ALERT_CRON_LOG="$FIXTURE_DIR/red-alert-cron.log"
export GLOBAL_PATROL_OUTPUT_DIR="$FIXTURE_DIR/logs"
export WAIO_CONTINUITY_STATE_DIR="$FIXTURE_DIR/continuity"

run_cron() {
  rm -f "$RED_ALERT_CRON_LOG"
  ./security/red_alert/red_alert_cron.sh
}

GP_REPORT="$FIXTURE_DIR/logs/global-patrol-report-latest.json"
SND_SNAPSHOT="$FIXTURE_DIR/continuity/snd_snapshot.json"

write_valid_gp_report() {
  cat > "$GP_REPORT" <<'EOF'
{
  "new_incidents": [
    {"id": "KEV-RA-1", "source": "cisa_kev_collector", "attack_pattern": "ransomware", "confidence_level": "HIGH", "country": "US"}
  ],
  "critical_infrastructure_watch": {
    "confirmed_activity": [],
    "precursor_hypotheses": []
  }
}
EOF
}

write_valid_snd_snapshot_with_overlap() {
  cat > "$SND_SNAPSHOT" <<'EOF'
{"pdc_cached_at": "2026-01-01T00:00:00Z", "snd_status": {"active_alerts": {"alerts": ["RANSOMWARE activity detected on segment 3"]}, "lan_status": null, "system_status": null, "terminals": null}}
EOF
}

write_valid_snd_snapshot_no_overlap() {
  cat > "$SND_SNAPSHOT" <<'EOF'
{"pdc_cached_at": "2026-01-01T00:00:00Z", "snd_status": {"active_alerts": {"alerts": ["routine LAN health check, nothing unusual"]}, "lan_status": null, "system_status": null, "terminals": null}}
EOF
}

echo ""
echo "=== I-series: integration tests against the real script ==="

echo ""
echo "[I1] neither input exists: ingest still runs, produces the empty report (NOT an error, NEVER invented data), log names both as absent/skipped"
rm -f "$GP_REPORT" "$SND_SNAPSHOT"
OUT="$(run_cron)"
RC=$?
assert_eq "I1 exit code 0" "0" "$RC"
assert_eq "I1 records_total 0" "0" "$(jget "$OUT" "d['records_total']")"
assert_contains "I1 log names global-patrol-report absent" "$(cat "$RED_ALERT_CRON_LOG")" "global-patrol-report: absent, SKIPPED"
assert_contains "I1 log names snd-snapshot absent" "$(cat "$RED_ALERT_CRON_LOG")" "snd-snapshot: absent, SKIPPED"

echo ""
echo "[I2] only a valid Global Patrol report exists: ingested; snd_crossref stays 0, log names snd-snapshot absent"
write_valid_gp_report
rm -f "$SND_SNAPSHOT"
OUT="$(run_cron)"
assert_eq "I2 global_patrol count 1" "1" "$(jget "$OUT" "d['sources_ingested']['global_patrol']")"
assert_eq "I2 snd_crossref count 0" "0" "$(jget "$OUT" "d['sources_ingested']['snd_crossref']")"
assert_contains "I2 log names snd-snapshot absent" "$(cat "$RED_ALERT_CRON_LOG")" "snd-snapshot: absent, SKIPPED"

echo ""
echo "[I3] *** THE CRITICAL END-TO-END CASE *** both real inputs present and valid, genuine keyword overlap: snd_crossref fires through the FULL script (resolve -> validate -> ingest), KEV-RA-1 becomes multi-source"
write_valid_gp_report
write_valid_snd_snapshot_with_overlap
OUT="$(run_cron)"
assert_eq "I3 snd_crossref count 1" "1" "$(jget "$OUT" "d['sources_ingested']['snd_crossref']")"
assert_eq "I3 KEV-RA-1 source_modules has both" "['global_patrol', 'snd_home_crossref']" "$(jget "$OUT" "d['entities']['KEV-RA-1']['source_modules']")"
assert_contains "I3 log confirms both inputs valid" "$(cat "$RED_ALERT_CRON_LOG")" "global-patrol-report: found and structurally valid"
assert_contains "I3 log confirms snd-snapshot valid" "$(cat "$RED_ALERT_CRON_LOG")" "snd-snapshot: found and structurally valid"

echo ""
echo "[I4] *** NEGATIVE CONTROL *** both present and valid, SND@HOME text has NO genuine keyword overlap: snd_crossref MUST stay 0, no false-positive multi-source corroboration"
write_valid_gp_report
write_valid_snd_snapshot_no_overlap
OUT="$(run_cron)"
assert_eq "I4 snd_crossref count 0 (negative control)" "0" "$(jget "$OUT" "d['sources_ingested']['snd_crossref']")"
assert_eq "I4 KEV-RA-1 source_modules is global_patrol ONLY" "['global_patrol']" "$(jget "$OUT" "d['entities']['KEV-RA-1']['source_modules']")"

echo ""
echo "[I5] Global Patrol report present but NOT valid JSON at all: validated and rejected BEFORE being handed to ingest, log says so explicitly, never a crash"
echo 'this is not json { [ broken' > "$GP_REPORT"
write_valid_snd_snapshot_with_overlap
OUT="$(run_cron)"
RC=$?
assert_eq "I5 exit code 0 despite malformed Global Patrol report" "0" "$RC"
assert_eq "I5 global_patrol count 0" "0" "$(jget "$OUT" "d['sources_ingested']['global_patrol']")"
assert_contains "I5 log says present but not valid JSON object" "$(cat "$RED_ALERT_CRON_LOG")" "global-patrol-report: present but not valid JSON object, SKIPPED"

echo ""
echo "[I6] Global Patrol report is valid JSON but top-level is a LIST, not an object: rejected by this script's OWN validation before ever reaching ingest"
echo '["not", "an", "object"]' > "$GP_REPORT"
OUT="$(run_cron)"
RC=$?
assert_eq "I6 exit code 0" "0" "$RC"
assert_eq "I6 global_patrol count 0" "0" "$(jget "$OUT" "d['sources_ingested']['global_patrol']")"
assert_contains "I6 log says present but not valid JSON object" "$(cat "$RED_ALERT_CRON_LOG")" "global-patrol-report: present but not valid JSON object, SKIPPED"

echo ""
echo "[I7] SND snapshot present but NOT valid JSON at all: validated and rejected BEFORE being handed to ingest, log says so explicitly"
write_valid_gp_report
echo 'also not json' > "$SND_SNAPSHOT"
OUT="$(run_cron)"
RC=$?
assert_eq "I7 exit code 0 despite malformed snd-snapshot" "0" "$RC"
assert_eq "I7 snd_crossref count 0" "0" "$(jget "$OUT" "d['sources_ingested']['snd_crossref']")"
assert_contains "I7 log says present but not valid JSON object" "$(cat "$RED_ALERT_CRON_LOG")" "snd-snapshot: present but not valid JSON object, SKIPPED"

echo ""
echo "[I8] SND snapshot is a valid JSON object but has no snd_status key at all: this script's OWN validation (object-shaped JSON) correctly lets it through, and ingest()'s own deeper handling (Phase A) degrades it to zero signals, not a crash -- proves the full hand-off chain"
write_valid_gp_report
echo '{"pdc_cached_at": "2026-01-01T00:00:00Z"}' > "$SND_SNAPSHOT"
OUT="$(run_cron)"
RC=$?
assert_eq "I8 exit code 0" "0" "$RC"
assert_eq "I8 snd_crossref count 0" "0" "$(jget "$OUT" "d['sources_ingested']['snd_crossref']")"
assert_contains "I8 log DOES say snd-snapshot was structurally valid (it is a JSON object)" "$(cat "$RED_ALERT_CRON_LOG")" "snd-snapshot: found and structurally valid"

echo ""
echo "[I9] *** INJECTION SAFETY, FULL SCRIPT *** a shell-metacharacter-laden attack_pattern string never gets executed anywhere in this script's own path, and this script's OWN log line never echoes the untrusted field content back out"
rm -f /tmp/waio_phaseB_injection_marker /tmp/waio_phaseB_injection_marker2
cat > "$GP_REPORT" <<'EOF'
{
  "new_incidents": [
    {"id": "INJ-1", "attack_pattern": "ransomware; touch /tmp/waio_phaseB_injection_marker ; `touch /tmp/waio_phaseB_injection_marker2`", "confidence_level": "HIGH", "source": "fixture"}
  ],
  "critical_infrastructure_watch": {"confirmed_activity": [], "precursor_hypotheses": []}
}
EOF
rm -f "$SND_SNAPSHOT"
OUT="$(run_cron)"
assert_eq "I9 no marker file was ever created (never executed)" "absent absent" "$([ -e /tmp/waio_phaseB_injection_marker ] && echo present || echo absent) $([ -e /tmp/waio_phaseB_injection_marker2 ] && echo present || echo absent)"
assert_contains "I9 the malicious-looking string reaches ingest's own output verbatim as inert text (Phase A already proved this is never executed there)" "$OUT" 'touch /tmp/waio_phaseB_injection_marker'
assert_not_contains "I9 this script's OWN log file never echoes the untrusted field content" "$(cat "$RED_ALERT_CRON_LOG")" "waio_phaseB_injection_marker"

echo ""
echo "[I10] *** VALID READ-ONLY OPERATION, AGAINST A REALISTIC FULL FIXTURE *** new_incidents + confirmed_activity + precursor_hypotheses all present, read correctly end to end, and the fixture files themselves are never modified by running this script"
cat > "$GP_REPORT" <<'EOF'
{
  "new_incidents": [
    {"id": "KEV-RA-1", "attack_pattern": "ransomware", "confidence_level": "HIGH", "source": "fixture"}
  ],
  "critical_infrastructure_watch": {
    "confirmed_activity": [
      {"id": "CIW-1", "critical_sectors": ["energy"], "attack_pattern": "grid_intrusion", "country": "JP", "confidence_level": "CONFIRMED"}
    ],
    "precursor_hypotheses": [
      {"attack_pattern": "grid_intrusion", "member_ids": ["CIW-1", "CIW-2"], "countries_involved": ["JP", "US"], "confidence_caveat": "hypothesis only"}
    ]
  }
}
EOF
write_valid_snd_snapshot_with_overlap
GP_HASH_BEFORE="$(shasum -a 256 "$GP_REPORT" | awk '{print $1}')"
SND_HASH_BEFORE="$(shasum -a 256 "$SND_SNAPSHOT" | awk '{print $1}')"
OUT="$(run_cron)"
GP_HASH_AFTER="$(shasum -a 256 "$GP_REPORT" | awk '{print $1}')"
SND_HASH_AFTER="$(shasum -a 256 "$SND_SNAPSHOT" | awk '{print $1}')"
assert_eq "I10 global_patrol count 1" "1" "$(jget "$OUT" "d['sources_ingested']['global_patrol']")"
assert_eq "I10 critical_infra_watch count 2 (confirmed_activity + precursor_hypothesis)" "2" "$(jget "$OUT" "d['sources_ingested']['critical_infra_watch']")"
assert_eq "I10 Global Patrol report fixture file byte-identical before/after (read-only)" "$GP_HASH_BEFORE" "$GP_HASH_AFTER"
assert_eq "I10 SND snapshot fixture file byte-identical before/after (read-only)" "$SND_HASH_BEFORE" "$SND_HASH_AFTER"

echo ""
echo "=== D-series: structural guards ==="

echo ""
echo "[D1] red_alert_cron.sh's ACTUAL code (comments stripped) never calls, by name, any Decision Engine / Guardian / DuCoPA / recovery / promotion / Human Gate tool"
cnt=0
for pattern in 'decision_engine\.sh' 'decision_engine_lib' 'guardian\.sh' 'guardian_intervene' 'guardian_release_agent' 'guardian_approve\.sh' 'ducopa\.sh' 'recovery_engine\.sh' 'recover\.sh' 'knowledge_manager\.sh' 'incident_human_gate\.sh'; do
  c="$(code_only security/red_alert/red_alert_cron.sh | grep -cE "$pattern" || true)"
  cnt=$((cnt + c))
done
assert_eq "D1 zero references to any Decision Engine/Guardian/DuCoPA/recovery/promotion/Human-Gate tool by name in actual code" "0" "$cnt"

echo ""
echo "[D2] red_alert_cron.sh never sources security/lib.sh and never calls egress_check/trigger_shutdown/audit_log in actual code"
for pattern in 'source security/lib\.sh' 'egress_check' 'trigger_shutdown' '\baudit_log\('; do
  cnt="$(code_only security/red_alert/red_alert_cron.sh | grep -cE "$pattern" || true)"
  assert_eq "D2 zero occurrences of '$pattern'" "0" "$cnt"
done

echo ""
echo "[D3] zero network tools (curl/wget/nc) and zero process/firewall-modifying commands anywhere in red_alert_cron.sh's actual code"
bad_calls=0
for pattern in '\b(curl|wget|nc )\b' '\bkill\b' '\bkillall\b' '\bpfctl\b' '\bifconfig\b' '\bnetworksetup\b'; do
  c="$(code_only security/red_alert/red_alert_cron.sh | grep -cE "$pattern" || true)"
  bad_calls=$((bad_calls + c))
done
assert_eq "D3 zero network/modifying-command invocations" "0" "$bad_calls"

echo ""
echo "[D4] red_alert_cron.sh never self-registers with launchd/cron -- no launchctl/crontab calls anywhere in its actual code"
cnt=0
for pattern in 'launchctl' 'crontab'; do
  c="$(code_only security/red_alert/red_alert_cron.sh | grep -cE "$pattern" || true)"
  cnt=$((cnt + c))
done
assert_eq "D4 zero launchctl/crontab self-registration calls" "0" "$cnt"

echo ""
echo "[D5] *** CURRENT-STATE PIN: STILL NOT SCHEDULED *** no launchd plist anywhere in this repo names red_alert_cron.sh or 'red-alert'/'red_alert', and no security/incident_learning/*.sh cron wrapper references it"
assert_eq "D5a no *red*alert* launchd plist anywhere" "0" "$(find . -iname '*red*alert*.plist*' -not -path './logs/*' -not -path './results/*' 2>/dev/null | wc -l | tr -d ' ')"
assert_eq "D5b zero references to red_alert_cron.sh in any *.plist* in this repo" "0" "$(grep -rl 'red_alert_cron' --include='*.plist*' . 2>/dev/null | wc -l | tr -d ' ')"
assert_eq "D5c zero references to red_alert in any security/incident_learning/*.sh cron wrapper" "0" "$(grep -l 'red_alert' security/incident_learning/*.sh 2>/dev/null | wc -l | tr -d ' ')"

echo ""
echo "[D6] security/red_alert/'s own pure, tested modules (red_alert_adapter.py, snd_crossref.py) are byte-for-byte unmodified by Phase B"
assert_eq "D6 zero working-tree diff on red_alert_adapter.py/snd_crossref.py" "" "$(git diff --name-only -- security/red_alert/red_alert_adapter.py security/red_alert/snd_crossref.py 2>/dev/null)"

echo ""
echo "[D7] this deployment's real Control Plane conf files were never touched by this suite"
for real_file in security/egress_allowlist.conf security/segments.conf security/ssh_management_allowlist.conf; do
  if [ -f "$real_file" ]; then
    assert_eq "D7 $real_file unchanged" "" "$(git diff --name-only -- "$real_file" 2>/dev/null)"
  fi
done

echo ""
echo "[D8] red_alert_cron.sh is not sourced or invoked from any OTHER script's ACTUAL CODE in this repo (manual, standalone invocation only) -- an existence check ([ -e ... ]) or a plain textual mention inside another test's own echo/comment (documenting that this file exists, or that it still doesn't get scheduled) does not count as an invocation, same 'naming a tool as documentation is not calling it' posture used throughout this pipeline's own D-series guards"
cnt=0
for f in $(grep -rl 'red_alert_cron\.sh' --include='*.sh' . 2>/dev/null | grep -vE '^\./(security/red_alert/red_alert_cron\.sh|tests/red_alert_cron_test\.sh)$'); do
  c="$(code_only "$f" | grep -vE '\[ -[ex] ' | grep -vE '^[[:space:]]*(echo|assert_eq|assert_contains|for)[[:space:]]' | grep -cE 'red_alert_cron\.sh' || true)"
  cnt=$((cnt + c))
done
assert_eq "D8 zero actual-code invocations of red_alert_cron.sh outside itself/its own test" "0" "$cnt"

echo ""
echo "=== Summary: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
  echo "Failures:"
  for f in "${FAILURES[@]}"; do echo "  - $f"; done
  exit 1
fi
exit 0
