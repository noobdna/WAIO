#!/bin/bash
set -uo pipefail

# tests/decision_engine_test.sh -- regression suite for the WAIO
# Decision Engine (security/decision_engine/decision_engine_lib.py +
# security/decision_engine/decision_engine.sh).
#
# Same three-layer convention as the rest of this pipeline's own test
# suites (tests/attack_graph_test.sh, tests/intelligence_layer_test.sh):
#   U-series: unit tests against decision_engine_lib.py's pure
#     functions.
#   I-series: integration tests against the CLI with a hand-written
#     Intelligence Layer report fixture -- no live shadow_ai/
#     attack_graph/intelligence_layer code invoked at all.
#   D-series: static structural guards -- D5 here is the SINGLE MOST
#     IMPORTANT check in this entire pipeline's test suite: this module
#     sits directly upstream of DuCoPA/Contain-Recover in the requested
#     pipeline shape, and must NEVER itself call any real containment
#     tool. See decision_engine_lib.py's and decision_engine.sh's own
#     "CRITICAL SAFETY BOUNDARY" headers.
#
# Every case runs against an isolated DECISION_ENGINE_STATE_DIR/
# DECISION_ENGINE_AUDIT_LOG, never this deployment's real
# security/state/decision_engine/.

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

pyval() {
  python3 -c "
import sys
sys.path.insert(0, 'security/decision_engine')
import decision_engine_lib as del_
$1
"
}

echo "=== WAIO Decision Engine regression suite ==="

echo ""
echo "=== U-series: decision_engine_lib.py unit tests (pure functions) ==="

echo ""
echo "[U1] decide_action: every branch of the stated table"
out="$(pyval "
print(del_.decide_action('CRITICAL', 'LOW', False))
print(del_.decide_action('HIGH', 'HIGH', False))
print(del_.decide_action('HIGH', 'LOW', True))
print(del_.decide_action('HIGH', 'LOW', False))
print(del_.decide_action('MEDIUM', 'HIGH', True))
print(del_.decide_action('MEDIUM', 'HIGH', False))
print(del_.decide_action('MEDIUM', 'LOW', True))
print(del_.decide_action('LOW', 'HIGH', True))
")"
assert_eq "U1 every branch produces the documented action" "$(printf 'RECOMMEND_CONTAINMENT\nRECOMMEND_CONTAINMENT\nRECOMMEND_CONTAINMENT\nALERT_HUMAN\nALERT_HUMAN\nMONITOR\nMONITOR\nNO_ACTION')" "$out"

echo ""
echo "[U2] requires_human_review / requires_human_approval_to_act: only RECOMMEND_CONTAINMENT needs approval, only NO_ACTION needs no review at all"
out="$(pyval "
for a in del_.ACTIONS:
    print(a, del_.requires_human_review(a), del_.requires_human_approval_to_act(a))
")"
assert_eq "U2 review/approval flags correct for all four actions" "$(printf 'NO_ACTION False False\nMONITOR True False\nALERT_HUMAN True False\nRECOMMEND_CONTAINMENT True True')" "$out"

echo ""
echo "[U3] decide_for_profile assembles a complete record and preserves identity fields"
out="$(pyval "
p = {'entity':'ollama','entity_type':'process','highest_risk':'CRITICAL','highest_confidence':'HIGH','source_modules':['attack_graph','shadow_ai_monitor'],'record_count':3}
d = del_.decide_for_profile(p)
print(d['entity'], d['entity_type'], d['risk'], d['confidence'], d['record_count'])
print(d['recommended_action'], d['requires_human_review'], d['requires_human_approval_to_act'])
print('CRITICAL' in d['reasoning'] and 'RECOMMEND_CONTAINMENT' in d['reasoning'])
")"
assert_eq "U3 fields preserved, correct decision, reasoning states the basis" \
  "$(printf 'ollama process CRITICAL HIGH 3\nRECOMMEND_CONTAINMENT True True\nTrue')" "$out"

echo ""
echo "[U4] decide_for_profile defaults missing risk/confidence/source_modules safely (never crashes on a sparse profile)"
out="$(pyval "
d = del_.decide_for_profile({'entity':'x','entity_type':'y'})
print(d['risk'], d['confidence'], d['recommended_action'])
")"
assert_eq "U4 missing fields default to LOW/LOW/NO_ACTION" "LOW LOW NO_ACTION" "$out"

echo ""
echo "[U5] decide_all produces one decision per entity"
out="$(pyval "
entities = {'a': {'entity':'a','entity_type':'x','highest_risk':'LOW','highest_confidence':'LOW','source_modules':['s'],'record_count':1},
            'b': {'entity':'b','entity_type':'x','highest_risk':'HIGH','highest_confidence':'HIGH','source_modules':['s'],'record_count':1}}
ds = del_.decide_all(entities)
print(len(ds))
print(sorted(d['entity'] for d in ds))
")"
assert_eq "U5 one decision per entity" "$(printf "2\n['a', 'b']")" "$out"

echo ""
echo "[U6] rank_decisions orders by action severity first, then risk, then entity name"
out="$(pyval "
decisions = [
    {'entity':'low1','recommended_action':'NO_ACTION','risk':'LOW'},
    {'entity':'contain-b','recommended_action':'RECOMMEND_CONTAINMENT','risk':'CRITICAL'},
    {'entity':'contain-a','recommended_action':'RECOMMEND_CONTAINMENT','risk':'CRITICAL'},
    {'entity':'alert1','recommended_action':'ALERT_HUMAN','risk':'HIGH'},
]
ranked = del_.rank_decisions(decisions)
print([d['entity'] for d in ranked])
")"
assert_eq "U6 containment first (alpha tie-break), then alert, then no_action" "['contain-a', 'contain-b', 'alert1', 'low1']" "$out"

echo ""
echo "[U7] decision_summary counts each action and lists ONLY RECOMMEND_CONTAINMENT entities as pending_human_approval"
out="$(pyval "
decisions = [
    {'entity':'a','recommended_action':'NO_ACTION','requires_human_approval_to_act':False},
    {'entity':'b','recommended_action':'ALERT_HUMAN','requires_human_approval_to_act':False},
    {'entity':'c','recommended_action':'RECOMMEND_CONTAINMENT','requires_human_approval_to_act':True},
]
s = del_.decision_summary(decisions)
print(s['decision_count'])
print(s['action_counts']['NO_ACTION'], s['action_counts']['ALERT_HUMAN'], s['action_counts']['RECOMMEND_CONTAINMENT'])
print(s['pending_human_approval'])
")"
assert_eq "U7 counts correct, pending list has only the containment entity" "$(printf '3\n1 1 1\n[\x27c\x27]')" "$out"

echo ""
echo "=== U-series (PHASE 104): local_corroboration_for_profile -- global-intel-only containment ceiling ==="
echo "    (closes the gap GLOBAL_ATTACK_COMMONALITY_AB_CORRELATION_INVESTIGATION.md Sec.7.7 identified:"
echo "     the real Phase C run produced 11 RECOMMEND_CONTAINMENT records, 100% multi_source=False,"
echo "     zero local corroboration -- see this file's own R-series below, which replays that exact input)"

echo ""
echo "[U8] local_corroboration_for_profile: GLOBAL-ONLY evidence (global_patrol alone, or global_patrol+critical_infra_watch+snd_home_crossref together) -> no trusted local corroboration, regardless of how many global modules agree"
out="$(pyval "
print(del_.local_corroboration_for_profile({'source_modules': ['global_patrol']}))
print(del_.local_corroboration_for_profile({'source_modules': ['global_patrol', 'critical_infra_watch', 'snd_home_crossref']}))
")"
assert_eq "U8 both global-only cases report (False, [])" "$(printf '(False, [])\n(False, [])')" "$out"

echo ""
echo "[U9] local_corroboration_for_profile: ZERO local corroboration vs VALID fresh local corroboration (shadow_ai_monitor record, risk HIGH, detected_at within 30 days of the injected 'now')"
out="$(pyval "
now = del_.datetime.datetime(2026, 10, 14, tzinfo=del_.datetime.timezone.utc)
no_local = {'source_modules': ['global_patrol']}
print(del_.local_corroboration_for_profile(no_local, now=now))
valid_local = {'source_modules': ['global_patrol', 'shadow_ai_monitor'], 'records': [{'source_module': 'shadow_ai_monitor', 'risk': 'HIGH', 'detected_at': '2026-10-10T00:00:00Z'}]}
print(del_.local_corroboration_for_profile(valid_local, now=now))
")"
assert_eq "U9 zero vs valid local corroboration" "$(printf "(False, [])\n(True, ['shadow_ai_monitor'])")" "$out"

echo ""
echo "[U10] local_corroboration_for_profile: STALE local evidence (shadow_ai_monitor record is 40 days old against the injected 'now') -> fails safe, excluded, NOT trusted"
out="$(pyval "
now = del_.datetime.datetime(2026, 10, 14, tzinfo=del_.datetime.timezone.utc)
stale = {'source_modules': ['global_patrol', 'shadow_ai_monitor'], 'records': [{'source_module': 'shadow_ai_monitor', 'risk': 'HIGH', 'detected_at': '2026-09-04T00:00:00Z'}]}
print(del_.local_corroboration_for_profile(stale, now=now))
")"
assert_eq "U10 stale evidence excluded" "(False, [])" "$out"

echo ""
echo "[U11] local_corroboration_for_profile: CONTRADICTORY local evidence (shadow_ai_monitor's own record for this entity is only LOW risk -- presence alone in source_modules is not proof) -> fails safe, excluded, NOT trusted"
out="$(pyval "
contradictory = {'source_modules': ['global_patrol', 'shadow_ai_monitor'], 'records': [{'source_module': 'shadow_ai_monitor', 'risk': 'LOW', 'detected_at': None}]}
print(del_.local_corroboration_for_profile(contradictory))
")"
assert_eq "U11 contradictory low-risk local record excluded" "(False, [])" "$out"

echo ""
echo "[U12] local_corroboration_for_profile: MISSING/MALFORMED input fails safe, never crashes -- malformed source_modules always (False, []); missing/empty/malformed 'records' with a genuinely local source_module trusts that source_modules-level signal (no record-level detail to contradict it, same 'don't invent missing integrations' posture as the rest of this pipeline)"
out="$(pyval "
print(del_.local_corroboration_for_profile({'source_modules': 'not-a-list'}))
print(del_.local_corroboration_for_profile({}))
print(del_.local_corroboration_for_profile({'source_modules': ['shadow_ai_monitor']}))
print(del_.local_corroboration_for_profile({'source_modules': ['shadow_ai_monitor'], 'records': 'not-a-list'}))
print(del_.local_corroboration_for_profile({'source_modules': ['shadow_ai_monitor'], 'records': []}))
print(del_.local_corroboration_for_profile({'source_modules': ['shadow_ai_monitor'], 'records': ['not-a-dict', {'source_module': 'unrelated_module', 'risk': 'HIGH'}]}))
")"
assert_eq "U12 six malformed/missing cases all fail safe" "$(printf "(False, [])\n(False, [])\n(True, ['shadow_ai_monitor'])\n(True, ['shadow_ai_monitor'])\n(True, ['shadow_ai_monitor'])\n(True, ['shadow_ai_monitor'])")" "$out"

echo ""
echo "[U13 PHASE104] decide_for_profile: the EXACT real-world gap shape -- CRITICAL risk, single global_patrol source, zero local corroboration -- is now CAPPED at ALERT_HUMAN, never RECOMMEND_CONTAINMENT, with the cap explicitly recorded (never a silent downgrade)"
out="$(pyval "
now = del_.datetime.datetime(2026, 10, 14, tzinfo=del_.datetime.timezone.utc)
p = {'entity': 'KEV-CVE-2015-3306', 'entity_type': 'cve', 'highest_risk': 'CRITICAL', 'highest_confidence': 'HIGH', 'source_modules': ['global_patrol'], 'record_count': 1}
d = del_.decide_for_profile(p, now=now)
print(d['recommended_action'], d['capped_from_recommend_containment'], d['local_corroboration'])
print('CAPPED from RECOMMEND_CONTAINMENT' in d['reasoning'])
")"
assert_eq "U13 capped to ALERT_HUMAN, flagged explicitly, reasoning states why" "$(printf 'ALERT_HUMAN True {\x27present\x27: False, \x27modules\x27: []}\nTrue')" "$out"

echo ""
echo "[U14 PHASE104] decide_for_profile: the SAME CRITICAL entity, but now with genuine fresh local corroboration (shadow_ai_monitor) -> RECOMMEND_CONTAINMENT is PRESERVED, not capped"
out="$(pyval "
now = del_.datetime.datetime(2026, 10, 14, tzinfo=del_.datetime.timezone.utc)
p = {'entity': 'ollama', 'entity_type': 'process', 'highest_risk': 'CRITICAL', 'highest_confidence': 'HIGH', 'source_modules': ['global_patrol', 'shadow_ai_monitor'], 'record_count': 2, 'records': [{'source_module': 'shadow_ai_monitor', 'risk': 'HIGH', 'detected_at': '2026-10-10T00:00:00Z'}]}
d = del_.decide_for_profile(p, now=now)
print(d['recommended_action'], d['capped_from_recommend_containment'], d['requires_human_approval_to_act'])
")"
assert_eq "U14 not capped, containment preserved, approval still required" "RECOMMEND_CONTAINMENT False True" "$out"

echo ""
echo "[U15 PHASE104] decide_for_profile: a CAPPED record never requires human approval to act (it is no longer RECOMMEND_CONTAINMENT at all) -- the human-approval requirement is strictly a property of the FINAL action, computed after capping, never bypassed or reinstated separately"
out="$(pyval "
p = {'entity': 'x', 'entity_type': 'cve', 'highest_risk': 'CRITICAL', 'highest_confidence': 'HIGH', 'source_modules': ['critical_infra_watch']}
d = del_.decide_for_profile(p)
print(d['recommended_action'], d['requires_human_approval_to_act'], d['requires_human_review'])
")"
assert_eq "U15 capped ALERT_HUMAN: no approval needed, review still required" "ALERT_HUMAN False True" "$out"

echo ""
echo "=== I-series: decision_engine.sh CLI integration tests (fixed Intelligence Layer report fixture) ==="

FIXTURE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/waio-decision-engine-test.XXXXXX")"
trap 'rm -rf "$FIXTURE_DIR"' EXIT
mkdir -p "$FIXTURE_DIR/state"

export DECISION_ENGINE_STATE_DIR="$FIXTURE_DIR/state"
export DECISION_ENGINE_AUDIT_LOG="$FIXTURE_DIR/audit.jsonl"

cat > "$FIXTURE_DIR/intelligence_report.json" <<'EOF'
{
  "generated_at": "2026-01-01T00:00:00Z",
  "entities": {
    "rogue-agent": {"entity": "rogue-agent", "entity_type": "process", "highest_risk": "CRITICAL", "highest_confidence": "HIGH", "source_modules": ["attack_graph", "shadow_ai_monitor"], "record_count": 3, "records": []},
    "ollama": {"entity": "ollama", "entity_type": "process", "highest_risk": "MEDIUM", "highest_confidence": "LOW", "source_modules": ["shadow_ai_monitor"], "record_count": 1, "records": []},
    "claude": {"entity": "claude", "entity_type": "process", "highest_risk": "LOW", "highest_confidence": "HIGH", "source_modules": ["shadow_ai_monitor"], "record_count": 1, "records": []}
  },
  "ranked_entities": ["rogue-agent", "ollama", "claude"],
  "summary": {}
}
EOF

echo ""
echo "[I1] decide (reading a FILE argument) exits 0, emits valid JSON, one decision per entity"
OUT="$(./security/decision_engine/decision_engine.sh decide "$FIXTURE_DIR/intelligence_report.json" 2>/tmp/waio-decision-engine-i1-stderr.log)"
RC=$?
assert_eq "I1 exit code 0" "0" "$RC"
assert_eq "I1 valid JSON" "true" "$(echo "$OUT" | python3 -c "import json,sys; json.load(sys.stdin); print('true')" 2>/dev/null || echo false)"
assert_eq "I1 decision_count 3" "3" "$(echo "$OUT" | python3 -c "import json,sys; print(json.load(sys.stdin)['summary']['decision_count'])")"

echo ""
echo "[I2] the CRITICAL-risk entity is correctly recommended for containment and listed as pending human approval"
assert_eq "I2 rogue-agent gets RECOMMEND_CONTAINMENT" "RECOMMEND_CONTAINMENT" "$(echo "$OUT" | python3 -c "
import json, sys
d = json.load(sys.stdin)
rec = [x for x in d['decisions'] if x['entity'] == 'rogue-agent'][0]
print(rec['recommended_action'])
")"
assert_contains "I2 rogue-agent is in pending_human_approval" "$(echo "$OUT" | python3 -c "import json,sys; print(json.load(sys.stdin)['summary']['pending_human_approval'])")" "rogue-agent"

echo ""
echo "[I3] the LOW-risk, single-source entity gets NO_ACTION and never appears in pending approval"
assert_eq "I3 claude gets NO_ACTION" "NO_ACTION" "$(echo "$OUT" | python3 -c "
import json, sys
d = json.load(sys.stdin)
rec = [x for x in d['decisions'] if x['entity'] == 'claude'][0]
print(rec['recommended_action'])
")"

echo ""
echo "[I4] decisions are ranked most-urgent-first: rogue-agent (containment) appears before claude (no_action)"
FIRST_ENTITY="$(echo "$OUT" | python3 -c "import json,sys; print(json.load(sys.stdin)['decisions'][0]['entity'])")"
assert_eq "I4 rogue-agent ranked first" "rogue-agent" "$FIRST_ENTITY"

echo ""
echo "[I5] decide also works reading from STDIN (the real pipe usage: intelligence_layer.sh ingest ... | decision_engine.sh decide)"
STDIN_OUT="$(cat "$FIXTURE_DIR/intelligence_report.json" | ./security/decision_engine/decision_engine.sh decide -)"
assert_eq "I5 stdin-fed decide produces the same decision_count" "3" "$(echo "$STDIN_OUT" | python3 -c "import json,sys; print(json.load(sys.stdin)['summary']['decision_count'])")"
assert_eq "I5 default (no arg) also reads stdin" "3" "$(cat "$FIXTURE_DIR/intelligence_report.json" | ./security/decision_engine/decision_engine.sh decide | python3 -c "import json,sys; print(json.load(sys.stdin)['summary']['decision_count'])")"

echo ""
echo "[I6] the report is persisted and readable via 'show'"
SHOW_OUT="$(./security/decision_engine/decision_engine.sh show)"
assert_eq "I6 persisted decision_count matches" "3" "$(echo "$SHOW_OUT" | python3 -c "import json,sys; print(json.load(sys.stdin)['summary']['decision_count'])")"

echo ""
echo "[I7] 'status' prints a read-only summary AND explicitly reminds that acting is a separate manual step when something is pending"
STATUS_OUT="$(./security/decision_engine/decision_engine.sh status)"
assert_contains "I7 status names rogue-agent as pending" "$STATUS_OUT" "rogue-agent"
assert_contains "I7 status explicitly states this module never acts on its own" "$STATUS_OUT" "never acts"

echo ""
echo "[I8] an Intelligence Layer report with zero entities produces zero decisions, never an error"
echo '{"generated_at": "x", "entities": {}}' > "$FIXTURE_DIR/empty_report.json"
EMPTY_OUT="$(./security/decision_engine/decision_engine.sh decide "$FIXTURE_DIR/empty_report.json" 2>/dev/null)"
EMPTY_RC=$?
assert_eq "I8 exit code 0 for an empty report" "0" "$EMPTY_RC"
assert_eq "I8 decision_count 0" "0" "$(echo "$EMPTY_OUT" | python3 -c "import json,sys; print(json.load(sys.stdin)['summary']['decision_count'])")"

echo ""
echo "[I9] a report with no 'entities' key at all is handled gracefully, never a crash"
echo '{"generated_at": "x"}' > "$FIXTURE_DIR/no_entities_key.json"
NOKEY_RC="$(./security/decision_engine/decision_engine.sh decide "$FIXTURE_DIR/no_entities_key.json" >/dev/null 2>&1; echo $?)"
assert_eq "I9 exit code 0 with no entities key" "0" "$NOKEY_RC"

echo ""
echo "[I10 PHASE104] CLI end-to-end: a CRITICAL, global_patrol-only entity (zero local corroboration) is capped at ALERT_HUMAN and is NOT in pending_human_approval, even though its own risk alone would otherwise read as containment-worthy"
cat > "$FIXTURE_DIR/global_only_report.json" <<'EOF'
{
  "generated_at": "2026-01-01T00:00:00Z",
  "entities": {
    "KEV-CVE-2015-3306": {"entity": "KEV-CVE-2015-3306", "entity_type": "cve", "highest_risk": "CRITICAL", "highest_confidence": "HIGH", "source_modules": ["global_patrol"], "record_count": 1, "records": []}
  },
  "ranked_entities": ["KEV-CVE-2015-3306"],
  "summary": {}
}
EOF
GO_OUT="$(./security/decision_engine/decision_engine.sh decide "$FIXTURE_DIR/global_only_report.json")"
assert_eq "I10 recommended_action is ALERT_HUMAN, not RECOMMEND_CONTAINMENT" "ALERT_HUMAN" "$(echo "$GO_OUT" | python3 -c "
import json, sys
d = json.load(sys.stdin)
print(d['decisions'][0]['recommended_action'])
")"
assert_eq "I10 pending_human_approval is empty" "[]" "$(echo "$GO_OUT" | python3 -c "import json,sys; print(json.load(sys.stdin)['summary']['pending_human_approval'])")"
assert_eq "I10 capped_from_recommend_containment True" "True" "$(echo "$GO_OUT" | python3 -c "
import json, sys
d = json.load(sys.stdin)
print(d['decisions'][0]['capped_from_recommend_containment'])
")"

echo ""
echo "=== R-series (PHASE 104): REAL-DATA regression against the exact Phase C input file ==="
echo "    Replays logs/global-patrol-report-latest.json (the SAME real, 74-incident, global_patrol-only"
echo "    file ARCHITECTURE.md Phase 103 Section 3 evaluated on 2026-10-12, producing 11"
echo "    RECOMMEND_CONTAINMENT / multi_source=False records) through the REAL"
echo "    security/intelligence/intelligence_layer.sh + security/decision_engine/decision_engine.sh"
echo "    pipeline, entirely into an isolated scratch state dir -- this deployment's real"
echo "    security/state/intelligence/ and security/state/decision_engine/ are never touched."
echo "    This is REAL, already-public incident metadata (CISA/GHSA/JPCERT/etc., via the"
echo "    already-approved Global Patrol pipeline) -- not a synthetic fixture -- used here"
echo "    read-only, exactly as Phase C itself did."

REAL_GP_REPORT="logs/global-patrol-report-latest.json"
if [ ! -f "$REAL_GP_REPORT" ]; then
  echo "  SKIP: R-series (real $REAL_GP_REPORT not present on this machine -- this is an optional, data-dependent regression check, not a hard requirement)"
else
  R_INTEL_STATE="$(mktemp -d "${TMPDIR:-/tmp}/waio-r-series-intel.XXXXXX")"
  R_DECISION_STATE="$(mktemp -d "${TMPDIR:-/tmp}/waio-r-series-decision.XXXXXX")"

  R_INTEL_OUT="$(INTELLIGENCE_STATE_DIR="$R_INTEL_STATE/state" INTELLIGENCE_AUDIT_LOG="$R_INTEL_STATE/audit.jsonl" \
    ./security/intelligence/intelligence_layer.sh ingest --global-patrol-report "$REAL_GP_REPORT" 2>/dev/null)"
  R_INTEL_RC=$?
  assert_eq "R1 real-data ingest exits 0" "0" "$R_INTEL_RC"

  echo "$R_INTEL_OUT" > "$R_INTEL_STATE/report.json"
  R_DECIDE_OUT="$(DECISION_ENGINE_STATE_DIR="$R_DECISION_STATE/state" DECISION_ENGINE_AUDIT_LOG="$R_DECISION_STATE/audit.jsonl" \
    ./security/decision_engine/decision_engine.sh decide "$R_INTEL_STATE/report.json" 2>/dev/null)"
  R_DECIDE_RC=$?
  assert_eq "R2 real-data decide exits 0" "0" "$R_DECIDE_RC"

  echo ""
  echo "[R3] *** THE ACTUAL REGRESSION *** before Phase 104, this exact real-data run produced 11 RECOMMEND_CONTAINMENT decisions, 100% multi_source=False, zero local corroboration (ARCHITECTURE.md Phase 103 Section 3). After Phase 104, on the SAME real input file: RECOMMEND_CONTAINMENT count is now ZERO (every one of those 11 is capped to ALERT_HUMAN, since this real run has no shadow_ai_monitor/attack_graph/saas_ato records at all -- only global_patrol), and NOT ONE of the capped records ever required human approval to act"
  echo "$R_DECIDE_OUT" | python3 -c "
import json, sys
d = json.load(sys.stdin)
decisions = d['decisions']
action_counts = d['summary']['action_counts']
capped = [x for x in decisions if x.get('capped_from_recommend_containment')]
capped_requiring_approval = [x for x in capped if x['requires_human_approval_to_act']]
print(action_counts.get('RECOMMEND_CONTAINMENT', 0))
print(len(capped))
print(len(capped_requiring_approval))
print(all(x['local_corroboration']['present'] is False for x in capped))
" > "$R_DECISION_STATE/r3_summary.txt"
  assert_eq "R3 RECOMMEND_CONTAINMENT count is now 0 on real data" "0" "$(sed -n '1p' "$R_DECISION_STATE/r3_summary.txt")"
  assert_eq "R3 exactly 11 real records were capped (matches Phase 103's own documented count)" "11" "$(sed -n '2p' "$R_DECISION_STATE/r3_summary.txt")"
  assert_eq "R3 zero capped records require human approval to act" "0" "$(sed -n '3p' "$R_DECISION_STATE/r3_summary.txt")"
  assert_eq "R3 every capped record genuinely has no local corroboration" "True" "$(sed -n '4p' "$R_DECISION_STATE/r3_summary.txt")"

  rm -rf "$R_INTEL_STATE" "$R_DECISION_STATE"
fi

echo ""
echo "=== D-series: structural read-only / no-network / no-Control-Plane / NO-CONTAINMENT guards ==="

code_only() {
  grep -vE '^[[:space:]]*#' "$1"
}

echo ""
echo "[D1] this module never sources security/lib.sh and never calls egress_check/audit_log/trigger_shutdown in actual code"
for pattern in 'source security/lib\.sh' 'egress_check' 'trigger_shutdown' '\baudit_log\('; do
  cnt="$(code_only security/decision_engine/decision_engine.sh | grep -cE "$pattern" || true)"
  assert_eq "D1 zero code occurrences of '$pattern'" "0" "$cnt"
done

echo ""
echo "[D2] zero network tools (curl/wget/nc) and zero ps/lsof calls anywhere in the shell wrapper's actual code"
bad_calls=0
for pattern in '\b(curl|wget|nc )\b' '\bps\b' '\blsof\b'; do
  c="$(code_only security/decision_engine/decision_engine.sh | grep -cE "$pattern" || true)"
  bad_calls=$((bad_calls + c))
done
assert_eq "D2 zero network/ps/lsof invocations" "0" "$bad_calls"

echo ""
echo "[D2b] decision_engine_lib.py never shells out (no subprocess/os.system/os.popen/exec)"
assert_eq "D2b zero subprocess/os.system/os.popen/os.exec calls" "0" "$(grep -cE '\b(subprocess|os\.system|os\.popen|os\.exec\w*)\b' security/decision_engine/decision_engine_lib.py || true)"

echo ""
echo "[D3] zero process/firewall/routing-modifying commands anywhere in the module's actual code"
mod_calls=0
for pattern in '\bkill\b' '\bkillall\b' '\bpfctl\b' '\broute\b' '\bifconfig\b' 'launchctl (unload|stop|kickstart)' '\bnetworksetup\b'; do
  for f in security/decision_engine/decision_engine.sh security/decision_engine/decision_engine_lib.py; do
    c="$(code_only "$f" | grep -cE "$pattern" || true)"
    mod_calls=$((mod_calls + c))
  done
done
assert_eq "D3 zero modifying-command invocations" "0" "$mod_calls"

echo ""
echo "[D4] this deployment's real Control Plane conf files were never touched by this suite"
for real_file in security/egress_allowlist.conf security/segments.conf security/ssh_management_allowlist.conf; do
  if [ -f "$real_file" ]; then
    assert_eq "D4 $real_file unchanged" "" "$(git diff --name-only -- "$real_file" 2>/dev/null)"
  fi
done

echo ""
echo "[D5] *** THE CRITICAL GUARD *** zero calls anywhere in decision_engine.sh's actual code to ANY real WAIO containment/human-gate tool -- this module recommends, it never executes. (decision_engine_lib.py is checked separately by D2b: it has no subprocess/os.system/os.popen/exec at all, which already proves it cannot invoke ANY external tool by any name -- a strictly stronger guarantee than a name-based grep, so its own docstring is free to NAME these tools as documentation of what it does not call, same as the Attack Graph / Intelligence Layer suites' own D2b precedent.)"
containment_calls=0
for pattern in \
  'guardian\.sh' 'guardian_intervene_wrapper\.sh' 'guardian_intervene_quarantine_wrapper\.sh' \
  'guardian_release_agent\.sh' 'guardian_approve\.sh' 'ducopa\.sh' 'recovery_engine\.sh' \
  '\brecover\.sh' 'knowledge_manager\.sh' 'incident_human_gate\.sh' \
  'guardian_quarantine_agent' 'guardian_dispatch' \
; do
  c="$(code_only security/decision_engine/decision_engine.sh | grep -cE "$pattern" || true)"
  containment_calls=$((containment_calls + c))
done
assert_eq "D5 zero references to any real containment/human-gate tool in decision_engine.sh's actual code" "0" "$containment_calls"

echo ""
echo "[D6] this module never imports/calls shadow_ai_lib, attack_graph_lib, or intelligence_lib directly -- it only consumes the Intelligence Layer's own JSON output shape, same loose-coupling discipline as every prior phase"
assert_eq "D6 zero 'import shadow_ai'/'import attack_graph'/'import intelligence_lib' statements" "0" "$(grep -cE '^\s*(import|from)\s+(shadow_ai|attack_graph|intelligence_lib)' security/decision_engine/decision_engine_lib.py || true)"
assert_eq "D6 zero calls to any upstream module's own CLI in actual code" "0" "$(code_only security/decision_engine/decision_engine.sh | grep -cE 'shadow_ai_monitor\.sh|attack_graph\.sh|intelligence_layer\.sh' || true)"

echo ""
echo "=== Summary: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
  echo "Failures:"
  for f in "${FAILURES[@]}"; do echo "  - $f"; done
  exit 1
fi
exit 0
