#!/bin/bash
set -uo pipefail

# tests/intelligence_layer_test.sh -- regression suite for the WAIO
# Intelligence / Evidence Layer (security/intelligence/intelligence_lib.py
# + security/intelligence/intelligence_layer.sh).
#
# Same three-layer convention as tests/attack_graph_test.sh:
#   U-series: unit tests against intelligence_lib.py's pure functions.
#   I-series: integration tests against the CLI with hand-written
#     fixture files for all three possible sources (a Shadow AI JSONL
#     file, an Attack Graph JSON file, and an Incident Learning
#     candidate directory) -- no live scan, no real shadow_ai/
#     attack_graph/incident_learning code invoked at all. This module
#     is coupled to its three sources only via their own documented
#     schemas, so hand-written fixtures matching those schemas are
#     enough to prove it works, same decoupling proof
#     tests/attack_graph_test.sh's own D5 already established.
#   D-series: static structural guards.
#
# Every case runs against an isolated INTELLIGENCE_STATE_DIR/
# INTELLIGENCE_AUDIT_LOG, never this deployment's real
# security/state/intelligence/. The Incident Learning fixture directory
# is this suite's OWN scratch directory, never this deployment's real
# security/state/incident_learning/candidates/.

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
sys.path.insert(0, 'security/intelligence')
import intelligence_lib as il
$1
"
}

echo "=== WAIO Intelligence/Evidence Layer regression suite ==="

echo ""
echo "=== U-series: intelligence_lib.py unit tests (pure functions) ==="

echo ""
echo "[U1] classify_risk_from_confidence_score: stated thresholds, non-numeric defaults to LOW"
out="$(pyval "
print(il.classify_risk_from_confidence_score(85))
print(il.classify_risk_from_confidence_score(65))
print(il.classify_risk_from_confidence_score(50))
print(il.classify_risk_from_confidence_score(49))
print(il.classify_risk_from_confidence_score(None))
print(il.classify_risk_from_confidence_score('not-a-number'))
")"
assert_eq "U1 thresholds correct, non-numeric safe" "$(printf 'CRITICAL\nHIGH\nMEDIUM\nLOW\nLOW\nLOW')" "$out"

echo ""
echo "[U2] classify_confidence_from_corroboration: 0->LOW, 1->MEDIUM, 2+->HIGH, non-numeric safe"
out="$(pyval "
print(il.classify_confidence_from_corroboration(0))
print(il.classify_confidence_from_corroboration(1))
print(il.classify_confidence_from_corroboration(2))
print(il.classify_confidence_from_corroboration(5))
print(il.classify_confidence_from_corroboration(None))
")"
assert_eq "U2 corroboration thresholds correct" "$(printf 'LOW\nMEDIUM\nHIGH\nHIGH\nLOW')" "$out"

echo ""
echo "[U3] from_shadow_ai_finding maps entity/risk/confidence/category correctly and preserves the raw original"
out="$(pyval "
f = {'id':'SHADOWAI-x','finding_type':'process','category':'local_llm_runtime','risk':'MEDIUM','confidence':'HIGH','reason':'r','process':{'comm':'ollama','pid':1}}
r = il.from_shadow_ai_finding(f)
print(r['entity'], r['entity_type'], r['risk'], r['confidence'], r['source_module'])
print(r['raw'] == f)
")"
assert_eq "U3 fields mapped, raw preserved" "$(printf 'ollama process MEDIUM HIGH shadow_ai_monitor\nTrue')" "$out"

echo ""
echo "[U4] from_shadow_ai_finding falls back to signature_matched as entity when no process context exists"
out="$(pyval "
f = {'id':'x','finding_type':'listening_port','category':'x','risk':'LOW','confidence':'LOW','signature_matched':'11434','process':None}
print(il.from_shadow_ai_finding(f)['entity'])
")"
assert_eq "U4 falls back to signature_matched" "11434" "$out"

echo ""
echo "[U5] from_attack_graph_node: confidence is MEDIUM with one contributing finding, HIGH with two or more"
out="$(pyval "
n1 = {'category':'x','highest_risk':'HIGH','finding_ids':['a'],'exposures':[]}
n2 = {'category':'x','highest_risk':'HIGH','finding_ids':['a','b'],'exposures':[]}
print(il.from_attack_graph_node('node1', n1)['confidence'])
print(il.from_attack_graph_node('node2', n2)['confidence'])
")"
assert_eq "U5 one finding MEDIUM, two+ findings HIGH" "$(printf 'MEDIUM\nHIGH')" "$out"

echo ""
echo "[U6] from_attack_graph_path builds its entity as the full joined path, fixed MEDIUM confidence"
out="$(pyval "
p = {'from':'a','to':'c','path':['a','b','c'],'path_risk':'CRITICAL'}
r = il.from_attack_graph_path(p)
print(r['entity'], r['entity_type'], r['risk'], r['confidence'])
")"
assert_eq "U6 full path as entity, correct type/risk, fixed MEDIUM confidence" "a->b->c attack_path CRITICAL MEDIUM" "$out"

echo ""
echo "[U7] from_incident_learning_candidate: entity is the first CVE when present, else the candidate id; risk/confidence derived from score/corroboration"
out="$(pyval "
c1 = {'id':'KEV-X','cve_list':['CVE-2026-1','CVE-2026-2'],'confidence_score':85,'evidence_corroborating_count':2,'source_type':'cert'}
r1 = il.from_incident_learning_candidate(c1)
print(r1['entity'], r1['entity_type'], r1['risk'], r1['confidence'])
c2 = {'id':'GHSA-NOcve','cve_list':[],'confidence_score':55,'evidence_corroborating_count':0}
r2 = il.from_incident_learning_candidate(c2)
print(r2['entity'], r2['entity_type'])
")"
assert_eq "U7 CVE entity + correct bucketing, id-fallback entity when no CVE" "$(printf 'CVE-2026-1 cve CRITICAL HIGH\nGHSA-NOcve incident_candidate')" "$out"

echo ""
echo "[U8] aggregate_by_entity merges records about the same entity: highest_risk/highest_confidence roll up, source_modules accumulate, record_count correct"
out="$(pyval "
r1 = {'entity':'x','entity_type':'process','risk':'LOW','confidence':'LOW','source_module':'shadow_ai_monitor'}
r2 = {'entity':'x','entity_type':'process','risk':'HIGH','confidence':'MEDIUM','source_module':'attack_graph'}
r3 = {'entity':'y','entity_type':'process','risk':'MEDIUM','confidence':'HIGH','source_module':'shadow_ai_monitor'}
profiles = il.aggregate_by_entity([r1, r2, r3])
px = profiles['x']
print(px['highest_risk'], px['highest_confidence'], px['record_count'], px['source_modules'])
py = profiles['y']
print(py['record_count'], py['source_modules'])
")"
assert_eq "U8 x rolls up to HIGH/MEDIUM from two sources, y stands alone" \
  "$(printf "HIGH MEDIUM 2 ['attack_graph', 'shadow_ai_monitor']\n1 ['shadow_ai_monitor']")" "$out"

echo ""
echo "[U9] rank_profiles sorts by risk desc, then confidence desc, then record_count desc, then entity name as the final deterministic tie-break"
out="$(pyval "
profiles = {
    'b': {'entity':'b','entity_type':'x','highest_risk':'HIGH','highest_confidence':'LOW','source_modules':['s'],'record_count':1,'records':[]},
    'a': {'entity':'a','entity_type':'x','highest_risk':'HIGH','highest_confidence':'LOW','source_modules':['s'],'record_count':1,'records':[]},
    'z': {'entity':'z','entity_type':'x','highest_risk':'CRITICAL','highest_confidence':'LOW','source_modules':['s'],'record_count':1,'records':[]},
    'm': {'entity':'m','entity_type':'x','highest_risk':'HIGH','highest_confidence':'HIGH','source_modules':['s'],'record_count':1,'records':[]},
}
ranked = il.rank_profiles(profiles)
print([p['entity'] for p in ranked])
")"
assert_eq "U9 CRITICAL first, then HIGH/HIGH-confidence, then HIGH/LOW alphabetical a before b" "['z', 'm', 'a', 'b']" "$out"

echo ""
echo "[U10] report_summary counts risk levels, counts multi-source entities, and lists the top 5 by rank"
out="$(pyval "
profiles = {}
for i, (risk, sources) in enumerate([('CRITICAL', ['a','b']), ('LOW', ['a']), ('LOW', ['a']), ('LOW', ['a']), ('LOW', ['a']), ('LOW', ['a']), ('LOW', ['a'])]):
    name = f'e{i}'
    profiles[name] = {'entity': name, 'entity_type':'x', 'highest_risk': risk, 'highest_confidence':'LOW', 'source_modules': sources, 'record_count': 1, 'records': []}
ranked = il.rank_profiles(profiles)
s = il.report_summary(ranked)
print(s['entity_count'], s['risk_counts']['CRITICAL'], s['risk_counts']['LOW'], s['multi_source_entity_count'])
print(len(s['top_entities']))
")"
assert_eq "U10 counts correct, top_entities capped at 5" "$(printf '7 1 6 1\n5')" "$out"

echo ""
echo "[U11] from_saas_ato_finding maps account/risk/confidence/entity_type correctly, summary names the signal_types, raw is preserved"
out="$(pyval "
f = {'id':'alice@contoso.example.invalid','account':'alice@contoso.example.invalid','risk':'CRITICAL','confidence':'HIGH','timestamp':'2026-01-01T00:00:00Z','signals':[{'signal_type':'mass_send'}],'correlation':{'candidate_incident': False}}
r = il.from_saas_ato_finding(f)
print(r['entity'], r['entity_type'], r['risk'], r['confidence'], r['source_module'], r['category'])
print('mass_send' in r['summary'])
print(r['raw'] == f)
")"
assert_eq "U11 fields mapped, summary names signal_types, raw preserved" "$(printf 'alice@contoso.example.invalid saas_account CRITICAL HIGH saas_ato account_takeover\nTrue\nTrue')" "$out"

echo ""
echo "=== I-series: intelligence_layer.sh CLI integration tests (fixed fixtures, no live modules invoked) ==="

FIXTURE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/waio-intelligence-test.XXXXXX")"
trap 'rm -rf "$FIXTURE_DIR"' EXIT
mkdir -p "$FIXTURE_DIR/state" "$FIXTURE_DIR/il_candidates"

export INTELLIGENCE_STATE_DIR="$FIXTURE_DIR/state"
export INTELLIGENCE_AUDIT_LOG="$FIXTURE_DIR/audit.jsonl"

# Shadow AI JSONL fixture: ollama (MEDIUM) also appears in the attack
# graph fixture below, so I4 can prove cross-source merging; claude is
# shadow-ai-only.
cat > "$FIXTURE_DIR/shadow_ai.jsonl" <<'EOF'
{"id": "SHADOWAI-1", "detected_at": "2026-01-01T00:00:00Z", "finding_type": "process", "category": "local_llm_runtime", "signature_matched": "ollama", "signature_label": "l", "match_kind": "process_name", "process": {"pid": 1, "ppid": 0, "user": "masa", "comm": "ollama", "args": "ollama serve"}, "network": null, "allowlisted": false, "risk": "MEDIUM", "confidence": "HIGH", "reason": "fixture"}
{"id": "SHADOWAI-2", "detected_at": "2026-01-01T00:00:00Z", "finding_type": "process", "category": "ai_desktop_app", "signature_matched": "claude", "signature_label": "l", "match_kind": "process_name", "process": {"pid": 2, "ppid": 0, "user": "masa", "comm": "claude", "args": "claude"}, "network": null, "allowlisted": true, "risk": "LOW", "confidence": "HIGH", "reason": "fixture"}
EOF

# Attack Graph fixture: ollama appears here too (same entity, different
# source) at a HIGHER risk (HIGH) than the shadow_ai fixture's own
# MEDIUM, plus one attack_path.
cat > "$FIXTURE_DIR/attack_graph.json" <<'EOF'
{
  "generated_at": "2026-01-01T00:00:00Z",
  "nodes": {
    "ollama": {"category": "local_llm_runtime", "highest_risk": "HIGH", "finding_ids": ["SHADOWAI-1", "SHADOWAI-x"], "exposures": []}
  },
  "edges": [],
  "analysis": {
    "node_count": 1, "edge_count": 0, "cycles": [],
    "attack_paths": [{"from": "scanner", "to": "ollama", "path": ["scanner", "ollama"], "path_risk": "HIGH"}],
    "highest_risk_node": {"name": "ollama", "risk": "HIGH"}
  }
}
EOF

# Incident Learning fixture candidates: one CANDIDATE (should be
# ingested), one PROMOTED (should be ingested), one REJECTED (must be
# excluded), one COLLECTED with no score yet (must be excluded).
cat > "$FIXTURE_DIR/il_candidates/KEV-INGEST-1.json" <<'EOF'
{"id": "KEV-INGEST-1", "status": "CANDIDATE", "source": "cisa_kev_collector", "cve_list": ["CVE-2026-90001"], "confidence_score": 55, "evidence_corroborating_count": 1, "collected_at": "2026-01-01T00:00:00Z"}
EOF
cat > "$FIXTURE_DIR/il_candidates/KEV-INGEST-2.json" <<'EOF'
{"id": "KEV-INGEST-2", "status": "PROMOTED", "source": "cisa_kev_collector", "cve_list": ["CVE-2026-90002"], "confidence_score": 90, "evidence_corroborating_count": 2, "collected_at": "2026-01-01T00:00:00Z"}
EOF
cat > "$FIXTURE_DIR/il_candidates/KEV-SKIP-REJECTED.json" <<'EOF'
{"id": "KEV-SKIP-REJECTED", "status": "REJECTED", "source": "cisa_kev_collector", "cve_list": ["CVE-2026-90003"], "confidence_score": 35, "evidence_corroborating_count": 0}
EOF
cat > "$FIXTURE_DIR/il_candidates/KEV-SKIP-COLLECTED.json" <<'EOF'
{"id": "KEV-SKIP-COLLECTED", "status": "COLLECTED", "source": "cisa_kev_collector"}
EOF

# SaaS ATO finding fixture: one CRITICAL-risk account (a simulated
# compromised-account mass-send burst), matching
# security/saas_ato/saas_ato_lib.py's own build_event() output shape
# exactly -- hand-written here, no live saas_ato_monitor.sh scan
# invoked, same decoupling-proof discipline as the shadow_ai/
# attack_graph fixtures above.
cat > "$FIXTURE_DIR/saas_ato.jsonl" <<'EOF'
{"event_type": "saas_ato", "id": "mallory@contoso.example.invalid", "risk": "CRITICAL", "confidence": "HIGH", "timestamp": "2026-01-01T00:00:00Z", "account": "mallory@contoso.example.invalid", "tenant": "contoso.example.invalid", "signals": [{"id": "BURST-1", "signal_type": "mass_send", "recipient_count": 9000}], "evidence": ["account=mallory@contoso.example.invalid"], "correlation": {"window_seconds": 300, "events": [], "candidate_incident": false}}
EOF

IL_DIR_BEFORE_HASH="$(find "$FIXTURE_DIR/il_candidates" -type f -name 'KEV-*' -exec shasum -a 256 {} \; | sort | shasum -a 256)"

echo ""
echo "[I1] ingest with ONLY --shadow-ai: two entities, attack_graph/incident_learning counts are zero"
OUT="$(./security/intelligence/intelligence_layer.sh ingest --shadow-ai "$FIXTURE_DIR/shadow_ai.jsonl" 2>/dev/null)"
assert_eq "I1 shadow_ai count 2" "2" "$(echo "$OUT" | python3 -c "import json,sys; print(json.load(sys.stdin)['sources_ingested']['shadow_ai'])")"
assert_eq "I1 attack_graph count 0" "0" "$(echo "$OUT" | python3 -c "import json,sys; print(json.load(sys.stdin)['sources_ingested']['attack_graph'])")"
assert_eq "I1 entity_count 2" "2" "$(echo "$OUT" | python3 -c "import json,sys; print(json.load(sys.stdin)['summary']['entity_count'])")"

echo ""
echo "[I2] ingest with NO flags at all produces a completely empty report -- never a silent default live read"
EMPTY_OUT="$(./security/intelligence/intelligence_layer.sh ingest 2>/dev/null)"
EMPTY_RC=$?
assert_eq "I2 exit code 0" "0" "$EMPTY_RC"
assert_eq "I2 records_total 0" "0" "$(echo "$EMPTY_OUT" | python3 -c "import json,sys; print(json.load(sys.stdin)['records_total'])")"

echo ""
echo "[I3] ingest with ONLY --incident-learning-dir: exactly 2 candidates ingested (CANDIDATE + PROMOTED), REJECTED/COLLECTED excluded"
IL_OUT="$(./security/intelligence/intelligence_layer.sh ingest --incident-learning-dir "$FIXTURE_DIR/il_candidates" 2>/dev/null)"
assert_eq "I3 incident_learning count 2 (not 4)" "2" "$(echo "$IL_OUT" | python3 -c "import json,sys; print(json.load(sys.stdin)['sources_ingested']['incident_learning'])")"
assert_contains "I3 CVE-2026-90001 (CANDIDATE) present" "$IL_OUT" "CVE-2026-90001"
assert_contains "I3 CVE-2026-90002 (PROMOTED) present" "$IL_OUT" "CVE-2026-90002"
assert_eq "I3 CVE-2026-90003 (REJECTED) absent" "0" "$(echo "$IL_OUT" | grep -c "CVE-2026-90003" || true)"

echo ""
echo "[I4] ingest with ALL THREE combined: ollama (seen from BOTH shadow_ai and attack_graph) merges into ONE entity at the higher risk (HIGH), correctly tagged multi-source"
FULL_OUT="$(./security/intelligence/intelligence_layer.sh ingest \
  --shadow-ai "$FIXTURE_DIR/shadow_ai.jsonl" \
  --attack-graph "$FIXTURE_DIR/attack_graph.json" \
  --incident-learning-dir "$FIXTURE_DIR/il_candidates" 2>/dev/null)"
assert_eq "I4 ollama's merged highest_risk is HIGH (not MEDIUM)" "HIGH" "$(echo "$FULL_OUT" | python3 -c "import json,sys; print(json.load(sys.stdin)['entities']['ollama']['highest_risk'])")"
assert_eq "I4 ollama record_count is 2 (one per source)" "2" "$(echo "$FULL_OUT" | python3 -c "import json,sys; print(json.load(sys.stdin)['entities']['ollama']['record_count'])")"
assert_eq "I4 ollama source_modules has both" "['attack_graph', 'shadow_ai_monitor']" "$(echo "$FULL_OUT" | python3 -c "import json,sys; print(json.load(sys.stdin)['entities']['ollama']['source_modules'])")"
assert_eq "I4 total entities: ollama, claude, scanner->ollama path, 2 CVEs = 5" "5" "$(echo "$FULL_OUT" | python3 -c "import json,sys; print(json.load(sys.stdin)['summary']['entity_count'])")"
assert_eq "I4 multi_source_entity_count is 1 (only ollama)" "1" "$(echo "$FULL_OUT" | python3 -c "import json,sys; print(json.load(sys.stdin)['summary']['multi_source_entity_count'])")"

echo ""
echo "[I5] the report is persisted and readable via 'show'"
SHOW_OUT="$(./security/intelligence/intelligence_layer.sh show)"
assert_eq "I5 persisted report matches the last ingest's entity_count" "5" "$(echo "$SHOW_OUT" | python3 -c "import json,sys; print(json.load(sys.stdin)['summary']['entity_count'])")"

echo ""
echo "[I6] 'status' prints a read-only human-readable summary without error"
STATUS_OUT="$(./security/intelligence/intelligence_layer.sh status)"
assert_contains "I6 status mentions entities" "$STATUS_OUT" "entities:"
assert_contains "I6 status names ollama among top entities" "$STATUS_OUT" "ollama"

echo ""
echo "[I7] a malformed line in the shadow-ai file and a malformed candidate JSON are both skipped gracefully, never crash the ingest"
printf 'not valid json\n{"id":"SHADOWAI-ok","finding_type":"process","category":"x","risk":"LOW","confidence":"LOW","process":{"comm":"okproc","pid":1}}\n' > "$FIXTURE_DIR/malformed_shadow_ai.jsonl"
echo 'not valid json either' > "$FIXTURE_DIR/il_candidates/malformed.json"
MALFORMED_OUT="$(./security/intelligence/intelligence_layer.sh ingest --shadow-ai "$FIXTURE_DIR/malformed_shadow_ai.jsonl" --incident-learning-dir "$FIXTURE_DIR/il_candidates" 2>/dev/null)"
MALFORMED_RC=$?
assert_eq "I7 exit code 0 despite malformed input" "0" "$MALFORMED_RC"
assert_contains "I7 the one valid shadow_ai finding still ingested" "$MALFORMED_OUT" "okproc"
rm -f "$FIXTURE_DIR/il_candidates/malformed.json"

echo ""
echo "[I8] ingest with ONLY --saas-ato: one entity at entity_type saas_account, CRITICAL risk, correctly tagged as single-source"
SAAS_OUT="$(./security/intelligence/intelligence_layer.sh ingest --saas-ato "$FIXTURE_DIR/saas_ato.jsonl" 2>/dev/null)"
assert_eq "I8 saas_ato count 1" "1" "$(echo "$SAAS_OUT" | python3 -c "import json,sys; print(json.load(sys.stdin)['sources_ingested']['saas_ato'])")"
assert_eq "I8 entity_type is saas_account" "saas_account" "$(echo "$SAAS_OUT" | python3 -c "import json,sys; print(json.load(sys.stdin)['entities']['mallory@contoso.example.invalid']['entity_type'])")"
assert_eq "I8 highest_risk is CRITICAL" "CRITICAL" "$(echo "$SAAS_OUT" | python3 -c "import json,sys; print(json.load(sys.stdin)['entities']['mallory@contoso.example.invalid']['highest_risk'])")"
assert_eq "I8 source_modules is ['saas_ato'] only" "['saas_ato']" "$(echo "$SAAS_OUT" | python3 -c "import json,sys; print(json.load(sys.stdin)['entities']['mallory@contoso.example.invalid']['source_modules'])")"

echo ""
echo "=== D-series: structural read-only / no-network / no-Control-Plane / loose-coupling guards ==="

code_only() {
  grep -vE '^[[:space:]]*#' "$1"
}

echo ""
echo "[D1] this module never sources security/lib.sh and never calls egress_check/audit_log/trigger_shutdown in actual code"
for pattern in 'source security/lib\.sh' 'egress_check' 'trigger_shutdown' '\baudit_log\('; do
  cnt="$(code_only security/intelligence/intelligence_layer.sh | grep -cE "$pattern" || true)"
  assert_eq "D1 zero code occurrences of '$pattern'" "0" "$cnt"
done

echo ""
echo "[D2] zero network tools (curl/wget/nc) and zero ps/lsof calls anywhere in the shell wrapper's actual code"
bad_calls=0
for pattern in '\b(curl|wget|nc )\b' '\bps\b' '\blsof\b'; do
  c="$(code_only security/intelligence/intelligence_layer.sh | grep -cE "$pattern" || true)"
  bad_calls=$((bad_calls + c))
done
assert_eq "D2 zero network/ps/lsof invocations" "0" "$bad_calls"

echo ""
echo "[D2b] intelligence_lib.py never shells out (no subprocess/os.system/os.popen/exec)"
assert_eq "D2b zero subprocess/os.system/os.popen/os.exec calls" "0" "$(grep -cE '\b(subprocess|os\.system|os\.popen|os\.exec\w*)\b' security/intelligence/intelligence_lib.py || true)"

echo ""
echo "[D3] zero process/firewall/routing-modifying commands anywhere in the module's actual code"
mod_calls=0
for pattern in '\bkill\b' '\bkillall\b' '\bpfctl\b' '\broute\b' '\bifconfig\b' 'launchctl (unload|stop|kickstart)' '\bnetworksetup\b'; do
  for f in security/intelligence/intelligence_layer.sh security/intelligence/intelligence_lib.py; do
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
echo "[D5] this module never imports shadow_ai_lib/attack_graph_lib/saas_ato_lib or calls shadow_ai_monitor.sh/attack_graph.sh/saas_ato_monitor.sh -- coupling is via each source's own documented schema only"
assert_eq "D5 zero 'import shadow_ai'/'import attack_graph'/'import saas_ato' statements" "0" "$(grep -cE '^\s*(import|from)\s+(shadow_ai|attack_graph|saas_ato)' security/intelligence/intelligence_lib.py || true)"
assert_eq "D5 zero calls to shadow_ai_monitor.sh/attack_graph.sh/saas_ato_monitor.sh in actual code" "0" "$(code_only security/intelligence/intelligence_layer.sh | grep -cE 'shadow_ai_monitor\.sh|attack_graph\.sh|saas_ato_monitor\.sh' || true)"

echo ""
echo "[D6] ingesting from --incident-learning-dir is read-only: not one byte of this suite's own fixture candidate directory was modified by any ingest call above (same guarantee a real deployment relies on when pointed at its actual security/state/incident_learning/candidates/)"
IL_DIR_AFTER_HASH="$(find "$FIXTURE_DIR/il_candidates" -type f -name 'KEV-*' -exec shasum -a 256 {} \; | sort | shasum -a 256)"
assert_eq "D6 KEV-*.json fixture files byte-identical before vs. after every ingest run above" "$IL_DIR_BEFORE_HASH" "$IL_DIR_AFTER_HASH"

echo ""
echo "=== Summary: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
  echo "Failures:"
  for f in "${FAILURES[@]}"; do echo "  - $f"; done
  exit 1
fi
exit 0
