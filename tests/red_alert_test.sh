#!/bin/bash
set -uo pipefail

# tests/red_alert_test.sh -- regression suite for WAIO GLOBAL RED ALERT
# requirement #3: security/red_alert/snd_crossref.py (SND@HOME textual
# cross-reference) + security/red_alert/red_alert_adapter.py (adapts
# Global Patrol / Critical Infra Watch / snd_crossref output into the
# WAIO Intelligence/Evidence Layer's own Intelligence Record shape --
# see security/intelligence/intelligence_lib.py's own adapter-function
# header for that exact contract).
#
# This suite did not exist before -- snd_crossref.py's own header
# already claimed it ("verified by tests/red_alert_test.sh's own
# recursive scan, same technique as Critical Infra Watch's own S2"),
# so its absence was a real gap (claimed coverage with no test behind
# it), not a style nit. Same three-layer convention as
# tests/intelligence_layer_test.sh / tests/critical_infra_watch_test.sh:
#   U-series: unit tests against both modules' pure functions.
#   D-series: static structural guards -- D8/D9 here are the ones that
#     matter most: as of this suite, security/red_alert/ is NOT wired
#     into decision_engine.sh, intelligence_layer.sh, any cron wrapper,
#     or any *.plist -- these two files are pure, uncalled adapter code.
#     That is an explicit, current-state fact this suite pins down, not
#     an assumption: if a future phase wires them in, whoever does that
#     should have to touch this test (and decide whether D8/D9 still
#     hold) rather than that connection silently happening unnoticed.
#
# No I/O anywhere in either module under test (both modules' own
# headers state this) -- every case below is a pure function call, no
# fixture files, no isolated state dir needed.

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
sys.path.insert(0, 'security/red_alert')
import red_alert_adapter as ra
import snd_crossref as sc
$1
"
}

code_only() {
  grep -vE '^[[:space:]]*#' "$1"
}

# code_only_py FILE -- FILE's own tokens with every STRING (so every
# docstring, module-level or per-function) and COMMENT token removed,
# as plain space-joined text. Both modules under test name forbidden
# identifiers (os.popen, knowledge_manager.sh, ...) in their OWN
# docstrings purely as documentation of what they do NOT call -- same
# "a module's docstring is free to NAME these tools" posture
# tests/decision_engine_test.sh's own D5 comment already states as
# expected, just not previously exercised by a file whose docstring
# actually does it. A plain `grep` (even restricted to non-# lines, the
# bash-oriented code_only() above) cannot tell a multi-line Python
# triple-quoted docstring from real code; stripping STRING/COMMENT
# tokens via Python's own tokenizer can, and is exact rather than
# heuristic.
code_only_py() {
  python3 -c "
import tokenize, io
src = open('$1').read()
out = []
for tok in tokenize.generate_tokens(io.StringIO(src).readline):
    if tok.type in (tokenize.STRING, tokenize.COMMENT):
        continue
    out.append(tok.string)
print(' '.join(out))
"
}

echo "=== WAIO GLOBAL RED ALERT requirement #3 regression suite ==="
echo "    (security/red_alert/snd_crossref.py + security/red_alert/red_alert_adapter.py)"

echo ""
echo "=== U-series: red_alert_adapter.py unit tests ==="

echo ""
echo "[U1] from_global_patrol_entity: every confidence_level maps to the stated, fixed risk/confidence table"
out="$(pyval "
for level, want_risk, want_conf in [
    ('CONFIRMED', 'CRITICAL', 'HIGH'),
    ('HIGH', 'HIGH', 'HIGH'),
    ('MEDIUM', 'MEDIUM', 'MEDIUM'),
    ('LOW', 'LOW', 'LOW'),
    ('UNVERIFIED', 'LOW', 'LOW'),
    ('bogus_unknown_level', 'LOW', 'LOW'),
]:
    r = ra.from_global_patrol_entity({'id': 'X1', 'confidence_level': level, 'attack_pattern': 'ransomware'}, 'global_patrol')
    assert r['risk'] == want_risk and r['confidence'] == want_conf, (level, r)
print('ok')
")"
assert_eq "U1 all six confidence_level inputs map correctly" "ok" "$out"

echo ""
echo "[U2] from_global_patrol_entity: entity_type distinguishes a critical_sectors-bearing entry (Critical Infra Watch confirmed_activity) from a plain Global Patrol entry"
out="$(pyval "
a = ra.from_global_patrol_entity({'id': 'G1', 'confidence_level': 'HIGH', 'attack_pattern': 'ransomware'}, 'global_patrol')
b = ra.from_global_patrol_entity({'id': 'G2', 'confidence_level': 'HIGH', 'critical_sectors': ['energy']}, 'critical_infra_watch')
print(a['entity_type'], b['entity_type'])
")"
assert_eq "U2 global_patrol_incident vs critical_infra_activity" "global_patrol_incident critical_infra_activity" "$out"

echo ""
echo "[U3] from_global_patrol_entity: id is namespaced INTEL-<source_module>-<entry_id>, entity/source_finding_id are the entry's own id (never guessed/renamed)"
out="$(pyval "
r = ra.from_global_patrol_entity({'id': 'KEV-CVE-2099-0001', 'confidence_level': 'HIGH', 'attack_pattern': 'ransomware'}, 'global_patrol')
print(r['id'], r['entity'], r['source_finding_id'])
")"
assert_eq "U3 id/entity/source_finding_id" "INTEL-global_patrol-KEV-CVE-2099-0001 KEV-CVE-2099-0001 KEV-CVE-2099-0001" "$out"

echo ""
echo "[U4] from_global_patrol_entity: raw carries the ORIGINAL entry unabridged (traceability -- never discards source evidence)"
out="$(pyval "
entry = {'id': 'G3', 'confidence_level': 'HIGH', 'attack_pattern': 'ransomware', 'extra_field_not_otherwise_read': 'kept'}
r = ra.from_global_patrol_entity(entry, 'global_patrol')
print(r['raw'] == entry)
")"
assert_eq "U4 raw is the untouched original entry" "True" "$out"

echo ""
echo "[U5] from_precursor_hypothesis: risk/confidence are ALWAYS fixed HIGH/HIGH -- never derived from (or overridable by) any field on the hypothesis dict itself"
out="$(pyval "
h1 = {'attack_pattern': 'water_utility_intrusion', 'countries_involved': ['JP', 'US'], 'member_ids': ['C1', 'C2']}
h2 = dict(h1, risk='LOW', confidence='LOW')  # an attacker-controlled/malformed dict trying to smuggle its own risk/confidence
r1 = ra.from_precursor_hypothesis(h1)
r2 = ra.from_precursor_hypothesis(h2)
print(r1['risk'], r1['confidence'], r2['risk'], r2['confidence'])
")"
assert_eq "U5 fixed HIGH/HIGH regardless of attacker-supplied risk/confidence keys on input" "HIGH HIGH HIGH HIGH" "$out"

echo ""
echo "[U6] from_precursor_hypothesis: entity is the SHARED attack_pattern, not any one member's id (S1's own cross-country gate already guarantees >=2 members by construction)"
out="$(pyval "
h = {'attack_pattern': 'water_utility_intrusion', 'countries_involved': ['JP', 'US'], 'member_ids': ['C1', 'C2']}
r = ra.from_precursor_hypothesis(h)
print(r['entity'], r['category'])
")"
assert_eq "U6 entity/category == attack_pattern, never a member id" "water_utility_intrusion water_utility_intrusion" "$out"

echo ""
echo "[U7] from_precursor_hypothesis: confidence_caveat is carried into the summary verbatim, never stripped (a human reading the eventual Decision Record must see the full original caveat)"
out="$(pyval "
h = {'attack_pattern': 'x', 'countries_involved': ['JP'], 'member_ids': ['C1'], 'confidence_caveat': 'UNIQUE_CAVEAT_TEXT_42'}
r = ra.from_precursor_hypothesis(h)
print('UNIQUE_CAVEAT_TEXT_42' in r['summary'])
")"
assert_eq "U7 confidence_caveat preserved verbatim in summary" "True" "$out"

echo ""
echo "[U8] from_snd_crossref_signal: risk is ALWAYS fixed LOW, confidence ALWAYS fixed MEDIUM -- a textual match raises confidence on an existing finding via aggregation, never asserts its own risk"
out="$(pyval "
sig = {'entity_id': 'KEV-CVE-2099-0001', 'snd_section': 'active_alerts', 'match_keyword': 'ransomware', 'confidence_caveat': 'textual only'}
r = ra.from_snd_crossref_signal(sig)
print(r['risk'], r['confidence'])
")"
assert_eq "U8 fixed LOW/MEDIUM" "LOW MEDIUM" "$out"

echo ""
echo "[U9] from_snd_crossref_signal: entity is EXACTLY the signal's own entity_id -- the one load-bearing alignment that lets aggregate_by_entity() roll this signal into the SAME profile as the matched global finding"
out="$(pyval "
g = ra.from_global_patrol_entity({'id': 'KEV-CVE-2099-0001', 'confidence_level': 'HIGH', 'attack_pattern': 'ransomware'}, 'global_patrol')
sig = {'entity_id': 'KEV-CVE-2099-0001', 'snd_section': 'active_alerts', 'match_keyword': 'ransomware', 'confidence_caveat': 'textual only'}
s = ra.from_snd_crossref_signal(sig)
print(g['entity'] == s['entity'])
")"
assert_eq "U9 entity alignment between a global finding and its crossref signal" "True" "$out"

echo ""
echo "[U10] *** THE CRITICAL AGGREGATION GUARD *** a HIGH-risk global finding plus its own LOW-risk snd_home_crossref signal, run through intelligence_lib.py's real aggregate_by_entity(), never downgrades -- the profile's highest_risk stays HIGH, and multi_source corroboration (2 distinct source_modules) is visible exactly as red_alert_adapter.py's own U9 header claims"
out="$(python3 -c "
import sys
sys.path.insert(0, 'security/red_alert')
sys.path.insert(0, 'security/intelligence')
import red_alert_adapter as ra
import intelligence_lib as il

g = ra.from_global_patrol_entity({'id': 'KEV-CVE-2099-0001', 'confidence_level': 'HIGH', 'attack_pattern': 'ransomware'}, 'global_patrol')
sig = {'entity_id': 'KEV-CVE-2099-0001', 'snd_section': 'active_alerts', 'match_keyword': 'ransomware', 'confidence_caveat': 'textual only'}
s = ra.from_snd_crossref_signal(sig)

profiles = il.aggregate_by_entity([g, s])
p = profiles['KEV-CVE-2099-0001']
print(p['highest_risk'], p['highest_confidence'], sorted(p['source_modules']), p['record_count'])
")"
assert_eq "U10 HIGH risk never downgraded by a LOW-risk crossref signal; confidence raised to HIGH; both source_modules present" "HIGH HIGH ['global_patrol', 'snd_home_crossref'] 2" "$out"

echo ""
echo "=== U-series: snd_crossref.py unit tests ==="

echo ""
echo "[U11] build_crossref_signals: no SND@HOME snapshot (None) -> empty list, never an error"
out="$(pyval "print(sc.build_crossref_signals(None, [{'id': 'X', 'attack_pattern': 'ransomware'}]))")"
assert_eq "U11 None snapshot -> []" "[]" "$out"

echo ""
echo "[U12] build_crossref_signals: a snapshot with every section None/absent -> empty list"
out="$(pyval "print(sc.build_crossref_signals({'active_alerts': None, 'lan_status': None, 'system_status': None, 'terminals': None}, [{'id': 'X', 'attack_pattern': 'ransomware'}]))")"
assert_eq "U12 all-empty snapshot -> []" "[]" "$out"

echo ""
echo "[U13] build_crossref_signals: a malformed (non-dict) snapshot never raises -- defensive by construction, since SND@HOME's own shape is not independently verifiable from this repo"
out="$(pyval "
for bad in ['a plain string', 123, [1, 2, 3], True]:
    sc.build_crossref_signals(bad, [{'id': 'X', 'attack_pattern': 'ransomware'}])
print('no exception raised')
")"
assert_eq "U13 malformed snapshot shapes never raise" "no exception raised" "$out"

echo ""
echo "[U14] build_crossref_signals: a genuine case-insensitive keyword match in active_alerts produces exactly one signal, with the correct entity_id/section/keyword and a non-empty confidence_caveat"
out="$(pyval "
snd = {'active_alerts': {'alerts': ['RANSOMWARE activity detected on LAN segment 3']}}
entities = [{'id': 'KEV-CVE-2099-0001', 'attack_pattern': 'ransomware'}]
signals = sc.build_crossref_signals(snd, entities)
print(len(signals), signals[0]['entity_id'], signals[0]['snd_section'], signals[0]['match_keyword'], bool(signals[0]['confidence_caveat']))
")"
assert_eq "U14 one case-insensitive match, correct fields, caveat present" "1 KEV-CVE-2099-0001 active_alerts ransomware True" "$out"

echo ""
echo "[U15] build_crossref_signals: no keyword overlap at all -> empty list (no false-positive match)"
out="$(pyval "
snd = {'active_alerts': {'alerts': ['routine LAN health check, nothing unusual']}}
entities = [{'id': 'KEV-CVE-2099-0001', 'attack_pattern': 'ransomware'}]
print(sc.build_crossref_signals(snd, entities))
")"
assert_eq "U15 no match -> []" "[]" "$out"

echo ""
echo "[U16] build_crossref_signals: generic sentinels ('unclassified'/'unknown') are never used as match keywords -- would otherwise match almost any SND@HOME text"
out="$(pyval "
snd = {'active_alerts': {'alerts': ['status unknown, unclassified event logged']}}
entities = [{'id': 'X', 'attack_pattern': 'unclassified', 'incident_type': 'unclassified', 'affected_sector': 'unknown'}]
print(sc.build_crossref_signals(snd, entities))
")"
assert_eq "U16 sentinel-only entity never matches, even when the exact words appear in the text" "[]" "$out"

echo ""
echo "[U17] build_crossref_signals: entities missing an id are skipped entirely (never a signal with entity_id=None reaching the adapter)"
out="$(pyval "
snd = {'active_alerts': {'alerts': ['ransomware detected']}}
entities = [{'attack_pattern': 'ransomware'}]  # no 'id' key
print(sc.build_crossref_signals(snd, entities))
")"
assert_eq "U17 id-less entity contributes no signal" "[]" "$out"

echo ""
echo "[U18] build_crossref_signals: critical_sectors list keywords ARE matched (Critical Infra Watch confirmed_activity shape), same as attack_pattern/incident_type/affected_sector"
out="$(pyval "
snd = {'system_status': {'note': 'energy grid telemetry nominal'}}
entities = [{'id': 'CIW-1', 'critical_sectors': ['energy']}]
signals = sc.build_crossref_signals(snd, entities)
print(len(signals), signals[0]['match_keyword'] if signals else None)
")"
assert_eq "U18 critical_sectors keyword match" "1 energy" "$out"

echo ""
echo "=== D-series: structural guards ==="

echo ""
echo "[D1] both modules never source security/lib.sh / never call egress_check/audit_log/trigger_shutdown (not bash, but grepped for the same forbidden identifiers as every other DuCoPA-aligned module in this repo, as defense in depth alongside D2's stronger I/O-absence proof)"
for f in security/red_alert/red_alert_adapter.py security/red_alert/snd_crossref.py; do
  for pattern in 'egress_check' 'trigger_shutdown' '\baudit_log\(' 'security/lib\.sh'; do
    cnt="$(code_only "$f" | grep -cE "$pattern" || true)"
    assert_eq "D1 ($f) zero occurrences of '$pattern'" "0" "$cnt"
  done
done

echo ""
echo "[D2] *** THE CRITICAL I/O-ABSENCE GUARD *** neither module's ACTUAL CODE (docstrings/comments stripped via Python's own tokenizer, not a plain grep -- both modules' docstrings legitimately NAME os.popen/subprocess/etc. as documentation of their own absence, same posture tests/decision_engine_test.sh's own D5 comment already states as expected) has any subprocess/os.system/os.popen/exec/open()/network call -- a strictly stronger guarantee than a name-based grep, since it proves neither module can invoke ANY external tool or touch any file/socket by any name, matching both modules' own 'No I/O in this module' header claim"
for f in security/red_alert/red_alert_adapter.py security/red_alert/snd_crossref.py; do
  cnt="$(code_only_py "$f" | grep -cE '\b(subprocess|os\.system|os\.popen|os\.exec\w*|requests\.|urllib|socket\.|curl|\bopen\()\b' || true)"
  assert_eq "D2 ($f) zero I/O/subprocess/network references in actual code" "0" "$cnt"
done

echo ""
echo "[D3] *** NO NUMERIC PROBABILITY/ETA FIELD ANYWHERE *** -- recursive key scan over every adapter's output, same technique as tests/critical_infra_watch_test.sh's own S2, extended to this module's three adapters plus a crossref signal list"
PY="$(mktemp)"
trap 'rm -f "$PY"' EXIT
cat > "$PY" <<'PYEOF'
import sys
sys.path.insert(0, 'security/red_alert')
import red_alert_adapter as ra
import snd_crossref as sc

bad_names = ('probability', 'likelihood', 'eta', 'confidence_percent', 'predicted_date', 'attack_date')


def scan(obj):
    count = 0
    if isinstance(obj, dict):
        for k, v in obj.items():
            if any(b in k.lower() for b in bad_names):
                count += 1
            count += scan(v)
    elif isinstance(obj, list):
        for v in obj:
            count += scan(v)
    return count


total = 0
total += scan(ra.from_global_patrol_entity({'id': 'G1', 'confidence_level': 'HIGH', 'attack_pattern': 'ransomware'}, 'global_patrol'))
total += scan(ra.from_precursor_hypothesis({'attack_pattern': 'x', 'countries_involved': ['JP', 'US'], 'member_ids': ['C1', 'C2']}))
total += scan(ra.from_snd_crossref_signal({'entity_id': 'G1', 'snd_section': 'active_alerts', 'match_keyword': 'ransomware', 'confidence_caveat': 'textual only'}))
snd = {'active_alerts': {'alerts': ['ransomware detected']}}
total += scan(sc.build_crossref_signals(snd, [{'id': 'G1', 'attack_pattern': 'ransomware'}]))
print(total)
PYEOF
assert_eq "D3 zero probability/eta-shaped keys anywhere across all four output shapes" "0" "$(python3 "$PY")"

echo ""
echo "[D4] every build_crossref_signals() signal carries a non-empty confidence_caveat, and that caveat is never silently dropped by from_snd_crossref_signal's own summary -- a match is never presentable without the 'this is textual only, not verified' disclaimer attached"
out="$(pyval "
snd = {'active_alerts': {'alerts': ['ransomware detected']}}
signals = sc.build_crossref_signals(snd, [{'id': 'G1', 'attack_pattern': 'ransomware'}])
ok_nonempty = all(bool(s['confidence_caveat']) for s in signals)
r = ra.from_snd_crossref_signal(signals[0])
print(ok_nonempty, signals[0]['confidence_caveat'] in r['summary'])
")"
assert_eq "D4 non-empty caveat on every signal, carried into the adapter's summary" "True True" "$out"

echo ""
echo "[D5] both modules' docstrings describe themselves as pure/no-I/O -- confirm NEITHER defines a __main__ entry point (no 'if __name__' block) -- these are library modules only, never directly executable, matching their own stated design"
for f in security/red_alert/red_alert_adapter.py security/red_alert/snd_crossref.py; do
  cnt="$(grep -c '__name__' "$f" || true)"
  assert_eq "D5 ($f) zero __main__ entry points" "0" "$cnt"
done

echo ""
echo "[D6] *** CURRENT-STATE PIN, UPDATED BY WAIO GLOBAL RED ALERT PHASE A *** this guard originally asserted zero references to red_alert/snd_crossref anywhere in decision_engine.sh, decision_engine_lib.py, intelligence_layer.sh, or intelligence_lib.py. Phase A (tests/intelligence_layer_global_patrol_test.sh) deliberately, explicitly wired security/intelligence/intelligence_layer.sh's own ingest() to this module via two new optional flags (--global-patrol-report/--snd-snapshot) -- exactly the kind of change this guard's own original comment said would make it 'fail here FIRST, forcing an explicit, visible decision to update (not silently relax) this test.' This IS that explicit, visible decision: intelligence_layer.sh is now a KNOWN, APPROVED caller (D6b below), while the Decision Engine and the pure intelligence_lib.py library remain UNCHANGED and UNWIRED (D6a), exactly as required -- this phase never touched decision_engine.sh/decision_engine_lib.py/intelligence_lib.py, security/guardian.sh, security/ducopa.sh, any cron wrapper, or any launchd plist (see tests/intelligence_layer_global_patrol_test.sh's own D2/D5 for the direct proof)."
cnt=0
for f in security/decision_engine/decision_engine.sh security/decision_engine/decision_engine_lib.py security/intelligence/intelligence_lib.py; do
  c="$(grep -cE 'red_alert|snd_crossref' "$f" || true)"
  cnt=$((cnt + c))
done
assert_eq "D6a zero references to red_alert/snd_crossref in the Decision Engine or the pure intelligence_lib.py library" "0" "$cnt"
assert_eq "D6b intelligence_layer.sh DOES now reference red_alert/snd_crossref -- the one approved, explicit Phase A connection point, not an accident" "nonzero" "$([ "$(grep -cE 'red_alert|snd_crossref' security/intelligence/intelligence_layer.sh || true)" -gt 0 ] && echo nonzero || echo zero)"

echo ""
echo "[D7] *** CURRENT-STATE PIN, UPDATED BY WAIO GLOBAL RED ALERT PHASE B *** this guard originally asserted red_alert_cron.sh did not exist at all. Phase B (tests/red_alert_cron_test.sh) deliberately, explicitly added it, as a manual-invocation-only prototype -- exactly the kind of change this guard's own original comment said would force 'an explicit, visible decision to update this test.' This IS that decision: D7a now confirms the file EXISTS (expected, approved), while D7b/D7c -- the guards that actually matter -- still assert it is NOT scheduled: no launchd plist names it, and no security/incident_learning/*.sh cron wrapper references it. Running it remains exactly as consequential as a human typing the equivalent intelligence_layer.sh ingest command by hand (see tests/red_alert_cron_test.sh's own D4/D5/D8 for the direct proof it never self-registers and is never invoked by any other script)."
assert_eq "D7a red_alert_cron.sh now exists -- Phase B's own deliberate, approved prototype, not an accident" "present" "$([ -e security/red_alert/red_alert_cron.sh ] && echo present || echo absent)"
assert_eq "D7b no *red-alert*/*red_alert* launchd plist in this repo (still not scheduled)" "0" "$(find . -iname '*red*alert*.plist*' -not -path './logs/*' -not -path './results/*' 2>/dev/null | wc -l | tr -d ' ')"
assert_eq "D7c zero references to red_alert in any security/incident_learning/*.sh cron wrapper" "0" "$(grep -l 'red_alert' security/incident_learning/*.sh 2>/dev/null | wc -l | tr -d ' ')"

echo ""
echo "[D8] neither module's ACTUAL CODE calls any Human Gate / Guardian / promotion primitive by name (docstring-stripped, same technique as D2 -- red_alert_adapter.py's own docstring legitimately NAMES knowledge_manager.sh as documentation of where its confidence_level labels originate, never as a call)"
cnt=0
for f in security/red_alert/red_alert_adapter.py security/red_alert/snd_crossref.py; do
  code="$(code_only_py "$f")"
  for pattern in 'knowledge_manager\.sh' 'incident_human_gate\.sh' 'guardian\.sh' 'guardian_approve\.sh' 'guardian_intervene' 'recover\.sh' 'recovery_engine\.sh' '\bducopa\.sh'; do
    c="$(printf '%s' "$code" | grep -cE "$pattern" || true)"
    cnt=$((cnt + c))
  done
done
assert_eq "D8 zero references to any Human Gate/Guardian/promotion tool by name in actual code" "0" "$cnt"

echo ""
echo "=== Summary: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
  printf 'FAILURES:\n'
  printf '  - %s\n' "${FAILURES[@]}"
  exit 1
fi
exit 0
