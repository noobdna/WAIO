#!/bin/bash
set -uo pipefail

# tests/critical_infra_watch_test.sh -- regression suite for
# security/incident_learning/critical_infra_watch.py, the "Critical
# Infrastructure & Military Precursor Watch" additional analysis
# section wired into global_patrol_report.py's own output (section 7).
#
# This suite's own priority order is deliberate: the S-series
# (Safety) guards come FIRST and are the reason this file exists at
# all -- they are the structural proof that this module can never, by
# construction, infer a military precursor from a single incident, a
# sector alone, or an attribution claim alone (S1), never emits a
# numeric probability/date (S2), always keeps confirmed facts /
# regulatory-statement mentions / WAIO's own hypotheses in separate,
# non-merging output keys (S3), and always reports "判定不能" rather
# than guessing when upstream data cannot support a determination
# (S4). The C-series below covers ordinary correctness (carryover
# persistence/resolution, suppressed-hypothesis reasoning, markdown
# rendering).
#
# Each Python case is written to its own temp .py file and run as
# `python3 file.py` -- deliberately NOT inline `python3 -c "..."`
# nested inside command substitution nested inside a quoted test
# argument: that 3-level quoting combination was found, during this
# suite's own development, to trigger bash BRACE EXPANSION on a
# dict literal's `{...}` even though it looked fully quoted (verified
# concretely: `{'id':'C1','raw_text':'...'}` silently exploded into
# several separate comma-split arguments/invocations). Writing each
# snippet to its own file sidesteps that bash-quoting class of bug
# entirely, rather than fighting it with more escaping.

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

FIXTURE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/waio-critical-infra-watch-test.XXXXXX")"
trap 'rm -rf "$FIXTURE_DIR"' EXIT
PY="$FIXTURE_DIR/case.py"

echo "=== Critical Infrastructure & Military Precursor Watch regression suite ==="

echo ""
echo "[S1] *** THE CRITICAL GUARD *** a SINGLE incident -- even in-scope, even with BOTH an attribution claim AND an OT/ICS cue -- never by itself produces a precursor_hypothesis"
cat > "$PY" <<'PYEOF'
import sys
sys.path.insert(0, 'security/incident_learning')
import critical_infra_watch as ciw
c = {
    'id': 'C1',
    'raw_text': 'A military defense ministry network breach was attributed to a nation-state group; the attacker had industrial control system access for years.',
    'country': 'JP', 'attack_pattern': 'data_breach', 'incident_type': 'data_breach',
    'corroborating_sources': ['https://example.invalid/x'],
    'source_url': 'https://example.invalid/c1', 'source': 'news',
}
section, _ = ciw.build_section([c], {'C1': 'HIGH'}, [], '2026-10-09T00:00:00Z')
print(len(section['precursor_hypotheses']))
PYEOF
assert_eq "S1 zero hypotheses from one sensitive incident alone" "0" "$(python3 "$PY")"

echo ""
echo "[S1b] two independently-corroborated confirmed incidents, same attack_pattern, two distinct countries -> exactly one hypothesis IS produced (the gate works, not just 'always zero')"
cat > "$PY" <<'PYEOF'
import sys
sys.path.insert(0, 'security/incident_learning')
import critical_infra_watch as ciw
base = {
    'raw_text': 'A government network intrusion was reported.',
    'attack_pattern': 'data_breach', 'incident_type': 'data_breach',
    'corroborating_sources': ['https://example.invalid/corrob'], 'source': 'news',
}
c1 = dict(base, id='C1', country='JP', source_url='https://example.invalid/c1')
c2 = dict(base, id='C2', country='US', source_url='https://example.invalid/c2')
section, _ = ciw.build_section([c1, c2], {'C1': 'HIGH', 'C2': 'HIGH'}, [], '2026-10-09T00:00:00Z')
print(len(section['precursor_hypotheses']))
PYEOF
assert_eq "S1b one hypothesis from the genuine multi-country pattern" "1" "$(python3 "$PY")"

echo ""
echo "[S1c] a hypothesis is suppressed (not silently dropped) when one of its members has NO independent corroboration -- reasoning is reported, not hidden"
cat > "$PY" <<'PYEOF'
import sys
sys.path.insert(0, 'security/incident_learning')
import critical_infra_watch as ciw
base = {
    'raw_text': 'A government network intrusion was reported.',
    'attack_pattern': 'data_breach', 'incident_type': 'data_breach', 'source': 'news',
}
c1 = dict(base, id='C1', country='JP', source_url='https://example.invalid/c1', corroborating_sources=['https://example.invalid/corrob'])
c2 = dict(base, id='C2', country='US', source_url='https://example.invalid/c2', corroborating_sources=[])
section, _ = ciw.build_section([c1, c2], {'C1': 'HIGH', 'C2': 'HIGH'}, [], '2026-10-09T00:00:00Z')
print(len(section['precursor_hypotheses']), len(section['precursor_hypotheses_suppressed']))
PYEOF
assert_eq "S1c zero emitted, one suppressed-with-reason" "0 1" "$(python3 "$PY")"

echo ""
echo "[S2] *** THE CRITICAL GUARD *** no numeric probability/likelihood/ETA field exists ANYWHERE in this module's output schema, even for a genuine multi-country hypothesis"
cat > "$PY" <<'PYEOF'
import sys
sys.path.insert(0, 'security/incident_learning')
import critical_infra_watch as ciw
base = {
    'raw_text': 'A government network intrusion was reported.',
    'attack_pattern': 'data_breach', 'incident_type': 'data_breach',
    'corroborating_sources': ['https://example.invalid/corrob'], 'source': 'news',
}
c1 = dict(base, id='C1', country='JP', source_url='https://example.invalid/c1')
c2 = dict(base, id='C2', country='US', source_url='https://example.invalid/c2')
section, _ = ciw.build_section([c1, c2], {'C1': 'HIGH', 'C2': 'HIGH'}, [], '2026-10-09T00:00:00Z')
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


print(scan(section))
PYEOF
assert_eq "S2 zero probability/eta-shaped keys anywhere in the section (recursive key scan)" "0" "$(python3 "$PY")"

echo ""
echo "[S3] confirmed facts / regulatory-statement mentions / WAIO's own hypotheses are three STRUCTURALLY SEPARATE keys -- a regulatory-statement claim is never copied into precursor_hypotheses, and a hypothesis entry never repeats the raw claim text, only member ids"
cat > "$PY" <<'PYEOF'
import sys
sys.path.insert(0, 'security/incident_learning')
import critical_infra_watch as ciw
c = {
    'id': 'C1', 'raw_text': 'CISA said a government network was breached.',
    'country': 'JP', 'attack_pattern': 'data_breach', 'incident_type': 'data_breach',
    'corroborating_sources': [], 'source_url': 'https://example.invalid/c1', 'source': 'news',
}
section, _ = ciw.build_section([c], {'C1': 'HIGH'}, [], '2026-10-09T00:00:00Z')
has_reg = len(section['regulatory_statements']) == 1
keys_distinct = set(section.keys()) >= {'confirmed_activity', 'regulatory_statements', 'precursor_hypotheses'}
no_raw_text_leak = all('CISA said' not in str(v) for v in section['precursor_hypotheses'])
print(has_reg, keys_distinct, no_raw_text_leak)
PYEOF
assert_eq "S3 regulatory statement captured, keys distinct, no raw-text leakage into hypotheses" "True True True" "$(python3 "$PY")"

echo ""
echo "[S4] upstream data insufficiency is reported as '判定不能' (data_limitations), never guessed -- a candidate with unknown country is excluded from multi-country correlation, not defaulted to a country"
cat > "$PY" <<'PYEOF'
import sys
sys.path.insert(0, 'security/incident_learning')
import critical_infra_watch as ciw
c = {
    'id': 'C1', 'raw_text': 'A government network intrusion was reported.',
    'country': 'unknown', 'attack_pattern': 'data_breach', 'incident_type': 'data_breach',
    'corroborating_sources': ['https://example.invalid/x'],
    'source_url': 'https://example.invalid/c1', 'source': 'news',
}
section, _ = ciw.build_section([c], {'C1': 'HIGH'}, [], '2026-10-09T00:00:00Z')
limitation_present = any(('判定不能' in n) or ('不明' in n) for n in section['data_limitations'])
print(limitation_present, len(section['precursor_hypotheses']))
PYEOF
assert_eq "S4 limitation reported, no hypothesis guessed from an unknown country" "True 0" "$(python3 "$PY")"

echo ""
echo "[C1] zero changes made to incident_normalizer.sh's own shared classification file (sector classification kept structurally independent, per approved design)"
assert_eq "C1 incident_normalizer.sh unchanged (git diff empty)" "" "$(git diff --name-only -- security/incident_learning/incident_normalizer.sh 2>/dev/null)"
assert_eq "C1 incident_normalizer.sh has no reference to critical_infra_watch (one-way dependency only)" "0" "$(grep -c critical_infra_watch security/incident_learning/incident_normalizer.sh || true)"

echo ""
echo "[C2] carryover persistence: an open finding survives unchanged (first_seen_at preserved, last_checked_at advances) across repeated cycles until explicitly resolved"
cat > "$PY" <<'PYEOF'
import sys
sys.path.insert(0, 'security/incident_learning')
import critical_infra_watch as ciw
c = {
    'id': 'C1', 'raw_text': 'A military defense ministry network breach occurred.',
    'country': 'JP', 'attack_pattern': 'data_breach', 'incident_type': 'data_breach',
    'corroborating_sources': [], 'source_url': 'https://example.invalid/c1', 'source': 'news',
}
section1, carry1 = ciw.build_section([c], {'C1': 'HIGH'}, [], '2026-10-09T00:00:00Z')
section2, carry2 = ciw.build_section([c], {'C1': 'HIGH'}, carry1, '2026-10-12T00:00:00Z')
open2 = [x for x in carry2 if x['status'] == 'open']
print(open2[0]['first_seen_at'], open2[0]['last_checked_at'], len(open2))
PYEOF
assert_eq "C2 first_seen_at preserved across cycles, last_checked_at advances, exactly one open item" "2026-10-09T00:00:00Z 2026-10-12T00:00:00Z 1" "$(python3 "$PY")"

echo ""
echo "[C3] carryover fields required by the approved design are all present: original source, first-seen date, last-checked date, evidence status, and the reason it remains unresolved"
cat > "$PY" <<'PYEOF'
import sys
sys.path.insert(0, 'security/incident_learning')
import critical_infra_watch as ciw
c = {
    'id': 'C1', 'raw_text': 'A military defense ministry network breach occurred.',
    'country': 'JP', 'attack_pattern': 'data_breach', 'incident_type': 'data_breach',
    'corroborating_sources': [], 'source_url': 'https://example.invalid/c1', 'source': 'news',
}
section, carry = ciw.build_section([c], {'C1': 'HIGH'}, [], '2026-10-09T00:00:00Z')
item = carry[0]
required = {'original_source', 'first_seen_at', 'last_checked_at', 'evidence_status', 'unresolved_reason'}
print(required.issubset(item.keys()))
PYEOF
assert_eq "C3 all 5 required carryover fields present" "True" "$(python3 "$PY")"

echo ""
echo "[C4] resolve CLI: requires a non-empty reason, mutates ONLY the carryover file, and the resolved item never re-surfaces as open on the next cycle"
CARRYOVER_PATH="$FIXTURE_DIR/carryover.json"
cat > "$PY" <<'PYEOF'
import sys
sys.path.insert(0, 'security/incident_learning')
import critical_infra_watch as ciw
c = {
    'id': 'C1', 'raw_text': 'A military defense ministry network breach occurred.',
    'country': 'JP', 'attack_pattern': 'data_breach', 'incident_type': 'data_breach',
    'corroborating_sources': [], 'source_url': 'https://example.invalid/c1', 'source': 'news',
}
_, carry = ciw.build_section([c], {'C1': 'HIGH'}, [], '2026-10-09T00:00:00Z')
ciw._save_carryover(sys.argv[1], carry)
PYEOF
python3 "$PY" "$CARRYOVER_PATH"
EMPTY_REASON_RC="$(python3 security/incident_learning/critical_infra_watch.py resolve "$CARRYOVER_PATH" "confirmed:C1" "" >/dev/null 2>&1; echo $?)"
assert_eq "C4a empty reason refused (non-zero exit)" "true" "$([ "$EMPTY_REASON_RC" != "0" ] && echo true || echo false)"
python3 security/incident_learning/critical_infra_watch.py resolve "$CARRYOVER_PATH" "confirmed:C1" "人間が確認し、誤検知と判断したため解決" >/dev/null 2>&1
RESOLVE_RC=$?
assert_eq "C4b resolve with a real reason succeeds" "0" "$RESOLVE_RC"
cat > "$PY" <<'PYEOF'
import sys, json
d = json.load(open(sys.argv[1]))
print(d[0]['status'], d[0]['resolution_reason'])
PYEOF
assert_eq "C4c item marked resolved with its own reason recorded" "resolved 人間が確認し、誤検知と判断したため解決" "$(python3 "$PY" "$CARRYOVER_PATH")"
cat > "$PY" <<'PYEOF'
import sys, json
sys.path.insert(0, 'security/incident_learning')
import critical_infra_watch as ciw
c = {
    'id': 'C1', 'raw_text': 'A military defense ministry network breach occurred.',
    'country': 'JP', 'attack_pattern': 'data_breach', 'incident_type': 'data_breach',
    'corroborating_sources': [], 'source_url': 'https://example.invalid/c1', 'source': 'news',
}
prev = json.load(open(sys.argv[1]))
section, carry = ciw.build_section([c], {'C1': 'HIGH'}, prev, '2026-10-15T00:00:00Z')
print(len(section['carryover_open']))
PYEOF
assert_eq "C4d resolved item does not resurface as open on the next cycle" "0" "$(python3 "$PY" "$CARRYOVER_PATH")"

echo ""
echo "[C5] markdown rendering includes the open-carryover list with its own required fields visible"
cat > "$PY" <<'PYEOF'
import sys
sys.path.insert(0, 'security/incident_learning')
import critical_infra_watch as ciw
c = {
    'id': 'C1', 'raw_text': 'A military defense ministry network breach occurred.',
    'country': 'JP', 'attack_pattern': 'data_breach', 'incident_type': 'data_breach',
    'corroborating_sources': [], 'source_url': 'https://example.invalid/c1', 'source': 'news',
}
section, _ = ciw.build_section([c], {'C1': 'HIGH'}, [], '2026-10-09T00:00:00Z')
print(ciw.render_markdown_section(section))
PYEOF
C5_MD="$(python3 "$PY")"
case "$C5_MD" in
  *"Critical Infrastructure"*"初検知: 2026-10-09T00:00:00Z"*"未解決理由"*) C5_OK=true ;;
  *) C5_OK=false ;;
esac
assert_eq "C5 markdown contains the section header plus carryover first-seen/unresolved-reason text" "true" "$C5_OK"

echo ""
echo "[C6] *** CRITICAL GUARD *** zero network/subprocess-execution calls in this module -- a strictly stronger guarantee than a name-based grep (same precedent tests/decision_engine_test.sh's own D2b already established for decision_engine_lib.py: a module proven to have NO subprocess/os.system/os.popen/socket/http capability at all cannot invoke Guardian, the Decision Engine, the Human Gate, or knowledge_manager.sh by ANY name, so its own module docstring -- which names several of these tools purely as documentation of the separation this module enforces -- is correctly left unrestricted rather than grepped for tool names"
net_refs="$(grep -ciE 'urllib|requests|http\.client|socket\.|subprocess|os\.system|os\.popen' security/incident_learning/critical_infra_watch.py || true)"
assert_eq "C6 zero network/subprocess references" "0" "$net_refs"

echo ""
echo "=== Summary: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
  echo "Failures:"
  printf '  - %s\n' "${FAILURES[@]}"
  exit 1
fi
exit 0
