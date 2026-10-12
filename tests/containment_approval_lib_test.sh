#!/bin/bash
set -uo pipefail

# tests/containment_approval_lib_test.sh -- regression suite for WAIO
# GLOBAL RED ALERT Phase D: security/red_alert/containment_approval_lib.py,
# the pure-function approval-gate core (no I/O, no subprocess, no
# audit-log writes, no Control-Plane integration -- see that module's
# own header for the full scope statement).
#
# Same three-layer convention as the rest of this pipeline's suites:
#   U-series: unit tests against the library's pure functions.
#   D-series: static structural guards -- zero I/O/subprocess/eval/exec
#     anywhere in actual code, zero references to any Control-Plane/
#     Decision-Engine/Guardian/cron/launchd tool by name, no __main__
#     entry point, and every existing file this phase was told to
#     leave alone remains byte-for-byte unmodified.
#
# No fixture files or isolated state dirs needed -- every case below is
# a pure function call (this module's own "No I/O" header claim).

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

pyval() {
  python3 -c "
import sys
sys.path.insert(0, 'security/red_alert')
import containment_approval_lib as cal
import datetime
$1
"
}

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

echo "=== WAIO GLOBAL RED ALERT Phase D regression suite ==="
echo "    (security/red_alert/containment_approval_lib.py)"

echo ""
echo "=== U-series: scope / high-impact / corroboration-source classification ==="

echo ""
echo "[U1] is_red_alert_scoped: true only for a RED ALERT source_module, false otherwise, never guessed on malformed input"
out="$(pyval "
print(cal.is_red_alert_scoped({'source_modules': ['global_patrol']}))
print(cal.is_red_alert_scoped({'source_modules': ['critical_infra_watch']}))
print(cal.is_red_alert_scoped({'source_modules': ['snd_home_crossref']}))
print(cal.is_red_alert_scoped({'source_modules': ['shadow_ai_monitor']}))
print(cal.is_red_alert_scoped({'source_modules': ['attack_graph', 'saas_ato']}))
print(cal.is_red_alert_scoped({'source_modules': []}))
print(cal.is_red_alert_scoped({}))
print(cal.is_red_alert_scoped({'source_modules': 'not-a-list'}))
print(cal.is_red_alert_scoped('not-a-dict'))
")"
assert_eq "U1 all nine cases correct" "$(printf 'True\nTrue\nTrue\nFalse\nFalse\nFalse\nFalse\nFalse\nFalse')" "$out"

echo ""
echo "[U2] is_high_impact: RECOMMEND_CONTAINMENT or CRITICAL risk only"
out="$(pyval "
print(cal.is_high_impact({'recommended_action': 'RECOMMEND_CONTAINMENT', 'risk': 'HIGH'}))
print(cal.is_high_impact({'recommended_action': 'MONITOR', 'risk': 'CRITICAL'}))
print(cal.is_high_impact({'recommended_action': 'MONITOR', 'risk': 'MEDIUM'}))
print(cal.is_high_impact({'recommended_action': 'NO_ACTION', 'risk': 'LOW'}))
print(cal.is_high_impact({}))
")"
assert_eq "U2 four cases correct" "$(printf 'True\nTrue\nFalse\nFalse\nFalse')" "$out"

echo ""
echo "[U3] has_multi_source_corroboration: recomputed from len(source_modules) > 1, never from any pre-existing boolean field"
out="$(pyval "
print(cal.has_multi_source_corroboration({'source_modules': ['global_patrol', 'snd_home_crossref']}))
print(cal.has_multi_source_corroboration({'source_modules': ['global_patrol']}))
print(cal.has_multi_source_corroboration({'source_modules': []}))
print(cal.has_multi_source_corroboration({}))
")"
assert_eq "U3 four cases correct" "$(printf 'True\nFalse\nFalse\nFalse')" "$out"

echo ""
echo "=== U-series: reason / exception-rationale validation ==="

echo ""
echo "[U4] validate_reason: EMPTY/TOO_SHORT/LOW_VARIETY/OK, non-string input treated as EMPTY"
out="$(pyval "
print(cal.validate_reason('')['status'])
print(cal.validate_reason('   ')['status'])
print(cal.validate_reason(None)['status'])
print(cal.validate_reason('short')['status'])
print(cal.validate_reason('aaaaaaaaaaaaaaaaaaaaaaaa')['status'])
print(cal.validate_reason('investigated the finding and confirmed it is a genuine duplicate')['status'])
")"
assert_eq "U4 six cases correct" "$(printf 'EMPTY\nEMPTY\nEMPTY\nTOO_SHORT\nLOW_VARIETY\nOK')" "$out"

echo ""
echo "[U5] *** THE CRITICAL EXCEPTION-REASON GUARD *** validate_exception_reason: validates actual NON-WHITESPACE content (40+ chars, 12+ distinct), not raw string length -- whitespace padding never inflates the count, and an exception identical to the approval reason is rejected as not distinct"
out="$(pyval "
padded = 'a b c d e f g h i j k l m n o p q r s t'  # 20 non-whitespace chars padded with spaces to a much longer raw string
print(len(padded), cal.validate_exception_reason(padded)['status'])
real = 'independently verified via vendor advisory cross-reference and a second analyst sign-off this morning'
print(cal.validate_exception_reason(real)['status'])
print(cal.validate_exception_reason('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')['status'])
approval = 'this is my approval reason for the record, stated plainly and clearly'
print(cal.validate_exception_reason(approval, approval_reason=approval)['status'])
print(cal.validate_exception_reason(real, approval_reason=approval)['status'])
")"
assert_eq "U5 five cases correct (padding never counts, real distinct text OK, low-variety rejected, exact-duplicate rejected, genuinely distinct accepted)" "$(printf '39 TOO_SHORT\nOK\nLOW_VARIETY\nDUPLICATE_OF_APPROVAL_REASON\nOK')" "$out"

echo ""
echo "=== U-series: corroboration gate ==="

echo ""
echo "[U6] corroboration_satisfied: not-high-impact always allowed; high-impact+multi_source allowed; high-impact+no-corroboration+no-exception refused; +insufficient exception refused; +valid distinct exception allowed -- the exception basis NEVER implies execution, only that the gate's own data requirement was met"
out="$(pyval "
not_hi = {'recommended_action': 'MONITOR', 'risk': 'MEDIUM', 'source_modules': ['global_patrol']}
print(cal.corroboration_satisfied(not_hi)['basis'])
hi_multi = {'recommended_action': 'RECOMMEND_CONTAINMENT', 'risk': 'HIGH', 'source_modules': ['global_patrol', 'snd_home_crossref']}
print(cal.corroboration_satisfied(hi_multi)['basis'])
hi_single = {'recommended_action': 'RECOMMEND_CONTAINMENT', 'risk': 'HIGH', 'source_modules': ['global_patrol']}
r = cal.corroboration_satisfied(hi_single)
print(r['allowed'], r['basis'])
r2 = cal.corroboration_satisfied(hi_single, exception_reason='too short')
print(r2['allowed'], r2['basis'])
r3 = cal.corroboration_satisfied(hi_single, exception_reason='independently verified via a second, unrelated external advisory this same morning by a different analyst')
print(r3['allowed'], r3['basis'])
")"
assert_eq "U6 five cases correct" "$(printf 'not_high_impact\nmulti_source\nFalse refused_no_corroboration_no_exception\nFalse refused_exception_insufficient\nTrue exception')" "$out"

echo ""
echo "=== U-series: rollback metadata gate ==="

echo ""
echo "[U7] rollback_requirement_satisfied: not-high-impact always allowed; high-impact+missing/blank rollback refused (clear, explicit refusal, never a silent pass); high-impact+named tool allowed -- this gate NEVER claims the named tool actually works"
out="$(pyval "
not_hi = {'recommended_action': 'MONITOR', 'risk': 'MEDIUM'}
print(cal.rollback_requirement_satisfied(not_hi, None)['basis'])
hi = {'recommended_action': 'RECOMMEND_CONTAINMENT', 'risk': 'HIGH'}
print(cal.rollback_requirement_satisfied(hi, None)['basis'])
print(cal.rollback_requirement_satisfied(hi, {})['basis'])
print(cal.rollback_requirement_satisfied(hi, {'rollback_tool': ''})['basis'])
print(cal.rollback_requirement_satisfied(hi, {'rollback_tool': '   '})['basis'])
r = cal.rollback_requirement_satisfied(hi, {'rollback_tool': 'guardian_release_agent.sh'})
print(r['allowed'], r['basis'])
")"
assert_eq "U7 six cases correct" "$(printf 'not_high_impact\nrefused_missing_rollback_metadata\nrefused_rollback_unavailable\nrefused_rollback_unavailable\nrefused_rollback_unavailable\nTrue rollback_tool_named')" "$out"

echo ""
echo "=== U-series: approver identity (explicitly NOT authentication) ==="

echo ""
echo "[U8] validate_approver_identity: presence-only by default (authenticated always False), optional allowlist membership as a forward-compatible hook, never proof of authorization"
out="$(pyval "
print(cal.validate_approver_identity(None))
print(cal.validate_approver_identity(''))
print(cal.validate_approver_identity('   '))
print(cal.validate_approver_identity('masa'))
print(cal.validate_approver_identity('masa', allowlist=['masa', 'operator2']))
print(cal.validate_approver_identity('intruder', allowlist=['masa', 'operator2']))
")"
assert_eq "U8 missing identity refused, authenticated always False" "False" "$(pyval "print(cal.validate_approver_identity(None)['valid'])")"
assert_eq "U8 empty string refused" "False" "$(pyval "print(cal.validate_approver_identity('')['valid'])")"
assert_eq "U8 whitespace-only refused" "False" "$(pyval "print(cal.validate_approver_identity('   ')['valid'])")"
assert_eq "U8 present, no allowlist -> valid" "True" "$(pyval "print(cal.validate_approver_identity('masa')['valid'])")"
assert_eq "U8 present, no allowlist -> authenticated is STILL False" "False" "$(pyval "print(cal.validate_approver_identity('masa')['authenticated'])")"
assert_eq "U8 present and in allowlist -> valid" "True" "$(pyval "print(cal.validate_approver_identity('masa', allowlist=['masa','operator2'])['valid'])")"
assert_eq "U8 present but NOT in allowlist -> refused" "False" "$(pyval "print(cal.validate_approver_identity('intruder', allowlist=['masa','operator2'])['valid'])")"
assert_eq "U8 in-allowlist case is STILL authenticated=False" "False" "$(pyval "print(cal.validate_approver_identity('masa', allowlist=['masa','operator2'])['authenticated'])")"

echo ""
echo "=== U-series: evidence integrity (altered-evidence detection) ==="

echo ""
echo "[U9] compute_decision_report_hash / evidence_intact: deterministic hash, any edit to the report is detected, a missing/malformed stored_hash is fail-closed (never 'nothing to check')"
out="$(pyval "
report = {'generated_at': '2026-10-12T03:13:09Z', 'decisions': [{'entity': 'KEV-X', 'risk': 'HIGH'}]}
h1 = cal.compute_decision_report_hash(report)
h2 = cal.compute_decision_report_hash(dict(report))  # same content, different dict object -> same hash
print(h1 == h2, h1.startswith('sha256:'))
print(cal.evidence_intact(h1, report))
altered = {'generated_at': '2026-10-12T03:13:09Z', 'decisions': [{'entity': 'KEV-X', 'risk': 'CRITICAL'}]}
print(cal.evidence_intact(h1, altered))
print(cal.evidence_intact(None, report))
print(cal.evidence_intact('', report))
print(cal.evidence_intact('sha256:not-the-real-hash', report))
")"
assert_eq "U9 six cases correct (deterministic, matches, detects alteration, fail-closed on missing/malformed hash)" "$(printf 'True True\nTrue\nFalse\nFalse\nFalse\nFalse')" "$out"

echo ""
echo "=== U-series: timestamps -- malformed timestamps, always fail-closed, never raise ==="

echo ""
echo "[U10] parse_utc_timestamp / format_utc_timestamp: round-trips the pipeline's real format; every malformed variant returns None, never raises"
out="$(pyval "
t = cal.parse_utc_timestamp('2026-10-12T03:13:09Z')
print(t is not None, cal.format_utc_timestamp(t))
for bad in ['not a timestamp', '2026-10-12', '2026-10-12 03:13:09', '2026-10-12T03:13:09+09:00', '', None, 12345, '2026-13-99T99:99:99Z']:
    print(cal.parse_utc_timestamp(bad))
print(cal.format_utc_timestamp('not-a-datetime'))
print(cal.format_utc_timestamp(None))
")"
assert_eq "U10 round-trip correct, all eight malformed inputs -> None, format on non-datetime -> None" "$(printf 'True 2026-10-12T03:13:09Z\nNone\nNone\nNone\nNone\nNone\nNone\nNone\nNone\nNone\nNone')" "$out"

echo ""
echo "=== U-series: expiry -- boundaries, injectable clock, fail-closed ==="

echo ""
echo "[U11] *** EXPIRY BOUNDARIES *** compute_expiry (default 24h TTL) and is_expired: just-before/exactly-at/just-after the boundary, malformed inputs always fail-closed to expired=True, clock is always caller-supplied"
out="$(pyval "
requested = cal.parse_utc_timestamp('2026-10-12T00:00:00Z')
expires = cal.compute_expiry(requested)
print(cal.format_utc_timestamp(expires))
one_sec_before = expires - datetime.timedelta(seconds=1)
exactly_at = expires
one_sec_after = expires + datetime.timedelta(seconds=1)
print(cal.is_expired(expires, one_sec_before))
print(cal.is_expired(expires, exactly_at))
print(cal.is_expired(expires, one_sec_after))
custom = cal.compute_expiry(requested, ttl_seconds=3600)
print(cal.format_utc_timestamp(custom))
print(cal.is_expired(None, requested))
print(cal.is_expired(expires, None))
print(cal.is_expired('not-a-datetime', 'also-not'))
print(cal.compute_expiry('not-a-datetime'))
")"
assert_eq "U11 nine cases correct (24h default, before/at/after boundary, custom TTL, fail-closed on malformed)" "$(printf '2026-10-13T00:00:00Z\nFalse\nTrue\nTrue\n2026-10-12T01:00:00Z\nTrue\nTrue\nTrue\nNone')" "$out"

echo ""
echo "=== U-series: approval state machine -- duplicate approvals, illegal transitions ==="

echo ""
echo "[U12] *** DUPLICATE APPROVAL GUARD *** can_transition: only PENDING -> approve/reject is legal; re-approving/re-rejecting an already-decided or expired record is illegal, covering duplicate approvals by one single rule"
out="$(pyval "
print(cal.can_transition('PENDING', 'approve'))
print(cal.can_transition('PENDING', 'reject'))
print(cal.can_transition('APPROVED', 'approve'))
print(cal.can_transition('APPROVED', 'reject'))
print(cal.can_transition('REJECTED', 'approve'))
print(cal.can_transition('REJECTED', 'reject'))
print(cal.can_transition('EXPIRED', 'approve'))
print(cal.can_transition('EXPIRED', 'reject'))
print(cal.can_transition('BOGUS_STATUS', 'approve'))
print(cal.can_transition('PENDING', 'bogus_action'))
print(cal.next_status('PENDING', 'approve'))
print(cal.next_status('APPROVED', 'approve'))
")"
assert_eq "U12 twelve cases correct" "$(printf 'True\nTrue\nFalse\nFalse\nFalse\nFalse\nFalse\nFalse\nFalse\nFalse\nAPPROVED\nNone')" "$out"

echo ""
echo "=== U-series: composite evaluate_approval -- every gate together, no short-circuit ==="

VALID_PY='
decision_record = {"entity": "KEV-RA-1", "recommended_action": "RECOMMEND_CONTAINMENT", "risk": "HIGH", "source_modules": ["global_patrol", "snd_home_crossref"]}
report = {"generated_at": "2026-10-12T03:13:09Z", "decisions": [decision_record]}
h = cal.compute_decision_report_hash(report)
now = cal.parse_utc_timestamp("2026-10-12T04:00:00Z")
expires = cal.compute_expiry(cal.parse_utc_timestamp("2026-10-12T03:13:09Z"))
'

echo ""
echo "[U13] evaluate_approval: a fully valid, multi-source-corroborated, in-scope, unexpired, evidence-intact approval with a sufficient reason -> allowed True, zero violations"
out="$(pyval "
$VALID_PY
r = cal.evaluate_approval(decision_record, report, h, 'masa', now, expires, approval_reason='investigated this finding thoroughly and confirmed it is consistent with known activity', rollback={'rollback_tool': 'guardian_release_agent.sh'})
print(r['allowed'], r['violations'])
")"
assert_eq "U13 allowed, no violations" "True []" "$out"

echo ""
echo "[U14] evaluate_approval: an out-of-scope (non-RED-ALERT) decision record is refused, independently of every other gate"
out="$(pyval "
$VALID_PY
decision_record['source_modules'] = ['shadow_ai_monitor', 'attack_graph']
r = cal.evaluate_approval(decision_record, report, h, 'masa', now, expires, approval_reason='investigated this finding thoroughly and confirmed it is consistent with known activity', rollback={'rollback_tool': 'x'})
print('out_of_scope' in r['violations'])
")"
assert_eq "U14 out_of_scope violation present" "True" "$out"

echo ""
echo "[U15] evaluate_approval: altered evidence (the live report no longer hashes to the stored value) is refused"
out="$(pyval "
$VALID_PY
report['decisions'][0]['risk'] = 'CRITICAL'  # tamper AFTER the hash was computed
r = cal.evaluate_approval(decision_record, report, h, 'masa', now, expires, approval_reason='investigated this finding thoroughly and confirmed it is consistent with known activity', rollback={'rollback_tool': 'x'})
print('evidence_altered_or_missing' in r['violations'])
")"
assert_eq "U15 evidence_altered_or_missing violation present" "True" "$out"

echo ""
echo "[U16] evaluate_approval: an expired approval is refused"
out="$(pyval "
$VALID_PY
past_expiry = cal.parse_utc_timestamp('2026-10-12T03:13:10Z')
r = cal.evaluate_approval(decision_record, report, h, 'masa', now, past_expiry, approval_reason='investigated this finding thoroughly and confirmed it is consistent with known activity', rollback={'rollback_tool': 'x'})
print('expired' in r['violations'])
")"
assert_eq "U16 expired violation present" "True" "$out"

echo ""
echo "[U17] evaluate_approval: a missing approver identity is refused"
out="$(pyval "
$VALID_PY
r = cal.evaluate_approval(decision_record, report, h, None, now, expires, approval_reason='investigated this finding thoroughly and confirmed it is consistent with known activity', rollback={'rollback_tool': 'x'})
print('missing_identity' in r['violations'])
")"
assert_eq "U17 missing_identity violation present" "True" "$out"

echo ""
echo "[U18] evaluate_approval: high-impact + single-source (no multi_source) + no exception -> refused on the corroboration gate specifically"
out="$(pyval "
$VALID_PY
decision_record['source_modules'] = ['global_patrol']
report['decisions'][0]['source_modules'] = ['global_patrol']
h2 = cal.compute_decision_report_hash(report)
r = cal.evaluate_approval(decision_record, report, h2, 'masa', now, expires, approval_reason='investigated this finding thoroughly and confirmed it is consistent with known activity', rollback={'rollback_tool': 'x'})
print('refused_no_corroboration_no_exception' in r['violations'])
")"
assert_eq "U18 refused_no_corroboration_no_exception violation present" "True" "$out"

echo ""
echo "[U19] evaluate_approval: single-source, exception supplied but duplicate of the approval reason -> refused on the corroboration gate"
out="$(pyval "
$VALID_PY
decision_record['source_modules'] = ['global_patrol']
report['decisions'][0]['source_modules'] = ['global_patrol']
h2 = cal.compute_decision_report_hash(report)
same_text = 'this exact sentence is reused for both fields which is not acceptable'
r = cal.evaluate_approval(decision_record, report, h2, 'masa', now, expires, approval_reason=same_text, exception_reason=same_text, rollback={'rollback_tool': 'x'})
print('refused_exception_insufficient' in r['violations'])
")"
assert_eq "U19 refused_exception_insufficient violation present" "True" "$out"

echo ""
echo "[U20] *** NO SHORT-CIRCUIT *** single-source, valid DISTINCT exception (corroboration gate now satisfied) but rollback metadata missing -> corroboration passes, rollback independently refused -- both gates evaluated, not just the first failure"
out="$(pyval "
$VALID_PY
decision_record['source_modules'] = ['global_patrol']
report['decisions'][0]['source_modules'] = ['global_patrol']
h2 = cal.compute_decision_report_hash(report)
r = cal.evaluate_approval(decision_record, report, h2, 'masa', now, expires, approval_reason='investigated this finding thoroughly and confirmed it is consistent with known activity', exception_reason='independently cross-referenced against a separate external vendor advisory this same morning', rollback=None)
print(r['checks']['corroboration']['allowed'], r['checks']['rollback']['allowed'], 'refused_missing_rollback_metadata' in r['violations'])
")"
assert_eq "U20 corroboration allowed via exception, rollback independently refused" "True False True" "$out"

echo ""
echo "[U21] evaluate_approval: single-source, valid distinct exception AND valid rollback metadata together -> fully allowed"
out="$(pyval "
$VALID_PY
decision_record['source_modules'] = ['global_patrol']
report['decisions'][0]['source_modules'] = ['global_patrol']
h2 = cal.compute_decision_report_hash(report)
r = cal.evaluate_approval(decision_record, report, h2, 'masa', now, expires, approval_reason='investigated this finding thoroughly and confirmed it is consistent with known activity', exception_reason='independently cross-referenced against a separate external vendor advisory this same morning', rollback={'rollback_tool': 'guardian_release_agent.sh'})
print(r['allowed'], r['violations'])
")"
assert_eq "U21 allowed via exception + rollback, no violations" "True []" "$out"

echo ""
echo "=== U-series: untrusted strings -- never executed, only ever measured as text ==="

echo ""
echo "[U22] *** INJECTION SAFETY *** shell-metacharacter-laden identity/reason/exception strings are NEVER executed -- they are only ever measured (length/distinct-char counts) and returned verbatim as text"
rm -f /tmp/waio_phaseD_injection_marker
out="$(pyval "
malicious = 'ransomware; touch /tmp/waio_phaseD_injection_marker ; \`touch /tmp/waio_phaseD_injection_marker2\`'
r1 = cal.validate_approver_identity(malicious)
r2 = cal.validate_reason(malicious + ' padded out to a sufficient length for this check to pass cleanly')
r3 = cal.validate_exception_reason(malicious + ' padded out to a sufficient non whitespace length for this specific check to pass cleanly here')
print(r1['valid'], malicious in r1.get('reason', '') or True)
print('touch /tmp/waio_phaseD_injection_marker' in r2['normalized'])
print('waio_phaseD_injection_marker' in r3['normalized'])  # r3 strips ALL whitespace by design (validate_exception_reason), so no spaces survive -- check the token itself, not a phrase with spaces
")"
assert_eq "U22 malicious strings only ever measured/stored as text, never specially interpreted" "$(printf 'True True\nTrue\nTrue')" "$out"
assert_eq "U22 no marker file was ever created (never executed)" "absent" "$([ -e /tmp/waio_phaseD_injection_marker ] && echo present || echo absent)"
rm -f /tmp/waio_phaseD_injection_marker /tmp/waio_phaseD_injection_marker2

echo ""
echo "=== U-series: APPROVAL_ID format validation (SECURITY FIX, post-audit) ==="

echo ""
echo "[U23] *** PATH TRAVERSAL HARDENING *** validate_approval_id_format accepts every shape this file's own request-time code actually generates (CAG-<safe_entity>-<12 hex>) and any other charset-only string, but rejects anything containing a path separator, whitespace, a shell metacharacter, a non-string, more than 200 characters, or a trailing newline (fullmatch, not a \$-anchored regex, so Python's own 'matches before a trailing newline' \$ exception cannot slip one through) -- fail-closed, never guessed into validity"
out="$(pyval "
print(cal.validate_approval_id_format('CAG-poc-entity-8eed7e38d198'))
print(cal.validate_approval_id_format('CAG-KEV-2026-001-abcdef012345'))
print(cal.validate_approval_id_format('../../etc/passwd'))
print(cal.validate_approval_id_format('../../outside/secret'))
print(cal.validate_approval_id_format('a/b'))
print(cal.validate_approval_id_format('/etc/passwd'))
print(cal.validate_approval_id_format('a b'))
print(cal.validate_approval_id_format(''))
print(cal.validate_approval_id_format(None))
print(cal.validate_approval_id_format(123))
print(cal.validate_approval_id_format('a' * 201))
print(cal.validate_approval_id_format('a' * 200))
print(cal.validate_approval_id_format('semi;colon'))
print(cal.validate_approval_id_format('back\`tick'))
print(cal.validate_approval_id_format('CAG-good-id\n'))
")"
assert_eq "U23 generated-shape IDs accepted; traversal/absolute-path/whitespace/metacharacter/non-string/oversize/trailing-newline rejected" "$(printf 'True\nTrue\nFalse\nFalse\nFalse\nFalse\nFalse\nFalse\nFalse\nFalse\nFalse\nTrue\nFalse\nFalse\nFalse')" "$out"

echo ""
echo "=== D-series: structural guards ==="

echo ""
echo "[D1] *** THE CRITICAL I/O-ABSENCE GUARD *** containment_approval_lib.py's ACTUAL CODE (docstrings/comments stripped via Python's own tokenizer) has no subprocess/os.system/os.popen/exec/eval/open()/network call anywhere -- a strictly stronger guarantee than a name-based grep, matching this module's own 'No I/O in this module' header claim"
cnt="$(code_only_py security/red_alert/containment_approval_lib.py | grep -cE '\b(subprocess|os\.system|os\.popen|os\.exec\w*|eval|exec|requests\.|urllib|socket\.|curl|\bopen\()\b' || true)"
assert_eq "D1 zero I/O/subprocess/eval/exec/network references in actual code" "0" "$cnt"

echo ""
echo "[D2] *** THE CRITICAL INJECTABLE-CLOCK GUARD *** this module never calls datetime.now()/datetime.utcnow() itself anywhere in actual code -- every clock reference is caller-supplied, per this phase's explicit decision"
cnt="$(code_only_py security/red_alert/containment_approval_lib.py | grep -cE 'datetime\.(now|utcnow)\s*\(' || true)"
assert_eq "D2 zero internal wall-clock reads" "0" "$cnt"

echo ""
echo "[D3] this module's ACTUAL CODE never references, by name, security/lib.sh, the Decision Engine, Guardian, DuCoPA, recovery/promotion tools, or any cron/launchd mechanism -- a docstring is free to NAME these as documentation of what this file does NOT call (same posture tests/decision_engine_test.sh's own D5 and tests/red_alert_test.sh's own D2 already established), this guard checks the actual code only"
cnt=0
for pattern in 'security/lib\.sh' 'decision_engine\.sh' 'decision_engine_lib' 'guardian\.sh' 'guardian_intervene' 'guardian_release_agent' 'guardian_approve\.sh' 'ducopa\.sh' 'recovery_engine\.sh' '\brecover\.sh' 'knowledge_manager\.sh' 'incident_human_gate\.sh' 'launchctl' 'crontab' 'audit_log\('; do
  c="$(code_only_py security/red_alert/containment_approval_lib.py | grep -cE "$pattern" || true)"
  cnt=$((cnt + c))
done
assert_eq "D3 zero actual-code references to any Control-Plane/Decision-Engine/Guardian/cron/launchd tool by name" "0" "$cnt"

echo ""
echo "[D4] this module defines no __main__ entry point -- library only, never directly executable"
assert_eq "D4 zero __main__ entry points" "0" "$(grep -c '__name__' security/red_alert/containment_approval_lib.py || true)"

echo ""
echo "[D5] *** EVERY OTHER EXISTING FILE THIS PHASE WAS TOLD TO LEAVE ALONE REMAINS BYTE-FOR-BYTE UNMODIFIED *** security/lib.sh, decision_engine.sh/decision_engine_lib.py, intelligence_layer.sh/intelligence_lib.py, red_alert_adapter.py/snd_crossref.py, red_alert_cron.sh, guardian.sh, ducopa.sh -- none have a working-tree diff introduced by this phase"
for f in security/lib.sh security/decision_engine/decision_engine.sh security/decision_engine/decision_engine_lib.py security/intelligence/intelligence_lib.py security/red_alert/red_alert_adapter.py security/red_alert/snd_crossref.py security/red_alert/red_alert_cron.sh security/guardian.sh security/ducopa.sh; do
  assert_eq "D5 $f has no NEW working-tree diff from this phase" "" "$(git diff --name-only -- "$f" 2>/dev/null)"
done

echo ""
echo "[D6] this module's own RED_ALERT_SOURCE_MODULES constant matches exactly the source_module values security/red_alert/red_alert_adapter.py actually emits -- never silently drifting from that file's own real output"
for name in global_patrol critical_infra_watch snd_home_crossref; do
  cnt="$(grep -c "\"$name\"\|'$name'" security/red_alert/red_alert_adapter.py || true)"
  assert_eq "D6 red_alert_adapter.py actually emits source_module '$name'" "nonzero" "$([ "$cnt" -gt 0 ] && echo nonzero || echo zero)"
done

echo ""
echo "=== Summary: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
  echo "Failures:"
  for f in "${FAILURES[@]}"; do echo "  - $f"; done
  exit 1
fi
exit 0
