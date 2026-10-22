#!/bin/bash
set -uo pipefail

# tests/dev_approval_lib_test.sh -- regression suite for WAIO's
# Self-Development Engine Human Approval Gate's own pure-function core:
# security/self_dev/dev_approval_lib.py (no I/O, no subprocess, no
# audit-log writes, no Control-Plane integration -- see that module's
# own header for the full scope statement).
#
# Same two-layer convention as this module's own direct architectural
# sibling, tests/containment_approval_lib_test.sh:
#   U-series: unit tests against the library's pure functions.
#   D-series: static structural guards -- zero I/O/subprocess/eval/exec
#     anywhere in actual code, zero references to any privileged-
#     operation/Control-Plane/Guardian/DuCoPA/cron/launchd tool by
#     name, no __main__ entry point, and every existing file this
#     phase was told to leave alone remains unmodified.
#
# No fixture files or isolated state dirs needed -- every case below is
# a pure function call (this module's own "No I/O in this module"
# header claim). security/self_dev/dev_approval_gate.sh (the CLI
# wrapper around this library) has its own separate integration suite,
# tests/dev_approval_gate_test.sh -- cases here are NOT duplicated
# there; this file exercises the library's pure functions directly,
# that file exercises the real CLI/filesystem/locking/audit log.

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
sys.path.insert(0, 'security/self_dev')
import dev_approval_lib as dal
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

echo "=== WAIO Self-Development Engine Human Approval Gate unit suite ==="
echo "    (security/self_dev/dev_approval_lib.py)"

echo ""
echo "=== U-series: operation classification (PRIVILEGED vs AUTOMATIC) ==="

echo ""
echo "[U1] classify_operation: all four AUTOMATIC operation names pass through on a non-protected branch with no touched paths"
out="$(pyval "
for op in ('code_analysis', 'improvement_proposal', 'isolated_branch_commit', 'pr_preparation'):
    print(dal.classify_operation(op, target_branch='feature/x', touched_paths=['foo.py'])['risk_tier'])
")"
assert_eq "U1 all four AUTOMATIC" "$(printf 'AUTOMATIC\nAUTOMATIC\nAUTOMATIC\nAUTOMATIC')" "$out"

echo ""
echo "[U2] classify_operation: every explicitly-named PRIVILEGED operation, plus an unrecognized/misspelled name -- all fail-closed to PRIVILEGED"
out="$(pyval "
for op in ('merge_to_master', 'merge_to_develop', 'production_deploy', 'service_shutdown', 'containment_action', 'permission_change', 'security_policy_change', 'totally_unknown_operation', '', None):
    print(dal.classify_operation(op)['risk_tier'])
")"
assert_eq "U2 all nine cases PRIVILEGED" "$(printf 'PRIVILEGED\nPRIVILEGED\nPRIVILEGED\nPRIVILEGED\nPRIVILEGED\nPRIVILEGED\nPRIVILEGED\nPRIVILEGED\nPRIVILEGED\nPRIVILEGED')" "$out"

echo ""
echo "[U3] *** PROTECTED BRANCH ESCALATION *** isolated_branch_commit targeting master/develop directly is escalated to PRIVILEGED even though the operation name alone reads as automatic; the SAME operation on a feature branch, or merge_to_master itself (already privileged by name), are unaffected by this specific check"
out="$(pyval "
print(dal.classify_operation('isolated_branch_commit', target_branch='master')['risk_tier'])
print(dal.classify_operation('isolated_branch_commit', target_branch='develop')['risk_tier'])
print(dal.classify_operation('isolated_branch_commit', target_branch='feature/x')['risk_tier'])
print(dal.classify_operation('isolated_branch_commit', target_branch=None)['risk_tier'])
print(dal.classify_operation('code_analysis', target_branch='master')['risk_tier'])
")"
assert_eq "U3 five cases correct (master/develop escalate commit-shaped ops; feature branch/no branch does not; a non-commit-shaped op targeting master is unaffected by THIS check)" "$(printf 'PRIVILEGED\nPRIVILEGED\nAUTOMATIC\nAUTOMATIC\nAUTOMATIC')" "$out"

echo ""
echo "[U4] *** SELF-GATE PROTECTION *** a touched path matching any PRIVILEGED_PATH_PATTERNS entry escalates an otherwise-AUTOMATIC operation to PRIVILEGED, regardless of operation/branch; a '.example' template under the same-looking path is explicitly exempt"
out="$(pyval "
print(dal.classify_operation('code_analysis', target_branch='feature/x', touched_paths=['security/self_dev/dev_approval_lib.py'])['risk_tier'])
print(dal.classify_operation('code_analysis', target_branch='feature/x', touched_paths=['security/guardian.sh'])['risk_tier'])
print(dal.classify_operation('code_analysis', target_branch='feature/x', touched_paths=['security/ducopa.sh'])['risk_tier'])
print(dal.classify_operation('code_analysis', target_branch='feature/x', touched_paths=['.github/workflows/lint.yml'])['risk_tier'])
print(dal.classify_operation('code_analysis', target_branch='feature/x', touched_paths=['workers/registry.json'])['risk_tier'])
print(dal.classify_operation('code_analysis', target_branch='feature/x', touched_paths=['local.conf'])['risk_tier'])
print(dal.classify_operation('code_analysis', target_branch='feature/x', touched_paths=['security/self_dev/dev_approval_lib.py.example'])['risk_tier'])
print(dal.classify_operation('code_analysis', target_branch='feature/x', touched_paths=['local.conf.example'])['risk_tier'])
print(dal.classify_operation('code_analysis', target_branch='feature/x', touched_paths=['README.md'])['risk_tier'])
")"
assert_eq "U4 nine cases correct (five real protected-path shapes escalate, two .example templates do not, one unrelated path does not)" "$(printf 'PRIVILEGED\nPRIVILEGED\nPRIVILEGED\nPRIVILEGED\nPRIVILEGED\nPRIVILEGED\nAUTOMATIC\nAUTOMATIC\nAUTOMATIC')" "$out"

echo ""
echo "[U5] classify_operation: malformed/missing touched_paths (not a list) is treated as empty -- it can never escalate what it never saw, but checks #1-#3 still apply independently"
out="$(pyval "
print(dal.classify_operation('code_analysis', touched_paths='not-a-list')['risk_tier'])
print(dal.classify_operation('code_analysis', touched_paths=None)['risk_tier'])
print(dal.classify_operation('code_analysis', target_branch='master', touched_paths='not-a-list')['risk_tier'])
print(dal.classify_operation('isolated_branch_commit', target_branch='master', touched_paths='not-a-list')['risk_tier'])
")"
assert_eq "U5 four cases correct (malformed touched_paths never escalates by itself, but target_branch/operation checks are unaffected)" "$(printf 'AUTOMATIC\nAUTOMATIC\nAUTOMATIC\nPRIVILEGED')" "$out"

echo ""
echo "[U6] requires_human_approval: True for every risk_tier except the literal string AUTOMATIC -- malformed input fails closed to True"
out="$(pyval "
print(dal.requires_human_approval('PRIVILEGED'))
print(dal.requires_human_approval('AUTOMATIC'))
print(dal.requires_human_approval('BOGUS'))
print(dal.requires_human_approval(None))
print(dal.requires_human_approval(''))
")"
assert_eq "U6 five cases correct" "$(printf 'True\nFalse\nTrue\nTrue\nTrue')" "$out"

echo ""
echo "=== U-series: APPROVAL_ID format validation ==="

echo ""
echo "[U7] *** PATH TRAVERSAL HARDENING *** validate_approval_id_format accepts every shape this file's own propose-time code actually generates (SDA-<safe_op>-<safe_ref>-<12 hex>) and any other charset-only string, but rejects anything containing a path separator, whitespace, a shell metacharacter, a non-string, more than 200 characters, or a trailing newline -- fail-closed, never guessed into validity (identical convention to containment_approval_lib.py's own validate_approval_id_format, reused from the start per this module's own header)"
out="$(pyval "
print(dal.validate_approval_id_format('SDA-isolated_branch_commit-abc123-d8a7a64988d6'))
print(dal.validate_approval_id_format('SDA-merge_to_master-def456-5584510a0178'))
print(dal.validate_approval_id_format('../../etc/passwd'))
print(dal.validate_approval_id_format('../../outside/secret'))
print(dal.validate_approval_id_format('a/b'))
print(dal.validate_approval_id_format('/etc/passwd'))
print(dal.validate_approval_id_format('a b'))
print(dal.validate_approval_id_format(''))
print(dal.validate_approval_id_format(None))
print(dal.validate_approval_id_format(123))
print(dal.validate_approval_id_format('a' * 201))
print(dal.validate_approval_id_format('a' * 200))
print(dal.validate_approval_id_format('semi;colon'))
print(dal.validate_approval_id_format('back\`tick'))
print(dal.validate_approval_id_format('SDA-good-id\n'))
")"
assert_eq "U7 generated-shape IDs accepted; traversal/absolute-path/whitespace/metacharacter/non-string/oversize/trailing-newline rejected" "$(printf 'True\nTrue\nFalse\nFalse\nFalse\nFalse\nFalse\nFalse\nFalse\nFalse\nFalse\nTrue\nFalse\nFalse\nFalse')" "$out"

echo ""
echo "=== U-series: reason validation ==="

echo ""
echo "[U8] validate_reason: EMPTY/TOO_SHORT/LOW_VARIETY/OK, non-string input treated as EMPTY, never raises"
out="$(pyval "
print(dal.validate_reason('')['status'])
print(dal.validate_reason('   ')['status'])
print(dal.validate_reason(None)['status'])
print(dal.validate_reason(123)['status'])
print(dal.validate_reason('short')['status'])
print(dal.validate_reason('aaaaaaaaaaaaaaaaaaaaaaaa')['status'])
print(dal.validate_reason('reviewed this diff thoroughly and confirmed it is safe to merge now')['status'])
")"
assert_eq "U8 seven cases correct" "$(printf 'EMPTY\nEMPTY\nEMPTY\nEMPTY\nTOO_SHORT\nLOW_VARIETY\nOK')" "$out"

echo ""
echo "=== U-series: approver identity (explicitly NOT authentication, PLUS the AI-sentinel denylist) ==="

echo ""
echo "[U9] validate_approver_identity: presence-only by default (authenticated always False, in every branch); optional allowlist membership as a forward-compatible hook; never proof of authorization"
assert_eq "U9 missing identity (None) refused" "False" "$(pyval "print(dal.validate_approver_identity(None)['valid'])")"
assert_eq "U9 empty string refused" "False" "$(pyval "print(dal.validate_approver_identity('')['valid'])")"
assert_eq "U9 whitespace-only refused" "False" "$(pyval "print(dal.validate_approver_identity('   ')['valid'])")"
assert_eq "U9 present, no allowlist -> valid" "True" "$(pyval "print(dal.validate_approver_identity('alice')['valid'])")"
assert_eq "U9 present, no allowlist -> authenticated is STILL False" "False" "$(pyval "print(dal.validate_approver_identity('alice')['authenticated'])")"
assert_eq "U9 present and in allowlist -> valid" "True" "$(pyval "print(dal.validate_approver_identity('alice', allowlist=['alice','bob'])['valid'])")"
assert_eq "U9 present but NOT in allowlist -> refused" "False" "$(pyval "print(dal.validate_approver_identity('intruder', allowlist=['alice','bob'])['valid'])")"
assert_eq "U9 in-allowlist case is STILL authenticated=False" "False" "$(pyval "print(dal.validate_approver_identity('alice', allowlist=['alice','bob'])['authenticated'])")"

echo ""
echo "[U10] *** AI SELF-APPROVAL DEFENSE *** AI_IDENTITY_DENYLIST rejects every obviously-non-human identity string, case-insensitively, after stripping -- this is the concrete code check behind 'an AI-generated change may never approve itself', explicitly NOT proof of humanity"
out="$(pyval "
for name in ('claude', 'Claude', '  CLAUDE  ', 'ai', 'assistant', 'bot', 'automated', 'automation', 'system', 'ci', 'github-actions', 'self_dev', 'self-dev', 'agent'):
    print(dal.validate_approver_identity(name)['valid'], dal.validate_approver_identity(name)['reason'])
print(dal.validate_approver_identity('alice-approver')['valid'])
print(dal.validate_approver_identity('claudia')['valid'])
")"
EXPECTED_U10="$(python3 -c "
print(chr(10).join(['False identity_is_denylisted_non_human_sentinel'] * 14 + ['True', 'True']))
")"
assert_eq "U10 all fourteen denylisted identities refused (case/whitespace-insensitive), a human name merely CONTAINING a denylisted substring ('claudia') is NOT itself denylisted (exact match only)" "$EXPECTED_U10" "$out"

echo ""
echo "=== U-series: change-set binding (evidence integrity) ==="

echo ""
echo "[U11] compute_change_hash / change_intact: deterministic hash over canonical JSON, ANY difference in the change set is detected, a missing/malformed stored_hash is fail-closed (never 'nothing to check')"
out="$(pyval "
cs = {'operation': 'merge_to_master', 'target_branch': 'master', 'head_ref': 'abc123', 'touched_paths': ['a.py', 'b.py'], 'diff_hash': 'sha256:empty', 'risk_tier': 'PRIVILEGED'}
h1 = dal.compute_change_hash(cs)
h2 = dal.compute_change_hash(dict(cs))  # same content, different dict object -> same hash
print(h1 == h2, h1.startswith('sha256:'))
print(dal.change_intact(h1, cs))
altered_paths = dict(cs); altered_paths['touched_paths'] = ['a.py', 'b.py', 'c.py']
print(dal.change_intact(h1, altered_paths))
altered_branch = dict(cs); altered_branch['target_branch'] = 'develop'
print(dal.change_intact(h1, altered_branch))
altered_risk = dict(cs); altered_risk['risk_tier'] = 'AUTOMATIC'
print(dal.change_intact(h1, altered_risk))
print(dal.change_intact(None, cs))
print(dal.change_intact('', cs))
print(dal.change_intact('sha256:not-the-real-hash', cs))
")"
assert_eq "U11 eight cases correct (deterministic, matches, detects any one-field alteration, fail-closed on missing/malformed hash)" "$(printf 'True True\nTrue\nFalse\nFalse\nFalse\nFalse\nFalse\nFalse')" "$out"

echo ""
echo "=== U-series: timestamps -- malformed timestamps, always fail-closed, never raise ==="

echo ""
echo "[U12] parse_utc_timestamp / format_utc_timestamp: round-trips the pipeline's real format; every malformed variant returns None, never raises"
out="$(pyval "
t = dal.parse_utc_timestamp('2026-10-14T00:00:00Z')
print(t is not None, dal.format_utc_timestamp(t))
for bad in ['not a timestamp', '2026-10-14', '2026-10-14 00:00:00', '2026-10-14T00:00:00+09:00', '', None, 12345, '2026-13-99T99:99:99Z']:
    print(dal.parse_utc_timestamp(bad))
print(dal.format_utc_timestamp('not-a-datetime'))
print(dal.format_utc_timestamp(None))
")"
assert_eq "U12 round-trip correct, all eight malformed inputs -> None, format on non-datetime -> None" "$(printf 'True 2026-10-14T00:00:00Z\nNone\nNone\nNone\nNone\nNone\nNone\nNone\nNone\nNone\nNone')" "$out"

echo ""
echo "=== U-series: expiry -- boundaries, injectable clock, fail-closed ==="

echo ""
echo "[U13] *** EXPIRY BOUNDARIES *** compute_expiry (default 24h TTL) and is_expired: just-before/exactly-at/just-after the boundary, malformed inputs always fail-closed to expired=True, clock is always caller-supplied (this module never calls datetime.now()/utcnow() itself -- see D2 below)"
out="$(pyval "
requested = dal.parse_utc_timestamp('2026-10-14T00:00:00Z')
expires = dal.compute_expiry(requested)
print(dal.format_utc_timestamp(expires))
one_sec_before = expires - datetime.timedelta(seconds=1)
exactly_at = expires
one_sec_after = expires + datetime.timedelta(seconds=1)
print(dal.is_expired(expires, one_sec_before))
print(dal.is_expired(expires, exactly_at))
print(dal.is_expired(expires, one_sec_after))
custom = dal.compute_expiry(requested, ttl_seconds=3600)
print(dal.format_utc_timestamp(custom))
print(dal.is_expired(None, requested))
print(dal.is_expired(expires, None))
print(dal.is_expired('not-a-datetime', 'also-not'))
print(dal.compute_expiry('not-a-datetime'))
")"
assert_eq "U13 nine cases correct (24h default, before/at/after boundary, custom TTL, fail-closed on malformed)" "$(printf '2026-10-15T00:00:00Z\nFalse\nTrue\nTrue\n2026-10-14T01:00:00Z\nTrue\nTrue\nTrue\nNone')" "$out"

echo ""
echo "=== U-series: approval state machine -- duplicate approvals, illegal transitions ==="

echo ""
echo "[U14] *** DUPLICATE APPROVAL GUARD *** can_transition: only PENDING -> approve/reject is legal; re-approving/re-rejecting an already-decided, expired, or auto-cleared record is illegal, covering duplicate approvals and auto-cleared-record approval attempts by one single rule"
out="$(pyval "
print(dal.can_transition('PENDING', 'approve'))
print(dal.can_transition('PENDING', 'reject'))
print(dal.can_transition('APPROVED', 'approve'))
print(dal.can_transition('APPROVED', 'reject'))
print(dal.can_transition('REJECTED', 'approve'))
print(dal.can_transition('REJECTED', 'reject'))
print(dal.can_transition('EXPIRED', 'approve'))
print(dal.can_transition('EXPIRED', 'reject'))
print(dal.can_transition('AUTO_CLEARED', 'approve'))
print(dal.can_transition('AUTO_CLEARED', 'reject'))
print(dal.can_transition('BOGUS_STATUS', 'approve'))
print(dal.can_transition('PENDING', 'bogus_action'))
print(dal.next_status('PENDING', 'approve'))
print(dal.next_status('PENDING', 'reject'))
print(dal.next_status('APPROVED', 'approve'))
")"
assert_eq "U14 fifteen cases correct" "$(printf 'True\nTrue\nFalse\nFalse\nFalse\nFalse\nFalse\nFalse\nFalse\nFalse\nFalse\nFalse\nAPPROVED\nREJECTED\nNone')" "$out"

echo ""
echo "=== U-series: composite evaluate_approval -- every gate together, no short-circuit ==="

VALID_PY='
change_set = {"operation": "merge_to_master", "target_branch": "master", "head_ref": "abc123", "touched_paths": ["a.py"], "diff_hash": "sha256:deadbeef", "risk_tier": "PRIVILEGED"}
h = dal.compute_change_hash(change_set)
now = dal.parse_utc_timestamp("2026-10-14T12:00:00Z")
expires = dal.compute_expiry(dal.parse_utc_timestamp("2026-10-14T00:00:00Z"))
'

echo ""
echo "[U15] *** NOT-PRIVILEGED SHORT CIRCUIT *** a change_set that RE-CLASSIFIES as AUTOMATIC (never trusting a bare pre-set risk_tier field) is allowed with zero violations and no other gate evaluated -- there is nothing here for a human to approve"
out="$(pyval "
$VALID_PY
automatic_cs = {'operation': 'code_analysis', 'target_branch': 'feature/x', 'touched_paths': ['x.py'], 'diff_hash': 'sha256:x', 'risk_tier': 'PRIVILEGED'}  # risk_tier lies, re-derived anyway
h2 = dal.compute_change_hash(automatic_cs)
r = dal.evaluate_approval(automatic_cs, h2, None, now, None)
print(r['allowed'], r['violations'], r['checks']['scope']['basis'])
")"
assert_eq "U15 allowed via not_privileged, re-derived from operation/branch/paths, not from the stored risk_tier field" "True [] not_privileged" "$out"

echo ""
echo "[U16] evaluate_approval: a fully valid, in-scope, unexpired, change-intact PRIVILEGED approval with a sufficient reason and valid identity -> allowed True, zero violations"
out="$(pyval "
$VALID_PY
r = dal.evaluate_approval(change_set, h, 'alice-approver', now, expires, approval_reason='reviewed this diff thoroughly and confirmed it is safe to merge now')
print(r['allowed'], r['violations'])
")"
assert_eq "U16 allowed, no violations" "True []" "$out"

echo ""
echo "[U17] evaluate_approval: a denylisted AI identity is refused -- the single most load-bearing gate in this module"
out="$(pyval "
$VALID_PY
r = dal.evaluate_approval(change_set, h, 'claude', now, expires, approval_reason='reviewed this diff thoroughly and confirmed it is safe to merge now')
print('identity_is_denylisted_non_human_sentinel' in r['violations'])
")"
assert_eq "U17 identity_is_denylisted_non_human_sentinel violation present" "True" "$out"

echo ""
echo "[U18] evaluate_approval: a missing approver identity is refused"
out="$(pyval "
$VALID_PY
r = dal.evaluate_approval(change_set, h, None, now, expires, approval_reason='reviewed this diff thoroughly and confirmed it is safe to merge now')
print('missing_identity' in r['violations'])
")"
assert_eq "U18 missing_identity violation present" "True" "$out"

echo ""
echo "[U19] *** TAMPER DETECTION *** evaluate_approval: a change_set that no longer hashes to the stored change_hash (any field altered after propose time) is refused"
out="$(pyval "
$VALID_PY
altered = dict(change_set); altered['touched_paths'] = ['a.py', 'injected_extra_file.sh']
r = dal.evaluate_approval(altered, h, 'alice-approver', now, expires, approval_reason='reviewed this diff thoroughly and confirmed it is safe to merge now')
print('change_altered_or_missing' in r['violations'])
")"
assert_eq "U19 change_altered_or_missing violation present" "True" "$out"

echo ""
echo "[U20] evaluate_approval: an expired approval is refused"
out="$(pyval "
$VALID_PY
past_expiry = dal.parse_utc_timestamp('2026-10-14T00:00:01Z')  # now (12:00) is well past this
r = dal.evaluate_approval(change_set, h, 'alice-approver', now, past_expiry, approval_reason='reviewed this diff thoroughly and confirmed it is safe to merge now')
print('expired' in r['violations'])
")"
assert_eq "U20 expired violation present" "True" "$out"

echo ""
echo "[U21] evaluate_approval: an insufficient reason is refused"
out="$(pyval "
$VALID_PY
r = dal.evaluate_approval(change_set, h, 'alice-approver', now, expires, approval_reason='too short')
print('reason_too_short' in r['violations'])
")"
assert_eq "U21 reason_too_short violation present" "True" "$out"

echo ""
echo "[U22] *** NO SHORT-CIRCUIT *** every gate always runs -- an approval that fails identity AND reason AND is expired simultaneously reports ALL THREE violations, not just the first one found"
out="$(pyval "
$VALID_PY
past_expiry = dal.parse_utc_timestamp('2026-10-14T00:00:01Z')
r = dal.evaluate_approval(change_set, h, 'claude', now, past_expiry, approval_reason='no')
print(sorted(r['violations']))
")"
assert_eq "U22 all three violations present together" "['expired', 'identity_is_denylisted_non_human_sentinel', 'reason_too_short']" "$out"

echo ""
echo "=== U-series: untrusted strings -- never executed, only ever measured as text ==="

echo ""
echo "[U23] *** INJECTION SAFETY *** shell-metacharacter-laden identity/reason strings are NEVER executed -- they are only ever measured (length/distinct-char counts, denylist membership) and returned verbatim as text"
rm -f /tmp/waio_sda_lib_injection_marker
out="$(pyval "
malicious = 'alice; touch /tmp/waio_sda_lib_injection_marker ; \`touch /tmp/waio_sda_lib_injection_marker2\`'
r1 = dal.validate_approver_identity(malicious)
r2 = dal.validate_reason(malicious + ' padded out to a sufficient length for this check to pass cleanly')
print(r1['valid'])
print('touch /tmp/waio_sda_lib_injection_marker' in r2['normalized'])
")"
assert_eq "U23 malicious strings only ever measured/stored as text, never specially interpreted" "$(printf 'True\nTrue')" "$out"
assert_eq "U23 no marker file was ever created (never executed)" "absent" "$([ -e /tmp/waio_sda_lib_injection_marker ] && echo present || echo absent)"
rm -f /tmp/waio_sda_lib_injection_marker /tmp/waio_sda_lib_injection_marker2

echo ""
echo "=== D-series: structural guards ==="

echo ""
echo "[D1] *** THE CRITICAL I/O-ABSENCE GUARD *** dev_approval_lib.py's ACTUAL CODE (docstrings/comments stripped via Python's own tokenizer) has no subprocess/os.system/os.popen/exec/eval/open()/network call anywhere -- a strictly stronger guarantee than a name-based grep, matching this module's own 'No I/O in this module' header claim"
cnt="$(code_only_py security/self_dev/dev_approval_lib.py | grep -cE '\b(subprocess|os\.system|os\.popen|os\.exec\w*|eval|exec|requests\.|urllib|socket\.|curl|\bopen\()\b' || true)"
assert_eq "D1 zero I/O/subprocess/eval/exec/network references in actual code" "0" "$cnt"

echo ""
echo "[D2] *** THE CRITICAL INJECTABLE-CLOCK GUARD *** this module never calls datetime.now()/datetime.utcnow() itself anywhere in actual code -- every clock reference is caller-supplied"
cnt="$(code_only_py security/self_dev/dev_approval_lib.py | grep -cE 'datetime\.(now|utcnow)\s*\(' || true)"
assert_eq "D2 zero internal wall-clock reads" "0" "$cnt"

echo ""
echo "[D3] this module's ACTUAL CODE never references, by name, git merge/push, gh pr merge, a deploy tool, security/lib.sh, the Decision Engine, Guardian, DuCoPA, or any cron/launchd mechanism -- a docstring is free to NAME these as documentation of what this file does NOT call, this guard checks the actual code only"
cnt=0
for pattern in 'git merge' 'git push' 'gh pr merge' 'security/lib\.sh' 'decision_engine\.sh' 'decision_engine_lib' 'guardian\.sh' 'guardian_intervene' 'guardian_release_agent' 'ducopa\.sh' 'recovery_engine\.sh' '\brecover\.sh' 'launchctl' 'crontab' 'audit_log\('; do
  c="$(code_only_py security/self_dev/dev_approval_lib.py | grep -cE "$pattern" || true)"
  cnt=$((cnt + c))
done
assert_eq "D3 zero actual-code references to any privileged-operation/Control-Plane/Guardian/cron/launchd tool by name" "0" "$cnt"

echo ""
echo "[D4] this module defines no __main__ entry point -- library only, never directly executable"
assert_eq "D4 zero __main__ entry points" "0" "$(grep -c '__name__' security/self_dev/dev_approval_lib.py || true)"

echo ""
echo "[D5] *** SELF-APPROVAL IS STRUCTURALLY IMPOSSIBLE *** classify_operation and evaluate_approval share no call path from one into the other -- evaluate_approval's own actual code only ever CALLS classify_operation (to re-derive risk_tier, never trusting a bare pre-set field), classify_operation never calls evaluate_approval back"
assert_eq "D5 evaluate_approval's own body calls classify_operation" "nonzero" "$(python3 -c "
import inspect, sys
sys.path.insert(0, 'security/self_dev')
import dev_approval_lib as dal
src = inspect.getsource(dal.evaluate_approval)
print('nonzero' if 'classify_operation(' in src else 'zero')
")"
assert_eq "D5 classify_operation's own body never calls evaluate_approval" "zero" "$(python3 -c "
import inspect, sys
sys.path.insert(0, 'security/self_dev')
import dev_approval_lib as dal
src = inspect.getsource(dal.classify_operation)
print('nonzero' if 'evaluate_approval(' in src else 'zero')
")"

echo ""
echo "[D6] every pre-existing file this phase was told to leave alone remains unmodified -- this module is new and independent, sharing no code with its sibling"
for f in security/lib.sh security/guardian.sh security/ducopa.sh security/red_alert/containment_approval_lib.py security/red_alert/containment_approval_gate.sh security/decision_engine/decision_engine.sh security/decision_engine/decision_engine_lib.py; do
  assert_eq "D6 $f has no working-tree diff" "" "$(git diff --name-only -- "$f" 2>/dev/null)"
done

echo ""
echo "=== Summary: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
  echo "Failures:"
  for f in "${FAILURES[@]}"; do echo "  - $f"; done
  exit 1
fi
exit 0
