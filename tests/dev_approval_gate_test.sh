#!/bin/bash
set -uo pipefail

# tests/dev_approval_gate_test.sh -- regression suite for WAIO's
# Self-Development Engine Human Approval Gate:
# security/self_dev/dev_approval_gate.sh, the audit-log-backed CLI
# wrapper around security/self_dev/dev_approval_lib.py's pure library.
# Implements exactly five verbs -- propose | approve | reject | status
# | list -- and NEVER executes, invokes, or queues a merge, deploy,
# shutdown, containment action, or any other privileged operation.
#
# Same two-layer convention as this gate's own direct architectural
# sibling, tests/containment_approval_gate_test.sh:
#   I-series: integration tests against the real CLI/real filesystem,
#     every case running against an isolated DEV_APPROVAL_STATE_DIR/
#     DEV_APPROVAL_AUDIT_LOG and an injected clock
#     (WAIO_SELF_DEV_APPROVAL_NOW) -- never this deployment's real
#     security/state/self_dev/.
#   D-series: static structural guards -- zero references to
#     security/lib.sh/Guardian/DuCoPA/git-merge/gh-pr-merge/a deploy
#     tool by name in actual code, and no verb through which an
#     APPROVED record could ever be turned into an executed action.

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
  python3 -c "import json,sys; d=json.load(sys.stdin); print($2)" <<<"$1"
}

code_only() {
  grep -vE '^[[:space:]]*#' "$1"
}

GATE=./security/self_dev/dev_approval_gate.sh

echo "=== WAIO Self-Development Engine Human Approval Gate regression suite ==="
echo "    (security/self_dev/dev_approval_gate.sh)"

FIXTURE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/waio-sda-test.XXXXXX")"
trap 'rm -rf "$FIXTURE_DIR" /tmp/waio_sda_injection_marker*' EXIT

export DEV_APPROVAL_STATE_DIR="$FIXTURE_DIR/state"
export DEV_APPROVAL_AUDIT_LOG="$FIXTURE_DIR/audit.jsonl"
export WAIO_SELF_DEV_APPROVAL_NOW="2026-10-14T00:00:00Z"

echo ""
echo "=== I-series: propose / classification ==="

echo ""
echo "[I1] propose: AUTOMATIC operation on a feature branch -> AUTO_CLEARED, no approval required, no expiry, record persisted"
OUT="$($GATE propose isolated_branch_commit feature/demo abc001 alice --path foo.py)"
RC=$?
ID1="$(jget "$OUT" "d['approval_id']")"
assert_eq "I1 exit code 0" "0" "$RC"
assert_eq "I1 duplicate false" "False" "$(jget "$OUT" "d['duplicate']")"
assert_eq "I1 status AUTO_CLEARED" "AUTO_CLEARED" "$(jget "$OUT" "d['status']")"
assert_eq "I1 requires_human_approval False" "False" "$(jget "$OUT" "d['record']['requires_human_approval']")"
assert_eq "I1 expires_at null" "None" "$(jget "$OUT" "d['record']['expires_at']")"
assert_eq "I1 proposed_by recorded" "alice" "$(jget "$OUT" "d['record']['proposed_by']")"
assert_eq "I1 the record file actually exists on disk" "true" "$([ -f "$DEV_APPROVAL_STATE_DIR/proposals/$ID1.json" ] && echo true || echo false)"

echo ""
echo "[I2] propose: PRIVILEGED operation (merge_to_master) -> PENDING, default 24h TTL applied from the injected clock"
OUT="$($GATE propose merge_to_master master def002 alice --path foo.py)"
RC=$?
ID2="$(jget "$OUT" "d['approval_id']")"
assert_eq "I2 exit code 0" "0" "$RC"
assert_eq "I2 status PENDING" "PENDING" "$(jget "$OUT" "d['status']")"
assert_eq "I2 requires_human_approval True" "True" "$(jget "$OUT" "d['record']['requires_human_approval']")"
assert_eq "I2 expires_at = proposed_at + default 24h TTL" "2026-10-15T00:00:00Z" "$(jget "$OUT" "d['record']['expires_at']")"

echo ""
echo "[I3] *** DUPLICATE PROPOSAL *** the SAME operation/branch/head_ref/paths/diff proposed again returns the EXISTING record unchanged -- no second file, no new TTL"
OUT3="$($GATE propose merge_to_master master def002 alice --path foo.py)"
ID3="$(jget "$OUT3" "d['approval_id']")"
assert_eq "I3 same approval_id returned" "$ID2" "$ID3"
assert_eq "I3 duplicate flag true" "True" "$(jget "$OUT3" "d['duplicate']")"
assert_eq "I3 expires_at unchanged" "2026-10-15T00:00:00Z" "$(jget "$OUT3" "d['record']['expires_at']")"

echo ""
echo "[I4] *** SELF-GATE-PROTECTION *** an otherwise-AUTOMATIC isolated_branch_commit DIRECTLY targeting a protected branch (master) is escalated to PRIVILEGED"
OUT="$($GATE propose isolated_branch_commit master def004 alice --path foo.py)"
assert_eq "I4 status PENDING (escalated)" "PENDING" "$(jget "$OUT" "d['status']")"
assert_contains "I4 classification_reasons cite the protected target_branch" "$(jget "$OUT" "d['record']['classification_reasons']")" "protected branch"

echo ""
echo "[I5] *** SELF-GATE-PROTECTION *** an AUTOMATIC operation touching this gate's own files is escalated to PRIVILEGED regardless of the operation name"
OUT="$($GATE propose code_analysis feature/demo def005 alice --path security/self_dev/dev_approval_gate.sh)"
assert_eq "I5 status PENDING (escalated)" "PENDING" "$(jget "$OUT" "d['status']")"
assert_contains "I5 classification_reasons cite the protected path pattern" "$(jget "$OUT" "d['record']['classification_reasons']")" "protected pattern"

echo ""
echo "[I6] a .example template under the same protected-looking path is NOT escalated -- editing a template is not editing real config"
OUT="$($GATE propose code_analysis feature/demo def006 alice --path security/self_dev/dev_approval_gate.sh.example)"
assert_eq "I6 status AUTO_CLEARED (not escalated)" "AUTO_CLEARED" "$(jget "$OUT" "d['status']")"

echo ""
echo "[I7] an unrecognized/misspelled operation name is fail-closed to PRIVILEGED, never guessed as automatic"
OUT="$($GATE propose totally_unknown_operation feature/demo def007 alice)"
assert_eq "I7 status PENDING (fail-closed)" "PENDING" "$(jget "$OUT" "d['status']")"

echo ""
echo "[I8] propose: --diff-file pointing at a nonexistent file is refused before any record is written"
OUT="$($GATE propose isolated_branch_commit feature/demo def008 alice --diff-file "$FIXTURE_DIR/does_not_exist.diff")"
RC=$?
assert_eq "I8 exit code 2" "2" "$RC"
assert_eq "I8 error diff_file_not_found" "diff_file_not_found" "$(jget "$OUT" "d['error']")"
assert_eq "I8 no record written for this head_ref" "0" "$(find "$DEV_APPROVAL_STATE_DIR/proposals" -name '*def008*' | wc -l | tr -d ' ')"

echo ""
echo "[I9] propose: a real --diff-file produces a non-empty diff_hash bound into change_hash"
echo "some diff content" > "$FIXTURE_DIR/real.diff"
OUT="$($GATE propose isolated_branch_commit feature/demo def009 alice --diff-file "$FIXTURE_DIR/real.diff")"
assert_eq "I9 diff_hash is not the empty sentinel" "False" "$(jget "$OUT" "d['record']['diff_hash'] == 'sha256:empty'")"

echo ""
echo "=== I-series: approve ==="

echo ""
echo "[I10] *** AI SELF-APPROVAL DEFENSE *** approve with a denylisted non-human identity ('claude') is refused"
OUT="$($GATE approve "$ID2" claude "this reason is padded out with enough additional text to pass the length check")"
RC=$?
assert_eq "I10 exit code 7" "7" "$RC"
assert_contains "I10 violations include identity_is_denylisted_non_human_sentinel" "$OUT" "identity_is_denylisted_non_human_sentinel"

echo ""
echo "[I11] approve: insufficient reason (too short) is refused"
OUT="$($GATE approve "$ID2" alice-approver "short")"
RC=$?
assert_eq "I11 exit code 7" "7" "$RC"
assert_contains "I11 violations include reason_too_short" "$OUT" "reason_too_short"

echo ""
echo "[I12] approve: valid human identity + valid reason on a PENDING record -> APPROVED, persisted"
OUT="$($GATE approve "$ID2" alice-approver "reviewed this diff thoroughly and confirmed it is safe to merge now")"
RC=$?
assert_eq "I12 exit code 0" "0" "$RC"
assert_eq "I12 status APPROVED" "APPROVED" "$(jget "$OUT" "d['status']")"
assert_eq "I12 decided_by recorded" "alice-approver" "$(jget "$OUT" "d['record']['decision']['decided_by']")"
PERSISTED="$(cat "$DEV_APPROVAL_STATE_DIR/proposals/$ID2.json")"
assert_eq "I12 status persisted to disk as APPROVED" "APPROVED" "$(jget "$PERSISTED" "d['status']")"

echo ""
echo "[I13] *** DUPLICATE APPROVAL *** approving an already-APPROVED record is refused, decision unchanged"
OUT="$($GATE approve "$ID2" bob-approver "a second, different approval attempt on an already-decided record")"
RC=$?
assert_eq "I13 exit code 6" "6" "$RC"
assert_eq "I13 error illegal_transition" "illegal_transition" "$(jget "$OUT" "d['error']")"
assert_eq "I13 decided_by still the FIRST approver" "alice-approver" "$(jget "$(cat "$DEV_APPROVAL_STATE_DIR/proposals/$ID2.json")" "d['decision']['decided_by']")"

echo ""
echo "[I13b] *** SEPARATION OF DUTIES *** the proposer's own identity (any case, padded) is refused as approver; a different identity then approves normally"
OUT="$($GATE propose merge_to_master master sod013 ai_defense_loop --path foo.py)"
ID13B="$(jget "$OUT" "d['approval_id']")"
OUT="$($GATE approve "$ID13B" ai_defense_loop "this reason is padded out with enough additional text to pass the length check")"
RC=$?
assert_eq "I13b exact proposer name refused (exit 7)" "7" "$RC"
assert_contains "I13b violation names approver_is_proposer" "$OUT" "approver_is_proposer"
OUT="$($GATE approve "$ID13B" "  AI_Defense_Loop " "this reason is padded out with enough additional text to pass the length check")"
RC=$?
assert_eq "I13b case/whitespace variant of the proposer refused (exit 7)" "7" "$RC"
assert_eq "I13b record still PENDING on disk" "PENDING" "$(jget "$(cat "$DEV_APPROVAL_STATE_DIR/proposals/$ID13B.json")" "d['status']")"
OUT="$($GATE approve "$ID13B" alice-approver "this reason is padded out with enough additional text to pass the length check")"
RC=$?
assert_eq "I13b a different identity approves (exit 0)" "0" "$RC"
assert_eq "I13b status APPROVED" "APPROVED" "$(jget "$OUT" "d['record']['status']")"

echo ""
echo "[I14] approve: nonexistent approval_id -> clear refusal"
OUT="$($GATE approve SDA-does-not-exist-000000000000 alice-approver "a reason that is long enough to pass the length check on its own merits")"
RC=$?
assert_eq "I14 exit code 2" "2" "$RC"
assert_eq "I14 error proposal_not_found" "proposal_not_found" "$(jget "$OUT" "d['error']")"

echo ""
echo "[I15] *** AUTO_CLEARED HAS NO LEGAL TRANSITION *** attempting to approve an AUTO_CLEARED record is refused -- there is nothing here for a human to approve"
OUT="$($GATE approve "$ID1" alice-approver "trying to approve an auto-cleared record anyway")"
RC=$?
assert_eq "I15 exit code 6" "6" "$RC"
assert_eq "I15 error illegal_transition" "illegal_transition" "$(jget "$OUT" "d['error']")"
assert_eq "I15 current_status reported as AUTO_CLEARED" "AUTO_CLEARED" "$(jget "$OUT" "d['current_status']")"

echo ""
echo "[I16] *** TAMPERED RECORD *** editing touched_paths on disk without updating change_hash is detected and refused on approve, fail-closed"
OUT="$($GATE propose containment_action develop tamper016 alice --path a.py)"
ID16="$(jget "$OUT" "d['approval_id']")"
python3 -c "
import json
p = '$DEV_APPROVAL_STATE_DIR/proposals/$ID16.json'
r = json.load(open(p))
r['touched_paths'] = ['a.py', 'injected_extra_file.sh']
json.dump(r, open(p, 'w'))
"
OUT="$($GATE approve "$ID16" alice-approver "approving after someone tampered with the record on disk")"
RC=$?
assert_eq "I16 exit code 7" "7" "$RC"
assert_contains "I16 violations include change_altered_or_missing" "$OUT" "change_altered_or_missing"

echo ""
echo "[I17] *** EXPIRY BOUNDARY *** a PENDING approval past its own expires_at is refused on approve (illegal_transition/EXPIRED), and EXPIRED is persisted as a side effect of the access"
OUT="$(DEV_APPROVAL_TTL_SECONDS=3600 $GATE propose production_deploy master exp017 alice --path deploy.yml)"
ID17="$(jget "$OUT" "d['approval_id']")"
assert_eq "I17 TTL respected (1h from 00:00 is 01:00)" "2026-10-14T01:00:00Z" "$(jget "$OUT" "d['record']['expires_at']")"
export WAIO_SELF_DEV_APPROVAL_NOW="2026-10-14T01:00:01Z"
OUT="$($GATE approve "$ID17" alice-approver "investigated this finding thoroughly and confirmed it matches known activity")"
RC=$?
assert_eq "I17 exit code 6" "6" "$RC"
assert_eq "I17 current_status EXPIRED" "EXPIRED" "$(jget "$OUT" "d['current_status']")"
assert_eq "I17 EXPIRED persisted to disk" "EXPIRED" "$(jget "$(cat "$DEV_APPROVAL_STATE_DIR/proposals/$ID17.json")" "d['status']")"
export WAIO_SELF_DEV_APPROVAL_NOW="2026-10-14T00:00:00Z"

echo ""
echo "[I17b] an APPROVED record past its own expires_at reads effective_status EXPIRED (stored status stays APPROVED, record not rewritten)"
OUT="$(DEV_APPROVAL_TTL_SECONDS=3600 $GATE propose production_deploy master exp017b alice --path deploy.yml)"
ID17B="$(jget "$OUT" "d['approval_id']")"
$GATE approve "$ID17B" alice-approver "investigated this finding thoroughly and confirmed it matches known activity" >/dev/null
assert_eq "I17b before expires_at: APPROVED" "APPROVED" "$(jget "$($GATE status "$ID17B")" "d['effective_status']")"
SUM17B="$(shasum -a 256 "$DEV_APPROVAL_STATE_DIR/proposals/$ID17B.json")"
export WAIO_SELF_DEV_APPROVAL_NOW="2026-10-14T01:00:00Z"
assert_eq "I17b at expires_at: EXPIRED" "EXPIRED" "$(jget "$($GATE status "$ID17B")" "d['effective_status']")"
assert_eq "I17b stored status still APPROVED" "APPROVED" "$(jget "$($GATE status "$ID17B")" "d['record']['status']")"
assert_eq "I17b record file not rewritten" "$SUM17B" "$(shasum -a 256 "$DEV_APPROVAL_STATE_DIR/proposals/$ID17B.json")"
export WAIO_SELF_DEV_APPROVAL_NOW="2026-10-14T00:00:00Z"

echo ""
echo "=== I-series: reject ==="

echo ""
echo "[I18] reject: valid identity+reason -> REJECTED, terminal"
OUT="$($GATE propose merge_to_develop develop rej018 alice --path x.py)"
ID18="$(jget "$OUT" "d['approval_id']")"
OUT="$($GATE reject "$ID18" alice-approver "reviewed this change and determined it is not ready to merge yet")"
RC=$?
assert_eq "I18 exit code 0" "0" "$RC"
assert_eq "I18 status REJECTED" "REJECTED" "$(jget "$OUT" "d['status']")"

echo ""
echo "[I19] *** REJECTION IS TERMINAL *** approving an already-REJECTED record is refused"
OUT="$($GATE approve "$ID18" alice-approver "trying to approve this anyway after it was already rejected")"
RC=$?
assert_eq "I19 exit code 6" "6" "$RC"
assert_eq "I19 error illegal_transition" "illegal_transition" "$(jget "$OUT" "d['error']")"

echo ""
echo "[I20] reject: insufficient reason -> refused, record stays PENDING"
OUT="$($GATE propose merge_to_develop develop rej020 alice --path y.py)"
ID20="$(jget "$OUT" "d['approval_id']")"
OUT="$($GATE reject "$ID20" alice-approver "no")"
RC=$?
assert_eq "I20 exit code 7" "7" "$RC"
assert_eq "I20 record still PENDING" "PENDING" "$(jget "$(cat "$DEV_APPROVAL_STATE_DIR/proposals/$ID20.json")" "d['status']")"

echo ""
echo "=== I-series: status / list (read-only) ==="

echo ""
echo "[I21] status: nonexistent approval_id -> clear refusal, never a crash"
OUT="$($GATE status SDA-does-not-exist-000000000000)"
RC=$?
assert_eq "I21 exit code 2" "2" "$RC"
assert_eq "I21 error proposal_not_found" "proposal_not_found" "$(jget "$OUT" "d['error']")"

echo ""
echo "[I22] status: read-only -- calling it twice never mutates a PENDING-but-not-yet-expired record"
OUT="$($GATE propose merge_to_develop develop ro022 alice --path z.py)"
ID22="$(jget "$OUT" "d['approval_id']")"
HASH_BEFORE="$(shasum -a 256 "$DEV_APPROVAL_STATE_DIR/proposals/$ID22.json" | awk '{print $1}')"
$GATE status "$ID22" > /dev/null
$GATE status "$ID22" > /dev/null
HASH_AFTER="$(shasum -a 256 "$DEV_APPROVAL_STATE_DIR/proposals/$ID22.json" | awk '{print $1}')"
assert_eq "I22 record file byte-identical before/after two status calls" "$HASH_BEFORE" "$HASH_AFTER"

echo ""
echo "[I23] list: --status filter returns only matching entries"
OUT="$($GATE list --status PENDING)"
assert_eq "I23 ro022's proposal is among PENDING" "True" "$(jget "$OUT" "any(e['approval_id'] == '$ID22' for e in d['entries'])")"
OUT="$($GATE list --status APPROVED)"
assert_eq "I23 the earlier APPROVED record ($ID2) is among APPROVED, not PENDING" "True" "$(jget "$OUT" "any(e['approval_id'] == '$ID2' for e in d['entries'])")"

echo ""
echo "[I24] *** MALFORMED RECORD ON DISK *** a corrupted proposal file is refused cleanly on status, and list reports it as corrupt rather than crashing the whole listing"
OUT="$($GATE propose merge_to_develop develop corrupt024 alice --path q.py)"
ID24="$(jget "$OUT" "d['approval_id']")"
echo 'this is not valid json at all' > "$DEV_APPROVAL_STATE_DIR/proposals/$ID24.json"
OUT="$($GATE status "$ID24")"
RC=$?
assert_eq "I24 status exit code 4" "4" "$RC"
assert_eq "I24 status error record_corrupt" "record_corrupt" "$(jget "$OUT" "d['error']")"
OUT="$($GATE list)"
assert_eq "I24 list reports the corrupt file by name, never crashes" "True" "$(jget "$OUT" "any('$ID24' in c['path'] for c in d['corrupt'])")"

echo ""
echo "=== I-series: APPROVAL_ID hardening (path-traversal defense) ==="

echo ""
echo "[I25] *** MALFORMED APPROVAL_ID BATTERY *** every non-charset-conforming id is refused cleanly (exit 10, invalid_approval_id) by approve/reject/status alike, never touching the filesystem outside proposals_dir"
for bad_id in "" "a b" "a;b" "a/b" "/etc/passwd" "../x" "$(python3 -c "print('a'*201)")"; do
  OUT="$($GATE status "$bad_id" 2>&1)"
  RC=$?
  assert_eq "I25 status refuses malformed id '$bad_id' (exit 10)" "10" "$RC"
done
OUT="$($GATE approve "../x" alice-approver "this reason is padded out with enough additional text to pass the length check" 2>&1)"
RC=$?
assert_eq "I25 approve also refuses a malformed id (exit 10)" "10" "$RC"
OUT="$($GATE reject "a;b" alice-approver "this reason is padded out with enough additional text to pass the length check" 2>&1)"
RC=$?
assert_eq "I25 reject also refuses a malformed id (exit 10)" "10" "$RC"

echo ""
echo "[I26] a legitimately-generated id is unaffected by the hardening above"
OUT="$($GATE propose merge_to_develop develop legit026 alice --path w.py)"
ID26="$(jget "$OUT" "d['approval_id']")"
OUT="$($GATE approve "$ID26" alice-approver "this reason is padded out with enough additional text to pass the length check")"
RC=$?
assert_eq "I26 exit code 0" "0" "$RC"
assert_eq "I26 status APPROVED" "APPROVED" "$(jget "$OUT" "d['status']")"

echo ""
echo "=== I-series: safe persistence (failure path) ==="

echo ""
echo "[I27] *** PERSISTENCE FAILURE *** an unwritable state-directory location is detected and refused cleanly, never a partial write"
RO_PARENT="$(mktemp -d)"
chmod 555 "$RO_PARENT"
OUT="$(DEV_APPROVAL_STATE_DIR="$RO_PARENT/nope/state" DEV_APPROVAL_AUDIT_LOG="$RO_PARENT/nope/audit.jsonl" $GATE propose isolated_branch_commit feature/demo ro027 alice 2>&1)"
RC=$?
assert_eq "I27 non-zero exit" "1" "$RC"
assert_contains "I27 clear error message naming safe persistence" "$OUT" "refusing to proceed without safe persistence"
chmod 755 "$RO_PARENT"
rm -rf "$RO_PARENT"

echo ""
echo "=== I-series: concurrency (REAL backgrounded processes) ==="

echo ""
echo "[I28] *** CONCURRENT DUPLICATE PROPOSALS *** two processes proposing the SAME operation/branch/head_ref/paths at once still produce exactly ONE record, serialized by the per-operation+head_ref lock"
$GATE propose merge_to_develop develop race028 alice --path r.py > "$FIXTURE_DIR/i28_a.json" 2>&1 &
PID_A=$!
$GATE propose merge_to_develop develop race028 alice --path r.py > "$FIXTURE_DIR/i28_b.json" 2>&1 &
PID_B=$!
wait "$PID_A"; RC_A=$?
wait "$PID_B"; RC_B=$?
assert_eq "I28 both processes exit 0" "0 0" "$RC_A $RC_B"
ID_A="$(jget "$(cat "$FIXTURE_DIR/i28_a.json")" "d['approval_id']")"
ID_B="$(jget "$(cat "$FIXTURE_DIR/i28_b.json")" "d['approval_id']")"
assert_eq "I28 both got the SAME approval_id" "$ID_A" "$ID_B"
assert_eq "I28 exactly one is the real propose, the other a detected duplicate" "True" "$([ "$(jget "$(cat "$FIXTURE_DIR/i28_a.json")" "d['duplicate']")" != "$(jget "$(cat "$FIXTURE_DIR/i28_b.json")" "d['duplicate']")" ] && echo True || echo False)"

echo ""
echo "[I29] *** CONCURRENT DUPLICATE APPROVALS *** two processes approving the SAME PENDING record at once: exactly one succeeds, the other sees illegal_transition -- never both APPROVED, never neither"
OUT="$($GATE propose merge_to_develop develop race029 alice --path s.py)"
ID29="$(jget "$OUT" "d['approval_id']")"
$GATE approve "$ID29" alice-approver "first of two concurrent approve attempts racing for this exact record" > "$FIXTURE_DIR/i29_a.json" 2>&1 &
PID_A=$!
$GATE approve "$ID29" bob-approver "second of two concurrent approve attempts racing for this exact record" > "$FIXTURE_DIR/i29_b.json" 2>&1 &
PID_B=$!
wait "$PID_A"; RC_A=$?
wait "$PID_B"; RC_B=$?
assert_eq "I29 exactly one success, one illegal_transition (rc 0 and 6, in either order)" "True" "$([ "$(( (RC_A==0) + (RC_B==0) ))" -eq 1 ] && [ "$(( (RC_A==6) + (RC_B==6) ))" -eq 1 ] && echo True || echo False)"
assert_eq "I29 final persisted status is APPROVED exactly once, never duplicated/lost" "APPROVED" "$(jget "$(cat "$DEV_APPROVAL_STATE_DIR/proposals/$ID29.json")" "d['status']")"

echo ""
echo "=== I-series: untrusted strings (injection safety, full CLI) ==="

echo ""
echo "[I30] *** INJECTION SAFETY *** a shell-metacharacter-laden proposed_by/approver identity/reason is NEVER executed anywhere in propose/approve -- stored and returned as inert text only"
rm -f /tmp/waio_sda_injection_marker
MALICIOUS='alice; touch /tmp/waio_sda_injection_marker ; `touch /tmp/waio_sda_injection_marker2`'
OUT="$($GATE propose merge_to_develop develop inj030 "$MALICIOUS" --path m.py)"
ID30="$(jget "$OUT" "d['approval_id']")"
assert_eq "I30 no marker file created by propose" "absent" "$([ -e /tmp/waio_sda_injection_marker ] && echo present || echo absent)"
OUT="$($GATE approve "$ID30" "$MALICIOUS (reviewer)" "$MALICIOUS this reason is padded with enough additional text to pass the length check cleanly")"
assert_eq "I30 no marker file created by approve" "absent" "$([ -e /tmp/waio_sda_injection_marker ] && echo present || echo absent)"
assert_contains "I30 the malicious string is stored verbatim as inert text in the persisted record" "$(cat "$DEV_APPROVAL_STATE_DIR/proposals/$ID30.json")" "touch /tmp/waio_sda_injection_marker"
rm -f /tmp/waio_sda_injection_marker /tmp/waio_sda_injection_marker2

echo ""
echo "=== I-series: audit log correctness (regression for the propose() detail_json brace-expansion fix) ==="

echo ""
echo "[I31] *** AUDIT DETAIL REGRESSION *** propose's own audit-log 'proposed' entry carries a correctly-populated {operation, status} detail object -- not null -- and propose emits no stray stderr output"
OUT="$($GATE propose isolated_branch_commit feature/demo aud031 alice --path n.py 2>"$FIXTURE_DIR/i31_stderr.txt")"
ID31="$(jget "$OUT" "d['approval_id']")"
LAST_AUDIT_LINE="$(grep "\"approval_id\": \"$ID31\"" "$DEV_APPROVAL_AUDIT_LOG" | tail -1)"
assert_eq "I31 audit detail.operation is isolated_branch_commit" "isolated_branch_commit" "$(jget "$LAST_AUDIT_LINE" "d['detail']['operation']")"
assert_eq "I31 audit detail.status is AUTO_CLEARED" "AUTO_CLEARED" "$(jget "$LAST_AUDIT_LINE" "d['detail']['status']")"
assert_eq "I31 propose produced no stderr output at all" "" "$(cat "$FIXTURE_DIR/i31_stderr.txt")"

echo ""
echo "=== I-series: classification-drift hardening on approve (regression for the evaluate_approval() not-privileged short circuit crash) ==="

echo ""
echo "[I32] *** CLASSIFICATION DRIFT ON APPROVE, FIXED *** a PENDING record whose touched_paths are tampered on disk so the SAME stored operation/target_branch now re-classifies as AUTOMATIC (evaluate_approval()'s own 'not-privileged short circuit', which carries no 'reason' key in its checks dict) is refused cleanly as gate_refused/classification_drift_since_proposal -- NEVER a raw Python traceback, NEVER a silent APPROVED, and the on-disk record is left untouched"
OUT="$($GATE propose code_analysis feature/demo drift032 alice --path security/self_dev/dev_approval_gate.sh)"
ID32="$(jget "$OUT" "d['approval_id']")"
assert_eq "I32 proposed PENDING (escalated by the self-gate-protection path pattern)" "PENDING" "$(jget "$OUT" "d['status']")"
python3 -c "
import json
p = '$DEV_APPROVAL_STATE_DIR/proposals/$ID32.json'
r = json.load(open(p))
r['touched_paths'] = []
json.dump(r, open(p, 'w'))
"
HASH_BEFORE_32="$(shasum -a 256 "$DEV_APPROVAL_STATE_DIR/proposals/$ID32.json" | awk '{print $1}')"
OUT="$($GATE approve "$ID32" alice-approver "this reason is padded out with enough additional text to pass the length check" 2>"$FIXTURE_DIR/i32_stderr.txt")"
RC=$?
assert_eq "I32 exit code 7 (gate_refused), never a crash exit code" "7" "$RC"
assert_eq "I32 no stray stderr output -- no raw Python traceback leaked" "" "$(cat "$FIXTURE_DIR/i32_stderr.txt")"
assert_eq "I32 stdout parses as valid JSON" "True" "$(python3 -c "
import json, sys
try:
    json.loads(sys.argv[1])
    print('True')
except Exception:
    print('False')
" "$OUT")"
assert_eq "I32 error is gate_refused" "gate_refused" "$(jget "$OUT" "d['error']")"
assert_contains "I32 violations name the classification drift" "$OUT" "classification_drift_since_proposal"
assert_eq "I32 record status on disk is still PENDING -- never silently APPROVED" "PENDING" "$(jget "$(cat "$DEV_APPROVAL_STATE_DIR/proposals/$ID32.json")" "d['status']")"
assert_eq "I32 the tampered-but-untouched-by-approve record file is byte-identical before/after the refused approve attempt" "$HASH_BEFORE_32" "$(shasum -a 256 "$DEV_APPROVAL_STATE_DIR/proposals/$ID32.json" | awk '{print $1}')"

echo ""
echo "[I33] a legitimately-classified PRIVILEGED record (no drift) is still approved normally after the I32 fix -- the new guard does not affect the ordinary path"
OUT="$($GATE propose merge_to_master master drift033 alice --path foo.py)"
ID33="$(jget "$OUT" "d['approval_id']")"
OUT="$($GATE approve "$ID33" alice-approver "this reason is padded out with enough additional text to pass the length check")"
RC=$?
assert_eq "I33 exit code 0" "0" "$RC"
assert_eq "I33 status APPROVED" "APPROVED" "$(jget "$OUT" "d['status']")"
assert_eq "I33 decision.reason recorded normally (the normal, non-drifted codepath for the same dict access)" "this reason is padded out with enough additional text to pass the length check" "$(jget "$OUT" "d['record']['decision']['reason']")"

echo ""
echo "=== I-series: proposals_dir symlink-escape hardening (status / approve / reject) ==="

echo ""
echo "[I34] *** SYMLINK ESCAPE, status *** a symlink planted directly inside proposals_dir, under an otherwise charset-valid APPROVAL_ID name, pointing at a secret file OUTSIDE proposals_dir is refused by the realpath containment check -- status never reads through it, never leaks the target content"
OUTSIDE_DIR="$FIXTURE_DIR/outside"
mkdir -p "$OUTSIDE_DIR"
cat > "$OUTSIDE_DIR/secret_status.json" <<'EOF'
{"DO_NOT_LEAK_MARKER": "sda-secret-content-outside-proposals-dir-status", "status": "APPROVED"}
EOF
ln -s "$OUTSIDE_DIR/secret_status.json" "$DEV_APPROVAL_STATE_DIR/proposals/SDA-symlink-attempt-status-000000000000.json"
OUT="$($GATE status "SDA-symlink-attempt-status-000000000000")"
RC=$?
assert_eq "I34 exit code 10 (symlink target rejected, not followed)" "10" "$RC"
assert_eq "I34 error invalid_approval_id" "invalid_approval_id" "$(jget "$OUT" "d['error']")"
assert_eq "I34 the symlinked-to secret content never appears in the output" "False" "$([[ "$OUT" == *"sda-secret-content"* ]] && echo True || echo False)"
rm -f "$DEV_APPROVAL_STATE_DIR/proposals/SDA-symlink-attempt-status-000000000000.json"

echo ""
echo "[I35] *** SYMLINK ESCAPE, approve *** the same symlink-inside-proposals_dir attack against approve is refused by its own independent realpath containment check -- never reads, never writes through the symlink, and the outside target is left completely untouched"
cat > "$OUTSIDE_DIR/secret_approve.json" <<'EOF'
{"DO_NOT_LEAK_MARKER": "sda-secret-content-outside-proposals-dir-approve", "status": "PENDING", "operation": "merge_to_master", "target_branch": "master", "head_ref": "x", "touched_paths": [], "diff_hash": "sha256:empty", "risk_tier": "PRIVILEGED", "change_hash": "sha256:bogus", "expires_at": null, "decision": {"outcome": null}}
EOF
HASH_BEFORE_35="$(shasum -a 256 "$OUTSIDE_DIR/secret_approve.json" | awk '{print $1}')"
ln -s "$OUTSIDE_DIR/secret_approve.json" "$DEV_APPROVAL_STATE_DIR/proposals/SDA-symlink-attempt-approve-000000000000.json"
OUT="$($GATE approve "SDA-symlink-attempt-approve-000000000000" alice-approver "this reason is padded out with enough additional text to pass the length check")"
RC=$?
assert_eq "I35 exit code 10 (symlink target rejected, not followed)" "10" "$RC"
assert_eq "I35 error invalid_approval_id" "invalid_approval_id" "$(jget "$OUT" "d['error']")"
assert_eq "I35 the symlinked-to secret content never appears in the output" "False" "$([[ "$OUT" == *"sda-secret-content"* ]] && echo True || echo False)"
assert_eq "I35 the outside target file is byte-identical before/after -- never written through the symlink" "$HASH_BEFORE_35" "$(shasum -a 256 "$OUTSIDE_DIR/secret_approve.json" | awk '{print $1}')"
rm -f "$DEV_APPROVAL_STATE_DIR/proposals/SDA-symlink-attempt-approve-000000000000.json"

echo ""
echo "[I36] *** SYMLINK ESCAPE, reject *** the same symlink-inside-proposals_dir attack against reject is refused by its own independent realpath containment check, same guarantees as I35"
cat > "$OUTSIDE_DIR/secret_reject.json" <<'EOF'
{"DO_NOT_LEAK_MARKER": "sda-secret-content-outside-proposals-dir-reject", "status": "PENDING", "operation": "merge_to_master", "target_branch": "master", "head_ref": "x", "touched_paths": [], "diff_hash": "sha256:empty", "risk_tier": "PRIVILEGED", "change_hash": "sha256:bogus", "expires_at": null, "decision": {"outcome": null}}
EOF
HASH_BEFORE_36="$(shasum -a 256 "$OUTSIDE_DIR/secret_reject.json" | awk '{print $1}')"
ln -s "$OUTSIDE_DIR/secret_reject.json" "$DEV_APPROVAL_STATE_DIR/proposals/SDA-symlink-attempt-reject-000000000000.json"
OUT="$($GATE reject "SDA-symlink-attempt-reject-000000000000" alice-approver "this reason is padded out with enough additional text to pass the length check")"
RC=$?
assert_eq "I36 exit code 10 (symlink target rejected, not followed)" "10" "$RC"
assert_eq "I36 error invalid_approval_id" "invalid_approval_id" "$(jget "$OUT" "d['error']")"
assert_eq "I36 the symlinked-to secret content never appears in the output" "False" "$([[ "$OUT" == *"sda-secret-content"* ]] && echo True || echo False)"
assert_eq "I36 the outside target file is byte-identical before/after -- never written through the symlink" "$HASH_BEFORE_36" "$(shasum -a 256 "$OUTSIDE_DIR/secret_reject.json" | awk '{print $1}')"
rm -f "$DEV_APPROVAL_STATE_DIR/proposals/SDA-symlink-attempt-reject-000000000000.json"

echo ""
echo "=== D-series: structural guards (no execution capability) ==="

echo ""
echo "[D1] dev_approval_gate.sh's ACTUAL CODE (comments stripped) never sources security/lib.sh and never references git merge/push, gh pr merge, a deploy tool, or any Guardian/DuCoPA tool by name"
cnt=0
for pattern in 'source security/lib\.sh' 'git merge' 'git push' 'gh pr merge' 'guardian\.sh' 'guardian_intervene' 'guardian_release_agent' 'ducopa\.sh' 'recovery_engine\.sh' '\brecover\.sh' 'launchctl' 'crontab'; do
  c="$(code_only security/self_dev/dev_approval_gate.sh | grep -cE "$pattern" || true)"
  cnt=$((cnt + c))
done
assert_eq "D1 zero actual-code references to any privileged-operation/Control-Plane/cron/launchd tool by name" "0" "$cnt"

echo ""
echo "[D2] zero network tools (curl/wget/nc) and zero process/firewall-modifying commands anywhere in this file's actual code"
bad_calls=0
for pattern in '\b(curl|wget|nc )\b' '\bkill -9\b' '\bkillall\b' '\bpfctl\b' '\bifconfig\b' '\bnetworksetup\b'; do
  c="$(code_only security/self_dev/dev_approval_gate.sh | grep -cE "$pattern" || true)"
  bad_calls=$((bad_calls + c))
done
assert_eq "D2 zero network/modifying-command invocations" "0" "$bad_calls"

echo ""
echo "[D3] this file never shells out on ANY field value it reads from a proposal record -- no eval/double-expansion of a variable holding record content anywhere in actual code (proposed_by/reason are read and returned as text only, see I30 above for the behavioral proof)"
cnt="$(code_only security/self_dev/dev_approval_gate.sh | grep -cE '\beval\b|\$\(\$' || true)"
assert_eq "D3 zero eval / double-expansion constructs in actual code" "0" "$cnt"

echo ""
echo "[D4] *** NO EXECUTION PATH EXISTS *** this CLI implements exactly propose|approve|reject|status|list -- any other verb (in particular anything merge/deploy/apply/execute-shaped) is refused with a usage error, proving an APPROVED record can never, by itself, cause this script to perform the privileged operation it describes"
for bad_verb in apply execute merge deploy run perform; do
  OUT="$($GATE "$bad_verb" "$ID26" 2>&1)"
  RC=$?
  assert_eq "D4 verb '$bad_verb' is not a recognized verb (exit 1)" "1" "$RC"
  assert_contains "D4 verb '$bad_verb' prints the usage message, not an action result" "$OUT" "Usage:"
done

echo ""
echo "[D5] this phase's own scope stayed entirely under security/self_dev/, tests/dev_approval_gate_test.sh, and ARCHITECTURE.md -- no pre-existing file outside that scope has a working-tree diff"
for f in security/lib.sh security/guardian.sh security/ducopa.sh security/red_alert/containment_approval_gate.sh security/red_alert/containment_approval_lib.py; do
  assert_eq "D5 $f has no working-tree diff" "" "$(git diff --name-only -- "$f" 2>/dev/null)"
done

echo ""
echo "=== D-series: audit log + integrity (sourced, standalone hash-chain) ==="

source "$GATE"

echo ""
echo "[D6] *** AUDIT LOG CORRUPTION *** tampering with a past audit-log line is detected by this file's own standalone integrity check, _sda_verify_audit_integrity (ported from containment_approval_gate.sh's own _cag_verify_audit_integrity -- this module had zero audit-integrity coverage of its own before this case)"
AUDIT_FIXTURE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/waio-sda-audit-test.XXXXXX")"
TAMPER_BEFORE="$(DEV_APPROVAL_STATE_DIR="$AUDIT_FIXTURE_DIR/state" DEV_APPROVAL_AUDIT_LOG="$AUDIT_FIXTURE_DIR/audit.jsonl" WAIO_SELF_DEV_APPROVAL_NOW="2026-10-15T00:00:00Z" bash -c "
source '$GATE'
$GATE propose code_analysis feature/demo d6head alice --path foo.py > /dev/null
echo 'BEFORE:'; _sda_verify_audit_integrity
sed -i.bak 's/proposed/proposed_TAMPERED/' '$AUDIT_FIXTURE_DIR/audit.jsonl'
")"
TAMPER_OUT="$(DEV_APPROVAL_STATE_DIR="$AUDIT_FIXTURE_DIR/state" DEV_APPROVAL_AUDIT_LOG="$AUDIT_FIXTURE_DIR/audit.jsonl" bash -c "source '$GATE'; _sda_verify_audit_integrity")"
assert_contains "D6 clean log read 'ok' before tampering" "$TAMPER_BEFORE" "BEFORE:
ok"
assert_contains "D6 corruption detected (broken:...) after tampering" "$TAMPER_OUT" "broken:"
rm -rf "$AUDIT_FIXTURE_DIR"

echo ""
echo "[D7] audit log integrity on a clean, untouched log (this suite's own main fixture, after every prior I-series case) reads 'ok'"
assert_eq "D7 clean log is ok" "ok" "$(_sda_verify_audit_integrity)"

echo ""
echo "=== D-series: HMAC-keyed audit hash chain (DEV_APPROVAL_AUDIT_HMAC_KEY_FILE) ==="

echo ""
echo "[D8] *** KEYED CHAIN ROUND-TRIP *** with DEV_APPROVAL_AUDIT_HMAC_KEY_FILE set, propose writes an HMAC-chained log that a verifier holding the SAME key confirms 'ok'"
HMAC_FIXTURE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/waio-sda-hmac-test.XXXXXX")"
KEY_FILE="$HMAC_FIXTURE_DIR/audit.key"
head -c 32 /dev/urandom > "$KEY_FILE" 2>/dev/null || date +%s%N > "$KEY_FILE"
D8_OUT="$(DEV_APPROVAL_STATE_DIR="$HMAC_FIXTURE_DIR/state" DEV_APPROVAL_AUDIT_LOG="$HMAC_FIXTURE_DIR/audit.jsonl" DEV_APPROVAL_AUDIT_HMAC_KEY_FILE="$KEY_FILE" WAIO_SELF_DEV_APPROVAL_NOW="2026-10-15T00:00:00Z" bash -c "
source '$GATE'
$GATE propose code_analysis feature/demo d8head alice --path foo.py > /dev/null
_sda_verify_audit_integrity
")"
assert_eq "D8 keyed chain, verified WITH the same key, is ok" "ok" "$D8_OUT"

echo ""
echo "[D9] *** KEY-BLIND VERIFIER CANNOT CONFIRM A KEYED CHAIN *** the SAME log from D8, re-verified WITHOUT DEV_APPROVAL_AUDIT_HMAC_KEY_FILE set (plain SHA-256 fallback), reads broken rather than a false 'ok' -- proving the stored chain hash actually depends on the key, fail-closed when the key is absent"
D9_OUT="$(DEV_APPROVAL_STATE_DIR="$HMAC_FIXTURE_DIR/state" DEV_APPROVAL_AUDIT_LOG="$HMAC_FIXTURE_DIR/audit.jsonl" bash -c "source '$GATE'; _sda_verify_audit_integrity")"
assert_contains "D9 key-blind re-verification of a keyed chain is broken, never ok" "$D9_OUT" "broken:"

echo ""
echo "[D10] *** KEYED CHAIN STILL DETECTS TAMPERING *** tampering with a keyed-chain log line is detected by a verifier holding the key, same as the unkeyed D6 case"
sed -i.bak 's/proposed/proposed_TAMPERED/' "$HMAC_FIXTURE_DIR/audit.jsonl"
D10_OUT="$(DEV_APPROVAL_STATE_DIR="$HMAC_FIXTURE_DIR/state" DEV_APPROVAL_AUDIT_LOG="$HMAC_FIXTURE_DIR/audit.jsonl" DEV_APPROVAL_AUDIT_HMAC_KEY_FILE="$KEY_FILE" bash -c "source '$GATE'; _sda_verify_audit_integrity")"
assert_contains "D10 tampering detected even with the correct key present" "$D10_OUT" "broken:"
rm -rf "$HMAC_FIXTURE_DIR"

echo ""
echo "[D11] with DEV_APPROVAL_AUDIT_HMAC_KEY_FILE unset (this suite's own main fixture), the hash chain is unaffected -- same plain-SHA-256 behavior as D7, proving the HMAC path is strictly opt-in and backward compatible"
assert_eq "D11 unkeyed main fixture is still ok after the HMAC cases above" "ok" "$(_sda_verify_audit_integrity)"

echo ""
echo "=== Summary: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
  echo "Failures:"
  for f in "${FAILURES[@]}"; do echo "  - $f"; done
  exit 1
fi
exit 0
