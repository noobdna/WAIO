#!/bin/bash
set -uo pipefail

# tests/containment_approval_gate_test.sh -- regression suite for WAIO
# GLOBAL RED ALERT Phase E: security/red_alert/containment_approval_gate.sh,
# the audit-log-backed CLI wrapper around Phase D's pure library
# (security/red_alert/containment_approval_lib.py). Implements exactly
# five verbs -- request | approve | reject | status | list -- and
# NEVER executes, invokes, or queues a containment action.
#
# Same three-layer convention as the rest of this pipeline's suites:
#   I-series: integration tests against the real CLI/real filesystem,
#     every case running against an isolated
#     CONTAINMENT_APPROVAL_STATE_DIR/AUDIT_LOG and an injected clock
#     (WAIO_CONTAINMENT_APPROVAL_NOW) -- never this deployment's real
#     security/state/containment_approval/.
#   D-series: static structural guards -- zero references to
#     security/lib.sh/Guardian/DuCoPA/decision_engine.sh/cron/launchd
#     by name in actual code, no containment tool ever shelled out on.
#
# This suite exercises REAL concurrency (backgrounded processes, not
# simulated) for its duplicate-request and duplicate-approval races --
# same `& ... wait` technique tests/incident_learning_lock_test.sh's
# own L10 already uses for the lock primitive this file's lock is
# copied from.

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

GATE=./security/red_alert/containment_approval_gate.sh

echo "=== WAIO GLOBAL RED ALERT Phase E regression suite ==="
echo "    (security/red_alert/containment_approval_gate.sh)"

FIXTURE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/waio-cag-test.XXXXXX")"
trap 'rm -rf "$FIXTURE_DIR" /tmp/waio_phaseE_injection_marker*' EXIT

export CONTAINMENT_APPROVAL_STATE_DIR="$FIXTURE_DIR/state"
export CONTAINMENT_APPROVAL_AUDIT_LOG="$FIXTURE_DIR/audit.jsonl"
export WAIO_CONTAINMENT_APPROVAL_NOW="2026-10-12T00:00:00Z"

write_report() {
  # write_report FILE ENTITY SOURCE_MODULES_JSON [RISK]
  local file="$1" entity="$2" modules="$3" risk="${4:-HIGH}"
  cat > "$file" <<EOF
{"generated_at": "2026-10-12T00:00:00Z", "decisions": [
  {"entity": "$entity", "entity_type": "global_patrol_incident", "risk": "$risk", "confidence": "HIGH", "source_modules": $modules, "recommended_action": "RECOMMEND_CONTAINMENT", "reasoning": "fixture"}
]}
EOF
}

REPORT="$FIXTURE_DIR/report.json"

echo ""
echo "=== I-series: request ==="

echo ""
echo "[I1] request: valid, in-scope, multi-source entity -> PENDING record created, correct fields persisted"
write_report "$REPORT" KEV-I1 '["global_patrol", "snd_home_crossref"]'
OUT="$($GATE request "$REPORT" KEV-I1 masa --rollback-tool guardian_release_agent.sh)"
RC=$?
ID1="$(jget "$OUT" "d['approval_id']")"
assert_eq "I1 exit code 0" "0" "$RC"
assert_eq "I1 ok true" "True" "$(jget "$OUT" "d['ok']")"
assert_eq "I1 duplicate false" "False" "$(jget "$OUT" "d['duplicate']")"
assert_eq "I1 status PENDING" "PENDING" "$(jget "$OUT" "d['record']['status']")"
assert_eq "I1 requested_by recorded" "masa" "$(jget "$OUT" "d['record']['requested_by']")"
assert_eq "I1 expires_at = requested_at + 24h default TTL" "2026-10-13T00:00:00Z" "$(jget "$OUT" "d['record']['expires_at']")"
assert_eq "I1 corroboration.multi_source True" "True" "$(jget "$OUT" "d['record']['corroboration']['multi_source']")"
assert_eq "I1b *** PHASE 104 *** corroboration.trusted_local_corroboration False (global_patrol+snd_home_crossref is multi_source but NOT trusted local evidence)" "False" "$(jget "$OUT" "d['record']['corroboration']['trusted_local_corroboration']")"
assert_eq "I1 the record file actually exists on disk" "true" "$([ -f "$CONTAINMENT_APPROVAL_STATE_DIR/approvals/$ID1.json" ] && echo true || echo false)"

echo ""
echo "[I2] *** DUPLICATE REQUEST *** requesting the SAME entity against the SAME report again returns the EXISTING record unchanged -- no second file, no new TTL, logged distinctly"
OUT2="$($GATE request "$REPORT" KEV-I1 masa --rollback-tool guardian_release_agent.sh)"
ID2="$(jget "$OUT2" "d['approval_id']")"
assert_eq "I2 same approval_id returned" "$ID1" "$ID2"
assert_eq "I2 duplicate flag true" "True" "$(jget "$OUT2" "d['duplicate']")"
assert_eq "I2 expires_at unchanged (not re-issued a fresh TTL)" "2026-10-13T00:00:00Z" "$(jget "$OUT2" "d['record']['expires_at']")"

echo ""
echo "[I3] request: out-of-scope entity (non-RED-ALERT source_modules) is refused before any file is written"
write_report "$FIXTURE_DIR/report_oos.json" SHADOW-I3 '["shadow_ai_monitor"]'
OUT="$($GATE request "$FIXTURE_DIR/report_oos.json" SHADOW-I3 masa)"
RC=$?
assert_eq "I3 exit code 3" "3" "$RC"
assert_eq "I3 error out_of_scope" "out_of_scope" "$(jget "$OUT" "d['error']")"
assert_eq "I3 no file was written for this entity" "0" "$(find "$CONTAINMENT_APPROVAL_STATE_DIR/approvals" -name 'CAG-SHADOW-I3-*' | wc -l | tr -d ' ')"

echo ""
echo "[I4] request: missing decision report file -> clear refusal, never a crash"
OUT="$($GATE request "$FIXTURE_DIR/does_not_exist.json" KEV-I4 masa)"
RC=$?
assert_eq "I4 exit code 2" "2" "$RC"
assert_eq "I4 error decision_report_not_found" "decision_report_not_found" "$(jget "$OUT" "d['error']")"

echo ""
echo "[I5] request: malformed decision report (not valid JSON) -> clear refusal, never a crash"
echo 'not json at all { [' > "$FIXTURE_DIR/malformed_report.json"
OUT="$($GATE request "$FIXTURE_DIR/malformed_report.json" KEV-I5 masa)"
RC=$?
assert_eq "I5 exit code 2" "2" "$RC"
assert_eq "I5 error decision_report_malformed" "decision_report_malformed" "$(jget "$OUT" "d['error']")"

echo ""
echo "[I6] request: entity not present in the report's own decisions list -> clear refusal"
write_report "$FIXTURE_DIR/report_i6.json" KEV-REAL '["global_patrol"]'
OUT="$($GATE request "$FIXTURE_DIR/report_i6.json" KEV-NOT-PRESENT masa)"
RC=$?
assert_eq "I6 exit code 2" "2" "$RC"
assert_eq "I6 error entity_not_found" "entity_not_found" "$(jget "$OUT" "d['error']")"

echo ""
echo "[I7] request: missing requested_by identity -> refused, same presence-only check as the pure library, NOT authentication"
write_report "$FIXTURE_DIR/report_i7.json" KEV-I7 '["global_patrol"]'
OUT="$($GATE request "$FIXTURE_DIR/report_i7.json" KEV-I7 "")"
RC=$?
assert_eq "I7 exit code 5" "5" "$RC"
assert_eq "I7 error invalid_requested_by" "invalid_requested_by" "$(jget "$OUT" "d['error']")"

echo ""
echo "=== I-series: approve ==="

echo ""
echo "[I8] approve: TRUSTED-LOCAL-corroborated entity (global_patrol + shadow_ai_monitor -- PHASE 104: two global-only modules would no longer be enough here), valid identity+reason, no exception/rollback needed beyond what was supplied at request -> APPROVED, persisted, audit-logged"
write_report "$FIXTURE_DIR/report_i8.json" KEV-I8 '["global_patrol", "shadow_ai_monitor"]'
OUT="$($GATE request "$FIXTURE_DIR/report_i8.json" KEV-I8 masa --rollback-tool guardian_release_agent.sh)"
ID8="$(jget "$OUT" "d['approval_id']")"
OUT="$($GATE approve "$ID8" masa "investigated this finding thoroughly and confirmed it matches known activity patterns")"
RC=$?
assert_eq "I8 exit code 0" "0" "$RC"
assert_eq "I8 status APPROVED" "APPROVED" "$(jget "$OUT" "d['status']")"
assert_eq "I8 decided_by recorded" "masa" "$(jget "$OUT" "d['record']['decision']['decided_by']")"
PERSISTED="$(cat "$CONTAINMENT_APPROVAL_STATE_DIR/approvals/$ID8.json")"
assert_eq "I8 status persisted to disk as APPROVED" "APPROVED" "$(jget "$PERSISTED" "d['status']")"

echo ""
echo "[I8b] self-approval stays possible on a single-operator host, but is recorded: requested_by == approver -> approver_is_requester true in the record and the audit line"
assert_eq "I8b approver_is_requester true in the output" "True" "$(jget "$OUT" "d['record']['decision']['approver_is_requester']")"
assert_eq "I8b approver_is_requester persisted" "True" "$(jget "$PERSISTED" "d['decision']['approver_is_requester']")"
assert_eq "I8b the approval_granted audit line carries the marker" "True" "$(python3 -c '
import json, sys
hit = False
for line in open(sys.argv[1]):
    try:
        e = json.loads(line)
    except ValueError:
        continue
    if e.get("event_type") == "approval_granted" and e.get("approval_id") == sys.argv[2]:
        hit = (((e.get("detail") or {}).get("record") or {}).get("decision") or {}).get("approver_is_requester") is True
print(hit)' "$CONTAINMENT_APPROVAL_AUDIT_LOG" "$ID8")"

echo ""
echo "[I8c] a different approver (case/whitespace variants of the requester count as the same) -> approver_is_requester false"
write_report "$FIXTURE_DIR/report_i8c.json" KEV-I8C '["global_patrol", "shadow_ai_monitor"]'
OUT="$($GATE request "$FIXTURE_DIR/report_i8c.json" KEV-I8C masa --rollback-tool guardian_release_agent.sh)"
ID8C="$(jget "$OUT" "d['approval_id']")"
OUT="$($GATE approve "$ID8C" operator2 "a second operator reviewed this finding and confirmed it matches known activity")"
assert_eq "I8c approved by a different identity" "APPROVED" "$(jget "$OUT" "d['status']")"
assert_eq "I8c approver_is_requester false" "False" "$(jget "$OUT" "d['record']['decision']['approver_is_requester']")"
write_report "$FIXTURE_DIR/report_i8d.json" KEV-I8D '["global_patrol", "shadow_ai_monitor"]'
OUT="$($GATE request "$FIXTURE_DIR/report_i8d.json" KEV-I8D masa --rollback-tool guardian_release_agent.sh)"
ID8D="$(jget "$OUT" "d['approval_id']")"
OUT="$($GATE approve "$ID8D" " MASA " "the same operator approving under a case and whitespace variant of the name")"
assert_eq "I8c a case/whitespace variant of the requester is still marked as self-approval" "True" "$(jget "$OUT" "d['record']['decision']['approver_is_requester']")"

echo ""
echo "[I9] *** DUPLICATE APPROVAL / INVALID STATE TRANSITION *** approving an already-APPROVED record is refused, record unchanged"
OUT="$($GATE approve "$ID8" operator2 "a second, different approval attempt on an already-decided record")"
RC=$?
assert_eq "I9 exit code 6" "6" "$RC"
assert_eq "I9 error illegal_transition" "illegal_transition" "$(jget "$OUT" "d['error']")"
assert_eq "I9 current_status reported as APPROVED" "APPROVED" "$(jget "$OUT" "d['current_status']")"
assert_eq "I9 decided_by still the FIRST approver, not overwritten" "masa" "$(jget "$(cat "$CONTAINMENT_APPROVAL_STATE_DIR/approvals/$ID8.json")" "d['decision']['decided_by']")"

echo ""
echo "[I10] approve: nonexistent approval_id -> clear refusal"
OUT="$($GATE approve CAG-DOES-NOT-EXIST masa "a reason that is long enough to pass the length check on its own merits")"
RC=$?
assert_eq "I10 exit code 2" "2" "$RC"
assert_eq "I10 error approval_not_found" "approval_not_found" "$(jget "$OUT" "d['error']")"

echo ""
echo "[I11] approve: missing approver identity -> refused via the gate, never approved"
write_report "$FIXTURE_DIR/report_i11.json" KEV-I11 '["global_patrol", "snd_home_crossref"]'
OUT="$($GATE request "$FIXTURE_DIR/report_i11.json" KEV-I11 masa --rollback-tool x)"
ID11="$(jget "$OUT" "d['approval_id']")"
OUT="$($GATE approve "$ID11" "" "a reason that is long enough to pass the length check on its own merits")"
RC=$?
assert_eq "I11 exit code 7 (gate_refused)" "7" "$RC"
assert_contains "I11 violations include missing_identity" "$OUT" "missing_identity"

echo ""
echo "[I12] approve: insufficient reason (too short) -> refused via the gate"
OUT="$($GATE approve "$ID11" masa "short")"
RC=$?
assert_eq "I12 exit code 7" "7" "$RC"
assert_contains "I12 violations include reason_too_short" "$OUT" "reason_too_short"

echo ""
echo "[I13] *** HIGH-IMPACT, NO CORROBORATION, NO EXCEPTION *** single-source entity's approve is refused on the corroboration gate specifically"
write_report "$FIXTURE_DIR/report_i13.json" KEV-I13 '["global_patrol"]'
OUT="$($GATE request "$FIXTURE_DIR/report_i13.json" KEV-I13 masa --rollback-tool guardian_release_agent.sh)"
ID13="$(jget "$OUT" "d['approval_id']")"
OUT="$($GATE approve "$ID13" masa "investigated this finding thoroughly and confirmed it matches known activity patterns")"
RC=$?
assert_eq "I13 exit code 7" "7" "$RC"
assert_contains "I13 violations include refused_no_local_corroboration_no_exception" "$OUT" "refused_no_local_corroboration_no_exception"

echo ""
echo "[I14] *** VALID EXCEPTION PATH *** the SAME single-source entity, now with a sufficient, DISTINCT exception rationale -> allowed"
OUT="$($GATE approve "$ID13" masa "investigated this finding thoroughly and confirmed it matches known activity patterns" "independently cross-referenced against a separate external vendor advisory received this same morning")"
RC=$?
assert_eq "I14 exit code 0" "0" "$RC"
assert_eq "I14 status APPROVED" "APPROVED" "$(jget "$OUT" "d['status']")"
assert_contains "I14 exception_reason persisted" "$(cat "$CONTAINMENT_APPROVAL_STATE_DIR/approvals/$ID13.json")" "independently cross-referenced"

echo ""
echo "[I15] *** NO SHORT-CIRCUIT *** single-source entity, NO rollback metadata at request time, valid exception at approve time -> corroboration passes but rollback independently refused, BOTH violations reported"
write_report "$FIXTURE_DIR/report_i15.json" KEV-I15 '["global_patrol"]'
OUT="$($GATE request "$FIXTURE_DIR/report_i15.json" KEV-I15 masa)"
ID15="$(jget "$OUT" "d['approval_id']")"
OUT="$($GATE approve "$ID15" masa "investigated this finding thoroughly and confirmed it matches known activity patterns" "independently cross-referenced against a separate external vendor advisory received this same morning")"
RC=$?
assert_eq "I15 exit code 7" "7" "$RC"
assert_contains "I15 violations include refused_rollback_unavailable" "$OUT" "refused_rollback_unavailable"
assert_eq "I15 violations do NOT include the corroboration refusal (it passed)" "0" "$(jget "$OUT" "int('refused_no_local_corroboration_no_exception' in d['violations'])")"

echo ""
echo "[I16] *** MISSING/ALTERED EVIDENCE *** approving after the underlying decision report file has been edited since request is refused, even with an otherwise-valid exception+rollback"
write_report "$FIXTURE_DIR/report_i16.json" KEV-I16 '["global_patrol"]'
OUT="$($GATE request "$FIXTURE_DIR/report_i16.json" KEV-I16 masa --rollback-tool guardian_release_agent.sh)"
ID16="$(jget "$OUT" "d['approval_id']")"
python3 -c "
import json
d = json.load(open('$FIXTURE_DIR/report_i16.json'))
d['decisions'][0]['risk'] = 'CRITICAL'
json.dump(d, open('$FIXTURE_DIR/report_i16.json', 'w'))
"
OUT="$($GATE approve "$ID16" masa "investigated this finding thoroughly and confirmed it matches known activity patterns" "independently cross-referenced against a separate external vendor advisory received this same morning")"
RC=$?
assert_eq "I16 exit code 7" "7" "$RC"
assert_contains "I16 violations include evidence_altered_or_missing" "$OUT" "evidence_altered_or_missing"

echo ""
echo "[I17] *** MISSING EVIDENCE (file deleted entirely) *** approving when the underlying report file no longer exists at all is refused the same way as an altered one"
write_report "$FIXTURE_DIR/report_i17.json" KEV-I17 '["global_patrol", "snd_home_crossref"]'
OUT="$($GATE request "$FIXTURE_DIR/report_i17.json" KEV-I17 masa --rollback-tool x)"
ID17="$(jget "$OUT" "d['approval_id']")"
rm -f "$FIXTURE_DIR/report_i17.json"
OUT="$($GATE approve "$ID17" masa "investigated this finding thoroughly and confirmed it matches known activity patterns")"
RC=$?
assert_eq "I17 exit code 7" "7" "$RC"
assert_contains "I17 violations include evidence_altered_or_missing" "$OUT" "evidence_altered_or_missing"

echo ""
echo "=== I-series: reject ==="

echo ""
echo "[I18] reject: valid identity+reason -> REJECTED, terminal"
write_report "$FIXTURE_DIR/report_i18.json" KEV-I18 '["global_patrol"]'
OUT="$($GATE request "$FIXTURE_DIR/report_i18.json" KEV-I18 masa)"
ID18="$(jget "$OUT" "d['approval_id']")"
OUT="$($GATE reject "$ID18" masa "reviewed this finding and determined it is a known false positive from this source")"
RC=$?
assert_eq "I18 exit code 0" "0" "$RC"
assert_eq "I18 status REJECTED" "REJECTED" "$(jget "$OUT" "d['status']")"

echo ""
echo "[I19] *** REJECTED ACTION IS TERMINAL *** approving an already-REJECTED record is refused"
OUT="$($GATE approve "$ID18" masa "trying to approve this anyway after it was already rejected")"
RC=$?
assert_eq "I19 exit code 6" "6" "$RC"
assert_eq "I19 error illegal_transition" "illegal_transition" "$(jget "$OUT" "d['error']")"

echo ""
echo "[I20] reject: insufficient reason -> refused, record stays PENDING"
write_report "$FIXTURE_DIR/report_i20.json" KEV-I20 '["global_patrol"]'
OUT="$($GATE request "$FIXTURE_DIR/report_i20.json" KEV-I20 masa)"
ID20="$(jget "$OUT" "d['approval_id']")"
OUT="$($GATE reject "$ID20" masa "no")"
RC=$?
assert_eq "I20 exit code 8" "8" "$RC"
assert_eq "I20 record still PENDING" "PENDING" "$(jget "$(cat "$CONTAINMENT_APPROVAL_STATE_DIR/approvals/$ID20.json")" "d['status']")"

echo ""
echo "=== I-series: approval expiry (boundaries, injected clock) ==="

echo ""
echo "[I21] *** EXPIRY BOUNDARY *** a PENDING approval past its own expires_at is refused on approve with error illegal_transition/current_status=EXPIRED, and EXPIRED is persisted to disk as a side effect of the access"
export CONTAINMENT_APPROVAL_TTL_SECONDS=3600
write_report "$FIXTURE_DIR/report_i21.json" KEV-I21 '["global_patrol", "snd_home_crossref"]'
OUT="$($GATE request "$FIXTURE_DIR/report_i21.json" KEV-I21 masa --rollback-tool x)"
ID21="$(jget "$OUT" "d['approval_id']")"
EXPIRES_AT="$(jget "$OUT" "d['record']['expires_at']")"
assert_eq "I21 TTL respected (1h from 00:00 is 01:00)" "2026-10-12T01:00:00Z" "$EXPIRES_AT"
export WAIO_CONTAINMENT_APPROVAL_NOW="2026-10-12T01:00:01Z"
OUT="$($GATE approve "$ID21" masa "investigated this finding thoroughly and confirmed it matches known activity patterns")"
RC=$?
assert_eq "I21 exit code 6" "6" "$RC"
assert_eq "I21 current_status EXPIRED" "EXPIRED" "$(jget "$OUT" "d['current_status']")"
assert_eq "I21 EXPIRED persisted to disk" "EXPIRED" "$(jget "$(cat "$CONTAINMENT_APPROVAL_STATE_DIR/approvals/$ID21.json")" "d['status']")"
unset CONTAINMENT_APPROVAL_TTL_SECONDS
export WAIO_CONTAINMENT_APPROVAL_NOW="2026-10-12T00:00:00Z"

echo ""
echo "[I21b] an APPROVED record past its own expires_at reads effective_status EXPIRED in status and list (stored status stays APPROVED)"
export CONTAINMENT_APPROVAL_TTL_SECONDS=3600
write_report "$FIXTURE_DIR/report_i21b.json" KEV-I21B '["global_patrol", "shadow_ai_monitor"]'
ID21B="$(jget "$($GATE request "$FIXTURE_DIR/report_i21b.json" KEV-I21B masa --rollback-tool x)" "d['approval_id']")"
unset CONTAINMENT_APPROVAL_TTL_SECONDS
$GATE approve "$ID21B" masa "investigated this finding thoroughly and confirmed it matches known activity patterns" >/dev/null
assert_eq "I21b before expires_at: APPROVED" "APPROVED" "$(jget "$($GATE status "$ID21B")" "d['effective_status']")"
SUM21B="$(shasum -a 256 "$CONTAINMENT_APPROVAL_STATE_DIR/approvals/$ID21B.json")"
export WAIO_CONTAINMENT_APPROVAL_NOW="2026-10-12T01:00:00Z"
assert_eq "I21b at expires_at: status EXPIRED" "EXPIRED" "$(jget "$($GATE status "$ID21B")" "d['effective_status']")"
assert_eq "I21b stored_status still APPROVED" "APPROVED" "$(jget "$($GATE status "$ID21B")" "d['stored_status']")"
assert_eq "I21b list --status APPROVED excludes it" "False" "$(jget "$($GATE list --status APPROVED)" "any(e['approval_id'] == '$ID21B' for e in d['entries'])")"
assert_eq "I21b record file not rewritten" "$SUM21B" "$(shasum -a 256 "$CONTAINMENT_APPROVAL_STATE_DIR/approvals/$ID21B.json")"
export WAIO_CONTAINMENT_APPROVAL_NOW="2026-10-12T00:00:00Z"

echo ""
echo "=== I-series: status / list (read-only) ==="

echo ""
echo "[I22] status: nonexistent approval_id -> clear refusal, never a crash"
OUT="$($GATE status CAG-DOES-NOT-EXIST)"
RC=$?
assert_eq "I22 exit code 2" "2" "$RC"
assert_eq "I22 error approval_not_found" "approval_not_found" "$(jget "$OUT" "d['error']")"

echo ""
echo "[I23] status: read-only -- calling it twice never mutates a PENDING-but-not-yet-expired record"
write_report "$FIXTURE_DIR/report_i23.json" KEV-I23 '["global_patrol"]'
OUT="$($GATE request "$FIXTURE_DIR/report_i23.json" KEV-I23 masa)"
ID23="$(jget "$OUT" "d['approval_id']")"
HASH_BEFORE="$(shasum -a 256 "$CONTAINMENT_APPROVAL_STATE_DIR/approvals/$ID23.json" | awk '{print $1}')"
$GATE status "$ID23" > /dev/null
$GATE status "$ID23" > /dev/null
HASH_AFTER="$(shasum -a 256 "$CONTAINMENT_APPROVAL_STATE_DIR/approvals/$ID23.json" | awk '{print $1}')"
assert_eq "I23 record file byte-identical before/after two status calls" "$HASH_BEFORE" "$HASH_AFTER"

echo ""
echo "[I24] list: --status filter returns only matching entries"
OUT="$($GATE list --status PENDING)"
assert_eq "I24 KEV-I23's approval is among PENDING" "True" "$(jget "$OUT" "any(e['entity'] == 'KEV-I23' for e in d['entries'])")"
OUT="$($GATE list --status APPROVED)"
assert_eq "I24 KEV-I8's approval is among APPROVED, not PENDING" "True" "$(jget "$OUT" "any(e['entity'] == 'KEV-I8' for e in d['entries'])")"

echo ""
echo "[I25] *** MALFORMED RECORD ON DISK *** a corrupted approval file is refused cleanly (status/approve/reject), and list reports it as corrupt rather than crashing the whole listing"
write_report "$FIXTURE_DIR/report_i25.json" KEV-I25 '["global_patrol"]'
OUT="$($GATE request "$FIXTURE_DIR/report_i25.json" KEV-I25 masa)"
ID25="$(jget "$OUT" "d['approval_id']")"
echo 'this is not valid json at all' > "$CONTAINMENT_APPROVAL_STATE_DIR/approvals/$ID25.json"
OUT="$($GATE status "$ID25")"
RC=$?
assert_eq "I25 status exit code 4" "4" "$RC"
assert_eq "I25 status error record_corrupt" "record_corrupt" "$(jget "$OUT" "d['error']")"
OUT="$($GATE approve "$ID25" masa "investigated this finding thoroughly and confirmed it matches known activity patterns")"
RC=$?
assert_eq "I25 approve exit code 4" "4" "$RC"
OUT="$($GATE list)"
assert_eq "I25 list reports the corrupt file by name, never crashes" "True" "$(jget "$OUT" "any('$ID25' in c['path'] for c in d['corrupt'])")"

echo ""
echo "=== I-series: safe persistence (failure path) ==="

echo ""
echo "[I26] *** PERSISTENCE FAILURE *** an unwritable state-directory location is detected and refused cleanly before any python logic runs, never a partial write"
RO_PARENT="$(mktemp -d)"
chmod 555 "$RO_PARENT"
OUT="$(CONTAINMENT_APPROVAL_STATE_DIR="$RO_PARENT/nope/state" CONTAINMENT_APPROVAL_AUDIT_LOG="$RO_PARENT/nope/audit.jsonl" $GATE request "$REPORT" KEV-I1 masa 2>&1)"
RC=$?
assert_eq "I26 non-zero exit" "1" "$RC"
assert_contains "I26 clear error message naming safe persistence" "$OUT" "refusing to proceed without safe persistence"
chmod 755 "$RO_PARENT"
rm -rf "$RO_PARENT"

echo ""
echo "=== I-series: concurrency (REAL backgrounded processes) ==="

echo ""
echo "[I27] *** CONCURRENT DUPLICATE REQUESTS *** two processes requesting the SAME entity+evidence at once still produce exactly ONE record, serialized by the per-entity lock"
write_report "$FIXTURE_DIR/report_i27.json" KEV-I27 '["global_patrol"]'
$GATE request "$FIXTURE_DIR/report_i27.json" KEV-I27 masa > "$FIXTURE_DIR/i27_a.json" 2>&1 &
PID_A=$!
$GATE request "$FIXTURE_DIR/report_i27.json" KEV-I27 masa > "$FIXTURE_DIR/i27_b.json" 2>&1 &
PID_B=$!
wait "$PID_A"; RC_A=$?
wait "$PID_B"; RC_B=$?
assert_eq "I27 both processes exit 0" "0 0" "$RC_A $RC_B"
ID_A="$(jget "$(cat "$FIXTURE_DIR/i27_a.json")" "d['approval_id']")"
ID_B="$(jget "$(cat "$FIXTURE_DIR/i27_b.json")" "d['approval_id']")"
assert_eq "I27 both got the SAME approval_id" "$ID_A" "$ID_B"
assert_eq "I27 exactly one is the real request, the other a detected duplicate" "True" "$([ "$(jget "$(cat "$FIXTURE_DIR/i27_a.json")" "d['duplicate']")" != "$(jget "$(cat "$FIXTURE_DIR/i27_b.json")" "d['duplicate']")" ] && echo True || echo False)"

echo ""
echo "[I28] *** CONCURRENT DUPLICATE APPROVALS *** two processes approving the SAME PENDING record at once: exactly one succeeds, the other sees illegal_transition -- never both APPROVED, never neither"
write_report "$FIXTURE_DIR/report_i28.json" KEV-I28 '["global_patrol", "shadow_ai_monitor"]'
OUT="$($GATE request "$FIXTURE_DIR/report_i28.json" KEV-I28 masa --rollback-tool guardian_release_agent.sh)"
ID28="$(jget "$OUT" "d['approval_id']")"
$GATE approve "$ID28" masa "first of two concurrent approve attempts racing for this exact record" > "$FIXTURE_DIR/i28_a.json" 2>&1 &
PID_A=$!
$GATE approve "$ID28" operator2 "second of two concurrent approve attempts racing for this exact record" > "$FIXTURE_DIR/i28_b.json" 2>&1 &
PID_B=$!
wait "$PID_A"; RC_A=$?
wait "$PID_B"; RC_B=$?
assert_eq "I28 exactly one success, one illegal_transition (rc 0 and 6, in either order)" "True" "$([ "$(( (RC_A==0) + (RC_B==0) ))" -eq 1 ] && [ "$(( (RC_A==6) + (RC_B==6) ))" -eq 1 ] && echo True || echo False)"
assert_eq "I28 final persisted status is APPROVED exactly once, never duplicated/lost" "APPROVED" "$(jget "$(cat "$CONTAINMENT_APPROVAL_STATE_DIR/approvals/$ID28.json")" "d['status']")"

echo ""
echo "=== I-series: untrusted strings (injection safety, full CLI) ==="

echo ""
echo "[I29] *** INJECTION SAFETY *** a shell-metacharacter-laden proposed_tool/rollback_tool/reason is NEVER executed anywhere in request/approve -- stored and returned as inert text only"
rm -f /tmp/waio_phaseE_injection_marker
write_report "$FIXTURE_DIR/report_i29.json" KEV-I29 '["global_patrol", "snd_home_crossref"]'
MALICIOUS='guardian_release_agent.sh; touch /tmp/waio_phaseE_injection_marker ; `touch /tmp/waio_phaseE_injection_marker2`'
OUT="$($GATE request "$FIXTURE_DIR/report_i29.json" KEV-I29 masa --proposed-tool "$MALICIOUS" --rollback-tool "$MALICIOUS")"
ID29="$(jget "$OUT" "d['approval_id']")"
assert_eq "I29 no marker file created by request" "absent" "$([ -e /tmp/waio_phaseE_injection_marker ] && echo present || echo absent)"
OUT="$($GATE approve "$ID29" masa "$MALICIOUS this reason is padded out with enough additional text to pass the length check cleanly")"
assert_eq "I29 no marker file created by approve" "absent" "$([ -e /tmp/waio_phaseE_injection_marker ] && echo present || echo absent)"
assert_contains "I29 the malicious string is stored verbatim as inert text in the persisted record" "$(cat "$CONTAINMENT_APPROVAL_STATE_DIR/approvals/$ID29.json")" "touch /tmp/waio_phaseE_injection_marker"
rm -f /tmp/waio_phaseE_injection_marker /tmp/waio_phaseE_injection_marker2

echo ""
echo "=== D-series: audit log + integrity (sourced, standalone hash-chain) ==="

source "$GATE"

echo ""
echo "[D1] *** AUDIT LOG CORRUPTION *** tampering with a past audit-log line is detected by this file's own standalone integrity check"
AUDIT_FIXTURE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/waio-cag-audit-test.XXXXXX")"
CONTAINMENT_APPROVAL_STATE_DIR="$AUDIT_FIXTURE_DIR/state" CONTAINMENT_APPROVAL_AUDIT_LOG="$AUDIT_FIXTURE_DIR/audit.jsonl" WAIO_CONTAINMENT_APPROVAL_NOW="2026-10-12T00:00:00Z" bash -c "
source '$GATE'
write_report() { cat > \"\$1\" <<EOF
{\"generated_at\": \"2026-10-12T00:00:00Z\", \"decisions\": [{\"entity\": \"\$2\", \"risk\": \"HIGH\", \"confidence\": \"HIGH\", \"source_modules\": [\"global_patrol\"], \"recommended_action\": \"RECOMMEND_CONTAINMENT\", \"reasoning\": \"fixture\"}]}
EOF
}
write_report '$AUDIT_FIXTURE_DIR/r.json' KEV-D1
cag_request '$AUDIT_FIXTURE_DIR/r.json' KEV-D1 masa > /dev/null
echo 'BEFORE:'; _cag_verify_audit_integrity
sed -i.bak 's/approval_requested/approval_requested_TAMPERED/' '$AUDIT_FIXTURE_DIR/audit.jsonl'
echo 'AFTER:'; _cag_verify_audit_integrity
"
TAMPER_OUT="$(CONTAINMENT_APPROVAL_STATE_DIR="$AUDIT_FIXTURE_DIR/state" CONTAINMENT_APPROVAL_AUDIT_LOG="$AUDIT_FIXTURE_DIR/audit.jsonl" bash -c "source '$GATE'; _cag_verify_audit_integrity")"
assert_contains "D1 corruption detected (broken:...)" "$TAMPER_OUT" "broken:"
rm -rf "$AUDIT_FIXTURE_DIR"

echo ""
echo "[D2] audit log integrity on a clean, untouched log reads 'ok'"
assert_eq "D2 clean log is ok" "ok" "$(_cag_verify_audit_integrity)"

echo ""
echo "=== D-series: structural guards ==="

echo ""
echo "[D3] containment_approval_gate.sh's ACTUAL CODE (comments stripped) never sources security/lib.sh and never references any Guardian/DuCoPA/recovery/promotion/Human-Gate tool by name, or decision_engine.sh itself"
cnt=0
for pattern in 'source security/lib\.sh' 'guardian\.sh' 'guardian_intervene' 'guardian_release_agent' 'guardian_approve\.sh' 'ducopa\.sh' 'recovery_engine\.sh' '\brecover\.sh' 'knowledge_manager\.sh' 'incident_human_gate\.sh' 'decision_engine\.sh' 'decision_engine_lib' 'launchctl' 'crontab'; do
  c="$(code_only security/red_alert/containment_approval_gate.sh | grep -cE "$pattern" || true)"
  cnt=$((cnt + c))
done
assert_eq "D3 zero actual-code references to any Control-Plane/Decision-Engine/cron/launchd tool by name" "0" "$cnt"

echo ""
echo "[D4] zero network tools (curl/wget/nc) and zero process/firewall-modifying commands anywhere in this file's actual code"
bad_calls=0
for pattern in '\b(curl|wget|nc )\b' '\bkill -9\b' '\bkillall\b' '\bpfctl\b' '\bifconfig\b' '\bnetworksetup\b'; do
  c="$(code_only security/red_alert/containment_approval_gate.sh | grep -cE "$pattern" || true)"
  bad_calls=$((bad_calls + c))
done
assert_eq "D4 zero network/modifying-command invocations" "0" "$bad_calls"

echo ""
echo "[D5] this file never shells out on ANY field value it reads from an approval record or decision report -- no eval/exec of a variable holding record content anywhere in actual code (proposed_tool/rollback_tool are read and returned as text only, see I29 above for the behavioral proof)"
cnt="$(code_only security/red_alert/containment_approval_gate.sh | grep -cE '\beval\b|\$\(\$' || true)"
assert_eq "D5 zero eval / double-expansion constructs in actual code" "0" "$cnt"

echo ""
echo "[D6] every other existing file this phase was told to leave alone remains byte-for-byte unmodified. (security/decision_engine/decision_engine.sh, decision_engine_lib.py, AND security/red_alert/containment_approval_lib.py are DELIBERATELY EXCLUDED from this list as of ARCHITECTURE.md Phase 104: that phase intentionally extends decide_for_profile()'s own safety gate AND this gate's own corroboration_satisfied() together, on their own documented merits -- see tests/containment_approval_lib_test.sh's own D5 for the matching exclusion and rationale.)"
for f in security/lib.sh security/intelligence/intelligence_lib.py security/red_alert/red_alert_adapter.py security/red_alert/snd_crossref.py security/red_alert/red_alert_cron.sh security/guardian.sh security/ducopa.sh; do
  assert_eq "D6 $f has no working-tree diff" "" "$(git diff --name-only -- "$f" 2>/dev/null)"
done

echo ""
echo "[D7] no new file this phase was created under security/decision_engine/, security/guardian*, or security/ducopa.sh's own directory -- this effort stays entirely under security/red_alert/"
assert_eq "D7 security/decision_engine/ contains only its own two pre-existing files" "decision_engine.sh decision_engine_lib.py" "$(ls security/decision_engine/ | sort | tr '\n' ' ' | sed 's/ $//')"

echo ""
echo "=== H-series: APPROVAL_ID path-traversal / symlink hardening (SECURITY FIX, post-audit) ==="
echo "    regression coverage for the read/write/delete PoCs confirmed during the post-PR-160 security audit"

OUTSIDE_DIR="$FIXTURE_DIR/outside"
mkdir -p "$OUTSIDE_DIR"
# Relative to APPROVALS_DIR ($FIXTURE_DIR/state/approvals) and to
# LOCKS_DIR ($FIXTURE_DIR/state/.locks), both exactly two levels below
# $FIXTURE_DIR, "../../outside/X" resolves to "$OUTSIDE_DIR/X" --
# the exact traversal shape the real audit PoC used against both.
EMPTY_REPORT_HASH="sha256:$(python3 -c "import json,hashlib; print(hashlib.sha256(json.dumps({}, sort_keys=True, ensure_ascii=False).encode('utf-8')).hexdigest())")"

echo ""
echo "[H1] *** READ PoC, FIXED *** status with a path-traversal APPROVAL_ID is refused (invalid_approval_id) and never reads a file outside approvals_dir"
cat > "$OUTSIDE_DIR/h1_secret.json" <<'EOF'
{"DO_NOT_LEAK_MARKER": "h1-secret-content-outside-approvals-dir", "status": "PENDING"}
EOF
OUT="$($GATE status "../../outside/h1_secret")"
RC=$?
assert_eq "H1 exit code 10" "10" "$RC"
assert_eq "H1 error invalid_approval_id" "invalid_approval_id" "$(jget "$OUT" "d['error']")"
assert_eq "H1 the outside secret marker never appears in the output" "False" "$([[ "$OUT" == *"h1-secret-content"* ]] && echo True || echo False)"

echo ""
echo "[H2] *** WRITE/OVERWRITE PoC, FIXED *** approve with a path-traversal APPROVAL_ID targeting an outside record that would otherwise satisfy every evaluate_approval gate is refused, and the outside file is left byte-for-byte unchanged"
cat > "$OUTSIDE_DIR/h2_secret.json" <<EOF
{"DO_NOT_LEAK_MARKER": "h2-secret-content", "status": "PENDING",
 "decision_record_ref": {"entity": "h2-victim", "source_modules": ["global_patrol"], "recommended_action": "MONITOR", "risk": "LOW", "decision_report_path": null, "decision_report_hash": "$EMPTY_REPORT_HASH"},
 "expires_at": "2099-01-01T00:00:00Z", "rollback": {}}
EOF
HASH_BEFORE_H2="$(shasum -a 256 "$OUTSIDE_DIR/h2_secret.json" | awk '{print $1}')"
OUT="$($GATE approve "../../outside/h2_secret" masa "this reason is padded out with enough additional text to pass the length check cleanly")"
RC=$?
assert_eq "H2 exit code 10" "10" "$RC"
assert_eq "H2 error invalid_approval_id" "invalid_approval_id" "$(jget "$OUT" "d['error']")"
assert_eq "H2 outside file byte-identical before/after the attempt" "$HASH_BEFORE_H2" "$(shasum -a 256 "$OUTSIDE_DIR/h2_secret.json" | awk '{print $1}')"

echo ""
echo "[H3] *** WRITE/OVERWRITE PoC (reject), FIXED *** reject with the same path-traversal APPROVAL_ID is refused identically, outside file unchanged"
HASH_BEFORE_H3="$(shasum -a 256 "$OUTSIDE_DIR/h2_secret.json" | awk '{print $1}')"
OUT="$($GATE reject "../../outside/h2_secret" masa "reviewed this finding and determined it is unrelated to any real activity")"
RC=$?
assert_eq "H3 exit code 10" "10" "$RC"
assert_eq "H3 error invalid_approval_id" "invalid_approval_id" "$(jget "$OUT" "d['error']")"
assert_eq "H3 outside file byte-identical before/after the attempt" "$HASH_BEFORE_H3" "$(shasum -a 256 "$OUTSIDE_DIR/h2_secret.json" | awk '{print $1}')"

echo ""
echo "[H4] *** DIRECTORY-DELETE PoC, FIXED *** approve with a path-traversal APPROVAL_ID targeting a pre-existing, stale, lock-shaped directory OUTSIDE locks_dir is refused BEFORE _cag_lock_acquire ever runs -- the directory and its contents survive"
mkdir -p "$OUTSIDE_DIR/h4_victim_dir.lock"
echo "irreplaceable victim content" > "$OUTSIDE_DIR/h4_victim_dir.lock/important_file.txt"
touch -t 202601010000 "$OUTSIDE_DIR/h4_victim_dir.lock"
OUT="$($GATE approve "../../outside/h4_victim_dir" masa "this reason is padded out with enough additional text to pass the length check cleanly")"
RC=$?
assert_eq "H4 exit code 10" "10" "$RC"
assert_eq "H4 error invalid_approval_id" "invalid_approval_id" "$(jget "$OUT" "d['error']")"
assert_eq "H4 the victim directory still exists" "true" "$([ -d "$OUTSIDE_DIR/h4_victim_dir.lock" ] && echo true || echo false)"
assert_eq "H4 the victim file inside it still exists with its original content" "irreplaceable victim content" "$(cat "$OUTSIDE_DIR/h4_victim_dir.lock/important_file.txt" 2>/dev/null)"

echo ""
echo "[H5] *** MALFORMED APPROVAL_ID BATTERY *** every non-charset-conforming id is refused cleanly (exit 10, invalid_approval_id) by approve/reject/status alike, never a crash -- a legitimate generated id is unaffected"
write_report "$FIXTURE_DIR/report_h5.json" KEV-H5 '["global_patrol", "shadow_ai_monitor"]'
OUT="$($GATE request "$FIXTURE_DIR/report_h5.json" KEV-H5 masa --rollback-tool guardian_release_agent.sh)"
ID_H5="$(jget "$OUT" "d['approval_id']")"
for bad_id in "" "a b" "a;b" "a/b" "/etc/passwd" "../x" "$(python3 -c "print('a'*201)")"; do
  OUT="$($GATE status "$bad_id" 2>&1)"
  RC=$?
  assert_eq "H5 status refuses malformed id '$bad_id' (exit 10)" "10" "$RC"
done
OUT="$($GATE approve "../x" masa "this reason is padded out with enough additional text to pass the length check cleanly" 2>&1)"
RC=$?
assert_eq "H5 approve also refuses a malformed id (exit 10, same as status)" "10" "$RC"
OUT="$($GATE reject "a;b" masa "reviewed this finding and determined it is unrelated to any real activity" 2>&1)"
RC=$?
assert_eq "H5 reject also refuses a malformed id (exit 10, same as status)" "10" "$RC"
OUT="$($GATE approve "$ID_H5" masa "this reason is padded out with enough additional text to pass the length check cleanly")"
RC=$?
assert_eq "H5 the legitimately-generated id is still accepted (unaffected by the hardening)" "0" "$RC"
assert_eq "H5 legitimate approve actually succeeded" "APPROVED" "$(jget "$OUT" "d['status']")"

echo ""
echo "[H6] *** SYMLINK-INSIDE-APPROVALS_DIR, FIXED *** a symlink planted directly inside approvals_dir, under an otherwise charset-valid name, pointing outside approvals_dir is refused by the realpath containment check -- status never reads through it"
ln -s "$OUTSIDE_DIR/h1_secret.json" "$CONTAINMENT_APPROVAL_STATE_DIR/approvals/CAG-symlink-attempt-000000000000.json"
OUT="$($GATE status "CAG-symlink-attempt-000000000000")"
RC=$?
assert_eq "H6 exit code 10 (symlink target rejected, not followed)" "10" "$RC"
assert_eq "H6 error invalid_approval_id" "invalid_approval_id" "$(jget "$OUT" "d['error']")"
assert_eq "H6 the symlinked-to secret content never appears in the output" "False" "$([[ "$OUT" == *"h1-secret-content"* ]] && echo True || echo False)"
rm -f "$CONTAINMENT_APPROVAL_STATE_DIR/approvals/CAG-symlink-attempt-000000000000.json"

echo ""
echo "=== Summary: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
  echo "Failures:"
  for f in "${FAILURES[@]}"; do echo "  - $f"; done
  exit 1
fi
exit 0
