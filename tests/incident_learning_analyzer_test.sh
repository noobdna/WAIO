#!/bin/bash
set -uo pipefail

# tests/incident_learning_analyzer_test.sh -- regression suite for
# Incident Learning Engine Step 5 (Phase 75):
# security/incident_learning/incident_analyzer.sh (VERIFIED->ANALYZED
# or VERIFIED->REJECTED).
#
# Before this phase, VERIFIED->ANALYZED was incident_evidence.sh's own
# hardcoded placeholder (no real duplicate/pattern check ever ran --
# see tests/incident_learning_evidence_test.sh's own history and
# ARCHITECTURE.md Phase 74's "known, already-documented limitations").
# This suite exercises the real logic this phase adds: comparison
# against already-PROMOTED security/knowledge/ entries only (never
# against other in-flight candidates -- see incident_analyzer.sh's own
# header for why), covering all three duplicate signals (CVE overlap,
# IOC overlap, same source_url) plus the narrower "contamination"
# signal (byte-identical raw_text), the clean pass-through case, skip/
# idempotency, and graceful handling of an unreadable knowledge file.
#
# Same fixture-sandbox pattern as every other
# tests/incident_learning_*_test.sh: KNOWLEDGE_MANAGER_STATE_DIR/
# KNOWLEDGE_MANAGER_AUDIT_LOG/KNOWLEDGE_MANAGER_KNOWLEDGE_DIR overrides
# mean this suite never reads or writes this deployment's real
# security/state/incident_learning/ or security/knowledge/. A1 builds
# its "already-promoted" fixture via the real pipeline end to end
# (create -> normalize -> evidence -> analyze -> confidence -> approve
# -> promote); A2-A5 write a hand-crafted knowledge JSON file directly
# (same test-only technique tests/incident_learning_failsafe_test.sh's
# own R2 case already uses) to isolate each duplicate-detection branch
# without re-running the whole upstream pipeline for each one.

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

FIXTURE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/waio-incident-analyzer-test.XXXXXX")"
trap 'rm -rf "$FIXTURE_DIR"; true' EXIT

mkdir -p "$FIXTURE_DIR/candidates" "$FIXTURE_DIR/knowledge"
export KNOWLEDGE_MANAGER_STATE_DIR="$FIXTURE_DIR/candidates"
export KNOWLEDGE_MANAGER_AUDIT_LOG="$FIXTURE_DIR/incident-learning-audit.jsonl"
export KNOWLEDGE_MANAGER_KNOWLEDGE_DIR="$FIXTURE_DIR/knowledge"

km() { bash security/incident_learning/knowledge_manager.sh "$@"; }
hg() { bash security/incident_learning/incident_human_gate.sh "$@"; }
evidence() { bash security/incident_learning/incident_evidence.sh "$@"; }
analyzer() { bash security/incident_learning/incident_analyzer.sh "$@"; }
field() { python3 -c "import json; print(json.load(open('$FIXTURE_DIR/candidates/$1.json')).get('$2',''))"; }
audit_events_for() { grep "\"candidate_id\": \"$1\"" "$FIXTURE_DIR/incident-learning-audit.jsonl" | python3 -c "import json,sys; [print(json.loads(l)['event']) for l in sys.stdin]"; }
audit_count() { wc -l < "$FIXTURE_DIR/incident-learning-audit.jsonl" | tr -d ' '; }

# write_knowledge ID [KEY=VALUE ...] -- test-only helper, writes a
# hand-crafted "already-promoted" knowledge JSON file directly (never
# something a real code path does -- knowledge_promote() is the only
# real writer into this directory). Exists purely to isolate one
# duplicate-detection branch at a time without re-running the whole
# upstream pipeline for each case.
write_knowledge() {
  local id="$1"; shift
  python3 -c "
import json, sys
d = {'id': sys.argv[1]}
for kv in sys.argv[2:]:
    k, _, v = kv.partition('=')
    try:
        d[k] = json.loads(v)
    except (json.JSONDecodeError, ValueError):
        d[k] = v
json.dump(d, open('$FIXTURE_DIR/knowledge/' + sys.argv[1] + '.json', 'w'))
" "$id" "$@"
}

echo "=== Incident Learning Engine (Step 5: incident_analyzer.sh) regression suite ==="

echo ""
echo "[A1] end-to-end: a candidate reaches VERIFIED via the real pipeline, is promoted for real, then a SECOND candidate sharing its CVE is correctly REJECTED as a duplicate of the real promoted entry (not a hand-crafted fixture)"
km create A1_ORIG mock_collector "source_type=vendor_advisory" "source_url=https://example.invalid/a1-orig" "raw_text=CVE-2026-5001 observed in the wild." "collected_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)" >/dev/null
km advance A1_ORIG NORMALIZED "t" "cve_list=[\"CVE-2026-5001\"]" >/dev/null
evidence A1_ORIG >/dev/null
assert_eq "A1 precondition: A1_ORIG is VERIFIED" "VERIFIED" "$(km status A1_ORIG)"
out="$(analyzer A1_ORIG)"
assert_contains "A1 first candidate (empty knowledge dir) reaches ANALYZED cleanly" "$out" "VERIFIED -> ANALYZED"
km score A1_ORIG 80 >/dev/null
hg approve A1_ORIG "confirmed, promoting for real" >/dev/null
km promote A1_ORIG >/dev/null
assert_eq "A1 precondition: A1_ORIG genuinely PROMOTED" "PROMOTED" "$(km status A1_ORIG)"
assert_eq "A1 a real knowledge file now exists on disk" "true" "$([ -f "$FIXTURE_DIR/knowledge/A1_ORIG.json" ] && echo true || echo false)"

km create A1_DUP mock_collector "source_type=news" "source_url=https://example.invalid/a1-dup" "raw_text=CVE-2026-5001 also reported here, independently." "collected_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)" >/dev/null
km advance A1_DUP NORMALIZED "t" "cve_list=[\"CVE-2026-5001\"]" >/dev/null
evidence A1_DUP >/dev/null
out="$(analyzer A1_DUP)"
assert_contains "A1 second candidate (same CVE) is rejected as a duplicate" "$out" "REJECTED (duplicate of 'A1_ORIG'"
assert_eq "A1 final status REJECTED" "REJECTED" "$(km status A1_DUP)"
assert_contains "A1 recorded reason names the CVE overlap" "$(field A1_DUP reason)" "CVE overlap"

echo ""
echo "[A2] IOC overlap against an existing promoted entry is also a duplicate"
write_knowledge K_IOC 'ioc_list=["198.51.100.7"]'
km create A2 mock_collector "source_type=vendor_advisory" "source_url=https://example.invalid/a2" "raw_text=traffic from 198.51.100.7 observed." "collected_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)" >/dev/null
km advance A2 NORMALIZED "t" 'ioc_list=["198.51.100.7"]' >/dev/null
evidence A2 >/dev/null
out="$(analyzer A2)"
assert_contains "A2 rejected as duplicate of K_IOC" "$out" "REJECTED (duplicate of 'K_IOC'"
assert_contains "A2 recorded reason names the IOC overlap" "$(field A2 reason)" "IOC overlap"
assert_eq "A2 final status REJECTED" "REJECTED" "$(km status A2)"

echo ""
echo "[A3] the exact same source_url as an existing promoted entry is a duplicate, even with no CVE/IOC overlap at all"
write_knowledge K_URL 'source_url=https://example.invalid/shared-source'
km create A3 mock_collector "source_type=vendor_advisory" "source_url=https://example.invalid/shared-source" "raw_text=a completely different write-up of the same advisory." "collected_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)" >/dev/null
km advance A3 NORMALIZED "t" >/dev/null
evidence A3 >/dev/null
out="$(analyzer A3)"
assert_contains "A3 rejected as duplicate of K_URL (same source_url)" "$out" "REJECTED (duplicate of 'K_URL'"
assert_contains "A3 recorded reason names the shared source_url" "$(field A3 reason)" "same source_url"
assert_eq "A3 final status REJECTED" "REJECTED" "$(km status A3)"

echo ""
echo "[A4] byte-identical raw_text to an existing promoted entry is flagged as 'contamination suspected', not plain 'duplicate' (a distinct, narrower signal -- see incident_analyzer.sh's own header)"
write_knowledge K_TEXT 'raw_text=Exact same wording, word for word.' 'source_url=https://example.invalid/k-text'
km create A4 mock_collector "source_type=vendor_advisory" "source_url=https://example.invalid/a4-different-url" "raw_text=Exact same wording, word for word." "collected_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)" >/dev/null
km advance A4 NORMALIZED "t" >/dev/null
evidence A4 >/dev/null
out="$(analyzer A4)"
assert_contains "A4 rejected with contamination framing" "$out" "REJECTED (contamination suspected against 'K_TEXT'"
assert_contains "A4 recorded reason says contamination suspected" "$(field A4 reason)" "contamination suspected"
assert_eq "A4 final status REJECTED" "REJECTED" "$(km status A4)"

echo ""
echo "[A5] a genuinely clean candidate (no overlap with any existing knowledge entry on any of the four signals) reaches ANALYZED, and the reason states exactly how many existing entries it was checked against"
km create A5 mock_collector "source_type=vendor_advisory" "source_url=https://example.invalid/a5-unique" "raw_text=A completely unrelated incident, CVE-2026-9999." "collected_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)" >/dev/null
km advance A5 NORMALIZED "t" 'cve_list=["CVE-2026-9999"]' >/dev/null
evidence A5 >/dev/null
out="$(analyzer A5)"
knowledge_count="$(ls "$FIXTURE_DIR/knowledge"/*.json 2>/dev/null | wc -l | tr -d ' ')"
assert_contains "A5 reaches ANALYZED" "$out" "VERIFIED -> ANALYZED"
assert_contains "A5 log states the checked-against count" "$out" "checked against $knowledge_count existing knowledge entries"
assert_eq "A5 final status ANALYZED" "ANALYZED" "$(km status A5)"

echo ""
echo "[A6] incident_analyzer.sh skips (no-op) a candidate not currently at VERIFIED (e.g. still NORMALIZED)"
km create A6 mock_collector "source_type=vendor_advisory" "source_url=https://example.invalid/a6" "raw_text=t" >/dev/null
km advance A6 NORMALIZED "t" >/dev/null
out="$(analyzer A6)"
assert_contains "A6 skips a NORMALIZED candidate" "$out" "skipping (status=NORMALIZED, not VERIFIED)"
assert_eq "A6 status unchanged" "NORMALIZED" "$(km status A6)"

echo ""
echo "[A7] idempotency: re-running the analyzer on an already-ANALYZED candidate is a clean no-op (skipped, not re-advanced, no duplicate audit event)"
before_count="$(audit_count)"
out="$(analyzer A5)"
assert_contains "A7 already-ANALYZED candidate is skipped" "$out" "skipping (status=ANALYZED, not VERIFIED)"
after_count="$(audit_count)"
assert_eq "A7 re-run adds zero audit lines" "true" "$([ "$((after_count - before_count))" -eq 0 ] && echo true || echo false)"

echo ""
echo "[A8] idempotency: re-running the analyzer on an already-REJECTED (duplicate) candidate is also a clean no-op"
before_count="$(audit_count)"
out="$(analyzer A1_DUP)"
assert_contains "A8 already-REJECTED candidate is skipped" "$out" "skipping (status=REJECTED, not VERIFIED)"
after_count="$(audit_count)"
assert_eq "A8 re-run adds zero audit lines" "true" "$([ "$((after_count - before_count))" -eq 0 ] && echo true || echo false)"

echo ""
echo "[A9] an unreadable/malformed existing knowledge file is skipped gracefully during the scan, never fatal to the run"
echo 'not valid json at all {{{' > "$FIXTURE_DIR/knowledge/K_BROKEN.json"
km create A9 mock_collector "source_type=vendor_advisory" "source_url=https://example.invalid/a9" "raw_text=another unrelated incident." "collected_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)" >/dev/null
km advance A9 NORMALIZED "t" >/dev/null
evidence A9 >/dev/null
out="$(analyzer A9)"; rc=$?
assert_eq "A9 exits zero despite the broken knowledge file present" "0" "$rc"
assert_contains "A9 still reaches ANALYZED (broken file skipped, not matched)" "$out" "VERIFIED -> ANALYZED"
rm -f "$FIXTURE_DIR/knowledge/K_BROKEN.json"

echo ""
echo "[A10] the full-loop invocation (no id argument) processes every VERIFIED candidate in one pass, and leaves a non-VERIFIED candidate alone"
km create A10_V mock_collector "source_type=vendor_advisory" "source_url=https://example.invalid/a10v" "raw_text=yet another unrelated incident." "collected_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)" >/dev/null
km advance A10_V NORMALIZED "t" >/dev/null
evidence A10_V >/dev/null
assert_eq "A10 precondition: A10_V is VERIFIED" "VERIFIED" "$(km status A10_V)"
km create A10_N mock_collector "source_type=vendor_advisory" "source_url=https://example.invalid/a10n" "raw_text=t" >/dev/null
km advance A10_N NORMALIZED "t" >/dev/null
assert_eq "A10 precondition: A10_N is NORMALIZED (not yet VERIFIED)" "NORMALIZED" "$(km status A10_N)"
bash security/incident_learning/incident_analyzer.sh >/dev/null
assert_eq "A10 the VERIFIED candidate reached ANALYZED via the full-loop invocation" "ANALYZED" "$(km status A10_V)"
assert_eq "A10 the NORMALIZED candidate was left untouched" "NORMALIZED" "$(km status A10_N)"

echo ""
echo "[D1] DuCoPA boundary: this suite's own run never touched any real Control Plane file"
for real_file in security/egress_allowlist.conf security/segments.conf security/ssh_management_allowlist.conf; do
  if [ -f "$real_file" ]; then
    assert_eq "D1 $real_file unchanged" "" "$(git diff --name-only -- "$real_file" 2>/dev/null)"
  fi
done

echo ""
echo "[D2] incident_analyzer.sh makes no network call (static guard)"
net_calls="$(grep -cE '\b(curl|wget|nc )\b' security/incident_learning/incident_analyzer.sh || true)"
assert_eq "D2 zero network-tool invocations" "0" "$net_calls"

echo ""
echo "=== Summary: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
  echo "Failures:"
  printf '  - %s\n' "${FAILURES[@]}"
  exit 1
fi
exit 0
