#!/bin/bash
set -uo pipefail

# tests/segment_recovery_test.sh -- regression suite for Phase 49
# (Segment Recovery MVP): security/segment_manager.sh,
# security/health_checker.sh, security/recovery_engine.sh, and
# dashboard/collect_segment_status.sh.
#
# Everything here runs against scratch fixtures under a temp dir via
# SEGMENT_MANAGER_CONF/SEGMENT_MANAGER_STATE_DIR/
# SEGMENT_MANAGER_AUDIT_LOG/RECOVERY_ENGINE_STATE_DIR overrides -- this
# suite never reads or writes this deployment's real
# security/segments.conf, security/state/segments/,
# logs/segment-audit.jsonl, or security/state/recovery/, and never
# touches any real remote host beyond a plain TCP connect (same
# LAN-optional, skip-cleanly posture as tests/security_test.sh's L1/L2
# and tests/ssh_guardian_config_test.sh's SG16/SG17).

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

SKIP=0
skip_case() {
  SKIP=$((SKIP + 1))
  echo "  SKIP: $1 ($2)"
}

# --- fixture sandbox ---------------------------------------------------
FIXTURE_DIR="$(mktemp -d -t waio-segment-test)"
trap 'rm -rf "$FIXTURE_DIR"; [ -n "${LISTENER_PID:-}" ] && kill "$LISTENER_PID" 2>/dev/null; true' EXIT

mkdir -p "$FIXTURE_DIR/state" "$FIXTURE_DIR/recovery_state"

# A local loopback listener (python3 http.server on an ephemeral port)
# stands in for a "reachable" segment without touching any real remote
# host. An address:port nothing listens on (127.0.0.1:1) stands in for
# an "unreachable" one -- always fails fast, no real network involved.
LISTEN_PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')"
python3 -m http.server "$LISTEN_PORT" --bind 127.0.0.1 >/dev/null 2>&1 &
LISTENER_PID=$!
sleep 0.3

UNREACHABLE_PORT=1

write_fixture_segments() {
  cat > "$FIXTURE_DIR/segments.conf" <<EOF
UP|127.0.0.1|$LISTEN_PORT|ECHO|reachable fixture segment
DOWN|127.0.0.1|$UNREACHABLE_PORT|ECHO|unreachable fixture segment
EOF
}
write_fixture_segments

export SEGMENT_MANAGER_CONF="$FIXTURE_DIR/segments.conf"
export SEGMENT_MANAGER_STATE_DIR="$FIXTURE_DIR/state"
export SEGMENT_MANAGER_AUDIT_LOG="$FIXTURE_DIR/segment-audit.jsonl"
export RECOVERY_ENGINE_STATE_DIR="$FIXTURE_DIR/recovery_state"
export HEALTH_CHECK_TIMEOUT=1
export HEALTH_CHECK_RETRIES=2
export HEALTH_CHECK_RETRY_DELAY=0

sm() { bash security/segment_manager.sh "$@"; }
hc() { bash security/health_checker.sh "$@"; }
re() { bash security/recovery_engine.sh "$@"; }

echo "=== Segment Recovery MVP (Phase 49) regression suite ==="
echo

# --- Segment Manager: identity, status, state machine -----------------
echo "[SM1] a freshly registered segment with no state file defaults to 'normal'"
assert_eq "SM1 UP defaults to normal" "normal" "$(sm status UP)"
assert_eq "SM1 DOWN defaults to normal" "normal" "$(sm status DOWN)"

echo
echo "[SM2] list shows both registered segments with their status"
LIST_OUT="$(sm list)"
assert_contains "SM2 UP listed" "$LIST_OUT" "UP|normal|127.0.0.1|$LISTEN_PORT|ECHO"
assert_contains "SM2 DOWN listed" "$LIST_OUT" "DOWN|normal|127.0.0.1|$UNREACHABLE_PORT|ECHO"

echo
echo "[SM3] valid transition normal -> suspicious succeeds"
OUT_SM3="$(sm set UP suspicious "test transition" 2>&1)"; RC_SM3=$?
assert_eq "SM3 exit code 0" "0" "$RC_SM3"
assert_eq "SM3 status now suspicious" "suspicious" "$(sm status UP)"

echo
echo "[SM4] invalid transition (normal -> recovered, skipping the whole state machine) is rejected"
sm set DOWN normal "reset" >/dev/null 2>&1
OUT_SM4="$(sm set DOWN recovered "should be rejected" 2>&1)"; RC_SM4=$?
assert_eq "SM4 exit code 1 (rejected)" "1" "$RC_SM4"
assert_contains "SM4 stderr explains rejection" "$OUT_SM4" "is not allowed"
assert_eq "SM4 status unchanged (still normal)" "normal" "$(sm status DOWN)"

echo
echo "[SM5] failed -> isolated requires --force (a human override -- recovery_engine.sh never does this itself)"
sm set DOWN suspicious "setup" >/dev/null 2>&1
sm set DOWN isolated "setup" >/dev/null 2>&1
sm set DOWN recovering "setup" --force >/dev/null 2>&1
sm set DOWN failed "setup" >/dev/null 2>&1
OUT_SM5A="$(sm set DOWN isolated "retry without force" 2>&1)"; RC_SM5A=$?
assert_eq "SM5 without --force: rejected" "1" "$RC_SM5A"
OUT_SM5B="$(sm set DOWN isolated "retry with force" --force 2>&1)"; RC_SM5B=$?
assert_eq "SM5 with --force: succeeds" "0" "$RC_SM5B"
assert_eq "SM5 status now isolated" "isolated" "$(sm status DOWN)"
sm set DOWN normal "cleanup" --force >/dev/null 2>&1

echo
echo "--- fail-closed on segment registry itself ---"
echo "[SM6] missing segments.conf refuses (fail closed, same posture as egress_allowlist.conf)"
OUT_SM6="$(SEGMENT_MANAGER_CONF="$FIXTURE_DIR/does_not_exist.conf" sm list 2>&1)"; RC_SM6=$?
assert_eq "SM6 exit code 1" "1" "$RC_SM6"
assert_contains "SM6 explains missing registry" "$OUT_SM6" "registry missing"

echo
echo "[SM7] an empty (comments-only) segments.conf is a valid, safe, zero-segment state (not an error)"
{ echo "# no segments configured yet"; } > "$FIXTURE_DIR/segments_empty.conf"
OUT_SM7="$(SEGMENT_MANAGER_CONF="$FIXTURE_DIR/segments_empty.conf" sm list 2>&1)"; RC_SM7=$?
assert_eq "SM7 exit code 0" "0" "$RC_SM7"
assert_eq "SM7 no output (zero segments)" "" "$OUT_SM7"

echo
echo "--- .example template sanity ---"
echo "[SM8] security/segments.conf.example: every non-comment/non-blank line has all 5 fields non-empty"
BAD_LINES=0
while IFS='|' read -r a_id a_host a_port a_worker a_label; do
  case "$a_id" in ""|\#*) continue ;; esac
  if [ -z "$a_id" ] || [ -z "$a_host" ] || [ -z "$a_port" ] || [ -z "$a_worker" ] || [ -z "$a_label" ]; then
    BAD_LINES=$((BAD_LINES + 1))
  fi
done < security/segments.conf.example
assert_eq "SM8 no malformed lines in the example template" "0" "$BAD_LINES"

# --- Health Checker -----------------------------------------------------
echo
echo "--- requirement-equivalent case: reachable segment health-checks pass, unreachable ones fail after retries ---"
echo "[HC1] health_check_segment against the loopback listener succeeds"
OUT_HC1="$(hc check UP 2>&1)"; RC_HC1=$?
assert_eq "HC1 exit code 0" "0" "$RC_HC1"

echo
echo "[HC2] health_check_segment against the unreachable fixture fails after the configured retries"
OUT_HC2="$(hc check DOWN 2>&1)"; RC_HC2=$?
assert_eq "HC2 exit code 1" "1" "$RC_HC2"

echo
echo "[HC3] every health_check_segment call logs exactly one audit event with all 6 required fields"
: > "$SEGMENT_MANAGER_AUDIT_LOG"
hc check UP >/dev/null 2>&1
EVENT_COUNT="$(wc -l < "$SEGMENT_MANAGER_AUDIT_LOG" | tr -d ' ')"
assert_eq "HC3 exactly one audit line written" "1" "$EVENT_COUNT"
FIELDS_OK="$(python3 -c "
import json
ev = json.loads(open('$SEGMENT_MANAGER_AUDIT_LOG').readline())
need = {'timestamp','segment_id','event','reason','action','result'}
print('true' if need.issubset(ev.keys()) else 'false')
")"
assert_eq "HC3 all 6 required audit fields present" "true" "$FIELDS_OK"

echo
echo "--- detection state machine: health_check_and_transition drives normal<->suspicious<->isolated ---"
echo "[HC4] normal segment, failing check -> suspicious"
sm set UP normal "reset" --force >/dev/null 2>&1
hc monitor DOWN >/dev/null 2>&1
assert_eq "HC4 DOWN now suspicious after first failure" "suspicious" "$(sm status DOWN)"

echo
echo "[HC5] suspicious segment, failing check again -> isolated (confirmed)"
hc monitor DOWN >/dev/null 2>&1
assert_eq "HC5 DOWN now isolated after second consecutive failure" "isolated" "$(sm status DOWN)"
sm set DOWN normal "cleanup" --force >/dev/null 2>&1

echo
echo "[HC6] suspicious segment, passing check -> normal (false alarm cleared)"
sm set UP suspicious "setup" --force >/dev/null 2>&1
hc monitor UP >/dev/null 2>&1
assert_eq "HC6 UP back to normal after passing check" "normal" "$(sm status UP)"

# --- Recovery Engine ------------------------------------------------
echo
echo "--- requirement #10-equivalent case: dry-run never changes state or runs the real action ---"
echo "[RE1] dry-run on an isolated segment: no state change, no state transition, logged as simulated"
sm set DOWN suspicious "setup" --force >/dev/null 2>&1
sm set DOWN isolated "setup" --force >/dev/null 2>&1
: > "$SEGMENT_MANAGER_AUDIT_LOG"
OUT_RE1="$(re DOWN reconnect 2>&1)"; RC_RE1=$?
assert_eq "RE1 exit code 0" "0" "$RC_RE1"
assert_contains "RE1 reports DRY RUN" "$OUT_RE1" "DRY RUN"
assert_eq "RE1 status unchanged (still isolated)" "isolated" "$(sm status DOWN)"
assert_contains "RE1 audit log has recovery_dry_run" "$(cat "$SEGMENT_MANAGER_AUDIT_LOG")" "recovery_dry_run"

echo
echo "--- authorized recovery target -> succeeds; multiple segments recover independently ---"
echo "[RE2] --execute against a reachable (isolated) segment: isolated -> recovering -> recovered"
# DOWN is the unreachable fixture; UP is the reachable one -- isolate
# UP for this case, since DOWN can never actually recover.
sm set DOWN normal "cleanup after RE1's dry-run attempt" --force >/dev/null 2>&1
sm set UP suspicious "setup" --force >/dev/null 2>&1
sm set UP isolated "setup" --force >/dev/null 2>&1
: > "$SEGMENT_MANAGER_AUDIT_LOG"
OUT_RE2="$(re UP reconnect --execute 2>&1)"; RC_RE2=$?
assert_eq "RE2 exit code 0" "0" "$RC_RE2"
assert_eq "RE2 status now recovered" "recovered" "$(sm status UP)"
AUDIT_RE2="$(cat "$SEGMENT_MANAGER_AUDIT_LOG")"
assert_contains "RE2 audit has recovery_started" "$AUDIT_RE2" "recovery_started"
assert_contains "RE2 audit has recovery_succeeded" "$AUDIT_RE2" "recovery_succeeded"
sm set UP normal "close out incident" >/dev/null 2>&1

echo
echo "[RE3] multiple isolated segments recover independently (their state doesn't cross-contaminate)"
sm set UP suspicious "setup" --force >/dev/null 2>&1
sm set UP isolated "setup" --force >/dev/null 2>&1
re UP reconnect --execute >/dev/null 2>&1
assert_eq "RE3 UP recovered" "recovered" "$(sm status UP)"
assert_eq "RE3 DOWN still normal, untouched by UP's recovery" "normal" "$(sm status DOWN)"
sm set UP normal "cleanup" >/dev/null 2>&1

echo
echo "--- requirement #10-equivalent case: recovery fails cleanly, escalates, never auto-retries ---"
echo "[RE4] --execute against an unreachable (isolated) segment: isolated -> recovering -> failed, escalation logged"
sm set DOWN suspicious "setup" --force >/dev/null 2>&1
sm set DOWN isolated "setup" --force >/dev/null 2>&1
: > "$SEGMENT_MANAGER_AUDIT_LOG"
OUT_RE4="$(re DOWN reconnect --execute 2>&1)"; RC_RE4=$?
assert_eq "RE4 exit code 1" "1" "$RC_RE4"
assert_eq "RE4 status now failed" "failed" "$(sm status DOWN)"
AUDIT_RE4="$(cat "$SEGMENT_MANAGER_AUDIT_LOG")"
assert_contains "RE4 audit has recovery_failed" "$AUDIT_RE4" "recovery_failed"
assert_contains "RE4 audit has human_escalation_required" "$AUDIT_RE4" "human_escalation_required"
assert_contains "RE4 stdout tells the operator how to manually clear it" "$OUT_RE4" "--force"

echo
echo "[RE5] no automatic infinite retry: re-running recovery on a 'failed' segment (no manual reset) is refused"
OUT_RE5="$(re DOWN reconnect --execute 2>&1)"; RC_RE5=$?
assert_eq "RE5 exit code 1 (still refused)" "1" "$RC_RE5"
assert_eq "RE5 status still failed (no auto-loop happened)" "failed" "$(sm status DOWN)"
assert_contains "RE5 explains it's not isolated" "$OUT_RE5" "not 'isolated'"
sm set DOWN isolated "manual investigation done" --force >/dev/null 2>&1
sm set DOWN normal "cleanup" --force >/dev/null 2>&1

echo
echo "--- whitelist enforcement: only reconnect/restart_worker_session exist, nothing else runs ---"
echo "[RE6] an action outside the whitelist is rejected before any state change or execution"
sm set UP suspicious "setup" --force >/dev/null 2>&1
sm set UP isolated "setup" --force >/dev/null 2>&1
OUT_RE6="$(re UP "rm -rf /" --execute 2>&1)"; RC_RE6=$?
assert_eq "RE6 exit code 1" "1" "$RC_RE6"
assert_contains "RE6 explains not allowed" "$OUT_RE6" "not an allowed action"
assert_eq "RE6 status unchanged (still isolated, no state change)" "isolated" "$(sm status UP)"
sm set UP normal "cleanup" --force >/dev/null 2>&1

echo
echo "[RE7] recovery is refused against a segment that isn't isolated (e.g. normal)"
OUT_RE7="$(re UP reconnect --execute 2>&1)"; RC_RE7=$?
assert_eq "RE7 exit code 1" "1" "$RC_RE7"
assert_contains "RE7 explains status precondition" "$OUT_RE7" "not 'isolated'"

echo
echo "[RE8] restart_worker_session is also a real, whitelisted, working action"
sm set UP suspicious "setup" --force >/dev/null 2>&1
sm set UP isolated "setup" --force >/dev/null 2>&1
OUT_RE8="$(re UP restart_worker_session --execute 2>&1)"; RC_RE8=$?
assert_eq "RE8 exit code 0" "0" "$RC_RE8"
assert_eq "RE8 status recovered" "recovered" "$(sm status UP)"
assert_eq "RE8 local bookkeeping marker written (no real remote mutation, see file header)" "true" "$([ -f "$FIXTURE_DIR/recovery_state/UP.attempt" ] && echo true || echo false)"
sm set UP normal "cleanup" >/dev/null 2>&1

# --- Dashboard collector ------------------------------------------------
echo
echo "--- dashboard collector (read-only, no network unless --check) ---"
echo "[DC1] collect_segment_status.sh produces valid JSON with the expected top-level shape"
# Reads via the same SEGMENT_MANAGER_* fixture overrides already
# exported above, so this exercises the fixture UP/DOWN segments, not
# this deployment's real ones. Its *output* path (logs/waio-segments-
# latest.json) is not fixture-overridable -- same as
# dashboard/collect_status.sh's own output path -- so this does
# regenerate that real, gitignored, always-regenerable snapshot file,
# consistent with how running any --run-tests/--check collector already
# does.
bash dashboard/collect_segment_status.sh >/tmp/waio_segment_collect_out.$$ 2>&1
DC1_RC=$?
assert_eq "DC1 exit code 0" "0" "$DC1_RC"
DC1_JSON_OK="$(python3 -c "
import json
try:
    d = json.load(open('logs/waio-segments-latest.json'))
    need = {'generated_at','segments','recent_events'}
    print('true' if need.issubset(d.keys()) and len(d['segments']) == 2 else 'false')
except Exception as e:
    print('false')
")"
assert_eq "DC1 JSON has expected shape and 2 segments" "true" "$DC1_JSON_OK"
rm -f /tmp/waio_segment_collect_out.$$

echo
echo "--- live LAN reachability sanity (skips cleanly with no LAN access, same pattern as other suites) ---"
REAL_HOST800_IP="192.168.1.91"
REAL_RPI_IP="192.168.1.150"
if nc -z -w 3 "$REAL_HOST800_IP" 22 >/dev/null 2>&1; then
  PASS=$((PASS + 1)); echo "  PASS: LAN1 real HOST800 segment ($REAL_HOST800_IP:22) reachable"
else
  skip_case "LAN1 real HOST800 segment reachability" "no LAN access to $REAL_HOST800_IP:22"
fi
if nc -z -w 3 "$REAL_RPI_IP" 22 >/dev/null 2>&1; then
  PASS=$((PASS + 1)); echo "  PASS: LAN2 real Raspberry Pi segment ($REAL_RPI_IP:22) reachable"
else
  skip_case "LAN2 real Raspberry Pi segment reachability" "no LAN access to $REAL_RPI_IP:22"
fi

echo
echo "=== Summary: $PASS passed, $FAIL failed, $SKIP skipped ==="
if [ "$FAIL" -gt 0 ]; then
  echo "Failures:"
  for f in "${FAILURES[@]}"; do echo "  - $f"; done
  exit 1
fi
exit 0
