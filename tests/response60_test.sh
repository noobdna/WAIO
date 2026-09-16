#!/bin/bash
set -uo pipefail

# tests/response60_test.sh -- WAIO 60 SEC RESPONSE TEST ("Kill60Sec",
# named and specified for the first time in this session; see
# ARCHITECTURE.md's Response60 entry for the full spec).
#
# Measures Detection -> Containment latency (the only phase bound by a
# 60-second SLA, per explicit spec) separately from Decision/
# Monitoring/Recovery (unbounded, safety-first -- Recovery in
# particular is scored on correctness, never on speed).
#
# Red Team: reuses the existing, already-reviewed local/dummy fixture
# (tests/security_fixtures/malicious_egress_worker.sh, RFC 5737
# TEST-NET-2 destination) -- no new attack code, no external network.
#
# Blue Team reporting label: アオタコ (Takomachi). This is a REPORTING
# LABEL ONLY -- the mechanism actually exercised below is WAIO's own
# security/lib.sh, security/notify_shutdown.sh, and security/recover.sh.
# Takomachi's real runtime/API is never invoked by this test, consistent
# with the Phase 39/40-B decision to keep Takomachi out of the
# notification/recovery loop.
#
# Recovery uses ONLY the LOCAL `security/recover.sh --confirm` path.
# The real Guardian SSH key/authorized_keys entry is never used or
# duplicated by this test, per explicit instruction -- Guardian-path
# recovery speed was already measured separately in Red Team Phase 2
# (N1) and is not re-measured here.
#
# Standalone script, not wired into .github/workflows/lint.yml -- same
# reasoning as tests/llm_dispatch_test.sh: this measures timing/scoring,
# not a pure pass/fail regression gate, so it stays a manually-run report
# rather than a CI-blocking check. Existing test files are untouched.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"
source security/lib.sh

now() { python3 -c 'import time; print(f"{time.time():.6f}")'; }
now_iso() { python3 -c 'import datetime; print(datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="milliseconds"))'; }
elapsed() { python3 -c "print(f'{$2 - $1:.2f}')"; }

echo "=== WAIO 60 SEC RESPONSE TEST ==="
echo "Red Team: local/dummy fixture only (RFC 5737 TEST-NET-2, no external network)."
echo "Blue Team (reporting label): アオタコ (Takomachi) -- mechanism exercised is WAIO's own security/lib.sh + notify_shutdown.sh + LOCAL recover.sh --confirm. No Guardian SSH key used or duplicated."
echo

if is_shutdown_active; then
  echo "ABORT: a shutdown is already active before this test started -- refusing to run so a real incident is never disturbed."
  exit 1
fi

# ---------------------------------------------------------------------
# Negative Control (run FIRST, mandatory): a legitimate request must
# never trigger a shutdown. If it does, this is a false positive and is
# reported as such -- never silently cleared without saying so.
# ---------------------------------------------------------------------
echo "--- Negative Control: legitimate request must NOT trigger shutdown ---"
NC_T0_ISO="$(now_iso)"
NC_OUT="$(./waio.sh -w ECHO "response60 negative control: legitimate request" 2>&1)"; NC_RC=$?
NC_SHUTDOWN_FIRED="$(is_shutdown_active && echo true || echo false)"
NC_RESULT="PASS"
if [ "$NC_SHUTDOWN_FIRED" = "true" ]; then
  NC_RESULT="FAIL"
  echo "NEGATIVE CONTROL FAILED: a legitimate request incorrectly triggered a shutdown."
  ./security/recover.sh --confirm "response60 test: clearing false-positive triggered by negative control" > /dev/null 2>&1
fi
echo "Negative control: $NC_RESULT (exit=$NC_RC, shutdown_fired=$NC_SHUTDOWN_FIRED, t0=$NC_T0_ISO)"
echo

# ---------------------------------------------------------------------
# Red Team attack run
# ---------------------------------------------------------------------
echo "--- Red Team attack run ---"
REGISTRY_PATH="workers/registry.conf"
REGISTRY_BACKUP="workers/registry.conf.response60-backup.$$"
cp "$REGISTRY_PATH" "$REGISTRY_BACKUP"
printf 'RESPONSE60_MALICIOUS|750|tests/security_fixtures/malicious_egress_worker.sh|response60-fixture\n' >> "$REGISTRY_PATH"
trap 'mv -f "$REGISTRY_BACKUP" "$REGISTRY_PATH" 2>/dev/null' EXIT

T0="$(now)"; T0_ISO="$(now_iso)"
./waio.sh -w RESPONSE60_MALICIOUS "response60: attack simulation" > /dev/null 2>&1

mv -f "$REGISTRY_BACKUP" "$REGISTRY_PATH"
trap - EXIT

# --- Detection ---
T_DETECTION="$(now)"; T_DETECTION_ISO="$(now_iso)"
DETECTION_OK="$(is_shutdown_active && echo true || echo false)"
AUDIT_CONTENT="$(cat "$SECURITY_AUDIT_LOG" 2>/dev/null || true)"
DETECTION_ACCURATE="false"
case "$AUDIT_CONTENT" in
  *"shutdown_triggered"*"198.51.100.1:9999"*) DETECTION_ACCURATE="true" ;;
esac

# --- Containment: probe with a new legitimate task, confirm refusal ---
T_CONTAIN_START="$(now)"
CONTAIN_OUT="$(./waio.sh -w ECHO "response60: containment probe" 2>&1)"; CONTAIN_RC=$?
T_CONTAINMENT="$(now)"; T_CONTAINMENT_ISO="$(now_iso)"
CONTAINMENT_OK="false"
if [ "$CONTAIN_RC" -ne 0 ] && [[ "$CONTAIN_OUT" == *"emergency shutdown active"* ]]; then
  CONTAINMENT_OK="true"
fi

# --- Decision (simulated Blue Team acknowledgement -- proceeds
# immediately, matching the existing R1e "reviewed" pattern; real
# incidents should take as long as genuine investigation requires, this
# test does not measure or reward rushing that judgment) ---
T_DECISION="$(now)"; T_DECISION_ISO="$(now_iso)"

# --- Monitoring: local notification (never auto-wired, invoked
# explicitly here as the test's own Decision step) ---
T_MONITOR_START="$(now)"
MONITOR_OUT="$(./security/notify_shutdown.sh 2>&1)"; MONITOR_RC=$?
T_MONITORING="$(now)"; T_MONITORING_ISO="$(now_iso)"

# --- Recovery: LOCAL --confirm path only, no Guardian SSH key ---
T_RECOVERY_START="$(now)"
RECOVERY_OUT="$(./security/recover.sh --confirm "response60 test: reviewed, dummy attack (198.51.100.1:9999, RFC 5737), expected trip, safe to recover" 2>&1)"; RECOVERY_RC=$?
T_RECOVERY="$(now)"; T_RECOVERY_ISO="$(now_iso)"
RECOVERY_OK="false"
if [ "$RECOVERY_RC" -eq 0 ] && [ "$(is_shutdown_active && echo true || echo false)" = "false" ]; then
  RECOVERY_OK="true"
fi

D_DETECTION="$(elapsed "$T0" "$T_DETECTION")"
D_CONTAINMENT="$(elapsed "$T0" "$T_CONTAINMENT")"
D_DECISION="$(elapsed "$T0" "$T_DECISION")"
D_MONITORING="$(elapsed "$T0" "$T_MONITORING")"
D_RECOVERY="$(elapsed "$T0" "$T_RECOVERY")"

SLA_60S="false"
if python3 -c "exit(0 if $D_CONTAINMENT <= 60.0 else 1)" 2>/dev/null; then
  SLA_60S="true"
fi

# ---------------------------------------------------------------------
# ZENY scoring (100 points, per the approved spec)
# ---------------------------------------------------------------------
SCORE_DETECTION=0
[ "$DETECTION_OK" = "true" ] && [ "$DETECTION_ACCURATE" = "true" ] && SCORE_DETECTION=20

SCORE_CONTAINMENT_COMPLETENESS=0
[ "$CONTAINMENT_OK" = "true" ] && SCORE_CONTAINMENT_COMPLETENESS=30

SCORE_CONTAINMENT_SPEED=0
[ "$SLA_60S" = "true" ] && SCORE_CONTAINMENT_SPEED=20

SCORE_NO_FALSE_POSITIVE=0
[ "$NC_RESULT" = "PASS" ] && SCORE_NO_FALSE_POSITIVE=20

SCORE_RECOVERY=0
[ "$RECOVERY_OK" = "true" ] && SCORE_RECOVERY=10

ZENY_TOTAL=$((SCORE_DETECTION + SCORE_CONTAINMENT_COMPLETENESS + SCORE_CONTAINMENT_SPEED + SCORE_NO_FALSE_POSITIVE + SCORE_RECOVERY))
if [ "$NC_RESULT" != "PASS" ] && [ "$ZENY_TOTAL" -gt 30 ]; then
  ZENY_TOTAL=30
fi

OVERALL_PASS="true"
[ "$DETECTION_OK" != "true" ] && OVERALL_PASS="false"
[ "$DETECTION_ACCURATE" != "true" ] && OVERALL_PASS="false"
[ "$CONTAINMENT_OK" != "true" ] && OVERALL_PASS="false"
[ "$SLA_60S" != "true" ] && OVERALL_PASS="false"
[ "$NC_RESULT" != "PASS" ] && OVERALL_PASS="false"
[ "$RECOVERY_OK" != "true" ] && OVERALL_PASS="false"

echo
echo "=== WAIO 60 SEC RESPONSE TEST -- RESULT ==="
echo "Blue Team: アオタコ (Takomachi) [reporting label; mechanism = WAIO security/lib.sh + notify_shutdown.sh + local recover.sh]"
echo
echo "T+0 (attack start):     $T0_ISO"
echo "t_detection:            $T_DETECTION_ISO  (+${D_DETECTION}s)  active=$DETECTION_OK accurate=$DETECTION_ACCURATE"
echo "t_containment:          $T_CONTAINMENT_ISO  (+${D_CONTAINMENT}s)  contained=$CONTAINMENT_OK  <=60s SLA: $SLA_60S"
echo "t_decision:             $T_DECISION_ISO  (+${D_DECISION}s)  [simulated ack, not speed-scored]"
echo "t_monitoring:           $T_MONITORING_ISO  (+${D_MONITORING}s)  notify_shutdown.sh exit=$MONITOR_RC"
echo "t_recovery:             $T_RECOVERY_ISO  (+${D_RECOVERY}s)  recovered=$RECOVERY_OK  [LOCAL --confirm only, no Guardian key, not speed-scored]"
echo
echo "Negative Control:       $NC_RESULT"
echo
echo "ZENY score breakdown:"
echo "  Detection accuracy:          $SCORE_DETECTION / 20"
echo "  Containment completeness:    $SCORE_CONTAINMENT_COMPLETENESS / 30"
echo "  Containment speed (<=60s):   $SCORE_CONTAINMENT_SPEED / 20"
echo "  No false positive:           $SCORE_NO_FALSE_POSITIVE / 20"
echo "  Recovery correctness:        $SCORE_RECOVERY / 10"
echo "  TOTAL ZENY:                  $ZENY_TOTAL / 100"
echo
echo "OVERALL: $([ "$OVERALL_PASS" = "true" ] && echo PASS || echo FAIL)"

# ---------------------------------------------------------------------
# Additive-only: export a JSON snapshot for dashboard/index.html to
# read (data layer, kept separate from the display layer). Written to
# logs/ (already gitignored, same convention as every other per-run
# artifact this repo produces) -- no new .gitignore entry needed.
# Does not alter anything computed above.
# ---------------------------------------------------------------------
DASHBOARD_SYSTEM_STATUS="ALERT"
[ "$OVERALL_PASS" = "true" ] && DASHBOARD_SYSTEM_STATUS="PROTECTED"
NC_FALSE_POSITIVE_COUNT=0
[ "$NC_RESULT" != "PASS" ] && NC_FALSE_POSITIVE_COUNT=1
mkdir -p logs
RESPONSE60_GENERATED_AT="$(now_iso)" \
RESPONSE60_SYSTEM_STATUS="$DASHBOARD_SYSTEM_STATUS" \
RESPONSE60_OVERALL="$([ "$OVERALL_PASS" = "true" ] && echo PASS || echo FAIL)" \
RESPONSE60_T0="$T0_ISO" RESPONSE60_T_DETECTION="$T_DETECTION_ISO" \
RESPONSE60_T_CONTAINMENT="$T_CONTAINMENT_ISO" RESPONSE60_T_DECISION="$T_DECISION_ISO" \
RESPONSE60_T_MONITORING="$T_MONITORING_ISO" RESPONSE60_T_RECOVERY="$T_RECOVERY_ISO" \
RESPONSE60_D_DETECTION="$D_DETECTION" RESPONSE60_D_CONTAINMENT="$D_CONTAINMENT" \
RESPONSE60_D_DECISION="$D_DECISION" RESPONSE60_D_MONITORING="$D_MONITORING" \
RESPONSE60_D_RECOVERY="$D_RECOVERY" \
RESPONSE60_SLA_PASS="$SLA_60S" \
RESPONSE60_NC_RESULT="$NC_RESULT" RESPONSE60_NC_FALSE_POSITIVES="$NC_FALSE_POSITIVE_COUNT" \
RESPONSE60_ZENY_DETECTION="$SCORE_DETECTION" RESPONSE60_ZENY_CONTAIN_COMPLETE="$SCORE_CONTAINMENT_COMPLETENESS" \
RESPONSE60_ZENY_CONTAIN_SPEED="$SCORE_CONTAINMENT_SPEED" RESPONSE60_ZENY_NO_FP="$SCORE_NO_FALSE_POSITIVE" \
RESPONSE60_ZENY_RECOVERY="$SCORE_RECOVERY" RESPONSE60_ZENY_TOTAL="$ZENY_TOTAL" \
python3 -c '
import json, os, sys

def env(name, cast=str):
    return cast(os.environ[name])

data = {
    "generated_at": env("RESPONSE60_GENERATED_AT"),
    "system_status": env("RESPONSE60_SYSTEM_STATUS"),
    "overall": env("RESPONSE60_OVERALL"),
    "red_team": {"status": "IDLE"},
    "blue_team": {"name": "アオタコ (Takomachi)", "status": "IDLE"},
    "timeline": {
        "t0": env("RESPONSE60_T0"),
        "t_detection": env("RESPONSE60_T_DETECTION"),
        "t_containment": env("RESPONSE60_T_CONTAINMENT"),
        "t_decision": env("RESPONSE60_T_DECISION"),
        "t_monitoring": env("RESPONSE60_T_MONITORING"),
        "t_recovery": env("RESPONSE60_T_RECOVERY"),
        "d_detection": env("RESPONSE60_D_DETECTION", float),
        "d_containment": env("RESPONSE60_D_CONTAINMENT", float),
        "d_decision": env("RESPONSE60_D_DECISION", float),
        "d_monitoring": env("RESPONSE60_D_MONITORING", float),
        "d_recovery": env("RESPONSE60_D_RECOVERY", float),
    },
    "sla_60s": {
        "pass": env("RESPONSE60_SLA_PASS") == "true",
        "measured_seconds": env("RESPONSE60_D_CONTAINMENT", float),
    },
    "negative_control": {
        "result": env("RESPONSE60_NC_RESULT"),
        "false_positive_count": env("RESPONSE60_NC_FALSE_POSITIVES", int),
    },
    "zeny": {
        "detection": env("RESPONSE60_ZENY_DETECTION", int),
        "containment_completeness": env("RESPONSE60_ZENY_CONTAIN_COMPLETE", int),
        "containment_speed": env("RESPONSE60_ZENY_CONTAIN_SPEED", int),
        "no_false_positive": env("RESPONSE60_ZENY_NO_FP", int),
        "recovery": env("RESPONSE60_ZENY_RECOVERY", int),
        "total": env("RESPONSE60_ZENY_TOTAL", int),
    },
}

with open("logs/response60-latest.json", "w") as f:
    json.dump(data, f, indent=2, ensure_ascii=False)
    f.write("\n")
'
echo
echo "Dashboard data written to logs/response60-latest.json"

if [ "$OVERALL_PASS" != "true" ]; then
  exit 1
fi
exit 0
