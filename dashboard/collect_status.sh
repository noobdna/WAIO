#!/bin/bash
set -uo pipefail

# dashboard/collect_status.sh -- read-only data collector for the WAIO
# Dashboard (dashboard/index.html). Data layer only: this script never
# writes to security/state/SHUTDOWN.lock, never calls
# security/recover.sh, never modifies security/lib.sh,
# notify_shutdown.sh, any Guardian file, authorized_keys, or
# sshd_config.d. It only reads already-existing local files and
# (optionally, with --run-tests) runs the three existing regression
# suites as unmodified external processes, parsing their own stdout
# summary line -- it never edits those test files.
#
# No SSH, no network call of any kind: "Guardian configured" below
# means "the forced-command line is present in this machine's own
# ~/.ssh/authorized_keys", checked by a local file read, never by
# connecting to 800号機.
#
# Usage:
#   ./dashboard/collect_status.sh              # fast, read-only snapshot
#   ./dashboard/collect_status.sh --run-tests   # also runs the three
#                                                # existing suites and
#                                                # records PASS/FAIL/SKIP
#                                                # counts (slower; L1/L2/
#                                                # N1-N4 will attempt real
#                                                # LAN traffic if reachable)
#
# Output: logs/waio-status-latest.json (logs/ already gitignored).

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"
source security/lib.sh

RUN_TESTS="false"
[ "${1:-}" = "--run-tests" ] && RUN_TESTS="true"

now_iso() { python3 -c 'import datetime; print(datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="milliseconds"))'; }
now_epoch() { python3 -c 'import time; print(f"{time.time():.6f}")'; }

GENERATED_AT="$(now_iso)"

# --- Shutdown / Containment state -------------------------------------
SHUTDOWN_ACTIVE="false"
SHUTDOWN_REASON=""
SHUTDOWN_TRIGGERED_AT=""
SHUTDOWN_AGE_SECONDS="0"
if is_shutdown_active; then
  SHUTDOWN_ACTIVE="true"
  SHUTDOWN_REASON="$(sed -n 's/^reason: //p' "$SHUTDOWN_LOCK" | head -1)"
  SHUTDOWN_TRIGGERED_AT="$(sed -n 's/^triggered_at: //p' "$SHUTDOWN_LOCK" | head -1)"
  if [ -n "$SHUTDOWN_TRIGGERED_AT" ]; then
    SHUTDOWN_AGE_SECONDS="$(python3 -c "
import datetime
try:
    t = datetime.datetime.strptime('$SHUTDOWN_TRIGGERED_AT', '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=datetime.timezone.utc)
    print(f'{(datetime.datetime.now(datetime.timezone.utc) - t).total_seconds():.1f}')
except Exception:
    print('0')
")"
  fi
fi

# --- Most recent recovery event (for the RECOVERY status window) ------
RECENT_RECOVERY="false"
LAST_RECOVERY_AT=""
if [ -f "$SECURITY_AUDIT_LOG" ]; then
  LAST_RECOVERY_LINE="$(grep -E '"event_type": "recovery_confirmed(_guardian)?"' "$SECURITY_AUDIT_LOG" 2>/dev/null | tail -1)"
  if [ -n "$LAST_RECOVERY_LINE" ]; then
    LAST_RECOVERY_AT="$(python3 -c "import json,sys; print(json.loads(sys.argv[1])['timestamp'])" "$LAST_RECOVERY_LINE" 2>/dev/null || true)"
    if [ -n "$LAST_RECOVERY_AT" ]; then
      RECOVERY_AGE_SECONDS="$(python3 -c "
import datetime
try:
    t = datetime.datetime.strptime('$LAST_RECOVERY_AT', '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=datetime.timezone.utc)
    print(f'{(datetime.datetime.now(datetime.timezone.utc) - t).total_seconds():.1f}')
except Exception:
    print('999999')
")"
      # "recent" = within the last 5 minutes (300s), an arbitrary but
      # documented window, not a precise/verified decay model.
      if python3 -c "exit(0 if $RECOVERY_AGE_SECONDS <= 300 else 1)" 2>/dev/null; then
        RECENT_RECOVERY="true"
      fi
    fi
  fi
fi

# --- WAIO-wide status (NORMAL / ALERT / CONTAINMENT / RECOVERY) -------
# Approximation, documented honestly: Detection->Containment is
# structurally near-instant by design (independently measured at
# well under 1s in Red Team Phase 2 / the 60 SEC RESPONSE TEST), so
# there is no reliable static signal to distinguish "just detected,
# not yet contained" from "contained and holding" other than elapsed
# time since the lock was written. ALERT = within the 60s response
# SLA window; CONTAINMENT = still locked down after it. This is an
# elapsed-time heuristic, not a independently-verified state machine.
if [ "$SHUTDOWN_ACTIVE" = "true" ]; then
  if python3 -c "exit(0 if $SHUTDOWN_AGE_SECONDS <= 60 else 1)" 2>/dev/null; then
    WAIO_STATUS="ALERT"
  else
    WAIO_STATUS="CONTAINMENT"
  fi
elif [ "$RECENT_RECOVERY" = "true" ]; then
  WAIO_STATUS="RECOVERY"
else
  WAIO_STATUS="NORMAL"
fi

# --- Guardian configuration presence (local file read, no SSH) --------
GUARDIAN_CONFIGURED="false"
if [ -f "$HOME/.ssh/authorized_keys" ] && grep -q "guardian_recover_wrapper.sh" "$HOME/.ssh/authorized_keys" 2>/dev/null; then
  GUARDIAN_CONFIGURED="true"
fi
LAST_GUARDIAN_RECOVERY_AT=""
if [ -f "$SECURITY_AUDIT_LOG" ]; then
  LAST_GUARDIAN_LINE="$(grep '"event_type": "recovery_confirmed_guardian"' "$SECURITY_AUDIT_LOG" 2>/dev/null | tail -1)"
  if [ -n "$LAST_GUARDIAN_LINE" ]; then
    LAST_GUARDIAN_RECOVERY_AT="$(python3 -c "import json,sys; print(json.loads(sys.argv[1])['timestamp'])" "$LAST_GUARDIAN_LINE" 2>/dev/null || true)"
  fi
fi

# --- notify_shutdown.sh auto-notify configuration (local read only) ---
NOTIFY_AUTO_ENABLED="false"
if [ "${WAIO_AUTO_NOTIFY:-}" = "1" ]; then
  NOTIFY_AUTO_ENABLED="true"
elif [ -f "$HOME/.waio.env" ] && grep -qE '^\s*export\s+WAIO_AUTO_NOTIFY=1' "$HOME/.waio.env" 2>/dev/null; then
  NOTIFY_AUTO_ENABLED="true"
fi

# --- Recent audit log events (last 10, most recent first) -------------
RECENT_EVENTS_JSON="[]"
if [ -f "$SECURITY_AUDIT_LOG" ]; then
  RECENT_EVENTS_JSON="$(tail -10 "$SECURITY_AUDIT_LOG" | python3 -c '
import json, sys
lines = [l for l in sys.stdin if l.strip()]
events = []
for l in reversed(lines):
    try:
        events.append(json.loads(l))
    except Exception:
        pass
print(json.dumps(events))
')"
fi

# --- Optional: run the three existing, unmodified regression suites ---
TEST_RESULTS_JSON="null"
if [ "$RUN_TESTS" = "true" ]; then
  parse_summary() {
    # Parses "=== Summary: N passed, M failed[, K skipped] ===" from
    # the suite's own unmodified stdout. Does not alter the suite.
    local output="$1"
    echo "$output" | grep -oE '=== Summary: [0-9]+ passed, [0-9]+ failed(, [0-9]+ skipped)? ===' | tail -1
  }
  SEC_OUT="$(./tests/security_test.sh 2>&1)"; SEC_RC=$?
  SEC_SUMMARY="$(parse_summary "$SEC_OUT")"
  WAIO_OUT="$(./tests/waio_test.sh 2>&1)"; WAIO_RC=$?
  WAIO_SUMMARY="$(parse_summary "$WAIO_OUT")"
  ORCH_OUT="$(./tests/orchestrate_worker_test.sh 2>&1)"; ORCH_RC=$?
  ORCH_SUMMARY="$(parse_summary "$ORCH_OUT")"

  TEST_RESULTS_JSON="$(python3 -c '
import json, re, sys

def parse(summary, rc):
    m = re.search(r"(\d+) passed, (\d+) failed(?:, (\d+) skipped)?", summary or "")
    if not m:
        return {"passed": None, "failed": None, "skipped": None, "exit_code": rc, "raw": summary}
    return {
        "passed": int(m.group(1)),
        "failed": int(m.group(2)),
        "skipped": int(m.group(3)) if m.group(3) else 0,
        "exit_code": rc,
        "raw": summary,
    }

sec_summary, sec_rc, waio_summary, waio_rc, orch_summary, orch_rc = sys.argv[1:7]
print(json.dumps({
    "collected_at": sys.argv[7],
    "security": parse(sec_summary, int(sec_rc)),
    "waio": parse(waio_summary, int(waio_rc)),
    "orchestrate": parse(orch_summary, int(orch_rc)),
}))
' "$SEC_SUMMARY" "$SEC_RC" "$WAIO_SUMMARY" "$WAIO_RC" "$ORCH_SUMMARY" "$ORCH_RC" "$(now_iso)")"

  # Leave WAIO's own state exactly as the suites left it -- they already
  # clean up after themselves (recover.sh --confirm on every trip); no
  # extra cleanup performed here.
fi

# --- Assemble and write --------------------------------------------------
mkdir -p logs
RESPONSE60_PATH="logs/response60-latest.json"
RESPONSE60_JSON="null"
if [ -f "$RESPONSE60_PATH" ]; then
  RESPONSE60_JSON="$(cat "$RESPONSE60_PATH")"
fi

python3 -c '
import json, sys

(generated_at, waio_status, shutdown_active, shutdown_reason, shutdown_triggered_at,
 shutdown_age, guardian_configured, last_guardian_recovery_at, notify_enabled,
 recent_events_json, test_results_json, response60_json) = sys.argv[1:13]

data = {
    "generated_at": generated_at,
    "waio_status": waio_status,
    "waio_status_note": "Elapsed-time heuristic (ALERT <=60s since trigger, else CONTAINMENT; RECOVERY <=300s since last recovery event, else NORMAL) -- not an independently verified state machine, see ARCHITECTURE.md.",
    "shutdown": {
        "active": shutdown_active == "true",
        "reason": shutdown_reason or None,
        "triggered_at": shutdown_triggered_at or None,
        "age_seconds": float(shutdown_age) if shutdown_active == "true" else None,
    },
    "guardian": {
        "authorized_keys_entry_present": guardian_configured == "true",
        "last_guardian_recovery_at": last_guardian_recovery_at or None,
        "note": "Local file read only (this machines own ~/.ssh/authorized_keys) -- no SSH to 800号機 performed by this collector.",
    },
    "notify": {
        "auto_notify_enabled": notify_enabled == "true",
        "note": "Reflects WAIO_AUTO_NOTIFY in this shells environment or ~/.waio.env at collection time; does not confirm a notification was ever actually delivered.",
    },
    "recent_events": json.loads(recent_events_json),
    "test_results": json.loads(test_results_json),
    "response60_latest": json.loads(response60_json),
}
with open("logs/waio-status-latest.json", "w") as f:
    json.dump(data, f, indent=2, ensure_ascii=False)
    f.write("\n")
' "$GENERATED_AT" "$WAIO_STATUS" "$SHUTDOWN_ACTIVE" "$SHUTDOWN_REASON" "$SHUTDOWN_TRIGGERED_AT" \
  "$SHUTDOWN_AGE_SECONDS" "$GUARDIAN_CONFIGURED" "$LAST_GUARDIAN_RECOVERY_AT" "$NOTIFY_AUTO_ENABLED" \
  "$RECENT_EVENTS_JSON" "$TEST_RESULTS_JSON" "$RESPONSE60_JSON"

echo "[COLLECT STATUS] WAIO status: $WAIO_STATUS"
echo "[COLLECT STATUS] Written to logs/waio-status-latest.json"
