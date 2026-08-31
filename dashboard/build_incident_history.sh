#!/bin/bash
set -uo pipefail

# dashboard/build_incident_history.sh -- read-only reconstruction of
# past Detection -> Containment -> Guardian -> Recovery incidents from
# logs/security-audit.jsonl, for the Dashboard's incident-timeline
# view. Data layer only: never writes to security/state/SHUTDOWN.lock,
# never calls security/recover.sh, never touches
# security/lib.sh/notify_shutdown.sh/any Guardian file/authorized_keys/
# sshd_config.d. Reads the audit log and (optionally, for
# cross-reference) logs/response60-latest.json -- both already-existing
# files -- and nothing else.
#
# Honesty constraints, deliberate:
# - trigger_shutdown() only ever logs a "shutdown_triggered" (Detection)
#   event and, on recovery, a "recovery_confirmed"/"recovery_confirmed_guardian"
#   (Recovery) event. It does NOT log a separate "containment confirmed"
#   timestamp -- so per-incident Containment duration is reported as
#   "not measured" for every incident EXCEPT the one whose detection
#   timestamp matches logs/response60-latest.json's own t_detection
#   (second-level match), which independently measured it.
# - notify_shutdown.sh never writes to the audit log (stdout only), so
#   per-incident Notify status can never be reconstructed from existing
#   logs -- every incident reports notify as "not recorded", not a
#   guess.
#
# Usage: ./dashboard/build_incident_history.sh
# Output: logs/incident-history-latest.json

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"
source security/lib.sh

now_iso() { python3 -c 'import datetime; print(datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="milliseconds"))'; }

mkdir -p logs
AUDIT_LOG_CONTENT=""
[ -f "$SECURITY_AUDIT_LOG" ] && AUDIT_LOG_CONTENT="$(cat "$SECURITY_AUDIT_LOG")"

RESPONSE60_JSON="null"
[ -f "logs/response60-latest.json" ] && RESPONSE60_JSON="$(cat "logs/response60-latest.json")"

GENERATED_AT="$(now_iso)"

python3 -c '
import json, sys, datetime

audit_text, response60_text, generated_at = sys.argv[1], sys.argv[2], sys.argv[3]

events = []
for line in audit_text.splitlines():
    line = line.strip()
    if not line:
        continue
    try:
        events.append(json.loads(line))
    except Exception:
        pass  # skip any malformed line rather than aborting the whole reconstruction

RECOVERY_TYPES = {"recovery_confirmed", "recovery_confirmed_guardian"}

# response60 cross-reference: only used to fill in Containment/Decision/
# Monitoring timing for the ONE incident it actually measured (matched
# by truncating its own t_detection to whole seconds and comparing
# against the audit logs second-precision shutdown_triggered timestamp).
response60 = None
try:
    r = json.loads(response60_text)
    if r:
        t_detect_iso = r["timeline"]["t_detection"]
        # "...T04:06:42.131+00:00" -> "...T04:06:42Z" for comparison
        # against the audit logs %Y-%m-%dT%H:%M:%SZ format.
        dt = datetime.datetime.fromisoformat(t_detect_iso.replace("Z", "+00:00"))
        response60 = {
            "match_timestamp": dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "d_containment": r["timeline"]["d_containment"],
            "d_decision": r["timeline"]["d_decision"],
            "d_monitoring": r["timeline"]["d_monitoring"],
            "sla_60s_pass": r["sla_60s"]["pass"],
        }
except Exception:
    response60 = None

incidents = []
open_incident = None

for ev in events:
    et = ev.get("event_type")
    if et == "shutdown_triggered":
        if open_incident is None:
            open_incident = {
                "incident_id": len(incidents) + 1,
                "status": "open",
                "detection": {
                    "triggered_at": ev.get("timestamp"),
                    "reason": ev.get("reason"),
                    "run_id": ev.get("run_id"),
                    "worker": ev.get("worker"),
                    "destination": ev.get("destination"),
                },
                "duplicate_trigger_count": 0,
                "containment": {"measured": False, "duration_seconds": None, "source": None},
                "recovery": {"measured": False, "recovered_at": None, "actor": None, "reason": None},
                "notify": {"measured": False, "note": "notify_shutdown.sh does not write to the audit log (stdout only) -- per-incident notify status cannot be reconstructed from existing logs."},
            }
        else:
            open_incident["duplicate_trigger_count"] += 1
    elif et in RECOVERY_TYPES and open_incident is not None:
        open_incident["status"] = "resolved"
        open_incident["recovery"] = {
            "measured": True,
            "recovered_at": ev.get("timestamp"),
            "actor": "guardian" if et == "recovery_confirmed_guardian" else "local",
            "reason": ev.get("reason"),
        }
        if response60 and open_incident["detection"]["triggered_at"] == response60["match_timestamp"]:
            open_incident["containment"] = {
                "measured": True,
                "duration_seconds": response60["d_containment"],
                "source": "logs/response60-latest.json (matched by detection timestamp)",
            }
        incidents.append(open_incident)
        open_incident = None
    # recovery_confirmed* with no open_incident: recover.sh only logs
    # this event on an actual clear (its own no-op path returns before
    # audit_log is ever called), so this should not occur in practice;
    # silently ignored rather than fabricating an incident for it.

if open_incident is not None:
    incidents.append(open_incident)

incidents.sort(key=lambda i: i["detection"]["triggered_at"] or "")
for idx, inc in enumerate(incidents, start=1):
    inc["incident_id"] = idx

data = {
    "generated_at": generated_at,
    "total_incidents": len(incidents),
    "open_incidents": sum(1 for i in incidents if i["status"] == "open"),
    "incidents": incidents,
}

with open("logs/incident-history-latest.json", "w") as f:
    json.dump(data, f, indent=2, ensure_ascii=False)
    f.write("\n")

open_count = data["open_incidents"]
print(f"[INCIDENT HISTORY] {len(incidents)} incident(s) reconstructed, {open_count} open.")
' "$AUDIT_LOG_CONTENT" "$RESPONSE60_JSON" "$GENERATED_AT"

echo "[INCIDENT HISTORY] Written to logs/incident-history-latest.json"
