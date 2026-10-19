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
# Incident-timeline hardening (2026-10-18, audit finding F-16):
# - The audit log is read by PATH inside python, never passed as a
#   command-line argument. The previous "$(cat audit log)" argv hand-off
#   hit ARG_MAX once the real log passed ~1 MiB ("Argument list too
#   long"): python never ran, the old output file stayed in place, and
#   this script still printed "Written" and exited 0 -- the Dashboard
#   silently showed a stale/empty timeline.
# - Any failure now exits non-zero and does NOT print "Written"; the
#   output is written to a temp file in the same directory and renamed
#   into place, so a failed run never leaves a partial file behind.
# - Events are processed in timestamp order (stable: ties keep file
#   order), not raw file order. A shutdown/recovery event with a missing
#   or malformed timestamp is never dropped -- it keeps its file position
#   and is flagged (timestamp_valid=false) and counted in input_stats.
#   Malformed JSON lines, exact-duplicate events (a replayed line --
#   impossible for a genuine hash-chained audit_log() write, whose
#   prev_hash always differs) and recoveries with no open incident are
#   counted in input_stats rather than silently ignored.
# - Every incident carries origin = "production" | "test_artifact" plus
#   the origin_basis that decided it, and the totals split production
#   vs. test artifacts, so a test-suite trip that reached the real audit
#   log can never be read as a genuine incident. Classification is a
#   LABEL only: it never hides an incident and never changes
#   status/open_incidents (an open lock is real whatever caused it).
#   Basis rules, deliberately narrow and auditable:
#     rfc5737_destination  -- destination host is in an RFC 5737
#                             documentation range (192.0.2.0/24,
#                             198.51.100.0/24, 203.0.113.0/24): reserved,
#                             unroutable, used only by this repo's test
#                             fixtures.
#     test_fixture_worker  -- worker is a tests/security_fixtures/ name.
#     redteam_run_id       -- run_id "redteam", hardcoded by those
#                             fixtures.
#
# Usage: ./dashboard/build_incident_history.sh
# Output: logs/incident-history-latest.json (WAIO_INCIDENT_HISTORY_OUTPUT
#   overrides it; WAIO_RESPONSE60_JSON overrides the response60 input --
#   same test-isolation override convention as WAIO_AUDIT_LOG)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"
source security/lib.sh

now_iso() { python3 -c 'import datetime; print(datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="milliseconds"))'; }

OUTPUT_PATH="${WAIO_INCIDENT_HISTORY_OUTPUT:-logs/incident-history-latest.json}"
RESPONSE60_PATH="${WAIO_RESPONSE60_JSON:-logs/response60-latest.json}"
mkdir -p "$(dirname "$OUTPUT_PATH")"

GENERATED_AT="$(now_iso)"

if ! python3 -c '
import datetime, ipaddress, json, os, re, sys, tempfile

audit_path, response60_path, generated_at, out_path = sys.argv[1:5]

RECOVERY_TYPES = {"recovery_confirmed", "recovery_confirmed_guardian"}
RELEVANT_TYPES = RECOVERY_TYPES | {"shutdown_triggered"}
TS_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
TEST_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]
TEST_FIXTURE_WORKERS = {"MALICIOUS_TEST_WORKER", "SECRET_LEAK_TEST_WORKER", "BULK_EXFIL_TEST_WORKER"}

stats = {
    "lines_read": 0,
    "malformed_lines": 0,
    "invalid_timestamp_events": 0,
    "duplicate_events_ignored": 0,
    "orphan_recoveries": 0,
}

# Read by path, line by line -- never via argv (see header: ARG_MAX).
events = []
seen = set()
last_valid_ts = ""
if os.path.isfile(audit_path):
    with open(audit_path, "r", encoding="utf-8", errors="replace") as f:
        for idx, raw in enumerate(f):
            line = raw.strip()
            if not line:
                continue
            stats["lines_read"] += 1
            try:
                ev = json.loads(line)
            except Exception:
                stats["malformed_lines"] += 1
                continue
            if not isinstance(ev, dict):
                stats["malformed_lines"] += 1
                continue
            ts = ev.get("timestamp")
            ts_valid = isinstance(ts, str) and bool(TS_RE.match(ts))
            if ts_valid:
                last_valid_ts = max(last_valid_ts, ts)
            if ev.get("event_type") not in RELEVANT_TYPES:
                continue
            key = json.dumps(ev, sort_keys=True)
            if key in seen:
                stats["duplicate_events_ignored"] += 1
                continue
            seen.add(key)
            if not ts_valid:
                stats["invalid_timestamp_events"] += 1
            # Sort key: own timestamp if valid, else the latest valid
            # timestamp seen so far in file order (keeps it in place);
            # file index breaks ties, so the sort is stable.
            events.append(((ts if ts_valid else last_valid_ts), idx, ts_valid, ev))

events.sort(key=lambda e: (e[0], e[1]))

def classify(det):
    basis = []
    dest = det.get("destination") or ""
    host = dest
    if dest.startswith("["):
        host = dest[1:].split("]", 1)[0]
    elif dest.count(":") == 1:
        host = dest.split(":", 1)[0]
    try:
        ip = ipaddress.ip_address(host)
        if any(ip in n for n in TEST_NETS):
            basis.append("rfc5737_destination")
    except ValueError:
        pass
    if det.get("worker") in TEST_FIXTURE_WORKERS:
        basis.append("test_fixture_worker")
    if det.get("run_id") == "redteam":
        basis.append("redteam_run_id")
    return ("test_artifact" if basis else "production"), basis

# response60 cross-reference: only used to fill in Containment timing
# for the ONE incident it actually measured (matched by truncating its
# own t_detection to whole seconds and comparing against the audit
# logs second-precision shutdown_triggered timestamp).
response60 = None
try:
    with open(response60_path, "r", encoding="utf-8") as f:
        r = json.load(f)
    if r:
        t_detect_iso = r["timeline"]["t_detection"]
        dt = datetime.datetime.fromisoformat(t_detect_iso.replace("Z", "+00:00"))
        response60 = {
            "match_timestamp": dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "d_containment": r["timeline"]["d_containment"],
        }
except Exception:
    response60 = None

incidents = []
open_incident = None

for _sort_ts, _idx, ts_valid, ev in events:
    et = ev.get("event_type")
    if et == "shutdown_triggered":
        if open_incident is None:
            detection = {
                "triggered_at": ev.get("timestamp") if ts_valid else None,
                "timestamp_valid": ts_valid,
                "reason": ev.get("reason"),
                "run_id": ev.get("run_id"),
                "worker": ev.get("worker"),
                "destination": ev.get("destination"),
            }
            origin, basis = classify(detection)
            open_incident = {
                "incident_id": len(incidents) + 1,
                "status": "open",
                "origin": origin,
                "origin_basis": basis,
                "detection": detection,
                "duplicate_trigger_count": 0,
                "containment": {"measured": False, "duration_seconds": None, "source": None},
                "recovery": {"measured": False, "recovered_at": None, "timestamp_valid": None, "actor": None, "reason": None},
                "notify": {"measured": False, "note": "notify_shutdown.sh does not write to the audit log (stdout only) -- per-incident notify status cannot be reconstructed from existing logs."},
            }
        else:
            open_incident["duplicate_trigger_count"] += 1
    elif et in RECOVERY_TYPES:
        if open_incident is None:
            stats["orphan_recoveries"] += 1
            continue
        open_incident["status"] = "resolved"
        open_incident["recovery"] = {
            "measured": True,
            "recovered_at": ev.get("timestamp") if ts_valid else None,
            "timestamp_valid": ts_valid,
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

if open_incident is not None:
    incidents.append(open_incident)

for idx, inc in enumerate(incidents, start=1):
    inc["incident_id"] = idx

data = {
    "generated_at": generated_at,
    "total_incidents": len(incidents),
    "open_incidents": sum(1 for i in incidents if i["status"] == "open"),
    "production_incidents": sum(1 for i in incidents if i["origin"] == "production"),
    "test_artifact_incidents": sum(1 for i in incidents if i["origin"] == "test_artifact"),
    "input_stats": stats,
    "incidents": incidents,
}

out_dir = os.path.dirname(os.path.abspath(out_path))
fd, tmp_path = tempfile.mkstemp(prefix=".incident-history.", suffix=".tmp", dir=out_dir)
try:
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.write("\n")
    os.replace(tmp_path, out_path)
except Exception:
    try:
        os.unlink(tmp_path)
    except OSError:
        pass
    raise

n_prod, n_test, n_open = data["production_incidents"], data["test_artifact_incidents"], data["open_incidents"]
print(f"[INCIDENT HISTORY] {len(incidents)} incident(s) reconstructed ({n_prod} production, {n_test} test artifact), {n_open} open.")
' "$SECURITY_AUDIT_LOG" "$RESPONSE60_PATH" "$GENERATED_AT" "$OUTPUT_PATH"; then
  echo "[INCIDENT HISTORY] ERROR: reconstruction failed -- $OUTPUT_PATH was NOT updated." >&2
  exit 1
fi

echo "[INCIDENT HISTORY] Written to $OUTPUT_PATH"
