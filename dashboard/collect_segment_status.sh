#!/bin/bash
set -uo pipefail

# dashboard/collect_segment_status.sh -- Phase 49 (Segment Recovery
# MVP): read-only data collector for the WAIO Dashboard, mirroring
# dashboard/collect_status.sh's own conventions exactly. Reads
# security/segments.conf and each segment's persisted state file plus
# logs/segment-audit.jsonl; never runs a recovery action and never
# writes to a segment's state file. By default it also performs no new
# network activity at all -- it reports last-known persisted status.
# Pass --check to additionally run a live (TCP-only) health check for
# every segment right now, same opt-in-only philosophy as
# collect_status.sh's --run-tests.
#
# Output: logs/waio-segments-latest.json (logs/ already gitignored).

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"
source security/health_checker.sh

RUN_CHECK="false"
[ "${1:-}" = "--check" ] && RUN_CHECK="true"

load_segments || exit 1

now_iso() { python3 -c 'import datetime; print(datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="milliseconds"))'; }

GENERATED_AT="$(now_iso)"

# --- per-segment snapshot ------------------------------------------
SEGMENTS_JSON_ARGS=()
for id in "${SEG_IDS[@]}"; do
  status="$(segment_get_status "$id")"
  host="$(segment_host "$id")"
  port="$(segment_port "$id")"
  worker="$(segment_worker "$id")"
  label="$(segment_label "$id")"

  live_result="not_checked"
  if [ "$RUN_CHECK" = "true" ]; then
    if health_check_segment "$id" 2 1 >/dev/null 2>&1; then
      live_result="pass"
    else
      live_result="fail"
    fi
  fi

  # last event for this segment from the audit log (most recent line
  # whose segment_id matches, if any)
  last_event_json="null"
  if [ -f "$SEGMENT_AUDIT_LOG" ]; then
    last_event_json="$(python3 -c "
import json, sys
path = sys.argv[1]
seg = sys.argv[2]
last = None
with open(path) as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            ev = json.loads(line)
        except Exception:
            continue
        if ev.get('segment_id') == seg:
            last = ev
print(json.dumps(last, ensure_ascii=False))
" "$SEGMENT_AUDIT_LOG" "$id" 2>/dev/null)"
    [ -z "$last_event_json" ] && last_event_json="null"
  fi

  SEGMENTS_JSON_ARGS+=("$id" "$status" "$host" "$port" "$worker" "$label" "$live_result" "$last_event_json")
done

# --- recent segment audit events (last 15, most recent first) ------
RECENT_EVENTS_JSON="[]"
if [ -f "$SEGMENT_AUDIT_LOG" ]; then
  RECENT_EVENTS_JSON="$(tail -15 "$SEGMENT_AUDIT_LOG" | python3 -c '
import json, sys
lines = [l for l in sys.stdin if l.strip()]
events = []
for l in reversed(lines):
    try:
        events.append(json.loads(l))
    except Exception:
        pass
print(json.dumps(events, ensure_ascii=False))
')"
fi

mkdir -p logs
python3 -c '
import json, sys

generated_at = sys.argv[1]
recent_events_json = sys.argv[2]
rest = sys.argv[3:]

segments = []
for i in range(0, len(rest), 8):
    seg_id, status, host, port, worker, label, live_result, last_event_json = rest[i:i+8]
    segments.append({
        "segment_id": seg_id,
        "status": status,
        "host": host,
        "port": port,
        "worker_name": worker,
        "label": label,
        "live_check": live_result,
        "last_event": json.loads(last_event_json),
    })

data = {
    "generated_at": generated_at,
    "note": "Display layer only, see dashboard/collect_segment_status.sh. live_check is \"not_checked\" unless run with --check (opt-in, same philosophy as collect_status.sh --run-tests); otherwise this reflects last-known persisted status only.",
    "segments": segments,
    "recent_events": json.loads(recent_events_json),
}
with open("logs/waio-segments-latest.json", "w") as f:
    json.dump(data, f, indent=2, ensure_ascii=False)
    f.write("\n")
' "$GENERATED_AT" "$RECENT_EVENTS_JSON" "${SEGMENTS_JSON_ARGS[@]}"

echo "[COLLECT SEGMENT STATUS] ${#SEG_IDS[@]} segment(s) snapshotted."
echo "[COLLECT SEGMENT STATUS] Written to logs/waio-segments-latest.json"
