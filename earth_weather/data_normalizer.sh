#!/bin/bash
set -uo pipefail

# earth_weather/data_normalizer.sh -- Earth & Weather Intelligence PoC,
# Data Normalizer step (COLLECTED weather + earthquake -> one shared
# timeline). No network call, no egress_check needed -- pure local file
# processing, same boundary security/incident_learning/incident_normalizer.sh
# already establishes for this codebase's other pipeline.
#
# Reads earth_weather/data/weather_raw.jsonl and
# earth_weather/data/earthquake_raw.jsonl (either or both may be
# missing/empty -- a Weather/Earthquake Agent outage never blocks this
# step, it just means fewer records) and writes:
#   - earth_weather/data/timeline.jsonl   -- full merged history, one
#     JSON object per line, tagged by "type" (weather/earthquake),
#     sorted by ts_utc. This is the canonical "common timeline" the PoC
#     spec calls for: one UTC axis, period-sliceable by any downstream
#     consumer (correlation_engine.sh, a future ad-hoc query, etc.)
#   - earth_weather/data/timeline_latest.json -- the same data as a
#     single JSON array (not JSONL), for dashboard/earth_weather.html
#     to fetch directly over HTTP.
#   - earth_weather/data/timeline_meta.json -- provenance/gap summary:
#     record counts, min/max ts per type, and each Agent's last fetch
#     status (surfaces a Weather/Earthquake outage explicitly rather
#     than letting a stale timeline look silently healthy).

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"

DATA_DIR="${EW_DATA_DIR:-earth_weather/data}"
WEATHER_RAW="$DATA_DIR/weather_raw.jsonl"
EARTHQUAKE_RAW="$DATA_DIR/earthquake_raw.jsonl"
TIMELINE_JSONL="$DATA_DIR/timeline.jsonl"
TIMELINE_JSON="$DATA_DIR/timeline_latest.json"
TIMELINE_META="$DATA_DIR/timeline_meta.json"

mkdir -p "$DATA_DIR"

python3 - "$WEATHER_RAW" "$EARTHQUAKE_RAW" "$TIMELINE_JSONL" "$TIMELINE_JSON" "$TIMELINE_META" <<'PYEOF'
import json, sys, datetime

weather_path, earthquake_path, timeline_jsonl_path, timeline_json_path, meta_path = sys.argv[1:6]


def read_jsonl(path):
    records = []
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                records.append(json.loads(line))
    except FileNotFoundError:
        pass
    return records


def read_json(path, default):
    try:
        with open(path) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return default


weather = read_jsonl(weather_path)
earthquake = read_jsonl(earthquake_path)

timeline = weather + earthquake
timeline.sort(key=lambda r: r.get("ts_utc") or "")

with open(timeline_jsonl_path, "w") as f:
    for rec in timeline:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")

with open(timeline_json_path, "w") as f:
    json.dump(timeline, f, ensure_ascii=False)

cache_dir = weather_path.rsplit("/", 1)[0] + "/cache"
weather_fetch_meta = read_json(cache_dir + "/weather_last_fetch_meta.json", {"status": "never_run"})
earthquake_fetch_meta = read_json(cache_dir + "/earthquake_last_fetch_meta.json", {"status": "never_run"})


def ts_range(records):
    ts_list = [r.get("ts_utc") for r in records if r.get("ts_utc")]
    if not ts_list:
        return None, None
    return min(ts_list), max(ts_list)


w_min, w_max = ts_range(weather)
e_min, e_max = ts_range(earthquake)

meta = {
    "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
    "weather_record_count": len(weather),
    "earthquake_record_count": len(earthquake),
    "weather_ts_range": {"from": w_min, "to": w_max},
    "earthquake_ts_range": {"from": e_min, "to": e_max},
    "weather_agent_last_fetch": weather_fetch_meta,
    "earthquake_agent_last_fetch": earthquake_fetch_meta,
}

with open(meta_path, "w") as f:
    json.dump(meta, f, ensure_ascii=False, indent=2)

print(f"[NORMALIZER] timeline: {len(weather)} weather record(s), {len(earthquake)} earthquake record(s)")
w_status = weather_fetch_meta.get("status")
if w_status != "ok":
    print(f"[NORMALIZER] WARNING: weather agent last status = {w_status}")
e_status = earthquake_fetch_meta.get("status")
if e_status != "ok":
    print(f"[NORMALIZER] WARNING: earthquake agent last status = {e_status}")
PYEOF

echo "[NORMALIZER] completed"
