#!/bin/bash
set -uo pipefail

# earth_weather/data_normalizer_global.sh -- Earth & Weather
# Intelligence PoC, GLOBAL Data Normalizer. No network call.
#
# Reads earth_weather/data/weather_global_raw.jsonl (multi-station) and
# earth_weather/data/earthquake_global_raw.jsonl (worldwide, USGS) and
# writes the same shared-timeline shape data_normalizer.sh already
# established for the single-point pipeline, at a "_global" suffix so
# neither pipeline can clobber the other's output:
#   - earth_weather/data/timeline_global.jsonl / timeline_global_latest.json
#   - earth_weather/data/timeline_global_meta.json (provenance/gap
#     summary, including per-agent last-fetch status so a partial
#     station outage is visible rather than silently absorbed into a
#     timeline that just looks a little smaller)
#
# This IS the "time + lat + lon" unified data model the PoC spec calls
# for: every record, weather or earthquake, carries ts_utc/lat/lon on
# the same axis regardless of which station or which catalog it came
# from -- a later consumer (correlation_engine_global.sh, or an ad-hoc
# query) never needs to know which Agent produced a given row.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"

DATA_DIR="${EW_DATA_DIR:-earth_weather/data}"
WEATHER_RAW="$DATA_DIR/weather_global_raw.jsonl"
EARTHQUAKE_RAW="$DATA_DIR/earthquake_global_raw.jsonl"
TIMELINE_JSONL="$DATA_DIR/timeline_global.jsonl"
TIMELINE_JSON="$DATA_DIR/timeline_global_latest.json"
TIMELINE_META="$DATA_DIR/timeline_global_meta.json"

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
weather_fetch_meta = read_json(cache_dir + "/weather_global_last_fetch_meta.json", {"status": "never_run"})
earthquake_fetch_meta = read_json(cache_dir + "/earthquake_global_last_fetch_meta.json", {"status": "never_run"})


def ts_range(records):
    ts_list = [r.get("ts_utc") for r in records if r.get("ts_utc")]
    if not ts_list:
        return None, None
    return min(ts_list), max(ts_list)


w_min, w_max = ts_range(weather)
e_min, e_max = ts_range(earthquake)

stations = sorted(set(r.get("station_id") for r in weather if r.get("station_id")))

meta = {
    "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
    "weather_record_count": len(weather),
    "earthquake_record_count": len(earthquake),
    "stations_present": stations,
    "weather_ts_range": {"from": w_min, "to": w_max},
    "earthquake_ts_range": {"from": e_min, "to": e_max},
    "weather_agent_last_fetch": weather_fetch_meta,
    "earthquake_agent_last_fetch": earthquake_fetch_meta,
}

with open(meta_path, "w") as f:
    json.dump(meta, f, ensure_ascii=False, indent=2)

print(f"[NORMALIZER GLOBAL] timeline: {len(weather)} weather record(s) across {len(stations)} station(s), {len(earthquake)} earthquake record(s)")
w_status = weather_fetch_meta.get("status")
if w_status not in ("ok",):
    print(f"[NORMALIZER GLOBAL] WARNING: weather agent last status = {w_status}")
e_status = earthquake_fetch_meta.get("status")
if e_status != "ok":
    print(f"[NORMALIZER GLOBAL] WARNING: earthquake agent last status = {e_status}")
PYEOF

echo "[NORMALIZER GLOBAL] completed"
