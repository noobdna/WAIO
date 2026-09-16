#!/bin/bash
set -uo pipefail

# earth_weather/weather_agent_global.sh -- Earth & Weather Intelligence
# PoC, GLOBAL Weather Agent (see ARCHITECTURE.md's "Earth & Weather
# Intelligence: global expansion" phase entry).
#
# Extends weather_agent.sh (single fixed point, default Tokyo) to a
# configurable list of stations spanning multiple continents/tectonic
# settings (earth_weather/stations.conf by default -- see that file's
# own header). Open-Meteo (api.open-meteo.com, keyless) is already a
# global weather model, so this is the same API, called once per
# station, not a different provider.
#
# NOT wired into workers/registry.conf or the production
# security/egress_allowlist.conf -- this script is intended to be
# exercised via tests/earth_weather_global_test.sh's fixture allowlist
# or a deliberately WAIO_EGRESS_ALLOWLIST-overridden manual run, per
# this phase's explicit "stay in the test-isolated environment,
# production dispatch/security config unchanged" scope.
#
# Same data-integrity contract as weather_agent.sh: source/source_url/
# fetched_at on every record, a single station's fetch failure never
# aborts the others or crashes the caller -- each station is fetched
# independently and a failure is recorded per-station in
# earth_weather/data/cache/weather_global_last_fetch_meta.json.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"

if [ -f "$HOME/.waio.env" ]; then
  source "$HOME/.waio.env"
fi

source security/lib.sh

STATIONS_FILE="${EW_STATIONS_FILE:-earth_weather/stations.conf}"
PAST_DAYS="${EW_WEATHER_PAST_DAYS:-2}"
HOST="api.open-meteo.com"
PORT="443"

DATA_DIR="${EW_DATA_DIR:-earth_weather/data}"
CACHE_DIR="$DATA_DIR/cache"
RAW_FILE="$DATA_DIR/weather_global_raw.jsonl"
mkdir -p "$CACHE_DIR"

if [ ! -f "$STATIONS_FILE" ]; then
  echo "[WEATHER AGENT GLOBAL] ERROR: stations file not found: $STATIONS_FILE"
  exit 1
fi

FETCHED_AT="$(python3 -c 'import datetime; print(datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"))')"

MANIFEST_DIR="$(mktemp -d)"
trap 'rm -rf "$MANIFEST_DIR"' EXIT
MANIFEST_FILE="$MANIFEST_DIR/manifest.jsonl"
: > "$MANIFEST_FILE"

FETCH_OK_COUNT=0
FETCH_FAIL_COUNT=0
declare -a FAILED_STATIONS=()

while IFS='|' read -r name lat lon note; do
  case "$name" in "" | \#*) continue ;; esac

  if ! egress_check "$HOST" "$PORT" "" "" "WEATHER_AGENT_GLOBAL"; then
    echo "[WEATHER AGENT GLOBAL] ERROR: egress denied by DLP guard for station $name -- request not sent"
    FETCH_FAIL_COUNT=$((FETCH_FAIL_COUNT + 1))
    FAILED_STATIONS+=("$name:egress_denied")
    continue
  fi

  URL="https://$HOST/v1/forecast?latitude=$lat&longitude=$lon&hourly=temperature_2m,relative_humidity_2m,precipitation,pressure_msl,wind_speed_10m,wind_direction_10m&past_days=$PAST_DAYS&forecast_days=1&timezone=UTC"
  BODY_FILE="$MANIFEST_DIR/$name.json"

  STATUS="$(curl -s -m 20 -o "$BODY_FILE" -w "%{http_code}" "$URL" 2>/dev/null || echo "000")"

  if [ "$STATUS" != "200" ]; then
    echo "[WEATHER AGENT GLOBAL] ERROR: fetch failed for station $name (HTTP $STATUS)"
    FETCH_FAIL_COUNT=$((FETCH_FAIL_COUNT + 1))
    FAILED_STATIONS+=("$name:http_$STATUS")
    continue
  fi

  python3 -c "
import json
print(json.dumps({'station_id': '$name', 'lat': $lat, 'lon': $lon, 'body_path': '$BODY_FILE', 'source_url': '$URL'}))
" >> "$MANIFEST_FILE"
  FETCH_OK_COUNT=$((FETCH_OK_COUNT + 1))
done < "$STATIONS_FILE"

MERGE_OUT="$(python3 - "$MANIFEST_FILE" "$RAW_FILE" "$FETCHED_AT" <<'PYEOF'
import json, sys

manifest_path, raw_path, fetched_at = sys.argv[1:4]

new_records = {}
with open(manifest_path) as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        entry = json.loads(line)
        station_id = entry["station_id"]
        lat, lon = entry["lat"], entry["lon"]
        source_url = entry["source_url"]

        with open(entry["body_path"]) as bf:
            body = json.load(bf)

        hourly = body.get("hourly", {})
        times = hourly.get("time", [])

        for i, t in enumerate(times):
            ts_utc = t + ":00+00:00"
            key = station_id + "|" + ts_utc

            def val(k):
                arr = hourly.get(k, [])
                return arr[i] if i < len(arr) else None

            new_records[key] = {
                "station_id": station_id,
                "ts_utc": ts_utc,
                "type": "weather",
                "source": "open-meteo",
                "source_url": source_url,
                "fetched_at": fetched_at,
                "lat": lat,
                "lon": lon,
                "pressure_hpa": val("pressure_msl"),
                "temperature_c": val("temperature_2m"),
                "precipitation_mm": val("precipitation"),
                "humidity_pct": val("relative_humidity_2m"),
                "wind_speed_kmh": val("wind_speed_10m"),
                "wind_direction_deg": val("wind_direction_10m"),
                "warnings": None,
                "warnings_note": "not collected: keyless Open-Meteo provider has no official warning feed for any region (see ARCHITECTURE.md)",
                "status": "ok",
            }

existing = {}
try:
    with open(raw_path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            existing[rec["station_id"] + "|" + rec["ts_utc"]] = rec
except FileNotFoundError:
    pass

existing.update(new_records)

with open(raw_path, "w") as f:
    for key in sorted(existing.keys()):
        f.write(json.dumps(existing[key], ensure_ascii=False) + "\n")

stations_touched = len(set(r["station_id"] for r in new_records.values()))
print(f"merged {len(new_records)} fetched station-hour(s) across {stations_touched} station(s) into {len(existing)} total")
PYEOF
)"

echo "[WEATHER AGENT GLOBAL] $MERGE_OUT (ok=$FETCH_OK_COUNT failed=$FETCH_FAIL_COUNT)"

python3 -c "
import json
json.dump({
    'status': 'ok' if $FETCH_FAIL_COUNT == 0 else ('partial' if $FETCH_OK_COUNT > 0 else 'error'),
    'stations_ok': $FETCH_OK_COUNT,
    'stations_failed': $FETCH_FAIL_COUNT,
    'failed_stations': '$( IFS=,; echo "${FAILED_STATIONS[*]:-}" )'.split(',') if '$( IFS=,; echo "${FAILED_STATIONS[*]:-}" )' else [],
    'fetched_at': '$FETCHED_AT',
}, open('$CACHE_DIR/weather_global_last_fetch_meta.json', 'w'))
"

echo "[WEATHER AGENT GLOBAL] completed"

if [ "$FETCH_OK_COUNT" -eq 0 ]; then
  exit 1
fi
exit 0
