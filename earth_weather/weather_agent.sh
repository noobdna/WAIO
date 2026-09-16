#!/bin/bash
set -uo pipefail

# earth_weather/weather_agent.sh -- Earth & Weather Intelligence PoC,
# Weather Agent (see ARCHITECTURE.md's "Earth & Weather Intelligence"
# phase entry for the full design rationale).
#
# Fetches hourly pressure/temperature/precipitation/humidity/wind
# speed+direction for one fixed lat/lon from Open-Meteo (keyless, no
# API key/account needed -- https://open-meteo.com). Appends one JSONL
# record per hour to earth_weather/data/weather_raw.jsonl, merging with
# whatever is already there (re-running never duplicates or loses an
# hour; a later fetch's revised value for an already-seen hour replaces
# the older one, same "most recent fetch wins" idea as
# incident_normalizer.sh's idempotent create).
#
# Data integrity (requirement #6 of the Earth & Weather Intelligence
# PoC): every record carries source/source_url/fetched_at so
# provenance is always inspectable; a failed fetch never crashes the
# caller (run_pipeline.sh) or the rest of WAIO -- it logs the failure
# to earth_weather/data/cache/weather_last_fetch_meta.json and exits
# non-zero, which run_pipeline.sh treats as one degraded stage, not a
# fatal pipeline error. Official JMA-style weather warnings are NOT
# collected here: Open-Meteo (the keyless provider this PoC defaults
# to) does not expose them. That gap is intentional and documented
# here + in intelligence_layer.sh's output rather than silently
# omitted -- see ARCHITECTURE.md for the extension point (a JMA feed or
# a paid provider, gated behind an API key read from ~/.waio.env, same
# pattern as every future paid provider this codebase would use).

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"

if [ -f "$HOME/.waio.env" ]; then
  source "$HOME/.waio.env"
fi

source security/lib.sh

LAT="${EW_LAT:-35.6762}"
LON="${EW_LON:-139.6503}"
PAST_DAYS="${EW_WEATHER_PAST_DAYS:-2}"
HOST="api.open-meteo.com"
PORT="443"

DATA_DIR="${EW_DATA_DIR:-earth_weather/data}"
CACHE_DIR="$DATA_DIR/cache"
RAW_FILE="$DATA_DIR/weather_raw.jsonl"
mkdir -p "$CACHE_DIR"

FETCHED_AT="$(python3 -c 'import datetime; print(datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"))')"

if ! egress_check "$HOST" "$PORT" "" "" "WEATHER_AGENT"; then
  echo "[WEATHER AGENT] ERROR: egress denied by DLP guard -- request not sent"
  python3 -c "
import json
json.dump({'status': 'error', 'error': 'egress_denied', 'fetched_at': '$FETCHED_AT'}, open('$CACHE_DIR/weather_last_fetch_meta.json', 'w'))
"
  exit 1
fi

URL="https://$HOST/v1/forecast?latitude=$LAT&longitude=$LON&hourly=temperature_2m,relative_humidity_2m,precipitation,pressure_msl,wind_speed_10m,wind_direction_10m&past_days=$PAST_DAYS&forecast_days=1&timezone=UTC"

TMP_BODY="$(mktemp)"
trap 'rm -f "$TMP_BODY"' EXIT

STATUS="$(curl -s -m 20 -o "$TMP_BODY" -w "%{http_code}" "$URL" 2>/dev/null || echo "000")"

if [ "$STATUS" != "200" ]; then
  echo "[WEATHER AGENT] ERROR: Open-Meteo fetch failed (HTTP $STATUS)"
  python3 -c "
import json
json.dump({'status': 'error', 'error': 'http_$STATUS', 'fetched_at': '$FETCHED_AT', 'source_url': '$URL'}, open('$CACHE_DIR/weather_last_fetch_meta.json', 'w'))
"
  exit 1
fi

cp "$TMP_BODY" "$CACHE_DIR/weather_last_success.json"

MERGE_OUT="$(python3 - "$TMP_BODY" "$RAW_FILE" "$FETCHED_AT" "$URL" "$LAT" "$LON" <<'PYEOF'
import json, sys

body_path, raw_path, fetched_at, source_url, lat, lon = sys.argv[1:7]

with open(body_path) as f:
    body = json.load(f)

hourly = body.get("hourly", {})
times = hourly.get("time", [])

new_records = {}
for i, t in enumerate(times):
    ts_utc = t + ":00+00:00"

    def val(key):
        arr = hourly.get(key, [])
        return arr[i] if i < len(arr) else None

    new_records[ts_utc] = {
        "ts_utc": ts_utc,
        "type": "weather",
        "source": "open-meteo",
        "source_url": source_url,
        "fetched_at": fetched_at,
        "lat": float(lat),
        "lon": float(lon),
        "pressure_hpa": val("pressure_msl"),
        "temperature_c": val("temperature_2m"),
        "precipitation_mm": val("precipitation"),
        "humidity_pct": val("relative_humidity_2m"),
        "wind_speed_kmh": val("wind_speed_10m"),
        "wind_direction_deg": val("wind_direction_10m"),
        "warnings": None,
        "warnings_note": "not collected: keyless Open-Meteo provider has no JMA-style warning feed (see ARCHITECTURE.md)",
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
            existing[rec["ts_utc"]] = rec
except FileNotFoundError:
    pass

existing.update(new_records)

with open(raw_path, "w") as f:
    for ts in sorted(existing.keys()):
        f.write(json.dumps(existing[ts], ensure_ascii=False) + "\n")

print(f"merged {len(new_records)} fetched hour(s) into {len(existing)} total")
PYEOF
)"

echo "[WEATHER AGENT] fetched lat=$LAT lon=$LON from $HOST: $MERGE_OUT"

python3 -c "
import json
json.dump({'status': 'ok', 'fetched_at': '$FETCHED_AT', 'source_url': '$URL'}, open('$CACHE_DIR/weather_last_fetch_meta.json', 'w'))
"

echo "[WEATHER AGENT] completed"
