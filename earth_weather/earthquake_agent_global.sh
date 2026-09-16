#!/bin/bash
set -uo pipefail

# earth_weather/earthquake_agent_global.sh -- Earth & Weather
# Intelligence PoC, GLOBAL Earthquake Agent (see ARCHITECTURE.md's
# "Earth & Weather Intelligence: global expansion" phase entry).
#
# Fetches worldwide earthquake events (event time, epicenter,
# magnitude, depth, place) from the USGS Earthquake Catalog (FDSN
# Event Web Service, earthquake.usgs.gov, keyless, no API key/account
# needed -- https://earthquake.usgs.gov/fdsnws/event/1/). This is a
# SEPARATE agent from earth_weather/earthquake_agent.sh (P2P地震情報,
# Japan-only, reports JMA shindo) -- that script is unchanged; this one
# exists because P2P地震情報 has no coverage outside Japan, and a
# world-scale analysis needs a global catalog. magnitude/depth/place
# apply everywhere; a JMA-style shindo (seismic intensity) figure does
# NOT exist for a global catalog, so max_shindo is always null here,
# with a note -- never fabricated or approximated from magnitude alone.
#
# NOT wired into workers/registry.conf or the production
# security/egress_allowlist.conf -- see weather_agent_global.sh's own
# header for the same "test-isolated environment only" scope note.
#
# Same data-integrity contract as the rest of this pipeline:
# source/source_url/fetched_at on every record, a failed fetch never
# crashes the caller (logs to
# earth_weather/data/cache/earthquake_global_last_fetch_meta.json and
# exits non-zero).

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"

if [ -f "$HOME/.waio.env" ]; then
  source "$HOME/.waio.env"
fi

source security/lib.sh

MIN_MAGNITUDE="${EW_EQ_MIN_MAGNITUDE:-4.5}"
LOOKBACK_HOURS="${EW_LOOKBACK_HOURS:-720}"
HOST="earthquake.usgs.gov"
PORT="443"

DATA_DIR="${EW_DATA_DIR:-earth_weather/data}"
CACHE_DIR="$DATA_DIR/cache"
RAW_FILE="$DATA_DIR/earthquake_global_raw.jsonl"
mkdir -p "$CACHE_DIR"

FETCHED_AT="$(python3 -c 'import datetime; print(datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"))')"
STARTTIME="$(python3 -c "import datetime; print((datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=$LOOKBACK_HOURS)).strftime(\"%Y-%m-%dT%H:%M:%S\"))")"
ENDTIME="$(python3 -c 'import datetime; print(datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S"))')"

if ! egress_check "$HOST" "$PORT" "" "" "EARTHQUAKE_AGENT_GLOBAL"; then
  echo "[EARTHQUAKE AGENT GLOBAL] ERROR: egress denied by DLP guard -- request not sent"
  python3 -c "
import json
json.dump({'status': 'error', 'error': 'egress_denied', 'fetched_at': '$FETCHED_AT'}, open('$CACHE_DIR/earthquake_global_last_fetch_meta.json', 'w'))
"
  exit 1
fi

URL="https://$HOST/fdsnws/event/1/query?format=geojson&starttime=$STARTTIME&endtime=$ENDTIME&minmagnitude=$MIN_MAGNITUDE"

TMP_BODY="$(mktemp)"
trap 'rm -f "$TMP_BODY"' EXIT

STATUS="$(curl -s -m 30 -o "$TMP_BODY" -w "%{http_code}" "$URL" 2>/dev/null || echo "000")"

if [ "$STATUS" != "200" ]; then
  echo "[EARTHQUAKE AGENT GLOBAL] ERROR: USGS fetch failed (HTTP $STATUS)"
  python3 -c "
import json
json.dump({'status': 'error', 'error': 'http_$STATUS', 'fetched_at': '$FETCHED_AT', 'source_url': '$URL'}, open('$CACHE_DIR/earthquake_global_last_fetch_meta.json', 'w'))
"
  exit 1
fi

cp "$TMP_BODY" "$CACHE_DIR/earthquake_global_last_success.json"

MERGE_OUT="$(python3 - "$TMP_BODY" "$RAW_FILE" "$FETCHED_AT" "$URL" <<'PYEOF'
import datetime, json, sys

body_path, raw_path, fetched_at, source_url = sys.argv[1:5]

with open(body_path) as f:
    geojson = json.load(f)

new_records = {}
for feat in geojson.get("features", []):
    props = feat.get("properties", {})
    geom = feat.get("geometry", {})
    coords = geom.get("coordinates", [None, None, None])
    event_id = feat.get("id")
    if not event_id:
        continue

    epoch_ms = props.get("time")
    ts_utc = None
    if epoch_ms is not None:
        dt = datetime.datetime.fromtimestamp(epoch_ms / 1000.0, tz=datetime.timezone.utc)
        ts_utc = dt.isoformat()

    lon, lat, depth_km = (coords + [None, None, None])[:3]
    tsunami_flag = props.get("tsunami")

    new_records[event_id] = {
        "id": event_id,
        "ts_utc": ts_utc,
        "type": "earthquake",
        "source": "usgs",
        "source_url": source_url,
        "fetched_at": fetched_at,
        "place": props.get("place"),
        "lat": lat,
        "lon": lon,
        "depth_km": depth_km,
        "magnitude": props.get("mag"),
        "magnitude_type": props.get("magType"),
        "max_shindo": None,
        "max_shindo_note": "not applicable: USGS is a global magnitude-based catalog, no JMA-style seismic-intensity figure exists outside Japan",
        "domestic_tsunami": bool(tsunami_flag) if tsunami_flag is not None else None,
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
            existing[rec["id"]] = rec
except FileNotFoundError:
    pass

existing.update(new_records)


def sort_key(rec):
    return rec.get("ts_utc") or ""


with open(raw_path, "w") as f:
    for rec in sorted(existing.values(), key=sort_key):
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")

print(f"merged {len(new_records)} fetched event(s) into {len(existing)} total")
PYEOF
)"

echo "[EARTHQUAKE AGENT GLOBAL] fetched from $HOST (minmagnitude=$MIN_MAGNITUDE, lookback=${LOOKBACK_HOURS}h): $MERGE_OUT"

python3 -c "
import json
json.dump({
    'status': 'ok',
    'fetched_at': '$FETCHED_AT',
    'source_url': '$URL',
    'min_magnitude': $MIN_MAGNITUDE,
    'coverage_start_utc': '${STARTTIME}+00:00',
    'coverage_end_utc': '${ENDTIME}+00:00',
}, open('$CACHE_DIR/earthquake_global_last_fetch_meta.json', 'w'))
"

echo "[EARTHQUAKE AGENT GLOBAL] completed"
