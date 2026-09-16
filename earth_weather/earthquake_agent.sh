#!/bin/bash
set -uo pipefail

# earth_weather/earthquake_agent.sh -- Earth & Weather Intelligence
# PoC, Earthquake Agent (see ARCHITECTURE.md's "Earth & Weather
# Intelligence" phase entry).
#
# Fetches recent JMA earthquake information (event time, hypocenter,
# magnitude, max observed shindo/intensity) from the P2P地震情報 public
# API v2 (https://www.p2pquake.net/develop/json-api-v2/, keyless, no
# API key/account needed). code=551 = "detailed seismic intensity
# information" (JMA's own per-event report). Appends one JSONL record
# per event to earth_weather/data/earthquake_raw.jsonl, merged/deduped
# by the API's own stable event id (re-running is idempotent).
#
# Same data-integrity contract as weather_agent.sh: source/source_url/
# fetched_at on every record, a failed fetch never crashes the caller
# (logs to earth_weather/data/cache/earthquake_last_fetch_meta.json and
# exits non-zero -- run_pipeline.sh treats this as one degraded stage).
#
# earthquake.time from this API is JST (matches JMA's own reporting
# convention), converted to UTC here so every record in the shared
# timeline (data_normalizer.sh) is comparable on one axis. Unknown
# hypocenter fields (the API uses -1 as an explicit "unknown" sentinel
# for magnitude/lat/lon/depth) are normalized to JSON null, never
# silently treated as 0 or dropped.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"

if [ -f "$HOME/.waio.env" ]; then
  source "$HOME/.waio.env"
fi

source security/lib.sh

LIMIT="${EW_EQ_LIMIT:-100}"
HOST="api.p2pquake.net"
PORT="443"

DATA_DIR="${EW_DATA_DIR:-earth_weather/data}"
CACHE_DIR="$DATA_DIR/cache"
RAW_FILE="$DATA_DIR/earthquake_raw.jsonl"
mkdir -p "$CACHE_DIR"

FETCHED_AT="$(python3 -c 'import datetime; print(datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"))')"

if ! egress_check "$HOST" "$PORT" "" "" "EARTHQUAKE_AGENT"; then
  echo "[EARTHQUAKE AGENT] ERROR: egress denied by DLP guard -- request not sent"
  python3 -c "
import json
json.dump({'status': 'error', 'error': 'egress_denied', 'fetched_at': '$FETCHED_AT'}, open('$CACHE_DIR/earthquake_last_fetch_meta.json', 'w'))
"
  exit 1
fi

URL="https://$HOST/v2/history?codes=551&limit=$LIMIT"

TMP_BODY="$(mktemp)"
trap 'rm -f "$TMP_BODY"' EXIT

STATUS="$(curl -s -m 20 -o "$TMP_BODY" -w "%{http_code}" "$URL" 2>/dev/null || echo "000")"

if [ "$STATUS" != "200" ]; then
  echo "[EARTHQUAKE AGENT] ERROR: P2P地震情報 fetch failed (HTTP $STATUS)"
  python3 -c "
import json
json.dump({'status': 'error', 'error': 'http_$STATUS', 'fetched_at': '$FETCHED_AT', 'source_url': '$URL'}, open('$CACHE_DIR/earthquake_last_fetch_meta.json', 'w'))
"
  exit 1
fi

cp "$TMP_BODY" "$CACHE_DIR/earthquake_last_success.json"

MERGE_OUT="$(python3 - "$TMP_BODY" "$RAW_FILE" "$FETCHED_AT" "$URL" <<'PYEOF'
import datetime, json, sys

body_path, raw_path, fetched_at, source_url = sys.argv[1:5]

with open(body_path) as f:
    events = json.load(f)

JST = datetime.timezone(datetime.timedelta(hours=9))

# JMA shindo (seismic intensity) scale codes used by this API
# maxScale field -- *10 so 45/55/65 can represent the "weak"/"strong"
# split within shindo 5/6. -1 = unknown.
SHINDO_LABELS = {
    -1: None, 10: "1", 20: "2", 30: "3", 40: "4",
    45: "5弱", 50: "5強", 55: "6弱", 60: "6強", 70: "7",
}


def none_if_unknown(v):
    return None if v is None or v == -1 else v


new_records = {}
for ev in events:
    eq = ev.get("earthquake", {})
    hypo = eq.get("hypocenter", {})

    event_id = ev.get("id")
    if not event_id:
        continue

    raw_time = eq.get("time")  # "YYYY/MM/DD HH:MM:SS", JST
    ts_utc = None
    ts_jst = None
    if raw_time:
        dt_jst = datetime.datetime.strptime(raw_time, "%Y/%m/%d %H:%M:%S").replace(tzinfo=JST)
        ts_jst = dt_jst.isoformat()
        ts_utc = dt_jst.astimezone(datetime.timezone.utc).isoformat()

    max_scale = none_if_unknown(eq.get("maxScale"))

    new_records[event_id] = {
        "id": event_id,
        "ts_utc": ts_utc,
        "ts_jst": ts_jst,
        "type": "earthquake",
        "source": "p2pquake",
        "source_url": source_url,
        "fetched_at": fetched_at,
        "hypocenter_name": hypo.get("name"),
        "lat": none_if_unknown(hypo.get("latitude")),
        "lon": none_if_unknown(hypo.get("longitude")),
        "depth_km": none_if_unknown(hypo.get("depth")),
        "magnitude": none_if_unknown(hypo.get("magnitude")),
        "max_scale_code": max_scale,
        "max_shindo": SHINDO_LABELS.get(max_scale) if max_scale is not None else None,
        "domestic_tsunami": eq.get("domesticTsunami"),
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

echo "[EARTHQUAKE AGENT] fetched from $HOST: $MERGE_OUT"

python3 -c "
import json
json.dump({'status': 'ok', 'fetched_at': '$FETCHED_AT', 'source_url': '$URL'}, open('$CACHE_DIR/earthquake_last_fetch_meta.json', 'w'))
"

echo "[EARTHQUAKE AGENT] completed"
