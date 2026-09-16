#!/bin/bash
set -uo pipefail

# earth_weather/correlation_engine_global.sh -- Earth & Weather
# Intelligence PoC, GLOBAL Correlation Engine. No network call --
# reads earth_weather/data/timeline_global.jsonl and
# earth_weather/data/cache/earthquake_global_last_fetch_meta.json only.
#
# Same non-causality design constraint as correlation_engine.sh (see
# that file's own header for the full method): Pearson r + a
# permutation-test p-value at each of a range of time lags, per weather
# variable, with Bonferroni correction across every test actually run.
# This script generalizes that to MULTIPLE globally-distributed
# stations (earth_weather/stations.conf) instead of one fixed point:
#
#   - PER-STATION: each station is tested independently against
#     earthquakes within EW_EQ_RADIUS_KM of that specific station --
#     comparing one point's weather against nationwide/worldwide
#     seismicity would still be a category error even at global scale.
#   - POOLED (global): every station's own (local weather value, local
#     earthquake count) pairs are concatenated into one larger sample
#     and the same lag sweep is run once more. This answers a
#     different, genuinely "world-scale" question -- "regardless of
#     WHERE you are, does a weather variable relate to nearby seismic
#     activity" -- but pooling assumes a common effect (direction and
#     rough magnitude) across climatically and tectonically different
#     stations. If different stations pull in opposite directions, a
#     pooled test can mask both real, opposite, station-specific
#     effects -- this is reported as a caveat, not glossed over, and
#     the per-station breakdown is always kept alongside the pooled
#     number specifically so this failure mode is checkable.
#
# Unlike earth_weather/correlation_engine.sh's P2P地震情報 source (a
# "most recent N events" endpoint with no explicit time bound, hence
# that script's own "only trust hours inside the feed's actually
# fetched coverage" caution), USGS is queried with an explicit
# starttime/endtime -- earthquake_agent_global.sh records the exact
# window it queried in its own fetch-meta file, so every hour in that
# window is a reliable "confirmed N earthquakes" (N possibly 0), not a
# guess. Multiple stations are analyzed against the SAME earthquake
# feed coverage window (all stations are queried once, together, by
# earthquake_agent_global.sh -- there is only one global earthquake
# fetch, not one per station).

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"

if [ -f "$HOME/.waio.env" ]; then
  source "$HOME/.waio.env"
fi

export EW_STATIONS_FILE="${EW_STATIONS_FILE:-earth_weather/stations.conf}"
export EW_EQ_RADIUS_KM="${EW_EQ_RADIUS_KM:-300}"
export EW_LAG_MAX_HOURS="${EW_LAG_MAX_HOURS:-48}"
export EW_MIN_EQ_N="${EW_MIN_EQ_N:-5}"
export EW_PERMUTATIONS="${EW_PERMUTATIONS:-300}"
export EW_SEED="${EW_SEED:-42}"

DATA_DIR="${EW_DATA_DIR:-earth_weather/data}"
TIMELINE="$DATA_DIR/timeline_global.jsonl"
FETCH_META="$DATA_DIR/cache/earthquake_global_last_fetch_meta.json"
REPORT="$DATA_DIR/correlation_report_global.json"

mkdir -p "$DATA_DIR"

if [ ! -f "$EW_STATIONS_FILE" ]; then
  echo "[CORRELATION ENGINE GLOBAL] ERROR: stations file not found: $EW_STATIONS_FILE"
  exit 1
fi

python3 - "$TIMELINE" "$FETCH_META" "$EW_STATIONS_FILE" "$REPORT" <<'PYEOF'
import datetime, json, math, os, random, sys

timeline_path, fetch_meta_path, stations_path, report_path = sys.argv[1:5]

RADIUS_KM = float(os.environ["EW_EQ_RADIUS_KM"])
LAG_MAX_HOURS = int(os.environ["EW_LAG_MAX_HOURS"])
MIN_EQ_N = int(os.environ["EW_MIN_EQ_N"])
PERMUTATIONS = int(os.environ["EW_PERMUTATIONS"])
SEED = int(os.environ["EW_SEED"])

VARIABLES = ["pressure_hpa", "temperature_c", "precipitation_mm", "humidity_pct", "wind_speed_kmh"]

CAVEATS = [
    "相関(または非相関)は統計的な関連の有無を示すだけであり、地震と気象の因果関係を示すものでは一切ない。",
    "多数の観測点×複数変数×複数ラグを同時に検定しているため、偶然による見かけ上の有意差(多重比較問題)が発生し得る。raw p値だけでなく significant_bonferroni を必ず確認すること。",
    "pooled(全球プール)結果は、地域ごとの気候・地震活動の違いを無視して観測点を1つの標本に統合している。地域ごとに逆方向の効果が存在すると、プール結果はその両方を打ち消して見えなくすることがある -- per_station の内訳と必ず併読すること。",
    "観測された地震数が少ない観測点/期間は統計的検出力が低く、「関連なし」という結果は「関連が本当にない」ことの証明ではない(検出力不足の可能性)。",
    "AliceSprings(地震活動が非常に低い大陸内部の安定地域)は意図的な対照地点として含まれている -- 活動的な地域と同程度の見かけ上の有意差が出る場合、それは地震活動そのものより検定手法側のノイズである可能性を示唆する。",
    "気象警報等の変数はキーレス提供元(Open-Meteo)からは取得できないため、この相関分析には含まれていない。",
]


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


def read_stations(path):
    stations = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split("|")
            if len(parts) < 3:
                continue
            name, lat, lon = parts[0], float(parts[1]), float(parts[2])
            note = parts[3] if len(parts) > 3 else ""
            stations.append({"name": name, "lat": lat, "lon": lon, "note": note})
    return stations


def haversine_km(lat1, lon1, lat2, lon2):
    r = 6371.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dlambda / 2) ** 2
    return 2 * r * math.asin(min(1.0, math.sqrt(a)))


def hour_floor(ts_iso):
    dt = datetime.datetime.fromisoformat(ts_iso)
    return dt.astimezone(datetime.timezone.utc).replace(minute=0, second=0, microsecond=0)


def pearson(xs, ys):
    n = len(xs)
    if n < 2:
        return None
    mx = sum(xs) / n
    my = sum(ys) / n
    cov = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
    vx = sum((x - mx) ** 2 for x in xs)
    vy = sum((y - my) ** 2 for y in ys)
    if vx == 0 or vy == 0:
        return None
    return cov / math.sqrt(vx * vy)


def permutation_p_value(xs, ys, observed_r, rng):
    if observed_r is None:
        return None
    ys_shuffled = list(ys)
    hits = 0
    for _ in range(PERMUTATIONS):
        rng.shuffle(ys_shuffled)
        r = pearson(xs, ys_shuffled)
        if r is not None and abs(r) >= abs(observed_r):
            hits += 1
    return (hits + 1) / (PERMUTATIONS + 1)


def lag_sweep(weather_by_hour, eq_count_by_hour, coverage_start, coverage_end, rng):
    lags = list(range(-LAG_MAX_HOURS, LAG_MAX_HOURS + 1))
    hours = sorted(weather_by_hour.keys())
    result = {}
    for var in VARIABLES:
        sweep = []
        for lag in lags:
            xs, ys = [], []
            for h in hours:
                wrec = weather_by_hour.get(h)
                if wrec is None or wrec.get(var) is None:
                    continue
                shifted = h + datetime.timedelta(hours=lag)
                if shifted < coverage_start or shifted > coverage_end:
                    continue
                xs.append(wrec[var])
                ys.append(eq_count_by_hour.get(shifted, 0))
            r = pearson(xs, ys)
            p = permutation_p_value(xs, ys, r, rng) if r is not None and len(xs) >= 3 else None
            sweep.append({"lag_hours": lag, "r": r, "p_value": p, "n": len(xs)})
        valid = [s for s in sweep if s["r"] is not None]
        best = max(valid, key=lambda s: abs(s["r"])) if valid else None
        result[var] = {"best": best, "sweep": sweep}
    return result, len(lags)


timeline = read_jsonl(timeline_path)
weather = [r for r in timeline if r.get("type") == "weather"]
earthquake = [r for r in timeline if r.get("type") == "earthquake"]
stations = read_stations(stations_path)

fetch_meta = read_json(fetch_meta_path, {})
coverage_start = None
coverage_end = None
if fetch_meta.get("coverage_start_utc") and fetch_meta.get("coverage_end_utc"):
    coverage_start = datetime.datetime.fromisoformat(fetch_meta["coverage_start_utc"])
    coverage_end = datetime.datetime.fromisoformat(fetch_meta["coverage_end_utc"])

now = datetime.datetime.now(datetime.timezone.utc)

report = {
    "generated_at": now.isoformat(timespec="seconds"),
    "window": {
        "eq_radius_km": RADIUS_KM,
        "lag_max_hours": LAG_MAX_HOURS,
        "min_eq_n_required": MIN_EQ_N,
        "permutations": PERMUTATIONS,
        "seed": SEED,
    },
    "earthquake_feed_coverage": {
        "from": coverage_start.isoformat() if coverage_start else None,
        "to": coverage_end.isoformat() if coverage_end else None,
        "min_magnitude": fetch_meta.get("min_magnitude"),
        "total_events_fetched": len(earthquake),
    },
    "stations": [],
    "per_station": {},
    "pooled": {},
    "caveats": CAVEATS,
}

if coverage_start is None or coverage_end is None:
    report["status"] = "insufficient_data"
    report["reason"] = "no earthquake feed coverage window recorded -- run earthquake_agent_global.sh first"
    with open(report_path, "w") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    print("[CORRELATION ENGINE GLOBAL] insufficient data: no earthquake feed coverage recorded")
    sys.exit(0)

rng = random.Random(SEED)
tests_run = 0
stations_analyzed = 0

pooled_weather_by_hour = {}
pooled_eq_count_by_hour = {}

for station in stations:
    name = station["name"]
    station_weather = [r for r in weather if r.get("station_id") == name and r.get("status") == "ok" and r.get("ts_utc")]
    weather_by_hour = {hour_floor(r["ts_utc"]): r for r in station_weather}

    in_radius = []
    for eq in earthquake:
        if eq.get("lat") is None or eq.get("lon") is None or not eq.get("ts_utc"):
            continue
        dist = haversine_km(station["lat"], station["lon"], eq["lat"], eq["lon"])
        if dist <= RADIUS_KM:
            in_radius.append(eq)

    eq_count_by_hour = {}
    for eq in in_radius:
        h = hour_floor(eq["ts_utc"])
        if coverage_start <= h <= coverage_end:
            eq_count_by_hour[h] = eq_count_by_hour.get(h, 0) + 1

    n_eq = len(in_radius)

    report["stations"].append({
        "name": name, "lat": station["lat"], "lon": station["lon"], "note": station["note"],
        "n_weather_hours": len(weather_by_hour), "n_earthquakes_in_radius": n_eq,
    })

    # feed pooled series regardless of this station own eligibility --
    # a station too quiet on its own to test individually can still
    # contribute real (weather, local-quake-count) pairs to the pooled
    # sample; a distinct pooled hour key per station keeps stations from
    # ever colliding on the same timestamp.
    for h, wrec in weather_by_hour.items():
        pooled_weather_by_hour[(name, h)] = wrec
    for h, count in eq_count_by_hour.items():
        pooled_eq_count_by_hour[(name, h)] = count

    if n_eq < MIN_EQ_N or not weather_by_hour:
        report["per_station"][name] = {"status": "insufficient_data", "n_earthquakes_in_radius": n_eq}
        continue

    variables, n_lags = lag_sweep(weather_by_hour, eq_count_by_hour, coverage_start, coverage_end, rng)
    report["per_station"][name] = {"status": "ok", "n_earthquakes_in_radius": n_eq, "variables": variables}
    tests_run += len(VARIABLES) * n_lags
    stations_analyzed += 1


# --- pooled (global) analysis: reindex the (station, hour) keys used
# above onto a synthetic "pooled hour axis" so lag_sweep (which shifts
# by a plain timedelta) can be reused unmodified -- each station keeps
# its own hour-of-day/date, offset by a large per-station constant so
# no two stations can ever overlap or be shifted into each other by a
# lag. This is bookkeeping only: it does not change any (weather
# value, local earthquake count) pair, it only lets the same lag-sweep
# function pool pairs from many stations without a coordinate clash.
if pooled_weather_by_hour:
    station_names_sorted = sorted(set(k[0] for k in pooled_weather_by_hour.keys()))
    offset_step = datetime.timedelta(days=3650)  # 10 years -- far larger than any real lag window
    base = datetime.datetime(2000, 1, 1, tzinfo=datetime.timezone.utc)
    pooled_weather_reindexed = {}
    pooled_eq_reindexed = {}
    for idx, sname in enumerate(station_names_sorted):
        station_base = base + offset_step * idx
        for (name, h), wrec in pooled_weather_by_hour.items():
            if name != sname:
                continue
            delta = h - coverage_start
            pooled_weather_reindexed[station_base + delta] = wrec
        for (name, h), count in pooled_eq_count_by_hour.items():
            if name != sname:
                continue
            delta = h - coverage_start
            pooled_eq_reindexed[station_base + delta] = count
    pooled_coverage_start = base
    pooled_coverage_end = base + offset_step * len(station_names_sorted) + (coverage_end - coverage_start)

    pooled_variables, n_lags = lag_sweep(pooled_weather_reindexed, pooled_eq_reindexed, pooled_coverage_start, pooled_coverage_end, rng)
    n_pooled_eq = sum(pooled_eq_reindexed.values())
    if n_pooled_eq < MIN_EQ_N:
        report["pooled"] = {"status": "insufficient_data", "n_earthquakes_pooled": n_pooled_eq}
    else:
        report["pooled"] = {
            "status": "ok",
            "n_stations_included": len(station_names_sorted),
            "n_earthquakes_pooled": n_pooled_eq,
            "variables": pooled_variables,
        }
        tests_run += len(VARIABLES) * n_lags
else:
    report["pooled"] = {"status": "insufficient_data", "n_earthquakes_pooled": 0}

bonferroni_alpha = 0.05 / tests_run if tests_run else 0.05
report["window"]["total_tests"] = tests_run
report["window"]["bonferroni_alpha"] = bonferroni_alpha
report["window"]["stations_analyzed"] = stations_analyzed
report["status"] = "ok" if tests_run else "insufficient_data"

# annotate significance (raw + bonferroni) now that the true total test
# count across every station and the pooled run is known.
def annotate(variables):
    for data in variables.values():
        for s in data.get("sweep", []):
            s["significant_raw"] = s["p_value"] is not None and s["p_value"] < 0.05
            s["significant_bonferroni"] = s["p_value"] is not None and s["p_value"] < bonferroni_alpha
        if data.get("best"):
            best = data["best"]
            best["significant_raw"] = best["p_value"] is not None and best["p_value"] < 0.05
            best["significant_bonferroni"] = best["p_value"] is not None and best["p_value"] < bonferroni_alpha


for station_result in report["per_station"].values():
    if station_result.get("status") == "ok":
        annotate(station_result["variables"])
if report["pooled"].get("status") == "ok":
    annotate(report["pooled"]["variables"])

with open(report_path, "w") as f:
    json.dump(report, f, ensure_ascii=False, indent=2)

pooled_status = report["pooled"].get("status")
print(f"[CORRELATION ENGINE GLOBAL] {stations_analyzed}/{len(stations)} station(s) analyzed, "
      f"{tests_run} test(s) total, bonferroni alpha={bonferroni_alpha:.6g}, "
      f"pooled status={pooled_status}")
PYEOF

echo "[CORRELATION ENGINE GLOBAL] completed"
