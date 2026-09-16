#!/bin/bash
set -uo pipefail

# earth_weather/correlation_engine.sh -- Earth & Weather Intelligence
# PoC, Correlation Engine step. No network call, no egress_check
# needed -- reads earth_weather/data/timeline.jsonl only.
#
# Deliberately does NOT assume a causal (or even correlated)
# relationship between weather and earthquakes exists. For each weather
# variable, it sweeps a range of time lags (weather leading/lagging
# earthquake activity by up to EW_LAG_MAX_HOURS hours) and, at each lag,
# computes:
#   - Pearson r between the weather variable and the count of nearby
#     earthquakes in that hour
#   - a permutation-test p-value (shuffles the earthquake series many
#     times and asks how often a real dataset with NO relationship
#     would produce |r| this large by chance) -- this repo has no
#     numpy/scipy, so this stdlib-only approach stands in for a
#     parametric significance test, and doubles as the more
#     appropriate choice anyway for a short, non-normally-distributed
#     earthquake-count series.
# Because many (variable, lag) combinations are tested, a naive
# p<0.05 read is expected to produce false positives by chance alone;
# this script reports both the raw p-value AND a Bonferroni-corrected
# threshold across every test actually run, and intelligence_layer.sh
# is required to surface both, never just the flattering one.
#
# Earthquakes are restricted to EW_EQ_RADIUS_KM of the weather point
# (EW_LAT/EW_LON) -- comparing nationwide seismicity against one
# point's weather would be a category error. Hours outside the
# earthquake feed's actual observed coverage window are excluded from
# every calculation rather than assumed quake-free (data integrity:
# "no record fetched" is never silently treated as "confirmed zero").
#
# If fewer than EW_MIN_EQ_N qualifying earthquakes exist in-window, no
# correlation is computed at all for that run -- the report says
# "insufficient_data" rather than printing a number with no real
# statistical power behind it.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"

if [ -f "$HOME/.waio.env" ]; then
  source "$HOME/.waio.env"
fi

export EW_LAT="${EW_LAT:-35.6762}"
export EW_LON="${EW_LON:-139.6503}"
export EW_EQ_RADIUS_KM="${EW_EQ_RADIUS_KM:-300}"
export EW_LOOKBACK_HOURS="${EW_LOOKBACK_HOURS:-720}"
export EW_LAG_MAX_HOURS="${EW_LAG_MAX_HOURS:-48}"
export EW_MIN_EQ_N="${EW_MIN_EQ_N:-5}"
export EW_PERMUTATIONS="${EW_PERMUTATIONS:-500}"
# Fixed seed for reproducibility of the permutation test across PoC
# runs given the same input data -- not a security/cryptographic
# control, purely so two runs over identical timeline.jsonl content
# produce identical p-values for review.
export EW_SEED="${EW_SEED:-42}"

DATA_DIR="${EW_DATA_DIR:-earth_weather/data}"
TIMELINE="$DATA_DIR/timeline.jsonl"
REPORT="$DATA_DIR/correlation_report.json"

mkdir -p "$DATA_DIR"

python3 - "$TIMELINE" "$REPORT" <<'PYEOF'
import datetime, json, math, os, random, sys

timeline_path, report_path = sys.argv[1:3]

LAT = float(os.environ["EW_LAT"])
LON = float(os.environ["EW_LON"])
RADIUS_KM = float(os.environ["EW_EQ_RADIUS_KM"])
LOOKBACK_HOURS = int(os.environ["EW_LOOKBACK_HOURS"])
LAG_MAX_HOURS = int(os.environ["EW_LAG_MAX_HOURS"])
MIN_EQ_N = int(os.environ["EW_MIN_EQ_N"])
PERMUTATIONS = int(os.environ["EW_PERMUTATIONS"])
SEED = int(os.environ["EW_SEED"])

VARIABLES = ["pressure_hpa", "temperature_c", "precipitation_mm", "humidity_pct", "wind_speed_kmh"]

CAVEATS = [
    "相関(または非相関)は統計的な関連の有無を示すだけであり、地震と気象の因果関係を示すものでは一切ない。",
    "複数の気象変数×複数のラグ(時間差)を同時に検定しているため、偶然による見かけ上の有意差(多重比較問題)が発生し得る。raw p値だけでなく significant_bonferroni を必ず確認すること。",
    "観測された地震数が少ない期間は統計的検出力が低く、「相関なし」という結果も「関連が本当にない」ことの証明にはならない(検出力不足の可能性)。",
    "気象警報等の変数は現行のキーレス提供元(Open-Meteo)からは取得できないため、この相関分析には含まれていない。",
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


def haversine_km(lat1, lon1, lat2, lon2):
    r = 6371.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dlambda / 2) ** 2
    return 2 * r * math.asin(min(1.0, math.sqrt(a)))


def hour_floor(ts_iso):
    dt = datetime.datetime.fromisoformat(ts_iso)
    dt = dt.astimezone(datetime.timezone.utc).replace(minute=0, second=0, microsecond=0)
    return dt


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


timeline = read_jsonl(timeline_path)
weather = [r for r in timeline if r.get("type") == "weather"]
earthquake = [r for r in timeline if r.get("type") == "earthquake"]

now = datetime.datetime.now(datetime.timezone.utc)
window_start = now - datetime.timedelta(hours=LOOKBACK_HOURS)

# Weather series, hour-keyed, restricted to the lookback window.
weather_by_hour = {}
for rec in weather:
    if rec.get("status") != "ok" or not rec.get("ts_utc"):
        continue
    h = hour_floor(rec["ts_utc"])
    if h < window_start:
        continue
    weather_by_hour[h] = rec

# Earthquake feed actual observed coverage (across ALL fetched
# events, not just in-radius ones) -- only hours inside this range are
# trustworthy as "confirmed zero earthquakes" if no matching record
# exists. Outside it, "no record" means "not fetched", not "none
# occurred", so those hours are excluded rather than defaulted to 0.
all_eq_ts = [hour_floor(r["ts_utc"]) for r in earthquake if r.get("ts_utc")]
coverage_start = min(all_eq_ts) if all_eq_ts else None
coverage_end = max(all_eq_ts) if all_eq_ts else None

in_radius_events = []
for rec in earthquake:
    if not rec.get("ts_utc") or rec.get("lat") is None or rec.get("lon") is None:
        continue
    h = hour_floor(rec["ts_utc"])
    if h < window_start:
        continue
    dist = haversine_km(LAT, LON, rec["lat"], rec["lon"])
    if dist <= RADIUS_KM:
        in_radius_events.append({**rec, "distance_km": round(dist, 1), "_hour": h})

eq_count_by_hour = {}
for ev in in_radius_events:
    eq_count_by_hour[ev["_hour"]] = eq_count_by_hour.get(ev["_hour"], 0) + 1

# Hours usable for the analysis: weather present AND inside the
# earthquake feed actual fetched coverage window.
usable_hours = sorted(
    h for h in weather_by_hour
    if coverage_start is not None and coverage_start <= h <= coverage_end
)

n_qualifying_eq = len(in_radius_events)

report = {
    "generated_at": now.isoformat(timespec="seconds"),
    "center": {"lat": LAT, "lon": LON},
    "window": {
        "lookback_hours": LOOKBACK_HOURS,
        "lag_max_hours": LAG_MAX_HOURS,
        "eq_radius_km": RADIUS_KM,
        "min_eq_n_required": MIN_EQ_N,
        "permutations": PERMUTATIONS,
        "seed": SEED,
    },
    "data_coverage": {
        "usable_weather_hours": len(usable_hours),
        "earthquake_feed_coverage": {
            "from": coverage_start.isoformat() if coverage_start else None,
            "to": coverage_end.isoformat() if coverage_end else None,
        },
        "earthquakes_in_radius_and_window": n_qualifying_eq,
        "earthquakes_total_fetched": len(earthquake),
    },
    "variables": {},
    "caveats": CAVEATS,
}

if n_qualifying_eq < MIN_EQ_N or not usable_hours:
    report["status"] = "insufficient_data"
    report["reason"] = (
        f"only {n_qualifying_eq} earthquake(s) within {RADIUS_KM}km and the feed "
        f"observed coverage window (need >= {MIN_EQ_N}), or no usable weather hours "
        f"({len(usable_hours)}) -- no correlation computed."
    )
    for var in VARIABLES:
        report["variables"][var] = {"status": "insufficient_data"}
    with open(report_path, "w") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    reason = report["reason"]
    print(f"[CORRELATION ENGINE] insufficient data: {reason}")
    sys.exit(0)

report["status"] = "ok"
lags = list(range(-LAG_MAX_HOURS, LAG_MAX_HOURS + 1))
total_tests = len(VARIABLES) * len(lags)
bonferroni_alpha = 0.05 / total_tests if total_tests else 0.05
report["window"]["total_tests"] = total_tests
report["window"]["bonferroni_alpha"] = bonferroni_alpha

rng = random.Random(SEED)

for var in VARIABLES:
    sweep = []
    for lag in lags:
        xs, ys = [], []
        for h in usable_hours:
            wrec = weather_by_hour.get(h)
            if wrec is None or wrec.get(var) is None:
                continue
            shifted = h + datetime.timedelta(hours=lag)
            if coverage_start is None or not (coverage_start <= shifted <= coverage_end):
                continue
            xs.append(wrec[var])
            ys.append(eq_count_by_hour.get(shifted, 0))

        r = pearson(xs, ys)
        p = permutation_p_value(xs, ys, r, rng) if r is not None and len(xs) >= 3 else None
        sweep.append({
            "lag_hours": lag,
            "r": r,
            "p_value": p,
            "n": len(xs),
            "significant_raw": (p is not None and p < 0.05),
            "significant_bonferroni": (p is not None and p < bonferroni_alpha),
        })

    valid = [s for s in sweep if s["r"] is not None]
    best = max(valid, key=lambda s: abs(s["r"])) if valid else None

    report["variables"][var] = {
        "status": "ok",
        "best": best,
        "sweep": sweep,
    }

with open(report_path, "w") as f:
    json.dump(report, f, ensure_ascii=False, indent=2)

print(f"[CORRELATION ENGINE] computed {total_tests} test(s) across {len(VARIABLES)} variable(s), "
      f"{len(lags)} lag(s) each; {n_qualifying_eq} earthquake(s) in radius/window; "
      f"bonferroni alpha={bonferroni_alpha:.6g}")
PYEOF

echo "[CORRELATION ENGINE] completed"
