#!/bin/bash
set -uo pipefail

# tests/earth_weather_global_test.sh -- regression suite for the
# GLOBAL Earth & Weather Intelligence PoC
# (earth_weather/{weather,earthquake}_agent_global.sh,
# data_normalizer_global.sh, correlation_engine_global.sh,
# intelligence_layer_global.sh, run_pipeline_global.sh,
# earth_weather/stations.conf). See ARCHITECTURE.md's "Earth & Weather
# Intelligence: global expansion" phase entry.
#
# Scope guard for this phase's own explicit constraint ("stay in the
# test-isolated environment, do not touch the production dispatcher,
# workers/registry.conf, security/egress_allowlist.conf, or
# security/state/SHUTDOWN.lock"): G12/G13 below assert those files were
# NOT modified to wire this global pipeline in -- if a future change
# wires EARTHWEATHERGLOBAL into the live dispatcher/allowlist, that is
# a deliberate, separate, reviewed decision, not a silent side effect.
#
# NO REAL NETWORK CALL. `curl` is shadowed on PATH by a fixture script
# (same idiom as tests/earth_weather_test.sh/tests/rpi_command_injection_test.sh),
# serving fixed Open-Meteo/USGS-shaped bodies with timestamps generated
# relative to "now" at test run time (both agents compute their actual
# fetch window from the real wall clock, so a fixture with hardcoded
# past dates would fall outside that window and never be exercised).
# Every case runs against an isolated
# EW_DATA_DIR/WAIO_SHUTDOWN_LOCK/WAIO_AUDIT_LOG/WAIO_EGRESS_ALLOWLIST/
# EW_STATIONS_FILE -- never the real deployment's earth_weather/data,
# stations.conf, or security state.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"

PASS=0
FAIL=0
declare -a FAILURES=()

assert_eq() {
  local label="$1" expected="$2" actual="$3"
  if [ "$expected" = "$actual" ]; then
    PASS=$((PASS + 1)); echo "  PASS: $label"
  else
    FAIL=$((FAIL + 1)); FAILURES+=("$label (expected='$expected' actual='$actual')")
    echo "  FAIL: $label (expected='$expected' actual='$actual')"
  fi
}

assert_contains() {
  local label="$1" haystack="$2" needle="$3"
  if [[ "$haystack" == *"$needle"* ]]; then
    PASS=$((PASS + 1)); echo "  PASS: $label"
  else
    FAIL=$((FAIL + 1)); FAILURES+=("$label (expected to contain '$needle')")
    echo "  FAIL: $label (expected to contain '$needle', got: $haystack)"
  fi
}

assert_not_contains() {
  local label="$1" haystack="$2" needle="$3"
  if [[ "$haystack" != *"$needle"* ]]; then
    PASS=$((PASS + 1)); echo "  PASS: $label"
  else
    FAIL=$((FAIL + 1)); FAILURES+=("$label (expected NOT to contain '$needle')")
    echo "  FAIL: $label (expected NOT to contain '$needle')"
  fi
}

assert_file_exists() {
  local label="$1" path="$2"
  if [ -f "$path" ]; then
    PASS=$((PASS + 1)); echo "  PASS: $label"
  else
    FAIL=$((FAIL + 1)); FAILURES+=("$label (missing: $path)")
    echo "  FAIL: $label (missing: $path)"
  fi
}

FIXTURE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/waio-earth-weather-global-test.XXXXXX")"
trap 'rm -rf "$FIXTURE_DIR"' EXIT
mkdir -p "$FIXTURE_DIR/bin" "$FIXTURE_DIR/data"

STATION_A_LAT="35.0"
STATION_A_LON="139.0"
STATION_B_LAT="0.0"
STATION_B_LON="0.0"

cat > "$FIXTURE_DIR/stations.conf" <<EOF
StationA|$STATION_A_LAT|$STATION_A_LON|fixture station near fixture earthquakes
StationB|$STATION_B_LAT|$STATION_B_LON|fixture station far from any fixture earthquake
EOF

# --- generate fixtures with timestamps relative to "now" -- both real
# agents compute their fetch window from the actual wall clock, so a
# fixture with hardcoded past dates would never fall inside it. -------
python3 - "$FIXTURE_DIR" <<'PYEOF'
import datetime, json, sys

fixture_dir = sys.argv[1]
now = datetime.datetime.now(datetime.timezone.utc).replace(minute=0, second=0, microsecond=0)
hours = [now - datetime.timedelta(hours=h) for h in range(5, -1, -1)]  # 6 hours, oldest first

open_meteo_body = {
    "hourly": {
        "time": [h.strftime("%Y-%m-%dT%H:%M") for h in hours],
        "temperature_2m": [10.0, 10.5, 11.0, 10.2, 9.8, 10.9],
        "relative_humidity_2m": [80, 81, 82, 79, 78, 83],
        "precipitation": [0.0, 0.1, 0.0, 0.2, 0.0, 0.1],
        "pressure_msl": [1000.0, 1005.0, 1010.0, 1002.0, 1008.0, 1003.0],
        "wind_speed_10m": [5.0, 5.5, 6.0, 4.8, 5.2, 5.9],
        "wind_direction_10m": [180, 181, 182, 179, 178, 183],
    }
}
with open(fixture_dir + "/open_meteo_body.json", "w") as f:
    json.dump(open_meteo_body, f)

lat_a, lon_a = 35.0, 139.0
quake_hours = [hours[0], hours[0], hours[2], hours[4]]  # 4 events, at 3 distinct hours
features = []
for i, h in enumerate(quake_hours):
    epoch_ms = int(h.timestamp() * 1000)
    features.append({
        "type": "Feature",
        "properties": {"mag": 4.8 + i * 0.1, "place": "fixture region " + str(i), "time": epoch_ms, "tsunami": 0, "magType": "mww"},
        "geometry": {"type": "Point", "coordinates": [lon_a + 0.05 * i, lat_a + 0.05 * i, 10.0]},
        "id": "FIXTURE-USGS-" + str(i),
    })
usgs_body = {"type": "FeatureCollection", "features": features}
with open(fixture_dir + "/usgs_body.json", "w") as f:
    json.dump(usgs_body, f)

print("fixture hours:", [h.isoformat() for h in hours])
PYEOF

# --- fake curl: routes by URL substring; supports whole-host failure
# (FAKE_CURL_FAIL_HOST) and single-station failure by latitude
# substring (FAKE_CURL_FAIL_LAT). ------------------------------------
cat > "$FIXTURE_DIR/bin/curl" <<FAKECURL
#!/bin/bash
URL="\${@: -1}"
OUT=""
declare -a ARGS=("\$@")
for i in "\${!ARGS[@]}"; do
  if [ "\${ARGS[\$i]}" = "-o" ]; then OUT="\${ARGS[\$((i+1))]}"; fi
done
if [ -n "\${FAKE_CURL_FAIL_HOST:-}" ] && [[ "\$URL" == *"\$FAKE_CURL_FAIL_HOST"* ]]; then
  echo -n "000"
  exit 0
fi
if [ -n "\${FAKE_CURL_FAIL_LAT:-}" ] && [[ "\$URL" == *"latitude=\$FAKE_CURL_FAIL_LAT"* ]]; then
  echo -n "000"
  exit 0
fi
if [[ "\$URL" == *"api.open-meteo.com"* ]]; then
  cp "$FIXTURE_DIR/open_meteo_body.json" "\$OUT"
  echo -n "200"
elif [[ "\$URL" == *"earthquake.usgs.gov"* ]]; then
  cp "$FIXTURE_DIR/usgs_body.json" "\$OUT"
  echo -n "200"
else
  echo -n "000"
fi
FAKECURL
chmod +x "$FIXTURE_DIR/bin/curl"

cat > "$FIXTURE_DIR/egress_allowlist.conf" <<'EOF'
api.open-meteo.com|443|test fixture
earthquake.usgs.gov|443|test fixture
EOF

export PATH="$FIXTURE_DIR/bin:$PATH"
export WAIO_EGRESS_ALLOWLIST="$FIXTURE_DIR/egress_allowlist.conf"
export WAIO_SHUTDOWN_LOCK="$FIXTURE_DIR/SHUTDOWN.lock"
export WAIO_AUDIT_LOG="$FIXTURE_DIR/audit.jsonl"
export WAIO_AUDIT_LOG_CHECKPOINT="$FIXTURE_DIR/audit_checkpoint"
export WAIO_AUDIT_INTEGRITY_ALERTS="$FIXTURE_DIR/audit_alerts.jsonl"
export WAIO_AUDIT_LOG_LOCK_DIR="$FIXTURE_DIR/audit_lock"
export EW_DATA_DIR="$FIXTURE_DIR/data"
export EW_STATIONS_FILE="$FIXTURE_DIR/stations.conf"
export EW_LOOKBACK_HOURS=6
export EW_LAG_MAX_HOURS=2
export EW_MIN_EQ_N=3
export EW_PERMUTATIONS=20
export EW_EQ_RADIUS_KM=300

echo "--- G1: weather_agent_global.sh fetches all stations ---"
OUT="$(./earth_weather/weather_agent_global.sh 2>&1)"; RC=$?
assert_eq "G1 exit code" "0" "$RC"
assert_contains "G1 output" "$OUT" "across 2 station(s)"
assert_eq "G1 raw file line count (2 stations x 6 hours)" "12" "$(wc -l < "$EW_DATA_DIR/weather_global_raw.jsonl" | tr -d ' ')"

echo "--- G2: re-running weather_agent_global.sh is idempotent ---"
./earth_weather/weather_agent_global.sh >/dev/null 2>&1
assert_eq "G2 raw file still 12 lines" "12" "$(wc -l < "$EW_DATA_DIR/weather_global_raw.jsonl" | tr -d ' ')"

echo "--- G3: partial failure -- one station down does not block the other ---"
rm -f "$EW_DATA_DIR/weather_global_raw.jsonl"
OUT="$(FAKE_CURL_FAIL_LAT="$STATION_B_LAT" ./earth_weather/weather_agent_global.sh 2>&1)"; RC=$?
assert_eq "G3 exit code (partial success still exits 0)" "0" "$RC"
assert_contains "G3 output reports one failure" "$OUT" "ok=1 failed=1"
assert_eq "G3 raw file has only StationA hours" "6" "$(wc -l < "$EW_DATA_DIR/weather_global_raw.jsonl" | tr -d ' ')"
FETCH_STATUS="$(python3 -c "import json; print(json.load(open('$EW_DATA_DIR/cache/weather_global_last_fetch_meta.json'))['status'])")"
assert_eq "G3 fetch-meta status is partial" "partial" "$FETCH_STATUS"

echo "--- G4: total weather outage does not crash, exits non-zero ---"
rm -f "$EW_DATA_DIR/weather_global_raw.jsonl"
OUT="$(FAKE_CURL_FAIL_HOST="api.open-meteo.com" ./earth_weather/weather_agent_global.sh 2>&1)"; RC=$?
assert_eq "G4 exit code" "1" "$RC"
./earth_weather/weather_agent_global.sh >/dev/null 2>&1  # restore for later stages

echo "--- G5: earthquake_agent_global.sh fetches worldwide USGS events ---"
OUT="$(./earth_weather/earthquake_agent_global.sh 2>&1)"; RC=$?
assert_eq "G5 exit code" "0" "$RC"
assert_contains "G5 output" "$OUT" "merged 4 fetched event(s)"
assert_contains "G5 shindo explicitly not applicable" "$(cat "$EW_DATA_DIR/earthquake_global_raw.jsonl")" "not applicable"

echo "--- G6: earthquake_agent_global.sh degrades gracefully on API failure ---"
OUT="$(FAKE_CURL_FAIL_HOST="earthquake.usgs.gov" ./earth_weather/earthquake_agent_global.sh 2>&1)"; RC=$?
assert_eq "G6 exit code" "1" "$RC"
assert_contains "G6 error message" "$OUT" "USGS fetch failed"
./earth_weather/earthquake_agent_global.sh >/dev/null 2>&1  # restore for later stages

echo "--- G7: data_normalizer_global.sh merges into one lat/lon/time timeline ---"
OUT="$(./earth_weather/data_normalizer_global.sh 2>&1)"; RC=$?
assert_eq "G7 exit code" "0" "$RC"
assert_contains "G7 output" "$OUT" "across 2 station(s), 4 earthquake record(s)"
TIMELINE_COUNT="$(python3 -c "import json; print(len(json.load(open('$EW_DATA_DIR/timeline_global_latest.json'))))")"
assert_eq "G7 timeline record count (12 weather + 4 earthquake)" "16" "$TIMELINE_COUNT"

echo "--- G8: correlation_engine_global.sh -- StationA ok, StationB insufficient_data, pooled ok ---"
OUT="$(./earth_weather/correlation_engine_global.sh 2>&1)"; RC=$?
assert_eq "G8 exit code" "0" "$RC"
assert_contains "G8 output mentions 1 station analyzed" "$OUT" "1/2 station(s) analyzed"
STATION_A_STATUS="$(python3 -c "import json; print(json.load(open('$EW_DATA_DIR/correlation_report_global.json'))['per_station']['StationA']['status'])")"
assert_eq "G8 StationA status" "ok" "$STATION_A_STATUS"
STATION_B_STATUS="$(python3 -c "import json; print(json.load(open('$EW_DATA_DIR/correlation_report_global.json'))['per_station']['StationB']['status'])")"
assert_eq "G8 StationB status (far from any fixture quake)" "insufficient_data" "$STATION_B_STATUS"
POOLED_STATUS="$(python3 -c "import json; print(json.load(open('$EW_DATA_DIR/correlation_report_global.json'))['pooled']['status'])")"
assert_eq "G8 pooled status" "ok" "$POOLED_STATUS"

echo "--- G9: correlation_engine_global.sh reports insufficient_data with no earthquake coverage recorded ---"
mkdir -p "$FIXTURE_DIR/data_nocov"
EW_DATA_DIR="$FIXTURE_DIR/data_nocov" ./earth_weather/weather_agent_global.sh >/dev/null 2>&1
EW_DATA_DIR="$FIXTURE_DIR/data_nocov" ./earth_weather/data_normalizer_global.sh >/dev/null 2>&1
OUT="$(EW_DATA_DIR="$FIXTURE_DIR/data_nocov" ./earth_weather/correlation_engine_global.sh 2>&1)"; RC=$?
assert_eq "G9 exit code" "0" "$RC"
assert_contains "G9 output" "$OUT" "insufficient data"

echo "--- G10: correlation_engine_global.sh never claims causation ---"
CAVEATS_JOINED="$(python3 -c "import json; print(' '.join(json.load(open('$EW_DATA_DIR/correlation_report_global.json'))['caveats']))")"
assert_contains "G10 caveat mentions non-causality" "$CAVEATS_JOINED" "因果関係"
assert_contains "G10 caveat mentions pooling risk" "$CAVEATS_JOINED" "打ち消して見えなくする"

echo "--- G11: intelligence_layer_global.sh produces pooled + per-station summary ---"
OUT="$(./earth_weather/intelligence_layer_global.sh 2>&1)"; RC=$?
assert_eq "G11 exit code" "0" "$RC"
assert_file_exists "G11 summary txt written" "$EW_DATA_DIR/intelligence_summary_global.txt"
SUMMARY_TXT="$(cat "$EW_DATA_DIR/intelligence_summary_global.txt")"
assert_contains "G11 non-causality disclaimer" "$SUMMARY_TXT" "因果関係の有無を示すものでは一切ありません"
assert_contains "G11 mentions StationA" "$SUMMARY_TXT" "StationA"
assert_contains "G11 mentions StationB insufficient_data" "$SUMMARY_TXT" "StationB"

echo "--- G12: run_pipeline_global.sh completes end-to-end (overall=ok) ---"
rm -rf "$EW_DATA_DIR"
mkdir -p "$EW_DATA_DIR"
OUT="$(./earth_weather/run_pipeline_global.sh 2>&1)"; RC=$?
assert_eq "G12 exit code" "0" "$RC"
assert_contains "G12 overall status" "$OUT" "overall=ok"

echo "--- G13: run_pipeline_global.sh degrades (not crashes) when earthquake API is down ---"
rm -rf "$EW_DATA_DIR"
mkdir -p "$EW_DATA_DIR"
OUT="$(FAKE_CURL_FAIL_HOST="earthquake.usgs.gov" ./earth_weather/run_pipeline_global.sh 2>&1)"; RC=$?
assert_eq "G13 exit code (degraded is not fatal)" "0" "$RC"
assert_contains "G13 overall status" "$OUT" "overall=degraded"
assert_contains "G13 earthquake stage marked failed" "$OUT" "earthquake_agent_global=failed"

echo "--- G14: scope guard -- this phase must NOT touch the production dispatcher/security config ---"
assert_not_contains "G14 registry.conf has no global worker entry" "$(cat workers/registry.conf)" "EARTHWEATHERGLOBAL"
assert_not_contains "G14 egress_allowlist.conf.example has no usgs entry" "$(cat security/egress_allowlist.conf.example)" "usgs"
assert_not_contains "G14 egress_allowlist.conf.example has no earthquake.usgs.gov entry" "$(cat security/egress_allowlist.conf.example)" "earthquake.usgs.gov"

echo "--- G15: default earth_weather/stations.conf is present, parseable, and diverse ---"
assert_file_exists "G15 stations.conf exists" "earth_weather/stations.conf"
STATION_COUNT="$(grep -vc '^\s*#\|^\s*$' earth_weather/stations.conf)"
if [ "$STATION_COUNT" -ge 5 ]; then
  PASS=$((PASS + 1)); echo "  PASS: G15 at least 5 default stations ($STATION_COUNT found)"
else
  FAIL=$((FAIL + 1)); FAILURES+=("G15 at least 5 default stations (found $STATION_COUNT)")
  echo "  FAIL: G15 at least 5 default stations (found $STATION_COUNT)"
fi

echo
echo "=== Summary: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
  echo "Failures:"
  for f in "${FAILURES[@]}"; do
    echo "  - $f"
  done
  exit 1
fi
exit 0
