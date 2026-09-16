#!/bin/bash
set -uo pipefail

# tests/earth_weather_test.sh -- regression suite for the Earth &
# Weather Intelligence PoC (earth_weather/*.sh, workers/earthweather_worker.sh,
# workers/registry.conf's EARTHWEATHER entry). See ARCHITECTURE.md's
# "Earth & Weather Intelligence" phase entry for the full design.
#
# NO REAL NETWORK CALL. `curl` is shadowed on PATH by a fixture script
# (same "shadow a binary on PATH" idiom as
# tests/rpi_command_injection_test.sh's fake `ssh`) that serves fixed
# JSON bodies matching Open-Meteo's/P2P地震情報's real response shapes,
# so weather_agent.sh/earthquake_agent.sh are exercised unmodified and
# end-to-end (real egress_check, real parsing/merge logic) except the
# actual network I/O. Every case runs against an isolated
# EW_DATA_DIR/WAIO_SHUTDOWN_LOCK/WAIO_AUDIT_LOG/WAIO_EGRESS_ALLOWLIST,
# never the real deployment's earth_weather/data or security state.

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

assert_file_exists() {
  local label="$1" path="$2"
  if [ -f "$path" ]; then
    PASS=$((PASS + 1)); echo "  PASS: $label"
  else
    FAIL=$((FAIL + 1)); FAILURES+=("$label (missing: $path)")
    echo "  FAIL: $label (missing: $path)"
  fi
}

FIXTURE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/waio-earth-weather-test.XXXXXX")"
trap 'rm -rf "$FIXTURE_DIR"' EXIT
mkdir -p "$FIXTURE_DIR/bin" "$FIXTURE_DIR/data"

# --- fixture Open-Meteo body: 3 hourly records -----------------------
cat > "$FIXTURE_DIR/open_meteo_body.json" <<'EOF'
{"hourly":{"time":["2026-01-01T00:00","2026-01-01T01:00","2026-01-01T02:00"],
"temperature_2m":[10.0,10.5,11.0],"relative_humidity_2m":[80,81,82],
"precipitation":[0.0,0.1,0.0],"pressure_msl":[1010.0,1009.5,1009.0],
"wind_speed_10m":[5.0,5.5,6.0],"wind_direction_10m":[180,181,182]}}
EOF

# --- fixture P2P地震情報 body: 2 events -------------------------------
cat > "$FIXTURE_DIR/p2pquake_body.json" <<'EOF'
[
  {"id":"FIXTURE-EQ-1","earthquake":{"time":"2026/01/01 09:00:00",
    "hypocenter":{"name":"Fixture Region A","latitude":35.5,"longitude":139.7,"depth":10,"magnitude":4.5},
    "maxScale":40,"domesticTsunami":"None"}},
  {"id":"FIXTURE-EQ-2","earthquake":{"time":"2026/01/01 11:00:00",
    "hypocenter":{"name":"Fixture Region B","latitude":35.6,"longitude":139.8,"depth":15,"magnitude":5.2},
    "maxScale":50,"domesticTsunami":"None"}}
]
EOF

# --- fake curl: routes by URL substring to one of the fixture bodies,
# or simulates an HTTP failure when FAKE_CURL_FAIL_HOST is set. -------
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
if [[ "\$URL" == *"api.open-meteo.com"* ]]; then
  cp "$FIXTURE_DIR/open_meteo_body.json" "\$OUT"
  echo -n "200"
elif [[ "\$URL" == *"api.p2pquake.net"* ]]; then
  cp "$FIXTURE_DIR/p2pquake_body.json" "\$OUT"
  echo -n "200"
else
  echo -n "000"
fi
FAKECURL
chmod +x "$FIXTURE_DIR/bin/curl"

cat > "$FIXTURE_DIR/egress_allowlist.conf" <<'EOF'
api.open-meteo.com|443|test fixture
api.p2pquake.net|443|test fixture
EOF

export PATH="$FIXTURE_DIR/bin:$PATH"
export WAIO_EGRESS_ALLOWLIST="$FIXTURE_DIR/egress_allowlist.conf"
export WAIO_SHUTDOWN_LOCK="$FIXTURE_DIR/SHUTDOWN.lock"
export WAIO_AUDIT_LOG="$FIXTURE_DIR/audit.jsonl"
export WAIO_AUDIT_LOG_CHECKPOINT="$FIXTURE_DIR/audit_checkpoint"
export WAIO_AUDIT_INTEGRITY_ALERTS="$FIXTURE_DIR/audit_alerts.jsonl"
export WAIO_AUDIT_LOG_LOCK_DIR="$FIXTURE_DIR/audit_lock"
export EW_DATA_DIR="$FIXTURE_DIR/data"

echo "--- E1: weather_agent.sh fetches and merges hourly records ---"
OUT="$(./earth_weather/weather_agent.sh 2>&1)"; RC=$?
assert_eq "E1 exit code" "0" "$RC"
assert_contains "E1 output" "$OUT" "merged 3 fetched hour(s)"
assert_file_exists "E1 raw file written" "$EW_DATA_DIR/weather_raw.jsonl"
assert_eq "E1 raw file line count" "3" "$(wc -l < "$EW_DATA_DIR/weather_raw.jsonl" | tr -d ' ')"

echo "--- E2: re-running weather_agent.sh is idempotent (no duplicate hours) ---"
./earth_weather/weather_agent.sh >/dev/null 2>&1
assert_eq "E2 raw file still 3 lines after re-fetch" "3" "$(wc -l < "$EW_DATA_DIR/weather_raw.jsonl" | tr -d ' ')"

echo "--- E3: earthquake_agent.sh fetches and normalizes shindo/magnitude ---"
OUT="$(./earth_weather/earthquake_agent.sh 2>&1)"; RC=$?
assert_eq "E3 exit code" "0" "$RC"
assert_contains "E3 output" "$OUT" "merged 2 fetched event(s)"
MAXSHINDO_1="$(python3 -c "import json; [print(json.loads(l)['max_shindo']) for l in open('$EW_DATA_DIR/earthquake_raw.jsonl') if json.loads(l)['id']=='FIXTURE-EQ-1']")"
assert_eq "E3 shindo mapping (maxScale 40 -> 4)" "4" "$MAXSHINDO_1"
MAXSHINDO_2="$(python3 -c "import json; [print(json.loads(l)['max_shindo']) for l in open('$EW_DATA_DIR/earthquake_raw.jsonl') if json.loads(l)['id']=='FIXTURE-EQ-2']")"
assert_eq "E3 shindo mapping (maxScale 50 -> 5強)" "5強" "$MAXSHINDO_2"

echo "--- E4: earthquake time correctly converted JST -> UTC (09:00 JST -> 00:00 UTC) ---"
TS_UTC="$(python3 -c "import json; [print(json.loads(l)['ts_utc']) for l in open('$EW_DATA_DIR/earthquake_raw.jsonl') if json.loads(l)['id']=='FIXTURE-EQ-1']")"
assert_contains "E4 UTC conversion" "$TS_UTC" "2026-01-01T00:00:00"

echo "--- E5: weather_agent.sh degrades gracefully on API failure (does not crash) ---"
OUT="$(FAKE_CURL_FAIL_HOST="api.open-meteo.com" ./earth_weather/weather_agent.sh 2>&1)"; RC=$?
assert_eq "E5 exit code (failure reported, not a crash)" "1" "$RC"
assert_contains "E5 error message" "$OUT" "Open-Meteo fetch failed"
assert_contains "E5 fetch meta records error" "$(cat "$EW_DATA_DIR/cache/weather_last_fetch_meta.json")" "\"status\": \"error\""

echo "--- E6: data_normalizer.sh merges both raw files into one timeline ---"
OUT="$(./earth_weather/data_normalizer.sh 2>&1)"; RC=$?
assert_eq "E6 exit code" "0" "$RC"
assert_contains "E6 output" "$OUT" "3 weather record(s), 2 earthquake record(s)"
TIMELINE_COUNT="$(python3 -c "import json; print(len(json.load(open('$EW_DATA_DIR/timeline_latest.json'))))")"
assert_eq "E6 timeline_latest.json record count" "5" "$TIMELINE_COUNT"

echo "--- E7: correlation_engine.sh reports insufficient_data below EW_MIN_EQ_N ---"
OUT="$(EW_MIN_EQ_N=5 ./earth_weather/correlation_engine.sh 2>&1)"; RC=$?
assert_eq "E7 exit code" "0" "$RC"
assert_contains "E7 output" "$OUT" "insufficient data"
STATUS="$(python3 -c "import json; print(json.load(open('$EW_DATA_DIR/correlation_report.json'))['status'])")"
assert_eq "E7 report status" "insufficient_data" "$STATUS"

echo "--- E8: correlation_engine.sh never claims causation (caveats always present) ---"
CAVEATS_JOINED="$(python3 -c "import json; print(' '.join(json.load(open('$EW_DATA_DIR/correlation_report.json'))['caveats']))")"
assert_contains "E8 caveat mentions non-causality" "$CAVEATS_JOINED" "因果関係"

echo "--- E9: intelligence_layer.sh produces a summary even for insufficient_data ---"
OUT="$(./earth_weather/intelligence_layer.sh 2>&1)"; RC=$?
assert_eq "E9 exit code" "0" "$RC"
assert_file_exists "E9 summary txt written" "$EW_DATA_DIR/intelligence_summary.txt"
assert_contains "E9 summary mentions non-causality disclaimer" "$(cat "$EW_DATA_DIR/intelligence_summary.txt")" "因果関係の有無を示すものでは一切ありません"

echo "--- E10: run_pipeline.sh completes end-to-end and reports overall=degraded when weather API is down ---"
rm -rf "$EW_DATA_DIR"
mkdir -p "$EW_DATA_DIR"
OUT="$(FAKE_CURL_FAIL_HOST="api.open-meteo.com" ./earth_weather/run_pipeline.sh 2>&1)"; RC=$?
assert_eq "E10 exit code (degraded is not a fatal exit)" "0" "$RC"
assert_contains "E10 overall status" "$OUT" "overall=degraded"
assert_contains "E10 weather stage marked failed" "$OUT" "weather_agent=failed"
assert_contains "E10 earthquake stage still ok" "$OUT" "earthquake_agent=ok"
assert_file_exists "E10 summary still produced from earthquake-only data" "$EW_DATA_DIR/intelligence_summary.json"

echo "--- E11: run_pipeline.sh reports overall=ok when both APIs succeed ---"
rm -rf "$EW_DATA_DIR"
mkdir -p "$EW_DATA_DIR"
OUT="$(./earth_weather/run_pipeline.sh 2>&1)"; RC=$?
assert_eq "E11 exit code" "0" "$RC"
assert_contains "E11 overall status" "$OUT" "overall=ok"

echo "--- E12: workers/earthweather_worker.sh (through ./waio.sh -w EARTHWEATHER) prints the summary ---"
rm -rf "$EW_DATA_DIR"
mkdir -p "$EW_DATA_DIR"
OUT="$(./waio.sh -w EARTHWEATHER "run earth weather pipeline" 2>&1)"; RC=$?
assert_eq "E12 exit code" "0" "$RC"
assert_contains "E12 dispatched to correct worker" "$OUT" "dispatching to EARTHWEATHER WORKER"
assert_contains "E12 summary printed" "$OUT" "相関分析サマリー"

echo "--- E13: workers/earthweather_worker.sh rejects an empty request (same convention as every other worker) ---"
OUT="$(./workers/earthweather_worker.sh "" 2>&1)"; RC=$?
assert_eq "E13 exit code" "1" "$RC"
assert_contains "E13 error text" "$OUT" "empty request"

echo "--- E14: registry.conf registers EARTHWEATHER pointing at an executable script ---"
assert_contains "E14 registry entry present" "$(cat workers/registry.conf)" "EARTHWEATHER|750|workers/earthweather_worker.sh|earthweather"
if [ -x "workers/earthweather_worker.sh" ]; then
  PASS=$((PASS + 1)); echo "  PASS: E14 worker script executable"
else
  FAIL=$((FAIL + 1)); FAILURES+=("E14 worker script executable")
  echo "  FAIL: E14 worker script executable"
fi

echo "--- E15: egress destinations are allowlisted in the committed template ---"
assert_contains "E15 open-meteo in egress_allowlist.conf.example" "$(cat security/egress_allowlist.conf.example)" "api.open-meteo.com|443"
assert_contains "E15 p2pquake in egress_allowlist.conf.example" "$(cat security/egress_allowlist.conf.example)" "api.p2pquake.net|443"

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
