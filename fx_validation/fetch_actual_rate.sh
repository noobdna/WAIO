#!/bin/bash
set -uo pipefail

# fx_validation/fetch_actual_rate.sh -- Step 2 helper for the FX
# Forecast Validation Engine: fetches one live snapshot of the five
# tracked pairs (USD/JPY, EUR/USD, AUD/USD, GBP/USD, USD/CNY) from
# Frankfurter (api.frankfurter.dev), a keyless ECB-reference-rate API,
# no account/API key required -- same "keyless first" provider choice
# earth_weather/weather_agent.sh made for Open-Meteo, and for the same
# reason: no secret to provision or rotate for a read-only public rate
# feed.
#
# Frankfurter quotes everything as "1 USD = X <currency>", so EUR/USD,
# GBP/USD and AUD/USD (quoted market-convention as "1 <ccy> = X USD")
# are inverted here; USD/JPY and USD/CNY are used as-is.
#
# On any failure (egress denied, network error, non-200, missing/
# malformed field) this prints nothing on stdout and exits non-zero --
# it never fabricates a rate. The caller (run_validation.sh) is
# responsible for turning that into DATA_UNAVAILABLE; this script's own
# job stops at "did the fetch succeed, and if so, what are the five
# numbers."
#
# Test-only escape hatch: if WAIO_FX_FIXTURE_RATES_JSON is set, this
# script reads that local file instead of making any network call at
# all -- same idiom as WAIO_AUDIT_LOG/WAIO_SHUTDOWN_LOCK elsewhere in
# this codebase, so tests/fx_validation_test.sh never depends on a live
# network or real market data. The fixture file must have the same
# shape Frankfurter itself returns: {"rates": {"JPY":.., "EUR":.., ...}}.
#
# Usage: fx_validation/fetch_actual_rate.sh
# Output (stdout, on success only): one JSON object --
#   {"USDJPY":.., "EURUSD":.., "AUDUSD":.., "GBPUSD":.., "USDCNY":..,
#    "source":"...", "source_url":"...", "fetched_at":"..."}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"
source security/lib.sh

CACHE_DIR="${WAIO_FX_CACHE_DIR:-fx_validation/data/cache}"
mkdir -p "$CACHE_DIR"

FETCHED_AT="$(python3 -c 'import datetime; print(datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"))')"

write_fetch_meta() {
  python3 -c "
import json
json.dump({'status': '$1', 'fetched_at': '$FETCHED_AT'}, open('$CACHE_DIR/actual_rates_last_fetch_meta.json', 'w'))
"
}

if [ -n "${WAIO_FX_FIXTURE_RATES_JSON:-}" ]; then
  if [ ! -f "$WAIO_FX_FIXTURE_RATES_JSON" ]; then
    echo "[FX ACTUAL] ERROR: fixture file not found: $WAIO_FX_FIXTURE_RATES_JSON" >&2
    write_fetch_meta "error_fixture_missing"
    exit 1
  fi
  BODY_PATH="$WAIO_FX_FIXTURE_RATES_JSON"
  SOURCE_URL="fixture:$WAIO_FX_FIXTURE_RATES_JSON"
  SOURCE_LABEL="test fixture (no network call)"
else
  HOST="api.frankfurter.dev"
  PORT="443"
  if ! egress_check "$HOST" "$PORT" "" "" "FX_VALIDATION"; then
    echo "[FX ACTUAL] ERROR: egress denied by DLP guard -- request not sent" >&2
    write_fetch_meta "error_egress_denied"
    exit 1
  fi
  SOURCE_URL="https://$HOST/v1/latest?from=USD&to=JPY,EUR,GBP,AUD,CNY"
  SOURCE_LABEL="Frankfurter (ECB reference rates, keyless)"
  BODY_PATH="$(mktemp)"
  trap 'rm -f "$BODY_PATH"' EXIT
  STATUS="$(curl -s -m 15 -o "$BODY_PATH" -w "%{http_code}" "$SOURCE_URL" 2>/dev/null || echo "000")"
  if [ "$STATUS" != "200" ]; then
    echo "[FX ACTUAL] ERROR: Frankfurter fetch failed (HTTP $STATUS)" >&2
    write_fetch_meta "error_http_$STATUS"
    exit 1
  fi
fi

RESULT="$(python3 -c "
import json, sys
try:
    with open(sys.argv[1]) as f:
        body = json.load(f)
    rates = body['rates']
    out = {
        'USDJPY': rates['JPY'],
        'USDCNY': rates['CNY'],
        'EURUSD': 1.0 / rates['EUR'],
        'GBPUSD': 1.0 / rates['GBP'],
        'AUDUSD': 1.0 / rates['AUD'],
        'source': sys.argv[3],
        'source_url': sys.argv[2],
        'fetched_at': sys.argv[4],
    }
    print(json.dumps(out))
except (KeyError, TypeError, ValueError, json.JSONDecodeError) as e:
    print('ERROR: malformed rate data: ' + str(e), file=sys.stderr)
    sys.exit(1)
" "$BODY_PATH" "$SOURCE_URL" "$SOURCE_LABEL" "$FETCHED_AT")"
RC=$?

if [ $RC -ne 0 ] || [ -z "$RESULT" ]; then
  echo "[FX ACTUAL] ERROR: could not parse rate data from $SOURCE_URL" >&2
  write_fetch_meta "error_malformed_response"
  exit 1
fi

printf '%s' "$RESULT" > "$CACHE_DIR/actual_rates_last_success.json"
write_fetch_meta "ok"
printf '%s\n' "$RESULT"
