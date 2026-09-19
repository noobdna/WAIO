# WAIO

A minimal, registry-driven request dispatcher. `waio.sh` takes a single
request, resolves it to a registered worker, and runs that worker — some
workers route through Takomachi (a local task-queue/agent-manager service)
to an LLM agent, others act locally or over SSH.

See [`ARCHITECTURE.md`](ARCHITECTURE.md) for the full design history and
phase-by-phase rationale. This README is just the quick-start.

## Setup

Three files hold this deployment's real hostnames/IPs/usernames and are
gitignored, not committed — copy each `.example` template, fill in your
real values, and the real file stays local-only:

```
cp workers/750.json.example workers/750.json
cp workers/800.json.example workers/800.json
cp security/egress_allowlist.conf.example security/egress_allowlist.conf
```

If any of these is missing entirely, WAIO fails closed rather than
guessing: a worker that reads `workers/800.json` errors out, and the DLP
layer's `egress_check()` (see below) denies every outbound connection
and trips Emergency Shutdown when `security/egress_allowlist.conf` isn't
there.

## Usage

```
./waio.sh [-w NAME | --worker NAME | --worker=NAME] "<request>"
```

Worker resolution order:

1. Explicit `-w`/`--worker` override — exact `NAME` match (case-insensitive).
2. `NAME`/`TYPE` substring match against the request text, in
   `workers/registry.conf` file order (first match wins).
3. If exactly one worker is registered, use it regardless.
4. Otherwise: error — no silent default.

```
./waio.sh "RESEARCH: summarize recent news on X"
./waio.sh -w ORCHESTRATE "compare two market strategies and give a recommendation"
```

## Registered workers

| NAME        | TYPE        | What it does                                                                   |
|-------------|-------------|---------------------------------------------------------------------------------|
| RESEARCH    | research    | Routes to the `waio-research` Takomachi agent                                   |
| ANALYSIS    | analysis    | Routes to the `waio-analysis` Takomachi agent                                   |
| AI          | ai          | Routes to the `waio-ai` Takomachi agent                                         |
| ORCHESTRATE | orchestrate | Runs a multi-stage pipeline for one request (see below)                         |
| RPI         | rpi         | SSHes to a Raspberry Pi worker itself                                           |
| HOST800     | infra       | SSHes to a registered remote host itself (read-only diagnostics)                |
| HEALTHCHECK | healthcheck | Queries Takomachi's own `GET /health` and reports agent/queue/plugin status     |
| ECHO        | echo        | Echoes the request back (no network calls; useful for dry-run checks)           |
| EARTHWEATHER | earthweather | Runs the Earth & Weather Intelligence pipeline (weather + earthquake data, correlation analysis) -- see below |

### ORCHESTRATE: the WAIO Controller

`ORCHESTRATE` runs a **pipeline** of the registered workers above (each
stage is itself resolved through the same registry, so it inherits every
worker's own dispatch/host/credential handling), not a fixed
RESEARCH→ANALYSIS→AI chain. Pipeline selection, highest priority first:

1. `WAIO_PIPELINE` env var — an explicit, space-separated list of NAMEs
   for that one call, e.g. `WAIO_PIPELINE="RESEARCH AI" ./waio.sh -w ORCHESTRATE "..."`.
2. **Router** — if no override is set, WAIO matches the request text
   against every registered NAME/TYPE (same substring rule as single-worker
   dispatch) and runs all matches, in registry order.
3. `workers/pipeline.conf` — a fixed fallback pipeline, used only if the
   Router found no match at all.

A stage token may also be:

- a `+`-joined group, e.g. `RESEARCH+ANALYSIS`, to run those workers
  concurrently (optionally capped with `WAIO_MAX_PARALLEL=N`) and merge
  their results before the next stage;
- prefixed `?ok:`/`?fail:` (case-insensitive), e.g. `?fail:ECHO`, to run
  that stage only if the immediately preceding stage succeeded/failed.

A failed stage does not abort the run — its error is forwarded into the
next stage's input, and the run's `overall_status` (`ok`/`degraded`/
`failed`, exit `0`/`1`/`2`) reflects whether the *final* stage still
produced a trustworthy answer. Every run writes a log (`logs/`) and a
human- and machine-readable result (`results/*.txt`/`*.json`). Full
detail, including every phase this was built up in, is in
[`ARCHITECTURE.md`](ARCHITECTURE.md).

Add a worker by adding one `NAME|HOST|SCRIPT|TYPE` line to
`workers/registry.conf`, dropping the script in `workers/`, and — if it
makes a real outbound connection (SSH/HTTP) — adding its destination to
`security/egress_allowlist.conf` (see below); an unlisted destination is
refused, not silently allowed.

### EARTHWEATHER: Earth & Weather Intelligence (PoC)

`EARTHWEATHER` runs a 5-stage pipeline (`earth_weather/*.sh`): Weather
Agent (Open-Meteo, keyless -- pressure/temperature/precipitation/
humidity/wind) -> Earthquake Agent (P2P地震情報, keyless -- event time,
hypocenter, magnitude, max shindo) -> Data Normalizer (merges both into
one UTC-indexed timeline) -> Correlation Engine (Pearson r + a
permutation-test p-value at each of a range of time lags, per weather
variable, with Bonferroni correction across every test run) ->
Intelligence Layer (classifies each variable's result and writes a
human-readable summary). **This explicitly does not assume weather and
earthquakes are related** -- every output states both the raw and
Bonferroni-corrected significance and repeats the same non-causality
caveat, and a period with too few nearby earthquakes is reported as
`insufficient_data` rather than a fabricated correlation.

```
./waio.sh -w EARTHWEATHER "run"          # one-off run through the dispatcher
./earth_weather/run_pipeline.sh          # equivalent, run directly
```

A failed Weather/Earthquake API call degrades that one stage (logged,
never crashes the pipeline or the rest of WAIO) -- see
`earth_weather/run_pipeline.sh`'s own header. Results land in
`earth_weather/data/` (gitignored, like `logs/`/`results/`):
`timeline.jsonl`/`timeline_latest.json`, `correlation_report.json`,
`intelligence_summary.json`/`.txt`. View them with
`dashboard/earth_weather.html` (same `python3 -m http.server`
convention as `dashboard/index.html`) or schedule the pipeline with
`earth_weather/com.waio.earth-weather.plist.example`. Optional env
vars (`EW_LAT`/`EW_LON`/`EW_EQ_RADIUS_KM`/`EW_LOOKBACK_HOURS`/
`EW_LAG_MAX_HOURS`, default: Tokyo / 300km / 30 days / 48h) go in
`~/.waio.env`, same as every other WAIO override -- no API key is
needed for the default providers. Official JMA-style weather warnings
are not available from the keyless Open-Meteo provider this PoC
defaults to; that gap is reported explicitly, not silently dropped.

### Global expansion (world-scale, not yet wired into the dispatcher)

`earth_weather/*_global.sh` extends the same pipeline to worldwide,
keyless data: `earth_weather/stations.conf` (10 diverse stations plus
one intentional low-seismicity control point) for Open-Meteo weather,
and the USGS Earthquake Catalog (`earthquake.usgs.gov`, keyless) for
worldwide events. Same non-causality method (per-station + a pooled
cross-station test, both Bonferroni-corrected). **Deliberately not
registered as a `workers/registry.conf` worker and not added to
`security/egress_allowlist.conf`** — run it directly:

```
./earth_weather/run_pipeline_global.sh
```

Test with `./tests/earth_weather_global_test.sh` (fixture-only, no
real network, isolated from production security state). Wiring this
into the live dispatcher/egress allowlist is a separate, later,
explicitly-gated decision -- see ARCHITECTURE.md's "global expansion"
phase entry.

## DLP / Emergency Shutdown Layer

Every real outbound connection (SSH or HTTP) any worker makes is checked
against `security/egress_allowlist.conf` first. An unlisted destination,
an anomalously large outbound payload, or a credential-shaped string
found in a worker's own response trips an **Emergency Shutdown**:
`security/state/SHUTDOWN.lock` is written (gitignored — this is runtime
state, not source) and every subsequent `./waio.sh` call, for any
worker, is refused until it is cleared.

- **Recovery is manual and explicit** —
  `./security/recover.sh --confirm "<reason>"` is the only way to clear
  it; it refuses to run without a non-empty reason, and there is no
  auto-recovery.
- **Audit trail**: every allow/deny/shutdown/recovery decision is
  appended as one JSON line to `logs/security-audit.jsonl` — destination
  and reason only, never a secret value, credential, or payload/response
  body.
- Full threat model, design rationale, and known limitations are in
  [`ARCHITECTURE.md`](ARCHITECTURE.md)'s "DLP / Emergency Shutdown
  Layer" section.

## Requirements

- The three Takomachi-backed workers (`RESEARCH`/`ANALYSIS`/`AI`, and by
  extension `ORCHESTRATE`) need:
  - a Takomachi instance running locally (`http://localhost:3000`) with the
    agent ids listed in `workers/takomachi_agents.conf` registered -- run
    `./workers/register_takomachi_agents.sh` once (idempotent, safe to
    re-run any time) to provision them; each worker resolves its own
    `target_agent_id` from that same file by capability tag at request
    time, never a hardcoded id, and
  - a `TAKOMACHI_API_KEY` retrievable from the macOS Keychain
    (`security find-generic-password -a "$(whoami)" -s "com.takomachi.api-key" -w`).
    No API key or credential is ever embedded in this repo's source.
  - `dashboard/collect_takomachi_status.sh`'s `expected_agents` section
    reports any id from `workers/takomachi_agents.conf` that isn't
    actually registered in Takomachi, so a mismatch (e.g. after
    Takomachi's own local database is rebuilt) is visible as an explicit
    "missing" list rather than only surfacing later as a dispatch failure.
- `RPI`/`HOST800` need SSH access to their respective hosts
  (`workers/750.json`/`workers/800.json`).
- Every destination above must also be listed in
  `security/egress_allowlist.conf` (already true for all workers listed
  here) — see "DLP / Emergency Shutdown Layer" above.

## Repo layout

- `waio.sh` — the dispatcher.
- `workers/registry.conf` — the worker registry (see comments in the file).
- `workers/*_worker.sh` — one script per registered worker.
- `workers/*.json` — per-host metadata (name, role, host, user);
  gitignored, see "Setup" above — `workers/*.json.example` are the
  committed templates.
- `workers/pipeline.conf` — `ORCHESTRATE`'s fixed fallback pipeline.
- `workers/takomachi_agents.conf` — single source of truth for every
  Takomachi agent id the Takomachi-backed workers dispatch to (see
  comments in the file); `workers/register_takomachi_agents.sh` provisions
  them idempotently (GET-before-POST, never overwrites).
- `security/` — the DLP / Emergency Shutdown layer (`lib.sh`,
  `recover.sh`, and `egress_allowlist.conf` — gitignored, see "Setup"
  above; `egress_allowlist.conf.example` is the committed template).
- `tests/` — automated regression suites:
  `orchestrate_worker_test.sh`, `waio_test.sh`, `security_test.sh` (a
  local Red Team harness for the DLP layer — no real external service is
  ever contacted). Run any of them directly, e.g. `./tests/waio_test.sh`.
- `earth_weather/` — the Earth & Weather Intelligence PoC pipeline
  (`weather_agent.sh`, `earthquake_agent.sh`, `data_normalizer.sh`,
  `correlation_engine.sh`, `intelligence_layer.sh`, `run_pipeline.sh`);
  see "EARTHWEATHER" above. `earth_weather/data/` (gitignored) holds
  its runtime output.
- `orchestrator/`, `jobs/` — earlier prototypes / standalone tools, kept
  for reference; not part of the canonical dispatch path (see
  `ARCHITECTURE.md`).
