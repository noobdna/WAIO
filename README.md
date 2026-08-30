# WAIO

A minimal, registry-driven request dispatcher. `waio.sh` takes a single
request, resolves it to a registered worker, and runs that worker — some
workers route through Takomachi (a local task-queue/agent-manager service)
to an LLM agent, others act locally or over SSH.

See [`ARCHITECTURE.md`](ARCHITECTURE.md) for the full design history and
phase-by-phase rationale. This README is just the quick-start.

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
    `waio-research`/`waio-analysis`/`waio-ai` agents registered, and
  - a `TAKOMACHI_API_KEY` retrievable from the macOS Keychain
    (`security find-generic-password -a "$(whoami)" -s "com.takomachi.api-key" -w`).
    No API key or credential is ever embedded in this repo's source.
- `RPI`/`HOST800` need SSH access to their respective hosts
  (`workers/750.json`/`workers/800.json`).
- Every destination above must also be listed in
  `security/egress_allowlist.conf` (already true for all workers listed
  here) — see "DLP / Emergency Shutdown Layer" above.

## Repo layout

- `waio.sh` — the dispatcher.
- `workers/registry.conf` — the worker registry (see comments in the file).
- `workers/*_worker.sh` — one script per registered worker.
- `workers/*.json` — per-host metadata (name, role, host, user).
- `workers/pipeline.conf` — `ORCHESTRATE`'s fixed fallback pipeline.
- `security/` — the DLP / Emergency Shutdown layer (`lib.sh`,
  `egress_allowlist.conf`, `recover.sh`).
- `tests/` — automated regression suites:
  `orchestrate_worker_test.sh`, `waio_test.sh`, `security_test.sh` (a
  local Red Team harness for the DLP layer — no real external service is
  ever contacted). Run any of them directly, e.g. `./tests/waio_test.sh`.
- `orchestrator/`, `jobs/` — earlier prototypes / standalone tools, kept
  for reference; not part of the canonical dispatch path (see
  `ARCHITECTURE.md`).
