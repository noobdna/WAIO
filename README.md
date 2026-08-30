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

| NAME       | TYPE       | What it does                                                                 |
|------------|------------|-------------------------------------------------------------------------------|
| RESEARCH   | research   | Routes to the `waio-research` Takomachi agent                                 |
| ANALYSIS   | analysis   | Routes to the `waio-analysis` Takomachi agent                                 |
| AI         | ai         | Routes to the `waio-ai` Takomachi agent                                       |
| ORCHESTRATE| orchestrate| Chains RESEARCH → ANALYSIS → AI for one request, passing each result forward |
| RPI        | rpi        | SSHes to a Raspberry Pi worker itself                                         |
| HOST800    | infra      | SSHes to a registered remote host itself (read-only diagnostics)              |
| ECHO       | echo       | Echoes the request back (no network calls; useful for dry-run checks)         |

Add a worker by adding one `NAME|HOST|SCRIPT|TYPE` line to
`workers/registry.conf` and dropping the script in `workers/`.

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

## Repo layout

- `waio.sh` — the dispatcher.
- `workers/registry.conf` — the worker registry (see comments in the file).
- `workers/*_worker.sh` — one script per registered worker.
- `workers/*.json` — per-host metadata (name, role, host, user).
- `orchestrator/`, `jobs/` — earlier prototypes / standalone tools, kept
  for reference; not part of the canonical dispatch path (see
  `ARCHITECTURE.md`).
