# WAIO structure (as of the registry/dispatch migration)

## Canonical dispatch path

```
waio.sh [-w NAME | --worker NAME | --worker=NAME] "<request>"
  -> reads workers/registry.conf  (NAME|HOST|SCRIPT|TYPE, one line per worker)
  -> resolves which worker to run, in this priority order:
       1. explicit -w/--worker override -> exact NAME match (case-insensitive)
       2. NAME-or-TYPE substring match against the request text, in
          registry file order (first entry whose NAME or TYPE appears wins)
       3. if the registry has exactly one entry, use it regardless
       4. otherwise: error, no silent default
  -> runs workers/<SCRIPT> locally (only HOST=750 is supported today)
```

`RESEARCH` behaves exactly as before (`waio.sh "RESEARCH: ..."` still matches
on step 2 as the first entry); the override flag and TYPE-based matching are
additive, not a replacement of the original keyword behavior.

Registered workers (`workers/registry.conf`): `RESEARCH`, `ANALYSIS`, `RPI`,
`ECHO`, `AI`. All run locally on 750; some (`RESEARCH`, `ANALYSIS`, `AI`) call
out to OpenRouter directly, and `RPI` internally SSHes to a Raspberry Pi
(192.168.1.150) itself — the dispatcher never SSHes anywhere on their behalf.
Today every worker's `TYPE` mirrors its `NAME` (lowercased), so TYPE-based
matching and NAME-based matching pick the same worker for all five; TYPE
matching starts to matter once a future worker's TYPE differs from its NAME
(verified with a temporary synthetic entry during testing, then reverted).

## Host roles

- **750** (`workers/750.json`, role: orchestrator) — this machine. Runs
  `waio.sh` and every registered worker script locally.
- **800号機** (`workers/800.json`, role: worker, host `192.168.1.91`) — a
  separate physical machine reached over SSH, used only by `jobs/` and
  `orchestrator/kuro.sh` for OS-level diagnostics (`system`/`identity`
  checks: hostname, OS version, uptime, disk). It is not a worker in the
  `registry.conf` sense — it has no request/response text contract, so it
  has not been folded into the registry.

## Deliberately not integrated

- **`jobs/`** — ad-hoc SSH diagnostic runners against 800号機. Different
  task shape than a `registry.conf` worker (fixed commands, not
  request/response). **Decision: kept as a separate, standalone tool —
  will not be folded into `registry.conf`/`waio.sh`.** (Phase 3 of the
  registry migration, which would have integrated it, was explicitly
  skipped.) Note: `jobs/test-job.sh` targets `192.168.1.193`, which does
  not match `workers/800.json`'s `192.168.1.91` — still unresolved, but
  out of scope since `jobs/` stays untouched.
- **`orchestrator/`** — earlier prototype, superseded by the path above. See
  `orchestrator/DEPRECATED.md`. Left untouched, not deleted.

## Known existing quirks (not fixed, since worker file contents are not to be
## modified without separate instruction)

- `workers/analysis_worker.sh` is near-byte-identical to `workers/ai_worker.sh`
  (same system prompt, same `[AI WORKER]` log tag) — likely a copy left over
  from when it was created. Dispatch still routes to it correctly via
  `registry.conf`; only its own internal log label is misleading.
