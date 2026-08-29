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
`ECHO`, `AI`, `HOST800`. All run locally on 750; some (`RESEARCH`,
`ANALYSIS`, `AI`) call out to OpenRouter directly, `RPI` internally SSHes to
a Raspberry Pi (192.168.1.150) itself, and `HOST800` internally SSHes to
800号機 itself (see "Phase 4" below) — the dispatcher never SSHes anywhere
on their behalf.
Across `RESEARCH`/`ANALYSIS`/`RPI`/`ECHO`/`AI`, every worker's `TYPE`
mirrors its `NAME` (lowercased), so TYPE-based and NAME-based matching pick
the same worker. `HOST800` is the first registered worker whose `TYPE`
(`infra`) differs from its `NAME` — the real-world case the TYPE-matching
path was built for (previously only verified with a temporary synthetic
entry during testing, then reverted).

## Host roles

- **750** (`workers/750.json`, role: orchestrator) — this machine. Runs
  `waio.sh` and every registered worker script locally.
- **800号機** (`workers/800.json`, role: worker, host `192.168.1.91`) — a
  separate physical machine reached over SSH. Two independent paths reach
  it: `jobs/`/`orchestrator/kuro.sh` (ad-hoc, fixed-command diagnostics —
  see "Deliberately not integrated" below) and, as of Phase 4,
  `registry.conf`'s `HOST800` entry — see "Phase 4" below.

## Phase 4 (commit `c565177`): HOST800 registry adapter

- `workers/registry.conf` now has a
  `HOST800|750|workers/host800_worker.sh|infra` entry — 800号機 **is**
  registered in the registry, reachable via `waio.sh -w HOST800 "..."` or
  the `HOST800` keyword.
- `workers/host800_worker.sh` is the worker script that entry points to: a
  thin request/response adapter (same self-contained-SSH pattern as
  `rpi_worker.sh`) that maps `system`/`identity` request keywords to the
  same read-only diagnostic commands `jobs/run-job.sh` already runs, and
  errors out on any other job type before attempting SSH.
- It has no hardcoded host or user — at request time it reads both from
  `workers/800.json` (`host`: `192.168.1.91`, `user`: `masa`), the same
  file `jobs/` already uses. `workers/800.json` itself was not modified by
  Phase 4.
- This adapter and its registry entry were added entirely in Phase 4
  (commit `c565177`, 2026-08-29); `jobs/`, `orchestrator/`, and every other
  worker script were left untouched (verified byte-identical). The
  standalone-tool decision for `jobs/`/`orchestrator/` (below) is
  unaffected — Phase 4 only added a second, independent path to 800号機.
- As of Phase 4, only the dispatch path and the pre-ssh guard clauses
  (empty request / unsupported job type) have been dry-run tested. The
  worker's own `ssh -o BatchMode=yes ...` call has not been exercised
  through this adapter — real SSH auth to 800号機 via `host800_worker.sh`
  is still untested and deferred pending explicit approval.

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
