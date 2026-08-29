# WAIO structure (as of the registry/dispatch migration)

## Canonical dispatch path

```
waio.sh "<NAME>: <request>"
  -> reads workers/registry.conf  (NAME|HOST|SCRIPT|TYPE, one line per worker)
  -> matches <NAME> case-insensitively against the request text
     (first match in file order wins; falls back to the sole registered
     worker only when exactly one is registered)
  -> runs workers/<SCRIPT> locally (only HOST=750 is supported today)
```

Registered workers (`workers/registry.conf`): `RESEARCH`, `ANALYSIS`, `RPI`,
`ECHO`, `AI`. All run locally on 750; some (`RESEARCH`, `ANALYSIS`, `AI`) call
out to OpenRouter directly, and `RPI` internally SSHes to a Raspberry Pi
(192.168.1.150) itself — the dispatcher never SSHes anywhere on their behalf.

## Host roles

- **750** (`workers/750.json`, role: orchestrator) — this machine. Runs
  `waio.sh` and every registered worker script locally.
- **800号機** (`workers/800.json`, role: worker, host `192.168.1.91`) — a
  separate physical machine reached over SSH, used only by `jobs/` and
  `orchestrator/kuro.sh` for OS-level diagnostics (`system`/`identity`
  checks: hostname, OS version, uptime, disk). It is not a worker in the
  `registry.conf` sense — it has no request/response text contract, so it
  has not been folded into the registry.

## Not yet migrated

- **`jobs/`** — ad-hoc SSH diagnostic runners against 800号機. Different
  task shape than a `registry.conf` worker (fixed commands, not
  request/response). Left as its own tool pending a decision on whether it
  gets a parallel "job" registry or stays separate. Note:
  `jobs/test-job.sh` targets `192.168.1.193`, which does not match
  `workers/800.json`'s `192.168.1.91` — unresolved, flagged for whoever
  picks this up next.
- **`orchestrator/`** — earlier prototype, superseded by the path above. See
  `orchestrator/DEPRECATED.md`. Left untouched, not deleted.

## Known existing quirks (not fixed, since worker file contents are not to be
## modified without separate instruction)

- `workers/analysis_worker.sh` is near-byte-identical to `workers/ai_worker.sh`
  (same system prompt, same `[AI WORKER]` log tag) — likely a copy left over
  from when it was created. Dispatch still routes to it correctly via
  `registry.conf`; only its own internal log label is misleading.
