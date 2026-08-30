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
`ANALYSIS`, `AI`) route through Takomachi, which then dispatches to the
underlying LLM provider (see "Takomachi integration Phase 2" below — before
that migration they called OpenRouter directly), `RPI` internally SSHes to
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

## Takomachi integration Phase 2 (commit `964e348`, 2026-08-30): LLM workers routed through Takomachi

This "Phase 2" numbering belongs to a separate planning track (WAIO ↔
Takomachi LLM-backend integration) from the registry-migration phases
above (1-4, with Phase 3 explicitly skipped — see "Deliberately not
integrated"). The two numbering schemes are independent; this section does
not continue Phase 4 above.

- `workers/research_worker.sh`, `workers/analysis_worker.sh`, and
  `workers/ai_worker.sh` no longer call OpenRouter directly. Each now:
  1. reads `TAKOMACHI_API_KEY` from macOS Keychain
     (`security find-generic-password -a "$(whoami)" -s "com.takomachi.api-key" -w`),
  2. `POST`s to `http://localhost:3000/tasks` with a fixed `target_agent_id`
     (`waio-research` / `waio-analysis` / `waio-ai` respectively) and the
     request text as the sole user message,
  3. polls `GET /tasks/:id` (up to 90s) until `status` is `completed` or
     `failed`, and
  4. prints `result.content` (or exits non-zero on any failure), never
     printing key/Authorization material at any step.
- The three Takomachi Agents (`waio-research`/`waio-analysis`/`waio-ai`,
  `provider=openrouter`, `model=openai/gpt-4o-mini`, `capability_tags`
  `research`/`analysis`/`ai` respectively) were registered ahead of time via
  the Takomachi repo's `scripts/register-waio-agents.sh` (GET-before-POST,
  never overwrites an existing agent) and reuse the `openrouter` provider
  credential already stored in Takomachi's own credential store — no
  separate OpenRouter key is used by these three workers anymore.
  `~/.waio.env`'s `OPENROUTER_API_KEY` is unreferenced by any currently
  registered worker as of this commit; it has not been rotated or removed
  (pending a separate decision, out of scope for this migration).
- Operational constraint confirmed during verification: `TAKOMACHI_API_KEY`
  retrieval only succeeded from an interactive GUI Terminal session with
  Keychain access. A non-interactive/sandboxed shell (an automation tool
  without a GUI session) failed the Keychain lookup and the worker exited
  with an explicit, secret-free error instead of falling back to any other
  credential source. These three workers are therefore GUI-Terminal-only
  today; unattended/cron-style execution would need further design work
  (a separate decision, not made here).
- Takomachi's own dispatch/queue/provider-adapter code (`src/`) was not
  modified for this migration — the existing `/agents` and `/tasks` API
  already covered everything needed.
- Not migrated, and out of scope for this integration: `RPI`, `ECHO`,
  `HOST800` — none of them calls an LLM provider (`RPI`/`HOST800` SSH
  directly, `ECHO` just echoes).
- End-to-end verified 2026-08-30: all three workers dispatched a minimal
  request ("Reply with exactly one word: ok") through Takomachi to their
  respective agent and received `status=completed` with the expected short
  response, each within the 90s deadline.

## Phase 5 (2026-08-30): minimal multi-agent orchestration (research → analysis → ai)

- `workers/orchestrate_worker.sh` is a new worker script, registered as
  `ORCHESTRATE|750|workers/orchestrate_worker.sh|orchestrate` (added above
  `RESEARCH` in `workers/registry.conf` so that a request containing both
  "ORCHESTRATE" and, say, "research" as plain words still keyword-matches
  `ORCHESTRATE` first — file order is match priority, per
  `workers/registry.conf`'s own header comment). Invoke it via
  `waio.sh -w ORCHESTRATE "<request>"` or a request whose text contains
  "ORCHESTRATE".
- It takes one request and runs it through `waio-research` →
  `waio-analysis` → `waio-ai` in sequence, using the exact same Takomachi
  contract the three existing workers already use (`POST /tasks` with
  `target_agent_id`/`payload.messages`, then poll `GET /tasks/:id` up to
  90s per stage) — no Task schema or Takomachi endpoint changes. Each
  stage's `result.content` is concatenated into the next stage's payload
  text (research result → analysis's input; research+analysis results →
  ai's input), so the final `waio-ai` response reflects all three stages.
  This chaining happens entirely in the new script; Takomachi's `depends_on`
  task field only gates dequeue ordering and does not itself pass a
  dependency's result into a dependent task's payload, so it was not used
  here — sequential client-side orchestration was the minimal fit.
- Credential handling is unchanged: same Keychain lookup
  (`security find-generic-password -a "$(whoami)" -s "com.takomachi.api-key" -w`)
  as `research_worker.sh`/`analysis_worker.sh`/`ai_worker.sh`, no new
  secrets, nothing embedded in source.
- `research_worker.sh`, `analysis_worker.sh`, `ai_worker.sh`, `waio.sh`,
  and every other registered worker were left untouched.
- Unrelated pre-existing issue fixed as a prerequisite for testing this
  phase: `~/.waio.env` had been reduced to a single 74-byte line with no
  `OPENROUTER_API_KEY=` variable-name prefix (just the raw key), which made
  `waio.sh`'s `source ~/.waio.env` (under `set -euo pipefail`) fail before
  reaching any dispatch logic — this blocked all workers, not just the new
  one. Fixed by prepending the missing `OPENROUTER_API_KEY=` back onto the
  existing line (value untouched); confirmed with the user before editing
  this file, since it holds a live credential outside the repo.
- End-to-end verified 2026-08-30: `waio.sh -w ORCHESTRATE "..."` ran all
  three stages and returned a coherent final `waio-ai` response
  incorporating the research and analysis stages, in ~7s total. Explicit
  `-w RESEARCH`/`-w ANALYSIS`/`-w AI` and keyword dispatch for all
  pre-existing workers were re-verified unaffected.

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

## Known existing quirks (historical)

- `workers/analysis_worker.sh` was near-byte-identical to
  `workers/ai_worker.sh` (same system prompt, same `[AI WORKER]` log tag)
  prior to commit `964e348` — likely a copy left over from when it was
  created. **Resolved** as a side effect of the Takomachi migration above:
  each worker was rewritten independently and now has its own log tag
  (`[ANALYSIS WORKER]`/`[AI WORKER]`) and its own `target_agent_id`
  (`waio-analysis`/`waio-ai`), so this is no longer an open issue.
