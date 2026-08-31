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
`ECHO`, `AI`, `HOST800`, `HEALTHCHECK` (added Phase 6, below). All run
locally on 750; some (`RESEARCH`, `ANALYSIS`, `AI`) route through
Takomachi, which then dispatches to the underlying LLM provider (see
"Takomachi integration Phase 2" below — before that migration they
called OpenRouter directly); `HEALTHCHECK` also routes through Takomachi,
but queries its own `GET /health` status endpoint directly, not an LLM
agent. `RPI` internally SSHes to a Raspberry Pi (192.168.1.150) itself,
and `HOST800` internally SSHes to 800号機 itself (see "Phase 4" below) —
the dispatcher never SSHes anywhere on their behalf.
Across `RESEARCH`/`ANALYSIS`/`RPI`/`ECHO`/`AI`/`HEALTHCHECK`, every
worker's `TYPE` mirrors its `NAME` (lowercased), so TYPE-based and
NAME-based matching pick the same worker. `HOST800` is the first
registered worker whose `TYPE`
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

## Phase 6 (2026-08-30): health-check worker

- `workers/healthcheck_worker.sh`, registered as
  `HEALTHCHECK|750|workers/healthcheck_worker.sh|healthcheck` in
  `workers/registry.conf`. Invoke via `waio.sh -w HEALTHCHECK "..."` or a
  request containing "HEALTHCHECK".
- Calls Takomachi's existing `GET /health` endpoint
  (`src/api-gateway/server.ts`, auth applied the same as every other
  route — no new Takomachi-side endpoint or schema) and prints
  `agent_manager`/`task_queue`/`plugin_system` status, counts, and
  `checked_at`. Warns (but does not fail) when `agent_manager` reports
  `degraded`, matching Takomachi's own "degraded is data, not a thrown
  error" design. Only a non-200 HTTP response (unreachable Takomachi,
  bad/missing credential) is treated as a hard failure (non-zero exit).
- Same Keychain credential lookup as every other worker; no new secrets.
- End-to-end verified 2026-08-30: `waio.sh -w HEALTHCHECK "check"` and
  plain-keyword `waio.sh "HEALTHCHECK please"` both dispatched correctly
  and returned live status (at verification time: `task_queue`/
  `plugin_system` ok, `agent_manager` degraded — 2 of 7 known agents
  currently in an error state; not investigated further here, out of
  scope for this change).

## Phase 7 (2026-08-30): WAIO Controller — Registry-driven pipeline

Redesigns `workers/orchestrate_worker.sh`'s internals (same file, same
registry entry `ORCHESTRATE|750|workers/orchestrate_worker.sh|orchestrate`,
same CLI contract — `waio.sh -w ORCHESTRATE "<request>"` still works
exactly as documented in Phase 5) to make the Registry the single source
of truth for which Agents/Workers run, instead of Phase 5's hardcoded
`waio-research`/`waio-analysis`/`waio-ai` Takomachi calls baked directly
into the script.

- **New file `workers/pipeline.conf`**: an ordered, newline-separated list
  of `workers/registry.conf` NAMEs (default: `RESEARCH`, `ANALYSIS`, `AI`
  — identical to Phase 5's fixed pipeline, so the default behavior is
  unchanged). This is the only place the pipeline's shape is defined; the
  Controller reads it at run time and never hardcodes a NAME, an Agent id,
  or a Takomachi call.
- **Flow**: REQUEST (the incoming request text) → ROUTE (look up each
  `pipeline.conf` NAME's entry in `workers/registry.conf`, exactly as
  `waio.sh` already does) → EXECUTE (`./waio.sh -w <NAME> "<stage input>"`
  — the Controller shells out to the existing top-level dispatcher for
  every stage, the same entry point a human operator uses, so it inherits
  registry resolution, host checks, and every worker's own credential
  handling for free) → COLLECT (strip each worker's own dispatch/log
  noise, keeping only the content after its `"] response:"` marker line —
  a convention every current Takomachi-backed worker already follows
  without modification) → RESULT (the last stage's collected content,
  plus a per-run log and result file).
- **Failed-worker-forwards-to-next-worker**: unlike Phase 5 (which
  `exit 1`'d immediately on any stage failure), a stage's failure no
  longer aborts the run. Its exit code and collected output (e.g. an
  HTTP/task error) are folded into the next stage's input, labeled
  `<NAME> (FAILED):`, so a later stage (or whoever reads the log) still
  sees what happened. The run's `overall_status` is `degraded` if any
  stage failed (`ok` otherwise), and the Controller's own exit code
  reflects that (`0` iff every stage was `ok`) — so a caller can still
  detect an unhealthy run without the pipeline stopping short. Verified
  with a controlled test: `ECHO → NONEXISTENT → ECHO` ran all three
  stages, stage 2 correctly reported `failed`/exit 1, its error text was
  visible inside stage 3's received input, and the overall run reported
  `overall_status: degraded`, exit code 1.
- **Logging/traceability**: every run writes `logs/orchestrate-<run_id>.log`
  (stage-by-stage status and collected output) and
  `results/orchestrate-<run_id>.txt` (pipeline, per-stage status,
  overall_status, final result) — reactivating the `logs/`/`results/`
  convention `orchestrator/dispatch.sh` used before the registry
  migration, now gitignored and wired into the canonical path.
- **Extensibility**: adding Claude/OpenAI/Gemini/a local agent needs no
  Controller change — register a new worker script + one
  `registry.conf` line (as every existing worker already does) and
  optionally add its NAME to `pipeline.conf`. The Controller only ever
  deals in Registry NAMEs.
- Credential handling: unchanged in spirit, but the Controller itself no
  longer touches Keychain or Takomachi directly at all (it has no
  `TAKOMACHI_API_KEY` lookup, no `curl`, no Task JSON parsing) — each
  stage's own worker script (`research_worker.sh`/`analysis_worker.sh`/
  `ai_worker.sh`, themselves untouched) handles its own credential exactly
  as before. This removes ~60 lines of duplicated HTTP/Keychain logic from
  the Controller.
- `waio.sh`, `workers/registry.conf`, and every individual worker script
  (`research_worker.sh`/`analysis_worker.sh`/`ai_worker.sh`/
  `healthcheck_worker.sh`/`host800_worker.sh`/`rpi_worker.sh`/
  `echo_worker.sh`) are untouched.
- End-to-end verified 2026-08-30: the default pipeline
  (`waio.sh -w ORCHESTRATE "..."`) still runs RESEARCH → ANALYSIS → AI and
  returns a coherent final result, now via Registry-driven dispatch
  instead of direct Takomachi calls; log and result files were inspected
  and contain only each stage's actual content (dispatch-line noise
  correctly stripped by the COLLECT step).
- Not implemented (see "next steps" in the accompanying session report):
  per-request pipeline override (today `pipeline.conf` defines a single,
  fixed default pipeline); parallel/branching stages (today strictly
  sequential); and no attempt was made to reconcile this with Takomachi's
  own `depends_on` task field (still unused, per Phase 5's reasoning — it
  only gates dequeue order, it does not pass a result between tasks).

## Phase 8 (2026-08-30): WAIO Controller as a formal external entry point

Polishes Phase 7's Controller (`workers/orchestrate_worker.sh`) into a
finished external execution interface, without changing its registration,
CLI contract, or exit-code semantics.

- **Formal entry point, unchanged**: `./waio.sh -w ORCHESTRATE "<request>"`
  is the one documented way to invoke the Controller — no new
  `registry.conf` entry, no new top-level script. `workers/registry.conf`
  and `workers/pipeline.conf` are byte-identical to Phase 7.
- **Execution path made explicit in the log**: every stage now logs its
  `ROUTE` (which registry NAME was resolved), `EXECUTE`
  (`./waio.sh -w NAME`), and `COLLECT` (status=ok/failed) sub-steps by
  name, and the run as a whole logs `REQUEST` at the start and `RESULT` at
  the end — the same REQUEST → ROUTE → EXECUTE → COLLECT → RESULT flow
  Phase 7 implemented, now labeled at each point instead of only
  implicit in the code.
- **`run_id` and traceability, unchanged in guarantee**: every run still
  unconditionally generates a `run_id` and writes
  `logs/orchestrate-<run_id>.log` and
  `results/orchestrate-<run_id>.txt`.
- **New: machine-readable result**, `results/orchestrate-<run_id>.json` —
  written on every run alongside the existing human-readable `.txt`
  (which is unchanged). Contains `run_id`, `pipeline` (array),
  `stages` (array of `{name, status, exit_code, result}` — the per-stage
  machine-readable status item 5 of this phase's requirements asked for),
  `overall_status`, `final_result`, `log_path`, `result_txt_path`. Built
  via `python3 -c` reading a temporary per-stage JSONL scratch file
  (`mktemp`, cleaned up on exit) so no stage's arbitrary text content is
  ever interpolated into Python source — every value crosses the
  bash/python boundary as an argv string or a JSON-encoded line, never as
  inline string substitution.
- **Human vs. machine output, deliberately not conflated**: stdout stays
  exactly the same kind of human-readable `[ORCHESTRATE WORKER] ...` text
  Phase 7 produced (plus the new ROUTE/EXECUTE/COLLECT/REQUEST/RESULT
  labels); the structured per-stage status data lives only in the new
  `.json` file, never printed inline on stdout. A caller that wants
  machine-readable output reads that file directly instead of parsing
  log text.
- **Exit code semantics unchanged**: `0` iff every stage's status was
  `ok`, `1` (`overall_status: degraded`) if any stage failed — verified
  again this phase (see tests below), matching Phase 7 exactly.
- `waio.sh`, `workers/registry.conf`, `workers/pipeline.conf`, and every
  individual worker script (`research_worker.sh`/`analysis_worker.sh`/
  `ai_worker.sh`/`healthcheck_worker.sh`/`host800_worker.sh`/
  `rpi_worker.sh`/`echo_worker.sh`) are untouched. No new
  `registry.conf` entries were added.
- End-to-end verified 2026-08-30, three cases:
  1. **Success path**: `waio.sh -w ORCHESTRATE "..."` ran RESEARCH →
     ANALYSIS → AI, exit code 0, `.json` result validated
     (`python3 -m json.tool`) with all three stages `status: ok`.
  2. **Worker failure path**: `pipeline.conf` temporarily set to
     `ECHO, NONEXISTENT, ECHO` — stage 2 failed (unregistered worker),
     the pipeline still ran stage 3 (which received stage 2's failure
     text as context), `overall_status: degraded`, exit code 1; `.json`
     result confirmed the middle stage as `status: failed, exit_code: 1`
     while the other two were `ok`. `pipeline.conf` restored to
     `RESEARCH, ANALYSIS, AI` afterward.
  3. **Invalid worker path**: `waio.sh -w BOGUS "..."` (top-level, not
     through ORCHESTRATE) still rejects cleanly with the pre-existing
     Registry error and exit code 1 — confirms this phase's changes don't
     affect Registry validation outside the Controller.
  Regression: ECHO and HEALTHCHECK re-verified unaffected; full
  `bash -n` sweep across `waio.sh` and every `workers/*.sh` passed.
- Not implemented: per-request pipeline override, parallel/branching
  stages, and `depends_on` integration — same open items Phase 7 already
  named, still out of scope here.

## Phase 9 (2026-08-30): per-request pipeline override

Closes Phase 7/8's first open item: `workers/pipeline.conf` no longer has
to be the pipeline for every run.

- **`WAIO_PIPELINE` environment variable**: if set to a space-separated
  list of `workers/registry.conf` NAMEs, `workers/orchestrate_worker.sh`
  uses that list for the stage sequence instead of reading
  `workers/pipeline.conf`, for that one invocation only:
  `WAIO_PIPELINE="RESEARCH AI" ./waio.sh -w ORCHESTRATE "<request>"`.
  `pipeline.conf` itself is never read or modified when the override is
  set — confirmed by inspecting the file's content unchanged after every
  override test below.
- **CLI contract unchanged**: still exactly
  `./waio.sh -w ORCHESTRATE "<request>"`; the override is an environment
  variable, not a new flag, so `waio.sh` needed no change (it still only
  ever forwards a single request string to whichever worker script is
  selected).
- **Traceability**: every run's log line, human-readable `.txt`, and
  machine-readable `.json` result now also record `pipeline_source`
  (either `workers/pipeline.conf` or `env:WAIO_PIPELINE`), so it is always
  possible to tell after the fact whether a run used the default or an
  override.
- **Same safety guarantees as the default path**: an overridden pipeline
  is still validated exactly like `pipeline.conf`'s contents — each NAME
  is resolved through `workers/registry.conf` via `./waio.sh -w NAME`
  (an invalid NAME fails that stage exactly like Phase 7/8's
  `NONEXISTENT`/`BOGUS` cases, without aborting the run), and listing
  `ORCHESTRATE` itself in the override is refused before any stage runs,
  the same guard `pipeline.conf` already had.
- `waio.sh`, `workers/registry.conf`, and `workers/pipeline.conf` are
  untouched; every individual worker script is untouched. No new
  registry entries added.
- End-to-end verified 2026-08-30, four cases:
  1. **Default (regression)**: no `WAIO_PIPELINE` set — ran RESEARCH →
     ANALYSIS → AI exactly as before, `pipeline_source: workers/pipeline.conf`.
  2. **Valid override**: `WAIO_PIPELINE="ECHO HEALTHCHECK"` ran a
     different, valid 2-stage pipeline for one request, exit 0,
     `pipeline_source: env:WAIO_PIPELINE`, `pipeline.conf` file content
     confirmed unchanged afterward.
  3. **Invalid worker inside an override**: `WAIO_PIPELINE="ECHO BOGUS ECHO"`
     — stage 2 failed (unregistered worker) but the run still completed
     all 3 stages, `overall_status: degraded`, exit 1, matching Phase 8's
     failure-forwarding behavior exactly.
  4. **Self-reference guard under override**: `WAIO_PIPELINE="ECHO ORCHESTRATE"`
     was refused before running any stage, exit 1.
  Regression: default-path JSON/txt/log output format unchanged; full
  `bash -n` sweep across `waio.sh` and every `workers/*.sh` passed.
- Not implemented: parallel/branching stages, and `depends_on`
  integration — still out of scope.

## Phase 10 (2026-08-30): Router — WAIO decides its own pipeline

Requested by the user as "Phase 9" in-session, but this repo already has a
Phase 9 (per-request `WAIO_PIPELINE` override, above); numbered Phase 10
here to avoid two sections sharing a name. Adds a Router so WAIO can
choose which registered Workers a request needs, instead of only ever
running a fixed or manually-specified list.

- **Pipeline selection priority, now three levels** (highest first):
  1. `WAIO_PIPELINE` env var (Phase 9, unchanged) — explicit override,
     always wins.
  2. **New: Router** — `workers/orchestrate_worker.sh` reads every
     NAME/TYPE pair directly out of `workers/registry.conf` at run time
     (skipping `ORCHESTRATE` itself) and includes a NAME in the pipeline
     iff its own NAME or TYPE appears as a case-insensitive substring of
     the REQUEST text — the exact same matching rule `waio.sh`'s own
     single-worker keyword dispatch already uses (see "Canonical dispatch
     path" above), just applied to build a whole ordered set instead of
     picking one worker. Order = the order those NAMEs appear in
     `registry.conf`. No NAME is ever hardcoded in the script; every NAME
     the Router can produce is one it just read from the registry.
  3. `workers/pipeline.conf` (Phase 7, unchanged) — fixed fallback, used
     only when the Router finds zero matches (e.g. a request that names
     no worker at all), so requests with no resolvable keyword still
     behave exactly as Phase 7-9 did.
  Every run's log line, `.txt`, and `.json` result record which of the
  three (`env:WAIO_PIPELINE` / `router` / `workers/pipeline.conf`) was
  actually used, via the existing `pipeline_source` field from Phase 9.
- **Known limitation, inherited, not new**: keyword substring matching can
  false-positive the same way `registry.conf`'s own header comment already
  warns about for `waio.sh` (e.g. `AI` appearing inside unrelated words
  like "said" or "again"). This is the same accepted tradeoff the
  single-worker dispatch has always had, not a new risk introduced by the
  Router — a smarter (e.g. NLP-based) router was out of scope for this
  minimal implementation.
- `waio.sh`, `workers/registry.conf`, `workers/pipeline.conf`, and every
  individual worker script are untouched (confirmed via `git diff --stat`
  showing zero changes to `registry.conf`/`pipeline.conf`). No new
  registry entries added.
- End-to-end verified 2026-08-30, five cases:
  1. **RESEARCH-only request**: routed to a single-stage `[RESEARCH]`
     pipeline, `pipeline_source: router`.
  2. **ANALYSIS-only request**: routed to a single-stage `[ANALYSIS]`
     pipeline, `pipeline_source: router`.
  3. **Composite request** naming research, analysis, and an AI
     recommendation: routed to `[RESEARCH, ANALYSIS, AI]` (registry file
     order), ran all three stages successfully, coherent final result.
  4. **Worker-failure forwarding regression**: `WAIO_PIPELINE="ECHO
     BOGUSWORKER ECHO"` — stage 2 failed but the run still completed all
     3 stages, `overall_status: degraded`, exit code 1 — confirms the
     Router changes didn't affect the shared failure-forwarding code path
     (stage execution operates on the `STAGES` array the same way
     regardless of which of the three sources populated it).
  5. **Invalid worker name**: `WAIO_PIPELINE="BOGUSWORKER"` alone — clean
     Registry error, exit code 1, not executed.
  Also verified: a request naming no worker keyword correctly falls back
  to `pipeline_source: workers/pipeline.conf` (Phase 7's default,
  unchanged); `ECHO`/`HEALTHCHECK` direct dispatch unaffected; full
  `bash -n` sweep across `waio.sh` and every `workers/*.sh` passed.
- Not implemented: parallel/branching stages, `depends_on` integration
  (still out of scope, same as prior phases), and any smarter-than-substring
  routing (e.g. LLM-assisted intent classification) — the Router here is
  intentionally the minimal keyword-based version.

## Phase 11 (2026-08-30): explicit REQUEST -> RESULT AGGREGATION pipeline, three-way status

Requested by the user as "Phase 11" in-session. Names and makes explicit
every stage of the flow Phase 7-10 already implemented, and closes one
real gap: `overall_status` could previously only be `ok`/`degraded`, with
no way to tell "a worker hiccuped but we still got an answer" apart from
"the run produced no trustworthy answer at all."

- **Full named flow**, each stage now logged by name:
  `REQUEST` -> `ROUTER` (Phase 10, unchanged) -> **TASK CLASSIFICATION**
  (new) -> **PIPELINE SELECTION** (Phase 7-10's priority logic,
  relabeled) -> **WORKER EXECUTION** (Phase 7-8's ROUTE/EXECUTE/COLLECT
  per stage, unchanged) -> **FAILURE HANDLING** (Phase 7's
  failure-forwarding, unchanged, now logged under this name) ->
  **RESULT AGGREGATION** (Phase 8's log/txt/json, extended below).
- **New: TASK CLASSIFICATION**, one of four values, now recorded in the
  log line, `.txt`, and `.json` result (`task_classification` field):
  - `override` — `WAIO_PIPELINE` was set (Phase 9).
  - `single` — the Router (Phase 10) matched exactly one worker.
  - `multi` — the Router matched two or more workers.
  - `fallback` — the Router matched nothing; `workers/pipeline.conf` is
    used (Phase 7's original default path).
  This is a direct, minimal read of the Router's own output count — no
  new matching logic, no hardcoded worker names.
- **New: three-way `overall_status`**, exit code always matching:
  - `ok` (exit `0`) — every stage succeeded (unchanged from Phase 7).
  - `degraded` (exit `1`) — at least one stage failed, but the LAST stage
    in the pipeline still succeeded, so `final_result` is a genuine
    answer produced despite trouble upstream.
  - `failed` (exit `2`, **new**) — the LAST stage itself failed, so
    `final_result` is actually that failure's error text, not a
    trustworthy answer.
  Determined from two facts the loop already tracked: whether any stage
  failed, and the last stage's own exit code (`$RC`, naturally still set
  to the final iteration's value once the loop ends) — no new tracking
  variables beyond a single `ANY_STAGE_FAILED` flag.
- **Behavior change to be aware of**: a single-stage run whose only stage
  is an invalid/failing worker now reports `failed`/exit `2` where
  Phase 7-10 reported `degraded`/exit `1` (e.g. `WAIO_PIPELINE=BOGUS`
  alone). A multi-stage run where a middle stage fails but the last stage
  still succeeds is unaffected: still `degraded`/exit `1`, exactly as
  before (verified below).
- `waio.sh`, `workers/registry.conf`, `workers/pipeline.conf`, and every
  individual worker script are untouched (confirmed via `git diff --stat`
  showing zero changes to `registry.conf`/`pipeline.conf`). No new
  registry entries added. The Claude/OpenAI/Gemini/local-agent extension
  point is unchanged from Phase 7 (register a worker script + a
  `registry.conf` line; the Router already picks it up automatically by
  NAME/TYPE, no Controller change needed).
- End-to-end verified 2026-08-30, five cases:
  1. **Single worker**: a RESEARCH-only request -> `task_classification:
     single`, `pipeline_source: router`, `overall_status: ok`, exit 0.
  2. **Multiple workers**: a composite research+analysis+AI request ->
     `task_classification: multi`, pipeline `RESEARCH ANALYSIS AI`,
     `overall_status: ok`, exit 0.
  3. **Worker failure (mid-pipeline, last stage recovers)**:
     `WAIO_PIPELINE="ECHO BOGUSWORKER ECHO"` -> stage 2 failed, `FAILURE
     HANDLING` logged, stage 3 still ran, `overall_status: degraded`,
     exit code **1**.
  4. **Invalid worker (sole/last stage)**: `WAIO_PIPELINE="BOGUSWORKER"`
     alone -> `overall_status: failed` (the new state), exit code **2** —
     confirms the refined three-way distinction.
  5. **Pipeline auto-selection**: a request naming `HEALTHCHECK` and
     `ECHO` (a combination other than the research/analysis/ai trio) ->
     `task_classification: multi`, pipeline resolved as `ECHO HEALTHCHECK`
     (registry.conf file order — `ECHO` is listed before `HEALTHCHECK` —
     not the order those words appeared in the request text, same
     documented Phase 10 ordering rule), `overall_status: ok`, exit 0.
  Also verified: a keyword-less request still falls back to
  `task_classification: fallback` / `pipeline_source:
  workers/pipeline.conf` (Phase 7's default); `ECHO`/`RESEARCH` direct
  dispatch unaffected; `.json` result validated with `python3 -m
  json.tool`; full `bash -n` sweep across `waio.sh` and every
  `workers/*.sh` passed.
- Not implemented: parallel/branching stages, `depends_on` integration,
  and anything beyond substring-based Router matching — same open items
  as Phase 10, still out of scope.

## Phase 12 (2026-08-30): known-issue cleanup (jobs/, HOST800, credential, Takomachi health)

Closes out the "Not implemented" / "unresolved" items tracked in prior phases
under category A (known bugs/inconsistencies), as opposed to category B
(new architecture like parallel stages) which remains open for a future
phase.

- **Fixed: `jobs/test-job.sh` IP mismatch.** It hardcoded `192.168.1.193`,
  while `workers/800.json` (the single source of truth every other `jobs/`
  script already reads from) says `192.168.1.91`. `jobs/run-job.sh` and
  `jobs/dispatch.sh` both already resolved the target dynamically via
  `python3 -c 'import json; print(json.load(open("workers/800.json"))["host"])'`;
  `test-job.sh` alone predated that convention (added in the very first
  baseline commit, before `800.json` existed). Changed it to read from
  `800.json` the same way, instead of hardcoding either IP, so it can't
  drift again. Verified by running it directly: connects to `800.local`
  (`192.168.1.91`), same host `run-job.sh`/`dispatch.sh`/`host800_worker.sh`
  target. Note: `192.168.1.193` also answers SSH on this network (a
  different, unrelated host) — that's almost certainly why the mismatch
  went unnoticed, the old script "worked", just against the wrong machine.
- **Resolved: HOST800 real SSH auth, previously untested (Phase 4 note).**
  Ran `./waio.sh -w HOST800 "system check"` and `"identity check"` for
  real — both completed end-to-end (`ssh -o BatchMode=yes
  masa@192.168.1.91`, key-based, no password prompt), exit 0, correct
  host/OS/uptime/disk and hostname/ComputerName output. The "deferred
  pending explicit approval" note from Phase 4 is closed; no code change
  needed, `workers/host800_worker.sh` worked as designed on first real
  attempt.
- **Still blocked, not a WAIO bug: `agent_manager` degraded status
  (Phase 6 note).** Attempted `./waio.sh -w HEALTHCHECK "check"` to get a
  fresh read; failed with `could not retrieve TAKOMACHI_API_KEY from
  Keychain` — this is the same documented constraint from the Takomachi
  integration phase (Keychain access only succeeds from an interactive GUI
  Terminal session, not this non-interactive shell), not a new issue.
  Investigating *why* specific Takomachi agents are degraded would mean
  reading Takomachi's own source/state, which lives in a separate repo not
  present on this machine — out of scope for WAIO. Still open, needs
  either a GUI-Terminal HEALTHCHECK run or direct Takomachi-side
  investigation by whoever owns that repo.
- **Resolved (moot): `OPENROUTER_API_KEY` rotation/removal decision
  (Takomachi Phase 2 note).** Re-confirmed no worker script references
  `OPENROUTER_API_KEY` (`grep` across every `*.sh`, zero hits, consistent
  with all three LLM workers routing through Takomachi since that phase).
  Additionally, `~/.waio.env` is now a 0-byte file — the key isn't just
  unreferenced, it's no longer present locally at all (changed outside
  this repo, not by this session). `source ~/.waio.env` in `waio.sh`
  still succeeds against an empty file under `set -euo pipefail`, and
  every worker exercised this phase ran fine, so this required no code
  change. No rotation action taken here (revoking the key at the
  provider, if desired, is a decision for whoever holds that account, out
  of scope for this repo).
- `waio.sh`, `workers/registry.conf`, `workers/pipeline.conf`,
  `workers/orchestrate_worker.sh`, and every worker script other than the
  one line in `jobs/test-job.sh` above are untouched.
- Category B items (parallel/branching pipeline stages, Takomachi
  `depends_on` integration, LLM-assisted Router matching) remain open,
  intentionally not attempted here — this phase was scoped to category A
  (known bugs/inconsistencies) only.

## Phase 13 (2026-08-30): parallel stages (fan-out/fan-in)

Closes the "parallel" half of Phase 7-11's long-standing open item
("parallel/branching stages"). Branching (conditional next-stage
selection based on a prior stage's result) is a different, larger
feature — a condition/predicate mechanism, not a concurrency mechanism —
and was deliberately scoped out of this phase; it remains open.

- **New: `+`-joined stage groups.** A single stage token in
  `WAIO_PIPELINE` (space-separated) or a single `workers/pipeline.conf`
  line may now be a `+`-joined list of `registry.conf` NAMEs, e.g.
  `WAIO_PIPELINE="RESEARCH+ANALYSIS AI"` — stage 1 runs `RESEARCH` and
  `ANALYSIS` concurrently against the same stage input, merges both
  results, then stage 2 (`AI`) runs as before. A token with no `+` is a
  group of exactly one NAME — every stage-processing code path was
  rewritten to treat "group of one" and "group of many" identically, so
  this is the same code a single-worker stage always ran, not a special
  case bolted on beside it.
- **Router (Phase 10) and TASK CLASSIFICATION (Phase 11) are completely
  unchanged.** The Router still only ever emits one bare NAME per match;
  it never produces a `+` group itself, and its four classification
  values (`override`/`single`/`multi`/`fallback`) keep their exact Phase
  11 meaning. Parallel groups are opt-in only, via an explicit `+` typed
  into `WAIO_PIPELINE` or `pipeline.conf` — never inferred automatically.
  This was a deliberate scope boundary set when this phase was designed:
  Router auto-parallelization and Takomachi `depends_on` integration are
  both still separate, unstarted items.
- **Fan-out execution**: each member of a group is dispatched via
  `./waio.sh -w <NAME> "<stage input>"` backgrounded (`&`), stdout+stderr
  captured to its own file in a per-run temp directory (`mktemp -d`,
  removed on exit via the same `trap` pattern Phase 8's JSONL scratch
  file already used), then `wait`ed on individually by PID — order of
  completion never affects anything.
- **Fan-in merge, deterministic**: each member's collected result (same
  `] response:`-marker COLLECT convention as every prior phase) is
  labeled `NAME (status):` and joined in **group-token order** (the
  order NAMEs were written in the `+` list), never completion order —
  verified by running the same two-member group repeatedly with the
  slower member listed first; the merged output's member order never
  changed across runs.
- **FAILURE HANDLING, extended per-member, not per-stage**: a failed
  group member no longer aborts anything (same non-aborting philosophy
  as Phase 7), and the rest of that member's group still runs to
  completion; the failure is folded into the next stage's input labeled
  `FAILED`, same as a failed single-worker stage always was.
- **`overall_status` generalized from Phase 11's three-way status**: Phase
  11 decided `degraded` vs `failed` from the last stage's single exit
  code (`$RC`). With a possibly-multi-member last stage, that became a
  new `LAST_GROUP_ALL_OK` flag (true iff every member of the LAST group
  succeeded) — for any group of one, this is exactly equivalent to Phase
  11's `$RC -eq 0` check, so every existing single-worker-stage run
  computes the identical `overall_status`/exit code it always did.
  `failed` (exit 2) now means "at least one member of the last stage
  failed"; `degraded` (exit 1) and `ok` (exit 0) keep their Phase 11
  meaning otherwise.
- **Self-reference guard, updated to check group members**: the existing
  "does the pipeline list ORCHESTRATE itself" guard now splits each
  token on `+` before comparing, so `ECHO+ORCHESTRATE` is caught before
  any stage runs, not just a bare `ORCHESTRATE` token.
- **JSON result, additive only**: each entry in the `stages` array keeps
  the exact same four fields Phase 8 defined (`name`/`status`/
  `exit_code`/`result`); a new fifth field, `step`, was added (entries
  sharing a `step` number ran in the same, possibly-parallel, group). A
  consumer reading only the original four fields is unaffected. The
  final-aggregation Python step needed no change at all — it already just
  loads whatever per-stage JSON objects were written, key-agnostic.
- **`waio.sh`, `workers/registry.conf`, and every individual worker
  script are untouched.** `workers/pipeline.conf`'s existing content
  (`RESEARCH`/`ANALYSIS`/`AI`, no `+`) is untouched and still 100% valid
  — the new syntax is additive, not a migration. Only
  `workers/orchestrate_worker.sh` changed.
- End-to-end verified 2026-08-30, from a non-interactive shell (so
  Keychain-gated workers RESEARCH/ANALYSIS/AI/HEALTHCHECK were not
  exercised live here — same documented environment constraint as
  Phase 2/6/12, not a new limitation); `ECHO`, `BOGUS` (deliberately
  unregistered), and the real `HOST800` SSH path were used instead:
  1. **Regression, no `+` anywhere** (4 cases): single-stage override,
     mid-pipeline failure with last-stage recovery (`degraded`/exit 1),
     sole/last-stage failure (`failed`/exit 2), and the flat
     self-reference guard — all four reproduced Phase 11's exact
     documented exit codes and `overall_status` values; the `.json`
     result's four original per-stage fields were byte-identical in
     shape, with only the new `step` field added.
  2. **2-member parallel group, both succeed**
     (`WAIO_PIPELINE="ECHO+HOST800 ECHO"`): stage 1 ran both concurrently
     (log shows `(parallel group, 2 members)`), both `status=ok`, stage 2
     received both labeled results in HISTORY, `overall_status: ok`,
     exit 0, `.json` validated with `python3 -m json.tool`.
  3. **Parallel partial failure, not in the last group**
     (`WAIO_PIPELINE="ECHO+BOGUS ECHO"`): the group did not abort, stage 2
     still ran, `overall_status: degraded`, exit **1**.
  4. **Parallel failure inside the last group**
     (`WAIO_PIPELINE="ECHO ECHO+BOGUS"`): `overall_status: failed`, exit
     **2** — confirms the new `LAST_GROUP_ALL_OK` logic (this case did
     not exist before Phase 13; previously every last stage was a single
     NAME).
  5. **Self-reference guard inside a group**
     (`WAIO_PIPELINE="ECHO+ORCHESTRATE"`): refused before any stage ran,
     exit 1.
  6. **Determinism**: the same 2-member group run repeatedly, reversed
     token order (`HOST800+ECHO`), merged in that same token order every
     time regardless of which member (the SSH-based `HOST800` or the
     near-instant `ECHO`) actually finished first.
  Full `bash -n` sweep across `waio.sh`, every `workers/*.sh`, and every
  `jobs/*.sh` passed. Local `shellcheck` was not available in this
  environment to pre-check (attempted, `brew install shellcheck` did not
  complete in-session); this repo's CI (`.github/workflows/lint.yml`)
  runs `shellcheck` on every PR and gates both `master` and `develop`, so
  it is verified there before merge, consistent with how Phase 12 was
  also only shellcheck-verified via CI.
- Not implemented, explicitly out of scope for this phase: branching
  (conditional stage selection), Router auto-detection of parallelizable
  groups, Takomachi `depends_on` integration, and any bound on how many
  members may run concurrently (a group's size is whatever `+` count is
  written; no concurrency cap was added — worth revisiting if a group
  ever gets large enough to worry about Takomachi-side rate limits or
  local resource use, per the risk noted when this phase was designed).

## Phase 14 (2026-08-30): Takomachi `depends_on` integration — investigated, not adopted

Category B-2 ("Takomachi `depends_on` integration"), the other long-standing
open item alongside Phase 13's parallel stages. Investigated end to end
against Takomachi's actual source (`/Users/masa/Projects/Takomachi`, local
server running); conclusion: **no code change**. This closes the backlog
item with a documented decision rather than an implementation.

- **What `depends_on` actually does, confirmed from source**:
  `src/task-queue/queue.ts`'s `dequeueNextEligibleTask`/
  `dequeueEligibleTasks` only ever use `depends_on` as a SQL filter — a
  task is excluded from dequeue eligibility while any task in its
  `depends_on` list is not yet `status = 'completed'`. `markCompleted`
  stores a finished task's `result` on that task itself and does nothing
  else — no code path anywhere in `src/agent-manager/` (selection,
  task-executor) or `src/task-queue/` reads a dependency's `result` and
  writes it into a dependent task's `payload`. Takomachi's own interface
  doc (`interfaces/agent-manager-task-queue.md`) describes
  `dequeueNextEligibleTask` the same way: "filtered to tasks whose
  dependency chain is satisfied" — a dequeue-order gate, nothing about
  data flow. This matches (and now confirms from source, not just prior
  API-level observation) what Phase 5 already noted in this file: "the
  `depends_on` task field only gates dequeue ordering and does not
  itself pass a dependency's result into a dependent task's payload."
- **Why that makes integration a net negative here**: WAIO's own
  orchestration (Phase 5's client-side sequencing, extended by Phase 13's
  parallel groups) already provides both things a real integration would
  need:
  1. **Ordering** — `workers/orchestrate_worker.sh` calls `./waio.sh -w
     NAME` synchronously per stage (or backgrounds a stage's group
     members and `wait`s them all before moving on), so the next stage
     never starts before the current one's result is in hand. Takomachi
     dequeue ordering would be redundant with this, not an improvement.
  2. **Result-passing** — every stage's `STAGE_INPUT` is built directly
     from prior stages' collected `result` text (`HISTORY`). This is
     exactly what `depends_on` does *not* provide. Submitting a whole
     pipeline up front as a Takomachi task DAG (the only way
     `depends_on` could meaningfully replace WAIO's own loop) would
     require knowing every stage's input payload before any upstream
     stage has run — impossible, since later payloads are built from
     earlier results.
  Net effect: adopting `depends_on` would add a dependency on
  Takomachi's queue semantics while solving a problem WAIO does not have
  (ordering) and leaving unsolved the one it does have (result-passing),
  which WAIO must keep doing itself either way. There is no reduction in
  code or risk from adopting it.
- **Takomachi source was not modified** — per this phase's explicit
  scope. Solving the missing piece (result injection into a dependent
  task's payload) would require a Takomachi-side change; that was
  correctly out of bounds for this phase, and is noted here only as the
  reason a different design is not available today, not as a
  recommendation to build it.
- `waio.sh`, `workers/registry.conf`, `workers/pipeline.conf`, and every
  worker script (including `workers/orchestrate_worker.sh`) are
  untouched — confirmed via `git diff --stat` showing zero code changes
  this phase, only this file. Full `bash -n` sweep re-run as a sanity
  check regardless (no code changed, so no behavior change was
  possible); Phase 7-13 regression is unaffected by construction, not
  just by testing.
- Not implemented, and not planned unless the situation changes: any
  `depends_on` usage in WAIO. Revisit only if Takomachi itself later adds
  a way to carry a completed dependency's result into a dependent task's
  payload — at that point this would be worth re-evaluating as a
  genuine alternative to (or complement of) WAIO's client-side model,
  not before.

## Phase 15 (2026-08-30): parallel group concurrency cap

Closes the one open risk Phase 13 flagged for itself: a `+`-group's size
was whatever the pipeline spec said, with no bound on how many members
run at once.

- **New: `WAIO_MAX_PARALLEL` env var**, an optional positive integer. Set,
  it caps how many members of a single `+` group run concurrently; a
  group larger than the cap runs in sequential batches of at most that
  many members instead of all at once. Unset (the default) is uncapped —
  byte-identical to Phase 13 behavior, confirmed by regression (below).
- **Validated once, up front**: before any stage runs (same "fail fast,
  no partial run" placement as the self-reference guard), a set-but-
  invalid `WAIO_MAX_PARALLEL` (non-numeric, or `< 1`, `0` included) is
  rejected with a clear error and nothing executes.
- **Batch order = group-token order**, same determinism Phase 13
  already guaranteed for merge order — a batch is just the next N
  members in the order they were written after `+`, not chosen by any
  other heuristic. Downstream COLLECT/merge logic is completely
  unchanged: it still just walks `MEMBERS` in order and reads each
  member's recorded exit code and output, so it can't tell whether that
  member ran in the first batch, a later batch, or (uncapped) all at
  once alongside everyone else.
- **`workers/orchestrate_worker.sh`'s single-shot launch-then-wait-all**
  block was restructured into a `while` loop over batches of at most
  `WAIO_MAX_PARALLEL` members (or the whole group in one batch when
  unset, i.e. the exact Phase 13 code path with the batch loop only
  ever running once) — everything else (COLLECT, FAILURE HANDLING,
  `LAST_GROUP_ALL_OK`, JSON `step` field, RESULT AGGREGATION) is
  unchanged, since none of it depends on how a group's members were
  batched, only on their final per-member status/result.
- **Log line, additive only**: a group's `ROUTE` line now says
  `(parallel group, N members, max M concurrent)` only when
  `WAIO_MAX_PARALLEL` actually caps that group (`M < N`); otherwise it's
  the exact `(parallel group, N members)` text Phase 13 already used
  (including when `WAIO_MAX_PARALLEL` is set but larger than the
  group — no visible change, since it doesn't actually cap anything).
- `waio.sh`, `workers/registry.conf`, `workers/pipeline.conf`, and every
  individual worker script are untouched. Only
  `workers/orchestrate_worker.sh` changed.
- End-to-end verified 2026-08-30 (same non-interactive-shell constraint
  as Phase 13 — `ECHO`/`BOGUS`/real-SSH `HOST800` used, not the
  Keychain-gated workers):
  1. **Regression, `WAIO_MAX_PARALLEL` unset**: the exact Phase 13
     2-member-group case (`ECHO+HOST800 ECHO`) and a flat
     mid-pipeline-failure case reproduced Phase 13's exact log text,
     `overall_status`, and exit codes.
  2. **3-member group, cap 2** (`ECHO+ECHO+HOST800`,
     `WAIO_MAX_PARALLEL=2`): ran as two batches (2 then 1), log shows
     `max 2 concurrent`, all three `COLLECT` lines present in member
     order, `overall_status: ok`.
  3. **Cap of 1 (fully sequential within a group)**
     (`ECHO+HOST800`, `WAIO_MAX_PARALLEL=1`): two single-member
     batches, same correct outcome.
  4. **Cap larger than the group**: log line has no `max N concurrent`
     suffix (matches Phase 13's plain text exactly) since the cap never
     actually binds.
  5. **Invalid values rejected before running**: non-numeric
     (`WAIO_MAX_PARALLEL=abc`) and `WAIO_MAX_PARALLEL=0` both refused,
     exit 1, no stage executed.
  6. **Failure inside a capped batch**: `ECHO+BOGUS+ECHO` with cap 2 —
     the failure was collected in the correct position, forwarded per
     Phase 13's `FAILURE HANDLING`, and (since this was the run's only,
     therefore last, group) correctly produced `overall_status: failed`,
     exit 2.
  `.json` result validated with `python3 -m json.tool` and confirmed the
  `step` field still groups all of a stage's members together
  regardless of which batch actually ran them. Full `bash -n` sweep
  across `waio.sh`/`workers/*.sh`/`jobs/*.sh` passed; a plain
  single-worker `ECHO` dispatch (unrelated to groups) re-verified
  unaffected.
- Not implemented: no default cap was introduced (still fully uncapped
  unless explicitly set — a deliberate choice to keep Phase 13 behavior
  as the zero-config default); no per-worker or per-registry-entry cap
  (`WAIO_MAX_PARALLEL` is global to the whole run, not configurable per
  NAME); branching, Router auto-parallelization, and Takomachi
  `depends_on` integration remain the same open/closed items Phase 13
  and 14 already left them as.

## Phase 16 (2026-08-30): branching stages (success/failure only)

Closes the "branching" half of Phase 7-11's original "parallel/branching
stages" open item (the "parallel" half was Phase 13). Deliberately
scoped to success/failure branching only, per the design discussion this
phase started from — branching on a stage's actual output content is a
separate, larger feature (needs a real condition/predicate language) and
remains unstarted.

- **New: `?ok:`/`?fail:` condition prefix**, case-insensitive, on a
  stage token in `WAIO_PIPELINE`/`workers/pipeline.conf`, e.g.
  `WAIO_PIPELINE="BOGUS ?fail:ECHO"` — stage 2 runs only if stage 1
  failed. Composes with Phase 13's `+` groups (the prefix covers the
  whole group, not per member): `?ok:RESEARCH+ANALYSIS` is valid. A
  token with no `?` prefix is unconditional, exactly as every stage
  before this phase — the overwhelming majority of existing pipelines
  are entirely unaffected, confirmed by regression (below).
- **Condition reference point: the last EXECUTED stage, skip-aware.** A
  skipped stage does not move `LAST_EXECUTED_GROUP_ALL_OK` (renamed from
  Phase 13/15's `LAST_GROUP_ALL_OK` — same variable, same meaning,
  updated in the same place, just now also read mid-run instead of only
  after the loop), so a later conditional stage correctly looks past any
  earlier skips to the last stage that actually ran. Before anything has
  executed, the baseline is `ok` (a `?ok:` first stage runs; a `?fail:`
  first stage is skipped) — verified as its own case (Phase 16 test 5,
  below).
- **A skipped stage runs nothing**: no `ROUTE`/`EXECUTE`/`COLLECT`, no
  contribution to `HISTORY`/`FINAL_RESULT`, no effect on
  `ANY_STAGE_FAILED`. It is still fully traceable: a `BRANCH` log line
  (new, only for conditional stages — an unconditional stage has no
  `BRANCH` step, same as before this phase) records the decision either
  way, and each of a skipped stage's members gets a `stage_status`
  entry and a JSON `stages` array entry (`status: "skipped"`,
  `exit_code: null`, `result: ""`) — a new possible per-stage `status`
  value, additive to the JSON contract the same way Phase 11 added
  `failed` to `overall_status` (a strict `"ok"`/`"failed"`-only consumer
  needs updating, noted in the header comment).
- **"First executed stage gets the bare request" generalized**: Phase
  7-15 used stage index `0` to decide whether a stage's input is the
  bare `$REQUEST` or `"Original request: ... $HISTORY"`. With stages now
  skippable, that became `EXECUTED_COUNT -eq 0` (a new counter,
  incremented only when a stage actually runs) — for any pipeline with
  no skips this is identical to `i -eq 0` for every existing case (index
  0 is always the first executed stage when nothing is ever skipped), so
  Phase 7-15 behavior is unchanged; a pipeline whose first stage(s) are
  skipped now correctly gives the first stage that actually runs the
  clean, unwrapped request text instead of an "Original request:" prefix
  around an empty `HISTORY` (verified, Phase 16 test 6 below).
- **All-skipped pipeline is a configuration error**: if `EXECUTED_COUNT`
  is still `0` after the loop (e.g. a lone `?fail:ECHO` with nothing
  before it to have failed), the run exits `1` with a clear error and
  writes no `results/` files — same "fail fast on nonsense config"
  posture as "no stages configured" and the self-reference guard, rather
  than silently reporting a hollow `ok` with an empty `final_result`.
- **Validation, up front, before any stage runs**: an unknown condition
  prefix (anything starting `?` other than `?ok:`/`?fail:`, e.g. a typo)
  and an empty stage after stripping a valid prefix (e.g. bare `?ok:`)
  are both rejected before the run starts, same placement and style as
  the self-reference guard and Phase 15's `WAIO_MAX_PARALLEL`
  validation. The self-reference guard itself now runs against the
  condition-stripped token, so `?ok:ECHO+ORCHESTRATE` is still caught.
- **Router (Phase 10) and TASK CLASSIFICATION (Phase 11) are completely
  unchanged.** The Router never emits a `?`-prefixed token; branching,
  like `+` groups, is opt-in only via `WAIO_PIPELINE`/`pipeline.conf`.
- `waio.sh`, `workers/registry.conf`, `workers/pipeline.conf`, and every
  individual worker script are untouched. Only
  `workers/orchestrate_worker.sh` changed.
- End-to-end verified 2026-08-30 (same non-interactive-shell constraint
  as Phase 13/15 — `ECHO`/`BOGUS`/real-SSH `HOST800` used):
  1. **Full regression, no `?` anywhere** (6 cases): single-stage
     override, mid-pipeline failure with recovery, sole/last-stage
     failure, the flat self-reference guard, a Phase 13 2-member
     parallel group, and a Phase 15 capped 3-member group — every one
     reproduced its prior phase's exact log text, `overall_status`, and
     exit code.
  2. **`?ok:` runs after a success** (`ECHO ?ok:ECHO`): `BRANCH ...
     condition met ... proceeding`, both stages ran, `overall_status: ok`.
  3. **`?fail:` skipped after a success** (`ECHO ?fail:ECHO`): `BRANCH
     ... skipped`, `stage_status` shows the second `ECHO=skipped`,
     `overall_status: ok` (the skip doesn't count as a failure).
  4. **`?fail:` runs after a failure** (`BOGUS ?fail:ECHO`): condition
     met, `ECHO` ran and succeeded, `overall_status: degraded` (`BOGUS`
     still failed earlier, but the last EXECUTED stage, `ECHO`,
     succeeded).
  5. **`?ok:` skipped after a failure** (`BOGUS ?ok:ECHO`): skipped,
     `overall_status: failed` — the last EXECUTED stage is `BOGUS`
     itself (the skip is invisible to this computation by design), exit
     **2**.
  6. **All-skipped** (`?fail:ECHO` alone, baseline `ok`): skipped, then
     refused with the new "every stage was skipped" error, exit 1, no
     `results/` files written for that run (file count before/after
     compared, unchanged).
  7. **Unknown condition prefix** (`?maybe:ECHO`) and **empty stage
     after a prefix** (`?ok:` alone): both rejected before any stage
     ran, exit 1.
  8. **Self-reference guard inside a conditional group**
     (`?ok:ECHO+ORCHESTRATE`): refused before any stage ran, exit 1.
  9. **Composability with a parallel group**
     (`BOGUS ?fail:ECHO+HOST800`): condition met, the 2-member group ran
     (real SSH `HOST800` included), `overall_status: degraded`.
  10. **First-executed-stage input, after a leading skip**
      (`?fail:ECHO ECHO`, baseline `ok` so stage 1 skips): the second
      `ECHO` (first to actually execute) received the bare request text
      with no `"Original request:"` wrapper, confirming
      `EXECUTED_COUNT`-based detection works correctly even when index
      `0` itself was skipped.
  `.json` result validated with `python3 -m json.tool` for both a normal
  and a skip-containing run, confirming a skipped member's `exit_code`
  serializes as JSON `null`. Full `bash -n` sweep across
  `waio.sh`/`workers/*.sh`/`jobs/*.sh` passed; a plain single-worker
  `ECHO` dispatch re-verified unaffected.
- Not implemented, explicitly out of scope: branching on a stage's
  actual output content (only success/failure of the whole stage is
  checked); any condition beyond "immediately preceding executed
  stage" (e.g. referencing an arbitrary earlier stage by name); Router
  auto-branching; and Takomachi `depends_on` integration (Phase 14's
  decision stands, unaffected by this phase).

## Phase 17 (2026-08-30): automated regression suite for the Controller

Every regression case from Phase 7-16 had been verified manually, one
`./waio.sh -w ORCHESTRATE ...` command at a time, and the result copied
into this file by hand. As `workers/orchestrate_worker.sh` accumulated
parallel groups (13), a concurrency cap (15), and branching (16) on top
of the original sequential Controller (7-11), that manual process became
the actual bottleneck on verifying further changes safely. This phase
adds an automated suite, with **zero changes to any existing file** —
confirmed by `git diff --stat` showing only the new `tests/` directory
added, nothing else touched.

- **New file `tests/orchestrate_worker_test.sh`**, a self-contained bash
  script (no new dependency — no `bats`/`shellspec`/etc., just `bash` +
  `python3`, exactly what `orchestrate_worker.sh` itself already
  requires). Run directly: `./tests/orchestrate_worker_test.sh`. It
  drives the real `./waio.sh -w ORCHESTRATE "<request>"` entry point
  exactly like a human operator would — no mocking, no stubbing, no
  changes to `orchestrate_worker.sh`/`waio.sh`/`registry.conf`/
  `pipeline.conf`. Runs still write to `logs/`/`results/` like any other
  invocation (gitignored, not cleaned up by the suite, same convention
  every manual verification already followed).
- **Two tiers, kept deliberately separate**, per this phase's explicit
  instruction to segment out what this environment cannot run:
  - **Tier 1 (always runs, 27 cases / 59 assertions)**: `ECHO` and
    `BOGUS` (deliberately unregistered) only — both pure bash, no
    network, no credentials, portable to any environment with
    `bash`+`python3`. Covers Phase 7-9's flat sequential pipeline
    (single-stage success, mid-pipeline failure with recovery,
    sole/last-stage failure, the self-reference guard, an empty
    request), Phase 13's parallel groups (success, partial failure not
    in the last group, failure in the last group, the guard inside a
    group), Phase 15's concurrency cap (batching, cap of 1, a
    non-binding cap, both invalid-value cases, failure inside a capped
    batch), Phase 16's branching (`?ok:`/`?fail:` after both success and
    failure, the all-skipped configuration error including a
    before/after `results/` file-count check, an unknown condition
    prefix, an empty stage after a prefix, the guard inside a
    conditional group, the `EXECUTED_COUNT`-based first-stage-input fix,
    and branching composed with a parallel group), and Phase 8/13/15/16's
    JSON result contract (stage shape, and a skipped member's
    `exit_code` serializing as JSON `null`).
  - **Tier 2 (skips cleanly, does not fail, when unreachable — 3
    cases / 5 assertions)**: adds the real `HOST800` worker (real SSH to
    `workers/800.json`'s host) for the two cases that specifically need
    a second, distinguishable real worker — parallel merge-order
    determinism (reversed group-token order, run twice, confirmed
    order-preserving regardless of which member actually finishes
    first) and Router multi-match (`task_classification: multi` from
    plain request text, no override). A preflight TCP check
    (`nc -z -w 2 <host> 22`, host read from `workers/800.json`, never
    hardcoded) decides whether to attempt these; unreachable means a
    clean `SKIP` line per case, not a failure, so the suite stays
    runnable from a machine without LAN access to 800号機.
- **Deliberately not automated, and not attempted**: anything that
  dispatches `RESEARCH`/`ANALYSIS`/`AI`/`HEALTHCHECK` — all four require
  `TAKOMACHI_API_KEY` from macOS Keychain, which (per the Takomachi
  integration phase's finding, re-confirmed still true in this
  environment as recently as Phase 12) only succeeds from an
  interactive GUI Terminal session. That includes the Router
  "**fallback**" classification's *full execution* (`pipeline.conf`'s
  default pipeline is `RESEARCH`/`ANALYSIS`/`AI`) — the classification
  logic itself is exercised indirectly by every Tier 1 case that relies
  on `WAIO_PIPELINE` (`override`) or Router matching on `ECHO`/`HOST800`
  (`single`/`multi`), but the fallback path's own successful end-to-end
  run remains manual-verification-only, exactly as Phase 10/11's
  `ARCHITECTURE.md` entries already documented it. Also not automated:
  the "no stages configured" error (would require temporarily emptying
  the real `workers/pipeline.conf`, judged not worth mutating a live
  config file for one low-value case).
- **CI is not wired up this phase.** `.github/workflows/lint.yml` runs
  `bash -n`/`shellcheck` over `waio.sh`/`workers/*.sh` only — it does
  not currently glob `tests/`, so this new script is not yet linted or
  run by CI. Deliberately left as a follow-up decision rather than
  changed here: Tier 2's `HOST800` cases would always skip (correctly,
  not fail) on a GitHub-hosted runner with no route to this LAN, but
  wiring Tier 1 alone into CI is a reasonable next step if wanted.
- End-to-end verified 2026-08-30: two full consecutive runs, both **64
  passed, 0 failed, 0 skipped** (this machine has LAN access to 800号機,
  so Tier 2 executed rather than skipped both times) — the second run
  confirmed the suite is reproducible, not just passing once. `bash -n`
  swept across `waio.sh`/`workers/*.sh`/`jobs/*.sh`/`tests/*.sh`. `git
  diff --stat` confirmed zero modifications to any existing file; `git
  status` shows only the new `tests/` directory as untracked before this
  phase's commit.
- Not implemented: no CI wiring (see above); no coverage for the
  Keychain-gated workers or the `pipeline.conf` "no stages configured"
  case (see above); no `bats`/similar framework adopted (a plain bash
  script was judged the minimal fit — no new tool dependency for a suite
  this size).

## Phase 18 (2026-08-30): wire Phase 17's regression suite into CI

Closes the follow-up Phase 17 explicitly flagged for itself ("wiring
Tier 1 alone into CI is a reasonable next step"). Chosen over the other
remaining backlog items (Router LLM-assisted matching, `agent_manager`
investigation, cron/unattended execution) because it is the one that is
entirely WAIO-repo-internal, has no dependency on Takomachi itself, a
GUI Terminal session, or Keychain access, and has an unambiguous,
immediately-visible effect: every future push/PR now gets an automated
check of Phase 7-16's behavior, not just a manual one.

- **`.github/workflows/lint.yml`**: added a new, separate `regression`
  job (alongside the existing `shellcheck` job, both triggered by the
  same `push`/`pull_request` events) that checks out the repo and runs
  `./tests/orchestrate_worker_test.sh`. Tier 2 (real `HOST800` SSH)
  correctly skips itself on a GitHub-hosted runner with no route to this
  machine's LAN — no workflow-side special-casing needed, the test
  script's own preflight (Phase 17) already handles it.
- **Deliberately a separate job, not a new step in `shellcheck`**: the
  existing `shellcheck` job/check is what `master`/`develop`'s branch
  protection currently requires (see "Repo hosting and branch policy"
  below) — folding the regression suite into it would have made it
  block merges immediately, before this specific script had ever been
  run on GitHub's actual `ubuntu-latest` environment (only run locally
  on this machine's macOS so far). A separate `regression` job runs and
  reports on every PR right away, without risking the existing required
  gate on an environment this phase couldn't fully verify in advance
  (Ubuntu's `python3`/`nc` availability and behavior). **Promoting it to
  a required check is a branch-protection settings change, and
  deliberately left to a separate, explicit decision — not made here.**
- **No change to the `shellcheck` job's own scope** (`waio.sh`
  `workers/*.sh` only, as before) — `tests/*.sh` is exercised by
  actually running it in the new job, which is a stronger check than
  linting it would be, so it was not added to the `shellcheck` glob.
- **Also fixed**: a stale note in "Deliberately not integrated" below,
  left unstale since Phase 12 fixed it — it still said
  `jobs/test-job.sh`'s IP mismatch was "unresolved" when it had already
  been resolved. Corrected while surveying open items for this phase;
  no code changed by this correction.
- **Found and fixed via the first real CI run of this job**: it failed
  completely on first push — 17 passed, 42 failed, 3 skipped, almost
  every non-trivial assertion red. Root cause, confirmed by
  reproducing locally with `HOME` pointed at an empty directory:
  `waio.sh` (line 7, unchanged since long before this phase) does
  `source ~/.waio.env` under `set -euo pipefail`; on this developer's
  machine that file already exists (0 bytes, since Phase 12 — sourcing
  an empty file is a no-op), but a fresh GitHub-hosted runner's `$HOME`
  has no such file at all, and `source`ing a **missing** file (as
  opposed to an empty one) fails hard under `-e`, killing `waio.sh`
  before it reaches any dispatch logic — every single stage in every
  test case, so almost every assertion failed uniformly. This is a
  pre-existing property of `waio.sh` itself, not a bug this phase
  introduced or one appropriate to fix in `waio.sh` (the local-dev
  assumption that `~/.waio.env` exists is intentional, per the
  Takomachi integration phase — it is deliberately not part of this
  repo, since it can hold a live credential). The correct, minimal fix
  is entirely on the CI side: the `regression` job gained one more
  step, `touch ~/.waio.env`, before running the suite — the same empty
  file this developer's machine already has, sourced as a no-op the
  same way. **No worker exercised by this suite (`ECHO`/`BOGUS`/
  `HOST800`) reads any variable from that file**, so an empty file is
  correct, not a workaround masking a real dependency.
- `waio.sh`, `workers/registry.conf`, `workers/pipeline.conf`, every
  worker script, and `tests/orchestrate_worker_test.sh` itself are
  untouched — confirmed via `git diff --stat` showing only
  `.github/workflows/lint.yml` and this file changed.
- Verified 2026-08-30: `.github/workflows/lint.yml` parses as valid YAML
  (`python3 -c "import yaml; yaml.safe_load(...)"`); the regression
  suite was re-run locally and stayed **64 passed, 0 failed, 0
  skipped**, confirming Phase 17's script itself needed no change for
  this wiring. The `~/.waio.env`-missing failure mode above was
  reproduced locally (`HOME=<empty dir>`) before the fix and confirmed
  gone after it (`HOME=<dir with only an empty .waio.env>` → 64/0/0)
  — the actual GitHub Actions failure was root-caused and fixed without
  needing another CI round-trip to iterate blind. Full `bash -n` sweep
  across `waio.sh`/`workers/*.sh`/`jobs/*.sh`/`tests/*.sh` passed. The
  `regression` job's real, fixed behavior on GitHub's runner is
  confirmed by this phase's own PR's second CI run.
- Not implemented: promoting `regression` to a required branch-
  protection check (explicitly left as a separate decision, see above);
  automated coverage for the Keychain-gated workers or the "no stages
  configured" case (same reasons Phase 17 already gave); Router
  LLM-assisted matching, `agent_manager` investigation, and
  cron/unattended execution for Takomachi workers all remain open,
  explicitly out of scope for this phase (Takomachi/GUI-Terminal/
  Keychain-dependent, per this phase's own instruction to not expand
  into that territory).

## Phase 19 (2026-08-30): empty-member guard for stray "+" in a group

Found while re-surveying the backlog after Phase 18: a "+"-group token
with a doubled `+` (e.g. `ECHO++BOGUS`) or a leading `+` (e.g. `+ECHO`)
produces an empty string as one of its members once split. Reproduced
directly before deciding to fix it: `WAIO_PIPELINE="ECHO++BOGUS"`
reached `./waio.sh -w ''` for that empty member, and `waio.sh` treats an
empty `-w` value as **no override at all**, silently falling back to
matching the stage's input text against registry keywords instead of
erroring — a real, if narrow, silent-misdispatch risk: if that input
text happened to contain a registered NAME/TYPE substring (plausible,
since later stages' input includes accumulated `HISTORY` from earlier
stages), the empty member would dispatch to whatever keyword matched,
not fail cleanly. This is exactly the class of thing every up-front
guard since Phase 7 exists to prevent.

- **Fix**: the existing up-front validation pass (Phase 16's
  condition-prefix parsing + self-reference guard, one loop over every
  stage token before any stage runs) now also rejects an empty member
  as soon as it splits a token on `+` — same loop, same placement, one
  new `[ -z "$gm" ]` check ahead of the existing `ORCHESTRATE`-name
  check. A bare `+` alone (`WAIO_PIPELINE="+"`) is caught the same way
  (splits to a single empty member).
- **Trailing `+` deliberately left alone**: `ECHO+` was already handled
  harmlessly before this phase — `read -ra ... <<< "$tok"` drops a
  trailing empty field, so it silently becomes a group of one (`ECHO`),
  identical to not having the `+` at all. Not a bug (nothing empty ever
  reaches `waio.sh`), so left unchanged rather than adding a guard for a
  case that was never actually broken.
- **Zero effect on any existing valid pipeline**: no `WAIO_PIPELINE`/
  `pipeline.conf` entry from any prior phase, or in current
  `workers/pipeline.conf` itself, was ever malformed this way —
  confirmed by the full regression suite staying green (below).
- `waio.sh`, `workers/registry.conf`, `workers/pipeline.conf`, and every
  individual worker script are untouched. Only
  `workers/orchestrate_worker.sh` (the guard) and
  `tests/orchestrate_worker_test.sh` (new cases) changed.
- End-to-end verified 2026-08-30: `ECHO++BOGUS`, `+ECHO`, and a bare `+`
  all rejected before any stage ran, exit 1, error text identifying the
  stray `+`; `ECHO+` (trailing) still runs exactly as before, exit 0.
  Added as four new cases (`P19-1`..`P19-4`) to
  `tests/orchestrate_worker_test.sh`'s Tier 1 section, alongside the
  existing Phase 7-16 cases (kept unchanged, not renumbered). Two
  consecutive full suite runs both **72 passed, 0 failed, 0 skipped**
  (the original 64 plus 8 new assertions), confirming both the fix and
  zero regression. Full `bash -n` sweep across
  `waio.sh`/`workers/*.sh`/`jobs/*.sh`/`tests/*.sh` passed. `shellcheck`
  and the `regression` CI job are verified via this phase's own PR, the
  same way every prior code-touching phase's CI status was ultimately
  confirmed (no local `shellcheck` available in this environment, as
  before Phase 17/18).
- Not implemented: no guard added for the harmless trailing-`+` case
  (see above, not a bug); every other backlog item surveyed at the
  start of this phase remains exactly where Phase 18 left it (branching
  content-based conditions, Router auto-parallelization, the "no stages
  configured" test gap, promoting `regression` to a required check, and
  every Takomachi/GUI-Terminal/Keychain-dependent item).

## Phase 20 (2026-08-30): automate the "no stages configured" test case

Closes the one remaining item Phase 17 explicitly flagged as skipped
("would require temporarily emptying the real `workers/pipeline.conf`,
judged not worth mutating a live config file for one low-value case")
and Phase 18/19 both left untouched. Re-judged this phase: the mutation
risk Phase 17 was avoiding can be fully contained with the same
trap-guaranteed-restore idiom `workers/orchestrate_worker.sh` itself
already uses for its own temp files, so the case is worth having.

- **New test case `P20-1`**, added to
  `tests/orchestrate_worker_test.sh`'s Tier 1 section: temporarily
  renames `workers/pipeline.conf` aside and replaces it with an empty
  file, sends a request with no resolvable Router keyword (so
  `task_classification` is `fallback`), confirms the exact
  `no stages configured (source: workers/pipeline.conf)` error and exit
  `1`, then restores the original file — verified byte-identical via an
  MD5 checksum comparison before/after, both this phase's local runs.
- **Restore is double-guaranteed**: an explicit restore runs
  immediately after the one `run_orchestrate` call (before any
  assertion even executes), and a `trap ... EXIT` set for the duration
  of the swap is a second safety net in case the script is interrupted
  between the rename and the explicit restore — the trap is cleared
  (`trap - EXIT`) right after the explicit restore succeeds, so it
  never fires redundantly, and it costs nothing (`2>/dev/null`, no-op)
  if the file is already back by the time the script actually exits.
  This is the **only** exception to Phase 17's original "no changes to
  any tracked file" property, scoped to milliseconds around one test
  case, not a persistent change — the header comment now documents this
  exception explicitly instead of the blanket claim it made before.
- **Zero production code changed**: `workers/orchestrate_worker.sh`,
  `waio.sh`, `workers/registry.conf`, and every worker script are
  untouched. Only `tests/orchestrate_worker_test.sh` changed — this
  phase is pure test-coverage work, the safest possible category of
  change with respect to Phase 1-19 compatibility (nothing to regress,
  since nothing that runs in production changed).
- End-to-end verified 2026-08-30: two full consecutive suite runs, both
  **75 passed, 0 failed, 0 skipped** (the prior 72 plus 3 new
  assertions); `workers/pipeline.conf`'s MD5 checksum confirmed
  identical before and after both runs; no leftover
  `workers/pipeline.conf.phase20-test-backup.*` file after either run.
  Full `bash -n` sweep across
  `waio.sh`/`workers/*.sh`/`jobs/*.sh`/`tests/*.sh` passed. `shellcheck`
  and the `regression` CI job verified via this phase's own PR.
- Not implemented: every other backlog item is unchanged from where
  Phase 19 left it (branching content-based conditions, Router
  auto-parallelization, promoting `regression` to a required
  branch-protection check, and every Takomachi/GUI-Terminal/
  Keychain-dependent item) — this phase closed exactly the one test-gap
  item named above, nothing more.

## Phase 21 (2026-08-30): automate the "pipeline config not found" test case

Closes the single remaining untested error path in
`workers/orchestrate_worker.sh`. Found by systematically enumerating
every `ERROR:`/`exit 1`/`exit 2` line in the script and cross-checking
each against `tests/orchestrate_worker_test.sh`'s existing 75
assertions: every guard added since Phase 7 had a case except one —
`pipeline config not found: $PIPELINE_CONF` (the fallback path when
`workers/pipeline.conf` doesn't exist at all), distinct from Phase 20's
`no stages configured` case (which covers the file *existing but
empty*). With this phase, every error path in the file now has direct
test coverage.

- **New test case `P21-1`**, added right after Phase 20's `P20-1` in
  `tests/orchestrate_worker_test.sh`'s Tier 1 section: temporarily
  renames `workers/pipeline.conf` aside (left absent entirely this
  time, no replacement file needed, unlike P20-1) using the exact same
  trap-guaranteed-restore idiom Phase 20 established, sends a request
  with no resolvable Router keyword, confirms the exact
  `pipeline config not found: workers/pipeline.conf` error and exit
  `1`, then restores the original file — verified byte-identical via
  MD5 checksum before/after, both this phase's local runs.
- **Same double-guaranteed restore as Phase 20**: explicit restore
  immediately after `run_orchestrate`, plus a `trap ... EXIT` safety
  net cleared right after the explicit restore succeeds. The header
  comment's "exceptions to no file changes" note now lists both P20-1
  and P21-1 together.
- **Zero production code changed** — same category as Phase 20: only
  `tests/orchestrate_worker_test.sh` changed.
  `workers/orchestrate_worker.sh`, `waio.sh`, `workers/registry.conf`,
  and every worker script are untouched.
- End-to-end verified 2026-08-30: two full consecutive suite runs, both
  **77 passed, 0 failed, 0 skipped** (the prior 75 plus 2 new
  assertions); `workers/pipeline.conf`'s MD5 checksum confirmed
  identical before and after both runs; no leftover
  `workers/pipeline.conf.phase21-test-backup.*` file after either run.
  Full `bash -n` sweep across
  `waio.sh`/`workers/*.sh`/`jobs/*.sh`/`tests/*.sh` passed. `shellcheck`
  and the `regression` CI job verified via this phase's own PR.
- Not implemented: every other backlog item is unchanged from where
  Phase 20 left it (branching content-based conditions, Router
  auto-parallelization, promoting `regression` to a required
  branch-protection check, and every Takomachi/GUI-Terminal/
  Keychain-dependent item). With this phase, `orchestrate_worker.sh`'s
  own error/guard paths have no known remaining gaps in automated
  coverage — further test-coverage phases of this exact shape are not
  expected to find another one without the script itself changing
  first.

## Phase 22 (2026-08-30): automated regression suite for waio.sh itself

Phase 21 concluded `orchestrate_worker.sh`'s own error paths had no
remaining automated-coverage gaps. Re-surveying the backlog with that
avenue closed, the most valuable remaining WAIO-internal, safe, minimal
item was a different gap entirely: `waio.sh` — the canonical dispatch
entry point every worker (including `orchestrate_worker.sh`) goes
through — had **zero** automated test coverage of its own. Every
existing test in `tests/orchestrate_worker_test.sh` exercises `waio.sh`
only incidentally, through `-w ORCHESTRATE`; none of `waio.sh`'s own
eight `ERROR:` paths (option parsing, request validation, registry
loading, worker resolution) were directly tested.

- **New file `tests/waio_test.sh`**, mirroring
  `tests/orchestrate_worker_test.sh`'s own conventions exactly:
  self-contained bash (the small `assert_eq`/`assert_contains` helpers
  are duplicated here rather than extracted into a shared file —
  extracting them would have meant modifying the existing test file
  too, which this phase's own "no unnecessary refactoring" instruction
  ruled out; each test file stays independently runnable, the same
  design choice Phase 17 made originally), no mocking, drives the real
  `./waio.sh` entry point. Run directly:
  `./tests/waio_test.sh`.
- **12 cases, all Keychain-free and network-free** (`ECHO`/`BOGUS`
  only, portable anywhere): the three ways to pass an explicit worker
  (`-w NAME`, `--worker NAME`, `--worker=NAME`), an unregistered `-w`
  name, an unknown CLI option, an empty request, single-keyword
  dispatch (`match=keyword` in the log line), no-keyword-match with
  multiple workers registered, and four `workers/registry.conf` error
  paths reached by briefly renaming it aside — missing entirely, present
  but empty, a registered worker whose `HOST` isn't `750` (the
  "remote execution target ... not supported yet" path, not reachable
  through the registry's real current content, so a throwaway one-line
  registry was substituted for that one case only), and a registered
  worker pointing at a nonexistent script.
- **Same trap-guaranteed restore idiom as Phase 20/21's `P20-1`/`P21-1`**
  (which did this for `workers/pipeline.conf`): explicit restore
  immediately after each of the four registry-swapping cases, plus a
  `trap ... EXIT` safety net cleared right after each explicit restore
  succeeds. Verified via MD5 checksum of `workers/registry.conf`
  before/after — identical both local runs.
- **`.github/workflows/lint.yml`**: the existing `regression` job
  (Phase 18) gained one more step, `./tests/waio_test.sh`, right after
  Phase 17's suite — same job, not a new one, since both are
  Keychain-free/network-free regression suites with the same CI
  requirements (the `~/.waio.env` setup step Phase 18 already added
  covers this suite too, no further CI environment change needed).
- **Zero changes to any production script**: `waio.sh`,
  `workers/orchestrate_worker.sh`, `workers/registry.conf`,
  `workers/pipeline.conf`, and every individual worker script are
  untouched — confirmed via `git diff --stat`. Only the new test file
  and the one-line CI workflow addition changed.
- End-to-end verified 2026-08-30: every one of the 12 planned cases was
  first dry-run manually against the real `waio.sh` (including the
  registry-swap cases, with checksum verification before automating
  them into the script) to confirm exact error text and exit codes
  before writing the assertions, the same care Phase 19-21 already
  applied. Two full consecutive runs of the new suite, both **24
  passed, 0 failed**; the existing `tests/orchestrate_worker_test.sh`
  re-run immediately after and confirmed still **77 passed, 0 failed, 0
  skipped**, unaffected. `workers/registry.conf`'s MD5 checksum
  confirmed identical before and after both new-suite runs; no leftover
  `workers/registry.conf.phase22-test-backup.*` file. `.github/workflows/lint.yml`
  parses as valid YAML. Full `bash -n` sweep across
  `waio.sh`/`workers/*.sh`/`jobs/*.sh`/`tests/*.sh` passed. `shellcheck`
  and both `regression` job steps verified via this phase's own PR.
- Not implemented: `waio.sh`'s Keychain-gated dispatch targets
  (`RESEARCH`/`ANALYSIS`/`AI`/`HEALTHCHECK`) remain manual-verification-
  only, same reason as every prior phase; every other backlog item is
  unchanged from where Phase 21 left it (branching content-based
  conditions, Router auto-parallelization, promoting `regression` to a
  required branch-protection check, and every Takomachi/GUI-Terminal/
  Keychain-dependent item).

## Phase 23 (2026-08-30): test coverage for a worker's own pre-SSH guards

Re-surveyed Phase 1-22's implementation, tests, and backlog to pick the
highest-value, lowest-compat-risk next item. `orchestrate_worker.sh`
(Phase 21) and `waio.sh` (Phase 22) both reached full automated
error-path coverage; every other open backlog item is either a bigger
feature repeatedly deferred as out of proportion for a single minimal
phase (branching content-based conditions, Router auto-parallelization),
a GitHub branch-protection settings change (out of scope for a code
phase), or explicitly Takomachi/GUI-Terminal/Keychain-dependent (out of
bounds per this phase's own instruction). Looking one layer deeper —
into an individual worker script's own logic, not just `waio.sh`/
`orchestrate_worker.sh`'s dispatch layer — found the next real, narrow,
zero-risk gap: `workers/host800_worker.sh` has two guard clauses
("empty request", "unsupported job type") that run and can reject
**before** it ever attempts its real SSH call, so both are fully
Keychain-free and LAN-free, yet neither was covered by any existing
test (only its successful `system`/`identity` paths were, in
`tests/orchestrate_worker_test.sh`'s LAN-dependent Tier 2). `rpi_worker.sh`
was checked too and has no equivalent guard logic — it SSHes
unconditionally with no pre-flight validation of its own, so it had
nothing analogous to add here.

- **Two new cases in `tests/waio_test.sh`**, `W13`/`W14`, right after
  `W12`: `W13` dispatches `./waio.sh -w HOST800 "<text with neither
  'system' nor 'identity'>"`, confirming the exact
  `unsupported job type in request` error and exit `1` — reachable
  directly through `waio.sh`, no registry manipulation needed. `W14`
  found and worked around a subtlety while writing it: `HOST800`'s own
  "empty request" guard is unreachable through `waio.sh` at all — `waio.sh`'s
  own empty-request check (`W6`) already rejects an empty request before
  any worker script is ever invoked, the same way `T5` already had to
  call `orchestrate_worker.sh` directly to reach *its* empty-request
  guard. `W14` follows that exact precedent: it calls
  `./workers/host800_worker.sh ""` directly, confirming
  `[HOST800 WORKER] ERROR: empty request` and exit `1`.
- **Zero production code changed**: `workers/host800_worker.sh`,
  `waio.sh`, `workers/orchestrate_worker.sh`, `workers/registry.conf`,
  `workers/pipeline.conf`, and every other worker script are untouched
  — confirmed via `git diff --stat` showing only `tests/waio_test.sh`
  changed. Same lowest-risk category as Phase 20-22.
- End-to-end verified 2026-08-30: both new cases dry-run manually
  against the real scripts first (same care as every prior test-adding
  phase) before being written into the suite. Two full consecutive runs
  of `tests/waio_test.sh`, both **28 passed, 0 failed** (the prior 24
  plus 4 new assertions); `tests/orchestrate_worker_test.sh` re-run
  immediately after and confirmed still **77 passed, 0 failed, 0
  skipped**, unaffected. Full `bash -n` sweep across
  `waio.sh`/`workers/*.sh`/`jobs/*.sh`/`tests/*.sh` passed. `shellcheck`
  and both `regression` job steps verified via this phase's own PR.
- Not implemented: `rpi_worker.sh` has no guard logic to add coverage
  for (checked, confirmed empty-handed, noted above rather than forcing
  a case where none exists); every other backlog item is unchanged from
  where Phase 22 left it (branching content-based conditions, Router
  auto-parallelization, promoting `regression` to a required
  branch-protection check, and every Takomachi/GUI-Terminal/
  Keychain-dependent item).
## DLP / Emergency Shutdown Layer (2026-08-30)

Requested by the user as a formal Data Loss Prevention / Emergency
Shutdown layer, red-team evaluated: **data exfiltration = failure**,
even if WAIO subsequently detects and stops itself. Scoped, per the
request, to what is implementable entirely inside this repo with local
dummy data and destinations only -- no real external service is
contacted or attacked by anything in this phase.

**Threat model, stated honestly** (see `security/lib.sh`'s own header
comment for the full version): WAIO is a single-operator local bash
tool, not a sandboxed multi-tenant system, and today's workers never
construct a destination from attacker-controlled input -- every
outbound call target is either hardcoded (`localhost:3000` for
Takomachi, `192.168.1.150` for the Pi) or read from a fixed local
config file (`workers/800.json`). This layer is a **cooperative choke
point** every current outbound call already goes through, not a
sandbox or network-level firewall: it stops an unauthorized
destination, an oversized payload, or a credential-shaped string in
worker output from silently reaching the real network, but it cannot
stop an attacker who has already replaced these library functions or
bypassed their call sites entirely. This is defense in depth on top of
the existing dispatch path. "権限逸脱" (privilege escalation) was
requested as a detection category but has no concrete mechanism in
this architecture (no privilege model exists to escalate within) --
left unimplemented rather than faked, noted explicitly here.

### 1. Data-loss prevention mechanism

- **`security/egress_allowlist.conf`**: `HOST|PORT|LABEL`, same format
  convention as `workers/registry.conf`. Lists WAIO's only three real
  outbound destinations today (Takomachi, the Pi, 800号機). Adding a
  new destination requires an explicit line here, same discipline as a
  new worker requiring a `registry.conf` line.
- **`security/lib.sh`** (sourced, not executable): `egress_check HOST
  PORT` denies (and trips shutdown) any destination not in the
  allowlist; `payload_size_check PAYLOAD` denies an outbound payload
  over `WAIO_MAX_PAYLOAD_BYTES` (default 100000, env-overridable, same
  pattern as Phase 15's `WAIO_MAX_PARALLEL`) -- catches a
  bulk-exfiltration-shaped request before it's sent; `secret_leak_check
  OUTPUT_TEXT` pattern-matches common credential shapes (API-key-style,
  AWS-access-key-style, PEM private key headers) in a worker's own
  response before it is printed, withholding it if matched.
- **Wired into every real outbound call site**: `egress_check` before
  the `ssh` call in `workers/rpi_worker.sh` and
  `workers/host800_worker.sh`; `egress_check` + `payload_size_check`
  before the Takomachi `curl` call and `secret_leak_check` on the
  response in `workers/research_worker.sh`/`analysis_worker.sh`/
  `ai_worker.sh`; `egress_check` only in `workers/healthcheck_worker.sh`
  (a fixed `GET /health` with no request-derived payload or
  Takomachi-driven response to check). Each insertion is additive --
  the existing call, its error handling, and its output format are
  otherwise untouched.

### 2. Shutdown conditions

Emergency Shutdown trips (via `trigger_shutdown`, writing
`security/state/SHUTDOWN.lock` -- gitignored runtime state, not
source) the instant any of these fire, from any worker, any stage:
- `egress_check` denies a destination not on the allowlist.
- `payload_size_check` denies an oversized outbound payload.
- `secret_leak_check` matches a credential-shaped string in output.
- The allowlist file itself is missing (fail-closed on a broken guard,
  not fail-open).

**Fail-closed, everywhere a task could start**: `waio.sh` checks
`is_shutdown_active` immediately after sourcing `~/.waio.env`, before
any registry/worker logic -- refuses every single-worker and
`ORCHESTRATE` dispatch alike while tripped.
`workers/orchestrate_worker.sh` has its own top-level check too (fails
fast and clearly if a run starts while shutdown is already active,
rather than running every stage to the same conclusion one by one).
**Mid-run propagation needed no new code**: since every
`orchestrate_worker.sh` stage dispatches via `./waio.sh -w NAME`
(unchanged since Phase 7), a shutdown tripped by stage N is
automatically enforced on stage N+1's `./waio.sh` call by the same
top-level `waio.sh` gate -- the existing Phase 7-16 FAILURE HANDLING
loop (unchanged) forwards the refusal and the run correctly ends
`overall_status: failed`, exit `2`, with zero modification to the
stage-execution loop itself. Verified directly (Red Team scenario 4,
below).

### 3. Audit specification

- **`security/lib.sh`'s `audit_log`**, one JSON line per event to
  `logs/security-audit.jsonl` (gitignored, same convention as
  `logs/`/`results/`): `{timestamp, event_type, run_id, stage, worker,
  destination, decision, reason}`. `event_type` is one of
  `egress_allowed`, `egress_denied`, `shutdown_triggered`, or (from
  `security/recover.sh`) `recovery_confirmed`.
- **No secret values, credentials, or payload/response content are
  ever logged** -- structurally, not by redaction: `audit_log`'s
  function signature has no parameter for payload or response content
  at all, only metadata fields, so there is no code path through which
  one could leak in. Verified directly (Red Team scenario 3, below:
  confirmed the dummy secret value never appears in the audit log).
- **`security/recover.sh`**: the only way to clear
  `security/state/SHUTDOWN.lock`. Refuses to run without
  `--confirm "<non-empty reason>"` (requirement: no auto-recovery, an
  explicit human confirmation is mandatory); on success, clears the
  lock and writes a `recovery_confirmed` audit event carrying the
  given reason.

### 4. Local Red Team test results

**`tests/security_test.sh`**, driving the real `waio.sh`/
`orchestrate_worker.sh`/worker scripts exactly like every other test
suite in this repo -- no mocking. Three purpose-built fixture workers
under `tests/security_fixtures/` (test-only, never registered
permanently) simulate a compromised worker attempting each anomaly
class, registered just long enough to dispatch once via the same
registry-swap-and-restore idiom Phase 22/23 already established.
**Nothing here ever contacts a real external service**:
`malicious_egress_worker.sh` targets `198.51.100.1` (RFC 5737
TEST-NET-2, reserved/unroutable by definition); `secret_leak_worker.sh`
uses a fabricated, non-functional dummy key string; every fixture is
expected to be stopped by the guard before reaching its own
`echo "...DATA_EXFILTRATED..."` marker line, and every test case
asserts that marker never appears in output -- the same "caught after
the fact is not a pass" standard the request specified, enforced
directly rather than assumed.

Evaluation matches the requested PASS/FAIL rule exactly: PASS requires
detection **and** zero data leaving the system in the same run; a
marker appearing anywhere (stdout, the per-run log, or the audit log)
fails that case regardless of what else happened.

**Results, two full consecutive runs, both PASS on every scenario**:
1. **R1 -- unauthorized egress destination**: denied before any SSH/curl
   attempt, `overall_status`-equivalent exit `1`, no exfiltration
   marker, shutdown tripped. **R1b**: a completely unrelated,
   legitimate new task (`ECHO`) is refused while shutdown is active
   (the core fail-closed requirement). **R1c**: audit log correctly
   recorded the trigger and the denied destination. **R1d**: recovery
   without `--confirm` is refused, shutdown stays active. **R1e/R1f**:
   recovery with `--confirm` clears it, normal operation resumes.
2. **R2 -- anomalous bulk payload** (200,000-byte dummy request vs. the
   100,000-byte default limit): denied before any network call, no
   exfiltration marker, shutdown tripped, recovered.
3. **R3 -- credential-shaped string in worker output**: denied before
   the dummy secret is printed, no exfiltration marker, **and the dummy
   secret value itself never appears in the audit log**, recovered.
4. **R4 -- mid-pipeline propagation**: `WAIO_PIPELINE="ECHO
   REDTEAM_MALICIOUS ECHO"` via `ORCHESTRATE` -- stage 1 (`ECHO`)
   succeeds, stage 2 (the malicious fixture) is denied and trips
   shutdown, stage 3 (`ECHO` again) is refused by `waio.sh`'s own gate
   with zero purpose-built code in `orchestrate_worker.sh` for this
   case (see "Shutdown conditions" above) -- `overall_status: failed`,
   exit `2`, no exfiltration marker anywhere in stdout or the per-run
   log.
5. **L1/L2 -- legitimate-traffic sanity** (real SSH, LAN-dependent,
   skips cleanly like `tests/orchestrate_worker_test.sh`'s Tier 2 when
   unreachable): `HOST800` and `RPI`, both allowlisted, both still
   succeed end to end with every guard wired in -- confirms the layer
   does not break real traffic to authorized destinations.

Total: **32 passed, 0 failed, 0 skipped** (this machine has LAN access
to both real targets) across two consecutive runs; `workers/registry.conf`'s
MD5 checksum confirmed identical before/after both runs.

### 5. Existing regression test results

Run immediately after the Red Team suite, both fully green, confirming
Phase 7-23's normal/parallel/branching/failure-forwarding behavior is
unaffected by every guard call added: `tests/orchestrate_worker_test.sh`
**77 passed, 0 failed, 0 skipped**; `tests/waio_test.sh` **28 passed, 0
failed**. Full `bash -n` sweep across
`waio.sh`/`workers/*.sh`/`security/*.sh`/`jobs/*.sh`/`tests/*.sh`/
`tests/security_fixtures/*.sh` passed.
`.github/workflows/lint.yml`'s `shellcheck`/`bash -n` glob was extended
to include `security/*.sh` (the DLP layer is now part of the canonical
dispatch path); the `regression` job gained a third step running
`tests/security_test.sh` (its own L1/L2 LAN check means it skips
cleanly, not fails, on a GitHub-hosted runner with no route to this
LAN, same as `tests/orchestrate_worker_test.sh`'s Tier 2).

### 6. Remaining risk (stated plainly, not minimized)

- **This is cooperative code, not a sandbox.** Every guard call is a
  function invocation the worker script chooses to make; a worker
  script modified to skip the `egress_check`/`payload_size_check`/
  `secret_leak_check` call entirely (or to call a different, attacker-
  supplied `security/lib.sh`) is not stopped by anything in this layer.
  True isolation would need an OS-level sandbox or network-level
  egress filtering outside bash's own reach -- explicitly out of scope
  per "WAIOリポジトリ内で実装可能な最小構成."
- **Secret-shape detection is pattern-based, not exhaustive.**
  `secret_leak_check`'s regex covers a few common credential shapes
  (OpenAI-style, AWS access keys, PEM private keys); a credential in an
  unrecognized format, or one deliberately obfuscated (base64, split
  across lines/calls), would not match.
- **No in-flight process is forcibly killed.** "隔離・停止" is achieved
  by refusing every *subsequent* dispatch (new stages, new top-level
  tasks) the instant shutdown trips, not by sending a signal to a
  `curl`/`ssh` process already in flight at the moment of detection
  (Phase 13's parallel-group PIDs are not touched by this phase). A
  same-stage sibling already running in parallel when one member trips
  shutdown will run to its own completion rather than being killed
  mid-flight.
- **`security/lib.sh`'s functions run in the same trust boundary as the
  worker calling them** -- there is no separate privilege level between
  "worker code" and "guard code" in a plain bash process.
- **Not implemented**, consistent with the request's stated minimal
  scope: privilege-escalation detection (no mechanism in this
  architecture to hook into, see "Threat model" above); real external
  egress testing (deliberately never attempted, all destinations here
  are reserved/dummy); Takomachi-side or GUI-Terminal-side integration
  of any kind (the user's separately recorded "DuCoPA" future direction
  — an external Guardian control plane in Takomachi — is exactly the
  kind of follow-on this layer's own limitations point toward, and is
  explicitly not part of this phase).

## Phase 24 (2026-08-30): direct unit tests for security/lib.sh's own edge cases

Applies the same "audit every guard path for automated coverage" habit
Phase 19-23 used across `orchestrate_worker.sh`/`waio.sh`/
`host800_worker.sh` to the DLP layer itself. The Red Team scenarios
(R1-R4) exercise `security/lib.sh`'s functions only indirectly, through
whichever single path a given fixture worker happens to take; several
of the functions' own internal branches were never reached by any of
them. No new attack surface, no Red Team/DuCoPA/Kill60Sec expansion —
this phase is pure test coverage of what already exists, same lowest-
risk category as Phase 20/21/23.

- **New: `tests/security_test.sh` calls `security/lib.sh`'s functions
  directly** (it already sources the library for its `is_shutdown_active`
  checks), rather than only through a fixture worker's single call site
  — reaches branches a fixture-worker-shaped test can't isolate:
  - **`U1`**: `security/recover.sh` with no active shutdown — the
    "nothing to do" early-return path, never exercised before (every
    prior test that reached `recover.sh` did so only after tripping a
    shutdown first).
  - **`U2`/`U3`**: `payload_size_check`/`secret_leak_check`'s own
    "allowed"/"clean" return-0 path, asserted directly (R2/R3 only ever
    exercised their *denial* path).
  - **`U4`**: `egress_check`'s `"*"` wildcard-port matching — untested
    before since `security/egress_allowlist.conf`'s three real entries
    are all exact ports. Tested via a temporary, trap-restored extra
    line (`203.0.113.5|*|...`, RFC 5737 TEST-NET-3 — reserved, same
    dummy-destination discipline as the Red Team fixtures), not a
    permanent change to the real allowlist.
  - **`U5`**: `egress_check` when `security/egress_allowlist.conf`
    itself is missing — the fail-closed-on-a-broken-guard path
    (`trigger_shutdown "egress allowlist missing..."`), reached via the
    same trap-guaranteed rename-aside-and-restore idiom used for
    `workers/registry.conf`/`workers/pipeline.conf` throughout Phase
    20-23.
  - **`U6`**: `trigger_shutdown` idempotency — calling it twice with
    different reasons confirms `security/state/SHUTDOWN.lock` keeps the
    *first* reason (so the original cause of a shutdown is never lost
    to a later, possibly less-informative trigger), while the audit log
    still records both attempts.
  - **`U7`**: `egress_check`'s own `is_shutdown_active` short-circuit —
    denies even an *allowlisted* destination once shutdown is already
    active. Documented here as effectively unreachable through the
    normal dispatch path today (`waio.sh`'s own gate, checked before any
    worker runs, already refuses the request earlier) — this test
    exercises it directly as the defense-in-depth branch it's designed
    to be, in case a future call site ever invokes `egress_check`
    without going through `waio.sh` first.
- **Zero production code changed** — confirmed via `git diff --stat`
  showing only `tests/security_test.sh` modified. `security/lib.sh`,
  `security/recover.sh`, `security/egress_allowlist.conf`, and every
  worker script are untouched.
- End-to-end verified 2026-08-30: two full consecutive runs of
  `tests/security_test.sh`, both **47 passed, 0 failed, 0 skipped**
  (the prior 32 plus 15 new assertions). `workers/registry.conf` and
  `security/egress_allowlist.conf` MD5 checksums confirmed identical
  before/after both runs; no leftover `*-backup.*` files.
  `tests/orchestrate_worker_test.sh` (77/0/0) and `tests/waio_test.sh`
  (28/0) re-run immediately after, unaffected. Full `bash -n` sweep
  across `waio.sh`/`workers/*.sh`/`security/*.sh`/`jobs/*.sh`/
  `tests/*.sh`/`tests/security_fixtures/*.sh` passed.
- Not implemented, deliberately: no Red Team scenario expansion, no
  DuCoPA/Kill60Sec work (explicitly out of scope for this phase per the
  user's own instruction); privilege-escalation detection and every
  other item Phase 24 either lists or is already listed under "DLP /
  Emergency Shutdown Layer" above remain exactly where they were.

## Phase 25 (2026-08-30): real production workers' own egress denial, not a fixture stand-in

Closes the last gap in DLP test coverage identifiable without touching
Red Team/DuCoPA/Twin AI/Kill60Sec (all explicitly out of scope unless
named): every denial scenario tested so far (R1-R4, Phase 24's U-series)
proves the *guard mechanism itself* works, using purpose-built fixture
workers under `tests/security_fixtures/` — but neither
`workers/host800_worker.sh`'s nor `workers/rpi_worker.sh`'s own
`egress_check` call site (wired in during the DLP phase) had ever been
proven to actually deny anything for real. Only their *allow* path was
covered, via `L1`/`L2`.

- **New cases `R5`/`R6`** in `tests/security_test.sh`: temporarily drop
  `HOST800`'s (`R5`) or `RPI`'s (`R6`) own line from
  `security/egress_allowlist.conf` (same trap-guaranteed backup/restore
  idiom as Phase 24's `U4`/`U5`), then dispatch the real worker via
  `./waio.sh -w HOST800 "system check"` / `./waio.sh -w RPI "ping"` —
  the exact commands `L1`/`L2` already use for the allowed case, this
  time with that one destination unlisted. Both denied immediately
  (`egress denied by DLP guard`, exit `1`, shutdown tripped) — no real
  SSH attempt is made (confirmed by how fast both cases run: the whole
  53-case suite completes in ~6 seconds locally, nowhere near an SSH
  connection attempt/timeout's worth of time).
- **Unconditional, not LAN-dependent**: unlike `L1`/`L2` (which need
  real connectivity to prove *success*), `R5`/`R6` prove *denial*,
  which requires no network access at all — they run the same way
  whether or not this machine can reach 800号機/the Pi, including in CI.
- **Defensive `timeout` wrap**: `R5`/`R6` run under `timeout 20` when
  available (present on Linux/GitHub Actions runners; guarded with
  `command -v timeout` since it is not always present, e.g. a bare
  macOS shell without GNU coreutils installed) — a safety net so that
  if this guard were ever broken by a future change, the test would
  fail loudly on a timeout instead of hanging the whole suite on a real
  SSH connection attempt.
- **Zero production code changed** — confirmed via `git diff --stat`
  showing only `tests/security_test.sh` modified. `workers/host800_worker.sh`,
  `workers/rpi_worker.sh`, `security/lib.sh`, and
  `security/egress_allowlist.conf` are untouched.
- End-to-end verified 2026-08-30: two full consecutive runs of
  `tests/security_test.sh`, both **53 passed, 0 failed, 0 skipped** (the
  prior 47 plus 6 new assertions), each completing in ~6 seconds locally
  — direct evidence neither case attempted a real network connection.
  `security/egress_allowlist.conf`'s MD5 checksum confirmed identical
  before/after both runs; no leftover `*-backup.*`/`*.phase25tmp` files.
  `tests/orchestrate_worker_test.sh` (77/0/0) and `tests/waio_test.sh`
  (28/0) re-run immediately after, unaffected. Full `bash -n` sweep
  across `waio.sh`/`workers/*.sh`/`security/*.sh`/`jobs/*.sh`/
  `tests/*.sh`/`tests/security_fixtures/*.sh` passed.
- Not implemented, deliberately: the same equivalent test for
  `research`/`analysis`/`ai`/`healthcheck_worker.sh`'s own `egress_check`
  call sites remains impossible in this environment — their own
  Keychain lookup (unrelated to this DLP layer) fails and exits *before*
  reaching their `egress_check` call at all, the same pre-existing,
  unfixable-here limitation every prior phase has already documented; no
  Red Team scenario expansion, no DuCoPA/Twin AI/Kill60Sec work
  (explicitly out of scope per the user's own instruction this phase).

## Phase 26 (2026-08-30): lint coverage for the test suites themselves

Closes the one remaining "written but never linted" gap identifiable
without touching Red Team/DuCoPA/Twin AI/Kill60Sec: `.github/workflows/lint.yml`'s
`shellcheck`/`bash -n` steps had covered `waio.sh`/`workers/*.sh`/
`security/*.sh` since Phase 18/DLP, but never `tests/*.sh` or
`tests/security_fixtures/*.sh` — by this phase, roughly 1000 lines of
test code across three suites plus three fixture workers that had only
ever been proven to *run* (via the `regression` job actually executing
them), never checked against `shellcheck`'s style/correctness rules the
rest of the codebase is held to.

- **`.github/workflows/lint.yml`**: both the `bash -n` and `shellcheck`
  steps in the `shellcheck` job now also glob `tests/*.sh` and
  `tests/security_fixtures/*.sh`. `jobs/*.sh` remains deliberately
  excluded, unchanged from the original Phase 18 scope note ("canonical
  dispatch path only") — `jobs/` is the standalone, not-integrated tool
  documented under "Deliberately not integrated" below, out of scope for
  this lint gate for the same reason it always has been.
- **No production script changed**: `waio.sh`, every `workers/*.sh`, and
  every `security/*.sh` file are untouched — this phase only widens
  which files the existing gate looks at.
- Local `shellcheck` remained unavailable in this environment this
  phase too (an install attempt was made and hit an unrelated, serious
  problem — see below); the test files were manually reviewed for the
  common patterns `shellcheck` flags (unquoted expansions in test
  brackets, backticks instead of `$()`, `local`-plus-command-
  substitution masking a return value) and none were found, but this
  phase's actual verification of the new lint scope is CI itself, per
  this phase's own instruction to identify and fix any CI failure rather
  than requiring local pre-verification.
- **Incident during this phase, unrelated to WAIO itself**: a `brew
  install shellcheck` attempt (to get local verification working)
  triggered a Homebrew formula path that built GHC from source in
  `/private/tmp`, which filled the local disk to 0 bytes free partway
  through this phase's work (every shell command, including plain
  `echo`, started failing). Diagnosed and recovered by killing the
  runaway build process tree, removing its `/private/tmp/ghc-*` build
  directory, and clearing `~/Library/Caches/Homebrew`'s download cache
  — free space went from 0 to roughly 2.4 GiB. No `WAIO` repository file
  was corrupted or lost (`git status` confirmed clean immediately after
  recovery, before any further edits); the one file edit that was
  in-flight when the disk filled (this phase's `lint.yml` change)
  simply hadn't been written yet and was reapplied cleanly afterward.
  No further local `brew install` of `shellcheck` was attempted this
  phase.
- End-to-end verified 2026-08-30 (after the disk-space recovery above):
  `.github/workflows/lint.yml` parses as valid YAML; full `bash -n`
  sweep across `waio.sh`/`workers/*.sh`/`security/*.sh`/`jobs/*.sh`/
  `tests/*.sh`/`tests/security_fixtures/*.sh` passed; all three existing
  regression suites re-run and unaffected —
  `tests/orchestrate_worker_test.sh` 77/0/0,
  `tests/waio_test.sh` 28/0, `tests/security_test.sh` 53/0/0 (158
  assertions total across the three, unchanged from where Phase 25 left
  them). `workers/registry.conf` and `security/egress_allowlist.conf`
  MD5 checksums confirmed unaffected. The new `shellcheck`/`bash -n`
  coverage of `tests/*.sh`/`tests/security_fixtures/*.sh` itself is
  verified via this phase's own PR's CI run, the only way to confirm
  `shellcheck` findings without a local install.
- Not implemented: `jobs/*.sh` remains outside any lint gate
  (unchanged, deliberate); no Red Team scenario expansion, no
  DuCoPA/Twin AI/Kill60Sec work (explicitly out of scope per the user's
  own instruction this phase); promoting `regression`/`shellcheck` to
  required branch-protection checks remains a separate, un-made
  decision (Phase 18's note still stands).

## Phase 29 (2026-08-30): Public / Private Security Boundary — real config gitignored

Implements the findings of a dedicated Phase 28 audit ("Public / Private
Security Boundary Audit", investigation-only, no commit) of what this
public GitHub repository exposes. That audit found **no credentials or
secrets anywhere in the repository or its full git history** (every
commit was searched for API-key/token/PEM-key-shaped strings; the only
match was `tests/security_fixtures/secret_leak_worker.sh`'s own
deliberately-fabricated dummy value). It did find three files holding
this specific deployment's real, non-secret-but-deployment-identifying
values — real LAN IPs, a real hostname, a real username — committed
alongside the generic, reusable framework code: `workers/750.json`,
`workers/800.json`, and `security/egress_allowlist.conf`.

- **New `.example` templates, committed**: `workers/750.json.example`,
  `workers/800.json.example`, `security/egress_allowlist.conf.example`
  — same shape as each real file, placeholder values
  (`REPLACE_WITH_YOUR_...`) instead of this deployment's real ones.
  `security/egress_allowlist.conf.example` keeps `localhost|3000|...`
  as-is (Takomachi is always local, not deployment-identifying) and
  only replaces the two real LAN-IP lines.
- **The three real files are now gitignored** and were removed from git
  tracking with `git rm --cached` (index only — confirmed each file was
  still present on disk, byte-identical, immediately after) so this
  machine's actual configuration keeps working exactly as before,
  untouched; only their presence in *future* commits to the public repo
  changes. `backups/WAIO-MVP-20260829-172803.tar.gz` (an early prototype
  snapshot, confirmed via extraction to contain no secrets, but binary
  archives are not something a source repo should carry going forward)
  was untracked the same way, and `backups/` was added to `.gitignore`.
- **Fails closed, not open, when a real file is absent** — already true
  before this phase, not a new behavior: `workers/800.json` missing
  makes any worker that reads it error out; `security/egress_allowlist.conf`
  missing makes `egress_check()` deny every destination and trip
  Emergency Shutdown (Phase 24's `U5` already covers exactly this case).
  A fresh clone of the public repo, before running the `Setup` steps
  README.md now documents, is therefore maximally restrictive by
  construction, not silently permissive.
- **`README.md`**: new "Setup" section (copy each `.example` to its real
  filename, fill in real values) placed before "Usage"; "Repo layout"
  updated to note each gitignored file's `.example` counterpart.
- **Explicitly not done this phase**, per the request: no git history
  rewrite, no force-push, no deletion of the historical `logs/`/`results/`
  entries that predate this repo's `logs/`/`results/` `.gitignore`
  entries (Phase 28's audit found low-sensitivity system-fingerprint
  content there — hostnames, disk/OS/uptime figures — still reachable
  through `git log`, not addressed here since history rewriting was
  out of scope this phase); no DuCoPA/Twin AI/Kill60Sec work (not
  present in this repository at all, per Phase 28's audit — nothing to
  separate).
- End-to-end verified 2026-08-30: `workers/750.json`, `workers/800.json`,
  and `security/egress_allowlist.conf` confirmed present and
  byte-identical on disk before and after the `git rm --cached` step.
  All three existing regression suites re-run and unaffected (they all
  read these files via the same relative paths production code uses, so
  this is a direct proof the change is behaviorally invisible to
  anything already running on this machine):
  `tests/orchestrate_worker_test.sh` 77/0/0, `tests/waio_test.sh` 28/0,
  `tests/security_test.sh` 53/0/0. Full `bash -n` sweep across
  `waio.sh`/`workers/*.sh`/`security/*.sh`/`jobs/*.sh`/`tests/*.sh`/
  `tests/security_fixtures/*.sh` passed.
- Not implemented: the "next Phase" items Phase 28's audit itself listed
  beyond the three `.example` files and gitignoring (abstracting
  `ARCHITECTURE.md`'s known-limitations prose, deciding what to do about
  the historical `logs/`/`results/` residue) remain open, explicitly
  deferred by this phase's own scope ("追加の設計変更は禁止").

## Phase 30 (2026-08-30): baseline re-audit + DuCoPA boundary clarification — investigation only

Requested as a "safe foundation phase" before any further work: re-verify
Phase 29's state, confirm the 750↔800 interface and DLP layer haven't
regressed, and — assuming a future Dual Control Plane Architecture
(DuCoPA, the user's own recorded future direction, not implemented here)
— clarify where a Main Control Plane (WAIO) and an external Guardian/
Rescue/Shutdown plane (a future Takomachi integration) would each be
responsible for what. Explicitly scoped to investigation and boundary
documentation; no large implementation, no DuCoPA/Twin AI/Kill60Sec code.

- **Structure/dependency re-check**: every `source security/lib.sh` call
  site re-enumerated (8 call sites: `waio.sh`, `workers/orchestrate_worker.sh`,
  and six individual workers) — unchanged from Phase-DLP/24/25.
  `workers/750.json` (unlike `workers/800.json`) is confirmed read by
  **no script in this repository** — it exists purely as registry-style
  documentation of this machine (`role: orchestrator`), the same way
  `workers/800.json` documents 800号機 (`role: worker`). Neither JSON's
  `role` field is read or enforced by any code today — it is prose, not
  a control boundary, an important fact for the DuCoPA discussion below.
- **Security boundary re-verified intact**: `.gitignore`'s Phase 29
  entries, the three real files' untracked status, and the three
  `.example` templates' tracked status all re-confirmed unchanged.
  Re-swept the whole tree for credential-shaped strings — same single,
  deliberately-fabricated dummy match as every prior phase
  (`tests/security_fixtures/secret_leak_worker.sh`), nothing new.
- **750↔800 interface, as it exists today**: one-directional and
  read-only. `workers/host800_worker.sh` (WAIO, on 750) SSHes out to
  800号機 for a fixed set of diagnostic commands (`system`/`identity`);
  800号機 has no channel back — it cannot signal, monitor, or influence
  WAIO in any way today. `jobs/*.sh` (the separate, deliberately-
  not-integrated standalone tool) reaches 800号機 the same one-directional
  way. Nothing here changed or needed to change.
- **DuCoPA boundary analysis** (design-only, matches and extends the
  vocabulary already recorded outside this repo — see the user's own
  DuCoPA note): a **Main Control Plane** (WAIO: Router, TASK
  CLASSIFICATION, pipeline execution, result aggregation, and — notably
  — the DLP/Emergency Shutdown layer itself, which today is entirely
  self-administered from inside WAIO's own trust boundary) versus an
  **External Guardian / Rescue / Shutdown Plane** (a future, separate
  Takomachi-side integration, not built). One concrete, useful finding
  from this phase: `security/state/SHUTDOWN.lock`'s design — a plain
  file whose mere existence trips `is_shutdown_active()` — already gives
  an external process a zero-code-change way to halt WAIO from outside
  it (create the file, WAIO refuses every subsequent dispatch on its
  very next check). The gap runs the other way: `security/recover.sh`,
  which *clears* that same lock, lives inside WAIO's own trust boundary
  today, so WAIO can always release its own shutdown — the opposite of
  DuCoPA's stated principle that "the Guardian's shutdown authority
  should not be releasable by WAIO alone." Closing that gap would need
  a real mechanism (e.g. recovery gated by something only a separate
  Guardian process holds) and is explicitly **not** attempted this
  phase — it is the clearest concrete starting point for a future one.
- **Decision this phase**: no production code change was warranted.
  The investigation found Phase 29's foundation fully intact, no
  regression, and no bug or safety gap urgent enough to justify a
  "minimal change" under this phase's own instruction to prioritize
  investigation and boundary-setting over implementation. This
  `ARCHITECTURE.md` entry is the only change.
- Verified 2026-08-30: `git status`/`git diff` empty and all four
  Phase-29 files' checksums identical both immediately before this
  phase's investigation began and again after this entry was written
  (`workers/750.json`, `workers/800.json`,
  `security/egress_allowlist.conf`, `backups/WAIO-MVP-20260829-172803.tar.gz`
  — none of them touched). All three regression suites re-run
  unaffected: `tests/orchestrate_worker_test.sh` 77/0/0,
  `tests/waio_test.sh` 28/0, `tests/security_test.sh` 53/0/0. Full
  `bash -n` sweep across
  `waio.sh`/`workers/*.sh`/`security/*.sh`/`jobs/*.sh`/`tests/*.sh`/
  `tests/security_fixtures/*.sh` passed.
- Not implemented, explicitly deferred as Phase 31 candidates (per this
  phase's own scope, not decided or started here): a test validating
  the three `.example` templates' own format (JSON syntax /
  `HOST|PORT|LABEL` shape) stays valid over time — a minor, real gap
  this phase's Agent-3-style test review noticed but judged outside
  Phase 30's purpose to add; any real DuCoPA/Guardian implementation
  (a genuinely separate, larger effort — this phase only clarified
  where its boundary would sit); recovery-authority separation between
  WAIO and a future Guardian (the concrete gap identified above).

## Phase 31 (2026-08-30): recovery-authority separation — design only, not implemented

Follow-on to Phase 30's finding that `security/recover.sh` clears
`security/state/SHUTDOWN.lock` from inside WAIO's own trust boundary,
the opposite of DuCoPA's principle that "the Guardian's shutdown
authority should not be releasable by WAIO alone." This phase asked
whether that gap could be closed with a minimal change. **No code was
written or changed.**

- **Confirmed via direct audit**: `security/recover.sh` is the *only*
  code path anywhere in this repository that removes `$SHUTDOWN_LOCK`
  (`rm -f "$SHUTDOWN_LOCK"`, one call site). Nothing in `waio.sh`,
  `workers/orchestrate_worker.sh`, or any worker script ever calls it or
  clears the lock itself — WAIO's *automated* dispatch path cannot
  self-recover today. Only an operator with local shell access to this
  repository can, by running `security/recover.sh` directly. Takomachi's
  own source (`/Users/masa/Projects/Takomachi`) was checked and has zero
  existing awareness of or hook into WAIO's shutdown mechanism.
- **Central finding**: any *technical* enforcement of "only Takomachi
  may recover" requires some way for code to tell a genuine Guardian
  request apart from WAIO's own operator running the same script — which
  is, by definition, an authentication/authorization mechanism. This
  phase's own instructions explicitly prohibited introducing one
  unilaterally ("新しい認証方式の独断導入" forbidden), and doing so would
  also have broken `tests/security_test.sh`'s design: that suite calls
  `./security/recover.sh --confirm "..."` ten times as its own
  self-contained cleanup between scenarios (R1e, R2, R3, R4, R5, R6, U1,
  U5, U6, U7) — gating recovery behind a Guardian-only credential would
  make the entire 53-assertion Red Team suite unusable without a
  running, specially-configured Takomachi, contradicting its
  offline-first design. A Takomachi-unreachable operator would also lose
  all means of recovery even after legitimately fixing the triggering
  cause — a real availability/deadlock risk.
- **Decision**: no safe minimal implementation exists that satisfies
  both "real separation" and "no new auth mechanism, don't break the
  existing test suite" at once. Concluded **design only, not
  implemented** — the correct outcome under this phase's own explicit
  rule that "実装しない" is the right answer when no safe path exists.
- Verified: `git status`/`git diff` empty throughout this phase; no
  files touched.

## Phase 32 (2026-08-30): Guardian authentication method comparison — design only, not implemented

Extends Phase 31 with an explicit comparison of concrete mechanisms
that could, in principle, let a Guardian identify itself to WAIO,
before concluding whether any of them are safe to build now. **No code
was written or changed.**

- **Five candidates compared** against this machine's actual
  configuration (confirmed: WAIO and Takomachi both run as the same
  local user, `masa`, uid 501 — no separate Takomachi OS account exists
  today):

  | Candidate | Finding |
  |---|---|
  | Reuse existing auth | No existing Takomachi→WAIO channel or credential exists to reuse — only WAIO→Takomachi (API key from Keychain) exists today, the wrong direction |
  | Unix permission / file ownership | Architecturally inert on a single-user machine — WAIO's own operator already has (or can `sudo` to) the same privileges any local "Guardian" account would need |
  | Dedicated capability / token | Is itself a new authentication mechanism — prohibited by this phase's own instruction |
  | External signature | Same as above, plus needs key management/distribution, edging toward "外部公開" |
  | Separate process boundary (alone) | Provides no real guarantee without an accompanying user/machine boundary — verifying "this caller really is that process" is itself an identity/auth problem |

- **Decision**: every candidate either (a) requires inventing a new
  authentication primitive (explicitly prohibited this phase), or (b) is
  architecturally inapplicable given the current single-user,
  single-machine deployment (Unix permissions). Concluded **design
  only, not implemented**, per the same "実装しない" rule as Phase 31 —
  now with a concrete, evidence-based comparison rather than an
  abstract conclusion.
- Verified: `git status`/`git diff` empty throughout this phase; no
  files touched.

## Phase 33 (2026-08-30): ARCHITECTURE DECISION — separate-machine Guardian (Option D)

A pure architecture decision, explicitly scoped as "DESIGN DECISION
ONLY" — no code, no new authentication implementation, no network
config change. Compares four placement options for a future Guardian
and commits to one for later phases to build toward.

- **Options compared** (A/B/C/D, per DuCoPA's stated test: does the
  option survive "WAIOが侵害された場合でも、Guardian側の権限が自動的に
  奪われない"?):
  - **A — same user (today's actual state)**: fails outright; WAIO *is*
    the recovery authority, per Phase 30/31's findings.
  - **B — separate OS user, same machine**: raises the bar (requires
    privilege escalation, not just "same process"), but does not fully
    satisfy the test — `masa` (WAIO's operator) is in the `admin` group
    on this machine, so `sudo` can reach a same-machine "Guardian"
    account's files regardless of ownership. Rejected as insufficient,
    not as unsafe.
  - **C — separate process alone (already true today for Takomachi)**:
    rejected — a process boundary without an accompanying user or
    machine boundary gives no real guarantee when both processes run as
    the same OS user with the same filesystem access.
  - **D — separate machine (chosen)**: 800号機 (`192.168.1.91`,
    `workers/800.json`, already integrated as the `HOST800` registry
    entry) already exists in this architecture as the natural
    candidate. A full compromise of 750号機 (WAIO's machine) still
    requires separately compromising SSH access to 800号機 before
    Guardian-side files could be touched — the most literal match for
    DuCoPA's "External Guardian Plane" framing, achievable without new
    hardware.
- **Authentication method recommended for a future implementation**
  (not built this phase): SSH key, the same pattern already established
  for every 750↔800 interaction in this codebase
  (`rpi_worker.sh`/`host800_worker.sh`) — chosen over the other Phase
  32 candidates specifically for consistency with existing structure,
  per this phase's own instruction to prioritize that over inventing
  something new.
- **Fail-safe re-evaluated for Option D** (all six scenarios from this
  phase's own checklist land safe-by-default, consistent with the
  fail-closed philosophy already established since Phase 12/24):
  WAIO down (Guardian unaffected, independent by design); network
  partition between 750/800 (shutdown-trigger already works locally, no
  network needed; recovery becomes unavailable, not bypassed —
  unavailability is the safe failure mode); Guardian down (same:
  recovery blocked, WAIO stays shut down); Guardian auth failure
  (denied, stays locked); recovery failure mid-operation (the lock
  either fully clears or not — no partial/ambiguous state, consistent
  with `trigger_shutdown`'s already-verified idempotency, Phase 24's
  `U6`); a corrupted lock file (`is_shutdown_active()` only checks file
  *existence*, never content, so corruption cannot accidentally read as
  "not active").
- **Requirements this decision implies for a future implementation
  phase, not started here**: an SSH channel in the *reverse* direction
  from every existing one in this codebase (800→750, versus today's
  750→800-only), and a dedicated keypair for it — both are network/config
  changes requiring their own explicit authorization before any code is
  written, per this phase's own prohibition on network configuration
  changes.
- **ARCHITECTURE DECISION: D** (separate machine, reusing 800号機,
  SSH-key authentication for the future Guardian channel).
- Verified: `git status`/`git diff` empty throughout this phase; no
  files, network configuration, or authentication mechanism touched or
  implemented.
- Not implemented, deferred to a future phase requiring its own
  explicit authorization: the actual 800→750 SSH channel and Guardian
  keypair; a Guardian-side recovery primitive on 800号機; any change to
  `security/recover.sh` itself (still today's unchanged, WAIO-side-only
  implementation).

## Phase 34 (2026-08-31): Guardian Recovery Protocol v1 — specification, not implemented

Follow-on to Phase 33's ARCHITECTURE DECISION D. Before opening the
800→750 reverse SSH channel Option D requires — itself a network/config
change Phase 33 explicitly gated behind its own separate authorization —
this phase writes down exactly what that channel's protocol would be, in
enough detail that a future implementation phase can build it directly
without re-deriving the design. **No code, key, or config was written or
changed this phase; scope was explicitly limited to specification by the
user's own instruction.**

- **Guardian Recovery Request shape**: an SSH forced-command entry in a
  future `~/.ssh/authorized_keys` on 750, of the shape
  `command="/path/to/WAIO/security/recover.sh --guardian-confirm <reason>",no-port-forwarding,no-X11-forwarding,no-agent-forwarding ssh-ed25519 AAAA... guardian@800`.
  The forced command restricts the Guardian's dedicated key to *only*
  ever invoking this one recovery call — never an arbitrary remote
  shell — the same `ssh -o BatchMode=yes user@host "cmd"` pattern
  already used by `workers/host800_worker.sh`/`workers/rpi_worker.sh`,
  reused for consistency per Phase 33's own instruction to prefer
  existing structure over inventing something new.
- **`security/recover.sh` future extension shape** (additive, not
  implemented): a new `--guardian-confirm "<reason>"` invocation mode
  alongside today's `--confirm "<reason>"`, writing `audit_log(...)`
  with a distinguishable actor field (`actor=guardian` vs. today's
  implicit `actor=operator`) so the audit trail can tell which party
  cleared the shutdown. The existing `--confirm` path, and all 12 of
  `tests/security_test.sh`'s existing `recover.sh` call sites, are
  intended to stay byte-for-byte unchanged — this is meant as a second,
  parallel code path, not a replacement of Phase 12/24/25's already
  fail-closed local-recovery behavior.
- **Fail-safe re-check against Phase 33's own six-scenario checklist**,
  applied to this specific extension: Guardian unreachable → recovery
  unavailable, not bypassed (safe, matches Phase 33's network-partition
  finding); a malformed or unauthenticated Guardian request → denied,
  lock stays (SSH forced-command plus key-based auth rejects it before
  `recover.sh` ever runs); a duplicate Guardian request after the lock
  is already clear → idempotent no-op, matching `recover.sh`'s existing
  "no active shutdown — nothing to do" exit-0 path; a 750-side
  compromise → still cannot forge the Guardian's private key, since
  under Option D that key never lives on 750.
- **Explicitly out of scope this phase, deferred to a future phase
  requiring its own separate authorization** (unchanged from Phase 33,
  restated for clarity): generating the Guardian keypair; installing it
  in 750's `authorized_keys`; opening 800→750 reachability; the actual
  code change to `security/recover.sh`. None of this — no key, no
  config, no code — was implemented this phase.
- Verified 2026-08-31: `git status`/`git diff` empty before this entry
  was written; `git diff --name-only` after shows only `ARCHITECTURE.md`
  changed. All three existing regression suites re-run unaffected (pure
  documentation change, same verification pattern as Phase 30):
  `tests/orchestrate_worker_test.sh`, `tests/waio_test.sh`,
  `tests/security_test.sh`. Full `bash -n` sweep across
  `waio.sh`/`workers/*.sh`/`security/*.sh`/`jobs/*.sh`/`tests/*.sh`/
  `tests/security_fixtures/*.sh` passed (sanity; no shell file touched).

## Phase 35 (2026-08-31): Guardian Recovery Protocol v1 — partial implementation (reachability deferred)

Implements three of Phase 34's four explicitly-deferred items, per the
user's individual, per-item authorization this session: ① Guardian
keypair generation, ② installing the public key in 750's
`authorized_keys`, ④ the `security/recover.sh` code change. **③ the
800→750 reverse SSH reachability/firewall work was explicitly declined
and remains out of scope** — the key installed this phase is inert until
a future phase authorizes and confirms reachability.

- **① Guardian keypair**: a dedicated `ed25519` keypair
  (`~/.ssh/waio_guardian{,.pub}`) was generated directly on 800号機
  (`192.168.1.91`) over the existing, already-working 750→800 SSH channel
  (`workers/host800_worker.sh`'s own `ssh -o BatchMode=yes` pattern). Only
  the public key was ever fetched back to 750 — the private key was never
  written to 750's disk at any point, stronger than a generate-then-delete
  approach.
- **② `authorized_keys` installation**: appended to `~/.ssh/authorized_keys`
  on 750 (file did not exist before this phase; created with `0600`), one
  restricted forced-command entry:
  `from="192.168.1.91",no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-pty,no-user-rc,command="/Users/masa/WAIO/security/guardian_recover_wrapper.sh"`.
  These restrictions mean the key can never do anything but invoke that
  one wrapper script — no shell, no forwarding. `from=` is a defense-in-depth,
  source-IP restriction, not a substitute for ③'s still-pending real
  reachability/firewall work (SSH `from=` is spoofable at the network
  layer). **Verified risk was already zero at install time**: nothing was
  listening on port 22 on this machine before or after this phase
  (`lsof -iTCP:22 -sTCP:LISTEN` empty both times) — the installed key is
  provably inert, not merely assumed so.
- **New `security/guardian_recover_wrapper.sh`** (tracked, generic — the
  `authorized_keys` line referencing it by absolute path is the only
  deployment-specific part, same separation Phase 29 established for
  `workers/800.json`): the sole command the Guardian key's forced-command
  restriction can run. Exists specifically to avoid a command-injection
  hole: sshd re-parses an `authorized_keys` `command=` value as shell
  text, so interpolating the Guardian-supplied (attacker-influenced)
  `$SSH_ORIGINAL_COMMAND` directly into that value would let embedded
  quotes/backticks/`$()`/`;` break out and run arbitrary commands. The
  wrapper instead names only a fixed script path in `command=`, and
  inside the script `"${SSH_ORIGINAL_COMMAND}"` is a single quoted bash
  parameter expansion passed as one argument — never re-parsed as shell
  syntax.
- **④ `security/recover.sh`**: additive `--guardian-confirm "<reason>"`
  mode alongside the existing `--confirm "<reason>"`. Identical
  validation and effect; the only difference is the `audit_log` event
  type (`recovery_confirmed` vs. `recovery_confirmed_guardian`), so the
  audit trail can tell which party recovered the system. No change to
  `security/lib.sh` — `audit_log`'s existing 7-argument signature already
  carried enough via `event_type`, so no other call site anywhere in the
  codebase needed touching. All 12 of `tests/security_test.sh`'s
  pre-existing `--confirm` call sites are unchanged in behavior, exit
  code, and output text.
- **New tests** (`tests/security_test.sh`, cases G1-G4, all local
  invocation — no real SSH, consistent with ③ being out of scope): G1
  confirms `--guardian-confirm` refuses without a reason exactly like
  `--confirm` does; G2 confirms a valid `--guardian-confirm` clears the
  shutdown and the audit log records `recovery_confirmed_guardian`; G3
  confirms the wrapper correctly forwards `$SSH_ORIGINAL_COMMAND` as the
  exact reason text without any real SSH session; G4 is the
  command-injection check — invokes the wrapper with a reason containing
  literal backticks, `$()`, and `;` designed to run `touch <marker-file>`
  if mishandled, then asserts the marker file was never created (proving
  the safe-quoting design actually holds, not just in theory) while the
  literal text still reaches the audit trail.
- **Explicitly not done this phase (③, and everything reachability-dependent)**:
  no network/firewall configuration change; Remote Login/sshd was not
  enabled on 750 and its state was not touched; no verification that 800
  can actually reach 750 on port 22; no Takomachi-side code calling this
  new path. The installed key and code path exist but cannot be exercised
  end-to-end until a future phase explicitly authorizes and confirms ③.
- Verified 2026-08-31: all three regression suites re-run, only the new
  cases added: `tests/orchestrate_worker_test.sh` 77/0/0,
  `tests/waio_test.sh` 28/0, `tests/security_test.sh` 65/0/0 (53 prior +
  12 new G1-G4 assertions, 0 failed). Full `bash -n` sweep across
  `waio.sh`/`workers/*.sh`/`security/*.sh`/`jobs/*.sh`/`tests/*.sh`/
  `tests/security_fixtures/*.sh` passed, including the new wrapper
  script. `git diff --check`: no whitespace errors.

## Phase 36 (2026-08-31): Guardian Recovery Protocol v1 — item ③ closed, live end-to-end verification

Closes Phase 34's item ③ (800→750 reverse SSH reachability), the one
item Phase 35 explicitly declined. No `security/`, `workers/`, or
`tests/` code changed this phase — this is deployment plus live
verification of what Phase 35 already built.

- **750-side deployment (done by the user, outside this session, before
  this phase started)**: macOS Remote Login enabled on 750, and a new
  `/etc/ssh/sshd_config.d/50-waio-guardian.conf` drop-in:
  ```
  PermitRootLogin no
  PasswordAuthentication no
  KbdInteractiveAuthentication no
  PubkeyAuthentication no

  Match Address 192.168.1.91
      PubkeyAuthentication yes
  ```
  This denies pubkey (and all other) authentication globally by default
  and re-enables `PubkeyAuthentication` only for connections whose
  source address is 800号機's (`192.168.1.91`) — a second, sshd-level
  restriction independent of the `from="192.168.1.91"` already present
  in the Guardian's `authorized_keys` forced-command entry (Phase 35).
  Confirmed live: `sshd` listening on port 22 on 750 (previously
  provably not listening, per Phase 35); `masa`'s own (non-Guardian) key
  still authenticates normally, since `Match Address` only narrows which
  addresses get pubkey auth at all — it does not restrict *which* key
  works from an allowed address, so `authorized_keys`'s own
  per-key restrictions remain the operative control for the Guardian key
  specifically.
- **800→750 TCP reachability, confirmed real**: from 750, SSHed into
  800号機 over the existing (Phase 4) 750→800 channel, then from inside
  that session ran a raw TCP probe from 800号機 to 750's LAN address
  (`192.168.1.116:22`, the `en0`/default-route interface — 750 also
  holds `192.168.1.193` on a second interface, `en1`) — connection
  succeeded. This is the first time this codebase has verified
  connectivity in the 800→750 direction; every prior channel
  (`workers/host800_worker.sh`, `jobs/`) is 750→800-only.
- **Guardian forced-command live verification (positive)**: still from
  inside that 800号機 session, used the Guardian private key
  (`~/.ssh/waio_guardian`, present only on 800号機 per Phase 35) to SSH
  into 750 with a real reason string as the SSH command. A real test
  shutdown was armed first (`trigger_shutdown`, not a fixture — the
  actual `security/state/SHUTDOWN.lock` mechanism) so the recovery path
  had something real to clear. Result: the forced-command routed to
  `security/guardian_recover_wrapper.sh` → `recover.sh --guardian-confirm`
  exactly as designed, the lock was removed, and
  `logs/security-audit.jsonl` recorded a `recovery_confirmed_guardian`
  event carrying the exact reason text sent over the real SSH session —
  end-to-end proof of Phase 34/35's design working over an actual
  network hop, not just G1-G4's local-invocation coverage.
- **Negative test 1 — command injection over real SSH**: armed another
  real test shutdown, then from 800号機 sent a reason string via the
  Guardian key containing backticks, `$()`, and `;` designed to `touch`
  a marker file on **750** if the injection succeeded. Result: the
  marker file was never created on 750, the literal text was recorded
  verbatim in the audit log, and the shutdown still cleared normally —
  confirms G4's local-only injection-safety assertion also holds when
  the reason text arrives over a real SSH session
  (`SSH_ORIGINAL_COMMAND` from an actual remote client), not only when
  set directly as a shell variable in a test harness.
- **Negative test 2 — port-forwarding restriction**: from 800号機,
  attempted `ssh -i ~/.ssh/waio_guardian -N -L 12345:127.0.0.1:22
  masa@<750>` (background, no forced command bypassed). The local
  listener opened (expected — that's client-side plumbing), but the
  moment a connection was pushed through it, sshd on 750 logged
  `channel 2: open failed: administratively prohibited: open failed`
  and refused the tunnel — confirming the `no-port-forwarding` flag in
  the Guardian's `authorized_keys` entry is actually enforced live, not
  merely declared. `no-pty`/`no-agent-forwarding`/`no-X11-forwarding`
  were not separately live-tested (same `authorized_keys`-flag
  enforcement mechanism the port-forwarding test just exercised; not
  re-verified individually this phase).
- **Still not tested / out of scope**: rejection from a source address
  other than 800号機's (the `from="192.168.1.91"` restriction) — no
  second host was available on this LAN to originate such an attempt
  from; `from=` remains a defense-in-depth, spoofable-at-the-network-layer
  control as already noted in Phase 35, unchanged by this phase. No
  Takomachi-side code calls this path yet — that remains a future phase.
- State after this phase: no active shutdown, Guardian private key
  still lives only on 800号機, `security/recover.sh` and
  `security/guardian_recover_wrapper.sh` unchanged from Phase 35.
  Regression suites re-run with zero code changes, same as Phase 35:
  `tests/security_test.sh` 65/0/0, `tests/waio_test.sh` 28/0,
  `tests/orchestrate_worker_test.sh` 77/0/0.

## Phase 37 (2026-08-31): Guardian-side recovery trigger primitive on 800号機

Implements the future-work item named explicitly in Phase 33
("a Guardian-side recovery primitive on 800号機, not started here") and
Phase 36 ("no Takomachi-side code calls this path yet"): replaces the
hand-typed `ssh -i ~/.ssh/waio_guardian ...` incantation Phase 36
verified end-to-end with a real, tracked, reusable script. **Does not
touch any Phase 35/36-verified path**: `security/recover.sh`,
`security/guardian_recover_wrapper.sh`, 750's `authorized_keys` entry,
and `/etc/ssh/sshd_config.d/50-waio-guardian.conf` are all unchanged —
confirmed by checksum before and after this phase for the two tracked
files, and by direct inspection for the two 750-local files.

- **New `security/guardian_recover_trigger.sh`** (tracked, generic —
  same separation Phase 35 established for
  `guardian_recover_wrapper.sh`): carries no deployment-specific
  host/user of its own. 800号機 has no checkout of this repo, so the
  file is meant to be copied there standalone and invoked with the real
  target supplied via `GUARDIAN_TARGET_HOST`/`GUARDIAN_TARGET_USER`
  environment variables (both required; the script refuses before
  attempting anything if either is missing). Fail-closed by design: no
  retry, no fallback, the `ssh` exit code is propagated as-is and an
  additional `[GUARDIAN TRIGGER] ERROR: recovery request failed`
  message is printed on failure so nothing is swallowed silently — a
  failure here looks exactly like a failure would to an operator typing
  the raw `ssh` command by hand. `GUARDIAN_KEY_PATH` (default
  `~/.ssh/waio_guardian`) and `GUARDIAN_CONNECT_TIMEOUT` (default `10`)
  are also overridable, primarily so tests can point the script at an
  intentionally-unreachable target without touching the real deployed
  key. Passes the reason to `ssh` as a single quoted argument (never
  through `eval`/`bash -c`), so it introduces no new local
  command-injection surface; the already-proven-safe handling of that
  text once it reaches 750 (Phase 35 G4, Phase 36 negative test 1) is
  entirely unaffected since the server-side path is untouched.
- **New tests** (`tests/security_test.sh`, cases H1-H3, no real SSH to
  750 — this is the client-side half meant to run on 800号機 itself):
  H1 confirms the script refuses before doing anything if
  `GUARDIAN_TARGET_HOST`/`GUARDIAN_TARGET_USER` aren't set; H2 confirms
  it refuses without a reason even with a target configured; H3 points
  it at `192.0.2.1` (RFC 5737 TEST-NET-1, reserved/non-routable) with a
  deliberately-invalid key path (`/dev/null`) and a short connect
  timeout, and asserts the resulting `ssh` failure surfaces as a
  non-zero exit code with the expected error text — proving the
  failure path isn't masked, without depending on real network
  reachability or CI's outbound network policy.
- **Not done this phase**: no change to the 800号機 deployment itself
  (copying this script there and wiring `GUARDIAN_TARGET_HOST`/
  `GUARDIAN_TARGET_USER` to the real values is a manual, local-network
  step outside what a PR to this repo can do or verify); no live
  end-to-end re-verification via this new script (Phase 36 already
  proved the underlying `ssh` invocation this script wraps works
  end-to-end; re-running that exact proof through the new wrapper is a
  manual follow-up, not a repo change); Takomachi-side integration
  remains a separate, future, cross-repo phase.
- Verified 2026-08-31: `tests/security_test.sh` 71/0/0 (65 prior + 6 new
  H1-H3 assertions, 0 failed), `tests/waio_test.sh` 28/0,
  `tests/orchestrate_worker_test.sh` 77/0/0. Full `bash -n` sweep across
  `waio.sh`/`workers/*.sh`/`security/*.sh`/`jobs/*.sh`/`tests/*.sh`/
  `tests/security_fixtures/*.sh` passed, including the new script.
  `git diff --check`: no whitespace errors. No active shutdown lock
  left behind after the test suite run.

## Phase 38 (2026-08-31): guardian_recover_trigger.sh deployed to 800号機, live end-to-end re-verification

Closes Phase 37's own "not done this phase" item: deploys the tracked
script to 800号機 and re-proves Phase 36's already-verified `ssh`
invocation now works through it. **No code in this repo changed** — a
deployment + verification phase, same shape as Phase 36. **No Phase
35/36-verified path touched**: `security/recover.sh` and
`security/guardian_recover_wrapper.sh` checksum-confirmed identical
before and after; 750's `authorized_keys` and
`/etc/ssh/sshd_config.d/50-waio-guardian.conf` confirmed byte-identical
by direct inspection before and after. No persistent configuration was
added on either machine.

- **Deployment**: `security/guardian_recover_trigger.sh` copied to
  800号機 (`~/guardian_recover_trigger.sh`) over the existing (Phase 4)
  750→800 `scp` channel — the target path was free (no collision) —
  then `chmod +x`. SHA-256 confirmed identical between the 750
  (tracked) copy and the deployed copy: no corruption or tampering in
  transit. `GUARDIAN_TARGET_HOST`/`GUARDIAN_TARGET_USER` were
  deliberately **not** persisted anywhere on 800号機 (no shell-profile
  edit) — passed inline at invocation time instead, to keep the
  deployment's footprint to exactly one file and keep rollback trivial
  (`ssh masa@192.168.1.91 'rm -f ~/guardian_recover_trigger.sh'`, one
  command, nothing else to undo).
- **Live positive re-verification**: armed a real test shutdown on 750
  (`trigger_shutdown`, the actual mechanism, not a fixture), then from
  800号機 ran the deployed script with
  `GUARDIAN_TARGET_HOST=192.168.1.116 GUARDIAN_TARGET_USER=masa`. Result:
  exit 0, the shutdown cleared, and `logs/security-audit.jsonl` recorded
  a `recovery_confirmed_guardian` event with the exact reason text —
  identical outcome to Phase 36's hand-typed `ssh` invocation, now
  reproduced through the tracked wrapper script instead.
- **Live negative re-check**: ran the deployed script on 800号機 with
  `GUARDIAN_TARGET_HOST`/`GUARDIAN_TARGET_USER` unset — refused
  immediately (exit 1, the expected error text), confirming H1's
  local-only assertion also holds for the actual deployed copy, not
  just the tracked source file tested in CI. The injection- and
  port-forwarding-safety properties proven in Phase 36 were not
  re-exercised here, since they are properties of the untouched
  server-side path (`guardian_recover_wrapper.sh` /
  `authorized_keys`), not of this client-side script.
- Verified 2026-08-31: `tests/security_test.sh` 71/0/0,
  `tests/waio_test.sh` 28/0, `tests/orchestrate_worker_test.sh` 77/0/0
  (all unchanged, re-run as a regression check after the live
  verification above). No active shutdown lock left behind. `git
  status` on 750 clean throughout — this phase's only artifact is this
  `ARCHITECTURE.md` entry.
- **Still not done**: `GUARDIAN_TARGET_HOST`/`GUARDIAN_TARGET_USER` are
  not persisted anywhere, so today's invocation on 800号機 must still
  supply them inline each time — a future phase could decide whether
  to persist them (and how) if manual inline invocation proves too
  friction-heavy in practice; Takomachi-side integration remains a
  separate, future, cross-repo phase.

## Phase 39 (2026-08-31): Takomachi integration re-examined — investigation only, not implemented

Follow-on to the "Takomachi-side integration" item named as future work
in Phase 36 and Phase 38. Before writing any code, this phase asks
whether Takomachi, as it actually exists and runs today, can even play
that role without contradicting Phase 33's own separation decision.
**No code was written or changed in either repository (WAIO or
Takomachi).**

- **Corrected assumption**: Takomachi is not a Cloudflare-edge service —
  it is a local-first Node.js application (`Projects/Takomachi`,
  `dist/main.js`, Agent Manager / Task Queue / Plugin System / API
  Gateway / Web Dashboard, per its own `README.md`). Confirmed **live
  and running** on this machine during this investigation (`ps aux`
  showed `node dist/main.js`, listening on `localhost:3000`). The
  `.wrangler`/`dashboard` directories in that repo are a separate,
  small public-facing fx-briefing Worker, unrelated to Takomachi's core
  orchestration engine.
- **Central finding, re-confirmed and now evidenced live**: Takomachi
  runs as the same local user (`masa`) on the same machine (750) as
  WAIO — exactly the shared-trust-boundary condition Phase 30/31 first
  identified, now directly observed rather than inferred. A `grep -ri
  guardian` across Takomachi's entire tracked source and docs returned
  zero matches; its only WAIO-awareness is the pre-existing Phase 2 LLM
  worker integration (`waio-research`/`waio-analysis`/`waio-ai`
  agents), unrelated to shutdown/recovery. Its own `shutdown` mentions
  (`src/main.ts`'s `SIGINT`/`SIGTERM` handling) are about Takomachi's
  own graceful process shutdown, not WAIO's Emergency Shutdown layer.
- **Why this blocks a naive implementation**: if Takomachi (same user,
  same machine as WAIO) were wired to call
  `security/guardian_recover_trigger.sh` or `recover.sh
  --guardian-confirm` directly, that call would carry no more real
  authority than WAIO's own operator already has by running
  `recover.sh --confirm` locally — the exact non-separation Phase 33's
  ARCHITECTURE DECISION (Option D, a separate machine) was chosen to
  avoid. Implementing "Takomachi calls this path" without addressing
  that would look like progress while adding no real DuCoPA separation.
- **Also checked**: Takomachi already has real, empirically-verified
  process/network sandboxing machinery of its own (`security/
  plugin-sandboxing.md` — `sandbox-exec` on macOS, network namespaces
  on Linux, an AppContainer helper on Windows, all covering plugin
  subprocesses) and a credential store gated by `TAKOMACHI_MASTER_KEY`
  (`security/credential-handling.md`). Neither is wired to anything
  Guardian/WAIO-shutdown-related today; both are evidence that *if* a
  future phase decided Takomachi should hold Guardian-relevant secrets
  or run sandboxed logic, established patterns already exist in that
  repo to build on — this phase only notes that, it does not use it.
- **Options noted for a future phase to compare** (not decided,
  matching Phase 32/33's own comparison-then-decide structure): (a)
  leave Takomachi on 750 and restrict any future integration to
  producing a human-reviewed notification, never an automated call —
  no authority gain over today, lowest risk; (b) relocate or mirror the
  specific monitoring/decision logic that would trigger recovery onto
  800号機 itself (the machine Phase 33 already committed to as the
  separate Guardian authority), polling WAIO's audit log/shutdown state
  over the existing read-only 750→800 direction rather than Takomachi
  pushing a decision from the compromised-trust-boundary side; (c)
  something not yet identified. No option was selected this phase.
- **Not done this phase**: no code, configuration, or network change in
  WAIO or Takomachi; no SSH to 800号機; no change to
  `security/guardian_recover_trigger.sh`,
  `security/guardian_recover_wrapper.sh`, `security/recover.sh`,
  750's `authorized_keys`, or `sshd_config.d`. Takomachi's live process
  (pid observed via `ps`, unchanged) was not touched or restarted.
- Verified 2026-08-31: `git status`/`git diff` empty in both `WAIO` and
  `Takomachi` throughout this phase; this `ARCHITECTURE.md` entry is
  the only change anywhere.

## Phase 40-D (2026-08-31): .example template format tests (Phase 30 gap, retroactively documented here)

Closes the minor test-coverage gap Phase 30 noted but judged outside
its own scope: nothing validated that the three tracked `.example`
templates (`workers/750.json.example`, `workers/800.json.example`,
`security/egress_allowlist.conf.example`) stay in valid format over
time. The real files they template are gitignored (Phase 29), so a
fresh checkout (including every CI run) never exercises them directly.
**Test-only change, unrelated to the Guardian Recovery Protocol
(Phase 33-39)** — merged via PR #51 without its own `ARCHITECTURE.md`
entry at the time; recorded here, out of chronological order, when
that gap was noticed while writing up Phase 40-C.

- **New cases I1-I3** (`tests/security_test.sh`): I1 confirms
  `workers/750.json.example` parses as valid JSON; I2 confirms
  `workers/800.json.example` parses as valid JSON and that its
  `host`/`user` keys (the ones real code — `host800_worker.sh`,
  `jobs/*.sh` — actually reads) are present and non-empty; I3 confirms
  every non-comment/non-blank line in
  `security/egress_allowlist.conf.example` has a non-empty HOST and
  PORT, matching `egress_check()`'s own `HOST|PORT|LABEL` parsing
  contract in `security/lib.sh`.
- Sanity-checked I1 actually fails, not just passes trivially: ran it
  against a deliberately corrupted copy of the JSON file, confirmed the
  assertion failed as expected, then restored the original (`git diff`
  confirmed empty on that file afterward).
- No application/security code touched — `tests/security_test.sh` was
  the only file this sub-phase changed. No network, SSH, or
  800号機/750号機/Takomachi configuration involved.
- Verified 2026-08-31: `tests/security_test.sh` 77/0/0 (71 prior + 6 new
  I1-I3 assertions), `tests/waio_test.sh` 28/0,
  `tests/orchestrate_worker_test.sh` 77/0/0. Full `bash -n` sweep
  passed. `git diff --check`: no whitespace errors.

## Phase 40-C (2026-08-31): guardian_recover_trigger.sh optional persisted target config

Implements the second of the four ordered Phase 40 candidates (D → C →
B → A) the user chose after Phase 39: removes the need to type
`GUARDIAN_TARGET_HOST`/`GUARDIAN_TARGET_USER` inline on every
invocation on 800号機, per Phase 38's own "still not done" note.
**Does not touch any Phase 35/36-verified path**: `security/recover.sh`
and `security/guardian_recover_wrapper.sh` unchanged (checksum
confirmed); 750's `authorized_keys` and `sshd_config.d` unchanged
(confirmed by direct inspection). No deployment to 800号機 and no
network/config change performed this phase — code only, per this
phase's explicit scope.

- **`security/guardian_recover_trigger.sh` extended** (not replaced):
  if `GUARDIAN_TARGET_HOST`/`GUARDIAN_TARGET_USER` aren't already set
  in the environment, the script now optionally falls back to a local
  config file (default `$HOME/.guardian_recover_trigger.conf`,
  override via the new `GUARDIAN_CONFIG_PATH`) — deliberately a path
  outside this repo's tree by default, so it can never be accidentally
  tracked or committed. The file is read line-by-line as plain
  `KEY=VALUE` pairs (`#`-comments and blank lines skipped, any key
  other than the two recognized ones silently ignored) and is **never
  `source`d or `eval`d** — a corrupted or tampered file can only ever
  supply a host/user string, never executable shell, the same
  no-shell-reinterpretation discipline `guardian_recover_wrapper.sh`
  established in Phase 35. An env var that is already set always wins
  (implemented as bash's own `${VAR:=value}` fallback assignment,
  applied only when the variable is unset or empty) — the file is
  strictly a fallback, never an override. If neither the env var nor
  the file supplies a value, behavior is byte-for-byte unchanged from
  before this phase: refuse before attempting anything.
- **New `security/guardian_recover_trigger.conf.example`** (tracked,
  documentation only — not deployed anywhere by this phase): the same
  `.example`-template convention Phase 29 established, showing the
  two-key format. Explicitly not exercised by Phase 40-D's I1-I3 format
  tests (those predate this file); left as a known, minor, honestly-
  noted gap rather than expanding this phase's scope to cover it.
- **New tests** (`tests/security_test.sh`, cases J1-J3, no real SSH to
  750, `GUARDIAN_CONFIG_PATH` always pointed at a throwaway `mktemp`
  file so the real `$HOME/.guardian_recover_trigger.conf`, if any ever
  exists on this machine, is never read or touched): J1 confirms the
  no-file/no-env-var refusal is unchanged (regression, not new
  behavior); J2 confirms a config file's values are picked up and used
  when env vars are absent (verified by checking the exact
  `target: fromconfig@192.0.2.2` string in the failure output, not just
  a generic non-zero exit); J3 confirms an explicitly-set env var wins
  over a simultaneously-present config file with different values, and
  that the file's values never leak through.
- **Explicitly honored constraints this phase**: no secret is ever
  stored in the config file (only host/user, which this codebase has
  never treated as secret — the same values already visible in plain
  text throughout this public repo's own `ARCHITECTURE.md` history);
  no change to 750's `authorized_keys`/`sshd_config.d`; no deployment
  to or SSH session with 800号機; existing env-var-only invocation
  keeps working exactly as before (J1/J3 both cover this).
- Verified 2026-08-31: `tests/security_test.sh` 83/0/0 (77 prior + 6 new
  J1-J3 assertions, 0 failed), `tests/waio_test.sh` 28/0,
  `tests/orchestrate_worker_test.sh` 77/0/0. Full `bash -n` sweep across
  `waio.sh`/`workers/*.sh`/`security/*.sh`/`jobs/*.sh`/`tests/*.sh`/
  `tests/security_fixtures/*.sh` passed, including the modified
  trigger script. `git diff --check`: no whitespace errors. No active
  shutdown lock left behind. `$HOME/.guardian_recover_trigger.conf`
  confirmed absent on this machine both before and after this phase —
  the new fallback path was exercised only via `GUARDIAN_CONFIG_PATH`
  overrides in tests, never against a real file.
- **Not done this phase**: no deployment of the updated
  `guardian_recover_trigger.sh` or the new `.example` file to 800号機
  (a manual, local-network follow-up, same as Phase 38 was for Phase
  37); Phase 40's remaining candidates (B: human-notification-only
  Takomachi integration; A: 800号機-side monitoring/decision logic)
  remain for later phases in the user's chosen D→C→B→A order.

## Phase 40-B / B-1 (2026-08-31): local shutdown notification, decoupled from Takomachi and from trigger_shutdown()

Investigated Phase 39/40's "B" candidate (Takomachi produces a
human-reviewed notification when WAIO shuts down, no automated
recovery) before implementing it, and found its natural-seeming
mechanism doesn't actually fit:

- **Corrected assumption, found during investigation**: Takomachi's
  only generic intake surface is its Task Queue (`POST /tasks`), and
  per its own `README.md` a submitted task flows
  receipt → `AgentSelection` dispatch → a real provider (LLM) call. It
  is built for agent-executed work, not passive human notification.
  Posting a shutdown event there risks an AI agent actually attempting
  to "handle" a security incident notification as a task — the
  opposite of "human-reviewed, no automated action." Takomachi has no
  existing alerts/notifications concept separate from the Task Queue.
  A correct Takomachi-routed notification would need a small
  Takomachi-side addition (a new endpoint/concept in that live,
  separately-maintained repo) — real scope beyond what this
  low-risk-labeled candidate was meant to cover.
- **Decision (B-1, chosen)**: drop Takomachi from this candidate
  entirely and keep the notification fully local to 750 — a macOS
  local notification (`osascript`), Takomachi untouched. This still
  satisfies DuCoPA's actual concern (a human learns about a shutdown
  without WAIO or Takomachi gaining any new authority over each other)
  without misusing an interface not designed for it.

Implementation:

- **New `security/notify_shutdown.sh`** (tracked, standalone): purely
  observational — reads `security/state/SHUTDOWN.lock`'s `reason` (via
  `is_shutdown_active`/`$SHUTDOWN_LOCK`, sourcing `security/lib.sh`
  read-only) and fires a local `osascript` notification if a shutdown
  is active. **Never writes to `SHUTDOWN.lock`, never calls
  `security/recover.sh`, and is not called by `trigger_shutdown()` or
  any existing guard call site** — `security/lib.sh` is byte-for-byte
  unchanged (confirmed: `git diff --stat security/lib.sh` empty).
  Deliberately **not wired to run automatically anywhere this phase**:
  `trigger_shutdown()` is the single most-tested function in this
  codebase (83 assertions touch it directly or indirectly before this
  phase), and wiring a notification call into it would mean every
  regression-suite run fires real local notifications on every
  developer machine — a real usability cost for a "nice to have," on
  top of adding risk to the most safety-critical code path in the
  repo. Automatic invocation (a scheduled check, or a future
  `trigger_shutdown()` hook once justified) is left for a later phase
  to decide, the same staged-rollout shape Phase 37→38 used for the
  Guardian trigger script.
- **Injection safety**: the shutdown `reason` can carry
  attacker-influenced text (same class of untrusted string
  `security/guardian_recover_wrapper.sh` guards against for the
  Guardian SSH path, Phase 35). It is never interpolated into the
  AppleScript source text — the script passed to `osascript` is a
  fixed, single-quoted heredoc; `WAIO_NOTIFY_TITLE`/`WAIO_NOTIFY_MSG`
  are exported as environment variables and read at AppleScript
  runtime via `system attribute`, never re-parsed as script syntax.
  Manually verified with a real reason containing `"`, backticks, and
  `$()` — notification fired correctly, no shell/AppleScript
  side-effect (see cases below for the automated equivalent).
  `notify_shutdown.sh` always exits 0 (whether or not a notification
  was actually shown) — its own success/failure is never allowed to
  look like a WAIO-state problem.
- **New tests** (`tests/security_test.sh`, cases K1-K4, real system
  notifications never fire during the suite — K3/K4 shadow `osascript`
  with a fake executable prepended to `PATH`): K1 confirms the no-op
  path (no active shutdown, `osascript` never invoked); K2 confirms the
  genuinely-`osascript`-unavailable path exits 0 with the reason still
  surfaced in text output — this case is environment-dependent (skips
  on this machine, where `osascript` is present; runs for real in CI's
  Ubuntu runners, which have none, mirroring the existing L1/L2
  LAN-dependent skip pattern); K3 confirms the correct title/reason
  reach the fake `osascript` via environment variables and that the
  captured AppleScript source contains `system attribute
  "WAIO_NOTIFY_MSG"` (proving the reason is never embedded directly);
  K4 repeats the check with an injection-shaped reason (backticks,
  `$()`, quotes) and confirms it reaches the fake `osascript` literally
  with no command executed (marker-file check, same technique as G4).
- Verified 2026-08-31: manual end-to-end run against a real `trigger_shutdown`
  with an injection-shaped reason (a genuine local notification fired
  correctly), then `tests/security_test.sh` 93/0/1 (83 prior + 10 new
  K1-K4 assertions, K2 skipped on this machine as expected, 0 failed),
  `tests/waio_test.sh` 28/0, `tests/orchestrate_worker_test.sh` 77/0/0.
  Full `bash -n` sweep passed, including the new script. `git diff
  --check`: no whitespace errors. No active shutdown lock left behind.
  `security/lib.sh`, `security/recover.sh`,
  `security/guardian_recover_wrapper.sh` all confirmed byte-identical
  before/after (checksums for the latter two, empty diff for the
  first); 750's `authorized_keys`/`sshd_config.d` untouched; Takomachi
  repo and its live process untouched.
- **Not done this phase**: no automatic invocation of
  `notify_shutdown.sh` anywhere (manual only, for now); no Takomachi
  involvement at all (superseded by the B-1 decision above); Phase 40's
  remaining candidate (A: 800号機-side monitoring/decision logic)
  remains for a later phase.

## Phase 40-A (2026-08-31): 800号機-side monitoring/decision logic — investigated, deferred, not implemented

Last of the four Phase 40 candidates (D→C→B→A, user-chosen order).
Investigated whether a Guardian-side monitoring/decision component on
800号機 is safe and worth building now. **No code, configuration, or
network change was made in WAIO, on 750, or on 800号機.**

- **What 800号機 would need to observe**: only `security/state/SHUTDOWN.lock`'s
  existence, plus `reason`/`triggered_at` if present — not the full
  `logs/security-audit.jsonl`, which is broader than needed and whose
  event shapes may change over time.
- **Central constraint, why this can't just call the existing recovery
  path automatically**: `security/recover.sh` never validates that a
  `--guardian-confirm`/`--confirm` reason is *true*, only that it's
  non-empty — the whole design (Phase 30/31) requires a human to have
  actually investigated. Any 800号機 logic that auto-invoked
  `security/guardian_recover_trigger.sh` on detecting a shutdown would
  silently defeat that safeguard. **Conclusion: any monitoring
  component must be strictly observe-and-notify — it must never call
  the existing recovery trigger itself.**
- **Safety under 800号機 compromise**: re-examining Phase 33's own
  fail-safe checklist (WAIO down / network partition / Guardian down /
  Guardian auth failure / recovery failure mid-operation / corrupted
  lock file) found a gap that checklist never covered: **Guardian
  machine (800号機) itself compromised**. Today, an attacker who
  compromises 800号機 already has the `waio_guardian` private key and
  can clear any real shutdown without genuine investigation (`recover.sh`
  doesn't check truthfulness) — a pre-existing risk this investigation
  surfaced, not one Phase 40-A would introduce. A hypothetical
  read-only monitoring credential, if added, should be a **separate**
  key from `waio_guardian`, so compromising it alone would grant
  observation only, never recovery-clearing authority (least
  privilege, consistent with the forced-command minimalism Phase 35
  established).
- **Relationship to Phase 33's Option D separation principle**: a
  correctly-scoped (observe-only, separate-credential) monitor would
  not weaken Option D — it could arguably be the **first real
  fulfillment** of DuCoPA's "Guardian watches WAIO" principle, since
  Phase 40-B-1's local notification depends on WAIO's own
  `trigger_shutdown()`/`notify_shutdown.sh` running correctly (a
  compromised WAIO could suppress it), whereas an 800号機-initiated
  pull is independent of WAIO's cooperation.
- **Relationship to the existing 750↔800 channels**: confirmed the
  existing `waio_guardian` key has **no read capability at all** — its
  forced-command restricts it to invoking
  `security/guardian_recover_wrapper.sh` and nothing else. A monitoring
  channel cannot reuse it; it would require a **new** forced-command
  entry in 750's `authorized_keys` (ideally under a separate key). This
  is the first Phase 40 candidate that would require touching 750's
  existing SSH surface at all — D/C/B-1 all avoided that entirely.
- **Hypothetical scope if implemented** (not built): a new, narrow,
  read-only forced-command wrapper on 750 (reporting only
  shutdown-active/reason/triggered_at, not arbitrary file contents); a
  new dedicated key pair on 800号機, separate from `waio_guardian`; an
  800号機-side script that polls this read-only channel and fires its
  own local notification on detecting an active shutdown — never
  calling the recovery trigger. Rollback would be trivial (remove the
  one new `authorized_keys` line, delete the new key and scripts) since
  nothing existing would be touched.
- **DECISION: deferred, not implemented.** Weighed against implementing
  now: Phase 40-B-1 already delivers local, human-visible notification
  on 750 itself, covering the common case where an operator is present;
  Phase 40-A's marginal value (detecting a shutdown when WAIO itself
  cannot notify, e.g. total compromise or crash) is real in principle
  but not backed by any concrete incident or operational need observed
  so far; implementing it would be the first Phase 40 candidate to add
  a new SSH surface to 750, the exact machine this whole Guardian
  design protects. This matches the same judgment Phase 30-32 reached
  repeatedly: understand and document the design, but do not implement
  a new authority/credential mechanism without a concrete need driving
  it. Revisit if a real need for WAIO-independent detection surfaces
  (e.g., 750 regularly runs unattended, or a real incident where local
  notification alone proved insufficient).
- Verified 2026-08-31: `git status`/`git diff` empty in WAIO throughout
  this phase; no SSH session opened to 800号機; 750's
  `authorized_keys`/`sshd_config.d` unchanged; this `ARCHITECTURE.md`
  entry is the only change anywhere.

## Repo hosting and branch policy (2026-08-30)

- Repo: `github.com/noobdna/WAIO` (public), MIT licensed.
- `master` and `develop` both require the `shellcheck` status check (from
  `.github/workflows/lint.yml`) to pass, with `enforce_admins: true` on
  both — a direct push to either branch is rejected until that commit has
  a passing check, so changes go through a branch + PR, not a direct push.
- `develop` was branched from `master` at commit `2ca7000` (same content,
  same worker set through Phase 6); no code changed as part of creating it.

## Deliberately not integrated

- **`jobs/`** — ad-hoc SSH diagnostic runners against 800号機. Different
  task shape than a `registry.conf` worker (fixed commands, not
  request/response). **Decision: kept as a separate, standalone tool —
  will not be folded into `registry.conf`/`waio.sh`.** (Phase 3 of the
  registry migration, which would have integrated it, was explicitly
  skipped.) Note: `jobs/test-job.sh` originally hardcoded `192.168.1.193`,
  which did not match `workers/800.json`'s `192.168.1.91` — **resolved**
  in Phase 12 (`jobs/test-job.sh` now reads the target from
  `workers/800.json`, the same way `jobs/run-job.sh`/`jobs/dispatch.sh`
  already did); this note was left stale here until Phase 18 caught it
  while surveying open items.
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
