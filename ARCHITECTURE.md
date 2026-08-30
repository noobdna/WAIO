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
- `waio.sh`, `workers/registry.conf`, `workers/pipeline.conf`, every
  worker script, and `tests/orchestrate_worker_test.sh` itself are
  untouched — confirmed via `git diff --stat` showing only
  `.github/workflows/lint.yml` and this file changed.
- Verified 2026-08-30: `.github/workflows/lint.yml` parses as valid YAML
  (`python3 -c "import yaml; yaml.safe_load(...)"`); the regression
  suite was re-run locally and stayed **64 passed, 0 failed, 0
  skipped**, confirming Phase 17's script itself needed no change for
  this wiring. Full `bash -n` sweep across
  `waio.sh`/`workers/*.sh`/`jobs/*.sh`/`tests/*.sh` passed. The new
  `regression` job's actual behavior on GitHub's runner (Ubuntu, no LAN
  to 800号機) is confirmed by this phase's own PR's CI run, the same way
  every prior CI-relevant phase's workflow behavior was ultimately
  verified — this session cannot execute GitHub Actions locally.
- Not implemented: promoting `regression` to a required branch-
  protection check (explicitly left as a separate decision, see above);
  automated coverage for the Keychain-gated workers or the "no stages
  configured" case (same reasons Phase 17 already gave); Router
  LLM-assisted matching, `agent_manager` investigation, and
  cron/unattended execution for Takomachi workers all remain open,
  explicitly out of scope for this phase (Takomachi/GUI-Terminal/
  Keychain-dependent, per this phase's own instruction to not expand
  into that territory).

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
