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
  (empty request / unsupported job type) had been dry-run tested; the
  worker's own `ssh -o BatchMode=yes ...` call had not yet been
  exercised through this adapter. **Resolved in Phase 12**: real SSH
  auth to 800号機 via `host800_worker.sh` was run for real
  (`./waio.sh -w HOST800 "system check"`/`"identity check"`, both
  completed end-to-end, exit 0) and has been re-exercised many times
  since (Phase 25's `L1`, Phase 42's `L3` neighbor, and every phase
  that re-ran the regression suites) — this note was left stale here
  until Phase 47 caught it while auditing open items.

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

## Phase 41 (2026-08-31): guardian_recover_trigger.sh (Phase 40-C version) redeployed to 800号機

Closes Phase 40-C's own "not done this phase" item: deploys the
config-file-fallback version of `security/guardian_recover_trigger.sh`
to 800号機, replacing the Phase 38-era copy that had been running there
since Phase 38. **No repository code changed** — deployment plus live
re-verification only, same shape as Phase 38/Phase 40's earlier
redeployment work. Change scoped to exactly one file on 800号機; no
other file, credential, or configuration touched anywhere.

- **Pre-deployment diff, confirmed before touching anything**: 800号機's
  deployed copy was SHA-256 `15e0cb65a480fc14bcd9574d96b22a021aadba0f69
  fdeac480c35fbba7509f6a` (the Phase 38 version, no config-file
  fallback); the repository's current version (post Phase 40-C) is
  SHA-256 `4cb8f00ff7eb1273d4644f7870cdb5b2e6b8ef9035186e2016ce0eb349f0
  a4a4`. The only behavioral difference is the optional
  `GUARDIAN_CONFIG_PATH`/`$HOME/.guardian_recover_trigger.conf` fallback
  Phase 40-C added — every other code path (target-required refusal,
  reason-required refusal, the `ssh` invocation itself, error handling,
  exit-code propagation) is unchanged, and behaves identically to the
  Phase 38 version when no config file is present (as it isn't here).
- **Redeployment**: `scp`'d over the existing 750→800 channel,
  overwriting `~/guardian_recover_trigger.sh` on 800号機, `chmod +x`
  re-applied (`-rwxr-xr-x`, unchanged from before). SHA-256 confirmed
  identical between the deployed copy and the repository's tracked file
  (`4cb8f00f...` both sides) — no corruption or tampering in transit.
  **No `~/.guardian_recover_trigger.conf` was created on 800号機** —
  deliberately out of scope this phase (the change was scoped to
  exactly the one script file); the config-fallback feature remains
  present-but-unused there, identical in effect to before this phase.
- **Live positive re-verification**: armed a real test shutdown on 750
  (`trigger_shutdown`, not a fixture), then from 800号機 invoked the
  redeployed script via `GUARDIAN_TARGET_HOST`/`GUARDIAN_TARGET_USER`
  env vars (no config file involved). Result: exit 0, the shutdown
  cleared, and `logs/security-audit.jsonl` recorded a
  `recovery_confirmed_guardian` event with the exact reason text — the
  same outcome Phase 36/38 already proved, now reproduced through the
  redeployed copy.
- **Live negative re-verification**: ran the redeployed script on
  800号機 with `GUARDIAN_TARGET_HOST`/`GUARDIAN_TARGET_USER` unset —
  refused immediately (exit 1, the expected error text), no `ssh`
  attempted.
- Verified 2026-08-31: `security/recover.sh` and
  `security/guardian_recover_wrapper.sh` checksums confirmed unchanged
  before and after; 750's `authorized_keys` and
  `sshd_config.d/50-waio-guardian.conf` confirmed byte-identical by
  direct inspection; no active shutdown lock left behind; `git status`
  on this repository clean throughout — this `ARCHITECTURE.md` entry is
  the only repository change.
- **Not done this phase**: no `.guardian_recover_trigger.conf` deployed
  to 800号機 (the config-fallback feature exists there now but is not
  yet exercised with a real file); no change to `notify_shutdown.sh`'s
  automatic-invocation status (still manual only, per Phase 40-B-1);
  Phase 40-A (800号機-side monitoring/decision logic) remains deferred,
  not implemented, per its own investigation's conclusion.

## Phase 42 (2026-08-31): HEALTHCHECK worker real-dispatch test (first non-Guardian coverage gap closed)

Following a re-survey of open work against WAIO's actual stated purpose
(a registry-driven dispatcher, some workers routing through Takomachi
to an LLM agent) rather than continuing to extend the Guardian Recovery
Protocol thread (Phase 33-41, now treated as settled), this phase
closes the first concrete gap found: of the four workers that reach
Takomachi (`RESEARCH`/`ANALYSIS`/`AI`/`HEALTHCHECK`), none had ever
been dispatched for real by any test — Phase 25 explicitly documented
this as blocked by a Keychain-lookup limitation for all four, but only
`HEALTHCHECK` can be exercised at zero cost and zero state-mutation
risk (`GET /health`, not an LLM call).

- **New case `L3`** (`tests/security_test.sh`, alongside the existing
  `L1`/`L2` legitimate-traffic checks — `healthcheck_worker.sh` calls
  its own `egress_check("localhost","3000",...)` the same way
  `host800_worker.sh`/`rpi_worker.sh` do, so this fits that section's
  existing purpose): dispatches `./waio.sh -w HEALTHCHECK "status
  check"` for real, once, and classifies the result — success asserts
  exit 0 and `HEALTHCHECK WORKER] completed`; three specific,
  recognized environment-limitation error texts (Keychain retrieval
  failure, egress-allowlist denial, `GET /health` unreachable) route to
  `skip_case` instead of a hard failure; anything else is a genuine,
  unmasked failure. Independent of `L1`/`L2`'s own `LAN_AVAILABLE`
  gate — `HEALTHCHECK`'s dependency (Keychain + a live Takomachi on
  `localhost:3000`) is unrelated to LAN reachability to 800号機/the Pi.
- **Verified both branches actually work, not just in theory**: running
  the real dispatch in this session's own non-interactive execution
  context hit exactly the Keychain-retrieval limitation Phase 25
  documented (confirmed directly: `security find-generic-password ...
  -w` fails here even though the entry's mere *presence* check
  succeeds) — `L3` correctly routed to `skip_case`, not a false pass or
  a hard failure. The success branch's classification logic was
  separately verified against a synthetic success-shaped string (falls
  through to the assert path as designed, doesn't collide with any of
  the three skip-pattern matches) — a genuine success can only be
  observed by a human running this suite interactively on a machine
  with a usable Keychain entry and a live Takomachi, which this session
  is not.
- **Zero application code changed** — `workers/healthcheck_worker.sh`,
  `security/lib.sh`, and every other file untouched; `tests/security_test.sh`
  is the only file this phase modified. No change to Takomachi (repo or
  live process) or to any network/SSH configuration.
- Verified 2026-08-31: `tests/security_test.sh` local run shows `L3`
  skipped (Keychain, as expected in this session), 93 passed / 0 failed
  / 2 skipped overall; `tests/waio_test.sh` 28/0,
  `tests/orchestrate_worker_test.sh` 77/0/0 (both unchanged). Full
  `bash -n` sweep passed. `git diff --check`: no whitespace errors. No
  active shutdown lock left behind. `git status` shows only
  `tests/security_test.sh` modified.
- **Not done this phase**: `RESEARCH`/`ANALYSIS`/`AI` remain untested
  (real LLM-call cost makes them a separate decision, not bundled into
  this zero-cost change); no CI workflow change (unneeded — the
  existing `regression` job already runs `security_test.sh`, and `L3`
  is expected to skip there the same way it did in this session, for
  the same Keychain-availability reason).

## Phase 43 (2026-08-31): opt-in, cost-incurring real LLM dispatch test (RESEARCH, representative case)

Closes Phase 42's explicitly-deferred item: a real-dispatch test for
one of the three LLM-routed workers (`RESEARCH` chosen as the
representative case; `ANALYSIS`/`AI` expansion noted below, not
implemented). Unlike `HEALTHCHECK`'s `L3` (Phase 42), a real
`RESEARCH` dispatch has a genuine, non-zero API cost — this phase's
design is built around that difference at every level. **No real LLM
call was made during this phase** — every verification below used
either the safe default (opt-in unset) or synthetic output strings fed
through the same classification logic, never live output from a real
API call.

- **New `tests/llm_dispatch_test.sh`** (new file, the only one this
  phase adds) — deliberately **not** added to
  `.github/workflows/lint.yml`'s `regression` job step list, and not
  invoked by any other test file. This is a stronger guarantee than an
  in-suite skip check: CI cannot spend money on this test no matter
  what environment variables happen to be present, because CI never
  runs this file at all. (`bash -n`/shellcheck static analysis still
  covers it automatically via the workflow's existing `tests/*.sh`
  glob — zero cost, so no reason to exclude it from that.)
  `.github/workflows/lint.yml` itself was not touched.
- **Opt-in gate**: does nothing unless `WAIO_ALLOW_LLM_COST_TESTS=1` is
  explicitly set — checked first, before any Keychain/network activity
  is even attempted. Verified locally: running the file with the
  variable unset (the default) produces a single clean `SKIP`, exit 0,
  confirmed via direct execution this phase.
  `workers/research_worker.sh` and `security/lib.sh` are both
  byte-for-byte unchanged (`git diff --stat` empty for both).
- **Minimal-cost prompt reused, not invented**: `"Reply with exactly
  one word: ok"` — the exact prompt already verified end-to-end during
  the original Takomachi integration (Phase 2), chosen there for the
  same reason (smallest plausible token count in both directions).
- **Classification logic** (mirrors `L3`'s shape, with one deliberate
  addition): dispatches once when opted in, then classifies the
  output — three environment-limitation error texts (Keychain
  retrieval failure, egress-allowlist denial, Takomachi
  unreachable/timeout) route to `skip_case`, matching `L3`. **New for
  this phase**: two *different* error texts —
  `payload_size_check`/`secret_leak_check` actually tripping — are
  deliberately **not** treated as environment limitations. A DLP guard
  firing on this trivial, benign prompt/response would be a genuine
  anomaly, not a missing credential or unreachable service, so that
  path is a hard `FAIL` instead, with an explicit note that a real
  shutdown lock may now be active. On success: asserts exit 0, the
  worker's own `RESEARCH WORKER] response:` marker present, and the
  response text contains `ok` case-insensitively (lenient on exact LLM
  wording, matching `L1`'s minimalism, while still checking it looks
  like the expected minimal reply).
- **Deliberately does NOT auto-recover**: unlike every
  `trigger_shutdown`-touching case in `tests/security_test.sh`
  (G/K-series), this file never calls `security/recover.sh` itself.
  Reasoning: this test never creates a shutdown deliberately (no setup
  `trigger_shutdown` call anywhere in it), so under every expected
  outcome (opt-out, or any of the three environment-limitation skips,
  or a genuine success) no lock is ever created by this test in the
  first place — "leave no state behind" is naturally satisfied without
  any cleanup code. The one path where a lock *could* appear is the
  DLP-trip hard-failure case above, and there this test intentionally
  leaves it for a human to investigate via `security/recover.sh`
  manually — auto-clearing it would be exactly the silent
  auto-recovery of a real incident the whole Guardian/DLP design
  (Phase 30/31 onward) exists to prevent.
- **Verified this phase, all without a real API call**: `bash -n` clean;
  direct execution with `WAIO_ALLOW_LLM_COST_TESTS` unset produced the
  expected single clean skip (exit 0); the full 7-branch classification
  table (1 success shape + 4 skip-triggering error texts + 2
  hard-failure DLP-trip error texts) was separately verified against
  synthetic strings, confirming each routes to the intended branch;
  `tests/security_test.sh` 93/0/2, `tests/waio_test.sh` 28/0,
  `tests/orchestrate_worker_test.sh` 77/0/0 (all three unchanged,
  confirming zero interference from the new file); full `bash -n` sweep
  across every script including the new file passed; `git diff --check`:
  no whitespace errors; no active shutdown lock at any point; `git
  status` shows only the new, untracked `tests/llm_dispatch_test.sh`.
- **Not done this phase, deliberately**: no real LLM/API call was made
  — that requires `WAIO_ALLOW_LLM_COST_TESTS=1` plus an interactive
  Keychain-capable session neither CI nor this session can provide, and
  in any case requires the user's own separate, explicit go-ahead before
  ever being exercised for real; `ANALYSIS`/`AI` were not added (see
  expansion note next); `.github/workflows/lint.yml` untouched.

**Expansion to `ANALYSIS`/`AI` (not implemented, recorded for a future
phase)**: identical pattern, added as `M2`/`M3` in the same file. Only
the dispatch target (`-w ANALYSIS`/`-w AI`) and the worker-name string
matched in each error-classification branch (`ANALYSIS WORKER`/`AI
WORKER` in place of `RESEARCH WORKER`) would differ — the opt-in gate,
minimal prompt, skip/fail classification shape, and no-auto-recovery
rule all carry over unchanged. Whether `WAIO_ALLOW_LLM_COST_TESTS`
should gate all three uniformly or be split per-worker
(`..._RESEARCH`/`..._ANALYSIS`/`..._AI`) for finer-grained cost control
is an open question for whoever implements that expansion, not decided
here.

## Phase 44 (2026-08-31): real LLM dispatch attempt — SKIP, Keychain limitation, no spend, no state change

Attempted the live verification Phase 43 flagged as needing the user's
own separate, explicit go-ahead: with that explicit approval given,
`WAIO_ALLOW_LLM_COST_TESTS=1 ./tests/llm_dispatch_test.sh` was actually
run for the first time. **No code, configuration, or network change
was made anywhere in this repository, on 750, on 800号機, or in
Takomachi; the Guardian/recovery/shutdown paths (Phase 33-41) were not
touched.**

- **Result: `M1` correctly routed to `SKIP`** — `TAKOMACHI_API_KEY`
  Keychain retrieval failed in this session's own non-interactive
  execution context, the exact constraint already documented in
  "Takomachi integration Phase 2" (2026-08-30: "retrieval only
  succeeded from an interactive GUI Terminal session... a
  non-interactive/sandboxed shell... failed") and re-confirmed
  empirically in Phase 42 for `HEALTHCHECK`. **No real API call was
  made, no cost was incurred**, exit 0, `0 passed, 0 failed, 1
  skipped`.
- **Central finding**: genuine live verification of `RESEARCH`'s real
  LLM dispatch **cannot be performed from within this session** — it
  requires the user's own interactive terminal (not a Claude Code
  session), where Keychain access actually succeeds. This is a
  structural, environment-level constraint, not a bug in
  `tests/llm_dispatch_test.sh` or in `workers/research_worker.sh`; both
  behaved exactly as designed (Phase 43's classification logic routed
  this specific, known error text to a clean skip, not a false pass or
  a masked failure).
- Verified 2026-08-31: `security/state/SHUTDOWN.lock` absent both
  before and after the attempt; `git status` clean throughout — this
  `ARCHITECTURE.md` entry is the only change.
- **Phase 44 is considered complete with this finding**, not with a
  successful real dispatch. A future phase, run by the user directly in
  their own interactive terminal (optionally with this session narrating
  or reviewing results after the fact), would be needed to actually
  observe `M1` pass against a real API response.

## Phase 45 (2026-08-31): ANALYSIS/AI dispatch tests (M2/M3), same pattern as Phase 43's M1

Implements the expansion Phase 43 explicitly recorded as a future-phase
note: `M2` (`ANALYSIS`) and `M3` (`AI`) added to `tests/llm_dispatch_test.sh`,
identical pattern to `M1` (`RESEARCH`) per-worker. **No real LLM/API
call was made this phase** — every verification used either the safe
default (opt-in unset) or synthetic output strings, same discipline as
Phase 43. `security/lib.sh`, `security/recover.sh`,
`security/guardian_recover_wrapper.sh`,
`security/guardian_recover_trigger.sh`, and
`.github/workflows/lint.yml` are all confirmed unchanged
(`git diff --stat` empty for each) — Guardian/recovery/shutdown paths
untouched, as instructed.

- **`workers/analysis_worker.sh` and `workers/ai_worker.sh` confirmed
  byte-for-byte structurally identical to `research_worker.sh`** (`diff`
  run before implementing) — only the log tag (`[ANALYSIS WORKER]`/
  `[AI WORKER]`), `AGENT_ID`, and the `egress_check`/`payload_size_check`/
  `secret_leak_check` worker-name argument differ. The five
  environment-limitation/DLP-trip error-text patterns `M1`'s `case`
  statement already matched on are worker-name-agnostic (none contain
  "RESEARCH"), so `M2`/`M3` reuse the exact same match patterns; only
  the dispatch target (`-w ANALYSIS`/`-w AI`) and the success-path
  `assert_contains` target (`ANALYSIS WORKER] response:`/`AI WORKER]
  response:`) needed to change.
- **Shared opt-in gate, matching Phase 43's own open question**: kept
  `WAIO_ALLOW_LLM_COST_TESTS` gating all three uniformly rather than
  splitting per-worker — simplest option, no user request for
  finer-grained per-worker cost control this phase. With the opt-in
  unset (the default), all three (`M1`/`M2`/`M3`) now emit their own
  `skip_case` (three distinct entries, matching the existing `L1`/`L2`
  precedent of one explicit skip per case even under a shared gate),
  rather than only `M1` skipping as before this phase.
- **`M1` (Phase 43's own test) unchanged in behavior**: its `case`
  statement, assertions, and error-classification logic were not
  touched; only the shared file header comment and the section's `echo`
  banner text were updated to mention all three workers, plus two new
  sibling `skip_case` lines for `M2`/`M3` alongside `M1`'s existing
  opt-out skip line. Re-run confirmed `M1` still skips with the exact
  same message as before this phase.
- **Same no-auto-recovery discipline as `M1`**: for both `M2` and `M3`,
  a `payload_size_check`/`secret_leak_check` trip on the trivial prompt
  is classified as a hard `FAIL`, never auto-cleared via
  `security/recover.sh` — identical reasoning to `M1` (Phase 43).
- Verified 2026-08-31: `bash -n` clean; direct execution with
  `WAIO_ALLOW_LLM_COST_TESTS` unset produced three clean skips (`M1`/
  `M2`/`M3`), exit 0; each of `M2`/`M3`'s five classification branches
  (Keychain, egress, Takomachi-unreachable, two DLP-trip variants) plus
  the success shape were separately verified against synthetic output
  strings, all routing to the intended branch;
  `tests/security_test.sh` 93/0/2, `tests/waio_test.sh` 28/0,
  `tests/orchestrate_worker_test.sh` 77/0/0 (all three unchanged); full
  `bash -n` sweep passed; `git diff --check`: no whitespace errors; no
  active shutdown lock at any point; `git status` shows only
  `tests/llm_dispatch_test.sh` modified.
- **Not done this phase**: no real LLM/API call for any of the three
  workers; per-worker opt-in gating remains an open option for a future
  phase if finer-grained cost control is ever wanted.

## Phase 46 (2026-08-31): `regression` promoted to a required status check (`develop`/`master`)

Closes the gap left open when the `regression` job was first added
(2026-08-30, see "Repo hosting and branch policy" below): back then it
ran and reported on every PR without blocking merges, deliberately —
`enforce_admins: true` was already set, and GitHub's own web UI is the
only reliable way to edit branch protection with the credentials
available in this environment. **No repository code or workflow file
changed** — GitHub-side branch protection settings only, done by the
user directly (`gh` CLI/API write access to this endpoint was
attempted first and failed, see below); this entry records that
already-completed change.

- **Attempted first via `gh api`, found unusable**: `PUT
  .../branches/{branch}/protection/required_status_checks` returned
  `404` three times in a row (both a form-encoded and a JSON-body
  attempt, with and without explicit API-version headers), despite the
  same token successfully reading full protection details (including
  `enforce_admins`) and `gh api repos/noobdna/WAIO -q .permissions`
  reporting `admin: true`. A broader diagnostic (`PUT
  .../protection`, replacing the whole protection object at once) was
  blocked by this session's own safety classifier before it could run
  — appropriately, since it was a larger-blast-radius operation than
  the task needed. Conclusion: the CLI's OAuth token can read but not
  write GitHub branch-protection endpoints in this environment; no
  further workaround was attempted.
- **Completed instead via GitHub's web UI**, by the user directly:
  Settings → Branches → edit rule → `Require status checks to pass
  before merging` → added `regression` alongside the existing
  `shellcheck`, for both `develop` and `master`. (One earlier attempt
  hit a `404` on the Settings page itself — diagnosed as the browser
  session not being logged into an account with admin rights on this
  repo, not a broken URL; resolved by confirming the correct
  account.)
- **Verified via `gh api` (read-only, works fine) after the change**:
  both `develop` and `master`'s `required_status_checks.contexts` now
  list `["shellcheck", "regression"]`; `strict: true` unchanged on
  both; `enforce_admins`/`allow_force_pushes`/`allow_deletions`
  confirmed unchanged (`true`/`false`/`false` on both, same as before)
  — only the one intended field changed, no incidental side effects
  from the earlier failed write attempts.
- **Impact assessed before the change**: both PRs open at the time
  (#54, #55) already had passing `regression` checks, so promoting it
  to required did not newly block anything already in flight.
- Verified 2026-08-31: `git status` clean throughout; `security/recover.sh`
  and `security/guardian_recover_wrapper.sh` checksums unchanged; no
  diff in `security/guardian_recover_trigger.sh`,
  `security/notify_shutdown.sh`, `security/lib.sh`, or
  `.github/workflows/lint.yml`; no active shutdown lock — Guardian/
  recovery/shutdown paths untouched throughout, as instructed.
- **Process note, caught later**: this phase's own PR (#60) was created
  and CI-verified but never actually merged — the session moved on to
  the next phase without merging it, so `develop` did not actually carry
  this entry for a while (a different, later PR merged cleanly on top
  of the same base, masking the gap since it touched a different part
  of the file). Caught and fixed while starting Phase 48: PR #60's
  branch was updated onto current `develop` and merged before Phase 48
  began, so this entry is exactly where it always should have been.

## Red Team Phase 2 (2026-08-31): Guardian channel real-SSH verification (N1-N4)

Automates the subset of Phase "Red Team Phase 2 investigation"'s three
candidates that could be verified safely: real Guardian SSH auth,
forced-command containment, and two of the `authorized_keys`
restriction flags (`no-port-forwarding`, `no-pty`). Explicitly out of
scope, per the user's own instruction: `no-agent-forwarding`/
`no-X11-forwarding` (no reliable automatable failure signal), any
`from="192.168.1.91"` source-IP-restriction test (would require either
a second physical host or a temporary `authorized_keys` change, neither
authorized this round), and any test of the real Guardian private
key's spoofing resistance specifically. **The existing production
`waio_guardian` key and 750's `authorized_keys` entry are exercised
exactly as Phase 36/38/41 already did manually — never modified.**

- **New cases `N1`-`N4`** (`tests/security_test.sh`, gated on the same
  `LAN_AVAILABLE` variable `L1`/`L2` already compute — LAN-dependent,
  skips cleanly in CI and anywhere without reachability to 800号機,
  exactly like `L1`/`L2`):
  - `N1`: arms a real test shutdown (`trigger_shutdown`), then from
    800号機 invokes the deployed `guardian_recover_trigger.sh` for
    real against 750 — asserts exit 0, shutdown cleared, and the audit
    log records `recovery_confirmed_guardian`. Automates what Phase
    36/38/41 each did by hand.
  - `N2`: same real-SSH path with an injection-shaped reason
    (backticks/`$()`/`;`) designed to `touch` a marker file on 750 if
    mishandled — asserts the marker is never created and the literal
    text reaches the audit log. Automates Phase 36's negative test 1
    over the exact same real channel.
  - `N3`: a real `-N -L` port-forward attempt over the Guardian key,
    with the tunnel actually used once (`nc` through the local
    listener) to trigger sshd's channel-open rejection — asserts
    `administratively prohibited` appears. Automates Phase 36's
    negative test 2.
  - `N4`: a real `-tt` PTY request over the Guardian key — asserts
    `PTY allocation request failed` appears and the connection exits
    255 (aborts entirely in `BatchMode=yes`, confirmed by manual
    observation before writing the assertion: the wrapper never even
    runs, no shutdown state changes as a result). Not previously
    verified in any phase; `no-pty` had been declared but never
    individually exercised until now.
- **One bug found and fixed during implementation, before any PR**:
  the first `N3` draft checked the local SSH log without ever pushing
  a connection through the forwarded port — `administratively
  prohibited` is only logged once sshd actually attempts to open the
  forwarding channel, not merely when the local listener opens (client-side
  plumbing only). Caught immediately by a real test run (`FAIL`), fixed
  by adding the same `nc` probe step Phase 36's manual procedure
  already used, re-verified passing.
- **Real Keychain/Guardian-authentication observation made before
  writing `N4`**: manually ran the `-tt` probe once first to capture
  the actual OpenSSH behavior (`PTY allocation request failed on
  channel 0`, exit 255, no wrapper execution, no audit log entry) —
  the assertion was written to match empirically observed output, not
  assumed wording.
- Verified 2026-08-31: `tests/security_test.sh` 104/0/2 (93 prior + 11
  new `N1`-`N4` assertions, `K2`/`L3`'s existing two skips unchanged, 0
  failed); `tests/waio_test.sh` 28/0, `tests/orchestrate_worker_test.sh`
  77/0/0 (both unchanged). Full `bash -n` sweep passed. `git diff
  --check`: no whitespace errors. No active shutdown lock at any
  point. No leftover temp files on 750 or 800号機
  (`/tmp/redteam_phase2_*` confirmed absent on 800号機 after the run).
  `security/recover.sh`/`guardian_recover_wrapper.sh` checksums and
  750's `authorized_keys` content confirmed byte-identical before and
  after — the production Guardian key/entry was exercised, never
  modified.
- **Not done this phase**: `no-agent-forwarding`/`no-X11-forwarding`
  automated verification (no reliable failure signal identified);
  `from="192.168.1.91"` source-IP-restriction testing (would need a
  second host or a temporary `authorized_keys` addition, out of scope
  this round); real Guardian private key spoofing-resistance testing
  (not possible without violating the key's single-location design).

## Red Team Phase 3 (2026-08-31): no-agent-forwarding / no-X11-forwarding / `from=` — investigated, retroactively documented here

Follow-on to Red Team Phase 2's "not done" list. Investigates whether
the three remaining `authorized_keys` restrictions can be dynamically
proven, using only safe, non-destructive, read-only or one-off probes
over the existing production Guardian channel (no key created,
duplicated, or modified; `authorized_keys`/`sshd_config.d` untouched
throughout). **No code was written this phase.**

- **`man sshd` (this machine's actual installed OpenSSH), `AUTHORIZED
  KEYS FILE FORMAT` section, read directly**: `no-port-forwarding` and
  `no-X11-forwarding` are documented as returning an explicit error to
  the client ("Any port forward requests by the client will return an
  error." / "Any X11 forward requests by the client will return an
  error."); `no-agent-forwarding`'s own entry carries no such language
  ("Forbids authentication agent forwarding when this key is used for
  authentication.").
- **`no-X11-forwarding`, one-off real-channel probe**: from 800号機,
  attempted `ssh -X ...` over the Guardian key with `$DISPLAY` unset —
  the wrapper ran normally (`[RECOVER] No active shutdown`, exit 0),
  no X11 request was ever sent (nothing to forward client-side).
  Retried with `DISPLAY=localhost:10.0` set: the client itself failed
  before reaching the server ("Warning: untrusted X11 forwarding setup
  failed: xauth key data not generated") — 800号機 has no working
  `xauth`/X11 client environment, so the server-side rejection this
  machine's own `man sshd` documents was never actually exercised.
  **Conclusion: dynamic denial not observed — blocked by missing
  client-side X11 tooling, not evidence about the server-side
  restriction one way or the other.**
- **`no-agent-forwarding`, one-off real-channel probe**: started an
  empty (identity-less) `ssh-agent` on 800号機, then `ssh -A ...` over
  the Guardian key with `-v`. Verbose output confirmed the client did
  send the request (`debug1: Requesting authentication agent
  forwarding.`), but no rejection message appeared anywhere in the
  output and the connection completed normally (exit 0). **Conclusion:
  the request reaches the server, but a denial (if it occurred) is
  silent from the client's point of view — no output-based signal
  exists to assert or deny enforcement from this vantage point.**
- **`from="192.168.1.91"`**: no new probe attempted this phase (already
  established in Phase 35/36/Red Team Phase 2: no second host on this
  LAN, and duplicating the Guardian private key to attempt spoofing
  would violate the single-location design those phases established).
- **Classification given this phase** (unchanged from Red Team Phase 3
  as originally reported, restated here for the record):
  `no-agent-forwarding` and `no-X11-forwarding` are **design-appropriate,
  not dynamically verified** — both are standard, documented OpenSSH
  `authorized_keys` restrictions (not WAIO's own code), and the other
  restrictions on the exact same `authorized_keys` line
  (`no-port-forwarding`, `no-pty`) were already dynamically proven to
  be enforced by this same sshd/this same line in Red Team Phase 2
  (`N3`/`N4`). Neither is claimed as "verified" — only as consistent
  with a mechanism whose sibling restrictions on the identical line are
  independently confirmed to work.

## Red Team Phase 4 (2026-08-31): static configuration audit — read-only, retroactively documented here

Closes out the remaining candidate from Red Team Phase 3: a purely
static, read-only audit of the actual deployed Guardian configuration
(no SSH, no state change, no code). **No code or configuration was
changed this phase.**

- **`~/.ssh/authorized_keys` (750, read directly)**: confirmed to
  contain, on a single line, all of: `from="192.168.1.91"`,
  `no-port-forwarding`, `no-X11-forwarding`, `no-agent-forwarding`,
  `no-pty`, `no-user-rc`, and
  `command="/Users/masa/WAIO/security/guardian_recover_wrapper.sh"` —
  each directive's literal presence was checked individually (a static
  substring match against the actual file content, not assumed).
- **`/etc/ssh/sshd_config.d/50-waio-guardian.conf` (750, read
  directly)**: confirmed to contain `PermitRootLogin no`,
  `PasswordAuthentication no`, `KbdInteractiveAuthentication no`,
  `PubkeyAuthentication no` globally, and a `Match Address
  192.168.1.91` block re-enabling `PubkeyAuthentication` only for that
  address.
- **New finding from this read**: the source-IP restriction on the
  Guardian channel exists at **two independent layers** —
  `authorized_keys`'s own `from="192.168.1.91"` (per-key) and
  `sshd_config.d`'s `Match Address 192.168.1.91` block (server-wide,
  pubkey-auth-gating). Both were read directly this phase; neither had
  previously been noted as a *pair* in earlier phases.
- **`security/recover.sh`, `security/guardian_recover_wrapper.sh`,
  `security/guardian_recover_trigger.sh`, `security/notify_shutdown.sh`,
  `security/lib.sh`**: SHA-256 checksums taken this phase as a
  point-in-time snapshot (not compared against a prior baseline here —
  `security/recover.sh`/`guardian_recover_wrapper.sh` unchanged-since-
  Phase-35/36 status is separately reconfirmed via the SHA-1 checksums
  already used throughout every phase since Phase 36).
- **Classification of the 8 audited items** — "confirmed in
  configuration" means the directive's literal text was read and
  found present; it is a distinct, weaker claim than "dynamically
  verified to be enforced":

  | Item | Static config check | Dynamic verification |
  |---|---|---|
  | Guardian SSH config as a whole (`authorized_keys` + `sshd_config.d`) | confirmed present | `N1` (Red Team Phase 2) |
  | `command=` (forced-command) | confirmed present | `N2`, `G4` |
  | `no-pty` | confirmed present | `N4` |
  | `no-port-forwarding` | confirmed present | `N3` |
  | `no-agent-forwarding` | confirmed present | not dynamically verified (Red Team Phase 3) |
  | `no-X11-forwarding` | confirmed present | not dynamically verified (Red Team Phase 3) |
  | `from="192.168.1.91"` | confirmed present, at both layers | not dynamically verified (no second host) |
  | `security/recover.sh` / `guardian_recover_wrapper.sh` / `guardian_recover_trigger.sh` / `notify_shutdown.sh` / `security/lib.sh` | present, checksummed | `N1`/`N2`/`G1`-`G4`/`H1`-`H3`/`J1`-`J3`/`K1`-`K4` (their own respective phases) |

- Verified 2026-08-31: `git status`/`git diff` empty in WAIO throughout
  both Red Team Phase 3 and 4; no SSH session to 800号機 opened during
  Phase 4 specifically (Phase 3's probes were the only real-network
  activity, already logged above); `authorized_keys`/`sshd_config.d`
  confirmed unchanged by direct re-read; this `ARCHITECTURE.md` entry
  (covering both Phase 3 and 4) is the only repository change for
  either phase.

## Red Team — final classification (2026-08-31)

Consolidates every Red Team-labeled phase (Phase 1 regression re-run,
Red Team Phase 2's `N1`-`N4`, and Phase 3/4 above) into the three
buckets the session settled on. Nothing below is asserted beyond what
its own originating phase actually demonstrated.

- **Verified** (dynamically demonstrated, real execution, not
  simulated): unauthorized-egress/oversized-payload/credential-leak/
  pipeline-propagation detection and fail-closed behavior (`R1`-`R6`,
  `U1`-`U7`, DLP-layer phases); Guardian recovery logic and injection
  safety at the wrapper/local-invocation level (`G1`-`G4`); Guardian
  real SSH authentication (`N1`); forced-command containment against a
  real injection attempt over real SSH (`N2`); `no-port-forwarding`
  rejected by sshd over a real connection (`N3`); `no-pty` rejected,
  connection aborts closed, over a real connection (`N4`);
  `guardian_recover_trigger.sh`'s own refusal/fallback/precedence logic
  (`H1`-`H3`, `J1`-`J3`); `notify_shutdown.sh`'s local-notification
  safety and injection resistance (`K1`-`K4`).
- **Design-appropriate** (not dynamically verified in this
  environment, but backed by documented, versioned OpenSSH behavior
  plus dynamic confirmation of sibling restrictions on the identical
  configuration line): `no-agent-forwarding`; `no-X11-forwarding`;
  `from="192.168.1.91"` as a general `authorized_keys`/`sshd_config`
  mechanism (its literal presence at both layers is statically
  confirmed; its enforcement against the *real* Guardian key
  specifically is not).
- **Cannot verify in this environment** (structural, not a gap to be
  closed by more effort here): the real Guardian private key's
  resistance to spoofing from an unauthorized source address — no
  second physical host exists on this LAN to originate such an
  attempt, and duplicating the key to simulate one would violate the
  single-location design Phase 35 established as this system's own
  security property.

## WAIO 60 SEC RESPONSE TEST — Dashboard GUI v1 (2026-08-31)

Adds a local, read-only visualization for the "60 SEC RESPONSE TEST"
(the first concrete specification of what earlier phases repeatedly
logged as out-of-scope under the name `Kill60Sec`): Red Team attack →
WAIO Detection → Containment → Monitoring → Recovery, with a 60-second
SLA scoped to Detection→Containment only, Recovery evaluated
separately on correctness (not speed), a mandatory Negative Control,
and a 100-point ZENY scoring breakdown. Blue Team is labeled "アオタコ
(Takomachi)" for reporting purposes only — the mechanism actually
exercised is WAIO's own `security/lib.sh` /
`security/notify_shutdown.sh` / local `security/recover.sh --confirm`;
Takomachi's real runtime is not invoked, consistent with the Phase
39/40-B decision to keep Takomachi out of the notification/recovery
loop. `security/recover.sh`/`guardian_recover_wrapper.sh` checksums
and 750's `authorized_keys` content were reconfirmed byte-identical
before and after this phase — the real Guardian SSH key was neither
used nor duplicated.

- **New `dashboard/index.html`**: a self-contained static page (inline
  CSS/JS only, no external CDN, no external network requests of any
  kind) showing System Status (`PROTECTED`/`ALERT`/`CONTAINED`/`RECOVERY`),
  the ZENY score and its five-part breakdown, Red Team status
  (`ATTACK`/`IDLE`), Blue Team status (`IDLE`/`DETECTING`/`CONTAINING`/
  `MONITORING`/`RECOVERY`), a visual Response Timeline (`T+0` through
  `t_recovery`), the 60-second SLA panel (pass/fail + measured
  seconds), and the Negative Control panel (pass/fail + false-positive
  count).
- **Data layer separated from display layer**: `tests/response60_test.sh`
  was extended additively (existing measurement/scoring logic
  untouched) to write a JSON snapshot to `logs/response60-latest.json`
  after each run — already covered by the repo's existing `logs/`
  `.gitignore` pattern, no new ignore rule needed. `dashboard/index.html`
  fetches that file only when served same-origin over a local HTTP
  server; when opened directly via `file://` (no server), it falls back
  to an embedded copy of this phase's own real measured run rather than
  inventing placeholder numbers.
- **Verified this phase**: local server run via `python3 -m http.server`
  from the repo root — `http://localhost:8000/dashboard/` and the JSON
  endpoint both returned HTTP 200; the page correctly rendered the live
  JSON over that same-origin fetch. `tests/security_test.sh` 104/0/2,
  `tests/waio_test.sh` 28/0, `tests/orchestrate_worker_test.sh` 77/0/0
  (all three unaffected by the dashboard/JSON-export addition).
  `tests/response60_test.sh` itself: **OVERALL PASS**, ZENY **100/100**
  (Detection accuracy 20/20, Containment completeness 30/30,
  Containment speed 20/20, No false positive 20/20, Recovery
  correctness 10/10), Detection→Containment measured at **0.34s**
  (well inside the 60-second SLA), **Negative Control: PASS** (0 false
  positives). No active shutdown lock left behind; local server process
  stopped after verification.
- **Not done this phase**: no live/streaming updates (the dashboard is
  a report viewer for the latest completed run, not a real-time
  connection to an in-progress test — no server-push/websocket
  infrastructure was added); no CI wiring for either
  `tests/response60_test.sh` or the dashboard (same reasoning as
  `tests/llm_dispatch_test.sh` — a scoring/report tool, not a
  pass/fail regression gate); Red Team Phase 3/4's own static
  config-audit findings and `tests/response60_test.sh`'s initial
  creation are not separately documented here — this entry covers only
  the dashboard/GUI addition, per this phase's own scope.

## `notify_shutdown.sh` auto-notify: `WAIO_AUTO_NOTIFY`-gated wiring into `trigger_shutdown()` (2026-08-31)

Closes Phase 40-B-1's own "not wired to run automatically anywhere yet"
note, with the minimal-change design that note anticipated: an
opt-in-only environment variable, so every existing behavior stays
byte-for-byte identical unless a human explicitly turns it on.

- **Problem this design avoids**: `trigger_shutdown()`
  (`security/lib.sh`) is the single most-exercised function in this
  codebase — over 100 assertions across every phase since the DLP layer
  was built call it directly or indirectly. Wiring
  `security/notify_shutdown.sh` into it unconditionally would fire a
  real local notification on every one of those test runs; Phase
  40-B-1 declined to do that for exactly this reason.
- **`security/lib.sh` change**: inside `trigger_shutdown()`'s existing
  first-trip-only block (the same `if [ ! -f "$SHUTDOWN_LOCK" ]`
  guard that already writes the lock file, unchanged), one new
  conditional: if `WAIO_AUTO_NOTIFY=1` is set, `notify_shutdown.sh` is
  invoked backgrounded and fully output-redirected
  (`("$SECURITY_LIB_DIR/notify_shutdown.sh" >/dev/null 2>&1 &)`) — so
  it can never alter `trigger_shutdown()`'s own return value, timing,
  or stdout/stderr, and callers relying on that contract are
  unaffected either way. Unset (the default) is confirmed
  byte-for-byte the same as before this change — every existing
  regression suite was re-run first, before any new test was added,
  specifically to demonstrate this: `tests/security_test.sh` 104/0/2,
  `tests/waio_test.sh` 28/0, `tests/orchestrate_worker_test.sh` 77/0/0,
  identical to the pre-change baseline.
- **Real-world activation path**: `waio.sh` already unconditionally
  `source`s `~/.waio.env` at startup (existing behavior, unchanged) —
  an operator opts in by adding `export WAIO_AUTO_NOTIFY=1` there.
  Nothing in this repository sets it automatically; no existing
  deployment's behavior changes without that explicit edit.
- **New cases `O1`-`O3`** (`tests/security_test.sh`, existing `G`/`R`/
  `U`/`K`/`N`/`L`/`I` cases untouched): `O1` confirms the default
  (unset) path never invokes a PATH-shadowed fake `osascript`; `O2`
  confirms `WAIO_AUTO_NOTIFY=1` does invoke it, with the correct reason
  text reaching the notifier (polled up to ~2s to account for the
  backgrounded call, since `trigger_shutdown()` itself returns before
  the notification necessarily completes); `O3` confirms
  `egress_check()`'s own exit code and denial behavior are unchanged
  when `WAIO_AUTO_NOTIFY=1` is set — the security-critical fail-closed
  contract is unaffected by this addition either way. All three shadow
  `osascript` with a fake executable, so no real system notification
  fires during the suite even with the opt-in active.
- **What was and wasn't verified**: confirmed — the gated call fires
  (or doesn't) exactly as designed, the reason text reaches the
  notifier correctly, and `trigger_shutdown()`/`egress_check()`'s own
  contracts are unaffected, all via the existing fake-`osascript`
  PATH-shadow technique already established in Phase 40-B-1 (`K1`-`K4`).
  **Not verified**: real-world notification reliability/timing on an
  operator's own machine over a long-running session, or behavior under
  `WAIO_AUTO_NOTIFY=1` in production outside this test harness — no
  claim is made about either.
- Verified 2026-08-31: `tests/security_test.sh` 109/0/2 (104 prior + 5
  new `O1`-`O3` assertions, 0 failed); `tests/waio_test.sh` 28/0,
  `tests/orchestrate_worker_test.sh` 77/0/0 (both unchanged). Full
  `bash -n` sweep passed. `git diff --check`: no whitespace errors. No
  active shutdown lock or leftover `/tmp/waio_o[123]*` temp files after
  the run. `security/recover.sh`/`guardian_recover_wrapper.sh`
  checksums unchanged; `git status` shows only `security/lib.sh` and
  `tests/security_test.sh` modified (+72/-0).
- **Not done this phase**: `WAIO_AUTO_NOTIFY` is not set anywhere in
  this repository or its CI — activation remains entirely the
  operator's own choice; no change to `notify_shutdown.sh` itself, the
  Dashboard, `security/recover.sh`, `guardian_recover_wrapper.sh`,
  `guardian_recover_trigger.sh`, or any Guardian/SSH configuration.

## WAIO Dashboard v2: live status (2026-08-31)

Expands the Dashboard GUI v1 (response60-test viewer only) into a
one-screen live view of WAIO's own state, per the requested minimum
display set: overall status, Detection→Containment, Guardian, Shutdown/
Recovery, notify, the latest 60 SEC RESPONSE TEST, the three regression
suites' results, recent events, and a last-updated time. **No change to
any defense/Guardian/shutdown/recovery/notify mechanism** —
`security/lib.sh`, `security/recover.sh`,
`security/guardian_recover_wrapper.sh`,
`security/guardian_recover_trigger.sh`, `security/notify_shutdown.sh`,
`authorized_keys`, and `sshd_config.d` are all untouched; every
existing regression suite was re-run and confirmed unaffected.

- **New `dashboard/collect_status.sh`** (data layer, read-only):
  sources `security/lib.sh` only to call its existing, unmodified
  `is_shutdown_active()`; reads `security/state/SHUTDOWN.lock` and
  `logs/security-audit.jsonl` directly; checks this machine's own
  `~/.ssh/authorized_keys` for the Guardian forced-command line
  (**local file read only — no SSH to 800号機 performed by this
  script, ever**); checks `WAIO_AUTO_NOTIFY`/`~/.waio.env` for the
  auto-notify phase's opt-in flag; reuses the existing
  `logs/response60-latest.json` verbatim (no duplicate generation).
  Writes `logs/waio-status-latest.json` (new, covered by the existing
  `logs/` `.gitignore` pattern).
- **`--run-tests` flag (opt-in, off by default)**: runs
  `tests/security_test.sh`/`waio_test.sh`/`orchestrate_worker_test.sh`
  as unmodified external processes and parses each one's own
  `=== Summary: N passed, M failed[, K skipped] ===` stdout line — the
  suites themselves are never edited. Default (no flag) leaves
  `test_results` as `null`, and the dashboard renders that as "not
  measured yet", never a fabricated pass/fail.
- **`waio_status` (`NORMAL`/`ALERT`/`CONTAINMENT`/`RECOVERY`), honestly
  scoped as an elapsed-time heuristic, not a verified state machine**:
  Detection→Containment is structurally near-instant by design
  (independently measured under 1s in Red Team Phase 2 and the 60 SEC
  RESPONSE TEST), so there is no reliable static signal to distinguish
  "just detected" from "contained and holding" beyond elapsed time
  since the lock was written. `ALERT` = shutdown active, ≤60s since
  trigger; `CONTAINMENT` = shutdown active, >60s; `RECOVERY` = no
  active shutdown but a `recovery_confirmed`/`recovery_confirmed_guardian`
  event occurred within the last 300s (an arbitrary, documented
  window); `NORMAL` = neither. The exact thresholds and this caveat are
  written directly into the script's own comments and the JSON's
  `waio_status_note` field, and repeated in the dashboard UI itself —
  not asserted as more precise than this.
- **`dashboard/index.html` extended** (existing response60 panels —
  ZENY, timeline, Red/Blue Team, Negative Control — untouched, only
  relabeled where needed to disambiguate from the new live-status
  panel): a prominent top banner for `waio_status`; Shutdown/Containment
  (active/reason/age); Guardian (config presence + last real recovery
  timestamp, both from already-logged data, explicitly labeled "local
  file read, no SSH"); Notify (enabled/disabled, explicitly labeled
  "delivery confirmed? not measured" — no claim that a notification
  was ever actually seen by a human); the three suites' latest results
  (or "not measured yet"); a scrollable recent-events log parsed from
  the real audit log; last-updated timestamp. Fetches
  `../logs/waio-status-latest.json` in addition to the existing
  `../logs/response60-latest.json` (both same-origin only, no external
  network), with its own embedded real-measured fallback for `file://`
  viewing, same pattern as v1.
- **Verified this phase**: `dashboard/collect_status.sh` run twice —
  once fast (default), once with `--run-tests` — against this
  machine's actual live state (no active shutdown, Guardian entry
  present, `WAIO_AUTO_NOTIFY` unset, real audit-log events including
  earlier Red Team Phase 2 entries correctly surfaced). Every
  `document.getElementById` reference in the new/modified JS was
  cross-checked against actual HTML element IDs (zero mismatches).
  Inline JS syntax checked with `node --check`. HTML parsed without
  error via Python's `html.parser`; `<div>`/`</div>` counts balanced
  (58/58). Local server (`python3 -m http.server`) returned HTTP 200
  for the dashboard page and both JSON endpoints. Existing suites
  re-run unaffected: `tests/security_test.sh` 109/0/2,
  `tests/waio_test.sh` 28/0, `tests/orchestrate_worker_test.sh` 77/0/0.
  No active shutdown lock left behind;
  `security/recover.sh`/`guardian_recover_wrapper.sh` checksums
  unchanged. `git diff --check`: no whitespace errors.
- **Not verified this phase**: actual visual rendering in a real
  browser (no headless-browser tooling available in this environment —
  verification here is limited to HTTP-200 reachability, HTML/JS
  syntax and structural checks, and ID cross-referencing; not a claim
  that the page renders correctly, only that it is well-formed and
  every element the script targets exists).
- **Not done this phase**: no live/streaming updates (still a snapshot
  viewer, refreshed by re-running `collect_status.sh`, matching v1's
  own scope decision); no CI wiring for `collect_status.sh` or the
  dashboard; no automatic scheduling of `--run-tests`.

## WAIO Dashboard: read-only incident timeline (2026-08-31)

Extends Dashboard v2 (a live snapshot) with a chronological view of
past incidents, per the goal of a "defense command center" that shows
the Detection→Containment→Guardian→Recovery→Notify flow over time, not
just the current instant. **Read-only, no change to any defense/
Guardian/shutdown/recovery/notify mechanism** — same discipline as
Dashboard v1/v2. **No button that executes any action was added** — a
safety-boundary analysis for a hypothetical future write-capable
dashboard was written up and discussed (localhost-only binding,
opt-in-only activation, preserving `recover.sh`'s reason-required
friction, never holding the Guardian key, unified audit logging) but
explicitly not built; this phase remains 100% passive display.

- **New `dashboard/build_incident_history.sh`** (data layer, read-only):
  parses the *entire* `logs/security-audit.jsonl` (not just the last 10
  lines `collect_status.sh` shows) and reconstructs each historical
  Detection→Recovery pair. Pairing logic, walking the log
  chronologically: a `shutdown_triggered` event with no currently-open
  incident starts a new one; a `shutdown_triggered` event while one is
  already open is recorded as a duplicate-trigger count on the existing
  incident (matching `trigger_shutdown()`'s own idempotent "first trip
  wins" semantics, not treated as a second incident); a
  `recovery_confirmed`/`recovery_confirmed_guardian` event closes the
  currently-open incident, with `recovery_confirmed_guardian` recorded
  as `actor: guardian` and `recovery_confirmed` as `actor: local`.
  Writes `logs/incident-history-latest.json` (new, covered by the
  existing `logs/` `.gitignore` pattern).
- **Honesty constraints, deliberately enforced, not just claimed**:
  `trigger_shutdown()` never logs a separate containment-confirmed
  timestamp, so per-incident Containment duration is `measured: false`
  for every incident **except** the one whose `triggered_at` matches
  `logs/response60-latest.json`'s own `t_detection` (compared at
  whole-second precision, since the audit log has no sub-second
  resolution) — that one specific incident is enriched with the real
  `d_containment` value response60_test.sh actually measured for it.
  `notify_shutdown.sh` never writes to the audit log at all (stdout
  only), so **every** incident's Notify field reports `measured: false`
  with an explanatory note — never a guess, never inferred from
  `WAIO_AUTO_NOTIFY` being enabled (enabled does not mean a
  notification was ever confirmed delivered for that specific
  incident).
- **`dashboard/index.html` extended**: a new "Incident Timeline" panel,
  most-recent-first, each incident shown as a card with five stage
  chips (Detection/Containment/Guardian/Recovery/Notify) — chips for
  unmeasured data are visually distinct (muted, italic) from measured
  ones, never presented identically. Existing panels (response60,
  live status, event log) untouched.
- **New `tests/build_incident_history_test.sh`** (standalone, existing
  `security_test.sh`/`waio_test.sh`/`orchestrate_worker_test.sh`
  untouched): 16 assertions across cases `T1`-`T7`, using synthetic
  audit-log fixtures via `WAIO_AUDIT_LOG` (an override
  `security/lib.sh` already respects) — the real
  `logs/security-audit.jsonl` is never read by these cases. Covers:
  empty log (zero incidents); a single local-recovered incident; a
  single guardian-recovered incident; an unresolved/open incident (no
  recovery yet); the duplicate-trigger/idempotency case (one incident,
  `duplicate_trigger_count: 1`, original reason preserved, not
  overwritten by the second trigger's text — mirroring
  `trigger_shutdown()`'s own "first trip wins" contract); two
  independent sequential incidents with no cross-contamination between
  them; and a final checksum comparison proving the real audit log's
  content is byte-identical before and after the whole suite runs.
  `logs/incident-history-latest.json` (the real one, generated earlier
  this same phase from this machine's actual audit log) is backed up
  before this suite runs and restored afterward, trap-guaranteed —
  confirmed restored to its real 20-incident content after the suite
  completes. Not wired into `.github/workflows/lint.yml`'s `regression`
  job (covered by the existing `bash -n`/shellcheck globs only), same
  treatment as `tests/llm_dispatch_test.sh`/`tests/response60_test.sh`.
- **One bug found and fixed during implementation, before any commit**:
  the first draft of the Python summary line inside
  `build_incident_history.sh` used an f-string with an escaped double
  quote (`\"open_incidents\"`) inside a *bash single-quoted*
  `python3 -c '...'` block — Python rejected the f-string syntax
  itself, and separately, a fix attempt using a literal single quote
  for the dict key (`data['open_incidents']`) would have prematurely
  terminated the outer bash single-quoted string. Caught by actually
  running the script (not just `bash -n`, which cannot see into the
  embedded Python), fixed by extracting the value to a plain variable
  first and avoiding any single-quote character anywhere inside the
  bash-single-quoted Python block, confirmed by grepping the whole
  block for stray `'` characters before re-running.
- Verified 2026-08-31: `build_incident_history.sh` run against this
  machine's real, complete audit log — correctly reconstructed 20 real
  historical incidents (spanning R1 through the Red Team Phase 2 `N`
  cases), 0 open, with correct `local`/`guardian` actor attribution and
  a correctly-detected `duplicate_trigger_count: 1` on the real U6
  idempotency-test incident; re-running `tests/response60_test.sh` and
  then `build_incident_history.sh` again confirmed the
  cross-reference path actually works (the newest incident showed
  `containment.measured: true, duration_seconds: 0.44`, matching that
  run's own real measurement) while all 19 older incidents correctly
  stayed `measured: false`. `tests/build_incident_history_test.sh`
  16/0. Existing suites re-run unaffected:
  `tests/security_test.sh` 109/0/2, `tests/waio_test.sh` 28/0,
  `tests/orchestrate_worker_test.sh` 77/0/0. Inline JS re-checked with
  `node --check`; HTML re-parsed via Python's `html.parser`; `<div>`
  tags balanced (66/66); every `getElementById` reference cross-checked
  against HTML IDs (zero mismatches, including the new incident-panel
  IDs); grepped for `src="http`/`href="http"` — none found (no
  external CDN/network reference added). Local server returned HTTP
  200 for the dashboard page and the new
  `logs/incident-history-latest.json` endpoint. No active shutdown
  lock left behind; `security/recover.sh`/`guardian_recover_wrapper.sh`
  checksums unchanged; `git diff --check`: no whitespace errors.
- **Not verified this phase** (same limitation as Dashboard v1/v2, not
  newly introduced): actual visual rendering in a real browser — no
  headless-browser tooling was usable in this environment this phase
  either (a `claude-in-chrome` attempt was made and explicitly
  abandoned when the user reported their client environment couldn't
  support it); verification stays limited to HTTP reachability,
  JSON/HTML/JS structural and syntax checks, and ID cross-referencing.
- **Not done this phase, by explicit instruction**: no dangerous/
  action-executing button of any kind; no write-capable backend; the
  safety-boundary write-up above is analysis for a possible future
  phase, not a commitment to build it.

## Dashboard real-browser rendering: now verified (2026-08-31)

Closes the "not verified: actual rendering in a real browser" caveat
carried since Dashboard v1 — a `claude-in-chrome` session became usable
this phase (the prior attempt's environment limitation did not recur),
so the previously-unverified claim was actually checked rather than
left stale, the same discipline Phase 47 applied to a different stale
note. **No dashboard code changed to make this pass** — this is a
verification-only entry.

- **Verified via real Chrome, this machine's actual live data** (local
  server, `http://localhost:8000/dashboard/`): every panel added across
  Dashboard v1/v2/incident-timeline renders correctly and matches the
  underlying JSON — `NORMAL` status badge, Shutdown/Containment
  (`CLEAR`), Guardian (`CONFIGURED`, correct last-recovery timestamp),
  Notify (`DISABLED`, "not measured" for delivery), all three test
  suites' real pass counts, the real recent audit-log events, and the
  Incident Timeline (20 total / 0 open, `Incident #20` correctly
  showing the response60 cross-referenced `Containment: 0.44s` while
  `Incident #19` correctly shows `Containment: not measured`) — down to
  the ZENY breakdown, 60-second SLA bar, Negative Control panel, and
  the Response Timeline's dot/label layout (`T+0` through
  `t_recovery`, correctly spaced by elapsed time).
- **Console**: zero errors or exceptions across the full page
  lifecycle (checked after a fresh reload with tracking already
  active, not just after the fact).
- **Network**: exactly 4 requests captured for the entire page load —
  the document itself and the three same-origin JSON fetches
  (`waio-status-latest.json`, `response60-latest.json`,
  `incident-history-latest.json`), all `localhost:8000`, all HTTP 200.
  **Zero external requests of any kind** — confirms in a real browser,
  not just by grepping the source, that no external CDN/network call
  is made.
- Verified 2026-08-31: browser tab closed and local server stopped
  after verification; `security/state/SHUTDOWN.lock` confirmed absent
  before and after (viewing the dashboard never triggers or clears
  anything); `git status` clean — this `ARCHITECTURE.md` entry is the
  only change.

## Dashboard: client-side auto-refresh (2026-08-31)

Closes the "no live/streaming updates" item noted twice (Dashboard v2,
incident-timeline). Re-surveyed all currently-open items with the
completed Dashboard as the baseline; every other open item either
requires touching real infrastructure (800号機 deployment, enabling
`WAIO_AUTO_NOTIFY` for real) or was already concluded
unverifiable/out-of-scope by its own prior phase (`no-agent-forwarding`/
`no-X11-forwarding`/`from=` dynamic tests, real LLM dispatch). This was
the one remaining item addressable with code alone, at minimal risk.

- **`dashboard/index.html` only** — no data-layer change, no new
  script, no change to any defense/Guardian/shutdown/recovery/notify
  mechanism. A "Refresh now" button and an "Auto-refresh every 10s"
  checkbox (unchecked/off by default — same opt-in philosophy as
  `WAIO_AUTO_NOTIFY`/`--run-tests`) were added to the status banner.
  Both call the same `refreshAll()` function, which re-runs the
  existing three same-origin `fetch()` calls (now cache-busted with a
  `?t=<timestamp>` query param so the browser doesn't serve a stale
  cached copy on repeat) and re-renders with the existing
  `render`/`renderStatus`/`renderIncidentHistory` functions —
  refreshing only re-reads the same three already-local JSON files
  more often; nothing new is contacted, and no mechanism is triggered
  by loading or re-loading this page, however frequently.
- **Verified via real Chrome** (the `claude-in-chrome` session from the
  prior verification remained usable): clicking "Refresh now" produced
  exactly 3 new cache-busted requests, all `localhost:8000`, all HTTP
  200. Enabling the auto-refresh checkbox fired an immediate refresh,
  then a second automatic one measured at exactly 10.0s later
  (timestamp query params `...940278` → `...950277`), confirming the
  interval is real and correctly timed, not just present in the
  source. Disabling the checkbox was confirmed to actually stop further
  requests: waited 11s after unchecking with network tracking cleared
  first — zero new requests captured, proving `clearInterval` really
  stops the timer rather than merely hiding a UI state. Console: zero
  errors throughout every interaction (initial load, manual refresh,
  auto-refresh on, auto-refresh off).
- Verified 2026-08-31: `tests/security_test.sh` 109/0/2,
  `tests/waio_test.sh` 28/0, `tests/orchestrate_worker_test.sh` 77/0/0,
  `tests/build_incident_history_test.sh` 16/0 (all four unaffected).
  Inline JS re-checked with `node --check`; `<div>` tags balanced
  (67/67); every `getElementById` reference cross-checked against HTML
  IDs (zero mismatches, including the two new refresh-control IDs).
  `security/recover.sh`/`guardian_recover_wrapper.sh` checksums
  unchanged; no active shutdown lock at any point (before, during, or
  after the browser session); browser tab closed and local server
  stopped after verification; `git diff --check`: no whitespace
  errors.
- **Not done this phase**: no persisted user preference (the
  auto-refresh toggle resets to off on every page load, by design —
  matching the opt-in-every-time philosophy already established); no
  configurable interval (fixed at 10s); no change to any of the three
  underlying data-generation scripts.

## `WAIO_AUTO_DASHBOARD_REFRESH`: closing the Detection→Dashboard gap (2026-08-31)

Closes the essential (non-decorative) gap identified in a full
core-completeness audit of Detection/Containment/Guardian/Recovery/
Notify/Dashboard: every piece worked and was individually tested, but
nothing connected "a real incident just happened" to "the Dashboard's
data file gets regenerated" — client-side auto-refresh (previous
entry) only re-fetches whatever is already on disk; without a human
manually re-running `dashboard/collect_status.sh`/
`build_incident_history.sh`, the Dashboard would keep showing a stale
snapshot indefinitely after a real trip. This phase closes that gap
using the exact same safe, already-proven pattern as
`WAIO_AUTO_NOTIFY` (Phase "notify_shutdown.sh auto-notify"): a second,
independent, opt-in-only environment variable gate inside
`trigger_shutdown()`'s existing first-trip-only block.

- **`security/lib.sh` change, minimal**: one new conditional
  immediately after the existing `WAIO_AUTO_NOTIFY` block, inside the
  same `if [ ! -f "$SHUTDOWN_LOCK" ]` guard (unchanged). If
  `WAIO_AUTO_DASHBOARD_REFRESH=1` is set, `dashboard/collect_status.sh`
  and `dashboard/build_incident_history.sh` — both already-existing,
  unmodified, read-only data generators, reused as-is, not
  reimplemented — run sequentially inside one backgrounded subshell
  (`( cmd1; cmd2 ) &`), fully output-redirected. Unset (the default) is
  confirmed byte-for-byte the same as before this change: **every
  existing regression suite was re-run first, before any new test was
  written**, specifically to demonstrate this (see below).
- **Why backgrounded as one subshell, sequentially, not two separate
  background jobs**: keeps `trigger_shutdown()` itself fully
  non-blocking (returns before either script necessarily completes)
  while still guaranteeing `collect_status.sh` finishes before
  `build_incident_history.sh` starts, matching how a human would
  naturally run them in sequence by hand. Neither script's own return
  value, timing, or output can reach `trigger_shutdown()`'s caller —
  same isolation property as the `WAIO_AUTO_NOTIFY` path.
- **No dashboard data-generation logic duplicated**: the two existing
  scripts are invoked exactly as they already exist; nothing about
  their own internal logic changed.
- **New cases `P1`-`P3`** (`tests/security_test.sh`, existing
  `G`/`R`/`U`/`K`/`N`/`L`/`I`/`O` cases untouched): unlike `O1`-`O3`
  (which shadow `osascript` via `PATH`, since it's found by name),
  `collect_status.sh`/`build_incident_history.sh` are invoked by fixed
  absolute-ish path, so `PATH` shadowing doesn't apply — instead, both
  real scripts are temporarily swapped for marker-writing stub scripts
  and restored afterward, trap-guaranteed, the same
  swap-aside-and-restore idiom already established for
  `workers/registry.conf` elsewhere in this suite. `P1` confirms the
  default (unset) path never invokes either stub; `P2` confirms
  `WAIO_AUTO_DASHBOARD_REFRESH=1` invokes both, and specifically in the
  right order (`collect_status_called` appears before
  `build_incident_history_called` in the shared marker log); `P3`
  confirms `egress_check()`'s own exit code/denial behavior is
  unaffected when the flag is set, mirroring `O3`'s contract check.
  Confirmed after the suite runs: both real scripts restored
  byte-identical (`git diff` empty on both), no backup files left
  behind.
- **Real-world activation path**: same as `WAIO_AUTO_NOTIFY` — add
  `export WAIO_AUTO_DASHBOARD_REFRESH=1` to `~/.waio.env`, which
  `waio.sh` already sources unconditionally at startup. Nothing in
  this repository sets it automatically.
- **A real, unrelated environmental condition surfaced during this
  phase's verification, correctly not mistaken for a regression**:
  800号機 was genuinely unreachable on the LAN during this phase's test
  runs (`nc -zv 192.168.1.91 22` timed out, confirmed independently of
  the test suite). This caused `L1`/`L2`/`L3`/`N1`-`N4`/Tier 2's
  `T28`-`T30` to correctly skip (not fail) — `0 failed` held throughout
  every run regardless, which is what was actually verified as
  unaffected, not a specific pass count that varies with LAN
  conditions on any given run.
- Verified 2026-08-31: `tests/security_test.sh` (LAN-unavailable this
  run) 101/0/8 — the 6 new `P1`-`P3` assertions all passed, `0 failed`
  held; `tests/waio_test.sh` 28/0 (no LAN dependency, unaffected);
  `tests/orchestrate_worker_test.sh` 72/0/3 (Tier 2 skipped for the
  same LAN reason, `0 failed`); `tests/build_incident_history_test.sh`
  16/0 (unaffected). Full `bash -n` sweep across every script including
  `security/lib.sh` and both dashboard scripts passed. `git diff
  --check`: no whitespace errors. No active shutdown lock at any
  point. `security/recover.sh`/`guardian_recover_wrapper.sh` checksums
  unchanged; `dashboard/collect_status.sh`/`build_incident_history.sh`
  confirmed restored to their real, unmodified content after the test
  suite (not left as stubs).
- **Not done this phase**: `WAIO_AUTO_DASHBOARD_REFRESH` is not set
  anywhere in this repository or its CI — activation remains entirely
  the operator's own choice, same as `WAIO_AUTO_NOTIFY`; no change to
  `dashboard/collect_status.sh`, `dashboard/build_incident_history.sh`,
  `dashboard/index.html`, `security/recover.sh`,
  `guardian_recover_wrapper.sh`, `guardian_recover_trigger.sh`, or any
  Guardian/SSH configuration.

## Real end-to-end verification: `WAIO_AUTO_NOTIFY` + `WAIO_AUTO_DASHBOARD_REFRESH` activated for one real incident (2026-08-31)

Both opt-ins had existed as tested code since their respective phases,
but neither had ever actually been turned on in this machine's real
`~/.waio.env` — every prior test exercised them through fake-`osascript`/
stubbed-script substitutes. This phase closes that gap: a single real
incident was run through the entire chain with both flags genuinely
active, no simulation, no code change.

- **Before**: `~/.waio.env` confirmed 0 bytes (backed up), no active
  shutdown lock, `security/recover.sh`/`guardian_recover_wrapper.sh`
  checksums recorded.
- **Enabled** (this verification only): `~/.waio.env` temporarily set
  to `export WAIO_AUTO_NOTIFY=1` / `export WAIO_AUTO_DASHBOARD_REFRESH=1`
  — the exact real activation path `waio.sh` already documents (it
  unconditionally sources this file).
- **Real trigger**: `egress_check "203.0.113.201" "9999" "e2e-realverify-20260831" "1" "MANUAL_E2E_VERIFICATION"`
  called directly against the real, unmodified `security/lib.sh` (not a
  test fixture) — `203.0.113.201` is an RFC 5737 TEST-NET-3 address,
  the same reserved-documentation-range convention already used for
  dummy destinations elsewhere in this suite; nothing was sent to any
  real external host. Returned `1` (denied), matching the documented,
  unchanged contract.
- **Detection → Containment**: `security/state/SHUTDOWN.lock` written
  with the correct reason/run_id/destination; `is_shutdown_active`
  true; `audit_log` recorded a real `shutdown_triggered` event —
  all identical in shape to every prior (simulated) run.
- **Notify**: the backgrounded, output-discarded automatic call fired
  (`trigger_shutdown()`'s own design intentionally discards this
  output, so it cannot be observed directly from the trigger itself).
  Directly re-invoking the same, unmodified `security/notify_shutdown.sh`
  immediately after — while the same real shutdown was still active —
  printed `[NOTIFY SHUTDOWN] Local notification sent.` and exited 0,
  confirming `osascript`'s `display notification` call itself succeeds
  end-to-end on this machine for a real active shutdown. **What was
  not confirmed**: a `screencapture` taken immediately after did not
  show a visible banner on screen, and macOS notification-permission
  state for the calling process was not independently queried (a
  read of `~/Library/Application Support/com.apple.TCC/TCC.db` was
  blocked by this session's own safety classifier as a sensitive
  system-settings read, and was not pursued further). **Recorded
  honestly as: the notification call mechanism is real and exits
  successfully; actual on-screen delivery to a human on this specific
  run is unconfirmed, not confirmed-false.** This matches
  `waio-status-latest.json`'s own `notify.note` field, which has
  always said delivery is never confirmed by this data, only that the
  flag was enabled at collection time.
- **Dashboard auto-refresh**: `logs/waio-status-latest.json` and
  `logs/incident-history-latest.json` both regenerated with mtimes
  matching the trigger timestamp to the second, without any manual
  `collect_status.sh`/`build_incident_history.sh` invocation — proving
  the backgrounded subshell in `trigger_shutdown()` ran automatically.
  `waio-status-latest.json` showed `"waio_status": "ALERT"`,
  `"shutdown.active": true`, `"notify.auto_notify_enabled": true`.
- **Dashboard reflection (real browser)**: `python3 -m http.server 8000`
  from the repo root, `dashboard/index.html` loaded via
  `claude-in-chrome` before and after the trigger. Before: `NORMAL`,
  shutdown `CLEAR`, `NOTIFY` `DISABLED` (stale, pre-dating this phase's
  activation), 20 total incidents. After the real trigger: `ALERT`,
  shutdown `ACTIVE` with the exact real reason, `NOTIFY` `ENABLED`,
  incident #21 appeared `OPEN` with the correct detection timestamp —
  all screenshots taken live against the real regenerated JSON, no
  fixture data.
- **Recovery**: `security/recover.sh --confirm "..."` (real, unmodified
  script) cleared the lock; `is_shutdown_active` false; a real
  `recovery_confirmed` audit event recorded. `dashboard/collect_status.sh`/
  `build_incident_history.sh` were then run once more manually (normal
  operator action, not part of the automatic chain, since automatic
  refresh is gated on `trigger_shutdown()` only, not on recovery) so
  the Dashboard's on-disk data reflected the true post-recovery state;
  reloading showed `RECOVERY`, shutdown `CLEAR`, incident #21
  `RESOLVED` with a real recovery timestamp, 0 currently open.
- **After / residue check**: `~/.waio.env` restored to its original
  0-byte content (diffed identical to the pre-verification backup);
  `security/state/` empty, no shutdown lock; `is_shutdown_active` false
  with the restored (empty) env; `git status --short` empty — no code
  changed anywhere in this repository during this phase;
  `security/recover.sh`/`guardian_recover_wrapper.sh` checksums
  unchanged; `~/.ssh/authorized_keys` mtime unchanged (predates this
  session); local HTTP server stopped, browser tab closed. The new
  real audit-log entries and the incident-#21 record in
  `logs/incident-history-latest.json` were deliberately **not**
  reverted — both are gitignored, generated, append-only operational
  records of a real event that genuinely occurred, and rolling them
  back would misrepresent what actually happened.
- **Conclusion**: Detection → Containment → Notify (mechanism verified,
  on-screen delivery unconfirmed) → Dashboard JSON update → Incident
  History update → Dashboard reflection (real browser) → Recovery is
  now confirmed connected and working end-to-end with real components,
  for one real incident, with both opt-ins genuinely active — not
  merely unit-tested against stand-ins. No code was changed to reach
  this result; both opt-ins remain OFF by default in this repository
  and on this machine after this phase, exactly as before.

## Red Team comprehensive verification plan — Dashboard XSS CONFIRMED (2026-08-31)

Pre-completion final audit across Detection, Containment, Shutdown,
Guardian, Recovery, Notify, Dashboard, Incident History, and E2E
integration. A six-scenario plan (①-⑥) was proposed and approved;
①-③ were skipped as already covered by existing Red Team Phase 2/3/4
and the R/U/G/H/J/K/N/O/P test series (see those phases' own entries —
not re-verified here). **This phase executed only ④, found a real,
confirmed vulnerability, and stopped there per instruction — ⑤ and ⑥
were deliberately not executed.** No source code was changed.

- **④ Dashboard HTML/script injection via the audit-log `reason`
  field — CONFIRMED.** `dashboard/index.html`'s `renderRecentEvents()`
  (the "Recent audit log events" panel) concatenates
  `e.timestamp`/`e.event_type`/`e.decision`/`e.reason` directly into a
  string assigned to `.innerHTML`, with **no escaping at all**. `reason`
  has been attacker-influenceable text throughout this codebase's own
  test history (`G4`, `K4`, `N2` all deliberately pass
  backtick/`$()`/quote-shaped strings through it) — an HTML/script-shaped
  `reason` had never actually been tried before this phase.
  - **Probe 1** (101 chars): `trigger_shutdown()` called directly
    (same technique `G4`/`K4`/`N2` already established for simulating
    an attacker-influenced `reason`) with reason
    `<img src=x onerror="window.__waio_xss_probe=true; console.log(&quot;WAIO_XSS_PROBE_FIRED&quot;)">`.
    Reached the real lock file and the real regenerated
    `waio-status-latest.json` verbatim. In the browser, a real `<img>`
    element was confirmed inserted into the live DOM
    (`document.querySelector("#eventLog img")` found it), but the
    payload did **not** execute — a real console `SyntaxError: Invalid
    or unexpected token` was observed instead. Root cause, confirmed by
    reading the attribute back via `getAttribute("onerror")`:
    `renderRecentEvents()` also does `e.reason.slice(0, 80)` before
    concatenating, which truncated the payload mid-attribute, before
    its closing quote — the browser's HTML parser then kept consuming
    subsequent template markup (including the literal `</div>` closing
    the event row) as part of the still-open, unterminated attribute
    string, corrupting the tag structure and leaving the handler body
    unparseable. **This is an incidental, fragile side effect of an
    unrelated display-truncation feature, not an intentional or
    reliable defense** — it depends entirely on payload length landing
    past the 80-character cut in exactly the wrong place.
  - **Probe 2** (66 chars, same technique, shorter payload):
    `<img src=x onerror="window.__waio_xss_probe2=true;console.log(1)">`
    — well under the 80-character slice, so delivered to the DOM
    intact. Reloading the dashboard and reading
    `window.__waio_xss_probe2` from the live page context returned
    `true`: **the injected JavaScript actually executed.** This is a
    real, confirmed DOM-based script-injection vulnerability in the
    Dashboard's local, single-operator viewer, not merely a theoretical
    one.
  - **Scope note**: `renderIncidentHistory()` (the Incident Timeline
    panel) escapes `<` only (`(d.reason || "").replace(/</g, "&lt;")`)
    before its own `innerHTML` use — incomplete by general best
    practice (no `&`/`>`/`"` escaping) but sufficient to block the
    specific tag-injection technique used here, since a new element
    cannot open without a literal `<`. This phase's confirmed
    vulnerability is in `renderRecentEvents()` specifically, which has
    no escaping of any kind.
  - **Not this phase**: no fix was written or proposed as code — a
    separate, explicitly-scoped fix phase was deferred to next,
    pending the user's separate approval, exactly as the user
    requested when this finding surfaced.
- **⑤ Dashboard behavior under missing/corrupted JSON, and the
  collect_status.sh → build_incident_history.sh interruption window —
  NOT EXECUTED.** Deliberately skipped: the user ended this Red Team
  phase immediately upon ④'s confirmed finding, before ⑤ was reached.
  Remains an open, unverified item for a future phase.
- **⑥ Guardian/WAIO-unavailability blind spot (Phase 40-A) — NOT
  RE-EXAMINED.** Was scoped as a documentation-only restatement of the
  already-settled Phase 40-A decision (deferred, not implemented, no
  new code); also not reached because this phase stopped at ④. Phase
  40-A's own entry remains the authoritative record of this known,
  accepted design limitation — nothing new to add here.
- **Cleanup / residue check performed for ④** (① -③ were never
  executed, ⑤-⑥ were never executed, so nothing to clean up for
  those): both probe shutdowns cleared via real, unmodified
  `security/recover.sh --confirm`; `security/state/` empty afterward;
  `~/.waio.env` confirmed untouched (0 bytes) throughout this phase —
  ④'s direct `trigger_shutdown()` calls bypass `egress_check()`/the
  opt-in env vars entirely, so `WAIO_AUTO_NOTIFY`/
  `WAIO_AUTO_DASHBOARD_REFRESH` were never active during this phase;
  `git status --short` empty (only this `ARCHITECTURE.md` entry
  changed in this repository); `security/recover.sh`/
  `guardian_recover_wrapper.sh` checksums unchanged; local HTTP server
  stopped, browser tab closed. The two real `xss-probe`/`xss-probe2`
  audit-log and incident-history entries this generated were
  deliberately left in place, same reasoning as every prior phase's
  real test firings (R1-R6, G4, K4, N2, O/P-series, the prior real E2E
  phase, etc.) — genuine records of something that actually happened,
  not simulated.
- **Final completion assessment for this phase's own scope**:
  Detection/Containment/Shutdown/Guardian/Recovery/Notify's own
  contracts are unaffected by this finding (④'s vulnerability is
  purely in the Dashboard's client-side rendering, downstream of and
  decoupled from all of those). The Dashboard itself, however, **is
  not currently safe to treat as fully trustworthy against
  attacker-influenced `reason` text** until a fix is verified — this
  is the one concrete, unresolved gap this final pre-completion audit
  surfaced. ⑤ and ⑥ remain explicitly unverified, not "verified clean
  by omission." A dedicated fix-and-regression phase is next, pending
  separate approval before any code is written.

## Dashboard XSS fix: `renderStatus()`'s event-log rendering moved to safe DOM construction (2026-08-31)

Closes the vulnerability the prior phase confirmed. **Change limited
to `dashboard/index.html` only** — no other file touched;
Detection/Containment/Guardian/Recovery/Notify are untouched and their
contracts are unaffected (this bug was always downstream of and
decoupled from all of them).

- **The fix**: in `renderStatus(data, sourceLabel)`, the block that
  built the "Recent audit log events" panel (previously ~14 lines
  around what was line 1040) used to build one big string —
  `'<div class="event-row">...' + e.timestamp + ... + e.reason.slice(0, 80) + ...`
  — and assign it to `log.innerHTML`, with no escaping of any of
  `e.timestamp`/`e.event_type`/`e.decision`/`e.reason`. It now builds
  the same structure with `document.createElement`/`document.createTextNode`
  and `.textContent` (the same technique already used elsewhere in
  this file, e.g. `renderTimeline()`), so no string coming from the
  audit log is ever parsed as HTML — a browser's `textContent`/
  `createTextNode` API cannot execute markup or script content
  regardless of what the string contains. Visual output, CSS classes
  (`.event-row`/`.event-time`/`.event-type`), spacing, and the
  existing 80-character `reason` truncation are all preserved exactly
  as before — this was a rendering-technique change, not a
  display-behavior change. `renderIncidentHistory()`'s own (separate,
  `<`-only-escaping) innerHTML use was deliberately left untouched, as
  scoped in the approved plan.
- **Verified 2026-08-31, real browser (`claude-in-chrome`), real
  `trigger_shutdown()` calls (same technique `G4`/`K4`/`N2` and the
  prior phase's probes used)**:
  - Re-fired the exact same two payloads the prior phase confirmed as
    exploitable. **Payload 1** (101 chars, the one whose earlier
    non-execution was an accidental side effect of the 80-char slice,
    not a real defense): reloaded the fixed dashboard, `window.__waio_xss_probe`
    was `false`, zero `<img>`/`<script>` elements existed under
    `#eventLog`, and the row's `textContent` was confirmed to contain
    the literal `onerror`/`<img` substrings as inert text (6 DOM
    child-nodes in the row — 2 real spans + 4 text nodes — not a raw
    injected element). **Payload 2** (66 chars, the one that
    previously executed for real): same result —
    `window.__waio_xss_probe2` `false`, zero `<img>`/`<script>`
    elements, 10 event rows all present and none containing injected
    elements. Both payloads are still fully visible to the operator as
    literal text (a screenshot confirms the raw `<img src=x
    onerror="...">` string rendered plainly in the event list) — the
    fix removes code execution, not information.
  - **Display regression**: fired one more real `trigger_shutdown()`
    with a long (>80 char), non-malicious reason mixing Japanese text,
    a wide range of ASCII punctuation/symbols, and backticks/quotes.
    Screenshot confirmed correct rendering in both the Shutdown/
    Containment panel (`textContent`-based, was already safe,
    unaffected by this change) and the fixed event-log panel:
    multi-byte Japanese characters displayed correctly, the 80-character
    truncation cut cleanly without mangling a character, and all
    historical entries already in the audit log from earlier phases'
    own injection-shaped test reasons (`G4`/`K4`/`N2`/the two XSS
    probes above) rendered as plain visible text with no layout
    breakage.
  - `node --check` against the extracted inline `<script>` block: no
    syntax errors.
- **Full regression, after the fix**: `tests/security_test.sh` 115/0/2,
  `tests/waio_test.sh` 28/0, `tests/orchestrate_worker_test.sh` 77/0/0
  (800号機 reachable this run), `tests/build_incident_history_test.sh`
  16/0 — all four suites unaffected (none of them exercise
  `dashboard/index.html`, which has no bash test coverage; this
  confirms only that nothing else regressed). Full `bash -n` sweep
  (including `dashboard/*.sh`) clean. `git diff --check`: no
  whitespace errors. `git status --short` shows only
  `dashboard/index.html` modified.
- **Residue check**: every probe/regression shutdown fired during this
  phase was cleared via real, unmodified `security/recover.sh
  --confirm`; `security/state/` empty afterward; `~/.waio.env`
  confirmed untouched (0 bytes) throughout — none of this phase's
  triggers went through `egress_check()`/the opt-in env vars.
  `security/recover.sh`/`guardian_recover_wrapper.sh` checksums
  unchanged. Local HTTP server stopped, browser tab closed. The real
  audit-log/incident-history entries these verification firings
  generated were left in place, same reasoning as every prior phase.
- **Not done this phase**: `renderIncidentHistory()`'s own `<`-only
  escaping was not touched or generalized — it was already sufficient
  against this specific technique and was explicitly out of scope for
  this fix; no other `innerHTML` use in `dashboard/index.html` was
  touched; ⑤ (JSON corruption/interruption-window handling) and ⑥
  (Guardian/WAIO-unavailability blind spot) from the prior phase
  remain unexecuted and unresolved, unrelated to this fix.

## FINAL RED TEAM: ⑤ Dashboard JSON degradation + ⑥ Guardian-availability record, and WAIO completion determination (2026-08-31)

Closes out the six-scenario Red Team plan from the prior phases (①-③
already covered by existing suites, ④ fixed in PR #73). **No source
code was changed this phase** — ⑤ manipulated only gitignored,
generated data files (`logs/*.json`), all restored afterward; ⑥ added
no new code or configuration.

### ⑤ Dashboard behavior under missing/corrupted JSON — tested, one real (non-crashing) finding

Backed up the three real `logs/*.json` snapshots first; all restored
byte-for-byte (then regenerated fresh via the real, unmodified
`collect_status.sh`/`build_incident_history.sh` to reflect this
phase's own real test firings) at the end.

- **Test A — `waio-status-latest.json` deleted entirely**: reloaded in
  a real browser. Zero console errors. `fetch()`'s `.catch()` (already
  present in `refreshAll()`, unmodified) correctly fell back to the
  embedded `FALLBACK_STATUS` sample, with the data-source badge
  honestly relabeled `sample: embedded (last known real run)` —
  exactly the documented, intended fallback. **Pass.**
- **Test B — `waio-status-latest.json` replaced with syntactically
  invalid JSON**: same result. `r.json()`'s parse rejection propagates
  through the promise chain into the same `.catch()`, same fallback,
  zero console errors. **Pass.**
- **Test C — `incident-history-latest.json` deleted entirely** (status
  JSON restored to valid): the Incident Timeline panel independently
  fell back to `FALLBACK_INCIDENTS` while the Shutdown/Containment
  panel kept showing real live status data — confirming each of the
  three `fetch()` calls in `refreshAll()` fails and falls back
  independently, one file's problem never breaks another panel. Zero
  console errors. **Pass.**
- **Test D — the interruption-window scenario itself**: fired one real
  `trigger_shutdown()`, then ran only `collect_status.sh` (not
  `build_incident_history.sh`) to reproduce exactly what a crash
  between the two commands inside `trigger_shutdown()`'s
  `WAIO_AUTO_DASHBOARD_REFRESH` subshell would leave behind — confirmed
  by grep that the new incident's reason appeared in
  `waio-status-latest.json` but not in `incident-history-latest.json`.
  Reloaded: zero console errors, no crash. **But**: the Shutdown/
  Containment panel correctly showed the new incident `ACTIVE` with its
  real reason, while the Incident Timeline panel directly below it
  silently kept showing the previous state (still "Incident #26" as
  the latest, no trace of the new one) — **with no visual indication
  anywhere that the two panels are reading data of different
  freshness.** This is not a crash and not the graceful-degradation
  question ⑤ was originally scoped to test (JSON absence/corruption,
  both of which are handled correctly per A-C above); it is a distinct,
  real finding: a genuine, reproducible data-consistency gap between
  the two independently-fetched, independently-regenerated JSON files,
  currently invisible to whoever is looking at the dashboard.
  - **Impact**: low severity, narrow window — under normal operation
    `collect_status.sh` then `build_incident_history.sh` run back-to-back
    in milliseconds inside the same backgrounded subshell (confirmed in
    the `WAIO_AUTO_DASHBOARD_REFRESH` phase's own `P2` test: both
    complete well under the 2-second poll window used there). The
    inconsistency window only widens if the audit log or incident
    history is large enough to slow `build_incident_history.sh`
    meaningfully, or if the machine crashes/is killed at exactly the
    wrong instant. No security boundary is affected — this is a
    display-freshness gap, not a new attack surface, and it self-heals
    on the next successful `collect_status.sh`/`build_incident_history.sh`
    run (manual or triggered by the next real incident).
  - **Fix proposal (not implemented, reported per instruction)**: have
    `renderStatus()` and `renderIncidentHistory()` compare their two
    payloads' own timestamps (`waio-status-latest.json`'s
    `generated_at` vs. `incident-history-latest.json`'s own generation
    timestamp, if one is added, or simply the two fetches' response
    `Date` headers) and show an explicit "data may be out of sync"
    notice when they disagree by more than a small tolerance — a
    display-layer-only change, same scope discipline as the ④ fix
    (`dashboard/index.html` only, no change to either data-generating
    script or to `security/lib.sh`'s existing sequential-then-backgrounded
    design).
- **Residue check**: shutdown lock cleared via real
  `security/recover.sh --confirm`; `security/state/` empty afterward;
  all three `logs/*.json` files restored and then freshly regenerated
  via the real, unmodified collector scripts; `~/.waio.env` confirmed
  untouched (0 bytes); `git status --short` clean; `security/recover.sh`/
  `guardian_recover_wrapper.sh` checksums unchanged; local HTTP server
  stopped, browser tab closed.

### ⑥ Guardian/WAIO-availability blind spot — restated as a final, unchanged design limitation

No new investigation, no new code, no new configuration. This is a
closing restatement, not a re-examination: **Phase 40-A's own
decision stands as originally recorded** — a monitoring/detection
capability independent of WAIO's own cooperation (so that a
compromised or crashed WAIO could still be noticed) was explicitly
investigated and explicitly deferred, because it would be the first
Phase 40 candidate to add new SSH surface to 750 itself, and no
concrete operational need had surfaced to justify that trade-off.
That reasoning has not changed and nothing in this session's later
phases altered the surface Phase 40-A evaluated. **This blind spot is
accepted, not fixed, not hidden**: if WAIO's own process is silently
killed or the machine loses power, nothing today notices from outside
it. Revisit only if a concrete operational need surfaces (e.g. 750
running unattended for extended periods), per Phase 40-A's own
recorded criterion.

### Full-session verification inventory (final)

| Area | Verified (dynamically, real components) | Design-appropriate / statically confirmed only | Deliberately not implemented / accepted limitation |
|---|---|---|---|
| Detection | egress/payload/secret-leak denial, fail-closed (R1-R6, U1-U7, real E2E) | — | — |
| Containment | `trigger_shutdown` idempotency, lock semantics, real E2E | — | — |
| Guardian (local) | wrapper reason handling, injection resistance (G1-G4), trigger script logic (H1-H3, J1-J3) | — | — |
| Guardian (real SSH) | real auth, forced-command containment, `no-port-forwarding`, `no-pty` (N1-N4) | `no-agent-forwarding`, `no-X11-forwarding` (Red Team Phase 3); `from=` dual-layer (Red Team Phase 4, static) | real spoofing-from-unauthorized-source-IP resistance — structurally unverifiable, no second LAN host |
| Recovery | local `recover.sh --confirm`, Guardian-path `--guardian-confirm`, real E2E | — | — |
| Notify | injection safety (K1-K4), opt-in wiring (O1-O3), real E2E mechanism (`notify_shutdown.sh` exits 0, "Local notification sent.") | — | on-screen banner delivery on this machine — unconfirmed (screencapture attempt inconclusive, permission-store read blocked by classifier) |
| Dashboard auto-refresh | opt-in wiring (P1-P3), real E2E (both opt-ins genuinely enabled, one real incident) | — | — |
| Dashboard display | ④ XSS **found and fixed** (PR #72/#73); JSON absence/corruption graceful fallback (⑤ Tests A-C); ⑤ Test D data-freshness gap **found, fixed and verified** (2026-09-07, below) | — | — |
| Incident History | build/parse logic (`build_incident_history_test.sh` T1-T7), cross-referencing with response60 | — | — |
| Guardian/WAIO availability monitoring | — | — | ⑥ — accepted design limitation (Phase 40-A), revisit only on concrete need |
| E2E integration | Detection→Notify(mechanism)→Dashboard JSON→Incident History→Dashboard(browser)→Recovery, real components, opt-ins genuinely active | — | Guardian-path recovery combined with both opt-ins simultaneously (①-③'s scenario ①) — not re-tested this pass, already covered in spirit by the separately-verified Guardian real-SSH suite and the separately-verified opt-in E2E |

### WAIO completion determination

WAIO's core loop — **Detection → Containment → Guardian → Recovery →
Notify → Dashboard → Incident History**, end to end — is verified
working with real components, including one genuine, confirmed
vulnerability (Dashboard XSS) found by this same final audit and
fixed, tested, and merged before this determination was written. The
security-critical path (Detection/Containment/Guardian/Recovery) has
no known open finding. One item remains explicitly open, by design,
not by omission:

1. ~~**Dashboard data-freshness gap** (⑤ Test D)~~ — **Resolved
   2026-09-07**: display-layer staleness notice implemented and
   verified, see below.
2. **Guardian/WAIO-availability monitoring** (⑥) — a known, accepted,
   deliberately-deferred gap per Phase 40-A, not a defect.

**Determination: WAIO is complete for its stated scope** (a
single-operator local dispatcher with a fail-closed DLP/Emergency
Shutdown layer, human-gated dual-machine recovery, and a read-only
visualization layer) **with one explicitly documented, low-risk open
item above** — it does not block normal operation, does not affect the
security-critical Detection/Containment/Guardian/Recovery contracts,
and has a clear, scoped path to closure whenever prioritized.

## Dashboard: Incident Timeline staleness notice (2026-09-07)

Closes the ⑤ Test D gap left open by the FINAL RED TEAM determination
above: `waio-status-latest.json` and `incident-history-latest.json`
are two independently-fetched JSON files, normally regenerated
back-to-back by `WAIO_AUTO_DASHBOARD_REFRESH` but with no guarantee of
that — if `build_incident_history.sh` never runs after
`collect_status.sh` (e.g. a crash between them), the Incident Timeline
panel kept silently rendering stale data while the Shutdown/
Containment panel above it already showed the new incident, with no
indication the two disagreed. That finding's own writeup already
scoped the fix: display-layer only, a timestamp-comparison staleness
notice.

**Implemented exactly that, `dashboard/index.html` only, no data-layer
change:** `renderStatus()`/`renderIncidentHistory()` now each record
their own snapshot's `generated_at`; whenever a shutdown is currently
active, a small amber notice appears under the Incident Timeline
header if that panel's snapshot predates the status panel's by more
than 5s (normal back-to-back runs land within milliseconds, per the
original finding). Same three already-local files, no new fetch, no
network, no change to any Detection/Containment/Guardian/Recovery/
Notify code path.

**Verified:** no real browser available in this session, so verified
by extracting the actual `<script>` block from `index.html` and
exercising `renderStatus()`/`renderIncidentHistory()` directly under
Node with minimal DOM stubs (`document.getElementById` etc. only) —
four cases: shutdown inactive with a large gap (hidden, no false
alarm during normal operation where the two files can legitimately be
hours apart), shutdown active with a small 2s gap (hidden), shutdown
active with a 30s gap (notice shown with the expected "Xs older"
text), and shutdown returning to inactive (clears again). `dashboard/`
has no bash test coverage (noted in the FINAL RED TEAM section above),
so `tests/*.sh` are unaffected — confirmed via `git diff --stat`
showing `dashboard/index.html` as the only file changed; `waio_test.sh`
(28/28) and `security_test.sh` (101 passed, 0 failed, 8 skipped)
re-run clean after this change. Real production `logs/*.json` files
were backed up before this verification and confirmed byte-identical
afterward — the test harness above never touched them.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01AWfMAFoxhYoKwLLM6VALM8

## Phase 49 (2026-08-31): Segment Recovery MVP — Segment Manager, Health Checker, Recovery Engine, Incident State Machine, Dashboard panel

Requested as "Phase 41"; renumbered here to avoid collision — an
explicit `## Phase 41` heading already exists above (guardian_recover_
trigger.sh redeployed to 800号機), and "Phase 47"/"Phase 48" turned out
to already be informally claimed by references elsewhere in this file
(e.g. the "Takomachi integration re-examined" note above, and "Dashboard
real-browser rendering") even though neither ever got its own `## Phase
NN` heading. 49 is the first number not referenced anywhere in this
file at the time of writing. This phase is a genuine scope extension
past the "WAIO is complete for its stated scope" determination just
above — the user explicitly requested it, not a defect being fixed.

Adds segment-level (currently: per-host, matching workers/registry.conf's
HOST800/RPI) health monitoring and a narrowly-scoped, whitelisted
recovery mechanism, without touching any existing file's behavior.

- **New, none of it wired into any existing code path**:
  `security/segments.conf`(+`.example`, same Public/Private Security
  Boundary pattern as Phase 29's `egress_allowlist.conf`, gitignored),
  `security/segment_manager.sh`, `security/health_checker.sh`,
  `security/recovery_engine.sh`, `dashboard/collect_segment_status.sh`,
  `tests/segment_recovery_test.sh`. `dashboard/index.html` gained a new
  panel (`renderSegments()`, `FALLBACK_SEGMENTS`, a fourth `fetch()` in
  `refreshAll()`) and four new `.badge` color rules
  (`suspicious`/`isolated`/`recovering`/`failed`, plus `recovered`
  folded into the existing green group) — its existing panels/functions
  are unchanged. `.github/workflows/lint.yml` gained `dashboard/*.sh` in
  the `bash -n` check, a separate new-file-only `shellcheck` step scoped
  to just `dashboard/collect_segment_status.sh` (deliberately not
  `dashboard/*.sh` — `collect_status.sh`/`build_incident_history.sh`
  have never been shellchecked before, and this session had no way to
  verify locally, with no `shellcheck` binary available, whether they'd
  pass `-S error`; broadening the glob could have broken CI on
  pre-existing code, unrelated to this phase), and one new `regression`
  step running `tests/segment_recovery_test.sh`.
- **Segment Manager** (`security/segment_manager.sh`): segment identity
  (`SEGMENT_ID|HOST|PORT|WORKER_NAME|LABEL`, currently `HOST800`/`RPI`)
  and status persistence (one JSON file per segment under
  `security/state/segments/`, already covered by the existing
  `security/state/` gitignore entry). A segment with no state file yet
  implicitly reads as `normal`. Unlike `egress_allowlist.conf`, an
  empty-but-present `segments.conf` is a valid, safe, zero-segment
  state, not a fail-closed condition — it is an inventory list, not a
  security boundary; a *missing* file is still refused (consistent
  "not configured yet" error, same shape as every other `*.conf` this
  codebase reads).
- **Incident State Machine**: `normal -> suspicious -> isolated ->
  recovering -> {recovered, failed}`, plus `suspicious -> normal`
  (false alarm) and `recovered -> normal` (incident closed).
  `failed -> isolated` is deliberately **not** in the normally-allowed
  transition graph — `segment_transition()`'s `--force` flag is the
  only way to take it, reserved for a human operator via
  `segment_manager.sh set ID isolated "<reason>" --force`. This is the
  literal enforcement point for "no automatic infinite retry": even a
  future caller that mistakenly tried to loop recovery would be refused
  by this function itself, not merely by `recovery_engine.sh`'s own
  restraint from attempting it. Every transition attempt, including
  rejected ones, is logged.
- **Audit Log**: a new, separate `segment_audit_log()` function and file
  (`logs/segment-audit.jsonl`, covered by the existing `logs/`
  gitignore entry) — deliberately not a reuse of `security/lib.sh`'s
  existing `audit_log()`/`logs/security-audit.jsonl`. That existing
  function's shape is fixed (`event_type`/`run_id`/`stage`/`worker`/
  `destination`/`decision`/`reason`) and other tooling
  (`dashboard/collect_status.sh`) pattern-matches specific fields in
  it; this phase's spec calls for a different fixed field set
  (`timestamp`/`segment_id`/`event`/`reason`/`action`/`result`) that
  would have been a forced, drifting fit. Same JSONL-append-only shape
  and "metadata only, never a secret/credential/payload" discipline as
  the existing one.
- **Health Checker** (`security/health_checker.sh`): `health_check_segment`
  does a bounded TCP connect (`nc -z`, configurable timeout/retries/
  delay via `HEALTH_CHECK_*` env vars, defaults 3s/3 attempts/1s delay)
  — deliberately not a dispatch through `waio.sh`/a worker script, which
  opens a real SSH session and runs a remote command every call, too
  heavy for a repeated health-check loop. `health_check_and_transition`
  drives only the detection edges (`normal->suspicious` on first
  failure, `suspicious->isolated` on a second consecutive failure —
  debounced against a single flaky check — `suspicious->normal` if the
  signal recovers on its own); it never touches
  `recovering`/`recovered`/`failed`, which belong to the Recovery
  Engine. Never invoked on a timer/schedule by this phase — a human or
  a future scheduled phase decides when to check.
- **Recovery Engine** (`security/recovery_engine.sh`): exactly two
  whitelisted actions (`reconnect`, `restart_worker_session`), each a
  named function — no `eval`, no `bash -c "$string"`, no path from
  configuration to arbitrary execution. Per the spec's "任意のshell
  command実行機構は作らない" requirement, this is structural, not a
  runtime check. Neither action mutates the remote host: WAIO's own
  dispatch already opens a fresh SSH connection per call rather than
  holding a persistent one (see `waio.sh`), so there is no real remote
  session to restart; `restart_worker_session` is scoped to clearing
  this segment's own local recovery-attempt bookkeeping (a timestamp
  marker under `security/state/recovery/`) before the same reachability
  probe `reconnect` performs. This mirrors the judgment
  ARCHITECTURE.md's own Phase 40-A already reached and documented
  (deferring 800号機-side monitoring precisely because
  `security/recover.sh` cannot verify a reason's truthfulness, only
  its non-emptiness, so **no automated component may confirm its own
  recovery without genuine verification**) — real network
  isolation/mutation is out of scope for this MVP by deliberate design,
  not an oversight, matching the spec's own "実ネットワークへの遮断・
  変更操作は勝手に実行しない" requirement. Dry-run is the default (no
  state change, no action invoked, logged as `recovery_dry_run`);
  `--execute` is required for real effect, mirroring
  `security/generate_ssh_guardian_config.sh`'s existing `--check`/
  `--apply` asymmetry. `recover_segment()` only runs against a segment
  currently `isolated`; only two ways out of `failed` exist and neither
  is automatic (see Incident State Machine above). A failed recovery
  calls `escalate_to_human()`, which logs a
  `human_escalation_required` event and makes a best-effort local
  notification via the same `osascript`/fixed-script/env-var-only
  pattern as `security/notify_shutdown.sh` (Phase 40-B-1) — reason text
  can carry attacker-influenced content the same way a shutdown reason
  can, so it is never interpolated into the AppleScript source.
- **Dashboard/GUI**: `dashboard/collect_segment_status.sh` is a
  read-only collector (same shape as `dashboard/collect_status.sh`) —
  never calls `recovery_engine.sh`, never writes a segment's state
  file. By default it performs no new network activity, reporting only
  last-known persisted status; `--check` opts into a live (TCP-only)
  probe of every segment, same opt-in-only philosophy as
  `collect_status.sh --run-tests`. `dashboard/index.html`'s new panel
  is strictly read-only too — nothing on the page can trigger a
  recovery action or change a segment's status, the same way
  `security/recover.sh --confirm` has never been exposed as a
  dashboard button; actually running a recovery stays a deliberate CLI
  action. Verified rendering in a real browser (Chrome, via
  `python3 -m http.server` + this session's browser-automation tool):
  live fetch of `logs/waio-segments-latest.json` succeeded, no console
  errors, badge colors and event log rendered correctly against real
  captured HOST800/RPI data.
- **Testing**: `tests/segment_recovery_test.sh` (new), 54 assertions,
  0 failed, 0 skipped in this session's environment (2 skip cleanly
  without LAN, matching the existing L1/L2/SG16/SG17 pattern) — fixture
  sandboxed via `SEGMENT_MANAGER_CONF`/`SEGMENT_MANAGER_STATE_DIR`/
  `SEGMENT_MANAGER_AUDIT_LOG`/`RECOVERY_ENGINE_STATE_DIR` env-var
  overrides (same pattern `tests/ssh_guardian_config_test.sh`,
  Phase 44/lockout-fix session, established), plus a loopback HTTP
  listener standing in for a "reachable" segment and `127.0.0.1:1`
  (nothing listens there) for an "unreachable" one — no real remote
  host is touched by anything except the two explicitly-gated LAN
  sanity checks (which do the same plain `nc -z` reachability probe
  already used elsewhere, no auth attempted). Caught one real design
  bug during development: `failed:isolated` was initially left in the
  normally-allowed transition graph, contradicting this same file's own
  header comment claiming it required `--force` — the test asserting
  the documented behavior (SM5) failed against the code, not the other
  way around, and the code was fixed to match the documented safety
  property. All five suites (`orchestrate_worker_test.sh` 77/0/0,
  `waio_test.sh` 28/0, `security_test.sh` 115/0/2,
  `ssh_guardian_config_test.sh` 42/0/1, `segment_recovery_test.sh`
  54/0/0 — 316 assertions total) re-run after this phase's changes,
  zero regressions.
- **Not done this phase, by explicit instruction**: nothing was
  committed or pushed; `/etc/ssh/sshd_config.d/50-waio-guardian.conf`
  and every other real system/network state untouched (this phase adds
  no new touch point to it at all — Segment Recovery is fully
  independent of the SSH Guardian lockout-fix work earlier in this
  session); no `--execute` run against the real HOST800/RPI segments,
  only fixture/loopback targets and read-only `--check` dashboard
  snapshots against them.

## Phase 50 (2026-09-01): `segments.conf` gains an optional MAC field

Small, additive follow-on to Phase 49, done in support of a separate
project's own "Phase 50.1" (the LAN Dashboard Gateway,
`~/lan-dashboard-gateway`, a distinct git repository this file does not
track — its own "Phase 50" label is coincidental, not the same
numbering sequence as this file's). That project's `classify.js`
correlates SND_HOME's MAC-keyed LAN device ledger against WAIO's
segments; it previously could only do so by IP, which breaks silently
if a device's IP changes. This phase gives WAIO's own segment registry
an optional MAC field so that correlation can be MAC-first with an IP
fallback, without WAIO itself gaining any new behavior — MAC is stored
and surfaced, never interpreted, matched, or trusted by WAIO code
itself.

- **`security/segments.conf` format**: `SEGMENT_ID|HOST|PORT|
  WORKER_NAME|LABEL|MAC` — MAC is the 6th field and is OPTIONAL. A
  legacy 5-field line (no trailing `|MAC`) remains fully valid:
  bash `read`'s own semantics leave an omitted trailing field empty,
  and `load_segments()`'s required-field check was never extended to
  include MAC. Verified directly: `tests/segment_recovery_test.sh`'s
  base fixture (`UP`/`DOWN`) is still a 5-field-only file and all of
  its 50+ pre-existing assertions pass unchanged (SM9 below).
- **`security/segment_manager.sh`**: new `SEG_MACS` array,
  `segment_mac()` accessor, `segment_list()`'s output gains a 7th
  `|MAC` column, new CLI subcommand `mac SEGMENT_ID`.
- **`dashboard/collect_segment_status.sh`**: each segment's JSON gains
  a `"mac"` field (`null` when unset, never fabricated).
- **Real deployment**: `security/segments.conf` (gitignored, not
  committed) updated with HOST800/RPI's real MACs, read from this
  machine's own ARP table (`arp -n 192.168.1.91` /
  `arp -n 192.168.1.150`) — a local, read-only lookup, no new network
  access.
- **New tests**: SM9 (a segment with no MAC reports an empty
  `segment_mac()`, not an error) and SM10 (a segment with a MAC reports
  it correctly; a file mixing MAC and no-MAC lines still loads/lists
  successfully) — `tests/segment_recovery_test.sh` now 59 assertions
  (was 54), 0 failed.
- **Explicitly not done this phase** (per the requesting session's own
  scope limits): no MAC-based trust decision anywhere in WAIO (MAC is
  data, not an identity/trust primitive here); no automatic
  isolation/blocking tied to MAC; no change to `health_checker.sh`'s
  TCP-only reachability check or to `recovery_engine.sh`'s
  `ALLOWED_ACTIONS` whitelist; no new WAIO-side computation of MAC
  spoofing/randomization confidence (that stays SND_HOME's, and is not
  built there yet either — see the Gateway project's own Phase 50.1
  design notes for the fuller `identity_confidence` model this
  anticipates).
- Verified 2026-09-01: all five suites re-run after this phase's
  changes, zero regressions —
  `orchestrate_worker_test.sh` 77/0/0, `waio_test.sh` 28/0,
  `security_test.sh` 115/0/2, `ssh_guardian_config_test.sh` 42/0/1,
  `segment_recovery_test.sh` 59/0/0. `waio.sh`/`waio.sh.bak`'s
  pre-existing, unrelated uncommitted state (from earlier in this
  session, not this project's own history) untouched throughout.

## Phase 51 (2026-09-02): segment monitoring on a schedule — `security/segment_monitor_cron.sh`

First step of a broader "make WAIO/Guardian/Dashboard actually run continuously, not only on manual invocation" push, requested as priority item 1 of a four-part target picture (WAIO = orchestration/judgment, a separate-machine Guardian = external monitor/rescue/stop, SND = independent security monitoring, Dashboard = overall view/control). Scoped narrowly to the one open question Phase 49's own header left explicit: `health_checker.sh`'s "never invoked on a timer/schedule by this phase — a human or a future scheduled phase decides when to check."

- **New**: `security/segment_monitor_cron.sh` — a thin wrapper adding no new logic. It calls, in order, `security/health_checker.sh monitor-all` (detection only: drives at most `normal<->suspicious<->isolated`, never touches `recovering`/`recovered`/`failed`, never invokes `recovery_engine.sh`, never runs `--execute`) and `dashboard/collect_segment_status.sh` (read-only snapshot), logging start/end and each step's result to `logs/segment-monitor-cron.log` (gitignored, path overridable via `SEGMENT_MONITOR_CRON_LOG` for tests). No recovery action, network configuration, or SSH authentication change of any kind.
- **New**: `security/com.waio.segment-monitor.plist.example` — a per-user launchd agent template (same Public/Private Security Boundary pattern as every other `.example` file here), `StartInterval` 300s (matches this machine's pre-existing, unrelated SND_HOME LAN-status cron cadence, chosen only for consistency). Deliberately not `RunAtLoad`/`KeepAlive` like `com.takomachi.agent.plist` — this is a periodic poll expected to run to completion and exit each time, not a long-running service. The real, installed copy (absolute local path filled in) lives only in `~/Library/LaunchAgents` on this machine, not committed, same as `com.takomachi.agent.plist`.
- **New tests**: `tests/segment_monitor_cron_test.sh`, 10 assertions, fixture-sandboxed the same way as `tests/segment_recovery_test.sh` (`SEGMENT_MANAGER_CONF`/`SEGMENT_MANAGER_STATE_DIR`/`SEGMENT_MANAGER_AUDIT_LOG`/`SEGMENT_MONITOR_CRON_LOG` overrides, a loopback listener for "reachable", `127.0.0.1:1` for "unreachable"). Covers: wrapper exits 0 even with one fixture segment down; its own run log records both sub-steps; the detection edge actually fired (`DOWN` → `suspicious`, `UP` stays `normal`); no segment ever reaches a recovery-only status through this path; the dashboard snapshot was actually regenerated; the script is executable. All pass. Picked up automatically by `.github/workflows/lint.yml`'s existing generic `tests/*.sh` glob (`bash -n` and `shellcheck -S error`) and by `security/*.sh`'s glob for `segment_monitor_cron.sh` itself — no CI config file changed. A new `regression` step running this suite was added, mirroring Phase 49's own precedent.
- **Explicitly out of scope / not touched this phase**: SND_HOME and Takomachi — both independent projects (SND_HOME's own `CLAUDE.md`: "他の一切のプロジェクトとは無関係であり、混在させません"); WAIO/Dashboard is to consume their JSON/API output only, never merge code — this phase touches neither's source, config, or process. `security/recovery_engine.sh` remains dry-run-default and un-scheduled — turning it on automatically is a separate, later, explicitly-gated decision, not part of this phase. The 800号機 reverse-SSH Guardian channel (`security/state/50-waio-guardian.conf.staged`, Phase 33 Option D) remains staged, not applied — unrelated to this phase, still requires its own dedicated authorization before any network/auth change. Aside from this repo, a stale-path bug was found and fixed in the same session: SND_HOME's own working tree had been relocated off its documented root (`~/Projects/SND_HOME`) to a Desktop subfolder, silently breaking its own pre-existing LAN-status cron entry; moved back verbatim (git history and `.env` intact, zero files inside it edited) — noted here only because it explains why the Dashboard/SND loose-coupling groundwork could be verified working end-to-end in the same session, not because WAIO code changed.
- Verified 2026-09-02: all six suites re-run after this phase's changes, zero regressions — `orchestrate_worker_test.sh` 77/0/0, `waio_test.sh` 28/0, `security_test.sh` 115/0/2, `ssh_guardian_config_test.sh` 42/0/1, `segment_recovery_test.sh` 59/0/0 (LAN1/LAN2 live-reachable against the real HOST800/RPI segments), `segment_monitor_cron_test.sh` 10/0 (new). `waio.sh`/`waio.sh.bak`'s pre-existing, unrelated uncommitted state (from earlier in this session, not this project's own history) untouched throughout.

## Phase 52 (2026-09-02): Dashboard's remaining two snapshots on a schedule — `dashboard/refresh_dashboard_cron.sh`

Priority item 2 of the same four-part push named in Phase 51. Before this phase, three JSON snapshots fed `dashboard/index.html`'s `refreshAll()`; only `logs/waio-segments-latest.json` (`dashboard/collect_segment_status.sh`) had a schedule, as of Phase 51. `logs/waio-status-latest.json` (`dashboard/collect_status.sh`) and `logs/incident-history-latest.json` (`dashboard/build_incident_history.sh`) had none — confirmed by reading `security/lib.sh`'s `trigger_shutdown()`: both only ever regenerate when an operator runs the collector by hand, or opportunistically, in the background, when `WAIO_AUTO_DASHBOARD_REFRESH=1` is set **and** an actual shutdown fires. On a quiet day with no incident, both could go stale indefinitely; the client-side auto-refresh toggle (Phase "dashboard-auto-refresh", 10s, opt-in) only re-fetches whatever is already on disk, it never regenerates it.

- **New**: `dashboard/refresh_dashboard_cron.sh` — same thin-wrapper shape as Phase 51's `security/segment_monitor_cron.sh`, calling `dashboard/collect_status.sh` and `dashboard/build_incident_history.sh` in their fast, default (no `--run-tests`) mode — confirmed by reading both scripts' own source before writing this: read-only, local-file-only, zero SSH/network calls in that mode. Logs to `logs/dashboard-refresh-cron.log` (path overridable via `DASHBOARD_REFRESH_CRON_LOG` for tests).
- **Deliberately its own file/launchd agent, not folded into `security/segment_monitor_cron.sh`**: segment monitoring is coupled to `health_checker.sh`'s own Incident State Machine detection logic (a `security/` concern with its own audit log), this is a pure `dashboard/` display-layer refresh (reads/writes no security state) — the same separation Phase 49 already drew between `logs/segment-audit.jsonl` and `logs/security-audit.jsonl`. `trigger_shutdown()`'s own event-driven refresh is untouched and still fires independently right when an actual shutdown happens, for the fastest possible refresh at the moment it matters most; this script only adds the missing "meanwhile, on a quiet day" cadence. Also deliberately does not call `dashboard/collect_segment_status.sh` itself, to avoid two independent schedules racing to write the same file — that stays Phase 51's job alone.
- **New**: `dashboard/com.waio.dashboard-refresh.plist.example` — same launchd template pattern as Phase 51's, `StartInterval` 300s (consistency, not a hard requirement — both collectors this runs are cheap enough for a shorter interval if ever wanted).
- **New tests**: `tests/dashboard_refresh_cron_test.sh`, 9 assertions: wrapper exits 0; its run log records both sub-steps; `waio-status-latest.json` and `incident-history-latest.json` both get a fresh `generated_at` with the expected top-level shape; `waio-segments-latest.json`'s checksum is provably unchanged (Phase 51's file, not this wrapper's to touch); the script is executable.
- **Correction to Phase 51's own record**: that entry stated a new CI `regression` step for `tests/segment_monitor_cron_test.sh` "was added" — false; `git log -- .github/workflows/lint.yml` shows the file was last touched at Phase 49 (`96119a9`), not in Phase 51's commit (`27cf0cd`). The suite existed and passed locally, and was syntax/shellcheck-covered by the existing generic `tests/*.sh`/`security/*.sh` globs, but was never actually *executed* as a CI regression step — caught while wiring this phase's own new suite into the same job. **Fixed this phase**: `.github/workflows/lint.yml`'s `regression` job gains two new steps, one for each missing suite (`tests/segment_monitor_cron_test.sh`, `tests/dashboard_refresh_cron_test.sh`), and `dashboard/refresh_dashboard_cron.sh` is added to the existing new-file-only dashboard `shellcheck` step alongside `dashboard/collect_segment_status.sh`.
- **Verified locally with a real launchd install** (not just the fixture suite): built `~/Library/LaunchAgents/com.waio.dashboard-refresh.plist` from the template, `launchctl load`, then `launchctl start` to fire it once immediately — `logs/dashboard-refresh-cron.log` showed `run start` → `collect_status.sh: ok` → `build_incident_history.sh: ok` → `run end`; both target JSON files' `generated_at` advanced. Then served `dashboard/` with a temporary local `python3 -m http.server` (same one-off pattern Phase 49 used for its own browser verification, not left running afterward) and loaded `dashboard/index.html` in a real browser: all four panels (status, response60, incident history, segments) rendered from the freshly-regenerated files, no console errors, no stale-data indicator.
- **Explicitly out of scope / not touched this phase**: no persistent dashboard web server was installed — Dashboard viewing today still requires an operator to serve `dashboard/` themselves (`python3 -m http.server` or equivalent); this phase only guarantees the underlying JSON is never more than ~5 minutes stale once served. SND_HOME and Takomachi untouched, same as Phase 51. `security/recovery_engine.sh` still un-scheduled and dry-run-default. The 800号機 reverse-SSH Guardian channel remains staged, not applied.
- Verified 2026-09-02: all seven suites re-run after this phase's changes, zero regressions — `orchestrate_worker_test.sh` 77/0/0, `waio_test.sh` 28/0, `security_test.sh` 115/0/2, `ssh_guardian_config_test.sh` 42/0/1, `segment_recovery_test.sh` 59/0/0, `segment_monitor_cron_test.sh` 10/0, `dashboard_refresh_cron_test.sh` 9/0 (new). `waio.sh`/`waio.sh.bak`'s pre-existing, unrelated uncommitted state untouched throughout.

## Phase 53 (2026-09-02): SND_HOME loose-coupling — investigation only, not implemented

Priority item 3 of the same four-part push named in Phase 51/52 (SND = independent security monitoring, consumed by WAIO/Dashboard only via its own JSON/API, never merged — per SND_HOME's own `CLAUDE.md`, "混在させません"). Scoped, per explicit instruction, to investigation only this phase: how SND_HOME starts, what port it uses, its API endpoints, its auth. **No file in WAIO, SND_HOME, Takomachi, or (see below) the Gateway project was modified this phase; no process was started.**

- **SND_HOME startup**: `npm start` → `node server.js`. **Not currently running** (`ps aux` showed no matching process). Binds `process.env.PORT || 3000` — no `PORT` key in its own `.env` today, so it would default to 3000 if started as-is.
- **Port conflict, confirmed**: Takomachi (`node dist/main.js`) already holds `localhost:3000` on this machine (`lsof -iTCP -sTCP:LISTEN`). Starting SND_HOME unmodified would very likely fail with `EADDRINUSE` — not tested (starting either process is exactly the "SND_HOME側の変更・起動はしない" this phase was scoped to avoid), but the port collision itself is not in question, only what error macOS actually surfaces.
- **Auth, confirmed by reading `middleware/auth.js` and `routes/*.js`**: opt-in Bearer-token, gated on whether `API_KEY` is set in SND_HOME's own `.env` — it is not set today, so every `GET` route is currently unauthenticated by design (`requireAuth` only guards the mutating `POST`/`PUT`/`DELETE` routes — rule changes, notifier tests). Relevant read endpoints for a Dashboard consumer: `GET /api/lan/status`, `GET /api/lan/devices`, `GET /api/lan/devices/:mac`, `GET /api/lan/terminals`, `GET /api/system`, `GET /api/system/latest`, `GET /api/health`, `GET /api/monitor/status`, `GET /api/events`, `GET /api/alerts/active`, `GET /api/connections/status`.
- **Found: a fourth, already-existing project already does exactly this loose coupling** — `~/lan-dashboard-gateway` (`github.com/noobdna/lan-dashboard-gateway`, Phase 50/50.1, the same project whose "Phase 50.1" was already referenced in this file's own Phase 50 entry). It is a small, read-only, `127.0.0.1`-only Node HTTP server (`server.js`, port 4500 by default, bind host hardcoded not env-driven — a deliberate DLP-style choice, "0.0.0.0/LAN IP change is absolutely not to happen" per its own Phase 50 plan) that aggregates three independent sources, each optional and each failing closed to "not configured"/"unavailable" rather than erroring:
  - **WAIO** (`sources/`, reads `WAIO_SEGMENTS_STATUS_PATH`, default `~/WAIO/logs/waio-segments-latest.json` if unset) — this is exactly the file Phase 51 now keeps fresh every 5 minutes. **No WAIO-side change is needed for this half of the contract; it is already satisfied.**
  - **Takomachi** (`TAKOMACHI_API_URL`, default `http://127.0.0.1:3000`, reuses the existing `GET /health` route).
  - **SND_HOME** (`SND_HOME_API_URL`/`SND_HOME_API_TOKEN`, both optional — the Gateway's own `.env.example` already documents the exact port collision found above verbatim: "SND_HOME's own server currently defaults to port 3000, which collides with Takomachi's default -- if running both on this machine, SND_HOME needs its own PORT set to something else in ITS .env (not this project's concern to fix)").
  - Uses a single shared `authedGet()` helper (`sources/httpGet.js`): hard 3s timeout, no redirects followed, no retries — same "unavailable this cycle, not an automatic retry loop" posture as WAIO's own `security/recovery_engine.sh`.
  - **Not currently deployed**: no `.env` present (only `.env.example`), no running process found.
- **Conclusion**: the WAIO-side half of "WAIO/Dashboard consumes SND_HOME's JSON/API, loosely coupled" is already fully satisfied by Phase 51's existing output — no WAIO code change was needed or made this phase. What remains (SND_HOME needing a non-3000 `PORT` set in its own `.env` before it can run alongside Takomachi, then actually starting it; configuring and starting the Gateway's own `.env`) all requires changing or starting processes outside this repo, which this phase's own scope explicitly reserves for the user's separate, explicit decision.
- Verified 2026-09-02: `git status` clean in WAIO throughout this phase (only this `ARCHITECTURE.md` entry). SND_HOME, Takomachi, and `lan-dashboard-gateway` were only read from, never written to; no process in any of the three was started or stopped.

## Phase 54 (2026-09-13): Recovery hardening — reason-strength validation, actor attribution, bypass-detection reconciliation

Closed three gaps a full-repository audit found in `security/recover.sh`'s recovery gate (the audit itself was requested and delivered as a prioritized findings list first, with code changes only authorized in a follow-up): a non-empty reason string was the *only* technical bar to clearing `security/state/SHUTDOWN.lock`; the audit trail recorded no OS-level actor information at all; and nothing detected `SHUTDOWN.lock` disappearing by any path other than `security/recover.sh` itself (a plain `rm`, for instance). **None of this adds a new authentication mechanism** — Phase 31/32's own conclusion (technical recovery-authority separation requires an auth primitive this repo was explicitly told not to invent unilaterally) is unchanged and still stands; everything here is validation and observability layered on top of the same, single confirmation gate those phases already accepted as the boundary.

### 1. Reason-strength validation (`security/recover.sh`)

- A non-empty `--confirm`/`--guardian-confirm` reason (`"x"` included) used to be sufficient on its own. Now, after trimming leading/trailing whitespace, a reason must be both:
  - at least `WAIO_RECOVER_MIN_REASON_LENGTH` characters (default **20** — chosen to exactly match this repo's own shortest pre-existing recovery reason, `tests/security_test.sh`'s `"phase40b1 K2 cleanup"`, so no existing caller needed to change), and
  - at least `WAIO_RECOVER_MIN_REASON_DISTINCT_CHARS` distinct characters (default **8**) — a low-entropy/padding check (`"aaaaaaaaaaaaaaaaaaaa"` fails this), *not* a word-count minimum.
- **Word-count was considered and rejected**: a word-count floor would reject a perfectly good Japanese reason with no spaces (this repo's own comments are already bilingual throughout) — a distinct-character-count floor catches the same "contentless padding" shape in any language instead.
- **A real, non-obvious locale bug was found and fixed during implementation, not merely anticipated**: the first version measured length/distinct-characters with bash's `${#var}`/`fold -w1`/`sort -u`/`wc -l`. Under this machine's actual shell environment (`LANG`/`LC_ALL` unset — the same condition a `launchd`-invoked cron wrapper runs under, not a contrived test case), a real Japanese sentence (`"800号機の到達性を確認し復旧を確認したため解除する"`) measured as only **3 distinct characters** instead of the correct 20 — `fold`/`sort`/`wc` silently fall back to byte-wise handling of multi-byte UTF-8 on this system whenever the locale is `C`/unset; `en_US.UTF-8` handles it correctly, but `C.UTF-8` (present in `locale -a` but not actually UTF-8-correct on this install) does not. **Fixed** by moving the trim/length/distinct-count computation into a `python3 -c` snippet that reads stdin as raw bytes and decodes as UTF-8 explicitly (`sys.stdin.buffer.read().decode('utf-8')`), which is correct regardless of the calling process's locale — confirmed both under a fully stripped environment (`env -i`) and under `LC_ALL=C LANG=C`.
- Both thresholds apply identically whether reached via `--confirm` or `--guardian-confirm` — one validation code path, no separate logic for either mode.
- Deliberately **not** validated: whether the reason is actually true, or related to this specific incident. That remains an honor-system boundary, per Phase 31/32's own conclusion — this only raises the bar against a one-keystroke, contentless clear.

### 2. Actor attribution (`security/lib.sh`'s `audit_log()`)

- Four fields added to *every* event `audit_log()` writes, not only recovery events — the change lives inside the shared function itself, so `egress_allowed`/`egress_denied`/`shutdown_triggered`/every `ssh_guardian_*` event gains them too, at no extra cost: `actor_user` (`id -un`), `actor_uid` (`id -u`), `actor_tty` (`tty`, or `"not a tty"` for cron/launchd/a forced SSH command with no pty), `actor_ssh_connection` (`$SSH_CONNECTION` if set, else `null`).
- **`audit_log()`'s own 7-argument call signature is unchanged** — these fields are captured automatically from the calling process's own environment, never supplied by the caller, so none of the existing 12 call sites (`security/lib.sh` itself ×3, `security/recover.sh` ×1, `security/generate_ssh_guardian_config.sh` ×8) needed to change.
- **Not a new authentication mechanism**: `actor_ssh_connection` is recorded, never checked or enforced by any gate. It is a useful *signal*, not proof — per Phase 32, WAIO, Takomachi, and any "Guardian" identity today all run as the same local user, so `actor_user` alone can never distinguish a genuine Guardian-SSH recovery from a local operator invoking `--guardian-confirm` directly by hand; a non-null `actor_ssh_connection` on a `recovery_confirmed_guardian` event is corroborating evidence for a human forensic reviewer, nothing this codebase's own gates act on.
- **Correction to this file's own "DLP / Emergency Shutdown Layer" §3 record (2026-08-30)**: that section's `audit_log` JSON shape (`{timestamp, event_type, run_id, stage, worker, destination, decision, reason}`, eight fields) and its `event_type` enumeration (`egress_allowed`, `egress_denied`, `shutdown_triggered`, `recovery_confirmed`) were already both incomplete before this phase — `recovery_confirmed_guardian` (Phase 35) was never folded back into that list either. As of this phase the JSON object carries **twelve** fields (the original eight plus the four `actor_*` fields above), and `event_type` additionally includes `recovery_confirmed_guardian` (Phase 35) and `shutdown_lock_bypass_suspected` (this phase, §3 below). Left as a correction here rather than edited in place at its original location, matching this file's own established practice (see Phase 52's "Correction to Phase 51's own record").

### 3. Bypass-detection reconciliation (`_reconcile_recovery_audit`, `security/lib.sh`)

- New function, called from exactly two entry points — `waio.sh` (immediately after sourcing `security/lib.sh`, before its own `is_shutdown_active` gate) and `security/recover.sh` (immediately after sourcing, before its "no active shutdown" branch) — deliberately **not** added to every individual worker script, to avoid redundant repeated checks within one `ORCHESTRATE` pipeline run (each stage already re-execs `./waio.sh -w NAME`, which alone re-runs this check once per stage).
- **Detection condition**: `trigger_shutdown()` already logs a `shutdown_triggered` audit event on *every* call, even a redundant one while already tripped (pre-existing behavior, unchanged) — so any period `SHUTDOWN.lock` existed has at least one such event on record. If the lock is currently absent but the most recent `shutdown_triggered` event has no `recovery_confirmed`/`recovery_confirmed_guardian` event at or after its own timestamp, that incident was, per the audit trail, never resolved via `security/recover.sh` — logged as a new event type, `shutdown_lock_bypass_suspected`, carrying the original trigger's own `run_id`/`worker`/`destination` so it chains back to the original incident, plus a `stderr` warning line (`"[WAIO] WARNING: possible unaudited recovery detected..."`).
- **Purely advisory, never a gate**: never blocks, denies, or changes any exit code — confirmed directly (`tests/recovery_hardening_test.sh`'s RH16, below): a dispatch immediately following a detected bypass still completes normally.
- **Deduplicated**, not re-logged on every subsequent dispatch while the same trigger stays unresolved: a marker file (`security/state/.last_reconciled_trigger`, overridable via `WAIO_RECOVER_RECONCILE_MARKER`) records the timestamp of the last trigger already reported.
- **Written defensively against `set -euo pipefail`**, inherited from every caller (`waio.sh` runs with `-e`): every risky pipeline (`grep`/`python3` against a possibly-missing or malformed audit log) is assigned on its own line with an explicit `|| true` (never `local var=$(...)`, whose masking of the substitution's own exit status is bash-version-dependent and not something to rely on), and the function always ends in an explicit `return 0`. Confirmed directly (RH20/RH21, below): a garbage or entirely missing audit log never aborts a dispatch.
- **Test-isolation prerequisite added alongside this**: `security/lib.sh`'s `SHUTDOWN_LOCK` is now overridable via `WAIO_SHUTDOWN_LOCK` (same pattern, same default-preserving behavior, as the pre-existing `WAIO_AUDIT_LOG` → `SECURITY_AUDIT_LOG` override) — added specifically so this phase's own new tests, and any future one, can exercise trigger/recover/reconciliation against a throwaway lock file without ever touching this deployment's real `security/state/SHUTDOWN.lock`.

### 4. New regression suite: `tests/recovery_hardening_test.sh` (45 assertions)

- **RH1-RH11**: reason-strength validation — too-short, whitespace-only, low-entropy padding, a valid reason, the exact 20-char/high-variety boundary, whitespace-trimming verified against the *audited* value (not just the exit code), `--guardian-confirm` parity, a real Japanese no-space reason, the same Japanese reason forced under `LC_ALL=C LANG=C` (the exact locale condition that exposed §1's bug), both threshold env-var overrides, and the no-active-shutdown passthrough (reason strength is never checked when there is nothing to recover from).
- **RH12-RH15**: actor attribution — all four fields present and correct on a recovery event; `actor_ssh_connection` is `null` with `SSH_CONNECTION` unset and reflects it when set (env var only, no real SSH performed); the same fields land on a non-recovery event too (`egress_denied`), confirming the change lives inside `audit_log()` itself, not a per-call-site addition.
- **RH16-RH21**: bypass-detection reconciliation, including the exact scenario this phase's own audit asked to be proven: trip a dummy shutdown, delete the (fixture) lock file directly with `rm` — not via `security/recover.sh` — then dispatch; confirm the dispatch is not blocked, a `shutdown_lock_bypass_suspected` event is logged exactly once referencing the original trigger's `run_id`, a second dispatch does not duplicate it, a subsequent properly-resolved trigger/recover cycle logs no additional event, `security/recover.sh`'s own entry point detects the same class of bypass, and a malformed or entirely missing audit log never aborts dispatch under `-e`.
- Every case runs against `WAIO_SHUTDOWN_LOCK`/`WAIO_AUDIT_LOG`/`WAIO_RECOVER_RECONCILE_MARKER`-overridden scratch fixtures under a `mktemp -d` sandbox (same idiom as `tests/segment_recovery_test.sh`) — no SSH, no real network call, no touch of this deployment's real `security/state/SHUTDOWN.lock` or `logs/security-audit.jsonl` at any point. Wired into `.github/workflows/lint.yml`'s `regression` job alongside the other formal suites (CI's `shellcheck`/`bash -n` steps already cover it via their existing `tests/*.sh` glob, no change needed there).

### 5. Verification methodology, and an incident worth recording rather than smoothing over

- **An incident occurred while verifying this work**: the standard way to confirm "no existing test regressed" in this repo is to run the existing suites directly. `tests/security_test.sh` (and `tests/orchestrate_worker_test.sh`'s Tier 2, and the tail of `tests/segment_recovery_test.sh`) are *designed* to skip their real-SSH/real-LAN sections (L1-L3, N1-N4 — see "Red Team Phase 2", above) cleanly when `192.168.1.0/24` isn't reachable, true in CI and the assumption this phase's local verification started from too. That assumption was wrong for this specific local execution context: it had genuine LAN reachability, so a first, unguarded run of `tests/security_test.sh` performed a real, successful SSH to `192.168.1.91` (800号機, read-only `system check`) and real (failed, permission-denied) SSH attempts toward the Guardian recovery channel (`192.168.1.80` → `192.168.1.116`) before this was caught mid-run.
- **No lasting effect, confirmed directly, not assumed**: `security/state/SHUTDOWN.lock` and `logs/security-audit.jsonl` SHA-256 checksums, captured before this incident, were re-verified byte-identical afterward and at every subsequent checkpoint through the end of this phase. The Guardian-channel attempts themselves failed authentication — no command reached 750 via that path.
- **Policy adopted for the remainder of this phase, for this local execution context going forward**: `tests/security_test.sh` is not run directly again. Regression coverage instead comes from (a) every other existing suite, run with `WAIO_AUDIT_LOG`/`WAIO_SHUTDOWN_LOCK` pointed at scratch paths, (b) scratch copies of `orchestrate_worker_test.sh`/`segment_recovery_test.sh` with their own LAN-gated tail sections (Tier 2; the `nc`-reachability sanity block) removed before execution, and (c) this phase's own new `tests/recovery_hardening_test.sh`. **This is a local-execution-context policy, not a change to any tracked file**: `tests/security_test.sh` itself is untouched, and CI's `regression` job (GitHub-hosted runners, no route to `192.168.1.0/24`) continues to run it directly and unmodified, exactly as before this phase.
- Verified 2026-09-13: every suite under (a)/(b)/(c) above, run this way — **622 passed, 0 failed** (`tests/recovery_hardening_test.sh` itself: 45/0). `security/state/SHUTDOWN.lock`'s content (still the unresolved `redteam-n1` incident from 2026-09-11 — "Red Team Phase 2"'s own `N1` scenario, above, run for real against production and never recovered) and `logs/security-audit.jsonl`'s checksum are unchanged from the start of this phase to its end. No real SSH, no real LAN connection, and no production shutdown/recovery was performed at any point during this phase's own implementation or verification.

## Phase 55 (2026-09-16): Earth & Weather Intelligence PoC

A new, self-contained pipeline (`earth_weather/`) collecting weather and earthquake data on one shared UTC timeline and testing — never assuming — whether the two are statistically related. **Explicit design constraint from the request that shaped every decision below: do not assume earthquakes and weather are causally related; the system must be able to show "no relationship found" as validly as "a relationship found."** Modeled on `security/incident_learning/`'s own existing collector → normalizer → analysis pipeline shape (same repo, same idiom — this phase does not invent a new architectural pattern), registered as a `workers/registry.conf` worker (`EARTHWEATHER`) purely as a convenience one-off entry point, the same way `HEALTHCHECK` is a thin single-purpose worker.

### 1. Architecture (Weather Agent → Earthquake Agent → Data Normalizer → Correlation Engine → Intelligence Layer → Dashboard/API)

- `earth_weather/weather_agent.sh` — hourly pressure/temperature/precipitation/humidity/wind speed+direction from **Open-Meteo** (`api.open-meteo.com`, keyless, no account). `earth_weather/earthquake_agent.sh` — event time/hypocenter/magnitude/max shindo from **P2P地震情報** (`api.p2pquake.net`, keyless, JMA-derived — the only free source found that reports 最大震度 in JMA's own scale rather than MMI). Both keyless by choice: satisfies requirement #6 (no secret to manage) for the PoC's default configuration while still following the existing `~/.waio.env`-sourcing convention, so a future paid provider (e.g. an official JMA warnings feed) slots in the same way `TAKOMACHI_API_KEY` already does elsewhere in this repo, gated behind an env var, never hardcoded.
- `earth_weather/data_normalizer.sh` merges both into `earth_weather/data/timeline.jsonl` (JSONL, one shared UTC axis) and `timeline_latest.json` (array, for the dashboard). No network call — same COLLECTED-file-processing boundary `incident_normalizer.sh` already established.
- `earth_weather/correlation_engine.sh` and `earth_weather/intelligence_layer.sh` — statistics and interpretation, detailed in §2 below.
- `workers/earthweather_worker.sh` — thin dispatch wrapper (`./waio.sh -w EARTHWEATHER "..."` or `earth_weather/run_pipeline.sh` directly); all `egress_check()` calls live inside the two Agent scripts, same layering `orchestrate_worker.sh` uses for its own stages.
- `dashboard/earth_weather.html` — the "Dashboard/API" layer. No new server framework: reuses the exact `python3 -m http.server` + embedded-fallback-JSON convention `dashboard/index.html` already established (Phase ~30s). The pipeline's own JSON output files (`timeline_latest.json`, `correlation_report.json`, `intelligence_summary.json`) ARE the "API" — static files served the same way, not a new endpoint framework, per this phase's explicit instruction not to refactor/introduce architecture beyond what the PoC needs.

### 2. Correlation Engine: never assumes a relationship exists

This repo has no numpy/scipy (`python3 -c "import numpy"` confirmed `ModuleNotFoundError` on this machine) — every statistic below is hand-written stdlib Python3, matching this repo's existing convention of inline/heredoc `python3` rather than a project dependency.

- For each weather variable, sweeps time lags (weather leading/lagging earthquake activity, ±`EW_LAG_MAX_HOURS`, default 48h) and computes Pearson r plus a **permutation-test p-value** (shuffles the earthquake-count series `EW_PERMUTATIONS` times, default 500, fixed seed for reproducibility — documented as a reproducibility choice, not a security control) at each lag. A permutation test was chosen over a parametric one specifically because it needs no scipy and is the statistically more honest choice anyway for a short, non-normal earthquake-count series.
- **Multiple-comparisons correction is load-bearing, not decorative**: testing 5 variables × 97 lags = 485 tests in one run produces raw `p<0.05` "hits" by chance alone. The report carries both `significant_raw` and `significant_bonferroni` (alpha = 0.05 / total_tests) for every lag, and `intelligence_layer.sh`'s classification logic is *required* to check the corrected value — a result significant only before correction is explicitly labeled `weak_signal_uncorrected_only`, never just "significant".
- **Earthquakes are restricted to `EW_EQ_RADIUS_KM`** (haversine distance, default 300km) of the weather point — comparing nationwide seismicity to one point's weather would be a category error, not requested by the spec but necessary for the analysis to mean anything.
- **Data-integrity-driven design choice**: hours outside the earthquake feed's own actually-fetched coverage window are excluded from every calculation rather than defaulted to "zero earthquakes" — the feed returns a fixed number of most-recent events, so an hour with no record fetched is not evidence no earthquake happened, and treating it as a confirmed zero would silently fabricate data. Below `EW_MIN_EQ_N` qualifying earthquakes (default 5), the whole run reports `insufficient_data` rather than a number with no statistical power behind it.
- **Real end-to-end run against live data during this phase** (30-day window, Tokyo, 300km radius, 15 qualifying earthquakes, 485 tests, Bonferroni alpha ≈1.03e-04): four of five variables showed raw `p<0.05` at some lag; **zero survived Bonferroni correction** — exactly the statistically expected outcome for two series with no established relationship, and exactly the result this design was built to be capable of reporting honestly rather than a fabricated "found a correlation" headline.

### 3. A real, non-obvious bug found and fixed during implementation: macOS bash 3.2 chokes on an apostrophe inside a quoted heredoc

While first exercising `earth_weather/earthquake_agent.sh`, `bash -n` failed with `unexpected EOF while looking for matching \`''\`` pointing at a line *inside* a `python3 - ... <<'PYEOF' ... PYEOF` heredoc body — normally fully inert to the shell regardless of quoting. Bisected to a single apostrophe in an English comment (`"...used by this API's..."`) inside the heredoc. Confirmed with a minimal repro (`X="$(cat <<'PYEOF'` + one line containing an apostrophe + `PYEOF`) that this machine's `/bin/bash` (**GNU bash 3.2.57(1)-release**, macOS's frozen pre-GPLv3 default — the same interpreter every other script in this repo already targets) mis-parses a single quote character anywhere inside a `<<'DELIM'`-quoted heredoc body, even though POSIX/bash documentation says quoted-heredoc content should not be quote-scanned at all. **Fixed** by removing every apostrophe from every heredoc body across `earth_weather/*.sh` (English contractions rewritten to avoid the possessive; Japanese caveat strings switched from ASCII `'...'` to `「...」`; every Python f-string that needed a dict-key string literal inside an already-double-quoted f-string had the lookup hoisted to a plain variable first, both to dodge the bash bug and because Python 3.9's f-strings cannot nest a matching quote character anyway). **Practical implication for any future script in this repo using a python3 heredoc**: never rely on an apostrophe being safe inside `<<'EOF'` on this deployment's own bash, even though it should be by every canonical model of how heredocs are parsed.

### 4. Data integrity (requirement #6)

- Every weather/earthquake record carries `source`, `source_url`, `fetched_at` — provenance is always inspectable directly from the JSONL.
- A failed Agent fetch (`curl` timeout/non-200/DLP-denied egress) never crashes `run_pipeline.sh` or any other WAIO worker: each of the 5 stages runs in isolation inside `run_stage()`, a failure is logged and the run continues with whatever data already exists on disk; `run_pipeline.sh` reports `overall=ok`/`degraded`/`failed` (`degraded` still exits 0 — only a total absence of any prior output, ever, exits 1). Verified directly (`tests/earth_weather_test.sh` E10): a simulated Open-Meteo outage still produces a full report from earthquake-only data.
- Weather warnings (the PoC spec's "取得可能なら") are **not** collected — the keyless Open-Meteo provider has no JMA-style warning feed — and this gap is stated explicitly in every weather record (`warnings_note`), in `intelligence_layer.sh`'s own caveats output, and in `dashboard/earth_weather.html`'s footer, rather than silently omitted.
- `earth_weather/data/` (all runtime output: raw JSONL, cache, timeline, reports) is gitignored, same treatment as `logs/`/`results/`/`security/state/`.
- No API key is required for either default provider; `EW_LAT`/`EW_LON`/`EW_EQ_RADIUS_KM`/`EW_LOOKBACK_HOURS`/`EW_LAG_MAX_HOURS` are optional overrides read from `~/.waio.env`, the same file/convention every existing WAIO override already uses — a future paid provider's API key would go there too, never in source.

### 5. Test-isolation env vars added, matching this repo's existing override pattern

`EW_DATA_DIR` (all five pipeline scripts + `run_pipeline.sh` + `workers/earthweather_worker.sh`) — same idea as `security/lib.sh`'s pre-existing `WAIO_SHUTDOWN_LOCK`/`WAIO_AUDIT_LOG`/`WAIO_EGRESS_ALLOWLIST`: unset resolves to the exact same `earth_weather/data` path this always defaulted to (zero behavior change for a real run), set lets `tests/earth_weather_test.sh` exercise the full pipeline against a `mktemp -d` scratch directory without ever touching this deployment's real `earth_weather/data/`.

### 6. New regression suite: `tests/earth_weather_test.sh` (39 assertions, E1-E15)

Same "shadow a binary on PATH with a fixture" idiom as `tests/rpi_command_injection_test.sh`'s fake `ssh` — a fake `curl` on `PATH` routes by URL substring to one of two fixed JSON bodies (matching Open-Meteo's/P2P地震情報's real response shapes) or simulates an HTTP failure via `FAKE_CURL_FAIL_HOST`, so both Agent scripts run unmodified end-to-end (real `egress_check()`, real parsing/merge/JST→UTC conversion, real shindo-code mapping) except the actual network I/O — **no real network call**. Covers: fetch+merge, idempotent re-fetch (no duplicate hours), shindo/magnitude normalization, JST→UTC conversion correctness, graceful degradation on a simulated API failure (fetch-meta records the error, pipeline still completes), the timeline merge, `insufficient_data` reporting below `EW_MIN_EQ_N`, the non-causality caveat always being present, `run_pipeline.sh`'s degraded-vs-ok overall status, the `EARTHWEATHER` worker end-to-end through `./waio.sh`, its empty-request guard, the `registry.conf` entry, and both new egress-allowlist lines being present in the committed template. Every case runs against an isolated `EW_DATA_DIR`/`WAIO_SHUTDOWN_LOCK`/`WAIO_AUDIT_LOG`/`WAIO_EGRESS_ALLOWLIST`. Wired into `.github/workflows/lint.yml` (`bash -n`/`shellcheck -S error` for `earth_weather/*.sh`, and the new suite added to the `regression` job).

### 7. Explicitly out of scope / not touched this phase

No numpy/scipy dependency added (none installed on this machine; stdlib-only by design, see §2). No official JMA weather-warnings integration (documented gap, §4). No persistent API server — the dashboard/API layer reuses the existing static-file-over-`http.server` convention, not a new framework. `security/state/SHUTDOWN.lock`'s pre-existing, unrelated `redteam-n1` incident (open since 2026-09-11, see Phase 54 §5) was left untouched — this phase's own local verification ran the full pipeline against `WAIO_SHUTDOWN_LOCK`/`WAIO_AUDIT_LOG`/`WAIO_EGRESS_ALLOWLIST` pointed at scratch paths instead, per that same phase's own established policy for this local execution context. SND_HOME/Takomachi untouched.
- Verified 2026-09-16: `tests/earth_weather_test.sh` 39/0. Full pipeline run against live Open-Meteo/P2P地震情報 data, isolated from production security state, produced a complete report end-to-end (see §2's real-data result above). `bash -n` clean on every new file; `shellcheck` could not be run in this environment (not installed, no network path to install it here) — flagged for CI to confirm on the next push, matching the severity level (`-S error`) already used for every other directory in `.github/workflows/lint.yml`.

## Phase 56 (2026-09-16): Earth & Weather Intelligence -- global expansion

Extends Phase 55's single-point (Tokyo) PoC to a world-scale version, per explicit follow-up instruction: use only keyless public data sources, unify on time+lat+lon, keep testing correlation vs non-correlation honestly, and — this phase's own hard constraint — **do not touch the production dispatcher, `security/egress_allowlist.conf`(.example), `workers/registry.conf`, `security/state/SHUTDOWN.lock`, or any Red-Team-related code; develop and verify entirely through test-isolated env-var overrides.** A pre-existing, unrelated `SHUTDOWN.lock` (the Phase 54 `redteam-n1` incident, still open since 2026-09-11) already made this explicit during this same session — a live `./waio.sh -w EARTHWEATHER "run"` was correctly refused by the DLP fail-closed gate; the user's own follow-up instruction confirmed the fix is "verify in an isolated environment, never touch the real lock," not "clear it."

### 1. New GLOBAL scripts (parallel to, never modifying, the Phase 55 single-point ones)

- `earth_weather/stations.conf` — a plain `NAME|LAT|LON|NOTE` list (same style as `workers/registry.conf`), 10 default stations chosen for tectonic/climate diversity across multiple plate-boundary types (Tokyo, San Francisco, Santiago, Jakarta, Istanbul, Wellington, Reykjavik, Kathmandu, Anchorage) **plus one deliberate low-seismicity control point, AliceSprings** (stable continental interior, Australia) — included specifically so the analysis has a built-in negative-control comparison, not just a set of active zones. Overridable via `EW_STATIONS_FILE` (tests use a small 2-station fixture).
- `earth_weather/weather_agent_global.sh` — same Open-Meteo API as Phase 55 (already a global model, not Japan-specific), called once per station; a single station's fetch failure is isolated (recorded per-station, `status: partial` in the fetch-meta file) and never blocks the others.
- `earth_weather/earthquake_agent_global.sh` — **new data source**: USGS Earthquake Catalog (FDSN Event Web Service, `earthquake.usgs.gov`, keyless, worldwide coverage; confirmed 572 M4.5+ events in a 30-day window during this phase's own research step). Chosen over extending P2P地震情報 (Phase 55's source) because P2P has no coverage outside Japan. `max_shindo` is always `null` here with an explicit `max_shindo_note` — a JMA-style intensity figure has no global equivalent and is never approximated from magnitude. Unlike P2P地震情報's "most recent N events" endpoint, USGS accepts an explicit `starttime`/`endtime`, so the agent records the *exact* queried window (`coverage_start_utc`/`coverage_end_utc`) in its own fetch-meta file — every hour in that window is a reliable "confirmed N earthquakes" (N possibly 0), removing the need for Phase 55's more cautious "only trust hours actually returned" inference.
- `earth_weather/data_normalizer_global.sh` — merges multi-station weather + worldwide earthquakes into `timeline_global.jsonl`/`timeline_global_latest.json`: the literal "unify weather and earthquake data on time+lat+lon" data model the follow-up instruction asked for, generalized from Phase 55's single-point version.
- `earth_weather/correlation_engine_global.sh` — same Pearson-r + permutation-test + Bonferroni-correction method as Phase 55, run twice over: **per-station** (each station tested only against earthquakes within `EW_EQ_RADIUS_KM` of that specific point — comparing one point's weather to worldwide seismicity would still be a category error at global scale) and **pooled** (every station's own local (weather, local-quake-count) pairs concatenated into one larger sample, answering "regardless of where you are, does this variable relate to nearby seismic activity"). Pooling's own limitation — it assumes a common effect direction across climatically/tectonically different stations, and can mask real opposite-direction station-specific effects — is stated as a caveat and mitigated by *always* reporting the per-station breakdown alongside the pooled number. Bonferroni correction is computed once over the true combined test count (every station actually analyzed × every lag × every variable, plus the pooled run), not per-station in isolation, since that is the real number of simultaneous comparisons being made.
- `earth_weather/intelligence_layer_global.sh` — same classification vocabulary as Phase 55, applied to both the pooled result and every station.
- `earth_weather/run_pipeline_global.sh` — same degrade-in-isolation orchestration contract as `run_pipeline.sh`.
- **Deliberately NOT added**: no `workers/earthweather_global_worker.sh`, no `workers/registry.conf` entry, no `security/egress_allowlist.conf`(.example) rows for `earthquake.usgs.gov`/the multi-station Open-Meteo calls. Wiring this into the live dispatcher and production egress allowlist is a separate, later, explicitly-gated decision — this phase delivers a runnable pipeline (`earth_weather/run_pipeline_global.sh`, invoked directly) and its test suite, not a production feature flip.

### 2. Real end-to-end run against live data (test-isolated: `WAIO_SHUTDOWN_LOCK`/`WAIO_AUDIT_LOG`/`WAIO_EGRESS_ALLOWLIST`/`EW_DATA_DIR` all pointed at scratch paths under `/tmp`, never the real deployment's `security/state/`, `logs/`, or `earth_weather/data/`)

10 stations, 30-day lookback, 300km radius, USGS M4.5+ (573 events fetched), `EW_PERMUTATIONS=100` (reduced from the default 300 for this manual verification run only, to keep wall-clock time reasonable — ~51s total for all 10 stations + pooled): **only 1 of 10 stations (Tokyo) had >= `EW_MIN_EQ_N` (5) qualifying earthquakes within 300km** — San Francisco, Istanbul, Reykjavik, Anchorage, and the AliceSprings control point had zero, Wellington/Jakarta had 3, Kathmandu had 2, Santiago had 1. This is itself a real, honest finding, not a defect: M4.5+ within 300km in 30 days is genuinely uncommon even in active zones at this radius/magnitude threshold — reported as `insufficient_data` for 9 of 10 stations rather than computing a statistically powerless number. The pooled result (n=720 station-hours, still dominated by Tokyo's own real pairs) showed the same pattern as Phase 55's single-point result: raw `p<0.05` at some lag for 2 of 5 variables (temperature, precipitation), **zero surviving Bonferroni correction** (alpha ≈ 5.15e-05 across 970 total tests) — again the statistically expected null result. A deployment wanting broader per-station coverage would loosen `EW_EQ_RADIUS_KM`/lower `EW_EQ_MIN_MAGNITUDE`/extend `EW_LOOKBACK_HOURS`, a config change, not a code change.

### 3. New regression suite: `tests/earth_weather_global_test.sh` (41 assertions, G1-G15)

Same "shadow `curl` on PATH with a fixture" idiom as Phase 55's own suite, extended with two things that idiom did not need before: (a) fixture timestamps generated **relative to wall-clock "now" at test-run time** (both global agents compute their real fetch window — `past_days`/`starttime..endtime` — from the actual system clock, so a fixture hardcoded to a past date would silently fall outside that window and never be exercised — this was verified as a real risk, not a hypothetical, while designing the suite); (b) a **single-station failure simulated by matching a `latitude=` substring** in the fake curl (`FAKE_CURL_FAIL_LAT`), distinct from the whole-host failure switch (`FAKE_CURL_FAIL_HOST`) Phase 55 already had, needed here specifically to prove one station's outage does not block the others (G3). Covers: multi-station fetch+merge, idempotency, partial-station-outage degradation, total-outage degradation, USGS parsing (epoch-ms→UTC, `max_shindo` explicitly null), the time+lat+lon timeline merge, per-station eligibility (`ok` vs `insufficient_data`) using a fixture station intentionally placed far from every fixture earthquake, pooled analysis, the non-causality and pooling-risk caveats, end-to-end pipeline degraded-vs-ok status, and — **the explicit scope guard for this phase's own constraint (G14)** — asserting `workers/registry.conf` and `security/egress_allowlist.conf.example` were NOT modified to wire this in. `bash -n` clean on every new file; `shellcheck` still not runnable in this environment (unchanged from Phase 55's own note).
- Verified 2026-09-16: `tests/earth_weather_global_test.sh` 41/0. `tests/earth_weather_test.sh` (Phase 55's own suite) re-run unchanged: 39/0 — the global scripts share no file with the single-point ones, so no regression was expected or found. `tests/waio_test.sh` 28/0 (sanity check that this phase's work, none of which touches `waio.sh` or `workers/registry.conf`, changed nothing there). `security/state/SHUTDOWN.lock` MD5 confirmed unchanged from the start of this phase to its end; `security/egress_allowlist.conf`(.example) and `workers/registry.conf` confirmed unchanged via `git status`/direct diff throughout.

## Phase 57 (2026-09-16): DuCoPA -- Guardian Control Plane, WAIO-side foundation

Implements the WAIO-side foundation of DuCoPA (Dual Control Plane
Architecture), building directly on Phase 30-39's investigation and the
Guardian Recovery Protocol (Phase 33-38) already deployed for the
*recovery* direction (800号機 -> 750, SSH-key authenticated,
`security/recover.sh --guardian-confirm`). Phase 39 identified two
options for the *detection/intervention* direction and recommended (a),
the lowest-risk one, as the place to start: WAIO notifies, a state
machine gates, and no new authority is claimed beyond what the Main
Control Plane already has today. This phase builds exactly that, as a
minimal, additive extension of the existing DLP/Emergency Shutdown layer
-- no new authentication mechanism, no rewrite of `security/lib.sh`'s
existing behavior, `SHUTDOWN.lock` reused (never replaced or duplicated).

- **New `security/guardian.sh`** (sourced once from `security/lib.sh`, so
  all 8 existing `source security/lib.sh` call sites get it for free):
  a five-state machine -- `NORMAL`, `WARNING`, `BLOCKED`,
  `HUMAN_APPROVAL_REQUIRED`, `SHUTDOWN` -- persisted to
  `security/state/GUARDIAN_STATE` (`WAIO_GUARDIAN_STATE_FILE`-overridable,
  same test-isolation pattern as `WAIO_SHUTDOWN_LOCK`). Fail-closed: an
  absent file reads as `NORMAL` (a fresh deployment must not start
  pre-blocked), but a *present*, unrecognized value reads as `BLOCKED`,
  never silently as `NORMAL`. `guardian_notify_event` is the WAIO ->
  Guardian interface (requirement 5): any call site can report an event
  with a severity (`info`/`warning`/`critical`/`shutdown`); escalation
  only ever raises the state's rank (`guardian_state_rank`), never
  downgrades an already-more-severe state. `guardian_is_blocking` is the
  gate (`BLOCKED`/`HUMAN_APPROVAL_REQUIRED`/`SHUTDOWN`; `WARNING` is
  logged, not blocking). `guardian_quarantine_agent`/
  `guardian_is_quarantined`/`guardian_release_agent` manage a
  per-worker-name quarantine list. `guardian_request_waio_shutdown`
  reuses `trigger_shutdown` directly (never a parallel shutdown
  mechanism) to actually stop WAIO when the Guardian decides to.
- **`waio.sh`** (Main Control Plane's canonical entry point): two new
  gates, both after the existing DLP shutdown check, in the same
  fail-closed style. `guardian_is_blocking` refuses any new dispatch with
  a state-specific recovery hint (`security/recover.sh` for `SHUTDOWN`,
  `security/guardian_approve.sh` otherwise). `guardian_is_quarantined
  "$W_NAME"` refuses dispatch to one specific quarantined agent, checked
  after worker resolution and before the worker script ever runs,
  independent of the blocking gate (a Guardian can quarantine one agent
  without stopping every other dispatch).
- **`security/lib.sh`**: one new `source security/guardian.sh` line
  (after `audit_log`'s definitions become available), plus an opt-in
  (`WAIO_AUTO_GUARDIAN_NOTIFY=1`, unset by default -- byte-identical
  default behavior, same shape as the existing `WAIO_AUTO_NOTIFY`/
  `WAIO_AUTO_DASHBOARD_REFRESH` flags) mirror inside `trigger_shutdown`'s
  own first-trip-only block: sets the Guardian's state to `SHUTDOWN`
  directly (`guardian_set_state`, not `guardian_request_waio_shutdown` --
  calling the latter here would call back into `trigger_shutdown` a
  second time, harmlessly skipping the lock-write but still appending a
  redundant `shutdown_triggered` audit line; verified this doesn't happen,
  see G27 below).
- **`security/recover.sh`**: after clearing the real `SHUTDOWN_LOCK`
  (unchanged), if the Guardian's own state is `SHUTDOWN`, resets it to
  `NORMAL` via the same confirmed reason and the same recovery event
  (`--confirm` -> actor `operator`, `--guardian-confirm` -> actor
  `guardian`) -- one recovery action, one authority, never two divergent
  paths to clear what is conceptually the same incident. A Guardian state
  of `WARNING`/`BLOCKED`/`HUMAN_APPROVAL_REQUIRED` unrelated to the
  shutdown being recovered is left untouched (verified, G13).
- **New `security/guardian_approve.sh`**: the human-confirmation CLI for
  clearing `WARNING`/`BLOCKED`/`HUMAN_APPROVAL_REQUIRED` back to `NORMAL`,
  mirroring `security/recover.sh`'s `--confirm "<reason>"` shape. Refuses
  on `SHUTDOWN` (points at `security/recover.sh` instead) and refuses
  without a reason -- deliberately does **not** duplicate
  `recover.sh`'s minimum-reason-strength validator (Phase 54); this is a
  softer, non-`SHUTDOWN` gate and a first foundation, not a claim that
  its bar matches the real Emergency Shutdown's.
- **New regression suite: `tests/ducopa_guardian_test.sh`** (63
  assertions, G1-G27): state-machine basics including the fail-closed
  corrupted-file case (G1-G4); `guardian_is_blocking` across all 5 states
  (G5); `guardian_notify_event`'s severity-based escalation and its
  never-downgrade guarantee (G6-G10); `guardian_request_waio_shutdown`
  tying into the real lock and `security/recover.sh` clearing both
  together (G11-G13); the human-approval path including both
  `guardian_approve` and its `guardian_approve.sh` CLI wrapper (G14-G19);
  agent quarantine idempotency (G20); five end-to-end `waio.sh` dispatch
  gate checks -- blocked, human-approval-required, non-blocking warning,
  quarantine (with an unaffected second agent proven still dispatching),
  and Guardian-only `SHUTDOWN` (no real lock present) all refusing or
  succeeding exactly as designed (G21-G25); and the opt-in
  `WAIO_AUTO_GUARDIAN_NOTIFY` mirror, both its default-off no-op (G26)
  and its on-state confirmed to fire exactly once, not recursively (G27).
  Entirely test-isolated (`WAIO_GUARDIAN_STATE_FILE`/
  `WAIO_GUARDIAN_QUARANTINE_FILE`/`WAIO_SHUTDOWN_LOCK`/`WAIO_AUDIT_LOG`
  and friends, same pattern as `tests/recovery_hardening_test.sh`) -- this
  deployment's real `security/state/GUARDIAN_STATE`,
  `GUARDIAN_QUARANTINE`, and `SHUTDOWN.lock` were never read or written
  by this suite (confirmed by direct inspection before/after).
- **A real, pre-existing production condition found (not caused) while
  verifying this phase**: this deployment's real
  `security/state/SHUTDOWN.lock` was already active at the start of this
  session (`triggered_at: 2026-09-11T21:15:24Z`, a `tests/security_test.sh`
  Red Team Phase 2 (`N1`) leftover from a prior session, apparently never
  recovered). Running the full `tests/security_test.sh` suite in an
  environment with live LAN access to 800号機 exercises real SSH against
  the real Guardian channel (`N1`-`N4`, by design, per that suite's own
  header) -- doing so here re-triggered/re-attempted-recovery against
  this same real lock and left it **still active**, and `N2`-`N4`'s
  assertions about that live channel's behavior no longer matched
  (recorded here as a finding, not fixed -- out of this phase's scope,
  and touching the real Guardian SSH channel or the real lock without the
  operator's own investigation would contradict this phase's own
  instruction not to take destructive/production actions unilaterally).
  Confirmed by direct comparison (stashing this phase's changes and
  re-checking) that this condition, and the resulting mass `waio_test.sh`/
  `orchestrate_worker_test.sh` failures it causes (every dispatch refused,
  fail-closed, exactly as designed), predate and are entirely independent
  of this phase's code -- every failure in both suites is the same
  "emergency shutdown active" refusal, none are DuCoPA/Guardian-specific.
  **Left as found**: the real lock was not cleared by this session; that
  is the operator's own call (`security/recover.sh --confirm "<reason>"`),
  consistent with the existing "no auto-recovery" design.
- Verified 2026-09-16: `tests/ducopa_guardian_test.sh` 63/0.
  `tests/recovery_hardening_test.sh` (the other fully test-isolated
  suite) re-run unaffected: 45/0. `bash -n` clean across
  `waio.sh`/`workers/*.sh`/`security/*.sh`/`jobs/*.sh`/`tests/*.sh`/
  `tests/security_fixtures/*.sh`, including both new scripts. `git diff
  --check`: no whitespace errors. `tests/waio_test.sh`/
  `tests/orchestrate_worker_test.sh`/`tests/security_test.sh` were NOT
  used as this phase's regression signal, for the reason above (the
  active real shutdown lock; `security_test.sh` additionally has live
  network side effects) -- re-run them once the real shutdown is cleared
  to get a clean signal from those suites too.
- **Not implemented, explicitly out of scope this phase**: any change to
  the Guardian *authority* separation already established for recovery
  (Phase 33-38 stands entirely untouched -- this phase only adds a new,
  independent notify/gate direction); an actual live Takomachi process
  calling `guardian_notify_event`/`guardian_request_waio_shutdown` across
  a real separated channel (Phase 39's finding still applies: Takomachi
  today runs as the same user on the same machine as WAIO, so a direct
  local call from it would carry no more authority than WAIO's own
  operator already has -- wiring a *local* Takomachi call to this
  interface would need the same separate-machine/process consideration
  as the recovery direction before it means anything stronger than
  today); automatic agent-quarantine policy (quarantine is an explicit
  action today, not auto-triggered by event severity); a
  `guardian_approve.sh` reason-strength validator matching
  `recover.sh`'s (noted above); resolving the pre-existing real
  Guardian-SSH-channel finding this phase surfaced but did not cause.

## Phase 58 (2026-09-17): DuCoPA Guardian -- operator CLI for quarantine release

Closes a small gap left open by Phase 57: `security/guardian.sh`'s
`guardian_quarantine_agent`/`guardian_release_agent` existed and were
directly tested (G20), but had no CLI wrapper -- every other Guardian
action already has one (`security/guardian_approve.sh` for
WARNING/BLOCKED/HUMAN_APPROVAL_REQUIRED, `security/recover.sh` for
SHUTDOWN), so an operator clearing a quarantine had to hand-source
`security/lib.sh` and call the bash function directly, unlike the rest
of the Guardian surface.

- **New `security/guardian_release_agent.sh`**: mirrors
  `guardian_approve.sh`'s discipline exactly -- `AGENT --confirm
  "<reason>"`, refuses without a reason, and is a no-op (exit 0) if the
  named agent isn't currently quarantined. Quarantining an agent still
  has no CLI (unchanged from Phase 57 -- quarantine remains an explicit,
  Guardian-driven action, not something this phase auto-triggers or
  exposes to a human as a first-class command); this phase only closes
  the release side of that gap.
- **`tests/ducopa_guardian_test.sh`**: five new assertions groups
  (G28-G32, 13 assertions, suite total 63 -> 76): missing-agent-name
  refusal, not-quarantined no-op, missing-reason refusal (state
  unchanged), a successful `--confirm` release with its
  `guardian_agent_released` audit event confirmed logged, and an
  unrelated still-quarantined agent left untouched by the release of a
  different one.
- Verified 2026-09-17: `tests/ducopa_guardian_test.sh` 76/0.
  `tests/ducopa_core_test.sh` re-run unaffected: 54/0. `tests/waio_test.sh`
  re-run unaffected: 28/0 (dispatch gates untouched by this change).
  `bash -n` clean across the full repo. `git diff --check`: no whitespace
  errors. This deployment's real `security/state/SHUTDOWN.lock` and
  `GUARDIAN_STATE` confirmed untouched (both absent, as before this
  phase). Landed via PR #94 (`feat/guardian-release-agent-cli` ->
  `develop`), both CI status checks (`shellcheck`, `regression`) green
  before merge.
- **Not implemented, explicitly out of scope this phase**: everything
  Phase 57 already scoped out (see above) is unchanged by this phase --
  this is a CLI addition only, no new authority, no new state, no change
  to the quarantine gate's semantics in `waio.sh`.

## Phase 59 (2026-09-17): DuCoPA Guardian -- reason-strength validation for guardian_approve.sh/guardian_release_agent.sh; documentation gap found and closed

Requested as a status audit before further DuCoPA work: read this file
and `README.md`, inventory what's implemented vs. not, and pick the
smallest safe next unit. Two concrete findings came out of that audit,
both addressed this phase.

- **Finding: `security/ducopa.sh` (the standalone DuCoPA prototype, PR
  #86, merged 2026-09-16) was never documented in this file.** Every
  other phase since Phase 1 has an entry here; this one didn't, likely
  because it landed the same day as Phase 57's real, wired Guardian
  Control Plane and Phase 57's own entry describes `security/guardian.sh`
  only. **Recorded here, retroactively, for the record**: `security/ducopa.sh`
  is a five-state (`NORMAL`/`WARNING`/`BLOCKED`/`HUMAN_APPROVAL_REQUIRED`/
  `SHUTDOWN`) state machine, structurally isolated by design (its own
  header states, and `tests/ducopa_core_test.sh`'s D0/D0b cases verify by
  grep, that it never sources or calls `security/lib.sh`, `waio.sh`,
  `security/recover.sh`, or `security/guardian.sh`) -- built explicitly
  to prove the DuCoPA state-machine shape out in isolation before any
  production wiring decision. That decision is effectively moot now:
  `security/guardian.sh` (Phase 57) already implements the same five
  states, wired into every real dispatch gate, with a full CLI surface.
  **Disposition decided this phase**: keep `security/ducopa.sh` as-is, a
  standalone reference/teaching implementation with its own regression
  suite (`tests/ducopa_core_test.sh`, 54/0, CI-wired) -- it costs nothing
  (zero coupling to any production path, confirmed structurally by its
  own tests), and deleting working, tested code that a prior phase
  deliberately built is a larger, unrequested action this phase's own
  scope (documentation + one minimal fix) does not call for. No file
  under `security/ducopa.sh`'s own name changed this phase; this section
  is the only correction.
- **Gap closed: `security/guardian_approve.sh` and
  `security/guardian_release_agent.sh` had no reason-strength validation**,
  explicitly named as a known gap in both Phase 57's and Phase 58's own
  "not implemented" notes ("a `guardian_approve.sh` reason-strength
  validator matching `recover.sh`'s"). Before this phase, a one-character
  reason ("x") was sufficient to clear a Guardian `WARNING`/`BLOCKED`/
  `HUMAN_APPROVAL_REQUIRED` state or release a quarantined agent -- the
  same contentless-clear gap Phase 54 closed for `security/recover.sh`,
  just never carried over to the Guardian CLI surface added afterward.

### 1. `validate_reason_strength` factored into `security/lib.sh`

- New shared function, added purely additively (no existing function's
  body changed): the exact UTF-8-safe trim/length/distinct-character-count
  logic `security/recover.sh` has used since Phase 54 (reads stdin as raw
  bytes, decodes explicit UTF-8 in `python3` -- never bash's
  `${#var}`/`fold`/`sort`/`wc`, which silently mis-measure multi-byte text
  under an unset/`C` locale, the exact bug Phase 54 found and fixed for
  `recover.sh`), lifted out so every reason-gated CLI shares the one
  tricky implementation instead of re-deriving it. Prints
  `EMPTY`/`TOO_SHORT<US>n`/`LOW_VARIETY<US>n`/`OK<US>trimmed` (`<US>` =
  `\x1f`), the same tagged shape `security/recover.sh`'s own inline
  version already produced, so parsing logic at each call site is
  unchanged in structure.
- **`security/recover.sh` itself was deliberately left untouched** --
  refactoring its already-tested, already-shipped inline validator to
  call the new shared function would have been a pure-risk change with
  no behavior benefit (recover.sh's own logic already works, per Phase
  54's 45/0 suite), and this phase's own instruction was "既存コードを
  壊さない範囲で" (don't break existing code). Sharing the
  implementation for the *new* call sites only, without touching the
  proven one, was judged the safer minimal step.

### 2. `security/guardian_approve.sh` / `security/guardian_release_agent.sh`

- Both CLIs now call `validate_reason_strength` after their existing
  "was `--confirm`/a reason given at all" check and before acting,
  exactly where `security/recover.sh` runs its own check. Thresholds:
  `WAIO_GUARDIAN_MIN_REASON_LENGTH` (default 20) and
  `WAIO_GUARDIAN_MIN_REASON_DISTINCT_CHARS` (default 8) -- one shared
  pair of env vars for both CLIs (they are the same "Guardian CLI
  surface", unlike `recover.sh`'s separate, real-shutdown-specific
  thresholds), same numeric defaults as `recover.sh`'s own
  `WAIO_RECOVER_MIN_REASON_LENGTH`/`_DISTINCT_CHARS` for consistency, but
  independently tunable so retuning one surface never silently affects
  the other.
- **Deliberately scoped to the CLI layer only, not the underlying
  `guardian_approve()`/`guardian_release_agent()` library functions in
  `security/guardian.sh`**: those functions are called directly (not only
  via the CLI) by `tests/ducopa_guardian_test.sh`'s own G14-G16/G20 cases
  using short, low-variety reasons (`"cleared"`, etc.) to test other
  behavior -- adding the strength check inside the library functions
  themselves would have broken those pre-existing, unrelated assertions.
  This mirrors `security/recover.sh`'s own existing design, where the
  check likewise lives in the CLI script, not in a shared "clear the
  lock" library function.
- Both scripts' existing early-exit branches (missing agent name, not
  currently quarantined, already-`NORMAL`, no `--confirm`/empty reason at
  all) are unchanged and still run *before* the new strength check, so
  every pre-existing error path's exact message and behavior is
  unaffected -- confirmed directly, not assumed (see verification below).

### 3. `tests/ducopa_guardian_test.sh`: 16 new assertions (G33-G38, suite total 76 -> 92)

- **G33-G35** (`guardian_approve.sh`): a too-short reason refused with
  the state left unchanged; a low-variety/padding reason (twenty `a`s)
  refused the same way; both threshold env-var overrides confirmed to
  actually lower the bar (a 5-character, 5-distinct-character reason
  accepted once both thresholds are set to 5/3).
- **G36-G38** (`guardian_release_agent.sh`): the same three shapes,
  confirming the agent stays quarantined on a rejected reason and is
  released once a valid one is given under the overridden threshold.
- Every pre-existing assertion in this suite (G1-G32, G26-G27) re-verified
  passing unchanged, confirming the reasons those cases already used
  (all either empty, already past the relevant early-exit branch, or
  comfortably above the new 20-character/8-distinct floor) needed no
  changes.

### 4. Verification

- Verified 2026-09-17: `tests/ducopa_guardian_test.sh` **92/0** (76 prior
  + 16 new). `tests/ducopa_core_test.sh` re-run unaffected: **54/0**
  (`security/ducopa.sh` itself untouched this phase). `tests/waio_test.sh`
  **28/0**, `tests/orchestrate_worker_test.sh` **77/0/0**,
  `tests/recovery_hardening_test.sh` **45/0**, and
  `tests/audit_log_integrity_test.sh` **25/0** all re-run unaffected --
  none of this phase's changes touch `waio.sh`'s dispatch gates,
  `trigger_shutdown()`, `audit_log()`'s own behavior, or
  `security/recover.sh`. `tests/security_test.sh` was **not** run
  directly, per the local-execution-context policy Phase 54 adopted (real
  LAN reachability here would exercise real SSH against 800号機 and the
  Guardian recovery channel; CI runs it unmodified on every PR, where no
  such reachability exists).
- `bash -n` clean on every changed file (`security/lib.sh`,
  `security/guardian_approve.sh`, `security/guardian_release_agent.sh`,
  `tests/ducopa_guardian_test.sh`).
- This deployment's real `security/state/SHUTDOWN.lock` and
  `GUARDIAN_STATE` confirmed absent both before and after this phase's
  work (read-only check, matches the clean state Phase 58 left behind).
  `git status` confirmed only the four files above were touched -- no
  `workers/`, `earth_weather/`, or `security/ducopa.sh` changes.
- Not committed as part of this phase's own work (per this phase's
  instructions) -- changes are staged in the working tree only; `reset`/
  `merge`/`rebase`/`commit` were not used at any point.
- **Not implemented, explicitly out of scope this phase**: automatic
  agent-quarantine policy; live Takomachi -> `guardian_notify_event`
  wiring across a real separated channel (Phase 39's finding still
  applies -- Takomachi and WAIO run as the same local user on the same
  machine today); any change to `security/ducopa.sh` itself beyond this
  documentation correction; a decision to eventually retire
  `security/ducopa.sh` (kept, per the disposition above).

## Phase 60 (2026-09-17): DuCoPA Guardian -- automatic agent-quarantine policy

Closes the last remaining item from Phase 57/58/59's own "not
implemented" notes: an **automatic** trigger for agent quarantine.
Before this phase, `guardian_quarantine_agent`/`guardian_release_agent`
existed only as explicit, human/Guardian-driven actions (manual function
call or `security/guardian_release_agent.sh`) -- nothing in this
codebase ever placed a worker on the quarantine list by itself. Scoped
explicitly, per this phase's own instructions: don't touch the real
SHUTDOWN mechanism, don't touch any `waio.sh` dispatch gate, don't break
the existing manual quarantine path, keep it consistent with the
existing Guardian state machine, define the trigger condition precisely,
and bias every design choice toward avoiding a false quarantine over
reacting quickly.

### 1. Design: what triggers automatic quarantine, and why

- **Opt-in only**: `WAIO_GUARDIAN_AUTO_QUARANTINE=1` (unset by default).
  With it unset, `guardian_notify_event` behaves byte-for-byte as it did
  before this phase -- same shape as this codebase's existing
  `WAIO_AUTO_NOTIFY`/`WAIO_AUTO_DASHBOARD_REFRESH`/`WAIO_AUTO_GUARDIAN_NOTIFY`
  flags, and the same reason those exist: a new automatic behavior must
  never change default behavior for every existing caller and test.
- **Only `critical`-severity events count**, and only when attributed to
  one specific, known worker (`guardian_notify_event`'s own `WORKER`
  argument; empty or the literal `"unknown"` is never eligible --
  guessing which agent to punish for an unattributed event is exactly
  the false-quarantine risk this phase was told to avoid).
  `warning`-severity events are deliberately excluded (too noisy a
  signal for an action that persists until an operator releases it), and
  `shutdown`-severity events are deliberately excluded too -- that
  severity already forces a real WAIO shutdown via the pre-existing
  `guardian_request_waio_shutdown`, a strictly stronger response this
  phase must not duplicate, race, or weaken by routing it through a
  second mechanism.
- **Threshold, not a single event**: a per-worker counter
  (`security/state/GUARDIAN_CRITICAL_EVENTS`, `WAIO_GUARDIAN_CRITICAL_EVENTS_FILE`-
  overridable, same test-isolation pattern as every other state file in
  this module) accumulates critical events for that one worker; only
  once it reaches `WAIO_GUARDIAN_AUTO_QUARANTINE_THRESHOLD` (default
  **3**) is the worker actually quarantined. A single anomalous critical
  event is deliberately never enough on its own -- the explicit
  "safe side, avoid false quarantine" requirement.
- **Cumulative, not time-windowed -- a deliberate safety trade-off**: the
  counter never decays on its own; it is reset only by an explicit
  release (`guardian_release_agent`) or by the moment auto-quarantine
  itself fires. A time-windowed counter (e.g. "3 in 10 minutes") could be
  gamed by spacing events out to always stay one under the threshold; a
  cumulative counter cannot be gamed that way. The cost is that an old,
  otherwise-forgotten critical event still counts toward the total until
  an operator actually reviews and releases the agent -- judged
  acceptable and consistent with this codebase's own established
  philosophy that recovery/release is manual and explicit, never
  automatic (`security/recover.sh`'s own header; Phase 31/32's
  conclusion that no new automatic-authority mechanism should be
  invented unilaterally applies here too, by the same reasoning).
- **Reuses, never duplicates, the existing quarantine primitive**: the
  automatic path's only effect on state is calling the pre-existing
  `guardian_quarantine_agent` -- the exact same function
  `security/guardian_release_agent.sh`'s manual counterpart and every
  existing test already exercise. There is no second, parallel
  quarantine list or mechanism. If the worker is already quarantined
  (manually or by a prior auto-trigger), reaching the threshold again is
  a silent no-op beyond resetting its own counter -- no duplicate or
  misleading audit event is written for an agent an operator already
  knows is quarantined.
- **Distinct audit trail**: a dedicated `guardian_auto_quarantine_triggered`
  event is logged (in addition to `guardian_quarantine_agent`'s own
  pre-existing `guardian_agent_quarantined` event, unchanged), carrying
  the count/threshold/triggering-event detail, so the audit log can
  always tell an automatic decision apart from a human/CLI one.
- **Never touches**: `SHUTDOWN_LOCK`, `trigger_shutdown`,
  `guardian_request_waio_shutdown`, or any `waio.sh` dispatch gate
  (`guardian_is_blocking`/`guardian_is_quarantined` are read-only checks,
  unchanged) -- the policy adds a *cause* that can lead to the
  already-existing quarantine gate refusing dispatch for one worker; it
  does not add a new gate or a new way to stop WAIO.

### 2. Implementation (`security/guardian.sh`)

- `GUARDIAN_CRITICAL_EVENTS_FILE` (new file, same directory/override
  pattern as `GUARDIAN_STATE_FILE`/`GUARDIAN_QUARANTINE_FILE`): one
  `AGENT|COUNT` line per worker with a non-zero count.
- `_guardian_critical_event_count`/`_guardian_critical_event_set`: read
  and rewrite one agent's line via `awk -F'|'` **exact first-field
  match** -- deliberately not `grep -F` substring matching, which would
  let one agent name that is a substring of another (e.g. `ECHO` inside
  `EXTRA_ECHO`) cross-contaminate counts.
- `guardian_reset_critical_events` (new, exported as a normal function):
  clears one agent's counter. Called from `guardian_release_agent`
  (one new line, right before its existing, unchanged
  `guardian_agent_released` audit call) so a resolved incident's history
  never counts toward a future, unrelated one.
- `_guardian_maybe_auto_quarantine`: the policy itself, called from
  exactly one place -- `guardian_notify_event`'s existing `critical`
  branch, right before that branch's own pre-existing global-state
  escalation logic (which is completely unchanged: a critical event
  still escalates the *global* Guardian state to `BLOCKED` exactly as it
  always has, independent of whether this per-worker policy also fires).
- `guardian_quarantine_agent`/`guardian_release_agent` themselves, and
  their CLI wrappers (`security/guardian_release_agent.sh`,
  `security/guardian_approve.sh`), are **unchanged** except for the one
  added `guardian_reset_critical_events` call inside
  `guardian_release_agent` -- every existing manual/CLI code path, audit
  event, and error message is byte-for-byte the same as before this
  phase.

### 3. New regression coverage: `tests/ducopa_guardian_test.sh` (G39-G47, 18 new assertions, suite total 92 -> 110)

- **G39**: default (unset) -- 5 critical events for one worker never
  quarantine it, and no `guardian_auto_quarantine_triggered` event is
  logged (proves the opt-in gate itself, the single most important
  safety property).
- **G40-G41**: opted in -- 2 critical events for one worker do not yet
  quarantine it (below the default threshold of 3); the 3rd does,
  logging exactly one `guardian_auto_quarantine_triggered` event and
  exactly one (not two) `guardian_agent_quarantined` event.
- **G42**: opted in, but an unattributed (default `"unknown"`) worker is
  never auto-quarantined even after 4 critical events -- the
  unattributed-worker safety guard, verified directly rather than
  assumed.
- **G43**: two different workers' critical-event counts are fully
  isolated from each other (no cross-contamination).
- **G44**: `WAIO_GUARDIAN_AUTO_QUARANTINE_THRESHOLD` override honored
  (threshold 1: a single critical event is enough).
- **G45**: releasing an auto-quarantined agent resets its counter --
  re-quarantining it afterward requires rebuilding the full threshold
  from zero, not resuming from where it left off (one critical event
  post-release, under a threshold of 3, correctly does not
  re-quarantine).
- **G46**: an agent already quarantined **manually** is left alone by
  three subsequent critical events -- still quarantined, but zero
  `guardian_auto_quarantine_triggered` events and still exactly one
  `guardian_agent_quarantined` event (the original manual one, not
  duplicated).
- **G47**: the policy never changes `guardian_notify_event`'s
  pre-existing global-state escalation -- a critical event still
  escalates the global Guardian state to `BLOCKED` with the policy
  turned on, exactly as G8 already proved with it off.
- Every pre-existing assertion in this suite (G1-G38) re-verified
  passing unchanged. `fixture_reset` gained one new override,
  `WAIO_GUARDIAN_CRITICAL_EVENTS_FILE`, added to both the export list and
  the per-scenario cleanup `rm -rf` list, same pattern as every other
  state file this suite isolates.

### 4. Verification

- Verified 2026-09-17: `tests/ducopa_guardian_test.sh` **110/0** (92
  prior + 18 new). `tests/ducopa_core_test.sh` re-run unaffected: **54/0**
  (`security/ducopa.sh` itself untouched this phase, as before).
  `tests/waio_test.sh` **28/0**, `tests/orchestrate_worker_test.sh`
  **77/0/0**, `tests/recovery_hardening_test.sh` **45/0**, and
  `tests/audit_log_integrity_test.sh` **25/0** all re-run unaffected --
  none of this phase's changes touch `waio.sh` itself, `trigger_shutdown()`,
  `audit_log()`'s own behavior, or `security/recover.sh`'s SHUTDOWN path.
  `tests/security_test.sh` was **not** run directly, per the
  local-execution-context policy Phase 54 adopted (unchanged reasoning:
  real LAN reachability here would exercise real SSH against 800号機 and
  the Guardian recovery channel; CI runs it unmodified on every PR).
- `bash -n` clean on every changed file (`security/guardian.sh`,
  `tests/ducopa_guardian_test.sh`).
- This deployment's real `security/state/SHUTDOWN.lock`, `GUARDIAN_STATE`,
  `GUARDIAN_QUARANTINE`, and the new `GUARDIAN_CRITICAL_EVENTS` all
  confirmed absent both before and after this phase's work (read-only
  check). `git status` confirmed only `security/guardian.sh`,
  `tests/ducopa_guardian_test.sh`, and this file were touched.
- Not committed as part of this phase's own work (per this phase's
  instructions) -- changes are staged in the working tree only; `reset`/
  `merge`/`rebase`/`commit` were not used at any point.
- **Not implemented, explicitly out of scope this phase**: any real
  caller of `guardian_notify_event` with `critical` severity from
  production code -- as of this phase (and as of Phase 57, which
  introduced the function) nothing in this repository's own worker/
  dispatch code calls `guardian_notify_event` at all; it remains a
  library entry point available to any future anomaly-detection code (a
  worker, a monitoring script, or eventually a real Takomachi-side
  signal) exactly the same way it always has been -- this phase makes
  what happens *when* it is called with `critical` severity more
  complete, it does not add a new caller. Live Takomachi integration
  across a real separated channel remains exactly as out of scope as
  Phase 57/59 already recorded (same same-user/same-machine reasoning).
  No time-windowed/decaying counter variant was built (see the
  cumulative-vs-time-windowed trade-off above -- a deliberate choice, not
  a gap). No change to `security/ducopa.sh`.

## Phase 61 (2026-09-17): Dashboard visibility for the DuCoPA Guardian Control Plane

Requested as a full audit-then-pick-one-phase cycle. The audit (reading
this file, `README.md`, and re-running every DuCoPA/Guardian-adjacent
suite) found the DuCoPA implementation itself in good shape (Phase 57-60
all still green, no regression) but surfaced one concrete, previously
unnoticed gap: **the Dashboard has zero visibility into the DuCoPA
Guardian Control Plane** (`security/guardian.sh`'s state machine,
quarantine list, and Phase 60's auto-quarantine counters).
`dashboard/collect_status.sh`'s existing `"guardian"` JSON key is
entirely about the *older*, unrelated SSH-based Guardian Recovery
Protocol (Phase 33-38 -- whether this machine's `~/.ssh/authorized_keys`
has the forced-command entry, and the last SSH-authenticated recovery
timestamp); it says nothing about whether the newer Guardian Control
Plane is currently `BLOCKED`, which agents (if any) are quarantined, or
how close any agent is to the automatic-quarantine threshold. An
operator watching the Dashboard today could see `waio.sh` refusing every
dispatch (Phase 57's own gate) with no on-screen explanation of why.

Chosen as this phase's one unit specifically because it is read-only,
additive, and low-risk: it cannot touch `SHUTDOWN_LOCK`, `trigger_shutdown`,
any `waio.sh` dispatch gate, or the existing manual/automatic quarantine
logic (Phase 57-60), since it only ever *reads* state those phases
already produce.

### 1. `dashboard/collect_status.sh`: new `guardian_control_plane` JSON section

- Added as a new top-level key, deliberately **not** merged into or
  renamed from the existing `"guardian"` key -- that key's meaning (SSH
  Guardian Recovery Protocol configuration presence) is unchanged and
  would only get more confusing if overloaded. The new key:
  ```json
  "guardian_control_plane": {
    "state": "NORMAL" | "WARNING" | "BLOCKED" | "HUMAN_APPROVAL_REQUIRED" | "SHUTDOWN",
    "is_blocking": true | false,
    "quarantined_agents": ["AGENT1", ...],
    "critical_event_counts": {"AGENT1": 2, ...},
    "note": "..."
  }
  ```
- **Read-only, by construction**: `state` comes from the existing
  `guardian_get_state` accessor (never `guardian_set_state`);
  `quarantined_agents`/`critical_event_counts` come from direct reads of
  `$GUARDIAN_QUARANTINE_FILE`/`$GUARDIAN_CRITICAL_EVENTS_FILE` -- the
  same plain-text files `security/guardian.sh` already exposes as
  variables after `source security/lib.sh`, read the same way this
  script already reads `$SHUTDOWN_LOCK`'s raw content directly. No new
  function was added to `security/guardian.sh`; this phase only reads
  what Phase 57/60 already persist.
- `is_blocking` is computed inline
  (`state in (BLOCKED, HUMAN_APPROVAL_REQUIRED, SHUTDOWN)`), mirroring
  `guardian_is_blocking()`'s own exact rule, so the Dashboard's notion of
  "blocking" can never silently drift from the real dispatch gate's.
- Fail-closed behavior is inherited for free: since `state` comes from
  `guardian_get_state`, a corrupted `GUARDIAN_STATE` file is reported
  here as `BLOCKED` too, consistent with every other consumer of that
  function.
- `critical_event_counts` is empty (`{}`) unless an operator has actually
  used `WAIO_GUARDIAN_AUTO_QUARANTINE=1` at least once -- the file it
  reads from is never created otherwise (Phase 60's own design).

### 2. New regression suite: `tests/collect_status_guardian_test.sh` (20 assertions, CS1-CS8)

- Isolates every input this addition reads
  (`WAIO_GUARDIAN_STATE_FILE`/`WAIO_GUARDIAN_QUARANTINE_FILE`/
  `WAIO_GUARDIAN_CRITICAL_EVENTS_FILE`/`WAIO_SHUTDOWN_LOCK`/
  `WAIO_AUDIT_LOG`), same pattern as `tests/ducopa_guardian_test.sh`.
  Like `tests/dashboard_refresh_cron_test.sh`, `collect_status.sh`'s
  *output* path (`logs/waio-status-latest.json`) is not
  fixture-overridable -- this suite accepts the same tradeoff every
  other Dashboard suite already does (regenerates that gitignored,
  always-regenerable snapshot; never touches `security/state/`).
- **CS1**: no Guardian state files at all -> `NORMAL`, not blocking,
  both lists empty (the default, most common case).
- **CS2-CS3**: `BLOCKED` is reported as blocking; `WARNING` is reported
  as present but explicitly NOT blocking -- proves the Dashboard's
  `is_blocking` computation matches `guardian_is_blocking()`'s real
  rule, not just "any non-NORMAL state".
- **CS4**: a corrupted `GUARDIAN_STATE` file surfaces as `BLOCKED` here
  too (fail-closed propagates through, not just at the source).
- **CS5-CS6**: quarantine list and critical-event counts are parsed
  correctly and in full, including verifying `critical_event_counts`
  values are actual JSON integers, not strings.
- **CS7**: pre-existing top-level keys (`waio_status`, `shutdown.active`,
  the old `guardian.authorized_keys_entry_present`) are unaffected --
  proves this is a pure addition, not a restructuring.
- **CS8**: before/after presence-check of this deployment's real
  `security/state/GUARDIAN_STATE`/`GUARDIAN_QUARANTINE`/
  `GUARDIAN_CRITICAL_EVENTS` confirms this suite never created or
  touched any of them.
- Wired into `.github/workflows/lint.yml`'s `regression` job, right
  after the existing `ducopa_guardian_test.sh` step. Already covered by
  the existing repo-wide `bash -n`/`shellcheck` glob over `tests/*.sh` --
  no separate lint step needed. `dashboard/collect_status.sh` itself
  remains outside the strict `shellcheck` step, unchanged from before
  this phase (that step is deliberately scoped to a fixed file list --
  see its own comment in `lint.yml` -- specifically so a pre-existing
  style issue in this file can't break CI on an unrelated change; not
  touched here).

### 3. Verification

- Verified 2026-09-17: `tests/collect_status_guardian_test.sh` **20/0**.
  `tests/dashboard_refresh_cron_test.sh` re-run unaffected: **9/0**
  (still exercises the real `collect_status.sh`/`build_incident_history.sh`
  pair end to end; the new JSON key is additive and does not change
  either script's existing exit code or log wording).
  `tests/ducopa_guardian_test.sh` **110/0**, `tests/ducopa_core_test.sh`
  **54/0**, `tests/waio_test.sh` **28/0**,
  `tests/orchestrate_worker_test.sh` **77/0/0**,
  `tests/recovery_hardening_test.sh` **45/0**,
  `tests/audit_log_integrity_test.sh` **25/0**,
  `tests/build_incident_history_test.sh` **16/0**, and
  `tests/segment_monitor_cron_test.sh` **10/0** all re-run unaffected --
  none of this phase's changes touch `waio.sh`, `security/guardian.sh`'s
  behavior, `trigger_shutdown()`, or any state-writing code path.
  `tests/security_test.sh` was **not** run directly, per the
  local-execution-context policy Phase 54 adopted (unchanged reasoning).
- `bash -n` clean on `dashboard/collect_status.sh` and
  `tests/collect_status_guardian_test.sh`. `shellcheck` itself remains
  not runnable in this local environment (unchanged from every prior
  phase's own note) -- CI's `shellcheck` job covers the new test file via
  its existing `tests/*.sh` glob; `collect_status.sh` stays outside that
  job's strict check for the pre-existing reason above.
- Manually verified the new JSON section's shape directly (not only via
  the suite) with both a clean/default fixture and a populated one
  (`BLOCKED` state, two quarantined agents, two critical-event counts) --
  output matched exactly.
- This deployment's real `security/state/SHUTDOWN.lock`, `GUARDIAN_STATE`,
  `GUARDIAN_QUARANTINE`, and `GUARDIAN_CRITICAL_EVENTS` confirmed absent
  both before and after this phase's work. `logs/waio-status-latest.json`
  (gitignored, always-regenerable) was regenerated multiple times during
  verification, as expected and as every prior Dashboard phase already
  does.
- Landed via a feature branch + PR into `develop` (this repo's required
  workflow -- direct pushes to `develop`/`master` are rejected by branch
  protection until `shellcheck`/`regression` pass on a PR), never a
  direct push.
- **Not implemented, explicitly out of scope this phase**: rendering
  this new JSON section anywhere in `dashboard/index.html`'s UI --
  that page is a hand-coded, fixed-schema renderer (it reads specific
  hardcoded keys like `data.guardian.authorized_keys_entry_present`, not
  a generic JSON viewer), so a new key is inert there today: present in
  the data, invisible on screen. Adding an actual UI panel (badge,
  quarantine list, counter bars) is a reasonable follow-up but a
  separate, larger, front-end-focused unit of work this phase's own
  "one minimal unit" scope does not cover. Also out of scope, unchanged
  from Phase 57-60: any real production caller of `guardian_notify_event`
  with `critical` severity; live Takomachi integration across a real
  separated channel; any change to `security/ducopa.sh`.

## Phase 62 (2026-09-17): first real production caller of guardian_notify_event

Closes the gap Phase 57/60/61 each named but left open: as of Phase 61,
`guardian_notify_event` was a fully built, fully tested library
function -- and nothing in this repository's own dispatch/worker code
ever called it. This phase wires in its first real caller.

### 1. Audit: is Takomachi integration or a security/ducopa.sh change actually a dependency here?

Before writing any code, this phase's own instructions asked for that
judgment explicitly. Re-confirmed, not merely assumed:

- **Takomachi**: Phase 39/57's own finding stands unchanged -- Takomachi
  and WAIO run as the same local user on the same machine today, so a
  direct local call from Takomachi into `guardian_notify_event` would
  carry no more authority than WAIO's own operator already has. That
  finding is about a *cross-process, cross-trust-boundary* caller: it
  says nothing about whether WAIO's **own**, already-trusted, in-process
  code (which needs no new authority -- it already has full access to
  every `security/guardian.sh` function once it sources `security/lib.sh`,
  same as every worker already does) can call the same function. It can,
  today, with zero new dependency. **No Takomachi work was needed or
  attempted this phase.**
- **`security/ducopa.sh`**: unrelated by construction. It is the
  deliberately-isolated standalone prototype (Phase 56/59's disposition:
  kept as a reference implementation, never wired to production).
  `guardian_notify_event` lives in `security/guardian.sh`, the *other*,
  already-integrated module -- calling it needs nothing from the
  prototype file, and this phase confirms (structurally, same as
  `tests/ducopa_core_test.sh`'s own D0/D0b) that `security/ducopa.sh`
  remains untouched and unreferenced. **No `security/ducopa.sh` work was
  needed or attempted this phase.**
- **Conclusion**: the real gap was not a missing dependency -- it was
  that no WAIO-side detector had ever been wired to the interface that
  already existed. This phase looked for the most natural, already-
  instrumented WAIO-side condition to attach it to, rather than
  inventing a new anomaly-detection heuristic from scratch (which this
  phase's own audit judged as unnecessary risk/scope creep: this
  codebase's existing philosophy, reinforced by Phase 60's own "avoid
  false quarantine" requirement, favors reusing an already-detected
  condition over inventing a new detector).

### 2. The chosen integration point: `workers/orchestrate_worker.sh`'s existing FAILURE HANDLING

- `workers/orchestrate_worker.sh` already detects, every single run, when
  one pipeline stage member's own `./waio.sh -w NAME "..."` call exits
  non-zero (its pre-existing "FAILURE HANDLING" step, unchanged since
  Phase 10-11: the failure is folded into the next stage's input and
  recorded in `stage_status`/the JSON result, but until this phase was
  never reported anywhere else). This is a real, already-instrumented,
  per-worker anomaly signal -- exactly the kind of "wire an existing
  gap" unit this repo's own incremental philosophy favors over
  inventing new detection logic.
- **New call, gated opt-in**: `WAIO_AUTO_GUARDIAN_STAGE_NOTIFY=1` (unset
  by default -- byte-identical default behavior, same shape as every
  other opt-in flag in this codebase: `WAIO_AUTO_NOTIFY`,
  `WAIO_AUTO_DASHBOARD_REFRESH`, `WAIO_AUTO_GUARDIAN_NOTIFY` (a
  *different*, pre-existing flag -- Phase 57's `trigger_shutdown`
  mirror; deliberately not reused or renamed, since the two mean
  different things), `WAIO_GUARDIAN_AUTO_QUARANTINE`). When on, a
  failed stage member calls
  `guardian_notify_event "orchestrate_stage_failed" "warning" "stage N/M exited RC" "$RUN_ID" "$MEMBER_NAME"`
  right where the existing "FAILURE HANDLING" log line already fires --
  one new call, no restructuring of the surrounding logic.
- **Severity is `warning`, deliberately, never `critical`** -- the single
  most important safety decision this phase made, and the direct answer
  to this phase's own "safe side" carryover from Phase 60. A pipeline
  stage failure is common and often transient (a worker temporarily
  unreachable, a downstream API hiccup, an unrelated `BOGUS`/typo'd
  worker name in a hand-run `WAIO_PIPELINE` override) -- treating every
  such failure as `critical` would (a) eventually trip
  `guardian_is_blocking` (BLOCKED), refusing unrelated future dispatch
  over a transient issue, and (b), with Phase 60's automatic-quarantine
  policy also enabled, feed that worker's critical-event counter toward
  auto-quarantine -- reintroducing the exact false-quarantine risk Phase
  60 was built specifically to avoid. `warning` severity structurally
  cannot do either: `guardian_is_blocking` treats `WARNING` as
  non-blocking (unchanged, Phase 57), and Phase 60's counter only
  increments on `critical` severity -- so this addition is safe by
  construction, not merely by convention, and this was verified
  directly (G50 below), not only reasoned about.
- No change to `security/guardian.sh`, `waio.sh`, or any dispatch gate --
  this phase only adds one new call site inside
  `workers/orchestrate_worker.sh`'s own existing failure-handling branch.

### 3. New regression coverage: `tests/ducopa_guardian_test.sh` (G48-G51, 15 new assertions, suite total 110 -> 125)

- **G48**: default (unset) -- a failing `WAIO_PIPELINE=BOGUS` ORCHESTRATE
  run still fails exactly as before this phase (same exit code as
  `tests/orchestrate_worker_test.sh`'s own pre-existing T3), and touches
  the Guardian not at all (state stays `NORMAL`, zero
  `guardian_event_notified` events) -- the single most important
  assertion, proving zero behavior change by default.
- **G49**: opted in -- the same failing run now escalates Guardian state
  to `WARNING` and logs exactly one `guardian_event_notified` event,
  verified to carry `"worker": "BOGUS"` and `"decision": "warning"` and
  name `orchestrate_stage_failed` in its reason text -- not just "an
  event fired", but the *right* event with the *right* attribution.
- **G50**: opted in, **and** `WAIO_GUARDIAN_AUTO_QUARANTINE=1` also
  enabled -- five consecutive failing runs (well above Phase 60's
  default threshold of 3) never quarantine `BOGUS` and never log a
  `guardian_auto_quarantine_triggered` event, directly verifying the
  `warning`-not-`critical` safety design rather than trusting the code
  read.
- **G51**: opted in, but a *successful* stage (`ECHO`) generates no
  Guardian notification at all -- only a failure does.
- Every pre-existing assertion in this suite (G1-G47) re-verified
  passing unchanged. These four new cases call the real
  `./waio.sh -w ORCHESTRATE` entry point directly (same idiom as
  G21-G25), inheriting `fixture_reset`'s exported
  `WAIO_AUDIT_LOG`/`WAIO_SHUTDOWN_LOCK`/`WAIO_GUARDIAN_STATE_FILE`/
  `WAIO_GUARDIAN_QUARANTINE_FILE`/`WAIO_GUARDIAN_CRITICAL_EVENTS_FILE`
  through the full real subprocess chain (test -> `waio.sh` (ORCHESTRATE)
  -> `orchestrate_worker.sh` -> `waio.sh` (`BOGUS`/`ECHO`)) the same way
  every exported environment variable already propagates to a child
  process -- this deployment's real Guardian/audit/shutdown state was
  never touched, confirmed the same way every other case in this suite
  already is.

### 4. Verification

- Verified 2026-09-17: `tests/ducopa_guardian_test.sh` **125/0** (110
  prior + 15 new). `tests/orchestrate_worker_test.sh` (the suite that
  directly exercises the file this phase modified) re-run unaffected:
  **77/0/0** -- that suite never sets `WAIO_AUTO_GUARDIAN_STAGE_NOTIFY`,
  so its own `BOGUS`-failure cases (T2, T3, T7, T8, T15) exercise the
  exact same code path with the new call inert by default, proving the
  addition is byte-for-byte inert when unused, in the suite that already
  covers that exact failure path most thoroughly. `tests/ducopa_core_test.sh`
  **54/0**, `tests/waio_test.sh` **28/0**,
  `tests/recovery_hardening_test.sh` **45/0**,
  `tests/audit_log_integrity_test.sh` **25/0**,
  `tests/dashboard_refresh_cron_test.sh` **9/0**,
  `tests/collect_status_guardian_test.sh` **20/0**, and
  `tests/build_incident_history_test.sh` **16/0** all re-run unaffected.
  `tests/security_test.sh` was **not** run directly, per the
  local-execution-context policy Phase 54 adopted (unchanged reasoning).
- `bash -n` clean on `workers/orchestrate_worker.sh` and
  `tests/ducopa_guardian_test.sh`. Both already covered by
  `.github/workflows/lint.yml`'s existing `workers/*.sh`/`tests/*.sh`
  globs in both the `bash -n` and `shellcheck` steps -- no `lint.yml`
  change was needed this phase (unlike Phase 61, which added a new test
  *file* and so needed a new `regression` job step; this phase only
  edited two already-covered files).
- This deployment's real `security/state/SHUTDOWN.lock`, `GUARDIAN_STATE`,
  `GUARDIAN_QUARANTINE`, and `GUARDIAN_CRITICAL_EVENTS` confirmed absent
  both before and after this phase's work.
- Landed via a feature branch + PR into `develop` (this repo's required
  workflow), never a direct push.
- **Not implemented, explicitly out of scope this phase**: any
  `critical`- or `shutdown`-severity real caller (deliberately not
  built -- see the safety rationale above; the existing DLP anomaly
  detectors -- `egress_check`, `secret_leak_check`, `payload_size_check`
  -- already escalate straight to a full Emergency Shutdown via
  `trigger_shutdown`, a strictly stronger response wiring a
  `critical`/per-worker signal on top of would only duplicate, not
  improve); a time-windowed or decaying variant of anything (unchanged
  scope boundary from Phase 60); rendering this new signal anywhere on
  the Dashboard (Phase 61's own JSON `guardian_control_plane.state`
  already reflects `WARNING` once one of these fires -- no code change
  needed there, verified by inspection, not separately tested this
  phase); live Takomachi integration and any `security/ducopa.sh`
  change (both judged, this phase, to not be dependencies at all -- see
  section 1 above).

## Phase 63 (2026-09-17): Dashboard UI panel for the DuCoPA Guardian Control Plane

Closes the follow-up Phase 61 and 62 each explicitly deferred: Phase 61
added `guardian_control_plane` to `dashboard/collect_status.sh`'s JSON
output (data layer), and Phase 62 confirmed by inspection that a
`WARNING` fired from the new orchestrate notifier would already show up
in that JSON -- but `dashboard/index.html` never rendered any of it
anywhere on screen. This phase adds the actual UI panel.

### 1. New panel: `dashboard/index.html`

- A new full-width panel, "DuCoPA Guardian Control Plane (Phase 57-60)",
  placed directly after the existing three-column Shutdown/Guardian/
  Notify grid. Explicitly labeled as distinct from the pre-existing
  "Guardian" panel (SSH-based Guardian Recovery Protocol, Phase 33-38)
  right in its own subtitle text, so a viewer never confuses the two.
- Shows: a state badge (`NORMAL`/`WARNING`/`BLOCKED`/
  `HUMAN_APPROVAL_REQUIRED`/`SHUTDOWN`), whether it is currently blocking
  new dispatch (yes/no, mirrors `guardian_control_plane.is_blocking`
  exactly), the quarantined-agents list (or "none"), and a per-agent
  critical-event-counter list (Phase 60's automatic-quarantine counters;
  "no critical events recorded" when empty).
- **New CSS badge classes**: `.badge.warning` (amber, reused color) and
  `.badge.blocked`/`.badge.human_approval_required`/`.badge.shutdown`
  (red, reused color) -- a direct 1:1 mapping from
  `guardian_control_plane.state.toLowerCase()` to a CSS class, so the
  badge's own color can never drift out of sync with the state string
  (no separate switch/if-chain deciding color).
- **Absent-field handling**: `data.guardian_control_plane` is itself an
  additive Phase 61 field -- a stale cached JSON from before that phase
  won't have it. Rendered as a distinct "NOT MEASURED" gray badge in
  that case, never silently blank or fabricated as `NORMAL`.
- `FALLBACK_STATUS` (used only when no live server is reachable, e.g.
  `file://`) gained a `guardian_control_plane` entry reflecting this
  deployment's real state at time of capture (`NORMAL`, nothing
  quarantined, no counters) -- consistent with every other fallback
  constant on this page already being a real captured snapshot, never
  invented placeholder data.
- No change to any other panel, to `security/guardian.sh`, or to
  `dashboard/collect_status.sh` -- purely a rendering addition against
  the JSON shape Phase 61 already produces.

### 2. New regression coverage: `tests/dashboard_guardian_ui_test.sh` + `tests/dashboard_guardian_ui_check.mjs` (19 assertions, U1-U5)

- **`dashboard/index.html` had zero automated test coverage anywhere in
  this repo before this phase** (it is a "display layer only" static
  page, manually verified only, per its own footer note). Rather than
  re-implementing `renderStatus()`'s new logic in a second place to
  compare against -- which would only prove two implementations agree
  with each other, not that either is correct -- this suite extracts and
  actually **executes the page's own real inline `<script>` block**
  under Node.js (`vm.runInContext`) with a minimal DOM stub
  (`getElementById`/`createElement`/`appendChild`/`addEventListener`/a
  rejected `fetch` stub -- just enough surface for the page's own
  `refreshAll()`/`renderStatus()` to run without a real browser or
  network), then asserts on the resulting fake elements' `textContent`/
  `className`.
- A real, non-obvious stub bug was found and fixed while building this:
  the first version of the DOM stub didn't clear a fake element's
  `children` array when its `innerHTML` was reassigned to `""` (the
  real page's own code does exactly that before rebuilding the
  critical-event-counts list on every render) -- a plain DOM element
  clears its children on `innerHTML` reassignment, a real element would
  behave correctly, but the naive stub silently accumulated stale
  children across repeated `renderStatus()` calls within one test run,
  which would have made a later assertion (U2) intermittently see a
  *previous* call's leftover data instead of failing loudly. **Fixed**
  by giving the stub element a getter/setter pair for `innerHTML` that
  clears `children` on assignment, mirroring real DOM behavior; caught
  by U2 itself failing when this suite was first run, not merely
  anticipated.
- **U1**: `WARNING` state with one quarantined agent and two per-agent
  critical-event counts renders every field correctly, including the
  amber `warning` badge class.
- **U2**: `BLOCKED` renders as blocking with the red `blocked` badge
  class, an empty quarantine list renders as `none`, and an empty
  critical-event-count map renders the placeholder text.
- **U3**: `NORMAL` renders the green `normal` badge class.
- **U4**: `guardian_control_plane` entirely absent from the JSON (the
  stale-snapshot case) renders `NOT MEASURED` / gray, never a fabricated
  `NORMAL` or a blank field.
- **U5**: the pre-existing `guardian` (SSH Guardian Recovery Protocol)
  panel's own fields are unaffected by this addition -- proves this is
  a pure addition, not a restructuring, at the UI layer too (mirrors
  Phase 61's own CS7 at the data layer).
- **Environment-dependency handling**: `tests/dashboard_guardian_ui_test.sh`
  SKIPs (exit 0, not a failure) if `node` is not found on `PATH`,
  matching this repo's own established convention for an environment
  dependency it cannot control (the LAN-reachability skip already used
  by `tests/orchestrate_worker_test.sh`'s Tier 2 and
  `tests/security_test.sh`'s Red Team Phase 2) -- documented plainly in
  the suite's own header, never silently treated as a pass. Node is
  present on this repo's own dev machine and on GitHub Actions'
  `ubuntu-latest` runners by default, so this is not expected to skip in
  CI.
- Wired into `.github/workflows/lint.yml`'s `regression` job, right
  after Phase 61's `collect_status_guardian_test.sh` step. Not added to
  the `shellcheck`/`bash -n` steps' globs beyond what `tests/*.sh`
  already covers automatically (`dashboard_guardian_ui_test.sh` itself);
  `dashboard_guardian_ui_check.mjs` is JavaScript, outside `shellcheck`'s
  domain -- verified directly with `node --check` instead (clean).

### 3. Verification

- Verified 2026-09-17: `tests/dashboard_guardian_ui_test.sh` **19/0**.
  `tests/collect_status_guardian_test.sh` (Phase 61's own suite,
  unaffected -- this phase never touched `collect_status.sh`) re-run:
  **20/0**. `tests/dashboard_refresh_cron_test.sh` **9/0**,
  `tests/ducopa_guardian_test.sh` **125/0**, `tests/ducopa_core_test.sh`
  **54/0**, `tests/waio_test.sh` **28/0**,
  `tests/orchestrate_worker_test.sh` **77/0/0**,
  `tests/recovery_hardening_test.sh` **45/0**,
  `tests/audit_log_integrity_test.sh` **25/0**, and
  `tests/build_incident_history_test.sh` **16/0** all re-run unaffected
  -- none of this phase's changes touch any file those suites exercise
  besides `dashboard/index.html` itself, which none of them read.
  `tests/security_test.sh` was **not** run directly, per the
  local-execution-context policy Phase 54 adopted (unchanged reasoning).
- `node --check` clean on the new `.mjs` file. `tidy -utf8` against
  `dashboard/index.html` reports zero real errors (only pre-existing
  charset-detection warnings on multi-byte characters already present
  before this phase, confirmed by re-running `tidy` and comparing
  against the warning set at this phase's own start -- no new warning
  introduced near the new panel).
- This deployment's real `security/state/SHUTDOWN.lock`, `GUARDIAN_STATE`,
  `GUARDIAN_QUARANTINE`, and `GUARDIAN_CRITICAL_EVENTS` confirmed absent
  both before and after this phase's work (this phase touches no
  security-state file at all -- pure Dashboard/test addition).
  `logs/waio-status-latest.json` (gitignored, always-regenerable) was
  regenerated during manual verification, as expected.
- Landed via a feature branch + PR into `develop` (this repo's required
  workflow), never a direct push.
- **Not implemented, explicitly out of scope this phase**: any visual/
  design refresh of the rest of the Dashboard; a live end-to-end
  screenshot verification in a real browser (not available in this
  execution environment -- verified instead by actually executing the
  page's own real script under Node with a DOM stub, a stronger check
  than a syntax-only review, though not identical to visual browser
  confirmation; `tidy`/`node --check` cover markup/script validity).
  Everything already out of scope per Phase 57-62 remains so: any
  `critical`/`shutdown`-severity real caller beyond Phase 62's; live
  Takomachi integration; any change to `security/ducopa.sh`.

## Phase 64 (2026-09-17): Guardian-initiated intervention channel -- WAIO-side receiving endpoint

Audited what remains open across Phase 57-63's own "not implemented" notes
before picking this phase's unit. Every remaining named item resolves to
one of three shapes: (a) a decision already made and closed (a
`critical`/`shutdown`-severity real caller was deliberately rejected,
`security/ducopa.sh`'s disposition was decided in Phase 59 -- kept as a
reference implementation, not retired), (b) genuinely non-actionable in
this environment (a live browser screenshot), or (c) "live Takomachi
integration across a real separated channel" -- named in every single
phase since 57 as the one substantial gap left. This phase makes real
progress on (c), entirely on the WAIO/750 side, without touching any
real remote machine, credential, or Takomachi process.

### 1. What direction was actually missing

Phase 33-38 already built and deployed a real, working, SSH-key-
authenticated channel for the **recovery** direction: a Guardian
(800号機) can release a WAIO-side stop
(`security/guardian_recover_wrapper.sh`, forced-command-restricted via
`authorized_keys`, calling `security/recover.sh --guardian-confirm`).
Phase 57-62 built the **detection/intervention** direction, but only the
half where WAIO notices something about *itself* and tells its own
Guardian plane (`guardian_notify_event`, called from WAIO's own code).
The other half -- a Guardian *independently deciding*, on its own
initiative, to restrain WAIO -- had no receiving endpoint on the WAIO
side at all. This phase builds that receiving endpoint: the mirror image
of the recovery direction's own wrapper.

### 2. Scope decision: exactly one action, the least authority available

- **`guardian_require_human_approval` only** -- not quarantine, not
  `critical`/`warning` notify, and absolutely not a remote shutdown
  trigger. `HUMAN_APPROVAL_REQUIRED` blocks new dispatch
  (`guardian_is_blocking`, unchanged) without ever touching the real
  `SHUTDOWN_LOCK`, and is trivially, immediately reversible by a WAIO-
  side operator via the already-existing `security/guardian_approve.sh`
  -- the single lowest-authority, most-reversible action in the entire
  state machine. This directly matches this phase's own "safe side"
  instruction, carried over from Phase 60's own framing: prove the
  channel exists and works with the smallest possible blast radius
  first, exactly the same incremental discipline Phase 34
  ("specification, not implemented") -> Phase 35 ("partial
  implementation") -> Phase 36-38 (full deployment) already used for the
  recovery direction.
- **One key, one fixed command, no argument-driven action selection over
  SSH** -- explicitly the same discipline `guardian_recover_wrapper.sh`
  already established (`command=` in `authorized_keys` names exactly one
  script, which runs exactly one action; the only thing the remote side
  supplies is free-text reason content, `$SSH_ORIGINAL_COMMAND`, never a
  choice of *which* function to call). A future phase MAY add more
  actions, each behind its *own*, separately-keyed forced command -- not
  built here.
- **No new authentication mechanism** -- reuses the exact SSH-key/
  forced-command architecture already accepted for the recovery
  direction (Option D, Phase 33), consistent with Phase 31/32/39's
  standing conclusion that inventing a new auth primitive is out of
  bounds. This channel grants a remote Guardian no more authority than a
  WAIO-side operator calling `guardian_require_human_approval` directly
  already has.

### 3. A real, latent correctness gap closed before this function gained its first caller

- `guardian_require_human_approval` (`security/guardian.sh`) had **zero
  callers anywhere, production or test**, since Phase 57 introduced it --
  confirmed by direct search before writing any code. Its old
  implementation was a raw, unconditional `guardian_set_state` call, with
  no rank check. Calling it while the real state was `SHUTDOWN` would
  have silently overwritten the Guardian's own state field down to
  `HUMAN_APPROVAL_REQUIRED` -- **not** a dispatch-gate bypass
  (`guardian_is_blocking` still refuses on both states, and
  `is_shutdown_active`'s check of the real `SHUTDOWN_LOCK` file in
  `waio.sh` is entirely separate and unaffected either way), but it would
  let `security/guardian_approve.sh` then clear the Guardian's own
  bookkeeping back to `NORMAL` while a real Emergency Shutdown was still
  active underneath it -- confusing, incorrect state, not a real
  security bypass, but exactly the class of drift `guardian_state_rank`/
  `guardian_notify_event`'s existing never-downgrade rule exists to
  prevent elsewhere in this same file. **Fixed**: added the identical
  rank-comparison guard `guardian_notify_event` already uses (no-op,
  audited as an informational event, if the target rank does not
  strictly exceed the current one) directly inside
  `guardian_require_human_approval` itself. Zero behavior change for any
  existing caller, because there were none -- this was closed
  specifically *before* exposing the function to a new, less-trusted
  remote channel, not after.

### 4. New `security/guardian_intervene_wrapper.sh`

- Mirrors `security/guardian_recover_wrapper.sh`'s exact safety pattern:
  `$SSH_ORIGINAL_COMMAND` is passed as one already-expanded argument to a
  bash function, never re-interpolated into a string that gets re-parsed
  as shell syntax -- the same discipline that makes the recovery
  wrapper safe against a Guardian-supplied reason containing quotes/
  backticks/`$()`/`;`.
  ```
  guardian_require_human_approval "$REASON" "$RUN_ID"
  ```
- Documented (not applied) `authorized_keys` line, mirroring the
  existing recovery-direction entry's own documented format exactly (see
  Phase 35's entry): a `from="192.168.1.91"`-restricted,
  `no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-pty,
  no-user-rc,command="/Users/masa/WAIO/security/guardian_intervene_wrapper.sh"`
  key, distinct from the recovery key (a compromised intervene-only key
  can request a pause; it cannot release one, recover, quarantine, or
  shut anything down).
- **Deliberately not deployed to any real machine this phase**: adding
  the real line to this deployment's real `~/.ssh/authorized_keys`,
  generating/distributing a real Guardian-intervene SSH keypair, and
  writing any corresponding trigger script for 800号機 to actually run
  are all real, operator-controlled credential/infrastructure actions on
  a live system -- the same boundary Phase 34 drew for the recovery
  direction before Phase 35-38's own later, separately-authorized
  deployment work. This phase builds and tests the code only.

### 5. New regression coverage: `tests/ducopa_guardian_test.sh` (G52-G61, 20 new assertions, suite total 125 -> 145)

- **G52-G54**: `guardian_require_human_approval` still escalates normally
  from `NORMAL`/`WARNING`/`BLOCKED` (every rank strictly below
  `HUMAN_APPROVAL_REQUIRED`).
- **G55**: the never-downgrade guard itself -- calling it while `SHUTDOWN`
  leaves the state at `SHUTDOWN`, logs no additional
  `guardian_state_changed` event, and confirms the no-op is still
  recorded as an informational `guardian_event_notified` event (never
  silent).
- **G56**: a repeat call while already `HUMAN_APPROVAL_REQUIRED` is
  likewise a no-op (equal rank), not a redundant state-change event.
- **G57**: the wrapper end-to-end -- forwards `$SSH_ORIGINAL_COMMAND` as
  the reason, transitions state, and its own output echoes the reason
  and points at `guardian_approve.sh` for clearing.
- **G58**: **the command-injection check**, mirroring
  `tests/security_test.sh`'s existing G3/G4 for the recovery-direction
  wrapper exactly (a reason string containing `"; touch <marker>; echo "`
  never creates the marker file) -- verified directly, not merely
  reasoned about from the quoting pattern.
- **G59**: the never-downgrade guard holds through the *wrapper*, not
  only the underlying function call directly.
- **G60**: the wrapper never creates or touches the real `SHUTDOWN_LOCK`
  file at all, under any input.
- **G61**: a missing `$SSH_ORIGINAL_COMMAND` (defensive case; a real SSH
  session invoking a forced command always sets it, but the script does
  not assume that) still transitions state, using the documented default
  reason text.
- Unlike `guardian_recover_wrapper.sh`'s own tests (`tests/security_test.sh`'s
  G3/G4, which necessarily run against this deployment's real
  `SHUTDOWN_LOCK`/audit log because `recover.sh` itself has no fixture-
  override path), `guardian_intervene_wrapper.sh` only ever touches
  `GUARDIAN_STATE_FILE` (already fixture-overridable) and never
  `SHUTDOWN_LOCK` -- so its entire test surface, including the injection
  check, could be written fully isolated in `tests/ducopa_guardian_test.sh`
  instead, safe to run directly in any environment, never requiring the
  `tests/security_test.sh`-only local-execution-context caveat Phase 54
  established.

### 6. Verification

- Verified 2026-09-17: `tests/ducopa_guardian_test.sh` **145/0** (125
  prior + 20 new). `tests/ducopa_core_test.sh` **54/0**,
  `tests/waio_test.sh` **28/0**, `tests/orchestrate_worker_test.sh`
  **77/0/0**, `tests/recovery_hardening_test.sh` **45/0**,
  `tests/dashboard_refresh_cron_test.sh` **9/0**,
  `tests/collect_status_guardian_test.sh` **20/0**,
  `tests/dashboard_guardian_ui_test.sh` **19/0**, and
  `tests/build_incident_history_test.sh` **16/0** all re-run unaffected.
  `tests/security_test.sh` was **not** run directly, per the
  local-execution-context policy Phase 54 adopted (unchanged reasoning).
- **A pre-existing, unrelated flakiness was observed, not caused, while
  verifying this phase**: `tests/audit_log_integrity_test.sh`'s I10 (a
  concurrent-write race-condition check against `security/lib.sh`'s
  audit-log lock) failed intermittently (roughly 1 run in 3,
  `broken:N` for varying `N`) both with this phase's changes applied and
  -- confirmed directly via `git stash` -- on the unmodified `develop`
  HEAD as well, with zero files from this phase present. This phase
  touches no file that check exercises (`security/lib.sh`'s locking code
  is unchanged); left as found, exactly as Phase 57 left the real
  `SHUTDOWN.lock` finding it surfaced but did not cause -- a note for a
  future phase's own investigation, not fixed here, per this phase's own
  minimal-unit scope.
- `bash -n` clean on `security/guardian.sh`,
  `security/guardian_intervene_wrapper.sh`, and
  `tests/ducopa_guardian_test.sh`. Both already covered by
  `.github/workflows/lint.yml`'s existing `security/*.sh`/`tests/*.sh`
  globs in both the `bash -n` and `shellcheck` steps -- no `lint.yml`
  change was needed this phase.
- Manually verified the injection-safety and never-downgrade properties
  directly against a scratch fixture before writing the formal test
  suite (three scenarios: normal escalation, a `"; touch ...; echo "`
  injection attempt, and a call while `SHUTDOWN` was already active) --
  all three behaved exactly as designed.
- This deployment's real `security/state/SHUTDOWN.lock`, `GUARDIAN_STATE`,
  `GUARDIAN_QUARANTINE`, and `GUARDIAN_CRITICAL_EVENTS` confirmed absent
  both before and after this phase's work. No real `~/.ssh/authorized_keys`
  or `sshd_config.d` file was read or written by this phase.
- Landed via a feature branch + PR into `develop` (this repo's required
  workflow), never a direct push.
- **Not implemented, explicitly out of scope this phase**: real
  deployment of the documented `authorized_keys` line to this or any
  deployment's actual `~/.ssh/authorized_keys` (operator-controlled
  credential configuration on a live system -- explicitly deferred, same
  boundary as Phase 34); generating or distributing any real Guardian-
  intervene SSH keypair; any corresponding trigger script meant to run
  on 800号機 (the actual remote-initiation side -- this phase built only
  the WAIO-side receiving endpoint); additional intervention actions
  beyond `HUMAN_APPROVAL_REQUIRED` (quarantine-via-SSH, notify-via-SSH,
  etc. -- deliberately deferred, one action proven first); a fix for the
  pre-existing `tests/audit_log_integrity_test.sh` flakiness noted above
  (unrelated file, out of this phase's own scope); live Takomachi
  integration in the sense of an actual Takomachi *process* driving any
  of this (Takomachi today still runs as the same local user on the same
  machine as WAIO -- this phase's channel is designed for a genuinely
  separate machine/key, per Option D, but nothing here assumes Takomachi
  itself has been wired to use it yet); any change to
  `security/ducopa.sh`.

## Phase 65 (2026-09-17): audit-log lock staleness hardening -- fixes the flakiness Phase 64 found

Closes the one concrete, previously-identified item left from Phase 64's
own "not implemented" note: `tests/audit_log_integrity_test.sh`'s I10
(12 concurrent `audit_log()` calls) failed intermittently -- roughly 1
run in 3 -- with a false-positive `broken:N` chain result. Confirmed via
`git stash` at the time to reproduce on unmodified `develop` too, so
clearly pre-existing and unrelated to Phase 64's own changes. Not
DuCoPA-specific, but a real correctness bug in `security/lib.sh`'s
audit-log lock -- the exact same function Phase 54's own PR #92 already
hardened once before for a different, cross-platform bug (`stat -f`
vs. `stat -c`). This phase continues that same hardening line.

### 1. Root cause

- `_audit_log_lock_acquire`'s stale-lock reclaim logic (`security/lib.sh`)
  decided "the current holder crashed, safe to steal" using **age
  alone**: if the lock directory's mtime was more than 5 seconds old, a
  waiter would `rmdir` it and try again, regardless of whether the
  original holder was still legitimately working.
- Under real concurrency (I10's 12 simultaneous `audit_log()` callers,
  each spawning at least one `python3` subprocess for line construction
  and hashing), a holder's own critical section can, under load,
  plausibly run long enough to cross that 5-second threshold **while
  still active, not crashed**. A waiter would then steal the lock
  mid-use, and both processes would end up inside the critical section
  at once -- two writers reading the same `prev_hash` and each
  appending as if they were the sole writer, which
  `verify_audit_log_integrity` correctly reports as a broken chain (it
  is one). The bug was in the lock, not in the verifier.
- This is exactly the class of race the lock exists to prevent; age was
  simply the wrong signal for "is the holder actually gone."

### 2. Fix: PID-liveness check before stealing (`security/lib.sh`)

- `_audit_log_lock_acquire`, on a successful `mkdir`, now also writes
  its own PID to `$AUDIT_LOG_LOCK_DIR/holder.pid` (`printf '%s' "$$"`,
  best-effort).
- A waiter that finds the lock older than 5 seconds now additionally
  reads that PID and checks `kill -0 "$holder_pid"` -- portable
  identically on macOS and Linux, no `/proc` dependency, no new
  external tool. Only reclaims the lock if the recorded PID is **no
  longer alive** (or the PID file is missing/unreadable, which falls
  back to the old age-only behavior for backward/defensive
  compatibility -- never *less* safe than before this phase, only
  stricter when the information is available). A legitimately slow but
  still-running holder is now never stolen from, no matter how long its
  critical section takes.
- Because the lock directory now holds a file, both the steal path and
  `_audit_log_lock_release` switched from `rmdir` (which only removes
  empty directories) to `rm -rf`.
- **Residual, explicitly acknowledged limit**: `_audit_log_lock_acquire`
  still gives up and returns failure after 50 retries (5 seconds) of
  genuinely waiting for a legitimately-still-working holder (its own
  liveness check correctly refuses to steal in that case) -- `audit_log()`
  proceeds without the lock if that happens, matching its own
  "never fails the caller" design. Reaching that condition now requires
  sustained contention lasting the full 5 seconds despite every waiter
  correctly declining to steal, far beyond what any current caller
  (12-way parallelism in I10, or `workers/orchestrate_worker.sh`'s own
  `WAIO_MAX_PARALLEL`-capped groups) actually produces -- left as a
  theoretical edge case, not fixed, since addressing it would mean
  either a longer retry budget or a different failure mode for
  `audit_log()` itself, a larger design change this phase's own
  "fix the identified bug" scope does not call for.

### 3. New regression coverage: `tests/audit_log_integrity_test.sh` (I13-I17, 6 new assertions, suite total 25 -> 31)

- **I13**: a stale-by-age lock whose recorded holder PID is genuinely
  dead (a PID essentially guaranteed not to exist) is reclaimed.
- **I14**: a stale-by-age lock whose recorded holder PID is this test
  script's own PID (`$$`, guaranteed alive throughout) is confirmed
  **not** reclaimed -- a backgrounded acquire attempt is shown to still
  be waiting (the lock directory is still present, no success marker
  written) after a short deliberate delay, then succeeds once the test
  itself removes the lock (simulating the real holder finishing).
- **I15**: a stale-by-age lock with no `holder.pid` file at all (the
  pre-existing-behavior/legacy case) still falls back to the old
  age-only reclaim -- backward compatibility, verified directly.
- **I16**: a successful acquisition actually records the caller's own
  PID in the lock directory.
- **I17**: release removes the entire lock directory (including
  `holder.pid`), confirming the `rmdir` -> `rm -rf` switch.
- Every pre-existing assertion in this suite (I1-I12) re-verified
  passing unchanged, including I10 itself -- now run 20+ times in a row
  with zero failures (see verification below), where it previously
  failed roughly 1 run in 3.

### 4. Verification

- **Reproduced, then fixed, then re-verified statistically, not just
  once**: before writing the fix, `tests/audit_log_integrity_test.sh`
  was run 20 times in a row -- 0 failures with the fix applied. A
  separate 15-run batch (run concurrently with an unrelated foreground
  regression sweep of *other* suites, as part of this phase's own
  verification work) surfaced one unrelated, pre-existing test-isolation
  gap instead (see the note below) -- re-run in isolation afterward:
  clean, 20/20. `git stash` confirmed 0/15 on unmodified `develop` too
  for that specific run style, consistent with the original I10
  flakiness being intermittent (probability, not certainty, on any
  single run) rather than deterministic.
- **A second, unrelated, pre-existing test-isolation gap noticed while
  stress-testing this fix, not caused by it and not fixed here**:
  `tests/audit_log_integrity_test.sh`'s I11/I12 (the real
  `./waio.sh -w ECHO` end-to-end cases) never override
  `WAIO_GUARDIAN_STATE_FILE` -- unlike every Guardian-aware suite added
  since Phase 57, this file predates the Guardian Control Plane and was
  never updated to isolate that variable. In one verification run, I11
  failed once (`waio.sh` exit 1 instead of 0) while this suite happened
  to be running concurrently with an unrelated foreground regression
  sweep of other suites in the same working tree -- consistent with a
  transient collision on that one un-isolated real file, not a defect
  in this phase's own lock fix (confirmed by two separate clean 20-run
  batches of the exact same code, run without that concurrent
  interference). Recorded here as a real, if narrow, pre-existing gap
  for a future phase to consider adding `WAIO_GUARDIAN_STATE_FILE`
  isolation to this suite's own `fixture_reset` -- not attempted this
  phase, which is scoped to the lock staleness bug specifically.
- All other suites re-run unaffected: `tests/ducopa_guardian_test.sh`
  **145/0**, `tests/ducopa_core_test.sh` **54/0**, `tests/waio_test.sh`
  **28/0**, `tests/orchestrate_worker_test.sh` **77/0/0**,
  `tests/recovery_hardening_test.sh` **45/0**,
  `tests/dashboard_refresh_cron_test.sh` **9/0**,
  `tests/collect_status_guardian_test.sh` **20/0**,
  `tests/dashboard_guardian_ui_test.sh` **19/0**,
  `tests/build_incident_history_test.sh` **16/0**,
  `tests/rpi_command_injection_test.sh` **47/0**,
  `tests/taco_control_injection_test.sh` **62/0**,
  `tests/jobs_taco_control_dlp_test.sh` **72/0**,
  `tests/earth_weather_test.sh` **39/0**, and
  `tests/earth_weather_global_test.sh` **41/0** -- every suite that
  exercises `audit_log()`/the lock, directly or indirectly, still
  passes cleanly. `tests/security_test.sh` was **not** run directly,
  per the local-execution-context policy Phase 54 adopted (unchanged
  reasoning).
- `bash -n` clean on both changed files. Both already covered by
  `.github/workflows/lint.yml`'s existing `security/*.sh`/`tests/*.sh`
  globs -- no `lint.yml` change was needed this phase.
- This deployment's real `security/state/SHUTDOWN.lock`, `GUARDIAN_STATE`,
  `GUARDIAN_QUARANTINE`, `GUARDIAN_CRITICAL_EVENTS`, and
  `logs/security-audit.jsonl` confirmed absent/unchanged both before and
  after this phase's work (the real audit log grew only from this
  session's own normal activity across the session, not from this
  phase's test runs, all of which are fixture-isolated).
- Landed via a feature branch + PR into `develop` (this repo's required
  workflow), never a direct push.
- **Not implemented, explicitly out of scope this phase**: the residual
  "give up after 5s and proceed unlocked" fallback noted above (a
  larger design question, not a bug this phase's own scope covers);
  adding `WAIO_GUARDIAN_STATE_FILE` isolation to
  `tests/audit_log_integrity_test.sh`'s `fixture_reset` (the
  I11/I12-adjacent gap noticed above -- unrelated file/concern, a
  candidate for a future phase); anything DuCoPA-specific (this phase
  is a general `security/lib.sh` correctness fix, not a DuCoPA feature)
  -- the standing DuCoPA items (real deployment of Phase 64's
  intervention channel, additional intervention actions, live Takomachi
  integration, any change to `security/ducopa.sh`) are all unchanged
  and still open.

## Phase 66 (2026-09-17): audit_log_integrity_test.sh gains Guardian Control Plane isolation

Closes the second, smaller item Phase 65 explicitly deferred:
`tests/audit_log_integrity_test.sh`'s `fixture_reset` never overrode
`WAIO_GUARDIAN_STATE_FILE`/`WAIO_GUARDIAN_QUARANTINE_FILE`/
`WAIO_GUARDIAN_CRITICAL_EVENTS_FILE` -- this file predates
`security/guardian.sh` (Phase 57) and was never updated to isolate that
variable, unlike every Guardian-aware suite added since
(`tests/ducopa_guardian_test.sh`, `tests/collect_status_guardian_test.sh`,
`tests/dashboard_guardian_ui_test.sh`). I11/I12 (the cases that dispatch
through the real `./waio.sh -w ECHO`) were therefore implicitly reading
and gating on this deployment's REAL `security/state/GUARDIAN_STATE`/
`GUARDIAN_QUARANTINE` -- harmless while that real state happens to be
`NORMAL`/empty, but a real collision risk otherwise, and directly
implicated in one transient I11 failure observed while stress-testing
Phase 65's own lock fix.

### 1. Fix (`tests/audit_log_integrity_test.sh`)

- `fixture_reset` now also exports `WAIO_GUARDIAN_STATE_FILE`/
  `WAIO_GUARDIAN_QUARANTINE_FILE`/`WAIO_GUARDIAN_CRITICAL_EVENTS_FILE`,
  each pointed at this suite's own `$FIXTURE_DIR` (same one-file-per-
  suffix pattern as every other override here), and includes all three
  in the per-case cleanup `rm -rf` list -- identical shape to
  `tests/ducopa_guardian_test.sh`'s own `fixture_reset`.
- No change to any production file (`security/guardian.sh`,
  `security/lib.sh`, `waio.sh`) -- this phase only closes a test-file
  gap.

### 2. New regression coverage (I18-I21, 10 new assertions, suite total 31 -> 41)

- **I18**: after `fixture_reset`, all three Guardian overrides actually
  point under this suite's own fixture directory, never at the real
  `security/state/` path.
- **I19**: **proves the override is genuinely read, not silently
  ignored** -- writing `BLOCKED` to the *fixture* Guardian state file
  causes a real `./waio.sh -w ECHO` dispatch to actually be refused,
  with the same message `waio.sh`'s own gate always produces. A
  same-shape assertion that only checked "the variable is set" without
  this would have missed a regression where the override path is
  exported but never actually wired into `guardian_get_state`.
- **I20**: this deployment's real `GUARDIAN_STATE`/`GUARDIAN_QUARANTINE`/
  `GUARDIAN_CRITICAL_EVENTS` files are confirmed untouched (still
  absent) after I18/I19 ran.
- **I21**: I11/I12's own real-dispatch pattern still works normally now
  that Guardian state is isolated (a fresh fixture is `NORMAL`/
  not-quarantined by default, so `./waio.sh -w ECHO` succeeds) --
  confirms this phase didn't accidentally break the very cases it set
  out to protect.
- Every pre-existing assertion (I1-I17) re-verified passing unchanged.

### 3. Verification

- Verified 2026-09-17: `tests/audit_log_integrity_test.sh` **41/0** (31
  prior + 10 new). Re-run **15 times in a row while
  `tests/ducopa_guardian_test.sh`/`tests/orchestrate_worker_test.sh`/
  `tests/waio_test.sh` ran concurrently in the foreground** --
  deliberately reproducing the exact contention shape that produced
  Phase 65's own transient I11 observation -- **0/15 failures**,
  confirming the isolation gap is genuinely closed, not merely
  theorized. `tests/ducopa_core_test.sh` **54/0**,
  `tests/recovery_hardening_test.sh` **45/0**,
  `tests/dashboard_refresh_cron_test.sh` **9/0**,
  `tests/collect_status_guardian_test.sh` **20/0**,
  `tests/dashboard_guardian_ui_test.sh` **19/0**, and
  `tests/build_incident_history_test.sh` **16/0** all re-run unaffected.
  `tests/security_test.sh` was **not** run directly, per the
  local-execution-context policy Phase 54 adopted (unchanged reasoning).
- `bash -n` clean. Already covered by `.github/workflows/lint.yml`'s
  existing `tests/*.sh` globs -- no `lint.yml` change needed.
- This deployment's real `security/state/SHUTDOWN.lock`, `GUARDIAN_STATE`,
  `GUARDIAN_QUARANTINE`, and `GUARDIAN_CRITICAL_EVENTS` confirmed absent
  both before and after this phase's work.
- Landed via a feature branch + PR into `develop` (this repo's required
  workflow), never a direct push.
- **Not implemented, explicitly out of scope this phase**: the residual
  "give up after 5s and proceed unlocked" lock fallback (Phase 65's own
  deferred item, unrelated to this phase's test-isolation fix); anything
  DuCoPA-specific -- the standing items (real deployment of Phase 64's
  intervention channel, additional intervention actions, live Takomachi
  integration, any change to `security/ducopa.sh`) remain unchanged and
  still open.

## Phase 67 (2026-09-17): audit-log lock retry-budget hardening -- closes Phase 65's own residual-risk note

Asked explicitly, after a scope check: harden the one residual risk
Phase 65 itself named and deliberately left open (`_audit_log_lock_acquire`
giving up and letting `audit_log()` proceed without the lock, after a
legitimately-still-working holder outlasts the waiter's own patience) --
**without** adding any new SSH-exposed action or otherwise changing the
lock's design. A prior turn in this same conversation had proposed
expanding the DuCoPA intervention channel with a second SSH action
instead; the user explicitly redirected to this narrower, non-security-
surface-expanding option.

### 1. Scope decision, confirmed against the actual code before writing anything

- Re-read `_audit_log_lock_acquire` and confirmed there are two distinct
  constants, easy to conflate: the **stale-lock age threshold**
  (`age -gt 5` -- how old a lock must look before a waiter even
  considers reclaiming it, now gated by Phase 65's PID-liveness check)
  and the **waiter's own retry budget** (`waited -gt 50`, i.e. 50
  polls * 0.1s = 5s -- how long a waiter keeps politely waiting on a
  lock it has correctly declined to steal before giving up entirely and
  letting `audit_log()` proceed unlocked). Phase 65's own "residual
  risk" note was about the second constant, not the first -- increasing
  the age threshold would only slow down *legitimate crash* recovery,
  not reduce this risk at all. This phase touches only the retry-budget
  constant.
- Considered and rejected, per this phase's own "no design change"
  instruction: a different locking primitive (`flock`, not portable
  identically across this repo's macOS dev machine and Linux CI
  runners without an extra dependency), jittered/randomized polling
  (a reasonable contention-reduction technique in general, but a change
  to the polling *algorithm*, not just a safety margin), or a different
  fallback contract for `audit_log()` itself (e.g. erroring instead of
  proceeding unlocked, which would break its own "never fails the
  caller" design every other function in this file already depends on).
  All three would have been legitimate engineering choices in the
  abstract, but none is "reinforce the existing fallback toward the
  safe side" -- each is a structural change this phase was explicitly
  told not to make.

### 2. The actual change (`security/lib.sh`)

- New overridable constant, same pattern as every other tunable
  threshold in this file (`WAIO_RECOVER_MIN_REASON_LENGTH`,
  `WAIO_GUARDIAN_AUTO_QUARANTINE_THRESHOLD`, `WAIO_MAX_PAYLOAD_BYTES`,
  etc.): `AUDIT_LOG_LOCK_MAX_WAIT_ITERATIONS="${WAIO_AUDIT_LOG_LOCK_MAX_WAIT:-150}"`.
  Default **150** (15 seconds), up from the hardcoded **50** (5
  seconds) -- a straight 3x increase in how long a waiter will keep
  correctly declining to steal from a live holder before giving up,
  with the retry *mechanism* itself (the `mkdir`-based loop, the 0.1s
  poll interval, the liveness-gated steal check) completely unchanged.
- `_audit_log_lock_acquire`'s own `[ "$waited" -gt 50 ]` became
  `[ "$waited" -gt "$AUDIT_LOG_LOCK_MAX_WAIT_ITERATIONS" ]` -- the only
  functional line changed in this phase.
- **Why 150, not some other number**: every real concurrency level this
  codebase actually produces (I10's 12-way concurrent-write test;
  `workers/orchestrate_worker.sh`'s `WAIO_MAX_PARALLEL`-capped "+"
  groups) resolves in well under a second even under load, so the
  original 5s budget already had large headroom; tripling it costs
  nothing in the overwhelmingly common case (the budget is only ever
  consumed while genuinely waiting) and meaningfully shrinks the
  already-narrow window in which this fallback could still be reached
  under some future, larger-than-anything-today parallel group,
  without picking an unbounded/indefinite wait that could make a
  genuinely-stuck caller hang forever.

### 3. New regression coverage: `tests/audit_log_integrity_test.sh` (I22-I24, 5 new assertions, suite total 41 -> 46)

- **I22**: the default retry budget is actually 150 (a direct read of
  the constant, not inferred).
- **I23**: `WAIO_AUDIT_LOG_LOCK_MAX_WAIT` is honored -- with the budget
  overridden down to 3 (0.3s) and a lock held by a genuinely alive PID
  that never releases, `_audit_log_lock_acquire` gives up (exit 1)
  quickly, confirmed by elapsed-time measurement, never stealing from
  the live holder. Proves the override actually reaches the retry loop,
  not just that the variable is set.
- **I24**: even after giving up, `audit_log()` itself still returns 0
  and still writes the entry (unprotected) -- the "never fails the
  caller" contract this whole mechanism depends on is unchanged by this
  hardening.
- Every pre-existing assertion (I1-I21) re-verified passing unchanged.

### 4. Verification

- Verified 2026-09-17: `tests/audit_log_integrity_test.sh` **46/0** (41
  prior + 5 new). Re-run **15 times in a row**: 0/15 failures.
  `tests/ducopa_guardian_test.sh` **145/0**, `tests/ducopa_core_test.sh`
  **54/0**, `tests/waio_test.sh` **28/0**,
  `tests/orchestrate_worker_test.sh` **77/0/0**,
  `tests/recovery_hardening_test.sh` **45/0**,
  `tests/dashboard_refresh_cron_test.sh` **9/0**,
  `tests/collect_status_guardian_test.sh` **20/0**,
  `tests/dashboard_guardian_ui_test.sh` **19/0**,
  `tests/build_incident_history_test.sh` **16/0**,
  `tests/rpi_command_injection_test.sh` **47/0**,
  `tests/taco_control_injection_test.sh` **62/0**,
  `tests/jobs_taco_control_dlp_test.sh` **72/0**,
  `tests/earth_weather_test.sh` **39/0**, and
  `tests/earth_weather_global_test.sh` **41/0** all re-run unaffected --
  every suite that exercises `audit_log()`/the lock, directly or
  indirectly, still passes cleanly. `tests/security_test.sh` was **not**
  run directly, per the local-execution-context policy Phase 54 adopted
  (unchanged reasoning).
- `bash -n` clean on both changed files. Already covered by
  `.github/workflows/lint.yml`'s existing `security/*.sh`/`tests/*.sh`
  globs -- no `lint.yml` change needed.
- This deployment's real `security/state/SHUTDOWN.lock`, `GUARDIAN_STATE`,
  `GUARDIAN_QUARANTINE`, and `GUARDIAN_CRITICAL_EVENTS` confirmed absent
  both before and after this phase's work.
- Landed via a feature branch + PR into `develop` (this repo's required
  workflow), never a direct push.
- **Not implemented, explicitly out of scope this phase, by the user's
  own direction**: any new SSH-exposed Guardian action (a second
  `security/guardian_intervene_wrapper.sh`-style channel, e.g. exposing
  quarantine remotely, was explicitly considered and set aside this
  phase in favor of this narrower, non-attack-surface-expanding fix);
  any structural change to the lock itself (`flock`, jittered polling,
  a different `audit_log()` fallback contract -- see section 1's
  rejected alternatives); anything else DuCoPA-specific -- the standing
  items (real deployment of Phase 64's intervention channel, additional
  intervention actions, live Takomachi integration, any change to
  `security/ducopa.sh`) remain unchanged and still open.

## Phase 68 (2026-09-17): full-repository security audit, and a fix for its one Critical finding

Asked to run a full-repository security audit (not a diff review --
privilege boundaries, secret exposure, input validation, SSH/external
execution, auth/approval flows, and DuCoPA's own safety boundaries),
find real, existing problems rather than propose new work, and report
without fixing anything unilaterally. Six findings came back; each was
independently re-verified against the actual current code (and, where
feasible, reproduced directly) before being reported, rather than
trusted at face value. **This phase implements a fix for the one
Critical finding only**, per explicit follow-up direction; the other
five remain open, reported but unaddressed.

### The audit and its six findings (severity, in order reported)

1. **Critical** -- `taco-control/taco_control_dispatch.sh`'s hardcoded
   default destination (`192.168.1.80`) collides with this deployment's
   real `workers/800.json` host, which is *also* `192.168.1.80` --
   while `ARCHITECTURE.md` extensively documents 800号機 as
   `192.168.1.91` (the Guardian Recovery Protocol's `from="192.168.1.91"`
   SSH restriction, `Match Address 192.168.1.91` in `sshd_config`, Phase
   33-38 throughout). `taco_control_dispatch.sh`'s own header explicitly
   states this destination is "distinct from 800号機's own 192.168.1.91"
   and therefore deliberately unlisted, so `egress_check` should fail
   closed until an operator reviews and adds it -- but because the real
   `security/egress_allowlist.conf` already carries a `192.168.1.80`
   entry (labeled "800号機 (HOST800 worker, host read from
   workers/800.json)"), that entry silently also covers the taco-control
   channel, defeating the intended fail-closed gate without anyone
   having reviewed or approved it. Fixed this phase -- see below.
2. **High** -- every SSH-based dispatch path (`workers/rpi_worker.sh`,
   `workers/host800_worker.sh`, `taco-control/taco_control_dispatch.sh`,
   `jobs/*.sh`) calls only `egress_check`, never `payload_size_check`
   (bulk-exfiltration) or `secret_leak_check` (credential-shape
   detection) -- both are wired into every HTTP-based Takomachi worker
   (`ai_worker.sh`/`analysis_worker.sh`/`research_worker.sh`) but absent
   from the entire SSH side, confirmed by direct `grep` across all
   files. **Not fixed this phase.**
3. **Medium** -- `security/guardian.sh`'s `_guardian_critical_event_set`/
   `guardian_quarantine_agent`/`guardian_release_agent` do an unguarded
   read-modify-write (`awk` read -> `mv` write) on
   `GUARDIAN_CRITICAL_EVENTS_FILE`/`GUARDIAN_QUARANTINE_FILE`, unlike
   `audit_log()`'s own dedicated `_audit_log_lock_acquire` (Phase
   65/67). With `WAIO_AUTO_GUARDIAN_STAGE_NOTIFY=1` and
   `WAIO_GUARDIAN_AUTO_QUARANTINE=1` both set, two members of a `"+"`-
   joined parallel `ORCHESTRATE` group failing near-simultaneously for
   the same worker can race: both read the same stale count, one
   increment is silently lost, and Phase 60's auto-quarantine threshold
   can be missed even though enough critical events genuinely occurred.
   **Not fixed this phase.**
4. **Medium** -- `security/generate_ssh_guardian_config.sh`'s
   `backup_existing()` prints its "Backed up ... -> $backup_path"
   progress line to stdout instead of stderr, so
   `apply_config()`'s `backup_path="$(backup_existing)"` captures a
   two-line string, not a bare path. Reproduced directly this phase
   (isolated fixture, not the real `/etc/ssh`): the subsequent
   `[ -f "$backup_path" ]` check is always false, so a `post_install_check`
   failure after a successful backup+install takes the `rm -f
   "$DEPLOYED_CONFIG"` branch -- deleting the newly-applied, broken
   drop-in outright instead of restoring the last-known-good config.
   `tests/ssh_guardian_config_test.sh` has zero coverage of this
   revert-on-failure path. **Not fixed this phase.**
5. **Medium-low** -- `security/guardian_intervene_wrapper.sh` (Phase
   64) passes `$SSH_ORIGINAL_COMMAND` straight to
   `guardian_require_human_approval` with no `validate_reason_strength`
   call, unlike every other reason-gated CLI (`recover.sh`,
   `guardian_approve.sh`, `guardian_release_agent.sh`, all hardened in
   Phase 59). Requires already possessing the Guardian-intervene SSH
   key (not exploitable by an unauthenticated party), but is a real
   inconsistency with this codebase's own established discipline that
   every state-changing action requires a descriptive, non-trivial
   reason. **Not fixed this phase.**
6. **Low** -- `workers/host800_worker.sh` is missing `set -uo pipefail`,
   present in every sibling worker script
   (`rpi_worker.sh`/`ai_worker.sh`/`analysis_worker.sh`/
   `research_worker.sh`/`orchestrate_worker.sh`). **Not fixed this
   phase.**

### Fix for finding 1: a host-collision guard (`taco-control/taco_control_dispatch.sh`)

- **What this phase deliberately did NOT do, and why**: the actual
  ground truth -- whether 800号機's real, current network address is
  `192.168.1.91` (as `ARCHITECTURE.md` documents throughout) or
  `192.168.1.80` (as the live, gitignored `workers/800.json` and
  `security/egress_allowlist.conf` say) -- cannot be determined by
  reading code. It is a real-world fact about this deployment's actual
  network that only the operator can confirm. This phase therefore
  does **not** edit `workers/800.json` (not tracked by git, not this
  phase's file to change), does **not** rewrite `ARCHITECTURE.md`'s
  historical `192.168.1.91` references to guess at a "corrected" value,
  and does **not** touch any real `~/.ssh/authorized_keys` or
  `/etc/ssh/sshd_config.d` file -- consistent with this codebase's own
  standing rule (Phase 64 and earlier) that real credential/network
  configuration on a live system is always an explicit, separate,
  operator-driven action, never something to guess at or apply
  unilaterally. **This remains open and needs the operator's own
  verification**: confirm 800号機's actual current IP, and check that
  the real SSH `from="..."` restriction and `Match Address` block
  actually match it.
- **What this phase DID fix, entirely at the code level, without
  needing to know the true IP**: a new guard in
  `taco_control_dispatch.sh`, placed right after `TACO_HOST` is
  resolved and before any other validation, reads `workers/800.json`'s
  own `host` field (the same `python3 json.load`, CWD-relative pattern
  `workers/host800_worker.sh` already uses -- read-only, no state
  written) and refuses outright (exit 1, a clear stderr explanation,
  and a new `taco_control_host_collision_detected` audit event) if it
  is identical to `TACO_HOST` -- regardless of whether that equality
  came from the script's own hardcoded default or an explicit
  `TACO_CONTROL_HOST` override. This restores the *intent* stated in
  the file's own header (this channel's destination must be reviewed
  and distinct from 800号機's) without ever needing to know which of
  `.91`/`.80` is actually correct: whichever host `workers/800.json`
  really points at, this channel may no longer silently coincide with
  it. **Fails safe toward NOT blocking** when there is nothing to
  compare against: a missing, unreadable, or malformed
  `workers/800.json` skips this check quietly (confirmed directly, C3/
  C4 below) -- `egress_check` remains the real, primary gate either
  way; this is an additional guard layered in front of it, not a
  replacement.

### New regression coverage: `tests/jobs_taco_control_dlp_test.sh` (C1-C4, 12 new assertions, suite total 72 -> 84)

- **C1**: `TACO_HOST` identical to the fixture `workers/800.json`'s host
  is refused, `ssh` is never invoked, and the refusal is audited --
  even when that colliding host is *also* present in the egress
  allowlist (proving the new guard fires independently of, and before,
  `egress_check`'s own allow/deny decision, exactly the scenario this
  phase's audit found).
- **C2**: a genuinely distinct `TACO_HOST` is unaffected -- dispatch
  proceeds normally, no collision event logged (the guard does not
  fire on legitimate, non-colliding destinations).
- **C3**: `workers/800.json` missing entirely -- check skipped safely,
  dispatch proceeds.
- **C4**: `workers/800.json` present but malformed JSON -- same safe
  skip, dispatch proceeds.
- Every pre-existing assertion in this suite (the per-target D1-D3
  loop across all four SSH-dispatching scripts, plus T1) re-verified
  passing unchanged -- none of their fixtures collide (the shared
  fixture `workers/800.json` uses `TESTHOST800`, distinct from every
  existing test's own `TACOHOST`/`dest_host` values).

### Verification

- Verified 2026-09-17: `tests/jobs_taco_control_dlp_test.sh` **84/0**
  (72 prior + 12 new). `tests/taco_control_injection_test.sh` **62/0**,
  `tests/rpi_command_injection_test.sh` **47/0**,
  `tests/waio_test.sh` **28/0**, and
  `tests/orchestrate_worker_test.sh` **77/0/0** all re-run unaffected.
  `tests/security_test.sh` was **not** run directly, per the
  local-execution-context policy Phase 54 adopted (unchanged
  reasoning).
- Manually verified all three branches directly (fixture-isolated, no
  real network) before writing the formal tests: a genuine collision
  refuses with the exact expected message and an audited event; a
  non-colliding destination proceeds to the real `egress_check`/`ssh`
  call; a missing `workers/800.json` proceeds normally.
- `bash -n` clean on both changed files. Already covered by
  `.github/workflows/lint.yml`'s existing
  `taco-control/*.sh`/`tests/*.sh` globs (both `bash -n` and
  `shellcheck` steps) -- no `lint.yml` change needed.
- This deployment's real `security/state/SHUTDOWN.lock`, `GUARDIAN_STATE`,
  `GUARDIAN_QUARANTINE`, and `GUARDIAN_CRITICAL_EVENTS` confirmed absent
  both before and after this phase's work. `workers/800.json`,
  `security/egress_allowlist.conf`, and every real SSH configuration
  file were read (for verification) but never written by this phase.
- Landed via a feature branch + PR into `develop` (this repo's required
  workflow), never a direct push.
- **Not implemented, explicitly out of scope this phase**: findings 2-6
  above (High/Medium/Medium/Medium-low/Low), all reported but
  unaddressed, pending the user's own prioritization; the operator's
  own real-world verification of 800号機's true IP and the real SSH
  `from=`/`Match Address` configuration (cannot be determined or
  changed by this phase -- see the dedicated note above); anything
  DuCoPA-specific -- the standing items (real deployment of Phase 64's
  intervention channel, additional intervention actions, live
  Takomachi integration, any change to `security/ducopa.sh`) remain
  unchanged and still open.

## Phase 69 (2026-09-17): every SSH-based dispatch path now runs payload_size_check/secret_leak_check

Closes Phase 68's finding 2 (High), asked for by name as the next
priority: `workers/rpi_worker.sh`, `workers/host800_worker.sh`,
`taco-control/taco_control_dispatch.sh`, and `jobs/{run-job,dispatch,
test-job}.sh` each called only `egress_check` -- never
`payload_size_check` (bulk-exfiltration) or `secret_leak_check`
(credential-shape detection), both of which every HTTP-based Takomachi
worker (`ai_worker.sh`/`analysis_worker.sh`/`research_worker.sh`) has
called since the DLP layer's own original phase. This closed a
systemic, half-the-dispatch-surface gap, not a single file's bug.

### 1. Which check applies where, decided per file, not applied uniformly by rote

- **`payload_size_check` (outbound, before the SSH call) added only
  where the outbound content can actually grow without bound**:
  - `workers/rpi_worker.sh`'s `REQUEST` is free-form text -- a
    hand-typed request, or (per this file's own existing header) an
    earlier `ORCHESTRATE` stage's own output forwarded verbatim. Added.
  - `taco-control/taco_control_dispatch.sh`'s `COMMAND` is restricted
    to `^[A-Z][A-Z0-9_]*$` by an existing shape check -- but that regex
    caps *characters*, not *length*; an arbitrarily long all-caps/
    digit/underscore string still matches it and would still reach the
    outbound SSH payload. Added.
  - **Deliberately NOT added** to `workers/host800_worker.sh` or any
    `jobs/*.sh` script: their outbound remote command is one of a
    small number of entirely hardcoded, fixed strings, selected by a
    keyword match against the caller's argument -- the argument itself
    never becomes part of the outbound payload, so there is no
    attacker-influenceable growth vector to check. Documented inline at
    each call site so this is a recorded decision, not a silent gap.
- **`secret_leak_check` (inbound, before printing/forwarding the
  response) added to all five files**, unconditionally -- even a fixed,
  whitelisted remote command's *response* (hostname, OS version,
  uptime, disk usage, a `PONG` liveness string) could in principle echo
  something sensitive from the remote environment, and every HTTP-based
  worker already scans its response regardless of how bounded the
  request was, so this fix matches that existing symmetry rather than
  reasoning case-by-case about whether it seemed "likely" needed.

### 2. Mechanical change: capture-then-check-then-forward

- Every one of the five files previously streamed its SSH response
  straight to stdout (and, for `jobs/run-job.sh`, into a `results/*.txt`
  file via `tee`) as soon as it arrived. Each now captures the response
  into a variable (`RESPONSE="$(ssh ...)"`, preserving `$?` as `RC`
  where the original script's own exit code was already SSH's exit
  code), runs `secret_leak_check` on it, and only then prints/`tee`s it
  -- so a tripped check withholds the response entirely; nothing
  partially leaks before the check runs.
- **Exit-code semantics preserved exactly per file**, not standardized
  by this phase: `workers/rpi_worker.sh` and
  `taco-control/taco_control_dispatch.sh` already forwarded SSH's own
  exit code (their SSH call was the last command in the script) --
  `exit "$RC"` added at the end to keep that identical.
  `workers/host800_worker.sh` never forwarded SSH's exit code (its
  final `echo "... completed"` always made the script exit 0
  regardless) -- deliberately left that way; this phase adds a new
  refusal path (`secret_leak_check` failing) without changing the
  pre-existing, unrelated "SSH itself failing" behavior, matching this
  phase's own scope discipline of fixing the reported finding only.
  `jobs/dispatch.sh`/`jobs/test-job.sh` had no exit-code handling of
  their own either (SSH was the last command) -- `exit "$RC"` added,
  matching what they already did implicitly. `jobs/run-job.sh` ran
  under `pipefail` through a `tee`, which already propagated SSH's
  exit code through the pipe -- `exit "$RC"` after the now-separate
  `echo | tee` preserves that same effective behavior.
- **Not part of this fix, explicitly**: `security/guardian_intervene_wrapper.sh`
  and every other file the Phase 68 audit did *not* name for this
  specific finding are unchanged.

### 3. Verification -- every new check manually triggered before writing tests

- Before touching any test file, manually reproduced, in isolated
  fixtures (never the real network, never real `security/state/`):
  `payload_size_check` tripping on an oversized `rpi_worker.sh` REQUEST
  and an oversized `taco_control_dispatch.sh` COMMAND; `secret_leak_check`
  tripping on a credential-shaped fake SSH response for all five files
  (including confirming `jobs/run-job.sh` writes **zero** `results/`
  files when the check fires -- the leak never reaches disk either).

### 4. New regression coverage

- **`tests/rpi_command_injection_test.sh`** (47 -> 54 assertions): the
  fake `remote_worker.sh` now also echoes a fixed, benign
  `REMOTE_WORKER_OK` marker (new assertion on the existing sanity case,
  S1, confirms this reaches `rpi_worker.sh`'s own stdout -- proving the
  capture-then-check-then-print restructuring didn't silently swallow
  a legitimate response). New **[P1]**: an oversized REQUEST is denied,
  SSH never invoked. New **[P2]**: a credential-shaped fake response is
  withheld -- the secret string itself is confirmed absent from the
  script's own output, not merely "an error was printed."
- **`tests/jobs_taco_control_dlp_test.sh`** (84 -> 112 assertions):
  the shared per-target `D3` case (all four pre-existing targets) gained
  one assertion confirming the legitimate response still reaches stdout.
  A new `security` symlink was added to the fixture's CWD so
  `workers/host800_worker.sh` (which sources `security/lib.sh` via a
  bare, CWD-relative path, unlike every other file in this suite) can
  be exercised the same fixture-isolated way for the first time. New
  **`SECRET_LEAK_TARGETS`** loop (`run-job.sh`, `dispatch.sh`,
  `test-job.sh`, `taco_control_dispatch.sh`, and `host800_worker.sh`,
  added to this suite's coverage for the first time) proves, for each:
  denied, secret never printed, and (for `run-job.sh` specifically) no
  `results/` file is left containing it. New **[SL2]**: an oversized,
  shape-valid `taco_control_dispatch.sh` COMMAND is denied before SSH.
- Every pre-existing assertion in both files re-verified passing
  unchanged.

### 5. Full verification

- Verified 2026-09-17: `tests/rpi_command_injection_test.sh` **54/0**,
  `tests/jobs_taco_control_dlp_test.sh` **112/0**,
  `tests/taco_control_injection_test.sh` **62/0**,
  `tests/waio_test.sh` **28/0**, `tests/orchestrate_worker_test.sh`
  **77/0/0**, and `tests/ducopa_guardian_test.sh` **145/0** all re-run
  -- the last two confirm this phase's changes to
  `workers/host800_worker.sh`/`workers/rpi_worker.sh` didn't disturb
  anything registry/dispatch-adjacent. `tests/security_test.sh` was
  **not** run directly, per the local-execution-context policy Phase
  54 adopted (unchanged reasoning).
- `bash -n` clean on all eight changed files. All already covered by
  `.github/workflows/lint.yml`'s existing
  `workers/*.sh`/`taco-control/*.sh`/`jobs/*.sh`/`tests/*.sh` globs --
  no `lint.yml` change needed.
- This deployment's real `security/state/SHUTDOWN.lock`, `GUARDIAN_STATE`,
  `GUARDIAN_QUARANTINE`, and `GUARDIAN_CRITICAL_EVENTS` confirmed absent
  both before and after this phase's work. No real SSH connection or
  real `workers/800.json`/`security/egress_allowlist.conf` was touched
  by any test or manual verification this phase -- every check ran
  against a fixture-isolated `ssh` stub.
- Landed via a feature branch + PR into `develop` (this repo's required
  workflow), never a direct push.
- **Not implemented, explicitly out of scope this phase**: findings 3-6
  from Phase 68's audit (Medium: `security/guardian.sh`'s unlocked
  critical-event-counter race; Medium: `generate_ssh_guardian_config.sh`'s
  `backup_existing()` stdout-capture bug; Medium-low:
  `security/guardian_intervene_wrapper.sh`'s missing
  `validate_reason_strength`; Low: `workers/host800_worker.sh`'s
  missing `set -uo pipefail`) -- all still reported, still unaddressed,
  pending further prioritization; the operator's own verification of
  800号機's true IP (Phase 68's own open item, unrelated to this
  phase); anything DuCoPA-specific -- the standing items remain
  unchanged and still open.

## Phase 70 (2026-09-17): closes Phase 68 finding 3 -- lost-update race in the auto-quarantine counter

Closes the first of the two remaining Medium findings from Phase 68's
audit: `security/guardian.sh`'s `_guardian_critical_event_set`/
`guardian_quarantine_agent`/`guardian_release_agent` did an unguarded
read-modify-write on `GUARDIAN_CRITICAL_EVENTS_FILE`/
`GUARDIAN_QUARANTINE_FILE`, unlike `audit_log()`'s own dedicated,
already-twice-hardened lock (Phase 65/67). Investigated further before
fixing: of the three functions named in the original finding, only the
critical-event counter's read-decide-write sequence actually has a
*silent correctness* problem under concurrency; the quarantine file's
own check-then-append/remove races are self-healing by construction
(see the scoping decision below). This phase fixes the real one.

### 1. Root cause, precisely -- not just "no lock exists"

- The race lives in the **caller**, `_guardian_maybe_auto_quarantine`,
  not inside `_guardian_critical_event_set` itself: it reads the
  current count (`_guardian_critical_event_count`), computes `count + 1`
  in its own local variable, decides whether to quarantine, and only
  *then* writes the new count back. Two concurrent invocations for the
  same worker (e.g. two `"+"`-joined `ORCHESTRATE` members failing at
  nearly the same instant, each running `guardian_notify_event` in its
  own separate process) can both read the same stale count, both
  compute the same `count + 1`, and the second write silently clobbers
  the first -- a classic lost update. Locking only *inside*
  `_guardian_critical_event_set` (protecting just its own final write)
  would **not** have closed this: the actual TOCTOU gap spans the read,
  all the way through the decision, to the write, all in the caller.
- **Empirically reproduced before fixing, not just reasoned about**: 40
  concurrent `guardian_notify_event` calls for one worker, threshold set
  to 40 (so only reaching a true count of 40 would quarantine it),
  repeated across trials on the pre-fix code: one trial produced a
  final on-disk counter of `W|39` -- one increment genuinely lost -- and
  `guardian_is_quarantined` correctly, if unfortunately, reported
  `false`, exactly the audit's predicted failure mode (a worker that
  should have been auto-quarantined silently wasn't). A smaller,
  12-concurrent trial (this phase's first attempt) did not reliably
  reproduce the race at all on this machine -- fast, lightly-scheduled
  local execution let 12 racing writers usually avoid actually
  overlapping; 40 was the point at which the bug became directly
  observable, not merely theoretical.

### 2. Fix: a dedicated lock, reusing the already-hardened mechanism (no reinvention)

- `security/lib.sh`'s `_audit_log_lock_acquire`/`_audit_log_lock_release`
  were refactored (behavior-preserving, not a rewrite) into a new
  generic `_waio_mkdir_lock_acquire LOCK_DIR MAX_WAIT_ITERATIONS`/
  `_waio_mkdir_lock_release LOCK_DIR` pair -- the exact same `mkdir`-
  based mutual exclusion, Phase 65's PID-liveness-gated steal, and
  Phase 67's widened retry budget, just parameterized by which lock
  directory and budget to use instead of hardcoded to the audit log's
  own. `_audit_log_lock_acquire`/`_audit_log_lock_release` themselves
  are now one-line wrappers around the generic function with the audit
  log's own `AUDIT_LOG_LOCK_DIR`/`AUDIT_LOG_LOCK_MAX_WAIT_ITERATIONS` --
  every existing caller and test (Phase 65/67's I13-I17/I22-I24, which
  call these exact function names and inspect `holder.pid` directly)
  is unaffected, confirmed by re-running them unchanged.
- `security/guardian.sh` gained its **own, separate** lock
  (`GUARDIAN_STATE_LOCK_DIR`, `WAIO_GUARDIAN_STATE_LOCK_DIR`-overridable,
  default `security/state/.guardian_state.lock`; its own
  `GUARDIAN_STATE_LOCK_MAX_WAIT_ITERATIONS`, default 150, same as the
  audit log's) -- deliberately **not** a reuse of `AUDIT_LOG_LOCK_DIR`
  itself, which would have serialized this feature's own contention
  against every unrelated `audit_log()` call system-wide for no reason.
- `_guardian_maybe_auto_quarantine` now wraps exactly the
  read-count -> decide -> write-count sequence in
  `_waio_mkdir_lock_acquire`/`_waio_mkdir_lock_release`, releasing the
  lock **before** calling `guardian_quarantine_agent` -- deliberately,
  to avoid a same-process nested-acquire deadlock (this simple `mkdir`
  lock is not reentrant), since `_guardian_maybe_auto_quarantine` and
  `guardian_quarantine_agent` would otherwise both try to hold the same
  lock in one call stack.
- **Fails OPEN if the lock itself cannot be acquired**, matching
  `audit_log()`'s own established contract: this is a best-effort,
  opt-in safety feature, not a core DLP gate, so lock contention never
  blocks or aborts a caller -- worst case (a scenario requiring
  sustained contention beyond the 15s budget, far beyond anything this
  codebase's own concurrency levels produce), it proceeds unprotected
  for that one call, same residual-risk shape Phase 67 already accepted
  and documented for the audit log's own lock.

### 3. Scoping decision: `guardian_quarantine_agent`/`guardian_release_agent` deliberately left unlocked

- Both do a check-then-mutate on **exact whole lines** (`grep -Fxq`
  before appending; `grep -Fxv` before writing back for removal) --
  under a race, the worst outcome is a harmless duplicate line (two
  processes both see "not yet quarantined", both append) or a
  redundant audit event, never a silently wrong final state:
  `guardian_is_quarantined`'s exact-line match still correctly reports
  quarantined either way, and `guardian_release_agent`'s exact-line
  removal still correctly removes every matching line (duplicates
  included) in one pass. This is a materially different risk shape
  from the counter's silent lost-update, and not what Phase 68's
  finding was actually about -- adding locking here would be
  unrequested scope expansion for a cosmetic-at-worst issue, not a
  correctness fix.

### 4. New regression coverage: `tests/ducopa_guardian_test.sh` (G62, 3 new assertions, suite total 145 -> 148)

- **G62**: 40 truly concurrent `guardian_notify_event` calls (real
  separate processes, `&`-backgrounded, `wait`-joined) for one worker,
  threshold set to 40, must still result in exactly one quarantine and
  an accurate count of 40 recorded notifications. Chosen width (40, not
  12) directly informed by the manual reproduction above -- documented
  in the test's own comment as **best-effort, probabilistic coverage**,
  explicitly not a guaranteed catch on every single run, the same
  honest framing `tests/audit_log_integrity_test.sh`'s own I10 already
  established for this exact class of concurrency test (Phase 65: ~1-
  in-3 failure rate pre-fix, not deterministic).
- Verified directly, not only by this suite: 5 manual trials of the
  underlying 40-way race **without** this phase's lock -- 1 clear
  failure (lost increment, `false` quarantine result); 5 manual trials
  **with** the fix -- 0 failures. The formal `tests/ducopa_guardian_test.sh`
  suite itself was also re-run 5 times in a row with the fix applied:
  0/5 failures.
- Every pre-existing assertion (G1-G61) re-verified passing unchanged.

### 5. Verification

- Verified 2026-09-17: `tests/ducopa_guardian_test.sh` **148/0**, re-run
  5 times in a row with 0 failures. `tests/ducopa_core_test.sh` **54/0**,
  `tests/audit_log_integrity_test.sh` **46/0** (confirms the
  `_audit_log_lock_acquire`/`_audit_log_lock_release` refactor is
  byte-for-byte behavior-preserving), `tests/waio_test.sh` **28/0**,
  `tests/orchestrate_worker_test.sh` **77/0/0**,
  `tests/recovery_hardening_test.sh` **45/0**,
  `tests/collect_status_guardian_test.sh` **20/0**, and
  `tests/dashboard_guardian_ui_test.sh` **19/0** all re-run unaffected.
  `tests/security_test.sh` was **not** run directly, per the
  local-execution-context policy Phase 54 adopted (unchanged reasoning).
- `bash -n` clean on all three changed files. Already covered by
  `.github/workflows/lint.yml`'s existing `security/*.sh`/`tests/*.sh`
  globs -- no `lint.yml` change needed.
- This deployment's real `security/state/SHUTDOWN.lock`, `GUARDIAN_STATE`,
  `GUARDIAN_QUARANTINE`, and `GUARDIAN_CRITICAL_EVENTS` confirmed absent
  both before and after this phase's work. All race reproduction and
  fix verification ran against scratch fixtures only.
- Landed via a feature branch + PR into `develop` (this repo's required
  workflow), never a direct push.
- **Not implemented, explicitly out of scope this phase**: locking
  `guardian_quarantine_agent`/`guardian_release_agent`'s own quarantine-
  file writes (deliberately judged unnecessary -- see section 3);
  Phase 68's remaining findings (Medium: `generate_ssh_guardian_config.sh`'s
  `backup_existing()` stdout-capture bug; Medium-low:
  `security/guardian_intervene_wrapper.sh`'s missing
  `validate_reason_strength`; Low: `workers/host800_worker.sh`'s
  missing `set -uo pipefail`) and the operator's own 800号機 IP
  verification remain open; anything DuCoPA-specific beyond this fix
  remains unchanged.

## Phase 71 (2026-09-18): closes Phase 68's three remaining findings -- backup_existing() stdout-capture bug, missing reason-strength validation on the intervention channel, missing `set -uo pipefail`

Closes every finding left open by Phase 68's full-repository security
audit except the operator's own real-world 800号機 IP verification
(cannot be resolved by code, unchanged). All three fixed here were
independently re-confirmed against the current code before fixing,
matching the audit's own original re-verification discipline.

### 1. `security/generate_ssh_guardian_config.sh`'s `backup_existing()` stdout-capture bug (Medium)

- **Root cause, confirmed by direct reproduction**: `backup_existing()`
  printed both its "Backed up ... -> $backup_path" progress line and,
  in the no-existing-config case, its "No existing deployed config to
  back up." message to stdout (fd 1) -- the exact same stream
  `apply_config()` captures via `backup_path="$(backup_existing)"` and
  expects to hold nothing but a bare path (or an empty string). Before
  this fix, `backup_path` instead held a two-line string whenever a
  backup was actually made, so `apply_config()`'s own
  `[ -f "$backup_path" ]` check (reached only if a later
  `post_install_check` failure requires reverting) was always false --
  the revert branch was unreachable, and the `else` branch
  (`rm -f "$DEPLOYED_CONFIG"`) ran instead, **deleting the newly
  installed, broken drop-in outright instead of restoring the
  last-known-good backup that had just been made moments earlier.**
  Reproduced directly this phase (fixture-isolated, no real
  `/etc/ssh`): sourced the generator, stubbed `post_install_check` to
  always fail, and called `apply_config` against the pre-fix code --
  confirmed the deployed fixture ended up deleted rather than restored.
- **Fix**: both messages now go to stderr (`>&2`) — `backup_existing()`'s
  stdout is now exactly a bare path, or nothing, matching what every
  caller has always assumed. No other behavior change: the function's
  return codes, the backup file itself, and every other message are
  unchanged.

### 2. `security/guardian_intervene_wrapper.sh` missing `validate_reason_strength` (Medium-low)

- Every other reason-gated Guardian CLI (`recover.sh`,
  `guardian_approve.sh`, `guardian_release_agent.sh`, all hardened in
  Phase 54/59) already refuses a one-keystroke or low-variety reason
  via `security/lib.sh`'s shared `validate_reason_strength`. Phase 64's
  intervention-channel wrapper passed `$SSH_ORIGINAL_COMMAND` straight
  to `guardian_require_human_approval` with no such check -- a real
  inconsistency, though not exploitable by an unauthenticated party
  (requires already possessing the Guardian-intervene SSH key).
- **Fix**: wired in the same `validate_reason_strength` call, same
  `WAIO_GUARDIAN_MIN_REASON_LENGTH`/`WAIO_GUARDIAN_MIN_REASON_DISTINCT_CHARS`
  env vars and defaults (20 / 8) as the rest of the Guardian CLI
  surface, same `EMPTY`/`TOO_SHORT`/`LOW_VARIETY`/`OK` dispatch pattern
  as `guardian_release_agent.sh`. A too-short or low-variety
  `SSH_ORIGINAL_COMMAND` now refuses (exit 1, explains why) **before**
  `guardian_require_human_approval` is ever called -- the Guardian
  Control Plane state is never escalated on an unexplained request. The
  pre-existing default text used when `SSH_ORIGINAL_COMMAND` is entirely
  absent ("guardian intervention request, no reason text supplied") is
  itself long and varied enough to already pass validation unchanged --
  Phase 64's existing G61 (missing-reason case) needed no change.
- `tests/ducopa_guardian_test.sh`'s existing G60 used a reason
  ("g60 request", 11 characters) that this fix's new validation now
  correctly rejects as too short -- G60 itself only asserts that the
  real `SHUTDOWN_LOCK` stays untouched, which remains true either way,
  so it did not fail, but it would have silently stopped exercising a
  genuinely successful wrapper call. Updated G60's reason text to be
  validation-compliant so it still tests what it always meant to.

### 3. `workers/host800_worker.sh` missing `set -uo pipefail` (Low)

- Every sibling worker (`rpi_worker.sh`, `ai_worker.sh`,
  `analysis_worker.sh`, `research_worker.sh`, `orchestrate_worker.sh`)
  has had `set -uo pipefail` since its own introduction;
  `host800_worker.sh` alone was missing it. Added, no other change.
  Confirmed no unset-variable regression: every existing invocation
  (real dispatch via `waio.sh`, and every direct-invocation test) always
  passes an explicit (possibly empty-string) `$1`, so `REQUEST="$1"`
  was never actually at risk under `set -u` -- re-verified by re-running
  every test that calls this script directly after adding the flag.

### New regression coverage

- `tests/ducopa_guardian_test.sh` (G63-G65 new, 8 assertions, suite
  total 148 -> 156): mirrors `guardian_release_agent.sh`'s own G36-G38
  exactly, against `guardian_intervene_wrapper.sh` instead -- too-short
  rejected (state stays `NORMAL`), low-variety rejected (state stays
  `NORMAL`), and the two override env vars honored (accepted under a
  lowered threshold, state correctly escalates).
- `tests/ssh_guardian_config_test.sh` (SG19-SG21 new): SG19 proves
  `backup_existing()`'s stdout is a single line and an actually-existing
  file path when a backup is made; SG20 proves it is empty when there
  is nothing to back up; SG21 is the end-to-end regression test Phase
  68 found entirely missing -- stubs `post_install_check` to fail after
  a real backup+install against fixtures, and proves `apply_config`
  genuinely **restores** the prior deployed content (not delete,
  not leave the broken new config in place).

### Verification

- Verified 2026-09-18: `tests/ducopa_guardian_test.sh` **156/0** (148
  prior, including Phase 70's G62, + 8 new assertions across G63-G65
  this phase = 156), `tests/ssh_guardian_config_test.sh` **48/0, 2
  skipped** (2 skips are
  the pre-existing, unrelated live-LAN-reachability SG16/SG18, same as
  every prior run of this suite). `tests/ducopa_core_test.sh`,
  `tests/waio_test.sh`, `tests/orchestrate_worker_test.sh`,
  `tests/recovery_hardening_test.sh`, `tests/audit_log_integrity_test.sh`,
  `tests/jobs_taco_control_dlp_test.sh`,
  `tests/rpi_command_injection_test.sh`,
  `tests/taco_control_injection_test.sh`,
  `tests/collect_status_guardian_test.sh`,
  `tests/dashboard_guardian_ui_test.sh` all re-run unaffected.
  `tests/security_test.sh` was **not** run directly, per the
  local-execution-context policy Phase 54 adopted (unchanged reasoning).
- `bash -n` clean on all five changed files
  (`security/generate_ssh_guardian_config.sh`,
  `security/guardian_intervene_wrapper.sh`, `workers/host800_worker.sh`,
  `tests/ducopa_guardian_test.sh`, `tests/ssh_guardian_config_test.sh`).
  Already covered by `.github/workflows/lint.yml`'s existing
  `security/*.sh`/`workers/*.sh`/`tests/*.sh` globs -- no `lint.yml`
  change needed.
- This deployment's real `security/state/SHUTDOWN.lock`, `GUARDIAN_STATE`,
  `GUARDIAN_QUARANTINE`, and `GUARDIAN_CRITICAL_EVENTS` confirmed absent
  both before and after this phase's work; no real `/etc/ssh` or SSH
  config touched (`tests/ssh_guardian_config_test.sh` remains entirely
  fixture-isolated).
- Landed via a feature branch + PR into `develop` (this repo's required
  workflow), never a direct push.
- **Not implemented, explicitly out of scope this phase**: the
  operator's own real-world verification of 800号機's true IP (`.91` vs
  `.80`, Phase 68's own open item -- cannot be determined or changed by
  reading/writing code); anything DuCoPA-specific -- the standing items
  (real deployment of Phase 64's intervention channel, additional
  intervention actions beyond `HUMAN_APPROVAL_REQUIRED`, live Takomachi
  integration, any change to `security/ducopa.sh`) remain unchanged and
  still open.

## Phase 72 (2026-09-18): second Guardian intervention action -- Guardian-initiated single-agent quarantine

Requested as the next DuCoPA standing item: Phase 64 deliberately built
only one intervention action (`HUMAN_APPROVAL_REQUIRED`) and explicitly
left room for "additional, separately-keyed actions behind their own
forced-command wrappers (one key, one fixed command each)" as a future
phase. This phase builds the second one. Scoped, per explicit
direction, to **code and tests that complete entirely in this
environment** -- no real key generation, no `authorized_keys` or
`sshd_config.d` edit, no SSH connection to any real host. Real
deployment remains a separate, later, operator-driven decision (same
boundary Phase 64 itself drew for its own wrapper).

### 1. Why quarantine, and why this is narrower authority than Phase 64's own action

- `HUMAN_APPROVAL_REQUIRED` blocks **all** new dispatch system-wide
  until an operator clears it. Quarantining one named agent
  (`guardian_quarantine_agent`, existing since Phase 57) blocks
  dispatch to **only that agent** -- every other agent is unaffected
  (`guardian_is_quarantined` is gated separately from
  `guardian_is_blocking`/the Guardian's global state, see G24). Adding
  this as intervention action #2 is, if anything, a *narrower* grant of
  remote authority than action #1 already carries, not a broader one.
- Reuses `guardian_quarantine_agent` exactly as-is -- the same function
  Phase 60's opt-in automatic-quarantine policy already calls, never a
  parallel mechanism. No change to `security/guardian.sh` itself this
  phase.
- Quarantine had no CLI of any kind before this phase (Phase 57's own
  header: "Quarantine itself has no CLI... an explicit, Guardian-driven
  action"). This wrapper is the first way to deliberately, manually
  quarantine one agent for a stated reason -- previously only the
  opt-in threshold-based auto-quarantine (Phase 60) could ever add an
  agent to the list.

### 2. New `security/guardian_intervene_quarantine_wrapper.sh`

- Same `SSH_ORIGINAL_COMMAND`-quoting safety as
  `guardian_intervene_wrapper.sh`/`guardian_recover_wrapper.sh`: routed
  through a fixed `command=` path, the remote text is never re-parsed
  as shell syntax.
- **Command shape**: `"<AGENT> <reason text>"` -- `read -r AGENT
  REASON <<< "$SSH_ORIGINAL_COMMAND"` splits on the first run of
  whitespace; `REASON` keeps its own internal spacing exactly (`read`'s
  own behavior with N variables against more fields, not a manual
  split). This is **data for one fixed action**, never an action
  selector -- the wrapper always does exactly one thing (quarantine the
  named agent) -- so it does not conflict with Phase 64's own "never an
  argument-driven action selector over SSH" note, which was about
  choosing *which action* runs, not supplying a target for a single,
  already-fixed action. Mirrors how `security/guardian_release_agent.sh`
  already accepts an `AGENT` argument from a trusted local caller with
  no registry-membership check -- same posture here: neither the agent
  name nor the reason is ever executed as shell text (confirmed
  directly, G72 below), both are opaque data threaded through bash
  function parameters and `audit_log()` (which shells out to `python3`
  with `sys.argv`, never string interpolation).
- **Same minimum reason-strength discipline** as every reason-gated
  Guardian CLI since Phase 54/59/71 (`validate_reason_strength`, same
  `WAIO_GUARDIAN_MIN_REASON_LENGTH`/`WAIO_GUARDIAN_MIN_REASON_DISTINCT_CHARS`
  env vars/defaults). A missing agent name refuses immediately (exit 1,
  before the reason is even checked); a too-short/low-variety reason
  refuses next -- `guardian_quarantine_agent` is only ever called after
  both checks pass.
- **Idempotent, matching `guardian_quarantine_agent`'s own contract**:
  an already-quarantined agent is a no-op (exit 0, "already
  quarantined, nothing to do"), no duplicate audit event.
- **Never touches** `guardian_set_state`/the Guardian's global state
  machine, the real `SHUTDOWN_LOCK`, or any agent other than the one
  named -- confirmed directly (G70/G74/G75), not only by design intent.

### 3. New regression coverage: `tests/ducopa_guardian_test.sh` (G66-G75, 29 new assertions, suite total 156 -> 185)

- **G66**: no agent name given (empty `SSH_ORIGINAL_COMMAND`) refuses,
  global state stays `NORMAL`.
- **G67-G69**: agent given but reason empty/too-short/low-variety each
  refuse; the named agent is confirmed NOT quarantined in every case.
- **G70**: agent + a real reason quarantines exactly that agent,
  echoes the reason, points at `guardian_release_agent.sh` for release,
  leaves the global Guardian state at `NORMAL`, and logs exactly one
  `guardian_agent_quarantined` event.
- **G71**: an already-quarantined agent is a no-op, exit 0, and does
  **not** produce a second `guardian_agent_quarantined` event (proves
  idempotency end to end, not just by reading the reused function's
  own docstring).
- **G72**: shell-metacharacter agent/reason text is never re-executed
  -- mirrors G58's own command-injection check for the human-approval
  wrapper, same fixture-marker-file technique.
- **G73**: `WAIO_GUARDIAN_MIN_REASON_LENGTH`/`_DISTINCT_CHARS`
  overrides are honored, same as G38/G65.
- **G74**: the real `SHUTDOWN_LOCK` is confirmed untouched.
- **G75**: end-to-end through `waio.sh` itself, driven through this
  wrapper (not by calling `guardian_quarantine_agent` directly, unlike
  the reused registry-swap idiom G24 established) -- the quarantined
  agent's dispatch is refused, and a second, unrelated agent still
  dispatches normally, same registry-swap-aside-and-restore idiom as
  G24/every prior phase that needs a throwaway registry entry.
- Every pre-existing assertion (G1-G65) re-verified passing unchanged.

### 4. Verification

- Verified 2026-09-18: `tests/ducopa_guardian_test.sh` **185/0**.
  `tests/ducopa_core_test.sh`, `tests/waio_test.sh`,
  `tests/orchestrate_worker_test.sh`, `tests/recovery_hardening_test.sh`,
  `tests/audit_log_integrity_test.sh`,
  `tests/collect_status_guardian_test.sh`,
  `tests/dashboard_guardian_ui_test.sh` all re-run unaffected.
  `tests/security_test.sh` was **not** run directly, per the
  local-execution-context policy Phase 54 adopted (unchanged reasoning).
- Manually smoke-tested every path against scratch fixtures before
  writing the formal suite: missing agent, missing/weak reason,
  successful quarantine, idempotent re-quarantine, global state
  untouched, and a direct shell-metacharacter injection attempt (fixed
  marker file, confirmed never created).
- `bash -n` clean on the new file and the changed test file. Already
  covered by `.github/workflows/lint.yml`'s existing
  `security/*.sh`/`tests/*.sh` globs -- no `lint.yml` change needed.
- This deployment's real `security/state/SHUTDOWN.lock`, `GUARDIAN_STATE`,
  `GUARDIAN_QUARANTINE`, and `GUARDIAN_CRITICAL_EVENTS` confirmed absent
  both before and after this phase's work. No real SSH key generated,
  no `~/.ssh/authorized_keys` or `sshd_config.d` file touched, no SSH
  connection to any real host made.
- Landed via a feature branch + PR into `develop` (this repo's required
  workflow), never a direct push.
- **Not implemented, explicitly out of scope this phase, by explicit
  direction**: real deployment of this wrapper (generating a real
  Guardian-intervene-quarantine SSH keypair, writing its
  `authorized_keys` forced-command line, any real `sshd_config.d`
  change) -- entirely an operator-driven action, same boundary Phase 64
  drew for its own wrapper; the operator's own real-world verification
  of 800号機's true IP (Phase 68's own open item, unrelated to this
  phase); any change to `security/ducopa.sh`; live Takomachi
  integration. The standing items list shrinks by one ("additional
  intervention actions beyond `HUMAN_APPROVAL_REQUIRED`" is now done in
  code) but the rest remain open.

## Phase 73 (2026-09-18): G62 concurrency-test retry -- test reliability only, no production or safety-boundary change

Investigated after `tests/ducopa_guardian_test.sh`'s G62 (Phase 70's
40-way concurrency proof) was observed failing on GitHub Actions
multiple times across recent PRs, including once on a PR that touched
**only** `ARCHITECTURE.md` -- direct proof the flake is an existing,
environment-dependent property of already-merged code, not a
regression introduced by any recent phase.

### Root cause investigated, not fixed at the production-code level (by explicit direction)

- `_guardian_maybe_auto_quarantine`'s `GUARDIAN_STATE_LOCK_DIR` lock
  deliberately fails OPEN under sustained contention (Phase 70's own
  documented contract, matching `audit_log()`'s established one: a
  best-effort safety feature must never block or abort a caller).
- Measured directly on an 8-core local machine: the exact 40-way G62
  burst takes 7s idle, 10-19s under artificial heavy CPU load -- far
  closer to the lock's 15s (`GUARDIAN_STATE_LOCK_MAX_WAIT_ITERATIONS`,
  default 150 x 0.1s) give-up budget than Phase 70 assumed ("far beyond
  anything this codebase's own concurrency levels produce"). GitHub
  Actions' standard Linux runners have 2 vCPUs, far fewer than this
  local machine.
- Directly confirmed the lock genuinely fails open under contention: with
  the budget deliberately shrunk to 2 iterations under heavy load, 36
  of 40 real concurrent lock-acquire attempts timed out.
- **However**, forcing that same fail-open condition did **not**
  reliably reproduce a lost update: 15/15 local trials (heavy load +
  shrunk budget, the same adversarial setup that reproduced the raw
  lock timeout) still converged correctly. This matches the *original*
  bug's own historical reproduction rate (Phase 70's commit: ~1-in-3,
  even fully unlocked) -- the unprotected read-increment-write window
  itself is short enough that even many concurrent unlocked attempts
  don't reliably collide. G62's CI flakiness is therefore a compound,
  low-probability event (lock timeout AND a subsequent real collision),
  more likely under CI's real resource constraints than locally, not a
  deterministic bug.
- **Explicit decision, per direction**: `security/guardian.sh`'s
  fail-open design is a deliberate, already-accepted safety tradeoff
  (favor availability over strict serialization for a best-effort,
  opt-in feature) and is **not** changed by this phase. No production
  file was touched.

### Fix: retry, inside the test only

- `tests/ducopa_guardian_test.sh`'s G62 now runs its 40-way burst up
  to 3 times (fresh fixture state each attempt via
  `fixture_reset "g62-attempt$g62_attempt"`), stopping as soon as one
  attempt converges (quarantined, exactly one auto-quarantine event,
  all 40 notifications recorded). The three original assertions are
  unchanged in wording and count -- they evaluate the final attempt's
  outcome exactly once, after the retry loop, so a genuine regression
  (never converging in any of 3 attempts) still fails the case for
  real, with the same three assertion messages as before.
- Verified the retry loop's own control flow in isolation (a
  standalone script with stub functions) before relying on it: an
  "eventually converges on attempt 3" case correctly breaks early and
  reports the converged (`true`) result; an "always fails" case
  correctly exhausts all 3 attempts and reports the final (`false`)
  result -- proving a real regression is still caught, not silently
  masked by the retry.
- Attempted to force the retry path to actually engage under the same
  adversarial local conditions (heavy load + shrunk lock budget) that
  earlier confirmed fail-open occurs -- G62 still converged on attempt
  1 every time tried, consistent with the low, compound probability
  established above. The retry path's correctness was therefore
  verified via the isolated control-flow check above, not via an
  organic reproduction in this environment.

### Verification

- Verified 2026-09-18: `tests/ducopa_guardian_test.sh` **185/0**
  (assertion count unchanged -- this phase does not add or remove any
  assertion, only wraps existing G62 execution in a retry). `bash -n`
  clean. `tests/ducopa_core_test.sh`, `tests/waio_test.sh`,
  `tests/orchestrate_worker_test.sh`,
  `tests/recovery_hardening_test.sh`,
  `tests/audit_log_integrity_test.sh` all re-run unaffected.
  `tests/security_test.sh` was **not** run directly, per the
  local-execution-context policy Phase 54 adopted (unchanged
  reasoning).
- Already covered by `.github/workflows/lint.yml`'s existing
  `tests/*.sh` glob -- no `lint.yml` change needed.
- This deployment's real `security/state/SHUTDOWN.lock`, `GUARDIAN_STATE`,
  `GUARDIAN_QUARANTINE`, and `GUARDIAN_CRITICAL_EVENTS` confirmed absent
  both before and after this phase's work. No production file touched
  (`security/guardian.sh`, `security/lib.sh` unchanged) -- confirmed by
  `git diff --stat` showing only `tests/ducopa_guardian_test.sh`
  modified.
- Landed via a feature branch + PR into `develop` (this repo's required
  workflow), never a direct push.
- **Not implemented, explicitly out of scope this phase, by explicit
  direction**: any change to `security/guardian.sh`'s locking or
  fail-open design; widening `GUARDIAN_STATE_LOCK_MAX_WAIT_ITERATIONS`'s
  default; an append-only counter redesign that would remove the need
  for this lock entirely -- all considered during investigation and
  set aside as production-code changes outside this phase's
  test-reliability-only scope.

## DuCoPA Guardian security audit -- consolidated status after Phase 68/71/72 (2026-09-18)

Phase 68's full-repository security audit (six findings) and the two
follow-on phases that closed its remaining code-addressable findings
(Phase 71) plus one long-standing DuCoPA item unrelated to the audit
itself (Phase 72) are now spread across five separate phase entries
(68, 69, 70, 71, 72). This section consolidates the current status in
one place, the same way "Red Team -- final classification" (2026-08-31,
above) consolidated every Red-Team-labeled phase into one summary.
Nothing below is a new decision or a new fix -- it is a summary of
decisions and fixes each already recorded, in full, in their own phase
entry.

### Phase 68's six findings: all six now closed in code

| # | Severity | Finding | Closed by |
|---|----------|---------|-----------|
| 1 | Critical | `taco_control_dispatch.sh`'s hardcoded default destination collides with `workers/800.json`'s real host, silently defeating the intended fail-closed `egress_check` gate | **Phase 68 itself** -- new host-collision guard |
| 2 | High | Every SSH-based dispatch path (`rpi_worker.sh`/`host800_worker.sh`/`taco_control_dispatch.sh`/`jobs/*.sh`) called only `egress_check`, never `payload_size_check`/`secret_leak_check` | **Phase 69** |
| 3 | Medium | `guardian.sh`'s auto-quarantine counter did an unguarded read-modify-write -- a lost-update race under concurrency | **Phase 70** |
| 4 | Medium | `generate_ssh_guardian_config.sh`'s `backup_existing()` leaked its progress message onto the same stdout `apply_config()` captures as a bare path, breaking revert-on-failure | **Phase 71** |
| 5 | Medium-low | `guardian_intervene_wrapper.sh` (Phase 64) never called `validate_reason_strength`, unlike every other reason-gated Guardian CLI | **Phase 71** |
| 6 | Low | `host800_worker.sh` was missing `set -uo pipefail`, present in every sibling worker | **Phase 71** |

**One item from finding 1's own fix remains open, and cannot be closed
by any further code change**: whether 800号機's real, current network
address is `192.168.1.91` (as this document's own history documents
throughout, Phase 33 onward) or `192.168.1.80` (as the live, gitignored
`workers/800.json` and `security/egress_allowlist.conf` say) is a
real-world fact about this deployment's actual network, not something
resolvable by reading or writing code. Phase 68's own guard makes the
ambiguity safe either way (refuses if `taco_control_dispatch.sh`'s
destination ever collides with whichever host `workers/800.json`
actually names) without needing to know which IP is correct -- but the
operator's own confirmation of the true IP, and a check that the real
SSH `from="..."`/`Match Address` restrictions actually match it, is
still outstanding.

### DuCoPA standing items (repeated in every phase's "out of scope" note since Phase 61): one closed, three still open

| Item | Status |
|------|--------|
| Additional Guardian intervention actions beyond `HUMAN_APPROVAL_REQUIRED` | **Closed in code by Phase 72** (single-agent quarantine, a second separately-keyed action) |
| Real deployment of the intervention channel(s) (Phase 64's `HUMAN_APPROVAL_REQUIRED` wrapper and Phase 72's quarantine wrapper) -- real SSH keypairs, `authorized_keys` forced-command lines, an 800号機-side trigger script | **Still open** -- operator-driven, and structurally unverifiable from this environment (Red Team Phase 4's own finding: no second physical host exists on this LAN to originate a real test connection) |
| Live Takomachi integration across a real separated channel | **Still open** |
| Any change to `security/ducopa.sh` (the standalone prototype, kept isolated since Phase 59) | **Still open** -- no scope has ever been defined for this item |

### Verification totals across the five phases

- `tests/ducopa_guardian_test.sh`: 145 (end of Phase 67) -> 148 (Phase 70) -> 156 (Phase 71) -> **185** (Phase 72), 0 failures at every step.
- `tests/ssh_guardian_config_test.sh`: 41 -> **48** (Phase 71), 0 failures, 2 pre-existing unrelated live-LAN skips throughout (directly re-confirmed by running the pre-Phase-71 version of this suite in place: 41/0/2).
- `tests/jobs_taco_control_dlp_test.sh`: 84 -> **112** (Phase 69), 0 failures.
- `tests/rpi_command_injection_test.sh`: 47 -> **54** (Phase 69), 0 failures.
- Every other pre-existing suite (`ducopa_core_test.sh`, `waio_test.sh`, `orchestrate_worker_test.sh`, `recovery_hardening_test.sh`, `audit_log_integrity_test.sh`, `collect_status_guardian_test.sh`, `dashboard_guardian_ui_test.sh`, `taco_control_injection_test.sh`) re-run unaffected at every phase in this arc.
- A pre-existing, probabilistic flake in `tests/ducopa_guardian_test.sh`'s own G62 (Phase 70's 40-way concurrency proof) was observed intermittently in CI across this arc's own PRs (roughly 1 failure in 4-5 CI runs, including once on a docs-only PR) -- not a regression introduced by any phase in this arc. **Investigated and hardened by Phase 73** (below): confirmed the cause (the lock's own documented fail-open behavior, more likely to trigger under GitHub Actions' 2-vCPU runners than assumed), left `security/guardian.sh`'s fail-open design unchanged by explicit direction, and added a test-only retry (up to 3 attempts) to `tests/ducopa_guardian_test.sh`'s G62 so a genuine regression still fails while this specific environment-dependent flake no longer requires a manual CI rerun.
- All five phases landed via a feature branch + PR into `develop` (this repo's required workflow), each subsequently synced into `master` via a separate `sync: develop into master` PR -- never a direct push to either branch.

### What this leaves for a future phase

- Operator-only: confirm 800号機's true IP and its real SSH restriction; real deployment of both intervention-channel wrappers.
- Undefined scope, needs a decision before any code work: any change to `security/ducopa.sh`.
- Not yet started, no blocker either: live Takomachi integration.
- Not part of this arc, but noted during the broader repo survey that produced Phase 72's candidate list: `security/incident_learning/` (Steps 1-8, fully implemented, three commits) has no dedicated ARCHITECTURE.md section of its own -- a documentation gap of the same shape Phase 59 found and closed for `security/ducopa.sh`.

## Phase 74 (2026-09-18): `security/incident_learning/` documentation gap closed -- dedicated ARCHITECTURE.md section for the Incident Learning Engine

Closes the gap this file itself flagged above ("What this leaves for a
future phase," Phase 68/71/72 consolidated status): `security/incident_learning/`
(Steps 1-8) had no dedicated section here, the same shape of gap Phase
59 found and closed for `security/ducopa.sh`. **Documentation only --
no code, test, or config file changed this phase**; every fact below
was re-derived by reading the current code and re-running its test
suites, not copied from prior commit messages unverified (one
inaccuracy in an earlier commit message is corrected below).

Landed across four commits, all already merged into `develop` before
this phase (`5d8d3d6` Step 1, `8afcd70` Step 2, `31ff9f7` Steps 3-8,
`a3b84a9` a Step 6 runtime-wiring audit) -- one more commit than the
consolidated-status note above stated ("three commits"), corrected
here.

### 1. What it is

A pipeline that turns an external incident report (a CVE advisory, an
IOC feed, a vendor bulletin) into a human-approved entry in
`security/knowledge/`, modeled directly on `security/segment_manager.sh`'s
own state-machine shape (same load/status/transition_allowed/transition/
audit_log split, same append-only JSONL audit trail, same "the state
machine graph is the actual enforcement point, not documentation"
posture). Explicit founding constraint carried through every file in
this domain: "自動学習＝無条件で自動採用にはするな" -- automated
learning must never auto-adopt without a human gate. `earth_weather/`
(Phase 55/56) is modeled on this same collector -> normalizer -> analysis
shape but is otherwise unrelated code.

### 2. The state machine (`security/incident_learning/knowledge_manager.sh`)

```
COLLECTED -> NORMALIZED -> VERIFIED -> ANALYZED -> SCORED -> CANDIDATE
                                                                 |  \
                                                                 |   -> REJECTED
                                                                 v
                                                                HOLD <-> CANDIDATE
                                                                 |
                                                        (via CANDIDATE or HOLD)
                                                                 v
                                                             APPROVED -> PROMOTED
```

Every stage except `HOLD`/`APPROVED`/`PROMOTED` can also transition
directly to `REJECTED` (malformed input, no traceable source,
duplicate/contamination, or confidence below `KNOWLEDGE_MIN_CONFIDENCE`,
default 50). There is **no `--force` override anywhere in this file**
(unlike `segment_manager.sh`'s `failed->isolated` escape hatch) -- every
path to `PROMOTED` runs through the human gate, with no legitimate
reason to skip it. `knowledge_manager.sh` is the *only* code that ever
writes a candidate's state file or a knowledge entry; every other
script in this domain calls into it rather than writing state directly.
Reserved fields (`status`, `confidence_score`, the four `evidence_*`
fields, etc.) cannot be set via a caller-supplied `KEY=VALUE` extra on
`create`/`advance` -- closing a forgery gap found during Steps 3-8's own
final audit, where `advance ID VERIFIED "reason" evidence_corroborating_count=99`
could otherwise fabricate Evidence's output directly. `record-evidence`
and `score` are the only commands that may set the evidence/confidence
fields, and both are resumable if a crash strands a candidate mid-stage
(`VERIFIED` without having reached `ANALYZED`, or `SCORED` without the
threshold decision yet applied) -- each re-run completes the remaining
write using the value already persisted, never a freshly recomputed
one. `promote` is similarly idempotent (already-`PROMOTED` is a no-op)
and self-reconciles the one crash window Step 7's hardening left open:
if a knowledge file already exists at the real path while the candidate
is still `APPROVED` (exactly what a kill between the file's atomic `mv`
and the `PROMOTED` transition would leave), it verifies the file
matches the current approval before completing the transition, never
rewriting it; a non-matching file is still refused outright.

### 3. The pipeline, one stage per file

- **`security/incident_learning/collectors/mock_collector.sh`**
  (Step 2): the only Collector that exists today. Emits 3 fixed,
  entirely fictional `RawIncident` records (JSONL: `id`/`source`/
  `source_type`/`source_url`/`collected_at`/`raw_text`, `example.invalid`
  domains, CVE ids in an unassigned range) -- zero network calls,
  confirmed by a static grep test for `curl`/`wget`/`nc`. Establishes
  the Collector contract any future real Collector (CISA KEV, CERT,
  NVD, a vendor feed) must conform to, so nothing downstream needs to
  know which Collector produced a record.
- **`incident_normalizer.sh`** (Step 2): `COLLECTED -> NORMALIZED`.
  Creates a Knowledge Candidate per new id (idempotent -- re-feeding the
  same record is a no-op) and extracts CVE ids / IPv4-shaped IOCs /
  detection-point / mitigation sentences via deliberately simple regex,
  not real NLP -- trust establishment is Evidence's job, not this
  stage's. Only ever acts on candidates still at `COLLECTED`.
- **`incident_evidence.sh`** (Step 3, part 1): `NORMALIZED -> VERIFIED`,
  then immediately to `ANALYZED` via a labeled placeholder (see
  limitation below). "Verified" means *examined and recorded*, not
  *confirmed true* -- a single-source, uncorroborated report still
  reaches `VERIFIED` (weak evidence, not rejection). The only rejection
  path here is an empty `source_url` (no traceable source at all).
  Records `evidence_source_type`/`evidence_corroborating_count`/
  `evidence_age_days`/`evidence_self_reported_uncorroborated` (the last
  a keyword scan for phrases like "single source"/"unverified" in the
  raw text itself).
- **`incident_confidence.sh`** (Step 3, part 2): `ANALYZED -> SCORED`,
  then hands the score to `knowledge_manager.sh score`, which owns the
  `SCORED -> CANDIDATE`/`REJECTED` threshold decision. A fully
  auditable 0-100 formula built only from Evidence's own recorded
  fields -- no new data fetched: source-type base weight
  (`vendor_advisory`=40, `cert`=35, `news`=20, `unknown`=5) + up to +30
  corroboration bonus (capped at 2 corroborating sources, so a single
  talkative "source" can't be split into many to game it) - 25
  staleness penalty (`evidence_age_days` > 30) - 20 self-reported-
  uncorroborated penalty.
- **`incident_human_gate.sh`** (Step 4): the only human-facing layer,
  adding no new state-machine edge. `review ID` is read-only, printing
  every Evidence/Confidence field already on the candidate so a
  reviewer sees the actual basis for the score before deciding.
  `approve`/`reject`/`hold`/`release` are thin wrappers over
  `knowledge_manager.sh`'s own commands of the same name that (a)
  refuse with a clear message if the candidate isn't in a state that
  action applies to, and (b) fold the same Evidence/Confidence summary
  into the audit reason string itself, so every human decision's audit
  entry permanently records what evidence was in front of the human
  when they made it. Never calls `promote` -- promotion stays a
  distinct, separate human action.
- **`incident_learning_cron.sh` + `com.waio.incident-learning.plist.example`**
  (Step 6): the scheduled entry point for the *automated* portion only
  -- every collector piped through the normalizer, then Evidence, then
  Confidence. **Never** calls `approve`/`reject`/`hold`/`release`/
  `promote`, and never calls `incident_human_gate.sh` at all: reaching
  `CANDIDATE` is exactly as far as automation goes. Idempotent (safe to
  run twice back-to-back). A per-user launchd agent template, same
  Public/Private Boundary pattern as `security/com.waio.segment-monitor.plist.example`
  -- the real, installed copy is deployment-specific and not committed.
  Confirmed via `launchctl list` this template is **not installed** on
  this machine (a dev checkout, not a live deployment, same as its
  segment-monitor/dashboard-refresh siblings).

### 4. DuCoPA isolation (explicit, load-bearing, identical across every file in this domain)

No file under `security/incident_learning/` ever reads or writes
`security/egress_allowlist.conf`, `security/segments.conf`,
`security/ssh_management_allowlist.conf`, or `sshd_config`, and makes
no network call anywhere in the domain (each Collector's own header
states this; the collector test suite additionally greps for
`curl`/`wget`/`nc`/`ssh` and asserts zero matches). A promoted entry
lands in `security/knowledge/`, a separate namespace nothing else in
this repo reads from -- confirmed by a repo-wide grep: no file outside
`security/incident_learning/` and `tests/incident_learning_*` (`earth_weather/`
excepted, unrelated code sharing only the pipeline shape) references
any of this domain's scripts or functions.

### 5. Known, already-documented limitations (not new findings; not addressed this phase)

- **`incident_analyzer.sh` does not exist.** `VERIFIED -> ANALYZED` is
  a hardcoded placeholder inside `incident_evidence.sh` itself (an
  explicitly labeled "no duplicate/pattern analysis implemented yet"
  reason string, not a real analysis claim) -- re-confirmed by reading
  the code this phase, not assumed from the commit history.
- **No Dashboard visibility.** Unlike `security/segment_monitor_cron.sh`'s
  own passive surface, nothing shows a human that a `CANDIDATE` exists
  once cron produces one -- an operator must run `knowledge_manager.sh
  list` / `incident_human_gate.sh review` by hand to find out.
- **No concurrent-process locking**, consistent with this codebase
  having no locking precedent anywhere `security/guardian.sh`'s own
  best-effort lock excepted (Phase 57/70).
- **Only one Collector exists** (the fixed-data mock) -- a real
  Collector (CISA KEV/CERT/NVD/vendor advisory) is not yet built.
- **Minor correction**: an earlier commit message in this domain
  described `security/knowledge/` as gitignored alongside
  `security/state/`/`logs/`. Checked directly this phase: it is **not**
  in `.gitignore` (only `security/state/`, `logs/`, and the Phase
  29 Public/Private Boundary files are). The directory is simply empty
  in this checkout (git does not track empty directories) -- a real
  promoted entry would be an ordinary trackable file unless someone
  deliberately adds `security/knowledge/` to `.gitignore` first. Not
  fixed this phase (no promoted entry exists in this checkout to make
  the gap concrete, and this phase's own scope is documentation, not a
  `.gitignore` change); flagged as a candidate for whichever future
  phase first promotes a real entry.

### 6. Verification

- Verified 2026-09-18: all 8 `tests/incident_learning_*_test.sh` suites
  re-run fresh, **344/0** total, unchanged from `a3b84a9`'s own count
  (`incident_learning_test.sh` 35, `_collector_test.sh` 26,
  `_evidence_test.sh` 28, `_human_gate_test.sh` 45, `_promote_test.sh`
  55, `_cron_test.sh` 22, `_advance_hardening_test.sh` 81,
  `_failsafe_test.sh` 52). `git status`/`git diff --stat` confirm only
  `ARCHITECTURE.md` changed this phase -- no file under
  `security/incident_learning/` or `tests/incident_learning_*.sh`
  touched.
- **Not implemented, explicitly out of scope this phase**: building
  `incident_analyzer.sh`; Dashboard integration for Incident Learning
  candidates; a real (non-mock) Collector; concurrent-process locking;
  adding `security/knowledge/` to `.gitignore`. All are pre-existing,
  already-documented gaps (Steps 1-8's own commit messages, and the
  `a3b84a9` runtime-wiring audit), not new findings, and none is
  addressed by this documentation-only phase.

## Phase 75 (2026-09-18): `security/incident_learning/incident_analyzer.sh` -- real VERIFIED->ANALYZED/REJECTED duplicate check, closing Phase 74's own documented placeholder gap

Implements the single most concretely-scoped, no-operator-dependency
gap Phase 74 flagged: `VERIFIED -> ANALYZED` was `incident_evidence.sh`'s
own hardcoded placeholder (`"placeholder: no duplicate/pattern analysis
implemented yet"`), never a real check, since `incident_analyzer.sh` --
named in `knowledge_manager.sh`'s own state-machine header since Step 1
-- did not yet exist. This phase builds it.

### 1. Scope decision: checked against `security/knowledge/` only, never other in-flight candidates

Per `knowledge_manager.sh`'s own header ("`VERIFIED -> ANALYZED
(incident_analyzer.sh: checked against existing knowledge)`"), this
file compares a candidate only against already-**PROMOTED** entries.
Comparing against other candidates still earlier in the pipeline was
deliberately rejected: two independent reports of the same real
incident, collected around the same time, would then reject each other
purely by processing order -- a non-deterministic, order-dependent
outcome for what should be a stable decision. Checking only against
what has already survived the full human gate gives an order-
independent target that only grows one entry at a time, each already
vetted.

### 2. What counts as a duplicate or contamination

Four signals, each compared against every entry in `security/knowledge/`:

- **CVE overlap** -- any `cve_list` entry in common with a promoted
  entry's own `cve_list`.
- **IOC overlap** -- any `ioc_list` entry in common.
- **Same `source_url`** -- a second collection of the exact same
  source (most likely a Collector that doesn't dedupe on its own
  side).
- **Contamination (a narrower, distinct signal from the three above)**
  -- byte-identical `raw_text` to a promoted entry, which two
  independent sources describing the same incident in their own words
  cannot explain.

A candidate matching any of these reaches `REJECTED` via `knowledge_manager.sh`'s
own `advance` command (event `advanced`/action `pipeline`, the same
automated-not-human-gate framing `incident_evidence.sh`'s own
no-source-url rejection already uses -- see that file's own header on
why this distinction is load-bearing for `tests/incident_learning_cron_test.sh`'s
CR6). A candidate matching none of them reaches `ANALYZED`, with the
audit reason stating exactly how many existing knowledge entries it was
checked against (0 the first time this pipeline ever promotes
anything) -- the same "state the basis, not just the verdict"
convention `incident_confidence.sh`'s own formula already established.
No change to `knowledge_manager.sh` itself this phase: `VERIFIED->ANALYZED`/
`VERIFIED->REJECTED` were already legal `advance` targets before this
file existed.

### 3. `incident_evidence.sh` now stops at `VERIFIED`

Previously this file made two writes per candidate
(`NORMALIZED->VERIFIED`, then an unconditional `VERIFIED->ANALYZED`
placeholder advance) and needed a resume branch for a crash between
them (Step 8 hardening, `tests/incident_learning_failsafe_test.sh`'s own
R3/R4). With the placeholder removed, this file makes exactly one write
again -- `process_one` now skips (no-op, logged) anything not currently
`NORMALIZED`, including an already-`VERIFIED` candidate, the same
single-status-ownership idiom `incident_normalizer.sh` already uses.
The old two-write crash window no longer exists in this file; R3/R4 were
rewritten to test the simpler, now-correct property instead (re-running
`incident_evidence.sh` on an already-`VERIFIED` candidate is a clean
no-op, not a resume).

### 4. `incident_learning_cron.sh` gains a fourth automated step

Step 6's schedule now runs collector→normalizer→**`incident_evidence.sh`**→
**`incident_analyzer.sh`**→`incident_confidence.sh`, in that order --
still never touching the Human Gate or Promote (Step 6's own founding
constraint, re-verified unchanged by `tests/incident_learning_cron_test.sh`'s
CR6). Every fixed record `mock_collector.sh` emits is checked against
an *empty* `security/knowledge/` in every test run (a fresh fixture
each time), so this phase introduces no risk of the mock data
spuriously rejecting itself as a duplicate of another mock record --
duplicate detection only ever fires against already-promoted entries,
never siblings still in the same batch.

### 5. New regression suite: `tests/incident_learning_analyzer_test.sh` (34 assertions, A1-A10 + D1-D2)

- **A1**: the only end-to-end case -- a candidate is genuinely promoted
  through the real pipeline (create→normalize→evidence→analyze
  [clean, empty knowledge dir]→confidence→approve→promote), then a
  second, independently-worded candidate sharing its CVE is correctly
  `REJECTED` as a duplicate of the *real* promoted entry, not a
  hand-crafted fixture.
- **A2-A4**: IOC overlap, same-`source_url`, and byte-identical-`raw_text`
  ("contamination suspected", distinct wording from plain "duplicate")
  each isolated against a hand-crafted knowledge fixture (same
  test-only direct-write technique `tests/incident_learning_failsafe_test.sh`'s
  own R2 already uses).
- **A5**: a genuinely clean candidate reaches `ANALYZED`, with the
  audit reason naming the exact count of existing entries checked.
- **A6**: skips a candidate not yet `VERIFIED`.
- **A7-A8**: idempotency -- re-running on an already-`ANALYZED` or
  already-`REJECTED` candidate is a clean no-op, zero new audit lines.
- **A9**: an unreadable/malformed `security/knowledge/*.json` file
  (simulating a partially-written or foreign file) is skipped during
  the scan, never fatal to the run.
- **A10**: the full-loop (no-id) invocation processes every `VERIFIED`
  candidate in one pass and leaves a still-`NORMALIZED` one untouched.
- **D1-D2**: DuCoPA boundary (no Control Plane file touched) and a
  static zero-network-call guard, same convention as every other suite
  in this domain.

### 6. Updated suites

- `tests/incident_learning_evidence_test.sh`: 28 -> **31** (E1/E3/E4
  each gained an explicit `analyzer()` call + assertion to reach
  `ANALYZED`, since that is no longer `incident_evidence.sh`'s own job;
  E5's skip message updated to `"not NORMALIZED"`).
- `tests/incident_learning_failsafe_test.sh`: **52** (unchanged count
  -- R3/R4 rewritten in place for the new single-write architecture,
  same number of assertions).
- `tests/incident_learning_cron_test.sh`: 22 -> **23** (CR2 gains an
  `incident_analyzer.sh: ok` log-line assertion).
- `tests/incident_learning_promote_test.sh`, `tests/incident_learning_human_gate_test.sh`,
  `tests/incident_learning_advance_hardening_test.sh`: **unaffected**
  (all three already build their own `ANALYZED` fixtures via a direct
  `km advance ID ANALYZED "t"` call, bypassing `incident_evidence.sh`'s
  own advance entirely -- confirmed by reading each file, not assumed).

### 7. Verification

- Verified 2026-09-18: all 9 `tests/incident_learning_*_test.sh` suites,
  **382/0** total (35 + 26 + 31 + 34 + 45 + 55 + 23 + 81 + 52). Broader
  regression re-run unaffected: `tests/waio_test.sh` 28/0,
  `tests/orchestrate_worker_test.sh` 77/0/0,
  `tests/ducopa_core_test.sh` 54/0, `tests/ducopa_guardian_test.sh`
  185/0, `tests/recovery_hardening_test.sh` 45/0,
  `tests/audit_log_integrity_test.sh` 46/0.
- `shellcheck -S error` (the exact CI gate) clean across the full
  `waio.sh workers/*.sh security/*.sh tests/*.sh tests/security_fixtures/*.sh`
  fileset, including both new files. `bash -n` clean across the full
  `lint.yml` fileset.
- `git status`/`git diff --stat` confirm exactly the expected files
  changed: new `security/incident_learning/incident_analyzer.sh` and
  `tests/incident_learning_analyzer_test.sh`; modified
  `incident_evidence.sh`, `incident_learning_cron.sh`,
  `incident_learning_evidence_test.sh`, `incident_learning_failsafe_test.sh`,
  `incident_learning_cron_test.sh`. `knowledge_manager.sh` untouched
  (no state-machine change needed -- see section 2 above). This
  deployment's real `security/knowledge/` confirmed empty both before
  and after (git-untracked, unaffected either way).
- **Not implemented, explicitly out of scope this phase** (unchanged
  from Phase 74's own list): Dashboard integration for Incident
  Learning candidates; a real (non-mock) Collector; concurrent-process
  locking; adding `security/knowledge/` to `.gitignore`.

## Phase 76 (2026-09-18/19): Dashboard integration -- Incident Learning, Takomachi, and an optional SND panel added to the existing `dashboard/`

Closes the first item of Phase 75's own out-of-scope list ("Dashboard
integration for Incident Learning candidates") and, per explicit
instruction, extends the request to a broader "WAIO as the top-level
dashboard" picture covering WAIO/DuCoPA/Takomachi/SND/Incident
Learning together. Before writing any code, investigated whether a
separate dashboard needed to exist at all.

### 1. Architecture decision: extend the existing `dashboard/`, do not build a second one, and do not make WAIO absorb SND/Takomachi's own aggregator role

`dashboard/` already exists (Phase 49-63) with a live collector/panel
pattern; WAIO's own status and the DuCoPA Guardian Control Plane
(Phase 57-63) were already fully represented there. So "WAIO becomes
the top-level dashboard" meant extending this file, not creating a
new one.

For SND specifically, investigation found a real conflict with a
prior, deliberate architecture decision (Phase 51-53): SND_HOME's own
`CLAUDE.md` states WAIO must only consume its JSON/API, never merge
code with it ("混在させません"), and a separate, dedicated project,
`~/lan-dashboard-gateway`, already exists specifically to aggregate
WAIO + Takomachi + SND_HOME. Checked this machine directly: neither
SND_HOME nor `~/lan-dashboard-gateway` is present here any more (only
a backup copy of SND_HOME on an external volume) -- so a live SND
panel would show "not configured" regardless. Per explicit user
decision: this phase does NOT reverse Phase 53's decision or have
WAIO absorb the Gateway project's aggregator role -- it adds SND as
this dashboard's own optional, additional, off-by-default panel
(`SND_HOME_API_URL` unset by default), never a replacement for the
Gateway project.

### 2. New panel: Incident Learning Engine (`dashboard/collect_incident_learning_status.sh`)

Fully local, zero network -- sources
`security/incident_learning/knowledge_manager.sh` only for its path
variables (`KNOWLEDGE_STATE_DIR`/`KNOWLEDGE_AUDIT_LOG`/`KNOWLEDGE_BASE_DIR`),
never calls its `candidate_transition`/`knowledge_promote`. Reports
counts per status (`COLLECTED` through `PROMOTED`/`REJECTED`/`HOLD`),
the Human Gate queue (`CANDIDATE`+`HOLD`, with reason/source_type,
oldest first), `promoted_knowledge_entries` (a real count of
`security/knowledge/*.json`), and the last 15 audit events. **Added to
the automated cron** (`dashboard/refresh_dashboard_cron.sh`) -- same
risk class (local-file-only) as the two collectors already there.
`dashboard/index.html` gains a matching panel, `renderIncidentLearning()`,
a `FALLBACK_INCIDENT_LEARNING` sample, and reuses the existing badge
color keywords (no new CSS) via an `IL_BADGE_CLASS` map: in-pipeline
statuses blue, `CANDIDATE`/`HOLD` amber (needs a human), `PROMOTED`
green, `REJECTED` red.

### 3. New panel: Takomachi (`dashboard/collect_takomachi_status.sh`) -- the first dashboard collector to make a real network call

Queries Takomachi's own existing `GET /health`, `GET /agents`,
`GET /tasks` (same routes `workers/healthcheck_worker.sh` already
calls for `/health`; no new Takomachi-side endpoint). Credential:
`TAKOMACHI_API_KEY` from the environment if set, else this machine's
Keychain (same lookup every Takomachi-calling worker already uses) --
per `tests/orchestrate_worker_test.sh`'s own documented finding
(Keychain access only succeeds from an interactive GUI Terminal
session), reports `"unavailable: no TAKOMACHI_API_KEY"` rather than
hanging or erroring when neither source has it.

**Deliberately bypasses `security/lib.sh`'s `egress_check()`/
`trigger_shutdown()` entirely** -- a real, explicit decision (not an
oversight): every WAIO worker that calls Takomachi routes through
that DLP gate, where an unlisted/unexpected destination doesn't just
fail, it calls `trigger_shutdown()` and writes
`security/state/SHUTDOWN.lock`, containing the whole system. That
blast radius fits a worker's own dispatch path; it does not fit a
passive, manually-run dashboard read. A misconfigured
`TAKOMACHI_API_URL`, unreachable Takomachi, or missing key must only
ever make this one panel say "unavailable" -- confirmed by never
`source security/lib.sh`-ing in this file at all, so the call is
structurally unreachable, not just avoided by convention. Real
external-communication/execution workers (`workers/*.sh`) keep their
own existing `egress_check()`/DLP gate completely unchanged -- this
file does not touch, wrap, or replace it.

**Manual/on-demand only** -- NOT added to
`dashboard/refresh_dashboard_cron.sh` (the first dashboard collector
to make a real network call stays off the automated schedule, by
explicit decision). 3s `curl --max-time`, no retries, always writes a
JSON snapshot (never leaves the file stale/absent, never exits
non-zero for a condition it fully expects) with `"available": true/false`
and a human-readable `"reason"`.

`dashboard/index.html` gains a matching panel (`renderTakomachi()`,
`FALLBACK_TAKOMACHI`): NOT MEASURED (gray, no reason at all) /
UNAVAILABLE (red, has a reason) / AVAILABLE (green), plus
agent_manager/task_queue/plugin_system health, agent count by status,
task count by status.

### 4. New panel: SND (`dashboard/collect_snd_status.sh`) -- optional, off by default

Same bypass-`egress_check` reasoning as Takomachi's own header (not
restated there a second time). `SND_HOME_API_URL`/`SND_HOME_API_TOKEN`
are both unset by default -- zero network attempts of any kind unless
`SND_HOME_API_URL` is explicitly set (env or `~/.waio.env`). Queries
SND_HOME's own existing `GET /api/lan/status`, `GET /api/system/latest`,
`GET /api/alerts/active` (confirmed reachable/unauthenticated-by-default
during Phase 53's own investigation). Manual/on-demand only, same
reasoning as Takomachi's own panel. `dashboard/index.html` gains
`renderSnd()`/`FALLBACK_SND`: NOT CONFIGURED (gray, the real default
state today) / UNAVAILABLE (red) / AVAILABLE (green).

### 5. bash 3.2 regression guard

This machine's own default `/bin/bash` is 3.2.57 (macOS), where
`"${arr[@]}"` on an empty array trips `unbound variable` under this
file's own `set -uo pipefail` (bash's own empty-array-expansion fix
only landed in 4.4). `collect_snd_status.sh`'s optional
`Authorization` header is built via two separate `curl` invocations
instead of a bash array for exactly this reason -- caught by actually
running the script against an empty `SND_HOME_API_TOKEN`, not by
inspection; `tests/collect_snd_status_test.sh`'s own SN3 case is a
standing regression guard against this specific failure mode.

### 6. CI wiring

`.github/workflows/lint.yml`: the three new collectors added to the
existing new-file-only dashboard `shellcheck -S error` step (same
Phase 52 precedent); six new named `regression` steps, one per new
suite (collector + UI, times three panels) -- matching this repo's
own established one-step-per-suite convention (Phase 61/63). Verified
by running the exact CI commands locally with a downloaded
`shellcheck` 0.11.0 binary (none was installed on this machine) --
both the pre-existing full fileset and the new dashboard step pass
clean, `0` errors.

### 7. New regression suites

- `tests/collect_incident_learning_status_test.sh` (21 assertions,
  CIL1-CIL7 + D1): counts, Human Gate queue contents, promoted count,
  malformed-file-skipped-gracefully, audit event ordering, real
  deployment state untouched, zero network calls.
- `tests/dashboard_incident_learning_ui_test.sh` +
  `tests/dashboard_incident_learning_ui_check.mjs` (21 assertions,
  U1-U5): same Node-executes-the-real-inline-script approach as
  `tests/dashboard_guardian_ui_test.sh` (Phase 63) -- extracts and
  runs `dashboard/index.html`'s actual shipped `<script>` under a
  minimal DOM stub rather than re-implementing render logic a second
  time to compare against itself.
- `tests/collect_takomachi_status_test.sh` (11 assertions, TK1-TK3 +
  D1-D2): no-key / unreachable / reachable-with-real-shaped-data via a
  local mock `http.server` fixture; static guard confirming the script
  never sources `security/lib.sh` and never calls
  `egress_check`/`trigger_shutdown` as functions (the naive
  string-grep version of this check false-positived on this file's own
  explanatory prose/JSON `"note"` field, which legitimately mentions
  both names -- fixed to anchor on an actual sourcing line / an actual
  function-call shape); confirms the real `SHUTDOWN.lock` is
  byte-for-byte unchanged by the whole suite. Deliberately does NOT
  attempt the real Keychain+Takomachi path -- per
  `tests/orchestrate_worker_test.sh`'s own documented finding, that
  combination is manually-verified-only in this repo, same as every
  other Takomachi-dispatch case.
- `tests/dashboard_takomachi_ui_test.sh` + `.mjs` (12 assertions,
  U1-U4).
- `tests/collect_snd_status_test.sh` (14 assertions, SN1-SN4 + D1-D2):
  same shape as the Takomachi suite, plus SN3's bash-3.2 array
  regression guard (see section 5).
- `tests/dashboard_snd_ui_test.sh` + `.mjs` (11 assertions, U1-U4).
- `tests/dashboard_refresh_cron_test.sh`: 9 -> **11** (DC2 gains a
  `collect_incident_learning_status.sh: ok` log-line assertion; new
  DC4b checks `logs/incident-learning-status-latest.json` is actually
  regenerated with a fresh `generated_at`).

### 8. Verification

- All seven new/updated Phase 76 suites, run individually: 21 + 21 +
  11 + 12 + 14 + 11 + 11 = **111/0**. Pre-existing
  `tests/collect_status_guardian_test.sh` 20/0 and
  `tests/dashboard_guardian_ui_test.sh` 19/0 re-run clean, confirming
  the new Incident Learning/Takomachi/SND panels didn't disturb the
  pre-existing DuCoPA panel's own render path (each suite's own final
  case says so explicitly).
- `bash -n` and `shellcheck -S error` re-run locally against the exact
  full fileset both of `.github/workflows/lint.yml`'s CI commands
  cover (a `shellcheck` binary was downloaded for this session only,
  not installed persistently) -- clean, `0` errors, including all six
  new files.
- Live HTTP smoke test: served `dashboard/` with `python3 -m http.server`,
  fetched `index.html`, confirmed HTTP 200 and all seven new element
  IDs (`ilCountsGrid`, `ilTotal`, `ilPromoted`, `ilQueueCount`,
  `ilStatusCounts`, `ilHumanGateQueue`, `ilEventLog`) present in the
  served markup. No real browser was available this session (the
  Claude in Chrome extension was declined) -- the Node DOM-stub suites
  above, which execute the real shipped inline script, are this
  phase's primary functional verification instead, same role Phase
  63's own suite already plays for the DuCoPA panel.
- `dashboard/index.html`'s `<div>` tag count confirmed balanced
  (108/108) before and after every edit in this phase.
- **A pre-existing, environment-dependent flake, NOT caused by this
  phase**: `tests/dashboard_refresh_cron_test.sh`'s own DC4 (incident
  history freshness) intermittently reports `false` -- confirmed via
  `git stash` to reproduce identically on the pre-Phase-76 tree,
  unrelated to any file this phase touches.

### 9. Separate finding during this phase's own verification: `tests/security_test.sh` truncated the real audit log tonight -- not this phase's own doing, but recorded here for the permanent record

While re-running every suite to confirm no regressions, included
`tests/security_test.sh` in an unattended sweep -- against that file's
own loud, explicit header warning ("*** WARNING: NOT ISOLATED --
OPERATES ON REAL PRODUCTION STATE ***" / "Do NOT include this file in
an unattended 'run every tests/*.sh' sweep -- run it by hand only,
knowing what it will reset" / already documents an identical prior
incident from 2026-09-16, 461->109 lines). Running it three times
tonight (once in an automated background sweep, twice more via `git
stash` comparisons) truncated the real `logs/security-audit.jsonl`
from the real hash-chain checkpoint's expected 3376 lines down to
210, of which 162 are the integrity-violation alarms this truncation
itself then triggered on every subsequent check -- 3166 lines of real
audit history are gone, unrecoverable (gitignored, no backup, same as
the documented 2026-09-16 precedent). The real `SHUTDOWN.lock`
(`redteam-n1`, open since 2026-09-11 per Phase 54) was independently
re-tripped by this same suite's own N1 sub-test for the same
already-documented reason (its SSH-dependent recovery can't complete
without real network access) -- not new damage, but also not cleared.

Confirmed via `git stash` that both conditions are identical with or
without this phase's own code changes applied (they are gitignored
runtime state, untouched by any file this phase edits) -- i.e. this
phase's own deliverables are unaffected and independently verified
clean via isolated fixtures (section 8 above), but the broader,
non-isolated regression sweep this phase's own verification step
attempted is not currently clean, for a reason that predates and is
unrelated to this phase's code. Per explicit instruction: left
entirely as found -- no `recover.sh`, no clearing `SHUTDOWN.lock`, no
further audit log writes beyond what read-only investigation itself
required. **`tests/security_test.sh` must never be included in an
unattended sweep again** -- its own header already said so; this
phase is the second confirmed incident of ignoring that warning.

### 10. Not implemented, explicitly out of scope this phase

Actually starting/configuring SND_HOME or `~/lan-dashboard-gateway` on
this machine (both remain absent; starting either is the user's own
separate, explicit decision, same posture Phase 53 already took);
adding the Takomachi/SND collectors to any automated schedule (manual/
on-demand only, by design -- see sections 3-4); a persistent dashboard
web server (still `python3 -m http.server` or equivalent, unchanged
since Phase 52); recovering the real audit log or clearing the real
`SHUTDOWN.lock` (section 9 -- the user's own separate decision);
wiring `tests/incident_learning_*_test.sh` into
`.github/workflows/lint.yml`'s `regression` job -- discovered during
this phase's own CI-wiring work that none of Phase 68-75's nine
suites (382 assertions per Phase 75's own count) are executed in CI
today, only syntax/style-checked by the generic `tests/*.sh` glob; a
real, separate, pre-existing gap, not touched by this phase since it
is unrelated to Dashboard integration.

## Phase 77 (2026-09-19): `tests/incident_learning_*_test.sh` wired into CI -- closes Phase 76's own discovered gap

Phase 76's own section 10 flagged this: none of Phase 68-75's nine
Incident Learning Engine suites were ever actually *executed* by
`.github/workflows/lint.yml`'s `regression` job -- only syntax/style-
checked by that job's generic `tests/*.sh` glob (`bash -n` +
`shellcheck -S error`). This phase closes that gap the same way every
other suite in this repo already got wired in (Phase 51/52/61/63's own
precedent): one named `regression` step per suite, no change to the
suites themselves.

### 1. Scope: all nine suites, one step each, `tests/security_test.sh` deliberately excluded from any sweep

`tests/incident_learning_test.sh` (Step 1, knowledge_manager.sh),
`incident_learning_collector_test.sh` (Step 2), `incident_learning_evidence_test.sh`
(Step 3), `incident_learning_human_gate_test.sh` (Step 4),
`incident_learning_analyzer_test.sh` (Step 5a, Phase 75),
`incident_learning_promote_test.sh` (Step 5b),
`incident_learning_cron_test.sh` (Step 6),
`incident_learning_advance_hardening_test.sh` (Step 7),
`incident_learning_failsafe_test.sh` (Step 8) -- every one of these
already isolates itself via `KNOWLEDGE_MANAGER_STATE_DIR`/
`KNOWLEDGE_MANAGER_AUDIT_LOG`/`KNOWLEDGE_MANAGER_KNOWLEDGE_DIR`
overrides (confirmed by reading each file's own header before adding
its step), same fixture-isolation convention every suite in this repo
follows except `tests/security_test.sh` -- which stays deliberately
excluded from this and every other automated sweep, per that file's
own loud header warning and Phase 76's section 9 (real, unrecoverable
audit-log damage from including it in an unattended sweep, confirmed
twice now: 2026-09-16 and 2026-09-18).

### 2. `.github/workflows/lint.yml`

Nine new named steps appended to the `regression` job, immediately
after Phase 76's own dashboard steps -- no change to the `shellcheck`
job (the generic `tests/*.sh` glob there already covered these files;
this phase only adds *execution*, not syntax coverage). `regression`
job step count: 26 -> **35**.

### 3. Verification

- All nine suites re-run individually this phase, `security_test.sh`
  never included in any sweep: **382/0** total (35 + 26 + 31 + 45 +
  34 + 55 + 23 + 81 + 52), an exact match to Phase 75's own
  independently-recorded count -- confirms no drift in the eleven days
  since.
- `bash -n` and `shellcheck -S error` re-run locally against the exact
  full CI fileset (same downloaded shellcheck 0.11.0 binary Phase 76
  used) -- clean, `0` errors; unaffected by this phase since no
  suite's own code changed, only `lint.yml`.
- `.github/workflows/lint.yml` re-parsed with `python3`'s own `yaml`
  module to confirm valid YAML and the expected step count before
  committing.
- A redundant, accidentally-duplicated local verification sweep
  (started before the first one's results had actually arrived) was
  killed mid-run once the first sweep's real results were in --
  avoided wasting a second full run of already-confirmed suites.

### 4. Not implemented, explicitly out of scope this phase

`tests/security_test.sh` itself remains entirely outside CI, by its
own explicit design (real production state, no fixture isolation) --
unchanged, not this phase's concern. The real `SHUTDOWN.lock` and
truncated audit log from Phase 76's own section 9 remain exactly as
found -- still the user's own separate decision, not touched here.
Every other Phase 75/76 out-of-scope item (concurrent-process locking,
a real non-mock Collector, actually starting SND_HOME/the Gateway
project, `.gitignore` for `security/knowledge/`) remains open,
unrelated to this phase's own narrow CI-wiring scope.

## Phase 78 (2026-09-19): concurrent-process locking for `incident_learning_cron.sh` -- closes another item of Phase 75's own out-of-scope list

Phase 75 explicitly left "concurrent-process locking" out of scope,
and `tests/incident_learning_failsafe_test.sh`'s own header names the
exact risk: "true concurrent-process locking (two invocations racing
at the exact same instant, as opposed to a sequential crash-then-
rerun) -- this codebase has no file-locking precedent anywhere". That
last clause is only true within `security/incident_learning/` itself
-- `security/lib.sh` already has a proven, three-times-hardened
`mkdir`-based mutual-exclusion primitive (Phase 65/67/70,
`_waio_mkdir_lock_acquire`/`_waio_mkdir_lock_release`), already reused
once by `security/guardian.sh`'s own critical-event counter. This
phase reuses that same proven algorithm for the Incident Learning
Engine, without reusing the file itself.

### 1. Why a standalone copy, not `source security/lib.sh`

Every file in `security/incident_learning/` states the same explicit,
load-bearing "DuCoPA alignment" principle: this domain never reads or
writes `security/egress_allowlist.conf`, `security/segments.conf`,
`sshd_config`, or any other Main/Guardian Control Plane file.
`source security/lib.sh` would pull in `SHUTDOWN_LOCK`, `egress_check`,
`guardian_*`, and their own state directory as a side effect,
entangling two subsystems this domain's own design has deliberately
kept apart since Step 1. New file,
`security/incident_learning/lock.sh`: `il_lock_acquire`/`il_lock_release`,
a byte-for-byte reuse of `_waio_mkdir_lock_acquire`/
`_waio_mkdir_lock_release`'s own algorithm (portable `mkdir` primitive,
Phase 65's PID-liveness-gated stale-lock steal -- age alone is never
enough -- Phase 67's widened retry budget, including the exact
`stat -f`/`stat -c` macOS/Linux fallback that Phase 65's own CI run
found broken the naive way) -- reused verbatim because the algorithm
is proven, not reinvented from scratch for a lower bar of testing.

### 2. Deliberately fail-CLOSED, not fail-open -- the one real behavioral difference from `security/lib.sh`'s own lock

`audit_log()`'s own lock lets its caller proceed WITHOUT the lock once
its retry budget is exhausted, because logging must never block a
real dispatch. Here the entire point of the lock is to stop two full
pipeline runs from processing the same candidates at once --
proceeding anyway after failing to acquire would defeat the only
reason this file exists. `incident_learning_cron.sh` calls
`il_lock_acquire "$CRON_LOCK_DIR" 0` (zero wait -- try once, fail
immediately, never block a scheduled trigger waiting on a run that
might legitimately take much longer than the audit log's own 15s
budget): on failure it logs `"skipped: another
incident_learning_cron.sh run is already in progress"` and exits 0 --
not an error, the expected outcome of a launchd re-fire landing on a
still-running previous invocation, or an operator manually re-running
this same script while the scheduled one is still going. Lock
acquired via a `trap 'il_lock_release ...' EXIT` right after
acquisition, so it releases on every exit path, not only the
happy-path end of the script.

### 3. Scope: the cron wrapper only, not every stage script individually

`incident_learning_cron.sh` is confirmed the sole scheduled entry
point into the whole pipeline (Phase 74's own runtime-wiring audit) --
locking there prevents the realistic concurrency scenario (an
overlapping scheduled/manual full-pipeline run) without touching
`knowledge_manager.sh`'s own already-hardened, 382-assertion-covered
internals, or any individual stage script
(`incident_evidence.sh`/`incident_analyzer.sh`/`incident_confidence.sh`)
directly. A human manually invoking one of those stage scripts by hand
while cron is also running remains outside this phase's own scope --
narrower and rarer than "the same wrapper script racing itself",
matching Phase 75/76's own literal wording ("overlapping
`incident_learning_cron.sh` runs... a manual run racing the scheduled
one").

### 4. New regression suite: `tests/incident_learning_lock_test.sh` (29 assertions, L1-L10 + D1-D3)

- **L1-L2**: basic acquire/release.
- **L3**: a fresh (<=5s old) lock is respected even with
  `MAX_WAIT_ITERATIONS=0` -- never stolen just because the caller isn't
  willing to wait.
- **L4**: a stale (>5s old) lock held by a genuinely live PID is
  correctly NOT stolen (mtime backdated via `touch -t`, portable
  macOS/Linux technique, no real multi-second sleep needed).
- **L5-L6**: a stale lock held by a dead PID (or with no readable
  `holder.pid` at all, simulating a crash between `mkdir` and writing
  it) IS reclaimed.
- **L7-L9**: `incident_learning_cron.sh`'s own integration with the
  lock -- a normal run acquires and releases cleanly; a run finding the
  lock already held skips cleanly (exit 0, logs it, creates zero
  candidates, never touches the held lock); a subsequent run after the
  simulated overlap clears proceeds normally (no lingering lock ever
  blocks a legitimate future run).
- **L10**: a genuine real-process race -- two actual
  `incident_learning_cron.sh` invocations launched at nearly the same
  instant (`&` + `wait`) against the same fixture. Confirmed reliably:
  exactly one of the two logs the skip, exactly one batch worth of
  candidates exists (5, never 10 -- would have meant double-processing),
  both exit 0 regardless of which won. The strongest evidence in this
  suite, since it exercises the real race rather than only simulated
  lock-directory states.
- **D1-D3**: DuCoPA boundary (no Control Plane file touched), `lock.sh`
  never sources `security/lib.sh` (static guard), zero network calls.

### 5. Separate, closely-related gap discovered and closed in the same phase: `security/incident_learning/*.sh` was never covered by any CI shellcheck/`bash -n` glob

While wiring this phase's own new file into CI, found that
`security/*.sh` (both the `bash -n` step and the main `shellcheck`
step) is a non-recursive glob -- it has never matched anything under
`security/incident_learning/` at all, across every phase since Step 1.
All nine files (`incident_analyzer.sh`, `incident_confidence.sh`,
`incident_evidence.sh`, `incident_human_gate.sh`,
`incident_learning_cron.sh`, `incident_normalizer.sh`,
`knowledge_manager.sh`, `collectors/mock_collector.sh`, and this
phase's own `lock.sh`) verified clean against both gates before adding
them -- `security/incident_learning/*.sh
security/incident_learning/collectors/*.sh` added to the existing
`bash -n` glob, plus a new dedicated `shellcheck -S error` step (own
step, not folded into the already-long "canonical dispatch path" one,
matching this file's own established per-domain-step convention).

### 6. Verification

- `tests/incident_learning_lock_test.sh`: **29/0** (new).
- All nine pre-existing Incident Learning suites re-run unchanged:
  **382/0** (23 + 35 + 26 + 31 + 34 + 45 + 55 + 81 + 52) -- confirms no
  disturbance to any stage script's own idempotency/skip logic from
  the new lock wrapping `incident_learning_cron.sh`'s own entry point.
- `bash -n` and `shellcheck -S error` re-run locally against the exact
  full CI fileset, including the two newly-added globs -- clean, `0`
  errors, across all four affected/new files plus the 9
  previously-uncovered `security/incident_learning/*.sh` files.
- `.github/workflows/lint.yml` re-parsed with `python3`'s own `yaml`
  module -- valid; `shellcheck` job 7 -> **8** steps, `regression` job
  35 -> **36** steps.
- Manual smoke tests (3 scenarios, real process invocations, before
  writing the automated suite): a normal run acquires+releases
  cleanly; a run against a fresh-and-held lock skips cleanly with zero
  side effects; a run against a stale-and-dead-PID lock correctly
  reclaims it and proceeds normally.

### 7. Not implemented, explicitly out of scope this phase

Locking any individual stage script's own standalone/manual invocation
(section 3); a real (non-mock) Collector; `.gitignore` for
`security/knowledge/`; actually starting SND_HOME/the Gateway project;
the real `SHUTDOWN.lock`/truncated audit log from Phase 76's own
section 9 (still the user's own separate decision, untouched here).

## Phase 79 (2026-09-19): `security/knowledge/*.json` gitignored -- closes the last item of Phase 75's own out-of-scope list

Closed a real, if latent, data-leak gap: `security/knowledge/` existed
(confirmed empty, but present) and was tracked by neither `.gitignore`
nor any `.example` convention -- the only writer into it,
`knowledge_manager.sh`'s own `knowledge_promote()`, was already
verified (Phase 75) to fire only via an explicit two-step human gate
(`approve` then `promote`), but nothing stopped a future real
promotion from landing in this public, MIT-licensed repo's own
tracked tree. This is the exact class of per-deployment real data
(this deployment's own real `cve_list`/`ioc_list`/`source_url`/
`raw_text` from an actual reviewed incident) Phase 29's Public/Private
Security Boundary Audit already gitignores everywhere else
(`workers/800.json`, `security/segments.conf`,
`security/egress_allowlist.conf`) -- this domain had simply never been
folded into that same audit.

### 1. `.gitignore`

`security/knowledge/*.json` added, with its own comment block (same
style as the Phase 29 block above it) explaining the rationale and
pointing at the new `.example` file below. Deliberately a glob on the
directory's contents, not the directory itself: the directory stays
trackable/creatable (`knowledge_manager.sh`'s own pre-existing
`mkdir -p "$KNOWLEDGE_BASE_DIR"` already recreates it on first run of
any fresh checkout, same self-healing behavior every `security/state/`
subpath already has -- confirmed this phase, not assumed), only the
real promoted entries inside it are excluded. Verified with
`git check-ignore`: a real `*.json` file placed there is correctly
ignored; the new `.example` file (below) is correctly NOT ignored.

### 2. New: `security/knowledge/EXAMPLE-CVE-0000.json.example`

Documents the real shape a promoted entry takes (every field
`knowledge_promote()` actually writes: the candidate's own accumulated
fields plus `source_candidate_id`/`approval_reason`/`approved_at`/
`promoted_at`) with fabricated data only, matching this repo's own
existing fake-data convention throughout (`CVE-2026-99999`,
`198.51.100.1` RFC 5737 TEST-NET-2, `example.invalid`) -- same
`.example`-next-to-the-real-gitignored-thing pattern as
`security/egress_allowlist.conf.example` etc.

### 3. `knowledge_manager.sh`'s own header

New paragraph, same "Public/Private Security Boundary" heading Phase
29's own `.gitignore` comment uses, cross-referencing both the
`.gitignore` entry and the new `.example` file -- so a future reader
of this file alone (without having read `.gitignore`) still learns
why a fresh checkout's `security/knowledge/` is always empty. No
functional change to any code path in this file.

### 4. Verification

- `python3 -c "import json; json.load(...)"` confirms the new
  `.example` file is valid JSON.
- `git check-ignore -v` confirms the exact intended behavior in both
  directions (a real `.json` there is ignored; the `.example` file is
  not) -- tested directly, not inferred from the glob pattern alone.
- `bash -n` and `shellcheck -S error` re-run against
  `security/incident_learning/*.sh` -- clean (comment-only change to
  `knowledge_manager.sh`, no behavior difference).
- `tests/incident_learning_test.sh`, `_promote_test.sh`,
  `_advance_hardening_test.sh`, `_failsafe_test.sh` (the four suites
  that exercise `knowledge_promote()` most directly) re-run --
  unaffected, as expected for a `.gitignore`/comment-only change (git
  tracking has no runtime effect on any script's own behavior).

### 5. Not implemented, explicitly out of scope this phase

Nothing else changed -- this was deliberately the smallest, lowest-
risk item left. A real (non-mock) Collector, actually starting
SND_HOME/the Gateway project, and the real `SHUTDOWN.lock`/truncated
audit log from Phase 76's own section 9 all remain open, the user's
own separate decisions.

## Repo hosting and branch policy (2026-08-30, updated 2026-08-31)

- Repo: `github.com/noobdna/WAIO` (public), MIT licensed.
- `master` and `develop` both require **`shellcheck` and `regression`**
  status checks (from `.github/workflows/lint.yml`) to pass, with
  `enforce_admins: true` on both (`regression` promoted from
  report-only to required in Phase 46, above) — a direct push to
  either branch is rejected until that commit has both checks passing,
  so changes go through a branch + PR, not a direct push.
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
