# WAIO Autopilot mission engine (WAIO-AUTO-001, 2026-10-21) -- WAIO executes, Guardian guards, DuCoPA keeps independent control

### 1. Phase 1 survey (read-only, before any change)

| Item | Found |
|---|---|
| Host | iMac "800", macOS 13.7.8 (x86_64), Node v22.23.2, Python 3.9.6 |
| Existing orchestration | `waio.sh -w ORCHESTRATE` + `workers/registry.conf` dispatches ONE request through a worker pipeline. `orchestrator/` is DEPRECATED. No mission/goal decomposition, no persistent task queue, no build-test-repair loop. |
| "AI" worker | Routes through Takomachi (`localhost:3000`, which runs on host 750, not here) to OpenRouter `openai/gpt-4o-mini`. That is an EXTERNAL model, not a local one. |
| Local AI on this host | `/Volumes/LocalAI`: llama.cpp b11700 (`llama-completion`, `llama-server`) and `qwen2.5-3b-instruct-q4_k_m.gguf`. Smoke test (2026-10-21): rc=0, correct one-word answer; cold load 57.6 s from the external volume; about 10 tokens/s generation. `llama-cli` rejects `-no-cnv` in this build; `llama-completion` accepts it. |
| Guardian | `security/guardian.sh` is the WAIO-side state machine (NORMAL/WARNING/BLOCKED/HUMAN_APPROVAL_REQUIRED/SHUTDOWN), sourced by `security/lib.sh`. Unreadable/invalid state means BLOCKED (fail closed). The Guardian-side decision half reaches this host only through SSH forced-command wrappers (Phase 64). |
| DuCoPA kill switch | `security/killswitch/` signs containment commands. Test environment only, a human or the Guardian is the origin, dry-run evaluation of SND events. |

Reuse decision: `waio.sh` dispatch is one-shot, and changing it would
change production behavior. So the mission engine is a NEW, separate
entry point (`autopilot/`) that REUSES the existing Guardian state
machine and Emergency Shutdown lock (through `security/lib.sh` itself)
and the existing WAIO -> Guardian interface (`guardian_notify_event`).
It does not modify waio.sh, the workers, Guardian or the kill switch.

### 2. Components

- `autopilot/autopilot_lib.py` (pure): mission validation (a test is
  required per task, acceptance per mission; limits are clamped to hard
  caps; cycles are rejected), the command policy, the task state machine,
  failure signatures, the completion verdict and redaction.
- `autopilot/autopilot.py` (engine): queue with dependencies, priority
  and bounded parallelism. Persistent `state.json` (atomic writes),
  append-only `events.jsonl`, `report.json`, an engine lock and a
  heartbeat.
- `autopilot/autopilot_watchdog.py` (separate process): heartbeat,
  deadline enforcement, orphan reaping when the engine dies, its own
  `watchdog.jsonl`, and Guardian notification.

### 3. Safety gates (checked before EVERY task start and retry)

1. Guardian not blocking and no Emergency Shutdown lock, read through
   `security/lib.sh`. Any error counts as blocking. Result: exit 4
   PAUSED_GUARDIAN, state saved.
2. A fresh watchdog heartbeat. If the monitor is down, no new task
   starts (exit 4).
3. The command policy: privilege, publish (git push, gh pr), network
   tools, host control (launchctl, pmset, kill), control-plane paths
   (guardian, ducopa, killswitch, lib.sh, security/state, .ssh),
   destructive git/rm, directory escape, secret stores. A match is never
   run: the task becomes BLOCKED_POLICY and the mission AWAITING_HUMAN
   (exit 3).

Technical backstop on macOS: each command runs under `sandbox-exec` with
no network, writes only to the workspace and temp dirs, and no reads of
`~/.ssh`, the Keychain or `security/state`. Each command also runs in its
own process group with a scrubbed environment, and logs are redacted.

### 4. Completion is never assumed

A mission is COMPLETE only when every task PASSED (by its own test's
exit code) AND every acceptance command passed when re-run at the end.
- Otherwise it is INCOMPLETE, or AWAITING_HUMAN, with reasons.
- The same failure signature twice in a row gives STUCK; attempts are
  capped.
- On resume, PASSED work is never repeated. An interrupted task is
  re-run only if it is declared idempotent; otherwise it becomes
  BLOCKED_RESUME.

### 5. Independence assessment (WAIO executes / Guardian guards / DuCoPA controls)

| Property | Status |
|---|---|
| Engine cannot change Guardian/DuCoPA state through task commands | Enforced: policy, plus the sandbox denies `security/state` reads and blocks writes outside the workspace. |
| Engine reads Guardian state; never writes it | Enforced. Static guard D1. |
| Monitor down means no new work | Enforced. G4. |
| Monitor runs in a separate process | Yes. |
| Monitor on a separate host or OS user | **NO.** Same host, same uid (masa). The user account itself could stop the watchdog or edit `guardian.sh` (same owner). Task commands cannot (policy plus sandbox), but the engine's own process could. Real separation needs a dedicated OS user or the Guardian host (750) running the watchdog. That needs sudo or a host change: operator approval. |
| DuCoPA independent control path | The kill switch exists and signs test-environment containment only. It is not wired into the engine; the engine never calls it. Phase 106's design keeps it human/Guardian-origin. |
| Co-failure | A host crash or sleep stops engine and watchdog together. That is safe (nothing runs) but not monitored. Resume is supported. |

### 6. Verified (tests/autopilot_test.sh, 60 passed / 0 failed locally)

- M: one mission gives 3 tasks (dependencies, parallelism) and COMPLETE.
- B: test fails, local-AI repair (deterministic stub) applies, re-test passes.
- L: STUCK after 2 attempts instead of 9.
- C: acceptance failure means never COMPLETE; a task with no test is
  rejected.
- P: curl, git push, a Guardian-state write and sudo are all
  BLOCKED_POLICY with zero side effects.
- G: Guardian BLOCKED, the shutdown lock, corrupt state, and a
  missing/stale watchdog each mean no task starts; resume completes,
  each task once.
- R: engine `kill -9` mid-task; the watchdog reaps the orphan and
  notifies the Guardian (WARNING); resume doesn't repeat PASSED work.
- W: the watchdog kills an overdue process group on its own.
- X: a duplicate engine, a changed mission file and a second watchdog
  on the same state dir are refused.
- S (macOS): a write outside the workspace and a network connect are
  both denied by the sandbox.
- E: env scrubbed, tokens redacted. T: every transition logged.
- D: the real Guardian state is untouched.
- A1 (opt-in, `AUTOPILOT_TEST_REAL_AI=1`): the REAL local model
  (qwen2.5-3b via llama.cpp) repaired the bug through the engine's own
  repair loop, and the acceptance test passed: 61 passed / 0 failed.
  CI does not run A1 (no model there).

### 7. Not done / next

- PHASE 5 (supervised operation) is not started. No LaunchAgent, nothing
  scheduled, nothing run against the real repo.
- Separate-user or separate-host watchdog: needs operator approval.
- `llama-server` keep-alive would remove the 58 s cold load; not wired.
- Mission decomposition from free text by the local model: not built.
  Missions declare their tasks explicitly. A 3B model is a weak planner;
  generated plans would need validation before being trusted.

### 8. Stop control and stopping running work (feat/autopilot-stop-control)

- `autopilot.py stop --state DIR` is a graceful stop:
  - running work finishes;
  - no new task and no retry starts;
  - `run` exits 6 (STOPPED_BY_OPERATOR) until
    `autopilot.py clear-stop --state DIR`.
- `stop --now` also has the watchdog stop the running process groups.
- **The watchdog now stops running work on its own** when the Guardian
  turns blocking (BLOCKED / HUMAN_APPROVAL_REQUIRED / SHUTDOWN) or the
  shutdown lock appears. Before this change, the gate was checked only at
  task start, so a task already running when the Guardian blocked kept
  running.
- A task stopped for a gate reason goes back to PENDING **without counting
  a failed attempt**, and resumes later.
- The watchdog writes its evidence record before notifying the Guardian,
  so a hung or failed notify cannot lose the record.
- Only one watchdog per state dir (`watchdog.lock`, flock). A second one
  exits 5 before writing anything. The kernel drops the lock when the
  holder dies, even on `kill -9`, so there is no stale lock to take over.
  A supervisor that restarts the watchdog therefore cannot stack copies.
- **Escaped task processes.** The watchdog and the timeout stop a task by
  process group. A task that `setsid()`s a child out of that group was not
  reached. If the child kept the output pipe open, the engine also blocked
  forever waiting for EOF. The engine now samples the task's process tree
  every `AUTOPILOT_TREE_SAMPLE_S` (0.5 s) while it runs. When the task
  ends, every recorded descendant that is still alive with the same start
  time (never a reused pid) is SIGKILLed (`escaped_process_killed`). After
  a timeout kill, output is drained for at most `AUTOPILOT_DRAIN_TIMEOUT_S`
  (3 s), then abandoned (`task_output_abandoned`).
  - **A double fork faster than one sample** is caught afterwards,
    independent of timing (X5; the previous engine reaped 0 of 5):
    - Linux: the engine is a child subreaper, so task orphans are
      reparented to it. Those not in its own process group are killed and
      reaped.
    - macOS: orphans (ppid 1) of the same uid, started after the task,
      that still have the engine's responsible process AND the task
      sandbox (network denied). A user-started app is responsible for
      itself, and an ordinary shell job is not sandboxed, so neither
      matches. X5 checks that an unrelated orphan survives.
  - **Remaining limits:**
    - Two Autopilot engines started from the same login session share a
      responsible process, so one engine's sweep also kills the other's
      escaped orphans. They are escapes either way.
    - An escapee that leaves the sandbox is not possible without a
      privilege change.
    - Full containment (jail, separate uid) remains an operator decision.
- **No false stop on a reused pgid.** The engine records the start time of
  the task's group leader (`pgid_start`). Before signaling, the watchdog
  checks it. If the number now belongs to another process (the engine
  died, the task ended, the pgid was reused), the watchdog logs
  `not_stopped / pgid_reused` and leaves it alone. W2 covers this. The
  previous watchdog SIGTERMed the unrelated group.

#### Proposal: a watchdog that is independent of the engine's uid (needs operator approval)
Today the engine, the watchdog and the user can all signal each other (one
uid). Options, from least to most change:
1. **Remote observer on host 750 (no sudo on 800):** 750 polls the
   watchdog heartbeat over the existing SSH forced-command channel and,
   when it is stale, escalates the Guardian through
   `guardian_intervene_wrapper.sh`. It can only block new work, not stop
   running work.
2. **Dedicated uid `_waiowd` with a root-owned helper on 800 (sudo):**
   - The watchdog runs as `_waiowd` (LaunchDaemon, KeepAlive with
     ThrottleInterval so it cannot crash-loop).
   - It reads `state.json` through a group-readable ACL.
   - It stops a group only through a root-owned helper allowed by one
     sudoers line. The helper checks that the target's uid is masa and
     that its leader start time matches `pgid_start` before signaling.
   - masa can no longer kill the watchdog.
3. **Jail or VM for task execution:** full containment of escapes.
All three are host or privilege changes. None of them is done here.

Tests:
- G5: Guardian SHUTDOWN mid-task; the process group is gone, the task is
  PENDING with 0 attempts, and resume completes.
- O1: graceful stop; the running task PASSED, the next one never
  started, the mission stays stopped until cleared, and both events are
  in the audit log.
- O2: `stop --now`; the process group is gone and no attempt is counted.

tests/autopilot_test.sh: 75 passed / 0 failed, stable across 3
consecutive runs.
