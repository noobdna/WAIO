# WAIO Adaptive Defense (WAD)

Status (2026-10-27): **PR 1 of the WAD plan: core engine, dry run only.**
Not scheduled by any cron/launchd job, not wired into Guardian, DuCoPA, the
containment runner or the kill switch. Nothing in `security/wad/` executes
a response.

## 1. Architecture and data flow

```
detector events (JSON / JSONL)
  │
  ▼  wad_lib.screen_events / normalize_event          [new]
  │    schema + size limits, strict tz timestamps, replay window,
  │    future-skew, idempotency key sha256(source_module, event_id),
  │    content digest → accepted | duplicate | conflict | rejected
  │
  ▼  intelligence_lib.aggregate_by_entity              [reused unchanged]
  ▼  decision_engine_lib.decide_for_profile            [reused unchanged]
  │    risk/confidence table + local-corroboration cap
  │
  ▼  wad_lib.assess                                    [new]
  │    decision → threat level L0..L4; missing/conflicting info → UNDETERMINED
  │
  ▼  wad_lib.plan_responses (policy, rate budget, stop signals)  [new]
  │    every step: DRY_RUN_PLANNED | AWAITING_APPROVAL |
  │                SUPPRESSED_RATE_LIMIT | HALTED_KILLSWITCH
  │
  ▼  wad.py Ledger (hash chain, flock, fsync)          [new]
       security/state/wad/ledger.jsonl + ledger.checkpoint
```

The scoring stays in the Decision Engine and is not rewritten here. WAD adds
everything around the decision: event hygiene, a fail-safe for missing
information, a versioned policy, a runaway budget and a decision audit trail.

Stop signals are read with `lstat`, never written, and fail closed:
`WAIO_SHUTDOWN_LOCK` (the system-wide lock security/lib.sh uses) and
`WAD_STOP_FILE` (default `security/state/wad/STOP`). Stopping WAD needs only
`touch`; it does not depend on WAD itself working.

## 2. Modules and API

| file | role |
|---|---|
| `security/wad/wad_lib.py` | pure functions, no I/O, clock injected |
| `security/wad/wad.py` | CLI, ledger, lock, stop signals |
| `security/wad/policies/wad_policy.json` | default policy `wad-default` v1 |
| `tests/wad_engine_test.sh` | U/I/S suite (142 checks) |

CLI (`python3 security/wad/wad.py …`):

| command | output | exit |
|---|---|---|
| `evaluate --events F [--policy P] [--now ISO]` | JSON report: counts, rejected, conflicts, assessments, plans | 0 ok, 1 bad input/policy (nothing written), 3 ledger write failed (no decision recorded), 4 ledger integrity broken (refused), 5 lock busy |
| `policy-check P` | `{policy_id, version, digest}` | 0 / 1 |
| `policy-diff OLD NEW` | `{from, to, identical, changes, loosening}` | 0 / 1 |
| `verify-ledger` | `ok: N entries` / `broken: …` | 0 / 4 |

Environment: `WAD_STATE_DIR`, `WAD_STOP_FILE`, `WAIO_SHUTDOWN_LOCK`,
`WAD_LOCK_WAIT_S` (default 10).

Event input (one object per line, or a JSON array):

| field | rule |
|---|---|
| `event_id` | `[A-Za-z0-9._:-]{1,128}` |
| `source_module` | `[a-z0-9_]{1,64}`; only `shadow_ai_monitor`, `attack_graph`, `saas_ato` count as local corroboration (Decision Engine allowlist) |
| `entity` | printable, 1-256 chars |
| `entity_type` | `[a-z_]{1,32}` |
| `risk` | `LOW`/`MEDIUM`/`HIGH`/`CRITICAL`, or absent |
| `confidence` | `LOW`/`MEDIUM`/`HIGH`, or absent |
| `observed_at` | ISO-8601 **with timezone**, or absent; within `[now - replay_window_s, now + clock_skew_s]` |
| `category`, `summary` | optional, printable, ≤64 / ≤1024 |

An **absent** risk/confidence/observed_at is kept and flagged `insufficient`.
A **present but wrong** value is rejected with reason codes and audited.

Ledger lines (`event_type`): `wad_event_rejected`, `wad_event_duplicate`,
`wad_event_conflict`, `wad_events_accepted` (key → digest, the only record of
what has been seen), `wad_decision` (entity, threat_level, risk, confidence,
reasons, event_keys, plan, killswitch_active, result). Every line carries
`run_id`, `policy {policy_id, version, digest}`, `mode: dry_run`, and
`prev_hash`. The chain format is identical to `security/lib.sh audit_log`.
The suite checks it with lib.sh's own `verify_audit_log_integrity` (I1, I4).

## 3. Defense policy (`wad-default` v1)

| level | meaning | responses |
|---|---|---|
| L0 NORMAL | Decision Engine NO_ACTION | none |
| L1 ELEVATED | MONITOR | monitor_increase |
| L2 HIGH | ALERT_HUMAN (includes the global-only CRITICAL cap) | + warn_operator |
| L3 SEVERE | RECOMMEND_CONTAINMENT, risk HIGH | + restrict_egress (approval) |
| L4 CRITICAL | RECOMMEND_CONTAINMENT, risk CRITICAL | + isolate_agent (approval) |
| UNDETERMINED | missing or conflicting info and computed level < L2 | monitor_increase, warn_operator |

Limits: `max_disruptive_per_hour` 3, `replay_window_s` 86400, `clock_skew_s` 300,
`max_events_per_run` 5000.

These invariants are enforced in code, and a policy file that breaks one is refused:
- A disruptive action (restrict_egress, isolate_agent, recover) always requires approval.
- Action classes are fixed in code.
- L0, L1 and UNDETERMINED never carry a disruptive action.
- Levels are monotonic: L0 ⊆ L1 ⊆ … ⊆ L4.
- Limits stay within hard caps: rate ≤ 20/h, window 60 s–7 d, skew ≤ 900 s.

Every report and ledger line names the policy digest. `policy-diff` lists
`loosening` separately; it also catches a missing version bump and a version
that goes backwards.

## 4. Tests and how to reproduce

    ./tests/wad_engine_test.sh          # 142 checks, ~17 s, temp dirs only
    ./tests/decision_engine_test.sh     # reused stage, unchanged
    ./tests/intelligence_layer_test.sh  # reused stage, unchanged

| directive item | checks |
|---|---|
| normal / abnormal / boundary | U1-U4 (inclusive window/skew edges, 256/257, 128/129, 1024/1025) |
| false positive / false negative | U6 (global-only, snd crossref, unknown module, LOW) / U7 (local CRITICAL, HIGH+HIGH, corroborated) |
| duplicate / out-of-order | U8 (720 permutations identical; a late older CRITICAL still raises), U9, I2, I8 |
| API down / partial failure | I7 (unwritable ledger → rc 3, events not marked seen, decided after repair), I9 (lock busy) |
| bad input / replay | U2-U4, I3 (altered replay = conflict, cannot downgrade), I3 (expired replay rejected), I11 |
| runaway prevention | U12, I10 (budget across runs, recovers after 1 h, operator still warned) |
| emergency stop | U12, I6 (SHUTDOWN.lock, WAD STOP, unreadable path = stop, lock never removed) |
| audit integrity | I1, I4 (edit), I5 (truncation, missing checkpoint) |
| no execution | S1 (no subprocess/socket/guardian/ducopa/firewall in code), S2 (sudo/ssh/curl/nc/osascript stubs 0 calls) |

Mutation check (run by hand, script not committed): five planted defects
were each caught by the suite. They were removing the approval invariant,
removing the canonical sort, treating a conflict as a new event, making the
stop check fail open, and removing the rate limit.

## 5. Remaining security issues (known, not fixed in PR 1)

1. **The ledger hash chain detects edits but not forged appends.** Anyone who
   can write the file can append valid lines; it is unkeyed, the same as
   lib.sh. *PR 2:* an optional keyed chain (`WAD_LEDGER_HMAC_KEY_FILE`, see
   §9) now catches forged appends, but only from a writer who cannot read
   the key file. Unkeyed remains the default.
2. **The idempotency key trusts `source_module` as written by the producer.**
   No producer authenticates yet, so a local process can inject events as
   `shadow_ai_monitor`. Today that leads at most to a plan awaiting
   approval, because nothing executes. Signed producer envelopes come before
   any executor.
3. **An event without `observed_at` cannot be bounded in time.** Dedup holds
   for 2× the replay window after acceptance; a later replay is re-accepted,
   but it can only reach UNDETERMINED (warn, no disruptive step).
4. **The ledger is re-read in full on each run.** That is O(n), with no
   rotation yet.
5. **A crash between the ledger append and the checkpoint rename leaves a
   mismatch, and the next run refuses (rc 4).** This is the safe outcome.
   *PR 2:* `wad.py repair-checkpoint` adopts the unacknowledged records,
   but only when the chain is intact and the old checkpoint is an exact
   prefix of it, and it records the repair in the ledger (§9).
6. **The rate budget is per state dir, not per host.**

## 6. Deploy and rollback

Not deployed. Nothing loads this code automatically. To try it by hand
against a scratch state dir:

    WAD_STATE_DIR=$(mktemp -d) python3 security/wad/wad.py evaluate --events events.jsonl

Rollback: revert the PR. WAD's only state is `security/state/wad/` (git-ignored),
and deleting it leaves no other component affected.

## 7. Planned PRs

| PR | scope | depends on |
|---|---|---|
| 1 | core engine, policy, ledger, suite | — |
| 2 (§9) | controlled response workflow: step state machine (planned → approved → executing → done/failed → rolled_back), approval checks reused from the existing containment approval library, interruption sweep, compensating rollback, optional keyed ledger chain, checkpoint repair; executors still dry-run only | 1 |
| 3 | adapters: real detector outputs (shadow_ai, attack_graph, saas_ato, distributed probe #182) → WAD events, signed producer envelope | 1 |
| 4 | executor binding for `isolate_agent` through the containment runner (#209/#211, signed policy v3), still `--dry-run` by default | 2, #209/#211 merged |
| 5 | Takomachi/Guardian oversight interface and DuCoPA independent-path checks | 2; real Takomachi process |

## 8. Not implemented, not verified, or external

- **Not implemented:** actual execution of any response, including
  restrict_egress, isolate_agent and recover. Also not implemented:
  producer authentication and authentication of the approver (PR 2's
  approvals check an allowlisted name only).
- **Not connected:** SND@HOME. Its API collector,
  `dashboard/collect_snd_status.sh`, is unconfigured on this host, and
  SND@ID exists only as a mock. Also not connected: Takomachi (no real
  process drives guardian.sh) and DuCoPA (`security/ducopa.sh` is a
  standalone prototype). WAD reads none of them.
- **Not verified:** behaviour on real detector output (all inputs are
  fixtures), and ledger throughput beyond the suite's sizes.
- **Verified on:** macOS 13 (bash 3.2, python3) locally; Linux CI after push.

## 9. PR 2: controlled response workflow

**Scope.** Every step of a `wad_decision` plan now has a lifecycle, recorded
in the same ledger (no second state file). The state machine lives in
`wad_response.py` and is pure. `wad.py response …` replays the ledger,
checks the request and appends the result under the existing lock.

```
awaiting_approval --approve--> approved --start--> executing --complete--> done
                  --reject---> rejected            executing --fail-----> failed
planned ---------------------------------start--> executing
done | failed --rollback--> rolled_back       (suppressed, halted: terminal)
```

Any other (state, action) pair is refused with exit 6, and the refusal itself
is recorded (`wad_transition_refused`). A duplicate request is just an illegal
transition from the step's current state, so it can never move the step.

**Commands.** `response list`, `approve|reject STEP --operator NAME --reason TEXT`,
`execute STEP`, `rollback STEP | --plan RUN_ID ENTITY`, `sweep`, and
`repair-checkpoint --operator NAME --reason TEXT`.

**Approval.** Reuses `security/red_alert/containment_approval_lib`:
`validate_approver_identity` (with an allowlist), `validate_reason`, and
`compute_expiry`/`is_expired` (24 h default, `WAD_APPROVAL_TTL_S`).
- Approval is refused when any of these holds: no allowlist file
  (`WAD_APPROVER_ALLOWLIST`, default `$WAD_STATE_DIR/approvers`; a symlink
  counts as absent), the name is not on it, the name is automated (`wad`,
  `claude…`, `…-bot`, …) or is the name of a WAIO component under `security/`,
  the reason is weak, the decision is more than 24 h old, the kill switch is
  active, or the decision digest changed.
- An approved step cannot start after its approval is 24 h old.
- **This is not authentication.** The name is whatever the caller typed,
  checked against a list. Every approval, rejection, rollback and repair
  record carries `"authenticated": false`. Anyone who can run `wad.py` as
  this user can type an allowlisted name, the same honor-system posture as
  `lib.sh audit_log` and the containment approval gate.

**Execution: dry run only.** `execute` makes the `start` record durable,
calls `dry_run_execute()` (which does nothing and returns
`{"result": "DRY_RUN", "would": "<action> <entity>"}`), then records
`complete`. There is no live mode and no executor binding. A crash between
`start` and `complete` leaves the step `executing`. Every transition runs
under the flock and finishes within one command, so `response sweep` marks
any `executing` step `failed` with "interrupted".

**Rollback.** Only `done` or `failed` steps, by an allowlisted operator with a
reason, never while the kill switch is active (a rollback loosens).
Compensations: `monitor_increase` → `monitor_restore`, `restrict_egress` →
`release_egress`, `isolate_agent` → `release_isolation`. `warn_operator` and
`recover` have none, so their rollback is refused. `--plan` rolls back a
plan's steps newest-completion first, and is refused as a whole if any step
cannot be rolled back. Compensations are dry runs too.

**Keyed chain.** With `WAD_LEDGER_HMAC_KEY_FILE` (≥16 bytes, not a symlink):
- each new record carries `mac` = HMAC-SHA256 over the record including
  `prev_hash`, and `ledger.checkpoint.mac` holds the checkpoint's HMAC;
- a bad mac, an unkeyed record after a keyed one, a bad checkpoint mac, or
  reading a keyed ledger without the key is an integrity failure (rc 4);
- `prev_hash` is unchanged, so `security/lib.sh verify_audit_log_integrity`
  still verifies the chain.

The key protects only against writers who cannot read the key file. The
agent and anything else running as this user can read it.

**Checkpoint repair.** Fixes exactly the PR 1 §5.5 crash: the chain is intact
and the checkpoint is an exact earlier prefix of it.
- It refuses a broken chain, a missing checkpoint, a checkpoint ahead of the
  ledger, a checkpoint hash that is not on the chain, or an operator outside
  the allowlist. A refusal writes nothing.
- On success it appends `wad_checkpoint_repaired` with the adopted record
  hashes and `adopted_authenticity`: `hmac-verified` with a key,
  `chain-only-unkeyed` without. Without a key, records an attacker appended
  in the right chain format look exactly like a crash, and the record says so.

**Tests.** `tests/wad_response_test.sh` covers R (state machine), T (invalid
transitions), A (unauthorized approvals), D (duplicates), X (execution,
stale approval, interruption), B (rollback), L (tamper and repair), K (keyed
chain) and S (nothing executes, nothing claims authentication). PR 1's
`tests/wad_engine_test.sh` passes unchanged, including its S1 no-call check.

**Not in PR 2:**
- A per-step timeout. The dry-run executor is synchronous, so there is
  nothing to time out; this becomes necessary with a real executor (PR 4).
- Executor binding (PR 4, needs #209/#211 merged).
- Producer signatures (PR 3).
- Approver authentication. That needs a mechanism this user cannot satisfy
  alone, such as a separate account or a key held off-host; it is not designed
  yet.

## 10. Emergency stop and failure breaker (consolidated from #212)

#212 (`feat/wad-adaptive-defense-core`) and #213/#214 both claimed
`security/wad/`. With #213 chosen as the base, #212's two pieces that #214
lacked are carried over here. #212 itself stays open until this is reviewed.

**`security/wad/wad_estop.sh`** is #212's script with one change: it writes
the stop file #213/#214 already read, `WAD_STOP_FILE` (default
`$WAD_STATE_DIR/STOP`), instead of #212's `security/state/wad_estop/ESTOP`.
- Plain bash: sources nothing and never runs python or `wad.py`. The suite
  engages it with no python on `PATH`.
- `engage` needs no identity.
- `release` needs an operator name (shape-checked, refused if it names an
  automated actor) and a reason of at least 10 characters. The name is not
  authenticated, and the log line says `authenticated=false`.
- The released file moves to `released/` and is never deleted.
- `status` exits 10 when engaged, including a symlink at the path and an
  unreadable directory.

`wad.py` only `lstat`s the file. It checks before every command and, for
`execute`, again after the start record and before the executor. A stop
engaged in that gap fails the step with "halted: stop engaged before the
executor ran", and the executor does not run. WAIO's `SHUTDOWN.lock` halts
WAD independently.

**Failure breaker.** #212 kept the breaker in a state file. Here it is
derived from the ledger (`wad_response.breaker_state`), so there is still
one source of truth.
- Three consecutive `failed` outcomes of one step action open it, and a
  `wad_breaker_tripped` record is appended. A `done` of that action resets
  its count.
- While it is open, every `execute` is refused (`breaker_open`).
- Only `response breaker-reset --operator NAME --reason TEXT` closes it. That
  needs an allowlisted, non-automated name (unauthenticated) and a strong
  reason, and it records `wad_breaker_reset`.
- Today the only failures are interrupted executions found by `sweep`, and
  stops engaged mid-execute: the dry-run executor itself cannot fail.

**Not carried over from #212:**
- its own `wad_lib.py` scoring (#213 reuses the Decision Engine instead);
- its live executor for observe/monitor/warn and its adapter subprocesses
  (#214 stays dry-run only, and executor binding is PR 4);
- its per-entity cooldown and hourly auto-action cap (#213's disruptive
  budget covers planning; an execution-rate cap belongs with a real
  executor);
- its atomic-plan auto-rollback (#214 rollback is operator-initiated).

**Tests.** `tests/wad_estop_breaker_test.sh`: E (tool), H (halting), P
(independence), F (breaker), S.
