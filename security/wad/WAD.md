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
   lib.sh. A keyed chain (HMAC, as the kill switch audit does) is planned
   for PR 2.
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
   mismatch, and the next run refuses (rc 4).** This is the safe outcome,
   but a human then has to repair the checkpoint; there is no repair command
   yet.
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
| 1 (this) | core engine, policy, ledger, suite | — |
| 2 | controlled response workflow: step state machine (planned → approved → executing → done/failed → rolled_back), approval via the existing containment approval gate, per-step timeout, compensating rollback, keyed ledger chain; executors still dry-run only | 1 |
| 3 | adapters: real detector outputs (shadow_ai, attack_graph, saas_ato, distributed probe #182) → WAD events, signed producer envelope | 1 |
| 4 | executor binding for `isolate_agent` through the containment runner (#209/#211, signed policy v3), still `--dry-run` by default | 2, #209/#211 merged |
| 5 | Takomachi/Guardian oversight interface and DuCoPA independent-path checks | 2; real Takomachi process |

## 8. Not implemented, not verified, or external

- **Not implemented:** actual execution of any response, including
  restrict_egress, isolate_agent and recover. Also not implemented: the
  approval flow, the rollback workflow, producer authentication and the
  keyed chain.
- **Not connected:** SND@HOME. Its API collector,
  `dashboard/collect_snd_status.sh`, is unconfigured on this host, and
  SND@ID exists only as a mock. Also not connected: Takomachi (no real
  process drives guardian.sh) and DuCoPA (`security/ducopa.sh` is a
  standalone prototype). WAD reads none of them.
- **Not verified:** behaviour on real detector output (all inputs are
  fixtures), and ledger throughput beyond the suite's sizes.
- **Verified on:** macOS 13 (bash 3.2, python3) locally; Linux CI after push.
