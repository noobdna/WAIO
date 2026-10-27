# WAIO Adaptive Defense (WAD) -- v1 core

WAD takes threat events and turns each one into a threat level (L0 to L4), using a
versioned policy. It then runs a graduated response plan: dry run by default, with every
decision audited. It sits after the existing Intelligence Layer and Decision Engine, and
does not replace them.

```
Shadow AI / Attack Graph / SaaS ATO / Incident Learning
        -> Intelligence Layer -> Decision Engine --(decision report)--\
sensor events (wad-event/1 JSONL) -------------------------------------> WAD
WAD: normalize -> dedup/replay/freshness -> assess (policy) -> plan -> run
       run: observe / monitor_up / warn       (automatic, local only, rate-limited)
            restrict_network / isolate_host   (approval request file -> human ->
                                               containment_approval_gate.sh / Guardian)
       every step: emergency-stop check; every event: hash-chained audit entry
```

## Status

| Part | Status |
|---|---|
| Normalization, assessment, planning (`wad_lib.py`) | Implemented and tested |
| Runner: state, lock, audit chain, dedup, replay, ordering, freshness, rate limit, breaker, timeout, rollback, recovery (`wad_cli.py`) | Implemented and tested |
| Emergency stop (`wad_estop.sh`) | Implemented and tested |
| Automatic local actions (watchlist, alert outbox) | Implemented and tested |
| `restrict_network`, `isolate_host` and their releases | **No executor.** Written out as approval requests only |
| Delivery of alerts beyond `alerts.jsonl` (mail, dashboard) | Not connected |
| Scheduling (LaunchAgent/cron) | Not connected. WAD runs only when someone invokes it |
| Live SND@HOME, Takomachi, DuCoPA inputs | Not connected. See "External dependencies" |

## Safety floors

These are enforced in code; a policy file cannot override them.

1. L3/L4 (restrict, isolate) need `local: true`, i.e. trusted local corroboration. This is
   the same invariant the Decision Engine has enforced since Phase 104.
2. Destructive actions are never automatic. `validate_policy()` rejects a policy that says
   otherwise, the planner marks them `pending_approval`, and the executor refuses them.
3. Uncertain input is capped at L2 (warn a human) and marked `uncertain: true` with the
   reasons. This covers incomplete or garbage events and LOW confidence.
4. The emergency stop is independent of the automated path. `wad_cli.py` only reads the
   stop file. Only `wad_estop.sh` (plain bash that shares no code with the runner) creates
   or releases it. An unreadable stop path counts as engaged. WAIO's own `SHUTDOWN.lock`
   also stops WAD.
5. Nothing is ever downgraded automatically. Recovery is operator-initiated, takes an
   operator name and a reason, and refuses automated identities. The operator name is
   checked for shape but is not authenticated.

## CLI (`security/wad/wad.sh`)

| Command | Effect | Exit |
|---|---|---|
| `assess --in F \| --decisions R [--policy P]` | Pure: prints the normalized event, assessment and plan. No state, no audit | 0 / 2 |
| `respond --in F \| --decisions R [--execute]` | Processes a batch. Dry run unless `--execute` | 0 ok, 1 step failed, 3 lock busy, 4 state corrupt, 5 audit tampered, 6 policy rollback refused, 7 stopped |
| `recover --entity E --operator N --reason T [--execute]` | Compensating plan for E's active level | same |
| `breaker-reset --operator N --reason T` | Closes the circuit breaker (audited) | 0 / 2 |
| `policy-check F`, `policy-diff OLD NEW` | Validates a policy / prints a path-level diff with digests | 0 / 2 |
| `audit-verify`, `status` | Checks the audit chain / prints state, breaker and stop status | 0 / 5 |

`wad_estop.sh engage [--operator N] [--reason T]` · `release --operator N --reason T` ·
`status` (exit 10 = engaged).

Environment variables:

- `WAD_STATE_DIR` (default `security/state/wad`)
- `WAD_POLICY`
- `WAD_ESTOP_FILE` (default `security/state/wad_estop/ESTOP`)
- `WAIO_SHUTDOWN_LOCK`
- `WAD_ADAPTER_DIR`: an executable per automatic action, which gets the JSON payload on
  stdin. It is killed as a process group at `step_timeout_seconds`, and refused if it or
  its directory is world-writable.
- `WAD_OPERATOR_ALLOWLIST`: comma-separated list of operator names.
- `WAD_FIXTURE_NOW`: tests only. It is refused unless `WAD_STATE_DIR` is set to a
  non-default directory.

### Event format `wad-event/1` (one JSON object per line)

```json
{"schema":"wad-event/1","event_id":"[A-Za-z0-9._:-]{1,128}","source":"[A-Za-z0-9._-]{1,64}",
 "entity":"<=256 chars, no control chars","entity_type":"host","observed_at":"2026-10-26T23:50:00Z",
 "risk":"LOW|MEDIUM|HIGH|CRITICAL","confidence":"LOW|MEDIUM|HIGH","local":true,"seq":0,"detail":{}}
```

Decision Engine reports (`decision_engine.sh` output) are accepted directly with
`--decisions`:

- `local` comes from `local_corroboration.present`.
- `observed_at` is the report's `generated_at`.
- The event id is a stable hash of the record, so ingesting the same report again is
  deduplicated.

## Policy v1 (`policies/wad_policy.v1.json`)

| Level | Reached when (first match wins) | Steps (automatic in bold) |
|---|---|---|
| L4 isolate | CRITICAL, local, confidence ≥ MEDIUM | **monitor_up**, **warn**, isolate_host (approval) |
| L3 restrict | HIGH, local, confidence HIGH | **monitor_up**, **warn**, restrict_network (approval) |
| L2 warn | CRITICAL or HIGH otherwise, MEDIUM with HIGH confidence, any incomplete event | **monitor_up**, **warn** |
| L1 watch | MEDIUM | **observe**, **monitor_up** |
| L0 none | LOW | **observe** |

Policy v1 limits:

- Events older than 24 h, or more than 300 s in the future, are refused.
- The dedup window is 24 h.
- At most 60 automatic actions per hour, across all entities.
- A 900 s per-entity cooldown suppresses repeats at the same level; an escalation still acts.
- The breaker trips after 3 consecutive failures of one action.
- Each step times out after 10 s.

To change the policy, add `wad_policy.vN.json` with a higher `version` and review it with
`policy-diff`. In execute mode, a lower version than the highest one already applied is
refused unless you pass `--allow-policy-rollback --operator --reason`; that acceptance is
audited.

## Run behavior

- **Dedup:** the same `source` + `event_id` with the same content is suppressed.
- **Replay:** the same identity with different content is a `replay_conflict`. It only
  warns a human.
- **Ordering:** a batch is sorted by `observed_at` and `seq`. An older event that arrives
  after a newer one for the same entity, at the same or a lower level, is
  `superseded_out_of_order`.
- **Separate state:** dry-run state and execute state live in separate files, so a dry
  run never deduplicates a later real run.
- **Partial failure:**
  - Non-atomic levels continue after a failed step. A failed `warn` keeps the added
    monitoring; more monitoring is the safe side.
  - A level with `"atomic": true` rolls back its completed steps in reverse order, using
    each action's `rollback` action.
- **Concurrency:** runs serialize on an `flock` of `WAD_STATE_DIR/.lock`. State is written
  atomically (temp file + rename). A corrupt state file is refused, never overwritten.
- **Audit:** `audit.jsonl` is hash-chained (`prev_hash`, `hash`). Each entry records the
  event, digest, outcome, level, reasons, confidence, uncertainty, policy id, version and
  sha256, and per-step results. A broken chain blocks further runs (exit 5).

## Tests

```
./tests/wad_test.sh        # 100 assertions: U1-U17 lib, I1-I22 CLI, D1-D4 static guards
```

What the suite covers:

- Policy floors and bad policies.
- Garbage, missing-field and non-UTC events, and boundary times (24 h, 24 h + 1 s,
  +300 s, +301 s).
- False-positive control: global-only CRITICAL is capped.
- Dry run vs execute.
- Approval hand-off.
- Duplicates, replay and out-of-order events.
- Cooldown vs escalation.
- Flood rate limiting (40 events capped at 60 actions).
- Breaker trip and reset; automated identity refused.
- A hung adapter killed as a process group.
- Atomic rollback.
- Emergency stop: before a run, mid-run, on an unreadable directory, and via
  `SHUTDOWN.lock`. Release is refused for automation, and released files are kept.
- Audit tamper detection.
- Corrupt state.
- Policy anti-rollback.
- Recovery: L1 recovers; L4 waits for approval.
- 4 concurrent runs.
- Static proof that WAD code never references Guardian, DuCoPA, the kill switch,
  `recover.sh`, `launchctl`, `sudo`, `pfctl`, `networksetup`, curl or sockets.

## Deploy / rollback

WAD v1 changes nothing that is running today. Nothing schedules it, nothing calls it, and
it writes only under `security/state/wad*` (gitignored).

- **Try it:** `wad.sh respond --decisions security/state/decision_engine/<report>.json`.
  This is a dry run. Read the output with `status` and `audit-verify`.
- **Roll back:** revert the commit. Optionally move `security/state/wad*` aside; they
  are not deleted automatically.

Running `--execute` from a scheduler is a separate, operator-approved step. It needs a
LaunchAgent change, and it should wait until the live checkout is on current master.

## Remaining risks and external dependencies

- **Operator identity is not authenticated.** It is a shape and allowlist check, the
  same honor-system posture as the existing approval gates. Anyone with shell access as
  this user can also edit the state and audit files: the chain detects edits but does not
  prevent them. It is not keyed; an attacker can rewrite the whole chain.
- **Adapters run as this user.** `WAD_ADAPTER_DIR` is trusted configuration.
- **No live data sources yet:**
  - SND@HOME's real event schema is still unverified (source not on host 800).
  - The Takomachi supervision interface is not defined.
  - DuCoPA's independent control path is not exercised by WAD.
  None of these are claimed as connected.
- **No executor for destructive actions.** Wiring `restrict_network` or `isolate_host` to
  the containment runner (open PRs #209/#211) or to Guardian needs a design review and
  owner approval first.
