# WAIO isolated end-to-end harness

Runs the real WAIO defense modules as one chain, entirely inside a
throwaway sandbox under `$TMPDIR`:

```
Shadow AI Monitor -> Attack Graph -> Intelligence Layer -> Decision Engine
  -> approval (real RED ALERT gate, or a narrow pre-approved policy rule)
  -> containment (real security/guardian.sh functions)
  -> independent validation (effect checked through ./waio.sh)
  -> human recovery (guardian_release_agent.sh / recover.sh) -> validation
```

Nothing here touches this deployment's real `security/state/`, `logs/`,
services, network devices, or the Guardian SSH path. Detection reads
fixture `ps`/`lsof` output, not the real process table.

## Run it

```
./tests/e2e/demo.sh                      # narrated demo (~4 s), add --keep to inspect the sandbox
./tests/e2e_pipeline_test.sh             # full harness suite (scenarios, failure modes, PDC)
./tests/e2e/kill60_bench.sh -n 50        # detection-to-containment latency, JSON summary
./tests/e2e/kill60_bench.sh -n 50 -a shutdown
./tests/e2e/kill60_bench.sh -n 30 --no-network   # every sample with all networking denied (macOS)
```

All three are safe to run on the production machine: each creates its
own sandbox, starts only its own child processes (tracked by PID; no
`pkill`/`killall`), and deletes the sandbox on exit.

## Files

| File | Role |
|---|---|
| `lib_env.sh` | Creates a sandbox and exports every state/audit/lock override the real modules already honor; fixture telemetry; runs detect -> decide. |
| `containment_bridge.sh` | **Test-only.** Executes one allowed action (`quarantine_agent:<worker>` or `emergency_shutdown`) for a `RECOMMEND_CONTAINMENT` decision, only with an APPROVED gate record or an unexpired exact-entity policy rule. Idempotent, bounded, fail-closed, audited. Refuses to run outside a sandbox. |
| `guardian_validator.sh` | **Test-only** stand-in for the independent Guardian check. Never sources the WAIO control plane; judges by effect (`./waio.sh` refuses/accepts a probe) plus state files. |
| `kill60_bench.sh` | Repeatable latency measurement. |
| `demo.sh` | Operator demonstration. |

## Measured (2026-10-18, this Mac, macOS 13, bash 3.2, Python 3.9)

Detection start -> independent confirmation of containment, pre-approved
policy (no human wait), fixture telemetry, one CRITICAL entity:

| Action | Samples | Failures | Median | p95 | Max |
|---|---|---|---|---|---|
| quarantine_agent | 50 | 0 | 1.287 s | 1.337 s | 1.346 s |
| emergency_shutdown | 50 | 0 | 1.384 s | 1.401 s | 1.422 s |
| quarantine_agent, all networking denied | 30 | 0 | 1.272 s | 1.343 s | 1.353 s |

Stage medians (quarantine): detection->decision 0.553 s, decision->contained
0.372 s, contained->confirmed 0.360 s.

What this does and does not show: the software path is far inside 60 s
on this machine under fixture conditions. It does **not** include
human approval time (the RED ALERT gate path waits for a person), real
telemetry volume, a scheduler interval (nothing runs the scan
continuously in production), or a real remote Guardian round trip.
60 s remains a target for the production path, not a guarantee.

## What the suite covers (`tests/e2e_pipeline_test.sh`)

| Series | Covers |
|---|---|
| S | negative control; policy path; real RED ALERT gate path (PENDING refused, approval replay against an edited report refused, REJECTED refused); emergency shutdown with a refused weak recovery reason |
| F | malformed reports and evidence, non-containment decisions, missing local corroboration, expired/wildcard/unregistered/injected policy rules, duplicate events, validator timeout, validator unavailable, failed quarantine, NOT_CONFIRMED / dishonest validator, sandbox guard |
| A | invalid requester and approver identity, too-short approval reason, approval reused for another entity, APPROVED-but-expired, path-traversal approval id, Guardian state unwritable during shutdown, hanging containment action (bounded), every containment path failing |
| G | validator independence (static), bridge never touching the validator, validator checksum |
| P | real TCP outage detection, stale-cache fallback with exact age, local-only operation offline, missing and corrupted cache, recovery and resync records, concurrent cache writers, credential-shaped output never cached, no replay |
| M | mocked Takomachi (/health, key from env, Keychain stubbed) and SND@HOME (PDC snapshot, last-known-good kept on outage, SND+global evidence capped to ALERT_HUMAN) in a temp copy of the tree |
| D | production modules unchanged, no pkill/killall, real `security/state/` untouched |

`tests/response60_isolation_test.sh` separately proves `tests/response60_test.sh`
never touches the real `SHUTDOWN.lock`, registry, audit log, Guardian state or
desktop notifications (it now runs in a temp copy of the tree).

## PDC: implemented vs. not

Implemented and tested: outage detection by real TCP health checks; fallback
to the last known good result with its true age; refusal to serve a corrupted
cache; refusal to cache credential-shaped output; resync and transition
records; atomic cache replace under concurrent writers.

**Not implemented:** replay of requests skipped during an outage (they are
answered from cache or not at all, and are not queued); conflict resolution
beyond last-writer-wins; fallback for anything other than ORCHESTRATE stages.

## Limitations (deliberate, test-harness scope)

- The bridge exists only here. Production has **no** component that
  executes a Decision Engine recommendation (`decision_engine.sh`
  "proposes, never disposes"); adding one is a separate human decision.
- Validator independence is process/path separation on one machine
  and one user. A real independent Guardian needs a different host
  and account (the existing Guardian SSH path), which is not exercised.
- Approver identity in the RED ALERT gate is a recorded claim, not
  authentication.
- PDC: no replay of requests skipped during an outage; cache conflict
  rule is last-writer-wins; only ORCHESTRATE uses the fallback.
