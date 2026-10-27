# WAD PR 4 design: binding `isolate_agent` to the containment runner

**Status: design only. Not implemented, and not implementable until #209 and
#211 (the containment runner) are merged.** This document is for review. It
changes no code and enables nothing.

Read-only sources (2026-10-27): `origin/feat/containment-runner-lifecycle`
(#211 @ ecd4455, on #209 @ 10440bc): `security/containment_runner/containment_runner.sh`
and `runner_lib.py`; and WAD #213–#220.

## 1. Principle: WAD never authorizes containment
| | WAD (#213–#220) | Containment runner (#209/#211) |
|---|---|---|
| Who may act | an allowlisted **name**, `authenticated: false` | an **RSA-SHA256-signed** operator policy rule naming the exact entity; the runner holds only public keys |
| Default | dry run only; no executor | dry run; real action needs `--execute` **and** `WAIO_CONTAINMENT_RUNNER_EXECUTE=1` |
| Scope | plans restrict_egress / isolate_agent / recover | only `guardian_quarantine_agent` for one **registered worker**; never release, never shutdown |

The runner's signed policy is the only real authorization in this pipeline.
PR 4 must hand off to it. A WAD approval is a **necessary, not sufficient**
precondition (defence in depth), and must never be presented as permission.

## 2. Proposed flow (dry run only in PR 4)
1. `response execute STEP` for an **approved `isolate_agent`** step (all
   existing WAD gates, including the optional evidence policy (§14), apply
   first).
2. WAD writes a one-decision report in the runner's input shape to
   `$WAD_STATE_DIR/runner/<step_id>.json`:
   `{"decisions": [{"entity", "recommended_action": "RECOMMEND_CONTAINMENT",
   "local_corroboration": {"present": <from evidence_provenance>},
   "wad": {"step_id", "decision_digest", "evidence_provenance"}}]}`.
3. WAD runs the runner **in dry run only**:
   `containment_runner.sh run --report <file>` (never `--execute`).
4. WAD records the runner's verdict (`PLAN` / `REFUSE` / `DUPLICATE`,
   `report_hash`, `why`) on the step:
   - `complete` with `runner_dry_run_plan` when the runner would act;
   - `fail` with the runner's reason when it refuses.
5. Real quarantine stays a separate human act: the operator runs the runner
   with `--execute` and `WAIO_CONTAINMENT_RUNNER_EXECUTE=1`. WAD gets no
   path to that in PR 4.

`restrict_egress` and `recover` have **no executor** in the runner. They stay
approval-request / dry-run only. Rollback of `isolate_agent`
(`release_isolation`) must **not** call anything: the runner never releases,
and recovery is human-only (`./security/guardian_release_agent.sh AGENT
--confirm "<reason>"`). WAD's rollback records that a human release is
required.

## 3. Conflicts to resolve before implementation
1. **#213's S1 safety test forbids it.** `tests/wad_engine_test.sh` S1 fails
   on `subprocess`, `containment_runner`, `guardian` anywhere in
   `security/wad/*.py`. PR 4 needs a deliberate, reviewed exception scoped
   to one new module (e.g. `security/wad/wad_runner_bridge.py`), with S1
   rewritten to assert that only that module may reference the runner, and
   only without `--execute`. **Needs your approval.**
2. **Entity namespaces differ.** WAD entities are process, graph node or
   account names (e.g. `ollama`). Runner rules match the exact `entity` string
   and quarantine a **registered worker** (`quarantine_agent:<WORKER>`). The
   operator would have to sign rules naming WAD entity strings, or a mapping
   entity → worker is needed. **Design decision for you.**
3. **Local corroboration semantics.** The runner requires
   `local_corroboration.present: true`. WAD's evidence summary can supply it,
   but attack_graph is derived from shadow_ai (§13), so "present" must come
   from an independent local module, not from module count.
4. **Two kill switches, two budgets.** WAD STOP/SHUTDOWN.lock and the
   runner's `DISABLED` must both be honoured, and WAD's disruptive budget plus
   the runner's hourly cap both apply. The stricter wins; neither may reset the
   other.
5. **Runner outcomes → WAD failures.** Runner exits 2 (refused), 4
   (`containment_unverified`), 6 (disabled) and 7 (overlap) map to a failed WAD
   step that counts toward WAD's breaker. Exit 4 must never be retried
   automatically (the runner's own rule).
6. **Signing.** Detector signing (#219) and the approval evidence policy (#220)
   are off by default. If the runner should only see decisions backed by
   verified evidence, that is the §14 policy with `all_verified: true`, an
   operator choice.

## 4. Tests PR 4 would need (after #209/#211 merge)
The real runner in its e2e sandbox (`--policy` is sandbox-only), with test
RSA keys generated per run, as #209's own suite does:
- signed rule present → `PLAN` recorded;
- no rule, two rules, expired rule or unregistered worker → `REFUSE` and a
  failed step;
- runner `DISABLED` and WAD STOP each block;
- WAD never passes `--execute` (static check plus a stub that records argv);
- rollback calls nothing;
- the S1 exception covers exactly one file.

## 5. Decisions needed from you
1. Approve or reject the S1 exception (one bridge module, dry run only).
2. Entity → worker mapping: signed rules naming WAD entities, or a mapping table.
3. Whether WAD may ever request runner `--execute` (this design says no).
4. Who signs runner policy rules, and how WAD-originated requests reach that
   person (today: the operator signs with `scripts/containment_policy_sign.py`).
