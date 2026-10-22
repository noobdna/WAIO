# WAIO Self-Development Engine -- completion tracking

Created 2026-10-15 during an autonomous continuation session on
`feat/self-dev-approval-gate`; updated the same day during a second,
third, and fourth continuation session. This file tracks the
completion criteria for that branch's remaining work, not WAIO's
overall roadmap (see `ARCHITECTURE.md` for full design history, Phase
105 Sections 1-9).

## Completion criteria (as stated by the operator)

| # | Criterion | Status |
|---|---|---|
| A | All tests pass, including regression | **DONE** -- see "Test status" below |
| B | Approval-record tamper detection verified by test | **DONE** -- `_sda_verify_audit_integrity` + optional HMAC-keyed chain, D6-D11 |
| C | self_dev integration status verified by test | **Options 1/3 implemented and tested (manual CLI; opt-in pre-push hook). Option 2 implemented, committed, pushed, verified in a real CI run on PR #164 -- correctly classifies/evaluates, `continue-on-error: true` confirmed non-blocking. Deliberately stays observational (operator decision, 2026-10-16): this repo has exactly one collaborator, so GitHub's own self-review refusal makes a genuine non-author APPROVED review structurally impossible here -- not a bug, not worked around. Option 4 unchanged, out of scope.** -- see "C" below |
| D | Approval gate reliably holds privileged operations | **DONE (unchanged, re-verified)** -- D4: no execution verb exists |
| E | SND@HOME / Takomachi integration recorded from real measurement | **NOT PERFORMED -- requires approval.** Local process/port state re-investigated read-only this session (see "E" below) |
| F | Remaining issues, constraints, ops/recovery procedures documented | **DONE** -- this file + ARCHITECTURE.md Phase 105 Sections 6-8 |
| G | Git diff and final state reported | **DONE** -- see final report |

Do not declare this branch "complete" until E is either performed (with
operator approval) and recorded, or explicitly descoped by the operator,
AND a decision is made on option 2 (C).

## Test status (re-verified this third session, no code changed since the second session)

```
bash tests/dev_approval_lib_test.sh           -- 44 passed, 0 failed   (unchanged)
bash tests/dev_approval_gate_test.sh          -- 133 passed, 0 failed  (unchanged)
bash tests/dev_approval_pre_push_hook_test.sh -- 31 passed, 0 failed   (unchanged)
bash tests/containment_approval_lib_test.sh   -- 47 passed, 0 failed   (unchanged)
bash tests/containment_approval_gate_test.sh  -- 118 passed, 0 failed  (unchanged)
bash tests/waio_test.sh                       -- 28 passed, 0 failed   (unchanged)
# self_dev/containment/dispatch subtotal: 401 passed, 0 failed
bash tests/collect_takomachi_status_test.sh   -- 18 passed, 0 failed  (mock HTTP server only)
bash tests/register_takomachi_agents_test.sh  -- 33 passed, 0 failed  (mock HTTP server only)
bash tests/dashboard_takomachi_ui_test.sh     -- 12 passed, 0 failed  (Node + DOM stub, no browser/network)
bash tests/collect_snd_status_test.sh         -- 19 passed, 0 failed  (mock HTTP server only)
bash tests/dashboard_snd_ui_test.sh           -- 22 passed, 0 failed  (Node + DOM stub, no browser/network)
bash tests/continuity_snd_snapshot_test.sh    -- 28 passed, 0 failed  (fixture-only)
# Takomachi/SND mock-suite subtotal: 132 passed, 0 failed
# grand total this pass: 533 passed, 0 failed
git diff --check                                          -- clean
```

No source file changed this (third) session -- this was re-verification
(item 3/5 of the operator's own checklist: re-run tamper-detection/
approval-gate/abnormal-path tests, and confirm the existing Takomachi/
SND mock suites still pass without touching the real, currently-stopped
services) plus investigation (Takomachi/SND_HOME startup requirements,
read-only) and documentation. Diff is still exactly what the second
session left: two new files
(`security/self_dev/dev_approval_pre_push_hook.sh`,
`tests/dev_approval_pre_push_hook_test.sh`), one additive line-pair in
`.github/workflows/lint.yml`, plus this file and `ARCHITECTURE.md`.
**No commit made.**

## B: Tamper detection -- unchanged from the prior session

See ARCHITECTURE.md Phase 105 Section 7 for the full account:
`_sda_verify_audit_integrity()` ported from the containment sibling,
plus an opt-in `DEV_APPROVAL_AUDIT_HMAC_KEY_FILE` HMAC-keyed chain
mode. Re-verified passing this session (D6-D11, unchanged).

## C: self_dev orchestration integration -- status

Of ARCHITECTURE.md Phase 105 Section 5's four surveyed options:

1. **Manual CLI use** -- already worked, zero wiring, unchanged.
2. **A CI required-check job** -- redesigned (v2, GitHub-native PR
   review, superseding the original local-state design which could
   never have worked in CI -- see "CI integration, option 2" below for
   the full account) and **now implemented** as a new
   `self-dev-approval-gate` job in `.github/workflows/lint.yml`
   (`continue-on-error: true`, observational), locally verified (YAML
   valid, scripts syntax-checked, classification logic exercised, full
   regression unaffected). This is the one piece of this phase's own
   integration survey that changes *merge-gating behavior for every
   future PR in this repository* once it actually starts running (even
   observationally, it will show up as a check on every PR) -- it is
   implemented in the local working tree only, **not committed, pushed,
   or merged**, per explicit instruction to stop at that boundary. See
   "CI integration, option 2" below for the full implementation/
   verification record.
3. **A local git `pre-push` hook** -- **implemented and tested this
   session**: `security/self_dev/dev_approval_pre_push_hook.sh` +
   `tests/dev_approval_pre_push_hook_test.sh` (30 assertions, all
   passing). Blocks a push to `master`/`develop` unless
   `WAIO_SELF_DEV_PUSH_APPROVAL_ID` names a record that is
   `APPROVED` for that exact branch AND that exact commit SHA being
   pushed. **Not installed anywhere** -- it is a plain tracked file; a
   human opts in per clone by copying it to `.git/hooks/pre-push`
   themselves (see the file's own header). This session did not touch
   `.git/hooks/` in this or any other clone. Per Section 5's own
   caveat (unchanged): this is NOT centrally enforced -- `git push
   --no-verify`, or simply never installing it, bypasses it entirely.
   It is a convenience for an operator who wants it, not a replacement
   for option 2.
4. **A full self-development orchestrator** -- still explicitly out of
   scope, unchanged.

**On the one `.github/workflows/lint.yml` edit made this session**:
a single new `regression` job step running the new
`tests/dev_approval_pre_push_hook_test.sh` suite, added immediately
after the existing `dev_approval_gate_test.sh` step -- the exact same
routine, purely-additive pattern every phase in this repository's
history has used when a new test file is added (new coverage; it does
not gate, block, or change pass/fail semantics for any other PR's own
changes). This is deliberately a different, much smaller thing than
option 2 above, and was made without separately asking, on the
judgment that "add a regression step for a test file introduced in
this same change" is routine CI hygiene rather than a policy change --
flagged here explicitly in case the operator disagrees with that
distinction.

## E: SND@HOME / Takomachi real-environment status

**First real-environment measurement performed, 2026-10-16, with
explicit operator approval naming this exact command**:

```
curl -s --max-time 3 -o <tmp> -w "HTTP_STATUS:%{http_code}\n" http://127.0.0.1:4500/health
```

Result: `HTTP_STATUS:200`, body `{"status":"ok"}`. **lan-dashboard-gateway
is confirmed live and healthy via a real connection.** No credential
was used or needed (this route returns before any auth check, per the
prior session's source-code review). This confirms only the gateway
process's own liveness, NOT Takomachi's or SND_HOME's own health --
the gateway's `/view/status` route is what would report its own
aggregated view of all three sources, and that route requires the
`LAN_GATEWAY_VIEW_TOKEN` Bearer credential, not yet approved/used.
Temp response file deleted immediately after reading it; no response
content persisted to disk.

Everything else below is unchanged from the prior (read-only,
no-network) investigation:

- **Takomachi** (`node dist/main.js`, docs' own default
  `http://127.0.0.1:3000`): **not running** (`ps aux` /
  `lsof -nP -iTCP:3000 -sTCP:LISTEN` both empty).
- **SND_HOME** (`node server.js`): **not running** (`ps aux` empty).
- **`~/lan-dashboard-gateway`** (the read-only aggregator
  ARCHITECTURE.md Phase 53 found already existed, default port 4500):
  **IS currently running** (`lsof -nP -iTCP:4500 -sTCP:LISTEN` shows a
  live listener) -- a change from Phase 53's "not currently deployed"
  finding. Not started by this session; found already running. Its
  `.env`/config content was not read.
- **What a real check would actually require**, read from each
  script's own source without executing it:
  - `dashboard/collect_takomachi_status.sh` / `./waio.sh -w
    HEALTHCHECK` → real `curl` to `http://localhost:3000/health`
    **AND** a macOS Keychain read for `TAKOMACHI_API_KEY` first -- a
    credential-access step, which needs sign-off on its own grounds
    independent of the network-connection gate. Moot right now anyway
    since Takomachi isn't running.
  - `dashboard/collect_snd_status.sh` → requires `SND_HOME_API_URL` to
    be set to attempt any network call at all; if unset, it reports
    `not configured` with zero network attempt (last confirmed unset
    in ARCHITECTURE.md Phase 76, not re-read this session). This one
    specific command could plausibly run with no real external effect,
    but was still not run without explicit sign-off, rather than
    unilaterally deciding it's an exception to "real connection
    attempts need approval".
  - `~/lan-dashboard-gateway`'s own three source endpoints could be
    queried at `http://127.0.0.1:4500/...` since it's already running
    -- also not attempted without sign-off.

### Startup procedure, config, dependencies -- read-only investigation (this session), nothing started

Per the operator's own instruction not to start or connect either
service, this is documentation review only -- no process was started,
no `.env` was created/edited, no key was generated. No secret VALUE is
reproduced anywhere below, only variable NAMES and non-secret
procedure, all read from each project's own committed, non-gitignored
docs.

- **Takomachi**, found locally at `/Users/masa/Projects/Takomachi`
  (its own `package.json`/`README.md`, read-only):
  - Dependencies: `ajv`, `ajv-formats`, `better-sqlite3` (already
    installed -- `node_modules/` present).
  - Startup: `npm start` runs `node --env-file-if-exists=.env
    dist/main.js` (`dist/` already built, present on disk).
  - **Required env vars to boot**, names only (README's own
    documented example generates each with `openssl rand`, never a
    fixed/shared value): `TAKOMACHI_API_KEY` (gates every Gateway
    endpoint), `TAKOMACHI_MASTER_KEY` (required to boot -- encrypts/
    decrypts its own credentials store). Optional:
    `TAKOMACHI_CONTROL_READ_KEY`/`TAKOMACHI_CONTROL_KEY` (enables a
    separate `/control/*` route family; omitted, that family is not
    registered at all). Also optional: `TAKOMACHI_DB_PATH`,
    `TAKOMACHI_PLUGINS_DIR`, `TAKOMACHI_TASK_POLL_INTERVAL_MS`,
    `TAKOMACHI_HEALTH_CHECK_INTERVAL_MS`.
  - Notable hardening already documented in its own README: `main.ts`
    deletes `TAKOMACHI_MASTER_KEY`/`TAKOMACHI_API_KEY` from its own
    `process.env` once captured, so neither lingers in that process's
    environment after boot.
  - **Existing read-only health-check method**: `npm run healthcheck`
    (`scripts/healthcheck.mjs`) -- sequences typecheck/test plus three
    live-API verification scripts into one HEALTHY/DEGRADED/FAILED
    verdict. This itself sends real provider API calls (by design, to
    verify each one) -- NOT a pure no-network check, so still gated the
    same as any other real connection.
  - Confirmed not running: `ps aux` / `lsof -nP -iTCP:3000
    -sTCP:LISTEN` both empty, same as the second session's finding.
- **SND_HOME**: not found under `~/Projects` or any other top-level
  home directory this session looked in. Per ARCHITECTURE.md Phase 76's
  own prior finding, it was last known to exist only "on an external
  volume" -- several are mounted on this machine (`/Volumes/800`,
  `Backup HD`, `Family`, `HDD1-4`), not individually searched this
  session (a multi-TB scan for an unconfirmed path felt disproportionate
  to what was asked; can be done on request). Startup procedure/config
  requirements are therefore taken from WAIO's own already-committed
  ARCHITECTURE.md Phase 53 record rather than re-read from the project
  itself: `npm start` → `node server.js`, binds `process.env.PORT ||
  3000` (collides with Takomachi's own default 3000 if both run),
  opt-in Bearer-token auth gated on `API_KEY` in its own `.env` (unset
  as of that phase -- every `GET` route unauthenticated by design when
  so; mutating routes always require it).
- **`~/lan-dashboard-gateway`** (at `/Users/masa/Projects/GW/
  lan-dashboard-gateway`, confirmed running, state unchanged this
  pass): its own project notes (`/Users/masa/Projects/GW/NOTES.md`,
  read-only, dated 2026-10-07) independently re-confirm WAIO's own
  description -- a small, dependency-free, `127.0.0.1`-only Node HTTP
  server that is purely a read-only dashboard viewer aggregating
  WAIO/Takomachi/SND_HOME status, never a network gateway/proxy/VPN/
  firewall in the infrastructure sense. Those notes also reference a
  separate, unrelated piece of real-world work (a physical
  gateway/router rebuild between two hosts, "750"/"800") that is
  outside WAIO's own scope and this branch's completion criteria --
  noted only to avoid confusing it with this repository's own "Gateway"
  references, not pursued further here.
  - **This pass went one level deeper: its actual source
    (`server.js`/`auth.js`), read-only, no network call made.**
    Confirmed in code, not just in the notes above: `BIND_HOST =
    "127.0.0.1"` is a hardcoded string literal with a header comment
    explicitly saying it is deliberately never env-var-driven (so a
    stray `.env` value could never silently expose it to the LAN);
    every non-`GET` request is refused `405` before any routing at
    all (`"this Gateway is read-only"`, enforced in code, not only
    documented); `Access-Control-Allow-*` is deliberately never set
    (no CORS, same-origin only). Exactly five routes exist: `/`,
    `/index.html`, `/app.js` (static assets), `/health` (no auth --
    returns before any auth check), and `/view/status` +
    `/view/devices/:id` (both gated on a Bearer token read from this
    project's own `LAN_GATEWAY_VIEW_TOKEN` env var, verified with a
    timing-safe comparison, plus a 5-failures/60s/30s-cooldown
    per-source-IP lockout). A second, `LAN_GATEWAY_OPERATE_TOKEN`
    scope is loaded but checked by zero routes -- "no `/operate/*`
    implementation yet", by the code's own comment. No token VALUE
    was read or displayed -- only the env var NAME and the auth
    mechanism's shape.

## npm auto-update permission error -- root cause found, read-only, nothing changed

Prior sessions found the npm prefix itself (`/Users/masa/.npm-global`)
user-owned with no obvious problem -- true, but incomplete: the actual
installed package underneath it is not. This pass went one level
deeper, read-only, no sudo, no ownership/permission change made
anywhere:

- `npm config get prefix` → `/Users/masa/.npm-global` (user-owned, as
  already known).
- The *directory itself* at
  `.npm-global/lib/node_modules/@anthropic-ai/claude-code/` (and every
  directory/file under it -- `bin/`, `node_modules/`, `package.json`,
  `cli-wrapper.cjs`, the `claude-code-darwin-x64` binary, etc.) is
  owned by **`root:staff`**, mode `755`/`644`, dated Sep 4 -- while its
  own parent (`@anthropic-ai/`) and the rest of the prefix tree are
  owned by `masa`. This is a mixed-ownership tree: only this one
  package's own installed directory is root-owned.
- **Safely reproduced the actual failure mode** (not merely inferred):
  attempted `touch` of a new, harmless temp filename inside that
  directory, and `touch` (mtime-only, no content change) of the
  existing `package.json` already there -- both denied with
  `Permission denied`, as the current user `masa` (`uid=501`, group
  `staff`), group permission bits on the root-owned directory grant
  only read+execute, never write. No file was created, altered, or
  removed by either probe (the first failed before creating anything;
  the second is a metadata-only no-op that was itself refused).
- **Root cause, precisely**: this exact package directory was
  installed or updated at some point via `sudo npm install -g
  @anthropic-ai/claude-code` (or equivalent), which created it
  root-owned inside an otherwise user-owned custom prefix. Any later
  `npm install -g`/auto-update run as `masa` (normal, no sudo) cannot
  write into that same directory -- `EACCES: permission denied`
  attempting to create or overwrite a file there -- which is exactly
  the class of error "npm auto-update has a write permission error"
  describes. `masa` IS a member of the `staff` group that owns these
  files, but the group permission bits (`r-x`/`r--`) never include
  write, so group membership alone doesn't help.
- **Why `rm -rf` as `masa` (no sudo) would NOT cleanly fix this
  either, not attempted**: deleting a directory's contents needs write
  permission on that directory itself (here, root-owned, denied to
  `masa`), not just on its parent -- so an unprivileged recursive
  delete of this specific directory would itself fail partway with the
  same `Permission denied`.

**Safe remediation options (neither executed -- both need explicit
sign-off, the first needs sudo once, the second needs none):**

1. **Recommended -- minimal, surgical, one-time sudo, no system-wide
   change**:
   ```
   sudo chown -R "$(id -un)":staff "/Users/masa/.npm-global/lib/node_modules/@anthropic-ai/claude-code"
   ```
   Re-owns only this one package's already-installed files to `masa`
   (matching the rest of the prefix tree); nothing is reinstalled,
   removed, or reconfigured. Every future `npm install -g`/auto-update
   of this package then succeeds without sudo. Narrowest possible
   scope: one `chown -R` under one package directory, not
   `/Users/masa/.npm-global` as a whole and not any system path.
2. **No-sudo alternative, more disruptive**: point npm at a fresh,
   fully-`masa`-owned prefix (`npm config set prefix
   ~/.npm-global-v2`), reinstall `@anthropic-ai/claude-code` there, and
   update `PATH`/shell rc to the new `bin/` directory. Avoids sudo
   entirely, but leaves the old root-owned directory orphaned on disk
   (harmless, just unused space) and changes where this very tool is
   installed from -- higher blast radius for continuity of the
   currently-running session than option 1, so not the recommendation.

Neither was run. Executing option 1 needs the operator's explicit
go-ahead (it is exactly the sudo/permission-change action the
operator's own rules gate on approval); option 2 needs the operator's
explicit preference between the two before either is attempted.

## Pending approval

### 1. CI integration, option 2 -- IMPLEMENTED locally and verified; commit/push/PR/merge pending approval

**Impact on the shared workflow, stated precisely**: `.github/workflows/lint.yml`
runs on `push`/`pull_request` with no path filter, i.e. on every PR to
this repository, including ones unrelated to `self_dev`. A new job in
the *fail-closed* shape below would, from the moment it merges, require
EVERY future PR that touches a privileged path or targets
`master`/`develop` to carry some form of human sign-off before this
required check passes -- the very next ordinary PR matching that scope
would fail it until that sign-off exists. This is exactly the "changes
merge-gating behavior for every future PR" impact flagged in every
prior session -- proposed here for review, not applied.

**v1 draft (superseded below, kept for the record)** read a
`Self-Dev-Approval-Id` out of the PR body and checked it against
`dev_approval_gate.sh status <id>`. A 2026-10-16 review (see
"Superseded v1 review findings" below) found this cannot work: the
approval state it reads (`security/state/self_dev/`) is `.gitignore`d
and never present in a GitHub-hosted runner's checkout, so the check
would return `proposal_not_found` for every id, always -- and the
obvious fix (commit the record into the PR) would let a PR's own
author forge their own `"APPROVED"` record, since the record's own
tamper-evidence (the hash-chain audit log) also never leaves the local
machine. Three directions were identified to actually make this work;
**direction (a) was chosen** (operator decision, 2026-10-16) over (b)
self-hosted runner (would let PR-triggered workflow code run on the
same trusted machine that holds the real approval state -- new,
unnecessary attack surface) and (c) a new authenticated service (real
new network-exposed infrastructure to build and maintain) -- (a) needs
nothing new to build or expose at all.

**v2 design (current, chosen direction, still NOT applied/deployed)**:
keep `classify_operation()` for the one thing it's actually suited to
in CI -- a pure function over the PR's target branch and changed paths,
no shared-state problem involved -- but gate on GitHub's own
already-centrally-hosted PR review approval instead of this repo's
local JSON state. No new secret, no new service, no new runner: the
GitHub-hosted runner's own built-in `GITHUB_TOKEN` and preinstalled
`gh` CLI are enough. This also gets "self-approval is structurally
impossible" for free -- GitHub itself refuses to let a PR's author
approve their own PR, the same guarantee `dev_approval_lib.py`'s own
identity denylist works harder to approximate locally.

```yaml
  self-dev-approval-gate:
    runs-on: ubuntu-latest
    if: github.event_name == 'pull_request'
    permissions:
      pull-requests: read
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Determine whether this PR touches a self_dev-privileged path or targets a protected branch
        id: scope
        run: |
          python3 -c "
          import os, subprocess, sys
          sys.path.insert(0, 'security/self_dev')
          import dev_approval_lib as dal
          base = os.environ['GITHUB_BASE_REF']
          changed = subprocess.run(['git','diff','--name-only', f'origin/{base}...HEAD'], capture_output=True, text=True, check=True).stdout.splitlines()
          cls = dal.classify_operation('isolated_branch_commit', target_branch=base, touched_paths=changed)
          privileged = cls['risk_tier'] == 'PRIVILEGED'
          print(f'privileged={str(privileged).lower()}', file=open(os.environ['GITHUB_OUTPUT'], 'a'))
          "

      - name: Require at least one human-APPROVED GitHub PR review when privileged
        if: steps.scope.outputs.privileged == 'true'
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          APPROVED="$(gh api "repos/${{ github.repository }}/pulls/${{ github.event.pull_request.number }}/reviews" \
            --jq '[.[] | select(.state=="APPROVED")] | length > 0')"
          if [ "$APPROVED" != "true" ]; then
            echo "::error::This PR touches a self_dev-privileged path or targets a protected branch and requires at least one human PR review with state=APPROVED before this check passes. (GitHub itself refuses a self-review, so this can never be satisfied by the PR's own author.)"
            exit 1
          fi
```

**What this deliberately gives up, stated plainly**: this is now a
*separate* record from self_dev's own local `propose`/`approve` audit
trail, not the same one -- the local CLI still governs what an AI
agent may do unprompted (its own original, unchanged scope); this CI
check instead governs whether a human reviewed the actual PR before
merge, using GitHub's own long-established, already-trusted mechanism
for that specific question rather than reinventing it. Not treated as
a flaw: a merge-time gate checking GitHub's own PR-review state is
arguably more appropriate than one reading a local CLI artifact that
was never designed to leave the proposer's own disk.

**Recommended rollout if approved**: land it first as
`continue-on-error: true` (observational -- visible in the PR checks
list, blocks nothing) for a trial period, then flip to blocking in a
separate, explicit follow-up once its false-positive rate against real
PRs is known (in particular, confirm `origin/{base}` actually resolves
under `actions/checkout@v4`'s `fetch-depth: 0` against a real run --
commonly reliable for this pattern, not yet verified here).

**IMPLEMENTED, 2026-10-16, on this branch (`feat/self-dev-approval-gate`),
verified, NOT committed/pushed/merged -- stopped at the approval
boundary.** Added as a new top-level `self-dev-approval-gate` job in
`.github/workflows/lint.yml` (+64 insertions, 0 deletions -- the file's
own only change, nothing else in it touched), exactly matching the v2
design above verbatim, with `continue-on-error: true` per the
recommended observational rollout. Verification performed this pass:

- `python3 -c "import yaml; yaml.safe_load(...)"` -- valid YAML; parsed
  job confirms `runs-on: ubuntu-latest`, `if:
  github.event_name == 'pull_request'`, `continue-on-error: true`,
  `permissions: {pull-requests: read}` (and nothing else -- GitHub
  Actions treats every unlisted permission as `none` once any
  `permissions:` map is set at job level, so this job can read PR
  reviews and nothing more; it cannot write, merge, or push anything).
- Both embedded scripts (the `classify_operation()` call and the `gh
  api` check) extracted and independently syntax-checked: `bash -n`
  clean on both, the embedded `python3 -c` payload `py_compile`-clean.
- `classify_operation()` itself exercised directly (pure function, no
  CI needed) against four realistic scenarios: touching this job's own
  `.github/workflows/lint.yml` targeting `develop` -> PRIVILEGED;
  an unrelated file targeting `develop` -> PRIVILEGED (protected-branch
  escalation); an unrelated file targeting a feature branch ->
  AUTOMATIC; touching `security/self_dev/` targeting a feature branch
  -> PRIVILEGED (self-gate). All four matched the documented
  classification rules exactly.
- Full regression re-run after the change: **458 passed, 0 failed**,
  unchanged baseline.
- `git diff --numstat -- .github/workflows/lint.yml` confirms the
  file's diff is 64 lines added, 0 removed -- pure addition. No secret
  literal anywhere in the new content (`GITHUB_TOKEN` is referenced
  only via `${{ secrets.GITHUB_TOKEN }}`, GitHub's own auto-issued
  per-run token, never a literal value).
- **Not empirically verified** (can't be, without a real GitHub Actions
  run): whether `origin/{base}` actually resolves under
  `actions/checkout@v4`'s `fetch-depth: 0` in a real PR run -- exactly
  the one open item the recommended rollout already flagged, now
  formally still open pending a real trial run after this is ever
  pushed/merged.

**Real-run results, PR #164 (2026-10-16):** pushed and opened against
`master`. `origin/{base}` resolution confirmed working in a real run --
the job correctly classified the PR as PRIVILEGED (it touches
`.github/workflows/lint.yml` itself, matching `^\.github/`) and
correctly evaluated the PR's review state via the real `gh api`/
`GITHUB_TOKEN` call, no crash, no unrelated error. `shellcheck`/
`regression` both passed (458/0, matching the local baseline, after a
small unrelated fix -- see below). `self-dev-approval-gate` itself
failed as designed (zero `APPROVED` reviews), `continue-on-error: true`
confirmed non-blocking (overall workflow conclusion: `success`; `master`'s
own `required_status_checks` confirmed unchanged, still exactly
`["shellcheck", "regression"]` -- `self-dev-approval-gate` was never
added to it, so it cannot block merge regardless of its own result).

**One CI-only defect found and fixed this same pass, unrelated to the
CI Option 2 design itself**: `tests/dev_approval_pre_push_hook_test.sh`
and `tests/serve_dashboard_test.sh` were committed as mode `100644`
instead of `100755` -- `lint.yml` invokes test files directly
(`./tests/...sh`), which needs the executable bit; every local run in
this session used `bash tests/...sh` explicitly, which doesn't, so this
was invisible until the real CI run (`Permission denied`, exit 126).
Fixed (`849aedc`, mode-only change, 0 insertions/deletions), re-verified
both locally and via the next real CI run (`regression`: pass, 4m30s).

**Structural finding: this specific check may be permanently
unsatisfiable on a single-maintainer repository.** `repos/noobdna/WAIO/
collaborators` confirmed exactly one collaborator (`noobdna`), the same
account that authored PR #164 -- GitHub refuses to let a PR's author
submit an `APPROVED` review on their own PR (confirmed: an attempted
self-approval produced zero review record, verified via both REST
`pulls/164/reviews` and GraphQL, independently, twice). There is
structurally no second account that could ever satisfy "a human review
that isn't the PR's own author" in this repository as currently
provisioned. **Operator decision, 2026-10-16: leave it observational
for now** -- no code or policy change made; this was already its exact
configured behavior (`continue-on-error: true`, not in `master`'s
`required_status_checks`), so merging remains unaffected either way.
Revisit only if/when a second collaborator account is ever added, or if
this check's own design is deliberately reconsidered for single-
maintainer use -- neither pursued further without a separate, explicit
decision.

**Still not committed, pushed, or merged** -- this exists only in the
local working tree on this branch, per explicit instruction to stop at
that boundary. The single next action, when authorized, is: commit
this change, push the branch, and open a PR so the observational job
can actually execute once in GitHub's own environment (the one thing
that cannot be verified locally) before ever considering the blocking
flip.

**Superseded v1 review findings (2026-10-16), kept for the record:**

- **BLOCKING PREREQUISITE, not previously flagged: this draft cannot
  work as written, regardless of the open design question above.**
  `security/state/self_dev/` is listed in `.gitignore` (`.gitignore:3`,
  confirmed) and nothing under it is tracked in git (`git ls-files
  security/state/` is empty). A GitHub-hosted runner's checkout of this
  repository therefore NEVER contains any proposal/approval record a
  human created locally with `propose`/`approve` -- `./security/self_dev/dev_approval_gate.sh
  status "$ID"` in the sketch above would read an empty/absent
  `proposals_dir` and return `proposal_not_found` for literally any id,
  every single time, independent of whether a human actually approved
  anything. As drafted, this job cannot ever pass -- not a
  false-positive-rate question the observational trial would surface
  gracefully, a structural gap.
  - **The naive fix is actively unsafe, flagged so it is not tried
    without discussion**: committing the approval record JSON file
    itself into the PR so CI's checkout contains it would let a PR's
    own author simply hand-write a `status: "APPROVED"` record with a
    `change_hash` matching their own diff and commit it -- nothing
    then stops self-approval, since the hash-chain audit log that
    would normally make such a record traceable/tamper-evident also
    only ever lives on the local machine that wrote it, never pushed
    or shared. This would defeat the entire point of the gate.
  - **Viable directions, not decided here**: (a) redesign this specific
    CI check to gate on GitHub's own native, centrally-hosted approval
    primitive (a required reviewer, or an Environment with required
    reviewers) instead of reading this repo's local JSON state --
    sidesteps the distribution problem entirely, but means this CI
    check would no longer be reading the SAME record a human sees via
    `dev_approval_gate.sh status`, two parallel approval records
    instead of one; (b) run this job on a self-hosted runner that has
    real access to the same machine's `security/state/self_dev/` --
    preserves a single source of truth, but self-hosted runners
    executing PR-triggered workflows carry their own well-known risk
    (a PR can modify the workflow file itself; GitHub's own docs warn
    against this for public/fork-based repos -- lower risk here since
    this is not fork-based today, but worth stating plainly); (c) stand
    up a small authenticated service the local `approve` step pushes
    records to and CI queries over HTTPS -- real new infrastructure,
    clearly bigger in scope than "a CI job," not attempted by sketching
    it further here.
  - This finding changes nothing about the recommendation to not
    implement Option 2 without sign-off -- it is now also not
    implementable as literally drafted even with sign-off, until one of
    the directions above (or another) is chosen.
- **Minor, non-blocking, worth validating empirically during any
  future trial rather than blocking on now**: `origin/{base}` (used in
  the `git diff --name-only origin/{base}...HEAD` scope-detection
  step) depends on `actions/checkout@v4`'s default fetch behavior
  actually populating that remote-tracking ref under `fetch-depth: 0`
  -- commonly reliable in practice for this exact "diff against PR
  base" pattern, but not verified against a real GitHub Actions run
  this pass (no workflow was deployed, per this task's own scope).
- **One already-correct, worth confirming explicitly**: the untrusted
  `github.event.pull_request.body` value is passed through a step-level
  `env:` mapping and read back via `os.environ` inside Python, never
  interpolated as `${{ ... }}` literal text inside a `run:` script body
  -- this is precisely the script-injection mitigation GitHub's own
  security guidance recommends for untrusted PR content, correctly
  applied in this draft already.
- **One already-correct side effect, noted as a positive property**:
  `PRIVILEGED_PATH_PATTERNS` (in `dev_approval_lib.py`) already
  includes `^\.github/` -- so a future PR modifying this very CI gate's
  own workflow file would itself classify PRIVILEGED under the same
  rule, once the blocking prerequisite above is resolved and the gate
  is actually active. Self-protecting by construction, not something
  this draft had to add separately.

### 2. Real SND@HOME/Takomachi/lan-dashboard-gateway connectivity check

Candidate commands, now precise (resolved this pass by reading
`lan-dashboard-gateway`'s own source, read-only, no network call made
-- see "LAN Dashboard Gateway" under the read-only inspection section
below for how each fact was confirmed):

```
./dashboard/collect_takomachi_status.sh         # needs Takomachi running (it is not) + a Keychain read for TAKOMACHI_API_KEY
./dashboard/collect_snd_status.sh               # needs SND_HOME_API_URL set (unconfirmed); likely no-ops to "not configured" otherwise
curl --max-time 3 http://127.0.0.1:4500/health         # lan-dashboard-gateway IS running; NO auth token needed (confirmed: this route returns before any auth check); lowest-risk candidate of the three
curl --max-time 3 -H "Authorization: Bearer <LAN_GATEWAY_VIEW_TOKEN>" http://127.0.0.1:4500/view/status   # same gateway; requires a Bearer token from its own LAN_GATEWAY_VIEW_TOKEN env var -- a credential-access step, same category as Takomachi's Keychain read, not attempted
```

Needs explicit sign-off naming exactly which command(s) to run; the
Takomachi path and the gateway's own `/view/status` path each
additionally need separate sign-off for the credential read involved
(Keychain, respectively `LAN_GATEWAY_VIEW_TOKEN`) regardless of the
network-connection decision. `/health` is the only one of the four
that involves no credential at all.

### 3. npm global permission fix

Root cause now found (see "npm auto-update permission error" section
above): `.npm-global/lib/node_modules/@anthropic-ai/claude-code/` is
root-owned inside an otherwise user-owned prefix, from a prior `sudo
npm install -g`. Two remediation options documented there, neither
executed. Needs the operator's choice of option (1, one-time `chown
-R`, sudo required -- or 2, new prefix + reinstall, no sudo but more
disruptive) before either is attempted.

Independent safe work (local implementation, local tests, docs) can
continue in parallel while any of the above await a decision.
