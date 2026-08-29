# orchestrator/ is superseded (informational only, nothing here was changed)

The scripts in this directory (`waio.sh`, `inbox.sh`, `router.sh`, `dispatch.sh`,
`kuro.sh`) were an earlier, standalone prototype of a keyword-based dispatch
layer. They are kept as-is for reference and history — nothing in this
directory has been modified or deleted.

**The canonical dispatch path is now the top-level `../waio.sh` together with
`../workers/registry.conf`.** All workers this prototype knew about
(RESEARCH, ANALYSIS, RPI, ECHO, AI) have been registered there and are
dispatched from the repo root, e.g.:

```
~/WAIO/waio.sh "RESEARCH: ..."
```

Known state of the scripts in this directory, unchanged since before this
migration:

- `router.sh` — hardcoded if/elif keyword routing; same set of workers as
  `../workers/registry.conf` now covers, but not read from any shared config.
- `dispatch.sh` — wraps `router.sh` with job-id logging into `../logs/` and
  `../results/`, using a different naming scheme than the new dispatch path.
- `inbox.sh` — interactive REPL that only echoes input; never actually
  dispatched to a worker.
- `waio.sh` (this directory's own, distinct from the repo-root `waio.sh`) —
  prints a static "Commander: 750 / Worker: 800" banner only.
- `kuro.sh` — has a broken heredoc (syntax error) and does not run. It
  otherwise would SSH to the host in `../workers/800.json` to run a system
  check. Left untouched.

`../jobs/` (SSH-based system/identity checks against 800号機) is a separate,
not-yet-migrated concern — it does not fit the worker request/response
contract used by `registry.conf` and is tracked for a later phase.
