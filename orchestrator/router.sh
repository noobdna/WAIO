#!/bin/bash
# orchestrator/router.sh -- DISABLED (2026-11-05 integration audit).
#
# This superseded prototype (see DEPRECATED.md) ran ./workers/*.sh
# directly, so every dispatch through it (and through dispatch.sh, which
# wraps it) bypassed the canonical gates in the repo-root waio.sh: the
# emergency-shutdown lock, the Guardian state and the Guardian quarantine
# list. It now refuses instead of dispatching. It deliberately does NOT
# forward to ../waio.sh: its keyword rules differ from registry.conf's,
# so a silent forward would change which worker runs.
#
# The original routing logic is in git history (before this commit).

echo "[WAIO ROUTER] ERROR: orchestrator/router.sh is deprecated and disabled -- it bypassed the shutdown/Guardian/quarantine gates." >&2
echo "[WAIO ROUTER] use the canonical entry point from the repo root: ./waio.sh \"<request>\"  (or ./waio.sh -w <NAME> \"<request>\")" >&2
exit 1
