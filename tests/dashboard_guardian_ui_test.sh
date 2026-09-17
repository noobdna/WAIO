#!/bin/bash
set -uo pipefail

# tests/dashboard_guardian_ui_test.sh -- regression suite for Phase 63
# (Dashboard UI for the DuCoPA Guardian Control Plane):
# dashboard/index.html's new "DuCoPA Guardian Control Plane" panel and
# its renderStatus() JS logic.
#
# dashboard/index.html has no prior automated test coverage anywhere in
# this repo (it is a "display layer only" static page -- see its own
# footer note); this is the first. The actual checks live in the
# companion tests/dashboard_guardian_ui_check.mjs, which extracts and
# executes the page's own real inline <script> under a minimal DOM stub
# (see that file's own header for why: exercising the real shipped code
# instead of a second, separately-written implementation of the same
# logic). This wrapper only locates node and reports its exit code, same
# split as every other *_test.sh in this repo that shells out to a real
# entry point.
#
# Requires node (present on this repo's own dev machine and on
# GitHub Actions' ubuntu-latest runners by default). SKIPS -- not fails
# -- if node is not on PATH, matching this repo's own LAN-reachability
# skip convention for a missing external dependency: documented, not
# silent, and never a false failure purely because of the local
# environment.
#
# Touches no security/state/ file and no real audit log -- the check
# only reads dashboard/index.html and feeds it synthetic in-memory JSON.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"

echo "=== Dashboard: DuCoPA Guardian Control Plane UI panel (Phase 63) ==="

if ! command -v node >/dev/null 2>&1; then
  echo "[DASHBOARD GUARDIAN UI TEST] SKIP: node not found on PATH -- cannot execute dashboard/index.html's inline script for this check."
  exit 0
fi

node "$SCRIPT_DIR/tests/dashboard_guardian_ui_check.mjs"
exit $?
