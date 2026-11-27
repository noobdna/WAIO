#!/bin/bash
set -uo pipefail

# tests/dashboard_identity_ui_test.sh -- regression suite for the WAIO identity
# DATA layer (version / active node / human approval), on top of the
# Blue Guardian layout (#236):
#   [C*] dashboard/collect_status.sh writes the additive "identity" key
#        (fixture-isolated exactly like collect_status_guardian_test.sh --
#        no real security/state/ file or audit log is read or written)
#   [S*] dashboard/serve_dashboard.py's identity_banner() startup line
#   [I*] dashboard/index.html topbar identity data (delegated to dashboard_identity_ui_check.mjs)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"

PASS=0; FAIL=0; FAILURES=()
assert_eq() {
  local label="$1" expected="$2" actual="$3"
  if [ "$expected" = "$actual" ]; then
    PASS=$((PASS + 1)); echo "  PASS: $label"
  else
    FAIL=$((FAIL + 1)); FAILURES+=("$label (expected='$expected' actual='$actual')")
    echo "  FAIL: $label (expected='$expected' actual='$actual')"
  fi
}

STATUS_PATH="logs/waio-status-latest.json"
status_get() {
  python3 -c "
import json
node = json.load(open('$STATUS_PATH'))
for part in '$1'.split('.'):
    node = node[part]
print(node if isinstance(node, str) else json.dumps(node))
" 2>/dev/null
}

FIXTURE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/waio-identity-test.XXXXXX")"
trap 'rm -rf "$FIXTURE_DIR"' EXIT
export WAIO_GUARDIAN_STATE_FILE="$FIXTURE_DIR/GUARDIAN_STATE"
export WAIO_GUARDIAN_QUARANTINE_FILE="$FIXTURE_DIR/GUARDIAN_QUARANTINE"
export WAIO_GUARDIAN_CRITICAL_EVENTS_FILE="$FIXTURE_DIR/GUARDIAN_CRITICAL_EVENTS"
export WAIO_SHUTDOWN_LOCK="$FIXTURE_DIR/SHUTDOWN.lock"
export WAIO_AUDIT_LOG="$FIXTURE_DIR/audit.jsonl"

echo "=== WAIO identity data (version / node / human approval) ==="

echo "[C1] collector writes identity with explicit WAIO_VERSION / WAIO_NODE_ID"
WAIO_VERSION="v9.9.9-test" WAIO_NODE_ID="node750" ./dashboard/collect_status.sh >/dev/null
assert_eq "C1 product" "WAIO" "$(status_get identity.product)"
assert_eq "C1 full_name" "World AI Orchestrator" "$(status_get identity.full_name)"
assert_eq "C1 role" "Governance & Security Control Plane" "$(status_get identity.role)"
assert_eq "C1 plane" "governance" "$(status_get identity.plane)"
assert_eq "C1 theme" "blue" "$(status_get identity.theme)"
assert_eq "C1 version" "v9.9.9-test" "$(status_get identity.version)"
assert_eq "C1 node" "node750" "$(status_get identity.node)"
assert_eq "C1 counterpart" "TAKOMACHI" "$(status_get identity.counterpart.product)"

echo "[C2] hostile WAIO_VERSION / WAIO_NODE_ID are sanitised to 'unknown'"
WAIO_VERSION='<script>x</script>' WAIO_NODE_ID='a b;rm -rf' ./dashboard/collect_status.sh >/dev/null
assert_eq "C2 version sanitised" "unknown" "$(status_get identity.version)"
assert_eq "C2 node sanitised" "unknown" "$(status_get identity.node)"

echo "[C3] defaults: git describe + hostname -s (non-empty, well-formed)"
env -u WAIO_VERSION -u WAIO_NODE_ID ./dashboard/collect_status.sh >/dev/null
v="$(status_get identity.version)"; n="$(status_get identity.node)"
assert_eq "C3 version well-formed" "ok" "$(printf '%s' "$v" | grep -Eq '^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$' && echo ok)"
assert_eq "C3 node well-formed" "ok" "$(printf '%s' "$n" | grep -Eq '^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$' && echo ok)"

echo "[C4] pre-existing keys unchanged"
assert_eq "C4 waio_status present" "NORMAL" "$(status_get waio_status)"
assert_eq "C4 guardian_control_plane.state present" "NORMAL" "$(status_get guardian_control_plane.state)"

echo "[S1] serve_dashboard.py identity_banner()"
banner="$(cd dashboard && WAIO_VERSION=v9.9.9-test WAIO_NODE_ID=node750 python3 -c 'import serve_dashboard as s; print(s.identity_banner())')"
assert_eq "S1 banner" "[WAIO] WAIO (World AI Orchestrator) -- Governance & Security Control Plane -- version v9.9.9-test -- node node750" "$banner"
banner="$(cd dashboard && WAIO_VERSION='$(id)' WAIO_NODE_ID='x y' python3 -c 'import serve_dashboard as s; print(s.identity_banner())')"
assert_eq "S1 banner sanitised" "[WAIO] WAIO (World AI Orchestrator) -- Governance & Security Control Plane -- version unknown -- node unknown" "$banner"

echo "[I] dashboard/index.html topbar identity data"
if command -v node >/dev/null 2>&1; then
  if node "$SCRIPT_DIR/tests/dashboard_identity_ui_check.mjs"; then PASS=$((PASS + 1)); else FAIL=$((FAIL + 1)); FAILURES+=("dashboard_identity_ui_check.mjs"); fi
else
  echo "  SKIP: node not on PATH"
fi

echo
echo "=== Results: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
  echo "Failures:"; for f in "${FAILURES[@]}"; do echo "  - $f"; done
  exit 1
fi
exit 0
