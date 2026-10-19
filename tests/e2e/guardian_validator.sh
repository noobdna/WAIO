#!/bin/bash
set -uo pipefail

# tests/e2e/guardian_validator.sh -- TEST-HARNESS ONLY stand-in for the
# independent Guardian's verification step. It answers one question:
# "is the containment (or the recovery) the bridge claims actually in
# effect?" -- judged by EFFECT through WAIO's public entry point
# (./waio.sh refusing or accepting a probe dispatch), cross-checked
# against the state files, never by trusting the bridge's own report.
#
# Independence, as far as one process on one machine can give it:
#   - does NOT source security/lib.sh or security/guardian.sh, and
#     calls no Guardian/containment/recovery function (static guard in
#     tests/e2e_pipeline_test.sh);
#   - reads WAIO state read-only; writes only its own verdict log under
#     E2E_VALIDATOR_DIR, a directory the bridge never references;
#   - the bridge can only ask it to verify; there is no verb that
#     changes its behaviour.
# Real independence (a different host and user, such as the existing
# Guardian SSH path) is NOT provided here -- see tests/e2e/README.md.
#
# Usage: guardian_validator.sh verify --expect quarantined|released|shutdown|clear --target AGENT
# Exit: 0 CONFIRMED, 1 NOT_CONFIRMED, 2 usage/sandbox error.
# Test hook: E2E_VALIDATOR_HANG=SECONDS makes it stall (timeout scenario).

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT" || exit 2

[ -n "${E2E_SANDBOX:-}" ] && [ -f "$E2E_SANDBOX/.waio-e2e-sandbox" ] || { echo "validator: no e2e sandbox" >&2; exit 2; }
[ -n "${E2E_VALIDATOR_DIR:-}" ] || { echo "validator: E2E_VALIDATOR_DIR unset" >&2; exit 2; }

[ "${1:-}" = "verify" ] || { echo "Usage: $0 verify --expect STATE --target AGENT" >&2; exit 2; }
shift
expect="" target=""
while [ $# -gt 0 ]; do
  case "$1" in
    --expect) expect="${2:-}"; shift 2 ;;
    --target) target="${2:-}"; shift 2 ;;
    *) echo "Usage: $0 verify --expect STATE --target AGENT" >&2; exit 2 ;;
  esac
done
case "$expect" in quarantined|released|shutdown|clear) ;; *) echo "validator: bad --expect" >&2; exit 2 ;; esac
case "$target" in ''|*[!A-Za-z0-9_-]*) echo "validator: bad --target" >&2; exit 2 ;; esac

if [ -n "${E2E_VALIDATOR_HANG:-}" ]; then sleep "$E2E_VALIDATOR_HANG"; fi

probe_text="e2e-validator-probe-$$"
out="$(./waio.sh -w "$target" "$probe_text" 2>&1)"; rc=$?

listed="false"
[ -f "$WAIO_GUARDIAN_QUARANTINE_FILE" ] && grep -Fxq "$target" "$WAIO_GUARDIAN_QUARANTINE_FILE" 2>/dev/null && listed="true"
locked="false"; [ -f "$WAIO_SHUTDOWN_LOCK" ] && locked="true"

verdict="NOT_CONFIRMED"
case "$expect" in
  quarantined) [ "$rc" -ne 0 ] && [[ "$out" == *"quarantined"* ]] && [ "$listed" = "true" ] && verdict="CONFIRMED" ;;
  shutdown)    [ "$rc" -ne 0 ] && [[ "$out" == *"emergency shutdown active"* ]] && [ "$locked" = "true" ] && verdict="CONFIRMED" ;;
  released|clear) [ "$rc" -eq 0 ] && [[ "$out" == *"$probe_text"* ]] && [ "$listed" = "false" ] && [ "$locked" = "false" ] && verdict="CONFIRMED" ;;
esac

ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
printf '{"ts":"%s","expect":"%s","target":"%s","probe_rc":%d,"quarantine_listed":%s,"shutdown_lock":%s,"verdict":"%s"}\n' \
  "$ts" "$expect" "$target" "$rc" "$listed" "$locked" "$verdict" >> "$E2E_VALIDATOR_DIR/verdicts.jsonl"
echo "$verdict"
[ "$verdict" = "CONFIRMED" ]
