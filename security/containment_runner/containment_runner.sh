#!/bin/bash
# security/containment_runner/containment_runner.sh -- quarantine-only
# containment runner for Decision Engine RECOMMEND_CONTAINMENT records.
#
# NOT WIRED INTO ANY LAUNCHAGENT OR CRON. Nothing calls this script; an
# operator has to run it, and wiring it into the detection schedule is a
# separate, explicit decision (~/waio-ops/CONTAINMENT_RUNNER_DESIGN.md).
#
# Usage:
#   containment_runner.sh run --report DECISIONS.json [--policy POLICY.json] [--execute] [--run-id ID]
#   (--policy only inside an e2e sandbox; otherwise the fixed policy path)
#
# Default is DRY RUN: every recommendation is authorized and planned
# exactly as for real, every outcome is audited, and nothing is changed.
# Real execution needs BOTH --execute AND WAIO_CONTAINMENT_RUNNER_EXECUTE=1;
# --execute alone is refused (exit 2), so a stray flag can never act.
#
# What it may do: guardian_quarantine_agent for one REGISTERED worker per
# recommendation, and only when a pre-approved policy rule names that
# exact entity in a policy document signed (RSA-SHA256) with the
# operator's PRIVATE key, under a key_id the runner trusts, with a serial
# no lower than any it accepted before, a bounded rule lifetime, and no
# human release of the target since the rule was issued (runner_lib.py).
# The runner only ever reads PUBLIC keys. Policies are signed off this
# path with scripts/containment_policy_sign.py.
# Never emergency_shutdown, never release, never anything else.
#
# Guard rails:
#   kill switch   $STATE_DIR/DISABLED present -> refuse everything (exit 6)
#   overlap lock  one run at a time (security/lib.sh mkdir lock); a second
#                 concurrent run exits 7 without doing anything
#   idempotent    a report/entity/action executed once is a logged no-op
#   budgets       each rule's max_executions, plus a global limit of
#                 WAIO_CONTAINMENT_RUNNER_MAX_PER_HOUR (default 3)
#                 executions in any rolling hour (a detection storm cannot
#                 quarantine every worker)
#   bounded       each quarantine runs under a hard timeout
#                 (WAIO_CONTAINMENT_RUNNER_ACTION_TIMEOUT, default 10 s)
#   verified      after the action the quarantine list is read back; a
#                 miss is reported containment_unverified (exit 4) and is
#                 never retried or rolled back automatically
#   audited       every outcome goes through audit_log() (hash-chained)
#
# Recovery (human only): ./security/guardian_release_agent.sh AGENT --confirm "<reason>"
#
# Output: one JSON line per recommendation on stdout.
# Exit: 0 nothing refused, 3 at least one refused/rate-limited, 4 an
# executed quarantine could not be verified, 2 usage, 6 disabled, 7 busy.

set -uo pipefail
# Fixed system PATH and a private umask: nothing inherited from the caller
# (a fixture or hostile PATH, a permissive umask) shapes what runs or who
# can read the runner's state.
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$SCRIPT_DIR" || exit 2

# Test overrides are honored ONLY inside a marked e2e sandbox
# (tests/e2e/lib_env.sh), and every overridden path must resolve inside
# it. Outside a sandbox the trust anchor (public key), the runner's
# budgets and the Guardian/audit paths come from fixed locations, so a
# caller's environment can neither substitute its own signing key nor
# reset budgets nor point containment at a decoy quarantine list.
# The default key path uses the account's real home (pwd), not $HOME.
in_sandbox=false sandbox_real=""
if [ -n "${E2E_SANDBOX:-}" ] && [ -f "$E2E_SANDBOX/.waio-e2e-sandbox" ]; then
  sandbox_real="$(cd "$E2E_SANDBOX" 2>/dev/null && pwd -P)" && in_sandbox=true
fi
for v in WAIO_CONTAINMENT_RUNNER_STATE_DIR WAIO_CONTAINMENT_POLICY_KEYDIR WAIO_CONTAINMENT_RUNNER_REGISTRY \
         WAIO_CONTAINMENT_RUNNER_MAX_PER_HOUR WAIO_CONTAINMENT_RUNNER_ACTION_TIMEOUT \
         WAIO_GUARDIAN_QUARANTINE_FILE WAIO_GUARDIAN_STATE_FILE WAIO_AUDIT_LOG WAIO_SHUTDOWN_LOCK; do
  [ -n "${!v:-}" ] || continue
  if [ "$in_sandbox" != true ]; then
    echo "containment_runner: refusing -- $v is set outside an e2e sandbox (test overrides are sandbox-only)" >&2
    exit 2
  fi
  case "$v" in *_MAX_PER_HOUR|*_ACTION_TIMEOUT) continue ;; esac
  parent="$(cd "$(dirname "${!v}")" 2>/dev/null && pwd -P)" || parent=""
  case "$parent/" in
    "$sandbox_real"/*) ;;
    *) echo "containment_runner: refusing -- $v points outside the e2e sandbox" >&2; exit 2 ;;
  esac
done
REAL_HOME="$(python3 -c 'import os, pwd; print(pwd.getpwuid(os.getuid()).pw_dir)')" || exit 2

STATE_DIR="${WAIO_CONTAINMENT_RUNNER_STATE_DIR:-$SCRIPT_DIR/security/state/containment_runner}"
# Trusted public keys, one per file: <key_id>.pub.pem (runner_lib.py).
KEY_DIR="${WAIO_CONTAINMENT_POLICY_KEYDIR:-$REAL_HOME/.config/waio/containment-keys}"
# Outside a sandbox the policy is read from this one fixed path only; a
# caller cannot point the runner at a saved copy of an older policy.
FIXED_POLICY="$REAL_HOME/.config/waio/containment-policy.json"
REGISTRY="${WAIO_CONTAINMENT_RUNNER_REGISTRY:-workers/registry.conf}"
MAX_PER_HOUR="${WAIO_CONTAINMENT_RUNNER_MAX_PER_HOUR:-3}"
ACTION_TIMEOUT="${WAIO_CONTAINMENT_RUNNER_ACTION_TIMEOUT:-10}"
case "$MAX_PER_HOUR" in ''|*[!0-9]*) MAX_PER_HOUR=3 ;; esac
case "$ACTION_TIMEOUT" in ''|*[!0-9]*|0) ACTION_TIMEOUT=10 ;; esac

usage() {
  echo "Usage: $0 run --report DECISIONS.json [--policy POLICY.json (sandbox only)] [--execute] [--run-id ID]" >&2
  exit 2
}

[ "${1:-}" = "run" ] || usage
shift
report="" policy="" execute=false run_id="containment-runner-$(date -u +%Y%m%dT%H%M%SZ)-$$"
while [ $# -gt 0 ]; do
  case "$1" in
    --report) [ $# -ge 2 ] || usage; report="$2"; shift 2 ;;
    --policy) [ $# -ge 2 ] || usage; policy="$2"; shift 2 ;;
    --execute) execute=true; shift ;;
    --run-id) [ $# -ge 2 ] || usage; run_id="$2"; shift 2 ;;
    *) usage ;;
  esac
done
[ -n "$report" ] || usage
if [ -n "$policy" ] && [ "$in_sandbox" != true ]; then
  echo "containment_runner: refusing -- --policy is honored only inside an e2e sandbox; the policy is read from $FIXED_POLICY" >&2
  exit 2
fi
[ -n "$policy" ] || policy="$FIXED_POLICY"
case "$run_id" in *[!A-Za-z0-9._-]*|'') echo "containment_runner: unsafe --run-id" >&2; exit 2 ;; esac

mode="dry_run"
if [ "$execute" = true ]; then
  if [ "${WAIO_CONTAINMENT_RUNNER_EXECUTE:-}" != "1" ]; then
    echo "containment_runner: --execute refused: WAIO_CONTAINMENT_RUNNER_EXECUTE=1 is not set (dry run is the default)" >&2
    exit 2
  fi
  mode="execute"
fi

source security/lib.sh

mkdir -p "$STATE_DIR/done" "$STATE_DIR/ledger" 2>/dev/null || { echo "containment_runner: cannot create $STATE_DIR" >&2; exit 2; }

if [ -e "$STATE_DIR/DISABLED" ]; then
  audit_log "containment_runner_disabled" "$run_id" "containment_runner" "n/a" "n/a" "refused" "kill switch $STATE_DIR/DISABLED present; nothing evaluated"
  echo '{"outcome":"disabled","detail":"kill switch present"}'
  exit 6
fi

LOCK_DIR="$STATE_DIR/.runner.lock"
if ! _waio_mkdir_lock_acquire "$LOCK_DIR" 0; then
  audit_log "containment_runner_busy" "$run_id" "containment_runner" "n/a" "n/a" "skipped" "another runner holds $LOCK_DIR"
  echo '{"outcome":"busy","detail":"another run in progress"}'
  exit 7
fi
trap '_waio_mkdir_lock_release "$LOCK_DIR"' EXIT

emit() {  # emit OUTCOME ENTITY ACTION TARGET DETAIL
  python3 -c 'import json, sys
o, e, a, t, d, m, r = sys.argv[1:8]
print(json.dumps({"outcome": o, "mode": m, "entity": e or None, "action": a or None, "target": t or None, "detail": d, "run_id": r}, ensure_ascii=False))' \
    "$1" "$2" "$3" "$4" "$5" "$mode" "$run_id"
}

plan_err="$STATE_DIR/.plan.err.$$"
plan_out="$(python3 security/containment_runner/runner_lib.py "$report" "$policy" "$KEY_DIR" "$STATE_DIR" "$REGISTRY" "$SECURITY_AUDIT_LOG" "$MAX_PER_HOUR" 2>"$plan_err")"
plan_rc=$?
if [ "$plan_rc" -ne 0 ]; then
  detail="authorization check crashed: $(tail -1 "$plan_err" 2>/dev/null)"
  rm -f "$plan_err"
  audit_log "containment_runner_refused" "$run_id" "containment_runner" "n/a" "n/a" "refused" "$detail"
  emit refused "" "" "" "$detail"
  exit 3
fi
rm -f "$plan_err"

rc=0
while IFS= read -r line; do
  [ -n "$line" ] || continue
  fields="$(python3 -c 'import json, sys
d = json.loads(sys.argv[1])
print("\x1f".join(str(d.get(k) or "").replace("\x1f", " ").replace("\n", " ") for k in ("status", "entity", "action", "target", "rule_id", "key", "why")))' "$line")"
  IFS=$'\x1f' read -r status entity action target rule_id key why <<< "$fields"
  case "$status" in
    SERIAL)
      # Anti-rollback: remember the highest policy serial accepted (atomic
      # rename, under the runner lock). runner_lib refuses any lower one.
      serial="$(python3 -c 'import json, sys; print(int(json.loads(sys.argv[1])["serial"]))' "$line")" || serial=""
      case "$serial" in ''|*[!0-9]*) ;; *)
        old=0; [ -f "$STATE_DIR/policy_serial" ] && old="$(cat "$STATE_DIR/policy_serial" 2>/dev/null)"
        case "$old" in ''|*[!0-9]*) old=0 ;; esac
        if [ "$serial" -gt "$old" ]; then
          printf '%s\n' "$serial" > "$STATE_DIR/policy_serial.tmp.$$" && mv -f "$STATE_DIR/policy_serial.tmp.$$" "$STATE_DIR/policy_serial"
        fi ;;
      esac
      continue ;;
    PLAN) ;;
    DUPLICATE)
      audit_log "containment_runner_duplicate" "$run_id" "containment_runner" "${entity:-n/a}" "n/a" "noop" "$why"
      emit duplicate "$entity" "$action" "$target" "$why"
      continue ;;
    RATE_LIMITED)
      audit_log "containment_runner_rate_limited" "$run_id" "containment_runner" "${entity:-n/a}" "n/a" "refused" "$why"
      emit rate_limited "$entity" "$action" "$target" "$why"
      rc=3; continue ;;
    *)
      audit_log "containment_runner_refused" "$run_id" "containment_runner" "${entity:-n/a}" "n/a" "refused" "$why"
      emit refused "$entity" "$action" "$target" "$why"
      rc=3; continue ;;
  esac

  if [ "$mode" = "dry_run" ]; then
    audit_log "containment_runner_dry_run" "$run_id" "containment_runner" "$entity" "n/a" "planned" "would quarantine $target ($why)"
    emit planned "$entity" "$action" "$target" "dry run: would quarantine $target ($why)"
    continue
  fi

  reason="containment_runner: $entity per $why"
  # Hard deadline: the action runs as a child; at the deadline it gets
  # TERM and the wrapper exits 124.
  perl -e 'my $t = shift; my $pid = fork; defined $pid or exit 125;
           if (!$pid) { exec @ARGV; exit 127 }
           $SIG{ALRM} = sub { kill "TERM", $pid; waitpid $pid, 0; exit 124 };
           alarm $t; waitpid $pid, 0; exit($? >> 8)' "$ACTION_TIMEOUT" \
    bash -c 'source security/lib.sh && guardian_quarantine_agent "$1" "$2" "$3"' _ "$target" "$reason" "$run_id" >/dev/null 2>&1
  action_rc=$?
  # Count the attempt against both budgets whatever happened: a run that
  # times out must not get a free retry on the next tick.
  date +%s >> "$STATE_DIR/executions.log"
  used=0; [ -f "$STATE_DIR/ledger/$rule_id" ] && used="$(cat "$STATE_DIR/ledger/$rule_id" 2>/dev/null)"
  case "$used" in ''|*[!0-9]*) used=0 ;; esac
  printf '%s\n' "$((used + 1))" > "$STATE_DIR/ledger/$rule_id"

  if guardian_is_quarantined "$target"; then
    printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$run_id" > "$STATE_DIR/done/$key"
    audit_log "containment_runner_contained" "$run_id" "containment_runner" "$entity" "n/a" "contained" "quarantined $target ($why); release: ./security/guardian_release_agent.sh $target --confirm \"<reason>\""
    emit contained "$entity" "$action" "$target" "quarantined $target; release with ./security/guardian_release_agent.sh $target --confirm \"<reason>\""
  else
    audit_log "containment_runner_unverified" "$run_id" "containment_runner" "$entity" "n/a" "unverified" "quarantine of $target not visible after the action (rc=$action_rc); needs a human"
    emit unverified "$entity" "$action" "$target" "quarantine of $target not visible after the action (rc=$action_rc); needs a human"
    [ "$rc" -eq 0 ] && rc=4
    [ "$rc" -eq 3 ] && rc=4
  fi
done <<< "$plan_out"

exit "$rc"
