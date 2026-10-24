#!/bin/bash
set -uo pipefail

# tests/e2e/containment_bridge.sh -- TEST-HARNESS ONLY. Connects a
# Decision Engine RECOMMEND_CONTAINMENT record to a real Guardian
# containment function inside an isolated e2e sandbox, then asks the
# independent validator (tests/e2e/guardian_validator.sh) to confirm
# the effect.
#
# This is NOT production code and is not wired into any production
# path: security/decision_engine/decision_engine.sh deliberately
# "proposes, never disposes", and the RED ALERT approval gate never
# executes anything. Whether WAIO should ever have a production
# executor like this is an explicit, separate human decision (see
# tests/e2e/README.md "Gaps"). This file exists to prove the stages
# compose correctly, and to measure them.
#
# Refuses to run unless EVERY state path it can reach lives inside an
# e2e sandbox (a directory carrying .waio-e2e-sandbox, created by
# tests/e2e/lib_env.sh) -- it can never act on this deployment's real
# security/state/ or logs/.
#
# Authorization -- exactly one of:
#   --approval-id ID  a RED ALERT approval record from the REAL
#                     security/red_alert/containment_approval_gate.sh,
#                     effective_status APPROVED, not past its expires_at,
#                     for this entity, whose stored decision_report_hash
#                     still matches the report on disk (tamper check),
#                     and whose proposed_tool names the action below.
#   --policy FILE     a pre-approved narrow policy: a rule naming this
#                     exact entity, one allowed action, an expires_at in
#                     the future, and an approved_by/reason. No
#                     wildcards.
# Allowed actions (nothing else): quarantine_agent:<REGISTRY_NAME>
# (reversible with security/guardian_release_agent.sh) and
# emergency_shutdown (reversible with security/recover.sh --confirm).
#
# Properties:
#   idempotent  same report+entity+action is executed at most once
#               (marker under E2E_BRIDGE_STATE_DIR/done/); a repeat is a
#               logged no-op.
#   bounded     the action and the validation each run under a hard
#               timeout (E2E_ACTION_TIMEOUT / E2E_VALIDATION_TIMEOUT).
#   fail-closed a quarantine whose post-check fails escalates to
#               emergency_shutdown; a validator that says NOT_CONFIRMED
#               does the same; a validator that is unavailable or
#               times out leaves containment in place and escalates to
#               a human (containment_unverified) -- it never rolls back.
#   audited     every outcome goes through security/lib.sh audit_log()
#               (hash-chained) in the sandbox's own audit log.
#
# Output: one JSON line on stdout. Exit 0 contained+confirmed or
# duplicate, 3 refused (nothing done), 4 contained but unverified,
# 5 escalated to emergency shutdown, 2 usage/sandbox error.

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT" || exit 2

die_usage() { echo "Usage: $0 execute --report FILE --entity ENTITY (--approval-id ID | --policy FILE) [--run-id ID]" >&2; exit 2; }

# --- sandbox guard ---------------------------------------------------
[ -n "${E2E_SANDBOX:-}" ] && [ -f "$E2E_SANDBOX/.waio-e2e-sandbox" ] || { echo "bridge: refusing -- no e2e sandbox" >&2; exit 2; }
sandbox_real="$(cd "$E2E_SANDBOX" && pwd -P)"
for v in E2E_BRIDGE_STATE_DIR WAIO_SHUTDOWN_LOCK WAIO_AUDIT_LOG WAIO_AUDIT_LOG_CHECKPOINT WAIO_AUDIT_LOG_LOCK_DIR \
         WAIO_GUARDIAN_STATE_FILE WAIO_GUARDIAN_QUARANTINE_FILE WAIO_GUARDIAN_CRITICAL_EVENTS_FILE \
         WAIO_RECOVER_RECONCILE_MARKER WAIO_AUDIT_INTEGRITY_ALERTS CONTAINMENT_APPROVAL_STATE_DIR CONTAINMENT_APPROVAL_AUDIT_LOG; do
  val="${!v:-}"
  [ -n "$val" ] || { echo "bridge: refusing -- $v unset" >&2; exit 2; }
  parent="$(cd "$(dirname "$val")" 2>/dev/null && pwd -P)" || { echo "bridge: refusing -- $v parent missing" >&2; exit 2; }
  case "$parent/" in "$sandbox_real"/*) ;; *) echo "bridge: refusing -- $v is outside the sandbox" >&2; exit 2 ;; esac
done

[ "${1:-}" = "execute" ] || die_usage
shift
report="" entity="" approval_id="" policy="" run_id="e2e-$$"
while [ $# -gt 0 ]; do
  case "$1" in
    --report) report="${2:-}"; shift 2 ;;
    --entity) entity="${2:-}"; shift 2 ;;
    --approval-id) approval_id="${2:-}"; shift 2 ;;
    --policy) policy="${2:-}"; shift 2 ;;
    --run-id) run_id="${2:-}"; shift 2 ;;
    *) die_usage ;;
  esac
done
[ -n "$report" ] && [ -n "$entity" ] || die_usage
if [ -n "$approval_id" ] && [ -n "$policy" ]; then die_usage; fi
[ -n "$approval_id" ] || [ -n "$policy" ] || die_usage

if [ -n "$policy" ]; then
  kp="$(cd "$(dirname "${E2E_POLICY_KEY_FILE:-/nonexistent/x}")" 2>/dev/null && pwd -P)" || kp=""
  case "$kp/" in "$sandbox_real"/*) ;; *) echo "bridge: refusing -- E2E_POLICY_KEY_FILE unset or outside the sandbox" >&2; exit 2 ;; esac
fi
ACTION_TIMEOUT="${E2E_ACTION_TIMEOUT:-10}"
VALIDATION_TIMEOUT="${E2E_VALIDATION_TIMEOUT:-10}"
VALIDATOR="${E2E_VALIDATOR:-$REPO_ROOT/tests/e2e/guardian_validator.sh}"
mkdir -p "$E2E_BRIDGE_STATE_DIR/done"

source security/lib.sh

now() { perl -MTime::HiRes -e 'printf "%.6f\n", Time::HiRes::time()'; }
t_start="$(now)"

emit() {  # emit OUTCOME RC ACTION TARGET DETAIL [VERDICT] [T_CONTAINED] [T_VERIFIED]
  python3 - "$1" "$2" "$3" "$4" "$5" "${6:-}" "${7:-}" "${8:-}" "$entity" "$run_id" "$t_start" <<'PYEOF'
import json, sys
outcome, rc, action, target, detail, verdict, t_c, t_v, entity, run_id, t0 = sys.argv[1:12]
def f(x):
    try: return float(x)
    except ValueError: return None
print(json.dumps({"outcome": outcome, "exit": int(rc), "entity": entity, "action": action or None,
                  "target": target or None, "detail": detail, "validator_verdict": verdict or None,
                  "run_id": run_id, "t_start": f(t0), "t_contained": f(t_c), "t_verified": f(t_v)}))
PYEOF
}

refuse() {  # refuse REASON
  audit_log "e2e_bridge_refused" "$run_id" "e2e_bridge" "$entity" "n/a" "refused" "$1"
  emit refused 3 "" "" "$1"
  exit 3
}

# --- 1. decision + authorization (pure checks, nothing executed) ------
auth_err="$E2E_BRIDGE_STATE_DIR/auth.err"
auth="$(python3 - "$report" "$entity" "$approval_id" "$policy" 2>"$auth_err" <<'PYEOF'
import json, os, sys, datetime, hashlib, subprocess
sys.path.insert(0, os.path.join(os.getcwd(), "security", "red_alert"))
import containment_approval_lib as cal

report_file, entity, approval_id, policy_file = sys.argv[1:5]
def out(status, a="", t="", why="", rid=""):
    # \x1f, not a tab: bash `read` collapses runs of whitespace IFS
    # characters, which would shift an empty field into the next one.
    print("\x1f".join([status, a, t, why.replace("\x1f", " ").replace("\n", " "), rid])); sys.exit(0)

try:
    with open(report_file) as f:
        report = json.load(f)
except Exception as e:
    out("REFUSE", why=f"decision report unreadable/malformed: {type(e).__name__}")
decisions = report.get("decisions") if isinstance(report, dict) else None
if not isinstance(decisions, list):
    out("REFUSE", why="decision report has no decisions list")
rec = next((d for d in decisions if isinstance(d, dict) and d.get("entity") == entity), None)
if rec is None:
    out("REFUSE", why="entity not in decision report")
if rec.get("recommended_action") != "RECOMMEND_CONTAINMENT":
    out("REFUSE", why=f"recommended_action is {rec.get('recommended_action')!r}, not RECOMMEND_CONTAINMENT")
lc = rec.get("local_corroboration")
if not (isinstance(lc, dict) and lc.get("present") is True):
    out("REFUSE", why="no trusted local corroboration")

def registry_names():
    names = set()
    with open("workers/registry.conf") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                names.add(line.split("|", 1)[0].upper())
    return names

def parse_action(tok):
    if tok == "emergency_shutdown":
        return "emergency_shutdown", ""
    if isinstance(tok, str) and tok.startswith("quarantine_agent:"):
        agent = tok.split(":", 1)[1].upper()
        if agent in registry_names():
            return "quarantine_agent", agent
        out("REFUSE", why=f"quarantine target {agent!r} is not a registered worker")
    out("REFUSE", why=f"action {tok!r} is not one of the allowed actions")

now = datetime.datetime.now(datetime.timezone.utc)
report_hash = cal.compute_decision_report_hash(report)

if approval_id:
    p = subprocess.run(["./security/red_alert/containment_approval_gate.sh", "status", approval_id],
                       capture_output=True, text=True, timeout=30)
    try:
        st = json.loads(p.stdout.strip().splitlines()[-1])
    except Exception:
        out("REFUSE", why="approval gate status unreadable")
    if not st.get("ok"):
        out("REFUSE", why=f"approval gate: {st.get('error')}")
    r = st.get("record") or {}
    ref = r.get("decision_record_ref") or {}
    scope = r.get("proposed_scope") or {}
    exp = cal.parse_utc_timestamp(r.get("expires_at"))
    if exp is None or cal.is_expired(exp, now):  # first, so the refusal names expiry (the gate also reads it EXPIRED)
        out("REFUSE", why="approval expired")
    if st.get("effective_status") != "APPROVED":
        out("REFUSE", why=f"approval effective_status is {st.get('effective_status')!r}")
    if ref.get("entity") != entity:
        out("REFUSE", why="approval is for a different entity")
    if ref.get("decision_report_hash") != report_hash:
        out("REFUSE", why="decision report changed since approval was requested (hash mismatch)")
    a, t = parse_action(scope.get("proposed_tool"))
    out("OK", a, t, f"approval {approval_id} decided_by={(r.get('decision') or {}).get('decided_by')}")

try:
    with open(policy_file) as f:
        pol = json.load(f)
except Exception as e:
    out("REFUSE", why=f"policy unreadable/malformed: {type(e).__name__}")
rules = pol.get("rules") if isinstance(pol, dict) else None
if not isinstance(rules, list):
    out("REFUSE", why="policy has no rules list")
rule = next((r for r in rules if isinstance(r, dict) and r.get("entity") == entity), None)
if rule is None:
    out("REFUSE", why="no pre-approved policy rule for this exact entity")
for k in ("rule_id", "approved_by", "reason", "expires_at", "action", "max_executions", "signature"):
    if not rule.get(k):
        out("REFUSE", why=f"policy rule missing {k}")

# Authenticity: the rule must be signed with the operator policy key,
# which the detection pipeline never has -- so no detection output (or
# anything else that can only write files) can grant itself authority.
import hmac, stat as _stat
key_path = os.environ.get("E2E_POLICY_KEY_FILE", "")
try:
    st = os.stat(key_path)
except OSError:
    out("REFUSE", why="policy key unavailable")
if not _stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or st.st_mode & 0o077:
    out("REFUSE", why="policy key file must be a 0600 regular file owned by this user")
key = open(key_path, "rb").read().strip()
if len(key) < 32:
    out("REFUSE", why="policy key too short")
unsigned = {k: v for k, v in rule.items() if k != "signature"}
want = "hmac-sha256:" + hmac.new(key, json.dumps(unsigned, sort_keys=True).encode(), hashlib.sha256).hexdigest()
if not hmac.compare_digest(str(rule.get("signature")), want):
    out("REFUSE", why="policy rule signature invalid")

exp = cal.parse_utc_timestamp(rule.get("expires_at"))
if exp is None or cal.is_expired(exp, now):
    out("REFUSE", why="policy rule expired")
a, t = parse_action(rule.get("action"))
if a != "quarantine_agent":
    out("REFUSE", why=f"{a} requires an explicit human approval (RED ALERT gate); a standing policy may only quarantine one agent")
try:
    max_exec = int(rule.get("max_executions"))
except (TypeError, ValueError):
    out("REFUSE", why="max_executions is not an integer")
rid = str(rule.get("rule_id"))
if not rid.replace("-", "").replace("_", "").isalnum():
    out("REFUSE", why="rule_id has unsafe characters")
ledger = os.path.join(os.environ["E2E_BRIDGE_STATE_DIR"], "ledger", rid)
used = int(open(ledger).read().strip() or 0) if os.path.isfile(ledger) else 0
if used >= max_exec:
    out("REFUSE", why=f"policy rule {rid} execution budget exhausted ({used}/{max_exec}) -- replay refused")
out("OK", a, t, f"policy rule {rid} ({used + 1}/{max_exec}) approved_by={rule.get('approved_by')}", rid)
PYEOF
)"
IFS=$'\x1f' read -r a_status action target a_detail rule_id <<< "$auth"
[ "$a_status" = "OK" ] || refuse "${a_detail:-authorization check crashed: $(tail -1 "$auth_err" 2>/dev/null)}"

# --- 2. idempotency ---------------------------------------------------
key="$( { cat "$report"; printf '\n%s|%s|%s' "$entity" "$action" "$target"; } | shasum -a 256 | cut -c1-32)"
marker="$E2E_BRIDGE_STATE_DIR/done/$key"
if [ -f "$marker" ]; then
  audit_log "e2e_bridge_duplicate" "$run_id" "e2e_bridge" "$entity" "n/a" "noop" "$action $target already executed ($(cat "$marker"))"
  emit duplicate 0 "$action" "$target" "already executed by $(cat "$marker")"
  exit 0
fi

# --- 3. execute (bounded) ---------------------------------------------
reason="e2e bridge: $entity RECOMMEND_CONTAINMENT, authorized by $a_detail"
# run_bounded SECONDS CMD... -- runs CMD in its own process group and,
# on timeout, terminates that whole group (so a stalled grandchild
# cannot keep a captured stdout pipe open) and exits 142. A command
# that cannot be executed exits 127, never 0.
run_bounded() {
  perl -e '
    my $t = shift; my $pid = fork(); exit 126 unless defined $pid;
    if ($pid == 0) { setpgrp(0, 0); exec @ARGV or exit 127; }
    $SIG{ALRM} = sub { kill "TERM", -$pid; select(undef, undef, undef, 0.5); kill "KILL", -$pid; waitpid($pid, 0); exit 142 };
    alarm $t; waitpid($pid, 0); alarm 0;
    exit(($? & 127) ? 128 + ($? & 127) : $? >> 8);
  ' "$@"
}
bounded() { run_bounded "$1" bash -c 'source security/lib.sh; "$@"' _ "${@:2}"; }
escalated=""
if [ "$action" = "quarantine_agent" ]; then
  bounded "$ACTION_TIMEOUT" guardian_quarantine_agent "$target" "$reason" "$run_id" >/dev/null 2>&1
  if ! guardian_is_quarantined "$target"; then
    audit_log "e2e_bridge_containment_failed" "$run_id" "e2e_bridge" "$entity" "n/a" "failed" "quarantine of $target did not take effect; escalating to emergency shutdown"
    escalated="quarantine_post_check_failed"
  fi
else
  bounded "$ACTION_TIMEOUT" guardian_request_waio_shutdown "$reason" "$run_id" "e2e_bridge" "$entity" "n/a" >/dev/null 2>&1
fi
if [ -n "$escalated" ]; then
  bounded "$ACTION_TIMEOUT" guardian_request_waio_shutdown "$reason (fail-closed: $escalated)" "$run_id" "e2e_bridge" "$entity" "n/a" >/dev/null 2>&1
fi
if [ "$action" = "emergency_shutdown" ] || [ -n "$escalated" ]; then
  is_shutdown_active || { audit_log "e2e_bridge_containment_failed" "$run_id" "e2e_bridge" "$entity" "n/a" "failed" "emergency shutdown did not take effect"
                          emit containment_failed 5 "$action" "$target" "no containment took effect"; exit 5; }
fi
t_contained="$(now)"
echo "$run_id" > "$marker"
if [ -n "${rule_id:-}" ]; then   # count this execution against the rule's budget
  mkdir -p "$E2E_BRIDGE_STATE_DIR/ledger"
  n="$(cat "$E2E_BRIDGE_STATE_DIR/ledger/$rule_id" 2>/dev/null || echo 0)"
  echo $((n + 1)) > "$E2E_BRIDGE_STATE_DIR/ledger/$rule_id"
fi
audit_log "e2e_bridge_contained" "$run_id" "e2e_bridge" "$entity" "n/a" "contained" "$action ${target:-all} ${escalated:+(escalated: $escalated)}"

# --- 4. independent validation (bounded) ------------------------------
if [ -n "$escalated" ] || [ "$action" = "emergency_shutdown" ]; then expect="shutdown"; probe="${target:-ECHO}"; else expect="quarantined"; probe="$target"; fi
verdict="$(run_bounded "$VALIDATION_TIMEOUT" "$VALIDATOR" verify --expect "$expect" --target "$probe" 2>/dev/null)"; vrc=$?
t_verified="$(now)"
[ "$vrc" -eq 0 ] && [ "$verdict" != "CONFIRMED" ] && vrc=1
case "$vrc" in
  0)
    audit_log "e2e_bridge_verified" "$run_id" "e2e_bridge" "$entity" "n/a" "confirmed" "validator confirmed $expect $probe"
    if [ -n "$escalated" ]; then emit escalated_shutdown 5 "$action" "$target" "$escalated" "$verdict" "$t_contained" "$t_verified"; exit 5; fi
    emit contained 0 "$action" "$target" "$a_detail" "$verdict" "$t_contained" "$t_verified"; exit 0 ;;
  1)
    audit_log "e2e_bridge_not_confirmed" "$run_id" "e2e_bridge" "$entity" "n/a" "not_confirmed" "validator did not confirm $expect $probe; escalating to emergency shutdown"
    bounded "$ACTION_TIMEOUT" guardian_request_waio_shutdown "$reason (fail-closed: validator NOT_CONFIRMED)" "$run_id" "e2e_bridge" "$entity" "n/a" >/dev/null 2>&1
    emit escalated_shutdown 5 "$action" "$target" "validator NOT_CONFIRMED" "$verdict" "$t_contained" "$t_verified"; exit 5 ;;
  *)
    audit_log "e2e_containment_unverified" "$run_id" "e2e_bridge" "$entity" "n/a" "unverified" "validator unavailable or timed out (rc=$vrc); containment left in place, human review required"
    bounded "$ACTION_TIMEOUT" guardian_notify_event "e2e_containment_unverified" "warning" "validator rc=$vrc for $entity" "$run_id" "e2e_bridge" >/dev/null 2>&1
    emit contained_unverified 4 "$action" "$target" "validator unavailable/timeout rc=$vrc; human review required" "" "$t_contained" "$t_verified"; exit 4 ;;
esac
