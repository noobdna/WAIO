#!/bin/bash
# tests/e2e/lib_env.sh -- sourced (never executed) by the isolated
# end-to-end harness: tests/e2e_pipeline_test.sh, tests/e2e/kill60_bench.sh
# and tests/e2e/demo.sh.
#
# e2e_sandbox_init DIR  -- turns an EMPTY temp dir into a sandbox and
# exports every state/audit/lock path the real pipeline modules, waio.sh,
# security/lib.sh, security/guardian.sh, the RED ALERT approval gate and
# PDC would otherwise resolve to this deployment's real security/state/
# or logs/. Each module already honors these overrides (they are the
# same variables each module's own test suite uses); nothing here
# changes production code paths.
#
# The marker file .waio-e2e-sandbox is what tests/e2e/containment_bridge.sh
# checks before it will act: every path it touches must live under a
# directory carrying that marker.
#
# Also clears the three opt-in side effects trigger_shutdown() has
# (desktop notification, dashboard refresh against the real logs/,
# Guardian mirror) -- WAIO_AUTO_GUARDIAN_NOTIFY is then set back to 1
# deliberately so the isolated Guardian state mirrors an isolated
# shutdown, same as production intends.

e2e_sandbox_init() {
  local d="$1"
  [ -d "$d" ] || { echo "e2e_sandbox_init: $d is not a directory" >&2; return 1; }
  if [ -n "$(ls -A "$d" 2>/dev/null)" ]; then
    echo "e2e_sandbox_init: $d is not empty" >&2; return 1
  fi
  touch "$d/.waio-e2e-sandbox"
  mkdir -p "$d/bin" "$d/fixtures" "$d/state"/{shadow_ai,attack_graph,intelligence,decision_engine,approval,bridge,segments,continuity,continuity_cache,recovery} \
           "$d/logs" "$d/validator"
  chmod 700 "$d/validator"

  export E2E_SANDBOX="$d"
  # waio.sh (also run by the validator) sources $HOME/.waio.env after
  # these exports; an empty sandbox HOME keeps that file from
  # re-pointing anything at real state or enabling notifications.
  mkdir -p "$d/home"
  export HOME="$d/home"
  export E2E_BRIDGE_STATE_DIR="$d/state/bridge"
  # Operator policy-signing key. Lives outside run/ and state/ and is
  # never read by any pipeline module; only e2e_write_policy (the
  # "operator") and the bridge use it.
  mkdir -p "$d/keys"; chmod 700 "$d/keys"
  ( umask 077; python3 -c 'import secrets; print(secrets.token_hex(32))' > "$d/keys/policy.key" )
  export E2E_POLICY_KEY_FILE="$d/keys/policy.key"
  export E2E_VALIDATOR_DIR="$d/validator"

  export SHADOW_AI_STATE_DIR="$d/state/shadow_ai"
  export SHADOW_AI_AUDIT_LOG="$d/logs/shadow-ai-audit.jsonl"
  export SHADOW_AI_SIGNATURES_FILE="$d/fixtures/signatures.conf"
  export SHADOW_AI_ALLOWLIST_FILE="$d/fixtures/allowlist.conf"
  export ATTACK_GRAPH_STATE_DIR="$d/state/attack_graph"
  export ATTACK_GRAPH_AUDIT_LOG="$d/logs/attack-graph-audit.jsonl"
  export INTELLIGENCE_STATE_DIR="$d/state/intelligence"
  export INTELLIGENCE_AUDIT_LOG="$d/logs/intelligence-audit.jsonl"
  export DECISION_ENGINE_STATE_DIR="$d/state/decision_engine"
  export DECISION_ENGINE_AUDIT_LOG="$d/logs/decision-engine-audit.jsonl"
  export CONTAINMENT_APPROVAL_STATE_DIR="$d/state/approval"
  export CONTAINMENT_APPROVAL_AUDIT_LOG="$d/logs/containment-approval-audit.jsonl"
  export CONTAINMENT_APPROVAL_AUDIT_CHECKPOINT="$d/state/approval/.audit_checkpoint"

  export WAIO_SHUTDOWN_LOCK="$d/state/SHUTDOWN.lock"
  export WAIO_AUDIT_LOG="$d/logs/security-audit.jsonl"
  export WAIO_AUDIT_LOG_CHECKPOINT="$d/state/.audit_log_chain_checkpoint"
  export WAIO_AUDIT_INTEGRITY_ALERTS="$d/logs/audit-integrity-alerts.jsonl"
  export WAIO_AUDIT_LOG_LOCK_DIR="$d/state/.audit_log.lock"
  export WAIO_RECOVER_RECONCILE_MARKER="$d/state/.last_reconciled_trigger"
  export WAIO_GUARDIAN_STATE_FILE="$d/state/GUARDIAN_STATE"
  export WAIO_GUARDIAN_QUARANTINE_FILE="$d/state/GUARDIAN_QUARANTINE"
  export WAIO_GUARDIAN_CRITICAL_EVENTS_FILE="$d/state/GUARDIAN_CRITICAL_EVENTS"
  export WAIO_GUARDIAN_STATE_LOCK_DIR="$d/state/.guardian_state.lock"
  export WAIO_ORCHESTRATE_LOG_DIR="$d/logs" WAIO_ORCHESTRATE_RESULTS_DIR="$d/results"

  export SEGMENT_MANAGER_CONF="$d/fixtures/segments.conf"
  export SEGMENT_MANAGER_STATE_DIR="$d/state/segments"
  export SEGMENT_MANAGER_AUDIT_LOG="$d/logs/segment-audit.jsonl"
  export WAIO_CONTINUITY_STATE_DIR="$d/state/continuity"
  export WAIO_CONTINUITY_CACHE_DIR="$d/state/continuity_cache"
  export WAIO_CONTINUITY_STATE_FILE="$d/state/continuity/CONTINUITY_STATE"
  export WAIO_CONTINUITY_SNAPSHOT_FILE="$d/state/continuity/last_known_good.json"
  export WAIO_CONTINUITY_AUDIT_LOG="$d/logs/continuity-audit.jsonl"
  export WAIO_CONTINUITY_SND_SNAPSHOT_FILE="$d/state/continuity/snd_snapshot.json"
  export RECOVERY_ENGINE_STATE_DIR="$d/state/recovery"
  export HEALTH_CHECK_TIMEOUT=1
  export HEALTH_CHECK_RETRIES=1
  export HEALTH_CHECK_RETRY_DELAY=0

  unset WAIO_AUTO_NOTIFY WAIO_AUTO_DASHBOARD_REFRESH WAIO_GUARDIAN_AUTO_QUARANTINE
  export WAIO_AUTO_GUARDIAN_NOTIFY=1

  # Detection telemetry: ps/lsof are shadowed on PATH by fixture
  # scripts (same technique as tests/shadow_ai_monitor_test.sh), so the
  # Shadow AI Monitor never reads this machine's real process table.
  export PATH="$d/bin:$PATH"
}

# e2e_write_detection_fixture DIR SCENARIO -- fixed fixture telemetry.
#   anomaly : one unapproved autonomous agent (CRITICAL signature) that
#             also listens on a known local-LLM port -> two findings,
#             one entity ("rogue-agent").
#   benign  : the same machine with only an allowlisted process
#             (negative control: no finding, no containment).
e2e_write_detection_fixture() {
  local d="$1" scenario="$2"
  cat > "$d/fixtures/signatures.conf" <<'EOF'
process|rogue-agent|ai_agent_framework|CRITICAL|Unapproved autonomous agent (e2e fixture)
port|11434|local_llm_runtime|MEDIUM|Ollama default API port (e2e fixture)
EOF
  echo "process|approved-assistant|reviewed and approved (e2e fixture)" > "$d/fixtures/allowlist.conf"
  case "$scenario" in
    anomaly)
      printf '#!/bin/bash\ncat <<X\n   200     1 e2e      rogue-agent      /opt/rogue-agent/run --loop\n   210     1 e2e      approved-assistant /opt/assistant/run\nX\n' > "$d/bin/ps"
      printf '#!/bin/bash\ncat <<X\nCOMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\nrogue-agent 200 e2e 12u IPv4 0x2 0t0 TCP *:11434 (LISTEN)\nX\n' > "$d/bin/lsof"
      ;;
    benign)
      printf '#!/bin/bash\ncat <<X\n   210     1 e2e      approved-assistant /opt/assistant/run\nX\n' > "$d/bin/ps"
      printf '#!/bin/bash\necho "COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME"\n' > "$d/bin/lsof"
      ;;
    *) echo "unknown scenario $scenario" >&2; return 1 ;;
  esac
  chmod +x "$d/bin/ps" "$d/bin/lsof"
}

# e2e_now -- epoch seconds with microseconds (bash 3.2 has no EPOCHREALTIME).
e2e_now() { perl -MTime::HiRes -e 'printf "%.6f\n", Time::HiRes::time()'; }

# e2e_detect_to_decision DIR [EXTRA_INGEST_ARGS...] -- runs the REAL
# Shadow AI Monitor -> Attack Graph -> Intelligence Layer -> Decision
# Engine chain, each stage consuming only the previous stage's file.
# Writes DIR/run/{shadow_ai.jsonl,attack_graph.json,intelligence.json,decisions.json}.
e2e_detect_to_decision() {
  local d="$1"; shift
  mkdir -p "$d/run"
  ./security/shadow_ai/shadow_ai_monitor.sh scan > "$d/run/shadow_ai.jsonl" 2>>"$d/run/stderr.log" || return 1
  ./security/attack_graph/attack_graph.sh build "$d/run/shadow_ai.jsonl" > "$d/run/attack_graph.json" 2>>"$d/run/stderr.log" || return 1
  ./security/intelligence/intelligence_layer.sh ingest --shadow-ai "$d/run/shadow_ai.jsonl" --attack-graph "$d/run/attack_graph.json" "$@" \
    > "$d/run/intelligence.json" 2>>"$d/run/stderr.log" || return 1
  ./security/decision_engine/decision_engine.sh decide "$d/run/intelligence.json" > "$d/run/decisions.json" 2>>"$d/run/stderr.log" || return 1
}

# e2e_write_policy FILE ENTITY ACTION EXPIRES_AT [MAX_EXECUTIONS] [RULE_ID]
# -- the operator's act of pre-approving one narrow rule: writes a
# single-rule policy signed with E2E_POLICY_KEY_FILE (HMAC-SHA256 over
# the rule's canonical JSON).
e2e_write_policy() {
  python3 - "$@" <<'PYEOF'
import hashlib, hmac, json, os, sys
path, entity, action, expires = sys.argv[1:5]
max_exec = int(sys.argv[5]) if len(sys.argv) > 5 else 1000
rule_id = sys.argv[6] if len(sys.argv) > 6 else "rule-" + hashlib.sha256((entity + action + expires).encode()).hexdigest()[:12]
rule = {"rule_id": rule_id, "entity": entity, "action": action, "approved_by": "e2e-operator (fixture)",
        "reason": "pre-approved narrow e2e rule", "expires_at": expires, "max_executions": max_exec}
key = open(os.environ["E2E_POLICY_KEY_FILE"], "rb").read().strip()
rule["signature"] = "hmac-sha256:" + hmac.new(key, json.dumps(rule, sort_keys=True).encode(), hashlib.sha256).hexdigest()
json.dump({"version": 2, "rules": [rule]}, open(path, "w"))
PYEOF
}
