#!/bin/bash
set -uo pipefail

# tests/e2e/demo.sh -- narrated, isolated end-to-end demonstration:
# detect -> evidence -> decide -> human approval (real RED ALERT gate)
# -> contain -> independent confirmation -> human recovery -> confirmed.
# Everything runs in a throwaway sandbox under $TMPDIR; nothing here
# touches this deployment's real state, services, network or Guardian.
#
#   ./tests/e2e/demo.sh            run and clean up
#   ./tests/e2e/demo.sh --keep     keep the sandbox for inspection

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT" || exit 2
KEEP=0; [ "${1:-}" = "--keep" ] && KEEP=1

# shellcheck source=tests/e2e/lib_env.sh
source tests/e2e/lib_env.sh
D="$(mktemp -d "${TMPDIR:-/tmp}/waio-e2e-demo.XXXXXX")"
[ "$KEEP" = "1" ] || trap 'rm -rf "$D"' EXIT
e2e_sandbox_init "$D" && e2e_write_detection_fixture "$D" anomaly || exit 1

step() { printf '\n== %s\n' "$*"; }
field() { python3 -c 'import json,sys; d=json.loads(sys.argv[1]); print(d.get(sys.argv[2]))' "$1" "$2"; }

cat > "$D/fixtures/global_patrol.json" <<'EOF'
{"new_incidents": [{"id": "rogue-agent", "source": "e2e_fixture", "source_url": "https://example.invalid/e2e", "country": "JP", "incident_type": "ai_agent_abuse", "attack_pattern": "autonomous_agent_exfiltration", "confidence_level": "HIGH", "published_at": "2026-10-18T00:00:00Z"}]}
EOF

echo "WAIO isolated end-to-end demo -- sandbox: $D"
T0="$(e2e_now)"

step "1. Detect + evidence + decide (Shadow AI -> Attack Graph -> Intelligence -> Decision Engine)"
e2e_detect_to_decision "$D" --global-patrol-report "$D/fixtures/global_patrol.json" || { echo "pipeline failed"; exit 1; }
python3 -c 'import json,sys
for d in json.load(open(sys.argv[1]))["decisions"]:
    print("   entity=%s risk=%s action=%s sources=%s local_corroboration=%s" % (d["entity"], d["risk"], d["recommended_action"], d["source_modules"], d["local_corroboration"]["present"]))' "$D/run/decisions.json"

step "2. Request human approval (security/red_alert/containment_approval_gate.sh)"
REQ="$(./security/red_alert/containment_approval_gate.sh request "$D/run/decisions.json" rogue-agent demo-analyst \
  --target-type agent --target-id ECHO --proposed-tool "quarantine_agent:ECHO" --rollback-tool "security/guardian_release_agent.sh ECHO --confirm" 2>/dev/null)"
AID="$(field "$REQ" approval_id)"
echo "   approval $AID: $(field "$REQ" effective_status)"
echo "   bridge before approval: $(field "$(./tests/e2e/containment_bridge.sh execute --report "$D/run/decisions.json" --entity rogue-agent --approval-id "$AID")" detail)"

step "3. A human approves (fixture identity -- the gate records the claim, it does not authenticate it)"
./security/red_alert/containment_approval_gate.sh approve "$AID" "demo-approver (fixture human)" "reviewed demo evidence: CRITICAL unapproved agent, locally corroborated" >/dev/null 2>&1
echo "   approval $AID: $(field "$(./security/red_alert/containment_approval_gate.sh status "$AID")" effective_status)"
T_APPROVED="$(e2e_now)"

step "4. Contain (Guardian quarantine of ECHO) + independent confirmation"
OUT="$(./tests/e2e/containment_bridge.sh execute --report "$D/run/decisions.json" --entity rogue-agent --approval-id "$AID" --run-id demo)"
echo "   outcome=$(field "$OUT" outcome) action=$(field "$OUT" action) target=$(field "$OUT" target) validator=$(field "$OUT" validator_verdict)"
echo "   ./waio.sh -w ECHO now says: $(./waio.sh -w ECHO "demo probe" 2>&1 | head -1)"
python3 -c 'import json,sys; r=json.loads(sys.argv[1]); print("   approval->contained %.2fs, contained->confirmed %.2fs" % (r["t_contained"] - float(sys.argv[2]), r["t_verified"] - r["t_contained"]))' "$OUT" "$T_APPROVED"

step "5. Human recovery (security/guardian_release_agent.sh) + independent confirmation"
./security/guardian_release_agent.sh ECHO --confirm "demo: investigated fixture rogue-agent, ECHO verified safe to release" >/dev/null 2>&1
echo "   validator: $(./tests/e2e/guardian_validator.sh verify --expect released --target ECHO)"
echo "   ./waio.sh -w ECHO now says: $(./waio.sh -w ECHO "demo probe after release" 2>&1 | tail -1)"

step "6. Audit trail (hash-chained, sandbox-local)"
bash -c 'source security/lib.sh; echo "   integrity: $(verify_audit_log_integrity)"'
grep -o '"event_type": "[a-z0-9_]*"' "$WAIO_AUDIT_LOG" | sed 's/"event_type": /   /'
python3 -c "import sys; print(f'\n   total demo wall time {float(sys.argv[2])-float(sys.argv[1]):.2f}s (includes scripted approval)')" "$T0" "$(e2e_now)"
[ "$KEEP" = "1" ] && echo "   sandbox kept: $D"
exit 0
