#!/bin/bash
set -uo pipefail

# tests/e2e/kill60_bench.sh -- repeatable detection-to-containment
# latency measurement for the 60-second target ("Kill60Sec"), on the
# isolated e2e harness (tests/e2e/lib_env.sh). Each sample is a fresh
# sandbox and runs the REAL pipeline stages:
#
#   t0  before the Shadow AI scan starts (fixture ps/lsof telemetry)
#   t1  Decision Engine report written (detection + evidence + decision)
#   t2  containment in effect (bridge post-check passed)
#   t3  independent validator CONFIRMED the effect via ./waio.sh
#
# Latency = t3 - t0. Authorization is a pre-approved policy rule, so no
# human wait is included -- a human-approved path (RED ALERT gate) adds
# however long the approver takes and is NOT measured here.
#
# Usage: kill60_bench.sh [-n SAMPLES] [-a quarantine|shutdown] [--no-network | --real-telemetry] [-o OUT.json]
#   --real-telemetry  the Shadow AI scan reads THIS machine's real `ps` and
#                 `lsof` (read-only) instead of fixture output; the anomaly
#                 is a test-owned dummy process named rogue-agent (a copy of
#                 `sleep`), started per sample and stopped by its own PID.
#                 Containment still only ever happens inside the sandbox;
#                 only timings are recorded, never process data.
#   --no-network  run every sample inside an OS sandbox that denies all
#                 networking (macOS sandbox-exec), to show the path has
#                 no network dependency.
# Prints a JSON summary; exit 0 if every sample was CONFIRMED and the
# maximum was under 60 s, 1 otherwise.

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT" || exit 2

N=20 ACTION=quarantine NONET=0 REALTEL=0 OUTFILE=""
while [ $# -gt 0 ]; do
  case "$1" in
    -n) N="$2"; shift 2 ;;
    -a) ACTION="$2"; shift 2 ;;
    --no-network) NONET=1; shift ;;
    --real-telemetry) REALTEL=1; shift ;;
    -o) OUTFILE="$2"; shift 2 ;;
    *) echo "Usage: $0 [-n SAMPLES] [-a quarantine|shutdown] [--no-network | --real-telemetry] [-o OUT.json]" >&2; exit 2 ;;
  esac
done
case "$ACTION" in quarantine) POLICY_ACTION="quarantine_agent:ECHO" ;; shutdown) POLICY_ACTION="emergency_shutdown" ;; *) exit 2 ;; esac
case "$N" in ''|*[!0-9]*) exit 2 ;; esac

ROOT="$(mktemp -d "${TMPDIR:-/tmp}/waio-kill60.XXXXXX")"
trap 'rm -rf "${ROOT:?}"' EXIT
SAMPLES="$ROOT/samples.jsonl"; : > "$SAMPLES"

one_sample() {  # one_sample INDEX -> appends one JSON line to $SAMPLES
  local d="$ROOT/s$1"
  mkdir -p "$d"
  # shellcheck source=tests/e2e/lib_env.sh
  source tests/e2e/lib_env.sh
  e2e_sandbox_init "$d" && e2e_write_detection_fixture "$d" anomaly || return 1
  local exp t0 t1 out rogue_pid="" entity="rogue-agent"
  if [ "${REALTEL:-0}" = "1" ]; then
    rm -f "${d:?}/bin/ps" "${d:?}/bin/lsof"     # use the real, read-only ps/lsof
    mkdir -p "$d/rogue"; cp "$(command -v sleep)" "$d/rogue/rogue-agent"
    "$d/rogue/rogue-agent" 300 & rogue_pid=$!
    for _ in $(seq 50); do ps -p "$rogue_pid" -o args= 2>/dev/null | grep -q rogue-agent && break; sleep 0.05; done
    # shadow_ai_monitor.sh names a process by its argv[0] basename (#171),
    # so the scan sees "rogue-agent", not ps's 16-character truncated
    # `comm` path. The operator pre-approves that name before timing
    # starts; the default entity above already is it.
  fi
  exp="$(python3 -c 'import datetime; print((datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"))')"
  local auth=(--policy "$d/fixtures/policy.json") extra=() ta0=0 ta1=0 aid
  if [ "$POLICY_ACTION" = "emergency_shutdown" ]; then
    # A standing policy may not authorize a shutdown: it goes through the
    # real RED ALERT gate with a scripted (fixture) human approval, whose
    # duration is reported separately and excluded from "automated".
    printf '{"new_incidents": [{"id": "rogue-agent", "source": "e2e_fixture", "source_url": "https://example.invalid/e2e", "country": "JP", "incident_type": "ai_agent_abuse", "attack_pattern": "autonomous_agent_exfiltration", "confidence_level": "HIGH", "published_at": "2026-10-18T00:00:00Z"}]}\n' > "$d/fixtures/global_patrol.json"
    extra=(--global-patrol-report "$d/fixtures/global_patrol.json")
  else
    e2e_write_policy "$d/fixtures/policy.json" "$entity" "$POLICY_ACTION" "$exp"
  fi
  t0="$(e2e_now)"
  e2e_detect_to_decision "$d" "${extra[@]+"${extra[@]}"}" || { echo "{\"i\": $1, \"ok\": false, \"stage\": \"detect_to_decision\"}" >> "$SAMPLES"; return 0; }
  t1="$(e2e_now)"
  if [ "$POLICY_ACTION" = "emergency_shutdown" ]; then
    ta0="$(e2e_now)"
    aid="$(./security/red_alert/containment_approval_gate.sh request "$d/run/decisions.json" rogue-agent kill60-bench --target-type waio --target-id all --proposed-tool emergency_shutdown --rollback-tool "security/recover.sh --confirm" 2>/dev/null | python3 -c 'import json,sys; print(json.load(sys.stdin).get("approval_id",""))')"
    ./security/red_alert/containment_approval_gate.sh approve "$aid" "kill60-bench approver (fixture human)" "scripted benchmark approval of fixture evidence" >/dev/null 2>&1
    ta1="$(e2e_now)"
    auth=(--approval-id "$aid")
  fi
  out="$(./tests/e2e/containment_bridge.sh execute --report "$d/run/decisions.json" --entity "$entity" "${auth[@]}" --run-id "kill60-$1")"
  python3 - "$1" "$t0" "$t1" "$out" "$ta0" "$ta1" >> "$SAMPLES" <<'PYEOF'
import json, sys
i, t0, t1, out = int(sys.argv[1]), float(sys.argv[2]), float(sys.argv[3]), sys.argv[4]
approval = float(sys.argv[6]) - float(sys.argv[5])
try:
    r = json.loads(out)
except Exception:
    print(json.dumps({"i": i, "ok": False, "stage": "bridge_output"})); sys.exit()
ok = r.get("outcome") == "contained" and r.get("validator_verdict") == "CONFIRMED"
s = {"i": i, "ok": ok, "outcome": r.get("outcome")}
if ok:
    s.update(detect_to_decision=t1 - t0, approval=approval,
             decision_to_contained=r["t_contained"] - t1 - approval,
             contained_to_verified=r["t_verified"] - r["t_contained"],
             total=r["t_verified"] - t0, automated=r["t_verified"] - t0 - approval)
print(json.dumps(s))
PYEOF
  if [ -n "$rogue_pid" ]; then kill "$rogue_pid" 2>/dev/null; wait "$rogue_pid" 2>/dev/null; fi
  rm -rf "${d:?}"
}

if [ "$NONET" = "1" ] && [ "$REALTEL" = "1" ]; then echo "--no-network and --real-telemetry are exclusive" >&2; exit 2; fi
if [ "$REALTEL" = "1" ] && [ "$ACTION" != "quarantine" ]; then echo "--real-telemetry supports -a quarantine only" >&2; exit 2; fi
if [ "$NONET" = "1" ]; then
  command -v sandbox-exec >/dev/null 2>&1 || { echo "--no-network needs sandbox-exec (macOS)" >&2; exit 2; }
  printf '(version 1)\n(allow default)\n(deny network*)\n' > "$ROOT/nonet.sb"
fi

for i in $(seq 1 "$N"); do
  if [ "$NONET" = "1" ]; then
    sandbox-exec -f "$ROOT/nonet.sb" bash -c 'ROOT="$1"; SAMPLES="$2"; POLICY_ACTION="$3"; '"$(declare -f one_sample)"'; one_sample "$4"' _ "$ROOT" "$SAMPLES" "$POLICY_ACTION" "$i"
  else
    one_sample "$i"
  fi
done

python3 - "$SAMPLES" "$N" "$ACTION" "$NONET" "$OUTFILE" "$REALTEL" <<'PYEOF'
import json, sys, platform, statistics, subprocess, datetime
path, n, action, nonet, outfile = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4] == "1", sys.argv[5]
realtel = sys.argv[6] == "1"
rows = [json.loads(l) for l in open(path) if l.strip()]
ok = [r for r in rows if r.get("ok")]
def pct(vals, p):  # nearest-rank percentile
    v = sorted(vals); k = max(1, -(-p * len(v) // 100)); return v[int(k) - 1]
def stats(key):
    v = [r[key] for r in ok]
    if not v: return None
    return {"median": round(statistics.median(v), 3), "p95": round(pct(v, 95), 3), "max": round(max(v), 3),
            "min": round(min(v), 3), "mean": round(statistics.mean(v), 3)}
summary = {
    "measured_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "samples_requested": n, "samples_completed": len(rows), "samples_confirmed": len(ok),
    "failures": len(rows) - len(ok) + (n - len(rows)),
    "seconds_total": stats("total"),
    "seconds_automated_excluding_approval": stats("automated"),
    "seconds_by_stage": {k: stats(k) for k in ("detect_to_decision", "approval", "decision_to_contained", "contained_to_verified")},
    "target_seconds": 60,
    "all_under_target": bool(ok) and len(ok) == n and max(r["automated"] for r in ok) < 60,
    "conditions": {
        "containment_action": action,
        "authorization": ("RED ALERT gate, scripted fixture approval (timed separately as approval)" if action == "shutdown"
                          else "signed pre-approved policy rule (no human wait)"),
        "telemetry": ("REAL ps/lsof of this machine (read-only) + one test-owned dummy process matching a CRITICAL signature"
                      if realtel else "fixture ps/lsof (Shadow AI Monitor), one CRITICAL entity"),
        "network_denied_by_os_sandbox": nonet,
        "isolation": "fresh temp sandbox per sample; real pipeline modules; validator probes ./waio.sh",
        "host": platform.node().split(".")[0], "os": platform.platform(), "python": platform.python_version(),
        "bash": subprocess.run(["bash", "--version"], capture_output=True, text=True).stdout.splitlines()[0],
    },
}
text = json.dumps(summary, indent=2)
print(text)
if outfile:
    open(outfile, "w").write(text + "\n")
sys.exit(0 if summary["all_under_target"] else 1)
PYEOF
