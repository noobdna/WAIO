#!/bin/bash
# tests/e2e/interval_bench.sh -- SIMULATED end-to-end latency including the
# detection schedule, inside an e2e sandbox. Not a production measurement.
#
# Usage: interval_bench.sh [-i INTERVAL_S] [-n SAMPLES] [-o OUT.json]
#
# Each sample: a fresh sandbox starts benign; a scheduler loop ticks every
# INTERVAL_S seconds (wall clock) and each tick runs the REAL Shadow AI ->
# Attack Graph -> Intelligence -> Decision Engine chain on fixture
# telemetry, then security/containment_runner/containment_runner.sh in
# execute mode with a signed quarantine-only policy (both opt-ins set, all
# state inside the sandbox). The anomaly appears at a random moment inside
# the first interval. Recovery is the human command
# (guardian_release_agent.sh --confirm) issued right after containment, so
# "recover" here is the tool latency, not human reaction time.
#
# Reported per sample and summarized: scheduling wait (appear -> tick
# start), detect -> decision, decision -> contained, contained -> recovered,
# and appear -> contained (the containment latency compared with 60 s).
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$SCRIPT_DIR" || exit 2

INTERVAL=30 N=5 OUTFILE=""
while [ $# -gt 0 ]; do
  case "$1" in
    -i) INTERVAL="$2"; shift 2 ;;
    -n) N="$2"; shift 2 ;;
    -o) OUTFILE="$2"; shift 2 ;;
    *) echo "Usage: $0 [-i INTERVAL_S] [-n SAMPLES] [-o OUT.json]" >&2; exit 2 ;;
  esac
done
case "$INTERVAL" in ''|*[!0-9]*|0) exit 2 ;; esac
case "$N" in ''|*[!0-9]*|0) exit 2 ;; esac

ROOT="$(mktemp -d "${TMPDIR:-/tmp}/waio-interval.XXXXXX")"
trap 'rm -rf "${ROOT:?}"' EXIT
SAMPLES="$ROOT/samples.jsonl"; : > "$SAMPLES"
( umask 077; openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$ROOT/signing.pem" 2>/dev/null ) || exit 2
now() { perl -MTime::HiRes -e 'printf "%.6f\n", Time::HiRes::time()'; }
sleep_until() { perl -MTime::HiRes -e '$d = $ARGV[0] - Time::HiRes::time(); Time::HiRes::sleep($d) if $d > 0' "$1"; }

one_sample() {  # one_sample INDEX
  local d="$ROOT/s$1" t_tick0 t_appear t_tick t_dec t_cont t_rec offset exp out
  mkdir -p "$d"
  # shellcheck source=tests/e2e/lib_env.sh
  source tests/e2e/lib_env.sh
  e2e_sandbox_init "$d" && e2e_write_detection_fixture "$d" benign || return 1
  export WAIO_CONTAINMENT_RUNNER_STATE_DIR="$d/state/runner" WAIO_CONTAINMENT_POLICY_PUBKEY="$d/keys/policy.pub.pem"
  openssl pkey -in "$ROOT/signing.pem" -pubout -out "$WAIO_CONTAINMENT_POLICY_PUBKEY" 2>/dev/null || return 1
  exp="$(python3 -c 'import datetime; print((datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"))')"
  python3 scripts/containment_policy_sign.py --private-key "$ROOT/signing.pem" --policy "$d/fixtures/policy.json" \
    --entity rogue-agent --action quarantine_agent:ECHO --expires-at "$exp" --max-executions 1000 \
    --rule-id rule-bench --approved-by bench-operator --reason "interval bench fixture rule" >/dev/null || return 1
  # The scheduler's phase is fixed at t_tick0; the anomaly appears at a
  # uniformly random offset inside the first interval.
  t_tick0="$(now)"
  offset="$(python3 -c "import random; print(random.uniform(0.05, $INTERVAL - 0.05))")"
  sleep_until "$(python3 -c "print($t_tick0 + $offset)")"
  e2e_write_detection_fixture "$d" anomaly
  t_appear="$(now)"
  # next tick
  sleep_until "$(python3 -c "print($t_tick0 + $INTERVAL)")"
  t_tick="$(now)"
  e2e_detect_to_decision "$d" || return 1
  t_dec="$(now)"
  out="$(WAIO_CONTAINMENT_RUNNER_EXECUTE=1 ./security/containment_runner/containment_runner.sh run --report "$d/run/decisions.json" --policy "$d/fixtures/policy.json" --execute 2>/dev/null)"
  t_cont="$(now)"
  case "$out" in *'"outcome": "contained"'*) ;; *) echo "sample $1: not contained: $out" >&2; return 1 ;; esac
  ./security/guardian_release_agent.sh ECHO --confirm "interval bench: fixture quarantine released after measurement" >/dev/null 2>&1 || return 1
  grep -Fxq ECHO "$WAIO_GUARDIAN_QUARANTINE_FILE" 2>/dev/null && return 1
  t_rec="$(now)"
  python3 -c 'import json, sys
a, tk, dc, ct, rc = map(float, sys.argv[1:6])
print(json.dumps({"scheduling_wait": tk - a, "detect_to_decision": dc - tk, "decision_to_contained": ct - dc,
                  "contained_to_recovered": rc - ct, "appear_to_contained": ct - a}))' "$t_appear" "$t_tick" "$t_dec" "$t_cont" "$t_rec" >> "$SAMPLES"
}

fails=0
for i in $(seq 1 "$N"); do
  ( one_sample "$i" ) || fails=$((fails + 1))
done

python3 - "$SAMPLES" "$INTERVAL" "$N" "$fails" "${OUTFILE:-}" <<'PYEOF'
import json, platform, statistics, sys, datetime
path, interval, n, fails, outfile = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4]), sys.argv[5]
rows = [json.loads(l) for l in open(path) if l.strip()]
def summ(k):
    v = sorted(r[k] for r in rows)
    if not v:
        return None
    p95 = v[min(len(v) - 1, int(round(0.95 * (len(v) - 1))))]
    return {"median": round(statistics.median(v), 3), "p95": round(p95, 3), "max": round(v[-1], 3), "min": round(v[0], 3)}
res = {
    "label": "SIMULATED (e2e sandbox, fixture telemetry) -- not a production measurement",
    "measured_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "interval_s": interval, "samples_requested": n, "samples_completed": len(rows), "failures": fails,
    "stages": {k: summ(k) for k in ("scheduling_wait", "detect_to_decision", "decision_to_contained", "contained_to_recovered")},
    "appear_to_contained": summ("appear_to_contained"),
    "target_s": 60,
    "all_under_target": bool(rows) and all(r["appear_to_contained"] < 60 for r in rows) and fails == 0,
    "worst_case_bound_s": round(interval + max((r["detect_to_decision"] + r["decision_to_contained"]) for r in rows), 3) if rows else None,
    "conditions": {"containment": "containment_runner execute, signed quarantine-only policy, no human approval",
                   "recovery": "guardian_release_agent.sh --confirm issued immediately (tool latency only)",
                   "host": platform.node(), "os": platform.platform(), "python": platform.python_version()},
}
text = json.dumps(res, indent=2)
print(text)
if outfile:
    open(outfile, "w").write(text + "\n")
PYEOF
