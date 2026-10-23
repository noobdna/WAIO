#!/bin/bash
set -uo pipefail

# security/yashi/yashi_learn.sh -- YASHI Defense Learning Mode CLI.
#
#   yashi_learn.sh            # learn from the pipeline's candidates
#
# Reads (never writes) every *.json in $YASHI_CANDIDATES_DIR (default:
# security/state/incident_learning/candidates, the Incident Learning
# Engine's own state) and writes ONLY into $YASHI_STATE_DIR (default:
# security/state/yashi):
#   cases.jsonl          one 7-section defense case per classified incident
#   validations.json     real-detector results on synthetic fixtures
#   proposals.json       PROPOSED_REQUIRES_HUMAN_APPROVAL defense updates
#   knowledge_index.json techniques seen so far (drives newly_observed vs
#                        previously_known on the next run) + run metadata
#   run.log              append-only, one line per run
#
# No network, no detector/config/allowlist edits, no containment call.
# See yashi_lib.py's header for the full safety contract.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
CANDIDATES_DIR="${YASHI_CANDIDATES_DIR:-$REPO_DIR/security/state/incident_learning/candidates}"
STATE_DIR="${YASHI_STATE_DIR:-$REPO_DIR/security/state/yashi}"

[ -d "$CANDIDATES_DIR" ] || { echo "yashi_learn: no candidates dir: $CANDIDATES_DIR" >&2; exit 2; }
mkdir -p "$STATE_DIR" || { echo "yashi_learn: cannot create $STATE_DIR" >&2; exit 2; }

python3 -I - "$SCRIPT_DIR" "$CANDIDATES_DIR" "$STATE_DIR" <<'PY'
import glob, hashlib, json, os, sys, datetime
lib_dir, cand_dir, state_dir = sys.argv[1:4]
sys.path.insert(0, lib_dir)
import yashi_lib as y

records, unreadable = [], []
for p in sorted(glob.glob(os.path.join(cand_dir, "*.json"))):
    try:
        raw = open(p, "rb").read()
        rec = json.loads(raw)
    except (OSError, ValueError):
        unreadable.append(os.path.basename(p))
        continue
    if not isinstance(rec, dict):  # valid JSON but not a record: skip, do not abort the run
        unreadable.append(os.path.basename(p))
        continue
    records.append((rec, hashlib.sha256(raw).hexdigest()))

idx_path = os.path.join(state_dir, "knowledge_index.json")
try:
    known = json.load(open(idx_path)).get("techniques", {})
except (OSError, ValueError, AttributeError):
    known = {}
if not isinstance(known, dict):
    known = {}

res = y.learn(records, known_techniques=known.keys())
now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def write(name, text):
    tmp = os.path.join(state_dir, "." + name + ".tmp")
    with open(tmp, "w") as f:
        f.write(text)
    os.replace(tmp, os.path.join(state_dir, name))

write("cases.jsonl", "".join(json.dumps(c, ensure_ascii=False, sort_keys=True) + "\n" for c in res["cases"]))
write("validations.json", json.dumps(res["validations"], ensure_ascii=False, indent=2, sort_keys=True) + "\n")
write("proposals.json", json.dumps(res["proposals"], ensure_ascii=False, indent=2, sort_keys=True) + "\n")
for t in res["observed_techniques"]:
    known.setdefault(t, {"first_seen_at": now})["last_seen_at"] = now
write("knowledge_index.json", json.dumps({"catalog_version": res["catalog_version"], "updated_at": now,
                                          "techniques": known}, indent=2, sort_keys=True) + "\n")
fails = sorted(t for t, v in res["validations"].items() if v["status"] == "FAIL")
line = ("%s input=%d unreadable=%d mock_excluded=%d eligible=%d cases=%d proposals=%d new_techniques=%s validation_fail=%s\n"
        % (now, res["input_records"], len(unreadable), res["excluded_mock"], res["eligible_after_dedupe"], len(res["cases"]),
           len(res["proposals"]), ",".join(res["newly_observed_techniques"]) or "-", ",".join(fails) or "-"))
with open(os.path.join(state_dir, "run.log"), "a") as f:
    f.write(line)
sys.stdout.write(line)
sys.exit(1 if fails else 0)
PY
