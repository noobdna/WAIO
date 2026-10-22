"""security/snd_behavior/behavior_monitor.py -- READ-ONLY / DRY-RUN CLI
around behavior_lib.py. Reads event files, writes detection records;
never contains anything and never calls security/killswitch/.

  baseline HISTORY.jsonl OUT.json
  detect BASELINE.json EVENTS.jsonl OUT_DIR [--context CONTEXT.json]
                                            [--targets TARGETS.json]
      Writes OUT_DIR/<event_id>.json per detection (0600, existing files
      are kept, so a re-run is idempotent) and prints a summary.

CONTEXT.json: [{"context_id","principal","kind":"travel|schedule_change|
  emergency_change","start","end","regions":[...],"hours":[a,b],
  "approved_by","reason"}]
TARGETS.json: {"<principal>": "<killswitch test target id>"}
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import behavior_lib as bl  # noqa: E402

MAX_FILE_BYTES = 32 * 1024 * 1024


def _read_jsonl(path):
    events, rejected = [], 0
    if os.path.getsize(path) > MAX_FILE_BYTES:
        raise ValueError("input exceeds %d bytes" % MAX_FILE_BYTES)
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                ev, err = bl.normalize(json.loads(line))
            except ValueError:
                ev, err = None, "bad json"
            if err:
                rejected += 1
            else:
                events.append(ev)
    return events, rejected


def _read_json(path, default):
    if not path:
        return default
    with open(path) as f:
        return json.load(f)


def main(argv):
    if len(argv) == 4 and argv[1] == "baseline":
        events, rejected = _read_jsonl(argv[2])
        base = bl.build_baseline(events)
        with open(argv[3], "w") as f:
            json.dump(base, f, sort_keys=True, indent=1)
        print(json.dumps({"ok": True, "principals": len(base["principals"]), "events": len(events),
                          "rejected": rejected}))
        return 0
    if len(argv) >= 5 and argv[1] == "detect":
        opts, rest = {}, argv[5:]
        while rest:
            if len(rest) < 2 or rest[0] not in ("--context", "--targets"):
                print(json.dumps({"ok": False, "detail": "usage"}))
                return 2
            opts[rest[0]] = rest[1]
            rest = rest[2:]
        base = _read_json(argv[2], {})
        if base.get("schema") != bl.SCHEMA_BASELINE:
            print(json.dumps({"ok": False, "detail": "baseline schema mismatch"}))
            return 2
        events, rejected = _read_jsonl(argv[3])
        dets = bl.detect(base, events, _read_json(opts.get("--context"), []), _read_json(opts.get("--targets"), {}))
        os.makedirs(argv[4], 0o700, exist_ok=True)
        written = 0
        for d in dets:
            path = os.path.join(argv[4], d["event_id"] + ".json")
            try:
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            except FileExistsError:
                continue
            with os.fdopen(fd, "w") as f:
                f.write(json.dumps(d, sort_keys=True) + "\n")
            written += 1
        by_risk = {}
        for d in dets:
            by_risk[d["risk"]] = by_risk.get(d["risk"], 0) + 1
        print(json.dumps({"ok": True, "mode": "DRY_RUN", "events": len(events), "rejected": rejected,
                          "detections": len(dets), "written": written, "by_risk": by_risk,
                          "rules": sorted({d["rule"] for d in dets})}, sort_keys=True))
        return 0
    print(json.dumps({"ok": False, "detail": "usage: baseline HISTORY OUT | detect BASELINE EVENTS OUT_DIR [--context F] [--targets F]"}))
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
