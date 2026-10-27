#!/usr/bin/env python3
"""security/wad/wad.py -- WAIO Adaptive Defense CLI and ledger.

    wad.py evaluate --events FILE [--policy FILE] [--now ISO8601]
    wad.py policy-check FILE
    wad.py policy-diff OLD NEW
    wad.py verify-ledger

DRY RUN ONLY. `evaluate` screens events, assesses threat levels, plans
responses and appends the result to the WAD ledger. It executes nothing:
see wad_lib.py's SAFETY BOUNDARY.

State (WAD_STATE_DIR, default security/state/wad/):
  ledger.jsonl       hash-chained JSONL, same chain format as
                     security/lib.sh audit_log (prev_hash = SHA-256 of the
                     previous line's text, 'genesis' first) so
                     verify_audit_log_integrity can check it unchanged.
  ledger.checkpoint  "count:hash" after the last successful append.
  .lock              flock; one evaluation at a time.
The ledger is the only source of truth for which events were already
decided; there is no second state file that could disagree with it after a
partial failure.

Stop signals, checked read-only and fail closed (an unreadable path counts
as present): WAIO_SHUTDOWN_LOCK (default security/state/SHUTDOWN.lock) and
WAD_STOP_FILE (default $WAD_STATE_DIR/STOP). WAD never creates or removes
either; stopping does not depend on WAD working.

Exit codes: 0 ok; 1 bad input/policy (nothing written); 3 ledger write
failed (no decision recorded); 4 ledger integrity broken (refused, nothing
written); 5 another evaluation holds the lock.
"""

import argparse
import datetime
import errno
import fcntl
import json
import os
import sys
import time
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import wad_lib as wl  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_POLICY = os.path.join(HERE, "policies", "wad_policy.json")
DEFAULT_STATE = os.path.join(HERE, "..", "state", "wad")
MAX_INPUT_BYTES = 16 * 1024 * 1024
LOCK_WAIT_S = float(os.environ.get("WAD_LOCK_WAIT_S", "10"))


def die(code, msg):
    print(f"wad: {msg}", file=sys.stderr)
    sys.exit(code)


def read_json_file(path, what):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as e:
        die(1, f"{what} unreadable or a symlink: {path} ({e.strerror})")
    with os.fdopen(fd, "rb") as f:
        data = f.read(MAX_INPUT_BYTES + 1)
    if len(data) > MAX_INPUT_BYTES:
        die(1, f"{what} larger than {MAX_INPUT_BYTES} bytes")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        die(1, f"{what} is not UTF-8")


def load_policy(path):
    try:
        return wl.validate_policy(json.loads(read_json_file(path, "policy")))
    except json.JSONDecodeError as e:
        die(1, f"policy is not JSON: {e}")
    except wl.PolicyError as e:
        die(1, f"policy refused: {e}")


def load_events(path):
    """A JSON array, or JSONL (one object per line). A line that is not
    JSON becomes a rejected entry, not a crash."""
    text = read_json_file(path, "events")
    stripped = text.lstrip()
    if stripped.startswith("["):
        try:
            events = json.loads(text)
        except json.JSONDecodeError as e:
            die(1, f"events array is not JSON: {e}")
        return events if isinstance(events, list) else [events]
    out = []
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            out.append({"_unparseable": True})
    return out


def stop_signal(path):
    """True when the stop file exists OR its presence cannot be determined."""
    try:
        os.lstat(path)
        return True
    except OSError as e:
        return e.errno != errno.ENOENT


class Ledger:
    def __init__(self, state_dir):
        self.dir = state_dir
        self.path = os.path.join(state_dir, "ledger.jsonl")
        self.checkpoint = os.path.join(state_dir, "ledger.checkpoint")

    def walk(self):
        """-> (lines as dicts, count, last_hash). Raises ValueError on a
        broken chain or a checkpoint that disagrees with the file."""
        entries, prev, count = [], "genesis", 0
        if os.path.exists(self.path):
            with open(self.path, "r", encoding="utf-8") as f:
                for lineno, raw in enumerate(f, start=1):
                    text = raw.rstrip("\n")
                    if not text:
                        continue
                    count += 1
                    try:
                        obj = json.loads(text)
                    except json.JSONDecodeError:
                        raise ValueError(f"broken:{lineno}")
                    if obj.get("prev_hash") != prev:
                        raise ValueError(f"broken:{lineno}")
                    prev = wl.sha256_hex(text)
                    entries.append(obj)
        cp = None
        if os.path.exists(self.checkpoint):
            with open(self.checkpoint, "r") as f:
                cp = f.read().strip()
        if cp is None:
            if count:
                raise ValueError("ledger has entries but no checkpoint")
        else:
            n, _, h = cp.partition(":")
            if not n.isdigit():
                raise ValueError("checkpoint malformed")
            if int(n) > count:
                raise ValueError("truncated")
            if int(n) != count or h != prev:
                raise ValueError("checkpoint_mismatch")
        return entries, count, prev

    def append(self, records, count, prev):
        lines = []
        for r in records:
            r = dict(r, prev_hash=prev)
            text = json.dumps(r)
            prev = wl.sha256_hex(text)
            lines.append(text)
        blob = ("\n".join(lines) + "\n").encode("utf-8")
        fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            written = os.write(fd, blob)
            if written != len(blob):
                raise OSError(errno.EIO, f"short write {written}/{len(blob)}")
            os.fsync(fd)
        finally:
            os.close(fd)
        tmp = self.checkpoint + ".tmp"
        with open(tmp, "w") as f:
            f.write(f"{count + len(lines)}:{prev}")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.checkpoint)


def acquire_lock(state_dir):
    fd = os.open(os.path.join(state_dir, ".lock"), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    deadline = time.monotonic() + LOCK_WAIT_S
    while True:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return fd
        except BlockingIOError:
            if time.monotonic() >= deadline:
                os.close(fd)
                die(5, "another WAD evaluation holds the lock")
            time.sleep(0.05)


def seen_from_ledger(entries, now, window_s):
    """{event key: digest} for events decided within the replay window. An
    event older than the window is rejected by normalize_event anyway, so
    forgetting its key cannot let it back in."""
    seen = {}
    horizon = now - datetime.timedelta(seconds=window_s * 2)
    for e in entries:
        if e.get("event_type") != "wad_events_accepted":
            continue
        ts = wl.parse_ts(e.get("timestamp"))
        if ts is None or ts < horizon:
            continue
        for k, d in (e.get("events") or {}).items():
            seen[k] = d
    return seen


def disruptive_in_last_hour(entries, now):
    horizon = now - datetime.timedelta(hours=1)
    total = 0
    for e in entries:
        if e.get("event_type") != "wad_decision":
            continue
        ts = wl.parse_ts(e.get("timestamp"))
        if ts is not None and ts >= horizon:
            total += wl.count_disruptive(e.get("plan") or {"steps": []})
    return total


def cmd_evaluate(args):
    now = wl.parse_ts(args.now) if args.now else datetime.datetime.now(datetime.timezone.utc)
    if now is None:
        die(1, "--now must be ISO-8601 with a timezone")
    policy = load_policy(args.policy)
    limits = policy["limits"]
    raw_events = load_events(args.events)
    if len(raw_events) > limits["max_events_per_run"]:
        die(1, f"{len(raw_events)} events exceeds max_events_per_run {limits['max_events_per_run']}")

    state_dir = os.environ.get("WAD_STATE_DIR", DEFAULT_STATE)
    os.makedirs(state_dir, mode=0o700, exist_ok=True)
    shutdown_lock = os.environ.get("WAIO_SHUTDOWN_LOCK", os.path.join(HERE, "..", "state", "SHUTDOWN.lock"))
    stop_file = os.environ.get("WAD_STOP_FILE", os.path.join(state_dir, "STOP"))

    lock_fd = acquire_lock(state_dir)
    try:
        ledger = Ledger(state_dir)
        try:
            entries, count, prev = ledger.walk()
        except ValueError as e:
            die(4, f"ledger integrity check failed ({e}); refusing to evaluate -- a human must inspect {ledger.path}")
        killswitch = stop_signal(shutdown_lock) or stop_signal(stop_file)
        screened = wl.screen_events(raw_events, seen_from_ledger(entries, now, limits["replay_window_s"]),
                                    now, limits)
        assessments = wl.assess(screened["accepted"], screened["conflicts"], now)
        plans = wl.plan_responses(assessments, policy, disruptive_in_last_hour(entries, now), killswitch)

        run_id = "wad-" + uuid.uuid4().hex[:12]
        ts = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        pref = wl.policy_ref(policy)
        base = {"timestamp": ts, "run_id": run_id, "policy": pref, "mode": "dry_run"}
        records = []
        for r in screened["rejected"]:
            records.append(dict(base, event_type="wad_event_rejected", **r))
        for d in screened["duplicates"]:
            records.append(dict(base, event_type="wad_event_duplicate", **d))
        for c in screened["conflicts"]:
            records.append(dict(base, event_type="wad_event_conflict", **c))
        if screened["accepted"]:
            records.append(dict(base, event_type="wad_events_accepted",
                                events={e["key"]: e["digest"] for e in screened["accepted"]}))
        by_entity = {p["entity"]: p for p in plans}
        for a in assessments:
            plan = by_entity[a["entity"]]
            statuses = sorted({s["status"] for s in plan["steps"]}) or ["NO_STEPS"]
            records.append(dict(base, event_type="wad_decision", entity=a["entity"],
                                threat_level=a["threat_level"], confidence=a["confidence"],
                                risk=a["risk"], reasons=a["reasons"] + plan["notes"],
                                event_keys=a["event_keys"], plan=plan, killswitch_active=killswitch,
                                result="DRY_RUN:" + ",".join(statuses)))
        if records:
            try:
                ledger.append(records, count, prev)
            except OSError as e:
                die(3, f"ledger write failed ({e.strerror or e}); no decision was recorded")
    finally:
        os.close(lock_fd)

    report = {"run_id": run_id, "timestamp": ts, "policy": pref, "mode": "dry_run",
              "killswitch_active": killswitch,
              "counts": {"input": len(raw_events), "accepted": len(screened["accepted"]),
                         "duplicates": len(screened["duplicates"]), "conflicts": len(screened["conflicts"]),
                         "rejected": len(screened["rejected"])},
              "rejected": screened["rejected"], "conflicts": screened["conflicts"],
              "assessments": assessments, "plans": plans}
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


def cmd_policy_check(args):
    p = load_policy(args.file)
    print(json.dumps(wl.policy_ref(p), sort_keys=True))
    return 0


def cmd_policy_diff(args):
    d = wl.diff_policies(load_policy(args.old), load_policy(args.new))
    print(json.dumps(d, indent=2, sort_keys=True))
    return 0


def cmd_verify(args):
    state_dir = os.environ.get("WAD_STATE_DIR", DEFAULT_STATE)
    try:
        _, count, _ = Ledger(state_dir).walk()
    except ValueError as e:
        print(f"broken: {e}")
        return 4
    print(f"ok: {count} entries")
    return 0


def main(argv):
    ap = argparse.ArgumentParser(prog="wad.py", description="WAIO Adaptive Defense (dry run only)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("evaluate")
    e.add_argument("--events", required=True)
    e.add_argument("--policy", default=DEFAULT_POLICY)
    e.add_argument("--now")
    e.set_defaults(fn=cmd_evaluate)
    c = sub.add_parser("policy-check")
    c.add_argument("file")
    c.set_defaults(fn=cmd_policy_check)
    d = sub.add_parser("policy-diff")
    d.add_argument("old")
    d.add_argument("new")
    d.set_defaults(fn=cmd_policy_diff)
    v = sub.add_parser("verify-ledger")
    v.set_defaults(fn=cmd_verify)
    args = ap.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
