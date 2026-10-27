#!/usr/bin/env python3
"""security/wad/wad.py -- WAIO Adaptive Defense CLI and ledger.

    wad.py evaluate --events FILE [--policy FILE] [--now ISO8601]
    wad.py policy-check FILE
    wad.py policy-diff OLD NEW
    wad.py verify-ledger
    wad.py response list
    wad.py response approve|reject STEP_ID --operator NAME --reason TEXT [--now ISO8601]
    wad.py response execute STEP_ID [--now ISO8601]
    wad.py response rollback (STEP_ID | --plan RUN_ID ENTITY) --operator NAME --reason TEXT [--now ISO8601]
    wad.py response sweep [--now ISO8601]
    wad.py repair-checkpoint --operator NAME --reason TEXT [--now ISO8601]

DRY RUN ONLY. `evaluate` screens events, assesses threat levels, plans
responses and appends the result to the WAD ledger. It executes nothing:
see wad_lib.py's SAFETY BOUNDARY. `response` drives each planned step
through the state machine in wad_response.py; "execute" is a dry-run no-op
that records what would have been done. Approvals check an allowlisted name
(WAD_APPROVER_ALLOWLIST, default $WAD_STATE_DIR/approvers; absent = every
approval refused). The name is NOT authenticated, and every record says so.

Keyed chain (optional): with WAD_LEDGER_HMAC_KEY_FILE set, every new record
carries "mac" = HMAC-SHA256(key, record without mac, prev_hash included) and
ledger.checkpoint.mac holds the checkpoint's HMAC. Once a keyed record
exists, an unkeyed record after it, a bad mac, or reading without the key is
an integrity failure. prev_hash stays sha256 of the full line, so
security/lib.sh verify_audit_log_integrity still checks the chain. A key
only helps against writers who cannot read the key file.

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
written); 5 another evaluation holds the lock; 6 transition refused (the
refusal itself is recorded; the step did not move).
"""

import argparse
import datetime
import errno
import fcntl
import hashlib
import hmac
import json
import os
import sys
import time
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import wad_lib as wl  # noqa: E402
import wad_response as wr  # noqa: E402

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


def load_key():
    """Bytes of WAD_LEDGER_HMAC_KEY_FILE, or None when unset. Set but
    unreadable, empty or a symlink is an error (fail closed), never a silent
    fall back to the unkeyed chain."""
    path = os.environ.get("WAD_LEDGER_HMAC_KEY_FILE", "")
    if not path:
        return None
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as e:
        raise ValueError(f"ledger key unreadable or a symlink ({e.strerror})")
    with os.fdopen(fd, "rb") as f:
        key = f.read(4096)
    if len(key) < 16:
        raise ValueError("ledger key shorter than 16 bytes")
    return key


def record_mac(key, obj):
    body = {k: v for k, v in obj.items() if k != "mac"}
    return hmac.new(key, json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8"),
                    hashlib.sha256).hexdigest()


class Ledger:
    def __init__(self, state_dir, key=None):
        self.dir = state_dir
        self.path = os.path.join(state_dir, "ledger.jsonl")
        self.checkpoint = os.path.join(state_dir, "ledger.checkpoint")
        self.checkpoint_mac = self.checkpoint + ".mac"
        self.key = key

    def chain(self):
        """-> (entries, hashes, keyed). hashes[i] is the chain hash after
        line i+1. Checks prev_hash links and macs, not the checkpoint.
        Raises ValueError on any break."""
        entries, hashes, prev, keyed = [], [], "genesis", False
        if os.path.exists(self.path):
            with open(self.path, "r", encoding="utf-8") as f:
                lineno = 0
                for raw in f:
                    text = raw.rstrip("\n")
                    if not text:
                        continue
                    lineno += 1
                    try:
                        obj = json.loads(text)
                    except json.JSONDecodeError:
                        raise ValueError(f"broken:{lineno}")
                    if not isinstance(obj, dict) or obj.get("prev_hash") != prev:
                        raise ValueError(f"broken:{lineno}")
                    if "mac" in obj:
                        if self.key is None:
                            raise ValueError(f"keyed_ledger_but_no_key:{lineno}")
                        if not hmac.compare_digest(record_mac(self.key, obj), str(obj["mac"])):
                            raise ValueError(f"mac_invalid:{lineno}")
                        keyed = True
                    elif keyed:
                        raise ValueError(f"unkeyed_record_after_keyed:{lineno}")
                    prev = wl.sha256_hex(text)
                    entries.append(obj)
                    hashes.append(prev)
        return entries, hashes, keyed

    def read_checkpoint(self):
        if not os.path.exists(self.checkpoint):
            return None
        with open(self.checkpoint, "r") as f:
            return f.read().strip()

    def checkpoint_mac_ok(self, cp):
        if self.key is None:
            if os.path.exists(self.checkpoint_mac):
                raise ValueError("keyed_checkpoint_but_no_key")
            return True
        try:
            with open(self.checkpoint_mac, "r") as f:
                stored = f.read().strip()
        except FileNotFoundError:
            return False
        return hmac.compare_digest(hmac.new(self.key, cp.encode("utf-8"), hashlib.sha256).hexdigest(), stored)

    def walk(self):
        """-> (lines as dicts, count, last_hash). Raises ValueError on a
        broken chain or a checkpoint that disagrees with the file."""
        entries, hashes, keyed = self.chain()
        count, prev = len(entries), (hashes[-1] if hashes else "genesis")
        cp = self.read_checkpoint()
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
            if (keyed or os.path.exists(self.checkpoint_mac)) and not self.checkpoint_mac_ok(cp):
                raise ValueError("checkpoint_mac_invalid")
        return entries, count, prev

    def append(self, records, count, prev):
        lines = []
        for r in records:
            r = dict(r, prev_hash=prev)
            if self.key is not None:
                r["mac"] = record_mac(self.key, r)
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
        self.write_checkpoint(count + len(lines), prev)
        return count + len(lines), prev

    def write_checkpoint(self, count, last_hash):
        cp = f"{count}:{last_hash}"
        tmp = self.checkpoint + ".tmp"
        with open(tmp, "w") as f:
            f.write(cp)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.checkpoint)
        if self.key is not None:
            tmp = self.checkpoint_mac + ".tmp"
            with open(tmp, "w") as f:
                f.write(hmac.new(self.key, cp.encode("utf-8"), hashlib.sha256).hexdigest())
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self.checkpoint_mac)


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
        ledger = open_ledger(state_dir)
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
        ledger = Ledger(state_dir, load_key())
        _, count, _ = ledger.walk()
        keyed = ledger.chain()[2]
    except ValueError as e:
        print(f"broken: {e}")
        return 4
    print(f"ok: {count} entries ({'hmac-sha256' if keyed else 'sha256-unkeyed'})")
    return 0


# ------------------------------------------------------------ response workflow

def state_paths():
    state_dir = os.environ.get("WAD_STATE_DIR", DEFAULT_STATE)
    shutdown_lock = os.environ.get("WAIO_SHUTDOWN_LOCK", os.path.join(HERE, "..", "state", "SHUTDOWN.lock"))
    stop_file = os.environ.get("WAD_STOP_FILE", os.path.join(state_dir, "STOP"))
    return state_dir, shutdown_lock, stop_file


def open_ledger(state_dir):
    try:
        return Ledger(state_dir, load_key())
    except ValueError as e:
        die(4, f"{e}; refusing")


def parse_now(text):
    now = wl.parse_ts(text) if text else datetime.datetime.now(datetime.timezone.utc)
    if now is None:
        die(1, "--now must be ISO-8601 with a timezone")
    return now


def load_allowlist(state_dir):
    """Set of approver names, or None when the file is absent, a symlink or
    empty (every approval is then refused)."""
    path = os.environ.get("WAD_APPROVER_ALLOWLIST", os.path.join(state_dir, "approvers"))
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        return None
    with os.fdopen(fd, "r", encoding="utf-8") as f:
        names = {ln.strip() for ln in f if ln.strip() and not ln.lstrip().startswith("#")}
    return names or None


def reserved_names():
    """Names of WAIO components under security/ (file stem or directory):
    never accepted as a human approver."""
    try:
        return {os.path.splitext(n)[0] for n in os.listdir(os.path.join(HERE, "..")) if not n.startswith(".")}
    except OSError:
        return set()


def approval_ttl():
    v = os.environ.get("WAD_APPROVAL_TTL_S", "")
    if not v:
        return wr.cal.DEFAULT_APPROVAL_TTL_SECONDS
    if not v.isdigit() or not 60 <= int(v) <= 7 * 86400:
        die(1, "WAD_APPROVAL_TTL_S must be an integer between 60 and 604800")
    return int(v)


def transition(base, step, action, actor, **extra):
    rec = dict(base, event_type="wad_step_transition", step_id=step["step_id"],
               decision_run_id=step["run_id"], entity=step["entity"], step_action=step["action"],
               action=action, to=wr.next_state(step["state"], action), actor=actor, authenticated=False, **extra)
    rec["from"] = step["state"]
    return rec


def refuse(ledger, count, prev, base, step_id, action, actor, violations):
    rec = dict(base, event_type="wad_transition_refused", step_id=step_id, action=action,
               requested_by=actor, authenticated=False, violations=violations)
    try:
        ledger.append([rec], count, prev)
    except OSError as e:
        die(3, f"ledger write failed ({e.strerror or e}); refusal not recorded")
    print(json.dumps({"refused": True, "step_id": step_id, "action": action, "violations": violations},
                     sort_keys=True))
    sys.exit(6)


def cmd_response(args):
    now = parse_now(getattr(args, "now", None))
    state_dir, shutdown_lock, stop_file = state_paths()
    os.makedirs(state_dir, mode=0o700, exist_ok=True)
    lock_fd = acquire_lock(state_dir)
    try:
        ledger = open_ledger(state_dir)
        try:
            entries, count, prev = ledger.walk()
        except ValueError as e:
            die(4, f"ledger integrity check failed ({e}); refusing -- a human must inspect {ledger.path}")
        killswitch = stop_signal(shutdown_lock) or stop_signal(stop_file)
        steps = wr.replay_steps(entries)
        base = {"timestamp": now.strftime("%Y-%m-%dT%H:%M:%SZ"), "run_id": "wad-op-" + uuid.uuid4().hex[:12],
                "mode": "dry_run"}

        if args.rcmd == "list":
            out = [{k: s[k] for k in ("step_id", "run_id", "entity", "index", "action", "class", "state")}
                   for s in sorted(steps.values(), key=lambda s: (s["decided_at"] or "", s["run_id"], s["entity"], s["index"]))]
            print(json.dumps(out, indent=2, sort_keys=True))
            return 0

        if args.rcmd == "sweep":
            # Every transition runs under this lock and finishes inside one
            # command, so a step still "executing" here was interrupted.
            recs = [transition(base, s, "fail", "wad", note="interrupted: executing with no completion record")
                    for s in steps.values() if s["state"] == wr.EXECUTING]
            if recs:
                try:
                    ledger.append(recs, count, prev)
                except OSError as e:
                    die(3, f"ledger write failed ({e.strerror or e})")
            print(json.dumps({"swept": [r["step_id"] for r in recs]}, sort_keys=True))
            return 0

        actor = getattr(args, "operator", None) or "wad"
        if args.rcmd == "rollback" and args.plan:
            targets = wr.rollback_order(steps, args.plan[0], args.plan[1])
            if not targets:
                refuse(ledger, count, prev, base, None, "rollback", actor,
                       [f"no_done_or_failed_steps:{args.plan[0]}:{args.plan[1]}"])
        else:
            sid = args.step_id
            if not wr.valid_step_id(sid):
                die(1, "STEP_ID must be 16 lowercase hex characters (see `response list`)")
            if sid not in steps:
                refuse(ledger, count, prev, base, sid, args.rcmd, actor, ["unknown_step"])
            targets = [steps[sid]]

        allow = load_allowlist(state_dir)
        reserved = reserved_names()
        if args.rcmd == "approve":
            step = targets[0]
            decision = next((e for e in reversed(entries) if e.get("event_type") == "wad_decision"
                             and e.get("run_id") == step["run_id"] and e.get("entity") == step["entity"]), {})
            ttl = approval_ttl()
            chk = wr.check_approval(step, args.operator, args.reason, allow, now, killswitch, ttl,
                                    wr.decision_digest(decision), reserved)
            if not chk["allowed"]:
                refuse(ledger, count, prev, base, step["step_id"], "approve", actor, chk["violations"])
            rec = transition(base, step, "approve", args.operator, reason=args.reason.strip(),
                             decision_digest=step["decision_digest"],
                             approval_expires_at=wr.cal.format_utc_timestamp(wr.cal.compute_expiry(now, ttl)),
                             identity_check="present_and_in_allowlist_not_authenticated")
            recs = [rec]
        elif args.rcmd == "reject":
            step = targets[0]
            v = []
            if wr.next_state(step["state"], "reject") is None:
                v.append(f"illegal_transition:{step['state']}->reject")
            ok, why, _ = wr.check_operator(args.operator, allow, reserved)
            if not ok:
                v.append(why)
            if wr.cal.validate_reason(args.reason)["status"] != "OK":
                v.append("reason_" + wr.cal.validate_reason(args.reason)["status"].lower())
            if v:
                refuse(ledger, count, prev, base, step["step_id"], "reject", actor, v)
            recs = [transition(base, step, "reject", args.operator, reason=args.reason.strip())]
        elif args.rcmd == "execute":
            step = targets[0]
            chk = wr.check_start(step, now, killswitch, approval_ttl())
            if not chk["allowed"]:
                refuse(ledger, count, prev, base, step["step_id"], "start", actor, chk["violations"])
            # The start record is durable before the (dry-run) executor runs;
            # a crash after this point leaves the step "executing" for `sweep`.
            try:
                count, prev = ledger.append([transition(base, step, "start", "wad")], count, prev)
            except OSError as e:
                die(3, f"ledger write failed ({e.strerror or e}); step not started")
            step = dict(step, state=wr.EXECUTING)
            try:
                result = wr.dry_run_execute(step["action"], step["entity"])
                recs = [transition(base, step, "complete", "wad", result=result)]
            except Exception as e:  # a dry run cannot really fail, but never leave it ambiguous
                recs = [transition(base, step, "fail", "wad", error=str(e)[:200])]
        elif args.rcmd == "rollback":
            violations = []
            for s in targets:
                chk = wr.check_rollback(s, args.operator, args.reason, allow, killswitch, reserved)
                violations += [f"{s['step_id']}:{x}" for x in chk["violations"]]
            if violations:
                refuse(ledger, count, prev, base, targets[0]["step_id"] if len(targets) == 1 else None,
                       "rollback", actor, violations)
            recs = [transition(base, s, "rollback", args.operator, reason=args.reason.strip(),
                               compensating_action=wr.COMPENSATION[s["action"]],
                               result=wr.dry_run_execute(wr.COMPENSATION[s["action"]], s["entity"]))
                    for s in targets]
        else:
            die(1, f"unknown response command {args.rcmd}")

        try:
            ledger.append(recs, count, prev)
        except OSError as e:
            die(3, f"ledger write failed ({e.strerror or e}); transition not recorded")
        print(json.dumps({"transitions": [{k: r[k] for k in ("step_id", "action", "from", "to")} for r in recs]},
                         sort_keys=True))
        return 0
    finally:
        os.close(lock_fd)


def cmd_repair(args):
    """Adopts records appended after the checkpoint when the checkpoint is a
    consistent prefix of an intact chain (the crash between append and
    checkpoint rename). Refuses a broken chain, a missing checkpoint, a
    checkpoint ahead of the ledger, a checkpoint hash that disagrees with
    the ledger prefix, and an operator outside the allowlist."""
    now = parse_now(args.now)
    state_dir, _, _ = state_paths()
    lock_fd = acquire_lock(state_dir)
    try:
        ledger = open_ledger(state_dir)
        try:
            entries, hashes, keyed = ledger.chain()
        except ValueError as e:
            die(4, f"chain itself is broken ({e}); repair refused")
        count, last = len(entries), (hashes[-1] if hashes else "genesis")
        cp = ledger.read_checkpoint()
        if cp is None:
            die(4, "no checkpoint; refusing to adopt an unanchored ledger")
        n, _, h = cp.partition(":")
        if not n.isdigit():
            die(4, "checkpoint malformed; repair refused")
        n = int(n)
        if n > count:
            die(4, "checkpoint is ahead of the ledger (truncated); repair refused")
        if h != ("genesis" if n == 0 else hashes[n - 1]):
            die(4, "checkpoint hash disagrees with the ledger prefix; repair refused")
        try:
            mac_ok = not (keyed or os.path.exists(ledger.checkpoint_mac)) or ledger.checkpoint_mac_ok(cp)
        except ValueError as e:
            die(4, f"{e}; repair refused")
        if n == count and mac_ok:
            print(json.dumps({"repaired": False, "reason": "checkpoint already consistent"}))
            return 0
        ok, why, _ = wr.check_operator(args.operator, load_allowlist(state_dir), reserved_names())
        rs = wr.cal.validate_reason(args.reason)["status"]
        if not ok or rs != "OK":
            # nothing is appended: appending would itself rewrite the checkpoint
            print(json.dumps({"repaired": False, "refused": [x for x in (None if ok else why,
                              None if rs == "OK" else "reason_" + rs.lower()) if x]}))
            return 6
        rec = {"timestamp": now.strftime("%Y-%m-%dT%H:%M:%SZ"), "run_id": "wad-op-" + uuid.uuid4().hex[:12],
               "mode": "dry_run", "event_type": "wad_checkpoint_repaired", "previous_checkpoint_count": n,
               "adopted_records": count - n, "adopted_hashes": hashes[n:count][:100],
               "adopted_authenticity": "hmac-verified" if keyed else "chain-only-unkeyed",
               "actor": args.operator, "authenticated": False, "reason": args.reason.strip()}
        try:
            ledger.append([rec], count, last)
        except OSError as e:
            die(3, f"ledger write failed ({e.strerror or e}); checkpoint not repaired")
        print(json.dumps({"repaired": True, "adopted_records": count - n}))
        return 0
    finally:
        os.close(lock_fd)


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
    r = sub.add_parser("response")
    rsub = r.add_subparsers(dest="rcmd", required=True)
    rl = rsub.add_parser("list")
    rl.add_argument("--now")
    rs = rsub.add_parser("sweep")
    rs.add_argument("--now")
    for name in ("approve", "reject"):
        p = rsub.add_parser(name)
        p.add_argument("step_id")
        p.add_argument("--operator", required=True)
        p.add_argument("--reason", required=True)
        p.add_argument("--now")
    rx = rsub.add_parser("execute")
    rx.add_argument("step_id")
    rx.add_argument("--now")
    rb = rsub.add_parser("rollback")
    rb.add_argument("step_id", nargs="?")
    rb.add_argument("--plan", nargs=2, metavar=("RUN_ID", "ENTITY"))
    rb.add_argument("--operator", required=True)
    rb.add_argument("--reason", required=True)
    rb.add_argument("--now")
    r.set_defaults(fn=cmd_response)
    rp = sub.add_parser("repair-checkpoint")
    rp.add_argument("--operator", required=True)
    rp.add_argument("--reason", required=True)
    rp.add_argument("--now")
    rp.set_defaults(fn=cmd_repair)
    args = ap.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
