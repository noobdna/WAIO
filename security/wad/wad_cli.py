"""security/wad/wad_cli.py -- I/O side of WAIO Adaptive Defense (WAD).
Run through security/wad/wad.sh. See wad_lib.py for the decision core
and its safety floors; this file owns state, audit, locking and the
controlled-response runner.

What this file may do, and nothing more:
  - read event / decision-report files and the policy file;
  - write under WAD_STATE_DIR (state, hash-chained audit log, watchlist,
    alert outbox, approval-request hand-off files);
  - run an operator-provided adapter from WAD_ADAPTER_DIR for an
    AUTOMATIC action only (observe / monitor_up / monitor_down / warn).
It never calls Guardian, DuCoPA, the kill switch, recover.sh, launchctl,
sudo, a firewall or the network. A destructive step (restrict_network,
isolate_host, their releases) is written out as an approval request for
a human to carry to the existing approval path (containment_approval_gate
.sh / Guardian wrappers) -- WAD has no executor for it.

Emergency stop: the ESTOP file (WAD_ESTOP_FILE) and WAIO's own
SHUTDOWN.lock (WAIO_SHUTDOWN_LOCK) are checked before a run and before
every step. This file only ever READS those paths; engaging and
releasing the stop is wad_estop.sh's job, which shares no code with
this file. An unreadable stop path counts as engaged (fail closed).

Default mode is DRY RUN: decisions are audited, nothing is executed, and
dry-run state is kept apart from execute state so a dry run can never
make a later real run skip an event.

Exit codes: 0 ok; 1 a step failed or timed out; 2 usage / invalid
policy or input; 3 state lock busy; 4 state file corrupt; 5 audit chain
invalid; 6 policy version rollback refused; 7 emergency stop engaged.
"""

import argparse
import errno
import fcntl
import json
import os
import signal
import stat
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import wad_lib as L  # noqa: E402

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DEFAULT_STATE_DIR = os.path.join(REPO, "security", "state", "wad")
DEFAULT_ESTOP = os.path.join(REPO, "security", "state", "wad_estop", "ESTOP")
DEFAULT_SHUTDOWN_LOCK = os.path.join(REPO, "security", "state", "SHUTDOWN.lock")
DEFAULT_POLICY = os.path.join(REPO, "security", "wad", "policies", "wad_policy.v1.json")

MAX_LINE_BYTES = 65536
MAX_EVENTS = 10000
LOCK_WAIT_SECONDS = 10
ADAPTER_OUTPUT_BYTES = 512


class Fatal(Exception):
    def __init__(self, code, message):
        Exception.__init__(self, message)
        self.code = code


# ---------------------------------------------------------------------
# environment
# ---------------------------------------------------------------------

def state_dir():
    return os.environ.get("WAD_STATE_DIR") or DEFAULT_STATE_DIR


def now_utc():
    """Real clock, unless a fixture clock is requested -- which is only
    honoured with an explicit, non-default WAD_STATE_DIR so a test clock
    can never steer the deployment's real state."""
    fixed = os.environ.get("WAD_FIXTURE_NOW")
    if fixed:
        sd = os.environ.get("WAD_STATE_DIR")
        if not sd or os.path.realpath(sd) == os.path.realpath(DEFAULT_STATE_DIR):
            raise Fatal(2, "WAD_FIXTURE_NOW is only allowed with a non-default WAD_STATE_DIR")
        dt = L.parse_utc(fixed)
        if dt is None:
            raise Fatal(2, "WAD_FIXTURE_NOW is not UTC ISO-8601")
        return dt
    return L.datetime.datetime.now(L.datetime.timezone.utc)


def stop_engaged():
    """-> (engaged, reason). Missing path = not engaged; any other
    error (permission, loop) = engaged."""
    for label, path in (("wad_estop", os.environ.get("WAD_ESTOP_FILE") or DEFAULT_ESTOP),
                        ("waio_shutdown", os.environ.get("WAIO_SHUTDOWN_LOCK") or DEFAULT_SHUTDOWN_LOCK)):
        try:
            os.lstat(path)
            return True, "%s present at %s" % (label, path)
        except OSError as e:
            if e.errno == errno.ENOENT:
                continue
            return True, "%s unreadable (%s) -- treated as engaged" % (label, e.strerror)
    return False, ""


def operator_allowlist():
    raw = os.environ.get("WAD_OPERATOR_ALLOWLIST")
    if not raw:
        return None
    return {x.strip() for x in raw.split(",") if x.strip()}


# ---------------------------------------------------------------------
# files: lock, atomic write, state, audit chain
# ---------------------------------------------------------------------

def ensure_dir(path):
    os.makedirs(path, mode=0o700, exist_ok=True)


class StateLock(object):
    def __init__(self, sd):
        ensure_dir(sd)
        self.path = os.path.join(sd, ".lock")
        self.fd = None

    def __enter__(self):
        self.fd = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        deadline = time.monotonic() + LOCK_WAIT_SECONDS
        while True:
            try:
                fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return self
            except OSError as e:
                if e.errno not in (errno.EAGAIN, errno.EACCES):
                    raise
                if time.monotonic() >= deadline:
                    os.close(self.fd)
                    raise Fatal(3, "state lock busy: %s" % self.path)
                time.sleep(0.1)

    def __exit__(self, *exc):
        fcntl.flock(self.fd, fcntl.LOCK_UN)
        os.close(self.fd)


def atomic_write_json(path, obj):
    d = os.path.dirname(path)
    ensure_dir(d)
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".tmp.")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(obj, f, sort_keys=True, indent=1)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def fresh_state():
    return {"seen": {}, "entities": {}, "auto_actions": [],
            "breaker": {"consecutive_failures": {}, "tripped": False},
            "policy_high_version": {}}


def load_state(sd, mode):
    path = os.path.join(sd, "state.%s.json" % mode)
    try:
        with open(path) as f:
            st = json.load(f)
    except FileNotFoundError:
        return fresh_state(), path
    except (OSError, ValueError) as e:
        raise Fatal(4, "state file unreadable or corrupt, refusing to overwrite it: %s (%s)" % (path, e))
    if not isinstance(st, dict) or not all(k in st for k in fresh_state()):
        raise Fatal(4, "state file has an unexpected shape, refusing to overwrite it: %s" % path)
    return st, path


def _entry_hash(entry):
    body = {k: v for k, v in entry.items() if k != "hash"}
    return L.sha256_hex(L.canonical_json(body))


def verify_audit(sd):
    """-> (ok, count, message). An absent log is valid and empty."""
    path = os.path.join(sd, "audit.jsonl")
    prev, n = "genesis", 0
    try:
        f = open(path)
    except FileNotFoundError:
        return True, 0, "no audit log yet"
    with f:
        for n, line in enumerate(f, 1):
            try:
                entry = json.loads(line)
            except ValueError:
                return False, n, "line %d is not JSON" % n
            if entry.get("prev_hash") != prev:
                return False, n, "line %d breaks the chain (prev_hash mismatch)" % n
            if entry.get("hash") != _entry_hash(entry):
                return False, n, "line %d was altered (hash mismatch)" % n
            prev = entry["hash"]
    return True, n, "chain intact"


class Audit(object):
    """Hash-chained, append-only JSONL. Callers hold StateLock."""

    def __init__(self, sd, mode, clock):
        self.path = os.path.join(sd, "audit.jsonl")
        self.mode = mode
        self.clock = clock
        ok, self.count, msg = verify_audit(sd)
        if not ok:
            raise Fatal(5, "audit chain invalid, refusing to append: %s" % msg)
        self.prev = "genesis"
        if self.count:
            with open(self.path, "rb") as f:
                f.seek(0, os.SEEK_END)
                size = f.tell()
                f.seek(max(0, size - MAX_LINE_BYTES * 4))
                last = f.read().splitlines()[-1]
            self.prev = json.loads(last)["hash"]

    def write(self, etype, **fields):
        entry = {"ts": L.format_utc(self.clock()), "seq": self.count + 1, "type": etype,
                 "mode": self.mode, "prev_hash": self.prev}
        entry.update(fields)
        entry["hash"] = _entry_hash(entry)
        line = L.canonical_json(entry) + "\n"
        fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            os.write(fd, line.encode("utf-8"))
            os.fsync(fd)
        finally:
            os.close(fd)
        self.prev, self.count = entry["hash"], self.count + 1
        return entry


# ---------------------------------------------------------------------
# policy and input
# ---------------------------------------------------------------------

def load_policy(path):
    try:
        with open(path) as f:
            policy = json.load(f)
    except (OSError, ValueError) as e:
        raise Fatal(2, "cannot read policy %s: %s" % (path, e))
    errs = L.validate_policy(policy)
    if errs:
        raise Fatal(2, "invalid policy %s: %s" % (path, "; ".join(errs)))
    return policy


def read_events(path):
    """-> list of (raw_or_None, parse_error_or_None)."""
    out = []
    try:
        f = open(path, "rb")
    except OSError as e:
        raise Fatal(2, "cannot read events %s: %s" % (path, e))
    with f:
        for n, line in enumerate(f, 1):
            if len(out) >= MAX_EVENTS:
                raise Fatal(2, "more than %d events in one batch" % MAX_EVENTS)
            if not line.strip():
                continue
            if len(line) > MAX_LINE_BYTES:
                out.append((None, "line %d longer than %d bytes" % (n, MAX_LINE_BYTES)))
                continue
            try:
                out.append((json.loads(line.decode("utf-8")), None))
            except (ValueError, UnicodeDecodeError):
                out.append((None, "line %d is not JSON" % n))
    return out


def read_decisions(path):
    try:
        with open(path) as f:
            report = json.load(f)
    except (OSError, ValueError) as e:
        raise Fatal(2, "cannot read decision report %s: %s" % (path, e))
    if not isinstance(report, dict) or not isinstance(report.get("decisions"), list):
        raise Fatal(2, "decision report has no decisions list")
    out = []
    for d in report["decisions"][:MAX_EVENTS]:
        if isinstance(d, dict):
            d = dict(d, kind="decision_record", observed_at=report.get("generated_at"))
        out.append((d, None))
    return out


def normalize_all(items):
    events = []
    for raw, perr in items:
        if perr:
            ev, errs = {"incomplete": True, "event_id": None, "source": None, "entity": None,
                        "observed_at": None, "seq": 0, "digest": None}, [perr]
        else:
            ev, errs = L.normalize_event(raw)
        ev["_errors"] = errs
        events.append(ev)
    return L.sort_events(events)


# ---------------------------------------------------------------------
# executors
# ---------------------------------------------------------------------

def _entity_file(sd, entity):
    return os.path.join(sd, "watchlist", L.sha256_hex(entity or "")[:32] + ".json")


def builtin_execute(sd, action, payload, clock):
    entity = payload.get("entity")
    if action == "observe":
        return "ok", "recorded"
    if action == "monitor_up":
        atomic_write_json(_entity_file(sd, entity), {"entity": entity, "level": payload.get("level"),
                                                      "since": L.format_utc(clock())})
        return "ok", "watchlist entry written"
    if action == "monitor_down":
        src = _entity_file(sd, entity)
        if not os.path.exists(src):
            return "ok", "no watchlist entry"
        dst_dir = os.path.join(sd, "watchlist", "released")
        ensure_dir(dst_dir)
        os.replace(src, os.path.join(dst_dir, "%s.%d" % (os.path.basename(src), int(time.time() * 1e6))))
        return "ok", "watchlist entry moved to released/"
    if action == "warn":
        line = L.canonical_json({"ts": L.format_utc(clock()), "entity": entity, "level": payload.get("level"),
                                 "event_id": payload.get("event_id"), "reasons": payload.get("reasons")})
        fd = os.open(os.path.join(sd, "alerts.jsonl"), os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            os.write(fd, (line + "\n").encode("utf-8"))
        finally:
            os.close(fd)
        return "ok", "alert appended"
    return "failed", "no builtin executor for %s" % action


def adapter_execute(adir, action, payload, timeout):
    path = os.path.join(adir, action)
    try:
        st = os.lstat(path)
        dst = os.stat(adir)
    except OSError:
        return None
    if not stat.S_ISREG(st.st_mode) or not os.access(path, os.X_OK):
        return "failed", "adapter is not a regular executable file"
    if (st.st_mode | dst.st_mode) & stat.S_IWOTH:
        return "failed", "adapter or adapter dir is world-writable"
    try:
        proc = subprocess.Popen([path], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, start_new_session=True, close_fds=True)
    except OSError as e:
        return "failed", "adapter did not start: %s" % e.strerror
    try:
        out, _ = proc.communicate(L.canonical_json(payload).encode("utf-8"), timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except OSError:
            pass
        proc.communicate()
        return "timeout", "adapter exceeded %ds" % timeout
    except BrokenPipeError:
        out = b""
        proc.wait()
    text = out[:ADAPTER_OUTPUT_BYTES].decode("utf-8", "replace")
    return ("ok" if proc.returncode == 0 else "failed"), "rc=%d %s" % (proc.returncode, text.strip())


def execute_action(ctx, action, payload):
    # Defense in depth: the planner never hands a destructive action
    # here, and this refuses one if it ever does.
    if L.ACTIONS[action]["class"] not in L.AUTO_CLASSES:
        return "failed", "refused: destructive action reached the executor"
    adir = os.environ.get("WAD_ADAPTER_DIR")
    if adir:
        res = adapter_execute(adir, action, payload, ctx["policy"]["step_timeout_seconds"])
        if res is not None:
            return res
    return builtin_execute(ctx["sd"], action, payload, ctx["clock"])


# ---------------------------------------------------------------------
# runner
# ---------------------------------------------------------------------

def _prune(state, now, policy):
    nowts = now.timestamp()
    window = policy["dedup_window_seconds"]
    state["seen"] = {k: v for k, v in state["seen"].items() if nowts - v.get("at", 0) <= window}
    state["auto_actions"] = [t for t in state["auto_actions"] if nowts - t <= 3600]


def _write_approval_request(ctx, step, payload):
    req = {"request_id": "wad-" + L.sha256_hex(L.canonical_json([payload, step["action"]]))[:24],
           "action": step["action"], "entity": payload.get("entity"), "level": payload.get("level"),
           "event_id": payload.get("event_id"), "reasons": payload.get("reasons"),
           "requested_at": L.format_utc(ctx["clock"]()), "policy": ctx["policy_ref"],
           "handoff": "WAD does not execute this. A human decides it via the existing approval "
                      "path (security/red_alert/containment_approval_gate.sh, Guardian wrappers)."}
    if ctx["mode"] == "execute":
        atomic_write_json(os.path.join(ctx["sd"], "approval_requests", req["request_id"] + ".json"), req)
    return req["request_id"]


def run_plan(ctx, plan, payload):
    """-> (step results, failed?). Honors estop, breaker, rate limit,
    timeouts and, for atomic plans, rolls back completed steps."""
    state, policy = ctx["state"], ctx["policy"]
    results, done, failed = [], [], False
    steps = plan["steps"]
    for i, step in enumerate(steps):
        engaged, why = stop_engaged()
        if engaged:
            ctx["halted"] = why
            for rest in steps[i:]:
                results.append({"action": rest["action"], "mode": rest["mode"], "status": "halted_estop"})
            break
        r = {"action": step["action"], "mode": step["mode"]}
        if step["mode"] == "pending_approval":
            r["status"] = "pending_approval"
            r["request_id"] = _write_approval_request(ctx, step, payload)
        elif state["breaker"]["tripped"]:
            r["status"] = "breaker_open"
        elif len(state["auto_actions"]) >= policy["rate_limits"]["auto_actions_per_hour"]:
            r["status"] = "rate_limited"
        elif ctx["mode"] == "dryrun":
            r["status"] = "dry_run"
            state["auto_actions"].append(ctx["clock"]().timestamp())
        else:
            status, detail = execute_action(ctx, step["action"], payload)
            state["auto_actions"].append(ctx["clock"]().timestamp())
            r["status"], r["detail"] = status, detail
            # Failures are counted per action, so a broken warn adapter
            # still trips the breaker while monitor_up keeps succeeding.
            # Once tripped, every automatic step stops until an operator
            # resets it.
            br = state["breaker"]
            counts = br["consecutive_failures"]
            if status == "ok":
                counts[step["action"]] = 0
                done.append(step)
            else:
                failed = True
                counts[step["action"]] = counts.get(step["action"], 0) + 1
                if counts[step["action"]] >= policy["circuit_breaker"]["max_consecutive_failures"] and not br["tripped"]:
                    br["tripped"] = True
                    ctx["audit"].write("breaker_tripped", action=step["action"],
                                       consecutive_failures=counts[step["action"]])
        results.append(r)
        if failed and plan["atomic"]:
            for rest in steps[i + 1:]:
                results.append({"action": rest["action"], "mode": rest["mode"], "status": "skipped_after_failure"})
            for prev in reversed(done):
                rb = prev["rollback"]
                if not rb:
                    continue
                status, detail = execute_action(ctx, rb, payload)
                results.append({"action": rb, "mode": "rollback", "status": status, "detail": detail,
                                "rolls_back": prev["action"]})
            break
    return results, failed


def process_event(ctx, ev):
    state, policy, audit = ctx["state"], ctx["policy"], ctx["audit"]
    now = ctx["clock"]()
    errs = ev.pop("_errors")
    base = {"event_id": ev.get("event_id"), "source": ev.get("source"), "entity": ev.get("entity"),
            "digest": ev.get("digest"), "policy": ctx["policy_ref"]}
    key = L.dedup_key(ev) if not errs else None

    if key and key in state["seen"]:
        if state["seen"][key]["digest"] == ev["digest"]:
            audit.write("event", outcome="duplicate_suppressed", **base)
            return "duplicate_suppressed", False
        # Same identity, different content: a replay or a forged update.
        # Nothing is executed for it; a human is told.
        assessment = {"level": L.UNCERTAIN_CAP, "rule": None, "confidence": "UNKNOWN", "uncertain": True,
                      "reasons": ["replay_conflict: event_id reused with different content"]}
        plan = {"level": "L2", "atomic": False,
                "steps": [s for s in L.plan_for("L2", policy)["steps"] if s["action"] == "warn"]}
        results, failed = run_plan(ctx, plan, dict(base, level="L2", reasons=assessment["reasons"]))
        audit.write("event", outcome="replay_conflict", assessment=assessment, steps=results, **base)
        return "replay_conflict", failed

    if not errs:
        why = L.check_freshness(ev, now, policy)
        if why:
            audit.write("event", outcome="refused_freshness", reason=why, **base)
            return "refused_freshness", False

    assessment = L.assess(ev, errs, policy)
    level = assessment["level"]
    entity = ev.get("entity") if not errs else None
    ent = state["entities"].get(entity) if entity else None
    nowts = now.timestamp()

    if ent and L.level_index(level) <= L.level_index(ent["level"]):
        if ev["observed_at"] < ent["last_observed_at"]:
            outcome = "superseded_out_of_order"
        elif nowts - ent.get("last_action_at", 0) < policy["rate_limits"]["per_entity_cooldown_seconds"]:
            outcome = "cooldown_suppressed"
        else:
            outcome = None
        if outcome:
            audit.write("event", outcome=outcome, assessment=assessment, active_level=ent["level"], **base)
            if key:
                state["seen"][key] = {"digest": ev["digest"], "at": nowts}
            return outcome, False

    plan = L.plan_for(level, policy)
    payload = dict(base, level=level, reasons=assessment["reasons"])
    results, failed = run_plan(ctx, plan, payload)
    audit.write("event", outcome="planned" if not ctx.get("halted") else "halted_estop",
                assessment=assessment, atomic=plan["atomic"], steps=results, **base)
    if ctx.get("halted"):
        return "halted_estop", failed
    if key:
        state["seen"][key] = {"digest": ev["digest"], "at": nowts}
    if entity:
        prev = state["entities"].get(entity) or {"level": "L0", "last_observed_at": ev["observed_at"]}
        state["entities"][entity] = {
            # Never downgraded automatically: recovery is the only way down.
            "level": L.higher_level(prev["level"], level),
            "last_observed_at": max(prev["last_observed_at"], ev["observed_at"]),
            "last_action_at": nowts,
            "recovery_pending": prev.get("recovery_pending", False),
        }
    return "planned", failed


def _open_run(args, mode):
    sd = state_dir()
    policy_path = args.policy or os.environ.get("WAD_POLICY") or DEFAULT_POLICY
    policy = load_policy(policy_path)
    clock = now_utc
    clock()  # validate a fixture clock before touching anything
    return sd, policy, policy_path, clock


def _policy_guard(ctx, args):
    """Anti-rollback for execute mode: a policy with a lower version than
    the highest one already applied is refused unless an operator
    explicitly accepts it (audited)."""
    p = ctx["policy"]
    high = ctx["state"]["policy_high_version"].get(p["policy_id"], 0)
    if p["version"] < high:
        if not args.allow_policy_rollback:
            ctx["audit"].write("policy_rollback_refused", policy=ctx["policy_ref"], highest_applied=high)
            raise Fatal(6, "policy %s v%d is older than applied v%d (use --allow-policy-rollback with "
                           "--operator/--reason)" % (p["policy_id"], p["version"], high))
        _require_operator(args)
        ctx["audit"].write("policy_rollback_accepted", policy=ctx["policy_ref"], highest_applied=high,
                           operator=args.operator, reason=args.reason)
    ctx["state"]["policy_high_version"][p["policy_id"]] = max(high, p["version"])


def _require_operator(args):
    v = L.validate_operator(getattr(args, "operator", None), operator_allowlist())
    if not v["valid"]:
        raise Fatal(2, "operator refused: %s" % v["reason"])
    if not L.validate_reason(getattr(args, "reason", None)):
        raise Fatal(2, "a reason of at least 10 characters (no control characters) is required")


def cmd_respond(args):
    mode = "execute" if args.execute else "dryrun"
    sd, policy, policy_path, clock = _open_run(args, mode)
    items = read_decisions(args.decisions) if args.decisions else read_events(args.input)
    with StateLock(sd):
        audit = Audit(sd, mode, clock)
        state, spath = load_state(sd, mode)
        ref = {"policy_id": policy["policy_id"], "version": policy["version"], "sha256": L.policy_digest(policy)}
        ctx = {"sd": sd, "mode": mode, "policy": policy, "policy_ref": ref, "state": state,
               "audit": audit, "clock": clock, "halted": None}
        engaged, why = stop_engaged()
        if engaged:
            audit.write("run_halted", reason=why, policy=ref)
            raise Fatal(7, "emergency stop engaged: %s" % why)
        if mode == "execute":
            _policy_guard(ctx, args)
        _prune(state, clock(), policy)
        audit.write("run_start", policy=ref, policy_path=os.path.basename(policy_path), events=len(items))
        counts, any_failed = {}, False
        for ev in normalize_all(items):
            if ctx["halted"]:
                counts["not_processed_estop"] = counts.get("not_processed_estop", 0) + 1
                continue
            outcome, failed = process_event(ctx, ev)
            counts[outcome] = counts.get(outcome, 0) + 1
            any_failed = any_failed or failed
        audit.write("run_end", counts=counts, halted=ctx["halted"], breaker=state["breaker"])
        atomic_write_json(spath, state)
    print(json.dumps({"mode": mode, "counts": counts, "halted": ctx["halted"], "breaker": state["breaker"],
                      "policy": ref}, sort_keys=True))
    if ctx["halted"]:
        return 7
    return 1 if any_failed else 0


def cmd_recover(args):
    _require_operator(args)
    mode = "execute" if args.execute else "dryrun"
    sd, policy, _, clock = _open_run(args, mode)
    with StateLock(sd):
        audit = Audit(sd, mode, clock)
        state, spath = load_state(sd, mode)
        ref = {"policy_id": policy["policy_id"], "version": policy["version"], "sha256": L.policy_digest(policy)}
        ent = state["entities"].get(args.entity)
        if not ent:
            raise Fatal(2, "entity has no active WAD state in %s mode" % mode)
        engaged, why = stop_engaged()
        if engaged:
            audit.write("recover_halted", entity=args.entity, reason=why)
            raise Fatal(7, "emergency stop engaged: %s" % why)
        ctx = {"sd": sd, "mode": mode, "policy": policy, "policy_ref": ref, "state": state,
               "audit": audit, "clock": clock, "halted": None}
        plan = L.recovery_plan(ent["level"], policy)
        payload = {"entity": args.entity, "level": plan["level"], "event_id": None,
                   "reasons": ["operator recovery: " + args.reason]}
        results, failed = run_plan(ctx, plan, payload)
        pending = any(r["status"] == "pending_approval" for r in results)
        if ctx["halted"] or failed:
            outcome = "recover_incomplete"
        elif pending:
            outcome = "recover_pending_approval"
            ent["recovery_pending"] = True
        else:
            outcome = "recovered"
            del state["entities"][args.entity]
        audit.write("recover", outcome=outcome, entity=args.entity, from_level=ent["level"], steps=results,
                    operator=args.operator, reason=args.reason, policy=ref)
        atomic_write_json(spath, state)
    print(json.dumps({"mode": mode, "outcome": outcome, "steps": results}, sort_keys=True))
    if ctx["halted"]:
        return 7
    return 1 if failed else 0


def cmd_breaker_reset(args):
    _require_operator(args)
    sd = state_dir()
    with StateLock(sd):
        audit = Audit(sd, "execute", now_utc)
        state, spath = load_state(sd, "execute")
        before = dict(state["breaker"])
        state["breaker"] = {"consecutive_failures": {}, "tripped": False}
        audit.write("breaker_reset", before=before, operator=args.operator, reason=args.reason)
        atomic_write_json(spath, state)
    print(json.dumps({"breaker": state["breaker"]}))
    return 0


def cmd_assess(args):
    policy = load_policy(args.policy or os.environ.get("WAD_POLICY") or DEFAULT_POLICY)
    items = read_decisions(args.decisions) if args.decisions else read_events(args.input)
    out = []
    for ev in normalize_all(items):
        errs = ev.pop("_errors")
        a = L.assess(ev, errs, policy)
        out.append({"event": ev, "errors": errs, "assessment": a, "plan": L.plan_for(a["level"], policy)})
    print(json.dumps(out, indent=1, sort_keys=True))
    return 0


def cmd_policy_check(args):
    try:
        with open(args.file) as f:
            policy = json.load(f)
    except (OSError, ValueError) as e:
        print(json.dumps({"valid": False, "errors": [str(e)]}))
        return 2
    errs = L.validate_policy(policy)
    print(json.dumps({"valid": not errs, "errors": errs,
                      "sha256": L.policy_digest(policy) if not errs else None}, indent=1))
    return 0 if not errs else 2


def cmd_policy_diff(args):
    a, b = load_policy(args.old), load_policy(args.new)
    print(json.dumps({"old": {"policy_id": a["policy_id"], "version": a["version"], "sha256": L.policy_digest(a)},
                      "new": {"policy_id": b["policy_id"], "version": b["version"], "sha256": L.policy_digest(b)},
                      "version_increases": b["version"] > a["version"],
                      "changes": L.diff_policies(a, b)}, indent=1, sort_keys=True))
    return 0


def cmd_audit_verify(args):
    ok, n, msg = verify_audit(state_dir())
    print(json.dumps({"ok": ok, "entries": n, "message": msg}))
    return 0 if ok else 5


def cmd_status(args):
    sd = state_dir()
    engaged, why = stop_engaged()
    ok, n, msg = verify_audit(sd)
    out = {"estop_engaged": engaged, "estop_reason": why, "audit_ok": ok, "audit_entries": n,
           "audit_message": msg}
    for mode in ("dryrun", "execute"):
        try:
            st, _ = load_state(sd, mode)
            out[mode] = {"entities": st["entities"], "breaker": st["breaker"],
                         "auto_actions_last_hour": len(st["auto_actions"])}
        except Fatal as e:
            out[mode] = {"error": str(e)}
    print(json.dumps(out, indent=1, sort_keys=True))
    return 0


def main(argv):
    p = argparse.ArgumentParser(prog="wad.sh", description="WAIO Adaptive Defense")
    sub = p.add_subparsers(dest="cmd")

    def src(sp):
        g = sp.add_mutually_exclusive_group(required=True)
        g.add_argument("--in", dest="input")
        g.add_argument("--decisions")
        sp.add_argument("--policy")

    sp = sub.add_parser("assess"); src(sp)
    sp = sub.add_parser("respond"); src(sp)
    sp.add_argument("--execute", action="store_true")
    sp.add_argument("--allow-policy-rollback", action="store_true")
    sp.add_argument("--operator"); sp.add_argument("--reason")
    sp = sub.add_parser("recover")
    sp.add_argument("--entity", required=True); sp.add_argument("--policy")
    sp.add_argument("--operator", required=True); sp.add_argument("--reason", required=True)
    sp.add_argument("--execute", action="store_true")
    sp = sub.add_parser("breaker-reset")
    sp.add_argument("--operator", required=True); sp.add_argument("--reason", required=True)
    sp = sub.add_parser("policy-check"); sp.add_argument("file")
    sp = sub.add_parser("policy-diff"); sp.add_argument("old"); sp.add_argument("new")
    sub.add_parser("audit-verify")
    sub.add_parser("status")

    args = p.parse_args(argv)
    handlers = {"assess": cmd_assess, "respond": cmd_respond, "recover": cmd_recover,
                "breaker-reset": cmd_breaker_reset, "policy-check": cmd_policy_check,
                "policy-diff": cmd_policy_diff, "audit-verify": cmd_audit_verify, "status": cmd_status}
    if args.cmd not in handlers:
        p.print_help(sys.stderr)
        return 2
    try:
        return handlers[args.cmd](args)
    except Fatal as e:
        print("wad: %s" % e, file=sys.stderr)
        return e.code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
