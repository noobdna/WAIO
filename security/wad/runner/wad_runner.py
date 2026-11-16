"""security/wad/runner/wad_runner.py -- the one place WAD starts a process.

PR 2 runner (live execution of NON-DISRUPTIVE steps only). Everything else in
security/wad/ still executes nothing; tests/wad_runner_test.sh S-series
checks that this file is the only WAD module that spawns.

What can run live:
  LIVE_ACTIONS = monitor_increase (monitor up), monitor_restore (monitor
  down, the rollback compensation of monitor_increase) and warn_operator.
  restrict_egress, isolate_agent, recover and release_* can never be
  configured here: load_config() refuses the whole file. Binding a
  disruptive action is PR 4 and goes through the containment runner.

Where commands come from: an operator-written config file (owner-only,
not a symlink, not group/other-writable) mapping each action to an absolute
argv. The step itself only selects WHICH configured adapter runs; nothing
from an event, a decision or the command line becomes part of argv. The
adapter learns the step through its environment (WAD_ACTION, WAD_ENTITY,
WAD_STEP_ID, WAD_MODE=live) and gets no other inherited variables.

Process groups: every adapter starts in a new session (its own process
group, pgid = its pid). run_adapter() ends the WHOLE group -- SIGTERM, a
grace period, then SIGKILL -- on timeout, on an engaged stop signal, and
also after a normal exit if anything the adapter left behind is still in
the group. While it runs, runner/active/<pgid> records "pgid", the process
start time from ps, and the step id, so security/wad/wad_estop.sh can end
the group even if the runner itself is hung or dead. The start time guards
against killing an unrelated group that reused the pid.
"""

import json
import os
import select
import signal
import stat
import subprocess
import time

LIVE_ACTIONS = {
    "monitor_increase": "observe",
    "monitor_restore": "observe",
    "warn_operator": "notify",
}
CONFIG_VERSION = 1
MAX_TIMEOUT_S = 60
MAX_LIVE_PER_HOUR = 60
MAX_ARGV = 16
MAX_ARG_LEN = 1024
MAX_CONFIG_BYTES = 64 * 1024
OUTPUT_TAIL = 512
TERM_GRACE_S = 2.0
KILL_WAIT_S = 2.0
POLL_S = 0.05
ADAPTER_PATH = "/usr/bin:/bin:/usr/sbin:/sbin"
PS_CANDIDATES = ("/bin/ps", "/usr/bin/ps")


class RunnerConfigError(Exception):
    pass


def _check_not_writable_by_others(st, what):
    if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise RunnerConfigError(f"{what} is group/other-writable")
    if st.st_uid not in (os.geteuid(), 0):
        raise RunnerConfigError(f"{what} is owned by another user")


def _check_executable(path):
    if not os.path.isabs(path):
        raise RunnerConfigError(f"adapter path must be absolute: {path!r}")
    real = os.path.realpath(path)
    try:
        st = os.stat(real)
    except OSError as e:
        raise RunnerConfigError(f"adapter {path!r} not found ({e.strerror})")
    if not stat.S_ISREG(st.st_mode):
        raise RunnerConfigError(f"adapter {path!r} is not a regular file")
    if not os.access(real, os.X_OK):
        raise RunnerConfigError(f"adapter {path!r} is not executable")
    _check_not_writable_by_others(st, f"adapter {path!r}")
    _check_not_writable_by_others(os.stat(os.path.dirname(real)), f"directory of adapter {path!r}")


def load_config(path):
    """-> validated config dict, or raises RunnerConfigError. Any problem
    refuses the whole file: a half-valid config never runs anything."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as e:
        raise RunnerConfigError(f"runner config unreadable or a symlink: {path} ({e.strerror})")
    with os.fdopen(fd, "rb") as f:
        st = os.fstat(f.fileno())
        if not stat.S_ISREG(st.st_mode):
            raise RunnerConfigError("runner config is not a regular file")
        if st.st_uid != os.geteuid() or st.st_mode & 0o022:
            raise RunnerConfigError("runner config must be owned by this user and not group/other-writable")
        data = f.read(MAX_CONFIG_BYTES + 1)
    if len(data) > MAX_CONFIG_BYTES:
        raise RunnerConfigError("runner config too large")
    try:
        cfg = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise RunnerConfigError(f"runner config is not JSON ({e})")
    if not isinstance(cfg, dict) or set(cfg) != {"version", "max_live_per_hour", "adapters"}:
        raise RunnerConfigError("runner config must have exactly version, max_live_per_hour, adapters")
    if cfg["version"] != CONFIG_VERSION:
        raise RunnerConfigError(f"runner config version must be {CONFIG_VERSION}")
    cap = cfg["max_live_per_hour"]
    if not (isinstance(cap, int) and not isinstance(cap, bool) and 0 <= cap <= MAX_LIVE_PER_HOUR):
        raise RunnerConfigError(f"max_live_per_hour must be an integer in [0, {MAX_LIVE_PER_HOUR}]")
    adapters = cfg["adapters"]
    if not isinstance(adapters, dict):
        raise RunnerConfigError("adapters must be an object")
    for action, spec in adapters.items():
        if action not in LIVE_ACTIONS:
            raise RunnerConfigError(f"action {action!r} can never run live (only {sorted(LIVE_ACTIONS)})")
        if not isinstance(spec, dict) or set(spec) != {"argv", "timeout_s"}:
            raise RunnerConfigError(f"adapter {action} must have exactly argv, timeout_s")
        argv, t = spec["argv"], spec["timeout_s"]
        if not (isinstance(argv, list) and 1 <= len(argv) <= MAX_ARGV
                and all(isinstance(a, str) and a and "\x00" not in a and len(a) <= MAX_ARG_LEN for a in argv)):
            raise RunnerConfigError(f"adapter {action} argv must be 1-{MAX_ARGV} non-empty strings")
        if not (isinstance(t, int) and not isinstance(t, bool) and 1 <= t <= MAX_TIMEOUT_S):
            raise RunnerConfigError(f"adapter {action} timeout_s must be an integer in [1, {MAX_TIMEOUT_S}]")
        _check_executable(argv[0])
    return cfg


def process_start(pid):
    """ps's start time for pid, or None if the process is gone or ps is
    unavailable. wad_estop.sh compares the same `ps -o lstart=` output."""
    for ps in PS_CANDIDATES:
        if os.path.exists(ps):
            try:
                out = subprocess.run([ps, "-o", "lstart=", "-p", str(pid)], capture_output=True,
                                     text=True, timeout=5, env={"PATH": ADAPTER_PATH, "LC_ALL": "C"})
            except (OSError, subprocess.SubprocessError):
                return None
            text = " ".join(out.stdout.split())
            return text or None
    return None


def group_alive(pgid):
    try:
        os.killpg(pgid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def terminate_group(pgid, leader=None):
    """SIGTERM the group, wait, SIGKILL, wait. -> (gone, errors). The leader
    Popen is reaped while waiting, so a zombie leader does not keep the group
    looking alive."""
    errors = []
    for sig, wait_s in ((signal.SIGTERM, TERM_GRACE_S), (signal.SIGKILL, KILL_WAIT_S)):
        try:
            os.killpg(pgid, sig)
        except ProcessLookupError:
            return True, errors
        except PermissionError:
            errors.append(f"EPERM sending {sig.name} to group {pgid}")
            return False, errors
        deadline = time.monotonic() + wait_s
        while time.monotonic() < deadline:
            if leader is not None:
                leader.poll()
            if not group_alive(pgid):
                return True, errors
            time.sleep(POLL_S)
    if leader is not None:
        leader.poll()
    gone = not group_alive(pgid)
    if not gone:
        errors.append(f"group {pgid} still alive after SIGKILL")
    return gone, errors


def _clean_tail(buf):
    text = buf[-OUTPUT_TAIL:].decode("utf-8", "replace")
    return "".join(c if c.isprintable() or c == "\n" else "?" for c in text)


def run_adapter(argv, action, entity, step_id, timeout_s, stop_check, active_dir):
    """Runs one adapter to completion, timeout or stop. Never raises for an
    adapter failure; returns the result dict that goes into the ledger.

    outcome: ok | exit_nonzero | timeout | halted_stop | spawn_failed
    group_terminated: the whole group is confirmed gone at the end.
    """
    started = time.monotonic()
    env = {"PATH": ADAPTER_PATH, "LC_ALL": "C", "WAD_MODE": "live",
           "WAD_ACTION": action, "WAD_ENTITY": entity, "WAD_STEP_ID": step_id}
    result = {"result": "LIVE", "action": action, "entity": entity, "adapter": argv[0],
              "timeout_s": timeout_s}
    try:
        proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, env=env, cwd="/", close_fds=True,
                                start_new_session=True)
    except OSError as e:
        result.update(outcome="spawn_failed", error=f"{type(e).__name__}: {e.strerror or e}",
                      group_terminated=True, duration_s=0.0)
        return result
    pgid = proc.pid
    os.makedirs(active_dir, mode=0o700, exist_ok=True)
    active = os.path.join(active_dir, str(pgid))
    tmp = active + ".tmp"
    with open(tmp, "w") as f:
        f.write(f"{pgid}\n{process_start(pgid) or 'unknown'}\n{step_id}\n")
    os.replace(tmp, active)

    buf, total, outcome = b"", 0, None
    gone, errors, leftover = False, [], False
    fd = proc.stdout.fileno()
    eof = False
    leader_exit_at = None
    try:
        while True:
            if not eof:
                ready, _, _ = select.select([fd], [], [], POLL_S)
                if ready:
                    chunk = os.read(fd, 65536)
                    if chunk:
                        total += len(chunk)
                        buf = (buf + chunk)[-4096:]
                    else:
                        eof = True
            else:
                time.sleep(POLL_S)
            if proc.poll() is not None:
                # A child left in the group may hold the pipe open; give the
                # output a moment to drain, then stop waiting for EOF.
                leader_exit_at = leader_exit_at or time.monotonic()
                if eof or time.monotonic() - leader_exit_at > 0.3:
                    break
            if stop_check():
                outcome = "halted_stop"
                break
            if time.monotonic() - started > timeout_s:
                outcome = "timeout"
                break
        leftover = group_alive(pgid) if outcome is None else True
        gone, errors = terminate_group(pgid, proc) if leftover else (True, [])
        if outcome is None and proc.poll() is None:
            proc.wait()
    finally:
        proc.stdout.close()
        # Keep the record while the group may still exist, so wad_estop.sh
        # can still end it.
        if gone:
            try:
                os.unlink(active)
            except OSError:
                pass
    if outcome is None:
        if proc.returncode == 0:
            outcome = "ok"
        elif stop_check():
            # wad_estop.sh ended the group before this loop saw the stop.
            outcome = "halted_stop"
        else:
            outcome = "exit_nonzero"
    result.update(outcome=outcome, exit_code=proc.returncode, output_bytes=total,
                  output_tail=_clean_tail(buf), group_terminated=gone,
                  leftover_processes_terminated=bool(leftover and outcome in ("ok", "exit_nonzero")),
                  duration_s=round(time.monotonic() - started, 3))
    if errors:
        result["kill_errors"] = errors
    return result
