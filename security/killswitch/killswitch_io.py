"""security/killswitch/killswitch_io.py -- file-I/O half of the DuCoPA
Independent Kill Switch, invoked only by killswitch_gate.sh. Every
decision is delegated to killswitch_lib.py (pure); this file reads the
inputs that library needs, and performs the single permitted side
effect: writing one containment marker into a validated test
environment.

Subcommands (each prints exactly one JSON object on stdout):
  decide COMMAND_FILE          -- parse + authenticate + authorize
  testenv TESTENV_DIR          -- validate a declared test environment
  effect ACTION TARGET TESTENV COMMAND_ID
                               -- write the marker (atomic rename)
  event EVENT_FILE             -- normalize + evaluate (dry-run only)
  record                       -- build a structured result record from
                                  KS_* environment values

Inputs from the gate's environment: KS_CONFIG_DIR, KS_KEYRING_DIR,
KS_NOW (UTC, optional), KS_FRESHNESS_SECONDS, KS_REPO_DIR.

Never imports or calls anything outside this directory and the Python
standard library.
"""

import datetime
import json
import os
import stat
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import killswitch_lib as ksl  # noqa: E402

TESTENV_MARKER = ".killswitch-test-env"


def out(obj):
    print(json.dumps(obj, ensure_ascii=False, sort_keys=True))


def now_utc():
    text = os.environ.get("KS_NOW", "")
    if text:
        parsed = ksl.parse_ts(text)
        if parsed is not None:
            return parsed
    return datetime.datetime.now(datetime.timezone.utc)


def read_text(path, limit):
    with open(path, "rb") as f:
        data = f.read(limit + 1)
    if len(data) > limit:
        raise ValueError("input exceeds %d bytes" % limit)
    return data.decode("utf-8")


def secure_private_file(path):
    """Regular file (not a symlink), owned by this uid, no group/other
    permission bits. Returns error text or ''."""
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return "missing"
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        return "not a regular file"
    if st.st_uid != os.getuid():
        return "not owned by the current user"
    if st.st_mode & 0o077:
        return "permissions %o allow group/other access" % (st.st_mode & 0o777)
    return ""


def load_config():
    """Returns (authz, targets, error_code, detail)."""
    cfg = os.environ.get("KS_CONFIG_DIR", "")
    tpath, apath = os.path.join(cfg, "targets.conf"), os.path.join(cfg, "authz.conf")
    if not cfg or not os.path.isfile(tpath) or not os.path.isfile(apath):
        return None, None, "DENIED_NOT_CONFIGURED", "targets.conf/authz.conf not present in the config dir"
    for p in (tpath, apath):
        err = secure_private_file(p)
        if err:
            return None, None, "DENIED_CONFIG_INVALID", "%s: %s" % (os.path.basename(p), err)
    targets, terr = ksl.parse_targets(read_text(tpath, 65536))
    authz, aerr = ksl.parse_authz(read_text(apath, 65536))
    if terr or aerr:
        return None, None, "DENIED_CONFIG_INVALID", "; ".join(terr + aerr)[:400]
    return authz, targets, None, ""


def public_view(cmd):
    """The command minus its signature, safe to record."""
    if not isinstance(cmd, dict):
        return {}
    view = {k: cmd.get(k) for k in sorted(ksl.COMMAND_FIELDS) if k != "signature"}
    if isinstance(view.get("reason"), str):
        view["reason"] = ksl.redact_summary(view["reason"])
    return view


def cmd_decide(path):
    try:
        text = read_text(path, ksl.MAX_COMMAND_BYTES)
    except (OSError, ValueError, UnicodeDecodeError) as exc:
        return out({"decision": "DENY", "code": "DENIED_INVALID_INPUT", "detail": "cannot read command: %s" % exc, "command": {}})
    cmd, perr = ksl.parse_command(text)
    if perr:
        return out({"decision": "DENY", "code": "DENIED_INVALID_INPUT", "detail": perr, "command": {}})
    authz, targets, code, detail = load_config()
    if code:
        return out({"decision": "DENY", "code": code, "detail": detail, "command": public_view(cmd)})

    key = None
    if ksl.valid_id(cmd["issuer"]):
        kpath = os.path.join(os.environ.get("KS_KEYRING_DIR", ""), cmd["issuer"] + ".key")
        kerr = secure_private_file(kpath)
        if kerr and kerr != "missing":
            return out({"decision": "DENY", "code": "DENIED_KEY_INSECURE",
                        "detail": "key for issuer '%s' refused: %s" % (cmd["issuer"], kerr), "command": public_view(cmd)})
        if not kerr:
            with open(kpath, "rb") as f:
                key = f.read(4097)
            if len(key) < 32 or len(key) > 4096:
                return out({"decision": "DENY", "code": "DENIED_KEY_INSECURE",
                            "detail": "key for issuer '%s' must be 32-4096 bytes" % cmd["issuer"], "command": public_view(cmd)})
    try:
        fresh = int(os.environ.get("KS_FRESHNESS_SECONDS", ksl.DEFAULT_FRESHNESS_SECONDS))
    except ValueError:
        fresh = ksl.DEFAULT_FRESHNESS_SECONDS
    result = ksl.evaluate_command(cmd, now_utc(), key, authz, targets, freshness_seconds=fresh)
    result["command"] = public_view(cmd)
    out(result)


def testenv_error(path):
    repo = os.path.realpath(os.environ.get("KS_REPO_DIR", "/nonexistent-repo"))
    if not path or not os.path.isabs(path):
        return "KILLSWITCH_TEST_ENV must be an absolute path"
    if os.path.islink(path) or not os.path.isdir(path):
        return "test environment is not a real directory"
    real = os.path.realpath(path)
    if real == repo or real.startswith(repo + os.sep):
        return "test environment must be outside the WAIO repository"
    for denied in ("/etc", "/private/etc", "/System", "/usr", "/bin", "/sbin", "/Library",
                   os.path.realpath(os.path.expanduser("~/.ssh"))):
        if real == denied or real.startswith(denied + os.sep):
            return "test environment may not live under %s" % denied
    marker = os.path.join(real, TESTENV_MARKER)
    if os.path.islink(marker) or not os.path.isfile(marker):
        return "missing %s marker file" % TESTENV_MARKER
    try:
        lines = [ln.strip() for ln in read_text(marker, 4096).splitlines()]
    except (OSError, ValueError, UnicodeDecodeError):
        return "unreadable %s marker file" % TESTENV_MARKER
    if "environment=test" not in lines:
        return "marker file does not declare environment=test"
    return ""


def cmd_testenv(path):
    err = testenv_error(path)
    out({"ok": not err, "detail": err or "valid test environment"})


def cmd_effect(action, target, testenv, command_id):
    err = testenv_error(testenv)
    if err:
        return out({"ok": False, "detail": err})
    if action not in ksl.ACTIONS or not ksl.valid_id(target) or not ksl.valid_id(command_id):
        return out({"ok": False, "detail": "invalid effect arguments"})
    kind_dir = os.path.join(os.path.realpath(testenv), ksl.ACTIONS[action])
    try:
        if not os.path.isdir(kind_dir):
            os.mkdir(kind_dir, 0o700)
        tmp = os.path.join(kind_dir, "." + target + ".tmp")
        final = os.path.join(kind_dir, target + ".contained")
        body = json.dumps({"action": action, "target_id": target, "command_id": command_id,
                           "contained_at": ksl.format_ts(now_utc())}, sort_keys=True)
        with open(tmp, "w") as f:
            f.write(body + "\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, final)
    except OSError as exc:
        return out({"ok": False, "detail": "marker write failed: %s" % exc.strerror})
    out({"ok": True, "detail": "marker written", "marker": os.path.join(ksl.ACTIONS[action], target + ".contained")})


def cmd_event(path):
    try:
        raw = json.loads(read_text(path, ksl.MAX_EVENT_BYTES))
    except (OSError, ValueError, UnicodeDecodeError) as exc:
        return out({"ok": False, "error": "invalid_event", "detail": str(exc)[:200]})
    event, err = ksl.normalize_event(raw)
    if err:
        return out({"ok": False, "error": "invalid_event", "detail": err})
    targets = set()
    authz, loaded, code, _ = load_config()
    if not code:
        targets = loaded
    record = ksl.evaluate_event(event, targets)
    record["recorded_at"] = ksl.format_ts(now_utc())
    out({"ok": True, "record": record})


def cmd_record():
    e = os.environ
    try:
        cmd = json.loads(e.get("KS_REC_COMMAND", "{}") or "{}")
    except ValueError:
        cmd = {}
    out({
        "record_type": "command",
        "command_id": cmd.get("command_id", ""),
        "event_id": cmd.get("event_ref", ""),
        "action": cmd.get("action", ""),
        "target_id": cmd.get("target_id", ""),
        "environment": cmd.get("environment", ""),
        "issuer": cmd.get("issuer", ""),
        "origin": cmd.get("origin", ""),
        "detection_reason": cmd.get("reason", ""),
        "risk": "OPERATOR_ASSERTED",
        "recommended_action": cmd.get("action", ""),
        "decision": e.get("KS_REC_DECISION", ""),
        "code": e.get("KS_REC_CODE", ""),
        "detail": e.get("KS_REC_DETAIL", "")[:400],
        "mode": e.get("KS_REC_MODE", ""),
        "execution_result": e.get("KS_REC_RESULT", ""),
        "recorded_at": ksl.format_ts(now_utc()),
    })


def main(argv):
    if len(argv) < 2:
        out({"ok": False, "detail": "usage"})
        return 2
    sub, args = argv[1], argv[2:]
    if sub == "decide" and len(args) == 1:
        cmd_decide(args[0])
    elif sub == "testenv" and len(args) == 1:
        cmd_testenv(args[0])
    elif sub == "effect" and len(args) == 4:
        cmd_effect(*args)
    elif sub == "event" and len(args) == 1:
        cmd_event(args[0])
    elif sub == "record" and not args:
        cmd_record()
    else:
        out({"ok": False, "detail": "usage"})
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
