"""security/ai_defense/ai_defense_loop.py -- WAIO v2 Local AI Autonomous
Defense Loop: analysis and patch PROPOSALS, never actions.

  analyze OUT.json --input DIR [--input DIR]... [--backend rule|command]
      Summarizes kill-switch / SND / decoy records, proposes root-cause
      hypotheses, tests and advisory next steps. Backend "rule" is
      deterministic (default, used by tests). Backend "command" pipes a
      bounded, redacted prompt to AI_DEFENSE_LLM_CMD (argv, no shell;
      e.g. a local llama-cli) and treats its stdout as UNTRUSTED TEXT.
  verify-patch PATCH --repo DIR --tests "t1.sh t2.sh" [--base REF]
               [--propose --branch NAME --approval-gate PATH]
      Policy-checks the diff, applies it in a throwaway `git worktree`
      (never the caller's tree), runs syntax checks + the named tests
      there, then always deletes that worktree ("rollback"). With
      --propose and a VERIFIED result, registers it with the WAIO
      Self-Development Engine Human Approval Gate (PENDING; this file
      cannot approve).
  deployable PATCH --approval-id ID --approval-gate PATH
      Answers yes only if that approval record is APPROVED and its
      diff_hash is this exact patch. Deploys nothing.

HARD LIMITS (Phase 6 items 2, 5, 7), enforced in code:
  - nothing an AI returns is executed, evaluated, or passed to a shell;
    only a fixed set of ADVISORY_ACTIONS survives validation, and even
    those are text for a human. Production-shaped requests (shutdown,
    containment, key rotation, DNS, deploy, shell) are listed under
    rejected_actions with requires_human_approval.
  - no kill-switch, Guardian, Cloudflare or key-management code path
    exists here; this file never signs anything (it holds no key).
  - a patch touching dependency manifests or adding a non-stdlib
    import is refused (no automatic dependency/model updates).
"""

import datetime
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile

SCHEMA = "waio.ai_defense.proposal.v1"
ADVISORY_ACTIONS = frozenset({
    "monitor", "collect_more_evidence", "suggest_operator_review", "suggest_test_containment",
    "add_detection_rule", "add_regression_test", "review_config",
})
MAX_TEXT, MAX_LIST, MAX_PATCH = 2000, 10, 64 * 1024
LLM_TIMEOUT, TEST_TIMEOUT = 120, 600

_SECRET = re.compile(r"(sk-[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY-----|"
                     r"gh[pousr]_[A-Za-z0-9]{30,}|WAIO-CANARY-[A-Za-z0-9_-]+|"
                     r"(?i:(api[_-]?key|passw(or)?d|secret|token|bearer)\s*[:=]\s*\S{6,}))")
_NETID = re.compile(r"\b\d{1,3}(\.\d{1,3}){3}\b")

# patch policy
ALLOWED_PATH = re.compile(r"^(security|tests|dashboard)/[A-Za-z0-9_./-]+$")
DEPENDENCY_FILES = re.compile(r"(^|/)(package(-lock)?\.json|requirements[^/]*\.txt|Pipfile(\.lock)?|"
                              r"pyproject\.toml|setup\.(py|cfg)|go\.(mod|sum)|Gemfile(\.lock)?|Cargo\.(toml|lock))$")
FORBIDDEN_ADDED = re.compile(r"\b(curl|wget|scp|sudo|launchctl|cloudflared|pfctl|networksetup|osascript|eval)\b|"
                             r"\bssh\s|\bnc\s|rm\s+-rf\s+/|git\s+push|find-generic-password|base64\s+-d")
LOCAL_MODULE = re.compile(r"^(\w+_lib|killswitch_\w+|behavior_\w+|zkeys_\w+)$")
STDLIB_HINT = frozenset(getattr(sys, "stdlib_module_names", ())) or frozenset({
    "argparse", "base64", "collections", "datetime", "functools", "hashlib", "hmac", "http", "io",
    "itertools", "json", "math", "os", "pathlib", "random", "re", "secrets", "shlex", "shutil",
    "socket", "socketserver", "stat", "string", "subprocess", "sys", "tempfile", "threading", "time",
    "typing", "unittest", "urllib", "uuid"})


def now_ts():
    return os.environ.get("AI_DEFENSE_NOW") or datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def redact(text, limit=MAX_TEXT):
    s = _SECRET.sub("[REDACTED]", str(text))
    s = _NETID.sub("[NETID]", s)
    return " ".join(s.split())[:limit]


# ------------------------------------------------------------------
# analyze
# ------------------------------------------------------------------

def load_records(dirs):
    recs = []
    for d in dirs:
        for root, _ds, names in os.walk(d):
            for n in sorted(names):
                if not n.endswith(".json"):
                    continue
                try:
                    with open(os.path.join(root, n)) as f:
                        r = json.loads(f.read(65536))
                except (OSError, ValueError):
                    continue
                if isinstance(r, dict):
                    recs.append({k: (redact(v, 300) if isinstance(v, str) else v) for k, v in r.items()
                                 if k in ("event_id", "command_id", "type", "rule", "risk", "severity", "source",
                                          "execution_result", "code", "action", "target_id", "target_ref",
                                          "detection_reason", "summary", "observed_at", "recorded_at", "principal")})
    return recs


_HYPOTHESIS = {
    "auth_failure_burst": "password spraying / credential stuffing against the account",
    "impossible_travel": "session token or credential used from a second location",
    "new_region_login": "credential use from an unfamiliar location (or undeclared travel)",
    "off_hours_login": "account used outside its normal pattern (or an undeclared schedule change)",
    "privilege_escalation": "unexpected grant of an elevated role",
    "bulk_data_access": "data staging / exfiltration, or an undeclared bulk job",
    "mfa_change_unfamiliar": "attacker persistence via MFA reset",
    "decoy_access": "reconnaissance: something touched a decoy that no legitimate user should reach",
}


def rule_backend(recs):
    kinds = {}
    for r in recs:
        k = r.get("rule") or r.get("type") or r.get("execution_result") or "unknown"
        kinds[k] = kinds.get(k, 0) + 1
    high = [r for r in recs if str(r.get("risk", "")).upper() in ("HIGH", "CRITICAL") or r.get("severity") in ("high", "critical")]
    failed = [r for r in recs if str(r.get("execution_result", "")).startswith("FAILED")]
    actions = [{"action": "monitor", "rationale": "keep collecting; no detection is acted on by this loop"}]
    if high:
        actions.append({"action": "suggest_operator_review", "rationale": "%d HIGH/CRITICAL record(s) need a human decision" % len(high)})
        actions.append({"action": "suggest_test_containment", "rationale": "operator may sign a test-environment kill-switch command"})
    if failed:
        actions.append({"action": "collect_more_evidence", "rationale": "%d containment attempt(s) FAILED; inspect the gate status" % len(failed)})
    return {
        "summary": "%d record(s): %s" % (len(recs), ", ".join("%s=%d" % kv for kv in sorted(kinds.items()))),
        "root_cause_hypotheses": [_HYPOTHESIS[k] for k in sorted(kinds) if k in _HYPOTHESIS],
        "proposed_tests": ["regression case replaying %s through the detector and the gate" % k for k in sorted(kinds) if k in _HYPOTHESIS],
        "recommended_actions": actions,
    }


def command_backend(recs):
    cmd = os.environ.get("AI_DEFENSE_LLM_CMD", "")
    if not cmd:
        raise RuntimeError("AI_DEFENSE_LLM_CMD is not set")
    prompt = ("You are a defensive security analyst. Reply with ONE JSON object with keys summary, "
              "root_cause_hypotheses, proposed_tests, recommended_actions (each {action, rationale}; "
              "action one of %s). Records:\n%s" % (sorted(ADVISORY_ACTIONS), json.dumps(recs[:200], sort_keys=True)))
    proc = subprocess.run(shlex.split(cmd), input=prompt[:60000], capture_output=True, text=True,
                          timeout=LLM_TIMEOUT, shell=False)
    return proc.stdout


def extract_json(text):
    if isinstance(text, dict):
        return text
    m = re.search(r"\{.*\}", text or "", re.S)
    if not m:
        return None
    try:
        obj = json.loads(m.group(0))
    except ValueError:
        return None
    return obj if isinstance(obj, dict) else None


def validate_ai_output(raw):
    """Untrusted model output -> the only shape a proposal may carry."""
    obj = extract_json(raw)
    if obj is None:
        return {"valid": False, "summary": "", "root_cause_hypotheses": [], "proposed_tests": [],
                "recommended_actions": [], "rejected_actions": [], "dropped_fields": [], "error": "no JSON object in model output"}
    allowed = {"summary", "root_cause_hypotheses", "proposed_tests", "recommended_actions"}
    res = {"valid": True, "dropped_fields": sorted(k for k in obj if k not in allowed)}
    res["summary"] = redact(obj.get("summary", "")) if isinstance(obj.get("summary"), str) else ""
    for k in ("root_cause_hypotheses", "proposed_tests"):
        v = obj.get(k)
        res[k] = [redact(x, 500) for x in v[:MAX_LIST] if isinstance(x, str)] if isinstance(v, list) else []
    acts, rejected = [], []
    for a in (obj.get("recommended_actions") or [])[:MAX_LIST] if isinstance(obj.get("recommended_actions"), list) else []:
        name = a.get("action") if isinstance(a, dict) else a
        name = str(name)[:80]
        why = redact(a.get("rationale", ""), 300) if isinstance(a, dict) else ""
        if name in ADVISORY_ACTIONS:
            acts.append({"action": name, "rationale": why})
        else:
            rejected.append({"action": redact(name, 80), "rationale": why, "status": "REJECTED_NOT_ADVISORY",
                             "requires_human_approval": True, "executed": False})
    res["recommended_actions"], res["rejected_actions"] = acts, rejected
    return res


def cmd_analyze(out_path, inputs, backend):
    recs = load_records(inputs)
    digest = hashlib.sha256(json.dumps(recs, sort_keys=True).encode()).hexdigest()
    error = ""
    try:
        raw = rule_backend(recs) if backend == "rule" else command_backend(recs)
    except (RuntimeError, OSError, subprocess.SubprocessError) as exc:
        raw, error = "", "backend failed: %s" % exc
    v = validate_ai_output(raw)
    proposal = dict(v, schema=SCHEMA, proposal_id="aid-" + digest[:16], created_at=now_ts(), backend=backend,
                    records=len(recs), input_digest="sha256:" + digest, execution="NONE",
                    requires_human_approval=True, backend_error=error)
    with open(out_path, "w") as f:
        json.dump(proposal, f, sort_keys=True, indent=1)
    print(json.dumps({"ok": v["valid"] and not error, "proposal_id": proposal["proposal_id"],
                      "records": len(recs), "recommended": [a["action"] for a in v["recommended_actions"]],
                      "rejected": [a["action"] for a in v["rejected_actions"]], "error": error or v.get("error", "")}))
    return 0


# ------------------------------------------------------------------
# verify-patch
# ------------------------------------------------------------------

def patch_policy(text):
    """Returns (touched_paths, problems)."""
    problems, paths = [], []
    if len(text.encode()) > MAX_PATCH:
        return [], ["patch exceeds %d bytes" % MAX_PATCH]
    for line in text.splitlines():
        if re.match(r"^(rename (from|to)|copy (from|to)) |^(new file|new|old|deleted file) mode 120000|^GIT binary patch", line):
            problems.append("rename/copy/symlink/binary hunks are not accepted: %s" % redact(line, 80))
            continue
        m = re.match(r"^\+\+\+ (?:b/)?(\S+)", line) or re.match(r"^--- (?:a/)?(\S+)", line)
        if m and m.group(1) != "/dev/null":
            if m.group(1) not in paths:
                paths.append(m.group(1))
            continue
        if line.startswith("+") and not line.startswith("+++"):
            added = line[1:]
            if FORBIDDEN_ADDED.search(added):
                problems.append("forbidden command in added line: %s" % redact(added, 120))
            imp = re.match(r"\s*(?:from\s+([A-Za-z_][\w]*)|import\s+([A-Za-z_][\w]*))", added)
            if imp:
                mod = imp.group(1) or imp.group(2)
                if mod not in STDLIB_HINT and not LOCAL_MODULE.match(mod):
                    problems.append("non-stdlib import '%s' (dependency changes need a human)" % mod)
    if not paths:
        problems.append("patch touches no files")
    for p in paths:
        if ".." in p.split("/") or not ALLOWED_PATH.match(p):
            problems.append("path outside security/, tests/, dashboard/: %s" % p)
        if DEPENDENCY_FILES.search(p):
            problems.append("dependency manifest change: %s" % p)
    return paths, problems


_SANDBOX_OK = None


def sandbox_usable():
    """sandbox-exec present AND able to apply a profile here (it cannot
    nest inside another sandbox). Cached per process."""
    global _SANDBOX_OK
    if _SANDBOX_OK is None:
        _SANDBOX_OK = False
        if shutil.which("sandbox-exec"):
            try:
                _SANDBOX_OK = subprocess.run(["sandbox-exec", "-p", "(version 1)(allow default)", "true"],
                                             capture_output=True, timeout=10).returncode == 0
            except (OSError, subprocess.SubprocessError):
                _SANDBOX_OK = False
    return _SANDBOX_OK


def _sandbox_profile(write_root):
    """macOS sandbox for running AI-written code: no network at all
    (loopback included), file writes only under write_root and /dev."""
    root = os.path.realpath(write_root).replace('"', "")
    return ('(version 1)(allow default)(deny network*)(deny file-write*)'
            '(allow file-write* (subpath "%s") (subpath "/dev"))' % root)


def _run(argv, cwd, timeout=TEST_TIMEOUT, sandbox_root=None):
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    if sandbox_root is not None:
        tmpdir = os.path.join(sandbox_root, "tmp")
        os.makedirs(tmpdir, exist_ok=True)
        env["TMPDIR"] = tmpdir
        if sandbox_usable():
            argv = ["sandbox-exec", "-p", _sandbox_profile(sandbox_root)] + argv
    try:
        p = subprocess.run(argv, cwd=cwd, capture_output=True, text=True, timeout=timeout, shell=False, env=env)
        return p.returncode, (p.stdout + p.stderr)[-1500:]
    except subprocess.TimeoutExpired:
        return 124, "timeout after %ds" % timeout


def cmd_verify_patch(patch_path, repo, tests, base, propose, branch, gate):
    with open(patch_path) as f:
        text = f.read()
    paths, problems = patch_policy(text)
    result = {"schema": "waio.ai_defense.patch_verification.v1", "patch_sha256": hashlib.sha256(text.encode()).hexdigest(),
              "touched_paths": paths, "policy_problems": problems, "static": [], "tests": [],
              "worktree_removed": None, "caller_tree_modified": False}
    before = _run(["git", "status", "--porcelain"], repo, 60)[1]
    if problems:
        result["verdict"] = "REJECTED_BY_POLICY"
        return _finish(result)
    if os.environ.get("AI_DEFENSE_REQUIRE_SANDBOX") == "1" and not sandbox_usable():
        result["verdict"] = "SANDBOX_UNAVAILABLE"
        return _finish(result)
    tmp = tempfile.mkdtemp(prefix="ai-defense-wt-")
    wt = os.path.join(tmp, "wt")
    try:
        rc, out = _run(["git", "-C", repo, "worktree", "add", "--detach", wt, base], repo, 120)
        if rc != 0:
            result["verdict"], result["detail"] = "WORKTREE_FAILED", out
            return _finish(result)
        rc, out = _run(["git", "apply", "--whitespace=nowarn", os.path.abspath(patch_path)], wt, 60)
        if rc != 0:
            result["verdict"], result["detail"] = "APPLY_FAILED", out
            return _finish(result)
        ok = True
        for p in paths:
            full = os.path.join(wt, p)
            if not os.path.isfile(full):
                continue
            if p.endswith(".sh"):
                rc, out = _run(["bash", "-n", full], wt, 60, sandbox_root=tmp)
            elif p.endswith(".py"):
                rc, out = _run([sys.executable, "-c", "import ast,sys; ast.parse(open(sys.argv[1]).read())", full], wt, 60,
                               sandbox_root=tmp)
            else:
                continue
            result["static"].append({"path": p, "ok": rc == 0, "output": out[-300:]})
            ok = ok and rc == 0
            if p.endswith(".sh") and shutil.which("shellcheck"):
                rc, out = _run(["shellcheck", "-S", "error", full], wt, 120, sandbox_root=tmp)
                result["static"].append({"path": p, "tool": "shellcheck", "ok": rc == 0, "output": out[-300:]})
                ok = ok and rc == 0
        result["sandbox"] = "sandbox-exec: no network, writes only in the temp worktree" if sandbox_usable() \
            else "NONE: sandbox-exec missing or unusable here; worktree isolation only (tests run with the caller's privileges)"
        if not shutil.which("shellcheck"):
            result["static_note"] = "shellcheck not installed; bash -n / ast.parse only"
        for t in tests:
            if not ALLOWED_PATH.match(t) or not t.startswith("tests/"):
                result["tests"].append({"test": t, "ok": False, "output": "refused: tests must be under tests/"})
                ok = False
                continue
            rc, out = _run(["bash", t], wt, sandbox_root=tmp)
            result["tests"].append({"test": t, "ok": rc == 0, "rc": rc, "output": out[-600:]})
            ok = ok and rc == 0
        result["verdict"] = "VERIFIED" if ok else "FAILED"
    finally:
        rc, _ = _run(["git", "-C", repo, "worktree", "remove", "--force", wt], repo, 120)
        shutil.rmtree(tmp, ignore_errors=True)
        _run(["git", "-C", repo, "worktree", "prune"], repo, 60)
        result["worktree_removed"] = not os.path.exists(wt)
        result["caller_tree_modified"] = _run(["git", "status", "--porcelain"], repo, 60)[1] != before
    if result["verdict"] == "FAILED":
        result["rollback"] = "isolated worktree discarded; caller's tree untouched"
    if propose and result["verdict"] == "VERIFIED":
        argv = ["bash", gate, "propose", "merge_to_develop", "develop", branch, "ai_defense_loop", "--diff-file",
                os.path.abspath(patch_path)]
        for p in paths:
            argv += ["--path", p]
        rc, out = _run(argv, _gate_root(gate), 120)
        result["approval"] = extract_json(out) or {"ok": False, "raw": out[-300:]}
    return _finish(result)


def _gate_root(gate):
    """dev_approval_gate.sh imports its library relative to the CWD, so
    it must run from its own repository root (security/self_dev/..)."""
    return os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(gate))))


def _finish(result):
    print(json.dumps(result, sort_keys=True))
    return 0 if result.get("verdict") == "VERIFIED" else 1


# The self_dev gate's own identity check is a small denylist with no
# proposer != approver rule (ARCHITECTURE.md Phase 107 finding), so this
# loop's own proposals ("ai_defense_loop") could be approved under that
# same name. deployable refuses that independently of the gate.
AI_APPROVER_PATTERN = re.compile(r"(?i)(^|[-_.])(ai|llm|bot|agent|claude|gpt|qwen|llama|takomachi|waio|auto\w*|"
                                 r"ai_defense\w*|assistant|model|system|ci)([-_.]|$)")


def approver_acceptable(decided_by, proposed_by):
    if not decided_by:
        return False, "no approver recorded"
    if decided_by == proposed_by:
        return False, "approver is the proposer (self-approval)"
    if AI_APPROVER_PATTERN.search(decided_by):
        return False, "approver identity looks non-human"
    allow = [x.strip() for x in os.environ.get("AI_DEFENSE_APPROVER_ALLOWLIST", "").split(",") if x.strip()]
    if allow and decided_by not in allow:
        return False, "approver not in AI_DEFENSE_APPROVER_ALLOWLIST"
    return True, "ok (identity is a recorded claim, not authenticated)"


def cmd_deployable(patch_path, approval_id, gate, repo):
    with open(patch_path, "rb") as f:
        digest = "sha256:" + hashlib.sha256(f.read()).hexdigest()
    rc, out = _run(["bash", gate, "status", approval_id], _gate_root(gate), 60)
    st = extract_json(out) or {}
    rec = st.get("record") if isinstance(st.get("record"), dict) else {}
    status = st.get("effective_status") or rec.get("status")
    decided_by = str((rec.get("decision") or {}).get("decided_by") or "")
    approver_ok, why = approver_acceptable(decided_by, str(rec.get("proposed_by") or ""))
    ok = status == "APPROVED" and rec.get("diff_hash") == digest and approver_ok
    print(json.dumps({"deployable": ok, "approval_status": status, "diff_matches": rec.get("diff_hash") == digest,
                      "approver_acceptable": approver_ok, "approver_check": why,
                      "note": "this tool never deploys; a human performs the approved action"}))
    return 0 if ok else 1


def main(argv):
    a = argv[1:]
    if len(a) >= 2 and a[0] == "analyze":
        out, inputs, backend, i = a[1], [], "rule", 2
        while i < len(a):
            if a[i] == "--input" and i + 1 < len(a):
                inputs.append(a[i + 1])
            elif a[i] == "--backend" and i + 1 < len(a) and a[i + 1] in ("rule", "command"):
                backend = a[i + 1]
            else:
                break
            i += 2
        else:
            return cmd_analyze(out, inputs, backend)
    if len(a) >= 2 and a[0] in ("verify-patch", "deployable"):
        opts, flags, i = {}, set(), 2
        while i < len(a):
            if a[i] == "--propose":
                flags.add("propose")
                i += 1
            elif a[i] in ("--repo", "--tests", "--base", "--branch", "--approval-gate", "--approval-id") and i + 1 < len(a):
                opts[a[i]] = a[i + 1]
                i += 2
            else:
                break
        else:
            repo = opts.get("--repo", os.getcwd())
            gate = opts.get("--approval-gate", os.path.join(repo, "security", "self_dev", "dev_approval_gate.sh"))
            if a[0] == "verify-patch":
                return cmd_verify_patch(a[1], repo, opts.get("--tests", "").split(), opts.get("--base", "HEAD"),
                                        "propose" in flags, opts.get("--branch", "ai-defense-patch"), gate)
            if "--approval-id" in opts:
                return cmd_deployable(a[1], opts["--approval-id"], gate, repo)
    print("usage: analyze OUT --input DIR... [--backend rule|command] | verify-patch PATCH --repo DIR --tests 'T...' "
          "[--base REF] [--propose --branch B] [--approval-gate G] | deployable PATCH --approval-id ID [--approval-gate G]",
          file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
