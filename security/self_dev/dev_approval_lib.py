"""security/self_dev/dev_approval_lib.py -- WAIO Self-Development Engine
Human Approval Gate (library only): pure functions implementing the
checks a human-operated CLI (security/self_dev/dev_approval_gate.sh)
uses before a privileged self-development operation (a merge into
master/develop, a production deploy, a service shutdown, a
containment action, or a permission/security-policy change) may be
recorded as approved.

SCOPE, STATED NARROWLY (same discipline as
security/red_alert/containment_approval_lib.py, this module's own
direct architectural sibling -- read that file first if this one is
unfamiliar; every design choice below is explained relative to it,
not reinvented from scratch):

  1. PURE FUNCTIONS ONLY. No I/O, no subprocess, no os.system/os.popen/
     os.exec*, no network access, no file reads/writes, no
     security/lib.sh audit_log() call, and no Control-Plane
     integration of any kind (no security/guardian.sh,
     security/ducopa.sh, git, gh, cron, launchd, SSH, firewall, or
     network config touched or named as a call target anywhere in
     this file's ACTUAL code). Every function takes already-loaded
     data (dicts, strings, datetimes) and returns a plain dict/bool/
     str -- same convention as every other `_lib.py` in this
     repository.
  2. NO EXECUTION CAPABILITY EXISTS IN THIS FILE, AND NEVER WILL.
     Every "allowed: True" result below answers the single, narrow
     question "may a human record this approval decision", never
     "perform this operation" -- there is no function here that
     merges a branch, pushes a commit, deploys anything, shuts down a
     service, or calls any WAIO containment tool. A human reading an
     APPROVED record is the one who, separately, by hand, runs
     `git merge`/`gh pr merge`/a deploy script/Guardian's own
     intervention wrapper -- exactly the same "propose, never
     dispose" boundary decision_engine_lib.py and
     containment_approval_lib.py both already state for their own
     domains.
  3. SELF-APPROVAL IS STRUCTURALLY IMPOSSIBLE, NOT MERELY DISCOURAGED.
     There is no function in this file that both classifies/proposes
     an operation AND records an approval for it -- `classify_operation()`
     and `evaluate_approval()` are entirely separate call paths with no
     shared mutable state (this file holds no state at all), so no
     code path exists by which a proposal-generation step could also
     approve its own proposal. `validate_approver_identity()` below
     additionally rejects a small, explicit denylist of
     obviously-non-human identity strings (defense in depth, NOT proof
     of humanity -- see that function's own docstring).
  4. FAIL-CLOSED ON AMBIGUITY, EVERYWHERE. `classify_operation()`
     defaults an unrecognized operation name to PRIVILEGED, never
     AUTOMATIC. A malformed/missing field anywhere in this file reads
     as the MORE RESTRICTIVE answer, never guessed toward permissiveness.

WHY THIS FILE EXISTS: WAIO's own self-development workflow (an AI
agent analyzing this codebase, proposing changes, developing them on
an isolated branch, testing them, and preparing a PR) is already
possible using WAIO's existing tooling (git, gh, the test suites) --
nothing about THAT process needed new code. What was missing was the
GOVERNANCE layer: a structural, testable distinction between
operations that may proceed automatically within already-approved
boundaries (read-only analysis, improvement proposals, isolated-branch
commits, PR preparation) and operations that require a human's
explicit, change-bound authorization before they happen at all
(merging into master or develop, production deployment, service
shutdown, containment actions, permission/security-policy changes).
This file is that governance layer, and nothing more.

APPROVER IDENTITY IS NOT AUTHENTICATION (explicit, load-bearing,
non-negotiable, identical posture to
containment_approval_lib.py's own section of the same name):
validate_approver_identity() below checks only that a non-empty
identity string was SUPPLIED by the caller, AND that it is not one of
a small set of strings that obviously are not a human name (see
AI_IDENTITY_DENYLIST below). It never proves who actually typed a
command. Every result this function returns carries
`authenticated: False`, always, specifically so a future caller can
never mistake "identity present and not an obvious AI sentinel" for
"identity proven."

CHANGE-SET BINDING (the "any material change invalidates the previous
approval" requirement, stated in code): compute_change_hash() hashes a
canonical JSON form of {operation, target_branch, head_ref,
touched_paths (sorted), diff_hash, risk_tier} -- the SAME
sha256-over-canonical-JSON technique
containment_approval_lib.py's own compute_decision_report_hash() uses
for Decision Records, applied here to a proposed change set instead.
change_intact() is this file's own evidence_intact() equivalent: any
difference anywhere in that structure -- a different file touched, a
different diff, a different declared risk tier -- produces a
different hash, and an approval recorded against the old hash is
refused, fail-closed, exactly like a tampered Decision Record.

No I/O in this module.
"""

import datetime
import hashlib
import json
import re

# -----------------------------------------------------------------------
# Section 0: operation classification (PRIVILEGED vs AUTOMATIC)
# -----------------------------------------------------------------------

# Operations an AI-driven self-development step may take WITHOUT a
# human approval record -- read-only analysis, a written proposal, a
# commit on an isolated branch (never master/develop directly -- see
# classify_operation()'s own target_branch check), and preparing
# (opening, not merging) a pull request. Logged for provenance by the
# CLI wrapper regardless, but never gated on human approval.
AUTOMATIC_OPERATIONS = frozenset({
    "code_analysis",
    "improvement_proposal",
    "isolated_branch_commit",
    "pr_preparation",
})

# Operations that ALWAYS require an explicit, change-bound human
# approval record before a human separately performs them by hand.
# This set is the direct, literal encoding of this phase's own
# mandatory rule #3 ("Explicit human authorization required").
PRIVILEGED_OPERATIONS = frozenset({
    "merge_to_master",
    "merge_to_develop",
    "production_deploy",
    "service_shutdown",
    "containment_action",
    "permission_change",
    "security_policy_change",
})

# A touched path matching ANY of these forces PRIVILEGED regardless of
# the operation's own stated name -- this is the concrete mechanism
# behind "the agent may not disable its own approval gate": a proposal
# labeled isolated_branch_commit that happens to edit this very gate's
# own files, Guardian, DuCoPA, a real (non-.example) local config file,
# or CI/branch-protection configuration is escalated, never trusted at
# face value. Patterns are matched against forward-slash-normalized
# relative paths with re.search (substring-anchored, not full-path
# anchored), deliberately broad rather than narrow.
PRIVILEGED_PATH_PATTERNS = (
    r"^security/self_dev/",
    r"^security/guardian",
    r"^security/ducopa\.sh$",
    r"^security/recovery_engine\.sh$",
    r"^security/recover\.sh$",
    r"\.conf$",            # real local config (the repo's own .conf.example files are templates, not config -- see _is_example_file())
    r"^\.github/",
    r"^workers/.*\.json$", # per-host real credentials-adjacent metadata (gitignored; .json.example are templates)
)

# Branches this gate treats as requiring PRIVILEGED classification for
# ANY merge-shaped operation targeting them, matching this repo's own
# documented convention (feature/fix branches -> develop; a dedicated
# sync branch -> master; nothing merges directly into either without
# review).
PROTECTED_TARGET_BRANCHES = frozenset({"master", "develop"})


def _is_example_file(path):
    """A `.conf.example`/`.json.example` template is NOT real local
    config -- see README.md's own "Setup" section, which documents
    these `.example` files as the committed templates, and the real
    files as gitignored. PRIVILEGED_PATH_PATTERNS' own `\\.conf$`/
    `\\.json$` patterns match the SUFFIX only, so this check exists
    specifically to exempt a `*.example` file from that escalation --
    editing a template is not editing real local config.
    """
    return isinstance(path, str) and path.endswith(".example")


def classify_operation(operation, target_branch=None, touched_paths=None):
    """Returns {"risk_tier": "PRIVILEGED"|"AUTOMATIC", "reasons": [str, ...]}.

    Fail-closed order of checks, each one capable of escalating to
    PRIVILEGED on its own (never capable of de-escalating):

      1. `operation` not in AUTOMATIC_OPERATIONS at all (including an
         unrecognized/misspelled name) -> PRIVILEGED. An operation
         this file has never heard of is never guessed into the
         permissive category.
      2. `operation` in PRIVILEGED_OPERATIONS explicitly -> PRIVILEGED
         (stated for clarity; already implied by #1, since
         PRIVILEGED_OPERATIONS and AUTOMATIC_OPERATIONS are disjoint).
      3. `target_branch` is a member of PROTECTED_TARGET_BRANCHES AND
         `operation` is itself a merge-shaped operation
         ("isolated_branch_commit" with target_branch set, or any
         "merge_to_*" operation) -> PRIVILEGED, even if the operation
         name alone would have read as AUTOMATIC. This is the literal
         "do not modify master directly" / "work only on a dedicated
         feature branch" rule, enforced here rather than only in a
         script header comment.
      4. Any entry in `touched_paths` matches a PRIVILEGED_PATH_PATTERNS
         pattern (and is not a `.example` template -- see
         _is_example_file()) -> PRIVILEGED, regardless of what
         `operation` or `target_branch` said. This is the self-gate-
         protection mechanism described in this module's own header.

    `touched_paths` malformed/missing (not a list) is treated as an
    empty list -- it cannot ESCALATE anything it never saw, but
    neither can it be used to claim a false AUTOMATIC: checks #1-#3
    still apply independently.
    """
    reasons = []

    if not isinstance(touched_paths, list):
        touched_paths = []

    if operation not in AUTOMATIC_OPERATIONS:
        reasons.append(
            f"operation '{operation}' is not in AUTOMATIC_OPERATIONS "
            "(either explicitly PRIVILEGED or unrecognized -- fail-closed)"
        )
        return {"risk_tier": "PRIVILEGED", "reasons": reasons}

    if (
        isinstance(target_branch, str)
        and target_branch in PROTECTED_TARGET_BRANCHES
        and operation in ("isolated_branch_commit",)
    ):
        reasons.append(
            f"target_branch '{target_branch}' is a protected branch -- "
            "a commit-shaped operation must never target it directly"
        )
        return {"risk_tier": "PRIVILEGED", "reasons": reasons}

    for path in touched_paths:
        if not isinstance(path, str) or _is_example_file(path):
            continue
        for pattern in PRIVILEGED_PATH_PATTERNS:
            if re.search(pattern, path):
                reasons.append(
                    f"touched path '{path}' matches protected pattern "
                    f"'{pattern}' -- escalated regardless of operation"
                )
                return {"risk_tier": "PRIVILEGED", "reasons": reasons}

    reasons.append(f"operation '{operation}' is automatic and no escalation check fired")
    return {"risk_tier": "AUTOMATIC", "reasons": reasons}


def requires_human_approval(risk_tier):
    """Only PRIVILEGED implies an actual human-gated authorization step
    -- AUTOMATIC proceeds without one (still logged by the CLI wrapper
    for provenance, never gated on it). Any other value (malformed
    input) is treated as requiring approval, fail-closed.
    """
    return risk_tier != "AUTOMATIC"


# -----------------------------------------------------------------------
# Section 0b: APPROVAL_ID format validation (CLI input-boundary defense)
# -----------------------------------------------------------------------

# Identical charset/fullmatch/length-cap convention to
# security/red_alert/containment_approval_lib.py's own
# validate_approval_id_format() (the proven fix for the path-traversal
# class of bug found and fixed there, commit 7983f08) -- reused here
# from the start rather than re-discovered after an audit.
_APPROVAL_ID_PATTERN = re.compile(r"[A-Za-z0-9_.-]+")
MAX_APPROVAL_ID_LENGTH = 200


def validate_approval_id_format(approval_id):
    """Pure format check for an APPROVAL_ID supplied to
    dev_approval_gate.sh's approve/reject/status verbs. Returns True
    iff approval_id is a non-empty string, at most
    MAX_APPROVAL_ID_LENGTH characters, composed ENTIRELY of
    [A-Za-z0-9_.-]. Any other input (wrong type, empty, containing
    "/", whitespace, shell metacharacters, control characters, or
    longer than the length cap) returns False -- fail-closed, never
    guessed into validity. fullmatch (not a $-anchored regex) so
    Python's own "$ matches before a trailing newline" exception can't
    slip one through.
    """
    if not isinstance(approval_id, str) or not approval_id:
        return False
    if len(approval_id) > MAX_APPROVAL_ID_LENGTH:
        return False
    return bool(_APPROVAL_ID_PATTERN.fullmatch(approval_id))


# -----------------------------------------------------------------------
# Section 1: reason validation
# -----------------------------------------------------------------------

DEFAULT_REASON_MIN_LENGTH = 20
DEFAULT_REASON_MIN_DISTINCT = 8


def validate_reason(text, min_length=DEFAULT_REASON_MIN_LENGTH,
                     min_distinct=DEFAULT_REASON_MIN_DISTINCT):
    """Approve/reject reason validator -- same two-part check (trimmed
    length, then distinct-character variety) as
    containment_approval_lib.py's own validate_reason(), duplicated
    here rather than imported (this file calls, and is called by,
    nothing in security/red_alert/ -- same loose-coupling discipline
    as every other `_lib.py` pair in this repository).

    Returns {"status": "EMPTY"|"TOO_SHORT"|"LOW_VARIETY"|"OK",
             "length": int, "distinct": int, "normalized": str}.
    Never raises on non-string input -- a non-string is treated as
    EMPTY.
    """
    if not isinstance(text, str):
        return {"status": "EMPTY", "length": 0, "distinct": 0, "normalized": ""}
    trimmed = text.strip()
    if not trimmed:
        return {"status": "EMPTY", "length": 0, "distinct": 0, "normalized": ""}
    length = len(trimmed)
    distinct = len(set(trimmed))
    if length < min_length:
        return {"status": "TOO_SHORT", "length": length, "distinct": distinct, "normalized": trimmed}
    if distinct < min_distinct:
        return {"status": "LOW_VARIETY", "length": length, "distinct": distinct, "normalized": trimmed}
    return {"status": "OK", "length": length, "distinct": distinct, "normalized": trimmed}


# -----------------------------------------------------------------------
# Section 2: approver identity (explicitly NOT authentication, PLUS a
# denylist making self-approval structurally harder, not just
# discouraged)
# -----------------------------------------------------------------------

# Obviously-non-human identity strings, case-insensitive exact match
# after stripping. This is DEFENSE IN DEPTH, NOT PROOF OF HUMANITY --
# a human could still type a different name while an AI agent is the
# one actually invoking the CLI. It exists because "Never allow an
# AI-generated change to approve itself" deserves a concrete code
# check, not prose alone, even though no string-based check can ever
# be a complete answer to that requirement on its own (see this
# module's own header, Section 3, and validate_approver_identity()'s
# own docstring for the honest limits of this check).
AI_IDENTITY_DENYLIST = frozenset({
    "claude", "ai", "assistant", "bot", "automated", "automation",
    "system", "ci", "github-actions", "self_dev", "self-dev", "agent",
})


def validate_approver_identity(identity, allowlist=None):
    """Checks PRESENCE of a non-empty identity string, REJECTS a small
    denylist of obviously-non-human identity strings
    (AI_IDENTITY_DENYLIST above, case-insensitive), and, OPTIONALLY (if
    `allowlist` -- an iterable of permitted identity strings -- is
    explicitly supplied), checks MEMBERSHIP in it.

    `authenticated` is ALWAYS False in this result, deliberately, in
    every branch -- this function NEVER proves who actually supplied
    the identity, and a caller must never treat `valid: True` as proof
    of authorization or of humanity. Same honor-system posture as
    containment_approval_lib.py's own validate_approver_identity().

    Returns {"valid": bool, "reason": str, "authenticated": False}.
    """
    if not isinstance(identity, str) or not identity.strip():
        return {"valid": False, "reason": "missing_identity", "authenticated": False}
    trimmed = identity.strip()
    if trimmed.lower() in AI_IDENTITY_DENYLIST:
        return {"valid": False, "reason": "identity_is_denylisted_non_human_sentinel", "authenticated": False}
    if allowlist is not None:
        try:
            in_allowlist = trimmed in allowlist
        except TypeError:
            in_allowlist = False
        if not in_allowlist:
            return {"valid": False, "reason": "identity_not_in_allowlist", "authenticated": False}
        return {"valid": True, "reason": "present_and_in_allowlist_not_authenticated", "authenticated": False}
    return {"valid": True, "reason": "present_not_denylisted_not_authenticated", "authenticated": False}


# -----------------------------------------------------------------------
# Section 3: change-set binding (evidence integrity, generalized from
# containment_approval_lib.py's own decision-report hash to a proposed
# change set instead)
# -----------------------------------------------------------------------

def compute_change_hash(change_set):
    """change_set: a dict describing the proposed operation (expected
    shape: {operation, target_branch, head_ref, touched_paths, diff_hash,
    risk_tier} -- see this module's own header). Returns a
    deterministic "sha256:<hex>" string over its canonical JSON form
    (sort_keys=True, UTF-8 encoded) -- the same value a proposal
    record's own change_hash field should store at propose time, and
    the same function a caller re-runs later against whatever change
    set is CURRENTLY proposed to detect drift. Pure computation only
    -- this function never reads a diff or a file itself; the caller
    (the CLI wrapper) is responsible for already having computed
    touched_paths/diff_hash before calling this.
    """
    canonical = json.dumps(change_set, sort_keys=True, ensure_ascii=False)
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


def change_intact(stored_hash, current_change_set):
    """stored_hash: the change_hash recorded on a proposal at propose
    time. current_change_set: the change set the caller is about to
    approve against right now. Returns True only if stored_hash
    exactly matches compute_change_hash(current_change_set) -- ANY
    difference (a different file touched, a different diff, a
    different declared risk tier, a different target branch) returns
    False. A missing/malformed stored_hash is treated as NOT intact
    (fail-closed), never as "nothing to check." This is the literal
    code implementation of "any material change invalidates the
    previous approval."
    """
    if not isinstance(stored_hash, str) or not stored_hash:
        return False
    return stored_hash == compute_change_hash(current_change_set)


# -----------------------------------------------------------------------
# Section 4: timestamps and expiry (clock always caller-injected)
# -----------------------------------------------------------------------

_TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
DEFAULT_APPROVAL_TTL_SECONDS = 24 * 60 * 60  # 24 hours, same default as the Containment Approval Gate


def parse_utc_timestamp(text):
    """Parses this pipeline's own standard UTC timestamp format
    (`%Y-%m-%dT%H:%M:%SZ`). Returns a timezone-aware (UTC)
    datetime.datetime, or None for anything that does not parse --
    never raises, so a malformed/absent timestamp can always be
    handled by the caller as "unknown", fail-closed.
    """
    if not isinstance(text, str):
        return None
    try:
        naive = datetime.datetime.strptime(text, _TIMESTAMP_FORMAT)
    except (ValueError, TypeError):
        return None
    return naive.replace(tzinfo=datetime.timezone.utc)


def format_utc_timestamp(dt):
    """Inverse of parse_utc_timestamp(). Returns None for non-datetime
    input, never raises.
    """
    if not isinstance(dt, datetime.datetime):
        return None
    return dt.strftime(_TIMESTAMP_FORMAT)


def compute_expiry(requested_at, ttl_seconds=DEFAULT_APPROVAL_TTL_SECONDS):
    """requested_at: a timezone-aware datetime.datetime. Returns
    requested_at + ttl_seconds, or None if requested_at is not a valid
    datetime -- never raises.
    """
    if not isinstance(requested_at, datetime.datetime):
        return None
    try:
        return requested_at + datetime.timedelta(seconds=ttl_seconds)
    except (OverflowError, TypeError):
        return None


def is_expired(expires_at, now):
    """FAIL-CLOSED: if EITHER argument is not a valid datetime, this
    returns True -- an unparseable or missing expiry is treated as
    ALREADY EXPIRED, never as "not expired". `now` is always
    caller-supplied (an injectable clock) -- this function never calls
    datetime.datetime.now()/utcnow() itself.
    """
    if not isinstance(expires_at, datetime.datetime) or not isinstance(now, datetime.datetime):
        return True
    return now >= expires_at


# -----------------------------------------------------------------------
# Section 5: approval state machine transition guard
# -----------------------------------------------------------------------

APPROVAL_STATUSES = ("PENDING", "APPROVED", "REJECTED", "EXPIRED")
_LEGAL_TRANSITIONS = {
    ("PENDING", "approve"): "APPROVED",
    ("PENDING", "reject"): "REJECTED",
}


def can_transition(current_status, action):
    """True only for PENDING -> approve/reject -- every other
    combination (already APPROVED/REJECTED/EXPIRED, or an unrecognized
    status/action) is illegal, covering duplicate approvals,
    re-approving a rejected record, and approving an expired one.
    """
    return (current_status, action) in _LEGAL_TRANSITIONS


def next_status(current_status, action):
    """The status current_status transitions to for action, or None if
    can_transition(current_status, action) is False. Never raises.
    """
    return _LEGAL_TRANSITIONS.get((current_status, action))


# -----------------------------------------------------------------------
# Section 6: composite evaluation (convenience orchestrator)
# -----------------------------------------------------------------------

def evaluate_approval(change_set, stored_change_hash, approver_identity,
                       now, expires_at, approval_reason=None,
                       allowlist=None,
                       reason_min_length=DEFAULT_REASON_MIN_LENGTH,
                       reason_min_distinct=DEFAULT_REASON_MIN_DISTINCT):
    """Ties every gate above together into one answer for "may this
    approval be recorded right now" -- still a PURE function (every
    input is caller-supplied; nothing is read from disk, nothing is
    executed). Returns:

        {"allowed": bool, "violations": [str, ...], "checks": {...}}

    `violations` lists every failed gate's own basis string (empty
    list iff allowed=True). `checks` carries each individual gate's
    own full result dict. Order of checks does not short-circuit --
    every gate always runs, so a caller sees every reason an approval
    would be refused, not just the first one.

    NOT-PRIVILEGED SHORT CIRCUIT: if change_set's own declared
    risk_tier is not PRIVILEGED (re-derived from change_set's own
    `operation`/`target_branch`/`touched_paths` via
    classify_operation(), never trusted as a bare pre-set field),
    no approval is required at all -- allowed=True,
    basis="not_privileged", and no other gate is evaluated (there is
    nothing here for a human to approve).

    THIS FUNCTION NEVER EXECUTES ANYTHING. "allowed: True" means only
    that every gate this file knows how to check has been satisfied by
    the data supplied -- it is not, and must never be read as, a
    command to perform any operation.
    """
    violations = []
    checks = {}

    change_set = change_set if isinstance(change_set, dict) else {}
    reclassified = classify_operation(
        change_set.get("operation"),
        target_branch=change_set.get("target_branch"),
        touched_paths=change_set.get("touched_paths"),
    )
    checks["classification"] = reclassified
    if not requires_human_approval(reclassified["risk_tier"]):
        checks["scope"] = {"allowed": True, "basis": "not_privileged"}
        return {"allowed": True, "violations": [], "checks": checks}
    checks["scope"] = {"allowed": True, "basis": "privileged_approval_in_progress"}

    identity_check = validate_approver_identity(approver_identity, allowlist=allowlist)
    checks["identity"] = identity_check
    if not identity_check["valid"]:
        violations.append(identity_check["reason"])

    intact = change_intact(stored_change_hash, change_set)
    checks["evidence"] = {"allowed": intact, "basis": "change_intact" if intact else "change_altered_or_missing"}
    if not intact:
        violations.append("change_altered_or_missing")

    expired = is_expired(expires_at, now)
    checks["expiry"] = {"allowed": not expired, "basis": "not_expired" if not expired else "expired"}
    if expired:
        violations.append("expired")

    reason_check = validate_reason(approval_reason, min_length=reason_min_length, min_distinct=reason_min_distinct)
    checks["reason"] = reason_check
    if reason_check["status"] != "OK":
        violations.append(f"reason_{reason_check['status'].lower()}")

    return {"allowed": len(violations) == 0, "violations": violations, "checks": checks}
