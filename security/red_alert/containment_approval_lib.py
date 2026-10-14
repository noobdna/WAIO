"""security/red_alert/containment_approval_lib.py -- WAIO GLOBAL RED
ALERT Phase D (library only): pure functions implementing the
human-approval checks a future containment-approval CLI would use
before a human is allowed to record an approval for a
RECOMMEND_CONTAINMENT Decision Record.

SCOPE, STATED NARROWLY (explicit user decision, this phase):
  1. Applies ONLY to Decision Records that are WAIO GLOBAL RED ALERT
     scoped -- see is_red_alert_scoped() below. decision_engine.sh,
     decision_engine_lib.py, and every other Decision Engine
     recommendation (Shadow AI / Attack Graph / SaaS ATO / plain
     Incident Learning) are UNCHANGED and UNAFFECTED by this file --
     nothing here is called by, or calls, either of those files.
  2. PURE FUNCTIONS ONLY. No I/O, no subprocess, no os.system/os.popen/
     os.exec*, no network access, no file reads/writes, no
     security/lib.sh audit_log() call, and no Control-Plane
     integration of any kind (no security/guardian.sh,
     security/ducopa.sh, cron, launchd, SSH, firewall, or network
     config touched or named as a call target anywhere in this file's
     ACTUAL code). Every function takes already-loaded data (dicts,
     strings, datetimes) and returns a plain dict/bool/str -- same
     convention as every other `_lib.py` in this pipeline
     (decision_engine_lib.py, intelligence_lib.py, red_alert_adapter.py).
  3. NO EXECUTION CAPABILITY EXISTS IN THIS FILE. Every "allowed: True"
     result below answers the single, narrow question "may a human
     record this approval decision", never "run this containment
     action" -- there is no function here that invokes anything. A
     corroboration exception (Section 2) or a satisfied rollback check
     (Section 3) NEVER triggers execution by itself, because nothing
     in this file is capable of executing anything in the first place.

WHY THIS FILE EXISTS (ARCHITECTURE.md Phase 103/104): Phase C's real
evaluation run produced 11 RECOMMEND_CONTAINMENT Decision Records, all
with multi_source=False (no cross-WAIO-module corroboration) and no
mapping to any local WAIO agent/worker/segment. This file is the first
piece of the approval-gate design (ARCHITECTURE.md Phase D design
notes) that can be built safely in isolation: the pure validation core,
with no CLI, no audit log, and no Control-Plane coupling yet -- those
remain explicit, separate, later decisions, same "prove the pure core
first" sequencing every prior phase in this pipeline already used.

APPROVER IDENTITY IS NOT AUTHENTICATION (explicit, load-bearing,
non-negotiable this phase): validate_approver_identity() below checks
only that a non-empty identity string was SUPPLIED by the caller (and,
optionally, that it appears in an explicitly-provided allowlist -- a
forward-compatible hook point for a future phase's real local
allowlist, NOT built here). It never proves who actually typed a
command, same honor-system posture security/lib.sh's own audit_log()
`actor_user` field already documents for itself (ARCHITECTURE.md Phase
32: "this field is not a new auth mechanism, it is only recorded,
never checked/enforced by any gate"). Every result this function
returns carries `authenticated: False`, always, specifically so a
future caller can never mistake "identity present" for "identity
proven."

EXPIRY IS NOT PROOF OF SAFETY (explicit): is_expired()/compute_expiry()
below implement a staleness gate only -- an unexpired approval is not
thereby "safe", it is merely "not yet stale enough to require a fresh
Decision Engine run." The clock is ALWAYS caller-injected (an explicit
`now` argument) -- no function in this file ever calls
datetime.datetime.now()/utcnow() itself, so every expiry check is
exactly reproducible in a test with no wall-clock dependency.

ROLLBACK IS NEVER "ENFORCED" BY THIS FILE (explicit):
rollback_requirement_satisfied() below checks only that rollback
METADATA (a non-empty `rollback_tool` name) was supplied for a
high-impact proposal -- it never verifies that tool exists, works, or
would actually reverse anything. Its absence produces an explicit
refusal requiring human review, never a silent pass.

No I/O in this module.
"""

import datetime
import hashlib
import json
import re

# -----------------------------------------------------------------------
# Section 0: scope and high-impact classification
# -----------------------------------------------------------------------

# The three source_module values security/red_alert/red_alert_adapter.py
# actually emits (from_global_patrol_entity's two source_module
# arguments, and from_snd_crossref_signal's own fixed "snd_home_crossref"
# source_module) -- see that file's own header for where each comes
# from. A Decision Record is in THIS file's scope if and only if at
# least one of its source_modules is one of these three; a Decision
# Record sourced purely from Shadow AI/Attack Graph/SaaS ATO/plain
# Incident Learning is never in scope here, by explicit user decision.
RED_ALERT_SOURCE_MODULES = frozenset({
    "global_patrol",
    "critical_infra_watch",
    "snd_home_crossref",
})

# PHASE 104 ADDITION (ARCHITECTURE.md Phase 104; closes the gap
# GLOBAL_ATTACK_COMMONALITY_AB_CORRELATION_INVESTIGATION.md Sec.7.7
# identified): source modules that represent WAIO's own observation of
# its REAL LOCAL environment -- as opposed to a module that only
# describes public threat intelligence about events elsewhere in the
# world. Deliberately duplicated from
# security/decision_engine/decision_engine_lib.py's own
# LOCAL_SOURCE_MODULES constant of the same name and value, NOT
# imported -- this file's own header states it calls, and is called
# by, nothing in decision_engine_lib.py/decision_engine.sh, same
# loose-coupling discipline as every other `_lib.py` pair in this
# pipeline. Keep both lists in sync by hand if a new local
# evidence-producing module is ever wired into the Intelligence Layer.
#
# Deliberately EXCLUDES every RED_ALERT_SOURCE_MODULES value above,
# even though that might look like the "obvious" allowlist for a
# RED-ALERT-scoped gate: snd_home_crossref in particular carries its
# own mandatory confidence_caveat (security/red_alert/snd_crossref.py)
# stating it is textual co-occurrence only, never causal/network/
# geographic proof -- trusting it as LOCAL evidence here would quietly
# reintroduce the exact gap this phase closes.
LOCAL_SOURCE_MODULES = frozenset({"shadow_ai_monitor", "attack_graph", "saas_ato"})

DEFAULT_APPROVAL_TTL_SECONDS = 24 * 60 * 60  # 24 hours, explicit default
DEFAULT_REASON_MIN_LENGTH = 20
DEFAULT_REASON_MIN_DISTINCT = 8
DEFAULT_EXCEPTION_MIN_NON_WHITESPACE = 40
DEFAULT_EXCEPTION_MIN_DISTINCT = 12


def is_red_alert_scoped(decision_record):
    """decision_record: one Decision Record dict (decision_engine_lib.py's
    own decide_for_profile() output shape -- entity/entity_type/risk/
    confidence/source_modules/recommended_action/reasoning/...).
    Returns True iff at least one of its source_modules is a WAIO
    GLOBAL RED ALERT source. A malformed/missing source_modules list
    is treated as out of scope (False), never guessed into scope.
    """
    if not isinstance(decision_record, dict):
        return False
    modules = decision_record.get("source_modules")
    if not isinstance(modules, list):
        return False
    return bool(RED_ALERT_SOURCE_MODULES.intersection(modules))


def is_high_impact(decision_record):
    """True iff decision_record's own recommended_action is
    RECOMMEND_CONTAINMENT, or its risk is CRITICAL -- reusing
    decision_engine_lib.py's own existing decision table rather than
    inventing a second severity score. A malformed/missing field reads
    as not-high-impact (False), never guessed upward.
    """
    if not isinstance(decision_record, dict):
        return False
    return (
        decision_record.get("recommended_action") == "RECOMMEND_CONTAINMENT"
        or decision_record.get("risk") == "CRITICAL"
    )


def has_multi_source_corroboration(decision_record):
    """Recomputes multi-source corroboration directly from
    source_modules (len > 1) -- the same definition
    decision_engine_lib.py's own decide_for_profile() already uses
    internally, rather than parsing its free-text `reasoning` string
    (which embeds the same fact as text, not as a separate boolean
    field in the Decision Record's own output shape).

    NOTE (PHASE 104): this is still a true, meaningful fact -- recorded
    in the approval audit trail (containment_approval_gate.sh's own
    cag_request) -- but it is NO LONGER, by itself, sufficient to
    satisfy corroboration_satisfied() below. Two global-intelligence
    modules agreeing with each other (e.g. source_modules=
    ["global_patrol", "snd_home_crossref"]) makes this True while
    has_trusted_local_corroboration() just below is False -- that
    combination is exactly the gap Phase 104 closes.
    """
    if not isinstance(decision_record, dict):
        return False
    modules = decision_record.get("source_modules")
    if not isinstance(modules, list):
        return False
    return len(modules) > 1


def has_trusted_local_corroboration(decision_record):
    """True iff at least one of decision_record's own source_modules is
    a TRUSTED LOCAL evidence-producing module (LOCAL_SOURCE_MODULES
    above) -- re-derived directly from source_modules, never trusted as
    a caller-supplied boolean, same posture as
    has_multi_source_corroboration() just above and
    is_red_alert_scoped() further above.

    Deliberately excludes the three WAIO GLOBAL RED ALERT source
    modules (global_patrol, critical_infra_watch, snd_home_crossref --
    RED_ALERT_SOURCE_MODULES above) even when two or more of them are
    present together: two global-intelligence sources agreeing with
    each other is still zero evidence that anything is actually
    happening inside WAIO's own environment right now.

    A malformed/missing source_modules list is treated as NO local
    corroboration (False), never guessed into it -- fail-closed, same
    convention as every other classification function in this file.
    """
    if not isinstance(decision_record, dict):
        return False
    modules = decision_record.get("source_modules")
    if not isinstance(modules, list):
        return False
    return bool(LOCAL_SOURCE_MODULES.intersection(m for m in modules if isinstance(m, str)))


# -----------------------------------------------------------------------
# Section 0b: APPROVAL_ID format validation (CLI input-boundary defense)
# -----------------------------------------------------------------------

# An approval_id this file's own request-time code generates (see
# containment_approval_gate.sh's own cag_request) is always
# "CAG-<safe_entity>-<12 hex chars>", where safe_entity is itself already
# restricted to this exact character set (that file's own safe_entity
# construction: ch.isalnum() or ch in "-_."). validate_approval_id_format()
# enforces that SAME character set on any approval_id a caller later
# supplies back to approve/reject/status, BEFORE containment_approval_gate.sh
# ever uses it to build a filesystem path. "/" is deliberately excluded
# from the allowed set -- with no path separator expressible, a string
# built from only this character set can never reference a parent or
# sibling directory (e.g. "../../etc/passwd"), only a single filename
# component within whatever directory it is joined against.
_APPROVAL_ID_PATTERN = re.compile(r"[A-Za-z0-9_.-]+")
MAX_APPROVAL_ID_LENGTH = 200


def validate_approval_id_format(approval_id):
    """Pure format check for an APPROVAL_ID supplied to
    containment_approval_gate.sh's approve/reject/status verbs. Returns
    True iff approval_id is a non-empty string, at most
    MAX_APPROVAL_ID_LENGTH characters, composed ENTIRELY of
    [A-Za-z0-9_.-]. Any other input (wrong type, empty, containing "/",
    whitespace, shell metacharacters, control characters, or longer
    than the length cap) returns False -- fail-closed, never guessed
    into validity.

    This is a pure format check only (no I/O in this module, per this
    file's own header): it does not know whether approval_id actually
    names an existing record on disk (the caller still handles
    "approval_not_found" separately), and every approval_id this file's
    own cag_request ever generates always satisfies this check.
    """
    if not isinstance(approval_id, str) or not approval_id:
        return False
    if len(approval_id) > MAX_APPROVAL_ID_LENGTH:
        return False
    # fullmatch (not match against a ^...$-anchored pattern): Python's
    # $ anchor also matches immediately before a trailing newline, which
    # would let an id like "CAG-good-id\n" slip through a ^...$ check.
    # fullmatch has no such exception -- it requires the ENTIRE string,
    # trailing newline included, to consist only of allowed characters.
    return bool(_APPROVAL_ID_PATTERN.fullmatch(approval_id))


# -----------------------------------------------------------------------
# Section 1: reason / exception-rationale validation
# -----------------------------------------------------------------------

def _is_whitespace_char(ch):
    return ch.isspace()


def _strip_all_whitespace(text):
    """Removes EVERY whitespace character (not just leading/trailing),
    unicode-aware (str.isspace() is correct for multi-byte text, same
    care security/lib.sh's own validate_reason_strength() takes for
    Japanese reasons -- see that function's own header for the
    incident this guards against). Used only by
    validate_exception_reason() below, which must validate actual
    non-whitespace CONTENT, not merely trimmed string length.
    """
    return "".join(ch for ch in text if not _is_whitespace_char(ch))


def validate_reason(text, min_length=DEFAULT_REASON_MIN_LENGTH,
                     min_distinct=DEFAULT_REASON_MIN_DISTINCT):
    """General approve/reject reason validator -- same two-part check
    (trimmed length, then distinct-character variety) as
    security/lib.sh's own validate_reason_strength(), re-implemented
    here in pure Python because this file must never source
    security/lib.sh (see module header). Trimming is leading/trailing
    only (str.strip()), matching that function's own existing
    semantics exactly, for the ORDINARY reason field -- the stricter
    all-whitespace-removed check is reserved for
    validate_exception_reason() below, per this phase's explicit
    reason-requirements decision.

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


def validate_exception_reason(text, min_non_whitespace=DEFAULT_EXCEPTION_MIN_NON_WHITESPACE,
                               min_distinct=DEFAULT_EXCEPTION_MIN_DISTINCT,
                               approval_reason=None):
    """Validator for the corroboration-exception rationale specifically
    (explicit, stricter requirement this phase: "at least 40
    non-whitespace characters... plus a distinct exception rationale").
    Two differences from validate_reason() above, both deliberate:

      1. Normalization strips ALL whitespace (every space/tab/newline/
         unicode whitespace character anywhere in the string, not just
         the ends) before counting length and distinct characters --
         so a reason padded with extra whitespace to superficially
         clear a raw-length threshold is correctly measured by its
         actual non-whitespace content, not its printed length.
      2. If `approval_reason` is also supplied (the SAME approval
         record's own ordinary `reason` field), an exception rationale
         that is identical to it (after the same all-whitespace-
         stripped normalization) is rejected as
         DUPLICATE_OF_APPROVAL_REASON -- "a distinct exception
         rationale" means the human must actually articulate a SEPARATE
         justification for proceeding without corroboration, not
         restate why they are approving at all.

    Returns {"status": "EMPTY"|"TOO_SHORT"|"LOW_VARIETY"|
             "DUPLICATE_OF_APPROVAL_REASON"|"OK",
             "non_whitespace_length": int, "distinct": int,
             "normalized": str}. `normalized` is the whitespace-stripped
    form used for these checks -- a future caller should still persist
    the human's ORIGINAL, unstripped text for display/audit purposes;
    this function only validates, it does not decide what gets stored.
    Never raises on non-string input.
    """
    if not isinstance(text, str):
        return {"status": "EMPTY", "non_whitespace_length": 0, "distinct": 0, "normalized": ""}
    normalized = _strip_all_whitespace(text)
    if not normalized:
        return {"status": "EMPTY", "non_whitespace_length": 0, "distinct": 0, "normalized": ""}
    length = len(normalized)
    distinct = len(set(normalized))
    if length < min_non_whitespace:
        return {"status": "TOO_SHORT", "non_whitespace_length": length, "distinct": distinct, "normalized": normalized}
    if distinct < min_distinct:
        return {"status": "LOW_VARIETY", "non_whitespace_length": length, "distinct": distinct, "normalized": normalized}
    if isinstance(approval_reason, str):
        other_normalized = _strip_all_whitespace(approval_reason)
        if other_normalized and normalized.lower() == other_normalized.lower():
            return {"status": "DUPLICATE_OF_APPROVAL_REASON", "non_whitespace_length": length, "distinct": distinct, "normalized": normalized}
    return {"status": "OK", "non_whitespace_length": length, "distinct": distinct, "normalized": normalized}


# -----------------------------------------------------------------------
# Section 2: corroboration gate
# -----------------------------------------------------------------------

def corroboration_satisfied(decision_record, exception_reason=None,
                             approval_reason=None,
                             min_non_whitespace=DEFAULT_EXCEPTION_MIN_NON_WHITESPACE,
                             min_distinct=DEFAULT_EXCEPTION_MIN_DISTINCT):
    """Decides whether a high-impact Decision Record's own corroboration
    requirement is satisfied -- NOT whether any action may be taken.
    Returns {"allowed": bool, "basis": str, "detail": dict|None}:

      - not high-impact at all               -> allowed=True,  basis="not_high_impact"
      - high-impact, TRUSTED LOCAL
        corroboration present (PHASE 104:
        NOT merely multi_source -- see
        has_trusted_local_corroboration())    -> allowed=True,  basis="trusted_local_corroboration"
      - high-impact, no local corroboration,
        no exception supplied                 -> allowed=False, basis="refused_no_local_corroboration_no_exception"
      - high-impact, no local corroboration,
        exception supplied but invalid        -> allowed=False, basis="refused_exception_insufficient"
      - high-impact, no local corroboration,
        exception supplied and valid          -> allowed=True,  basis="exception"

    PHASE 104 CHANGE: this gate used to pass on bare multi_source
    (len(source_modules) > 1), which a Decision Record built from two
    GLOBAL-only modules (e.g. source_modules=["global_patrol",
    "snd_home_crossref"]) could satisfy with zero evidence that
    anything is actually happening inside WAIO's own environment. It
    now requires has_trusted_local_corroboration() specifically -- a
    global-only record must take the `exception` path (an explicit,
    validated, human-authored rationale) to be approved at all; it is
    never auto-approved on corroboration grounds alone.

    THE "exception" BASIS NEVER TRIGGERS EXECUTION BY ITSELF -- this
    function has no side effect, calls nothing, and this entire module
    has no execution capability (see module header). It only answers
    whether a human recording an approval decision satisfied this one
    gate.
    """
    if not is_high_impact(decision_record):
        return {"allowed": True, "basis": "not_high_impact", "detail": None}
    if has_trusted_local_corroboration(decision_record):
        return {
            "allowed": True,
            "basis": "trusted_local_corroboration",
            "detail": {"source_modules": decision_record.get("source_modules")},
        }
    if exception_reason is None:
        return {"allowed": False, "basis": "refused_no_local_corroboration_no_exception", "detail": None}
    check = validate_exception_reason(
        exception_reason,
        min_non_whitespace=min_non_whitespace,
        min_distinct=min_distinct,
        approval_reason=approval_reason,
    )
    if check["status"] != "OK":
        return {"allowed": False, "basis": "refused_exception_insufficient", "detail": check}
    return {"allowed": True, "basis": "exception", "detail": check}


# -----------------------------------------------------------------------
# Section 3: rollback metadata gate
# -----------------------------------------------------------------------

def rollback_requirement_satisfied(decision_record, rollback):
    """Decides whether a high-impact Decision Record's own rollback-
    metadata requirement is satisfied. Checks PRESENCE of a named
    `rollback_tool` string only -- never that the tool exists, works,
    or would actually succeed; this function has no way to verify any
    of that (no I/O, no subprocess) and must never be read as doing so.

    rollback: expected shape {"rollback_tool": str|None, ...} or None.

    Returns {"allowed": bool, "basis": str, "detail": str|None}:
      - not high-impact                        -> allowed=True,  basis="not_high_impact"
      - high-impact, rollback metadata missing
        entirely (not a dict)                  -> allowed=False, basis="refused_missing_rollback_metadata"
      - high-impact, rollback_tool absent/blank -> allowed=False, basis="refused_rollback_unavailable"
      - high-impact, rollback_tool named        -> allowed=True,  basis="rollback_tool_named"

    A refusal here is explicit and requires human review -- it is never
    silently treated as "rollback not needed" or "proceed anyway."
    """
    if not is_high_impact(decision_record):
        return {"allowed": True, "basis": "not_high_impact", "detail": None}
    if not isinstance(rollback, dict):
        return {
            "allowed": False,
            "basis": "refused_missing_rollback_metadata",
            "detail": "rollback metadata object is required for high-impact proposals and was not supplied",
        }
    tool = rollback.get("rollback_tool")
    if not isinstance(tool, str) or not tool.strip():
        return {
            "allowed": False,
            "basis": "refused_rollback_unavailable",
            "detail": "no rollback_tool named -- rollback is not available for this proposed action; this refusal requires human review before any containment action, and nothing is approved automatically as a result of it",
        }
    return {"allowed": True, "basis": "rollback_tool_named", "detail": {"rollback_tool": tool}}


# -----------------------------------------------------------------------
# Section 4: approver identity (explicitly NOT authentication)
# -----------------------------------------------------------------------

def validate_approver_identity(identity, allowlist=None):
    """Checks only PRESENCE of a non-empty identity string, and,
    OPTIONALLY (if `allowlist` -- an iterable of permitted identity
    strings -- is explicitly supplied), MEMBERSHIP in it. This is the
    forward-compatible hook point for a future phase's real local
    allowlist; `allowlist=None` (this phase's only supported mode) lets
    any non-empty string through.

    `authenticated` is ALWAYS False in this result, deliberately, in
    every branch -- this function NEVER proves who actually supplied
    the identity, and a caller must never treat `valid: True` as proof
    of authorization. Same honor-system posture as
    security/lib.sh's own audit_log() `actor_user` field.

    Returns {"valid": bool, "reason": str, "authenticated": False}.
    """
    if not isinstance(identity, str) or not identity.strip():
        return {"valid": False, "reason": "missing_identity", "authenticated": False}
    trimmed = identity.strip()
    if allowlist is not None:
        try:
            in_allowlist = trimmed in allowlist
        except TypeError:
            in_allowlist = False
        if not in_allowlist:
            return {"valid": False, "reason": "identity_not_in_allowlist", "authenticated": False}
        return {"valid": True, "reason": "present_and_in_allowlist_not_authenticated", "authenticated": False}
    return {"valid": True, "reason": "present_only_not_authenticated", "authenticated": False}


# -----------------------------------------------------------------------
# Section 5: evidence integrity (altered-evidence detection)
# -----------------------------------------------------------------------

def compute_decision_report_hash(report):
    """report: a Decision Engine report dict (or any JSON-serializable
    dict/list). Returns a deterministic "sha256:<hex>" string over its
    canonical JSON form (sort_keys=True, UTF-8 encoded) -- the same
    value an approval record's own decision_report_hash field should
    store at request time, and the same function a caller re-runs
    later against whatever report is CURRENTLY on disk to detect
    tampering. Pure computation only -- this function never reads a
    file itself; the caller is responsible for already having loaded
    `report` into memory.
    """
    canonical = json.dumps(report, sort_keys=True, ensure_ascii=False)
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


def evidence_intact(stored_hash, current_report):
    """stored_hash: the decision_report_hash recorded on an approval
    record at request time. current_report: the Decision Engine report
    dict the caller is about to approve against right now. Returns
    True only if stored_hash exactly matches
    compute_decision_report_hash(current_report) -- any mismatch
    (edited, truncated, or replaced report) returns False, and a
    missing/malformed stored_hash is treated as NOT intact (fail-
    closed), never as "nothing to check."
    """
    if not isinstance(stored_hash, str) or not stored_hash:
        return False
    return stored_hash == compute_decision_report_hash(current_report)


# -----------------------------------------------------------------------
# Section 6: timestamps and expiry (clock always caller-injected)
# -----------------------------------------------------------------------

_TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def parse_utc_timestamp(text):
    """Parses this pipeline's own standard UTC timestamp format
    (`%Y-%m-%dT%H:%M:%SZ`, e.g. "2026-10-12T03:13:09Z" -- the exact
    format decision_engine.sh/intelligence_layer.sh/red_alert_cron.sh
    already all emit via `date -u +%Y-%m-%dT%H:%M:%SZ`). Returns a
    timezone-aware (UTC) datetime.datetime, or None for anything that
    does not parse -- never raises, so a malformed/absent timestamp can
    always be handled by the caller as "unknown", fail-closed.
    """
    if not isinstance(text, str):
        return None
    try:
        naive = datetime.datetime.strptime(text, _TIMESTAMP_FORMAT)
    except (ValueError, TypeError):
        return None
    return naive.replace(tzinfo=datetime.timezone.utc)


def format_utc_timestamp(dt):
    """Inverse of parse_utc_timestamp() -- formats a timezone-aware (or
    naive, assumed UTC) datetime back into this pipeline's own standard
    string format. Returns None for non-datetime input, never raises.
    """
    if not isinstance(dt, datetime.datetime):
        return None
    return dt.strftime(_TIMESTAMP_FORMAT)


def compute_expiry(requested_at, ttl_seconds=DEFAULT_APPROVAL_TTL_SECONDS):
    """requested_at: a timezone-aware datetime.datetime (the approval
    request's own timestamp). ttl_seconds: configurable TTL, default
    24 hours (DEFAULT_APPROVAL_TTL_SECONDS) per this phase's explicit
    decision. Returns requested_at + ttl_seconds as a new datetime, or
    None if requested_at is not a valid datetime -- never raises.
    """
    if not isinstance(requested_at, datetime.datetime):
        return None
    try:
        return requested_at + datetime.timedelta(seconds=ttl_seconds)
    except (OverflowError, TypeError):
        return None


def is_expired(expires_at, now):
    """expires_at, now: datetime.datetime objects. FAIL-CLOSED: if
    EITHER argument is not a valid datetime (e.g. a malformed timestamp
    that parse_utc_timestamp() already turned into None), this returns
    True -- an unparseable or missing expiry is treated as ALREADY
    EXPIRED, never as "not expired" / "no expiry set". `now` is always
    caller-supplied (an injectable clock) -- this function never calls
    datetime.datetime.now()/utcnow() itself, so it is exactly
    reproducible in a test.

    EXPIRY IS NOT PROOF OF SAFETY: an unexpired result (False) means
    only "not yet stale enough to require a fresh Decision Engine run"
    -- it is not evidence that the underlying containment recommendation
    is itself safe to act on.
    """
    if not isinstance(expires_at, datetime.datetime) or not isinstance(now, datetime.datetime):
        return True
    return now >= expires_at


# -----------------------------------------------------------------------
# Section 7: approval state machine transition guard
# -----------------------------------------------------------------------

APPROVAL_STATUSES = ("PENDING", "APPROVED", "REJECTED", "EXPIRED")
_LEGAL_TRANSITIONS = {
    ("PENDING", "approve"): "APPROVED",
    ("PENDING", "reject"): "REJECTED",
}


def can_transition(current_status, action):
    """current_status: one of APPROVAL_STATUSES. action: "approve" or
    "reject". Returns True only for PENDING -> approve/reject -- every
    other combination (already APPROVED/REJECTED/EXPIRED, or an
    unrecognized status/action) is illegal, covering duplicate
    approvals, re-approving a rejected record, and approving an expired
    one, all by the same single rule: only a PENDING record may ever
    transition, exactly once.
    """
    return (current_status, action) in _LEGAL_TRANSITIONS


def next_status(current_status, action):
    """The status current_status transitions to for action, or None if
    can_transition(current_status, action) is False. Never raises.
    """
    return _LEGAL_TRANSITIONS.get((current_status, action))


# -----------------------------------------------------------------------
# Section 8: composite evaluation (convenience orchestrator)
# -----------------------------------------------------------------------

def evaluate_approval(decision_record, current_decision_report, stored_decision_report_hash,
                       approver_identity, now, expires_at,
                       approval_reason=None, exception_reason=None,
                       rollback=None, allowlist=None,
                       reason_min_length=DEFAULT_REASON_MIN_LENGTH,
                       reason_min_distinct=DEFAULT_REASON_MIN_DISTINCT,
                       exception_min_non_whitespace=DEFAULT_EXCEPTION_MIN_NON_WHITESPACE,
                       exception_min_distinct=DEFAULT_EXCEPTION_MIN_DISTINCT):
    """Ties every gate above together into one answer for "may this
    approval be recorded right now" -- still a PURE function (every
    input is caller-supplied; nothing is read from disk, nothing is
    executed). Returns:

        {"allowed": bool, "violations": [str, ...], "checks": {...}}

    `violations` lists every failed gate's own basis string (empty list
    iff allowed=True). `checks` carries each individual gate's own full
    result dict, for a caller that wants the detail. Order of checks
    does not short-circuit -- every gate always runs, so a caller sees
    every reason an approval would be refused, not just the first one.

    THIS FUNCTION NEVER EXECUTES ANYTHING. "allowed: True" means only
    that every gate this file knows how to check has been satisfied by
    the data supplied -- it is not, and must never be read as, a
    command to perform any containment action.
    """
    violations = []
    checks = {}

    scope_ok = is_red_alert_scoped(decision_record)
    checks["scope"] = {"allowed": scope_ok, "basis": "red_alert_scoped" if scope_ok else "out_of_scope"}
    if not scope_ok:
        violations.append("out_of_scope")

    identity_check = validate_approver_identity(approver_identity, allowlist=allowlist)
    checks["identity"] = identity_check
    if not identity_check["valid"]:
        violations.append(identity_check["reason"])

    evidence_ok = evidence_intact(stored_decision_report_hash, current_decision_report)
    checks["evidence"] = {"allowed": evidence_ok, "basis": "evidence_intact" if evidence_ok else "evidence_altered_or_missing"}
    if not evidence_ok:
        violations.append("evidence_altered_or_missing")

    expired = is_expired(expires_at, now)
    checks["expiry"] = {"allowed": not expired, "basis": "not_expired" if not expired else "expired"}
    if expired:
        violations.append("expired")

    reason_check = validate_reason(approval_reason, min_length=reason_min_length, min_distinct=reason_min_distinct)
    checks["reason"] = reason_check
    if reason_check["status"] != "OK":
        violations.append(f"reason_{reason_check['status'].lower()}")

    corroboration_check = corroboration_satisfied(
        decision_record,
        exception_reason=exception_reason,
        approval_reason=approval_reason,
        min_non_whitespace=exception_min_non_whitespace,
        min_distinct=exception_min_distinct,
    )
    checks["corroboration"] = corroboration_check
    if not corroboration_check["allowed"]:
        violations.append(corroboration_check["basis"])

    rollback_check = rollback_requirement_satisfied(decision_record, rollback)
    checks["rollback"] = rollback_check
    if not rollback_check["allowed"]:
        violations.append(rollback_check["basis"])

    return {"allowed": len(violations) == 0, "violations": violations, "checks": checks}
