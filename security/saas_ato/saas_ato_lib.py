"""security/saas_ato/saas_ato_lib.py -- pure-ish computation core for
the SaaS Account Takeover (ATO) Monitor (signal parsing, per-signal
risk/confidence classification, per-account aggregation, state-diff
correlation, evidence/event assembly).

Position in the requested pipeline (same shape as Phase 90-93's own
diagram, this module is a fourth, parallel evidence producer):

    Shadow AI Monitor  -\\
    Attack Graph         -> WAIO Intelligence/Evidence Layer -> WAIO Decision Engine -> DuCoPA -> Contain/Recover
    Incident Learning   -/
    SaaS ATO Monitor    -/

Scope (same READ-ONLY / detection-only posture as
security/shadow_ai/shadow_ai_lib.py's and
security/ssh_exposure/ssh_exposure_lib.py's own headers): every
function here is a pure function of already-collected data -- a
RawSignal record (see parse_signal_line's own header for the exact
contract any current or future Collector must emit) or a previously-
persisted state snapshot. Nothing in this module shells out, opens a
socket, reads a credential, or writes to any file -- the only
filesystem writes anywhere in the SaaS ATO Monitor are its own state
snapshot (security/state/saas_ato/state.json) and its own audit log,
both performed by saas_ato_monitor.sh, never here.

CRITICAL SAFETY BOUNDARY, same posture as
security/decision_engine/decision_engine_lib.py's own header: this
module DETECTS, IT NEVER CONTAINS. It has no code path to
security/guardian.sh, security/ducopa.sh, security/recover.sh, or any
real Microsoft 365 / Google Workspace admin API write endpoint
(disable account, revoke session, delete a mail rule). A finding
reaching CRITICAL risk here is a human reading the WAIO Decision
Engine's own RECOMMEND_CONTAINMENT output and THEN, separately, by
hand, choosing to act -- same handoff
security/decision_engine/decision_engine_lib.py's own header already
documents for Shadow AI Monitor/Attack Graph/Incident Learning. No
real M365/Google Workspace connection, credential, or Keychain access
exists anywhere in this module either (see this file's own README-
equivalent note in saas_ato_monitor.sh's header for the explicit scope
line) -- a real-environment (P1) connection is a separate, later,
deliberately out-of-scope task, same boundary already drawn for
SND@HOME/Takomachi in the dashboard's own System Overview panel.

Deliberately loose coupling with every sibling evidence producer: this
module does not import shadow_ai_lib.py, attack_graph_lib.py, or
security/incident_learning/'s own Python helpers -- same "depend only
on the documented schema, never the sibling module's code" discipline
security/attack_graph/attack_graph_lib.py's own header already states.
It is also deliberately NOT named after, and does not import or
modify, security/incident_learning/incident_normalizer.sh's own
"Identity Exposure classification" fields (exposure_categories /
identity_document_types / potential_abuse_paths / defensive_priorities)
-- that layer classifies PUBLIC BREACH-DISCLOSURE PROSE about OTHER
organizations' incidents; this module detects an actual suspected
takeover of THIS deployment's own SaaS accounts. Two different
questions, kept as two different modules on purpose.

No I/O in this module -- every function is a pure function of its
arguments, same convention as every other `_lib.py` in this pipeline.
"""

import json

RISK_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
CONFIDENCE_ORDER = ["LOW", "MEDIUM", "HIGH"]

_REQUIRED_SIGNAL_FIELDS = ("id", "source", "tenant", "account", "signal_type", "detected_at")


def _risk_index(risk):
    return RISK_ORDER.index(risk) if risk in RISK_ORDER else 0


def _higher_risk(a, b):
    return a if _risk_index(a) >= _risk_index(b) else b


def _confidence_index(confidence):
    return CONFIDENCE_ORDER.index(confidence) if confidence in CONFIDENCE_ORDER else 0


def _higher_confidence(a, b):
    return a if _confidence_index(a) >= _confidence_index(b) else b


# --- signal parsing ---------------------------------------------------

def parse_signal_line(line):
    """Parses one line of RawSignal JSONL (a Collector's own stdout --
    see security/saas_ato/collectors/mock_m365_collector.sh's own
    header for the shape contract any current or future Collector,
    real or mock, must conform to). Returns the parsed dict, or None
    for a blank line, malformed JSON, or a JSON value missing any of
    _REQUIRED_SIGNAL_FIELDS -- never raises. Same "skip gracefully,
    never crash on a malformed line" posture every Collector-contract
    reader in this repo already has (see
    security/incident_learning/incident_normalizer.sh's own while-read
    loop, security/attack_graph/attack_graph_lib.py's own
    parse_findings()).
    """
    line = (line or "").strip()
    if not line:
        return None
    try:
        record = json.loads(line)
    except (json.JSONDecodeError, TypeError):
        return None
    if not isinstance(record, dict):
        return None
    if any(record.get(f) in (None, "") for f in _REQUIRED_SIGNAL_FIELDS):
        return None
    return record


def parse_signals(lines):
    """lines -> list of parsed signal dicts, malformed lines silently
    skipped. Convenience wrapper over parse_signal_line for an already-
    open file's own readlines()/iteration.
    """
    out = []
    for line in lines:
        parsed = parse_signal_line(line)
        if parsed is not None:
            out.append(parsed)
    return out


def group_by_account(signals):
    """signals -> {account: [signal, ...]}, preserving encounter order
    within each account's own list. Never mutates the input list.
    """
    groups = {}
    for s in signals:
        groups.setdefault(s["account"], []).append(s)
    return groups


# --- per-signal risk/confidence classification -----------------------
#
# Deliberately simple, fully auditable fixed tables -- never a
# weighted/blended score, same "state the basis, not just the verdict"
# posture as every other classifier in this repo
# (incident_confidence.sh's own formula, ssh_exposure_lib.py's own
# classify_severity()). An unrecognized signal_type is NEVER silently
# dropped (parse_signal_line already guarantees signal_type is present
# and non-empty) and is NEVER defaulted to the safest outcome -- see
# the final `else` branch below, which fails toward MORE scrutiny,
# same fail-closed posture security/lib.sh's own egress_check() and
# ssh_exposure_lib.py's own classify_severity() already establish for
# an unknown/unreadable input.

MASS_SEND_CRITICAL_THRESHOLD = 500
MASS_SEND_HIGH_THRESHOLD = 100
MASS_SEND_MEDIUM_THRESHOLD = 20

# Sensitive OAuth scopes: a fixed, named list of scopes that grant
# mail/file/directory read-write or send capability -- the categories
# of app permission an attacker-registered OAuth app actually wants
# after a successful credential phish, not every scope a legitimate
# app might request. Lowercased for case-insensitive matching (a real
# Collector may report a scope string in either Microsoft's or
# Google's own casing convention).
SENSITIVE_OAUTH_SCOPES = {
    "mail.read", "mail.readwrite", "mail.send",
    "full_access_as_app", "directory.readwrite.all",
    "files.readwrite.all", "mailboxsettings.readwrite",
}


def _account_domain(account):
    """account ('alice@contoso.com') -> 'contoso.com', or '' if no '@'
    is present (never raises on a malformed account string -- treated
    as "no domain to compare against", which classify_new_forwarding_
    rule below already handles by falling back to the non-external
    branch).
    """
    return account.rsplit("@", 1)[1].lower() if "@" in (account or "") else ""


def classify_signal(signal):
    """signal (a parsed RawSignal dict) -> (risk, confidence, basis)
    where basis is a short human-readable string stating exactly which
    rule fired -- never a bare score, same posture as every other
    evidence string in this repo (see build_evidence() below).
    """
    stype = signal.get("signal_type")

    if stype == "mass_send":
        count = signal.get("recipient_count") or 0
        try:
            count = int(count)
        except (TypeError, ValueError):
            count = 0
        if count >= MASS_SEND_CRITICAL_THRESHOLD:
            risk = "CRITICAL"
        elif count >= MASS_SEND_HIGH_THRESHOLD:
            risk = "HIGH"
        elif count >= MASS_SEND_MEDIUM_THRESHOLD:
            risk = "MEDIUM"
        else:
            risk = "LOW"
        # confidence HIGH: a recipient count is a directly reported
        # fact, not a heuristic -- same "a hard count is already
        # strong evidence" posture security/lib.sh's own
        # payload_size_check() already applies to a byte count.
        return risk, "HIGH", f"mass_send: recipient_count={count} (thresholds: critical>={MASS_SEND_CRITICAL_THRESHOLD}, high>={MASS_SEND_HIGH_THRESHOLD}, medium>={MASS_SEND_MEDIUM_THRESHOLD}) -> {risk}"

    if stype == "impossible_travel_signin":
        # Fixed HIGH/MEDIUM: a single impossible-travel sign-in is
        # already a strong anomaly on its own, but geo-IP-derived
        # location heuristics are known to false-positive (VPN exit
        # nodes, mobile carrier NAT) -- confidence MEDIUM reflects
        # that, same "the signal is real but the inference step below
        # it carries its own known error rate" distinction
        # incident_evidence.sh's own self_reported_uncorroborated flag
        # already draws for a different signal.
        return "HIGH", "MEDIUM", f"impossible_travel_signin: {signal.get('location_from', '?')} -> {signal.get('location_to', '?')} in {signal.get('minutes_between', '?')} minute(s) -> HIGH"

    if stype == "new_forwarding_rule":
        account = signal.get("account", "")
        forwards_to = signal.get("forwards_to", "") or ""
        external = "@" in forwards_to and _account_domain(forwards_to) != _account_domain(account)
        if external:
            # confidence HIGH: this is a direct config/API read (a
            # mail rule either exists or it doesn't), same certainty
            # class as ssh_exposure_lib.py's own sshd_config read.
            return "HIGH", "HIGH", f"new_forwarding_rule: forwards_to={forwards_to} is EXTERNAL to account domain -> HIGH"
        return "MEDIUM", "MEDIUM", f"new_forwarding_rule: forwards_to={forwards_to} is internal to account domain -> MEDIUM"

    if stype == "oauth_grant":
        scopes = {str(s).lower() for s in (signal.get("scopes") or [])}
        sensitive = sorted(scopes & SENSITIVE_OAUTH_SCOPES)
        if sensitive:
            return "HIGH", "MEDIUM", f"oauth_grant: app={signal.get('app_name', '?')} sensitive_scopes={sensitive} -> HIGH"
        return "LOW", "LOW", f"oauth_grant: app={signal.get('app_name', '?')} scopes={sorted(scopes)} (none sensitive) -> LOW"

    # Unrecognized signal_type: never dropped, never defaulted to the
    # SAFEST outcome -- fails toward more scrutiny (MEDIUM/LOW), same
    # fail-closed posture as the rest of this repo's own classifiers
    # for an unreadable/unknown input.
    return "MEDIUM", "LOW", f"unrecognized signal_type='{stype}': treated conservatively (MEDIUM/LOW), never dropped"


def account_risk_confidence(classified_signals):
    """classified_signals: a list of signal dicts, each already
    carrying its own 'risk'/'confidence' (as set by the caller from
    classify_signal's own return). Returns (risk, confidence) for the
    WHOLE account this scan cycle:
      risk       - the highest risk among every signal.
      confidence - HIGH whenever two or more DISTINCT signal_types
                   fired for this account in the same cycle (same
                   "independent corroborating evidence raises
                   confidence" reasoning
                   security/attack_graph/attack_graph_lib.py's own
                   from_attack_graph_node-equivalent two-finding rule
                   and
                   security/decision_engine/decision_engine_lib.py's
                   own multi_source bump already apply, reapplied here
                   to signal TYPE count rather than source-module
                   count); otherwise the highest individual confidence
                   among the (necessarily single-type) signals.
    Returns ("LOW", "LOW") for an empty list (nothing observed this
    cycle for this account -- never reached for a real account since
    group_by_account only creates an entry when at least one signal
    exists, but kept total/safe for direct unit testing).
    """
    if not classified_signals:
        return "LOW", "LOW"
    risk = "LOW"
    confidence = "LOW"
    for s in classified_signals:
        risk = _higher_risk(risk, s["risk"])
        confidence = _higher_confidence(confidence, s["confidence"])
    distinct_types = {s["signal_type"] for s in classified_signals}
    if len(distinct_types) >= 2:
        confidence = "HIGH"
    return risk, confidence


# --- state diff / change correlation --------------------------------
#
# Same shape as security/ssh_exposure/ssh_exposure_lib.py's own
# compute_correlation() -- reused as a PATTERN, not as shared code
# (this module does not import ssh_exposure_lib, same loose-coupling
# discipline stated in this file's own header): purely TEMPORAL
# co-occurrence of a NEW signal_type appearing for this account THIS
# cycle that was not present LAST cycle, within this module's own
# smallest time resolution (one scan cycle). `candidate_incident` is
# true only when at least two DISTINCT signal_types newly appeared in
# the same cycle -- a flag for a human to look closer, never a
# verdict on its own (a CRITICAL risk from a single mass_send signal
# alone, see account_risk_confidence() above, already does not depend
# on this flag at all -- that classification fires on the FIRST scan
# that observes it, never waiting for a second cycle to confirm it).

def compute_correlation(prev_account_state, now_iso, signal_types_this_cycle, window_seconds=300):
    """prev_account_state: None (this account has never been scanned
    before) or this account's own previously-persisted state dict
    (`{"signal_types": {type: first_seen_at, ...}, "last_scan_at": ...}`).
    signal_types_this_cycle: an iterable of distinct signal_type
    strings observed THIS cycle for this one account.

    `prev_account_state is None` is treated as "no baseline to diff
    against" and deliberately produces ZERO events -- every signal
    type is, trivially, "new" on a first scan of a never-before-seen
    account, and reporting a `*_appeared` event for each one would be
    noise, not a signal (same reasoning
    security/ssh_exposure/ssh_exposure_lib.py's own compute_correlation
    already documents for its own first-scan case). An account with a
    REAL prior empty/partial snapshot (e.g. only mass_send was present
    last cycle) is diffed normally.

    Returns (correlation_dict, new_account_state_dict). Pure function
    -- the caller persists new_account_state_dict; this function never
    touches disk. new_account_state_dict's own "signal_types" only
    retains types CURRENTLY observed this cycle (not a growing history)
    -- same "state reflects what's current, not everything ever seen"
    discipline ssh_exposure_lib.py's own listener_keys already applies,
    so a signal_type that stops and later resumes is correctly
    reported as newly-appeared again, not silently ignored forever.
    """
    is_first_scan = prev_account_state is None
    prev_types = (prev_account_state or {}).get("signal_types") or {}
    signal_types_this_cycle = set(signal_types_this_cycle)

    events = []
    if not is_first_scan:
        for t in sorted(signal_types_this_cycle):
            if t not in prev_types:
                events.append({"type": f"{t}_appeared", "at": now_iso})

    distinct_event_types = {e["type"] for e in events}
    candidate_incident = len(distinct_event_types) >= 2

    new_state = {
        "signal_types": {t: prev_types.get(t, now_iso) for t in signal_types_this_cycle},
        "last_scan_at": now_iso,
    }
    correlation = {
        "window_seconds": window_seconds,
        "events": events,
        "candidate_incident": candidate_incident,
    }
    return correlation, new_state


# --- evidence / event assembly --------------------------------------

def build_evidence(account, classified_signals, correlation):
    """A flat list of short, human-readable strings stating the basis
    for the risk/confidence verdict -- never a black-box score, same
    "state the basis, not just the verdict" posture as every other
    classifier in this repo (see
    security/ssh_exposure/ssh_exposure_lib.py's own build_evidence()).
    """
    ev = [f"account={account}"]
    for s in classified_signals:
        ev.append(f"signal id={s.get('id')} type={s['signal_type']} source={s.get('source')}: {s.get('basis', '')}")
    distinct_types = sorted({s["signal_type"] for s in classified_signals})
    ev.append(f"distinct_signal_types_this_cycle={distinct_types}")
    new_this_cycle = sorted(e["type"] for e in correlation.get("events", []))
    ev.append(f"newly_appeared_this_cycle={new_this_cycle} candidate_incident={correlation.get('candidate_incident')}")
    return ev


def build_event(account, tenant, now_iso, classified_signals, correlation):
    """Assembles the one `saas_ato` event this scan produces for one
    account, matching the same top-level shape convention as
    security/ssh_exposure/ssh_exposure_lib.py's own build_event()
    (event_type/risk/confidence/timestamp/entity-identifying fields/
    evidence/correlation).
    """
    risk, confidence = account_risk_confidence(classified_signals)
    evidence = build_evidence(account, classified_signals, correlation)
    return {
        "event_type": "saas_ato",
        "id": account,
        "risk": risk,
        "confidence": confidence,
        "timestamp": now_iso,
        "account": account,
        "tenant": tenant,
        "signals": classified_signals,
        "evidence": evidence,
        "correlation": correlation,
    }
