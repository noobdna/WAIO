"""security/shadow_ai/shadow_ai_lib.py -- pure-ish computation core for
the Shadow AI Monitor (config parsing, signature matching, secret
redaction, risk/confidence classification, finding assembly, inventory
merge). Kept as a standalone module, imported by both
shadow_ai_monitor.sh's own analysis step and tests/shadow_ai_monitor_test.sh,
so the classification rules are defined exactly once and the test suite
can exercise the real logic directly against fixed inputs -- same
convention as fx_validation/validation_lib.py.

The only I/O here is reading the two small config files (signatures,
allowlist) -- everything else (matching/redaction/classification/
finding assembly/inventory merge) is a pure function of its arguments,
directly unit-testable with no ps/lsof fixture needed. Parsing REAL
`ps`/`lsof` output text is also handled here (parse_ps_line/
parse_lsof_line) as pure string-in/dict-out functions, so
shadow_ai_monitor.sh's own job is reduced to "run ps/lsof, hand the raw
text to this module, print what comes back" -- see that file's header.

Hard safety rule, enforced here (not left to the caller): redact_args()
is the ONLY path any process command-line text takes before it can ever
reach a finding, an inventory entry, or stdout. Every finding-emitting
function in this module accepts already-redacted text, never raw args.
"""

import hashlib
import re


# --- config parsing --------------------------------------------------

def _parse_pipe_conf(path, expected_fields):
    """Shared reader for the pipe-delimited TYPE|... conf files this
    module owns. Blank lines and lines starting with # are skipped.
    Returns a list of dicts with the given field names, in file order
    (first-match-wins semantics belong to the caller, e.g. allowlist
    lookups checking every entry, not this parser).
    """
    entries = []
    try:
        with open(path) as f:
            lines = f.readlines()
    except FileNotFoundError:
        return entries

    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("|", len(expected_fields) - 1)
        if len(parts) != len(expected_fields):
            continue
        entries.append(dict(zip(expected_fields, parts)))
    return entries


def load_signatures(path):
    """shadow_ai_signatures.conf -> list of
    {type, pattern, category, risk, label}."""
    return _parse_pipe_conf(path, ["type", "pattern", "category", "risk", "label"])


def load_allowlist(path):
    """known_ai_allowlist.conf -> list of {type, pattern, label}."""
    return _parse_pipe_conf(path, ["type", "pattern", "label"])


# --- redaction ---------------------------------------------------------

# Deliberately a fixed, named list of known secret SHAPES (vendor key
# prefixes + generic key=value/Bearer patterns) -- NOT a "redact every
# long opaque string" catch-all, which would also swallow ordinary file
# paths and flags and make a finding's own process args useless for a
# human reviewer. This is the same "deliberately simple, auditable,
# best-effort, not exhaustive" posture
# security/incident_learning/incident_evidence.sh's own keyword scan
# already documents for a different field -- a missed pattern here is a
# gap to close by adding a new named pattern, never an excuse to widen
# this into a blanket redaction that destroys the field's own value.
_SECRET_PATTERNS = [
    re.compile(r"sk-ant-[A-Za-z0-9\-_]{10,}"),         # Anthropic API key
    re.compile(r"sk-[A-Za-z0-9]{20,}"),                # OpenAI-style API key
    re.compile(r"AKIA[0-9A-Z]{16}"),                   # AWS access key id
    re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),         # GitHub token
    re.compile(r"AIza[0-9A-Za-z\-_]{30,}"),            # Google API key
    re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}"),       # Slack token
    re.compile(r"(?i)bearer\s+\S+"),                   # Authorization: Bearer <token>
    re.compile(
        r"(?i)(api[_-]?key|token|secret|password|passwd|auth|credential)s?"
        r"[\s:=]+[^\s]+"
    ),                                                  # KEY=VALUE / KEY: VALUE shaped
]

MAX_ARGS_LEN = 300


def redact_args(raw_args):
    """Returns a redacted, length-capped copy of a process's own
    command-line argument string. Never returns the original text for
    anything matching a known secret shape. Safe to call on None/empty.
    """
    text = raw_args or ""
    for pattern in _SECRET_PATTERNS:
        text = pattern.sub("[REDACTED]", text)
    if len(text) > MAX_ARGS_LEN:
        text = text[:MAX_ARGS_LEN] + "...[truncated]"
    return text


# --- ps / lsof parsing -------------------------------------------------

def parse_ps_line(line):
    """Parses one line of `ps -axo pid=,ppid=,user=,comm=,args=` output
    (no header row -- the `=` suffix on each field suppresses it).
    Returns {pid, ppid, user, comm, args} with args already redacted,
    or None for a blank/malformed line.
    """
    parts = line.split(None, 4)
    if len(parts) < 5:
        return None
    pid, ppid, user, comm, args = parts
    if not pid.isdigit():
        return None
    return {
        "pid": int(pid),
        "ppid": int(ppid) if ppid.isdigit() else None,
        "user": user,
        "comm": comm,
        "args": redact_args(args),
    }


_LSOF_LISTEN_RE = re.compile(r"^\[?([^\]]*)\]?:(\d+)\s*\(LISTEN\)$")
_LSOF_ESTABLISHED_RE = re.compile(
    r"^\[?([^\]]*?)\]?:(\d+)->\[?([^\]]*?)\]?:(\d+)\s*\(ESTABLISHED\)$"
)


def parse_lsof_line(line):
    """Parses one line of `lsof -i -P -n` output (the header line,
    starting with 'COMMAND', is skipped by the caller before this is
    ever called). Returns a dict describing a LISTEN or ESTABLISHED
    socket, or None for any other/malformed line (lsof -i also lists
    UDP and other states this module has no use for -- silently
    ignored, not an error).

    {command, pid, user, state: 'LISTEN'|'ESTABLISHED',
     local_host, local_port,
     remote_host, remote_port}  (remote_* is None for LISTEN)
    """
    parts = line.split(None, 8)
    if len(parts) < 9:
        return None
    command, pid, user, _fd, _type, _device, _sizeoff, _node, name = parts
    if not pid.isdigit():
        return None

    m = _LSOF_ESTABLISHED_RE.match(name)
    if m:
        local_host, local_port, remote_host, remote_port = m.groups()
        return {
            "command": command,
            "pid": int(pid),
            "user": user,
            "state": "ESTABLISHED",
            "local_host": local_host,
            "local_port": int(local_port),
            "remote_host": remote_host,
            "remote_port": int(remote_port),
        }

    m = _LSOF_LISTEN_RE.match(name)
    if m:
        local_host, local_port = m.groups()
        return {
            "command": command,
            "pid": int(pid),
            "user": user,
            "state": "LISTEN",
            "local_host": local_host or "*",
            "local_port": int(local_port),
            "remote_host": None,
            "remote_port": None,
        }

    return None


# --- signature matching -------------------------------------------------

def match_process_signatures(comm, redacted_args, signatures):
    """Returns a list of (signature, match_kind) for every process-type
    signature whose pattern appears (case-insensitively) in comm or in
    the ALREADY-REDACTED args. match_kind is 'process_name' when the
    signature matched comm itself (the stronger, more specific signal),
    'args_substring' when it only matched somewhere in args.
    """
    hits = []
    comm_l = (comm or "").lower()
    args_l = (redacted_args or "").lower()
    for sig in signatures:
        if sig["type"] != "process":
            continue
        pattern_l = sig["pattern"].lower()
        if pattern_l in comm_l:
            hits.append((sig, "process_name"))
        elif pattern_l in args_l:
            hits.append((sig, "args_substring"))
    return hits


def match_port_signature(port, signatures):
    """Returns the first port-type signature whose PATTERN equals this
    exact port number, or None. Exact match only -- a port number
    substring match would be meaningless (e.g. '80' inside '8080').
    """
    port_s = str(port)
    for sig in signatures:
        if sig["type"] == "port" and sig["pattern"] == port_s:
            return sig
    return None


def match_domain_in_text(redacted_text, signatures):
    """Returns a list of domain-type signatures whose pattern appears in
    the given (already-redacted) text. See this module's own header and
    shadow_ai_signatures.conf's TYPE=domain doc: this is matched against
    process args text only, never a resolved network destination --
    this module performs no DNS/reverse-DNS lookups of its own.
    """
    text_l = (redacted_text or "").lower()
    return [
        sig for sig in signatures
        if sig["type"] == "domain" and sig["pattern"].lower() in text_l
    ]


def is_allowlisted(allowlist, type_, pattern):
    """True if (type_, pattern) -- the SAME (type, pattern) pair a
    signature match carries -- appears in the allowlist. Exact match on
    both fields: an allowlist entry approves one specific signature
    pattern, not a broader category.
    """
    return any(a["type"] == type_ and a["pattern"] == pattern for a in allowlist)


# --- risk / confidence classification -----------------------------------

_RISK_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


def classify_risk(base_risk, allowlisted, finding_type):
    """Deliberately simple, fully auditable -- every input is already on
    the finding, no hidden score (same posture as
    incident_confidence.sh's own formula):
      - allowlisted: always LOW, regardless of base_risk or finding_type
        (a reviewed/approved match is expected, not a finding needing
        attention -- still reported, at the lowest shelf, for inventory
        completeness).
      - not allowlisted: base_risk, escalated ONE step for a
        'listening_port' or 'agent_to_agent' finding (a service exposed
        to accept connections, or two AI-flagged processes actually
        talking to each other, is a materially bigger exposure than a
        single outbound client call or a merely-running process) --
        capped at CRITICAL.
    """
    if allowlisted:
        return "LOW"
    base = base_risk if base_risk in _RISK_ORDER else "LOW"
    idx = _RISK_ORDER.index(base)
    if finding_type in ("listening_port", "agent_to_agent"):
        idx = min(idx + 1, len(_RISK_ORDER) - 1)
    return _RISK_ORDER[idx]


def classify_confidence(match_kind):
    """match_kind -> confidence, stated plainly rather than computed:
      exact_port      -> HIGH   (an exact port number match is unambiguous)
      process_name    -> HIGH   (the signature matched the process's own
                                  command name, not just something in its
                                  arguments)
      args_substring   -> MEDIUM (matched only inside command-line args --
                                  could be a coincidental substring)
      domain_in_args   -> MEDIUM (same reasoning as args_substring)
    Unknown match_kind defaults to MEDIUM rather than erroring -- a new
    match kind added later without updating this table should never
    silently claim HIGH confidence.
    """
    return {
        "exact_port": "HIGH",
        "process_name": "HIGH",
        "args_substring": "MEDIUM",
        "domain_in_args": "MEDIUM",
    }.get(match_kind, "MEDIUM")


_LOOPBACK_HOSTS = ("127.0.0.1", "::1", "localhost")


def find_agent_links(ps_records, lsof_records, signatures):
    """Correlates already-parsed ps records and lsof records to find
    LOCAL AI-agent-to-AI-agent connections: process A (AI-signature-
    matched) has an ESTABLISHED loopback connection to a port that
    process B (a DIFFERENT AI-signature-matched process) is LISTENing
    on. Deliberately loopback-only and PID-cross-referenced -- this
    module performs no DNS resolution and no packet inspection, so
    "two local AI-flagged processes are connected to each other" is the
    one agent-to-agent signal it can establish with the data it already
    has, without guessing at anything remote.

    Returns a list of (client_ps_record, client_match, listener_pid,
    listener_command, listener_port) tuples. Pure function: takes
    already-collected data, makes no system calls of its own.
    """
    ai_matches_by_pid = {}
    for rec in ps_records:
        hits = match_process_signatures(rec["comm"], rec["args"], signatures)
        if hits:
            ai_matches_by_pid[rec["pid"]] = (rec, hits[0][0])

    listeners_by_port = {}
    for lr in lsof_records:
        if lr["state"] == "LISTEN" and lr["pid"] in ai_matches_by_pid:
            listeners_by_port.setdefault(lr["local_port"], []).append(
                (lr["pid"], lr["command"])
            )

    links = []
    for lr in lsof_records:
        if lr["state"] != "ESTABLISHED":
            continue
        if lr["pid"] not in ai_matches_by_pid:
            continue
        if lr["remote_host"] not in _LOOPBACK_HOSTS:
            continue
        for listener_pid, listener_command in listeners_by_port.get(
            lr["remote_port"], []
        ):
            if listener_pid == lr["pid"]:
                continue
            client_rec, client_sig = ai_matches_by_pid[lr["pid"]]
            links.append(
                (client_rec, client_sig, listener_pid, listener_command, lr["remote_port"])
            )
    return links


# --- finding assembly ----------------------------------------------------

def stable_identity(finding_type, signature_pattern, extra=""):
    """A short, deterministic id derived from what this finding actually
    IS (finding type + which signature matched + an optional extra
    disambiguator such as a local port or command name) -- NEVER from a
    pid or a timestamp, both of which change every single scan even for
    the exact same underlying recurring thing. Used both as a finding's
    own "id" and as the inventory's own merge key, so the same real
    process/service is recognized as "the same thing" across scans.
    """
    basis = f"{finding_type}:{signature_pattern}:{extra}"
    return "SHADOWAI-" + hashlib.sha1(basis.encode("utf-8")).hexdigest()[:12]


def build_finding(
    finding_type,
    signature,
    match_kind,
    allowlisted,
    detected_at,
    reason,
    process=None,
    network=None,
    identity_extra="",
):
    """Assembles one finding dict, JSON-serializable as-is. `process`
    and `network` are already-sanitized dicts (or None) -- this
    function does not itself redact anything (see redact_args, applied
    at parse time, well before a finding is ever built).
    """
    risk = classify_risk(signature["risk"], allowlisted, finding_type)
    confidence = classify_confidence(match_kind)
    return {
        "id": stable_identity(finding_type, signature["pattern"], identity_extra),
        "detected_at": detected_at,
        "finding_type": finding_type,
        "category": signature["category"],
        "signature_matched": signature["pattern"],
        "signature_label": signature["label"],
        "match_kind": match_kind,
        "process": process,
        "network": network,
        "allowlisted": allowlisted,
        "risk": risk,
        "confidence": confidence,
        "reason": reason,
    }


# --- inventory merge -----------------------------------------------------

def merge_inventory(existing, findings, now):
    """Pure function: existing inventory dict (id -> entry) + this
    scan's findings -> new inventory dict. Never mutates `existing`.
    A finding already in the inventory has its last_seen/last_risk/
    last_confidence/times_seen updated; first_seen is set only the
    first time an id is ever observed. Nothing is ever removed here --
    an entry that stops appearing in a scan simply stops being updated,
    still visible in the inventory as "not seen since <last_seen>" (no
    silent disappearance of a prior finding).
    """
    merged = dict(existing)
    for f in findings:
        fid = f["id"]
        prior = merged.get(fid)
        merged[fid] = {
            "id": fid,
            "finding_type": f["finding_type"],
            "category": f["category"],
            "signature_matched": f["signature_matched"],
            "signature_label": f["signature_label"],
            "allowlisted": f["allowlisted"],
            "first_seen": prior["first_seen"] if prior else now,
            "last_seen": now,
            "last_risk": f["risk"],
            "last_confidence": f["confidence"],
            "times_seen": (prior["times_seen"] + 1) if prior else 1,
        }
    return merged
