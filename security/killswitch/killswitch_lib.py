"""security/killswitch/killswitch_lib.py -- DuCoPA Independent Kill Switch:
the pure decision library behind security/killswitch/killswitch_gate.sh.

============================================================
SCOPE, STATED NARROWLY -- read before touching this file
============================================================
The Kill Switch is the "Contain" box of Detect -> Decide -> Contain ->
Recover, built so its authority does NOT depend on WAIO's own AI-driven
judgment: it never reads a Decision Engine report, the Guardian Control
Plane's state, the DuCoPA prototype's state, or anything WAIO's main
dispatcher produces. A containment action happens ONLY when an
operator-held key signs an explicit command whose action, target and
environment are all on a local allowlist.

Exactly three containment actions exist, all TEST-ENVIRONMENT ONLY:
  revoke_test_session  -- mark one test session revoked
  block_test_endpoint  -- mark one test endpoint blocked
  isolate_test_worker  -- mark one test worker isolated
"Executing" one of them writes a single marker file inside an explicitly
declared test-environment directory (see killswitch_gate.sh). Nothing in
this module or its CLI touches production traffic, firewall rules,
Cloudflare, SSH keys, credentials, or any real WAIO state.

Anything else -- an unknown action, a non-"test" environment, a target
not on the allowlist, a command whose origin is not a human operator or
the Guardian, an unsigned/badly-signed/stale command -- is refused, and
the refusal itself is the recorded result.

AUTHENTICATION IS KEY POSSESSION, NOTHING MORE (load-bearing): a valid
HMAC-SHA256 signature proves the signer held the issuer's key file, not
that a human typed the command. `origin` is a recorded claim the signer
makes. Keeping AI agents away from operator keys (separate machine,
separate macOS user) is a deployment property this code cannot enforce.

SND@HOME / SND@ID events are ADVISORY ONLY: evaluate_event() turns a
detection into a structured recommendation and never into a command.
There is no function in this module that converts an event record into
something execute-able -- the only executable input is a signed command.

Pure functions only: no file, network, subprocess or clock access here.
The CLI passes in file contents, key bytes, and "now".
"""

import datetime
import hashlib
import hmac
import json
import re

SCHEMA_COMMAND = "waio.killswitch.command.v1"
SCHEMA_EVENT = "waio.killswitch.event.v1"

# action -> the test-environment marker sub-directory it writes into
ACTIONS = {
    "revoke_test_session": "sessions",
    "block_test_endpoint": "endpoints",
    "isolate_test_worker": "workers",
}

ALLOWED_ORIGINS = frozenset({"human_operator", "guardian"})
AI_ORIGINS = frozenset({
    "ai", "llm", "agent", "model", "waio", "waio_ai", "decision_engine",
    "qwen", "claude", "takomachi", "auto", "automatic", "snd_event",
})
ALLOWED_ENVIRONMENTS = frozenset({"test"})

# event_ref links a command to the SND event that motivated it ("" if none)
COMMAND_FIELDS = frozenset({
    "schema", "command_id", "action", "target_id", "environment",
    "issued_at", "origin", "issuer", "reason", "event_ref", "signature",
})

MAX_COMMAND_BYTES = 8192
MAX_EVENT_BYTES = 16384
DEFAULT_FRESHNESS_SECONDS = 300
MAX_FUTURE_SKEW_SECONDS = 60
DEFAULT_REASON_MIN_LENGTH = 20
DEFAULT_REASON_MIN_DISTINCT = 8
MAX_REASON_LENGTH = 500
MAX_SUMMARY_LENGTH = 200

_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")
_TS_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

# Same credential shapes as security/lib.sh's secret_leak_check(), plus
# bearer/password assignments; used to redact event summaries.
_SECRET_PATTERN = re.compile(
    r"(sk-[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY-----"
    r"|gh[pousr]_[A-Za-z0-9]{30,}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\."
    r"|(?i:(api[_-]?key|passw(or)?d|secret|token|bearer)\s*[:=]\s*\S{6,}))"
)
_NETWORK_ID_PATTERN = re.compile(
    r"(\b\d{1,3}(\.\d{1,3}){3}\b|\b[0-9A-Fa-f]{2}([:-][0-9A-Fa-f]{2}){5}\b)"
)


# ------------------------------------------------------------------
# small validators
# ------------------------------------------------------------------

def valid_id(value):
    """Identifier shape for command_id/target_id/issuer/event_id: 1-64
    chars of [A-Za-z0-9_.-], starting alphanumeric. Rejects '..', '/',
    whitespace and shell metacharacters by construction, so a valid id
    is always safe as a single path component."""
    return isinstance(value, str) and _ID_PATTERN.fullmatch(value) is not None


def parse_ts(text):
    if not isinstance(text, str):
        return None
    try:
        return datetime.datetime.strptime(text, _TS_FORMAT).replace(tzinfo=datetime.timezone.utc)
    except ValueError:
        return None


def format_ts(dt):
    return dt.astimezone(datetime.timezone.utc).strftime(_TS_FORMAT)


def validate_reason(text, min_length=DEFAULT_REASON_MIN_LENGTH, min_distinct=DEFAULT_REASON_MIN_DISTINCT):
    """Same two-threshold discipline as the repo's other reason-gated
    CLIs (length and distinct characters). Returns (ok, error)."""
    if not isinstance(text, str):
        return False, "reason must be a string"
    t = text.strip()
    if not t:
        return False, "reason is empty"
    if len(t) > MAX_REASON_LENGTH:
        return False, "reason exceeds %d characters" % MAX_REASON_LENGTH
    if len(t) < min_length:
        return False, "reason is %d characters, minimum is %d" % (len(t), min_length)
    if len(set(t)) < min_distinct:
        return False, "reason has %d distinct characters, minimum is %d" % (len(set(t)), min_distinct)
    return True, ""


# ------------------------------------------------------------------
# configuration parsing (contents handed in by the CLI)
# ------------------------------------------------------------------

def parse_targets(text):
    """targets.conf: one 'action|target_id|environment' per line, '#'
    comments. Returns (set_of_tuples, errors). ANY malformed line, an
    unknown action, or an environment other than 'test' makes the whole
    file an error -- the CLI then refuses every command (fail closed)
    rather than guessing which lines were meant."""
    allowed, errors = set(), []
    for lineno, raw in enumerate((text or "").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip() for p in line.split("|")]
        if len(parts) != 3:
            errors.append("line %d: expected action|target_id|environment" % lineno)
            continue
        action, target, env = parts
        if action not in ACTIONS:
            errors.append("line %d: unknown action '%s'" % (lineno, action))
        elif not valid_id(target):
            errors.append("line %d: invalid target_id" % lineno)
        elif env not in ALLOWED_ENVIRONMENTS:
            errors.append("line %d: environment '%s' is not allowed (test only)" % (lineno, env))
        else:
            allowed.add((action, target, env))
    return allowed, errors


def parse_authz(text):
    """authz.conf: one 'issuer|action[,action...]' per line. Same
    all-or-nothing error handling as parse_targets."""
    authz, errors = {}, []
    for lineno, raw in enumerate((text or "").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip() for p in line.split("|")]
        if len(parts) != 2 or not valid_id(parts[0]):
            errors.append("line %d: expected issuer|action[,action...]" % lineno)
            continue
        actions = [a.strip() for a in parts[1].split(",") if a.strip()]
        bad = [a for a in actions if a not in ACTIONS]
        if bad or not actions:
            errors.append("line %d: unknown or empty action list" % lineno)
            continue
        authz.setdefault(parts[0], set()).update(actions)
    return authz, errors


# ------------------------------------------------------------------
# signing (canonical form shared by signer and verifier)
# ------------------------------------------------------------------

def canonical_payload(command):
    """Every field except 'signature', sorted-key compact JSON."""
    body = {k: v for k, v in command.items() if k != "signature"}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def sign(command, key_bytes):
    return hmac.new(key_bytes, canonical_payload(command), hashlib.sha256).hexdigest()


def verify_signature(command, key_bytes):
    sig = command.get("signature")
    if not isinstance(sig, str) or not re.fullmatch(r"[0-9a-f]{64}", sig):
        return False
    return hmac.compare_digest(sign(command, key_bytes), sig)


# ------------------------------------------------------------------
# command evaluation
# ------------------------------------------------------------------

def parse_command(text):
    """Returns (command_dict, error). Size, JSON shape and the exact
    field set are checked here; unknown or missing fields are refused."""
    if text is None:
        return None, "no command input"
    if len(text.encode("utf-8", "replace")) > MAX_COMMAND_BYTES:
        return None, "command exceeds %d bytes" % MAX_COMMAND_BYTES
    try:
        cmd = json.loads(text)
    except ValueError:
        return None, "command is not valid JSON"
    if not isinstance(cmd, dict):
        return None, "command must be a JSON object"
    keys = set(cmd)
    if keys != COMMAND_FIELDS:
        missing = sorted(COMMAND_FIELDS - keys)
        extra = sorted(keys - COMMAND_FIELDS)
        return None, "command fields mismatch (missing=%s extra=%s)" % (missing, extra)
    if any(not isinstance(cmd[k], str) for k in COMMAND_FIELDS):
        return None, "every command field must be a string"
    return cmd, None


def evaluate_command(cmd, now, key_bytes, authz, targets,
                     freshness_seconds=DEFAULT_FRESHNESS_SECONDS):
    """Decides whether a parsed command may run. Order matters: shape
    checks first, then authentication (so an unauthenticated sender
    learns nothing about allowlists), then origin/environment/action
    policy, authorization, target allowlist, freshness.

    key_bytes is None when the issuer has no usable key file.
    Returns {'decision': 'ALLOW'|'DENY', 'code': ..., 'detail': ...}."""
    def deny(code, detail):
        return {"decision": "DENY", "code": code, "detail": detail}

    if cmd.get("schema") != SCHEMA_COMMAND:
        return deny("DENIED_SCHEMA", "schema must be %s" % SCHEMA_COMMAND)
    for field in ("command_id", "target_id", "issuer"):
        if not valid_id(cmd.get(field)):
            return deny("DENIED_INVALID_INPUT", "%s has an invalid format" % field)
    if cmd.get("event_ref") and not valid_id(cmd["event_ref"]):
        return deny("DENIED_INVALID_INPUT", "event_ref has an invalid format")

    if key_bytes is None:
        return deny("DENIED_UNAUTHENTICATED", "issuer '%s' has no usable key" % cmd["issuer"])
    if not verify_signature(cmd, key_bytes):
        return deny("DENIED_UNAUTHENTICATED", "signature does not verify for issuer '%s'" % cmd["issuer"])

    origin = cmd["origin"].strip().lower()
    if origin in AI_ORIGINS:
        return deny("DENIED_AI_ORIGIN", "commands originating from '%s' are never executed" % origin)
    if origin not in ALLOWED_ORIGINS:
        return deny("DENIED_ORIGIN", "origin '%s' is not an allowed origin" % origin)

    if cmd["environment"] not in ALLOWED_ENVIRONMENTS:
        return deny("DENIED_PRODUCTION", "environment '%s' refused: only the test environment is in scope" % cmd["environment"])
    if cmd["action"] not in ACTIONS:
        return deny("DENIED_ACTION_NOT_ALLOWLISTED", "action '%s' is not an allowlisted containment action" % cmd["action"])

    if cmd["action"] not in authz.get(cmd["issuer"], set()):
        return deny("DENIED_UNAUTHORIZED", "issuer '%s' is not authorized for '%s'" % (cmd["issuer"], cmd["action"]))
    if (cmd["action"], cmd["target_id"], cmd["environment"]) not in targets:
        return deny("DENIED_TARGET_NOT_ALLOWLISTED", "target '%s' is not allowlisted for '%s'" % (cmd["target_id"], cmd["action"]))

    ok, err = validate_reason(cmd["reason"])
    if not ok:
        return deny("DENIED_INVALID_INPUT", "reason rejected: %s" % err)

    issued = parse_ts(cmd["issued_at"])
    if issued is None:
        return deny("DENIED_INVALID_INPUT", "issued_at must be %s" % _TS_FORMAT)
    age = (now - issued).total_seconds()
    if age > freshness_seconds:
        return deny("DENIED_STALE", "command is %ds old, limit %ds" % (int(age), freshness_seconds))
    if age < -MAX_FUTURE_SKEW_SECONDS:
        return deny("DENIED_STALE", "issued_at is %ds in the future" % int(-age))

    return {"decision": "ALLOW", "code": "ALLOWED", "detail": "all checks passed"}


# ------------------------------------------------------------------
# SND@HOME / SND@ID event evaluation -- advisory, DRY-RUN only
# ------------------------------------------------------------------

_RISK = {"info": "LOW", "low": "LOW", "warning": "MEDIUM", "medium": "MEDIUM",
         "high": "HIGH", "critical": "CRITICAL"}

# event type -> containment action a human may choose to sign
_TYPE_TO_ACTION = {
    "session_hijack": "revoke_test_session",
    "credential_misuse": "revoke_test_session",
    "impossible_travel": "revoke_test_session",
    "c2_beacon": "block_test_endpoint",
    "anomalous_egress": "block_test_endpoint",
    "data_exfiltration": "block_test_endpoint",
    "malware_detected": "isolate_test_worker",
    "compromised_worker": "isolate_test_worker",
    "lateral_movement": "isolate_test_worker",
}


def _first(raw, *keys):
    for k in keys:
        if k in raw and raw[k] not in (None, ""):
            return raw[k]
    return None


def redact_summary(text):
    """Bounded, credential- and network-identifier-free summary. IP and
    MAC addresses are dropped rather than stored: the kill switch needs
    the detection reason, not the traffic metadata."""
    if text is None:
        return ""
    s = str(text)[:MAX_SUMMARY_LENGTH * 2]
    s = _SECRET_PATTERN.sub("[REDACTED]", s)
    s = _NETWORK_ID_PATTERN.sub("[NETID]", s)
    s = " ".join(s.split())
    return s[:MAX_SUMMARY_LENGTH]


def normalize_event(raw):
    """Maps an SND@HOME/SND@ID event onto the minimal v1 shape. SND's own
    field names are not verifiable from this repo (its source is not on
    this machine), so a few common aliases are accepted and everything
    else -- payloads, headers, tokens, addresses -- is discarded.
    Returns (event, error)."""
    if not isinstance(raw, dict):
        return None, "event must be a JSON object"
    source = str(_first(raw, "source") or "").strip().lower()
    if source not in ("snd_home", "snd_id"):
        return None, "source must be snd_home or snd_id"
    event_id = _first(raw, "event_id", "id", "alertId", "alert_id")
    event_id = str(event_id) if event_id is not None else ""
    if not valid_id(event_id):
        return None, "event_id missing or invalid"
    etype = str(_first(raw, "type", "event_type", "category") or "").strip().lower()
    severity = str(_first(raw, "severity", "level") or "").strip().lower()
    target = _first(raw, "target_ref", "test_target")
    target = str(target) if target is not None else ""
    return {
        "schema": SCHEMA_EVENT,
        "source": source,
        "event_id": event_id,
        "type": etype if re.fullmatch(r"[a-z0-9_]{1,40}", etype or "") else "unknown",
        "severity": severity if severity in _RISK else "unknown",
        "observed_at": str(_first(raw, "observed_at", "timestamp", "createdAt") or "")[:40],
        "target_ref": target if valid_id(target) else "",
        "summary": redact_summary(_first(raw, "summary", "message", "description")),
    }, None


def evaluate_event(event, targets):
    """Structured recommendation for one normalized event. ALWAYS dry-run:
    execution_result is fixed to NOT_EXECUTED. A detection alone never
    contains anything; a human must sign a separate command."""
    risk = _RISK.get(event["severity"], "UNKNOWN")
    action = _TYPE_TO_ACTION.get(event["type"])
    if action is None or risk in ("LOW", "UNKNOWN"):
        recommended = "MONITOR"
        reason = "event type '%s' at risk %s does not map to a containment action" % (event["type"], risk)
    else:
        recommended = action
        reason = "event type '%s' at risk %s maps to %s" % (event["type"], risk, action)
    target_allowlisted = bool(event["target_ref"]) and recommended in ACTIONS and \
        (recommended, event["target_ref"], "test") in targets
    return {
        "event_id": event["event_id"],
        "source": event["source"],
        "detection_reason": reason,
        "summary": event["summary"],
        "risk": risk,
        "recommended_action": recommended,
        "target_ref": event["target_ref"],
        "target_allowlisted": target_allowlisted,
        "mode": "DRY_RUN",
        "execution_result": "NOT_EXECUTED",
        "execution_note": "detection alone never triggers containment; an operator must sign a separate command",
    }
