"""security/ssh_exposure/ssh_exposure_lib.py -- pure-ish computation core
for the SSH Exposure Monitor (sshd_config parsing, ps/lsof line parsing,
listener scope classification, severity classification, event assembly,
state diff/correlation). Same standalone-module convention as
security/shadow_ai/shadow_ai_lib.py and fx_validation/validation_lib.py:
imported directly by both ssh_exposure_monitor.sh's own analysis step and
tests/ssh_exposure_monitor_test.sh, so the classification rules are
defined exactly once and are directly unit-testable with no live
sshd/ps/lsof/firewall state needed.

Scope (same READ-ONLY / observation-only posture as shadow_ai_lib.py's
own header): every function here only ever reads already-collected text
(sshd_config lines, ps/lsof output, an OS adapter's read-only probe
output) or a previously-persisted state snapshot. Nothing in this module
runs a subprocess, opens a socket, writes to any Control Plane file, or
calls sudo -- the only filesystem writes anywhere in the SSH Exposure
Monitor are its own state snapshot
(security/state/ssh_exposure/state.json) and its own audit log, both
performed by ssh_exposure_monitor.sh, never here.

Deliberately loose coupling with security/shadow_ai/shadow_ai_lib.py:
this module does NOT import it, even though both parse `ps`/`lsof`
output -- same explicit design decision
security/attack_graph/attack_graph_lib.py's own header already states
for a different pair of modules ("depend only on the documented
schema, never the sibling module's code").
"""

import glob
import hashlib
import ipaddress
import json
import os
import re

# --- sshd_config parsing (with Include expansion) -----------------------

_DEFAULT_PORT = 22
_INCLUDE_MAX_DEPTH = 5


def _read_file_lines(path):
    """Returns (lines, error). error is None on success, else a short
    machine-readable reason string ('not_found' / 'permission_denied' /
    str(OSError)) -- never raises. No sudo is ever attempted to read a
    file this process cannot already read as itself.
    """
    try:
        with open(path) as f:
            return f.readlines(), None
    except FileNotFoundError:
        return [], "not_found"
    except PermissionError:
        return [], "permission_denied"
    except OSError as e:
        return [], str(e)


def collect_config_entries(path, _depth=0, _included=None, _errors=None):
    """Reads an sshd_config-style file, expanding `Include` directives
    inline (glob-matched, sorted for determinism, depth-capped at
    _INCLUDE_MAX_DEPTH to guard against a cyclical Include). Returns
    (entries, included_files, read_errors):
      entries        - list of (keyword_lower, value_str) in the exact
                        order they were encountered (Include'd files'
                        own lines inserted at the point of inclusion --
                        this matters for `first_value`'s first-wins
                        semantics below, which mirrors real sshd's own
                        documented "the first obtained value is used"
                        behavior for most keywords).
      included_files - every file actually opened, in open order.
      read_errors     - one entry per file that could NOT be read
                        (missing / permission-denied / other OSError),
                        never raised -- a real deployment's
                        /etc/ssh/sshd_config is commonly root-owned
                        mode 600 on some distros, and this module must
                        degrade to "unavailable", never escalate.
    """
    if _included is None:
        _included = []
    if _errors is None:
        _errors = []
    entries = []
    if _depth > _INCLUDE_MAX_DEPTH:
        _errors.append(f"{path}: include depth exceeded")
        return entries, _included, _errors

    lines, err = _read_file_lines(path)
    if err:
        _errors.append(f"{path}: {err}")
        return entries, _included, _errors
    _included.append(path)

    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        keyword = parts[0].lower()
        value = parts[1].strip() if len(parts) > 1 else ""
        if keyword == "include":
            pattern = value
            if not os.path.isabs(pattern):
                pattern = os.path.join(os.path.dirname(path) or ".", pattern)
            for inc in sorted(glob.glob(pattern)):
                if inc in _included:
                    continue
                sub_entries, _, _ = collect_config_entries(
                    inc, _depth=_depth + 1, _included=_included, _errors=_errors
                )
                entries.extend(sub_entries)
            continue
        entries.append((keyword, value))
    return entries, _included, _errors


def first_value(entries, keyword, default=None):
    """First-wins lookup -- matches real sshd's own documented keyword
    precedence (the FIRST occurrence across the main file + its
    Include'd files, in file order, wins; later occurrences are
    ignored), NOT last-wins.
    """
    for k, v in entries:
        if k == keyword:
            return v
    return default


def all_values(entries, keyword):
    """Every occurrence, in encountered order -- used for `Port`, which
    is cumulative (sshd listens on every Port line given), never
    first-wins.
    """
    return [v for k, v in entries if k == keyword]


def parse_sshd_config(path):
    """Returns a structured dict of the security-relevant directives
    this phase cares about. `source` is 'live_config' when the file (or
    at least some of its Include chain) was readable, 'unavailable'
    when nothing could be read at all -- callers must treat 'unavailable'
    conservatively (see classify_severity's own header: an unknown
    PasswordAuthentication/PermitRootLogin is treated the same as its
    enabled/allowed default, never silently treated as safe).
    """
    entries, included, errors = collect_config_entries(path)
    if not entries and errors and len(errors) == len(included) + 1:
        return {
            "source": "unavailable",
            "path": path,
            "included_files": included,
            "read_errors": errors,
            "port": [_DEFAULT_PORT],
            "password_authentication": "unknown",
            "permit_root_login": "unknown",
            "pubkey_authentication": "unknown",
            "listen_address": [],
        }

    ports = []
    for v in all_values(entries, "port"):
        try:
            p = int(v.split()[0])
        except (ValueError, IndexError):
            continue
        if p not in ports:
            ports.append(p)
    if not ports:
        ports = [_DEFAULT_PORT]

    return {
        "source": "live_config",
        "path": path,
        "included_files": included,
        "read_errors": errors,
        "port": ports,
        # OpenSSH's own documented defaults when the keyword is absent:
        # PasswordAuthentication defaults to "yes", PermitRootLogin to
        # "prohibit-password" (root login via key IS still permitted by
        # default -- only root login via password is not), PubkeyAuthentication
        # to "yes".
        "password_authentication": (first_value(entries, "passwordauthentication", "yes") or "yes").lower(),
        "permit_root_login": (first_value(entries, "permitrootlogin", "prohibit-password") or "prohibit-password").lower(),
        "pubkey_authentication": (first_value(entries, "pubkeyauthentication", "yes") or "yes").lower(),
        "listen_address": all_values(entries, "listenaddress"),
    }


# --- ps / lsof parsing ---------------------------------------------------

def parse_ps_line(line):
    """Parses one line of `ps -axo pid=,ppid=,comm=` output (no header
    row). Returns {pid, ppid, comm} or None for a blank/malformed line.
    No `args` field at all -- unlike shadow_ai_lib.py, this module never
    needs a process's command-line arguments (sshd's own exposure signal
    is entirely in its LISTEN sockets and its config file, never in its
    argv), so there is nothing here that would ever need redaction.
    """
    parts = line.split(None, 2)
    if len(parts) < 3:
        return None
    pid, ppid, comm = parts
    if not pid.isdigit():
        return None
    return {
        "pid": int(pid),
        "ppid": int(ppid) if ppid.isdigit() else None,
        "comm": comm,
    }


_LSOF_LISTEN_RE = re.compile(r"^\[?([^\]]*)\]?:(\*|\d+)\s*\(LISTEN\)$")


def parse_lsof_listen_line(line):
    """Parses one line of `lsof -i -P -n` output, returning a LISTEN
    socket record or None for anything else (ESTABLISHED/UDP/malformed
    -- this module only ever cares about LISTEN sockets, never
    established connections, since "is SSH reachable" is entirely a
    LISTEN-state question). Returns
    {command, pid, local_host, local_port}.
    """
    parts = line.split(None, 8)
    if len(parts) < 9:
        return None
    command, pid, _user, _fd, _type, _device, _sizeoff, _node, name = parts
    if not pid.isdigit():
        return None
    m = _LSOF_LISTEN_RE.match(name)
    if not m:
        return None
    host, port = m.groups()
    if port == "*":
        return None
    return {
        "command": command,
        "pid": int(pid),
        "local_host": host or "*",
        "local_port": int(port),
    }


# --- SSH listener identification -----------------------------------------

def is_sshd_process(comm):
    return bool(comm) and "sshd" in comm.lower()


def is_socket_activation_wrapper(comm):
    """True for the process names known to listen ON BEHALF OF sshd
    under on-demand socket activation (macOS launchd, systemd socket
    units) -- i.e. there is no resident `sshd` process yet, but a
    connection to this port WOULD spawn one. See this module's own
    header / ARCHITECTURE.md Phase entry for why this exists: without
    it, a default macOS "Remote Login" setup (launchd-activated,
    port NOT hardcoded -- taken from the running config's own Port
    list) would be invisible to this monitor until someone actually
    connected.
    """
    c = (comm or "").lower()
    return c in ("launchd", "systemd")


def find_ssh_listeners(lsof_listen_records, configured_ports):
    """Returns the subset of LISTEN records that are SSH-relevant: every
    record whose owning process is literally `sshd` (any port -- a
    non-default `Port` in sshd_config is still detected, never
    hardcoded to 22), PLUS any record owned by a socket-activation
    wrapper process (launchd/systemd) whose port is one of
    `configured_ports` (itself read from sshd_config, defaulting to 22
    only as the documented SSH protocol default, never an assumption).
    Each returned record gets a `via` field: 'sshd' (a real resident
    sshd process already) or 'socket_activation' (not yet spawned, but
    this port will reach it).
    """
    out = []
    for rec in lsof_listen_records:
        if is_sshd_process(rec["command"]):
            out.append(dict(rec, via="sshd"))
        elif is_socket_activation_wrapper(rec["command"]) and rec["local_port"] in configured_ports:
            out.append(dict(rec, via="socket_activation"))
    return out


# --- listener scope / exposure classification -----------------------------

_LOOPBACK_TOKENS = {"127.0.0.1", "::1", "localhost"}
_ANY_TOKENS = {"*", "0.0.0.0", "::", "[::]"}


def classify_listener_scope(host):
    """Classifies ONE listener's bind address. Returns (scope, family):
      scope  - 'localhost' | 'lan' | 'all_interfaces' | 'external_direct'
               | 'unknown'
      family - 'ipv4' | 'ipv6' | 'unknown'
    Uses the stdlib `ipaddress` module for private/loopback/link-local
    range detection (IPv4 AND IPv6) rather than hand-rolled regexes --
    deliberately, correctness here directly drives severity.
    """
    h = (host or "").strip()
    if h in _LOOPBACK_TOKENS:
        return "localhost", ("ipv6" if h == "::1" else "ipv4")
    if h in _ANY_TOKENS:
        return "all_interfaces", ("ipv6" if h in ("::", "[::]") else ("ipv4+ipv6" if h == "*" else "ipv4"))

    h_stripped = h.split("%", 1)[0]  # strip an IPv6 zone id, e.g. fe80::1%en0
    try:
        addr = ipaddress.ip_address(h_stripped)
    except ValueError:
        return "unknown", "unknown"
    family = "ipv6" if addr.version == 6 else "ipv4"
    if addr.is_loopback:
        return "localhost", family
    if addr.is_private or addr.is_link_local:
        return "lan", family
    return "external_direct", family


def host_has_public_address(iface_addrs):
    """True if at least one of this host's OWN local interface addresses
    (read-only, locally observed -- never a live reachability probe,
    see this module's own header on the external-connection-test ban)
    is a publicly routable address (not loopback/private/link-local/
    multicast/reserved). Used only to disambiguate an 'all_interfaces'
    (0.0.0.0/::) bind -- it never upgrades a LAN-only bind.
    """
    for raw in iface_addrs:
        h = (raw or "").split("%", 1)[0].strip()
        if not h:
            continue
        try:
            addr = ipaddress.ip_address(h)
        except ValueError:
            continue
        if addr.is_loopback or addr.is_private or addr.is_link_local or addr.is_multicast or addr.is_reserved:
            continue
        return True
    return False


_SCOPE_RANK = {"localhost": 0, "unknown": 1, "lan": 1, "all_interfaces": 2, "external_direct": 3}


def overall_exposure(listener_scopes, external_ip_present):
    """Reduces every individual listener's scope to ONE worst-case
    exposure verdict for the whole host:
      'none'                  - no SSH listener at all
      'localhost'             - every listener is loopback-only
      'lan'                   - worst listener is bound to a specific
                                 private/link-local address
      'all_interfaces_private'- worst listener is 0.0.0.0/:: (bound to
                                 every interface), but this host has NO
                                 publicly routable address of its own
                                 (typical home LAN behind NAT/router --
                                 still flagged, per spec, just one notch
                                 below a confirmed-external bind)
      'external'               - either a listener is bound DIRECTLY to
                                 a specific public address, or it is
                                 bound to 0.0.0.0/:: AND this host also
                                 has a public address -- either way,
                                 this is a configuration FACT read
                                 locally, never a live reachability
                                 probe (no outbound connection test is
                                 ever made to confirm it, per this
                                 module's own safety constraints).
    """
    if not listener_scopes:
        return "none"
    worst = max(listener_scopes, key=lambda s: _SCOPE_RANK.get(s, 1))
    if worst == "all_interfaces":
        return "external" if external_ip_present else "all_interfaces_private"
    if worst == "external_direct":
        return "external"
    return worst  # localhost | lan | unknown


# --- severity classification ----------------------------------------------

SEVERITY_ORDER = ["informational", "low", "medium", "high", "critical"]


def classify_severity(sshd_active, exposure, password_authentication, permit_root_login):
    """Deliberately simple, fully auditable -- every input is already on
    the event, no hidden score (same posture as
    security/incident_learning/incident_confidence.sh's own formula and
    security/shadow_ai/shadow_ai_lib.py's own classify_risk()):

      sshd not active / no listener at all       -> informational
      every listener is loopback-only             -> informational
      worst listener is a specific LAN address    -> low
      worst listener is 0.0.0.0/:: AND no public  -> medium, escalated
        address exists on this host                 to high if
                                                      PasswordAuthentication
                                                      is enabled, or if
                                                      root login is
                                                      allowed (capped at
                                                      high -- exposure to
                                                      the actual internet
                                                      is NOT confirmed
                                                      here)
      confirmed external exposure (bound directly  -> high baseline,
        to a public address, or 0.0.0.0/:: on a        escalated to
        host with its own public address)              CRITICAL if root
                                                        login is allowed

    `password_authentication`/`permit_root_login` of None or 'unknown'
    (config unreadable) is treated the SAME as its documented
    enabled/allowed default -- fail toward MORE scrutiny, never less,
    mirroring security/lib.sh's own fail-closed egress_check() posture.
    """
    if not sshd_active or exposure in ("none", "localhost"):
        return "informational"
    if exposure in ("lan", "unknown"):
        return "low"

    pw_enabled = (password_authentication or "yes").lower() != "no"
    root_allowed = (permit_root_login or "prohibit-password").lower() != "no"

    severity = "medium" if exposure == "all_interfaces_private" else "high"
    if root_allowed:
        severity = "critical" if exposure == "external" else "high"
    elif pw_enabled:
        severity = "high"
    return severity


# --- evidence / event assembly --------------------------------------------

def build_evidence(sshd_active, listeners, config, firewall, exposure_scope, external_ip_present):
    """A flat list of short, human-readable strings stating the basis
    for the severity verdict -- never a black-box score, same "state the
    basis, not just the verdict" posture as every other classifier in
    this repo.
    """
    ev = [f"sshd_active={sshd_active}"]
    if listeners:
        for l in listeners:
            ev.append(
                f"listener {l['local_host']}:{l['local_port']} via={l['via']} "
                f"process={l['command']} scope={l['scope']} family={l['family']}"
            )
    else:
        ev.append("no SSH LISTEN socket observed")
    ev.append(f"config_source={config.get('source')}")
    ev.append(f"PasswordAuthentication={config.get('password_authentication')}")
    ev.append(f"PermitRootLogin={config.get('permit_root_login')}")
    ev.append(f"PubkeyAuthentication={config.get('pubkey_authentication')}")
    ev.append(f"exposure_scope={exposure_scope} external_ip_present={external_ip_present}")
    ev.append(f"firewall={firewall.get('tool')}:{firewall.get('state')}")
    return ev


def build_event(host, now, sshd_active, listeners, config, firewall, iface_addrs, correlation):
    """Assembles the one `ssh_exposure` event this scan produces,
    matching the requested top-level shape exactly (event_type/severity/
    timestamp/host/ssh/firewall/exposure/evidence), plus a `correlation`
    section (see compute_correlation's own header).
    """
    listener_scopes = [l["scope"] for l in listeners]
    external_ip_present = host_has_public_address(iface_addrs)
    exposure_scope = overall_exposure(listener_scopes, external_ip_present)
    severity = classify_severity(
        sshd_active, exposure_scope,
        config.get("password_authentication"), config.get("permit_root_login"),
    )
    evidence = build_evidence(sshd_active, listeners, config, firewall, exposure_scope, external_ip_present)
    return {
        "event_type": "ssh_exposure",
        "severity": severity,
        "timestamp": now,
        "host": host,
        "ssh": {
            "sshd_active": sshd_active,
            "listeners": listeners,
            "config": config,
        },
        "firewall": firewall,
        "exposure": {
            "scope": exposure_scope,
            "external_ip_present": external_ip_present,
        },
        "evidence": evidence,
        "correlation": correlation,
    }


# --- state diff / change correlation (requirement 7) -----------------------

def config_fingerprint(config):
    """A short deterministic hash of just the security-relevant fields
    of a parsed config -- used to detect "the SSH config changed"
    across scans without storing/diffing the raw file text.
    """
    basis = json.dumps(
        {k: config.get(k) for k in (
            "port", "password_authentication", "permit_root_login",
            "pubkey_authentication", "listen_address",
        )},
        sort_keys=True,
    )
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()[:16]


def listener_key(listener):
    return f"{listener['local_host']}:{listener['local_port']}"


def compute_correlation(prev_state, now_iso, sshd_active, config_hash, listener_keys, window_seconds=300):
    """Compares this scan's observed state to the PREVIOUS scan's
    persisted snapshot and reports purely TEMPORAL co-occurrence of
    three specific SSH-domain event types -- config change, sshd
    stopped<->started transition, a brand-new LISTEN socket appearing
    -- within the same scan cycle (this module's own smallest time
    resolution; see its own header/ARCHITECTURE.md Phase entry for why
    sub-interval timestamps are explicitly NOT attempted here).

    Deliberately narrow and causality-free, per the request's own
    constraint: this NEVER reasons about, names, or correlates against
    any other application/process/domain (e.g. a mail client) -- the
    only inputs are this module's own three SSH-domain signals.
    `candidate_incident` is true only when at least two DISTINCT event
    types fired in the same cycle; it is a flag for a human to look
    closer, never a verdict.

    Returns (correlation_dict, new_state_dict). Pure function -- the
    caller persists new_state_dict; this function never touches disk.

    `prev_state is None` (no prior snapshot exists at all -- the very
    first scan this module has ever run on this host) is treated as
    "no baseline to diff against" and deliberately produces ZERO
    events: every listener/every config value is, trivially, "new"
    on a first run, and reporting a `listener_appeared` for each one
    would be noise, not a signal, and could never legitimately
    correlate with anything (there is nothing else to correlate a
    first-ever observation against). An empty-but-present prior
    snapshot (e.g. sshd was previously stopped, no listeners) is a
    REAL baseline and IS diffed normally.
    """
    is_first_scan = prev_state is None
    prev_state = prev_state or {}
    events = []

    prev_hash = prev_state.get("config_hash")
    if not is_first_scan and prev_hash is not None and prev_hash != config_hash:
        events.append({"type": "config_changed", "at": now_iso})

    prev_active = prev_state.get("sshd_active")
    sshd_active_since = prev_state.get("sshd_active_since")
    if is_first_scan:
        sshd_active_since = now_iso if sshd_active else None
    elif prev_active is False and sshd_active is True:
        events.append({"type": "sshd_started", "at": now_iso})
        sshd_active_since = now_iso
    elif prev_active is True and sshd_active is False:
        events.append({"type": "sshd_stopped", "at": now_iso})
        sshd_active_since = None
    elif sshd_active:
        sshd_active_since = sshd_active_since or now_iso
    else:
        sshd_active_since = None

    prev_listener_keys = prev_state.get("listener_keys") or {}
    if not is_first_scan:
        for k in listener_keys:
            if k not in prev_listener_keys:
                events.append({"type": "listener_appeared", "listener": k, "at": now_iso})

    distinct_types = {e["type"] for e in events}
    candidate_incident = len(distinct_types) >= 2

    new_state = {
        "config_hash": config_hash,
        "sshd_active": sshd_active,
        "sshd_active_since": sshd_active_since,
        "listener_keys": {k: prev_listener_keys.get(k, now_iso) for k in listener_keys},
        "last_scan_at": now_iso,
    }
    correlation = {
        "window_seconds": window_seconds,
        "events": events,
        "candidate_incident": candidate_incident,
    }
    return correlation, new_state


# --- OS adapter output parsing ---------------------------------------------

def parse_adapter_output(text):
    """Parses the fixed KEY=VALUE (+ repeated IFACE_ADDR=) line format
    every OS adapter script under security/ssh_exposure/adapters/ emits
    on stdout (see any of those files' own header for the exact
    contract). Unknown keys are ignored, never an error -- an adapter
    gaining a new informational field later should never break this
    parser.
    """
    platform_ = "unknown"
    tool = "none"
    state = "unknown"
    detail = ""
    iface_addrs = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or "=" not in line:
            continue
        key, _, value = line.partition("=")
        if key == "PLATFORM":
            platform_ = value
        elif key == "FIREWALL_TOOL":
            tool = value
        elif key == "FIREWALL_STATE":
            state = value
        elif key == "FIREWALL_DETAIL":
            detail = value
        elif key == "IFACE_ADDR":
            if value:
                iface_addrs.append(value)
    return {
        "platform": platform_,
        "tool": tool,
        "state": state,
        "detail": detail,
    }, iface_addrs
