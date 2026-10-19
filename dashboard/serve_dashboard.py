#!/usr/bin/env python3
"""dashboard/serve_dashboard.py -- WAIO Dashboard HTTP server.

Replaces the plain `python3 -m http.server --directory dashboard`
command the real, installed `com.waio.dashboard-server` LaunchAgent
currently runs. That command's `--directory dashboard` scope is why
dashboard/index.html's own `fetch("../logs/*.json")` calls 404 --
`logs/` is a sibling of `dashboard/`, outside what `--directory`
exposes. This file fixes that WITHOUT widening the served directory to
the repo root (which would also expose workers/*.json, security/state/,
and every other log) -- instead, it serves an exact, hardcoded path
allowlist: three static assets plus seven specific logs/*.json files,
nothing else, no directory listing, no path-derived traversal of any
kind (the allowlist maps fixed URL strings to fixed file paths; there
is no code path that turns a request path into a filesystem path by
substitution, so there is nothing for a `..`-style attack to exploit).

`snd-status-latest.json` is deliberately NOT in this allowlist: its own
collector (dashboard/collect_snd_status.sh) documents that SND_HOME's
own upstream API gates this exact data (a LAN device/MAC list) behind a
Bearer token because "a LAN device list is sensitive" -- serving it
here, unauthenticated, would reopen that same exposure. Omitted by
explicit operator decision, not an oversight; the dashboard's own JS
already falls back to its embedded sample for that one panel, same as
it does for any other fetch failure.

Bind/port/root directories are overridable via environment variables
for test isolation (same convention every other WAIO test-overridable
script in this repo already uses, e.g. DEV_APPROVAL_STATE_DIR).

Access policy (fail closed):
  - WAIO_DASHBOARD_BIND defaults to 127.0.0.1.
  - Any non-loopback bind (e.g. 0.0.0.0 for iPad/iPhone access on the
    LAN) refuses to start unless BOTH of these are configured:
      WAIO_DASHBOARD_AUTH_FILE        HTTP Basic credential file written
                                      by dashboard/set_dashboard_auth.py:
                                      one line "user:pbkdf2_sha256$iter$
                                      salt$hash", owned by this user,
                                      mode 0600, kept outside the repo.
                                      Only a salted hash is stored; no
                                      password is ever in Git or logs.
      WAIO_DASHBOARD_ALLOWED_CLIENTS  comma-separated client CIDRs, each
                                      private or loopback (e.g.
                                      192.168.1.0/24). Public ranges and
                                      catch-alls are refused.
  - When set, both are enforced on loopback binds too. With neither set
    and a loopback bind, only 127.0.0.1/::1 clients are accepted.
  - 0.0.0.0 listens on every IPv4 interface, not "the LAN": the client
    allowlist is what limits who can connect. Binds are IPv4 only; an
    IPv6 address such as ::1 fails to start (exit 1, never listens).
  - Basic auth over plain HTTP is readable by anyone who can sniff the
    LAN; use a password unique to this dashboard. TLS is not provided.
"""

import base64
import binascii
import hashlib
import hmac
import http.server
import ipaddress
import os
import socketserver
import stat
import sys
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit, unquote

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent

DASHBOARD_DIR = Path(os.environ.get("WAIO_DASHBOARD_ROOT", str(SCRIPT_DIR))).resolve()
LOGS_DIR = Path(os.environ.get("WAIO_DASHBOARD_LOGS_ROOT", str(REPO_ROOT / "logs"))).resolve()
# Loopback by default; see "Access policy" in the header for what a
# non-loopback bind additionally requires.
BIND = os.environ.get("WAIO_DASHBOARD_BIND", "127.0.0.1")
PORT = int(os.environ.get("WAIO_DASHBOARD_PORT", "8000"))
AUTH_FILE = os.environ.get("WAIO_DASHBOARD_AUTH_FILE", "")
ALLOWED_CLIENTS = os.environ.get("WAIO_DASHBOARD_ALLOWED_CLIENTS", "")

MIN_PBKDF2_ITERATIONS = 100000
# Per-client-IP brute-force brake, same shape as the LAN Dashboard
# Gateway's own lockout: 5 failures within 60s -> 30s of 429s.
LOCKOUT_FAILURES = 5
LOCKOUT_WINDOW = 60
LOCKOUT_COOLDOWN = 30

# path -> (base_dir, relative_filename, content_type). Every entry here
# was reviewed and approved explicitly; adding a new one is a security
# decision, not a drive-by edit -- see this file's own header.
ALLOWLIST = {
    "/": (DASHBOARD_DIR, "index.html", "text/html; charset=utf-8"),
    "/index.html": (DASHBOARD_DIR, "index.html", "text/html; charset=utf-8"),
    "/earth_weather.html": (DASHBOARD_DIR, "earth_weather.html", "text/html; charset=utf-8"),
    "/logs/waio-status-latest.json": (LOGS_DIR, "waio-status-latest.json", "application/json; charset=utf-8"),
    "/logs/response60-latest.json": (LOGS_DIR, "response60-latest.json", "application/json; charset=utf-8"),
    "/logs/incident-history-latest.json": (LOGS_DIR, "incident-history-latest.json", "application/json; charset=utf-8"),
    "/logs/waio-segments-latest.json": (LOGS_DIR, "waio-segments-latest.json", "application/json; charset=utf-8"),
    "/logs/incident-learning-status-latest.json": (LOGS_DIR, "incident-learning-status-latest.json", "application/json; charset=utf-8"),
    "/logs/decision-status-latest.json": (LOGS_DIR, "decision-status-latest.json", "application/json; charset=utf-8"),
    "/logs/takomachi-status-latest.json": (LOGS_DIR, "takomachi-status-latest.json", "application/json; charset=utf-8"),
}


def _resolve_allowed(path):
    """Returns (absolute_path, content_type) for an allowlisted path
    whose resolved file still lands inside its own declared base_dir,
    or None otherwise (not in the allowlist, or the resolved path
    somehow escaped -- defense in depth; the allowlist's own filenames
    are fixed strings with no user input in them, so this should never
    actually trigger, but costs nothing to check, same realpath-
    containment convention this repo's approval gates already use)."""
    entry = ALLOWLIST.get(path)
    if entry is None:
        return None
    base_dir, filename, content_type = entry
    candidate = (base_dir / filename).resolve()
    try:
        candidate.relative_to(base_dir)
    except ValueError:
        return None
    return (candidate, content_type)


class ConfigError(Exception):
    pass


def is_loopback_bind(bind):
    if bind == "localhost":
        return True
    try:
        return ipaddress.ip_address(bind).is_loopback
    except ValueError:
        return False


def parse_allowed_clients(spec):
    """Comma-separated CIDRs -> list of networks. Every entry must be
    private or loopback; a public range or a catch-all is refused."""
    nets = []
    for item in (x.strip() for x in spec.split(",")):
        if not item:
            continue
        try:
            net = ipaddress.ip_network(item, strict=False)
        except ValueError:
            raise ConfigError(f"WAIO_DASHBOARD_ALLOWED_CLIENTS: not a CIDR: {item!r}")
        if net.prefixlen == 0 or not (net.is_private or net.is_loopback):
            raise ConfigError(f"WAIO_DASHBOARD_ALLOWED_CLIENTS: {item} is not a private/loopback range")
        nets.append(net)
    if not nets:
        raise ConfigError("WAIO_DASHBOARD_ALLOWED_CLIENTS is empty")
    return nets


def load_auth_file(path):
    """Returns (user, iterations, salt, digest). Refuses a file that is
    missing, not a regular file, not owned by this user, or readable by
    group/others."""
    try:
        st = os.stat(path)
    except OSError as e:
        raise ConfigError(f"WAIO_DASHBOARD_AUTH_FILE: cannot stat {path}: {e.strerror}")
    if not stat.S_ISREG(st.st_mode):
        raise ConfigError(f"WAIO_DASHBOARD_AUTH_FILE: {path} is not a regular file")
    if st.st_uid != os.getuid():
        raise ConfigError(f"WAIO_DASHBOARD_AUTH_FILE: {path} is not owned by this user")
    if st.st_mode & 0o077:
        raise ConfigError(f"WAIO_DASHBOARD_AUTH_FILE: {path} must be mode 0600")
    try:
        line = Path(path).read_text().strip()
    except OSError as e:
        raise ConfigError(f"WAIO_DASHBOARD_AUTH_FILE: cannot read {path}: {e.strerror}")
    except ValueError:
        raise ConfigError(f"WAIO_DASHBOARD_AUTH_FILE: {path} is malformed")
    try:
        user, rec = line.split(":", 1)
        scheme, iters, salt, digest = rec.split("$")
        iters = int(iters)
        salt = base64.b64decode(salt, validate=True)
        digest = base64.b64decode(digest, validate=True)
    except (ValueError, binascii.Error):
        raise ConfigError(f"WAIO_DASHBOARD_AUTH_FILE: {path} is malformed")
    if not user or scheme != "pbkdf2_sha256" or iters < MIN_PBKDF2_ITERATIONS or len(salt) < 16 or len(digest) != 32:
        raise ConfigError(f"WAIO_DASHBOARD_AUTH_FILE: {path} is malformed or too weak")
    return (user, iters, salt, digest)


def build_policy(bind, auth_file, allowed_clients):
    """Returns {"auth": tuple|None, "clients": [networks]} or raises
    ConfigError. A non-loopback bind without auth AND a client
    allowlist is refused (fail closed)."""
    if not is_loopback_bind(bind):
        if not auth_file or not allowed_clients:
            raise ConfigError(
                f"refusing to bind {bind}: a non-loopback bind requires both "
                "WAIO_DASHBOARD_AUTH_FILE and WAIO_DASHBOARD_ALLOWED_CLIENTS")
    auth = load_auth_file(auth_file) if auth_file else None
    if allowed_clients:
        clients = parse_allowed_clients(allowed_clients)
    else:
        clients = [ipaddress.ip_network("127.0.0.0/8"), ipaddress.ip_network("::1/128")]
    return {"auth": auth, "clients": clients}


def client_allowed(addr, clients):
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return any(ip.version == net.version and ip in net for net in clients)


class DashboardHandler(http.server.BaseHTTPRequestHandler):
    server_version = "WAIODashboard/1"
    policy = {"auth": None, "clients": [ipaddress.ip_network("127.0.0.0/8"), ipaddress.ip_network("::1/128")]}
    _failures = {}
    _verified = set()
    _state_lock = threading.Lock()

    def _reject(self, code, headers=()):
        self.send_response(code)
        for k, v in headers:
            self.send_header(k, v)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _locked_out(self, ip, now):
        with self._state_lock:
            times = [t for t in self._failures.get(ip, []) if now - t < LOCKOUT_WINDOW + LOCKOUT_COOLDOWN]
            self._failures[ip] = times
            recent = [t for t in times if now - t < LOCKOUT_WINDOW]
            return len(recent) >= LOCKOUT_FAILURES and now - times[-1] < LOCKOUT_COOLDOWN

    def _record_failure(self, ip, now):
        with self._state_lock:
            self._failures.setdefault(ip, []).append(now)

    def _authenticated(self):
        user, iters, salt, digest = self.policy["auth"]
        header = self.headers.get("Authorization", "")
        if not header.startswith("Basic "):
            return False
        # Repeat requests (index.html fetches seven JSON files) skip the
        # PBKDF2 cost once a header has verified; only its hash is kept.
        key = hashlib.sha256(header.encode()).digest()
        with self._state_lock:
            if key in self._verified:
                return True
        try:
            got_user, got_pw = base64.b64decode(header[6:], validate=True).decode("utf-8").split(":", 1)
        except (ValueError, binascii.Error, UnicodeDecodeError):
            return False
        calc = hashlib.pbkdf2_hmac("sha256", got_pw.encode("utf-8"), salt, iters)
        ok = hmac.compare_digest(got_user.encode(), user.encode()) & hmac.compare_digest(calc, digest)
        if ok:
            with self._state_lock:
                self._verified.add(key)
        return ok

    def do_GET(self):
        ip = self.client_address[0]
        if not client_allowed(ip, self.policy["clients"]):
            self._reject(403)
            return
        if self.policy["auth"] is not None:
            now = time.monotonic()
            if self._locked_out(ip, now):
                self._reject(429, [("Retry-After", str(LOCKOUT_COOLDOWN))])
                return
            if not self._authenticated():
                if self.headers.get("Authorization"):
                    self._record_failure(ip, now)
                self._reject(401, [("WWW-Authenticate", 'Basic realm="WAIO Dashboard", charset="UTF-8"')])
                return
        path = unquote(urlsplit(self.path).path)
        resolved = _resolve_allowed(path)
        if resolved is None:
            self._reject(404)
            return
        file_path, content_type = resolved
        try:
            data = file_path.read_bytes()
        except OSError:
            # Allowlisted route, but the collector hasn't written this
            # file yet (e.g. first run) -- 404 is exactly what the
            # dashboard's own fetch().catch() already treats as
            # "fall back to the embedded sample".
            self._reject(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def _method_not_allowed(self):
        # Same order as do_GET: a client outside the allowlist learns
        # nothing beyond 403, whatever the method.
        if not client_allowed(self.client_address[0], self.policy["clients"]):
            self._reject(403)
            return
        self._reject(405)

    do_HEAD = _method_not_allowed
    do_POST = _method_not_allowed
    do_PUT = _method_not_allowed
    do_DELETE = _method_not_allowed
    do_PATCH = _method_not_allowed
    do_OPTIONS = _method_not_allowed


class ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def main():
    try:
        DashboardHandler.policy = build_policy(BIND, AUTH_FILE, ALLOWED_CLIENTS)
    except ConfigError as e:
        print(f"[WAIO Dashboard] ERROR: {e}. Not starting.", file=sys.stderr)
        sys.exit(2)
    policy = DashboardHandler.policy
    with ThreadingHTTPServer((BIND, PORT), DashboardHandler) as httpd:
        print(f"[WAIO Dashboard] serving {len(ALLOWLIST)} allowlisted paths on {BIND}:{PORT} "
              f"(dashboard_dir={DASHBOARD_DIR} logs_dir={LOGS_DIR} "
              f"auth={'basic' if policy['auth'] else 'off'} "
              f"clients={','.join(str(n) for n in policy['clients'])})", file=sys.stderr)
        httpd.serve_forever()


if __name__ == "__main__":
    main()
