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
script in this repo already uses, e.g. DEV_APPROVAL_STATE_DIR). The bind
default is 127.0.0.1; a deployment that needs LAN access sets
WAIO_DASHBOARD_BIND explicitly.
"""

import http.server
import os
import socketserver
import sys
from pathlib import Path
from urllib.parse import urlsplit, unquote

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent

DASHBOARD_DIR = Path(os.environ.get("WAIO_DASHBOARD_ROOT", str(SCRIPT_DIR))).resolve()
LOGS_DIR = Path(os.environ.get("WAIO_DASHBOARD_LOGS_ROOT", str(REPO_ROOT / "logs"))).resolve()
# Loopback by default: the dashboard has no authentication, so LAN
# exposure must be an explicit opt-in (WAIO_DASHBOARD_BIND=0.0.0.0 in the
# LaunchAgent's EnvironmentVariables), never the silent default.
BIND = os.environ.get("WAIO_DASHBOARD_BIND", "127.0.0.1")
PORT = int(os.environ.get("WAIO_DASHBOARD_PORT", "8000"))

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


class DashboardHandler(http.server.BaseHTTPRequestHandler):
    server_version = "WAIODashboard/1"

    def _reject(self, code):
        self.send_response(code)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
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
        self.end_headers()
        self.wfile.write(data)

    def _method_not_allowed(self):
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
    with ThreadingHTTPServer((BIND, PORT), DashboardHandler) as httpd:
        print(f"[WAIO Dashboard] serving {len(ALLOWLIST)} allowlisted paths on {BIND}:{PORT} "
              f"(dashboard_dir={DASHBOARD_DIR} logs_dir={LOGS_DIR})", file=sys.stderr)
        httpd.serve_forever()


if __name__ == "__main__":
    main()
