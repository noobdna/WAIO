"""security/deception/decoy_service.py -- TEST-ENVIRONMENT decoy (honeypot)
HTTP service for WAIO v2 Active Containment & Deception.

  python3 decoy_service.py --test-env DIR --sensor-id ID --sensor-key FILE
                           --target-ref TEST_TARGET [--port 0]

SAFETY PROPERTIES (each checked at startup, refusal = exit 2):
  - binds 127.0.0.1 only; there is no option to bind anything else
  - --test-env must be an absolute directory outside this repository
    carrying .killswitch-test-env with "environment=test"
  - serves ONLY canary values generated at startup (secrets.token_hex,
    prefixed WAIO-CANARY-); no real data, user, credential or key is
    read from anywhere. Canaries are written to <test-env>/decoy/
    canaries.json so a later sighting can be matched to this decoy.
  - nothing is sent anywhere: no outbound connection, no reply to the
    requester beyond the fake page, no "hack back" of any kind

EVERY REQUEST IS A HIGH-RISK EVENT: any access to a decoy is hostile by
definition. Each one becomes a waio.killswitch.sensor_event.v1 record
(type decoy_access, severity critical, source snd_home -- the same
shape killswitch_gate.sh execute-policy verifies), HMAC-signed with the
sensor key, written to <test-env>/decoy/spool/<event_id>.json (0600).
Data minimization: the record keeps the decoy route NAME from a fixed
table and the HTTP method -- never the raw path, query, headers, body,
or source address (always loopback here anyway).

Rate limit: at most RATE_LIMIT_PER_MIN events per minute are written;
beyond that requests are still refused but only counted, so a flood
cannot fill the disk.
"""

import argparse
import hashlib
import hmac
import http.server
import json
import os
import secrets
import socketserver
import stat
import sys
import threading
import time

REPO = os.path.realpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
BIND = "127.0.0.1"
RATE_LIMIT_PER_MIN = 60
MAX_BODY = 4096
SCHEMA = "waio.killswitch.sensor_event.v1"

ROUTES = {
    "/admin/login": "admin_login",
    "/backup/db_dump.sql": "db_backup",
    "/.env": "dotenv",
    "/api/v1/keys": "api_keys",
}


def _ts(t=None):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))


def sign(obj, key):
    body = {k: v for k, v in obj.items() if k != "signature"}
    canon = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    return hmac.new(key, canon, hashlib.sha256).hexdigest()


def testenv_error(path):
    if not path or not os.path.isabs(path) or os.path.islink(path) or not os.path.isdir(path):
        return "test env must be an absolute, real directory"
    real = os.path.realpath(path)
    if real == REPO or real.startswith(REPO + os.sep):
        return "test env must be outside the WAIO repository"
    try:
        with open(os.path.join(real, ".killswitch-test-env")) as f:
            if "environment=test" not in [ln.strip() for ln in f.read(4096).splitlines()]:
                return "marker does not declare environment=test"
    except OSError:
        return "missing .killswitch-test-env marker"
    return ""


class Decoy:
    def __init__(self, test_env, sensor_id, key, target_ref):
        self.dir = os.path.join(os.path.realpath(test_env), "decoy")
        self.spool = os.path.join(self.dir, "spool")
        os.makedirs(self.spool, 0o700, exist_ok=True)
        self.sensor_id, self.key, self.target_ref = sensor_id, key, target_ref
        self.canaries = {name: "WAIO-CANARY-%s-%s" % (name, secrets.token_hex(16)) for name in ROUTES.values()}
        with open(os.path.join(self.dir, "canaries.json"), "w") as f:
            json.dump({"generated_at": _ts(), "note": "synthetic decoy values; not real credentials",
                       "canaries": self.canaries}, f, indent=1, sort_keys=True)
        os.chmod(os.path.join(self.dir, "canaries.json"), 0o600)
        self.lock = threading.Lock()
        self.window_start, self.window_count, self.suppressed = time.time(), 0, 0

    def record(self, route, method):
        with self.lock:
            now = time.time()
            if now - self.window_start >= 60:
                self.window_start, self.window_count = now, 0
            if self.window_count >= RATE_LIMIT_PER_MIN:
                self.suppressed += 1
                return None
            self.window_count += 1
        ev = {"schema": SCHEMA, "event_id": "decoy-" + secrets.token_hex(10), "sensor_id": self.sensor_id,
              "source": "snd_home", "type": "decoy_access", "severity": "critical",
              "target_ref": self.target_ref, "observed_at": _ts(now),
              "summary": "decoy route %s accessed with %s" % (route, method)}
        ev["signature"] = sign(ev, self.key)
        tmp = os.path.join(self.spool, "." + ev["event_id"] + ".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(json.dumps(ev, sort_keys=True) + "\n")
        os.replace(tmp, os.path.join(self.spool, ev["event_id"] + ".json"))
        return ev["event_id"]


def make_handler(decoy):
    class Handler(http.server.BaseHTTPRequestHandler):
        server_version = "nginx"
        sys_version = ""

        def log_message(self, *args):
            pass   # no access log: the signed event is the record

        def _handle(self, method):
            route = ROUTES.get(self.path.split("?", 1)[0], "unknown_path")
            try:
                length = min(int(self.headers.get("Content-Length") or 0), MAX_BODY)
            except ValueError:
                length = 0
            if length:
                self.rfile.read(length)   # drained, never stored
            decoy.record(route, method if method in ("GET", "POST", "PUT", "DELETE", "HEAD") else "OTHER")
            if route == "admin_login" and method == "GET":
                code, body = 200, "<html><body><form method=post><input name=u><input name=p type=password></form></body></html>"
            elif route in ("db_backup", "dotenv", "api_keys") and method == "GET":
                code, body = 200, "API_TOKEN=%s\n" % decoy.canaries[route]
            else:
                code, body = 401 if route == "admin_login" else 404, "denied\n"
            data = body.encode()
            self.send_response(code)
            self.send_header("Content-Type", "text/plain" if "<html>" not in body else "text/html")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            if method != "HEAD":
                self.wfile.write(data)

        def do_GET(self):
            self._handle("GET")

        def do_POST(self):
            self._handle("POST")

        def do_HEAD(self):
            self._handle("HEAD")

        def do_PUT(self):
            self._handle("PUT")

        def do_DELETE(self):
            self._handle("DELETE")
    return Handler


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--test-env", required=True)
    ap.add_argument("--sensor-id", required=True)
    ap.add_argument("--sensor-key", required=True)
    ap.add_argument("--target-ref", required=True)
    ap.add_argument("--port", type=int, default=0)
    a = ap.parse_args()
    err = testenv_error(a.test_env)
    if err:
        print(json.dumps({"ok": False, "detail": err}))
        return 2
    try:
        st = os.lstat(a.sensor_key)
    except OSError:
        st = None
    if st is None or not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or st.st_mode & 0o077:
        print(json.dumps({"ok": False, "detail": "sensor key must be a private regular file owned by you"}))
        return 2
    with open(a.sensor_key, "rb") as f:
        key = f.read()
    decoy = Decoy(a.test_env, a.sensor_id, key, a.target_ref)
    with Server((BIND, a.port), make_handler(decoy)) as httpd:
        port = httpd.server_address[1]
        with open(os.path.join(decoy.dir, "port"), "w") as f:
            f.write(str(port))
        print(json.dumps({"ok": True, "bind": BIND, "port": port}), flush=True)
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
