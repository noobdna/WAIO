#!/usr/bin/env python3
"""tests/e2e/mock_services.py -- TEST-ONLY loopback mock of the two
external services WAIO reads from, using the response shapes their own
collector suites already pin (tests/collect_takomachi_status_test.sh,
tests/collect_snd_status_test.sh):

  Takomachi  GET /health /agents /tasks
  SND@HOME   GET /api/lan/status /api/system/latest /api/alerts/active /api/lan/terminals

Binds 127.0.0.1 only. Usage: mock_services.py PORT
The active SND alert mentions "ransomware" so the RED ALERT SND
cross-reference has something to match against a fixture Global Patrol
entry; all data is fixture data.
"""
import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

ROUTES = {
    "/health": {"agent_manager": {"status": "ok"}, "task_queue": {"status": "ok"},
                "plugin_system": {"status": "ok"}, "checked_at": "2026-10-18T00:00:00Z"},
    "/agents": [{"id": "waio-research", "status": "idle"}, {"id": "waio-analysis", "status": "busy"}],
    "/tasks": [{"id": "t1", "status": "in_progress", "assigned_agent_id": "waio-analysis"}],
    "/api/lan/status": {"devices_total": 3, "devices_online": 2},
    "/api/system/latest": {"cpu_pct": 7.5},
    "/api/alerts/active": [{"id": "e2e-a1", "severity": "warning",
                            "message": "ransomware beacon pattern blocked on fixture-terminal"}],
    "/api/lan/terminals": {"status": "ok", "data": [
        {"terminalId": "fixture-terminal", "displayIp": "fixture", "online": True,
         "macs": [], "nickname": "fixture-terminal",
         "firstSeenAt": "2026-10-01T00:00:00.000Z", "lastSeenAt": "2026-10-18T00:00:00.000Z"}]},
}


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = ROUTES.get(self.path.split("?", 1)[0])
        if body is None:
            self.send_response(404)
            self.end_headers()
            return
        data = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    HTTPServer(("127.0.0.1", int(sys.argv[1])), Handler).serve_forever()
