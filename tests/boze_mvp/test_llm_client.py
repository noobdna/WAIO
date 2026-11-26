"""U1 tests: boze/llm/client.py against a stub server on 127.0.0.1 only."""

import http.server
import json
import os
import sys
import threading
import time
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, REPO)

from boze.llm import client as C  # noqa: E402
from boze.llm import schema as S  # noqa: E402

KEY = "k" * 64


class Stub(http.server.BaseHTTPRequestHandler):
    mode = "ok"
    reply = "こんにちは"
    seen = []

    def log_message(self, *a):
        pass

    def _send(self, status, body):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        Stub.seen.append(("GET", self.path, self.headers.get("Authorization")))
        self._send(200, b'{"status":"ok"}')

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(n))
        Stub.seen.append(("POST", self.path, self.headers.get("Authorization"), body))
        if self.headers.get("Authorization") != "Bearer " + KEY:
            return self._send(401, b'{"error":"unauthorized"}')
        m = Stub.mode
        if m == "slow":
            time.sleep(1.5)
        if m == "huge":  # a well-formed reply that is simply too big
            out = {"choices": [{"message": {"role": "assistant", "content": "x" * 5000}}]}
            return self._send(200, json.dumps(out).encode())
        if m == "garbage":
            return self._send(200, b"not json")
        if m == "500":
            return self._send(500, b"{}")
        if m == "redirect":
            self.send_response(302)
            self.send_header("Location", "http://example.com/")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        out = {"choices": [{"message": {"role": "assistant", "content": Stub.reply}}]}
        self._send(200, json.dumps(out, ensure_ascii=False).encode("utf-8"))


class LLMClientTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Stub)
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def setUp(self):
        Stub.mode, Stub.reply, Stub.seen = "ok", "こんにちは", []
        self.url = "http://127.0.0.1:%d" % self.port

    def client(self, **kw):
        kw.setdefault("api_key", KEY)
        return C.LLMClient(self.url, **kw)

    # URL policy
    def test_rejects_non_loopback_urls(self):
        for bad in ("http://192.168.1.80:8081", "http://localhost:8081", "https://127.0.0.1:8081",
                    "http://127.0.0.1", "http://user:pw@127.0.0.1:8081", "http://127.0.0.1:8081/v1",
                    "http://127.0.0.1:8081?x=1", "http://127.0.0.2:8081", "http://[::1]:8081",
                    "http://0.0.0.0:8081", "http://127.0.0.1.evil.com:8081", "ftp://127.0.0.1:21", None):
            with self.assertRaises(C.LLMConfigError, msg=bad):
                C.LLMClient(bad)

    def test_accepts_strict_loopback(self):
        self.assertEqual(C.parse_loopback_url("http://127.0.0.1:8081"), 8081)
        self.assertEqual(C.parse_loopback_url("http://127.0.0.1:8081/"), 8081)

    # happy path
    def test_chat_returns_text_and_sends_bearer(self):
        self.assertEqual(self.client().chat([{"role": "user", "content": "hi"}]), "こんにちは")
        self.assertEqual(Stub.seen[-1][1], "/v1/chat/completions")
        self.assertEqual(Stub.seen[-1][2], "Bearer " + KEY)
        self.assertFalse(Stub.seen[-1][3]["stream"])

    def test_health(self):
        self.assertTrue(self.client().health())
        self.assertFalse(C.LLMClient("http://127.0.0.1:1", timeout=1).health())

    def test_proxy_env_is_ignored(self):
        old = {k: os.environ.get(k) for k in ("HTTP_PROXY", "http_proxy", "ALL_PROXY")}
        try:
            for k in old:
                os.environ[k] = "http://10.255.255.1:3128"
            self.assertEqual(self.client(timeout=3).chat([{"role": "user", "content": "x"}]), "こんにちは")
        finally:
            for k, v in old.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v

    # failure modes
    def test_auth_error(self):
        with self.assertRaises(C.LLMAuthError):
            C.LLMClient(self.url, api_key="wrong").chat([{"role": "user", "content": "x"}])

    def test_timeout(self):
        Stub.mode = "slow"
        with self.assertRaises(C.LLMTimeout):
            self.client(timeout=0.5).chat([{"role": "user", "content": "x"}])

    def test_oversized_response(self):
        Stub.mode = "huge"
        with self.assertRaisesRegex(C.LLMResponseError, "larger than"):
            self.client(max_response_bytes=1000).chat([{"role": "user", "content": "x"}])
        self.assertEqual(len(self.client().chat([{"role": "user", "content": "x"}])), 5000)

    def test_garbage_and_500_and_redirect(self):
        for mode, exc in (("garbage", C.LLMResponseError), ("500", C.LLMError), ("redirect", C.LLMError)):
            Stub.mode = mode
            with self.assertRaises(exc, msg=mode):
                self.client().chat([{"role": "user", "content": "x"}])

    def test_prompt_cap_and_message_shape(self):
        with self.assertRaises(C.LLMConfigError):
            self.client(max_prompt_chars=10).chat([{"role": "user", "content": "x" * 11}])
        for bad in ([], [{"role": "tool", "content": "x"}], [{"role": "user", "content": 1}], "hi"):
            with self.assertRaises(C.LLMConfigError):
                self.client().chat(bad)
        self.assertEqual(Stub.seen, [])  # nothing was sent

    def test_key_never_in_repr_or_errors(self):
        c = self.client()
        self.assertNotIn(KEY, repr(c))
        Stub.mode = "500"
        try:
            c.chat([{"role": "user", "content": "x"}])
        except C.LLMError as e:
            self.assertNotIn(KEY, str(e))
        with self.assertRaises(C.LLMConfigError):
            C.LLMClient(self.url, api_key="bad key\n")

    # JSON schema
    SCHEMA = {"type": "object", "additionalProperties": False, "required": ["title", "year"],
              "properties": {"title": {"type": "string", "maxLength": 50},
                             "year": {"type": ["integer", "null"], "minimum": 1900, "maximum": 2100}}}

    def test_json_schema_ok(self):
        Stub.reply = '{"title":"求人A","year":null}'
        self.assertEqual(self.client().chat([{"role": "user", "content": "x"}], json_schema=self.SCHEMA),
                         {"title": "求人A", "year": None})
        self.assertEqual(Stub.seen[-1][3]["response_format"]["schema"], self.SCHEMA)

    def test_json_schema_violations(self):
        for reply in ('{"title":"a"}', '{"title":"a","year":1800}', '{"title":"a","year":2020,"x":1}',
                      '{"title":1,"year":2020}', 'not json', '[1]'):
            Stub.reply = reply
            with self.assertRaises(C.LLMResponseError, msg=reply):
                self.client().chat([{"role": "user", "content": "x"}], json_schema=self.SCHEMA)

    def test_unsupported_schema_refused_before_sending(self):
        with self.assertRaises(S.SchemaError):
            self.client().chat([{"role": "user", "content": "x"}], json_schema={"type": "string", "pattern": "a"})
        self.assertEqual(Stub.seen, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
