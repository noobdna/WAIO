"""MAIL GUARD P2 unit tests: security/mail_guard/mail_guard_lib.py + CLI.

Temp dirs, a 127.0.0.1 stub S3 server, a fake KV and throwaway ed25519 keys
only. No network, no Keychain, no real Cloudflare. All data is synthetic
(example.* / *.invalid domains).
"""

import datetime
import http.server
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from contextlib import redirect_stdout, redirect_stderr

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "security", "mail_guard"))

import mail_guard_lib as L  # noqa: E402
import mail_guard as CLI  # noqa: E402
from boze.approval import approval as A  # noqa: E402

os.environ["MAILGUARD_NO_KEYCHAIN"] = "1"
NOW = datetime.datetime(2026, 11, 28, 12, 0, 0, tzinfo=datetime.timezone.utc)


def jload(path):
    with open(path) as f:
        return json.load(f)


def ev(**kw):
    e = {"event": "decision", "ts": "2026-11-28T11:00:00.123Z", "gateway": "waio-email-threat-gateway",
         "version": "2.0.0-dev", "mode": "monitor", "verdict": "pass", "action": "forward",
         "level": "allow", "score": 0, "reasons": [], "flags": [], "indicators": [],
         "high_confidence": [], "msg_id_hash": "0123456789abcdef", "env_from_domain": "news.example.org",
         "hdr_from_domain": "example.org", "hdr_from_hash": "fedcba9876543210",
         "rcpt_domain": "example.net", "rcpt_hash": "00112233aabbccdd",
         "auth": {"spf": "pass", "dkim": "pass", "dmarc": "pass"},
         "body": {"scanned": True, "truncated": False, "url_count": 1, "url_domains": ["example.org"],
                  "foreign_url_domains": [], "url_blocklist_hits": [], "anchor_mismatches": 0,
                  "attachments": [{"ext": "pdf", "type": "application/pdf"}]},
         "route": "default", "policy_version": None, "policy_source": "baseline",
         "raw_size": 2048, "duration_ms": 3, "config_warnings": []}
    e.update(kw)
    return e


def phish(**kw):
    return ev(verdict="would-quarantine", level="quarantine", score=7,
              indicators=["DISPLAY_NAME_SPOOF", "HTML_ANCHOR_TEXT_MISMATCH"],
              hdr_from_domain="evil.invalid", env_from_domain="evil.invalid",
              body={"scanned": True, "url_count": 2, "url_domains": ["login.evil.invalid"],
                    "foreign_url_domains": ["login.evil.invalid"], "url_blocklist_hits": [],
                    "anchor_mismatches": 1, "attachments": []}, **kw)


# ------------------------------------------------------------------ SigV4

class SigV4Test(unittest.TestCase):
    def test_aws_documented_get_object_vector(self):
        # AWS S3 SigV4 documentation example "GET Object" (examplebucket, Range bytes=0-9).
        auth = L.sigv4_headers(
            "GET", "examplebucket.s3.amazonaws.com", "/test.txt", [], {"range": "bytes=0-9"},
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "us-east-1", "s3",
            "20130524T000000Z")
        self.assertIn("SignedHeaders=host;range;x-amz-content-sha256;x-amz-date", auth)
        self.assertTrue(auth.endswith("Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"))

    def test_aws_documented_list_objects_vector(self):
        auth = L.sigv4_headers(
            "GET", "examplebucket.s3.amazonaws.com", "/", [("max-keys", "2"), ("prefix", "J")], {},
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "us-east-1", "s3",
            "20130524T000000Z")
        self.assertTrue(auth.endswith("Signature=34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7"))


# ------------------------------------------------------------------ events

class SanitizeTest(unittest.TestCase):
    def test_valid_event_keeps_whitelisted_fields_only(self):
        s = L.sanitize_event(ev(subject="hello", hdr_from_hash="fedcba9876543210", extra={"x": 1}))
        self.assertIsNotNone(s)
        for k in ("subject", "extra", "hdr_from_hash", "rcpt_hash", "gateway"):
            self.assertNotIn(k, s)
        self.assertEqual(s["ts"], "2026-11-28T11:00:00Z")
        self.assertEqual(s["body"]["attachments"], [{"ext": "pdf", "type": "application/pdf"}])

    def test_rejects_wrong_gateway_or_bad_ts(self):
        self.assertIsNone(L.sanitize_event(ev(gateway="other")))
        self.assertIsNone(L.sanitize_event(ev(ts="yesterday")))
        self.assertIsNone(L.sanitize_event([1, 2]))

    def test_hostile_values_are_dropped(self):
        s = L.sanitize_event(ev(
            hdr_from_domain="<img src=x onerror=alert(1)>.example",
            env_from_domain="user@example.org", verdict="pwned", mode="yolo",
            indicators=["OK_FLAG", "<script>", "x" * 500, 7],
            score=True, raw_size=-1,
            body={"url_domains": ["ok.example", "bad domain", "аpple.com", "a" * 300],
                  "attachments": [{"ext": "exe\"><", "type": "text/html<"}], "url_count": "9"}))
        self.assertIsNone(s["hdr_from_domain"])
        self.assertIsNone(s["env_from_domain"])
        self.assertIsNone(s["verdict"])
        self.assertIsNone(s["mode"])
        self.assertEqual(s["indicators"], ["OK_FLAG"])
        self.assertIsNone(s["score"])
        self.assertIsNone(s["raw_size"])
        self.assertEqual(s["body"]["url_domains"], ["ok.example"])
        self.assertEqual(s["body"]["attachments"], [{"ext": "", "type": ""}])
        self.assertEqual(s["body"]["url_count"], 0)

    def test_lists_are_capped(self):
        s = L.sanitize_event(ev(flags=["F%d" % i for i in range(500)],
                                body={"url_domains": ["d%d.example" % i for i in range(500)]}))
        self.assertEqual(len(s["flags"]), 40)
        self.assertEqual(len(s["body"]["url_domains"]), 20)


# ------------------------------------------------------------------ R2 pull

class _S3Stub(http.server.BaseHTTPRequestHandler):
    objects = {}
    auth_seen = []
    page = 1000

    def log_message(self, *a):
        pass

    def do_GET(self):
        import urllib.parse as up
        self.auth_seen.append(self.headers.get("Authorization", ""))
        u = up.urlsplit(self.path)
        q = dict(up.parse_qsl(u.query))
        if u.path == "/waio-mailguard-events":
            after = q.get("start-after", "")
            keys = sorted(k for k in self.objects if k.startswith(q.get("prefix", "")) and k > after)
            mk = min(int(q.get("max-keys", "1000")), self.page)
            page, trunc = keys[:mk], len(keys) > mk
            body = ('<?xml version="1.0" encoding="UTF-8"?><ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
                    + "".join("<Contents><Key>%s</Key></Contents>" % k for k in page)
                    + "<IsTruncated>%s</IsTruncated></ListBucketResult>" % ("true" if trunc else "false")).encode()
            self.send_response(200)
        else:
            key = up.unquote(u.path[len("/waio-mailguard-events/"):])
            if key not in self.objects:
                self.send_response(404)
                body = b""
            else:
                self.send_response(200)
                body = self.objects[key]
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class PullTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = http.server.HTTPServer(("127.0.0.1", 0), _S3Stub)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.endpoint = "http://127.0.0.1:%d" % cls.srv.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="mg-pull-")
        _S3Stub.objects = {}
        _S3Stub.auth_seen = []
        _S3Stub.page = 1000

    def tearDown(self):
        shutil.rmtree(self.d)

    def client(self):
        return L.R2Client(self.endpoint, "waio-mailguard-events", "AKTEST", "SKTEST", now=lambda: NOW)

    def put(self, key, obj):
        _S3Stub.objects[key] = obj if isinstance(obj, bytes) else json.dumps(obj).encode()

    def test_pull_stores_sanitised_events_and_advances_cursor(self):
        self.put("events/2026/11/28/10/a.json", ev())
        self.put("events/2026/11/28/11/b.json", phish())
        self.put("events/2026/11/28/11/c.json", b"not json")
        self.put("events/2026/11/25/00/old.json", ev())  # before the 48 h lookback
        r = L.pull(self.client(), self.d, now=NOW)
        self.assertEqual((r["fetched"], r["stored"], r["rejected"]), (3, 2, 1))
        self.assertEqual(r["cursor_after"], "events/2026/11/28/11/c.json")
        self.assertTrue(all(a.startswith("AWS4-HMAC-SHA256 Credential=AKTEST/20261128/auto/s3/") for a in _S3Stub.auth_seen))
        self.assertEqual(oct(os.stat(os.path.join(self.d, "events.jsonl")).st_mode & 0o777), "0o600")
        # second run: nothing new; a new object is picked up exactly once
        self.assertEqual(L.pull(self.client(), self.d, now=NOW)["fetched"], 0)
        self.put("events/2026/11/28/11/d.json", ev())
        self.assertEqual(L.pull(self.client(), self.d, now=NOW)["stored"], 1)
        self.assertEqual(len(L.load_events(self.d)), 3)

    def test_pagination_and_per_run_cap(self):
        for i in range(25):
            self.put("events/2026/11/28/11/%03d.json" % i, ev())
        _S3Stub.page = 10
        r = L.pull(self.client(), self.d, now=NOW, max_objects=15)
        self.assertEqual(r["stored"], 15)
        self.assertTrue(r["more"])
        r = L.pull(self.client(), self.d, now=NOW, max_objects=15)
        self.assertEqual(r["stored"], 10)

    def test_unexpected_key_shapes_are_skipped_not_fetched(self):
        self.put("events/2026/11/28/11/../../x.json", ev())
        self.put("events/2026/11/28/11/ok.json", ev())
        r = L.pull(self.client(), self.d, now=NOW)
        self.assertEqual((r["fetched"], r["stored"], r["rejected"]), (1, 1, 1))

    def test_oversized_object_stops_run_and_keeps_cursor_before_it(self):
        self.put("events/2026/11/28/10/a.json", ev())
        self.put("events/2026/11/28/11/big.json", b"{" + b" " * (L.MAX_EVENT_BYTES + 10) + b"}")
        with self.assertRaises(L.MailGuardError):
            L.pull(self.client(), self.d, now=NOW)
        cur = jload(os.path.join(self.d, "cursor.json"))
        self.assertEqual(cur["after"], "events/2026/11/28/10/a.json")

    def test_dtd_in_list_response_is_refused(self):
        class C(L.R2Client):
            def _get(self, *a):
                return 200, b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "b">]><x>&a;</x>'
        with self.assertRaises(L.MailGuardError):
            C(self.endpoint, "waio-mailguard-events", "a", "b").list("events/", "")

    def test_endpoint_must_be_the_egress_checked_host(self):
        h = L.r2_host("0" * 32)
        self.assertEqual(L.check_endpoint("https://" + h, h), "https://" + h)
        for bad in ("http://" + h, "https://evil.example", "https://u:p@" + h, "https://%s/x" % h,
                    "https://%s?x=1" % h, "http://127.0.0.2:9"):
            with self.assertRaises(L.MailGuardError, msg=bad):
                L.check_endpoint(bad, h)
        with self.assertRaises(L.MailGuardError):
            L.r2_host("not-hex")

    def test_prune_keeps_recent_only(self):
        p = os.path.join(self.d, "events.jsonl")
        with open(p, "w") as f:
            f.write(json.dumps(L.sanitize_event(ev(ts="2026-10-01T00:00:00Z"))) + "\n")
            f.write(json.dumps(L.sanitize_event(ev())) + "\n")
            f.write("garbage\n")
        self.assertEqual(L.prune_events(self.d, 30, now=NOW), 1)
        with open(p) as f:
            self.assertEqual(len(f.read().splitlines()), 1)


# ------------------------------------------------------------------ summaries

class SummaryTest(unittest.TestCase):
    def events(self):
        return [L.sanitize_event(e) for e in
                [ev(), ev(ts="2026-11-28T08:00:00Z"), phish(), phish(ts="2026-11-27T13:00:00Z"),
                 ev(ts="2026-11-24T00:00:00Z", verdict="would-reject", level="block",
                    hdr_from_domain="blocked.invalid", body={"url_blocklist_hits": ["blocked.invalid"]}),
                 ev(route="unmapped", flags=["internal_error"])]]

    def test_summary_counts(self):
        s = L.summarize(self.events(), now=NOW)
        self.assertEqual(s["last_24h"]["messages"], 5)
        self.assertEqual(s["last_24h"]["flagged"], 2)
        self.assertEqual(s["last_24h"]["by_verdict"]["would-quarantine"], 2)
        self.assertEqual(s["last_24h"]["top_flagged_sender_domains"], [{"name": "evil.invalid", "count": 2}])
        self.assertEqual(s["last_24h"]["errors"], 1)
        self.assertEqual(s["last_24h"]["unmapped_routes"], 1)
        self.assertEqual(s["last_7d"]["messages"], 6)
        self.assertEqual(s["last_7d"]["top_url_blocklist_hits"], [{"name": "blocked.invalid", "count": 1}])
        self.assertEqual(s["mode"], "monitor")

    def test_incident_records_follow_collector_contract(self):
        recs = L.incident_records(self.events(), now=NOW)
        self.assertEqual(len(recs), 3)  # evil.invalid x 2 days, blocked.invalid x 1
        for r in recs:
            for k in ("id", "source", "source_type", "source_url", "collected_at", "raw_text"):
                self.assertIn(k, r)
            self.assertTrue(r["id"].startswith("MAILGUARD-"))
            self.assertNotIn("0123456789abcdef", r["raw_text"])  # no message hashes
            self.assertNotIn("@", r["raw_text"])
        again = L.incident_records(self.events(), now=NOW)
        self.assertEqual([r["id"] for r in recs], [r["id"] for r in again])


# ------------------------------------------------------------------ policy

def body_v1(**kw):
    ch = {"mode": "monitor", "add_sender_block": ["bad.invalid"], "add_url_block": ["login.evil.invalid"]}
    ch.update(kw)
    return L.build_policy(None, 1, ch, now=NOW)


class PolicyTest(unittest.TestCase):
    def test_build_produces_a_worker_valid_body(self):
        b = body_v1(set_route={"Info": "owner@dest.example", "*": "catch@dest.example"})
        self.assertEqual(L.validate_policy(b, now=NOW, require_approval=False), [])
        self.assertEqual(L.validate_policy(b, now=NOW), ["approval_missing"])
        self.assertEqual(b["routes"], {"*": "catch@dest.example", "info": "owner@dest.example"})
        self.assertNotIn("base_version", b)
        self.assertEqual(b["expires_at"], "2026-12-28T12:00:00Z")

    def test_validation_rules_match_worker(self):
        good = dict(body_v1(), approved_by_sig_sha256="a" * 64)
        cases = {
            "schema_mismatch": {"schema": 2}, "version_invalid": {"version": 0},
            "mode_invalid": {"mode": "observe"}, "approval_missing": {"approved_by_sig_sha256": "x"},
            "expired": {"expires_at": "2026-11-28T11:59:59Z"}, "expires_invalid": {"expires_at": "soon"},
            "sender_block_entry_invalid": {"sender_block": ["ok.example", "bad domain"]},
            "url_block_invalid": {"url_block": "x.example"},
            "thresholds_invalid": {"review_threshold": 6},
            "route_entry_invalid": {"routes": {"a b": "x@dest.example"}},
        }
        self.assertEqual(L.validate_policy(good, now=NOW), [])
        for want, patch in cases.items():
            self.assertIn(want, L.validate_policy(dict(good, **patch), now=NOW), want)
        self.assertIn("routes_invalid", L.validate_policy(
            dict(good, routes={"r%d" % i: "x@dest.example" for i in range(201)}), now=NOW))

    def test_build_refuses_bad_input(self):
        with self.assertRaises(L.MailGuardError):
            body_v1(add_sender_block=["not a domain"])
        with self.assertRaises(L.MailGuardError):
            body_v1(add_sender_block=["аpple.com"])  # non-ASCII is refused, not converted
        with self.assertRaises(L.MailGuardError):
            L.build_policy(body_v1(), 2, {"remove_url_block": ["absent.example"]}, now=NOW)
        with self.assertRaises(L.MailGuardError):
            L.build_policy(body_v1(), 1, {}, now=NOW)  # version not newer
        with self.assertRaises(L.MailGuardError):
            body_v1(set_route={"x": "not-an-address"})

    def test_diff_masks_route_destinations(self):
        b1 = body_v1(set_route={"info": "owner@dest.example"})
        b2 = L.build_policy(b1, 2, {"mode": "quarantine", "remove_sender_block": ["bad.invalid"],
                                    "add_sender_allow": ["partner.example"],
                                    "set_route": {"info": "other@dest2.example"}}, now=NOW)
        self.assertEqual(b2["base_version"], 1)
        text = "\n".join(L.diff_policy(b1, b2))
        self.assertIn("mode: monitor -> quarantine", text)
        self.assertIn("- sender_block bad.invalid", text)
        self.assertIn("+ sender_allow partner.example", text)
        self.assertIn("route info: ***@dest.example -> ***@dest2.example", text)
        self.assertNotIn("owner@", text)
        self.assertNotIn("other@", text)


# ------------------------------------------------------------------ publish

class FakeKV:
    def __init__(self, data=None, corrupt_readback=False):
        self.data = dict(data or {})
        self.puts = []
        self.corrupt = corrupt_readback

    def get(self, key):
        v = self.data.get(key)
        if v is not None and self.corrupt and key.startswith("policy:v"):
            return v + b"x"
        return v

    def put(self, key, value):
        self.puts.append(key)
        self.data[key] = value


def keygen(d, name):
    k = os.path.join(d, name)
    subprocess.check_call(["/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", name, "-f", k])
    with open(k + ".pub") as f:
        return k, f.read().strip()


def sign(key, path):
    subprocess.check_call(["/usr/bin/ssh-keygen", "-q", "-Y", "sign", "-f", key, "-n", A.NAMESPACE, path],
                          stderr=subprocess.DEVNULL)
    with open(path + ".sig", "rb") as f:
        return f.read()


class PublishTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keys = tempfile.mkdtemp(prefix="mg-keys-")
        cls.key, pub = keygen(cls.keys, "operator")
        cls.stranger, _ = keygen(cls.keys, "stranger")
        cls.signers = os.path.join(cls.keys, "allowed_signers")
        with open(cls.signers, "w") as f:
            f.write('operator@waio namespaces="%s" %s\n' % (A.NAMESPACE, pub))
        os.chmod(cls.signers, 0o644)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.keys)

    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="mg-pub-")
        self.ledger = os.path.join(self.d, "ledger.jsonl")
        self.log = os.path.join(self.d, "publish.log.jsonl")

    def tearDown(self):
        shutil.rmtree(self.d)

    def approve(self, body, key=None, version=None, action=None):
        bb = L.canonical(body)
        req = A.make_request(L.POLICY_JOB_ID, action or L.publish_action(version or body["version"]),
                             L.sha256_hex(bb), 3600)
        p = os.path.join(self.d, "req-%d.json" % len(os.listdir(self.d)))
        with open(p, "wb") as f:
            f.write(req)
        return bb, req, sign(key or self.key, p)

    def publish(self, kv, bb, req, sig):
        return L.publish(kv, bb, req, sig, self.signers, self.ledger, self.log, A)

    def test_happy_path_writes_version_then_pointer(self):
        kv = FakeKV()
        bb, req, sig = self.approve(body_v1())
        entry = self.publish(kv, bb, req, sig)
        self.assertEqual(kv.puts, ["policy:v1", "policy:current"])
        doc = json.loads(kv.data["policy:v1"])
        self.assertEqual(L.validate_policy(doc), [])
        self.assertEqual(doc["approved_by_sig_sha256"], L.sha256_hex(sig))
        stripped = dict(doc)
        del stripped["approved_by_sig_sha256"]
        self.assertEqual(L.sha256_hex(L.canonical(stripped)), entry["body_sha256"])  # auditable
        self.assertEqual(kv.data["policy:current"], b"1")
        self.assertEqual(entry["principal"], "operator@waio")
        # next version on top of it
        b2 = L.build_policy(doc, 2, {"mode": "quarantine"})
        self.publish(kv, *self.approve(b2))
        self.assertEqual(kv.data["policy:current"], b"2")

    def test_replay_is_refused(self):
        kv = FakeKV()
        bb, req, sig = self.approve(body_v1())
        self.publish(kv, bb, req, sig)
        kv2 = FakeKV()
        with self.assertRaisesRegex(L.MailGuardError, "replay"):
            self.publish(kv2, bb, req, sig)
        self.assertEqual(kv2.puts, [])

    def test_tampered_body_or_wrong_signer_writes_nothing(self):
        kv = FakeKV()
        bb, req, sig = self.approve(body_v1())
        tampered = L.canonical(dict(json.loads(bb), sender_block=[]))
        with self.assertRaisesRegex(L.MailGuardError, "approval refused"):
            self.publish(kv, tampered, req, sig)
        with self.assertRaisesRegex(L.MailGuardError, "approval refused"):
            self.publish(kv, *self.approve(body_v1(), key=self.stranger))
        with self.assertRaisesRegex(L.MailGuardError, "approval refused"):
            self.publish(kv, *self.approve(body_v1(), action="publish-v9"))
        with self.assertRaisesRegex(L.MailGuardError, "canonical"):
            self.publish(kv, bb.rstrip(b"\n") + b" \n", req, sig)
        self.assertEqual(kv.puts, [])
        self.assertFalse(os.path.exists(self.ledger))

    def test_stale_base_or_existing_version_is_refused_before_consume(self):
        kv = FakeKV({"policy:current": b"3"})
        bb, req, sig = self.approve(body_v1())
        with self.assertRaisesRegex(L.MailGuardError, "built on"):
            self.publish(kv, bb, req, sig)
        kv = FakeKV({"policy:v1": b"{}"})
        with self.assertRaisesRegex(L.MailGuardError, "immutable"):
            self.publish(kv, bb, req, sig)
        kv = FakeKV({"policy:current": b"garbage"})
        with self.assertRaisesRegex(L.MailGuardError, "not a version"):
            self.publish(kv, bb, req, sig)
        self.assertFalse(os.path.exists(self.ledger))  # approval still usable
        self.publish(FakeKV(), bb, req, sig)

    def test_readback_mismatch_never_switches_pointer(self):
        kv = FakeKV(corrupt_readback=True)
        with self.assertRaisesRegex(L.MailGuardError, "NOT switched"):
            self.publish(kv, *self.approve(body_v1()))
        self.assertNotIn("policy:current", kv.data)

    def test_cli_build_then_dry_run_verify(self):
        state = os.path.join(self.d, "state")
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = CLI.main(["--state-dir", state, "policy-build", "--base-none", "--mode", "monitor",
                           "--add-sender-block", "bad.invalid", "--set-route", "info=owner@dest.example"])
        self.assertEqual(rc, 0, err.getvalue())
        self.assertIn("+ sender_block bad.invalid", out.getvalue())
        self.assertNotIn("owner@", out.getvalue())
        pdir = os.path.join(state, "policy")
        sign(self.key, os.path.join(pdir, "policy-v1.request.json"))
        out = io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = CLI.main(["--state-dir", state, "policy-publish", "--version", "1",
                           "--allowed-signers", self.signers])
        self.assertEqual(rc, 0, err.getvalue())
        self.assertTrue(json.loads(out.getvalue())["dry_run"])
        self.assertFalse(os.path.exists(os.path.join(pdir, "approval-ledger.jsonl")))  # not consumed
        # same version again is refused (files are write-once)
        with redirect_stdout(io.StringIO()), redirect_stderr(err):
            self.assertEqual(CLI.main(["--state-dir", state, "policy-build", "--base-none", "--version", "1"]), 2)
        # --execute without config is "not configured", never a network call
        with redirect_stdout(io.StringIO()), redirect_stderr(err):
            self.assertEqual(CLI.main(["--state-dir", state, "policy-publish", "--version", "1", "--execute",
                                       "--expect-host", "api.cloudflare.com",
                                       "--allowed-signers", self.signers]), 3)

    def test_cli_publish_requires_explicit_signers(self):
        env = os.environ.pop("BOZE_ALLOWED_SIGNERS", None)
        try:
            state = os.path.join(self.d, "state")
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                CLI.main(["--state-dir", state, "policy-build", "--base-none"])
                sign(self.key, os.path.join(state, "policy", "policy-v1.request.json"))
                self.assertEqual(CLI.main(["--state-dir", state, "policy-publish", "--version", "1"]), 3)
        finally:
            if env is not None:
                os.environ["BOZE_ALLOWED_SIGNERS"] = env


class StatusCliTest(unittest.TestCase):
    def test_status_unavailable_then_available(self):
        d = tempfile.mkdtemp(prefix="mg-status-")
        try:
            out = os.path.join(d, "status.json")
            with redirect_stderr(io.StringIO()):
                self.assertEqual(CLI.main(["--state-dir", d, "status", "--out", out]), 0)
            s = jload(out)
            self.assertFalse(s["available"])
            self.assertIn("no events", s["reason"])
            now = L.iso(L.utcnow())
            with open(os.path.join(d, "events.jsonl"), "w") as f:
                f.write(json.dumps(L.sanitize_event(phish(ts=now))) + "\n")
            CLI.main(["--state-dir", d, "status", "--out", out])
            s = jload(out)
            self.assertTrue(s["available"])
            self.assertEqual(s["last_24h"]["flagged"], 1)
        finally:
            shutil.rmtree(d)


if __name__ == "__main__":
    unittest.main(verbosity=1)
