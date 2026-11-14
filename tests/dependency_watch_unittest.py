"""tests/dependency_watch_unittest.py -- unit tests for
security/dependency_watch/dependency_watch_lib.py. Fabricated feeds
only (example.invalid); no network. Run via tests/dependency_watch_test.sh."""

import json
import os
import shutil
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "security", "dependency_watch"))
import dependency_watch_lib as dw  # noqa: E402


def feed(*entries):
    body = "".join(
        "<entry><id>%s</id><title>%s</title><link rel=\"alternate\" href=\"https://example.invalid/i/%s\"/>"
        "<published>2026-01-01T00:00:00Z</published><updated>%s</updated><content type=\"html\">%s</content></entry>"
        % (i, t, i, u, c) for i, t, u, c in entries)
    return ('<?xml version="1.0" encoding="UTF-8"?><feed xml:lang="en-US" xmlns="http://www.w3.org/2005/Atom">'
            "<title>Example Status - Incident History</title>%s</feed>" % body).encode("utf-8")


class Classify(unittest.TestCase):
    def test_security(self):
        self.assertEqual(dw.classify("Security incident affecting tokens", "")[0], "security")
        cat, terms = dw.classify("Investigating", "&lt;p&gt;unauthorized access to some accounts&lt;/p&gt;")
        self.assertEqual(cat, "security")
        self.assertIn("unauthorized", terms)

    def test_security_beats_outage(self):
        cat, terms = dw.classify("Degraded performance", "caused by compromised credentials")
        self.assertEqual(cat, "security")
        self.assertIn("compromised", terms)

    def test_outage_maintenance_other(self):
        self.assertEqual(dw.classify("Elevated error rates on API", "")[0], "outage")
        self.assertEqual(dw.classify("Scheduled maintenance in FRA", "")[0], "maintenance")
        self.assertEqual(dw.classify("Welcome to our new page", ""), ("other", []))

    def test_japanese(self):
        self.assertEqual(dw.classify("不正アクセスに関するお知らせ", "")[0], "security")
        self.assertEqual(dw.classify("一部機能の障害", "")[0], "outage")
        self.assertEqual(dw.classify("定期メンテナンス", "")[0], "maintenance")

    def test_word_boundary(self):
        # "download" must not match "down"; "tokenizer" must not match "token"
        self.assertEqual(dw.classify("New download page", "tokenizer docs"), ("other", []))


class Parse(unittest.TestCase):
    def test_parse(self):
        es = dw.parse_atom(feed(("tag:a", "Outage", "2026-01-01T01:00:00Z", "x")))
        self.assertEqual(len(es), 1)
        self.assertEqual(es[0]["url"], "https://example.invalid/i/tag:a")
        self.assertEqual(es[0]["updated_at"], "2026-01-01T01:00:00Z")

    def test_refuse_doctype_entity(self):
        bad = b'<?xml version="1.0"?><!DOCTYPE feed [<!ENTITY a "x">]><feed xmlns="http://www.w3.org/2005/Atom">&a;</feed>'
        with self.assertRaises(dw.FeedError):
            dw.parse_atom(bad)

    def test_refuse_non_atom_and_garbage(self):
        with self.assertRaises(dw.FeedError):
            dw.parse_atom(b"<rss><channel/></rss>")
        with self.assertRaises(dw.FeedError):
            dw.parse_atom(b"<html>nope")

    def test_refuse_oversize(self):
        with self.assertRaises(dw.FeedError):
            dw.parse_atom(b" " * (dw.MAX_FEED_BYTES + 1))


class Process(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="dw-unit-")
        self.notices = os.path.join(self.tmp, "notices.jsonl")

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def run_feed(self, raw):
        p = os.path.join(self.tmp, "f.atom")
        with open(p, "wb") as f:
            f.write(raw)
        return dw.process("example-status", p, self.notices, "2026-01-02T00:00:00Z")

    def lines(self):
        with open(self.notices) as f:
            return [json.loads(l) for l in f if l.strip()]

    def test_new_then_dedupe_then_update(self):
        s = self.run_feed(feed(("tag:a", "Security incident", "2026-01-01T01:00:00Z", ""),
                               ("tag:b", "Scheduled maintenance", "2026-01-01T01:00:00Z", "")))
        self.assertEqual((s["entries"], s["written"], len(s["security_new"])), (2, 2, 1))
        s = self.run_feed(feed(("tag:a", "Security incident", "2026-01-01T01:00:00Z", "")))
        self.assertEqual(s["written"], 0)
        s = self.run_feed(feed(("tag:a", "Security incident - resolved", "2026-01-01T05:00:00Z", "")))
        self.assertEqual(s["written"], 1)
        L = self.lines()
        self.assertEqual(len(L), 3)
        self.assertEqual(L[-1]["change"], "updated")
        self.assertEqual(L[0]["notice_id"], L[-1]["notice_id"])

    def test_record_shape(self):
        self.run_feed(feed(("tag:a", "Elevated errors", "2026-01-01T01:00:00Z", "")))
        r = self.lines()[0]
        for k in ("notice_id", "change", "source_id", "title", "url", "published_at", "updated_at",
                  "fetched_at", "category", "matched_terms", "affected_assets", "raw_sha256"):
            self.assertIn(k, r)
        self.assertTrue(r["notice_id"].startswith("example-status:"))
        self.assertEqual(len(r["raw_sha256"]), 64)

    def test_append_only(self):
        self.run_feed(feed(("tag:a", "Outage", "2026-01-01T01:00:00Z", "")))
        with open(self.notices) as f:
            first = f.read()
        self.run_feed(feed(("tag:b", "Outage 2", "2026-01-01T02:00:00Z", "")))
        with open(self.notices) as f:
            self.assertTrue(f.read().startswith(first))


if __name__ == "__main__":
    unittest.main(verbosity=2)
