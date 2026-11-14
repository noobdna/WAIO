"""tests/hunt_for_red_unittest.py -- HUNT FOR RED P1 Evidence Ledger.

Fabricated data only (198.51.100.0/24, example.invalid). Every test
uses its own temporary HFR_HOME outside any git tree, never the real
~/waio-ops/hunt-for-red. Run via tests/hunt_for_red_test.sh.
"""

import json
import os
import shutil
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "security", "hunt_for_red"))
import hfr_lib as hl  # noqa: E402
import hfr  # noqa: E402

REGISTRY = {
    "registry_version": "test",
    "sources": [
        {"source_id": "ok-feed", "kind": "cert", "status": "ALLOWED",
         "allowed_uses": {"collect": "yes", "store_raw": "yes"}},
        {"source_id": "ok-json", "kind": "vuln_db", "status": "ALLOWED",
         "allowed_uses": {"collect": "conditional", "store_raw": "conditional"},
         "redact_json_keys": ["credits"]},
        {"source_id": "unknown-src", "kind": "cert", "status": "UNKNOWN",
         "allowed_uses": {"collect": "unknown", "store_raw": "unknown"}},
        {"source_id": "denied-src", "kind": "cert", "status": "DENIED",
         "allowed_uses": {"collect": "yes", "store_raw": "yes"}},
        {"source_id": "nostore", "kind": "cert", "status": "ALLOWED",
         "allowed_uses": {"collect": "yes", "store_raw": "no"}},
        {"source_id": "owner", "kind": "owner_provided", "status": "ALLOWED",
         "allowed_uses": {"collect": "yes", "store_raw": "yes"}},
    ],
}
TS = "2026-01-01T00:00:00Z"
AG = "test-agent"


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="hfr-test-")
        self.home = os.path.join(self.tmp, "home")
        os.makedirs(os.path.join(self.home, "registry"))
        with open(os.path.join(self.home, "registry", "sources.json"), "w") as f:
            json.dump(REGISTRY, f)
        self.led = hl.Ledger(self.home, "HFR-0001")
        self.n = 0

    def tearDown(self):
        for dp, dn, fn in os.walk(self.tmp):
            for x in fn:
                os.chmod(os.path.join(dp, x), 0o644)
        shutil.rmtree(self.tmp)

    def open_case(self, **over):
        f = {"title": "fabricated case", "scope": {"period": "2026-01"}, "approved_by": "human:owner",
             "approved_at": TS, "approval_ref": "TEST-1", "cost_cap": {"minutes": 100, "yen": 0}}
        f.update(over)
        self.led.append("case", f, AG)
        self.led.append("event", {"event": "OPENED", "reason": "test"}, AG)

    def src_file(self, content=b"fabricated advisory text"):
        self.n += 1
        p = os.path.join(self.tmp, "in%d" % self.n)
        with open(p, "wb") as f:
            f.write(content)
        return p

    def cap(self, verification="primary", source="ok-feed", method="feed", content=None, ct="text/plain"):
        c = content if content is not None else ("fabricated text %d" % self.n).encode()
        return self.led.capture_file(self.src_file(c), {
            "source_id": source, "method": method, "url": "https://example.invalid/a",
            "fetched_at": TS, "content_type": ct, "verification": verification}, AG)


class U1Hash(Base):
    def test_canonical_is_key_order_independent(self):
        self.assertEqual(hl.record_hash({"a": 1, "b": "x"}), hl.record_hash({"b": "x", "a": 1}))

    def test_chain_links(self):
        self.open_case()
        r = self.cap()
        recs = self.led.records()
        self.assertEqual(recs[0]["prev_hash"], hl.GENESIS)
        self.assertEqual(recs[-1]["record_id"], r["record_id"])
        self.assertEqual(recs[-1]["prev_hash"], recs[-2]["record_hash"])
        self.assertEqual(hl.verify_case(self.led)["records"], 3)


class U2Tamper(Base):
    def _mut(self, fn):
        self.open_case()
        self.cap()
        self.cap()
        with open(self.led.path) as f:
            lines = f.read().splitlines()
        lines = fn(lines)
        with open(self.led.path, "w") as f:
            f.write("\n".join(lines) + "\n")
        with self.assertRaises(hl.HFRError):
            hl.verify_case(self.led)

    def test_one_char_edit(self):
        self._mut(lambda L: L[:2] + [L[2].replace("fabricated", "fabricatex", 1) if "fabricated" in L[2] else L[2].replace("https", "httpx")] + L[3:])

    def test_line_deleted(self):
        self._mut(lambda L: L[:2] + L[3:])

    def test_lines_swapped(self):
        self._mut(lambda L: L[:2] + [L[3], L[2]])

    def test_raw_file_changed(self):
        self.open_case()
        r = self.cap()
        p = os.path.join(self.led.raw_dir, r["raw_sha256"])
        os.chmod(p, 0o644)
        with open(p, "ab") as f:
            f.write(b"x")
        with self.assertRaises(hl.HFRError):
            hl.verify_case(self.led)

    def test_append_refuses_on_broken_chain(self):
        self._mut(lambda L: L[:2] + L[3:])
        with self.assertRaises(hl.HFRError):
            self.cap()


class U3Registry(Base):
    def test_gates(self):
        self.open_case()
        for src in ("unknown-src", "denied-src", "not-registered", "nostore"):
            with self.assertRaises(hl.HFRError, msg=src):
                self.cap(source=src)
        self.cap(source="ok-feed")

    def test_active_methods_refused(self):
        self.open_case()
        for m in ("dns_resolve", "http_probe", "port_scan", "url_fetch_target"):
            with self.assertRaises(hl.HFRError, msg=m):
                self.cap(method=m)

    def test_owner_method_pairing(self):
        self.open_case()
        with self.assertRaises(hl.HFRError):
            self.cap(source="ok-feed", method="owner_provided")
        with self.assertRaises(hl.HFRError):
            self.cap(source="owner", method="feed")
        self.cap(source="owner", method="owner_provided")


class U4Case(Base):
    def test_capture_before_case(self):
        with self.assertRaises(hl.HFRError):
            self.cap()

    def test_unapproved_case(self):
        with self.assertRaises(hl.HFRError):
            self.open_case(approved_by="claude")

    def test_single_case_record(self):
        self.open_case()
        with self.assertRaises(hl.HFRError):
            self.led.append("case", {"title": "x"}, AG)

    def test_ledger_assigned_fields(self):
        self.open_case()
        with self.assertRaises(hl.HFRError):
            self.led.append("cost", {"kind": "api", "record_hash": "0"}, AG)

    def test_bad_case_id(self):
        with self.assertRaises(hl.HFRError):
            hl.Ledger(self.home, "../evil")

    def test_home_inside_git_tree_refused(self):
        repo = os.path.join(self.tmp, "fakerepo")
        os.makedirs(os.path.join(repo, ".git"))
        with self.assertRaises(hl.HFRError):
            hl.Ledger(repo, "HFR-0001")
        with self.assertRaises(hl.HFRError):
            hl.Ledger(os.path.join(repo, "nonexistent", "sub"), "HFR-0001")


class U5Claims(Base):
    def setUp(self):
        Base.setUp(self)
        self.open_case()
        self.p = self.cap("primary")["record_id"]
        self.s = self.cap("secondary")["record_id"]
        self.d = self.cap("directive_only")["record_id"]

    def claim(self, cls, sup=(), con=(), alt=()):
        return self.led.append("claim", {"text": "t", "class": cls, "rationale": "r", "attribution": False,
                                         "supports": list(sup), "contradicts": list(con), "alternatives": list(alt)}, AG)

    def test_fact_ok(self):
        self.claim("FACT", [self.p])

    def test_fact_needs_primary(self):
        with self.assertRaises(hl.HFRError):
            self.claim("FACT", [self.s])

    def test_fact_with_counter_evidence(self):
        with self.assertRaises(hl.HFRError):
            self.claim("FACT", [self.p], [self.s])
        self.claim("HYPOTHESIS", [self.p], [self.s], ["alt"])

    def test_hypothesis_needs_alternative(self):
        with self.assertRaises(hl.HFRError):
            self.claim("HYPOTHESIS", [self.s])

    def test_directive_only_is_unknown(self):
        with self.assertRaises(hl.HFRError):
            self.claim("HYPOTHESIS", [self.d], alt=["a"])
        with self.assertRaises(hl.HFRError):
            self.claim("FACT", [self.d])
        self.claim("UNKNOWN", [self.d])

    def test_attribution_flag_required(self):
        with self.assertRaises(hl.HFRError):
            self.led.append("claim", {"text": "t", "class": "UNKNOWN", "rationale": "r"}, AG)

    def test_refs_must_be_captures(self):
        with self.assertRaises(hl.HFRError):
            self.claim("UNKNOWN", ["HFR-0001-K-0001"])

    def test_supersedes(self):
        c = self.claim("UNKNOWN", [self.d])
        f = {"text": "t2", "class": "FACT", "rationale": "r", "attribution": False,
             "supports": [self.p], "supersedes": c["record_id"]}
        self.led.append("claim", f, AG)
        with self.assertRaises(hl.HFRError):
            self.led.append("claim", dict(f, supersedes="HFR-0001-C-0099"), AG)
        self.assertEqual(len([r for r in self.led.records() if r["record_type"] == "claim"]), 2)


class U6Ioc(Base):
    def test_defang(self):
        self.assertEqual(hl.defang("198.51.100.7", "ip"), "198[.]51[.]100[.]7")
        self.assertEqual(hl.defang("https://bad.example.invalid/x", "url"), "hxxps://bad[.]example[.]invalid/x")
        self.assertEqual(hl.defang("a@example.invalid", "email_addr"), "a[@]example[.]invalid")
        self.assertEqual(hl.defang("example[.]invalid", "domain"), "example[.]invalid")
        with self.assertRaises(hl.HFRError):
            hl.defang("not-an-ip", "ip")

    def test_live_value_refused(self):
        self.open_case()
        c = self.cap()["record_id"]
        base = {"ioc_type": "domain", "first_capture": c, "status": "candidate"}
        with self.assertRaises(hl.HFRError):
            self.led.append("ioc", dict(base, value_defanged="example.invalid"), AG)
        with self.assertRaises(hl.HFRError):
            self.led.append("ioc", dict(base, value="example.invalid", value_defanged="example[.]invalid"), AG)
        self.led.append("ioc", dict(base, value_defanged="example[.]invalid"), AG)

    def test_cli_defangs(self):
        self.open_case()
        c = self.cap()["record_id"]
        os.environ["HFR_HOME"] = self.home
        try:
            self.assertEqual(hfr.main(["ioc", "HFR-0001", "--agent", AG, "--type", "ip", "--value", "198.51.100.9",
                                       "--first-capture", c, "--status", "candidate"]), 0)
        finally:
            del os.environ["HFR_HOME"]
        self.assertEqual(self.led.records()[-1]["value_defanged"], "198[.]51[.]100[.]9")
        with open(self.led.path) as f:
            self.assertNotIn("198.51.100.9", f.read())


class U7Redaction(Base):
    def test_credits_removed(self):
        self.open_case()
        body = json.dumps({"ghsa_id": "GHSA-xxxx", "summary": "s",
                           "credits": [{"user": {"login": "someone"}, "type": "reporter"}]}).encode()
        r = self.cap(source="ok-json", content=body, ct="application/json", verification="primary")
        with open(os.path.join(self.led.raw_dir, r["raw_sha256"]), "rb") as f:
            stored = f.read()
        self.assertNotIn(b"someone", stored)
        self.assertEqual(r["redaction"]["removed"], ["credits"])
        self.assertEqual(r["redaction"]["original_sha256"], hl.sha256_bytes(body))
        self.assertNotEqual(r["raw_sha256"], r["redaction"]["original_sha256"])

    def test_unlisted_personal_field_refused(self):
        self.open_case()
        body = json.dumps({"summary": "s", "reporter": {"login": "someone"}}).encode()
        with self.assertRaises(hl.HFRError):
            self.cap(source="ok-json", content=body, ct="application/json")
        self.assertFalse(os.path.isdir(self.led.raw_dir) and os.listdir(self.led.raw_dir))

    def test_non_json_with_rules_refused(self):
        self.open_case()
        with self.assertRaises(hl.HFRError):
            self.cap(source="ok-json", content=b"<html>", ct="text/html")

    def test_raw_read_only_and_dedupe(self):
        self.open_case()
        a = self.cap(content=b"same")
        b = self.cap(content=b"same")
        self.assertEqual(b["duplicate_of"], a["record_id"])
        p = os.path.join(self.led.raw_dir, a["raw_sha256"])
        self.assertEqual(os.stat(p).st_mode & 0o777, 0o444)


class U8StopAndCost(Base):
    def test_held_blocks_and_resume_needs_human(self):
        self.open_case()
        self.led.append("event", {"event": "HELD", "reason": "terms unclear", "stop_condition": 1}, AG)
        with self.assertRaises(hl.HFRError):
            self.cap()
        with self.assertRaises(hl.HFRError):
            self.led.append("event", {"event": "RESUMED", "reason": "x"}, AG)
        self.led.append("event", {"event": "RESUMED", "reason": "ok", "approved_by": "human:owner"}, AG)
        self.cap()

    def test_cost_cap_auto_hold(self):
        self.open_case(cost_cap={"minutes": 10, "yen": 0})
        self.led.append("cost", {"kind": "agent_time", "minutes": 8}, AG)
        self.assertEqual(hl.Ledger.case_state(self.led.records()), "OPEN")
        self.led.append("cost", {"kind": "agent_time", "minutes": 5}, AG)
        last = self.led.records()[-1]
        self.assertEqual((last["event"], last["stop_condition"], last["agent"]), ("HELD", 6, "hfr_lib:auto"))
        with self.assertRaises(hl.HFRError):
            self.cap()
        hl.verify_case(self.led)

    def test_cost_validation(self):
        self.open_case()
        for bad in ({"kind": "guess"}, {"kind": "api", "yen": -1}, {"kind": "api", "minutes": 1.5}):
            with self.assertRaises(hl.HFRError, msg=str(bad)):
                self.led.append("cost", bad, AG)

    def test_closed_is_final(self):
        self.open_case()
        self.led.append("event", {"event": "CLOSED", "reason": "done"}, AG)
        with self.assertRaises(hl.HFRError):
            self.led.append("event", {"event": "RESUMED", "reason": "x", "approved_by": "human:owner"}, AG)

    def test_stop_condition_range(self):
        self.open_case()
        with self.assertRaises(hl.HFRError):
            self.led.append("event", {"event": "HELD", "reason": "x", "stop_condition": 9}, AG)


class U9Manifest(Base):
    def test_manifest(self):
        self.open_case()
        self.cap()
        os.environ["HFR_HOME"] = self.home
        try:
            self.assertEqual(hfr.main(["manifest", "HFR-0001"]), 0)
            self.assertEqual(hfr.main(["verify", "HFR-0001"]), 0)
        finally:
            del os.environ["HFR_HOME"]
        with open(os.path.join(self.led.dir, "MANIFEST.sha256")) as f:
            m = f.read()
        self.assertIn("ledger.jsonl", m)
        self.assertEqual(m.count("raw/"), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
