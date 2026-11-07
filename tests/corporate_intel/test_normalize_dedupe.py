"""重複排除テスト + CVE Data Normalizer."""

import copy
import json
import os
import unittest

import _helpers  # noqa: F401 -- must come first: puts security/corporate_intel on sys.path
import ci
from _helpers import FETCHED, StoreCase, fixture, nvd_fixture
from ci_lib import cveid, normalize


class CveIdTest(unittest.TestCase):
    def test_normalize(self):
        self.assertEqual(cveid.normalize(" cve-2026-10004 "), "CVE-2026-10004")
        self.assertEqual(cveid.normalize("CVE‑2026–10004"), "CVE-2026-10004")
        self.assertEqual(cveid.normalize("CVE-2026-1234567"), "CVE-2026-1234567")

    def test_reject(self):
        for bad in ("CVE-26-1000", "CVE-2026-123", "CVE-2026-12345678", "CVE-2026-1000;rm -rf /",
                    "CVE-2026-10001&apiKey=x", "", None, 42, "NOT-A-CVE"):
            self.assertIsNone(cveid.normalize(bad), bad)


class DedupeTest(StoreCase):
    def test_reingest_identical_is_noop(self):
        ci.ingest_body(self.store, "kev", fixture("kev.json"), FETCHED)
        c = ci.ingest_body(self.store, "kev", fixture("kev.json"), "2026-11-07T00:00:00Z")
        self.assertEqual((c["added"], c["updated"], c["removed"]), (0, 0, 0))
        self.assertEqual(c["unchanged"], 3)
        raws = os.listdir(self.store.path("raw", "kev"))
        self.assertEqual(len([r for r in raws if not r.startswith(".")]), 1)
        # fresher confirmation refreshes provenance, content unchanged
        rec = self.store.load_source("kev")["records"]["CVE-2026-10001"]
        self.assertEqual(rec["provenance"]["fetched_at"], "2026-11-07T00:00:00Z")

    def test_kev_duplicate_rows_keep_earliest(self):
        ci.ingest_body(self.store, "kev", fixture("kev.json"), FETCHED)
        rec = self.store.load_source("kev")["records"]["CVE-2026-10001"]
        self.assertEqual(rec["date_added"], "2026-11-01T00:00:00Z")
        self.assertEqual(rec["known_ransomware_campaign_use"], "Known")

    def test_kev_full_replace_counts_removed(self):
        ci.ingest_body(self.store, "kev", fixture("kev.json"), FETCHED)
        data = json.loads(fixture("kev.json"))
        data["vulnerabilities"] = [v for v in data["vulnerabilities"] if v.get("cveID") != "CVE-2026-10006"]
        c = ci.ingest_body(self.store, "kev", json.dumps(data).encode(), "2026-11-07T00:00:00Z")
        self.assertEqual(c["removed"], 1)
        self.assertNotIn("CVE-2026-10006", self.store.load_source("kev")["records"])

    def test_older_nvd_response_never_overwrites_newer(self):
        ci.ingest_body(self.store, "nvd", nvd_fixture("CVE-2026-10002"), FETCHED)
        older = json.loads(nvd_fixture("CVE-2026-10002"))
        cve = older["vulnerabilities"][0]["cve"]
        cve["lastModified"] = "2026-01-01T00:00:00.000"
        cve["descriptions"][0]["value"] = "stale older text"
        c = ci.ingest_body(self.store, "nvd", json.dumps(older).encode(), "2026-11-07T00:00:00Z")
        self.assertEqual(c["unchanged"], 1)
        rec = self.store.load_source("nvd")["records"]["CVE-2026-10002"]
        self.assertNotEqual(rec["description"], "stale older text")

    def test_newer_nvd_response_updates(self):
        ci.ingest_body(self.store, "nvd", nvd_fixture("CVE-2026-10002"), FETCHED)
        newer = json.loads(nvd_fixture("CVE-2026-10002"))
        newer["vulnerabilities"][0]["cve"]["lastModified"] = "2026-11-06T00:00:00.000"
        newer["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"][1]["cvssData"]["baseScore"] = 8.8
        c = ci.ingest_body(self.store, "nvd", json.dumps(newer).encode(), "2026-11-07T00:00:00Z")
        self.assertEqual(c["updated"], 1)
        self.assertEqual(self.store.load_source("nvd")["records"]["CVE-2026-10002"]["cvss"]["base_score"], 8.8)


class NormalizeTest(StoreCase):
    def test_one_record_per_cve_across_sources(self):
        self.ingest_all()
        recs = normalize.build(self.store)
        self.assertEqual(sorted(recs), ["CVE-2026-10001", "CVE-2026-10002", "CVE-2026-10003",
                                        "CVE-2026-10004", "CVE-2026-10005", "CVE-2026-10006"])
        r = recs["CVE-2026-10001"]
        self.assertTrue(r["kev"] and r["nvd"] and r["epss"])
        self.assertEqual(r["missing"], [])

    def test_missing_fields_listed(self):
        self.ingest_all()
        recs = normalize.build(self.store)
        self.assertEqual(recs["CVE-2026-10003"]["missing"], ["epss"])
        self.assertEqual(recs["CVE-2026-10004"]["missing"], ["cvss"])
        self.assertEqual(recs["CVE-2026-10006"]["missing"], ["nvd", "cvss", "epss"])

    def test_kev_status_unknown_without_catalog(self):
        ci.ingest_body(self.store, "nvd", nvd_fixture("CVE-2026-10002"), FETCHED)
        rec = normalize.build(self.store)["CVE-2026-10002"]
        self.assertFalse(rec["kev_catalog_known"])
        self.assertIn("kev_status", rec["missing"])

    def test_build_does_not_mutate_store(self):
        self.ingest_all()
        before = copy.deepcopy(self.store.load_source("nvd"))
        self.store.record_failure("nvd", "2026-11-07T00:00:00Z", "x")
        recs = normalize.build(self.store)
        self.assertTrue(recs["CVE-2026-10002"]["nvd"]["provenance"]["stale"])
        self.assertEqual(self.store.load_source("nvd"), before)


if __name__ == "__main__":
    unittest.main()
