"""データ欠損テスト + API障害時の安全動作 + state-boundary tests."""

import json
import os
import unittest
from datetime import datetime, timezone
from unittest import mock

import _helpers  # noqa: F401 -- must come first: puts security/corporate_intel on sys.path
import ci
from _helpers import FETCHED, INVENTORY, StoreCase, fixture
from ci_lib import kev, risk, store as store_mod
from ci_lib.store import StoreError

NOW = datetime(2026, 11, 7, tzinfo=timezone.utc)


class MissingDataTest(unittest.TestCase):
    def test_missing_cvss_epss_is_not_low_risk(self):
        r = risk.score_risk({"kev_catalog_known": True}, {"exposure": "internal", "business_impact": "tier3"})
        self.assertEqual(sorted(r["missing"]), ["cvss", "epss"])
        self.assertEqual(r["breakdown"]["severity"], risk.WEIGHTS["severity"] * risk.UNKNOWN_SEVERITY)
        self.assertEqual(r["breakdown"]["likelihood"], risk.WEIGHTS["likelihood"] * risk.UNKNOWN_LIKELIHOOD)
        low = risk.score_risk({"nvd": {"cvss": {"base_score": 2.0}}, "epss": {"probability": 0.001},
                               "kev_catalog_known": True}, {"exposure": "internal", "business_impact": "tier3"})
        self.assertGreater(r["score"], low["score"])

    def test_unknown_exposure_and_impact_are_worst_case(self):
        r = risk.score_risk({"nvd": {"cvss": {"base_score": 5.0}}, "epss": {"probability": 0.1},
                             "kev_catalog_known": True}, {})
        self.assertEqual(r["breakdown"]["exposure"], risk.WEIGHTS["exposure"])
        self.assertEqual(r["breakdown"]["impact"], risk.WEIGHTS["impact"])
        self.assertEqual(sorted(r["missing"]), ["business_impact", "exposure"])

    def test_missing_data_lowers_confidence(self):
        full = {"nvd": {"cvss": {"base_score": 5}, "provenance": {"fetched_at": FETCHED}},
                "epss": {"probability": 0.1, "provenance": {"fetched_at": FETCHED}}, "kev_catalog_known": True}
        thin = {"nvd": {"cvss": None, "provenance": {"fetched_at": FETCHED}}, "kev_catalog_known": False}
        self.assertGreater(risk.score_confidence(full, "exact_cpe", NOW)["score"],
                           risk.score_confidence(thin, "exact_cpe", NOW)["score"])

    def test_old_data_is_less_fresh(self):
        rec = {"nvd": {"cvss": {"base_score": 5}, "provenance": {"fetched_at": "2026-09-01T00:00:00Z"}},
               "kev_catalog_known": True}
        self.assertEqual(risk.score_confidence(rec, "exact_cpe", NOW)["factors"]["freshness"], 10.0)


class ApiFailureTest(StoreCase):
    def _kev_count(self):
        return len(self.store.load_source("kev")["records"])

    def _ingest_file(self, body, name="body.json"):
        p = os.path.join(self.tmp, name)
        with open(p, "wb") as f:
            f.write(body)
        return ci.main(["--state-dir", self.store.root, "ingest", "--source", "kev", "--file", p,
                        "--fetched-at", "2026-11-07T00:00:00Z"])

    def setUp(self):
        super().setUp()
        self.ingest_all()
        self.before = self.store.load_source("kev")

    def assert_kept_and_stale(self):
        self.assertEqual(self.store.load_source("kev"), self.before)
        st = self.store.load_status("kev")
        self.assertTrue(st["stale"])
        self.assertEqual(st["last_success_at"], FETCHED)
        self.assertTrue(st["last_error"])

    def test_malformed_json(self):
        self.assertEqual(self._ingest_file(b"<html>503 Service Unavailable</html>"), 2)
        self.assert_kept_and_stale()

    def test_empty_body(self):
        self.assertEqual(self._ingest_file(b"   \n"), 2)
        self.assert_kept_and_stale()

    def test_wrong_shape(self):
        self.assertEqual(self._ingest_file(b'{"error":"rate limited"}'), 2)
        self.assert_kept_and_stale()

    def test_oversize_body(self):
        with mock.patch.object(ci, "MAX_BODY_BYTES", 10):
            self.assertEqual(self._ingest_file(fixture("kev.json")), 2)
        self.assert_kept_and_stale()

    def test_stale_propagates_to_report(self):
        self._ingest_file(b"garbage")
        with open(INVENTORY) as f:
            inv = json.load(f)
        rep = ci.build_report(self.store, inv, NOW)
        a01 = [f for f in rep["findings"] if f["asset_id"] == "EMB-A01"][0]
        self.assertIn("kev", a01["confidence"]["stale_sources"])
        self.assertTrue(a01["provenance"]["kev"]["stale"])
        self.assertTrue(rep["source_status"]["kev"]["stale"])
        self.assertTrue(a01["kev_listed"])  # previous good data still used

    def test_recovery_clears_stale(self):
        self._ingest_file(b"garbage")
        self.assertEqual(self._ingest_file(fixture("kev.json"), "ok.json"), 0)
        self.assertFalse(self.store.load_status("kev")["stale"])

    def test_fetch_failure_keeps_data(self):
        with mock.patch.object(ci, "_run_fetch", side_effect=RuntimeError("fetch kev failed (rc=1, http=500)")):
            rc = ci.main(["--state-dir", self.store.root, "fetch", "--source", "kev", "--online"])
        self.assertEqual(rc, 2)
        self.assert_kept_and_stale()

    def test_nvd_rate_limit_aborts_cycle(self):
        calls = []

        def fake(source, out, ids):
            calls.append(ids)
            raise RuntimeError("fetch nvd failed (rc=1, http=429)")
        with mock.patch.object(ci, "_run_fetch", side_effect=fake), mock.patch.object(ci.time, "sleep"):
            rc = ci.main(["--state-dir", self.store.root, "fetch", "--source", "nvd", "--online",
                          "--cve", "CVE-2026-10001", "--cve", "CVE-2026-10002", "--cve", "CVE-2026-10003"])
        self.assertEqual(rc, 2)
        self.assertEqual(len(calls), 1)
        self.assertEqual(self.store.load_status("nvd")["failed_ids"],
                         ["CVE-2026-10001", "CVE-2026-10002", "CVE-2026-10003"])

    def test_fetch_refused_offline(self):
        with mock.patch.object(ci, "_run_fetch") as rf:
            rc = ci.main(["--state-dir", self.store.root, "fetch", "--source", "kev"])
        self.assertEqual(rc, 3)
        rf.assert_not_called()

    def test_fetch_rejects_injection_ids(self):
        with mock.patch.object(ci, "_run_fetch") as rf:
            rc = ci.main(["--state-dir", self.store.root, "fetch", "--source", "nvd", "--online",
                          "--cve", "CVE-2026-10001&apiKey=x"])
        self.assertEqual(rc, 2)
        rf.assert_not_called()


class StoreBoundaryTest(StoreCase):
    def test_path_traversal_refused(self):
        with self.assertRaises(StoreError):
            self.store.write_json(("..", "escape.json"), {})
        with self.assertRaises(StoreError):
            self.store.path("/etc/passwd")

    def test_atomic_write_leaves_old_file_on_crash(self):
        self.store.write_json(("sources", "kev.json"), {"records": {"keep": 1}})
        with mock.patch.object(store_mod.os, "replace", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                self.store.write_json(("sources", "kev.json"), {"records": {}})
        self.assertEqual(self.store.load_source("kev"), {"records": {"keep": 1}})
        leftovers = [n for n in os.listdir(self.store.path("sources")) if n.startswith(".tmp-")]
        self.assertEqual(leftovers, [])

    def test_files_private(self):
        p = self.store.write_json(("reports", "r.json"), {})
        self.assertEqual(os.stat(p).st_mode & 0o777, 0o600)

    def test_kev_parse_error_type(self):
        with self.assertRaises(kev.ParseError):
            kev.parse(b"\xff\xfe", FETCHED)


if __name__ == "__main__":
    unittest.main()
