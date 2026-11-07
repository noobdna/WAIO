"""CVE照合テスト + リスク判定テスト (incl. risk/confidence separation)."""

import copy
import json
import unittest
from datetime import datetime, timezone

import _helpers  # noqa: F401 -- must come first: puts security/corporate_intel on sys.path
import ci
from _helpers import INVENTORY, StoreCase
from ci_lib import correlate, risk

NOW = datetime(2026, 11, 7, tzinfo=timezone.utc)


def _inv():
    with open(INVENTORY) as f:
        return json.load(f)


class VersionTest(unittest.TestCase):
    def test_compare(self):
        cv = correlate.compare_versions
        self.assertEqual(cv("4.1.9", "4.2.1"), -1)
        self.assertEqual(cv("4.2.1", "4.2.1"), 0)
        self.assertEqual(cv("4.10", "4.9"), 1)
        self.assertEqual(cv("1.0.1", "1.0"), 1)
        self.assertEqual(cv("1.0rc1", "1.0"), -1)
        self.assertIsNone(cv("*", "1.0"))
        self.assertIsNone(cv("", "1.0"))

    def test_range_boundaries(self):
        cm = {"version_start_including": "3.0", "version_end_including": "3.4"}
        for v, exp in (("2.9", False), ("3.0", True), ("3.4", True), ("3.4.1", False)):
            self.assertEqual(correlate.version_in_range(v, cm, "*"), exp, v)
        cm = {"version_start_excluding": "1.0", "version_end_excluding": "2.0"}
        for v, exp in (("1.0", False), ("1.5", True), ("2.0", False)):
            self.assertEqual(correlate.version_in_range(v, cm, "*"), exp, v)

    def test_exact_and_wildcard_without_bounds(self):
        self.assertTrue(correlate.version_in_range("7.1.0", {}, "7.1.0"))
        self.assertFalse(correlate.version_in_range("7.1.1", {}, "7.1.0"))
        self.assertIsNone(correlate.version_in_range("7.1.0", {}, "*"))

    def test_cpe_parse_escapes(self):
        c = correlate.parse_cpe(r"cpe:2.3:a:acme:mail\:server:3.4:*:*:*:*:*:*:*")
        self.assertEqual((c["vendor"], c["product"], c["version"]), ("acme", "mail:server", "3.4"))
        self.assertIsNone(correlate.parse_cpe("cpe:/a:acme:mail_server:3.4"))


class CorrelateTest(StoreCase):
    def setUp(self):
        super().setUp()
        self.ingest_all()
        self.rep = ci.build_report(self.store, _inv(), NOW)
        self.pairs = {(f["asset_id"], f["cve_id"]): f for f in self.rep["findings"]}

    def test_expected_matches(self):
        self.assertEqual(
            {k: f["match_level"] for k, f in self.pairs.items()},
            {("EMB-A01", "CVE-2026-10001"): "exact_cpe",
             ("EMB-A07", "CVE-2026-10001"): "vendor_product",          # version unknown
             ("EMB-A03", "CVE-2026-10002"): "vendor_product_version",  # 3.4 == end-including
             ("EMB-A08", "CVE-2026-10002"): "vendor_product_version",  # 3.0 == start-including
             ("EMB-A04", "CVE-2026-10003"): "vendor_product_version",  # exact cpe version
             ("EMB-A05", "CVE-2026-10004"): "vendor_product"})         # KEV-only fallback

    def test_patched_and_out_of_range_do_not_match(self):
        self.assertNotIn(("EMB-A02", "CVE-2026-10001"), self.pairs)   # 4.2.1 == end-excluding
        self.assertNotIn(("EMB-A06", "CVE-2026-10005"), self.pairs)   # 12.3 > 12.0
        self.assertFalse(any(c == "CVE-2026-10006" for _, c in self.pairs))

    def test_not_vulnerable_cpe_ignored(self):
        rec = {"nvd": {"cpe_matches": [{"criteria": "cpe:2.3:o:examplesoft:ledger_os:-:*:*:*:*:*:*:*",
                                         "vulnerable": False}]}}
        asset = {"vendor": "ExampleSoft", "product": "Ledger OS", "version": "1"}
        self.assertIsNone(correlate.match_asset(asset, rec))

    def test_report_is_sorted_by_risk(self):
        scores = [f["risk"]["score"] for f in self.rep["findings"]]
        self.assertEqual(scores, sorted(scores, reverse=True))
        self.assertTrue(self.rep["synthetic"])


class RiskTest(StoreCase):
    def setUp(self):
        super().setUp()
        self.ingest_all()
        self.rep = ci.build_report(self.store, _inv(), NOW)
        self.f = {(f["asset_id"], f["cve_id"]): f for f in self.rep["findings"]}

    def test_expected_tiers(self):
        self.assertEqual(self.f[("EMB-A01", "CVE-2026-10001")]["risk"]["tier"], "P1")
        self.assertEqual(self.f[("EMB-A05", "CVE-2026-10004")]["risk"]["tier"], "P2")
        self.assertEqual(self.f[("EMB-A03", "CVE-2026-10002")]["risk"]["tier"], "P3")

    def test_known_value(self):
        # CVSS 4.0 9.3 -> 32.55, KEV -> 35, internet 15, tier2 12, ransomware 5
        r = self.f[("EMB-A01", "CVE-2026-10001")]["risk"]
        self.assertEqual(r["score"], 99.55)
        self.assertEqual(r["likelihood_basis"], "kev_listed")

    def test_breakdown_sums_to_score(self):
        for f in self.rep["findings"]:
            self.assertAlmostEqual(sum(f["risk"]["breakdown"].values()), f["risk"]["score"], places=2)
            self.assertLessEqual(f["risk"]["score"], 100.0)

    def test_kev_floor(self):
        rec = {"kev": {"known_ransomware_campaign_use": "Unknown"}, "nvd": {"cvss": {"base_score": 1.0}},
               "kev_catalog_known": True}
        r = risk.score_risk(rec, {"exposure": "isolated", "business_impact": "tier4"})
        self.assertEqual(r["score"], risk.KEV_FLOOR)
        self.assertGreater(r["breakdown"]["kev_floor_adjustment"], 0)

    def test_monotonic_in_exposure_and_impact(self):
        rec = {"nvd": {"cvss": {"base_score": 7.0}}, "epss": {"probability": 0.1}, "kev_catalog_known": True}
        exps = ["isolated", "internal", "partner_network", "internet_facing"]
        s = [risk.score_risk(rec, {"exposure": e, "business_impact": "tier3"})["score"] for e in exps]
        self.assertEqual(s, sorted(s))
        imps = ["tier4", "tier3", "tier2", "tier1"]
        s = [risk.score_risk(rec, {"exposure": "internal", "business_impact": i})["score"] for i in imps]
        self.assertEqual(s, sorted(s))

    def test_monotonic_in_epss_and_cvss(self):
        asset = {"exposure": "internal", "business_impact": "tier3"}
        s = [risk.score_risk({"nvd": {"cvss": {"base_score": 7.0}}, "epss": {"probability": p},
                              "kev_catalog_known": True}, asset)["score"] for p in (0.0, 0.01, 0.3, 0.9)]
        self.assertEqual(s, sorted(s))
        s = [risk.score_risk({"nvd": {"cvss": {"base_score": c}}, "epss": {"probability": 0.1},
                              "kev_catalog_known": True}, asset)["score"] for c in (0.0, 4.0, 7.0, 10.0)]
        self.assertEqual(s, sorted(s))

    def test_confidence_inputs_do_not_change_risk(self):
        key = ("EMB-A03", "CVE-2026-10002")
        base = self.f[key]
        self.store.record_failure("nvd", "2026-11-07T00:00:00Z", "simulated outage")
        self.store.record_failure("epss", "2026-11-07T00:00:00Z", "simulated outage")
        later = datetime(2027, 3, 1, tzinfo=timezone.utc)
        rep2 = ci.build_report(self.store, _inv(), later)
        f2 = {(f["asset_id"], f["cve_id"]): f for f in rep2["findings"]}[key]
        self.assertEqual(f2["risk"], base["risk"])
        self.assertLess(f2["confidence"]["score"], base["confidence"]["score"])
        self.assertEqual(sorted(f2["confidence"]["stale_sources"]), ["epss", "nvd"])

    def test_confidence_reflects_match_precision(self):
        a01 = self.f[("EMB-A01", "CVE-2026-10001")]["confidence"]
        a07 = self.f[("EMB-A07", "CVE-2026-10001")]["confidence"]
        self.assertGreater(a01["score"], a07["score"])
        self.assertEqual(self.f[("EMB-A01", "CVE-2026-10001")]["risk"]["breakdown"]["severity"],
                         self.f[("EMB-A07", "CVE-2026-10001")]["risk"]["breakdown"]["severity"])

    def test_risk_input_change_does_not_change_confidence(self):
        rec = {"nvd": {"cvss": {"base_score": 7.0}, "provenance": {"fetched_at": "2026-11-06T00:00:00Z"}},
               "epss": {"probability": 0.1, "provenance": {"fetched_at": "2026-11-06T00:00:00Z"}},
               "kev_catalog_known": True}
        c1 = risk.score_confidence(rec, "exact_cpe", NOW)
        rec2 = copy.deepcopy(rec)
        rec2["nvd"]["cvss"]["base_score"] = 9.9
        rec2["epss"]["probability"] = 0.9
        self.assertEqual(risk.score_confidence(rec2, "exact_cpe", NOW), c1)


if __name__ == "__main__":
    unittest.main()
