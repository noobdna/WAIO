"""データ取得テスト: KEV / NVD / EPSS parsing + provenance."""

import unittest

from _helpers import FETCHED, fixture, nvd_fixture
from ci_lib import epss, kev, nvd, provenance


class KevTest(unittest.TestCase):
    def setUp(self):
        self.recs, self.stats = kev.parse(fixture("kev.json"), FETCHED)

    def test_valid_entries_only(self):
        self.assertEqual(sorted(self.recs), ["CVE-2026-10001", "CVE-2026-10004", "CVE-2026-10006"])
        self.assertEqual(self.stats["invalid_id"], 2)
        self.assertEqual(self.stats["duplicates"], 1)

    def test_fields(self):
        r = self.recs["CVE-2026-10001"]
        self.assertEqual(r["known_ransomware_campaign_use"], "Known")
        self.assertEqual(r["date_added"], "2026-11-01T00:00:00Z")
        self.assertEqual(r["cwes"], ["CWE-78"])

    def test_provenance_complete_and_distinct_times(self):
        for r in self.recs.values():
            p = r["provenance"]
            self.assertEqual(provenance.validate(p), [])
            self.assertEqual(p["source"], "kev")
            self.assertEqual(p["identifier"], r["cve_id"])
            self.assertEqual(p["fetched_at"], FETCHED)
            # source_updated_at is the catalog's own dateReleased, never 'now'
            self.assertEqual(p["source_updated_at"], "2026-11-05T15:00:00Z")
            self.assertTrue(p["source_url"].startswith("https://www.cisa.gov/"))


class NvdTest(unittest.TestCase):
    def parse(self, cve):
        recs, _ = nvd.parse(nvd_fixture(cve), FETCHED)
        return recs[cve]

    def test_cvss_v40_preferred_over_v31(self):
        c = self.parse("CVE-2026-10001")["cvss"]
        self.assertEqual((c["version"], c["base_score"]), ("4.0", 9.3))

    def test_primary_preferred_within_version(self):
        c = self.parse("CVE-2026-10002")["cvss"]
        self.assertEqual((c["version"], c["base_score"], c["metric_type"]), ("3.1", 8.1, "Primary"))

    def test_unanalyzed_has_no_cvss_and_no_cpes(self):
        r = self.parse("CVE-2026-10004")
        self.assertIsNone(r["cvss"])
        self.assertEqual(r["cpe_matches"], [])

    def test_cpe_ranges_kept(self):
        cm = self.parse("CVE-2026-10001")["cpe_matches"][0]
        self.assertEqual((cm["version_start_including"], cm["version_end_excluding"]), ("4.0", "4.2.1"))

    def test_provenance(self):
        p = self.parse("CVE-2026-10002")["provenance"]
        self.assertEqual(provenance.validate(p), [])
        self.assertEqual(p["source_updated_at"], "2026-10-10T00:00:00Z")
        self.assertIn("cveId=CVE-2026-10002", p["source_url"])


class EpssTest(unittest.TestCase):
    def test_parse(self):
        recs, stats = epss.parse(fixture("epss.json"), FETCHED)
        self.assertEqual(sorted(recs), ["CVE-2026-10001", "CVE-2026-10002", "CVE-2026-10004", "CVE-2026-10005"])
        self.assertEqual((stats["invalid_id"], stats["invalid_score"]), (1, 1))
        r = recs["CVE-2026-10001"]
        self.assertAlmostEqual(r["probability"], 0.94)
        self.assertEqual(r["provenance"]["source_updated_at"], "2026-11-05T00:00:00Z")
        self.assertEqual(provenance.validate(r["provenance"]), [])

    def test_out_of_range_probability_rejected(self):
        body = b'{"data":[{"cve":"CVE-2026-10001","epss":"1.5","percentile":"0.1","date":"2026-11-05"}]}'
        recs, stats = epss.parse(body, FETCHED)
        self.assertEqual(recs, {})
        self.assertEqual(stats["invalid_score"], 1)


class ProvenanceTest(unittest.TestCase):
    def test_bad_fetched_at_rejected(self):
        with self.assertRaises(ValueError):
            provenance.make("kev", "u", "CVE-2026-10001", "2026-11-06", None, "0" * 64)

    def test_unknown_source_rejected(self):
        with self.assertRaises(ValueError):
            provenance.make("rumor", "u", "x", FETCHED, None, "0" * 64)

    def test_unparseable_updated_at_is_none_not_guessed(self):
        p = provenance.make("nvd", "u", "x", FETCHED, "yesterday-ish", "0" * 64)
        self.assertIsNone(p["source_updated_at"])


if __name__ == "__main__":
    unittest.main()
