"""Shared helpers for tests/corporate_intel/test_*.py (run by
tests/corporate_intel_test.sh). No network: every test reads fixtures."""

import os
import shutil
import sys
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
MODULE = os.path.join(REPO, "security", "corporate_intel")
FIXTURES = os.path.join(MODULE, "fixtures")
INVENTORY = os.path.join(MODULE, "synthetic", "example_bank_inventory.json")
sys.path.insert(0, MODULE)

import ci  # noqa: E402
from ci_lib.store import Store  # noqa: E402

FETCHED = "2026-11-06T00:00:00Z"
NVD_IDS = ("CVE-2026-10001", "CVE-2026-10002", "CVE-2026-10003", "CVE-2026-10004", "CVE-2026-10005")


def fixture(*parts):
    with open(os.path.join(FIXTURES, *parts), "rb") as f:
        return f.read()


def nvd_fixture(cve):
    return fixture("nvd", f"{cve}.json")


class StoreCase(unittest.TestCase):
    def setUp(self):
        base = os.environ.get("WAIO_TEST_ROOT") or None
        self.tmp = tempfile.mkdtemp(prefix="ci-unit-", dir=base)
        self.store = Store(os.path.join(self.tmp, "state"))

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def ingest_all(self, fetched_at=FETCHED):
        ci.ingest_body(self.store, "kev", fixture("kev.json"), fetched_at)
        self.store.record_success("kev", fetched_at)
        for cve in NVD_IDS:
            ci.ingest_body(self.store, "nvd", nvd_fixture(cve), fetched_at)
        self.store.record_success("nvd", fetched_at)
        ci.ingest_body(self.store, "epss", fixture("epss.json"), fetched_at)
        self.store.record_success("epss", fetched_at)
