"""秘密情報の漏洩防止テスト. A canary value is placed in secret-looking
env vars; a full offline CLI run must not leak it to stdout, stderr,
or any file in the state dir. Also checks the fetch path never
forwards NVD_API_KEY."""

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import _helpers  # noqa: F401 -- must come first: puts security/corporate_intel on sys.path
import ci
from _helpers import FIXTURES, INVENTORY, MODULE
from ci_lib import redact

CANARY = "CANARY-7f3a9c2e-0b1d-4e5f-a6b7-c8d9e0f1a2b3"


class RedactUnitTest(unittest.TestCase):
    def test_env_values_masked(self):
        env = {"NVD_API_KEY": CANARY, "HOME": "/x"}
        self.assertEqual(redact.redact(f"key={CANARY} ok", env), "key=[REDACTED] ok")

    def test_header_and_query_patterns(self):
        for s in ("apiKey: abc123secretvalue", "Authorization: Bearer abcdefghijkl",
                  "https://x/?cveId=CVE-2026-1&apiKey=abc123secret", '{"api_key": "abc123secret"}'):
            out = redact.redact(s, {})
            self.assertNotIn("abc123secret", out, s)
            self.assertNotIn("abcdefghijkl", out, s)
            self.assertIn("[REDACTED]", out)

    def test_short_or_non_secret_env_not_masked(self):
        out = redact.redact("PATH and value abc", {"PATH": "abc", "MY_TOKEN": "short"})
        self.assertEqual(out, "PATH and value abc")


class CanaryEndToEndTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="ci-canary-", dir=os.environ.get("WAIO_TEST_ROOT") or None)
        self.state = os.path.join(self.tmp, "state")
        self.env = dict(os.environ, NVD_API_KEY=CANARY, WAIO_FAKE_SECRET_TOKEN=CANARY,
                        WAIO_CI_STATE_DIR=self.state)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_ci(self, *args):
        p = subprocess.run([sys.executable, os.path.join(MODULE, "ci.py"), *args], env=self.env,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return p.stdout.decode() + p.stderr.decode()

    def test_no_canary_anywhere(self):
        out = ""
        out += self.run_ci("ingest", "--source", "kev", "--file", os.path.join(FIXTURES, "kev.json"))
        for n in os.listdir(os.path.join(FIXTURES, "nvd")):
            out += self.run_ci("ingest", "--source", "nvd", "--file", os.path.join(FIXTURES, "nvd", n))
        out += self.run_ci("ingest", "--source", "epss", "--file", os.path.join(FIXTURES, "epss.json"))
        out += self.run_ci("ingest", "--source", "epss", "--file", "/nonexistent/" + CANARY)  # error path
        out += self.run_ci("report", "--inventory", INVENTORY)
        out += self.run_ci("status")
        out += self.run_ci("fetch", "--source", "kev")
        self.assertIn("findings=", out)
        self.assertNotIn(CANARY, out)
        for root, _, files in os.walk(self.state):
            for name in files:
                self.assertNotIn(CANARY, name)
                with open(os.path.join(root, name), "rb") as f:
                    self.assertNotIn(CANARY.encode(), f.read(), name)

    def test_fetch_never_forwards_api_key(self):
        seen = {}

        def fake_run(argv, env=None, **kw):
            seen["env"], seen["argv"] = env, argv
            raise subprocess.TimeoutExpired(argv, 1)
        with mock.patch.dict(os.environ, {"NVD_API_KEY": CANARY}), \
                mock.patch.object(ci.subprocess, "run", side_effect=fake_run):
            with self.assertRaises(subprocess.TimeoutExpired):
                ci._run_fetch("nvd", os.path.join(self.tmp, "o.json"), ["CVE-2026-10001"])
        self.assertNotIn("NVD_API_KEY", seen["env"])
        self.assertNotIn(CANARY, " ".join(seen["argv"]))
        self.assertEqual(seen["env"]["WAIO_CI_ONLINE"], "1")


if __name__ == "__main__":
    unittest.main()
