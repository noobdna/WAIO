"""Static security-boundary checks (SECURITY_BOUNDARIES §1-§5)."""

import ast
import ipaddress
import json
import os
import re
import subprocess
import unittest

from _helpers import FIXTURES, INVENTORY, MODULE, REPO

FORBIDDEN_IMPORTS = {"socket", "urllib", "http", "requests", "ftplib", "smtplib", "ssl", "asyncio"}
FORBIDDEN_CALLS = re.compile(r"guardian|ducopa|recover\.sh|recovery_engine|knowledge_manager|killswitch|"
                             r"containment|launchctl|ssh\b|osascript", re.I)
DOC_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]


def _py_files():
    for root, _, files in os.walk(MODULE):
        for n in files:
            if n.endswith(".py"):
                yield os.path.join(root, n)


class BoundaryTest(unittest.TestCase):
    def test_no_network_imports(self):
        for path in _py_files():
            tree = ast.parse(open(path).read())
            for node in ast.walk(tree):
                names = []
                if isinstance(node, ast.Import):
                    names = [a.name for a in node.names]
                elif isinstance(node, ast.ImportFrom) and node.level == 0:
                    names = [node.module or ""]
                for n in names:
                    self.assertNotIn(n.split(".")[0], FORBIDDEN_IMPORTS, f"{path}: import {n}")

    def test_only_subprocess_target_is_ci_fetch(self):
        src = open(os.path.join(MODULE, "ci.py")).read()
        self.assertEqual(len(re.findall(r"subprocess\.run\(", src)), 1)
        self.assertIn('["bash", FETCH_SH, source, out_path, *ids]', src)
        for path in _py_files():
            if not path.endswith("ci.py"):
                self.assertNotIn("subprocess", open(path).read(), path)

    def test_no_control_plane_calls(self):
        for path in list(_py_files()) + [os.path.join(MODULE, "ci_fetch.sh")]:
            code = "\n".join(l for l in open(path).read().splitlines() if not l.lstrip().startswith("#"))
            code = re.sub(r'"""[\s\S]*?"""', "", code)
            m = FORBIDDEN_CALLS.search(code)
            self.assertIsNone(m, f"{path}: {m and m.group(0)}")

    def test_fetch_hosts_fixed(self):
        src = open(os.path.join(MODULE, "ci_fetch.sh")).read()
        self.assertEqual(sorted(set(re.findall(r'HOST="([^"]+)"', src))),
                         ["api.first.org", "services.nvd.nist.gov", "www.cisa.gov"])
        self.assertIn("--proto '=https'", src)
        self.assertNotRegex(src, r"\s-L\b|--location")
        self.assertNotIn("NVD_API_KEY", re.sub(r"#.*", "", src))

    def test_synthetic_data_is_synthetic(self):
        inv = json.load(open(INVENTORY))
        self.assertTrue(inv["synthetic"])
        self.assertTrue(inv["organization"]["domain"].endswith(".invalid"))
        for a in inv["assets"]:
            if "ip" in a:
                ip = ipaddress.ip_address(a["ip"])
                self.assertTrue(any(ip in n for n in DOC_NETS), a["ip"])
        ipv4 = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
        for root, _, files in os.walk(FIXTURES):
            for n in files:
                text = open(os.path.join(root, n)).read()
                for cve in re.findall(r"CVE-\d{4}-\d+", text, re.I):
                    self.assertRegex(cve.upper(), r"^CVE-2026-1\d{4}$", f"{n}: non-synthetic id {cve}")
                for ip in ipv4.findall(text):
                    if all(0 <= int(x) <= 255 for x in ip.split(".")):
                        self.assertTrue(any(ipaddress.ip_address(ip) in d for d in DOC_NETS), f"{n}: {ip}")
                self.assertIn("SYNTHETIC", text.upper() if n.endswith(".json") else "SYNTHETIC")

    def test_state_dir_is_gitignored(self):
        p = subprocess.run(["git", "-C", REPO, "check-ignore", "-q",
                            "security/state/corporate_intel/reports/report.json"])
        if p.returncode == 128:
            self.skipTest("not a git checkout")
        self.assertEqual(p.returncode, 0, "security/state/corporate_intel must be gitignored")

    def test_default_state_dir(self):
        from ci_lib.store import DEFAULT_STATE_DIR
        self.assertEqual(os.path.relpath(DEFAULT_STATE_DIR, REPO), os.path.join("security", "state", "corporate_intel"))


if __name__ == "__main__":
    unittest.main()
