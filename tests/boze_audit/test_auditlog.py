"""Tests for boze/audit/auditlog.py. Scratch temp dirs only; no network.

Run: python3 tests/boze_audit/test_auditlog.py   (or tests/boze_audit_log_test.sh)
"""

import json
import multiprocessing
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(REPO, "boze", "audit"))

import auditlog  # noqa: E402


def _worker(args):
    log, wid, n = args
    for i in range(n):
        auditlog.append(log, "worker-%d" % wid, "test.append", payload=b"%d" % i)
    return n


class AuditLogTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="boze-audit-test-")
        self.log = os.path.join(self.dir, "audit.jsonl")

    def tearDown(self):
        if sys.platform == "darwin" and os.path.exists(self.log):
            subprocess.call(["chflags", "nouappnd", self.log])
        shutil.rmtree(self.dir)

    def _fill(self, n=5):
        for i in range(n):
            auditlog.append(self.log, "boze", "act.%d" % i, payload="p%d" % i, detail={"i": i})

    def _lines(self):
        with open(self.log, "rb") as f:
            return f.read().split(b"\n")[:-1]

    def _write_lines(self, lines):
        with open(self.log, "wb") as f:
            f.write(b"".join(l + b"\n" for l in lines))

    # --- happy path ---------------------------------------------------
    def test_empty_log_verifies(self):
        r = auditlog.verify(self.log)
        self.assertTrue(r["ok"], r)
        self.assertEqual(r["last_seq"], 0)

    def test_append_and_verify(self):
        self._fill(5)
        r = auditlog.verify(self.log)
        self.assertTrue(r["ok"], r)
        self.assertEqual(r["last_seq"], 5)
        first = json.loads(self._lines()[0])
        self.assertEqual(first["prev_hash"], auditlog.GENESIS)
        self.assertEqual(first["payload_sha256"], auditlog._sha(b"p0"))
        self.assertNotIn("p0", self._lines()[0].decode())  # payload never stored

    def test_japanese_detail_roundtrip(self):
        auditlog.append(self.log, "boze", "note", detail={"msg": "番長、おはようございます"})
        self.assertTrue(auditlog.verify(self.log)["ok"])
        self.assertEqual(json.loads(self._lines()[0])["detail"]["msg"], "番長、おはようございます")

    # --- tamper detection ---------------------------------------------
    def test_detects_edit_in_middle(self):
        self._fill(5)
        lines = self._lines()
        lines[2] = lines[2].replace(b"act.2", b"act.X")
        self._write_lines(lines)
        r = auditlog.verify(self.log)
        self.assertFalse(r["ok"])
        self.assertTrue(any("seq 4" in e for e in r["errors"]), r["errors"])

    def test_detects_edit_of_last_line(self):
        self._fill(3)
        lines = self._lines()
        lines[-1] = lines[-1].replace(b"act.2", b"act.Z")
        self._write_lines(lines)
        self.assertFalse(auditlog.verify(self.log)["ok"])

    def test_detects_deletion(self):
        self._fill(5)
        lines = self._lines()
        del lines[1]
        self._write_lines(lines)
        self.assertFalse(auditlog.verify(self.log)["ok"])

    def test_detects_reorder(self):
        self._fill(5)
        lines = self._lines()
        lines[1], lines[2] = lines[2], lines[1]
        self._write_lines(lines)
        self.assertFalse(auditlog.verify(self.log)["ok"])

    def test_detects_tail_truncation_via_checkpoint(self):
        self._fill(5)
        self._write_lines(self._lines()[:3])
        r = auditlog.verify(self.log)
        self.assertFalse(r["ok"])
        self.assertTrue(any("checkpoint" in e for e in r["errors"]))

    def test_detects_truncation_plus_checkpoint_rewrite_via_anchor(self):
        self._fill(5)
        anchor = auditlog.head(self.log)
        lines = self._lines()[:3]
        self._write_lines(lines)
        # attacker also rewrites the checkpoint consistently
        auditlog._write_checkpoint(self.log + ".checkpoint", 3, auditlog._sha(lines[-1]),
                                   os.path.getsize(self.log))
        self.assertTrue(auditlog.verify(self.log)["ok"])  # checkpoint alone is fooled
        r = auditlog.verify(self.log, anchors={anchor["seq"]: anchor["line_sha256"]})
        self.assertFalse(r["ok"])  # the off-host anchor is not

    def test_detects_wrong_anchor(self):
        self._fill(3)
        r = auditlog.verify(self.log, anchors={2: "f" * 64})
        self.assertFalse(r["ok"])

    # --- fail-closed append -------------------------------------------
    def test_append_refused_after_tamper(self):
        self._fill(3)
        lines = self._lines()
        lines[-1] = lines[-1].replace(b"act.2", b"act.Q")
        self._write_lines(lines)
        with self.assertRaises(auditlog.AuditError):
            auditlog.append(self.log, "boze", "after-tamper")

    def test_append_refused_when_checkpoint_missing(self):
        self._fill(2)
        os.remove(self.log + ".checkpoint")
        with self.assertRaises(auditlog.AuditError):
            auditlog.append(self.log, "boze", "x")

    def test_append_refused_after_truncation(self):
        self._fill(4)
        self._write_lines(self._lines()[:2])
        with self.assertRaises(auditlog.AuditError):
            auditlog.append(self.log, "boze", "x")

    def test_crash_between_write_and_checkpoint_is_recovered(self):
        self._fill(3)
        with open(self.log + ".checkpoint") as f:
            cp = f.read()
        auditlog.append(self.log, "boze", "fourth")
        with open(self.log + ".checkpoint", "w") as f:  # simulate crash: old checkpoint
            f.write(cp)
        rec = auditlog.append(self.log, "boze", "fifth")
        self.assertEqual(rec["seq"], 5)
        self.assertTrue(auditlog.verify(self.log)["ok"])

    def test_garbage_after_checkpoint_refused(self):
        self._fill(2)
        with open(self.log, "ab") as f:
            f.write(b'{"forged":true}\n')
        with self.assertRaises(auditlog.AuditError):
            auditlog.append(self.log, "boze", "x")

    def test_input_validation(self):
        for actor in ("", "a\nb", "x" * 200):
            with self.assertRaises(auditlog.AuditError):
                auditlog.append(self.log, actor, "act")
        with self.assertRaises(auditlog.AuditError):
            auditlog.append(self.log, "boze", "act", detail={"big": "x" * 5000})
        with self.assertRaises(auditlog.AuditError):
            auditlog.append(self.log, "boze", "act", detail=["not", "a", "dict"])
        self.assertFalse(os.path.exists(self.log))

    # --- concurrency --------------------------------------------------
    def test_concurrent_appends_1000(self):
        with multiprocessing.Pool(8) as pool:
            total = sum(pool.map(_worker, [(self.log, w, 125) for w in range(8)]))
        self.assertEqual(total, 1000)
        r = auditlog.verify(self.log)
        self.assertTrue(r["ok"], r["errors"][:5])
        self.assertEqual(r["last_seq"], 1000)

    # --- uappnd (macOS) -----------------------------------------------
    @unittest.skipUnless(sys.platform == "darwin", "chflags uappnd is BSD/macOS")
    def test_works_with_uappnd_and_blocks_overwrite(self):
        self._fill(2)
        subprocess.check_call(["chflags", "uappnd", self.log])
        auditlog.append(self.log, "boze", "after-uappnd")
        self.assertTrue(auditlog.verify(self.log)["ok"])
        with self.assertRaises(PermissionError):
            open(self.log, "wb").close()
        with self.assertRaises(PermissionError):
            os.remove(self.log)

    # --- CLI ----------------------------------------------------------
    def test_cli(self):
        exe = [sys.executable, "-I", os.path.join(REPO, "boze", "audit", "auditlog.py")]
        out = subprocess.run(exe + ["append", "--log", self.log, "--actor", "boze", "--action", "cli",
                                    "--payload-file", "-", "--detail-json", '{"k":1}'],
                             input=b"hello", capture_output=True, check=True)
        self.assertEqual(json.loads(out.stdout)["seq"], 1)
        h = json.loads(subprocess.run(exe + ["head", "--log", self.log], capture_output=True,
                                      check=True).stdout)
        ok = subprocess.run(exe + ["verify", "--log", self.log, "--anchor",
                                   "%d:%s" % (h["seq"], h["line_sha256"])], capture_output=True)
        self.assertEqual(ok.returncode, 0)
        bad = subprocess.run(exe + ["verify", "--log", self.log, "--anchor", "1:" + "0" * 64],
                             capture_output=True)
        self.assertEqual(bad.returncode, 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
