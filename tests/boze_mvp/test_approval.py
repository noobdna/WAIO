"""U3 tests: boze/approval/approval.py with throwaway ed25519 keys (temp dir only)."""

import json
import multiprocessing
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, REPO)

from boze.approval import approval as A  # noqa: E402

PSHA = "ab" * 32


def keygen(d, name):
    k = os.path.join(d, name)
    subprocess.check_call(["/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", name, "-f", k])
    with open(k + ".pub") as f:
        return k, f.read().strip()


def sign(d, key, data, ns=A.NAMESPACE):
    p = os.path.join(d, "req-%d.json" % time.time_ns())
    with open(p, "wb") as f:
        f.write(data)
    subprocess.check_call(["/usr/bin/ssh-keygen", "-q", "-Y", "sign", "-f", key, "-n", ns, p],
                          stderr=subprocess.DEVNULL)
    with open(p + ".sig", "rb") as f:
        return f.read()


def _consume_worker(args):
    ledger, verified = args
    try:
        A.consume(ledger, verified)
        return "ok"
    except A.ApprovalError:
        return "replay"


class ApprovalTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = tempfile.mkdtemp(prefix="boze-approval-test-")
        cls.key, pub = keygen(cls.d, "operator")
        cls.other, other_pub = keygen(cls.d, "stranger")
        cls.signers = os.path.join(cls.d, "allowed_signers")
        with open(cls.signers, "w") as f:
            f.write('operator@boze namespaces="%s" %s\n' % (A.NAMESPACE, pub))
        os.chmod(cls.signers, 0o644)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.d)

    def req(self, **kw):
        args = dict(job_id="J001", action="export_final", payload_sha256=PSHA, ttl_seconds=3600)
        args.update(kw)
        return A.make_request(**args)

    def expect(self, **kw):
        e = {"job_id": "J001", "action": "export_final", "payload_sha256": PSHA}
        e.update(kw)
        return e

    def test_valid_signature_verifies(self):
        r = self.req()
        res = A.verify(r, sign(self.d, self.key, r), self.signers, self.expect())
        self.assertEqual(res["principal"], "operator@boze")
        self.assertEqual(res["request"]["job_id"], "J001")

    def test_request_is_canonical_and_parse_rejects_variants(self):
        r = self.req()
        obj = json.loads(r)
        self.assertEqual(A.parse_request(r), obj)
        for bad in (json.dumps(obj, indent=1).encode(), r.rstrip(b"\n"), r + b" ",
                    A._canonical(dict(obj, extra=1)), A._canonical({k: v for k, v in obj.items() if k != "nonce"}),
                    A._canonical(dict(obj, v=2)), A._canonical(dict(obj, issued_at="1")), b"\xff"):
            with self.assertRaises(A.ApprovalError):
                A.parse_request(bad)

    def test_tampered_request_fails(self):
        r = self.req()
        sig = sign(self.d, self.key, r)
        forged = A._canonical(dict(json.loads(r), payload_sha256="cd" * 32))
        with self.assertRaises(A.ApprovalError):
            A.verify(forged, sig, self.signers, self.expect(payload_sha256="cd" * 32))

    def test_tampered_signature_fails(self):
        r = self.req()
        sig = bytearray(sign(self.d, self.key, r))
        i = sig.index(b"\n") + 20
        sig[i] = ord("A") if sig[i] != ord("A") else ord("B")
        with self.assertRaises(A.ApprovalError):
            A.verify(r, bytes(sig), self.signers, self.expect())

    def test_binding_mismatches(self):
        r = self.req()
        sig = sign(self.d, self.key, r)
        for k, v in (("job_id", "J002"), ("action", "send_mail"), ("payload_sha256", "cd" * 32),
                     ("nonce", "0" * 32)):
            with self.assertRaises(A.ApprovalError, msg=k):
                A.verify(r, sig, self.signers, self.expect(**{k: v}))
        with self.assertRaises(A.ApprovalError):
            A.verify(r, sig, self.signers, {"job_id": "J001"})  # caller must bind everything

    def test_expired_and_future(self):
        now = int(time.time())
        r = self.req(now=now - 7200, ttl_seconds=3600)
        with self.assertRaises(A.ApprovalError):
            A.verify(r, sign(self.d, self.key, r), self.signers, self.expect())
        r = self.req(now=now + 3600)
        with self.assertRaises(A.ApprovalError):
            A.verify(r, sign(self.d, self.key, r), self.signers, self.expect())
        r = self.req()
        sig = sign(self.d, self.key, r)
        with self.assertRaises(A.ApprovalError):
            A.verify(r, sig, self.signers, self.expect(), now=now + 3601)

    def test_overlong_window_refused(self):
        with self.assertRaises(A.ApprovalError):
            self.req(ttl_seconds=A.MAX_TTL + 1)
        obj = json.loads(self.req())
        obj["expires_at"] = obj["issued_at"] + A.MAX_TTL + 1
        r = A._canonical(obj)
        with self.assertRaises(A.ApprovalError):
            A.verify(r, sign(self.d, self.key, r), self.signers, self.expect())

    def test_unknown_key_refused(self):
        r = self.req()
        with self.assertRaises(A.ApprovalError):
            A.verify(r, sign(self.d, self.other, r), self.signers, self.expect())

    def test_wrong_namespace_refused(self):
        r = self.req()
        with self.assertRaises(A.ApprovalError):
            A.verify(r, sign(self.d, self.key, r, ns="git"), self.signers, self.expect())

    def test_signers_file_safety(self):
        r = self.req()
        sig = sign(self.d, self.key, r)
        os.chmod(self.signers, 0o666)
        try:
            with self.assertRaises(A.ApprovalError):
                A.verify(r, sig, self.signers, self.expect())
        finally:
            os.chmod(self.signers, 0o644)
        link = os.path.join(self.d, "signers-link")
        os.symlink(self.signers, link)
        with self.assertRaises(A.ApprovalError):
            A.verify(r, sig, link, self.expect())
        with self.assertRaises(A.ApprovalError):
            A.verify(r, sig, os.path.join(self.d, "missing"), self.expect())

    def test_malformed_signature_refused(self):
        r = self.req()
        for sig in (b"", b"garbage", b"x" * (A.MAX_SIG_BYTES + 1), None):
            with self.assertRaises(A.ApprovalError):
                A.verify(r, sig, self.signers, self.expect())

    def test_consume_once_then_replay_refused(self):
        r = self.req()
        v = A.verify(r, sign(self.d, self.key, r), self.signers, self.expect())
        ledger = os.path.join(self.d, "ledger-%d.jsonl" % time.time_ns())
        A.consume(ledger, v)
        with self.assertRaises(A.ApprovalError):
            A.consume(ledger, v)
        with open(ledger) as f:
            self.assertEqual(len(f.readlines()), 1)

    def test_concurrent_consume_exactly_one_wins(self):
        r = self.req()
        v = A.verify(r, sign(self.d, self.key, r), self.signers, self.expect())
        with multiprocessing.Pool(16) as pool:
            for rnd in range(25):  # repeat: an unlocked check-then-append races often, not always
                ledger = os.path.join(self.d, "ledger-race-%d.jsonl" % rnd)
                out = pool.map(_consume_worker, [(ledger, v)] * 32, chunksize=1)
                self.assertEqual(out.count("ok"), 1, "round %d" % rnd)
                self.assertEqual(out.count("replay"), 31)

    def test_cli_request_and_verify(self):
        payload = os.path.join(self.d, "draft.md")
        with open(payload, "wb") as f:
            f.write("応募書類 下書き\n".encode())
        out = os.path.join(self.d, "cli-req.json")
        exe = [sys.executable, "-I", os.path.join(REPO, "boze", "approval", "approval.py")]
        env = dict(os.environ, PYTHONPATH=REPO)
        subprocess.run(exe + ["request", "--job-id", "J009", "--action", "export_final",
                              "--payload", payload, "--out", out], check=True, capture_output=True, env=env)
        with open(out, "rb") as f:
            sig = sign(self.d, self.key, f.read())
        sigp = out + ".sig"
        with open(sigp, "wb") as f:
            f.write(sig)
        ok = subprocess.run(exe + ["verify", "--request", out, "--sig", sigp, "--allowed-signers",
                                   self.signers, "--payload", payload], capture_output=True, env=env)
        self.assertEqual(ok.returncode, 0, ok.stdout)
        with open(payload, "ab") as f:
            f.write(b"changed")
        bad = subprocess.run(exe + ["verify", "--request", out, "--sig", sigp, "--allowed-signers",
                                    self.signers, "--payload", payload], capture_output=True, env=env)
        self.assertEqual(bad.returncode, 2)
        again = subprocess.run(exe + ["request", "--job-id", "J009", "--action", "export_final",
                                      "--payload", payload, "--out", out], capture_output=True, env=env)
        self.assertEqual(again.returncode, 2)  # never overwrites an existing request


if __name__ == "__main__":
    unittest.main(verbosity=2)
