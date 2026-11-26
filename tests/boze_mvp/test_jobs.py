"""U4 tests: boze/jobs/jobs.py -- state machine + approval-gated executor (temp dirs only)."""

import json
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
from boze.audit import auditlog as L  # noqa: E402
from boze.jobs import jobs as J  # noqa: E402

DRAFT = "# 応募書類 (下書き)\n\n株式会社サンプル 御中\n"


class JobsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keys = tempfile.mkdtemp(prefix="boze-jobs-keys-")
        cls.key = os.path.join(cls.keys, "op")
        subprocess.check_call(["/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "op", "-f", cls.key])
        cls.stranger = os.path.join(cls.keys, "x")
        subprocess.check_call(["/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "x", "-f", cls.stranger])
        with open(cls.key + ".pub") as f:
            pub = f.read().strip()
        cls.signers = os.path.join(cls.keys, "allowed_signers")
        with open(cls.signers, "w") as f:
            f.write('operator@boze namespaces="%s" %s\n' % (A.NAMESPACE, pub))

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.keys)

    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="boze-jobs-test-")
        self.audit = os.path.join(self.d, "audit.jsonl")
        self.outbox = os.path.join(self.d, "outbox")
        self.s = J.JobStore(os.path.join(self.d, "jobs"), self.audit, self.signers,
                            os.path.join(self.d, "ledger.jsonl"), self.outbox)

    def tearDown(self):
        shutil.rmtree(self.d)

    def sign(self, path, key=None):
        subprocess.check_call(["/usr/bin/ssh-keygen", "-q", "-Y", "sign", "-f", key or self.key,
                               "-n", A.NAMESPACE, path], stderr=subprocess.DEVNULL)
        with open(path + ".sig", "rb") as f:
            sig = f.read()
        os.remove(path + ".sig")
        return sig

    def drafted(self, job_id="J001"):
        self.s.create(job_id, "求人: サンプル職", "boze")
        self.s.set_analysis(job_id, {"title": "サンプル職"}, "boze")
        self.s.set_draft(job_id, DRAFT, "boze")

    def audit_actions(self):
        with open(self.audit, "rb") as f:
            return [json.loads(l)["action"] for l in f.read().splitlines()]

    def out(self, job_id="J001"):
        return os.path.join(self.outbox, job_id, "final.md")

    # happy path
    def test_full_flow_exports_exact_approved_bytes(self):
        self.drafted()
        req = self.s.request_approval("J001", "export_final", "boze")
        res = self.s.execute("J001", self.sign(req), "operator")
        with open(res["path"], "rb") as f:
            self.assertEqual(f.read(), DRAFT.encode())
        job = self.s.load("J001")
        self.assertEqual(job["state"], "executed")
        self.assertEqual([h["to"] for h in job["history"]],
                         ["analyzed", "drafted", "awaiting_approval", "approved", "executed"])
        self.assertTrue(L.verify(self.audit)["ok"])
        self.assertEqual(self.audit_actions().count("job.transition"), 5)

    # refusals -- each must leave state unchanged and nothing exported
    def assertRefused(self, fn, state="awaiting_approval", job_id="J001"):
        with self.assertRaises(J.JobError):
            fn()
        self.assertEqual(self.s.load(job_id)["state"], state)
        self.assertFalse(os.path.exists(self.out(job_id)))

    def test_execute_without_request_refused(self):
        self.drafted()
        self.assertRefused(lambda: self.s.execute("J001", b"", "operator"), state="drafted")
        self.assertIn("job.execute_denied", self.audit_actions())

    def test_bad_or_foreign_signature_refused(self):
        self.drafted()
        req = self.s.request_approval("J001", "export_final", "boze")
        self.assertRefused(lambda: self.s.execute("J001", b"-----BEGIN SSH SIGNATURE-----\nAAAA\n", "operator"))
        self.assertRefused(lambda: self.s.execute("J001", self.sign(req, self.stranger), "operator"))

    def test_payload_changed_after_signing_refused(self):
        self.drafted()
        req = self.s.request_approval("J001", "export_final", "boze")
        sig = self.sign(req)
        with open(os.path.join(self.d, "jobs", "J001", "draft.md"), "ab") as f:
            f.write("追記: 口座番号 0000".encode())
        self.assertRefused(lambda: self.s.execute("J001", sig, "operator"))

    def test_signature_for_other_job_refused(self):
        self.drafted("J001")
        self.drafted("J002")
        r1 = self.s.request_approval("J001", "export_final", "boze")
        self.s.request_approval("J002", "export_final", "boze")
        self.assertRefused(lambda: self.s.execute("J002", self.sign(r1), "operator"), job_id="J002")

    def test_swapped_request_file_refused(self):
        self.drafted()
        req = self.s.request_approval("J001", "export_final", "boze")
        forged = A.make_request("J001", "export_final", A.sha256_bytes(DRAFT.encode()))
        with open(req, "wb") as f:  # attacker writes a fresh request and gets it signed elsewhere
            f.write(forged)
        self.assertRefused(lambda: self.s.execute("J001", self.sign(req), "operator"))  # nonce mismatch

    def test_replay_refused(self):
        self.drafted()
        req = self.s.request_approval("J001", "export_final", "boze")
        sig = self.sign(req)
        self.s.execute("J001", sig, "operator")
        with self.assertRaises(J.JobError):
            self.s.execute("J001", sig, "operator")
        self.assertEqual(self.s.load("J001")["state"], "executed")

    def test_ledger_blocks_replay_even_if_job_record_is_rolled_back(self):
        self.drafted()
        req = self.s.request_approval("J001", "export_final", "boze")
        jp = os.path.join(self.d, "jobs", "J001", "job.json")
        with open(jp, "rb") as f:
            snapshot = f.read()
        sig = self.sign(req)
        self.s.execute("J001", sig, "operator")
        with open(os.path.join(self.d, "ledger.jsonl")) as f:
            self.assertEqual(json.loads(f.read())["nonce"], self.s.load("J001")["approval"]["nonce"])
        os.remove(self.out())
        with open(jp, "wb") as f:  # attacker restores the pre-execution job record
            f.write(snapshot)
        self.assertRefused(lambda: self.s.execute("J001", sig, "operator"))

    def test_revise_voids_pending_approval(self):
        self.drafted()
        req = self.s.request_approval("J001", "export_final", "boze")
        sig = self.sign(req)
        self.s.set_draft("J001", DRAFT, "boze")  # same text, new revision
        self.assertRefused(lambda: self.s.execute("J001", sig, "operator"), state="drafted")
        req2 = self.s.request_approval("J001", "export_final", "boze")
        self.assertRefused(lambda: self.s.execute("J001", sig, "operator"))  # old sig, new nonce
        self.s.execute("J001", self.sign(req2), "operator")
        self.assertEqual(self.s.load("J001")["state"], "executed")

    def test_expired_approval(self):
        self.drafted()
        req = self.s.request_approval("J001", "export_final", "boze", ttl_seconds=60)
        sig = self.sign(req)
        later = int(time.time()) + 120
        self.assertRefused(lambda: self.s.execute("J001", sig, "operator", now=later))
        with self.assertRaises(J.JobError):
            self.s.expire("J001", "boze")  # not yet expired
        self.s.expire("J001", "boze", now=later)
        self.assertEqual(self.s.load("J001")["state"], "expired")

    def test_action_not_allowlisted(self):
        self.drafted()
        for act in ("send_mail", "apply", "pay", "../x", None):
            with self.assertRaises(J.JobError):
                self.s.request_approval("J001", act, "boze")
        self.assertEqual(self.s.load("J001")["state"], "drafted")
        self.assertIn("job.action_not_allowed", self.audit_actions())

    def test_illegal_transitions(self):
        self.s.create("J001", "x", "boze")
        with self.assertRaises(J.JobError):
            self.s.set_draft("J001", "d", "boze")  # received -> drafted
        with self.assertRaises(J.JobError):
            self.s.request_approval("J001", "export_final", "boze")
        self.s.reject("J001", "operator", "対象外")
        for fn in (lambda: self.s.set_analysis("J001", {}, "boze"), lambda: self.s.reject("J001", "boze")):
            with self.assertRaises(J.JobError):
                fn()
        self.assertEqual(self.s.load("J001")["state"], "rejected")
        self.assertIn("job.illegal_transition", self.audit_actions())

    def test_outbox_never_overwritten(self):
        self.drafted()
        os.makedirs(os.path.dirname(self.out()))
        with open(self.out(), "w") as f:
            f.write("pre-existing")
        req = self.s.request_approval("J001", "export_final", "boze")
        with self.assertRaises(J.JobError):
            self.s.execute("J001", self.sign(req), "operator")
        self.assertEqual(self.s.load("J001")["state"], "failed")
        with open(self.out()) as f:
            self.assertEqual(f.read(), "pre-existing")

    def test_audit_tamper_blocks_all_changes(self):
        self.drafted()
        with open(self.audit, "ab") as f:
            f.write(b'{"forged":true}\n')
        with self.assertRaises(J.JobError):
            self.s.request_approval("J001", "export_final", "boze")
        self.assertEqual(self.s.load("J001")["state"], "drafted")

    def test_input_validation(self):
        for jid in ("", "../etc", "a/b", "x" * 65, None):
            with self.assertRaises(J.JobError):
                self.s.create(jid, "t", "boze")
        for actor in ("", "Boze", "a b", None):
            with self.assertRaises(J.JobError):
                self.s.create("J1", "t", actor)
        with self.assertRaises(J.JobError):
            self.s.create("J1", "", "boze")
        self.s.create("J1", "t", "boze")
        with self.assertRaises(J.JobError):
            self.s.create("J1", "t", "boze")


if __name__ == "__main__":
    unittest.main(verbosity=2)
