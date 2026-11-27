"""boze/jobs/jobs.py -- BOZE job state machine and approval-gated executor (U4).

  received -> analyzed -> drafted -> awaiting_approval -> approved -> executed
  received/analyzed/drafted/awaiting_approval -> rejected
  awaiting_approval -> drafted   (revise: the pending approval request is void)
  awaiting_approval -> expired
  approved -> failed            (handler error after a valid approval)

Rules:
  * Only actions in ACTIONS can ever run, and only through execute().
  * execute() reads the payload bytes once, hashes them, verifies a human
    signature (boze.approval) bound to job_id + action + that hash + the
    nonce recorded at request time, consumes the nonce (single use), and
    then hands exactly those bytes to the handler.
  * Every transition and every refusal is appended to the BOZE audit log
    (boze.audit.auditlog). If the audit log cannot be written, the
    operation fails before any state change.
  * All mutations run under one store-wide flock; job.json is replaced atomically.

MVP action: export_final -- write the approved draft to outbox/<job_id>/final.md
(never overwrites). Nothing here sends, applies, or pays.
Python 3.9 standard library only.
"""

import datetime
import fcntl
import json
import os
import re

from boze.approval import approval as _approval
from boze.audit import auditlog as _audit

ACTOR_RE = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")
JOB_RE = _approval.ID_RE
MAX_TEXT = 512 * 1024

TRANSITIONS = {
    "received": {"analyzed", "rejected"},
    "analyzed": {"drafted", "rejected"},
    "drafted": {"awaiting_approval", "rejected"},
    "awaiting_approval": {"approved", "drafted", "rejected", "expired"},
    "approved": {"executed", "failed"},
    "executed": set(), "rejected": set(), "expired": set(), "failed": set(),
}


class JobError(Exception):
    """Refused job operation."""


def _now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _export_final(store, job_id, payload):
    d = os.path.join(store.outbox, job_id)
    os.makedirs(d, mode=0o700, exist_ok=True)
    p = os.path.join(d, "final.md")
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(payload)
        f.flush()
        os.fsync(f.fileno())
    with open(p, "rb") as f:
        if _approval.sha256_bytes(f.read()) != _approval.sha256_bytes(payload):
            raise JobError("exported file does not match approved payload")
    return {"path": p}


ACTIONS = {"export_final": _export_final}


class JobStore:
    def __init__(self, root, audit_log, allowed_signers, ledger, outbox):
        self.root, self.audit_log = root, audit_log
        self.allowed_signers, self.ledger, self.outbox = allowed_signers, ledger, outbox
        os.makedirs(root, mode=0o700, exist_ok=True)

    # -- plumbing ----------------------------------------------------------
    def _lock(self):
        fd = os.open(os.path.join(self.root, ".lock"), os.O_WRONLY | os.O_CREAT, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX)
        return fd

    @staticmethod
    def _unlock(fd):
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)

    def _dir(self, job_id):
        if not isinstance(job_id, str) or not JOB_RE.match(job_id):
            raise JobError("invalid job_id")
        return os.path.join(self.root, job_id)

    def _write(self, path, data):
        tmp = path + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)

    def _save(self, job):
        self._write(os.path.join(self._dir(job["job_id"]), "job.json"),
                    json.dumps(job, ensure_ascii=False, sort_keys=True, indent=1).encode("utf-8"))

    def load(self, job_id):
        try:
            with open(os.path.join(self._dir(job_id), "job.json"), "rb") as f:
                job = json.loads(f.read())
        except FileNotFoundError:
            raise JobError("no such job")
        if job.get("job_id") != job_id or job.get("state") not in TRANSITIONS:
            raise JobError("job record is corrupt")
        return job

    def _audit(self, who, event, payload=b"", **detail):
        try:
            _audit.append(self.audit_log, who, event, payload=payload, detail=detail)
        except _audit.AuditError as e:
            raise JobError("audit log refused write: %s" % e)

    def _require(self, job, to, actor):
        """Audit and refuse if job cannot move to `to` from its current state."""
        frm = job["state"]
        if to not in TRANSITIONS[frm]:
            self._audit(actor, "job.illegal_transition", job_id=job["job_id"], frm=frm, to=to)
            raise JobError("illegal transition %s -> %s" % (frm, to))

    def _move(self, job, to, actor, **detail):
        self._require(job, to, actor)
        frm = job["state"]
        self._audit(actor, "job.transition", job_id=job["job_id"], frm=frm, to=to, **detail)
        job["state"] = to
        job["history"].append({"from": frm, "to": to, "actor": actor, "ts": _now()})
        self._save(job)

    @staticmethod
    def _check_actor(actor):
        if not isinstance(actor, str) or not ACTOR_RE.match(actor):
            raise JobError("invalid actor")

    @staticmethod
    def _text(text):
        if not isinstance(text, str) or not text or len(text.encode("utf-8")) > MAX_TEXT:
            raise JobError("text must be non-empty and <= %d bytes" % MAX_TEXT)
        return text.encode("utf-8")

    # -- API ---------------------------------------------------------------
    def create(self, job_id, source_text, actor):
        self._check_actor(actor)
        data = self._text(source_text)
        fd = self._lock()
        try:
            d = self._dir(job_id)
            try:
                os.mkdir(d, 0o700)
            except FileExistsError:
                raise JobError("job already exists")
            self._audit(actor, "job.create", payload=data, job_id=job_id)
            self._write(os.path.join(d, "source.txt"), data)
            job = {"job_id": job_id, "state": "received", "created_at": _now(),
                   "history": [], "approval": None}
            self._save(job)
            return job
        finally:
            self._unlock(fd)

    def set_analysis(self, job_id, analysis, actor):
        self._check_actor(actor)
        if not isinstance(analysis, dict):
            raise JobError("analysis must be an object")
        data = json.dumps(analysis, ensure_ascii=False, sort_keys=True).encode("utf-8")
        fd = self._lock()
        try:
            job = self.load(job_id)
            self._require(job, "analyzed", actor)
            self._write(os.path.join(self._dir(job_id), "analysis.json"), data)
            self._move(job, "analyzed", actor, analysis_sha256=_approval.sha256_bytes(data))
            return job
        finally:
            self._unlock(fd)

    def set_draft(self, job_id, draft_text, actor):
        self._check_actor(actor)
        data = self._text(draft_text)
        fd = self._lock()
        try:
            job = self.load(job_id)
            self._require(job, "drafted", actor)
            void = job.get("approval")
            job["approval"] = None
            self._write(os.path.join(self._dir(job_id), "draft.md"), data)
            self._move(job, "drafted", actor, draft_sha256=_approval.sha256_bytes(data),
                       voided_nonce=void["nonce"] if void else None)
            return job
        finally:
            self._unlock(fd)

    def request_approval(self, job_id, action, actor, ttl_seconds=3600):
        """Write <job>/approval/request-<nonce>.json for a human to sign; return its path."""
        self._check_actor(actor)
        if action not in ACTIONS:
            self._audit(actor, "job.action_not_allowed", job_id=job_id, action=str(action)[:64])
            raise JobError("action not allowed: %r" % action)
        fd = self._lock()
        try:
            job = self.load(job_id)
            if job["state"] != "drafted":
                self._audit(actor, "job.illegal_transition", job_id=job_id, frm=job["state"],
                            to="awaiting_approval")
                raise JobError("approval can only be requested for a drafted job")
            with open(os.path.join(self._dir(job_id), "draft.md"), "rb") as f:
                psha = _approval.sha256_bytes(f.read())
            req = _approval.make_request(job_id, action, psha, ttl_seconds)
            parsed = _approval.parse_request(req)
            ad = os.path.join(self._dir(job_id), "approval")
            os.makedirs(ad, mode=0o700, exist_ok=True)
            path = os.path.join(ad, "request-%s.json" % parsed["nonce"])
            self._write(path, req)
            job["approval"] = {"action": action, "payload_sha256": psha, "nonce": parsed["nonce"],
                               "expires_at": parsed["expires_at"], "request": path}
            self._move(job, "awaiting_approval", actor, action=action, payload_sha256=psha,
                       nonce=parsed["nonce"], expires_at=parsed["expires_at"])
            return path
        finally:
            self._unlock(fd)

    def execute(self, job_id, sig_bytes, actor, now=None):
        """Run the approved action. Raises JobError without side effects on any refusal."""
        self._check_actor(actor)
        fd = self._lock()
        try:
            job = self.load(job_id)
            pend = job.get("approval")
            if job["state"] != "awaiting_approval" or not pend:
                self._audit(actor, "job.execute_denied", job_id=job_id, reason="not awaiting approval",
                            state=job["state"])
                raise JobError("job is not awaiting approval (state %s)" % job["state"])
            action = pend["action"]
            if action not in ACTIONS:
                self._audit(actor, "job.execute_denied", job_id=job_id, reason="action not allowed")
                raise JobError("action not allowed")
            with open(os.path.join(self._dir(job_id), "draft.md"), "rb") as f:
                payload = f.read()
            with open(pend["request"], "rb") as f:
                req = f.read()
            try:
                v = _approval.verify(req, sig_bytes, self.allowed_signers,
                                     {"job_id": job_id, "action": action, "nonce": pend["nonce"],
                                      "payload_sha256": _approval.sha256_bytes(payload)}, now=now)
                _approval.consume(self.ledger, v)
            except _approval.ApprovalError as e:
                self._audit(actor, "job.execute_denied", payload=payload, job_id=job_id, reason=str(e))
                raise JobError("approval refused: %s" % e)
            self._move(job, "approved", actor, principal=v["principal"], nonce=pend["nonce"])
            try:
                result = ACTIONS[action](self, job_id, payload)
            except (OSError, JobError) as e:
                self._move(job, "failed", actor, error=type(e).__name__)
                raise JobError("action %s failed: %s" % (action, e))
            self._move(job, "executed", actor, action=action, payload_sha256=v["request"]["payload_sha256"])
            return result
        finally:
            self._unlock(fd)

    def reject(self, job_id, actor, reason=""):
        self._check_actor(actor)
        fd = self._lock()
        try:
            job = self.load(job_id)
            self._move(job, "rejected", actor, reason=str(reason)[:200])
            return job
        finally:
            self._unlock(fd)

    def expire(self, job_id, actor, now=None):
        """Move an awaiting job whose approval window has passed to expired."""
        self._check_actor(actor)
        now = int(datetime.datetime.now().timestamp() if now is None else now)
        fd = self._lock()
        try:
            job = self.load(job_id)
            pend = job.get("approval")
            if job["state"] != "awaiting_approval" or not pend or now < pend["expires_at"]:
                raise JobError("job has no expired approval request")
            self._move(job, "expired", actor, nonce=pend["nonce"])
            return job
        finally:
            self._unlock(fd)
