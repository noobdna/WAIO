"""State store for collected public intelligence.

Layout under the state dir (default security/state/corporate_intel/,
gitignored -- real snapshots never enter the public repo):

    raw/<source>/<sha256>.json      exact bytes received (content-addressed)
    sources/<source>.json           current parsed records + provenance
    status/<source>.json            last attempt / success / error / stale
    normalized/cves.json            CveRecord set (normalize.py)
    reports/report-<ts>.json        correlation + risk reports

Guarantees (all tested):
  - writes are atomic (temp file + os.replace) -- a crash never leaves a
    half-written JSON file behind;
  - every write path is resolved and must stay inside the state dir;
  - re-ingesting identical bytes is a no-op (dedupe by sha256);
  - a FAILED fetch never deletes or overwrites previous good data -- it
    only records the failure and marks the source stale.
"""

import json
import os
import tempfile

from . import provenance, redact

MAX_BODY_BYTES = 20 * 1024 * 1024
DEFAULT_STATE_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "state", "corporate_intel")


class StoreError(RuntimeError):
    pass


class Store:
    def __init__(self, state_dir=None):
        self.root = os.path.realpath(state_dir or os.environ.get("WAIO_CI_STATE_DIR") or DEFAULT_STATE_DIR)

    # -- path safety -------------------------------------------------
    def path(self, *parts):
        p = os.path.realpath(os.path.join(self.root, *parts))
        if p != self.root and not p.startswith(self.root + os.sep):
            raise StoreError(f"refusing path outside state dir: {os.path.join(*parts)}")
        return p

    def _write_bytes(self, rel_parts, data):
        target = self.path(*rel_parts)
        d = os.path.dirname(target)
        os.makedirs(d, mode=0o700, exist_ok=True)
        fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=d)
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            os.chmod(tmp, 0o600)
            os.replace(tmp, target)
        except BaseException:
            try:
                os.unlink(tmp)
            except FileNotFoundError:
                pass
            raise
        return target

    def write_json(self, rel_parts, obj):
        # every JSON file this module writes passes the secret filter (raw
        # response bytes are stored verbatim -- they come from public feeds)
        text = redact.redact(json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True))
        data = (text + "\n").encode("utf-8")
        return self._write_bytes(rel_parts, data)

    def read_json(self, rel_parts, default=None):
        p = self.path(*rel_parts)
        if not os.path.exists(p):
            return default
        with open(p, "rb") as f:
            return json.loads(f.read().decode("utf-8"))

    # -- raw snapshots -----------------------------------------------
    def save_raw(self, source, body):
        """Returns (sha256, is_new)."""
        if len(body) > MAX_BODY_BYTES:
            raise StoreError(f"{source} body exceeds {MAX_BODY_BYTES} bytes")
        digest = provenance.sha256_bytes(body)
        rel = ("raw", source, f"{digest}.json")
        if os.path.exists(self.path(*rel)):
            return digest, False
        self._write_bytes(rel, body)
        return digest, True

    # -- parsed source records ---------------------------------------
    def load_source(self, source):
        return self.read_json(("sources", f"{source}.json"), default={"records": {}})

    def merge_source(self, source, records, replace_all=False):
        """KEV is a full catalog: replace_all=True swaps the whole set.
        NVD/EPSS are per-CVE: a record replaces the stored one only if
        it is different content and not older (source_updated_at, then
        fetched_at). Returns {'added','updated','unchanged'} counts."""
        current = self.load_source(source)
        old = current.get("records", {})
        counts = {"added": 0, "updated": 0, "unchanged": 0, "removed": 0}
        if replace_all:
            new = {}
            for cve, rec in records.items():
                prev = old.get(cve)
                if prev is None:
                    counts["added"] += 1
                elif _same(prev, rec):
                    counts["unchanged"] += 1  # content same; keep the fresher provenance
                else:
                    counts["updated"] += 1
                new[cve] = rec
            counts["removed"] = len(set(old) - set(new))
        else:
            new = dict(old)
            for cve, rec in records.items():
                prev = old.get(cve)
                if prev is None:
                    counts["added"] += 1
                    new[cve] = rec
                elif _older(rec, prev):
                    counts["unchanged"] += 1  # never let an older response win
                elif _same(prev, rec):
                    counts["unchanged"] += 1
                    new[cve] = rec  # same content, fresher provenance
                else:
                    counts["updated"] += 1
                    new[cve] = rec
        self.write_json(("sources", f"{source}.json"), {"source": source, "records": new})
        return counts

    # -- fetch status ------------------------------------------------
    def load_status(self, source):
        return self.read_json(("status", f"{source}.json"), default={})

    def record_success(self, source, at):
        st = self.load_status(source)
        st.update({"source": source, "last_attempt_at": at, "last_success_at": at,
                   "last_error": None, "stale": False, "failed_ids": []})
        self.write_json(("status", f"{source}.json"), st)

    def record_failure(self, source, at, error, failed_ids=None):
        st = self.load_status(source)
        st.update({"source": source, "last_attempt_at": at, "last_error": str(error)[:300],
                   "stale": True, "failed_ids": sorted(failed_ids or [])})
        st.setdefault("last_success_at", None)
        self.write_json(("status", f"{source}.json"), st)


def _payload(rec):
    return {k: v for k, v in rec.items() if k != "provenance"}


def _same(a, b):
    return _payload(a) == _payload(b)


def _older(new, old):
    pn, po = new.get("provenance", {}), old.get("provenance", {})
    key = lambda p: (p.get("source_updated_at") or "", p.get("fetched_at") or "")  # noqa: E731
    return key(pn) < key(po)
