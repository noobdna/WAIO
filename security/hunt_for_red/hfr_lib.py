"""security/hunt_for_red/hfr_lib.py -- HUNT FOR RED P1: Evidence Ledger
and Source Registry checks.

Design: ~/waio-ops/hunt-for-red/P1_DESIGN_v0.1.md (approved 2026-11-14,
private; not in this public repo). D-1: HFR is a layer on top of the
Incident Learning Engine. It only REFERENCES candidate ids, read-only,
and never imports, calls or writes the engine's state machine or its state.
D-2: case data lives only under HFR_HOME (default
~/waio-ops/hunt-for-red), never inside a git working tree.

This module makes NO network calls. A capture records a file the caller
already has on disk. Fetching is P3, and under D-3 only passive methods
exist at all (see METHODS).

Ledger format: one JSONL file per case. Records are append-only and
hash-chained (SHA-256 over canonical JSON). The chain is UNKEYED: it
detects accidental edits, truncation and reordering, but not someone
who rewrites the whole file consistently. Keying it needs an
owner decision on key storage (design section 2.1).

"approved_by" must start with "human:". This module cannot tell whether
a human actually wrote that string -- an agent with write access could
forge it (the same limitation Mission 001 found). It records who CLAIMS
to have approved; enforcing that only a human can approve is open
decision D-7 (Takomachi supervision).
"""

import datetime
import fcntl
import hashlib
import ipaddress
import json
import os
import re
import subprocess  # used only for `git rev-parse` in refuse_inside_git_tree; no network
import sys

GENESIS = "0" * 64
RECORD_TYPES = ("case", "capture", "claim", "ioc", "cost", "event")
ID_LETTER = {"case": "K", "capture": "R", "claim": "C", "ioc": "I", "cost": "X", "event": "E"}

# D-3 (approved 2026-11-14): passive only. Reading registered third-party
# sources (feeds, advisories, public databases, search results, material
# the owner hands over) is passive. Anything that connects to the
# investigated infrastructure itself -- DNS resolution of an indicator,
# fetching a phishing URL, port checks -- is active and is deliberately
# NOT a value here. Adding one needs an owner approval under spec §8.
METHODS = ("feed", "manual_browse", "web_search_result", "owner_provided")
VERIFICATION = ("primary", "secondary", "directive_only")
CLAIM_CLASSES = ("FACT", "HYPOTHESIS", "UNKNOWN")
IOC_TYPES = ("ip", "domain", "url", "sha256", "email_addr", "header_pattern")
IOC_STATUS = ("candidate", "known_public", "false_positive", "withdrawn")
COST_KINDS = ("agent_time", "human_time", "api", "other")
EVENTS = ("OPENED", "HELD", "STOPPED", "SCALED_DOWN", "RESUMED", "CLOSED")
HOSTS = ("800", "750")
# Spec §7 Autonomous Stop Conditions, numbered in the order listed there.
STOP_CONDITIONS = {
    1: "source terms of use unknown",
    2: "a prohibited operation would be required",
    3: "improper acquisition of confidential or personal information",
    4: "scope exceeds the approved scope",
    5: "evidence integrity cannot be ensured",
    6: "cost cap reached",
    7: "serious disagreement between AIs",
}
# Keys that indicate data about a person. After a source's own
# redaction rules have run, any of these left in a JSON capture makes
# the capture fail (design §2.3: unknown personal fields -> reject).
PERSONAL_KEY_HINTS = frozenset(("login", "email", "avatar_url", "gravatar_id", "user", "html_url_user"))

CASE_ID_RE = re.compile(r"^HFR-\d{4}$")
ISO_Z_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class HFRError(Exception):
    """Every refusal raises this, with a reason a human can act on."""


# ---------------------------------------------------------------- basics

def utc_now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def canonical_json(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def record_hash(rec):
    body = {k: v for k, v in rec.items() if k != "record_hash"}
    return hashlib.sha256(canonical_json(body)).hexdigest()


def sha256_bytes(b):
    return hashlib.sha256(b).hexdigest()


def _require(cond, msg):
    if not cond:
        raise HFRError(msg)


def _is_iso_z(v):
    return isinstance(v, str) and bool(ISO_Z_RE.match(v))


def refuse_inside_git_tree(path):
    """D-2: case data must never land inside a git working tree (this
    repo is public). Walks up from path looking for a .git entry.
    It also asks git, in case the tree is a worktree with an unusual
    layout."""
    p = os.path.abspath(path)
    cur = p
    while True:
        if os.path.exists(os.path.join(cur, ".git")):
            raise HFRError("refusing HFR_HOME inside a git working tree (%s): case data must stay out of the public repo (D-2)" % cur)
        parent = os.path.dirname(cur)
        if parent == cur:
            break
        cur = parent
    probe = p
    while not os.path.isdir(probe):
        probe = os.path.dirname(probe)
    try:
        r = subprocess.run(["git", "-C", probe, "rev-parse", "--is-inside-work-tree"],
                           capture_output=True, text=True, timeout=10)
        if r.returncode == 0 and r.stdout.strip() == "true":
            raise HFRError("refusing HFR_HOME inside a git working tree (%s) (D-2)" % probe)
    except (OSError, subprocess.TimeoutExpired):
        pass


# ---------------------------------------------------------------- defang

def defang(value, ioc_type):
    v = value.strip()
    if ioc_type == "sha256":
        v = v.lower()
        _require(SHA256_RE.match(v), "sha256 IOC is not 64 hex chars")
        return v
    if ioc_type == "ip":
        try:
            ipaddress.ip_address(v.replace("[.]", ".").replace("[:]", ":"))
        except ValueError:
            raise HFRError("not an IP address: %r" % value)
        v = v.replace("[.]", ".").replace("[:]", ":")
        return v.replace(".", "[.]") if ":" not in v else v.replace(":", "[:]")
    v = re.sub(r"^http", "hxxp", v, flags=re.I)
    v = re.sub(r"(?<!\[)\.(?!\])", "[.]", v)
    v = re.sub(r"(?<!\[)@(?!\])", "[@]", v)
    return v


def is_defanged(value, ioc_type):
    if ioc_type == "sha256":
        return bool(SHA256_RE.match(value))
    if re.search(r"(?<!\[)\.(?!\])", value):
        return False
    if re.search(r"(?<!\[)@(?!\])", value):
        return False
    if re.match(r"^https?://", value, flags=re.I):
        return False
    if ioc_type == "ip" and ":" in value and "[:]" not in value:
        return False
    return True


# ---------------------------------------------------------------- registry

class Registry(object):
    def __init__(self, path):
        _require(os.path.isfile(path), "Source Registry not found: %s" % path)
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        self.version = data.get("registry_version")
        self.sources = {s["source_id"]: s for s in data.get("sources", [])}

    def check_capture(self, source_id, method):
        s = self.sources.get(source_id)
        _require(s is not None, "source '%s' is not in the Source Registry (stop condition 1)" % source_id)
        _require(s.get("status") == "ALLOWED",
                 "source '%s' has status %s, not ALLOWED (stop condition 1)" % (source_id, s.get("status")))
        uses = s.get("allowed_uses", {})
        for use in ("collect", "store_raw"):
            _require(uses.get(use) in ("yes", "conditional"),
                     "source '%s' allowed_uses.%s=%s (stop condition 1)" % (source_id, use, uses.get(use)))
        _require(method in METHODS, "method '%s' is not a passive method (D-3); allowed: %s" % (method, ", ".join(METHODS)))
        _require((method == "owner_provided") == (s.get("kind") == "owner_provided"),
                 "method 'owner_provided' is only for the owner-provided source, and that source only takes it")
        return s

    def redact_keys(self, source_id):
        return tuple(self.sources.get(source_id, {}).get("redact_json_keys", ()))


def _strip_keys(obj, keys):
    removed = []

    def walk(o, path):
        if isinstance(o, dict):
            for k in list(o.keys()):
                if k in keys:
                    removed.append(path + k)
                    del o[k]
                else:
                    walk(o[k], path + k + ".")
        elif isinstance(o, list):
            for item in o:
                walk(item, path + "[].")
    walk(obj, "")
    return sorted(set(removed))


def _find_keys(obj, keys):
    found = []

    def walk(o, path):
        if isinstance(o, dict):
            for k, v in o.items():
                if k in keys:
                    found.append(path + k)
                walk(v, path + k + ".")
        elif isinstance(o, list):
            for item in o:
                walk(item, path + "[].")
    walk(obj, "")
    return sorted(set(found))


def prepare_raw(raw_bytes, content_type, redact_keys):
    """Returns (bytes_to_store, redaction_or_None). For JSON, removes the
    source's redact keys, then refuses if a personal-looking key remains.
    Non-JSON content can't be inspected that way. A source with redact
    rules therefore refuses non-JSON content rather than storing it
    unchecked."""
    is_json = content_type.split(";")[0].strip() in ("application/json", "application/vnd.github+json")
    if not is_json:
        _require(not redact_keys, "source has redaction rules but content_type %s cannot be redacted; refusing to store it unchecked" % content_type)
        return raw_bytes, None
    try:
        obj = json.loads(raw_bytes.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise HFRError("content_type says JSON but the body does not parse")
    removed = _strip_keys(obj, set(redact_keys)) if redact_keys else []
    leftover = _find_keys(obj, PERSONAL_KEY_HINTS)
    _require(not leftover, "personal-looking fields remain after redaction: %s -- define them in the registry's redact_json_keys or drop the capture (stop condition 3)" % ", ".join(leftover))
    if not removed:
        return raw_bytes, None
    stored = json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8")
    return stored, {"removed": removed, "original_sha256": sha256_bytes(raw_bytes)}


# ---------------------------------------------------------------- ledger

class Ledger(object):
    def __init__(self, hfr_home, case_id):
        _require(CASE_ID_RE.match(case_id or ""), "case_id must look like HFR-0001")
        refuse_inside_git_tree(hfr_home)
        self.home = os.path.abspath(hfr_home)
        self.case_id = case_id
        self.dir = os.path.join(self.home, "cases", case_id)
        self.path = os.path.join(self.dir, "ledger.jsonl")
        self.raw_dir = os.path.join(self.dir, "raw")
        self.registry_path = os.path.join(self.home, "registry", "sources.json")

    # -- reading
    def records(self):
        if not os.path.isfile(self.path):
            return []
        out = []
        with open(self.path, encoding="utf-8") as f:
            for n, line in enumerate(f, 1):
                line = line.rstrip("\n")
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except ValueError:
                    raise HFRError("ledger line %d is not JSON" % n)
        return out

    @staticmethod
    def case_state(recs):
        """OPEN / HELD / STOPPED / CLOSED from the event trail."""
        state = "OPEN"
        for r in recs:
            if r.get("record_type") != "event":
                continue
            e = r["event"]
            if e in ("HELD", "STOPPED", "CLOSED"):
                state = e
            elif e == "RESUMED":
                state = "OPEN"
        return state

    # -- writing
    def append(self, record_type, fields, agent, host="800"):
        _require(record_type in RECORD_TYPES, "unknown record_type %r" % record_type)
        _require(isinstance(agent, str) and agent.strip(), "agent is required")
        _require(host in HOSTS, "host must be one of %s" % (HOSTS,))
        os.makedirs(self.dir, exist_ok=True)
        lock_path = os.path.join(self.dir, ".ledger.lock")
        with open(lock_path, "a") as lockf:
            fcntl.flock(lockf, fcntl.LOCK_EX)
            try:
                recs = self.records()
                if recs:
                    verify_chain(recs)
                rec = dict(fields)
                self._validate(record_type, rec, recs)
                n = 1 + sum(1 for r in recs if r.get("record_type") == record_type)
                rec.update({
                    "record_id": "%s-%s-%04d" % (self.case_id, ID_LETTER[record_type], n),
                    "record_type": record_type,
                    "case_id": self.case_id,
                    "ts": utc_now(),
                    "agent": agent,
                    "host": host,
                    "prev_hash": recs[-1]["record_hash"] if recs else GENESIS,
                })
                rec["record_hash"] = record_hash(rec)
                with open(self.path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(rec, ensure_ascii=False, sort_keys=True) + "\n")
                    f.flush()
                    os.fsync(f.fileno())
                recs.append(rec)
                follow = self._after_append(rec, recs)
            finally:
                fcntl.flock(lockf, fcntl.LOCK_UN)
        if follow is not None:
            self.append("event", follow, agent="hfr_lib:auto", host=host)
        return rec

    def _after_append(self, rec, recs):
        """Cost cap -> automatic HELD (stop condition 6), design §2.6."""
        if rec["record_type"] != "cost":
            return None
        case = recs[0]
        cap = case.get("cost_cap", {})
        mins = sum(r.get("minutes", 0) for r in recs if r["record_type"] == "cost")
        yen = sum(r.get("yen", 0) for r in recs if r["record_type"] == "cost")
        over = (mins > cap.get("minutes", float("inf"))) or (yen > cap.get("yen", float("inf")))
        if over and self.case_state(recs) == "OPEN":
            return {"event": "HELD", "stop_condition": 6,
                    "reason": "cost cap reached: %d min / %d yen against cap %s" % (mins, yen, json.dumps(cap, sort_keys=True))}
        return None

    def _validate(self, t, rec, recs):
        _require("record_id" not in rec and "record_hash" not in rec and "prev_hash" not in rec,
                 "record_id/prev_hash/record_hash are assigned by the ledger")
        by_id = {r["record_id"]: r for r in recs}
        if t == "case":
            _require(not recs, "a case record must be the first and only case record")
            _require(isinstance(rec.get("title"), str) and rec["title"].strip(), "case.title is required")
            _require(isinstance(rec.get("scope"), dict), "case.scope must be an object")
            _require(str(rec.get("approved_by", "")).startswith("human:"),
                     "case.approved_by must name a human approver (human:...) -- no capture without an approved scope")
            _require(_is_iso_z(rec.get("approved_at")), "case.approved_at must be UTC ISO 8601 (Z)")
            _require(isinstance(rec.get("approval_ref"), str) and rec["approval_ref"].strip(), "case.approval_ref is required")
            cap = rec.get("cost_cap")
            _require(isinstance(cap, dict) and isinstance(cap.get("minutes"), int) and isinstance(cap.get("yen"), int),
                     "case.cost_cap needs integer minutes and yen")
            lc = rec.setdefault("linked_candidates", [])
            _require(isinstance(lc, list) and all(isinstance(x, str) for x in lc), "linked_candidates must be a list of ids")
            return
        _require(recs and recs[0]["record_type"] == "case", "the case record must come first")
        if "supersedes" in rec:
            old = by_id.get(rec["supersedes"])
            _require(old is not None and old["record_type"] == t,
                     "supersedes must name an existing %s record" % t)
        state = self.case_state(recs)
        if t == "capture":
            _require(state == "OPEN", "case is %s: no new captures until it is RESUMED" % state)
            self._validate_capture(rec, recs)
        elif t == "claim":
            _validate_claim(rec, by_id)
        elif t == "ioc":
            _require(rec.get("ioc_type") in IOC_TYPES, "ioc_type must be one of %s" % (IOC_TYPES,))
            _require("value" not in rec, "pass the indicator as value_defanged only; the live value is never stored")
            _require(isinstance(rec.get("value_defanged"), str) and is_defanged(rec["value_defanged"], rec["ioc_type"]),
                     "value_defanged is not defanged")
            fc = by_id.get(rec.get("first_capture"))
            _require(fc is not None and fc["record_type"] == "capture", "first_capture must name a capture record")
            _require(rec.get("status") in IOC_STATUS, "ioc.status must be one of %s" % (IOC_STATUS,))
        elif t == "cost":
            _require(rec.get("kind") in COST_KINDS, "cost.kind must be one of %s" % (COST_KINDS,))
            for k in ("minutes", "yen"):
                v = rec.setdefault(k, 0)
                _require(isinstance(v, int) and not isinstance(v, bool) and v >= 0, "cost.%s must be a non-negative integer (measured, not estimated)" % k)
        elif t == "event":
            e = rec.get("event")
            _require(e in EVENTS, "event must be one of %s" % (EVENTS,))
            _require(e != "OPENED" or not any(r["record_type"] == "event" for r in recs), "OPENED only once")
            _require(isinstance(rec.get("reason"), str) and rec["reason"].strip(), "event.reason is required")
            sc = rec.get("stop_condition")
            _require(sc is None or sc in STOP_CONDITIONS, "stop_condition must be 1-7 (spec §7)")
            if e == "RESUMED":
                _require(state in ("HELD", "STOPPED"), "RESUMED only from HELD or STOPPED")
                _require(str(rec.get("approved_by", "")).startswith("human:"), "RESUMED requires approved_by=human:...")
            _require(state != "CLOSED", "case is CLOSED")

    def _validate_capture(self, rec, recs):
        reg = Registry(self.registry_path)
        reg.check_capture(rec.get("source_id"), rec.get("method"))
        for k in ("url",):
            _require(isinstance(rec.get(k), str) and rec[k].strip(), "capture.%s is required" % k)
        _require(_is_iso_z(rec.get("fetched_at")), "capture.fetched_at must be UTC ISO 8601 (Z)")
        _require(rec.get("published_at") is None or _is_iso_z(rec["published_at"]),
                 "capture.published_at must be UTC ISO 8601 (Z) or null -- never an estimate")
        rec.setdefault("published_at", None)
        _require(rec.get("verification") in VERIFICATION, "verification must be one of %s" % (VERIFICATION,))
        _require(SHA256_RE.match(rec.get("raw_sha256", "")), "raw_sha256 missing (use Ledger.capture_file)")
        raw = os.path.join(self.raw_dir, rec["raw_sha256"])
        _require(os.path.isfile(raw), "raw file for raw_sha256 is not in raw/")
        dup = [r["record_id"] for r in recs if r["record_type"] == "capture" and r["raw_sha256"] == rec["raw_sha256"]]
        if dup:
            rec["duplicate_of"] = dup[0]

    def capture_file(self, src_path, fields, agent, host="800"):
        """Stores src_path (after redaction) as raw/<sha256>, read-only,
        then appends the capture record."""
        _require(os.path.isfile(src_path), "no such file: %s" % src_path)
        reg = Registry(self.registry_path)
        reg.check_capture(fields.get("source_id"), fields.get("method"))
        with open(src_path, "rb") as f:
            raw = f.read()
        ct = fields.get("content_type", "")
        _require(isinstance(ct, str) and ct, "capture.content_type is required")
        stored, redaction = prepare_raw(raw, ct, reg.redact_keys(fields["source_id"]))
        digest = sha256_bytes(stored)
        os.makedirs(self.raw_dir, exist_ok=True)
        dst = os.path.join(self.raw_dir, digest)
        if not os.path.exists(dst):
            tmp = dst + ".tmp.%d" % os.getpid()
            with open(tmp, "wb") as f:
                f.write(stored)
                f.flush()
                os.fsync(f.fileno())
            os.chmod(tmp, 0o444)
            os.rename(tmp, dst)
        fields = dict(fields)
        fields.update({"raw_sha256": digest, "raw_bytes": len(stored)})
        if redaction:
            fields["redaction"] = redaction
        return self.append("capture", fields, agent, host)

    def write_manifest(self):
        lines = []
        for name in sorted(os.listdir(self.raw_dir)) if os.path.isdir(self.raw_dir) else []:
            with open(os.path.join(self.raw_dir, name), "rb") as f:
                lines.append("%s  raw/%s" % (sha256_bytes(f.read()), name))
        with open(self.path, "rb") as f:
            lines.append("%s  ledger.jsonl" % sha256_bytes(f.read()))
        out = os.path.join(self.dir, "MANIFEST.sha256")
        tmp = out + ".tmp"
        with open(tmp, "w") as f:
            f.write("\n".join(lines) + "\n")
        os.rename(tmp, out)
        return out


def _validate_claim(rec, by_id):
    _require(isinstance(rec.get("text"), str) and rec["text"].strip(), "claim.text is required")
    cls = rec.get("class")
    _require(cls in CLAIM_CLASSES, "claim.class must be one of %s" % (CLAIM_CLASSES,))
    _require(isinstance(rec.get("attribution"), bool), "claim.attribution (true/false) is required")
    _require(isinstance(rec.get("rationale"), str) and rec["rationale"].strip(), "claim.rationale is required")
    sup = rec.setdefault("supports", [])
    con = rec.setdefault("contradicts", [])
    rec.setdefault("alternatives", [])
    for rid in sup + con:
        r = by_id.get(rid)
        _require(r is not None and r["record_type"] == "capture", "supports/contradicts must name capture records (%s)" % rid)
    ver = [by_id[rid]["verification"] for rid in sup]
    if cls == "FACT":
        _require("primary" in ver, "FACT needs at least one primary capture in supports")
        _require(not con, "FACT is impossible while any capture contradicts it -- record it as HYPOTHESIS")
    elif cls == "HYPOTHESIS":
        _require(any(v in ("primary", "secondary") for v in ver),
                 "HYPOTHESIS needs a primary or secondary capture; directive_only support alone is UNKNOWN")
        _require(rec["alternatives"], "HYPOTHESIS needs at least one alternative explanation")


def verify_chain(recs):
    """Raises HFRError on the first broken link."""
    prev = GENESIS
    seen = set()
    for i, r in enumerate(recs, 1):
        _require(r.get("prev_hash") == prev, "record %d (%s): prev_hash does not match the previous record" % (i, r.get("record_id")))
        _require(record_hash(r) == r.get("record_hash"), "record %d (%s): record_hash does not match its content" % (i, r.get("record_id")))
        _require(r["record_id"] not in seen, "record %d: duplicate record_id %s" % (i, r["record_id"]))
        seen.add(r["record_id"])
        prev = r["record_hash"]
    return prev


def verify_case(ledger):
    """Chain + raw files + references. Returns a summary dict."""
    recs = ledger.records()
    _require(recs, "empty ledger")
    head = verify_chain(recs)
    _require(recs[0]["record_type"] == "case", "first record is not the case record")
    for r in recs:
        _require(r.get("case_id") == ledger.case_id, "%s belongs to another case" % r["record_id"])
        if r["record_type"] == "capture":
            p = os.path.join(ledger.raw_dir, r["raw_sha256"])
            _require(os.path.isfile(p), "%s: raw file missing" % r["record_id"])
            with open(p, "rb") as f:
                _require(sha256_bytes(f.read()) == r["raw_sha256"], "%s: raw file content does not match raw_sha256" % r["record_id"])
    counts = {}
    for r in recs:
        counts[r["record_type"]] = counts.get(r["record_type"], 0) + 1
    return {"case_id": ledger.case_id, "records": len(recs), "head": head,
            "state": Ledger.case_state(recs), "counts": counts}


if __name__ == "__main__":
    sys.stderr.write("library module; use hfr.py\n")
    sys.exit(2)
