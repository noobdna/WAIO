#!/usr/bin/env python3
"""security/mail_guard/mail_guard_lib.py -- WAIO side of MAIL GUARD (P2).

The Cloudflare Email Worker (waio-email-threat-gateway v2, separate repo)
decides per message and writes one pseudonymised JSON event per message to
an R2 bucket. It never contacts this host. This module is everything 800
does with that:

  * sanitize_event()   -- events are untrusted input: whitelist + type-check
                          every field, drop the rest, cap every size
  * R2Client / pull()  -- read-only S3-compatible pull (SigV4, stdlib only),
                          cursor based, bounded per run
  * summarize()        -- counts for the dashboard panel
  * incident_records() -- RawIncident JSONL for the existing Incident
                          Learning pipeline (no new pipeline)
  * build_policy() / validate_policy() / diff_policy()
                       -- the KV policy document, same rules as the Worker's
                          src/policy-store.js validatePolicy()
  * publish()          -- BOZE-signed approval (boze/approval) -> KV PUT

Nothing here reads mail bodies, subjects or addresses: the events never
contain them. Python 3.9 stdlib only.
"""

import datetime
import hashlib
import hmac
import json
import os
import re
import subprocess
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

SCHEMA = 1
MODES = ("monitor", "quarantine", "enforce")
MAX_LIST = 5000
MAX_ROUTES = 200
MAX_DOC_BYTES = 1024 * 1024
POLICY_JOB_ID = "mailguard-policy"
LEVELS = ("block", "quarantine", "review", "allow")
VERDICTS = ("pass", "review", "quarantine", "reject", "would-reject", "would-quarantine")

LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
TOKEN_RE = re.compile(r"^[A-Za-z0-9_.:+-]{1,64}$")
HEX16_RE = re.compile(r"^[0-9a-f]{16}$")
HEX32_RE = re.compile(r"^[0-9a-f]{32}$")
ROUTE_KEY_RE = re.compile(r"^[a-z0-9._-]{1,64}$")
ISO_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$")
EVENT_KEY_RE = re.compile(r"^events/\d{4}/\d{2}/\d{2}/\d{2}/[0-9A-Za-z_.-]{1,120}\.json$")
BUCKET_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$")

MAX_EVENT_BYTES = 64 * 1024
MAX_LIST_BYTES = 4 * 1024 * 1024
MAX_OBJECTS_PER_RUN = 2000
HTTP_TIMEOUT = 20


class MailGuardError(Exception):
    """A refused or failed MAIL GUARD operation (message is safe to print)."""


def canonical(obj):
    return (json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def utcnow():
    return datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)


def iso(dt):
    return dt.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso(s):
    if not isinstance(s, str) or not ISO_RE.match(s):
        return None
    try:
        return datetime.datetime.strptime(s[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=datetime.timezone.utc)
    except ValueError:
        return None


# ---------------------------------------------------------------- domains

def normalize_domain(value):
    """ASCII (LDH / punycode) domain, lower case, or None.

    Stricter than the Worker's normalizeDomain(): non-ASCII input is refused
    instead of being IDNA-converted, so whatever this side writes into a
    policy is accepted by the Worker byte for byte. A leading "*." is dropped
    (same as the Worker: entries always cover subdomains).
    """
    if not isinstance(value, str):
        return None
    d = value.strip().lower()
    if d.startswith("*."):
        d = d[2:]
    d = d.rstrip(".")
    if not d or len(d) > 253 or not d.isascii() or "." not in d:
        return None
    labels = d.split(".")
    if not all(LABEL_RE.match(l) for l in labels):
        return None
    if labels[-1].isdigit():
        return None
    return d


def _addr_spec(value):
    """Minimal addr-spec check for route destinations (no quotes, no spaces)."""
    if not isinstance(value, str) or len(value) > 320:
        return None
    v = value.strip()
    if v.count("@") != 1 or any(c.isspace() for c in v) or not v.isascii():
        return None
    local, dom = v.split("@")
    d = normalize_domain(dom)
    if not local or len(local) > 64 or not d or '"' in local:
        return None
    return local + "@" + d


# ---------------------------------------------------------------- events

def _tok(v, maxlen=64):
    return v if isinstance(v, str) and len(v) <= maxlen and TOKEN_RE.match(v) else None


def _int(v, lo=0, hi=10 ** 9):
    return v if isinstance(v, int) and not isinstance(v, bool) and lo <= v <= hi else None


def _num(v, lo=0, hi=10 ** 7):
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        return None
    return v if lo <= v <= hi else None


def _tok_list(v, cap=40):
    if not isinstance(v, list):
        return []
    return [t for t in (_tok(x) for x in v[:cap]) if t]


def _dom_list(v, cap=20):
    if not isinstance(v, list):
        return []
    out = []
    for x in v[:cap]:
        d = normalize_domain(x)
        if d and d not in out:
            out.append(d)
    return out


def sanitize_event(obj):
    """Return a clean event dict or None. Unknown fields are dropped.

    Events come from R2 and are treated as hostile: a compromised Worker or a
    leaked write token must not be able to inject markup, control characters,
    huge values or addresses into WAIO state or the dashboard.
    """
    if not isinstance(obj, dict) or obj.get("gateway") != "waio-email-threat-gateway":
        return None
    ts = parse_iso(obj.get("ts"))
    if ts is None:
        return None
    ev = {
        "ts": iso(ts),
        "event": _tok(obj.get("event")),
        "version": _tok(obj.get("version")),
        "mode": obj.get("mode") if obj.get("mode") in MODES else None,
        "verdict": obj.get("verdict") if obj.get("verdict") in VERDICTS else None,
        "action": _tok(obj.get("action")),
        "level": obj.get("level") if obj.get("level") in LEVELS else None,
        "score": _int(obj.get("score"), 0, 1000),
        "reasons": _tok_list(obj.get("reasons")),
        "flags": _tok_list(obj.get("flags")),
        "indicators": _tok_list(obj.get("indicators")),
        "high_confidence": _tok_list(obj.get("high_confidence")),
        "msg_id_hash": obj.get("msg_id_hash") if isinstance(obj.get("msg_id_hash"), str) and HEX16_RE.match(obj["msg_id_hash"]) else None,
        "env_from_domain": normalize_domain(obj.get("env_from_domain")),
        "hdr_from_domain": normalize_domain(obj.get("hdr_from_domain")),
        "rcpt_domain": normalize_domain(obj.get("rcpt_domain")),
        "route": obj.get("route") if obj.get("route") in ("default", "mapped", "catchall", "unmapped") else None,
        "policy_version": _int(obj.get("policy_version"), 1, 10 ** 9),
        "policy_source": obj.get("policy_source") if obj.get("policy_source") in ("kv", "last_good", "baseline") else None,
        "raw_size": _int(obj.get("raw_size"), 0, 64 * 1024 * 1024),
        "duration_ms": _num(obj.get("duration_ms"), 0, 10 ** 6),
        "config_warnings": _tok_list(obj.get("config_warnings")),
    }
    auth = obj.get("auth")
    if isinstance(auth, dict):
        ev["auth"] = {k: _tok(auth.get(k), 16) for k in ("spf", "dkim", "dmarc")}
    b = obj.get("body")
    if isinstance(b, dict):
        atts = []
        for a in (b.get("attachments") or [])[:20] if isinstance(b.get("attachments"), list) else []:
            if isinstance(a, dict):
                ext = a.get("ext") if isinstance(a.get("ext"), str) and re.match(r"^[a-z0-9]{0,8}$", a["ext"]) else ""
                typ = a.get("type") if isinstance(a.get("type"), str) and re.match(r"^[a-z0-9.+/-]{1,80}$", a["type"]) else ""
                atts.append({"ext": ext, "type": typ})
        ev["body"] = {
            "scanned": b.get("scanned") is True,
            "truncated": b.get("truncated") is True,
            "skipped": _tok(b.get("skipped")),
            "url_count": _int(b.get("url_count"), 0, 10 ** 6) or 0,
            "url_domains": _dom_list(b.get("url_domains")),
            "foreign_url_domains": _dom_list(b.get("foreign_url_domains")),
            "url_blocklist_hits": _dom_list(b.get("url_blocklist_hits")),
            "anchor_mismatches": _int(b.get("anchor_mismatches"), 0, 10 ** 6) or 0,
            "attachments": atts,
        }
    err = obj.get("error")
    if isinstance(err, dict):
        ev["error"] = {"name": _tok(err.get("name"))}
    return ev


def is_flagged(ev):
    """True for messages that reached quarantine or block level."""
    return ev.get("level") in ("block", "quarantine") or ev.get("verdict") in (
        "reject", "quarantine", "would-reject", "would-quarantine")


# ---------------------------------------------------------------- SigV4 / R2

def _hmac(key, msg):
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def sigv4_headers(method, host, path, query, headers, payload_sha256, access_key, secret_key,
                  region, service, amz_date):
    """Return the Authorization header value (AWS Signature Version 4).

    query: list of (name, value) pairs (unencoded). headers: dict of extra
    headers to sign (lower-case names); host, x-amz-date and
    x-amz-content-sha256 are always signed.
    """
    signed = dict((k.lower(), v.strip()) for k, v in headers.items())
    signed["host"] = host
    signed["x-amz-date"] = amz_date
    signed["x-amz-content-sha256"] = payload_sha256
    names = sorted(signed)
    canon_q = "&".join("%s=%s" % (urllib.parse.quote(k, safe="-_.~"), urllib.parse.quote(v, safe="-_.~"))
                       for k, v in sorted(query))
    canon_req = "\n".join([
        method, urllib.parse.quote(path, safe="/-_.~"), canon_q,
        "".join("%s:%s\n" % (n, signed[n]) for n in names), ";".join(names), payload_sha256])
    day = amz_date[:8]
    scope = "%s/%s/%s/aws4_request" % (day, region, service)
    to_sign = "\n".join(["AWS4-HMAC-SHA256", amz_date, scope, sha256_hex(canon_req.encode("utf-8"))])
    k = _hmac(("AWS4" + secret_key).encode("utf-8"), day)
    k = _hmac(k, region)
    k = _hmac(k, service)
    k = _hmac(k, "aws4_request")
    sig = hmac.new(k, to_sign.encode("utf-8"), hashlib.sha256).hexdigest()
    return "AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s" % (
        access_key, scope, ";".join(names), sig)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def _opener():
    return urllib.request.build_opener(_NoRedirect)


def _http(method, url, headers, body=None, max_bytes=MAX_LIST_BYTES):
    """Return (status, bytes). Never follows redirects; caps the body size."""
    req = urllib.request.Request(url, data=body, method=method, headers=headers)
    try:
        resp = _opener().open(req, timeout=HTTP_TIMEOUT)
        status = resp.status
    except urllib.error.HTTPError as e:
        resp, status = e, e.code
    except (urllib.error.URLError, OSError, ValueError) as e:
        raise MailGuardError("network error (%s)" % type(e).__name__)
    try:
        data = resp.read(max_bytes + 1)
    finally:
        resp.close()
    if len(data) > max_bytes:
        raise MailGuardError("response larger than %d bytes" % max_bytes)
    return status, data


def check_endpoint(endpoint, expect_host):
    """https://<expect_host> only (127.0.0.1 http allowed for tests)."""
    u = urllib.parse.urlsplit(endpoint)
    loopback = u.scheme == "http" and u.hostname == "127.0.0.1"
    if not (u.scheme == "https" or loopback) or u.username or u.password or u.query or u.fragment \
            or u.path not in ("", "/"):
        raise MailGuardError("endpoint must be a bare https://host")
    if not loopback and u.hostname != expect_host:
        raise MailGuardError("endpoint host is not the egress-checked host")
    return "%s://%s" % (u.scheme, u.netloc)


def r2_host(account_id):
    if not isinstance(account_id, str) or not HEX32_RE.match(account_id):
        raise MailGuardError("account_id must be 32 lowercase hex chars")
    return "%s.r2.cloudflarestorage.com" % account_id


class R2Client:
    """Read-only S3-compatible client: ListObjectsV2 and GetObject only."""

    def __init__(self, endpoint, bucket, access_key, secret_key, now=None):
        if not BUCKET_RE.match(bucket or ""):
            raise MailGuardError("invalid bucket name")
        self.base = endpoint.rstrip("/")
        self.host = urllib.parse.urlsplit(self.base).netloc
        self.bucket, self.ak, self.sk = bucket, access_key, secret_key
        self._now = now

    def _get(self, path, query, max_bytes):
        amz_date = (self._now() if self._now else utcnow()).strftime("%Y%m%dT%H%M%SZ")
        empty = sha256_hex(b"")
        auth = sigv4_headers("GET", self.host, path, query, {}, empty, self.ak, self.sk, "auto", "s3", amz_date)
        qs = urllib.parse.urlencode(sorted(query), quote_via=urllib.parse.quote)
        url = self.base + urllib.parse.quote(path, safe="/-_.~") + ("?" + qs if qs else "")
        return _http("GET", url, {"Authorization": auth, "x-amz-date": amz_date,
                                  "x-amz-content-sha256": empty}, max_bytes=max_bytes)

    def list(self, prefix, start_after, max_keys=1000):
        q = [("list-type", "2"), ("prefix", prefix), ("max-keys", str(max_keys))]
        if start_after:
            q.append(("start-after", start_after))
        status, data = self._get("/" + self.bucket, q, MAX_LIST_BYTES)
        if status != 200:
            raise MailGuardError("list failed: HTTP %d" % status)
        if b"<!DOCTYPE" in data or b"<!ENTITY" in data:
            raise MailGuardError("list response contains a DTD")
        try:
            root = ET.fromstring(data)
        except ET.ParseError:
            raise MailGuardError("list response is not XML")
        keys = []
        truncated = False
        for el in root.iter():
            tag = el.tag.rsplit("}", 1)[-1]
            if tag == "Key" and el.text:
                keys.append(el.text)
            elif tag == "IsTruncated":
                truncated = (el.text or "").strip() == "true"
        return keys, truncated

    def get(self, key):
        status, data = self._get("/%s/%s" % (self.bucket, key), [], MAX_EVENT_BYTES)
        if status != 200:
            raise MailGuardError("get failed: HTTP %d" % status)
        return data


# ---------------------------------------------------------------- state

def _read_json(path, default):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return default
    except (OSError, ValueError):
        raise MailGuardError("unreadable state file: %s" % os.path.basename(path))


def _write_json_atomic(path, obj):
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(obj, f, sort_keys=True, indent=1)
        f.write("\n")
    os.replace(tmp, path)


def ensure_state_dir(state_dir):
    os.makedirs(state_dir, mode=0o700, exist_ok=True)
    return state_dir


def initial_cursor(now, lookback_hours=48):
    t = now - datetime.timedelta(hours=lookback_hours)
    return t.strftime("events/%Y/%m/%d/%H/")


def pull(client, state_dir, now=None, max_objects=MAX_OBJECTS_PER_RUN, lookback_hours=48):
    """Pull new events after the stored cursor; append sanitised ones.

    Returns a result dict. The cursor only advances past keys that were
    fetched (good or rejected), so a failure mid-run resumes there.
    """
    now = now or utcnow()
    ensure_state_dir(state_dir)
    cur_path = os.path.join(state_dir, "cursor.json")
    cursor = _read_json(cur_path, {}).get("after") or initial_cursor(now, lookback_hours)
    events_path = os.path.join(state_dir, "events.jsonl")
    res = {"fetched": 0, "stored": 0, "rejected": 0, "more": False, "cursor_before": cursor}
    seen = 0
    try:
        while seen < max_objects:
            keys, truncated = client.list("events/", cursor, min(1000, max_objects - seen))
            keys = [k for k in keys if k > cursor]
            if not keys:
                break
            with open(events_path, "a", encoding="utf-8") as out:
                os.chmod(events_path, 0o600)
                for k in keys:
                    if seen >= max_objects:
                        break
                    seen += 1
                    if not EVENT_KEY_RE.match(k):
                        res["rejected"] += 1
                        cursor = k
                        continue
                    raw = client.get(k)
                    res["fetched"] += 1
                    try:
                        ev = sanitize_event(json.loads(raw.decode("utf-8")))
                    except (UnicodeDecodeError, ValueError):
                        ev = None
                    if ev is None:
                        res["rejected"] += 1
                    else:
                        ev["key"] = k
                        out.write(json.dumps(ev, sort_keys=True, ensure_ascii=True) + "\n")
                        res["stored"] += 1
                    cursor = k
            if not truncated:
                break
        res["more"] = seen >= max_objects
    finally:
        _write_json_atomic(cur_path, {"after": cursor, "updated_at": iso(now)})
        res["cursor_after"] = cursor
    return res


def load_events(state_dir, since=None):
    path = os.path.join(state_dir, "events.jsonl")
    out = []
    try:
        f = open(path, "r", encoding="utf-8")
    except FileNotFoundError:
        return out
    with f:
        for line in f:
            try:
                ev = sanitize_event(dict(json.loads(line), gateway="waio-email-threat-gateway"))
            except (ValueError, TypeError):
                continue
            if ev is None:
                continue
            if since and parse_iso(ev["ts"]) < since:
                continue
            out.append(ev)
    return out


def prune_events(state_dir, keep_days, now=None):
    """Drop local events older than keep_days (design D-7: 30 days)."""
    now = now or utcnow()
    path = os.path.join(state_dir, "events.jsonl")
    keep = load_events(state_dir, since=now - datetime.timedelta(days=keep_days))
    if not os.path.exists(path):
        return 0
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        for ev in keep:
            f.write(json.dumps(ev, sort_keys=True, ensure_ascii=True) + "\n")
    os.replace(tmp, path)
    return len(keep)


# ---------------------------------------------------------------- summaries

def _count(items):
    d = {}
    for i in items:
        if i:
            d[i] = d.get(i, 0) + 1
    return dict(sorted(d.items(), key=lambda kv: (-kv[1], kv[0])))


def _top(d, n=10):
    return [{"name": k, "count": v} for k, v in list(d.items())[:n]]


def summarize(events, now=None):
    now = now or utcnow()
    out = {}
    for label, hours in (("last_24h", 24), ("last_7d", 168)):
        since = now - datetime.timedelta(hours=hours)
        evs = [e for e in events if parse_iso(e["ts"]) >= since]
        flagged = [e for e in evs if is_flagged(e)]
        out[label] = {
            "messages": len(evs),
            "by_verdict": _count(e.get("verdict") for e in evs),
            "by_level": _count(e.get("level") for e in evs),
            "flagged": len(flagged),
            "top_indicators": _top(_count(i for e in evs for i in e.get("indicators", []))),
            "top_flagged_sender_domains": _top(_count(e.get("hdr_from_domain") or e.get("env_from_domain") for e in flagged)),
            "top_url_blocklist_hits": _top(_count(d for e in evs for d in (e.get("body") or {}).get("url_blocklist_hits", []))),
            "errors": sum(1 for e in evs if e.get("error") or "internal_error" in e.get("flags", [])),
            "unmapped_routes": sum(1 for e in evs if e.get("route") == "unmapped"),
        }
    last = max(events, key=lambda e: e["ts"]) if events else None
    out["latest_event_at"] = last["ts"] if last else None
    out["mode"] = last.get("mode") if last else None
    out["policy_version"] = last.get("policy_version") if last else None
    out["policy_source"] = last.get("policy_source") if last else None
    out["gateway_version"] = last.get("version") if last else None
    out["config_warnings"] = sorted(set(last.get("config_warnings", []))) if last else []
    return out


def incident_records(events, now=None, min_messages=1):
    """RawIncident JSONL objects (security/incident_learning collector contract).

    One record per (UTC day, sender domain) among flagged messages. Only
    domains, indicator names and counts -- never hashes or addresses.
    """
    now = now or utcnow()
    groups = {}
    for e in events:
        if not is_flagged(e):
            continue
        dom = e.get("hdr_from_domain") or e.get("env_from_domain")
        if not dom:
            continue
        groups.setdefault((e["ts"][:10], dom), []).append(e)
    recs = []
    for (day, dom), evs in sorted(groups.items()):
        if len(evs) < min_messages:
            continue
        inds = _count(i for e in evs for i in e.get("indicators", []))
        urls = _count(d for e in evs for d in (e.get("body") or {}).get("foreign_url_domains", []))
        verdicts = _count(e.get("verdict") for e in evs)
        text = ("WAIO MAIL GUARD inbound mail detection: %d message(s) from sender domain %s were classified "
                "%s on %s (verdicts: %s). Indicators: %s. Linked URL domains: %s. "
                "Detection point: Cloudflare Email Routing worker (waio-email-threat-gateway). "
                "Recommended mitigation: human review; if confirmed, add the domain to the MAIL GUARD "
                "sender_block list via the signed policy publish."
                % (len(evs), dom, "/".join(sorted(set(e.get("level") or "?" for e in evs))), day,
                   ", ".join("%s x%d" % kv for kv in verdicts.items()) or "none",
                   ", ".join(list(inds)[:10]) or "none", ", ".join(list(urls)[:10]) or "none"))
        recs.append({
            "id": "MAILGUARD-%s-%s" % (day.replace("-", ""), sha256_hex(dom.encode("ascii"))[:12]),
            "source": "mail_guard",
            "source_type": "internal_telemetry",
            "source_url": "waio://mail_guard/%s/%s" % (day, dom),
            "collected_at": iso(now),
            "raw_text": text,
            "language": "en",
        })
    return recs


# ---------------------------------------------------------------- policy

def _domain_list(v, field, errors):
    if v is None:
        return []
    if not isinstance(v, list) or len(v) > MAX_LIST:
        errors.append(field + "_invalid")
        return []
    out = []
    for x in v:
        d = normalize_domain(x)
        if not d:
            errors.append(field + "_entry_invalid")
            return []
        if d not in out:
            out.append(d)
    return out


def _intin(v, lo, hi):
    return isinstance(v, int) and not isinstance(v, bool) and lo <= v <= hi


def validate_policy(doc, now=None, require_approval=True):
    """Same acceptance rules as the Worker's validatePolicy(); returns error list.

    require_approval=False validates the *body* a human signs (the document
    without approved_by_sig_sha256).
    """
    now = now or utcnow()
    if not isinstance(doc, dict):
        return ["not_object"]
    e = []
    if doc.get("schema") != SCHEMA:
        e.append("schema_mismatch")
    if not _intin(doc.get("version"), 1, 10 ** 9):
        e.append("version_invalid")
    if doc.get("mode") not in MODES:
        e.append("mode_invalid")
    if require_approval:
        a = doc.get("approved_by_sig_sha256")
        if not (isinstance(a, str) and re.match(r"^[0-9a-f]{64}$", a)):
            e.append("approval_missing")
    elif "approved_by_sig_sha256" in doc:
        e.append("body_must_not_carry_approval")
    exp = parse_iso(doc.get("expires_at"))
    if exp is None:
        e.append("expires_invalid")
    elif exp <= now:
        e.append("expired")
    for f in ("sender_block", "url_block", "sender_allow"):
        _domain_list(doc.get(f), f, e)
    q, r, c = (doc.get("quarantine_threshold", 6), doc.get("review_threshold", 3),
               doc.get("catchall_quarantine_threshold", 3))
    if not (_intin(q, 1, 50) and _intin(r, 1, 50) and _intin(c, 1, 50)) or r >= q:
        e.append("thresholds_invalid")
    routes = doc.get("routes")
    if routes is not None:
        if not isinstance(routes, dict) or len(routes) > MAX_ROUTES:
            e.append("routes_invalid")
        else:
            for k, v in routes.items():
                if not ((k == "*" or ROUTE_KEY_RE.match(str(k).lower())) and _addr_spec(v)):
                    e.append("route_entry_invalid")
                    break
    if len(canonical(doc)) > MAX_DOC_BYTES:
        e.append("too_large")
    return sorted(set(e))


def build_policy(base, version, changes, now=None, ttl_days=30):
    """Return a new policy *body* (unsigned) from base (dict or None) + changes.

    changes keys (all optional): mode, add/remove_sender_block, add/remove_url_block,
    add/remove_sender_allow (lists of domains), quarantine_threshold,
    review_threshold, catchall_quarantine_threshold, routes (full replacement),
    set_route {key: dest}, remove_route [keys].
    """
    now = now or utcnow()
    base = base or {}
    body = {"schema": SCHEMA, "version": version, "created_at": iso(now),
            "expires_at": iso(now + datetime.timedelta(days=ttl_days)),
            "base_version": base.get("version")}
    body["mode"] = changes.get("mode") or base.get("mode") or "monitor"
    for f in ("sender_block", "url_block", "sender_allow"):
        cur = [d for d in (normalize_domain(x) for x in base.get(f, [])) if d]
        for x in changes.get("add_" + f, []):
            d = normalize_domain(x)
            if not d:
                raise MailGuardError("invalid domain for %s: %r" % (f, x))
            if d not in cur:
                cur.append(d)
        for x in changes.get("remove_" + f, []):
            d = normalize_domain(x)
            if d not in cur:
                raise MailGuardError("%s does not contain %r" % (f, x))
            cur.remove(d)
        body[f] = sorted(cur)
    for f, dflt in (("quarantine_threshold", 6), ("review_threshold", 3), ("catchall_quarantine_threshold", 3)):
        body[f] = changes.get(f, base.get(f, dflt))
    routes = dict(changes["routes"]) if "routes" in changes else dict(base.get("routes") or {})
    routes.update(changes.get("set_route") or {})
    for k in changes.get("remove_route") or []:
        if k not in routes:
            raise MailGuardError("routes has no key %r" % k)
        del routes[k]
    if routes:
        body["routes"] = {str(k).lower(): _addr_spec(v) or v for k, v in sorted(routes.items())}
    if body["base_version"] is None:
        del body["base_version"]
    errs = validate_policy(body, now=now, require_approval=False)
    if errs:
        raise MailGuardError("policy invalid: %s" % ", ".join(errs))
    if base.get("version") is not None and version <= base["version"]:
        raise MailGuardError("version must be greater than the base version")
    return body


def _mask_route(v):
    # Destinations are personal addresses: show only the domain in diffs.
    return "***@" + v.rsplit("@", 1)[-1] if isinstance(v, str) and "@" in v else "***"


def diff_policy(base, new):
    """Human-readable diff lines (route destinations masked)."""
    base = base or {}
    lines = ["MAIL GUARD policy v%s -> v%s" % (base.get("version", "-"), new.get("version"))]
    if base.get("mode") != new.get("mode"):
        lines.append("mode: %s -> %s" % (base.get("mode", "(baseline)"), new.get("mode")))
    for f in ("sender_block", "url_block", "sender_allow"):
        old, cur = set(base.get(f, [])), set(new.get(f, []))
        lines += ["+ %s %s" % (f, d) for d in sorted(cur - old)]
        lines += ["- %s %s" % (f, d) for d in sorted(old - cur)]
    for f in ("quarantine_threshold", "review_threshold", "catchall_quarantine_threshold"):
        if base.get(f) != new.get(f):
            lines.append("%s: %s -> %s" % (f, base.get(f, "-"), new.get(f)))
    ob, nb = base.get("routes") or {}, new.get("routes") or {}
    for k in sorted(set(ob) | set(nb)):
        if ob.get(k) != nb.get(k):
            lines.append("route %s: %s -> %s" % (k, _mask_route(ob[k]) if k in ob else "(none)",
                                                 _mask_route(nb[k]) if k in nb else "(removed)"))
    lines.append("expires_at: %s" % new.get("expires_at"))
    if len(lines) == 2:
        lines.insert(1, "(no list/mode/threshold/route changes; expiry renewal only)")
    return lines


def publish_action(version):
    return "publish-v%d" % version


# ---------------------------------------------------------------- KV / publish

class KVClient:
    """Cloudflare Workers KV REST API (values endpoint only)."""

    def __init__(self, endpoint, account_id, namespace_id, token):
        if not HEX32_RE.match(account_id or "") or not HEX32_RE.match(namespace_id or ""):
            raise MailGuardError("account_id/namespace_id must be 32 lowercase hex chars")
        self.base = "%s/client/v4/accounts/%s/storage/kv/namespaces/%s/values/" % (
            endpoint.rstrip("/"), account_id, namespace_id)
        self.token = token

    def _url(self, key):
        return self.base + urllib.parse.quote(key, safe="")

    def get(self, key):
        status, data = _http("GET", self._url(key), {"Authorization": "Bearer " + self.token},
                             max_bytes=MAX_DOC_BYTES + 1024)
        if status == 404:
            return None
        if status != 200:
            raise MailGuardError("KV get %s failed: HTTP %d" % (key, status))
        return data

    def put(self, key, value):
        status, _ = _http("PUT", self._url(key), {"Authorization": "Bearer " + self.token,
                                                  "Content-Type": "text/plain"}, body=value, max_bytes=65536)
        if status != 200:
            raise MailGuardError("KV put %s failed: HTTP %d" % (key, status))


def publish(kv, body_bytes, request_bytes, sig_bytes, allowed_signers, ledger_path, publish_log,
            approval_mod, now=None):
    """Verify the BOZE approval for body_bytes, consume it, then write KV.

    Order: parse/validate body -> verify signature (job/action/sha bound) ->
    check KV state (base_version == current, target version unused) ->
    consume nonce -> PUT policy:v<N> -> read back -> PUT policy:current ->
    read back -> append publish log. Any failure before consume leaves the
    approval reusable; any failure after it needs a new approval.
    """
    now = now or utcnow()
    try:
        body = json.loads(body_bytes.decode("ascii"))
    except (UnicodeDecodeError, ValueError):
        raise MailGuardError("policy body is not ASCII JSON")
    if canonical(body) != body_bytes:
        raise MailGuardError("policy body is not in canonical form")
    errs = validate_policy(body, now=now, require_approval=False)
    if errs:
        raise MailGuardError("policy body invalid: %s" % ", ".join(errs))
    n = body["version"]
    psha = sha256_hex(body_bytes)
    try:
        verified = approval_mod.verify(request_bytes, sig_bytes, allowed_signers,
                                       {"job_id": POLICY_JOB_ID, "action": publish_action(n),
                                        "payload_sha256": psha})
    except approval_mod.ApprovalError as e:
        raise MailGuardError("approval refused: %s" % e)

    cur = kv.get("policy:current")
    cur_n = int(cur.decode("ascii").strip()) if cur and cur.strip().isdigit() else None
    if cur is not None and cur_n is None:
        raise MailGuardError("KV policy:current is not a version number; refusing")
    if body.get("base_version") != cur_n:
        raise MailGuardError("KV current is v%s but this policy was built on v%s; rebuild and re-approve"
                             % (cur_n, body.get("base_version")))
    if cur_n is not None and n <= cur_n:
        raise MailGuardError("version v%d is not newer than current v%d" % (n, cur_n))
    if kv.get("policy:v%d" % n) is not None:
        raise MailGuardError("policy:v%d already exists (versions are immutable)" % n)

    try:
        approval_mod.consume(ledger_path, verified)
    except approval_mod.ApprovalError as e:
        raise MailGuardError("approval refused: %s" % e)

    full = dict(body, approved_by_sig_sha256=sha256_hex(sig_bytes))
    errs = validate_policy(full, now=now)
    if errs:
        raise MailGuardError("signed policy invalid: %s" % ", ".join(errs))
    full_bytes = canonical(full)
    key = "policy:v%d" % n
    kv.put(key, full_bytes)
    if kv.get(key) != full_bytes:
        raise MailGuardError("read-back of %s did not match; policy:current NOT switched" % key)
    kv.put("policy:current", str(n).encode("ascii"))
    if (kv.get("policy:current") or b"").strip() != str(n).encode("ascii"):
        raise MailGuardError("read-back of policy:current did not match")
    entry = {"published_at": iso(now), "version": n, "base_version": cur_n, "mode": body["mode"],
             "body_sha256": psha, "doc_sha256": sha256_hex(full_bytes),
             "sig_sha256": full["approved_by_sig_sha256"], "principal": verified["principal"],
             "nonce": verified["request"]["nonce"]}
    fd = os.open(publish_log, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    try:
        os.write(fd, canonical(entry))
    finally:
        os.close(fd)
    return entry


# ---------------------------------------------------------------- secrets

def keychain_secret(service):
    """Read a generic password from the login Keychain (never printed).

    MAILGUARD_NO_KEYCHAIN=1 disables the lookup (test suites).
    """
    if os.environ.get("MAILGUARD_NO_KEYCHAIN") == "1":
        return None
    try:
        r = subprocess.run(["/usr/bin/security", "find-generic-password", "-a", os.environ.get("USER", ""),
                            "-s", service, "-w"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                           timeout=10, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None
    v = r.stdout.decode("utf-8", "replace").strip() if r.returncode == 0 else ""
    return v or None


def secret(env_name, service):
    return os.environ.get(env_name) or keychain_secret(service)
