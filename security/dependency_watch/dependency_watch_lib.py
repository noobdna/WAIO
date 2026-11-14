"""security/dependency_watch/dependency_watch_lib.py -- W-1 Dependency
Notice Watch: the pure parsing/classification/diff core. NO network
access: dependency_watch.sh does the fetch (behind egress_check and the
HFR registry gate), then hands the saved feed file to this module.

Design: security/dependency_watch/DESIGN.md. In short:
  - Atom only (the status pages publish history.atom). A feed containing
    a DOCTYPE or ENTITY declaration is refused before parsing, so entity
    expansion is never attempted.
  - Every notice is classified security / outage / maintenance / other
    by keyword, and the matched terms are recorded with it (state the
    basis, never a black box). Keyword matching can be wrong; the first
    weeks are record-only.
  - Output is append-only JSONL. A notice already recorded with the same
    `updated` value is not written again. A changed `updated` value
    produces a new line with change="updated".
"""

import hashlib
import json
import os
import re
import sys
import xml.etree.ElementTree as ET

ATOM = "{http://www.w3.org/2005/Atom}"
MAX_FEED_BYTES = 5 * 1024 * 1024
CATEGORIES = ("security", "outage", "maintenance", "other")

# Checked in this order; the first category with a match wins, so a
# notice that mentions both a security term and an outage term is
# classified as security.
TERMS = {
    "security": (
        "security incident", "security issue", "security vulnerability", "vulnerability",
        "unauthorized", "compromise", "compromised", "breach", "credential", "credentials",
        "token", "tokens", "leaked", "exposure", "malicious", "phishing", "account takeover",
        "セキュリティ", "不正アクセス", "脆弱性", "漏えい", "漏洩", "侵害", "認証情報", "フィッシング",
    ),
    "outage": (
        "outage", "degraded", "degradation", "unavailable", "disruption", "elevated error",
        "errors", "incident", "partial", "down", "latency", "investigating",
        "障害", "停止", "遅延", "不具合", "接続できない",
    ),
    "maintenance": (
        "scheduled maintenance", "maintenance", "planned", "upgrade window",
        "メンテナンス", "計画",
    ),
}


class FeedError(Exception):
    pass


def _norm(text):
    return re.sub(r"\s+", " ", text or "").strip()


def _strip_html(text):
    return _norm(re.sub(r"<[^>]+>", " ", text or ""))


def _term_hit(term, haystack):
    if re.search(r"[぀-ヿ一-鿿]", term):
        return term in haystack
    return re.search(r"(?<![a-z0-9])" + re.escape(term) + r"(?![a-z0-9])", haystack) is not None


def classify(title, body):
    """-> (category, matched_terms). Title and body are matched
    case-insensitively; matched terms are returned sorted."""
    hay = (_norm(title) + " " + _strip_html(body)).lower()
    for cat in ("security", "outage", "maintenance"):
        hits = sorted({t for t in TERMS[cat] if _term_hit(t.lower(), hay)})
        if hits:
            return cat, hits
    return "other", []


def parse_atom(raw):
    """raw bytes -> list of dicts (entry_id, title, url, published_at,
    updated_at, body). Refuses DOCTYPE/ENTITY and oversized input."""
    if len(raw) > MAX_FEED_BYTES:
        raise FeedError("feed larger than %d bytes" % MAX_FEED_BYTES)
    head = raw[:4096].decode("utf-8", "replace").upper()
    if "<!DOCTYPE" in head or "<!ENTITY" in raw.decode("utf-8", "replace").upper():
        raise FeedError("feed contains a DOCTYPE/ENTITY declaration; refused")
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as e:
        raise FeedError("not well-formed XML: %s" % e)
    if root.tag != ATOM + "feed":
        raise FeedError("not an Atom feed (root=%s)" % root.tag)
    out = []
    for e in root.findall(ATOM + "entry"):
        link = ""
        for l in e.findall(ATOM + "link"):
            if l.get("rel", "alternate") == "alternate" and l.get("href"):
                link = l.get("href")
                break
        out.append({
            "entry_id": _norm(e.findtext(ATOM + "id")),
            "title": _norm(e.findtext(ATOM + "title")),
            "url": link,
            "published_at": _norm(e.findtext(ATOM + "published")) or None,
            "updated_at": _norm(e.findtext(ATOM + "updated")) or None,
            "body": e.findtext(ATOM + "content") or e.findtext(ATOM + "summary") or "",
        })
    return out


def notice_id(source_id, entry):
    key = entry["entry_id"] or entry["url"] or entry["title"]
    return "%s:%s" % (source_id, hashlib.sha256(key.encode("utf-8")).hexdigest()[:16])


def load_seen(notices_path):
    """notice_id -> last recorded updated_at."""
    seen = {}
    if os.path.isfile(notices_path):
        with open(notices_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    r = json.loads(line)
                    seen[r["notice_id"]] = r.get("updated_at")
    return seen


def build_records(source_id, entries, seen, fetched_at, raw_sha256):
    recs = []
    for e in entries:
        nid = notice_id(source_id, e)
        if nid in seen and seen[nid] == e["updated_at"]:
            continue
        cat, terms = classify(e["title"], e["body"])
        recs.append({
            "notice_id": nid,
            "change": "updated" if nid in seen else "new",
            "source_id": source_id,
            "title": e["title"],
            "url": e["url"],
            "published_at": e["published_at"],
            "updated_at": e["updated_at"],
            "fetched_at": fetched_at,
            "category": cat,
            "matched_terms": terms,
            "affected_assets": [],
            "raw_sha256": raw_sha256,
        })
        seen[nid] = e["updated_at"]
    return recs


def process(source_id, feed_path, notices_path, fetched_at):
    """Parse feed_path, append new/updated notices to notices_path.
    Returns a summary dict. Never deletes or rewrites existing lines."""
    with open(feed_path, "rb") as f:
        raw = f.read()
    entries = parse_atom(raw)
    digest = hashlib.sha256(raw).hexdigest()
    seen = load_seen(notices_path)
    recs = build_records(source_id, entries, seen, fetched_at, digest)
    if recs:
        os.makedirs(os.path.dirname(os.path.abspath(notices_path)), exist_ok=True)
        with open(notices_path, "a", encoding="utf-8") as f:
            for r in recs:
                f.write(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n")
    return {
        "source_id": source_id,
        "entries": len(entries),
        "written": len(recs),
        "security_new": [r["notice_id"] for r in recs if r["category"] == "security"],
        "raw_sha256": digest,
    }


if __name__ == "__main__":
    a = sys.argv
    if len(a) == 6 and a[1] == "process":
        try:
            print(json.dumps(process(a[2], a[3], a[4], a[5]), sort_keys=True))
            sys.exit(0)
        except FeedError as e:
            sys.stderr.write("[DEPENDENCY WATCH] feed refused: %s\n" % e)
            sys.exit(3)
    sys.stderr.write("usage: dependency_watch_lib.py process SOURCE_ID FEED_PATH NOTICES_PATH FETCHED_AT\n")
    sys.exit(2)
