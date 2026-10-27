"""security/mail_forensics/mail_forensics_lib.py -- static, read-only
analysis of ONE suspicious email (.eml / Apple Mail .emlx) for the
detection -> evidence -> risk -> human-approval flow. Same "pure core,
imported by its own test" convention as shadow_ai/shadow_ai_lib.py.

What it extracts: From / Reply-To / Return-Path / Message-ID / Date /
To / Subject, the Received chain, every Authentication-Results /
Received-SPF verdict grouped by the authserv-id that wrote it, every URL
in text/html parts (plus anchors whose visible text names a different
domain than their href), attachments (name, type, decoded size,
SHA-256), and forwarding evidence (Cloudflare Email Routing SRS /
X-Forwarded-For -- which alias actually received the mail).

Hard safety rules, enforced here (not left to the caller):
  - nothing is ever fetched, resolved, rendered or executed: no network,
    subprocess, eval/exec imports or calls exist in this module (the
    test suite's D-series greps for them);
  - the input file is opened read-only, and attachment payloads are
    hashed in memory and never written anywhere;
  - the verdict is ALWAYS a recommendation for human review. This module
    has no delete/quarantine/report/reply action at all.

Trust model for authentication results: any Authentication-Results
header BELOW the first hop you trust could have been written by the
sender. So verdicts are taken from the TOPMOST header of the first
authserv-id in `trusted_authserv` that appears in the message (default:
mx.cloudflare.net, the Cloudflare Email Routing edge that receives
this deployment's mail first). When none is present the topmost header of any authserv-id
is used and AUTH_UNTRUSTED_SOURCE is raised.
"""

import email
import email.policy
import email.utils
import hashlib
import html
import json
import re
import sys
import unicodedata


DEFAULT_TRUSTED_AUTHSERV = ("mx.cloudflare.net",)

# Extensions that execute (or open macro-capable documents) on a
# double-click. An archive is listed because it routinely wraps one.
RISKY_ATTACHMENT_EXT = (
    ".exe", ".scr", ".com", ".bat", ".cmd", ".js", ".jse", ".vbs", ".vbe",
    ".wsf", ".hta", ".lnk", ".iso", ".img", ".msi", ".ps1", ".jar",
    ".docm", ".xlsm", ".pptm", ".html", ".htm", ".svg",
    ".zip", ".rar", ".7z",
)

INDICATOR_WEIGHTS = {
    "DMARC_FAIL": 3,
    "DMARC_NONE": 2,
    "SPF_FAIL": 2,
    "DKIM_NOT_ALIGNED": 1,
    "AUTH_UNTRUSTED_SOURCE": 1,
    "REPLY_TO_DOMAIN_MISMATCH": 2,
    "RETURN_PATH_DOMAIN_MISMATCH": 1,
    "MESSAGE_ID_DOMAIN_MISMATCH": 1,
    "DISPLAY_NAME_DOMAIN_MISMATCH": 3,
    "HTML_ANCHOR_TEXT_MISMATCH": 3,
    "URL_DOMAIN_NOT_ALIGNED": 1,
    "RISKY_ATTACHMENT": 3,
}

_URL_RE = re.compile(r"""https?://[^\s"'<>()\[\]{}]+""", re.I)
_DOMAIN_IN_TEXT_RE = re.compile(r"\b((?:[a-z0-9-]+\.)+[a-z]{2,})\b", re.I)
# href may be double-, single- or UN-quoted (browsers accept all three).
# Anchor text is bounded so a run of unclosed <a> tags cannot make the
# scan quadratic in the body size.
_ANCHOR_RE = re.compile(r"""<a\b[^>]{0,2000}?\bhref\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'<>`=]+))[^>]{0,2000}>(.{0,4000}?)</a\s*>""", re.I | re.S)
MAX_HEADER_SCAN = 8192
_TAG_RE = re.compile(r"<[^>]+>")


# --- small pure helpers ----------------------------------------------

def addr_domain(addr):
    """Lower-cased domain part of an address (display name ignored), or ''."""
    _, a = email.utils.parseaddr(addr or "")
    return a.rpartition("@")[2].lower().strip(">") if "@" in a else ""


def url_domain(url):
    # WHATWG URL rules: userinfo ends at the first / ? # or backslash, so
    # "https://evil.test\\@good.example/" and "https://evil.test?@good.example"
    # both go to evil.test. Only an '@' before any of those is userinfo.
    m = re.match(r"https?:[/\\]*(?:[^@/?#\\]*@)?([^/\\:?#@]+)", (url or "").strip(), re.I)
    return m.group(1).lower().rstrip(".") if m else ""


def org_domain(domain):
    """Crude organisational domain: last two labels, or last three when
    the second-to-last is a common 2nd-level label (co.jp, go.jp, ...).
    Good enough for alignment checks; not a Public Suffix List."""
    labels = [l for l in (domain or "").lower().split(".") if l]
    if len(labels) >= 3 and labels[-2] in ("co", "go", "ne", "or", "ac", "ed", "ad", "gr", "lg", "com", "net", "org"):
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def aligned(a, b):
    return bool(a) and bool(b) and org_domain(a) == org_domain(b)


def parse_auth_results(value):
    """'mx.example; spf=pass smtp.mailfrom=x; dkim=fail header.d=y' ->
    (authserv_id, [{"method","result","props":{...}}, ...])."""
    value = re.sub(r"\([^()]*\)", " ", value or "")  # drop RFC comments
    parts = [p.strip() for p in value.split(";")]
    authserv = parts[0].split()[0].lower() if parts and parts[0] else ""
    results = []
    for p in parts[1:]:
        m = re.match(r"([a-z0-9_-]+)\s*=\s*([a-z0-9_-]+)(.*)", p, re.I | re.S)
        if not m:
            continue
        props = dict((k.lower(), v.strip('"')) for k, v in re.findall(r"([a-z0-9_.-]+)\s*=\s*(\"[^\"]*\"|\S+)", m.group(3), re.I))
        results.append({"method": m.group(1).lower(), "result": m.group(2).lower(), "props": props})
    return authserv, results


def parse_received(value):
    v = " ".join((value or "")[:MAX_HEADER_SCAN].split())
    frm = re.search(r"\bfrom\s+(\S+)", v, re.I)
    by = re.search(r"\bby\s+(\S+)", v, re.I)
    ip = re.search(r"\[((?:\d{1,3}\.){3}\d{1,3}|(?:ipv6:)?[0-9a-f:.]{2,45})\]", v, re.I)
    if not ip:
        ip = re.search(r"\((?:\S+\s+)?((?:\d{1,3}\.){3}\d{1,3}|[0-9a-f]{1,4}(?::[0-9a-f]{0,4}){2,})\)", v, re.I)
    date = v.rpartition(";")[2].strip() if ";" in v else ""
    return {"from": frm.group(1) if frm else "", "by": by.group(1) if by else "",
            "ip": ip.group(1) if ip else "", "date": date}


def anchor_mismatches(html_text):
    """Anchors whose visible text itself names a domain that is not the
    href's domain -- the classic 'shows nta.go.jp, links elsewhere'."""
    out = []
    for dq, sq, uq, inner in _ANCHOR_RE.findall(html_text or ""):
        href = dq or sq or uq
        text = html.unescape(_TAG_RE.sub("", inner)).strip()
        hdom = url_domain(html.unescape(href))
        shown = _DOMAIN_IN_TEXT_RE.findall(text)
        if hdom and shown and not any(aligned(s, hdom) for s in shown):
            out.append({"text": text[:200], "href_domain": hdom, "shown_domains": sorted(set(s.lower() for s in shown))})
    return out


# --- parsing ---------------------------------------------------------

def load_message(raw):
    """bytes -> email.message.EmailMessage. Apple Mail .emlx is a byte
    count line, the RFC 822 message, then an XML plist; strip both."""
    first, _, rest = raw.partition(b"\n")
    if first.strip().isdigit():
        raw = rest[: int(first.strip())]
    return email.message_from_bytes(raw, policy=email.policy.default)


def _header_str(msg, name):
    v = msg.get(name)
    return str(v) if v is not None else ""


def analyze_message(msg, trusted_authserv=DEFAULT_TRUSTED_AUTHSERV):
    hdr = {k: _header_str(msg, k) for k in ("From", "Reply-To", "Return-Path", "Message-ID", "Date", "To", "Subject")}
    from_name, from_addr = email.utils.parseaddr(hdr["From"])
    from_dom = addr_domain(hdr["From"])

    received = [parse_received(str(v)) for v in (msg.get_all("Received") or [])]

    # Authentication results, in header order (topmost first).
    auth = []
    for name in ("Authentication-Results", "ARC-Authentication-Results"):
        for v in msg.get_all(name) or []:
            sv = str(v)
            if name.startswith("ARC-"):
                sv = re.sub(r"^\s*i=\d+\s*;\s*", "", sv)
            authserv, results = parse_auth_results(sv)
            auth.append({"header": name, "authserv_id": authserv, "results": results})
    trusted = None
    for t in trusted_authserv:
        trusted = next((a for a in auth if a["authserv_id"] == t.lower() and a["header"] == "Authentication-Results"), None)
        if trusted:
            break
    untrusted_source = trusted is None
    if trusted is None:
        trusted = next((a for a in auth if a["header"] == "Authentication-Results"), None)

    verdict = {"source": trusted["authserv_id"] if trusted else "", "spf": "none", "dkim": [], "dmarc": "none"}
    for r in (trusted or {}).get("results", []):
        if r["method"] == "spf":
            verdict["spf"] = r["result"]
        elif r["method"] == "dmarc":
            verdict["dmarc"] = r["result"]
        elif r["method"] == "dkim":
            verdict["dkim"].append({"result": r["result"], "d": r["props"].get("header.d", r["props"].get("header.i", "").lstrip("@")).lower()})

    # Bodies, URLs, attachments.
    urls, anchors, attachments = [], [], []
    for part in msg.walk():
        if part.is_multipart():
            continue
        ctype = part.get_content_type()
        fname = part.get_filename()
        disp = part.get_content_disposition()
        # Any non-text leaf is reported: an unnamed application/* part is
        # still a payload a mail client may offer to open.
        if fname or disp == "attachment" or not ctype.startswith(("text/", "multipart/", "message/")):
            payload = part.get_payload(decode=True) or b""
            attachments.append({"filename": fname or "", "content_type": ctype, "size": len(payload),
                                "sha256": hashlib.sha256(payload).hexdigest()})
            continue
        if ctype in ("text/plain", "text/html"):
            try:
                text = part.get_content()
            except (LookupError, ValueError):
                text = (part.get_payload(decode=True) or b"").decode("utf-8", "replace")
            for u in _URL_RE.findall(html.unescape(text)):
                if u not in urls:
                    urls.append(u)
            if ctype == "text/html":
                anchors.extend(anchor_mismatches(text))

    fwd_for = _header_str(msg, "X-Forwarded-For").split()
    forwarding = {
        "cloudflare_email_routing": bool(re.search(r"cloudflare-email\.net|mx\.cloudflare\.net", " ".join(r["from"] + " " + r["by"] for r in received) + " " + " ".join(a["authserv_id"] for a in auth))),
        "srs_return_path": "SRS0=" in hdr["Return-Path"] or "SRS1=" in hdr["Return-Path"],
        "received_alias": fwd_for[0] if fwd_for else "",
        "forwarded_to": _header_str(msg, "X-Forwarded-To"),
    }

    indicators = []

    def flag(code, detail):
        indicators.append({"code": code, "weight": INDICATOR_WEIGHTS[code], "detail": detail})

    if untrusted_source:
        flag("AUTH_UNTRUSTED_SOURCE", "no Authentication-Results from %s; verdict taken from %r" % ("/".join(trusted_authserv), verdict["source"]))
    if verdict["dmarc"] == "fail":
        flag("DMARC_FAIL", "dmarc=fail for header.from %s" % from_dom)
    elif verdict["dmarc"] in ("none", "neutral", "temperror", "permerror"):
        flag("DMARC_NONE", "dmarc=%s for header.from %s" % (verdict["dmarc"], from_dom))
    if verdict["spf"] in ("fail", "softfail"):
        flag("SPF_FAIL", "spf=%s" % verdict["spf"])
    if not any(d["result"] == "pass" and aligned(d["d"], from_dom) for d in verdict["dkim"]):
        flag("DKIM_NOT_ALIGNED", "no passing DKIM signature aligned with %s" % from_dom)
    rt_dom = addr_domain(hdr["Reply-To"])
    if rt_dom and not aligned(rt_dom, from_dom):
        flag("REPLY_TO_DOMAIN_MISMATCH", "Reply-To %s vs From %s" % (rt_dom, from_dom))
    rp_dom = addr_domain(hdr["Return-Path"])
    if rp_dom and not forwarding["srs_return_path"] and not aligned(rp_dom, from_dom):
        flag("RETURN_PATH_DOMAIN_MISMATCH", "Return-Path %s vs From %s" % (rp_dom, from_dom))
    mid_dom = hdr["Message-ID"].strip("<> ").rpartition("@")[2].lower()
    if mid_dom and not aligned(mid_dom, from_dom):
        flag("MESSAGE_ID_DOMAIN_MISMATCH", "Message-ID domain %s vs From %s" % (mid_dom, from_dom))
    # NFKC folds fullwidth "nta．go．jp" to "nta.go.jp" before the domain scan.
    shown = [d for d in _DOMAIN_IN_TEXT_RE.findall(unicodedata.normalize("NFKC", from_name or "")) if not aligned(d, from_dom)]
    if shown:
        flag("DISPLAY_NAME_DOMAIN_MISMATCH", "display name names %s but From domain is %s" % (",".join(shown), from_dom))
    if anchors:
        flag("HTML_ANCHOR_TEXT_MISMATCH", "%d anchor(s) show one domain and link to another" % len(anchors))
    foreign = sorted(set(url_domain(u) for u in urls if url_domain(u) and not aligned(url_domain(u), from_dom)))
    if foreign:
        flag("URL_DOMAIN_NOT_ALIGNED", ",".join(foreign))
    # Windows/Finder ignore trailing dots and spaces ("invoice.exe." runs as .exe).
    risky = [a["filename"] or "(unnamed %s)" % a["content_type"] for a in attachments
             if a["filename"].lower().rstrip(". \t").endswith(RISKY_ATTACHMENT_EXT)
             or (not a["filename"] and a["content_type"] in ("application/x-msdownload", "application/x-dosexec", "application/octet-stream"))]
    if risky:
        flag("RISKY_ATTACHMENT", ",".join(risky))

    score = sum(i["weight"] for i in indicators)
    risk = "HIGH" if score >= 6 else "MEDIUM" if score >= 3 else "LOW"
    return {
        "headers": hdr,
        "from_display_name": from_name,
        "from_address": from_addr,
        "received": received,
        "authentication": auth,
        "auth_verdict": verdict,
        "urls": urls,
        "anchor_mismatches": anchors,
        "attachments": attachments,
        "forwarding": forwarding,
        "indicators": indicators,
        "score": score,
        "risk": risk,
        # Never anything else: no automatic delete/quarantine/report.
        "recommended_action": "HUMAN_REVIEW",
    }


def analyze_file(path, trusted_authserv=DEFAULT_TRUSTED_AUTHSERV):
    with open(path, "rb") as f:
        raw = f.read()
    result = analyze_message(load_message(raw), trusted_authserv)
    result["source_sha256"] = hashlib.sha256(raw).hexdigest()
    result["source_size"] = len(raw)
    return result


def main(argv):
    if len(argv) < 2:
        sys.stderr.write("usage: mail_forensics_lib.py <message.eml|.emlx> [trusted_authserv,...]\n")
        return 2
    trusted = tuple(t for t in argv[2].split(",") if t) if len(argv) > 2 else DEFAULT_TRUSTED_AUTHSERV
    print(json.dumps(analyze_file(argv[1], trusted), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
