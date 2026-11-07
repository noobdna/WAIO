"""NIST NVD CVE API 2.0 response parser.

Severity selection order (documented, tested): CVSS v4.0 > v3.1 > v3.0
> v2, and within one version the 'Primary' (NVD's own) metric over a
'Secondary' (CNA) one. The chosen metric's version and source are kept
so a reader can see exactly which score drove the risk number."""

import json

from . import cveid, provenance

API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_METRIC_KEYS = (("cvssMetricV40", "4.0"), ("cvssMetricV31", "3.1"),
                ("cvssMetricV30", "3.0"), ("cvssMetricV2", "2.0"))


class ParseError(ValueError):
    pass


def source_url(cve):
    return f"{API_BASE}?cveId={cve}"


def _pick_cvss(metrics):
    if not isinstance(metrics, dict):
        return None
    for key, version in _METRIC_KEYS:
        entries = [m for m in (metrics.get(key) or []) if isinstance(m, dict)]
        if not entries:
            continue
        entries.sort(key=lambda m: 0 if m.get("type") == "Primary" else 1)
        for m in entries:
            data = m.get("cvssData") or {}
            score = data.get("baseScore")
            if isinstance(score, (int, float)) and 0 <= score <= 10:
                return {
                    "version": version,
                    "base_score": float(score),
                    "vector": str(data.get("vectorString") or ""),
                    "severity": str(data.get("baseSeverity") or m.get("baseSeverity") or ""),
                    "metric_source": str(m.get("source") or ""),
                    "metric_type": str(m.get("type") or ""),
                }
    return None


def _cpe_matches(configurations):
    out = []
    for conf in configurations or []:
        for node in (conf or {}).get("nodes") or []:
            for cm in (node or {}).get("cpeMatch") or []:
                if not isinstance(cm, dict) or not isinstance(cm.get("criteria"), str):
                    continue
                out.append({
                    "criteria": cm["criteria"],
                    "vulnerable": bool(cm.get("vulnerable", False)),
                    "version_start_including": cm.get("versionStartIncluding"),
                    "version_start_excluding": cm.get("versionStartExcluding"),
                    "version_end_including": cm.get("versionEndIncluding"),
                    "version_end_excluding": cm.get("versionEndExcluding"),
                })
    return out


def parse(body, fetched_at, http_status=200, url=None):
    """Returns (records, stats); records is {CVE: {...nvd fields, provenance}}."""
    try:
        data = json.loads(body.decode("utf-8"))
    except Exception as e:  # noqa: BLE001
        raise ParseError(f"NVD body is not valid JSON: {type(e).__name__}") from None
    if not isinstance(data, dict) or not isinstance(data.get("vulnerabilities"), list):
        raise ParseError("NVD body has no 'vulnerabilities' list")
    digest = provenance.sha256_bytes(body)
    stats = {"entries": len(data["vulnerabilities"]), "invalid_id": 0}
    records = {}
    for item in data["vulnerabilities"]:
        c = (item or {}).get("cve") if isinstance(item, dict) else None
        cve = cveid.normalize((c or {}).get("id"))
        if not cve:
            stats["invalid_id"] += 1
            continue
        desc = ""
        for d in c.get("descriptions") or []:
            if isinstance(d, dict) and d.get("lang") == "en":
                desc = str(d.get("value") or "")
                break
        records[cve] = {
            "cve_id": cve,
            "vuln_status": str(c.get("vulnStatus") or ""),
            "published": provenance.normalize_ts(c.get("published")),
            "last_modified": provenance.normalize_ts(c.get("lastModified")),
            "description": desc[:2000],
            "cvss": _pick_cvss(c.get("metrics")),
            "cpe_matches": _cpe_matches(c.get("configurations")),
            "provenance": provenance.make(
                "nvd", url or source_url(cve), cve, fetched_at,
                c.get("lastModified"), digest, http_status),
        }
    return records, stats
