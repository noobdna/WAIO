"""CISA Known Exploited Vulnerabilities catalog parser (full catalog --
unlike security/incident_learning/collectors/cisa_kev_collector.sh,
which deliberately emits only a 7-day window for a different purpose)."""

import json

from . import cveid, provenance

SOURCE_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


class ParseError(ValueError):
    pass


def parse(body, fetched_at, http_status=200):
    """body: raw bytes. Returns (records, stats). records is
    {CVE: {kev fields..., provenance}}. Entries without a valid cveID
    are skipped and counted, never invented. Duplicate cveIDs keep the
    earliest dateAdded."""
    try:
        data = json.loads(body.decode("utf-8"))
    except Exception as e:  # noqa: BLE001 -- any decode failure is a parse failure
        raise ParseError(f"KEV body is not valid JSON: {type(e).__name__}") from None
    if not isinstance(data, dict) or not isinstance(data.get("vulnerabilities"), list):
        raise ParseError("KEV body has no 'vulnerabilities' list")

    digest = provenance.sha256_bytes(body)
    catalog_updated = data.get("dateReleased")
    stats = {"entries": len(data["vulnerabilities"]), "invalid_id": 0, "duplicates": 0,
             "catalog_version": data.get("catalogVersion"), "date_released": catalog_updated}
    records = {}
    for v in data["vulnerabilities"]:
        if not isinstance(v, dict):
            stats["invalid_id"] += 1
            continue
        cve = cveid.normalize(v.get("cveID"))
        if not cve:
            stats["invalid_id"] += 1
            continue
        rec = {
            "cve_id": cve,
            "vendor_project": str(v.get("vendorProject") or ""),
            "product": str(v.get("product") or ""),
            "vulnerability_name": str(v.get("vulnerabilityName") or ""),
            "date_added": provenance.normalize_ts(v.get("dateAdded")),
            "due_date": provenance.normalize_ts(v.get("dueDate")),
            "required_action": str(v.get("requiredAction") or ""),
            "known_ransomware_campaign_use": str(v.get("knownRansomwareCampaignUse") or "Unknown"),
            "cwes": [c for c in (v.get("cwes") or []) if isinstance(c, str)],
            "provenance": provenance.make(
                "kev", SOURCE_URL, cve, fetched_at,
                catalog_updated, digest, http_status),
        }
        if cve in records:
            stats["duplicates"] += 1
            prev = records[cve]["date_added"] or "9999"
            if (rec["date_added"] or "9999") >= prev:
                continue
        records[cve] = rec
    return records, stats
