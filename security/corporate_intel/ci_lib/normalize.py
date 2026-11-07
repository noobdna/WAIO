"""CVE Data Normalizer: merges the three source stores into one
CveRecord per CVE id:

    {"cve_id", "kev": {...}|None, "nvd": {...}|None, "epss": {...}|None,
     "kev_catalog_known": bool, "missing": [...]}

`kev: None` is ambiguous on its own (not listed vs. no catalog loaded),
so kev_catalog_known says which: only when a KEV catalog snapshot exists
does "not in KEV" become a real finding. A block whose source is marked
stale (last fetch failed) carries provenance.stale=True -- the previous
data is still used, but flagged, never silently passed off as fresh."""

import copy

SOURCES = ("kev", "nvd", "epss")


def _stale_flag(rec, status):
    if not status.get("stale"):
        return rec
    failed = set(status.get("failed_ids") or [])
    if failed and rec.get("cve_id") not in failed:
        return rec
    rec = copy.deepcopy(rec)
    rec["provenance"]["stale"] = True
    return rec


def build(store, extra_ids=()):
    data = {s: store.load_source(s).get("records", {}) for s in SOURCES}
    status = {s: store.load_status(s) for s in SOURCES}
    kev_known = bool(data["kev"]) or bool(status["kev"].get("last_success_at"))
    ids = set(extra_ids)
    for s in SOURCES:
        ids.update(data[s])
    out = {}
    for cve in sorted(ids):
        rec = {"cve_id": cve, "kev_catalog_known": kev_known}
        for s in SOURCES:
            r = data[s].get(cve)
            rec[s] = _stale_flag(r, status[s]) if r else None
        rec["missing"] = missing_fields(rec)
        out[cve] = rec
    return out


def missing_fields(rec):
    missing = []
    if not rec.get("nvd"):
        missing.append("nvd")
    if not (rec.get("nvd") or {}).get("cvss"):
        missing.append("cvss")
    if not rec.get("epss"):
        missing.append("epss")
    if not rec.get("kev_catalog_known"):
        missing.append("kev_status")
    return missing
