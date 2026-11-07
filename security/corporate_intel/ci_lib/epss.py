"""FIRST EPSS API (v1) response parser. EPSS is a model estimate, not
an observation -- it feeds the risk axis as likelihood and the
confidence axis only as a lower-authority source."""

import json

from . import cveid, provenance

API_BASE = "https://api.first.org/data/v1/epss"
MAX_BATCH = 100


class ParseError(ValueError):
    pass


def source_url(cves):
    return f"{API_BASE}?cve={','.join(cves)}"


def _prob(value):
    try:
        f = float(value)
    except (TypeError, ValueError):
        return None
    return f if 0.0 <= f <= 1.0 else None


def parse(body, fetched_at, http_status=200, url=None):
    try:
        data = json.loads(body.decode("utf-8"))
    except Exception as e:  # noqa: BLE001
        raise ParseError(f"EPSS body is not valid JSON: {type(e).__name__}") from None
    if not isinstance(data, dict) or not isinstance(data.get("data"), list):
        raise ParseError("EPSS body has no 'data' list")
    digest = provenance.sha256_bytes(body)
    stats = {"entries": len(data["data"]), "invalid_id": 0, "invalid_score": 0}
    records = {}
    for row in data["data"]:
        cve = cveid.normalize((row or {}).get("cve") if isinstance(row, dict) else None)
        if not cve:
            stats["invalid_id"] += 1
            continue
        p, pct = _prob(row.get("epss")), _prob(row.get("percentile"))
        if p is None:
            stats["invalid_score"] += 1
            continue
        records[cve] = {
            "cve_id": cve,
            "probability": p,
            "percentile": pct,
            "score_date": provenance.normalize_ts(row.get("date")),
            "model_version": row.get("model_version") or data.get("model_version"),
            "provenance": provenance.make(
                "epss", url or source_url([cve]), cve, fetched_at,
                row.get("date"), digest, http_status),
        }
    return records, stats
