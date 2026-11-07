"""Two independent axes per (asset, CVE) finding.

RISK (0-100) -- "how bad would this be": severity (CVSS), likelihood
(EPSS / KEV), exposure and business impact. Additive, so the breakdown
sums exactly to the score and every point is explainable.

EVIDENCE CONFIDENCE (0-100) -- "how much should you trust that risk
number": data completeness, freshness, match precision, source
authority. Computed from different inputs and NEVER fed into the risk
score (tests assert this: changing only confidence inputs leaves risk
untouched). This is the deliberate opposite of
security/intelligence/intelligence_lib.py's
classify_risk_from_confidence_score(), which this module does not use.

Missing data is never read as "low risk": an unknown CVSS/EPSS/exposure/
impact takes a conservative middle-or-worse value AND is listed in
`missing`, which also lowers confidence.
"""

import math

from . import provenance

WEIGHTS = {"severity": 35.0, "likelihood": 35.0, "exposure": 15.0, "impact": 15.0}
RANSOMWARE_BONUS = 5.0
KEV_FLOOR = 70.0
TIERS = ((85.0, "P1"), (70.0, "P2"), (40.0, "P3"), (0.0, "P4"))

UNKNOWN_SEVERITY = 0.5     # CVSS absent -> middle, not zero
UNKNOWN_LIKELIHOOD = 0.5   # EPSS absent -> middle, not zero
EXPOSURE = {"internet_facing": 1.0, "partner_network": 0.75, "internal": 0.5, "isolated": 0.25}
IMPACT = {"tier1": 1.0, "tier2": 0.8, "tier3": 0.5, "tier4": 0.25}
UNKNOWN_EXPOSURE = 1.0     # unknown exposure is treated as worst case
UNKNOWN_IMPACT = 1.0

FRESH_DAYS = 7
MATCH_POINTS = {"exact_cpe": 30, "vendor_product_version": 22, "vendor_product": 10}


def tier(score):
    for threshold, name in TIERS:
        if score >= threshold:
            return name
    return "P4"


def score_risk(rec, asset):
    missing = []
    cvss = ((rec.get("nvd") or {}).get("cvss") or {}).get("base_score")
    if isinstance(cvss, (int, float)):
        sev = max(0.0, min(1.0, cvss / 10.0))
    else:
        sev = UNKNOWN_SEVERITY
        missing.append("cvss")

    kev = rec.get("kev")
    epss = (rec.get("epss") or {}).get("probability")
    if kev:
        lik, lik_basis = 1.0, "kev_listed"
    elif isinstance(epss, (int, float)):
        lik, lik_basis = math.sqrt(max(0.0, min(1.0, epss))), "epss"
    else:
        lik, lik_basis = UNKNOWN_LIKELIHOOD, "unknown"
        missing.append("epss")
    if not kev and not rec.get("kev_catalog_known"):
        missing.append("kev_status")

    exp_key = asset.get("exposure")
    exp = EXPOSURE.get(exp_key)
    if exp is None:
        exp = UNKNOWN_EXPOSURE
        missing.append("exposure")
    imp_key = asset.get("business_impact")
    imp = IMPACT.get(imp_key)
    if imp is None:
        imp = UNKNOWN_IMPACT
        missing.append("business_impact")

    breakdown = {
        "severity": round(WEIGHTS["severity"] * sev, 2),
        "likelihood": round(WEIGHTS["likelihood"] * lik, 2),
        "exposure": round(WEIGHTS["exposure"] * exp, 2),
        "impact": round(WEIGHTS["impact"] * imp, 2),
        "ransomware_bonus": 0.0,
        "kev_floor_adjustment": 0.0,
    }
    if kev and kev.get("known_ransomware_campaign_use", "").lower() == "known":
        breakdown["ransomware_bonus"] = RANSOMWARE_BONUS
    subtotal = sum(breakdown.values())
    if subtotal > 100.0:
        breakdown["ransomware_bonus"] = round(breakdown["ransomware_bonus"] - (subtotal - 100.0), 2)
        subtotal = sum(breakdown.values())
    if kev and subtotal < KEV_FLOOR:
        breakdown["kev_floor_adjustment"] = round(KEV_FLOOR - subtotal, 2)
    score = round(sum(breakdown.values()), 2)
    return {
        "score": score,
        "tier": tier(score),
        "breakdown": breakdown,
        "likelihood_basis": lik_basis,
        "cvss_version": ((rec.get("nvd") or {}).get("cvss") or {}).get("version"),
        "missing": missing,
    }


def _age_days(prov, now):
    dt = provenance.parse_ts((prov or {}).get("fetched_at"))
    return None if dt is None else (now - dt).total_seconds() / 86400.0


def score_confidence(rec, match_level, now=None):
    now = now or provenance.utc_now()
    factors = {}
    # completeness (max 40)
    factors["completeness"] = (
        (15 if ((rec.get("nvd") or {}).get("cvss")) else 0)
        + (10 if rec.get("epss") else 0)
        + (15 if rec.get("kev_catalog_known") else 0))
    # freshness (max 20): split evenly across the blocks actually present
    blocks = [rec[s] for s in ("kev", "nvd", "epss") if rec.get(s)]
    if blocks:
        per = 20.0 / len(blocks)
        fresh = 0.0
        for b in blocks:
            prov = b.get("provenance") or {}
            age = _age_days(prov, now)
            if prov.get("stale") or age is None:
                continue
            fresh += per if age <= FRESH_DAYS else per / 2
        factors["freshness"] = round(fresh, 2)
    else:
        factors["freshness"] = 0.0
    # match precision (max 30)
    factors["match_precision"] = MATCH_POINTS.get(match_level, 0)
    # authority (max 10): an observed/government source beats a model estimate
    if rec.get("kev") or rec.get("nvd"):
        factors["authority"] = 10
    elif rec.get("epss"):
        factors["authority"] = 5
    else:
        factors["authority"] = 0
    score = round(sum(factors.values()), 2)
    level = "HIGH" if score >= 75 else "MEDIUM" if score >= 50 else "LOW"
    stale_sources = [s for s in ("kev", "nvd", "epss")
                     if rec.get(s) and (rec[s].get("provenance") or {}).get("stale")]
    return {"score": score, "level": level, "factors": factors, "stale_sources": stale_sources}
