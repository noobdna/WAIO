"""Intelligence Correlation Engine: asset inventory x CveRecord set.

Match precision levels (strongest first):
  exact_cpe               asset declares a CPE whose vendor/product match an
                          NVD vulnerable cpeMatch, and its version is inside
                          the declared range
  vendor_product_version  asset vendor/product fields match and its version
                          is inside the range
  vendor_product          vendor/product match but the version cannot be
                          decided (asset version unknown, range not
                          comparable, or the only evidence is KEV's own
                          vendorProject/product text) -- kept, never dropped,
                          because silently dropping it would hide exposure
A version that is decidably OUTSIDE every range is not a match."""

import re

LEVELS = ("exact_cpe", "vendor_product_version", "vendor_product")
_RANK = {lvl: i for i, lvl in enumerate(LEVELS)}


def norm_name(s):
    s = (s or "").strip().lower()
    s = re.sub(r"[\s\-./]+", "_", s)
    return re.sub(r"_+", "_", s).strip("_")


def parse_cpe(cpe):
    """cpe:2.3:part:vendor:product:version:... -> dict, honoring '\\:'
    escapes. Returns None for anything that is not a CPE 2.3 string."""
    if not isinstance(cpe, str) or not cpe.startswith("cpe:2.3:"):
        return None
    fields, cur, esc = [], [], False
    for ch in cpe:
        if esc:
            cur.append(ch)
            esc = False
        elif ch == "\\":
            esc = True
        elif ch == ":":
            fields.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    fields.append("".join(cur))
    if len(fields) < 6:
        return None
    return {"part": fields[2], "vendor": norm_name(fields[3]),
            "product": norm_name(fields[4]), "version": fields[5]}


def _tokens(v):
    return [int(t) if t.isdigit() else t for t in re.findall(r"\d+|[a-z]+", v.lower())]


def compare_versions(a, b):
    """-1/0/1, or None when either side is not comparable."""
    if not a or not b or a in ("*", "-") or b in ("*", "-"):
        return None
    ta, tb = _tokens(a), _tokens(b)
    if not ta or not tb:
        return None
    for x, y in zip(ta, tb):
        if type(x) is not type(y):
            # '1.0' vs '1.0rc1' style: a number outranks a pre-release tag
            return 1 if isinstance(x, int) else -1
        if x != y:
            return -1 if x < y else 1
    if len(ta) == len(tb):
        return 0
    longer, sign = (ta, 1) if len(ta) > len(tb) else (tb, -1)
    nxt = longer[min(len(ta), len(tb))]
    # 1.0.1 > 1.0 ; 1.0rc1 < 1.0
    return sign if isinstance(nxt, int) else -sign


def version_in_range(version, cm, cpe_version):
    """True/False when decidable, None when not."""
    bounds = [("version_start_including", lambda c: c >= 0),
              ("version_start_excluding", lambda c: c > 0),
              ("version_end_including", lambda c: c <= 0),
              ("version_end_excluding", lambda c: c < 0)]
    has_bounds = any(cm.get(k) for k, _ in bounds)
    if not has_bounds:
        if cpe_version in ("*", ""):
            return None  # "all versions" with no bound: vendor-level claim only
        if cpe_version == "-":
            return None
        c = compare_versions(version, cpe_version)
        return None if c is None else c == 0
    for key, ok in bounds:
        b = cm.get(key)
        if not b:
            continue
        c = compare_versions(version, b)
        if c is None:
            return None
        if not ok(c):
            return False
    return True


def _asset_identity(asset):
    cpe = parse_cpe(asset.get("cpe"))
    vendor = cpe["vendor"] if cpe else norm_name(asset.get("vendor"))
    product = cpe["product"] if cpe else norm_name(asset.get("product"))
    version = asset.get("version") or (cpe["version"] if cpe and cpe["version"] not in ("*", "-") else None)
    return vendor, product, version, bool(cpe)


def match_asset(asset, rec):
    """Best match level for one asset/CVE pair, or None."""
    vendor, product, version, has_cpe = _asset_identity(asset)
    if not vendor or not product:
        return None
    best = None
    nvd = rec.get("nvd") or {}
    for cm in nvd.get("cpe_matches") or []:
        if not cm.get("vulnerable"):
            continue
        c = parse_cpe(cm.get("criteria"))
        if not c or c["vendor"] != vendor or c["product"] != product:
            continue
        inside = version_in_range(version, cm, c["version"]) if version else None
        if inside is False:
            continue
        lvl = ("exact_cpe" if has_cpe else "vendor_product_version") if inside else "vendor_product"
        if best is None or _RANK[lvl] < _RANK[best]:
            best = lvl
    if best is None and not nvd.get("cpe_matches"):
        kev = rec.get("kev") or {}
        if norm_name(kev.get("vendor_project")) == vendor and norm_name(kev.get("product")) == product:
            best = "vendor_product"
    return best


def correlate(inventory, cve_records):
    """Returns a list of {asset_id, cve_id, match_level} sorted stably."""
    out = []
    for asset in inventory.get("assets", []):
        for cve, rec in cve_records.items():
            lvl = match_asset(asset, rec)
            if lvl:
                out.append({"asset_id": asset.get("id"), "cve_id": cve, "match_level": lvl})
    out.sort(key=lambda m: (m["asset_id"] or "", m["cve_id"]))
    return out
