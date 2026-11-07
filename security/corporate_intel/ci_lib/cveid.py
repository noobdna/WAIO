"""CVE identifier normalization -- the one place that decides what a
valid CVE id is. Used for dedupe keys AND as the only gate before a CVE
id may appear in a fetch URL (ci_fetch.sh re-validates independently)."""

import re

_CVE_RE = re.compile(r"^CVE-(\d{4})-(\d{4,7})$")


def normalize(value):
    """'  cve-2026-10001 ' -> 'CVE-2026-10001'; anything else -> None.
    Unicode dashes are folded; leading zeros in the sequence part are
    kept (they are significant only in the 4-digit minimum form)."""
    if not isinstance(value, str):
        return None
    s = value.strip().upper()
    for dash in ("‐", "‑", "‒", "–", "—", "−"):
        s = s.replace(dash, "-")
    m = _CVE_RE.match(s)
    if not m:
        return None
    return f"CVE-{m.group(1)}-{m.group(2)}"


def is_valid(value):
    return isinstance(value, str) and _CVE_RE.match(value) is not None
