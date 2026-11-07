"""Provenance envelope: every stored record says where it came from
(source, source_url, identifier), when WAIO fetched it (fetched_at),
when the source itself last updated it (source_updated_at -- None when
the source does not say; never guessed), a hash of the exact bytes
received, and whether it is stale."""

import hashlib
import re
from datetime import datetime, timezone

from . import COLLECTOR_VERSION

SOURCES = ("kev", "nvd", "epss", "synthetic")
REQUIRED_FIELDS = (
    "source", "source_url", "identifier", "fetched_at", "source_updated_at",
    "content_sha256", "collector_version", "http_status", "stale",
)
_TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


def utc_now():
    return datetime.now(timezone.utc).replace(microsecond=0)


def iso(dt):
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_ts(value):
    """Lenient parse of the timestamp shapes KEV/NVD/EPSS use
    ('2026-11-05', '2026-11-05T14:12:00.123', '...Z'). Returns an aware
    UTC datetime or None -- never raises, never invents a value."""
    if not isinstance(value, str) or not value.strip():
        return None
    s = value.strip().rstrip("Z")
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def normalize_ts(value):
    dt = parse_ts(value)
    return iso(dt) if dt else None


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def make(source, source_url, identifier, fetched_at, source_updated_at,
         content_sha256, http_status=200, stale=False):
    if source not in SOURCES:
        raise ValueError(f"unknown provenance source: {source!r}")
    if not _TS_RE.match(fetched_at or ""):
        raise ValueError(f"fetched_at must be UTC ISO-8601 (got {fetched_at!r})")
    return {
        "source": source,
        "source_url": source_url,
        "identifier": identifier,
        "fetched_at": fetched_at,
        "source_updated_at": normalize_ts(source_updated_at),
        "content_sha256": content_sha256,
        "collector_version": COLLECTOR_VERSION,
        "http_status": http_status,
        "stale": bool(stale),
    }


def validate(env):
    """Returns a list of problems (empty == valid)."""
    if not isinstance(env, dict):
        return ["provenance is not an object"]
    problems = [f"missing {k}" for k in REQUIRED_FIELDS if k not in env]
    if env.get("source") not in SOURCES:
        problems.append("bad source")
    if not _TS_RE.match(str(env.get("fetched_at", ""))):
        problems.append("bad fetched_at")
    if not re.fullmatch(r"[0-9a-f]{64}", str(env.get("content_sha256", ""))):
        problems.append("bad content_sha256")
    return problems
