"""security/detector_signing.py -- shared detector-side signing primitives.

One implementation of the envelope every WAIO detector that signs its output
uses, and that WAIO Adaptive Defense verifies (security/wad/wad_adapters.py):

  "signing": {"scan_id": <128-bit random hex>, "seq": <int >= 0>, "signed_at": <UTC>},
  "wad_sig": {"alg": "hmac-sha256", "key_id": <detector>, "mac": <hex>}

mac = HMAC-SHA256(key, canonical JSON of the object without "wad_sig"); the
signing block is inside the mac. Canonical = sorted keys, (",", ":")
separators, ensure_ascii=True, UTF-8.

Used by shadow_ai_lib (one finding per emitted line, key_id "shadow_ai") and
attack_graph.sh (the whole graph document, key_id "attack_graph").

What a valid mac proves: the object was produced by a holder of that key
file and not changed since. HMAC is symmetric: every verifier holds the key
and could sign, and any process able to read the key file can sign. Key
storage is the operator's decision (security/shadow_ai/SIGNING.md).
Standard library only. Nothing here reads a key unless asked to, and no key
is ever created here.
"""

import datetime
import hashlib
import hmac
import json
import os
import re
import secrets
import stat

SIG_FIELD = "wad_sig"
SIGNING_FIELD = "signing"
SIG_ALG = "hmac-sha256"
MIN_KEY_BYTES = 32
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_SCAN_ID_HEX = re.compile(r"^[0-9a-f]{32}$")
_TS_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


class SigningKeyError(Exception):
    pass


def load_signing_key(path):
    """Key bytes from `path`. Refused (SigningKeyError) unless it is a
    regular file (not a symlink), owned by this user, not readable or
    writable by group/others, and at least MIN_KEY_BYTES long."""
    if not path:
        raise SigningKeyError("no key file configured")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as e:
        raise SigningKeyError(f"key unreadable or a symlink ({e.strerror})")
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise SigningKeyError("key is not a regular file")
        if st.st_uid != os.getuid():
            raise SigningKeyError("key is not owned by this user")
        if st.st_mode & 0o077:
            raise SigningKeyError("key is accessible to group/others (needs 0600 or stricter)")
        key = os.read(fd, 4096)
    finally:
        os.close(fd)
    if len(key) < MIN_KEY_BYTES:
        raise SigningKeyError(f"key shorter than {MIN_KEY_BYTES} bytes")
    return key


def canonical(obj):
    """The exact bytes the mac covers."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def new_scan_id():
    return secrets.token_hex(16)


def sign(obj, key, key_id, scan_id, seq, signed_at):
    """-> a new dict: obj + signing block + wad_sig. Never mutates obj."""
    body = {k: v for k, v in obj.items() if k != SIG_FIELD}
    body[SIGNING_FIELD] = {"scan_id": scan_id, "seq": seq, "signed_at": signed_at}
    mac = hmac.new(key, canonical(body), hashlib.sha256).hexdigest()
    return dict(body, **{SIG_FIELD: {"alg": SIG_ALG, "key_id": key_id, "mac": mac}})


def parse_utc(text):
    if not isinstance(text, str):
        return None
    try:
        return datetime.datetime.strptime(text, _TS_FORMAT).replace(tzinfo=datetime.timezone.utc)
    except ValueError:
        return None


def verify(obj, key, key_id, now, max_age_s=86400, max_skew_s=300, seen=None):
    """-> (status, reason): verified | missing | invalid | stale | replay.
    The mac is checked before any field it covers is trusted. `seen`
    (optional set) records (scan_id, seq) of verified objects; a second one
    with the same pair is a replay."""
    if not isinstance(obj, dict) or SIG_FIELD not in obj:
        return "missing", "no wad_sig"
    sig = obj[SIG_FIELD]
    if not (isinstance(sig, dict) and sig.get("alg") == SIG_ALG and sig.get("key_id") == key_id
            and isinstance(sig.get("mac"), str) and _HEX64.match(sig["mac"])):
        return "invalid", "malformed envelope"
    body = {k: v for k, v in obj.items() if k != SIG_FIELD}
    expected = hmac.new(key, canonical(body), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, sig["mac"]):
        return "invalid", "mac mismatch"
    meta = body.get(SIGNING_FIELD)
    if not (isinstance(meta, dict) and isinstance(meta.get("scan_id"), str) and _SCAN_ID_HEX.match(meta["scan_id"])
            and isinstance(meta.get("seq"), int) and not isinstance(meta.get("seq"), bool) and meta["seq"] >= 0):
        return "invalid", "missing or malformed signing block"
    signed = parse_utc(meta.get("signed_at"))
    if signed is None:
        return "invalid", "bad signed_at"
    age = (now - signed).total_seconds()
    if age > max_age_s:
        return "stale", f"signed {int(age)}s ago (max {max_age_s}s)"
    if age < -max_skew_s:
        return "stale", "signed_at in the future"
    if seen is not None:
        ident = (meta["scan_id"], meta["seq"])
        if ident in seen:
            return "replay", "scan_id/seq already seen"
        seen.add(ident)
    return "verified", "ok"
