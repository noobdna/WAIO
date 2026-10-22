"""security/zkeys/zkeys_lib.py -- "Z" key-lifecycle server and party
logic, TEST ENVIRONMENT ONLY (stdlib only, no I/O, no network).

============================================================
WHAT Z IS AND IS NOT TRUSTED WITH
============================================================
Z authenticates parties (A, B, ...) and issues short-lived session
TICKETS binding two parties' Diffie-Hellman public values. Z never sees
a DH private exponent, so Z cannot derive the A<->B session key and
cannot read their traffic (end-to-end requirement, Phase 4 item 5).

Z IS trusted for public-key authenticity: a malicious Z could hand A a
public value of its own (MITM). Mitigation available here:
session_fingerprint() -- A and B compare it out of band (SAS); a
mismatch exposes the substitution. Production should use a vetted
protocol (Noise/X3DH/TLS 1.3 with X25519 and an AEAD) -- see
ARCHITECTURE.md Phase 107. This module exists to make the lifecycle
(issue, expire, rotate, revoke, re-key, replay refusal) testable.

Primitives (all stdlib):
  - randomness: secrets (CSPRNG). No key is ever produced by an AI.
  - key agreement: finite-field DH, RFC 3526 2048-bit MODP group 14,
    256-bit private exponents, peer values checked to be in the
    prime-order subgroup (1 < y < p-1, y^q == 1 mod p).
  - KDF: HKDF-SHA256 (RFC 5869).
  - authentication: HMAC-SHA256 with per-party enrollment keys.
  - TEST-ONLY channel cipher: HMAC-SHA256 in counter mode + encrypt-
    then-MAC. Not a standard AEAD; never use it outside tests.
"""

import hashlib
import hmac
import json
import secrets

P_HEX = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"
    "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB"
    "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
    "3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF"
)
P = int(P_HEX, 16)
Q = (P - 1) // 2
G = 2

TS_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
DEFAULT_TICKET_TTL = 300
MAX_TICKET_TTL = 3600
MAX_CLOCK_SKEW = 60
REQUEST_FRESHNESS = 120


class ZError(Exception):
    """Refusal with a stable code (code attribute)."""

    def __init__(self, code, detail=""):
        super().__init__("%s: %s" % (code, detail))
        self.code = code


# ------------------------------------------------------------------
# primitives
# ------------------------------------------------------------------

def _canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def mac(key, obj):
    return hmac.new(key, _canon(obj), hashlib.sha256).hexdigest()


def mac_ok(key, obj, tag):
    return isinstance(tag, str) and hmac.compare_digest(mac(key, obj), tag)


def hkdf(ikm, salt, info, length=32):
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    out, block, i = b"", b"", 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([i]), hashlib.sha256).digest()
        out += block
        i += 1
    return out[:length]


def dh_keypair():
    priv = secrets.randbits(256) | (1 << 255)
    return priv, pow(G, priv, P)


def valid_public(y):
    return isinstance(y, int) and 1 < y < P - 1 and pow(y, Q, P) == 1


def dh_shared(priv, peer_pub):
    if not valid_public(peer_pub):
        raise ZError("INVALID_PUBLIC_KEY", "peer value outside the prime-order subgroup")
    return pow(peer_pub, priv, P).to_bytes(256, "big")


def is_probable_prime(n, rounds=40):
    if n < 2:
        return False
    for sp in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29):
        if n % sp == 0:
            return n == sp
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def fingerprint(pub):
    return hashlib.sha256(pub.to_bytes(256, "big")).hexdigest()[:32]


# ------------------------------------------------------------------
# Z server (state is a plain dict so a CLI could persist it)
# ------------------------------------------------------------------

class ZServer:
    def __init__(self, state=None):
        self.s = state or {"parties": {}, "tickets": {}, "revoked_tickets": [],
                           "seen_nonces": {}, "epoch": 0}

    # enrollment: Z generates the per-party MAC key with the CSPRNG and
    # hands it to the party out of band (once). Z keeps it (it must, to
    # authenticate the party); it is NOT a content key.
    def enroll(self, party_id, now):
        if party_id in self.s["parties"] and self.s["parties"][party_id]["status"] == "active":
            raise ZError("ALREADY_ENROLLED", party_id)
        key = secrets.token_bytes(32)
        self.s["parties"][party_id] = {"key_id": "%s-k%d" % (party_id, self._next_gen(party_id)),
                                       "mac_key": key.hex(), "status": "active", "dh_pub": None,
                                       "dh_epoch": 0, "enrolled_at": now}
        return {"party_id": party_id, "key_id": self.s["parties"][party_id]["key_id"], "mac_key": key}

    def _next_gen(self, party_id):
        old = self.s["parties"].get(party_id)
        return int(old["key_id"].rsplit("-k", 1)[1]) + 1 if old else 1

    def rotate_enrollment(self, party_id, now):
        """New enrollment key; the old key stops authenticating at once."""
        self._party(party_id)
        self.s["parties"][party_id]["status"] = "rotated"
        return self.enroll(party_id, now)

    def revoke_party(self, party_id):
        self._party(party_id)
        self.s["parties"][party_id]["status"] = "revoked"
        for tid, t in self.s["tickets"].items():
            if party_id in (t["initiator"], t["responder"]) and tid not in self.s["revoked_tickets"]:
                self.s["revoked_tickets"].append(tid)

    def revoke_ticket(self, ticket_id):
        if ticket_id not in self.s["tickets"]:
            raise ZError("UNKNOWN_TICKET", ticket_id)
        if ticket_id not in self.s["revoked_tickets"]:
            self.s["revoked_tickets"].append(ticket_id)

    def _party(self, party_id):
        p = self.s["parties"].get(party_id)
        if p is None:
            raise ZError("UNKNOWN_PARTY", party_id)
        return p

    def _authenticate(self, req, now_epoch):
        body = {k: v for k, v in req.items() if k != "mac"}
        p = self._party(req.get("party_id"))
        if p["status"] != "active":
            raise ZError("PARTY_NOT_ACTIVE", "%s is %s" % (req["party_id"], p["status"]))
        if req.get("key_id") != p["key_id"] or not mac_ok(bytes.fromhex(p["mac_key"]), body, req.get("mac")):
            raise ZError("UNAUTHENTICATED", "request MAC invalid for %s" % req["party_id"])
        ts = req.get("ts_epoch")
        if not isinstance(ts, int) or abs(now_epoch - ts) > REQUEST_FRESHNESS:
            raise ZError("STALE_REQUEST", "request timestamp outside %ds" % REQUEST_FRESHNESS)
        nonce = req.get("nonce")
        if not isinstance(nonce, str) or len(nonce) < 32 or nonce in self.s["seen_nonces"]:
            raise ZError("REPLAY", "request nonce reused or invalid")
        self.s["seen_nonces"][nonce] = ts
        # forget nonces older than the freshness window (they would be stale anyway)
        self.s["seen_nonces"] = {n: t for n, t in self.s["seen_nonces"].items() if now_epoch - t <= 2 * REQUEST_FRESHNESS}
        return p

    def register_public(self, req, now_epoch):
        p = self._authenticate(req, now_epoch)
        if req.get("op") != "register_public" or not valid_public(req.get("dh_pub")):
            raise ZError("INVALID_PUBLIC_KEY", "not a valid subgroup element")
        p["dh_pub"] = req["dh_pub"]
        p["dh_epoch"] += 1
        return {"party_id": req["party_id"], "dh_epoch": p["dh_epoch"], "fingerprint": fingerprint(req["dh_pub"])}

    def issue_ticket(self, req, now_epoch):
        a = self._authenticate(req, now_epoch)
        if req.get("op") != "issue_ticket":
            raise ZError("INVALID_REQUEST", "op")
        b = self._party(req.get("peer_id"))
        if b["status"] != "active":
            raise ZError("PARTY_NOT_ACTIVE", "peer %s is %s" % (req["peer_id"], b["status"]))
        if a["dh_pub"] is None or b["dh_pub"] is None:
            raise ZError("NO_PUBLIC_KEY", "both parties must register a DH public value first")
        ttl = req.get("ttl", DEFAULT_TICKET_TTL)
        if not isinstance(ttl, int) or not 1 <= ttl <= MAX_TICKET_TTL:
            raise ZError("INVALID_TTL", "ttl must be 1-%d s" % MAX_TICKET_TTL)
        self.s["epoch"] += 1
        body = {"ticket_id": "zt-" + secrets.token_hex(12), "initiator": req["party_id"], "responder": req["peer_id"],
                "initiator_pub": a["dh_pub"], "responder_pub": b["dh_pub"],
                "initiator_dh_epoch": a["dh_epoch"], "responder_dh_epoch": b["dh_epoch"],
                "issued_at": now_epoch, "expires_at": now_epoch + ttl, "z_epoch": self.s["epoch"]}
        self.s["tickets"][body["ticket_id"]] = {k: body[k] for k in ("initiator", "responder", "issued_at", "expires_at")}
        return {"body": body,
                "mac_initiator": mac(bytes.fromhex(a["mac_key"]), body),
                "mac_responder": mac(bytes.fromhex(b["mac_key"]), body)}

    def ticket_status(self, ticket_id, now_epoch):
        t = self.s["tickets"].get(ticket_id)
        if t is None:
            return "unknown"
        if ticket_id in self.s["revoked_tickets"]:
            return "revoked"
        if now_epoch >= t["expires_at"]:
            return "expired"
        return "valid"


# ------------------------------------------------------------------
# party side
# ------------------------------------------------------------------

class Party:
    def __init__(self, party_id, enrollment):
        self.id = party_id
        self.key_id = enrollment["key_id"]
        self.mac_key = enrollment["mac_key"]
        self.priv, self.pub = None, None

    def new_dh(self):
        """Fresh DH key pair; the private exponent never leaves this object."""
        self.priv, self.pub = dh_keypair()

    def request(self, op, now_epoch, **fields):
        body = dict(fields, op=op, party_id=self.id, key_id=self.key_id, ts_epoch=now_epoch,
                    nonce=secrets.token_hex(16))
        body["mac"] = mac(self.mac_key, body)
        return body

    def open_session(self, ticket, z_status, now_epoch):
        """Verify a ticket and derive the session. z_status is Z's
        ticket_status() answer (or a callable) -- revocation is checked
        at establishment and again on every received message."""
        body = ticket.get("body", {})
        role = "initiator" if body.get("initiator") == self.id else "responder" if body.get("responder") == self.id else None
        if role is None:
            raise ZError("NOT_A_PARTY", "ticket is not for %s" % self.id)
        if not mac_ok(self.mac_key, body, ticket.get("mac_" + role)):
            raise ZError("UNAUTHENTICATED", "ticket MAC invalid (tampered or wrong Z key)")
        if now_epoch >= body["expires_at"]:
            raise ZError("TICKET_EXPIRED", body["ticket_id"])
        if body["issued_at"] - now_epoch > MAX_CLOCK_SKEW:
            raise ZError("TICKET_NOT_YET_VALID", body["ticket_id"])
        own_pub = body[role + "_pub"]
        if own_pub != self.pub:
            raise ZError("STALE_PUBLIC_KEY", "ticket binds a DH value this party no longer holds")
        peer_pub = body["responder_pub" if role == "initiator" else "initiator_pub"]
        return Session(self.id, role, body, dh_shared(self.priv, peer_pub), z_status)


def session_fingerprint(body):
    """Short authentication string both parties can compare out of band."""
    return hashlib.sha256(_canon({"i": body["initiator_pub"], "r": body["responder_pub"],
                                  "t": body["ticket_id"]})).hexdigest()[:16]


class Session:
    """TEST-ONLY secure channel: per-direction keys, counters, replay
    refusal, expiry and revocation enforced on every message."""

    def __init__(self, party_id, role, body, shared, z_status):
        self.party_id, self.role, self.body = party_id, role, body
        self.ticket_id = body["ticket_id"]
        self.z_status = z_status
        salt = hashlib.sha256(body["ticket_id"].encode()).digest()
        info = ("waio-z-e2e-v1|%s|%s" % (body["initiator"], body["responder"])).encode()
        okm = hkdf(shared, salt, info, 128)
        k = {"i2r_enc": okm[0:32], "i2r_mac": okm[32:64], "r2i_enc": okm[64:96], "r2i_mac": okm[96:128]}
        out_dir, in_dir = ("i2r", "r2i") if role == "initiator" else ("r2i", "i2r")
        self.send_enc, self.send_mac = k[out_dir + "_enc"], k[out_dir + "_mac"]
        self.recv_enc, self.recv_mac = k[in_dir + "_enc"], k[in_dir + "_mac"]
        self.session_key_id = hashlib.sha256(okm).hexdigest()[:16]   # identifies the key, reveals nothing
        self.send_ctr, self.recv_ctr = 0, 0
        self._raw = okm   # kept only so a test can model a leaked key

    def _check_live(self, now_epoch):
        status = self.z_status(self.ticket_id, now_epoch) if callable(self.z_status) else self.z_status
        if status != "valid" or now_epoch >= self.body["expires_at"]:
            raise ZError("SESSION_NOT_VALID", "ticket %s is %s" % (self.ticket_id,
                                                                   status if status != "valid" else "expired"))

    @staticmethod
    def _stream(key, nonce, n):
        out, i = b"", 0
        while len(out) < n:
            out += hmac.new(key, nonce + i.to_bytes(4, "big"), hashlib.sha256).digest()
            i += 1
        return out[:n]

    def seal(self, plaintext, now_epoch):
        self._check_live(now_epoch)
        self.send_ctr += 1
        nonce = self.send_ctr.to_bytes(8, "big")
        ct = bytes(a ^ b for a, b in zip(plaintext, self._stream(self.send_enc, nonce, len(plaintext))))
        tag = hmac.new(self.send_mac, self.ticket_id.encode() + nonce + ct, hashlib.sha256).hexdigest()
        return {"ticket_id": self.ticket_id, "ctr": self.send_ctr, "ct": ct.hex(), "tag": tag}

    def open(self, msg, now_epoch):
        self._check_live(now_epoch)
        if msg.get("ticket_id") != self.ticket_id:
            raise ZError("WRONG_SESSION", "message for another ticket")
        ctr = msg.get("ctr")
        if not isinstance(ctr, int) or ctr <= self.recv_ctr:
            raise ZError("REPLAY", "counter %r not greater than %d" % (ctr, self.recv_ctr))
        nonce = ctr.to_bytes(8, "big")
        ct = bytes.fromhex(msg.get("ct", ""))
        expect = hmac.new(self.recv_mac, self.ticket_id.encode() + nonce + ct, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expect, str(msg.get("tag"))):
            raise ZError("UNAUTHENTICATED", "message tag invalid")
        self.recv_ctr = ctr
        return bytes(a ^ b for a, b in zip(ct, self._stream(self.recv_enc, nonce, len(ct))))
