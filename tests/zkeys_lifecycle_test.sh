#!/bin/bash
set -uo pipefail

# tests/zkeys_lifecycle_test.sh -- "Z" key lifecycle (security/zkeys/),
# test environment only: in-memory state, synthetic parties, no real key
# is generated for, written to, or rotated in any deployment.
#
#   Z1  primitives: RFC 3526 group is a safe prime, DH agrees, invalid
#       public values refused, HKDF RFC 5869 test vector
#   Z2  normal path: enroll, register, ticket, E2E channel both ways
#   Z3  Z cannot read A<->B traffic (holds no DH private value)
#   Z4  expiry: expired ticket refused at open and mid-session
#   Z5  revocation: ticket / party revocation ends live sessions
#   Z6  replay: request nonce, message counter
#   Z7  rotation / re-key: old enrollment key dead, new session key differs
#   Z8  leak simulations: leaked session key after revocation, leaked old
#       enrollment key, tampered ticket, MITM key substitution (SAS)
#   Z9  static: CSPRNG only; no file/network I/O in the library

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"
export PYTHONDONTWRITEBYTECODE=1

python3 - <<'EOF'
import ast, hashlib, os, sys
sys.path.insert(0, "security/zkeys")
import zkeys_lib as z

P = F = 0
fails = []
def check(label, cond):
    global P, F
    if cond:
        P += 1; print("  PASS: " + label)
    else:
        F += 1; fails.append(label); print("  FAIL: " + label)

def refused(label, code, fn):
    try:
        fn()
    except z.ZError as e:
        check("%s -> %s" % (label, code), e.code == code)
        return
    check("%s -> %s (no refusal raised)" % (label, code), False)

T = 1_800_000_000
print("[Z1] primitives")
check("Z1 p is a 2048-bit safe prime", z.P.bit_length() == 2048 and z.is_probable_prime(z.P) and z.is_probable_prime(z.Q))
check("Z1 g generates the prime-order subgroup", pow(z.G, z.Q, z.P) == 1)
a, A = z.dh_keypair(); b, B = z.dh_keypair()
check("Z1 DH agreement", z.dh_shared(a, B) == z.dh_shared(b, A))
for bad in (0, 1, z.P - 1, z.P, z.P + 5):
    check("Z1 invalid public value %s refused" % ("p-1" if bad == z.P - 1 else bad if bad < 10 else "p+k"), not z.valid_public(bad))
non_subgroup = next(y for y in range(3, 200) if pow(y, z.Q, z.P) != 1)
check("Z1 element outside the subgroup refused", not z.valid_public(non_subgroup))
# RFC 5869 test case 1
okm = z.hkdf(bytes.fromhex("0b" * 22), bytes.fromhex("000102030405060708090a0b0c"), bytes.fromhex("f0f1f2f3f4f5f6f7f8f9"), 42)
check("Z1 HKDF matches RFC 5869 test vector 1", okm.hex() == "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")
check("Z1 private exponents are fresh per call", z.dh_keypair()[0] != z.dh_keypair()[0])

print("[Z2] normal path")
srv = z.ZServer()
alice = z.Party("alice", srv.enroll("alice", T)); bob = z.Party("bob", srv.enroll("bob", T))
alice.new_dh(); bob.new_dh()
srv.register_public(alice.request("register_public", T, dh_pub=alice.pub), T)
srv.register_public(bob.request("register_public", T, dh_pub=bob.pub), T)
tk = srv.issue_ticket(alice.request("issue_ticket", T, peer_id="bob", ttl=300), T)
status = srv.ticket_status
sa = alice.open_session(tk, status, T + 1); sb = bob.open_session(tk, status, T + 1)
check("Z2 both sides derive the same session key", sa._raw == sb._raw)
m = sa.seal(b"contain test-worker-echo now", T + 2)
check("Z2 A->B message decrypts", sb.open(m, T + 2) == b"contain test-worker-echo now")
check("Z2 ciphertext does not contain plaintext", b"contain" not in bytes.fromhex(m["ct"]))
check("Z2 B->A message decrypts", sa.open(sb.seal(b"ack", T + 3), T + 3) == b"ack")
check("Z2 ticket TTL is short (300 s)", tk["body"]["expires_at"] - tk["body"]["issued_at"] == 300)
refused("Z2 TTL above the cap", "INVALID_TTL", lambda: srv.issue_ticket(alice.request("issue_ticket", T, peer_id="bob", ttl=86400), T))

print("[Z3] Z cannot read A<->B traffic")
z_state = repr(srv.s)
check("Z3 Z's state holds no DH private value", str(alice.priv) not in z_state and str(bob.priv) not in z_state)
check("Z3 Z's state holds no session key material", sa._raw.hex() not in z_state)
# Z's best effort with everything it holds: every enrollment key and both public values
guesses = [z.hkdf(k, hashlib.sha256(tk["body"]["ticket_id"].encode()).digest(), b"waio-z-e2e-v1|alice|bob", 128)
           for k in [bytes.fromhex(p["mac_key"]) for p in srv.s["parties"].values()] +
                    [tk["body"]["initiator_pub"].to_bytes(256, "big"), tk["body"]["responder_pub"].to_bytes(256, "big")]]
check("Z3 nothing Z holds derives the session key", sa._raw not in guesses)
try:
    eve = z.Session("z", "responder", tk["body"], (tk["body"]["initiator_pub"] * tk["body"]["responder_pub"] % z.P).to_bytes(256, "big"), status)
    eve.open(sa.seal(b"secret", T + 4), T + 4); ok = False
except z.ZError as e:
    ok = e.code == "UNAUTHENTICATED"
check("Z3 a Z-side session built from public data cannot open A's messages", ok)

print("[Z4] expiry")
refused("Z4 open after expiry", "TICKET_EXPIRED", lambda: bob.open_session(tk, status, T + 300))
refused("Z4 send on a live session after expiry", "SESSION_NOT_VALID", lambda: sa.seal(b"late", T + 301))
refused("Z4 stale request (outside 120 s)", "STALE_REQUEST", lambda: srv.issue_ticket(alice.request("issue_ticket", T - 500, peer_id="bob"), T))

print("[Z5] revocation")
tk2 = srv.issue_ticket(alice.request("issue_ticket", T + 10, peer_id="bob"), T + 10)
s2a = alice.open_session(tk2, status, T + 11); s2b = bob.open_session(tk2, status, T + 11)
msg = s2a.seal(b"before revoke", T + 12)
srv.revoke_ticket(tk2["body"]["ticket_id"])
refused("Z5 receiving on a revoked session", "SESSION_NOT_VALID", lambda: s2b.open(msg, T + 13))
refused("Z5 opening a revoked ticket", "SESSION_NOT_VALID", lambda: bob.open_session(tk2, status, T + 13).seal(b"x", T + 13))
carol = z.Party("carol", srv.enroll("carol", T)); carol.new_dh()
srv.register_public(carol.request("register_public", T + 20, dh_pub=carol.pub), T + 20)
tk3 = srv.issue_ticket(carol.request("issue_ticket", T + 20, peer_id="bob"), T + 20)
s3 = carol.open_session(tk3, status, T + 21)
srv.revoke_party("carol")
refused("Z5 revoked party's live session ends", "SESSION_NOT_VALID", lambda: s3.seal(b"x", T + 22))
refused("Z5 revoked party cannot request tickets", "PARTY_NOT_ACTIVE", lambda: srv.issue_ticket(carol.request("issue_ticket", T + 22, peer_id="bob"), T + 22))
refused("Z5 nobody can open a new session with a revoked party", "PARTY_NOT_ACTIVE", lambda: srv.issue_ticket(bob.request("issue_ticket", T + 22, peer_id="carol"), T + 22))

print("[Z6] replay")
req = alice.request("issue_ticket", T + 30, peer_id="bob")
srv.issue_ticket(req, T + 30)
refused("Z6 identical request replayed", "REPLAY", lambda: srv.issue_ticket(req, T + 31))
tk4 = srv.issue_ticket(alice.request("issue_ticket", T + 40, peer_id="bob"), T + 40)
s4a, s4b = alice.open_session(tk4, status, T + 41), bob.open_session(tk4, status, T + 41)
m1 = s4a.seal(b"one", T + 42); m2 = s4a.seal(b"two", T + 42)
s4b.open(m1, T + 42); s4b.open(m2, T + 42)
refused("Z6 replayed message", "REPLAY", lambda: s4b.open(m1, T + 43))
refused("Z6 forged message with a fresh counter", "UNAUTHENTICATED", lambda: s4b.open(dict(m2, ctr=99), T + 43))
refused("Z6 message from another session", "WRONG_SESSION", lambda: sb.open(m1, T + 43))

print("[Z7] rotation and re-key")
old = alice.mac_key
alice_new = srv.rotate_enrollment("alice", T + 50)
stale_alice = z.Party("alice", {"key_id": "alice-k1", "mac_key": old}); stale_alice.pub = alice.pub
refused("Z7 old enrollment key no longer authenticates", "UNAUTHENTICATED", lambda: srv.issue_ticket(stale_alice.request("issue_ticket", T + 51, peer_id="bob"), T + 51))
alice = z.Party("alice", alice_new); alice.new_dh()
srv.register_public(alice.request("register_public", T + 52, dh_pub=alice.pub), T + 52)
tk5 = srv.issue_ticket(alice.request("issue_ticket", T + 53, peer_id="bob"), T + 53)
s5 = alice.open_session(tk5, status, T + 54)
check("Z7 new key id after rotation", alice.key_id == "alice-k2")
check("Z7 re-keyed session key differs from earlier sessions", s5._raw not in (sa._raw, s4a._raw))
refused("Z7 a ticket issued under the rotated-out enrollment key is refused", "UNAUTHENTICATED", lambda: alice.open_session(tk4, status, T + 54))

print("[Z8] leak simulations")
import copy
thief = copy.copy(s4b); thief.recv_ctr = 0          # attacker holding bob's leaked session keys
check("Z8 (control) leaked keys do decrypt while the ticket is live", thief.open(m1, T + 59) == b"one")
srv.revoke_ticket(tk4["body"]["ticket_id"])
thief.recv_ctr = 0
refused("Z8 leaked session key is useless once the ticket is revoked", "SESSION_NOT_VALID", lambda: thief.open(m1, T + 60))
mal = srv.issue_ticket(alice.request("issue_ticket", T + 61, peer_id="bob"), T + 61)
mal["body"]["responder_pub"] = z.dh_keypair()[1]
refused("Z8 ticket with a substituted public key (MAC check)", "UNAUTHENTICATED", lambda: alice.open_session(mal, status, T + 62))
# malicious Z: signs a ticket with its own DH value in place of bob's -> MACs valid, but SAS differs
mitm_priv, mitm_pub = z.dh_keypair()
honest = srv.issue_ticket(alice.request("issue_ticket", T + 63, peer_id="bob"), T + 63)
evil_body = dict(honest["body"], responder_pub=mitm_pub)
evil = {"body": evil_body, "mac_initiator": z.mac(alice.mac_key, evil_body), "mac_responder": z.mac(bob.mac_key, evil_body)}
alice.open_session(evil, status, T + 64)
check("Z8 malicious-Z key substitution is visible via the out-of-band SAS", z.session_fingerprint(evil_body) != z.session_fingerprint(honest["body"]))
refused("Z8 the honest responder cannot open the substituted ticket", "STALE_PUBLIC_KEY", lambda: bob.open_session(evil, status, T + 64))

print("[Z9] static properties")
src = open("security/zkeys/zkeys_lib.py").read()
tree = ast.parse(src)
mods = {a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
check("Z9 imports only hashlib/hmac/json/secrets", mods <= {"hashlib", "hmac", "json", "secrets"})
check("Z9 no use of the non-cryptographic random module", "import random" not in src)
check("Z9 no open()/socket/subprocess in the library", not any(isinstance(n, ast.Call) and getattr(n.func, "id", "") == "open" for n in ast.walk(tree)))

print()
print("=== Summary: %d passed, %d failed ===" % (P, F))
for f in fails:
    print("  - " + f)
sys.exit(1 if F else 0)
EOF
