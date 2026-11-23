"""Keystone Ed25519 (SHA3-512 instead of SHA-512) key generation and signing.

Test and analysis helper only: the controller verifies with
keystone_attestation.ed25519_sha3_verify and never signs. Mirrors
external/keystone/bootrom/ed25519/keypair.c and sign.c.
"""
import hashlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from keystone_attestation import _B, _L, _compress, _scalar_mult  # noqa: E402


def keypair(seed: bytes):
    """(public 32 B, private 64 B) from a 32 B seed, as ed25519_create_keypair."""
    assert len(seed) == 32
    sk = bytearray(hashlib.sha3_512(seed).digest())
    sk[0] &= 248
    sk[31] &= 63
    sk[31] |= 64
    a = int.from_bytes(sk[:32], "little")
    return _compress(_scalar_mult(a, _B)), bytes(sk)


def sign(message: bytes, public_key: bytes, private_key: bytes) -> bytes:
    """Signature as ed25519_sign (deterministic)."""
    r = int.from_bytes(hashlib.sha3_512(private_key[32:] + message).digest(), "little") % _L
    big_r = _compress(_scalar_mult(r, _B))
    h = int.from_bytes(hashlib.sha3_512(big_r + public_key + message).digest(), "little") % _L
    a = int.from_bytes(private_key[:32], "little")
    return big_r + ((r + h * a) % _L).to_bytes(32, "little")
