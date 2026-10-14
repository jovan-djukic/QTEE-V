"""
Keystone attestation report verification (controller side).

Python port of the Keystone SDK verifier (sdk/src/verifier/Report.cpp,
examples/attestation/host/verifier.cpp), so the controller can verify the
raw report that relay.c's get_attestation_report() produces inside the
enclave via the attest_enclave() runtime syscall.

Keystone's Ed25519 is NOT RFC 8032 Ed25519: both the SM (sm/src/ed25519)
and the SDK verifier (sdk/src/verifier/ed25519) replace SHA-512 with
SHA3-512 inside the signature scheme. Standard Ed25519 libraries
(cryptography, PyNaCl, wolfSSL) will therefore reject every genuine
report, so the verify equation is implemented here directly.

Report layout (sdk/include/verifier/Report.hpp, little-endian, no padding):

    enclave.hash        64   SHA3-512 measurement of loader+runtime+eapp
    enclave.data_len     8   uint64
    enclave.data      1024   caller-supplied data (relay.c: "<relay_id>:<nonce_hex>")
    enclave.signature   64   Ed25519-SHA3 by SM key over hash||data_len||data[:data_len]
    sm.hash             64   SHA3-512 of the Security Monitor image
    sm.public_key       32
    sm.signature        64   Ed25519-SHA3 by device root key over sm.hash||sm.public_key
    dev_public_key      32   (informational -- never trusted, the pinned key is used)
"""

import hashlib
import hmac
import struct
from dataclasses import dataclass

MDSIZE = 64
PUBLIC_KEY_SIZE = 32
SIGNATURE_SIZE = 64
ATTEST_DATA_MAXLEN = 1024  # sm/src/enclave.h

_ENCLAVE_FMT = f"<{MDSIZE}sQ{ATTEST_DATA_MAXLEN}s{SIGNATURE_SIZE}s"
_SM_FMT = f"<{MDSIZE}s{PUBLIC_KEY_SIZE}s{SIGNATURE_SIZE}s"
REPORT_SIZE = (struct.calcsize(_ENCLAVE_FMT) + struct.calcsize(_SM_FMT)
               + PUBLIC_KEY_SIZE)  # 1352

# Keystone's published TEST device root public key
# (sdk/include/verifier/test_dev_key.h). The matching secret key is public
# too, so a report chained to this key proves nothing on real hardware --
# it is only meaningful for the QEMU demonstration.
KEYSTONE_TEST_DEV_PUBLIC_KEY = bytes.fromhex(
    "0faad4ff01178583baa588966f7c1ff32564dd17d7dc2b46cb50a84a69270b4c")


class AttestationError(Exception):
    pass


# ==================== Ed25519 with SHA3-512 (verify only) ====================

_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)
_BY = 4 * pow(5, _P - 2, _P) % _P


def _point_add(p, q):
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = (y1 - x1) * (y2 - x2) % _P
    b = (y1 + x1) * (y2 + x2) % _P
    c = 2 * t1 * t2 * _D % _P
    d = 2 * z1 * z2 % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _scalar_mult(s, p):
    q = (0, 1, 1, 0)
    while s:
        if s & 1:
            q = _point_add(q, p)
        p = _point_add(p, p)
        s >>= 1
    return q


def _recover_x(y, sign):
    if y >= _P:
        return None
    x2 = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P)
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P:
        return None
    if (x & 1) != sign:
        x = _P - x
    return x


def _decompress(b):
    y = int.from_bytes(b, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % _P)


def _compress(p):
    x, y, z, _ = p
    zi = pow(z, _P - 2, _P)
    x, y = x * zi % _P, y * zi % _P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


_B = (_recover_x(_BY, 0), _BY, 1, _recover_x(_BY, 0) * _BY % _P)


def ed25519_sha3_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Keystone ed25519_verify(): R == s*B - H(R||A||M)*A, H = SHA3-512."""
    if len(public_key) != 32 or len(signature) != 64:
        return False
    if signature[63] & 224:
        return False
    a = _decompress(public_key)
    if a is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _L:
        return False
    h = int.from_bytes(
        hashlib.sha3_512(signature[:32] + public_key + message).digest(),
        "little") % _L
    neg_a = (_P - a[0], a[1], a[2], _P - a[3])
    r = _point_add(_scalar_mult(s, _B), _scalar_mult(h, neg_a))
    return hmac.compare_digest(_compress(r), signature[:32])


# ==================== Report parsing & verification ====================

@dataclass
class KeystoneReport:
    enclave_hash: bytes
    data: bytes
    enclave_signature: bytes
    sm_hash: bytes
    sm_public_key: bytes
    sm_signature: bytes
    dev_public_key: bytes
    _data_len_raw: bytes

    @classmethod
    def from_bytes(cls, raw: bytes) -> "KeystoneReport":
        # relay.c base64-encodes a fixed ATTESTATION_REPORT_SIZE (2048)
        # buffer; everything past the struct is unused.
        if len(raw) < REPORT_SIZE:
            raise AttestationError(f"report too short ({len(raw)} < {REPORT_SIZE})")
        e_len = struct.calcsize(_ENCLAVE_FMT)
        s_len = struct.calcsize(_SM_FMT)
        e_hash, data_len, data, e_sig = struct.unpack_from(_ENCLAVE_FMT, raw, 0)
        sm_hash, sm_pk, sm_sig = struct.unpack_from(_SM_FMT, raw, e_len)
        dev_pk = raw[e_len + s_len:e_len + s_len + PUBLIC_KEY_SIZE]
        if data_len > ATTEST_DATA_MAXLEN:
            raise AttestationError(f"invalid data_len {data_len}")
        return cls(e_hash, data[:data_len], e_sig, sm_hash, sm_pk, sm_sig,
                   dev_pk, raw[MDSIZE:MDSIZE + 8])


def verify_report(raw: bytes, *, dev_public_key: bytes,
                  expected_enclave_hash: bytes, expected_sm_hash: bytes = None,
                  expected_data: bytes) -> KeystoneReport:
    """Mirror of Report::verify() + Verifier::verify_data(). Raises on failure.

    The chain is: pinned device key -> signs (sm.hash, sm.public_key) ->
    SM key signs (enclave.hash, data). Only after both signatures hold are
    the hashes and data meaningful.
    """
    r = KeystoneReport.from_bytes(raw)

    if not ed25519_sha3_verify(dev_public_key, r.sm_hash + r.sm_public_key,
                               r.sm_signature):
        raise AttestationError("SM signature invalid (not endorsed by pinned device key)")

    signed = r.enclave_hash + r._data_len_raw + r.data
    if not ed25519_sha3_verify(r.sm_public_key, signed, r.enclave_signature):
        raise AttestationError("enclave signature invalid")

    if expected_sm_hash is not None and not hmac.compare_digest(r.sm_hash, expected_sm_hash):
        raise AttestationError(f"SM measurement mismatch: {r.sm_hash.hex()}")

    if not hmac.compare_digest(r.enclave_hash, expected_enclave_hash):
        raise AttestationError(f"enclave measurement mismatch: {r.enclave_hash.hex()}")

    if not hmac.compare_digest(r.data, expected_data):
        raise AttestationError("attested data does not bind relay_id and session nonce")

    return r
