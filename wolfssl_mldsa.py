# wolfssl_mldsa.py - Updated to match oqs.Signature API

import ctypes
import os
import struct
from pathlib import Path

# Load the shared library
_lib_path = Path(__file__).parent / "libwolfssl_mldsa.so"
_lib = ctypes.CDLL(str(_lib_path))

# Function signatures
_lib.mldsa_init.restype = ctypes.c_int
_lib.mldsa_cleanup.restype = None
_lib.mldsa_pk_size.restype = ctypes.c_uint
_lib.mldsa_sk_size.restype = ctypes.c_uint
_lib.mldsa_sig_size.restype = ctypes.c_uint

_lib.mldsa_keygen.argtypes = [
    ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_uint),
    ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_uint)
]
_lib.mldsa_keygen.restype = ctypes.c_int

_lib.mldsa_sign.argtypes = [
    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint,
    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint,
    ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_uint)
]
_lib.mldsa_sign.restype = ctypes.c_int

_lib.mldsa_verify.argtypes = [
    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint,
    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint,
    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint
]
_lib.mldsa_verify.restype = ctypes.c_int

_lib.mldsa_privkey_to_pkcs8_der.argtypes = [
    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint,
    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint,
]
_lib.mldsa_privkey_to_pkcs8_der.restype = ctypes.c_int

# Initialize
if _lib.mldsa_init() != 0:
    raise RuntimeError("Failed to initialize WolfSSL ML-DSA")

# Sizes
PK_SIZE = _lib.mldsa_pk_size()
SK_SIZE = _lib.mldsa_sk_size()
SIG_SIZE = _lib.mldsa_sig_size()


class Signature:
    """Drop-in replacement for oqs.Signature for ML-DSA-65."""
    
    def __init__(self, algorithm: str = "ML-DSA-65", secret_key: bytes = None):
        """
        Initialize signature object.
        
        Args:
            algorithm: Algorithm name (only ML-DSA-65 supported)
            secret_key: Optional secret key to import
        """
        self.details = {
            "length_public_key": PK_SIZE,
            "length_secret_key": SK_SIZE,
            "length_signature": SIG_SIZE,
        }
        self._pk = None
        self._sk = secret_key  # Can be set via constructor
    
    def generate_keypair(self) -> bytes:
        """Generate keypair, return public key."""
        pk = (ctypes.c_ubyte * PK_SIZE)()
        sk = (ctypes.c_ubyte * SK_SIZE)()
        pk_len = ctypes.c_uint(PK_SIZE)
        sk_len = ctypes.c_uint(SK_SIZE)
        
        ret = _lib.mldsa_keygen(pk, ctypes.byref(pk_len), sk, ctypes.byref(sk_len))
        if ret != 0:
            raise RuntimeError(f"Key generation failed: {ret}")
        
        self._pk = bytes(pk[:pk_len.value])
        self._sk = bytes(sk[:sk_len.value])
        return self._pk
    
    def export_secret_key(self) -> bytes:
        """Export secret key."""
        if self._sk is None:
            raise RuntimeError("No secret key available")
        return self._sk
    
    def sign(self, message: bytes) -> bytes:
        """Sign a message."""
        if self._sk is None:
            raise RuntimeError("No secret key available")
        
        sk = (ctypes.c_ubyte * len(self._sk))(*self._sk)
        msg = (ctypes.c_ubyte * len(message))(*message)
        sig = (ctypes.c_ubyte * SIG_SIZE)()
        sig_len = ctypes.c_uint(SIG_SIZE)
        
        ret = _lib.mldsa_sign(sk, len(self._sk), msg, len(message), sig, ctypes.byref(sig_len))
        if ret != 0:
            raise RuntimeError(f"Signing failed: {ret}")
        
        return bytes(sig[:sig_len.value])
    
    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """Verify a signature."""
        pk = (ctypes.c_ubyte * len(public_key))(*public_key)
        msg = (ctypes.c_ubyte * len(message))(*message)
        sig = (ctypes.c_ubyte * len(signature))(*signature)

        ret = _lib.mldsa_verify(pk, len(public_key), msg, len(message), sig, len(signature))
        return ret == 0


def pkcs8_mldsa65_der(raw_sk: bytes) -> bytes:
    """
    Convert a raw ML-DSA-65 private key (4032 bytes) to PKCS#8 DER using
    WolfSSL's wc_Dilithium_PrivateKeyToDer — the format that
    wolfSSL_CTX_use_PrivateKey_buffer() actually accepts.
    """
    sk_arr = (ctypes.c_ubyte * len(raw_sk))(*raw_sk)
    out = (ctypes.c_ubyte * 8192)()
    n = _lib.mldsa_privkey_to_pkcs8_der(sk_arr, len(raw_sk), out, 8192)
    if n <= 0:
        raise RuntimeError(f"mldsa_privkey_to_pkcs8_der failed: {n}")
    return bytes(out[:n])


# ==================== X.509 cert signature verification (WolfSSL crypto) ====================
#
# WolfSSL's TLS X.509 chain verifier fails for ML-DSA-65 certs even with
# --enable-dilithium (ASN_SIG_CONFIRM_E).  We bypass the handshake-level
# check (_pqc_verify_accept_all in C) and verify manually here using
# WolfSSL's raw crypto via Signature.verify().

def _parse_len(data: bytes, pos: int):
    b = data[pos]; pos += 1
    if b < 0x80:
        return b, pos
    nb = b & 0x7F
    return int.from_bytes(data[pos:pos + nb], 'big'), pos + nb


def _skip_tlv(data: bytes, pos: int) -> int:
    pos += 1  # tag
    length, pos = _parse_len(data, pos)
    return pos + length


def verify_cert_der(cert_der: bytes, ca_der: bytes) -> bool:
    """
    Verify an ML-DSA-65 X.509 DER certificate against a CA DER certificate
    using WolfSSL's Signature.verify() (raw WolfCrypt ML-DSA-65).
    """
    # Extract TBSCertificate and signature from cert_der
    pos = 0
    assert cert_der[pos] == 0x30; pos += 1
    _, pos = _parse_len(cert_der, pos)

    tbs_start = pos
    assert cert_der[pos] == 0x30; pos += 1
    tbs_content_len, pos = _parse_len(cert_der, pos)
    tbs_end = pos + tbs_content_len
    tbs_bytes = cert_der[tbs_start:tbs_end]
    pos = tbs_end

    pos = _skip_tlv(cert_der, pos)           # signature algorithm

    assert cert_der[pos] == 0x03; pos += 1   # BIT STRING
    sig_bs_len, pos = _parse_len(cert_der, pos)
    assert cert_der[pos] == 0x00; pos += 1   # unused bits = 0
    sig_bytes = cert_der[pos:pos + sig_bs_len - 1]

    # Extract CA public key from ca_der SubjectPublicKeyInfo
    pos = 0
    assert ca_der[pos] == 0x30; pos += 1
    _, pos = _parse_len(ca_der, pos)

    assert ca_der[pos] == 0x30; pos += 1
    _, pos = _parse_len(ca_der, pos)

    if ca_der[pos] == 0xA0:
        pos = _skip_tlv(ca_der, pos)
    for _ in range(5):                       # serial, sigAlg, issuer, validity, subject
        pos = _skip_tlv(ca_der, pos)

    assert ca_der[pos] == 0x30; pos += 1     # SubjectPublicKeyInfo
    _, pos = _parse_len(ca_der, pos)
    pos = _skip_tlv(ca_der, pos)             # AlgorithmIdentifier

    assert ca_der[pos] == 0x03; pos += 1     # BIT STRING
    pk_bs_len, pos = _parse_len(ca_der, pos)
    assert ca_der[pos] == 0x00; pos += 1     # unused bits = 0
    ca_pk = ca_der[pos:pos + pk_bs_len - 1]

    verifier = Signature("ML-DSA-65")
    return verifier.verify(tbs_bytes, sig_bytes, ca_pk)


# ==================== PQC TLS (WolfSSL mTLS) ====================

# pqc_tls_t* is treated as an opaque pointer (c_void_p)
_lib.pqc_tls_server_new.argtypes = [
    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int,
    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int,
    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int,
]
_lib.pqc_tls_server_new.restype = ctypes.c_void_p

_lib.pqc_tls_client_new.argtypes = [
    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int,
    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int,
    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int,
]
_lib.pqc_tls_client_new.restype = ctypes.c_void_p

_lib.pqc_tls_accept.argtypes  = [ctypes.c_void_p, ctypes.c_int]
_lib.pqc_tls_accept.restype   = ctypes.c_int

_lib.pqc_tls_connect.argtypes = [ctypes.c_void_p, ctypes.c_int]
_lib.pqc_tls_connect.restype  = ctypes.c_int

_lib.pqc_tls_write.argtypes = [
    ctypes.c_void_p, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int
]
_lib.pqc_tls_write.restype = ctypes.c_int

_lib.pqc_tls_read.argtypes = [
    ctypes.c_void_p, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int
]
_lib.pqc_tls_read.restype = ctypes.c_int

# Generous ceiling for a DER-encoded ML-DSA-65 X.509 cert
_CERT_DER_MAX = 8192

_lib.pqc_tls_peer_cert_der.argtypes = [
    ctypes.c_void_p, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int
]
_lib.pqc_tls_peer_cert_der.restype = ctypes.c_int

_lib.pqc_tls_free.argtypes = [ctypes.c_void_p]
_lib.pqc_tls_free.restype  = None

# Anonymous-client variants (for controller channel)
_lib.pqc_tls_client_anon_new.argtypes = [
    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int,
]
_lib.pqc_tls_client_anon_new.restype = ctypes.c_void_p

_lib.pqc_tls_server_anon_client_new.argtypes = [
    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int,
    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int,
]
_lib.pqc_tls_server_anon_client_new.restype = ctypes.c_void_p


def _buf(data: bytes):
    """Return (ctypes ubyte array, length) from bytes."""
    arr = (ctypes.c_ubyte * len(data))(*data)
    return arr, len(data)


class PqcTlsConn:
    """Wraps a WolfSSL mTLS connection with length-prefixed message framing."""

    def __init__(self, handle: int):
        self._h = handle  # opaque c_void_p value

    # -- raw byte I/O --

    def write(self, data: bytes) -> None:
        arr, n = _buf(data)
        if _lib.pqc_tls_write(self._h, arr, n) != 0:
            raise OSError("pqc_tls_write failed")

    def read(self, n: int) -> bytes:
        buf = (ctypes.c_ubyte * n)()
        if _lib.pqc_tls_read(self._h, buf, n) != 0:
            raise OSError("pqc_tls_read failed")
        return bytes(buf)

    # -- length-prefixed message framing (4-byte big-endian header) --

    def sendmsg(self, data: bytes) -> None:
        self.write(struct.pack(">I", len(data)) + data)

    def recvmsg(self) -> bytes:
        header = self.read(4)
        length = struct.unpack(">I", header)[0]
        return self.read(length)

    # -- peer certificate --

    def peer_cert_der(self) -> bytes:
        buf = (ctypes.c_ubyte * _CERT_DER_MAX)()
        n = _lib.pqc_tls_peer_cert_der(self._h, buf, _CERT_DER_MAX)
        if n < 0:
            raise RuntimeError("Failed to retrieve peer certificate")
        return bytes(buf[:n])

    def close(self) -> None:
        if self._h:
            _lib.pqc_tls_free(self._h)
            self._h = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def pqc_tls_server_accept(fd: int, cert_der: bytes, pkcs8_der: bytes, ca_der: bytes) -> PqcTlsConn:
    """Create server TLS context, perform mTLS handshake on fd, return PqcTlsConn.

    After the handshake the peer cert is verified via verify_cert_der()
    (WolfSSL raw crypto) because WolfSSL's TLS chain verifier fails for
    ML-DSA-65 certs (ASN_SIG_CONFIRM_E).
    """
    os.set_blocking(fd, True)
    c, cl = _buf(cert_der)
    k, kl = _buf(pkcs8_der)
    a, al = _buf(ca_der)
    handle = _lib.pqc_tls_server_new(c, cl, k, kl, a, al)
    if not handle:
        raise RuntimeError("pqc_tls_server_new failed")
    if _lib.pqc_tls_accept(handle, fd) != 0:
        _lib.pqc_tls_free(handle)
        raise RuntimeError("TLS server handshake failed")
    conn = PqcTlsConn(handle)
    try:
        if not verify_cert_der(conn.peer_cert_der(), ca_der):
            raise RuntimeError("Peer certificate signature verification failed")
    except Exception:
        conn.close()
        raise
    return conn


def pqc_tls_client_connect(fd: int, cert_der: bytes, pkcs8_der: bytes, ca_der: bytes) -> PqcTlsConn:
    """Create client TLS context, perform mTLS handshake on fd, return PqcTlsConn.

    After the handshake the peer cert is verified via verify_cert_der()
    (WolfSSL raw crypto).
    """
    os.set_blocking(fd, True)
    c, cl = _buf(cert_der)
    k, kl = _buf(pkcs8_der)
    a, al = _buf(ca_der)
    handle = _lib.pqc_tls_client_new(c, cl, k, kl, a, al)
    if not handle:
        raise RuntimeError("pqc_tls_client_new failed")
    if _lib.pqc_tls_connect(handle, fd) != 0:
        _lib.pqc_tls_free(handle)
        raise RuntimeError("TLS client handshake failed")
    conn = PqcTlsConn(handle)
    try:
        if not verify_cert_der(conn.peer_cert_der(), ca_der):
            raise RuntimeError("Peer certificate signature verification failed")
    except Exception:
        conn.close()
        raise
    return conn


def pqc_tls_client_connect_anon(fd: int, ca_der: bytes) -> PqcTlsConn:
    """TLS client with server-only authentication (no client certificate).

    Used for the controller channel: the repetitor does not yet hold a
    CA-signed cert.  The controller's cert is verified via verify_cert_der()
    (WolfSSL raw crypto) after the handshake.
    """
    os.set_blocking(fd, True)
    a, al = _buf(ca_der)
    handle = _lib.pqc_tls_client_anon_new(a, al)
    if not handle:
        raise RuntimeError("pqc_tls_client_anon_new failed")
    if _lib.pqc_tls_connect(handle, fd) != 0:
        _lib.pqc_tls_free(handle)
        raise RuntimeError("TLS anonymous client handshake failed")
    conn = PqcTlsConn(handle)
    try:
        if not verify_cert_der(conn.peer_cert_der(), ca_der):
            raise RuntimeError("Controller certificate signature verification failed")
    except Exception:
        conn.close()
        raise
    return conn


def pqc_tls_server_accept_anon_client(fd: int, cert_der: bytes, pkcs8_der: bytes) -> PqcTlsConn:
    """TLS server that does NOT require a client certificate.

    Used for the controller: the connecting repetitor has no CA-signed cert
    yet.  The controller authenticates itself via its ML-DSA-65 cert; the
    repetitor authenticates via the attestation exchange inside the TLS tunnel.

    Steps:
      1. os.set_blocking(fd, True)
      2. pqc_tls_server_anon_client_new(cert_der, pkcs8_der)
      3. pqc_tls_accept(fd)
      (No client cert to verify.)
    """
    os.set_blocking(fd, True)
    c, cl = _buf(cert_der)
    k, kl = _buf(pkcs8_der)
    handle = _lib.pqc_tls_server_anon_client_new(c, cl, k, kl)
    if not handle:
        raise RuntimeError("pqc_tls_server_anon_client_new failed")
    if _lib.pqc_tls_accept(handle, fd) != 0:
        _lib.pqc_tls_free(handle)
        raise RuntimeError("TLS anonymous-client server handshake failed")
    return PqcTlsConn(handle)