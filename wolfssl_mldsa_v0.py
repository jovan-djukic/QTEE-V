# wolfssl_mldsa.py - Updated to match oqs.Signature API

import ctypes
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