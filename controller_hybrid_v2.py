"""
QKD Relay Controller - Hybrid PQC/RSA Version

This controller implements:
1. WolfSSL TLS server (port 8001) for all controller-repetitor protocol:
   - Mutual Kyber-768 key exchange (controller ↔ repetitor)
   - Configuration distribution
   - ML-DSA-65 certificates for repetitor ↔ repetitor communication
   - RSA certificates (via CFSSL) for repetitor ↔ KME communication
2. Plain HTTP server (port 8000, FastAPI/uvicorn) for bootstrap only:
   - GET /ca_cert  — returns CA cert DER (public, no auth needed)
   - GET /health   — health check

Bootstrap order:
  Repetitor fetches CA cert via HTTP GET /ca_cert, then connects to
  port 8001 via WolfSSL TLS (server-only auth: controller presents its
  ML-DSA-65 cert; repetitor is authenticated by the ML-KEM exchange inside
  the TLS tunnel).

Two PKI domains:
  - Internal (PQC): Controller signs with ML-DSA-65 CA
  - External (RSA): CFSSL signs with RSA CA (for QuKayDee KME)

Usage:
  # Generate PQC CA:
  python generate_pqc_ca.py --output-dir ./pqc_ca

  # Start CFSSL for RSA signing:
  cfssl serve -address=0.0.0.0 -port=8888 -ca=./cfssl/client-root-ca.crt -ca-key=./cfssl/client-root-ca.key

  # Run controller:
  python controller_hybrid.py --pqc-ca-cert ./pqc_ca/ca_certificate.pem --pqc-ca-key ./pqc_ca/ca_private_key.pem
"""

import threading
from typing import Union, Dict, Optional, Tuple
from fastapi import FastAPI, Response
from pydantic import BaseModel
import socket
from urllib.parse import urlsplit
import base64
import os
import sys
import json
import hashlib
import argparse

try:
    import oqs
    # === WOLFSSL SHIM ===
    try:
        import wolfssl_mldsa
        _original_oqs_signature = oqs.Signature

        class HybridSignature:
            """Use WolfSSL for ML-DSA, liboqs for others."""
            def __new__(cls, algorithm, secret_key=None):
                if "DSA" in algorithm or "Dilithium" in algorithm:
                    return wolfssl_mldsa.Signature(algorithm, secret_key)
                if secret_key is not None:
                    return _original_oqs_signature(algorithm, secret_key)
                return _original_oqs_signature(algorithm)

        oqs.Signature = HybridSignature
        print("[*] Using WolfSSL for ML-DSA signatures")
    except ImportError as e:
        print(f"[*] WolfSSL ML-DSA not available ({e}), using liboqs")
    # === END WOLFSSL SHIM ===

except ImportError:
    print("Error: liboqs-python not installed")
    print("Install with: pip install liboqs-python")
    sys.exit(1)

import httpx
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timedelta, timezone

application = FastAPI()

# ==================== Configuration ====================

PYTHON_URL = "127.0.0.1"
RISCV_URL = "192.168.100.2"

# CFSSL for RSA certificate signing (KME communication)
CFSSL_URL = "http://127.0.0.1:8888"

# TLS port for the WolfSSL controller server
CTRL_TLS_PORT = 8001

# Algorithm names in liboqs
def get_kyber_algorithm():
    """Determine which Kyber/ML-KEM algorithm is available."""
    for name in ["ML-KEM-768", "Kyber768"]:
        try:
            kem = oqs.KeyEncapsulation(name)
            _ = kem.generate_keypair()
            print(f"Using KEM algorithm: {name}")
            return name
        except:
            continue
    raise RuntimeError("No Kyber/ML-KEM algorithm available in liboqs!")

def get_mldsa_algorithm():
    """Determine which Dilithium/ML-DSA algorithm is available."""
    for name in ["ML-DSA-65", "Dilithium3"]:
        try:
            sig = oqs.Signature(name)
            _ = sig.generate_keypair()
            print(f"Using signature algorithm: {name}")
            return name
        except:
            continue
    raise RuntimeError("No Dilithium/ML-DSA algorithm available in liboqs!")

# These will be set at startup
KYBER_ALGORITHM = None
MLDSA_ALGORITHM = None

# PQC CA (for repetitor-to-repetitor)
PQC_CA_PRIVATE_KEY: Optional[bytes] = None
PQC_CA_PUBLIC_KEY: Optional[bytes] = None
PQC_CA_CERTIFICATE: Optional[str] = None
PQC_CA_SUBJECT_CN: Optional[str] = None

# Controller's own ML-DSA-65 cert (for TLS server auth)
CTRL_PRIVATE_KEY: Optional[bytes] = None
CTRL_CERTIFICATE: Optional[str] = None   # PEM string

# CA file paths
PQC_CA_CERT_PATH = "./pqc_ca/ca_certificate.pem"
PQC_CA_KEY_PATH = "./pqc_ca/ca_private_key.pem"

# ==================== Threading Primitives ====================

sessions_lock = threading.Lock()
repetitors_lock = threading.Lock()
configuration_condition = threading.Condition(repetitors_lock)

# ==================== PEM Encoding/Decoding ====================

def encode_pem(data: bytes, label: str) -> str:
    """Encode binary data as PEM-like format."""
    b64 = base64.b64encode(data).decode('ascii')
    lines = [b64[i:i+64] for i in range(0, len(b64), 64)]
    return f"-----BEGIN {label}-----\n" + "\n".join(lines) + f"\n-----END {label}-----\n"


def decode_pem(pem_str: str, label: str) -> bytes:
    """Decode PEM-like format to binary data."""
    lines = pem_str.strip().split('\n')
    b64_lines = [line for line in lines if not line.startswith('-----')]
    b64_data = ''.join(b64_lines)
    return base64.b64decode(b64_data)


# ==================== X.509 DER Utilities for ML-DSA-65 ====================
# ML-DSA-65 OID: 2.16.840.1.101.3.4.3.18  (NIST FIPS 204)
# CommonName OID: 2.5.4.3

_OID_MLDSA65 = bytes([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12])
_OID_CN      = bytes([0x55, 0x04, 0x03])


def _enc_len(n: int) -> bytes:
    """DER length encoding."""
    if n < 0x80:
        return bytes([n])
    enc: list = []
    tmp = n
    while tmp > 0:
        enc.append(tmp & 0xFF)
        tmp >>= 8
    enc.reverse()
    return bytes([0x80 | len(enc)] + enc)


def _tlv(tag: int, val: bytes) -> bytes:
    return bytes([tag]) + _enc_len(len(val)) + val


def _seq(*items: bytes) -> bytes:
    return _tlv(0x30, b''.join(items))


def _set(*items: bytes) -> bytes:
    return _tlv(0x31, b''.join(items))


def _int_der(n: int) -> bytes:
    if n == 0:
        return _tlv(0x02, b'\x00')
    enc: list = []
    tmp = n
    while tmp > 0:
        enc.append(tmp & 0xFF)
        tmp >>= 8
    enc.reverse()
    if enc[0] & 0x80:
        enc.insert(0, 0x00)
    return _tlv(0x02, bytes(enc))


def _oid(raw: bytes) -> bytes:
    return _tlv(0x06, raw)


def _utf8str(s: str) -> bytes:
    return _tlv(0x0C, s.encode('utf-8'))


def _utctime(dt: datetime) -> bytes:
    return _tlv(0x17, dt.strftime('%y%m%d%H%M%SZ').encode('ascii'))


def _bitstr(data: bytes) -> bytes:
    """BIT STRING with 0 unused bits."""
    return _tlv(0x03, b'\x00' + data)


def _ctx0(*items: bytes) -> bytes:
    """[0] EXPLICIT context tag."""
    return _tlv(0xA0, b''.join(items))


def _mldsa65_alg_id() -> bytes:
    """AlgorithmIdentifier for ML-DSA-65 (no parameters per FIPS 204)."""
    return _seq(_oid(_OID_MLDSA65))


def _x509_name(cn: str) -> bytes:
    """X.509 Name containing a single CommonName attribute."""
    return _seq(_set(_seq(_oid(_OID_CN), _utf8str(cn))))


def _spki(pk: bytes) -> bytes:
    """SubjectPublicKeyInfo for ML-DSA-65."""
    return _seq(_mldsa65_alg_id(), _bitstr(pk))


def _read_len(data: bytes, pos: int):
    """Parse DER length at pos. Returns (length, new_pos)."""
    first = data[pos]
    pos += 1
    if first < 0x80:
        return first, pos
    n_bytes = first & 0x7F
    length = 0
    for _ in range(n_bytes):
        length = (length << 8) | data[pos]
        pos += 1
    return length, pos


def _read_tlv(data: bytes, pos: int):
    """Parse one DER TLV at pos. Returns (tag, value_bytes, next_pos)."""
    tag = data[pos]
    pos += 1
    length, pos = _read_len(data, pos)
    return tag, data[pos:pos + length], pos + length


def _parse_name_cn(name_tlv: bytes) -> str:
    """Extract CommonName from an X.509 Name TLV (includes outer tag+length)."""
    _, seq_val, _ = _read_tlv(name_tlv, 0)
    pos = 0
    while pos < len(seq_val):
        _, rdn_val, pos = _read_tlv(seq_val, pos)
        p2 = 0
        while p2 < len(rdn_val):
            _, attr_val, p2 = _read_tlv(rdn_val, p2)
            p3 = 0
            _, oid_val, p3 = _read_tlv(attr_val, p3)
            _, str_val, _ = _read_tlv(attr_val, p3)
            if oid_val == _OID_CN:
                return str_val.decode('utf-8')
    return ""


def _parse_x509_cert(der: bytes):
    """
    Parse X.509 Certificate DER bytes.
    Returns (subject_cn: str, public_key: bytes, tbs_raw: bytes).
    """
    _, cert_val, _ = _read_tlv(der, 0)
    pos = 0
    tbs_start = pos
    _, tbs_val, pos = _read_tlv(cert_val, pos)
    tbs_raw = cert_val[tbs_start:pos]

    tpos = 0
    if tbs_val[tpos] == 0xA0:
        _, _, tpos = _read_tlv(tbs_val, tpos)
    _, _, tpos = _read_tlv(tbs_val, tpos)
    _, _, tpos = _read_tlv(tbs_val, tpos)
    _, _, tpos = _read_tlv(tbs_val, tpos)
    _, _, tpos = _read_tlv(tbs_val, tpos)
    subj_start = tpos
    _, _, tpos = _read_tlv(tbs_val, tpos)
    subject_cn = _parse_name_cn(tbs_val[subj_start:tpos])
    _, spki_val, _ = _read_tlv(tbs_val, tpos)
    sp = 0
    _, _, sp = _read_tlv(spki_val, sp)
    _, bs_val, _ = _read_tlv(spki_val, sp)
    public_key = bs_val[1:]

    return subject_cn, public_key, tbs_raw


def _verify_dilithium_x509(cert_der: bytes, ca_public_key: bytes) -> bool:
    """Verify a Dilithium X.509 certificate's signature against a CA public key."""
    _, cert_val, _ = _read_tlv(cert_der, 0)
    pos = 0
    tbs_start = pos
    _, _, pos = _read_tlv(cert_val, pos)
    tbs_raw = cert_val[tbs_start:pos]
    _, _, pos = _read_tlv(cert_val, pos)
    _, sig_bs, _ = _read_tlv(cert_val, pos)
    signature = sig_bs[1:]
    return mldsa_verify(ca_public_key, tbs_raw, signature)


def build_dilithium_x509_cert(
    subject_cn: str,
    public_key: bytes,
    serial: int,
    not_before: datetime,
    not_after: datetime,
    issuer_cn: str,
    ca_sk: bytes,
) -> bytes:
    """Build and sign a DER-encoded X.509 certificate using ML-DSA-65."""
    tbs = _seq(
        _ctx0(_int_der(2)),
        _int_der(serial),
        _mldsa65_alg_id(),
        _x509_name(issuer_cn),
        _seq(_utctime(not_before), _utctime(not_after)),
        _x509_name(subject_cn),
        _spki(public_key),
    )
    signature = mldsa_sign(ca_sk, tbs)
    return _seq(tbs, _mldsa65_alg_id(), _bitstr(signature))


def build_dilithium_x509_cert_pem(
    subject_cn: str,
    public_key: bytes,
    serial: int,
    not_before: datetime,
    not_after: datetime,
    issuer_cn: str,
    ca_sk: bytes,
) -> str:
    """Build a Dilithium X.509 certificate and return standard PEM."""
    der = build_dilithium_x509_cert(
        subject_cn, public_key, serial, not_before, not_after, issuer_cn, ca_sk
    )
    return encode_pem(der, "CERTIFICATE")


# ==================== PQC CA Loading ====================

def load_pqc_ca_credentials(cert_path: str, key_path: str):
    """Load PQC CA certificate and private key from files."""
    global PQC_CA_PRIVATE_KEY, PQC_CA_PUBLIC_KEY, PQC_CA_CERTIFICATE, PQC_CA_SUBJECT_CN

    with open(key_path, 'r') as f:
        key_pem = f.read()
    PQC_CA_PRIVATE_KEY = decode_pem(key_pem, "ML-DSA-65 PRIVATE KEY")

    with open(cert_path, 'r') as f:
        PQC_CA_CERTIFICATE = f.read()

    cert_der = decode_pem(PQC_CA_CERTIFICATE, "CERTIFICATE")
    PQC_CA_SUBJECT_CN, PQC_CA_PUBLIC_KEY, _ = _parse_x509_cert(cert_der)

    print(f"Loaded PQC CA: CN={PQC_CA_SUBJECT_CN}")
    print(f"  Private key size: {len(PQC_CA_PRIVATE_KEY)} bytes")
    print(f"  Public key size: {len(PQC_CA_PUBLIC_KEY)} bytes")


def generate_controller_cert():
    """Generate the controller's own ML-DSA-65 certificate, signed by the PQC CA.

    This certificate is presented to repetitors during the TLS handshake on
    port 8001, allowing them to verify they are talking to the real controller.
    """
    global CTRL_PRIVATE_KEY, CTRL_CERTIFICATE
    ctrl_signer = oqs.Signature(MLDSA_ALGORITHM)
    ctrl_pk = ctrl_signer.generate_keypair()
    ctrl_sk = ctrl_signer.export_secret_key()

    CTRL_PRIVATE_KEY = ctrl_sk
    CTRL_CERTIFICATE = build_dilithium_x509_cert_pem(
        subject_cn="QKD Relay Controller",
        public_key=ctrl_pk,
        serial=int.from_bytes(os.urandom(16), 'big'),
        not_before=datetime.now(timezone.utc).replace(tzinfo=None),
        not_after=datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(days=365),
        issuer_cn=PQC_CA_SUBJECT_CN,
        ca_sk=PQC_CA_PRIVATE_KEY,
    )
    print(f"[*] Generated controller TLS cert (CN=QKD Relay Controller, signed by {PQC_CA_SUBJECT_CN})")


# ==================== Kyber Key Exchange ====================

def kyber_generate_keypair() -> Tuple[bytes, bytes]:
    """Generate Kyber-768 keypair. Returns (public_key, secret_key)."""
    kem = oqs.KeyEncapsulation(KYBER_ALGORITHM)
    public_key = kem.generate_keypair()
    secret_key = kem.export_secret_key()
    return public_key, secret_key


def kyber_encapsulate(public_key: bytes) -> Tuple[bytes, bytes]:
    """Encapsulate to a public key. Returns (ciphertext, shared_secret)."""
    kem = oqs.KeyEncapsulation(KYBER_ALGORITHM)
    ciphertext, shared_secret = kem.encap_secret(public_key)
    return ciphertext, shared_secret


def kyber_decapsulate(secret_key: bytes, ciphertext: bytes) -> bytes:
    """Decapsulate using secret key. Returns shared_secret."""
    kem = oqs.KeyEncapsulation(KYBER_ALGORITHM, secret_key)
    shared_secret = kem.decap_secret(ciphertext)
    return shared_secret


# ==================== ML-DSA Signatures ====================

def mldsa_sign(private_key: bytes, data: bytes) -> bytes:
    """Sign data with ML-DSA-65."""
    signer = oqs.Signature(MLDSA_ALGORITHM, private_key)
    return signer.sign(data)


def mldsa_verify(public_key: bytes, data: bytes, signature: bytes) -> bool:
    """Verify ML-DSA-65 signature."""
    verifier = oqs.Signature(MLDSA_ALGORITHM)
    return verifier.verify(data, signature, public_key)


# ==================== AES Encryption ====================

def derive_shared_key(ss1: bytes, ss2: bytes, context: str = "qkd-relay-v1") -> bytes:
    """Derive final shared key from two Kyber shared secrets using HKDF."""
    combined = ss1 + ss2
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=context.encode(),
        backend=default_backend()
    )
    result = hkdf.derive(combined)
    print(f"[DEBUG] derive_shared_key:")
    print(f"  ss1 (first 16 bytes): {ss1[:16].hex()}")
    print(f"  ss2 (first 16 bytes): {ss2[:16].hex()}")
    print(f"  derived key (first 16 bytes): {result[:16].hex()}")
    return result


def aes_encrypt(plaintext: str, key: bytes) -> str:
    """Encrypt with AES-256-CBC, returns base64(IV + ciphertext)."""
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(plaintext.encode()) + padder.finalize()

    ciphertext = encryptor.update(padded) + encryptor.finalize()
    return base64.b64encode(iv + ciphertext).decode()


def aes_decrypt(ciphertext_b64: str, key: bytes) -> str:
    """Decrypt AES-256-CBC from base64(IV + ciphertext)."""
    data = base64.b64decode(ciphertext_b64)
    iv = data[:16]
    ciphertext = data[16:]

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    padded = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = sym_padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded) + unpadder.finalize()

    return plaintext.decode()


# ==================== PQC Certificate Signing (ML-DSA X.509) ====================

def sign_pqc_csr(csr_json: dict) -> Optional[str]:
    """Sign a PQC CSR (ML-DSA) and return a standard X.509 PEM certificate."""
    try:
        subject_cn = csr_json.get("subject_cn", "")
        public_key_b64 = csr_json.get("public_key", "")

        if not subject_cn or not public_key_b64:
            print(f"Invalid PQC CSR: missing fields")
            return None

        public_key = base64.b64decode(public_key_b64)

        not_before = datetime.now(timezone.utc).replace(tzinfo=None)
        not_after = not_before + timedelta(days=365)
        serial = int.from_bytes(os.urandom(16), 'big')

        return build_dilithium_x509_cert_pem(
            subject_cn=subject_cn,
            public_key=public_key,
            serial=serial,
            not_before=not_before,
            not_after=not_after,
            issuer_cn=PQC_CA_SUBJECT_CN,
            ca_sk=PQC_CA_PRIVATE_KEY,
        )
    except Exception as e:
        print(f"PQC CSR signing failed: {e}")
        return None


# ==================== RSA Certificate Signing (via CFSSL) ====================

def sign_rsa_csr_with_cfssl(csr_pem: str) -> Optional[str]:
    """Sign an RSA CSR using CFSSL service (for KME communication)."""
    try:
        payload = {
            "certificate_request": csr_pem,
            "profile": "client"
        }

        with httpx.Client(timeout=30.0) as client:
            response = client.post(
                f"{CFSSL_URL}/api/v1/cfssl/sign",
                json=payload
            )

        if response.status_code == 200:
            result = response.json()
            if result.get("success") and "result" in result:
                return result["result"].get("certificate")

        print(f"CFSSL error: {response.text}")
        return None
    except Exception as e:
        print(f"CFSSL request failed: {e}")
        return None


# ==================== Helper Functions ====================

def url_to_ipv4(url: str) -> str:
    """Convert URL to IPv4 address."""
    try:
        split_url = urlsplit(url)
        hostname = split_url.netloc or split_url.path
        if hostname.startswith('[') and hostname.endswith(']'):
            hostname = hostname.strip('[]')
        if ':' in hostname and hostname.count(':') < 2:
            hostname = hostname.split(':')[0]
        return socket.gethostbyname(hostname)
    except Exception as e:
        return f"Error: {e}"


def unescape_json_string(s: str) -> str:
    """Unescape JSON string escape sequences."""
    result = s.replace("\\n", "\n")
    result = result.replace("\\r", "\r")
    result = result.replace("\\t", "\t")
    result = result.replace('\\"', '"')
    result = result.replace("\\\\", "\\")
    return result


# ==================== Data Storage ====================

LINKS = [
    {
        "start": "link0-left.acct-2563.etsi-qkd-api.qukaydee.com",
        "end": "link0-right.acct-2563.etsi-qkd-api.qukaydee.com",
        "start_sae": "link0-sae-left",
        "end_sae": "link0-sae-right",
    },
    {
        "start": "link1-left.acct-2563.etsi-qkd-api.qukaydee.com",
        "end": "link1-right.acct-2563.etsi-qkd-api.qukaydee.com",
        "start_sae": "link1-sae-left",
        "end_sae": "link1-sae-right",
    }
]


class RepetitorSession:
    def __init__(self):
        self.kyber_pk_rep: Optional[bytes] = None
        self.kyber_sk_ctrl: Optional[bytes] = None
        self.kyber_pk_ctrl: Optional[bytes] = None
        self.ss1: Optional[bytes] = None
        self.ss2: Optional[bytes] = None
        self.shared_key: Optional[bytes] = None
        self.nonce: Optional[bytes] = None
        self.commitment: Optional[str] = None
        self.rep_url: str = ""
        self.authenticated: bool = False


SESSIONS: Dict[str, RepetitorSession] = {}
REPETITORS = [None, None, None]


# ==================== Protocol Handlers (sync, thread-safe) ====================

def handle_step1(data: dict) -> dict:
    """Handle key_exchange_step1 inside the TLS tunnel."""
    try:
        repetitor_id = data["repetitor_id"]
        kyber_pk_rep = base64.b64decode(data["kyber_public_key"])

        print(f"[{repetitor_id}] Key exchange step 1")

        kyber_pk_ctrl, kyber_sk_ctrl = kyber_generate_keypair()
        kyber_ct_rep, ss1 = kyber_encapsulate(kyber_pk_rep)
        nonce = os.urandom(32)
        commitment = hashlib.sha256(kyber_pk_rep + repetitor_id.encode()).hexdigest()

        with sessions_lock:
            session = RepetitorSession()
            session.kyber_pk_rep = kyber_pk_rep
            session.kyber_sk_ctrl = kyber_sk_ctrl
            session.kyber_pk_ctrl = kyber_pk_ctrl
            session.ss1 = ss1
            session.nonce = nonce
            session.commitment = commitment
            session.rep_url = data.get("repetitor_url", "")
            SESSIONS[repetitor_id] = session

        print(f"[{repetitor_id}] Nonce: {nonce.hex()}")

        return {
            "kyber_public_key": base64.b64encode(kyber_pk_ctrl).decode(),
            "kyber_ciphertext": base64.b64encode(kyber_ct_rep).decode(),
            "nonce": nonce.hex()
        }
    except Exception as e:
        print(f"Error in handle_step1: {e}")
        return {"error": str(e)}


def handle_step2(data: dict) -> dict:
    """Handle key_exchange_step2 inside the TLS tunnel."""
    try:
        repetitor_id = data["repetitor_id"]
        kyber_ct_ctrl = base64.b64decode(data["kyber_ciphertext"])

        with sessions_lock:
            if repetitor_id not in SESSIONS:
                return {"error": "No session found"}
            session = SESSIONS[repetitor_id]

        ss2 = kyber_decapsulate(session.kyber_sk_ctrl, kyber_ct_ctrl)
        session.ss2 = ss2
        shared_key = derive_shared_key(session.ss1, ss2)
        session.shared_key = shared_key

        try:
            decrypted = aes_decrypt(data["encrypted_payload"], shared_key)
            payload = json.loads(decrypted)
        except Exception as e:
            print(f"[{repetitor_id}] Decryption failed: {e}")
            return {"error": "Decryption failed"}

        commitment = payload.get("commitment", "")
        if commitment != session.commitment:
            print(f"[{repetitor_id}] Commitment mismatch!")
            return {"error": "Commitment verification failed"}

        print(f"[{repetitor_id}] Authenticated")
        session.authenticated = True

        with repetitors_lock:
            try:
                index = int(repetitor_id[-1])
                if 0 <= index < len(REPETITORS):
                    REPETITORS[index] = {
                        "repetitor_id": repetitor_id,
                        "repetitor_port": session.rep_url.split(":")[-1] if ":" in session.rep_url else "9001",
                    }
                    print(f"[{repetitor_id}] Registered (index {index})")
            except (ValueError, IndexError) as e:
                print(f"[{repetitor_id}] Could not parse index: {e}")

            configuration_condition.notify_all()

        ack = json.dumps({"status": "authenticated", "repetitor_id": repetitor_id})
        encrypted_ack = aes_encrypt(ack, shared_key)
        return {"encrypted_response": encrypted_ack}

    except Exception as e:
        print(f"Error in handle_step2: {e}")
        return {"error": str(e)}


def handle_configuration(data: dict) -> dict:
    """Handle configuration request inside the TLS tunnel. Blocks until all repetitors are ready."""
    try:
        payload = None
        repetitor_id = None
        session = None

        with sessions_lock:
            for rid, sess in SESSIONS.items():
                if sess.shared_key is None or not sess.authenticated:
                    continue
                try:
                    decrypted = aes_decrypt(data["encrypted_payload"], sess.shared_key)
                    payload = json.loads(decrypted)
                    if payload.get("repetitor_id") == rid:
                        repetitor_id = rid
                        session = sess
                        break
                except:
                    continue

        if payload is None or repetitor_id is None:
            return {"error": "Could not decrypt payload"}

        print(f"[{repetitor_id}] Configuration request")

        # Block until all repetitors have registered
        with configuration_condition:
            while any(r is None for r in REPETITORS):
                status = [r['repetitor_id'] if r else None for r in REPETITORS]
                print(f"[{repetitor_id}] Waiting... REPETITORS = {status}")
                configuration_condition.wait()

        print(f"[{repetitor_id}] All repetitors registered!")

        index = None
        for i, rep in enumerate(REPETITORS):
            if rep and rep["repetitor_id"] == repetitor_id:
                index = i
                break

        if index is None:
            return {"error": "Repetitor not found"}

        base_url = RISCV_URL if "riscv" in repetitor_id else PYTHON_URL

        left_port = REPETITORS[index - 1]["repetitor_port"] if index > 0 else "8998"
        right_port = REPETITORS[index + 1]["repetitor_port"] if index < len(REPETITORS) - 1 else "8999"

        configuration = {
            "left_repetitor_url": f"{base_url}:{left_port}",
            "right_repetitor_url": f"{base_url}:{right_port}",
            "left_repetitor_id": REPETITORS[index - 1]["repetitor_id"] if index > 0 else "test_client",
            "right_repetitor_id": REPETITORS[index + 1]["repetitor_id"] if index < len(REPETITORS) - 1 else "test_client",
            "left_kme": LINKS[index - 1]["end"] if index > 0 else "",
            "right_kme": LINKS[index]["start"] if index < len(LINKS) else "",
            "left_cn": LINKS[index - 1]["end_sae"] if index > 0 else "test_client",
            "right_cn": LINKS[index]["start_sae"] if index < len(LINKS) else "test_client",
            "left_kme_peer": LINKS[index - 1]["start_sae"] if index > 0 else "",
            "right_kme_peer": LINKS[index]["end_sae"] if index < len(LINKS) else "",
            "whitelist": "|".join([r["repetitor_id"] for r in REPETITORS if r and r["repetitor_id"] != repetitor_id] + ["test_client", "QKD Relay PQC CA"]),
            "pqc_ca_certificate": PQC_CA_CERTIFICATE
        }

        configuration["left_kme_url"] = url_to_ipv4(configuration["left_kme"]) if configuration["left_kme"] else ""
        configuration["right_kme_url"] = url_to_ipv4(configuration["right_kme"]) if configuration["right_kme"] else ""

        response_json = json.dumps(configuration)
        encrypted_response = aes_encrypt(response_json, session.shared_key)
        return {"encrypted_response": encrypted_response}

    except Exception as e:
        print(f"Error in handle_configuration: {e}")
        return {"error": str(e)}


def handle_generate_certs(data: dict) -> dict:
    """Handle generate_certificates request inside the TLS tunnel."""
    try:
        if PQC_CA_PRIVATE_KEY is None:
            return {"error": "PQC CA not configured"}

        payload = None
        repetitor_id = None
        session = None

        with sessions_lock:
            for rid, sess in SESSIONS.items():
                if sess.shared_key is None or not sess.authenticated:
                    continue
                try:
                    decrypted = aes_decrypt(data["encrypted_payload"], sess.shared_key)
                    payload = json.loads(decrypted)
                    if payload.get("repetitor_id") == rid:
                        repetitor_id = rid
                        session = sess
                        break
                except:
                    continue

        if payload is None or repetitor_id is None:
            return {"error": "Could not decrypt payload"}

        print(f"[{repetitor_id}] Certificate generation request")

        pqc_csr = payload.get("pqc_csr", {})
        print(f"[{repetitor_id}] Signing PQC certificate...")
        pqc_cert = sign_pqc_csr(pqc_csr)

        if not pqc_cert:
            return {"error": "Failed to sign PQC certificate"}

        left_rsa_csr = unescape_json_string(payload.get("left_rsa_csr", ""))
        right_rsa_csr = unescape_json_string(payload.get("right_rsa_csr", ""))

        left_rsa_cert = None
        right_rsa_cert = None

        if left_rsa_csr:
            print(f"[{repetitor_id}] Signing left RSA certificate via CFSSL...")
            left_rsa_cert = sign_rsa_csr_with_cfssl(left_rsa_csr)

        if right_rsa_csr:
            print(f"[{repetitor_id}] Signing right RSA certificate via CFSSL...")
            right_rsa_cert = sign_rsa_csr_with_cfssl(right_rsa_csr)

        response = {
            "pqc_certificate": pqc_cert,
            "left_rsa_certificate": left_rsa_cert or "",
            "right_rsa_certificate": right_rsa_cert or ""
        }

        response_json = json.dumps(response)
        encrypted_response = aes_encrypt(response_json, session.shared_key)

        print(f"[{repetitor_id}] Certificates signed and sent")
        print(f"[{repetitor_id}]   PQC: ✓")
        print(f"[{repetitor_id}]   Left RSA: {'✓' if left_rsa_cert else '(not requested)'}")
        print(f"[{repetitor_id}]   Right RSA: {'✓' if right_rsa_cert else '(not requested)'}")

        return {"encrypted_response": encrypted_response}

    except Exception as e:
        print(f"Error in handle_generate_certs: {e}")
        return {"error": str(e)}


def dispatch_action(action: str, data: dict) -> dict:
    """Dispatch a TLS protocol action to the appropriate handler."""
    if action == "key_exchange_step1":
        return handle_step1(data)
    elif action == "key_exchange_step2":
        return handle_step2(data)
    elif action == "configuration":
        return handle_configuration(data)
    elif action == "generate_certificates":
        return handle_generate_certs(data)
    return {"error": f"Unknown action: {action}"}


# ==================== WolfSSL TLS Server (port 8001) ====================

def handle_tls_client(conn_sock: socket.socket, cert_der: bytes, pkcs8_der: bytes):
    """Handle one repetitor connection over WolfSSL TLS."""
    addr = conn_sock.getpeername()
    print(f"[TLS] New connection from {addr}")
    try:
        with wolfssl_mldsa.pqc_tls_server_accept_anon_client(
                conn_sock.fileno(), cert_der, pkcs8_der) as conn:
            print(f"[TLS] Handshake complete with {addr}")
            while True:
                try:
                    req_bytes = conn.recvmsg()
                except OSError:
                    break
                try:
                    req = json.loads(req_bytes)
                except json.JSONDecodeError as e:
                    conn.sendmsg(json.dumps({"error": f"JSON parse error: {e}"}).encode())
                    continue

                action = req.get("action", "")
                data = req.get("data", {})
                result = dispatch_action(action, data)
                conn.sendmsg(json.dumps(result).encode())
    except Exception as e:
        print(f"[TLS] Error handling {addr}: {e}")
    finally:
        conn_sock.close()
        print(f"[TLS] Connection from {addr} closed")


def run_tls_server():
    """Run the WolfSSL TLS socket server on CTRL_TLS_PORT."""
    cert_der  = decode_pem(CTRL_CERTIFICATE, "CERTIFICATE")
    pkcs8_der = wolfssl_mldsa.pkcs8_mldsa65_der(CTRL_PRIVATE_KEY)

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind(("0.0.0.0", CTRL_TLS_PORT))
    server_sock.listen(10)
    print(f"[*] WolfSSL TLS controller server on port {CTRL_TLS_PORT}")

    while True:
        conn_sock, _addr = server_sock.accept()
        t = threading.Thread(
            target=handle_tls_client,
            args=(conn_sock, cert_der, pkcs8_der),
            daemon=True
        )
        t.start()


# ==================== FastAPI: Bootstrap Endpoints Only ====================

@application.get("/ca_cert")
async def get_ca_cert():
    """Return the PQC CA certificate DER (public — no authentication required).

    Repetitors fetch this first to bootstrap the WolfSSL TLS connection to
    port 8001, where they verify the controller's certificate against this CA.
    """
    ca_der = decode_pem(PQC_CA_CERTIFICATE, "CERTIFICATE")
    return Response(content=ca_der, media_type="application/octet-stream")


@application.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "ok",
        "pqc_ca_loaded": PQC_CA_PRIVATE_KEY is not None,
        "ctrl_cert_loaded": CTRL_CERTIFICATE is not None,
        "cfssl_url": CFSSL_URL,
        "ctrl_tls_port": CTRL_TLS_PORT,
        "kyber_algorithm": KYBER_ALGORITHM,
        "signature_algorithm": MLDSA_ALGORITHM
    }


# ==================== Main ====================

parser = argparse.ArgumentParser(description="QKD Relay Hybrid PQC/RSA Controller")
parser.add_argument("--pqc-ca-cert", default=PQC_CA_CERT_PATH, help="Path to PQC CA certificate")
parser.add_argument("--pqc-ca-key", default=PQC_CA_KEY_PATH, help="Path to PQC CA private key")
parser.add_argument("--cfssl-url", default=CFSSL_URL, help="CFSSL URL for RSA signing")
parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")
parser.add_argument("--port", type=int, default=8000, help="HTTP port (for /ca_cert bootstrap)")
parser.add_argument("--tls-port", type=int, default=CTRL_TLS_PORT, help="WolfSSL TLS port")

args = parser.parse_args()

PQC_CA_CERT_PATH = args.pqc_ca_cert
PQC_CA_KEY_PATH = args.pqc_ca_key
CFSSL_URL = args.cfssl_url
CTRL_TLS_PORT = args.tls_port

if os.path.exists(PQC_CA_CERT_PATH) and os.path.exists(PQC_CA_KEY_PATH):
    load_pqc_ca_credentials(PQC_CA_CERT_PATH, PQC_CA_KEY_PATH)
else:
    print(f"Error: PQC CA files not found")
    print(f"  Certificate: {PQC_CA_CERT_PATH}")
    print(f"  Private key: {PQC_CA_KEY_PATH}")
    print(f"\nGenerate with: python generate_pqc_ca.py --output-dir ./pqc_ca")
    sys.exit(1)

print(f"\nCFSSL URL: {CFSSL_URL}")
print(f"Make sure CFSSL is running for RSA certificate signing!\n")

# Detect PQC algorithms early (fail fast)
try:
    KYBER_ALGORITHM = get_kyber_algorithm()
    MLDSA_ALGORITHM = get_mldsa_algorithm()
except RuntimeError as e:
    print(f"Error: {e}")
    sys.exit(1)

# Generate controller's own TLS certificate
generate_controller_cert()

# Start WolfSSL TLS server in a daemon thread
tls_thread = threading.Thread(target=run_tls_server, daemon=True)
tls_thread.start()

import uvicorn
uvicorn.run(application, host=args.host, port=args.port)