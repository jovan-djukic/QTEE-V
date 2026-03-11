"""
QKD Relay Controller - Hybrid PQC/RSA Version

This controller implements:
1. Mutual Kyber-768 key exchange (controller ↔ repetitor)
2. ML-DSA-65 certificates for repetitor ↔ repetitor communication
3. RSA certificates (via CFSSL) for repetitor ↔ KME communication

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

from typing import Union, Dict, Optional, Tuple
from fastapi import FastAPI, HTTPException, Response
from pydantic import BaseModel
import socket
from urllib.parse import urlsplit
import asyncio
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
from datetime import datetime, timedelta

application = FastAPI()

# ==================== Configuration ====================

PYTHON_URL = "127.0.0.1"
RISCV_URL = "192.168.100.2"

# CFSSL for RSA certificate signing (KME communication)
CFSSL_URL = "http://127.0.0.1:8888"

# Algorithm names in liboqs
# Try ML-KEM-768 (NIST standard) first, fall back to Kyber768 if needed
# WolfSSL uses ML-KEM-768, so we need to match
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

# CA file paths
PQC_CA_CERT_PATH = "./pqc_ca/ca_certificate.pem"
PQC_CA_KEY_PATH = "./pqc_ca/ca_private_key.pem"

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


# ==================== PQC CA Loading ====================

def load_pqc_ca_credentials(cert_path: str, key_path: str):
    """Load PQC CA certificate and private key from files."""
    global PQC_CA_PRIVATE_KEY, PQC_CA_PUBLIC_KEY, PQC_CA_CERTIFICATE
    
    with open(key_path, 'r') as f:
        key_pem = f.read()
    PQC_CA_PRIVATE_KEY = decode_pem(key_pem, "ML-DSA-65 PRIVATE KEY")
    
    with open(cert_path, 'r') as f:
        PQC_CA_CERTIFICATE = f.read()
    
    cert_data = decode_pem(PQC_CA_CERTIFICATE, "PQC CERTIFICATE")
    cert_json = json.loads(cert_data.decode('utf-8'))
    PQC_CA_PUBLIC_KEY = base64.b64decode(cert_json["tbs_certificate"]["public_key"]["key"])
    
    print(f"Loaded PQC CA: CN={cert_json['tbs_certificate']['subject']['CN']}")
    print(f"  Private key size: {len(PQC_CA_PRIVATE_KEY)} bytes")
    print(f"  Public key size: {len(PQC_CA_PUBLIC_KEY)} bytes")


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
    # Debug output
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


# ==================== PQC Certificate Creation (ML-DSA) ====================

def create_pqc_certificate(
    subject_cn: str,
    public_key: bytes,
    serial_number: int,
    not_before: datetime,
    not_after: datetime,
    is_ca: bool = False
) -> str:
    """Create and sign a PQC certificate with ML-DSA CA."""
    if PQC_CA_PRIVATE_KEY is None:
        raise ValueError("PQC CA private key not loaded")
    
    ca_cert_data = decode_pem(PQC_CA_CERTIFICATE, "PQC CERTIFICATE")
    ca_cert_json = json.loads(ca_cert_data.decode('utf-8'))
    issuer_cn = ca_cert_json["tbs_certificate"]["subject"]["CN"]
    
    cert_data = {
        "version": 3,
        "serial_number": serial_number,
        "signature_algorithm": "ML-DSA-65",
        "issuer": {"CN": issuer_cn},
        "subject": {"CN": subject_cn},
        "validity": {
            "not_before": not_before.isoformat(),
            "not_after": not_after.isoformat()
        },
        "public_key": {
            "algorithm": "ML-DSA-65",
            "key": base64.b64encode(public_key).decode('ascii')
        },
        "extensions": {
            "basic_constraints": {"ca": is_ca, "path_length": None},
            "key_usage": ["digital_signature"]
        }
    }
    
    tbs_json = json.dumps(cert_data, sort_keys=True, separators=(',', ':'))
    tbs_bytes = tbs_json.encode('utf-8')
    signature = mldsa_sign(PQC_CA_PRIVATE_KEY, tbs_bytes)
    
    full_cert = {
        "tbs_certificate": cert_data,
        "signature_algorithm": "ML-DSA-65",
        "signature": base64.b64encode(signature).decode('ascii')
    }
    
    cert_bytes = json.dumps(full_cert, indent=2).encode('utf-8')
    return encode_pem(cert_bytes, "PQC CERTIFICATE")


def sign_pqc_csr(csr_json: dict) -> Optional[str]:
    """Sign a PQC CSR (ML-DSA) and return certificate."""
    try:
        subject_cn = csr_json.get("subject_cn", "")
        public_key_b64 = csr_json.get("public_key", "")
        
        if not subject_cn or not public_key_b64:
            print(f"Invalid PQC CSR: missing fields")
            return None
        
        public_key = base64.b64decode(public_key_b64)
        
        not_before = datetime.utcnow()
        not_after = not_before + timedelta(days=365)
        serial_number = int.from_bytes(os.urandom(16), 'big')
        
        return create_pqc_certificate(
            subject_cn=subject_cn,
            public_key=public_key,
            serial_number=serial_number,
            not_before=not_before,
            not_after=not_after,
            is_ca=False
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

# Async primitives
sessions_lock: asyncio.Lock = None
repetitors_lock: asyncio.Lock = None
configuration_condition: asyncio.Condition = None


@application.on_event("startup")
async def startup_event():
    """Initialize async primitives on startup."""
    global sessions_lock, repetitors_lock, configuration_condition
    global KYBER_ALGORITHM, MLDSA_ALGORITHM
    
    sessions_lock = asyncio.Lock()
    repetitors_lock = asyncio.Lock()
    configuration_condition = asyncio.Condition()
    print("Async locks initialized")
    
    # Detect available algorithms
    KYBER_ALGORITHM = get_kyber_algorithm()
    MLDSA_ALGORITHM = get_mldsa_algorithm()
    
    if os.path.exists(PQC_CA_CERT_PATH) and os.path.exists(PQC_CA_KEY_PATH):
        try:
            load_pqc_ca_credentials(PQC_CA_CERT_PATH, PQC_CA_KEY_PATH)
        except Exception as e:
            print(f"Warning: Could not load PQC CA credentials: {e}")
    else:
        print(f"Warning: PQC CA files not found")
        print(f"Generate with: python generate_pqc_ca.py --output-dir ./pqc_ca")


# ==================== API Models ====================

class KeyExchangeStep1Request(BaseModel):
    repetitor_id: str
    repetitor_url: str
    kyber_public_key: str


class KeyExchangeStep1Response(BaseModel):
    kyber_public_key: str
    kyber_ciphertext: str
    nonce: str


class KeyExchangeStep2Request(BaseModel):
    repetitor_id: str
    kyber_ciphertext: str
    encrypted_payload: str


class EncryptedRequest(BaseModel):
    encrypted_payload: str


# ==================== API Endpoints ====================

@application.post("/key_exchange_step1")
async def key_exchange_step1(request: KeyExchangeStep1Request) -> KeyExchangeStep1Response:
    """Step 1: Receive repetitor's Kyber public key, return controller's."""
    try:
        repetitor_id = request.repetitor_id
        kyber_pk_rep = base64.b64decode(request.kyber_public_key)
        
        print(f"[{repetitor_id}] Key exchange step 1")
        
        kyber_pk_ctrl, kyber_sk_ctrl = kyber_generate_keypair()
        kyber_ct_rep, ss1 = kyber_encapsulate(kyber_pk_rep)
        nonce = os.urandom(32)
        commitment = hashlib.sha256(kyber_pk_rep + repetitor_id.encode()).hexdigest()
        
        async with sessions_lock:
            session = RepetitorSession()
            session.kyber_pk_rep = kyber_pk_rep
            session.kyber_sk_ctrl = kyber_sk_ctrl
            session.kyber_pk_ctrl = kyber_pk_ctrl
            session.ss1 = ss1
            session.nonce = nonce
            session.commitment = commitment
            session.rep_url = request.repetitor_url
            SESSIONS[repetitor_id] = session
        
        print(f"[{repetitor_id}] Nonce: {nonce.hex()}")
        
        return KeyExchangeStep1Response(
            kyber_public_key=base64.b64encode(kyber_pk_ctrl).decode(),
            kyber_ciphertext=base64.b64encode(kyber_ct_rep).decode(),
            nonce=nonce.hex()
        )
        
    except Exception as e:
        print(f"Error in key_exchange_step1: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@application.post("/key_exchange_step2")
async def key_exchange_step2(request: KeyExchangeStep2Request):
    """Step 2: Complete key exchange, verify attestation."""
    try:
        repetitor_id = request.repetitor_id
        kyber_ct_ctrl = base64.b64decode(request.kyber_ciphertext)
        
        async with sessions_lock:
            if repetitor_id not in SESSIONS:
                raise HTTPException(status_code=400, detail="No session found")
            session = SESSIONS[repetitor_id]
        
        ss2 = kyber_decapsulate(session.kyber_sk_ctrl, kyber_ct_ctrl)
        session.ss2 = ss2
        shared_key = derive_shared_key(session.ss1, ss2)
        session.shared_key = shared_key
        
        try:
            decrypted = aes_decrypt(request.encrypted_payload, shared_key)
            payload = json.loads(decrypted)
        except Exception as e:
            print(f"[{repetitor_id}] Decryption failed: {e}")
            raise HTTPException(status_code=400, detail="Decryption failed")
        
        commitment = payload.get("commitment", "")
        if commitment != session.commitment:
            print(f"[{repetitor_id}] Commitment mismatch!")
            raise HTTPException(status_code=400, detail="Commitment verification failed")
        
        print(f"[{repetitor_id}] Authenticated")
        session.authenticated = True
        
        async with repetitors_lock:
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
        
        async with configuration_condition:
            configuration_condition.notify_all()
        
        ack = json.dumps({"status": "authenticated", "repetitor_id": repetitor_id})
        encrypted_ack = aes_encrypt(ack, shared_key)
        
        return {"encrypted_response": encrypted_ack}
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error in key_exchange_step2: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@application.post("/configuration")
async def get_configuration(request: EncryptedRequest):
    """Get configuration. Blocks until all repetitors registered."""
    try:
        payload = None
        repetitor_id = None
        session = None
        
        async with sessions_lock:
            for rid, sess in SESSIONS.items():
                if sess.shared_key is None or not sess.authenticated:
                    continue
                try:
                    decrypted = aes_decrypt(request.encrypted_payload, sess.shared_key)
                    payload = json.loads(decrypted)
                    if payload.get("repetitor_id") == rid:
                        repetitor_id = rid
                        session = sess
                        break
                except:
                    continue
        
        if payload is None or repetitor_id is None:
            raise HTTPException(status_code=400, detail="Could not decrypt payload")
        
        print(f"[{repetitor_id}] Configuration request")
        
        async with configuration_condition:
            while any(r is None for r in REPETITORS):
                status = [r['repetitor_id'] if r else None for r in REPETITORS]
                print(f"[{repetitor_id}] Waiting... REPETITORS = {status}")
                await configuration_condition.wait()
        
        print(f"[{repetitor_id}] All repetitors registered!")
        
        index = None
        for i, rep in enumerate(REPETITORS):
            if rep and rep["repetitor_id"] == repetitor_id:
                index = i
                break
        
        if index is None:
            raise HTTPException(status_code=400, detail="Repetitor not found")
        
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
            # Include PQC CA certificate for repetitor-to-repetitor verification
            "pqc_ca_certificate": PQC_CA_CERTIFICATE
        }
        
        configuration["left_kme_url"] = url_to_ipv4(configuration["left_kme"]) if configuration["left_kme"] else ""
        configuration["right_kme_url"] = url_to_ipv4(configuration["right_kme"]) if configuration["right_kme"] else ""
        
        response_json = json.dumps(configuration)
        encrypted_response = aes_encrypt(response_json, session.shared_key)
        
        return {"encrypted_response": encrypted_response}
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error in configuration: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@application.post("/generate_certificates")
async def generate_certificates(request: EncryptedRequest):
    """
    Sign certificates - both PQC (for repetitors) and RSA (for KME).
    
    Expected payload:
    {
        "repetitor_id": "DR0",
        "pqc_csr": {"subject_cn": "DR0", "public_key": "base64..."},  # ML-DSA
        "left_rsa_csr": "-----BEGIN CERTIFICATE REQUEST-----...",     # RSA PEM
        "right_rsa_csr": "-----BEGIN CERTIFICATE REQUEST-----..."     # RSA PEM
    }
    
    Returns:
    {
        "pqc_certificate": "-----BEGIN PQC CERTIFICATE-----...",      # For repetitor-to-repetitor
        "left_rsa_certificate": "-----BEGIN CERTIFICATE-----...",     # For left KME
        "right_rsa_certificate": "-----BEGIN CERTIFICATE-----..."     # For right KME
    }
    """
    try:
        if PQC_CA_PRIVATE_KEY is None:
            raise HTTPException(status_code=500, detail="PQC CA not configured")
        
        payload = None
        repetitor_id = None
        session = None
        
        async with sessions_lock:
            for rid, sess in SESSIONS.items():
                if sess.shared_key is None or not sess.authenticated:
                    continue
                try:
                    decrypted = aes_decrypt(request.encrypted_payload, sess.shared_key)
                    payload = json.loads(decrypted)
                    if payload.get("repetitor_id") == rid:
                        repetitor_id = rid
                        session = sess
                        break
                except:
                    continue
        
        if payload is None or repetitor_id is None:
            raise HTTPException(status_code=400, detail="Could not decrypt payload")
        
        print(f"[{repetitor_id}] Certificate generation request")
        
        # Sign PQC certificate (ML-DSA) for repetitor-to-repetitor
        pqc_csr = payload.get("pqc_csr", {})
        print(f"[{repetitor_id}] Signing PQC certificate...")
        
        loop = asyncio.get_event_loop()
        pqc_cert = await loop.run_in_executor(None, sign_pqc_csr, pqc_csr)
        
        if not pqc_cert:
            raise HTTPException(status_code=500, detail="Failed to sign PQC certificate")
        
        # Sign RSA certificates (via CFSSL) for KME communication
        left_rsa_csr = unescape_json_string(payload.get("left_rsa_csr", ""))
        right_rsa_csr = unescape_json_string(payload.get("right_rsa_csr", ""))
        
        left_rsa_cert = None
        right_rsa_cert = None
        
        if left_rsa_csr:
            print(f"[{repetitor_id}] Signing left RSA certificate via CFSSL...")
            left_rsa_cert = await loop.run_in_executor(None, sign_rsa_csr_with_cfssl, left_rsa_csr)
        
        if right_rsa_csr:
            print(f"[{repetitor_id}] Signing right RSA certificate via CFSSL...")
            right_rsa_cert = await loop.run_in_executor(None, sign_rsa_csr_with_cfssl, right_rsa_csr)
        
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
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error in generate_certificates: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ==================== Health Check ====================

@application.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "ok",
        "pqc_ca_loaded": PQC_CA_PRIVATE_KEY is not None,
        "cfssl_url": CFSSL_URL,
        "kyber_algorithm": KYBER_ALGORITHM,
        "signature_algorithm": MLDSA_ALGORITHM
    }


# ==================== Main ====================

parser = argparse.ArgumentParser(description="QKD Relay Hybrid PQC/RSA Controller")
parser.add_argument("--pqc-ca-cert", default=PQC_CA_CERT_PATH, help="Path to PQC CA certificate")
parser.add_argument("--pqc-ca-key", default=PQC_CA_KEY_PATH, help="Path to PQC CA private key")
parser.add_argument("--cfssl-url", default=CFSSL_URL, help="CFSSL URL for RSA signing")
parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")
parser.add_argument("--port", type=int, default=8000, help="Port to bind to")

args = parser.parse_args()

PQC_CA_CERT_PATH = args.pqc_ca_cert
PQC_CA_KEY_PATH = args.pqc_ca_key
CFSSL_URL = args.cfssl_url

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

# Detect PQC algorithms early (also happens in startup but we want to fail fast)
try:
    KYBER_ALGORITHM = get_kyber_algorithm()
    MLDSA_ALGORITHM = get_mldsa_algorithm()
except RuntimeError as e:
    print(f"Error: {e}")
    sys.exit(1)

import uvicorn
uvicorn.run(application, host=args.host, port=args.port)