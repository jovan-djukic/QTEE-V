"""
QKD Relay Controller - Post-Quantum Cryptography Version

This controller implements:
1. Mutual Kyber-768 key exchange (both parties contribute to shared secret)
2. ML-DSA-65 CA for certificate signing (replaces CFSSL)
3. Async handling for concurrent repetitors

Usage:
  # Generate CA first:
  python generate_pqc_ca.py --output-dir ./pqc_ca
  
  # Run controller:
  python controller_pqc.py --ca-cert ./pqc_ca/ca_certificate.pem --ca-key ./pqc_ca/ca_private_key.pem

Protocol:
  Step 1 (Key Exchange):
    Repetitor -> Controller: { rep_id, rep_url, kyber_pk_rep }
    Controller -> Repetitor: { kyber_pk_ctrl, kyber_ct_rep, nonce }
    Repetitor -> Controller: { kyber_ct_ctrl, AES(attestation + commitment) }
    
  Step 2 (Configuration):
    Repetitor -> Controller: AES(config_request)
    Controller -> Repetitor: AES(configuration)
    
  Step 3 (Certificates):
    Repetitor -> Controller: AES(CSRs with ML-DSA public keys)
    Controller -> Repetitor: AES(ML-DSA signed certificates)
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
except ImportError:
    print("Error: liboqs-python not installed")
    print("Install with: pip install liboqs-python")
    sys.exit(1)

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

# Algorithm names in liboqs
KYBER_ALGORITHM = "Kyber768"
# DILITHIUM_ALGORITHM = "Dilithium3"
DILITHIUM_ALGORITHM = "ML-DSA-65"


# Will be loaded from files
CA_PRIVATE_KEY: Optional[bytes] = None
CA_PUBLIC_KEY: Optional[bytes] = None
CA_CERTIFICATE: Optional[str] = None

# CA file paths (can be overridden via command line)
CA_CERT_PATH = "./pqc_ca/ca_certificate.pem"
CA_KEY_PATH = "./pqc_ca/ca_private_key.pem"

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


# ==================== CA Loading ====================

def load_ca_credentials(cert_path: str, key_path: str):
    """Load CA certificate and private key from files."""
    global CA_PRIVATE_KEY, CA_PUBLIC_KEY, CA_CERTIFICATE
    
    # Load private key
    with open(key_path, 'r') as f:
        key_pem = f.read()
    CA_PRIVATE_KEY = decode_pem(key_pem, "ML-DSA-65 PRIVATE KEY")
    
    # Load certificate
    with open(cert_path, 'r') as f:
        CA_CERTIFICATE = f.read()
    
    # Extract public key from certificate
    cert_data = decode_pem(CA_CERTIFICATE, "PQC CERTIFICATE")
    cert_json = json.loads(cert_data.decode('utf-8'))
    CA_PUBLIC_KEY = base64.b64decode(cert_json["tbs_certificate"]["public_key"]["key"])
    
    print(f"Loaded CA certificate: CN={cert_json['tbs_certificate']['subject']['CN']}")
    print(f"  Private key size: {len(CA_PRIVATE_KEY)} bytes")
    print(f"  Public key size: {len(CA_PUBLIC_KEY)} bytes")


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
    signer = oqs.Signature(DILITHIUM_ALGORITHM, private_key)
    return signer.sign(data)


def mldsa_verify(public_key: bytes, data: bytes, signature: bytes) -> bool:
    """Verify ML-DSA-65 signature."""
    verifier = oqs.Signature(DILITHIUM_ALGORITHM)
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
    return hkdf.derive(combined)


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


# ==================== Certificate Creation ====================

def create_certificate(
    subject_cn: str,
    public_key: bytes,
    serial_number: int,
    not_before: datetime,
    not_after: datetime,
    is_ca: bool = False
) -> str:
    """Create and sign a certificate with ML-DSA CA."""
    if CA_PRIVATE_KEY is None:
        raise ValueError("CA private key not loaded")
    
    # Parse CA certificate to get issuer CN
    ca_cert_data = decode_pem(CA_CERTIFICATE, "PQC CERTIFICATE")
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
    
    # Sign TBS certificate
    tbs_json = json.dumps(cert_data, sort_keys=True, separators=(',', ':'))
    tbs_bytes = tbs_json.encode('utf-8')
    signature = mldsa_sign(CA_PRIVATE_KEY, tbs_bytes)
    
    # Complete certificate
    full_cert = {
        "tbs_certificate": cert_data,
        "signature_algorithm": "ML-DSA-65",
        "signature": base64.b64encode(signature).decode('ascii')
    }
    
    cert_bytes = json.dumps(full_cert, indent=2).encode('utf-8')
    return encode_pem(cert_bytes, "PQC CERTIFICATE")


def sign_csr(csr_json: dict) -> Optional[str]:
    """Sign a CSR and return certificate."""
    try:
        subject_cn = csr_json.get("subject_cn", "")
        public_key_b64 = csr_json.get("public_key", "")
        
        if not subject_cn or not public_key_b64:
            print(f"Invalid CSR: missing fields")
            return None
        
        public_key = base64.b64decode(public_key_b64)
        
        not_before = datetime.utcnow()
        not_after = not_before + timedelta(days=365)
        serial_number = int.from_bytes(os.urandom(16), 'big')
        
        return create_certificate(
            subject_cn=subject_cn,
            public_key=public_key,
            serial_number=serial_number,
            not_before=not_before,
            not_after=not_after,
            is_ca=False
        )
    except Exception as e:
        print(f"CSR signing failed: {e}")
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

# Per-repetitor session data
class RepetitorSession:
    def __init__(self):
        self.kyber_pk_rep: Optional[bytes] = None  # Repetitor's Kyber public key
        self.kyber_sk_ctrl: Optional[bytes] = None  # Controller's Kyber secret key
        self.kyber_pk_ctrl: Optional[bytes] = None  # Controller's Kyber public key
        self.ss1: Optional[bytes] = None  # Shared secret from encap to rep
        self.ss2: Optional[bytes] = None  # Shared secret from encap to ctrl
        self.shared_key: Optional[bytes] = None  # Final derived key
        self.nonce: Optional[bytes] = None
        self.commitment: Optional[str] = None  # Expected commitment
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
    sessions_lock = asyncio.Lock()
    repetitors_lock = asyncio.Lock()
    configuration_condition = asyncio.Condition()
    print("Async locks initialized")
    
    # Load CA if files exist
    if os.path.exists(CA_CERT_PATH) and os.path.exists(CA_KEY_PATH):
        try:
            load_ca_credentials(CA_CERT_PATH, CA_KEY_PATH)
        except Exception as e:
            print(f"Warning: Could not load CA credentials: {e}")
    else:
        print(f"Warning: CA files not found at {CA_CERT_PATH} and {CA_KEY_PATH}")
        print("Generate with: python generate_pqc_ca.py --output-dir ./pqc_ca")


# ==================== API Models ====================

class KeyExchangeStep1Request(BaseModel):
    """Step 1: Repetitor sends Kyber public key."""
    repetitor_id: str
    repetitor_url: str
    kyber_public_key: str  # base64 encoded


class KeyExchangeStep1Response(BaseModel):
    """Step 1 response: Controller sends its Kyber public key and encapsulation."""
    kyber_public_key: str  # base64 - controller's public key
    kyber_ciphertext: str  # base64 - encapsulation to repetitor's key
    nonce: str  # hex


class KeyExchangeStep2Request(BaseModel):
    """Step 2: Repetitor sends encapsulation to controller and encrypted attestation."""
    repetitor_id: str
    kyber_ciphertext: str  # base64 - encapsulation to controller's key
    encrypted_payload: str  # AES encrypted { attestation, commitment }


class EncryptedRequest(BaseModel):
    """Generic encrypted request."""
    encrypted_payload: str


# ==================== API Endpoints ====================

@application.post("/key_exchange_step1")
async def key_exchange_step1(request: KeyExchangeStep1Request) -> KeyExchangeStep1Response:
    """
    Step 1 of mutual Kyber key exchange.
    
    Repetitor sends: { rep_id, rep_url, kyber_pk_rep }
    Controller returns: { kyber_pk_ctrl, kyber_ct_rep, nonce }
    """
    try:
        repetitor_id = request.repetitor_id
        kyber_pk_rep = base64.b64decode(request.kyber_public_key)
        
        print(f"[{repetitor_id}] Key exchange step 1 - received Kyber public key")
        
        # Generate controller's Kyber keypair
        kyber_pk_ctrl, kyber_sk_ctrl = kyber_generate_keypair()
        
        # Encapsulate to repetitor's public key
        kyber_ct_rep, ss1 = kyber_encapsulate(kyber_pk_rep)
        
        # Generate nonce
        nonce = os.urandom(32)
        
        # Calculate expected commitment
        commitment = hashlib.sha256(kyber_pk_rep + repetitor_id.encode()).hexdigest()
        
        # Store session data
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
        
        print(f"[{repetitor_id}] Generated controller keypair and encapsulated")
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
    """
    Step 2 of mutual Kyber key exchange.
    
    Repetitor sends: { kyber_ct_ctrl, AES(attestation + commitment) }
    Controller verifies attestation and commitment, completes key derivation.
    """
    try:
        repetitor_id = request.repetitor_id
        kyber_ct_ctrl = base64.b64decode(request.kyber_ciphertext)
        
        async with sessions_lock:
            if repetitor_id not in SESSIONS:
                raise HTTPException(status_code=400, detail="No session found - call step1 first")
            session = SESSIONS[repetitor_id]
        
        # Decapsulate to get ss2
        ss2 = kyber_decapsulate(session.kyber_sk_ctrl, kyber_ct_ctrl)
        session.ss2 = ss2
        
        # Derive shared key
        shared_key = derive_shared_key(session.ss1, ss2)
        session.shared_key = shared_key
        
        # Decrypt attestation payload
        try:
            decrypted = aes_decrypt(request.encrypted_payload, shared_key)
            payload = json.loads(decrypted)
        except Exception as e:
            print(f"[{repetitor_id}] Decryption failed: {e}")
            raise HTTPException(status_code=400, detail="Decryption failed")
        
        attestation_report = payload.get("attestation_report", "")
        commitment = payload.get("commitment", "")
        
        # Verify commitment (proves repetitor owns the Kyber key)
        if commitment != session.commitment:
            print(f"[{repetitor_id}] Commitment mismatch!")
            print(f"  Expected: {session.commitment}")
            print(f"  Received: {commitment}")
            raise HTTPException(status_code=400, detail="Commitment verification failed")
        
        print(f"[{repetitor_id}] Commitment verified")
        
        # Verify attestation (placeholder - in real system, verify enclave attestation)
        # The attestation should bind the Kyber public key to the enclave
        print(f"[{repetitor_id}] Attestation received (verification placeholder)")
        
        session.authenticated = True
        
        # Register repetitor
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
        
        # Notify waiting tasks
        async with configuration_condition:
            configuration_condition.notify_all()
        
        # Return encrypted acknowledgment
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
    """
    Get configuration (encrypted with session key).
    Blocks until all repetitors have registered.
    """
    try:
        # Find session by trying to decrypt
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
        
        print(f"[{repetitor_id}] Configuration request received")
        
        # Wait for all repetitors
        print(f"[{repetitor_id}] Waiting for all repetitors...")
        async with configuration_condition:
            while any(r is None for r in REPETITORS):
                status = [r['repetitor_id'] if r else None for r in REPETITORS]
                print(f"[{repetitor_id}] Still waiting... REPETITORS = {status}")
                await configuration_condition.wait()
        
        print(f"[{repetitor_id}] All repetitors registered!")
        
        # Find index
        index = None
        for i, rep in enumerate(REPETITORS):
            if rep and rep["repetitor_id"] == repetitor_id:
                index = i
                break
        
        if index is None:
            raise HTTPException(status_code=400, detail="Repetitor not found")
        
        print(f"[{repetitor_id}] Configuration index: {index}")
        
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
            "whitelist": "|".join([r["repetitor_id"] for r in REPETITORS if r and r["repetitor_id"] != repetitor_id] + ["test_client"]),
            # Include CA certificate for repetitor-to-repetitor verification
            "ca_certificate": CA_CERTIFICATE
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
    Sign ML-DSA CSRs and return certificates.
    """
    try:
        if CA_PRIVATE_KEY is None:
            raise HTTPException(status_code=500, detail="CA not configured")
        
        # Find session
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
        
        # Extract CSRs (JSON format with subject_cn and public_key)
        left_csr = payload.get("left_csr", {})
        right_csr = payload.get("right_csr", {})
        repetitor_csr = payload.get("repetitor_csr", {})
        
        print(f"[{repetitor_id}] Signing certificates...")
        
        # Sign CSRs
        loop = asyncio.get_event_loop()
        left_cert = await loop.run_in_executor(None, sign_csr, left_csr)
        right_cert = await loop.run_in_executor(None, sign_csr, right_csr)
        repetitor_cert = await loop.run_in_executor(None, sign_csr, repetitor_csr)
        
        if not all([left_cert, right_cert, repetitor_cert]):
            raise HTTPException(status_code=500, detail="Failed to sign certificates")
        
        response = {
            "left_certificate": left_cert,
            "right_certificate": right_cert,
            "repetitor_certificate": repetitor_cert
        }
        
        response_json = json.dumps(response)
        encrypted_response = aes_encrypt(response_json, session.shared_key)
        
        print(f"[{repetitor_id}] Certificates signed and sent")
        
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
        "ca_loaded": CA_PRIVATE_KEY is not None,
        "kyber_algorithm": KYBER_ALGORITHM,
        "signature_algorithm": DILITHIUM_ALGORITHM
    }


# ==================== Main ====================

def main():
    parser = argparse.ArgumentParser(description="QKD Relay PQC Controller")
    parser.add_argument("--ca-cert", default=CA_CERT_PATH, help="Path to CA certificate")
    parser.add_argument("--ca-key", default=CA_KEY_PATH, help="Path to CA private key")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")
    parser.add_argument("--port", type=int, default=8000, help="Port to bind to")
    
    args = parser.parse_args()
    
    global CA_CERT_PATH, CA_KEY_PATH
    CA_CERT_PATH = args.ca_cert
    CA_KEY_PATH = args.ca_key
    
    # Load CA credentials
    if os.path.exists(CA_CERT_PATH) and os.path.exists(CA_KEY_PATH):
        load_ca_credentials(CA_CERT_PATH, CA_KEY_PATH)
    else:
        print(f"Error: CA files not found")
        print(f"  Certificate: {CA_CERT_PATH}")
        print(f"  Private key: {CA_KEY_PATH}")
        print(f"\nGenerate with: python generate_pqc_ca.py --output-dir ./pqc_ca")
        sys.exit(1)
    
    import uvicorn
    uvicorn.run(application, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
