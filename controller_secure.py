"""
QKD Relay Controller - Secure Communication Protocol

This controller implements:
1. RSA decryption of initial key exchange using CA private key
2. AES symmetric encryption for all subsequent communication
3. Certificate generation via CFSSL
4. Blocking configuration until all repetitors have registered

FIXED: Uses asyncio primitives instead of threading to avoid blocking the event loop.
FIXED: Removed manual newline escaping - json.dumps handles it correctly.
"""

from typing import Union, Dict, Optional
from fastapi import FastAPI, HTTPException, Response, Request
from pydantic import BaseModel
import socket
from urllib.parse import urlsplit
import asyncio
import base64
import os
import json
import httpx
from cryptography.hazmat.primitives import serialization, hashes, padding as sym_padding
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import load_pem_x509_certificate

application = FastAPI()

# Configuration
PYTHON_URL = "127.0.0.1"
RISCV_URL = "192.168.100.2"
CFSSL_URL = "http://127.0.0.1:8888"

# CA Certificate and Private Key paths
CA_CERT_PATH = "./cfssl/client-root-ca.crt"
CA_KEY_PATH = "./cfssl/client-root-ca.key"

# Load CA private key for RSA decryption
CA_PRIVATE_KEY = None
CA_CERTIFICATE = None

def load_ca_credentials():
    """Load CA certificate and private key from files or environment."""
    global CA_PRIVATE_KEY, CA_CERTIFICATE
    
    ca_key_env = os.environ.get("CA_PRIVATE_KEY_PEM")
    ca_cert_env = os.environ.get("CA_CERTIFICATE_PEM")
    
    if ca_key_env:
        CA_PRIVATE_KEY = serialization.load_pem_private_key(
            ca_key_env.encode() if isinstance(ca_key_env, str) else ca_key_env,
            password=None,
            backend=default_backend()
        )
    elif os.path.exists(CA_KEY_PATH):
        with open(CA_KEY_PATH, "rb") as f:
            CA_PRIVATE_KEY = serialization.load_pem_private_key(
                f.read(), password=None, backend=default_backend()
            )
    
    if ca_cert_env:
        CA_CERTIFICATE = load_pem_x509_certificate(
            ca_cert_env.encode() if isinstance(ca_cert_env, str) else ca_cert_env,
            default_backend()
        )
    elif os.path.exists(CA_CERT_PATH):
        with open(CA_CERT_PATH, "rb") as f:
            CA_CERTIFICATE = load_pem_x509_certificate(f.read(), default_backend())

# Initialize CA credentials
try:
    load_ca_credentials()
except Exception as e:
    print(f"Warning: Could not load CA credentials: {e}")

# Data storage
NONCE_DICTIONARY: Dict[str, bytes] = {}
SYMMETRIC_KEYS: Dict[str, bytes] = {}

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

REPETITORS = [None, None, None]

# Async locks and condition - created at startup
nonce_lock: asyncio.Lock = None
symmetric_keys_lock: asyncio.Lock = None
repetitors_lock: asyncio.Lock = None
configuration_condition: asyncio.Condition = None


@application.on_event("startup")
async def startup_event():
    """Initialize async primitives on startup."""
    global nonce_lock, symmetric_keys_lock, repetitors_lock, configuration_condition
    nonce_lock = asyncio.Lock()
    symmetric_keys_lock = asyncio.Lock()
    repetitors_lock = asyncio.Lock()
    configuration_condition = asyncio.Condition()
    print("Async locks initialized")


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


def rsa_decrypt(encrypted_b64: str) -> bytes:
    """Decrypt RSA-encrypted data using CA private key."""
    if CA_PRIVATE_KEY is None:
        raise ValueError("CA private key not loaded")
    
    encrypted = base64.b64decode(encrypted_b64)
    return CA_PRIVATE_KEY.decrypt(
        encrypted,
        padding.PKCS1v15()
    )


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


def unescape_json_string(s: str) -> str:
    """Unescape JSON string escape sequences."""
    # Handle common JSON escape sequences
    result = s.replace("\\n", "\n")
    result = result.replace("\\r", "\r")
    result = result.replace("\\t", "\t")
    result = result.replace('\\"', '"')
    result = result.replace("\\\\", "\\")
    return result


def sign_csr_with_cfssl(csr_pem: str) -> Optional[str]:
    """Sign a CSR using CFSSL service (synchronous)."""
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


class EncryptedRequest(BaseModel):
    encrypted_payload: str


@application.post("/get_nonce")
async def get_nonce(request: EncryptedRequest):
    """
    Phase 1: Receive RSA-encrypted payload with repetitor_id and symmetric_key.
    Returns AES-encrypted nonce.
    """
    try:
        decrypted = rsa_decrypt(request.encrypted_payload)
        payload = json.loads(decrypted.decode())
        
        repetitor_id = payload.get("repetitor_id")
        symmetric_key_b64 = payload.get("symmetric_key")
        repetitor_url = payload.get("repetitor_url", "")
        
        if not repetitor_id or not symmetric_key_b64:
            raise HTTPException(status_code=400, detail="Missing required fields")
        
        symmetric_key = base64.b64decode(symmetric_key_b64)
        if len(symmetric_key) != 32:
            raise HTTPException(status_code=400, detail="Invalid symmetric key size")
        
        async with symmetric_keys_lock:
            SYMMETRIC_KEYS[repetitor_id] = symmetric_key
        
        nonce = os.urandom(32)
        async with nonce_lock:
            NONCE_DICTIONARY[repetitor_id] = nonce
        
        # Register repetitor
        async with repetitors_lock:
            try:
                index = int(repetitor_id[-1])
                if 0 <= index < len(REPETITORS):
                    REPETITORS[index] = {
                        "repetitor_id": repetitor_id,
                        "repetitor_port": repetitor_url.split(":")[-1] if ":" in repetitor_url else "9001",
                    }
                    print(f"[{repetitor_id}] Registered in get_nonce (index {index})")
            except (ValueError, IndexError) as e:
                print(f"[{repetitor_id}] Could not parse index: {e}")
        
        # Notify waiting tasks that a new repetitor registered
        async with configuration_condition:
            configuration_condition.notify_all()
        
        print(f"[{repetitor_id}] Generated nonce: {nonce.hex()}")
        
        response_json = json.dumps({"nonce": nonce.hex()})
        encrypted_response = aes_encrypt(response_json, symmetric_key)
        
        return {"encrypted_response": encrypted_response}
        
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON in payload")
    except Exception as e:
        print(f"Error in get_nonce: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@application.post("/configuration")
async def get_configuration(request: EncryptedRequest):
    """
    Phase 2: Receive AES-encrypted attestation report.
    Returns AES-encrypted configuration. Blocks until all repetitors registered.
    """
    try:
        payload = None
        repetitor_id = None
        symmetric_key = None
        
        async with symmetric_keys_lock:
            keys_copy = dict(SYMMETRIC_KEYS)
        
        for rid, key in keys_copy.items():
            try:
                decrypted = aes_decrypt(request.encrypted_payload, key)
                payload = json.loads(decrypted)
                if payload.get("repetitor_id") == rid:
                    repetitor_id = rid
                    symmetric_key = key
                    break
            except:
                continue
        
        if payload is None or repetitor_id is None:
            raise HTTPException(status_code=400, detail="Could not decrypt payload")
        
        attestation_report = payload.get("attestation_report")
        print(f"[{repetitor_id}] Attestation report received")
        
        # Wait for all repetitors using async condition (does NOT block event loop)
        print(f"[{repetitor_id}] Waiting for all repetitors...")
        async with configuration_condition:
            while any(r is None for r in REPETITORS):
                status = [r['repetitor_id'] if r else None for r in REPETITORS]
                print(f"[{repetitor_id}] Still waiting... REPETITORS = {status}")
                await configuration_condition.wait()
        
        print(f"[{repetitor_id}] All repetitors registered!")
        
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
            "whitelist": "|".join([r["repetitor_id"] for r in REPETITORS if r and r["repetitor_id"] != repetitor_id] + ["test_client"])
        }
        
        configuration["left_kme_url"] = url_to_ipv4(configuration["left_kme"]) if configuration["left_kme"] else ""
        configuration["right_kme_url"] = url_to_ipv4(configuration["right_kme"]) if configuration["right_kme"] else ""
        
        response_json = json.dumps(configuration)
        encrypted_response = aes_encrypt(response_json, symmetric_key)
        
        return {"encrypted_response": encrypted_response}
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error in configuration: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@application.post("/generate_certificates")
async def generate_certificates(request: EncryptedRequest):
    """
    Phase 3: Receive AES-encrypted CSRs.
    Returns AES-encrypted signed certificates.
    """
    try:
        payload = None
        repetitor_id = None
        symmetric_key = None
        
        async with symmetric_keys_lock:
            keys_copy = dict(SYMMETRIC_KEYS)
        
        for rid, key in keys_copy.items():
            try:
                decrypted = aes_decrypt(request.encrypted_payload, key)
                payload = json.loads(decrypted)
                if payload.get("repetitor_id") == rid:
                    repetitor_id = rid
                    symmetric_key = key
                    break
            except:
                continue
        
        if payload is None or repetitor_id is None:
            raise HTTPException(status_code=400, detail="Could not decrypt payload")
        
        # CSRs come with escaped newlines from C code - unescape them
        left_csr = unescape_json_string(payload.get("left_csr", ""))
        right_csr = unescape_json_string(payload.get("right_csr", ""))
        repetitor_csr = unescape_json_string(payload.get("repetitor_csr", ""))
        
        print(f"[{repetitor_id}] Signing certificates...")
        
        # Sign CSRs with CFSSL (run in thread pool to not block)
        loop = asyncio.get_event_loop()
        left_cert = await loop.run_in_executor(None, sign_csr_with_cfssl, left_csr)
        right_cert = await loop.run_in_executor(None, sign_csr_with_cfssl, right_csr)
        repetitor_cert = await loop.run_in_executor(None, sign_csr_with_cfssl, repetitor_csr)
        
        if not all([left_cert, right_cert, repetitor_cert]):
            raise HTTPException(status_code=500, detail="Failed to sign certificates")
        
        # DO NOT manually escape newlines - json.dumps handles it correctly!
        # json.dumps will convert \n to \n in JSON (backslash-n)
        # The C code's extract_field_from_json handles \n -> newline
        response = {
            "left_certificate": left_cert,
            "right_certificate": right_cert,
            "repetitor_certificate": repetitor_cert
        }
        
        response_json = json.dumps(response)
        encrypted_response = aes_encrypt(response_json, symmetric_key)
        
        print(f"[{repetitor_id}] Certificates signed and sent")
        
        return {"encrypted_response": encrypted_response}
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error in generate_certificates: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# Legacy endpoints for backward compatibility
@application.get("/get_nonce")
async def legacy_get_nonce(repetitor_id: Union[str, None] = None):
    """Legacy endpoint - returns unencrypted nonce."""
    if repetitor_id is None:
        raise HTTPException(status_code=400, detail="Missing repetitor ID")
    
    nonce = os.urandom(32)
    async with nonce_lock:
        NONCE_DICTIONARY[repetitor_id] = nonce
    
    print(f"[{repetitor_id}] Generated nonce (legacy): {nonce.hex()}")
    return Response(content=nonce, media_type="application/octet-stream")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(application, host="0.0.0.0", port=8000)
