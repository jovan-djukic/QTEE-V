#!/usr/bin/env python3
"""
QKD Relay Repetitor - Post-Quantum Cryptography Version (Python)

This repetitor implements:
1. Mutual Kyber-768 key exchange with controller
2. ML-DSA-65 certificates for mTLS
3. Kyber-based TLS for repetitor-to-repetitor communication (future)

Protocol:
  Step 1: Generate Kyber keypair, send public key to controller
  Step 2: Receive controller's Kyber public key and ciphertext, decapsulate
  Step 3: Encapsulate to controller's key, derive shared secret
  Step 4: Send encrypted attestation with commitment
  Step 5: Get configuration, generate ML-DSA keys, get certificates
"""

import binascii
import hashlib
import hmac
import json
import socket
import ssl
import sys
import os
import tempfile
import base64
import re
import requests
from typing import Tuple, Union, Optional, Dict, Any
from datetime import datetime
from threading import Thread, Semaphore

try:
    import oqs
except ImportError:
    print("Error: liboqs-python not installed")
    print("Install with: pip install liboqs-python")
    sys.exit(1)

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa


# ==================== Configuration ====================

HOST = "127.0.0.1"
CONTROLLER_HOST = "127.0.0.1"
CONTROLLER_PORT = "8000"
KME_PORT = "443"

# Algorithm names
KYBER_ALGORITHM = "Kyber768"
DILITHIUM_ALGORITHM = "Dilithium3"

# QKD CA certificate (for KME communication - remains RSA)
QKD_CA_CERTIFICATE = """-----BEGIN CERTIFICATE-----
MIIDbTCCAlWgAwIBAgIQCzuhkEQXTouuETnIFrtF1jANBgkqhkiG9w0BAQsFADBn
MSwwKgYDVQQDDCNhY2N0LTI1NjMuZXRzaS1xa2QtYXBpLnF1a2F5ZGVlLmNvbTEe
MBwGA1UECgwVUXVLYXlEZWUgYWNjb3VudCAyNTYzMRcwFQYDVQQLDA5TZXJ2ZXIg
cm9vdCBDQTAgFw0yNTA1MjYwODMxMzlaGA8yMTI1MDUwMzA4MzEzOVowZzEsMCoG
A1UEAwwjYWNjdC0yNTYzLmV0c2ktcWtkLWFwaS5xdWtheWRlZS5jb20xHjAcBgNV
BAoMFVF1S2F5RGVlIGFjY291bnQgMjU2MzEXMBUGA1UECwwOU2VydmVyIHJvb3Qg
Q0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC6fv8Hp8hL7P6Rs3Zc
X3oHL6hEXbx5hmSPLFvSIpLnF1iZepdlJtXJiq2oVZNcdtDgnYA5ugl6CGQE8v3A
79hxrWOSSfysYryoIBBYSvaEPEN16TSKcY7+cAnSU8fu736uRhKwz2jeJw2g+4pb
lcmsJhLq40F23Px+XkpA99DPIGHWWy2ZelcddnP1M99/l937V2AvGaM+P71NMS9a
F/K/2iiDOiAQ3XZXVIjmsdSMHth2780U80wiAaH2PsOILMbKNLdxDLYIJa5awmXY
1D8Dik9Ot7e0It+ZfdaXxUHBxnTj7CgajqhOvd78p2PCwMhZ61DO+5subpzhywxE
t92/AgMBAAGjEzARMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEB
AAuWsi3TFKGn1H6raS0aSw6JqE5c/PUMGRTBDzmSpIUMjnaG/9Ise1SGxujAYvpm
ahExKKFkgTuSV4GmYL1n4Yakls3sr9hbP40L2wJLus+psfGKsN+Xa3hwyFrQVyKY
dNpIH+AIhH/nI2WKyYnhv0dE2PR/UzR3AtCum/uu8C2JnY0qnBlQ3ooOopti0+MK
zEHJBAK2jxm9vjEgHs+zHKIxOiuCM6jmPZsG4PdBWkcf1C6Coof0kfO3vednsE/B
0Q1c9TemcUbH6OR0kDxJFV/Alsim2wolJ722QOlBB2+m88POeSqN9JLxcj3pQe53
wkKhllHrkuVRW7pw4wXXn8w=
-----END CERTIFICATE-----"""

# PQC CA certificate (loaded from configuration)
PQC_CA_CERTIFICATE: Optional[str] = None


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

def mldsa_generate_keypair() -> Tuple[bytes, bytes]:
    """Generate ML-DSA-65 keypair. Returns (public_key, private_key)."""
    signer = oqs.Signature(DILITHIUM_ALGORITHM)
    public_key = signer.generate_keypair()
    private_key = signer.export_secret_key()
    return public_key, private_key


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
    
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext.encode()) + padder.finalize()
    
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    return base64.b64encode(iv + ciphertext).decode('ascii')


def aes_decrypt(ciphertext_b64: str, key: bytes) -> str:
    """Decrypt AES-256-CBC from base64(IV + ciphertext)."""
    data = base64.b64decode(ciphertext_b64)
    iv = data[:16]
    ciphertext = data[16:]
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded) + unpadder.finalize()
    
    return plaintext.decode()


# ==================== Attestation ====================

def get_attestation_report(nonce: str, kyber_pk: bytes) -> str:
    """
    Generate attestation report binding nonce and Kyber public key.
    In real implementation, this would be an enclave attestation.
    """
    data = nonce.encode() + kyber_pk
    report_hash = hashlib.sha256(data).hexdigest()
    return f"attestation_report:{report_hash}"


# ==================== Secure Configuration Protocol ====================

def get_configuration_pqc(
    controller_host: str,
    controller_port: str,
    repetitor_id: str,
    repetitor_url: str
) -> Dict[str, Any]:
    """
    Get configuration using PQC mutual Kyber key exchange.
    """
    base_url = f"http://{controller_host}:{controller_port}"
    
    # ===== Step 1: Key Exchange - Send our Kyber public key =====
    print(f"[DEBUG] Generating Kyber-768 keypair...")
    kyber_pk, kyber_sk = kyber_generate_keypair()
    print(f"[DEBUG]   Public key size: {len(kyber_pk)} bytes")
    
    print(f"[DEBUG] Sending Kyber public key to controller...")
    step1_response = requests.post(
        f"{base_url}/key_exchange_step1",
        json={
            "repetitor_id": repetitor_id,
            "repetitor_url": repetitor_url,
            "kyber_public_key": base64.b64encode(kyber_pk).decode()
        },
        timeout=30
    )
    step1_response.raise_for_status()
    step1_data = step1_response.json()
    
    # Parse controller's response
    kyber_pk_ctrl = base64.b64decode(step1_data["kyber_public_key"])
    kyber_ct_rep = base64.b64decode(step1_data["kyber_ciphertext"])
    nonce = step1_data["nonce"]
    
    print(f"[DEBUG] Received controller's Kyber public key and ciphertext")
    print(f"[DEBUG] Nonce: {nonce}")
    
    # ===== Step 2: Decapsulate and encapsulate =====
    print(f"[DEBUG] Decapsulating controller's ciphertext...")
    ss1 = kyber_decapsulate(kyber_sk, kyber_ct_rep)
    
    print(f"[DEBUG] Encapsulating to controller's public key...")
    kyber_ct_ctrl, ss2 = kyber_encapsulate(kyber_pk_ctrl)
    
    # Derive shared key
    shared_key = derive_shared_key(ss1, ss2)
    print(f"[DEBUG] Derived shared key")
    
    # ===== Step 3: Send encrypted attestation with commitment =====
    attestation_report = get_attestation_report(nonce, kyber_pk)
    commitment = hashlib.sha256(kyber_pk + repetitor_id.encode()).hexdigest()
    
    attestation_payload = json.dumps({
        "attestation_report": attestation_report,
        "commitment": commitment
    })
    encrypted_attestation = aes_encrypt(attestation_payload, shared_key)
    
    print(f"[DEBUG] Sending attestation and commitment...")
    step2_response = requests.post(
        f"{base_url}/key_exchange_step2",
        json={
            "repetitor_id": repetitor_id,
            "kyber_ciphertext": base64.b64encode(kyber_ct_ctrl).decode(),
            "encrypted_payload": encrypted_attestation
        },
        timeout=30
    )
    step2_response.raise_for_status()
    
    # Verify acknowledgment
    step2_data = step2_response.json()
    ack_json = aes_decrypt(step2_data["encrypted_response"], shared_key)
    ack = json.loads(ack_json)
    
    if ack.get("status") != "authenticated":
        raise RuntimeError("Authentication failed")
    
    print(f"[DEBUG] Authenticated with controller")
    
    # ===== Step 4: Request configuration =====
    print(f"[DEBUG] Requesting configuration...")
    config_request = json.dumps({"repetitor_id": repetitor_id})
    encrypted_config_request = aes_encrypt(config_request, shared_key)
    
    config_response = requests.post(
        f"{base_url}/configuration",
        json={"encrypted_payload": encrypted_config_request},
        timeout=120  # May block waiting for other repetitors
    )
    config_response.raise_for_status()
    
    config_data = config_response.json()
    config_json = aes_decrypt(config_data["encrypted_response"], shared_key)
    configuration = json.loads(config_json)
    
    print(f"[DEBUG] Received configuration")
    
    # Store CA certificate for later use
    global PQC_CA_CERTIFICATE
    PQC_CA_CERTIFICATE = configuration.get("ca_certificate")
    
    # ===== Step 5: Generate ML-DSA keys and request certificates =====
    print(f"[DEBUG] Generating ML-DSA-65 keypairs...")
    left_pk, left_sk = mldsa_generate_keypair()
    right_pk, right_sk = mldsa_generate_keypair()
    repetitor_pk, repetitor_sk = mldsa_generate_keypair()
    
    # Create CSR-like structures
    csrs = {
        "repetitor_id": repetitor_id,
        "left_csr": {
            "subject_cn": configuration["left_cn"],
            "public_key": base64.b64encode(left_pk).decode()
        },
        "right_csr": {
            "subject_cn": configuration["right_cn"],
            "public_key": base64.b64encode(right_pk).decode()
        },
        "repetitor_csr": {
            "subject_cn": repetitor_id,
            "public_key": base64.b64encode(repetitor_pk).decode()
        }
    }
    
    print(f"[DEBUG] Requesting certificates...")
    cert_request = json.dumps(csrs)
    encrypted_cert_request = aes_encrypt(cert_request, shared_key)
    
    cert_response = requests.post(
        f"{base_url}/generate_certificates",
        json={"encrypted_payload": encrypted_cert_request},
        timeout=30
    )
    cert_response.raise_for_status()
    
    cert_data = cert_response.json()
    certs_json = aes_decrypt(cert_data["encrypted_response"], shared_key)
    certificates = json.loads(certs_json)
    
    print(f"[DEBUG] Received all certificates")
    
    return {
        "configuration": configuration,
        "left_private_key": left_sk,
        "left_public_key": left_pk,
        "left_certificate": certificates["left_certificate"],
        "right_private_key": right_sk,
        "right_public_key": right_pk,
        "right_certificate": certificates["right_certificate"],
        "repetitor_private_key": repetitor_sk,
        "repetitor_public_key": repetitor_pk,
        "repetitor_certificate": certificates["repetitor_certificate"]
    }


# ==================== RSA Key/CSR Generation (for KME) ====================

def build_rsa_key() -> rsa.RSAPrivateKey:
    """Generate RSA-2048 key for KME communication."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def build_rsa_csr(key: rsa.RSAPrivateKey, common_name: str) -> bytes:
    """Build RSA CSR for KME communication."""
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(common_name)]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.PEM)


# ==================== KME Communication (RSA-based, unchanged) ====================

def kme_get_status(
    private_key: rsa.RSAPrivateKey,
    certificate: str,
    ca_certificate: str,
    kme_host: str,
    kme_port: str,
    kme_slave: str
):
    """Get status from KME using RSA mTLS."""
    url = f"https://{kme_host}:{kme_port}/api/v1/keys/{kme_slave}/status"
    
    key_pem = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=NoEncryption()
    )
    
    with tempfile.NamedTemporaryFile() as cert_file, \
         tempfile.NamedTemporaryFile() as key_file, \
         tempfile.NamedTemporaryFile() as ca_file:
        
        cert_file.write(certificate.encode("utf-8"))
        key_file.write(key_pem)
        ca_file.write(ca_certificate.encode("utf-8"))
        
        cert_file.flush()
        key_file.flush()
        ca_file.flush()
        
        response = requests.get(
            url=url,
            cert=(cert_file.name, key_file.name),
            verify=ca_file.name
        )
    
    return response


def kme_get_key(
    private_key: rsa.RSAPrivateKey,
    certificate: str,
    ca_certificate: str,
    kme_host: str,
    kme_port: str,
    kme_slave: str
):
    """Get encryption key from KME."""
    url = f"https://{kme_host}:{kme_port}/api/v1/keys/{kme_slave}/enc_keys"
    
    key_pem = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=NoEncryption()
    )
    
    with tempfile.NamedTemporaryFile() as cert_file, \
         tempfile.NamedTemporaryFile() as key_file, \
         tempfile.NamedTemporaryFile() as ca_file:
        
        cert_file.write(certificate.encode("utf-8"))
        key_file.write(key_pem)
        ca_file.write(ca_certificate.encode("utf-8"))
        
        cert_file.flush()
        key_file.flush()
        ca_file.flush()
        
        response = requests.get(
            url=url,
            cert=(cert_file.name, key_file.name),
            verify=ca_file.name
        )
    
    return response.json()


def kme_get_key_with_id(
    private_key: rsa.RSAPrivateKey,
    certificate: str,
    ca_certificate: str,
    kme_host: str,
    kme_port: str,
    kme_master: str,
    key_id: str
):
    """Get decryption key from KME by ID."""
    url = f"https://{kme_host}:{kme_port}/api/v1/keys/{kme_master}/dec_keys?key_ID={key_id}"
    
    key_pem = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=NoEncryption()
    )
    
    with tempfile.NamedTemporaryFile() as cert_file, \
         tempfile.NamedTemporaryFile() as key_file, \
         tempfile.NamedTemporaryFile() as ca_file:
        
        cert_file.write(certificate.encode("utf-8"))
        key_file.write(key_pem)
        ca_file.write(ca_certificate.encode("utf-8"))
        
        cert_file.flush()
        key_file.flush()
        ca_file.flush()
        
        response = requests.get(
            url=url,
            cert=(cert_file.name, key_file.name),
            verify=ca_file.name
        )
    
    return response.json()


# ==================== Message Encryption (QKD keys) ====================

def derive_keys(master_key: bytes) -> Tuple[bytes, bytes]:
    """Derive AES and HMAC keys from master key."""
    aes_key = hashlib.sha256(master_key).digest()
    hmac_ctx = hashlib.sha256()
    hmac_ctx.update(master_key)
    hmac_ctx.update(b"Mac")
    hmac_key = hmac_ctx.digest()
    return aes_key, hmac_key


def decode_master_key(text: str) -> bytes:
    """Decode master key from hex or base64."""
    stripped = text.strip()
    if len(stripped) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in stripped):
        return binascii.unhexlify(stripped)
    else:
        return base64.b64decode(stripped)


def encrypt_message(plaintext: Union[str, bytes], key_text: str) -> str:
    """Encrypt message with QKD key."""
    if isinstance(plaintext, str):
        plaintext = plaintext.encode("utf-8")
    
    master_key = decode_master_key(key_text)
    aes_key, hmac_key = derive_keys(master_key)
    
    iv = os.urandom(16)
    iv_hex = binascii.hexlify(iv).decode("ascii")
    
    # AES-CBC encrypt
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    ciphertext_b64 = base64.b64encode(ciphertext).decode("ascii")
    
    # HMAC
    tag = hmac.new(hmac_key, ciphertext_b64.encode("ascii"), hashlib.sha256).digest()
    tag_hex = binascii.hexlify(tag).decode("ascii")
    
    blob_raw = (iv_hex + ciphertext_b64 + tag_hex).encode("ascii")
    return base64.b64encode(blob_raw).decode("ascii")


def decrypt_message(blob_base64: str, key_text: str) -> bytes:
    """Decrypt message with QKD key."""
    master_key = decode_master_key(key_text)
    aes_key, hmac_key = derive_keys(master_key)
    
    blob = base64.b64decode(blob_base64).decode("ascii")
    
    iv_hex = blob[:32]
    tag_hex = blob[-64:]
    ciphertext_b64 = blob[32:-64]
    
    # Verify HMAC
    calculated_tag = hmac.new(hmac_key, ciphertext_b64.encode("ascii"), hashlib.sha256).digest()
    calculated_tag_hex = binascii.hexlify(calculated_tag).decode("ascii")
    
    if not hmac.compare_digest(calculated_tag_hex, tag_hex.lower()):
        raise ValueError("HMAC mismatch")
    
    # Decrypt
    iv = binascii.unhexlify(iv_hex)
    ciphertext = base64.b64decode(ciphertext_b64)
    
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded) + unpadder.finalize()
    
    return plaintext


# ==================== Main ====================

def main(repetitor_id: str, port: int, print_semaphore: Semaphore) -> None:
    """Main function for repetitor."""
    
    # Get configuration using PQC protocol
    result = get_configuration_pqc(
        CONTROLLER_HOST,
        CONTROLLER_PORT,
        repetitor_id,
        f"127.0.0.1:{port}"
    )
    
    configuration = result["configuration"]
    
    print_semaphore.acquire()
    print(f"[{datetime.now():%H:%M:%S}][{repetitor_id}] configuration received:")
    print(json.dumps({k: v for k, v in configuration.items() if k != "ca_certificate"}, indent=4))
    print_semaphore.release()
    
    # PQC keys and certificates (for repetitor-to-repetitor - to be implemented)
    left_pqc_sk = result["left_private_key"]
    left_pqc_pk = result["left_public_key"]
    left_pqc_cert = result["left_certificate"]
    
    right_pqc_sk = result["right_private_key"]
    right_pqc_pk = result["right_public_key"]
    right_pqc_cert = result["right_certificate"]
    
    repetitor_pqc_sk = result["repetitor_private_key"]
    repetitor_pqc_pk = result["repetitor_public_key"]
    repetitor_pqc_cert = result["repetitor_certificate"]
    
    # Extract configuration values
    left_kme = configuration["left_kme"]
    right_kme = configuration["right_kme"]
    left_cn = configuration["left_cn"]
    right_cn = configuration["right_cn"]
    left_kme_peer = configuration["left_kme_peer"]
    right_kme_peer = configuration["right_kme_peer"]
    whitelist = [item.strip() for item in configuration["whitelist"].split("|")]
    
    left_repetitor_url = configuration["left_repetitor_url"]
    right_repetitor_url = configuration["right_repetitor_url"]
    left_repetitor_id = configuration["left_repetitor_id"]
    right_repetitor_id = configuration["right_repetitor_id"]
    
    # Determine position
    position = "left" if left_kme == "" else ("right" if right_kme == "" else "middle")
    
    print_semaphore.acquire()
    print(f"[{datetime.now():%H:%M:%S}][{repetitor_id}] position: {position}")
    print(f"[{datetime.now():%H:%M:%S}][{repetitor_id}] PQC certificates received")
    print(f"[{datetime.now():%H:%M:%S}][{repetitor_id}]   Left cert CN: {left_cn}")
    print(f"[{datetime.now():%H:%M:%S}][{repetitor_id}]   Right cert CN: {right_cn}")
    print(f"[{datetime.now():%H:%M:%S}][{repetitor_id}]   Repetitor cert CN: {repetitor_id}")
    print_semaphore.release()
    
    # Note: For KME communication, we still need RSA certificates
    # This would require a separate certificate request to a traditional CA
    # or the controller could also provide RSA certificates for KME
    
    print_semaphore.acquire()
    print(f"[{datetime.now():%H:%M:%S}][{repetitor_id}] Ready for operation")
    print(f"[{datetime.now():%H:%M:%S}][{repetitor_id}]   (KME communication requires separate RSA certificates)")
    print_semaphore.release()
    
    # Main loop would go here
    # For now, just wait
    print(f"[{datetime.now():%H:%M:%S}][{repetitor_id}] Standing by...")


if __name__ == "__main__":
    print_semaphore = Semaphore(1)
    
    # Default: run repetitors 0 and 2
    repetitor_indices = [0, 1, 2]
    
    if len(sys.argv) > 1:
        repetitor_indices = [int(arg) for arg in sys.argv[1:]]
    
    for i in repetitor_indices:
        thread = Thread(
            target=main,
            args=(f"DR{i}", 9000 + i, print_semaphore)
        )
        thread.start()
