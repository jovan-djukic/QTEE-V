#!/usr/bin/env python3
"""
QKD Relay Repetitor - Hybrid PQC/RSA Version

This repetitor implements:
1. Mutual Kyber-768 key exchange with controller
2. PQC channel (Kyber + ML-DSA) for repetitor ↔ repetitor communication
3. RSA-2048 mTLS for repetitor ↔ KME communication (QuKayDee)

Two communication channels:
  - PQC Channel: Custom protocol using Kyber for key exchange, ML-DSA for auth
  - RSA Channel: Standard mTLS for KME communication
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
import struct
from typing import Tuple, Optional, Dict, Any, List
from datetime import datetime
from threading import Thread, Semaphore, Lock

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

KYBER_ALGORITHM = "Kyber768"
MLDSA_ALGORITHM = "ML-DSA-65"

# QKD CA certificate (for KME communication - RSA)
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
    b64 = base64.b64encode(data).decode('ascii')
    lines = [b64[i:i+64] for i in range(0, len(b64), 64)]
    return f"-----BEGIN {label}-----\n" + "\n".join(lines) + f"\n-----END {label}-----\n"


def decode_pem(pem_str: str, label: str) -> bytes:
    lines = pem_str.strip().split('\n')
    b64_lines = [line for line in lines if not line.startswith('-----')]
    b64_data = ''.join(b64_lines)
    return base64.b64decode(b64_data)


# ==================== Kyber Key Exchange ====================

def kyber_generate_keypair() -> Tuple[bytes, bytes]:
    kem = oqs.KeyEncapsulation(KYBER_ALGORITHM)
    public_key = kem.generate_keypair()
    secret_key = kem.export_secret_key()
    return public_key, secret_key


def kyber_encapsulate(public_key: bytes) -> Tuple[bytes, bytes]:
    kem = oqs.KeyEncapsulation(KYBER_ALGORITHM)
    ciphertext, shared_secret = kem.encap_secret(public_key)
    return ciphertext, shared_secret


def kyber_decapsulate(secret_key: bytes, ciphertext: bytes) -> bytes:
    kem = oqs.KeyEncapsulation(KYBER_ALGORITHM, secret_key)
    shared_secret = kem.decap_secret(ciphertext)
    return shared_secret


# ==================== ML-DSA Signatures ====================

def mldsa_generate_keypair() -> Tuple[bytes, bytes]:
    signer = oqs.Signature(MLDSA_ALGORITHM)
    public_key = signer.generate_keypair()
    private_key = signer.export_secret_key()
    return public_key, private_key


def mldsa_sign(private_key: bytes, data: bytes) -> bytes:
    signer = oqs.Signature(MLDSA_ALGORITHM, private_key)
    return signer.sign(data)


def mldsa_verify(public_key: bytes, data: bytes, signature: bytes) -> bool:
    verifier = oqs.Signature(MLDSA_ALGORITHM)
    return verifier.verify(data, signature, public_key)


# ==================== RSA Key/CSR Generation (for KME) ====================

def rsa_generate_keypair() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def rsa_key_to_pem(key: rsa.RSAPrivateKey) -> bytes:
    return key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=NoEncryption()
    )


def rsa_create_csr(key: rsa.RSAPrivateKey, common_name: str) -> str:
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(common_name)]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.PEM).decode()


# ==================== AES Encryption ====================

def derive_shared_key(ss1: bytes, ss2: bytes, context: str = "qkd-relay-v1") -> bytes:
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
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext.encode()) + padder.finalize()
    
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    return base64.b64encode(iv + ciphertext).decode('ascii')


def aes_decrypt(ciphertext_b64: str, key: bytes) -> str:
    data = base64.b64decode(ciphertext_b64)
    iv = data[:16]
    ciphertext = data[16:]
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded) + unpadder.finalize()
    
    return plaintext.decode()


def aes_encrypt_bytes(plaintext: bytes, key: bytes) -> bytes:
    """Encrypt bytes with AES-256-CBC, returns IV + ciphertext."""
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    return iv + ciphertext


def aes_decrypt_bytes(data: bytes, key: bytes) -> bytes:
    """Decrypt AES-256-CBC from IV + ciphertext."""
    iv = data[:16]
    ciphertext = data[16:]
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


# ==================== Attestation ====================

def get_attestation_report(nonce: str, kyber_pk: bytes) -> str:
    data = nonce.encode() + kyber_pk
    report_hash = hashlib.sha256(data).hexdigest()
    return f"attestation_report:{report_hash}"


# ==================== PQC Certificate Verification ====================

def verify_pqc_certificate(cert_pem: str, ca_cert_pem: str) -> Tuple[bool, str, bytes]:
    """
    Verify a PQC certificate against CA.
    Returns (is_valid, subject_cn, public_key).
    """
    try:
        cert_data = decode_pem(cert_pem, "PQC CERTIFICATE")
        cert_json = json.loads(cert_data.decode('utf-8'))
        
        ca_data = decode_pem(ca_cert_pem, "PQC CERTIFICATE")
        ca_json = json.loads(ca_data.decode('utf-8'))
        ca_public_key = base64.b64decode(ca_json["tbs_certificate"]["public_key"]["key"])
        
        tbs_json = json.dumps(cert_json["tbs_certificate"], sort_keys=True, separators=(',', ':'))
        tbs_bytes = tbs_json.encode('utf-8')
        signature = base64.b64decode(cert_json["signature"])
        
        if not mldsa_verify(ca_public_key, tbs_bytes, signature):
            return False, "", b""
        
        subject_cn = cert_json["tbs_certificate"]["subject"]["CN"]
        public_key = base64.b64decode(cert_json["tbs_certificate"]["public_key"]["key"])
        
        not_before = datetime.fromisoformat(cert_json["tbs_certificate"]["validity"]["not_before"])
        not_after = datetime.fromisoformat(cert_json["tbs_certificate"]["validity"]["not_after"])
        now = datetime.utcnow()
        
        if now < not_before or now > not_after:
            return False, subject_cn, public_key
        
        return True, subject_cn, public_key
        
    except Exception as e:
        print(f"Certificate verification failed: {e}")
        return False, "", b""


def extract_public_key_from_cert(cert_pem: str) -> bytes:
    """Extract ML-DSA public key from PQC certificate."""
    cert_data = decode_pem(cert_pem, "PQC CERTIFICATE")
    cert_json = json.loads(cert_data.decode('utf-8'))
    return base64.b64decode(cert_json["tbs_certificate"]["public_key"]["key"])


# ==================== Secure Configuration Protocol ====================

def get_configuration_hybrid(
    controller_host: str,
    controller_port: str,
    repetitor_id: str,
    repetitor_url: str
) -> Dict[str, Any]:
    """Get configuration using hybrid PQC/RSA protocol."""
    base_url = f"http://{controller_host}:{controller_port}"
    
    # Step 1: Kyber Key Exchange
    print(f"[DEBUG] Generating Kyber-768 keypair...")
    kyber_pk, kyber_sk = kyber_generate_keypair()
    
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
    
    kyber_pk_ctrl = base64.b64decode(step1_data["kyber_public_key"])
    kyber_ct_rep = base64.b64decode(step1_data["kyber_ciphertext"])
    nonce = step1_data["nonce"]
    
    print(f"[DEBUG] Received controller's Kyber public key")
    print(f"[DEBUG] Nonce: {nonce}")
    
    # Step 2: Decapsulate and encapsulate
    print(f"[DEBUG] Decapsulating...")
    ss1 = kyber_decapsulate(kyber_sk, kyber_ct_rep)
    
    print(f"[DEBUG] Encapsulating to controller...")
    kyber_ct_ctrl, ss2 = kyber_encapsulate(kyber_pk_ctrl)
    
    shared_key = derive_shared_key(ss1, ss2)
    print(f"[DEBUG] Derived shared key")
    
    # Step 3: Send attestation
    attestation_report = get_attestation_report(nonce, kyber_pk)
    commitment = hashlib.sha256(kyber_pk + repetitor_id.encode()).hexdigest()
    
    attestation_payload = json.dumps({
        "attestation_report": attestation_report,
        "commitment": commitment
    })
    encrypted_attestation = aes_encrypt(attestation_payload, shared_key)
    
    print(f"[DEBUG] Sending attestation...")
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
    
    step2_data = step2_response.json()
    ack_json = aes_decrypt(step2_data["encrypted_response"], shared_key)
    ack = json.loads(ack_json)
    
    if ack.get("status") != "authenticated":
        raise RuntimeError("Authentication failed")
    
    print(f"[DEBUG] Authenticated with controller")
    
    # Step 4: Get configuration
    print(f"[DEBUG] Requesting configuration...")
    config_request = json.dumps({"repetitor_id": repetitor_id})
    encrypted_config_request = aes_encrypt(config_request, shared_key)
    
    config_response = requests.post(
        f"{base_url}/configuration",
        json={"encrypted_payload": encrypted_config_request},
        timeout=120
    )
    config_response.raise_for_status()
    
    config_data = config_response.json()
    config_json = aes_decrypt(config_data["encrypted_response"], shared_key)
    configuration = json.loads(config_json)
    
    print(f"[DEBUG] Received configuration")
    
    global PQC_CA_CERTIFICATE
    PQC_CA_CERTIFICATE = configuration.get("pqc_ca_certificate")
    
    # Step 5: Generate keys and request certificates
    
    # PQC key for repetitor-to-repetitor (ML-DSA)
    print(f"[DEBUG] Generating ML-DSA-65 keypair for repetitor identity...")
    pqc_pk, pqc_sk = mldsa_generate_keypair()
    
    # RSA keys for KME communication
    left_rsa_key = None
    right_rsa_key = None
    left_rsa_csr = ""
    right_rsa_csr = ""
    
    left_cn = configuration.get("left_cn", "")
    right_cn = configuration.get("right_cn", "")
    
    if left_cn and left_cn != "test_client":
        print(f"[DEBUG] Generating RSA keypair for left KME ({left_cn})...")
        left_rsa_key = rsa_generate_keypair()
        left_rsa_csr = rsa_create_csr(left_rsa_key, left_cn)
    
    if right_cn and right_cn != "test_client":
        print(f"[DEBUG] Generating RSA keypair for right KME ({right_cn})...")
        right_rsa_key = rsa_generate_keypair()
        right_rsa_csr = rsa_create_csr(right_rsa_key, right_cn)
    
    # Request certificates
    cert_request = {
        "repetitor_id": repetitor_id,
        "pqc_csr": {
            "subject_cn": repetitor_id,
            "public_key": base64.b64encode(pqc_pk).decode()
        },
        "left_rsa_csr": left_rsa_csr.replace("\n", "\\n") if left_rsa_csr else "",
        "right_rsa_csr": right_rsa_csr.replace("\n", "\\n") if right_rsa_csr else ""
    }
    
    print(f"[DEBUG] Requesting certificates...")
    encrypted_cert_request = aes_encrypt(json.dumps(cert_request), shared_key)
    
    cert_response = requests.post(
        f"{base_url}/generate_certificates",
        json={"encrypted_payload": encrypted_cert_request},
        timeout=30
    )
    cert_response.raise_for_status()
    
    cert_data = cert_response.json()
    certs_json = aes_decrypt(cert_data["encrypted_response"], shared_key)
    certificates = json.loads(certs_json)
    
    print(f"[DEBUG] Received certificates")
    
    return {
        "configuration": configuration,
        "pqc_private_key": pqc_sk,
        "pqc_public_key": pqc_pk,
        "pqc_certificate": certificates["pqc_certificate"],
        "left_rsa_key": left_rsa_key,
        "left_rsa_certificate": certificates.get("left_rsa_certificate", ""),
        "right_rsa_key": right_rsa_key,
        "right_rsa_certificate": certificates.get("right_rsa_certificate", "")
    }


# ==================== PQC Channel (Repetitor to Repetitor) ====================

"""
PQC Channel Protocol:
1. Client connects to server via TCP
2. Server sends: { kyber_pk, cert, signature_of_kyber_pk }
3. Client verifies server cert & signature
4. Client sends: { kyber_ciphertext, cert, signature_of_ciphertext }
5. Server verifies client cert & signature
6. Both derive shared key from Kyber
7. All subsequent messages are AES encrypted with shared key

Message format: [4-byte length][payload]
"""

def send_length_prefixed(sock: socket.socket, data: bytes):
    """Send length-prefixed message."""
    length = struct.pack('>I', len(data))
    sock.sendall(length + data)


def recv_length_prefixed(sock: socket.socket) -> bytes:
    """Receive length-prefixed message."""
    length_bytes = b''
    while len(length_bytes) < 4:
        chunk = sock.recv(4 - len(length_bytes))
        if not chunk:
            raise ConnectionError("Connection closed")
        length_bytes += chunk
    
    length = struct.unpack('>I', length_bytes)[0]
    
    data = b''
    while len(data) < length:
        chunk = sock.recv(min(4096, length - len(data)))
        if not chunk:
            raise ConnectionError("Connection closed")
        data += chunk
    
    return data


def pqc_channel_server_handshake(
    sock: socket.socket,
    my_private_key: bytes,
    my_certificate: str,
    ca_certificate: str,
    whitelist: List[str]
) -> Tuple[bytes, str]:
    """
    Server-side PQC handshake.
    Returns (session_key, peer_cn).
    """
    # Generate ephemeral Kyber keypair for this session
    kyber_pk, kyber_sk = kyber_generate_keypair()
    
    # Sign our Kyber public key
    signature = mldsa_sign(my_private_key, kyber_pk)
    
    # Send our Kyber public key, certificate, and signature
    server_hello = json.dumps({
        "kyber_pk": base64.b64encode(kyber_pk).decode(),
        "certificate": my_certificate,
        "signature": base64.b64encode(signature).decode()
    }).encode()
    send_length_prefixed(sock, server_hello)
    
    # Receive client's response
    client_hello = recv_length_prefixed(sock)
    client_data = json.loads(client_hello.decode())
    
    kyber_ct = base64.b64decode(client_data["kyber_ciphertext"])
    client_cert = client_data["certificate"]
    client_sig = base64.b64decode(client_data["signature"])
    
    # Verify client certificate
    valid, peer_cn, peer_pk = verify_pqc_certificate(client_cert, ca_certificate)
    if not valid:
        raise ValueError(f"Invalid client certificate")
    
    if whitelist and peer_cn not in whitelist:
        raise ValueError(f"Client {peer_cn} not in whitelist")
    
    # Verify client's signature on the ciphertext
    if not mldsa_verify(peer_pk, kyber_ct, client_sig):
        raise ValueError("Invalid client signature")
    
    # Decapsulate to get shared secret
    shared_secret = kyber_decapsulate(kyber_sk, kyber_ct)
    
    # Derive session key
    session_key = hashlib.sha256(shared_secret).digest()
    
    return session_key, peer_cn


def pqc_channel_client_handshake(
    sock: socket.socket,
    my_private_key: bytes,
    my_certificate: str,
    ca_certificate: str
) -> Tuple[bytes, str]:
    """
    Client-side PQC handshake.
    Returns (session_key, peer_cn).
    """
    # Receive server's hello
    server_hello = recv_length_prefixed(sock)
    server_data = json.loads(server_hello.decode())
    
    server_kyber_pk = base64.b64decode(server_data["kyber_pk"])
    server_cert = server_data["certificate"]
    server_sig = base64.b64decode(server_data["signature"])
    
    # Verify server certificate
    valid, peer_cn, peer_pk = verify_pqc_certificate(server_cert, ca_certificate)
    if not valid:
        raise ValueError("Invalid server certificate")
    
    # Verify server's signature on its Kyber public key
    if not mldsa_verify(peer_pk, server_kyber_pk, server_sig):
        raise ValueError("Invalid server signature")
    
    # Encapsulate to server's Kyber public key
    kyber_ct, shared_secret = kyber_encapsulate(server_kyber_pk)
    
    # Sign the ciphertext
    signature = mldsa_sign(my_private_key, kyber_ct)
    
    # Send our response
    client_hello = json.dumps({
        "kyber_ciphertext": base64.b64encode(kyber_ct).decode(),
        "certificate": my_certificate,
        "signature": base64.b64encode(signature).decode()
    }).encode()
    send_length_prefixed(sock, client_hello)
    
    # Derive session key
    session_key = hashlib.sha256(shared_secret).digest()
    
    return session_key, peer_cn


def pqc_send_message(
    host: str,
    port: int,
    my_private_key: bytes,
    my_certificate: str,
    ca_certificate: str,
    message: dict,
    repetitor_id: str
):
    """Send message to another repetitor using PQC channel."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(30)
        sock.connect((host, port))
        
        # Perform PQC handshake
        session_key, peer_cn = pqc_channel_client_handshake(
            sock, my_private_key, my_certificate, ca_certificate
        )
        
        print(f"[{datetime.now():%H:%M:%S}][{repetitor_id}] PQC connected to {peer_cn} at {host}:{port}")
        
        # Encrypt and send message
        message_json = json.dumps(message).encode()
        encrypted = aes_encrypt_bytes(message_json, session_key)
        send_length_prefixed(sock, encrypted)
        
        # Receive acknowledgment
        ack_encrypted = recv_length_prefixed(sock)
        ack = aes_decrypt_bytes(ack_encrypted, session_key)
        
        print(f"[{datetime.now():%H:%M:%S}][{repetitor_id}] Received ack: {ack.decode()}")


def pqc_receive_message(
    host: str,
    port: int,
    my_private_key: bytes,
    my_certificate: str,
    ca_certificate: str,
    whitelist: List[str],
    repetitor_id: str
) -> Tuple[str, dict]:
    """Receive message from another repetitor using PQC channel."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_sock:
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((host, port))
        server_sock.listen(5)
        
        print(f"[{datetime.now():%H:%M:%S}][{repetitor_id}] PQC listener on {host}:{port}")
        
        conn, addr = server_sock.accept()
        conn.settimeout(30)
        
        try:
            # Perform PQC handshake
            session_key, peer_cn = pqc_channel_server_handshake(
                conn, my_private_key, my_certificate, ca_certificate, whitelist
            )
            
            print(f"[{datetime.now():%H:%M:%S}][{repetitor_id}] PQC connection from {peer_cn} at {addr}")
            
            # Receive encrypted message
            encrypted = recv_length_prefixed(conn)
            message_json = aes_decrypt_bytes(encrypted, session_key)
            message = json.loads(message_json.decode())
            
            # Send acknowledgment
            ack = b"RECEIVED"
            ack_encrypted = aes_encrypt_bytes(ack, session_key)
            send_length_prefixed(conn, ack_encrypted)
            
            return peer_cn, message
            
        finally:
            conn.close()


# ==================== KME Communication (RSA-based) ====================

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
    
    key_pem = rsa_key_to_pem(private_key)
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.crt', delete=False) as cert_file, \
         tempfile.NamedTemporaryFile(mode='wb', suffix='.key', delete=False) as key_file, \
         tempfile.NamedTemporaryFile(mode='w', suffix='.crt', delete=False) as ca_file:
        
        cert_file.write(certificate)
        cert_file.flush()
        key_file.write(key_pem)
        key_file.flush()
        ca_file.write(ca_certificate)
        ca_file.flush()
        
        try:
            response = requests.get(
                url=url,
                cert=(cert_file.name, key_file.name),
                verify=ca_file.name,
                timeout=30
            )
            return response
        finally:
            os.unlink(cert_file.name)
            os.unlink(key_file.name)
            os.unlink(ca_file.name)


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
    
    key_pem = rsa_key_to_pem(private_key)
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.crt', delete=False) as cert_file, \
         tempfile.NamedTemporaryFile(mode='wb', suffix='.key', delete=False) as key_file, \
         tempfile.NamedTemporaryFile(mode='w', suffix='.crt', delete=False) as ca_file:
        
        cert_file.write(certificate)
        cert_file.flush()
        key_file.write(key_pem)
        key_file.flush()
        ca_file.write(ca_certificate)
        ca_file.flush()
        
        try:
            response = requests.get(
                url=url,
                cert=(cert_file.name, key_file.name),
                verify=ca_file.name,
                timeout=30
            )
            return response.json()
        finally:
            os.unlink(cert_file.name)
            os.unlink(key_file.name)
            os.unlink(ca_file.name)


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
    
    key_pem = rsa_key_to_pem(private_key)
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.crt', delete=False) as cert_file, \
         tempfile.NamedTemporaryFile(mode='wb', suffix='.key', delete=False) as key_file, \
         tempfile.NamedTemporaryFile(mode='w', suffix='.crt', delete=False) as ca_file:
        
        cert_file.write(certificate)
        cert_file.flush()
        key_file.write(key_pem)
        key_file.flush()
        ca_file.write(ca_certificate)
        ca_file.flush()
        
        try:
            response = requests.get(
                url=url,
                cert=(cert_file.name, key_file.name),
                verify=ca_file.name,
                timeout=30
            )
            return response.json()
        finally:
            os.unlink(cert_file.name)
            os.unlink(key_file.name)
            os.unlink(ca_file.name)


# ==================== QKD Message Encryption/Decryption ====================

def derive_qkd_keys(master_key: bytes) -> Tuple[bytes, bytes]:
    """Derive AES and HMAC keys from QKD master key."""
    aes_key = hashlib.sha256(master_key).digest()
    hmac_ctx = hashlib.sha256()
    hmac_ctx.update(master_key)
    hmac_ctx.update(b"Mac")
    hmac_key = hmac_ctx.digest()
    return aes_key, hmac_key


def decode_qkd_key(text: str) -> bytes:
    """Decode QKD key from hex or base64."""
    stripped = text.strip()
    if len(stripped) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in stripped):
        return binascii.unhexlify(stripped)
    else:
        return base64.b64decode(stripped)


def qkd_encrypt(plaintext: str, key_text: str) -> str:
    """Encrypt message with QKD key."""
    master_key = decode_qkd_key(key_text)
    aes_key, hmac_key = derive_qkd_keys(master_key)
    
    iv = os.urandom(16)
    iv_hex = binascii.hexlify(iv).decode("ascii")
    
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext.encode()) + padder.finalize()
    
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    ciphertext_b64 = base64.b64encode(ciphertext).decode("ascii")
    
    tag = hmac.new(hmac_key, ciphertext_b64.encode("ascii"), hashlib.sha256).digest()
    tag_hex = binascii.hexlify(tag).decode("ascii")
    
    blob_raw = (iv_hex + ciphertext_b64 + tag_hex).encode("ascii")
    return base64.b64encode(blob_raw).decode("ascii")


def qkd_decrypt(blob_base64: str, key_text: str) -> str:
    """Decrypt message with QKD key."""
    master_key = decode_qkd_key(key_text)
    aes_key, hmac_key = derive_qkd_keys(master_key)
    
    blob = base64.b64decode(blob_base64).decode("ascii")
    
    iv_hex = blob[:32]
    tag_hex = blob[-64:]
    ciphertext_b64 = blob[32:-64]
    
    calculated_tag = hmac.new(hmac_key, ciphertext_b64.encode("ascii"), hashlib.sha256).digest()
    calculated_tag_hex = binascii.hexlify(calculated_tag).decode("ascii")
    
    if not hmac.compare_digest(calculated_tag_hex, tag_hex.lower()):
        raise ValueError("HMAC mismatch")
    
    iv = binascii.unhexlify(iv_hex)
    ciphertext = base64.b64decode(ciphertext_b64)
    
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded) + unpadder.finalize()
    
    return plaintext.decode()


# ==================== Main ====================

def main(repetitor_id: str, port: int, print_semaphore: Semaphore) -> None:
    """Main function for repetitor."""
    
    # Get configuration using hybrid PQC/RSA protocol
    result = get_configuration_hybrid(
        CONTROLLER_HOST,
        CONTROLLER_PORT,
        repetitor_id,
        f"127.0.0.1:{port}"
    )
    
    configuration = result["configuration"]
    
    print_semaphore.acquire()
    print(f"\n[{datetime.now():%H:%M:%S}][{repetitor_id}] Configuration received:")
    print(json.dumps({k: v for k, v in configuration.items() if k != "pqc_ca_certificate"}, indent=2))
    print_semaphore.release()
    
    # PQC credentials (for repetitor-to-repetitor)
    pqc_sk = result["pqc_private_key"]
    pqc_pk = result["pqc_public_key"]
    pqc_cert = result["pqc_certificate"]
    
    # RSA credentials (for KME)
    left_rsa_key = result["left_rsa_key"]
    left_rsa_cert = result["left_rsa_certificate"]
    right_rsa_key = result["right_rsa_key"]
    right_rsa_cert = result["right_rsa_certificate"]
    
    # Extract configuration values
    left_kme = configuration.get("left_kme", "")
    right_kme = configuration.get("right_kme", "")
    left_kme_peer = configuration.get("left_kme_peer", "")
    right_kme_peer = configuration.get("right_kme_peer", "")
    whitelist = [item.strip() for item in configuration.get("whitelist", "").split("|") if item.strip()]
    
    left_repetitor_url = configuration.get("left_repetitor_url", "")
    right_repetitor_url = configuration.get("right_repetitor_url", "")
    left_repetitor_id = configuration.get("left_repetitor_id", "")
    right_repetitor_id = configuration.get("right_repetitor_id", "")
    
    # Determine position
    position = "left" if not left_kme else ("right" if not right_kme else "middle")
    
    print_semaphore.acquire()
    print(f"[{datetime.now():%H:%M:%S}][{repetitor_id}] Position: {position}")
    print(f"[{datetime.now():%H:%M:%S}][{repetitor_id}] Whitelist: {whitelist}")
    print(f"[{datetime.now():%H:%M:%S}][{repetitor_id}] Left neighbor: {left_repetitor_id} at {left_repetitor_url}")
    print(f"[{datetime.now():%H:%M:%S}][{repetitor_id}] Right neighbor: {right_repetitor_id} at {right_repetitor_url}")
    print_semaphore.release()
    
    # Verify PQC CA certificate
    if PQC_CA_CERTIFICATE:
        valid, cn, _ = verify_pqc_certificate(pqc_cert, PQC_CA_CERTIFICATE)
        print_semaphore.acquire()
        print(f"[{datetime.now():%H:%M:%S}][{repetitor_id}] PQC certificate verification: {'✓' if valid else '✗'} (CN={cn})")
        print_semaphore.release()
    
    # Test KME connectivity
    if left_kme and left_rsa_key and left_rsa_cert:
        print_semaphore.acquire()
        print(f"[{datetime.now():%H:%M:%S}][{repetitor_id}] Testing left KME ({left_kme})...")
        try:
            status = kme_get_status(left_rsa_key, left_rsa_cert, QKD_CA_CERTIFICATE, left_kme, KME_PORT, left_kme_peer)
            print(f"[{datetime.now():%H:%M:%S}][{repetitor_id}] Left KME status: {status.status_code}")
        except Exception as e:
            print(f"[{datetime.now():%H:%M:%S}][{repetitor_id}] Left KME error: {e}")
        print_semaphore.release()
    
    if right_kme and right_rsa_key and right_rsa_cert:
        print_semaphore.acquire()
        print(f"[{datetime.now():%H:%M:%S}][{repetitor_id}] Testing right KME ({right_kme})...")
        try:
            status = kme_get_status(right_rsa_key, right_rsa_cert, QKD_CA_CERTIFICATE, right_kme, KME_PORT, right_kme_peer)
            print(f"[{datetime.now():%H:%M:%S}][{repetitor_id}] Right KME status: {status.status_code}")
        except Exception as e:
            print(f"[{datetime.now():%H:%M:%S}][{repetitor_id}] Right KME error: {e}")
        print_semaphore.release()
    
    print(f"[{datetime.now():%H:%M:%S}][{repetitor_id}] Ready - entering message relay loop")
    
    # ==================== Main Message Relay Loop ====================
    while True:
        try:
            # Wait for incoming message via PQC channel
            sender_cn, from_message = pqc_receive_message(
                host="0.0.0.0",
                port=port,
                my_private_key=pqc_sk,
                my_certificate=pqc_cert,
                ca_certificate=PQC_CA_CERTIFICATE,
                whitelist=whitelist,
                repetitor_id=repetitor_id
            )
            
            print_semaphore.acquire()
            print(f"[{datetime.now():%H:%M:%S}][{repetitor_id}] Received message from {sender_cn}")
            print_semaphore.release()
            
            # Determine direction (from left or right)
            is_from_left = (sender_cn == left_repetitor_id)
            
            # Get KME info for decryption (incoming direction)
            kme_decrypt = left_kme if is_from_left else right_kme
            kme_decrypt_peer = left_kme_peer if is_from_left else right_kme_peer
            kme_decrypt_key = left_rsa_key if is_from_left else right_rsa_key
            kme_decrypt_cert = left_rsa_cert if is_from_left else right_rsa_cert
            
            # Get KME info for encryption (outgoing direction)
            kme_encrypt = right_kme if is_from_left else left_kme
            kme_encrypt_peer = right_kme_peer if is_from_left else left_kme_peer
            kme_encrypt_key = right_rsa_key if is_from_left else left_rsa_key
            kme_encrypt_cert = right_rsa_cert if is_from_left else left_rsa_cert
            
            # Get next hop info
            to_url = right_repetitor_url if is_from_left else left_repetitor_url
            
            # Extract message content
            from_ciphertext = from_message.get("message", "")
            from_key_id = from_message.get("key_ID", "")
            
            # Decrypt incoming message (if we have a KME on that side)
            if kme_decrypt and kme_decrypt_key and kme_decrypt_cert and from_key_id:
                print(f"[{datetime.now():%H:%M:%S}][{repetitor_id}] Getting decryption key from KME {kme_decrypt}...")
                get_key_response = kme_get_key_with_id(
                    private_key=kme_decrypt_key,
                    certificate=kme_decrypt_cert,
                    ca_certificate=QKD_CA_CERTIFICATE,
                    kme_host=kme_decrypt,
                    kme_port=KME_PORT,
                    kme_master=kme_decrypt_peer,
                    key_id=from_key_id
                )
                from_key = get_key_response["keys"][0]["key"]
                print(f"[{datetime.now():%H:%M:%S}][{repetitor_id}] Decrypting with QKD key...")
                plaintext = qkd_decrypt(from_ciphertext, from_key)
            else:
                # No KME on incoming side (we're at an edge)
                plaintext = from_ciphertext
            
            print_semaphore.acquire()
            print(f"[{datetime.now():%H:%M:%S}][{repetitor_id}] Plaintext: {plaintext[:100]}...")
            print_semaphore.release()
            
            # Encrypt for outgoing (if we have a KME on that side)
            if kme_encrypt and kme_encrypt_key and kme_encrypt_cert:
                print(f"[{datetime.now():%H:%M:%S}][{repetitor_id}] Getting encryption key from KME {kme_encrypt}...")
                get_key_response = kme_get_key(
                    private_key=kme_encrypt_key,
                    certificate=kme_encrypt_cert,
                    ca_certificate=QKD_CA_CERTIFICATE,
                    kme_host=kme_encrypt,
                    kme_port=KME_PORT,
                    kme_slave=kme_encrypt_peer
                )
                to_key_id = get_key_response["keys"][0]["key_ID"]
                to_key = get_key_response["keys"][0]["key"]
                print(f"[{datetime.now():%H:%M:%S}][{repetitor_id}] Encrypting with QKD key...")
                to_ciphertext = qkd_encrypt(plaintext, to_key)
            else:
                # No KME on outgoing side (we're at an edge)
                to_ciphertext = plaintext
                to_key_id = ""
            
            to_message = {"message": to_ciphertext, "key_ID": to_key_id}
            
            # Forward to next hop via PQC channel
            to_host, to_port = to_url.split(":")
            print(f"[{datetime.now():%H:%M:%S}][{repetitor_id}] Forwarding to {to_url}...")
            
            try:
                pqc_send_message(
                    host=to_host,
                    port=int(to_port),
                    my_private_key=pqc_sk,
                    my_certificate=pqc_cert,
                    ca_certificate=PQC_CA_CERTIFICATE,
                    message=to_message,
                    repetitor_id=repetitor_id
                )
                print(f"[{datetime.now():%H:%M:%S}][{repetitor_id}] Message forwarded successfully")
            except Exception as e:
                print_semaphore.acquire()
                print(f"[{datetime.now():%H:%M:%S}][{repetitor_id}] Error forwarding: {e}")
                print_semaphore.release()
                
        except Exception as e:
            print_semaphore.acquire()
            print(f"[{datetime.now():%H:%M:%S}][{repetitor_id}] Error in relay loop: {e}")
            print_semaphore.release()
            import traceback
            traceback.print_exc()


if __name__ == "__main__":
    print_semaphore = Semaphore(1)
    
    repetitor_indices = [0, 1, 2]
    
    if len(sys.argv) > 1:
        repetitor_indices = [int(arg) for arg in sys.argv[1:]]
    
    for i in repetitor_indices:
        thread = Thread(
            target=main,
            args=(f"DR{i}", 9000 + i, print_semaphore)
        )
        thread.start()
