#!/usr/bin/env python3
"""
QKD Relay Repetitor - Secure Communication Protocol (Python Implementation)

This version implements encrypted communication with the controller:
1. Initial key exchange encrypted with controller's RSA public key
2. All subsequent messages encrypted with AES symmetric key
3. Controller acts as CA for certificate generation
"""

import binascii
import hashlib
import hmac
import json
import socket
import ssl
import sys
import os 
import ipaddress
from typing import Tuple, Union, Optional
import cryptography
import requests
import pprint
import tempfile
import base64
import re

from urllib.parse import urljoin
from urllib.parse import quote 

from pathlib import Path

from datetime import datetime

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import PrivateFormat
from cryptography.hazmat.primitives.serialization import NoEncryption
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.ciphers import modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import load_pem_x509_certificate

from threading import Thread
from threading import Semaphore

import time
def print_semaphore_acquire(sem: Semaphore):
    # time.sleep(1)
    sem.acquire()

def print_semaphore_release(sem: Semaphore):
    # time.sleep(1)
    sem.release()


HOST = "127.0.0.1"

CONTROLLER_HOST = "127.0.0.1"
CONTROLLER_PORT = "8000"
CONTROLLER_GET_NONCE_PATH = "get_nonce"
CONTROLLER_GET_CONFIGURATION_PATH = "configuration"
CONTROLLER_GENERATE_CERTIFICATES_PATH = "generate_certificates"

KME_PORT = "443"

SYMMETRIC_KEY_SIZE = 32

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

REPETITOR_CA_CERTIFICATE = """-----BEGIN CERTIFICATE-----
MIIDrzCCApegAwIBAgIUXeRoaA0s2FWtqv9KV6xjUPLMHgkwDQYJKoZIhvcNAQEL
BQAwXjELMAkGA1UEBhMCUlMxCzAJBgNVBAgTAlJTMREwDwYDVQQHEwhCZWxncmFk
ZTEMMAoGA1UEChMDRVRGMQwwCgYDVQQLEwNSVEkxEzARBgNVBAMTCk15IFJvb3Qg
Q0EwHhcNMjUwOTA2MTAyNzAwWhcNMzAwOTA1MTAyNzAwWjBeMQswCQYDVQQGEwJS
UzELMAkGA1UECBMCUlMxETAPBgNVBAcTCEJlbGdyYWRlMQwwCgYDVQQKEwNFVEYx
DDAKBgNVBAsTA1JUSTETMBEGA1UEAxMKTXkgUm9vdCBDQTCCASIwDQYJKoZIhvcN
AQEBBQADggEPADCCAQoCggEBANtfOpPGqxY8mkRxlNMRQn6wVQ0aUeO9zjLANhZ9
bG81fV1uP9i5pJ/wgUEx2B3b1kj0nD/a51xp++Y+/12y52ZbGPpYBOJu5cb5aFTw
J95OB+ri8c1uqFwRA2mxrSRUgrlRuZKsbPLnZeNC/2t5anR37GncsZWgWppgJ8nO
UXXymXy2QK1k2hMAhO4uIGVmzG8eHvpCMEMMj+9hlhE2y8jId0GyHA2EWyuQNOe3
T7go91MotJY+/uPsEY8uSajRrN/fUcXqQrBysZDMbPiHlvaG/NyVGI+vQBPEULNE
ebG/47G79h542xwpflz6H9VOpboXjBgzgyvzLuGlJzSL+20CAwEAAaNlMGMwDgYD
VR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFIS8fn+Ob/PH
pPC5AIgKR7GWKOJFMCEGA1UdEQQaMBiHBH8AAAGHEAAAAAAAAAAAAAAAAAAAAAEw
DQYJKoZIhvcNAQELBQADggEBAHmXsmyq+KJTm2/+lXoZnpB/fM16T9dqypQdzIme
K0PcrNzcJzxF4dxi7IJWr97ICRJfSqKppUVLBWGVYXau6Prtbf+dXs9KM0Juzo9a
GYD3tNfdlAmI4ZSMt4H/EwaCO5MiXMSwvtg6qMpWjDXjJOvTIyDdWIe0JE+Soz2T
cGr1d8RyvYUAL0whxbAqAVAKBe9c4MTm1rlS5hMrpTVTSmI+HKPJyzZvvoiemzZg
Aw8+YxNOFwljTCl4ZCi5/PME9utT3IWqQUhrGwa4LMduRaieSnjIstNurvNsOBnd
tGAHFnSILfyZq0Z4vpnMhr4D6UmLvsis0W/lBAMkVlSJvKQ=
-----END CERTIFICATE-----"""

# TODO: remove after testing - load from file if exists
try:
    with open("./cfssl/client-root-ca.crt", "r") as file:
        REPETITOR_CA_CERTIFICATE = file.read()
except FileNotFoundError:
    pass


# ==================== Secure Communication Functions ====================

def rsa_encrypt_with_cert(data: bytes, cert_pem: str) -> str:
    """Encrypt data using the public key from a PEM certificate."""
    cert = load_pem_x509_certificate(cert_pem.encode(), default_backend())
    public_key = cert.public_key()
    
    encrypted = public_key.encrypt(
        data,
        asym_padding.PKCS1v15()  # Match WolfSSL's default
    )
    
    return base64.b64encode(encrypted).decode('ascii')


def aes_encrypt_msg(plaintext: str, key: bytes) -> str:
    """Encrypt with AES-256-CBC, returns base64(IV + ciphertext)."""
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # PKCS7 padding
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext.encode()) + padder.finalize()
    
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    return base64.b64encode(iv + ciphertext).decode('ascii')


def aes_decrypt_msg(ciphertext_b64: str, key: bytes) -> str:
    """Decrypt AES-256-CBC from base64(IV + ciphertext)."""
    data = base64.b64decode(ciphertext_b64)
    iv = data[:16]
    ciphertext = data[16:]
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    
    # PKCS7 unpadding
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded) + unpadder.finalize()
    
    return plaintext.decode()


def get_attestation_report(nonce: str) -> str:
    """Generate attestation report (placeholder - returns nonce as base64)."""
    return base64.b64encode(nonce.encode()).decode('ascii')


# ==================== Secure Configuration Protocol ====================

def get_configuration_secure(
    controller_host: str,
    controller_port: str,
    controller_get_nonce_path: str,
    controller_get_configuration_path: str,
    controller_generate_certificates_path: str,
    repetitor_id: str,
    repetitor_url: str
) -> dict:
    """
    Get configuration using the secure communication protocol.
    
    Protocol:
    1. Generate symmetric key
    2. Encrypt {repetitor_id, symmetric_key, repetitor_url} with controller's RSA public key
    3. POST to /get_nonce, receive AES-encrypted nonce
    4. Get attestation report with nonce
    5. POST encrypted {repetitor_id, attestation_report} to /configuration
    6. Receive encrypted configuration
    7. Generate keys and CSRs
    8. POST encrypted CSRs to /generate_certificates
    9. Receive encrypted certificates
    """
    
    base_url = f"http://{controller_host}:{controller_port}"
    
    # Step 1: Generate symmetric key
    print(f"[DEBUG] Generating symmetric key...")
    symmetric_key = os.urandom(SYMMETRIC_KEY_SIZE)
    symmetric_key_b64 = base64.b64encode(symmetric_key).decode('ascii')
    
    # Step 2: Create initial payload and encrypt with RSA
    print(f"[DEBUG] Encrypting initial payload with controller public key...")
    initial_payload = json.dumps({
        "repetitor_id": repetitor_id,
        "symmetric_key": symmetric_key_b64,
        "repetitor_url": repetitor_url
    })
    
    encrypted_initial = rsa_encrypt_with_cert(
        initial_payload.encode(),
        REPETITOR_CA_CERTIFICATE
    )
    
    # Step 3: Send to get_nonce endpoint
    print(f"[DEBUG] Requesting nonce from controller...")
    nonce_response = requests.post(
        f"{base_url}/{controller_get_nonce_path}",
        json={"encrypted_payload": encrypted_initial},
        timeout=30
    )
    nonce_response.raise_for_status()
    
    # Decrypt nonce response
    encrypted_nonce = nonce_response.json().get("encrypted_response")
    nonce_json = aes_decrypt_msg(encrypted_nonce, symmetric_key)
    nonce = json.loads(nonce_json).get("nonce")
    print(f"[DEBUG] Received nonce: {nonce}")
    
    # Step 4: Get attestation report
    attestation_report = get_attestation_report(nonce)
    
    # Step 5: Request configuration
    print(f"[DEBUG] Requesting configuration...")
    config_payload = json.dumps({
        "repetitor_id": repetitor_id,
        "attestation_report": attestation_report
    })
    encrypted_config_payload = aes_encrypt_msg(config_payload, symmetric_key)
    
    config_response = requests.post(
        f"{base_url}/{controller_get_configuration_path}",
        json={"encrypted_payload": encrypted_config_payload},
        timeout=60  # May block waiting for other repetitors
    )
    config_response.raise_for_status()
    
    # Decrypt configuration
    encrypted_config = config_response.json().get("encrypted_response")
    config_json = aes_decrypt_msg(encrypted_config, symmetric_key)
    configuration = json.loads(config_json)
    print(f"[DEBUG] Received configuration")
    
    # Step 6: Generate keys and CSRs
    print(f"[DEBUG] Generating keys and CSRs...")
    left_key = build_key()
    right_key = build_key()
    repetitor_key = build_key()
    
    left_csr = build_csr(left_key, configuration["left_cn"])
    right_csr = build_csr(right_key, configuration["right_cn"])
    repetitor_csr = build_csr(repetitor_key, repetitor_id)
    
    # Step 7: Request certificates
    print(f"[DEBUG] Requesting certificates...")
    cert_payload = json.dumps({
        "repetitor_id": repetitor_id,
        "left_csr": left_csr.decode().replace("\n", "\\n"),
        "right_csr": right_csr.decode().replace("\n", "\\n"),
        "repetitor_csr": repetitor_csr.decode().replace("\n", "\\n")
    })
    encrypted_cert_payload = aes_encrypt_msg(cert_payload, symmetric_key)
    
    cert_response = requests.post(
        f"{base_url}/{controller_generate_certificates_path}",
        json={"encrypted_payload": encrypted_cert_payload},
        timeout=30
    )
    cert_response.raise_for_status()
    
    # Decrypt certificates
    encrypted_certs = cert_response.json().get("encrypted_response")
    certs_json = aes_decrypt_msg(encrypted_certs, symmetric_key)
    certificates = json.loads(certs_json)
    
    # json.loads automatically unescapes \n in JSON to actual newlines
    left_cert = certificates["left_certificate"]
    right_cert = certificates["right_certificate"]
    repetitor_cert = certificates["repetitor_certificate"]
    
    print(f"[DEBUG] Received all certificates")
    
    # Return configuration with keys and certificates
    return {
        "configuration": configuration,
        "left_private_key": left_key,
        "left_certificate": left_cert,
        "right_private_key": right_key,
        "right_certificate": right_cert,
        "repetitor_private_key": repetitor_key,
        "repetitor_certificate": repetitor_cert
    }


# ==================== Key/CSR Generation ====================

def build_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def build_csr(key: rsa.RSAPrivateKey, common_name: str) -> bytes:
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"{common_name}")])
        )
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(f"{common_name}")]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.PEM)


# ==================== KME Functions ====================

def kme_get_status(
    private_key,
    certificate,
    ca_root_certificate,
    kme_host,
    kme_port,
    kme_slave
):
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
        ca_file.write(ca_root_certificate.encode("utf-8"))
        
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
    private_key,
    certificate,
    ca_root_certificate,
    kme_host,
    kme_port,
    kme_slave
):
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
        ca_file.write(ca_root_certificate.encode("utf-8"))
        
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
    private_key,
    certificate,
    ca_root_certificate,
    kme_host,
    kme_port,
    kme_master,
    key_id
):
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
        ca_file.write(ca_root_certificate.encode("utf-8"))
        
        cert_file.flush()
        key_file.flush()
        ca_file.flush()
        
        response = requests.get(
            url=url,
            cert=(cert_file.name, key_file.name),
            verify=ca_file.name
        )
    
    return response.json()


# ==================== Message Send/Receive ====================

def send_message(
    private_key,
    certificate_pem: str,
    ca_certificate_pem: str,
    host: str,
    port: int,
    data: dict
):
    private_key_pem = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=NoEncryption(),
    )
    
    with tempfile.NamedTemporaryFile() as cert_file, \
         tempfile.NamedTemporaryFile() as key_file:
        
        cert_file.write(certificate_pem.encode("utf-8"))
        key_file.write(private_key_pem)
        cert_file.flush()
        key_file.flush()
        
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_cert_chain(certfile=cert_file.name, keyfile=key_file.name)
        context.load_verify_locations(cadata=ca_certificate_pem)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((host, port)) as sock:
            with context.wrap_socket(sock) as tls:
                print(f"[{datetime.now():%H:%M:%S}] Connected to {host}:{port} via mTLS")
                
                wire_bytes = (json.dumps({**data, "message": data["message"]}) + "\n").encode("utf-8")
                tls.sendall(wire_bytes + b"\n")
                
                response = tls.recv(4096)
                print("Server replied:", response.decode())
                tls.unwrap()


def receive_message(
    private_key,
    certificate_pem: str,
    ca_certificate_pem: str,
    host: str,
    port: int,
    client_whitelist: list,
    repetitor_id: str
):
    private_key_pem = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=NoEncryption(),
    )
    
    with tempfile.NamedTemporaryFile() as cert_file, \
         tempfile.NamedTemporaryFile() as key_file:
        
        cert_file.write(certificate_pem.encode("utf-8"))
        key_file.write(private_key_pem)
        cert_file.flush()
        key_file.flush()
        
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=cert_file.name, keyfile=key_file.name)
        context.load_verify_locations(cadata=ca_certificate_pem)
        context.verify_mode = ssl.CERT_REQUIRED
        
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((host, port))
            sock.listen(5)
            
            print(f"[{datetime.now():%H:%M:%S}][{repetitor_id}] mTLS listener on {host}:{port} (waiting...)")
            
            conn, addr = sock.accept()
            
            with context.wrap_socket(conn, server_side=True) as tls:
                peer_cert_der = tls.getpeercert(binary_form=True)
                peer_cert = x509.load_der_x509_certificate(peer_cert_der)
                common_name = re.search(r"CN=([^)>]+)", str(peer_cert.subject)).group(1)
                
                if common_name not in client_whitelist and len(client_whitelist) > 0:
                    raise RuntimeError(f"Client {common_name} not in whitelist")
                
                chunks = []
                while True:
                    data = tls.recv(4096)
                    if not data:
                        break
                    chunks.append(data)
                    if b"\n" in data:
                        break
                
                message = b"".join(chunks)
                tls.sendall(b"RECEIVED\n")
                tls.unwrap()
                
                return common_name, message


# ==================== Message Encryption/Decryption ====================

def is_hex(string: str) -> bool:
    try:
        int(string, 16)
        return True
    except ValueError:
        return False


def b64_decode_tolerant(string: str) -> bytes:
    string = string.strip()
    missing = 0 if len(string) % 4 == 0 else 4 - (len(string) % 4)
    if missing != 0:
        string = string + ("=" * missing)
    return base64.b64decode(string, validate=False)


def b64_encode(byte_array: bytes) -> str:
    return base64.b64encode(byte_array).decode("ascii")


def bytes_to_hex(byte_array: bytes) -> str:
    return binascii.hexlify(byte_array).decode("ascii")


def hex_to_bytes(string: str) -> bytes:
    return binascii.unhexlify(string.encode("ascii"))


def decode_master_key(text: str) -> bytes:
    stripped = text.strip()
    if len(stripped) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in stripped):
        return hex_to_bytes(stripped)
    else:
        return b64_decode_tolerant(stripped)


def derive_keys(master_key: bytes) -> Tuple[bytes, bytes]:
    aes_key = hashlib.sha256(master_key).digest()
    hmac_ctx = hashlib.sha256()
    hmac_ctx.update(master_key)
    hmac_ctx.update(b"Mac")
    hmac_key = hmac_ctx.digest()
    return aes_key, hmac_key


def aes256_cbc_encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded = padder.update(plaintext) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(padded) + encryptor.finalize()


def aes256_cbc_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def encrypt(plaintext: Union[str, bytes], key_text: str) -> str:
    if isinstance(plaintext, str):
        plaintext = plaintext.encode("utf-8")
    
    master_key = decode_master_key(key_text)
    aes_key, hmac_key = derive_keys(master_key)
    
    iv = os.urandom(16)
    iv_hex = bytes_to_hex(iv)
    
    ciphertext_binary = aes256_cbc_encrypt(plaintext, aes_key, iv)
    ciphertext_b64 = b64_encode(ciphertext_binary)
    
    tag = hmac.new(hmac_key, ciphertext_b64.encode("ascii"), hashlib.sha256).digest()
    tag_hex = bytes_to_hex(tag)
    
    blob_raw = (iv_hex + ciphertext_b64 + tag_hex).encode("ascii")
    return b64_encode(blob_raw)


def decrypt(blob_base64: str, key_text: str) -> bytes:
    master_key = decode_master_key(key_text)
    aes_key, hmac_key = derive_keys(master_key)
    
    blob = b64_decode_tolerant(blob_base64).decode("ascii", errors="strict")
    
    if len(blob) < 32 + 64:
        raise ValueError("Blob too short")
    
    iv_hex = blob[:32]
    tag_hex = blob[-64:]
    ciphertext_b64 = blob[32:-64]
    
    calculated_tag = hmac.new(hmac_key, ciphertext_b64.encode("ascii"), hashlib.sha256).digest()
    calculated_tag_hex = bytes_to_hex(calculated_tag)
    
    if not hmac.compare_digest(calculated_tag_hex, tag_hex.lower()):
        raise ValueError("Authentication failed (HMAC mismatch)")
    
    iv = hex_to_bytes(iv_hex)
    if len(iv) != 16:
        raise ValueError("Invalid IV length")
    
    ciphertext_binary = b64_decode_tolerant(ciphertext_b64)
    return aes256_cbc_decrypt(ciphertext_binary, aes_key, iv)


# ==================== Main Function ====================

def main(repetitor_id: str, port: int, print_semaphore: Semaphore) -> None:
    # Get configuration using secure protocol
    result = get_configuration_secure(
        CONTROLLER_HOST,
        CONTROLLER_PORT,
        CONTROLLER_GET_NONCE_PATH,
        CONTROLLER_GET_CONFIGURATION_PATH,
        CONTROLLER_GENERATE_CERTIFICATES_PATH,
        repetitor_id,
        f"127.0.0.1:{port}"
    )
    
    configuration = result["configuration"]
    
    # Extract keys and certificates from secure config
    left_private_key = result["left_private_key"]
    left_certificate_pem = result["left_certificate"]
    right_private_key = result["right_private_key"]
    right_certificate_pem = result["right_certificate"]
    repetitor_key = result["repetitor_private_key"]
    repetitor_certificate_pem = result["repetitor_certificate"]
    
    print_semaphore_acquire(print_semaphore)
    print(f"[{datetime.now():%H:%M:%S}][{repetitor_id}] configuration received:")
    print(json.dumps(configuration, indent=4))
    print_semaphore_release(print_semaphore)
    
    # Extract configuration values
    left_kme = configuration["left_kme"]
    right_kme = configuration["right_kme"]
    left_cn = configuration["left_cn"]
    right_cn = configuration["right_cn"]
    left_kme_peer = configuration["left_kme_peer"]
    right_kme_peer = configuration["right_kme_peer"]
    whitelist = [item.strip() for item in configuration["whitelist"].split("|")]
    
    # Check KME status
    if left_kme != "":
        status_response = kme_get_status(
            private_key=left_private_key,
            certificate=left_certificate_pem,
            ca_root_certificate=QKD_CA_CERTIFICATE,
            kme_host=left_kme,
            kme_port=KME_PORT,
            kme_slave=left_kme_peer
        )
        if status_response.status_code != 200:
            raise Exception(f"{repetitor_id}: Could not get status from left KME {left_kme}: {status_response.status_code} {status_response.text}")
    
    if right_kme != "":
        status_response = kme_get_status(
            private_key=right_private_key,
            certificate=right_certificate_pem,
            ca_root_certificate=QKD_CA_CERTIFICATE,
            kme_host=right_kme,
            kme_port=KME_PORT,
            kme_slave=right_kme_peer
        )
        if status_response.status_code != 200:
            raise Exception(f"{repetitor_id}: Could not get status from right KME {right_kme}: {status_response.status_code} {status_response.text}")
    
    left_repetitor_url = configuration["left_repetitor_url"]
    right_repetitor_url = configuration["right_repetitor_url"]
    left_repetitor_id = configuration["left_repetitor_id"]
    right_repetitor_id = configuration["right_repetitor_id"]
    
    print_semaphore_acquire(print_semaphore)
    position = "left" if left_kme == "" else ("right" if right_kme == "" else "middle")
    print(f"[{datetime.now():%H:%M:%S}][{repetitor_id}] position: {position}")
    print_semaphore_release(print_semaphore)
    
    # Main message relay loop
    while True:
        subject, from_message_bytearray = receive_message(
            private_key=repetitor_key,
            certificate_pem=repetitor_certificate_pem,
            ca_certificate_pem=REPETITOR_CA_CERTIFICATE,
            host="0.0.0.0",
            port=port,
            client_whitelist=whitelist,
            repetitor_id=repetitor_id
        )
        
        print_semaphore_acquire(print_semaphore)
        print(f"[{datetime.now():%H:%M:%S}] {repetitor_id} received message: {from_message_bytearray.decode('utf-8')}")
        print_semaphore_release(print_semaphore)
        
        from_url = left_repetitor_url if subject == left_repetitor_id else right_repetitor_url
        to_url = right_repetitor_url if subject == left_repetitor_id else left_repetitor_url
        
        kme_master = left_kme if subject == left_repetitor_id else right_kme
        kme_slave = right_kme if subject == left_repetitor_id else left_kme
        
        kme_master_peer = left_kme_peer if subject == left_repetitor_id else right_kme_peer
        kme_slave_peer = right_kme_peer if subject == left_repetitor_id else left_kme_peer
        
        kme_master_private_key = left_private_key if subject == left_repetitor_id else right_private_key
        kme_slave_private_key = right_private_key if subject == left_repetitor_id else left_private_key
        
        kme_master_certificate = left_certificate_pem if subject == left_repetitor_id else right_certificate_pem
        kme_slave_certificate = right_certificate_pem if subject == left_repetitor_id else left_certificate_pem
        
        from_message = json.loads(from_message_bytearray.decode("utf-8"))
        from_ciphertext = from_message["message"]
        from_key_id = from_message["key_ID"]
        
        if kme_master != "":
            get_key_with_id_response = kme_get_key_with_id(
                private_key=kme_master_private_key,
                certificate=kme_master_certificate,
                ca_root_certificate=QKD_CA_CERTIFICATE,
                kme_host=kme_master,
                kme_port=KME_PORT,
                kme_master=kme_master_peer,
                key_id=from_key_id
            )
            from_key = get_key_with_id_response["keys"][0]["key"]
            print (f"[{datetime.now():%H:%M:%S}] {repetitor_id} obtained decryption key from KME {kme_master}: {from_key}")
            plaintext = decrypt(from_ciphertext, from_key).decode("utf-8")
        else:
            plaintext = from_ciphertext
        
        print_semaphore_acquire(print_semaphore)
        print(f"[{datetime.now():%H:%M:%S}] {repetitor_id} decrypted message: {plaintext}")
        print_semaphore_release(print_semaphore)
        
        to_ciphertext = None
        to_key_id = None
        
        if kme_slave != "":
            get_key_response = kme_get_key(
                private_key=kme_slave_private_key,
                certificate=kme_slave_certificate,
                ca_root_certificate=QKD_CA_CERTIFICATE,
                kme_host=kme_slave,
                kme_port=KME_PORT,
                kme_slave=kme_slave_peer
            )
            to_key_id = get_key_response["keys"][0]["key_ID"]
            to_key = get_key_response["keys"][0]["key"]
            print (f"[{datetime.now():%H:%M:%S}] {repetitor_id} obtained decryption key from KME {kme_slave}: {to_key}")
            to_ciphertext = encrypt(plaintext, to_key)
        else:
            to_ciphertext = plaintext
            to_key_id = ""
        
        to_message = {"message": to_ciphertext, "key_ID": to_key_id}
        
        try:
            send_message(
                private_key=repetitor_key,
                certificate_pem=repetitor_certificate_pem,
                ca_certificate_pem=REPETITOR_CA_CERTIFICATE,
                host=to_url.split(":")[0],
                port=int(to_url.split(":")[1]),
                data=to_message
            )
        except Exception as e:
            print_semaphore_acquire(print_semaphore)
            print(f"[{datetime.now():%H:%M:%S}] {repetitor_id} error sending message to {to_url}: {e}")
            print_semaphore_release(print_semaphore)


if __name__ == "__main__":
    print_semaphore = Semaphore(1)
    
    # Default: run repetitors 0 and 2
    repetitor_indices = [0, 2]
    
    if len(sys.argv) > 1:
        repetitor_indices = [int(arg) for arg in sys.argv[1:]]
    else: 
        print("No repetitor indices provided as arguments.")
        exit(1)
    
    for i in repetitor_indices:
        thread = Thread(
            target=main,
            args=(f"DR{i}", 9000 + i, print_semaphore)
        )
        thread.start()
