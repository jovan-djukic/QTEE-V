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
from typing import Tuple, Optional, Dict, Any, List
from datetime import datetime, timezone, timedelta
from threading import Thread, Semaphore, Lock

try:
    import oqs
    import wolfssl_mldsa
except ImportError:
    print("Error: liboqs-python not installed")
    print("Install with: pip install liboqs-python")
    sys.exit(1)

# Monkey-patch oqs.Signature to use WolfSSL for ML-DSA
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
CTRL_TLS_PORT = 8001       # WolfSSL TLS port — all protocol steps after CA cert fetch
KME_PORT = "443"

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

# PQC CA certificate — pre-deployed in firmware, loaded from disk at startup.
# NOT fetched over the network; the file must exist before the repetitor starts.
PQC_CA_CERT_PATH = "./pqc_ca/ca_certificate.pem"
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


def _der_tlv(tag: int, val: bytes) -> bytes:
    return bytes([tag]) + _enc_len(len(val)) + val


def _pkcs8_mldsa65_der(raw_key: bytes) -> bytes:
    """Convert a raw ML-DSA-65 private key to PKCS#8 DER via WolfSSL."""
    return wolfssl_mldsa.pkcs8_mldsa65_der(raw_key)


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


def _parse_utctime(val: bytes) -> datetime:
    """Parse UTCTime bytes (YYMMDDHHMMSSZ) to a naive UTC datetime."""
    s = val.decode('ascii')
    yy = int(s[0:2])
    year = 2000 + yy if yy < 50 else 1900 + yy
    return datetime(year, int(s[2:4]), int(s[4:6]),
                    int(s[6:8]), int(s[8:10]), int(s[10:12]))


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
    Returns (subject_cn, public_key, tbs_raw, not_before, not_after).
    tbs_raw is the complete TBSCertificate DER for signature verification.
    not_before / not_after are naive UTC datetimes (or None if not UTCTime).
    """
    _, cert_val, _ = _read_tlv(der, 0)
    pos = 0
    tbs_start = pos
    _, tbs_val, pos = _read_tlv(cert_val, pos)
    tbs_raw = cert_val[tbs_start:pos]

    tpos = 0
    if tbs_val[tpos] == 0xA0:           # version [0] EXPLICIT (optional)
        _, _, tpos = _read_tlv(tbs_val, tpos)
    _, _, tpos = _read_tlv(tbs_val, tpos)   # serialNumber
    _, _, tpos = _read_tlv(tbs_val, tpos)   # signature AlgorithmIdentifier
    _, _, tpos = _read_tlv(tbs_val, tpos)   # issuer

    _, validity_val, tpos = _read_tlv(tbs_val, tpos)   # validity
    vp = 0
    tag_nb, nb_val, vp = _read_tlv(validity_val, vp)
    tag_na, na_val, _  = _read_tlv(validity_val, vp)
    not_before = _parse_utctime(nb_val) if tag_nb == 0x17 else None
    not_after  = _parse_utctime(na_val) if tag_na == 0x17 else None

    subj_start = tpos
    _, _, tpos = _read_tlv(tbs_val, tpos)   # subject
    subject_cn = _parse_name_cn(tbs_val[subj_start:tpos])

    _, spki_val, _ = _read_tlv(tbs_val, tpos)  # subjectPublicKeyInfo
    sp = 0
    _, _, sp = _read_tlv(spki_val, sp)          # AlgorithmIdentifier
    _, bs_val, _ = _read_tlv(spki_val, sp)      # BIT STRING
    public_key = bs_val[1:]                     # skip unused-bits byte

    return subject_cn, public_key, tbs_raw, not_before, not_after


def _verify_dilithium_x509(cert_der: bytes, ca_public_key: bytes) -> bool:
    """Verify a Dilithium X.509 certificate's signature against a CA public key."""
    _, cert_val, _ = _read_tlv(cert_der, 0)
    pos = 0
    tbs_start = pos
    _, _, pos = _read_tlv(cert_val, pos)
    tbs_raw = cert_val[tbs_start:pos]
    _, _, pos = _read_tlv(cert_val, pos)    # skip signatureAlgorithm
    _, sig_bs, _ = _read_tlv(cert_val, pos)
    signature = sig_bs[1:]
    return mldsa_verify(ca_public_key, tbs_raw, signature)


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


def derive_session_key(shared_secret: bytes, context: str = "pqc-channel-v1") -> bytes:
    """Derive session key for PQC channel using HKDF (matches C implementation)."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=context.encode(),
        backend=default_backend()
    )
    result = hkdf.derive(shared_secret)
    # Debug output
    print(f"[DEBUG] derive_session_key:")
    print(f"  shared_secret (first 16 bytes): {shared_secret[:16].hex()}")
    print(f"  session_key (first 16 bytes): {result[:16].hex()}")
    return result


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

def get_attestation_report(nonce: str, repetitor_id: str) -> str:
    data = nonce.encode() + repetitor_id.encode()
    report_hash = hashlib.sha256(data).hexdigest()
    return f"attestation_report:{report_hash}"


# ==================== PQC Certificate Verification ====================

def verify_pqc_certificate(cert_pem: str, ca_cert_pem: str) -> Tuple[bool, str, bytes]:
    """
    Verify an X.509 Dilithium certificate against the CA.
    Returns (is_valid, subject_cn, public_key).
    """
    try:
        cert_der = decode_pem(cert_pem, "CERTIFICATE")
        ca_der   = decode_pem(ca_cert_pem, "CERTIFICATE")

        _, ca_public_key, _, _, _ = _parse_x509_cert(ca_der)

        subject_cn, public_key, _, not_before, not_after = _parse_x509_cert(cert_der)

        if not _verify_dilithium_x509(cert_der, ca_public_key):
            return False, "", b""

        now = datetime.now(timezone.utc).replace(tzinfo=None)
        if not_before and now < not_before:
            return False, subject_cn, public_key
        if not_after and now > not_after:
            return False, subject_cn, public_key

        return True, subject_cn, public_key

    except Exception as e:
        print(f"Certificate verification failed: {e}")
        return False, "", b""


def extract_public_key_from_cert(cert_pem: str) -> bytes:
    """Extract ML-DSA public key from an X.509 Dilithium certificate."""
    cert_der = decode_pem(cert_pem, "CERTIFICATE")
    _, public_key, _, _, _ = _parse_x509_cert(cert_der)
    return public_key


# ==================== Secure Configuration Protocol ====================

def get_configuration_hybrid(
    controller_host: str,
    repetitor_id: str,
    repetitor_url: str
) -> Dict[str, Any]:
    """Get configuration over WolfSSL TLS.

    Bootstrap: CA cert is pre-deployed at PQC_CA_CERT_PATH (loaded from disk).
    All protocol steps (register, attest, configuration, certificate generation)
    happen inside a single WolfSSL TLS connection to controller:CTRL_TLS_PORT.
    """
    # ── Bootstrap: load pre-deployed CA cert from disk ────────────────────────
    print(f"[DEBUG] Loading CA cert from {PQC_CA_CERT_PATH}...")
    with open(PQC_CA_CERT_PATH, "rb") as f:
        ca_pem = f.read().decode()
    ca_der = decode_pem(ca_pem, "CERTIFICATE")
    print(f"[*] Loaded CA cert ({len(ca_der)} bytes)")

    # ── Open persistent WolfSSL TLS connection ────────────────────────────────
    print(f"[DEBUG] Connecting to controller TLS on {controller_host}:{CTRL_TLS_PORT}...")
    sock = socket.create_connection((controller_host, CTRL_TLS_PORT), timeout=30)
    try:
        with wolfssl_mldsa.pqc_tls_client_connect_anon(sock.fileno(), ca_der) as conn:
            print(f"[*] WolfSSL TLS connected to controller")

            # ── Step 1: Register — get nonce ──────────────────────────────────
            print(f"[DEBUG] Sending register...")
            conn.sendmsg(json.dumps({
                "action": "register",
                "data": {"repetitor_id": repetitor_id, "repetitor_url": repetitor_url}
            }).encode())

            reg_data = json.loads(conn.recvmsg())
            if "error" in reg_data:
                raise RuntimeError(f"Register failed: {reg_data['error']}")
            nonce = reg_data["nonce"]
            print(f"[DEBUG] Received nonce={nonce}")

            # ── Step 2: Attest — SHA256(nonce_hex + repetitor_id) ────────────
            attestation_report = get_attestation_report(nonce, repetitor_id)
            print(f"[DEBUG] Sending attest...")
            conn.sendmsg(json.dumps({
                "action": "attest",
                "data": {"repetitor_id": repetitor_id, "attestation_report": attestation_report}
            }).encode())

            attest_data = json.loads(conn.recvmsg())
            if "error" in attest_data:
                raise RuntimeError(f"Attestation failed: {attest_data['error']}")
            if attest_data.get("status") != "authenticated":
                raise RuntimeError("Authentication failed")
            print(f"[DEBUG] Authenticated with controller")

            # ── Step 3: Configuration (blocks until all repetitors ready) ─────
            print(f"[DEBUG] Requesting configuration...")
            conn.sendmsg(json.dumps({
                "action": "configuration",
                "data": {"repetitor_id": repetitor_id}
            }).encode())

            configuration = json.loads(conn.recvmsg())
            if "error" in configuration:
                raise RuntimeError(f"Configuration failed: {configuration['error']}")
            print(f"[DEBUG] Received configuration")

            global PQC_CA_CERTIFICATE
            PQC_CA_CERTIFICATE = ca_pem   # already loaded from pre-deployed file

            # ── Step 4: Generate keys and request certificates ────────────────
            print(f"[DEBUG] Generating ML-DSA-65 keypair for repetitor identity...")
            pqc_pk, pqc_sk = mldsa_generate_keypair()

            left_rsa_key  = None
            right_rsa_key = None
            left_rsa_csr  = ""
            right_rsa_csr = ""

            left_cn  = configuration.get("left_cn", "")
            right_cn = configuration.get("right_cn", "")

            if left_cn and left_cn != "test_client":
                print(f"[DEBUG] Generating RSA keypair for left KME ({left_cn})...")
                left_rsa_key = rsa_generate_keypair()
                left_rsa_csr = rsa_create_csr(left_rsa_key, left_cn)

            if right_cn and right_cn != "test_client":
                print(f"[DEBUG] Generating RSA keypair for right KME ({right_cn})...")
                right_rsa_key = rsa_generate_keypair()
                right_rsa_csr = rsa_create_csr(right_rsa_key, right_cn)

            print(f"[DEBUG] Requesting certificates...")
            conn.sendmsg(json.dumps({
                "action": "generate_certificates",
                "data": {
                    "repetitor_id": repetitor_id,
                    "pqc_csr": {
                        "subject_cn": repetitor_id,
                        "public_key": base64.b64encode(pqc_pk).decode()
                    },
                    "left_rsa_csr":  left_rsa_csr.replace("\n", "\\n")  if left_rsa_csr  else "",
                    "right_rsa_csr": right_rsa_csr.replace("\n", "\\n") if right_rsa_csr else ""
                }
            }).encode())

            certificates = json.loads(conn.recvmsg())
            if "error" in certificates:
                raise RuntimeError(f"Certificate generation failed: {certificates['error']}")
            print(f"[DEBUG] Received certificates")

            return {
                "configuration": configuration,
                "pqc_private_key": pqc_sk,
                "pqc_public_key":  pqc_pk,
                "pqc_certificate": certificates["pqc_certificate"],
                "left_rsa_key":          left_rsa_key,
                "left_rsa_certificate":  certificates.get("left_rsa_certificate", ""),
                "right_rsa_key":         right_rsa_key,
                "right_rsa_certificate": certificates.get("right_rsa_certificate", "")
            }
    finally:
        sock.close()


# ==================== PQC Channel (Repetitor to Repetitor via WolfSSL mTLS) ====================

def pqc_send_message(
    host: str,
    port: int,
    my_private_key: bytes,
    my_certificate: str,
    ca_certificate: str,
    message: dict,
    repetitor_id: str
):
    """Send message to another repetitor using PQC mTLS (WolfSSL ML-DSA-65)."""
    cert_der  = decode_pem(my_certificate, "CERTIFICATE")
    pkcs8_der = _pkcs8_mldsa65_der(my_private_key)
    ca_der    = decode_pem(ca_certificate, "CERTIFICATE")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(30)
        sock.connect((host, port))

        with wolfssl_mldsa.pqc_tls_client_connect(sock.fileno(), cert_der, pkcs8_der, ca_der) as conn:
            peer_cn, _, _, _, _ = _parse_x509_cert(conn.peer_cert_der())
            print(f"[{datetime.now():%H:%M:%S}][{repetitor_id}] PQC mTLS connected to {peer_cn} at {host}:{port}")

            conn.sendmsg(json.dumps(message).encode())
            ack = conn.recvmsg()
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
    """Receive message from another repetitor using PQC mTLS (WolfSSL ML-DSA-65)."""
    cert_der  = decode_pem(my_certificate, "CERTIFICATE")
    pkcs8_der = _pkcs8_mldsa65_der(my_private_key)
    ca_der    = decode_pem(ca_certificate, "CERTIFICATE")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_sock:
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((host, port))
        server_sock.listen(5)

        print(f"[{datetime.now():%H:%M:%S}][{repetitor_id}] PQC mTLS listener on {host}:{port}")

        conn_sock, addr = server_sock.accept()
        conn_sock.settimeout(30)

        try:
            with wolfssl_mldsa.pqc_tls_server_accept(conn_sock.fileno(), cert_der, pkcs8_der, ca_der) as conn:
                peer_cn, _, _, _, _ = _parse_x509_cert(conn.peer_cert_der())

                if whitelist and peer_cn not in whitelist:
                    raise ValueError(f"Client {peer_cn} not in whitelist")

                print(f"[{datetime.now():%H:%M:%S}][{repetitor_id}] PQC mTLS connection from {peer_cn} at {addr}")

                message = json.loads(conn.recvmsg().decode())
                conn.sendmsg(b"RECEIVED")

                return peer_cn, message
        finally:
            conn_sock.close()


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
