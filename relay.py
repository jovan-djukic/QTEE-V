#!/usr/bin/env python3
"""
QKD Relay

Every connection is WolfSSL TLS 1.3 with ML-KEM-768 as the sole configured
key-exchange group (strict -- no classical fallback) and ML-DSA-65 X.509
certs for signatures. Three connection types, not two:

1. Controller channel -- server-only auth (pqc_tls_client_connect_anon()):
   the controller presents its ML-DSA-65 cert; the relay has none yet at
   this point and is instead authenticated via HW attestation inside the
   tunnel. Not mTLS.
2. Relay <-> relay channel -- true mTLS (pqc_tls_client_connect()), both
   sides present ML-DSA-65 certs signed by the Relay CA. Custom
   length-prefixed message framing (pqc_send_message/pqc_receive_message).
3. Relay <-> KME channel -- also true mTLS, same Relay CA identity cert
   reused (no separate KME-facing cert), verified by the KME against a
   copy of that same Relay CA. Hand-rolled HTTP/1.1 over the mTLS tunnel
   (_kme_http_get()), since the KME speaks ETSI GS QKD 014 over HTTP, not
   the relay's own message protocol.
"""

import binascii
import hashlib
import hmac
import json
import socket
import sys
import os
import base64
from typing import Tuple, Optional, Dict, Any, List
from datetime import datetime, timezone
from threading import Thread, Semaphore, Lock

import wolfssl_mldsa

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend


# ==================== Configuration ====================

HOST = "127.0.0.1"
CONTROLLER_HOST = "127.0.0.1"
CONTROLLER_PORT = "8000"
CTRL_TLS_PORT = 8001       # WolfSSL TLS port — all protocol steps after CA cert fetch
KME_PORT = "8443"  # self-hosted next-door-key-simulator proxy port (all 4 KMEs)

MLDSA_ALGORITHM = "ML-DSA-65"

# Relay CA certificate — pre-deployed in firmware, loaded from disk at
# startup. NOT fetched over the network; the file must exist before the
# relay starts. Signs the controller's cert, this relay's own identity
# cert, and (since that same cert now doubles as the relay's SAE identity)
# is what each KME checks a relay's client cert against.
PQC_CA_CERT_PATH = "./pqc_ca/ca_certificate.pem"
PQC_CA_CERTIFICATE: Optional[str] = None

# KME CA certificate — NOT pre-deployed; delivered by the controller over
# the already-authenticated TLS channel (see configuration["kme_ca_certificate"]).
# Used to verify a KME's own server cert. The relay never has this CA's
# private key.
KME_CA_CERTIFICATE: Optional[str] = None


# ==================== PEM Decoding ====================

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
#
# wolfssl_mldsa.c's keygen/sign both draw from a single process-wide WC_RNG
# (g_rng) with no internal locking. All 3 relays run as threads in one
# process (see __main__ below) and each generates its own ML-DSA-65 identity
# keypair at startup, so unsynchronized concurrent calls race on that shared
# RNG state -- observed as one relay's KME/relay TLS calls hanging
# indefinitely (not erroring) after a corrupted-looking keygen. Verification
# doesn't touch the RNG and needs no lock; keygen and signing do.
_MLDSA_RNG_LOCK = Lock()


def mldsa_generate_keypair() -> Tuple[bytes, bytes]:
    with _MLDSA_RNG_LOCK:
        signer = wolfssl_mldsa.Signature(MLDSA_ALGORITHM)
        public_key = signer.generate_keypair()
        private_key = signer.export_secret_key()
    return public_key, private_key


def mldsa_sign(private_key: bytes, data: bytes) -> bytes:
    with _MLDSA_RNG_LOCK:
        signer = wolfssl_mldsa.Signature(MLDSA_ALGORITHM, private_key)
        return signer.sign(data)


def mldsa_verify(public_key: bytes, data: bytes, signature: bytes) -> bool:
    verifier = wolfssl_mldsa.Signature(MLDSA_ALGORITHM)
    return verifier.verify(data, signature, public_key)


# ==================== Attestation ====================

def get_attestation_report(nonce: str, relay_id: str) -> str:
    data = nonce.encode() + relay_id.encode()
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


# ==================== Secure Configuration Protocol ====================

def get_configuration(
    controller_host: str,
    relay_id: str,
    relay_ip: str
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
                "data": {"relay_id": relay_id, "relay_ip": relay_ip, "platform": "native"}
            }).encode())

            reg_data = json.loads(conn.recvmsg())
            if "error" in reg_data:
                raise RuntimeError(f"Register failed: {reg_data['error']}")
            nonce = reg_data["nonce"]
            print(f"[DEBUG] Received nonce={nonce}")

            # ── Step 2: Attest — SHA256(nonce_hex + relay_id) ────────────
            attestation_report = get_attestation_report(nonce, relay_id)
            print(f"[DEBUG] Sending attest...")
            conn.sendmsg(json.dumps({
                "action": "attest",
                "data": {"relay_id": relay_id, "attestation_report": attestation_report}
            }).encode())

            attest_data = json.loads(conn.recvmsg())
            if "error" in attest_data:
                raise RuntimeError(f"Attestation failed: {attest_data['error']}")
            if attest_data.get("status") != "authenticated":
                raise RuntimeError("Authentication failed")
            print(f"[DEBUG] Authenticated with controller")

            # ── Step 3: Configuration (blocks until all relays ready) ─────
            print(f"[DEBUG] Requesting configuration...")
            conn.sendmsg(json.dumps({
                "action": "configuration",
                "data": {"relay_id": relay_id}
            }).encode())

            configuration = json.loads(conn.recvmsg())
            if "error" in configuration:
                raise RuntimeError(f"Configuration failed: {configuration['error']}")
            print(f"[DEBUG] Received configuration")

            global PQC_CA_CERTIFICATE, KME_CA_CERTIFICATE
            PQC_CA_CERTIFICATE = ca_pem   # already loaded from pre-deployed file
            KME_CA_CERTIFICATE = configuration.get("kme_ca_certificate", "")

            # ── Step 4: Generate identity keypair and request a certificate ───
            # This one ML-DSA-65 cert (Relay CA-signed) is used everywhere:
            # relay <-> relay mTLS, and now relay <-> KME auth too (the KME
            # trusts it via the Relay CA cert the controller handed it).
            print(f"[DEBUG] Generating ML-DSA-65 keypair for relay identity...")
            pqc_pk, pqc_sk = mldsa_generate_keypair()

            print(f"[DEBUG] Requesting certificate...")
            conn.sendmsg(json.dumps({
                "action": "generate_certificates",
                "data": {
                    "relay_id": relay_id,
                    "pqc_csr": {
                        "subject_cn": relay_id,
                        "public_key": base64.b64encode(pqc_pk).decode()
                    }
                }
            }).encode())

            certificates = json.loads(conn.recvmsg())
            if "error" in certificates:
                raise RuntimeError(f"Certificate generation failed: {certificates['error']}")
            print(f"[DEBUG] Received certificate")

            return {
                "configuration": configuration,
                "pqc_private_key": pqc_sk,
                "pqc_public_key":  pqc_pk,
                "pqc_certificate": certificates["pqc_certificate"]
            }
    finally:
        sock.close()


# ==================== PQC Channel (Relay to Relay via WolfSSL mTLS) ====================

def pqc_send_message(
    host: str,
    port: int,
    my_private_key: bytes,
    my_certificate: str,
    ca_certificate: str,
    message: dict,
    relay_id: str
):
    """Send message to another relay via mTLS (WolfSSL TLS 1.3, ML-KEM-768 KEX, ML-DSA-65 certs)."""
    cert_der  = decode_pem(my_certificate, "CERTIFICATE")
    pkcs8_der = _pkcs8_mldsa65_der(my_private_key)
    ca_der    = decode_pem(ca_certificate, "CERTIFICATE")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(30)
        sock.connect((host, port))

        with wolfssl_mldsa.pqc_tls_client_connect(sock.fileno(), cert_der, pkcs8_der, ca_der) as conn:
            peer_cn, _, _, _, _ = _parse_x509_cert(conn.peer_cert_der())
            print(f"[{datetime.now():%H:%M:%S}][{relay_id}] PQC mTLS connected to {peer_cn} at {host}:{port}")

            conn.sendmsg(json.dumps(message).encode())
            ack = conn.recvmsg()
            print(f"[{datetime.now():%H:%M:%S}][{relay_id}] Received ack: {ack.decode()}")


def pqc_receive_message(
    host: str,
    port: int,
    my_private_key: bytes,
    my_certificate: str,
    ca_certificate: str,
    whitelist: List[str],
    relay_id: str
) -> Tuple[str, dict]:
    """Receive message to another relay via mTLS (WolfSSL TLS 1.3, ML-KEM-768 KEX, ML-DSA-65 certs)."""
    cert_der  = decode_pem(my_certificate, "CERTIFICATE")
    pkcs8_der = _pkcs8_mldsa65_der(my_private_key)
    ca_der    = decode_pem(ca_certificate, "CERTIFICATE")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_sock:
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((host, port))
        server_sock.listen(5)

        print(f"[{datetime.now():%H:%M:%S}][{relay_id}] PQC mTLS listener on {host}:{port}")

        conn_sock, addr = server_sock.accept()
        conn_sock.settimeout(30)

        try:
            with wolfssl_mldsa.pqc_tls_server_accept(conn_sock.fileno(), cert_der, pkcs8_der, ca_der) as conn:
                peer_cn, _, _, _, _ = _parse_x509_cert(conn.peer_cert_der())

                if whitelist and peer_cn not in whitelist:
                    raise ValueError(f"Client {peer_cn} not in whitelist")

                print(f"[{datetime.now():%H:%M:%S}][{relay_id}] PQC mTLS connection from {peer_cn} at {addr}")

                message = json.loads(conn.recvmsg().decode())
                conn.sendmsg(b"RECEIVED")

                return peer_cn, message
        finally:
            conn_sock.close()


# ==================== KME Communication (mTLS, ML-KEM-768 + ML-DSA-65) ====================
#
# The KME (next-door-key-simulator) speaks plain HTTP/1.1 over a WolfSSL
# mTLS tunnel (TLS 1.3, ML-KEM-768 KEX, ML-DSA-65 certs), not TLS terminated
# by Python's ssl module (which cannot handle ML-DSA-65 certs or ML-KEM-768).
# We open the raw TCP socket ourselves, hand it to wolfssl_mldsa's mTLS
# client, and speak HTTP by hand — same idiom the relay already uses for
# relay-to-relay PQC messaging.

class _KmeHttpResponse:
    """Minimal stand-in for requests.Response — just enough for the callers."""
    def __init__(self, status_code: int, body: bytes):
        self.status_code = status_code
        self._body = body

    def json(self):
        return json.loads(self._body.decode())


def _split_host_port(host_port: str, default_port: str) -> Tuple[str, str]:
    """Split "host:port" (controller.py's LINKS entries) into (host, port).
    Falls back to default_port if no ":" is present (bare host)."""
    if not host_port:
        return "", default_port
    if ":" in host_port:
        host, port = host_port.rsplit(":", 1)
        return host, port
    return host_port, default_port


def _kme_http_get(
    private_key: bytes,
    certificate: str,
    ca_certificate: str,
    kme_host: str,
    kme_port: str,
    path: str
) -> _KmeHttpResponse:
    """Issue an HTTP GET to a KME over mTLS (ML-KEM-768 + ML-DSA-65) and return the response."""
    cert_der = decode_pem(certificate, "CERTIFICATE")
    ca_der = decode_pem(ca_certificate, "CERTIFICATE")
    pkcs8_der = _pkcs8_mldsa65_der(private_key)

    sock = socket.create_connection((kme_host, int(kme_port)), timeout=30)
    try:
        with wolfssl_mldsa.pqc_tls_client_connect(sock.fileno(), cert_der, pkcs8_der, ca_der) as conn:
            request = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {kme_host}\r\n"
                f"Connection: close\r\n\r\n"
            ).encode()
            conn.send(request)
            raw = conn.recv_until_close()
    finally:
        sock.close()

    header_blob, _, body = raw.partition(b"\r\n\r\n")
    status_line = header_blob.split(b"\r\n", 1)[0].decode()
    status_code = int(status_line.split(" ")[1])
    return _KmeHttpResponse(status_code, body)


def kme_get_status(
    private_key: bytes,
    certificate: str,
    ca_certificate: str,
    kme_host: str,
    kme_port: str,
    kme_slave: str
):
    """Get status from KME."""
    return _kme_http_get(private_key, certificate, ca_certificate, kme_host, kme_port,
                          f"/api/v1/keys/{kme_slave}/status")


def kme_get_key(
    private_key: bytes,
    certificate: str,
    ca_certificate: str,
    kme_host: str,
    kme_port: str,
    kme_slave: str
):
    """Get encryption key from KME."""
    return _kme_http_get(private_key, certificate, ca_certificate, kme_host, kme_port,
                          f"/api/v1/keys/{kme_slave}/enc_keys").json()


def kme_get_key_with_id(
    private_key: bytes,
    certificate: str,
    ca_certificate: str,
    kme_host: str,
    kme_port: str,
    kme_master: str,
    key_id: str
):
    """Get decryption key from KME by ID."""
    return _kme_http_get(private_key, certificate, ca_certificate, kme_host, kme_port,
                          f"/api/v1/keys/{kme_master}/dec_keys?key_ID={key_id}").json()


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

def main(relay_id: str, port: int, print_semaphore: Semaphore) -> None:
    """Main function for relay."""
    
    # Get configuration from the controller (all ML-DSA-65 PQC)
    result = get_configuration(
        CONTROLLER_HOST,
        relay_id,
        f"127.0.0.1:{port}"
    )
    
    configuration = result["configuration"]
    
    print_semaphore.acquire()
    print(f"\n[{datetime.now():%H:%M:%S}][{relay_id}] Configuration received:")
    print(json.dumps({k: v for k, v in configuration.items() if k != "pqc_ca_certificate"}, indent=2))
    print_semaphore.release()
    
    # PQC credentials -- one identity cert, used for relay-to-relay mTLS
    # AND relay-to-KME auth (the KME verifies it against a copy of the
    # Relay CA the controller handed it; see KME_CA_CERTIFICATE).
    pqc_sk = result["pqc_private_key"]
    pqc_pk = result["pqc_public_key"]
    pqc_cert = result["pqc_certificate"]

    # Extract configuration values. left_kme/right_kme carry "host:port" (see
    # controller.py's LINKS) since the 4 KME containers map to different host
    # ports rather than sharing one -- split out here instead of using a
    # fixed KME_PORT.
    left_kme = configuration.get("left_kme", "")
    right_kme = configuration.get("right_kme", "")
    left_kme_host, left_kme_port = _split_host_port(left_kme, KME_PORT)
    right_kme_host, right_kme_port = _split_host_port(right_kme, KME_PORT)
    left_kme_peer = configuration.get("left_kme_peer", "")
    right_kme_peer = configuration.get("right_kme_peer", "")
    whitelist = [item.strip() for item in configuration.get("whitelist", "").split("|") if item.strip()]
    
    left_relay_ip = configuration.get("left_relay_ip", "")
    right_relay_ip = configuration.get("right_relay_ip", "")
    left_relay_id = configuration.get("left_relay_id", "")
    right_relay_id = configuration.get("right_relay_id", "")
    
    # Determine position
    position = "left" if not left_kme else ("right" if not right_kme else "middle")
    
    print_semaphore.acquire()
    print(f"[{datetime.now():%H:%M:%S}][{relay_id}] Position: {position}")
    print(f"[{datetime.now():%H:%M:%S}][{relay_id}] Whitelist: {whitelist}")
    print(f"[{datetime.now():%H:%M:%S}][{relay_id}] Left neighbor: {left_relay_id} at {left_relay_ip}")
    print(f"[{datetime.now():%H:%M:%S}][{relay_id}] Right neighbor: {right_relay_id} at {right_relay_ip}")
    print_semaphore.release()
    
    # Verify PQC CA certificate
    if PQC_CA_CERTIFICATE:
        valid, cn, _ = verify_pqc_certificate(pqc_cert, PQC_CA_CERTIFICATE)
        print_semaphore.acquire()
        print(f"[{datetime.now():%H:%M:%S}][{relay_id}] PQC certificate verification: {'✓' if valid else '✗'} (CN={cn})")
        print_semaphore.release()
    
    # Test KME connectivity (using this relay's own identity cert as its SAE cert)
    if left_kme:
        print_semaphore.acquire()
        print(f"[{datetime.now():%H:%M:%S}][{relay_id}] Testing left KME ({left_kme})...")
        try:
            status = kme_get_status(pqc_sk, pqc_cert, KME_CA_CERTIFICATE, left_kme_host, left_kme_port, left_kme_peer)
            print(f"[{datetime.now():%H:%M:%S}][{relay_id}] Left KME status: {status.status_code}")
        except Exception as e:
            print(f"[{datetime.now():%H:%M:%S}][{relay_id}] Left KME error: {e}")
        print_semaphore.release()

    if right_kme:
        print_semaphore.acquire()
        print(f"[{datetime.now():%H:%M:%S}][{relay_id}] Testing right KME ({right_kme})...")
        try:
            status = kme_get_status(pqc_sk, pqc_cert, KME_CA_CERTIFICATE, right_kme_host, right_kme_port, right_kme_peer)
            print(f"[{datetime.now():%H:%M:%S}][{relay_id}] Right KME status: {status.status_code}")
        except Exception as e:
            print(f"[{datetime.now():%H:%M:%S}][{relay_id}] Right KME error: {e}")
        print_semaphore.release()
    
    print(f"[{datetime.now():%H:%M:%S}][{relay_id}] Ready - entering message relay loop")
    
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
                relay_id=relay_id
            )
            
            print_semaphore.acquire()
            print(f"[{datetime.now():%H:%M:%S}][{relay_id}] Received message from {sender_cn}")
            print_semaphore.release()
            
            # Determine direction (from left or right)
            is_from_left = (sender_cn == left_relay_id)
            
            # Get KME info for decryption (incoming direction) -- this
            # relay's own identity cert doubles as its SAE cert everywhere
            kme_decrypt = left_kme if is_from_left else right_kme
            kme_decrypt_host = left_kme_host if is_from_left else right_kme_host
            kme_decrypt_port = left_kme_port if is_from_left else right_kme_port
            kme_decrypt_peer = left_kme_peer if is_from_left else right_kme_peer

            # Get KME info for encryption (outgoing direction)
            kme_encrypt = right_kme if is_from_left else left_kme
            kme_encrypt_host = right_kme_host if is_from_left else left_kme_host
            kme_encrypt_port = right_kme_port if is_from_left else left_kme_port
            kme_encrypt_peer = right_kme_peer if is_from_left else left_kme_peer

            # Get next hop info
            to_ip = right_relay_ip if is_from_left else left_relay_ip
            
            # Extract message content
            from_ciphertext = from_message.get("message", "")
            from_key_id = from_message.get("key_ID", "")
            
            # Decrypt incoming message (if we have a KME on that side)
            if kme_decrypt and from_key_id:
                print(f"[{datetime.now():%H:%M:%S}][{relay_id}] Getting decryption key from KME {kme_decrypt}...")
                get_key_response = kme_get_key_with_id(
                    private_key=pqc_sk,
                    certificate=pqc_cert,
                    ca_certificate=KME_CA_CERTIFICATE,
                    kme_host=kme_decrypt_host,
                    kme_port=kme_decrypt_port,
                    kme_master=kme_decrypt_peer,
                    key_id=from_key_id
                )
                from_key = get_key_response["keys"][0]["key"]
                print(f"[{datetime.now():%H:%M:%S}][{relay_id}] Decrypting with QKD key...")
                plaintext = qkd_decrypt(from_ciphertext, from_key)
            else:
                # No KME on incoming side (we're at an edge)
                plaintext = from_ciphertext
            
            print_semaphore.acquire()
            print(f"[{datetime.now():%H:%M:%S}][{relay_id}] Plaintext: {plaintext[:100]}...")
            print_semaphore.release()
            
            # Encrypt for outgoing (if we have a KME on that side)
            if kme_encrypt:
                print(f"[{datetime.now():%H:%M:%S}][{relay_id}] Getting encryption key from KME {kme_encrypt}...")
                get_key_response = kme_get_key(
                    private_key=pqc_sk,
                    certificate=pqc_cert,
                    ca_certificate=KME_CA_CERTIFICATE,
                    kme_host=kme_encrypt_host,
                    kme_port=kme_encrypt_port,
                    kme_slave=kme_encrypt_peer
                )
                to_key_id = get_key_response["keys"][0]["key_ID"]
                to_key = get_key_response["keys"][0]["key"]
                print(f"[{datetime.now():%H:%M:%S}][{relay_id}] Encrypting with QKD key...")
                to_ciphertext = qkd_encrypt(plaintext, to_key)
            else:
                # No KME on outgoing side (we're at an edge)
                to_ciphertext = plaintext
                to_key_id = ""
            
            to_message = {"message": to_ciphertext, "key_ID": to_key_id}
            
            # Forward to next hop via PQC channel
            to_host, to_port = to_ip.split(":")
            print(f"[{datetime.now():%H:%M:%S}][{relay_id}] Forwarding to {to_ip}...")
            
            try:
                pqc_send_message(
                    host=to_host,
                    port=int(to_port),
                    my_private_key=pqc_sk,
                    my_certificate=pqc_cert,
                    ca_certificate=PQC_CA_CERTIFICATE,
                    message=to_message,
                    relay_id=relay_id
                )
                print(f"[{datetime.now():%H:%M:%S}][{relay_id}] Message forwarded successfully")
            except Exception as e:
                print_semaphore.acquire()
                print(f"[{datetime.now():%H:%M:%S}][{relay_id}] Error forwarding: {e}")
                print_semaphore.release()
                
        except Exception as e:
            print_semaphore.acquire()
            print(f"[{datetime.now():%H:%M:%S}][{relay_id}] Error in relay loop: {e}")
            print_semaphore.release()
            import traceback
            traceback.print_exc()


if __name__ == "__main__":
    print_semaphore = Semaphore(1)
    
    relay_indices = [0, 1, 2]
    
    if len(sys.argv) > 1:
        relay_indices = [int(arg) for arg in sys.argv[1:]]
    
    for i in relay_indices:
        thread = Thread(
            target=main,
            args=(f"R{i}", 9000 + i, print_semaphore)
        )
        thread.start()
