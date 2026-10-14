"""
QKD Relay Controller

This controller implements:
1. WolfSSL TLS server (port 8001) for all controller-relay protocol:
   - Relay registration and attestation (nonce-based)
   - Configuration distribution
   - ML-DSA-65 certificates for relay ↔ relay communication
   - ML-DSA-65 certificates for relay ↔ KME communication
2. Plain HTTP server (port 8000, FastAPI/uvicorn):
   - GET /health   — health check

Bootstrap order:
  The PQC CA certificate is pre-deployed on every relay (copied to
  ./pqc_ca/ca_certificate.pem before first run).  Relays load it from
  disk, then connect to port 8001 via WolfSSL TLS (server-only auth:
  controller presents its ML-DSA-65 cert; relay is authenticated via
  nonce-based attestation inside the TLS tunnel).

Attestation:
  A relay is admitted only on a Keystone attestation report that chains to
  the pinned root key, carries the pinned enclave measurement, and binds
  "<relay_id>:<nonce_hex>" (see keystone_attestation.py). The SHA256
  stand-in report of non-enclave relays (relay.py, native relay.c) is
  refused unless --insecure-dev-attestation names that relay. The relay's
  platform is inferred from which kind of report verified, never taken
  from the relay. All actions after register are bound to the TLS
  connection that registered, not to a relay_id the client names.

One PKI domain: the controller signs everything (its own cert, relay
identity certs, and KME/SAE identity certs) with a single ML-DSA-65 CA.

Usage:
  # Generate PQC CA:
  python generate_pqc_ca.py --output-dir ./pqc_ca

  # Run controller:
  python controller.py --pqc-ca-cert ./pqc_ca/ca_certificate.pem --pqc-ca-key ./pqc_ca/ca_private_key.pem \
      --enclave-measurement <hex>                # admit enclave relays
      [--insecure-dev-attestation R0,R2]         # also admit these non-enclave relays (dev only)
"""

import threading
from typing import Dict, Optional
from fastapi import FastAPI
import socket
import base64
import os
import sys
import json
import hashlib
import hmac
import binascii
import argparse

import wolfssl_mldsa
import keystone_attestation
from keystone_attestation import AttestationError

from datetime import datetime, timedelta, timezone

application = FastAPI()

# ==================== Configuration ====================

PYTHON_IP = "127.0.0.1"
RISCV_IP = "192.168.100.2"

# TLS port for the WolfSSL controller server
CTRL_TLS_PORT = 8001

# wolfssl_mldsa.Signature only supports ML-DSA-65 -- no detection needed.
MLDSA_ALGORITHM = "ML-DSA-65"

# Relay CA (for controller <-> relay, relay <-> relay, and now relay <-> KME
# identity -- the controller signs and holds the private key)
PQC_CA_PRIVATE_KEY: Optional[bytes] = None
PQC_CA_PUBLIC_KEY: Optional[bytes] = None
PQC_CA_CERTIFICATE: Optional[str] = None
PQC_CA_SUBJECT_CN: Optional[str] = None

# KME CA (signs each KME's own server cert -- a *separate* trust domain so a
# compromised controller/relay can't forge a cert a KME would trust, and
# vice versa). The controller only ever reads this CA's public certificate,
# to hand to relays so they can verify a KME's server cert -- it never has
# and never needs the KME CA's private key.
KME_CA_CERTIFICATE: Optional[str] = None

# Controller's own ML-DSA-65 cert (for TLS server auth)
CTRL_PRIVATE_KEY: Optional[bytes] = None
CTRL_CERTIFICATE: Optional[str] = None   # PEM string

# Attestation policy (set from the command line, see Main)
# SHA3-512 measurement of the release relay enclave (loader + eyrie-rt +
# relay eapp). None => no enclave relay can be admitted.
ENCLAVE_MEASUREMENT: Optional[bytes] = None
# SHA3-512 of the Security Monitor image. None => SM hash not pinned (the
# SM is still authenticated through the root-key signature).
SM_MEASUREMENT: Optional[bytes] = None
# Ed25519(SHA3) device root key that must endorse the SM.
ATTESTATION_ROOT_KEY: bytes = keystone_attestation.KEYSTONE_TEST_DEV_PUBLIC_KEY
# Relays allowed to authenticate with the SHA256 dev stand-in report:
# None => nobody (default), "*" => everybody, else a set of relay_ids.
DEV_ATTESTATION_RELAYS = None
DEV_REPORT_PREFIX = "attestation_report:"

# CA file paths
PQC_CA_CERT_PATH = "./pqc_ca/ca_certificate.pem"
PQC_CA_KEY_PATH = "./pqc_ca/ca_private_key.pem"
KME_CA_CERT_PATH = "./kme_ca/ca_certificate.pem"

# ==================== Threading Primitives ====================

sessions_lock = threading.Lock()
relays_lock = threading.Lock()
configuration_condition = threading.Condition(relays_lock)

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


def load_kme_ca_certificate(cert_path: str):
    """Load the KME CA's *public* certificate only -- the controller never
    holds the KME CA private key (see KME_CA_CERTIFICATE comment above)."""
    global KME_CA_CERTIFICATE

    with open(cert_path, 'r') as f:
        KME_CA_CERTIFICATE = f.read()

    cn, _, _ = _parse_x509_cert(decode_pem(KME_CA_CERTIFICATE, "CERTIFICATE"))
    print(f"Loaded KME CA certificate: CN={cn} (public cert only, no private key)")


def generate_controller_cert():
    """Generate the controller's own ML-DSA-65 certificate, signed by the PQC CA.

    This certificate is presented to relays during the TLS handshake on
    port 8001, allowing them to verify they are talking to the real controller.
    """
    global CTRL_PRIVATE_KEY, CTRL_CERTIFICATE
    ctrl_signer = wolfssl_mldsa.Signature(MLDSA_ALGORITHM)
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


# ==================== ML-DSA Signatures ====================

def mldsa_sign(private_key: bytes, data: bytes) -> bytes:
    """Sign data with ML-DSA-65."""
    signer = wolfssl_mldsa.Signature(MLDSA_ALGORITHM, private_key)
    return signer.sign(data)


def mldsa_verify(public_key: bytes, data: bytes, signature: bytes) -> bool:
    """Verify ML-DSA-65 signature."""
    verifier = wolfssl_mldsa.Signature(MLDSA_ALGORITHM)
    return verifier.verify(data, signature, public_key)


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


# ==================== Helper Functions ====================

def url_to_ipv4(url: str) -> str:
    """Convert a URL / bare "host[:port]" to an IPv4 address.

    Deliberately does NOT use urlsplit(): for a scheme-less input like
    "127.0.0.1:8010" (which is what LINKS entries are — see below), urlsplit
    treats "127.0.0.1" as the *scheme* (its scheme parsing is lenient about
    leading digits) and leaves "8010" as the path, which gethostbyname()
    then happily resolves as a legacy 32-bit-integer IP literal instead of
    raising -- e.g. "127.0.0.1:8010" silently became "0.0.31.74". Plain
    string splitting sidesteps that class of confusion entirely.
    """
    try:
        hostname = url
        if "://" in hostname:
            hostname = hostname.split("://", 1)[1]
        hostname = hostname.split("/", 1)[0]
        if hostname.startswith('[') and ']' in hostname:
            hostname = hostname[1:hostname.index(']')]
        elif hostname.count(':') == 1:
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

# Self-hosted next-door-key-simulator KMEs (external/next-door-key-simulator),
# one pair per QKD link. "host:port" per entry (not
# just a host with a shared port) since the relay/controller run on the
# Docker *host*, not inside the kme-network bridge -- on VM-backed Docker
# setups (Docker Desktop etc.) the host has no route to the bridge subnet at
# all, so the containers' `ports:` host-mappings (docker-compose.yml) are
# the only thing reachable, and each of the 4 containers maps to a
# different host port. Relays parse the port out of these strings (see
# relay.py's KME calls / relay.c's parse_url()) instead of using one fixed
# KME_PORT. If your Docker setup gives the host a real route to the bridge
# network, "172.23.1.10:8443" (the container's own address) works too.
# No SAE-specific naming here anymore: each relay presents its own single
# PQC identity cert (pqc_certificate, signed by the Relay CA) as its SAE
# identity too, so a KME's ATTACHED_SAE_ID is just that relay's relay_id.
LINKS = [
    {
        "start": "127.0.0.1:8010",   # kme-link0-start
        "end": "127.0.0.1:8011",     # kme-link0-end
    },
    {
        "start": "127.0.0.1:8012",   # kme-link1-start
        "end": "127.0.0.1:8013",     # kme-link1-end
    }
]


class RelaySession:
    def __init__(self, relay_id: str):
        self.relay_id: str = relay_id
        self.nonce: Optional[bytes] = None
        self.relay_ip: str = ""
        self.authenticated: bool = False
        # "riscv" (verified Keystone enclave report) or "native" (dev SHA256
        # stand-in, only under --insecure-dev-attestation). Set by
        # handle_attest from the kind of report that verified -- never
        # taken from the relay. Kept independent of relay_id, which must
        # stay a clean "R0"/"R1"/"R2" to match the KME's fixed ATTACHED_SAE_ID.
        self.platform: Optional[str] = None


class ConnContext:
    """Per-TLS-connection state. register binds a session to the connection;
    every later action uses that session, so a second connection cannot ride
    on another connection's attestation by naming its relay_id."""
    def __init__(self):
        self.session: Optional[RelaySession] = None


# Admitted (or in-progress) sessions by relay_id -- used only to stop a
# second registration for a relay that has already been admitted.
SESSIONS: Dict[str, RelaySession] = {}
RELAYS = [None, None, None]


# ==================== Attestation Verification ====================

def dev_attestation_allowed(relay_id: str) -> bool:
    if DEV_ATTESTATION_RELAYS is None:
        return False
    return DEV_ATTESTATION_RELAYS == "*" or relay_id in DEV_ATTESTATION_RELAYS


def verify_attestation(relay_id: str, nonce: bytes, report: str) -> str:
    """Verify an attestation report; return the platform it proves.

    Raises AttestationError on any failure.
    """
    if report.startswith(DEV_REPORT_PREFIX):
        if not dev_attestation_allowed(relay_id):
            raise AttestationError(
                "non-enclave (dev stand-in) report refused; "
                "--insecure-dev-attestation does not cover this relay")
        print(f"[{relay_id}] !!! WARNING: INSECURE DEV ATTESTATION -- "
              f"relay is NOT running in a TEE; report is a nonce echo !!!")
        expected = DEV_REPORT_PREFIX + hashlib.sha256(
            nonce.hex().encode() + relay_id.encode()).hexdigest()
        if not hmac.compare_digest(report, expected):
            raise AttestationError("dev stand-in report mismatch")
        return "native"

    if ENCLAVE_MEASUREMENT is None:
        raise AttestationError(
            "no --enclave-measurement pinned; enclave relays cannot be admitted")
    try:
        raw = base64.b64decode(report, validate=True)
    except (binascii.Error, ValueError):
        raise AttestationError("report is neither a dev stand-in nor a base64 Keystone report")

    # relay.c binds snprintf("%s:%s", relay_id, nonce_hex) into the report
    expected_data = f"{relay_id}:{nonce.hex()}".encode()
    r = keystone_attestation.verify_report(
        raw,
        dev_public_key=ATTESTATION_ROOT_KEY,
        expected_enclave_hash=ENCLAVE_MEASUREMENT,
        expected_sm_hash=SM_MEASUREMENT,
        expected_data=expected_data,
    )
    print(f"[{relay_id}] Keystone report verified: "
          f"enclave={r.enclave_hash.hex()[:16]}... sm={r.sm_hash.hex()[:16]}... "
          f"data={expected_data.decode()}")
    return "riscv"


# ==================== Protocol Handlers (sync, thread-safe) ====================

def handle_register(data: dict, ctx: ConnContext) -> dict:
    """Handle register inside the TLS tunnel: issue a nonce for attestation."""
    try:
        relay_id = data["relay_id"]
        print(f"[{relay_id}] Register")

        if ctx.session is not None:
            return {"error": "Connection already registered"}

        nonce = os.urandom(32)
        with sessions_lock:
            existing = SESSIONS.get(relay_id)
            if existing is not None and existing.authenticated:
                print(f"[{relay_id}] Refused: relay already admitted")
                return {"error": "Relay already admitted"}
            session = RelaySession(relay_id)
            session.nonce = nonce
            session.relay_ip = data.get("relay_ip", "")
            SESSIONS[relay_id] = session
        ctx.session = session

        print(f"[{relay_id}] Nonce: {nonce.hex()}")
        return {"nonce": nonce.hex()}
    except Exception as e:
        print(f"Error in handle_register: {e}")
        return {"error": str(e)}


def handle_attest(data: dict, ctx: ConnContext) -> dict:
    """Handle attest inside the TLS tunnel: verify the attestation report
    against the nonce issued on this connection."""
    try:
        session = ctx.session
        relay_id = session.relay_id
        attestation_report = data.get("attestation_report", "")

        # Single use: a nonce is consumed by the first attest, pass or fail.
        nonce, session.nonce = session.nonce, None
        if nonce is None:
            return {"error": "No outstanding nonce (register again)"}

        try:
            platform = verify_attestation(relay_id, nonce, attestation_report)
        except AttestationError as e:
            print(f"[{relay_id}] Attestation verification failed: {e}")
            with sessions_lock:
                if SESSIONS.get(relay_id) is session:
                    del SESSIONS[relay_id]
            ctx.session = None
            return {"error": "Attestation verification failed"}

        with sessions_lock:
            if SESSIONS.get(relay_id) is not session:
                # Another connection re-registered this relay_id meanwhile
                return {"error": "Session superseded"}
            session.platform = platform
            session.authenticated = True
        print(f"[{relay_id}] Authenticated (platform={platform})")

        with relays_lock:
            try:
                index = int(relay_id[-1])
                if 0 <= index < len(RELAYS):
                    RELAYS[index] = {
                        "relay_id": relay_id,
                        "relay_port": session.relay_ip.split(":")[-1] if ":" in session.relay_ip else "9001",
                        "platform": session.platform,
                    }
                    print(f"[{relay_id}] Registered (index {index})")
            except (ValueError, IndexError) as e:
                print(f"[{relay_id}] Could not parse index: {e}")

            configuration_condition.notify_all()

        return {"status": "authenticated"}
    except Exception as e:
        print(f"Error in handle_attest: {e}")
        return {"error": str(e)}


def handle_configuration(data: dict, ctx: ConnContext) -> dict:
    """Handle configuration request inside the TLS tunnel. Blocks until all relays are ready."""
    try:
        session = ctx.session
        if not session.authenticated:
            return {"error": "Not authenticated"}
        relay_id = session.relay_id

        print(f"[{relay_id}] Configuration request")

        # Block until all relays have registered
        with configuration_condition:
            while any(r is None for r in RELAYS):
                status = [r['relay_id'] if r else None for r in RELAYS]
                print(f"[{relay_id}] Waiting... RELAYS = {status}")
                configuration_condition.wait()

        print(f"[{relay_id}] All relays registered!")

        index = None
        for i, rep in enumerate(RELAYS):
            if rep and rep["relay_id"] == relay_id:
                index = i
                break

        if index is None:
            return {"error": "Relay not found"}

        base_ip = RISCV_IP if RELAYS[index].get("platform") == "riscv" else PYTHON_IP

        left_port = RELAYS[index - 1]["relay_port"] if index > 0 else "8998"
        right_port = RELAYS[index + 1]["relay_port"] if index < len(RELAYS) - 1 else "8999"

        # KME addresses need the same base_ip substitution as relay-to-relay
        # ones: from inside QEMU, 127.0.0.1 is the guest's own loopback, not
        # the host running the KME containers -- a riscv relay must reach
        # them via the same NAT gateway (RISCV_IP) it uses for everything
        # else on the host. LINKS only supplies the port; the host comes
        # from base_ip, same as left_relay_ip/right_relay_ip above.
        left_kme_port = LINKS[index - 1]["end"].split(":")[-1] if index > 0 else ""
        right_kme_port = LINKS[index]["start"].split(":")[-1] if index < len(LINKS) else ""

        configuration = {
            "left_relay_ip": f"{base_ip}:{left_port}",
            "right_relay_ip": f"{base_ip}:{right_port}",
            "left_relay_id": RELAYS[index - 1]["relay_id"] if index > 0 else "test_client",
            "right_relay_id": RELAYS[index + 1]["relay_id"] if index < len(RELAYS) - 1 else "test_client",
            "left_kme": f"{base_ip}:{left_kme_port}" if left_kme_port else "",
            "right_kme": f"{base_ip}:{right_kme_port}" if right_kme_port else "",
            # This relay's own identity (its pqc_certificate CN) doubles as
            # its SAE ID on both KMEs it talks to -- no separate SAE cert.
            "left_cn": relay_id if index > 0 else "test_client",
            "right_cn": relay_id if index < len(LINKS) else "test_client",
            "left_kme_peer": RELAYS[index - 1]["relay_id"] if index > 0 else "",
            "right_kme_peer": RELAYS[index + 1]["relay_id"] if index < len(RELAYS) - 1 else "",
            "whitelist": "|".join(filter(None, [
                RELAYS[index - 1]["relay_id"] if index > 0 else "test_client",
                RELAYS[index + 1]["relay_id"] if index < len(RELAYS) - 1 else "test_client",
            ])),
            "pqc_ca_certificate": PQC_CA_CERTIFICATE,
            "kme_ca_certificate": KME_CA_CERTIFICATE
        }

        configuration["left_kme_ip"] = url_to_ipv4(configuration["left_kme"]) if configuration["left_kme"] else ""
        configuration["right_kme_ip"] = url_to_ipv4(configuration["right_kme"]) if configuration["right_kme"] else ""

        return configuration

    except Exception as e:
        print(f"Error in handle_configuration: {e}")
        return {"error": str(e)}


def handle_generate_certs(data: dict, ctx: ConnContext) -> dict:
    """Handle generate_certificates request inside the TLS tunnel."""
    try:
        if PQC_CA_PRIVATE_KEY is None:
            return {"error": "PQC CA not configured"}

        session = ctx.session
        if not session.authenticated:
            return {"error": "Not authenticated"}
        relay_id = session.relay_id

        print(f"[{relay_id}] Certificate generation request")

        pqc_csr = data.get("pqc_csr", {})
        print(f"[{relay_id}] Signing PQC certificate...")
        pqc_cert = sign_pqc_csr(pqc_csr)

        if not pqc_cert:
            return {"error": "Failed to sign PQC certificate"}

        # This one cert (Relay CA-signed) is also presented to KMEs as the
        # relay's SAE identity -- no separate KME-facing cert or CSR needed.
        print(f"[{relay_id}] Certificate signed and sent")

        return {
            "pqc_certificate": pqc_cert
        }

    except Exception as e:
        print(f"Error in handle_generate_certs: {e}")
        return {"error": str(e)}


def dispatch_action(action: str, data: dict, ctx: ConnContext) -> dict:
    """Dispatch a TLS protocol action to the appropriate handler.

    Everything after register runs against the session bound to this
    connection; a relay_id in the request, if any, must match it.
    """
    if action == "register":
        return handle_register(data, ctx)
    if action not in ("attest", "configuration", "generate_certificates"):
        return {"error": f"Unknown action: {action}"}
    if ctx.session is None:
        return {"error": "Not registered on this connection"}
    if data.get("relay_id", ctx.session.relay_id) != ctx.session.relay_id:
        return {"error": "relay_id does not match this connection's session"}
    if action == "attest":
        return handle_attest(data, ctx)
    elif action == "configuration":
        return handle_configuration(data, ctx)
    return handle_generate_certs(data, ctx)


# ==================== WolfSSL TLS Server (port 8001) ====================

def handle_tls_client(conn_sock: socket.socket, cert_der: bytes, pkcs8_der: bytes):
    """Handle one relay connection over WolfSSL TLS."""
    addr = conn_sock.getpeername()
    print(f"[TLS] New connection from {addr}")
    try:
        with wolfssl_mldsa.pqc_tls_server_accept_anon_client(
                conn_sock.fileno(), cert_der, pkcs8_der) as conn:
            print(f"[TLS] Handshake complete with {addr}")
            ctx = ConnContext()
            while True:
                try:
                    req_bytes = conn.recvmsg()
                except OSError as e:
                    print(f"[TLS] {addr} recvmsg failed, closing: {e}")
                    break
                try:
                    req = json.loads(req_bytes)
                except json.JSONDecodeError as e:
                    print(f"[TLS] {addr} sent invalid JSON: {e}")
                    conn.sendmsg(json.dumps({"error": f"JSON parse error: {e}"}).encode())
                    continue

                action = req.get("action", "")
                data = req.get("data", {})
                result = dispatch_action(action, data, ctx)
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


@application.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "ok",
        "pqc_ca_loaded": PQC_CA_PRIVATE_KEY is not None,
        "kme_ca_loaded": KME_CA_CERTIFICATE is not None,
        "ctrl_cert_loaded": CTRL_CERTIFICATE is not None,
        "ctrl_tls_port": CTRL_TLS_PORT,
        "signature_algorithm": MLDSA_ALGORITHM
    }


# ==================== Main ====================

parser = argparse.ArgumentParser(description="QKD Relay Hybrid PQC Controller")
parser.add_argument("--pqc-ca-cert", default=PQC_CA_CERT_PATH, help="Path to Relay CA certificate")
parser.add_argument("--pqc-ca-key", default=PQC_CA_KEY_PATH, help="Path to Relay CA private key")
parser.add_argument("--kme-ca-cert", default=KME_CA_CERT_PATH, help="Path to KME CA certificate (public cert only)")
parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")
parser.add_argument("--port", type=int, default=8000, help="HTTP port (for /ca_cert bootstrap)")
parser.add_argument("--tls-port", type=int, default=CTRL_TLS_PORT, help="WolfSSL TLS port")
parser.add_argument("--enclave-measurement", default=None, metavar="HEX",
                    help="SHA3-512 measurement (128 hex chars) of the release relay enclave; "
                         "required to admit any enclave relay")
parser.add_argument("--sm-measurement", default=None, metavar="HEX",
                    help="SHA3-512 measurement of the Keystone Security Monitor (optional pin)")
parser.add_argument("--attestation-root-key", default=None, metavar="HEX",
                    help="Ed25519 device root public key (64 hex chars) that must endorse the SM; "
                         "defaults to Keystone's public TEST key (QEMU only)")
parser.add_argument("--insecure-dev-attestation", nargs="?", const="*", default=None,
                    metavar="RELAY_IDS",
                    help="DEV ONLY: accept the SHA256 stand-in report (no TEE) from the given "
                         "comma-separated relays, e.g. R0,R2; with no value, from all relays")

args = parser.parse_args()

PQC_CA_CERT_PATH = args.pqc_ca_cert
PQC_CA_KEY_PATH = args.pqc_ca_key
KME_CA_CERT_PATH = args.kme_ca_cert
CTRL_TLS_PORT = args.tls_port


def _hex_arg(value: str, length: int, name: str) -> bytes:
    try:
        b = bytes.fromhex(value)
    except ValueError:
        b = b""
    if len(b) != length:
        print(f"Error: {name} must be {2 * length} hex characters")
        sys.exit(1)
    return b


if args.enclave_measurement:
    ENCLAVE_MEASUREMENT = _hex_arg(args.enclave_measurement, keystone_attestation.MDSIZE,
                                   "--enclave-measurement")
if args.sm_measurement:
    SM_MEASUREMENT = _hex_arg(args.sm_measurement, keystone_attestation.MDSIZE, "--sm-measurement")
if args.attestation_root_key:
    ATTESTATION_ROOT_KEY = _hex_arg(args.attestation_root_key, keystone_attestation.PUBLIC_KEY_SIZE,
                                    "--attestation-root-key")
if args.insecure_dev_attestation is not None:
    DEV_ATTESTATION_RELAYS = ("*" if args.insecure_dev_attestation == "*" else
                              {r.strip() for r in args.insecure_dev_attestation.split(",") if r.strip()})

if ENCLAVE_MEASUREMENT is None:
    print("[!] No --enclave-measurement: enclave relays will be refused")
else:
    print(f"[*] Pinned enclave measurement: {ENCLAVE_MEASUREMENT.hex()}")
if ATTESTATION_ROOT_KEY == keystone_attestation.KEYSTONE_TEST_DEV_PUBLIC_KEY:
    print("[!] Attestation root key is Keystone's public TEST key -- "
          "reports prove nothing outside QEMU")
if DEV_ATTESTATION_RELAYS is not None:
    who = "ALL relays" if DEV_ATTESTATION_RELAYS == "*" else ", ".join(sorted(DEV_ATTESTATION_RELAYS))
    print(f"[!] WARNING: --insecure-dev-attestation: non-TEE relays admitted without "
          f"attestation: {who}")

if os.path.exists(PQC_CA_CERT_PATH) and os.path.exists(PQC_CA_KEY_PATH):
    load_pqc_ca_credentials(PQC_CA_CERT_PATH, PQC_CA_KEY_PATH)
else:
    print(f"Error: Relay CA files not found")
    print(f"  Certificate: {PQC_CA_CERT_PATH}")
    print(f"  Private key: {PQC_CA_KEY_PATH}")
    print(f"\nGenerate with: python generate_pqc_ca.py --output-dir ./pqc_ca")
    sys.exit(1)

if os.path.exists(KME_CA_CERT_PATH):
    load_kme_ca_certificate(KME_CA_CERT_PATH)
else:
    print(f"Error: KME CA certificate not found: {KME_CA_CERT_PATH}")
    print(f"\nGenerate with: python generate_pqc_ca.py --output-dir ./kme_ca --cn \"QKD KME CA\"")
    sys.exit(1)

# Generate controller's own TLS certificate
generate_controller_cert()

# Start WolfSSL TLS server in a daemon thread
tls_thread = threading.Thread(target=run_tls_server, daemon=True)
tls_thread.start()

import uvicorn
uvicorn.run(application, host=args.host, port=args.port)