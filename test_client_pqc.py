#!/usr/bin/env python3
"""
PQC Test Client for QKD Relay

Uses WolfSSL mTLS (wolfssl_mldsa.py) and standard X.509 certificates,
compatible with controller_hybrid.py, repetitor_hybrid.py, and eapp_final.c.

Usage:
    # Generate test client credentials (one time):
    python test_client_pqc.py --generate-credentials

    # Send a message to DR0 (left edge):
    python test_client_pqc.py --send --target 127.0.0.1:9000 --message "Hello!"

    # Listen for incoming messages:
    python test_client_pqc.py --receive --port 8998
"""

import argparse
import base64
import json
import os
import socket
import sys
from datetime import datetime, timedelta, timezone
from typing import Optional

try:
    import wolfssl_mldsa
except ImportError:
    print("Error: wolfssl_mldsa not available (libwolfssl_mldsa.so not found)")
    print("Build wolfssl_mldsa.c first and ensure the .so is in the same directory.")
    sys.exit(1)

try:
    from cryptography import x509 as _x509lib
    from cryptography.hazmat.backends import default_backend as _backend
except ImportError:
    print("Error: cryptography library not installed")
    print("Install with: pip install cryptography")
    sys.exit(1)


# ==================== Configuration ====================

CLIENT_ID = "test_client"

CREDENTIALS_DIR = "./test_client_creds"
PRIVATE_KEY_FILE = f"{CREDENTIALS_DIR}/private_key.pem"
CERTIFICATE_FILE = f"{CREDENTIALS_DIR}/certificate.pem"
CA_CERT_FILE     = "./pqc_ca/ca_certificate.pem"
CA_KEY_FILE      = "./pqc_ca/ca_private_key.pem"

# Global credentials (loaded once)
PQC_PRIVATE_KEY: Optional[bytes] = None   # raw 4032-byte ML-DSA-65 private key
PQC_CERTIFICATE: Optional[bytes] = None   # DER bytes of own X.509 certificate
PQC_CA_CERT_DER: Optional[bytes] = None   # DER bytes of CA certificate


# ==================== PEM helpers ====================

def encode_pem(data: bytes, label: str) -> str:
    b64 = base64.b64encode(data).decode('ascii')
    lines = [b64[i:i+64] for i in range(0, len(b64), 64)]
    return f"-----BEGIN {label}-----\n" + "\n".join(lines) + f"\n-----END {label}-----\n"


def decode_pem(pem_str: str, label: str) -> bytes:
    lines = pem_str.strip().split('\n')
    b64 = ''.join(ln for ln in lines if not ln.startswith('-----'))
    return base64.b64decode(b64)


# ==================== X.509 DER builder ====================
# Same DER primitives as generate_pqc_ca.py / controller_hybrid.py

def _enc_len(n: int) -> bytes:
    if n < 0x80:   return bytes([n])
    if n < 0x100:  return bytes([0x81, n])
    return bytes([0x82, n >> 8, n & 0xFF])

def _tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _enc_len(len(content)) + content

def _seq(*items: bytes) -> bytes: return _tlv(0x30, b''.join(items))
def _set(*items: bytes) -> bytes: return _tlv(0x31, b''.join(items))
def _oid(v: bytes) -> bytes:      return _tlv(0x06, v)
def _utf8str(s: str) -> bytes:    return _tlv(0x0C, s.encode())
def _ctx0(v: bytes) -> bytes:     return _tlv(0xA0, v)
def _bitstr(data: bytes) -> bytes: return _tlv(0x03, b'\x00' + data)

def _int_der(n: int) -> bytes:
    b = n.to_bytes((n.bit_length() + 8) // 8, 'big')
    return _tlv(0x02, b)

def _utctime(dt: datetime) -> bytes:
    return _tlv(0x17, dt.strftime('%y%m%d%H%M%SZ').encode())

_MLDSA65_OID = bytes([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12])
_CN_OID      = bytes([0x55, 0x04, 0x03])

def _mldsa65_alg_id() -> bytes:
    return _seq(_oid(_MLDSA65_OID))

def _x509_name(cn: str) -> bytes:
    return _seq(_set(_seq(_oid(_CN_OID), _utf8str(cn))))

def _spki(pk: bytes) -> bytes:
    return _seq(_mldsa65_alg_id(), _bitstr(pk))

def _mldsa_sign(private_key: bytes, data: bytes) -> bytes:
    signer = wolfssl_mldsa.Signature("ML-DSA-65", private_key)
    return signer.sign(data)


def build_leaf_cert_der(cn: str, public_key: bytes,
                        ca_private_key: bytes, ca_cn: str,
                        serial: int,
                        not_before: datetime, not_after: datetime) -> bytes:
    """Build a CA-signed X.509 v3 leaf certificate in DER."""
    tbs = _seq(
        _ctx0(_int_der(2)),                                    # version v3
        _int_der(serial),
        _mldsa65_alg_id(),
        _x509_name(ca_cn),                                     # issuer
        _seq(_utctime(not_before), _utctime(not_after)),       # validity
        _x509_name(cn),                                        # subject
        _spki(public_key),
    )
    sig = _mldsa_sign(ca_private_key, tbs)
    return _seq(tbs, _mldsa65_alg_id(), _bitstr(sig))


# ==================== X.509 CN extraction ====================

def x509_get_cn(der: bytes) -> str:
    """Extract CN from a DER-encoded X.509 certificate."""
    try:
        cert = _x509lib.load_der_x509_certificate(der, _backend())
        attrs = cert.subject.get_attributes_for_oid(_x509lib.NameOID.COMMON_NAME)
        return attrs[0].value if attrs else "unknown"
    except Exception:
        return "unknown"


# ==================== Credential Management ====================

def generate_credentials() -> bool:
    """Generate test client X.509 credentials, signed by the PQC CA."""
    print("[*] Generating test client credentials (X.509 / WolfSSL mTLS)...")

    if not os.path.exists(CA_CERT_FILE):
        print(f"[-] CA certificate not found: {CA_CERT_FILE}")
        print("    Run: python generate_pqc_ca.py --output-dir ./pqc_ca")
        return False

    if not os.path.exists(CA_KEY_FILE):
        print(f"[-] CA private key not found: {CA_KEY_FILE}")
        return False

    # Load CA
    with open(CA_CERT_FILE, 'r') as f:
        ca_cert_pem = f.read()
    with open(CA_KEY_FILE, 'r') as f:
        ca_key_pem = f.read()

    ca_der         = decode_pem(ca_cert_pem, "CERTIFICATE")
    ca_private_key = decode_pem(ca_key_pem,  "ML-DSA-65 PRIVATE KEY")
    ca_cn          = x509_get_cn(ca_der)
    print(f"[+] Loaded CA certificate (CN={ca_cn})")

    # Generate ML-DSA-65 keypair
    print("[*] Generating ML-DSA-65 keypair...")
    signer     = wolfssl_mldsa.Signature("ML-DSA-65")
    public_key = signer.generate_keypair()
    private_key = signer.export_secret_key()

    # Build X.509 leaf certificate signed by CA
    print("[*] Building X.509 certificate...")
    serial     = int.from_bytes(os.urandom(16), 'big') & 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    not_before = datetime.now(timezone.utc).replace(tzinfo=None)
    not_after  = not_before + timedelta(days=365)

    cert_der = build_leaf_cert_der(
        cn=CLIENT_ID,
        public_key=public_key,
        ca_private_key=ca_private_key,
        ca_cn=ca_cn,
        serial=serial,
        not_before=not_before,
        not_after=not_after,
    )
    cert_pem = encode_pem(cert_der, "CERTIFICATE")

    # Save
    os.makedirs(CREDENTIALS_DIR, exist_ok=True)

    with open(PRIVATE_KEY_FILE, 'w') as f:
        f.write(encode_pem(private_key, "ML-DSA-65 PRIVATE KEY"))

    with open(CERTIFICATE_FILE, 'w') as f:
        f.write(cert_pem)

    print(f"[+] Credentials saved to {CREDENTIALS_DIR}/")
    print(f"    Private key : {PRIVATE_KEY_FILE}")
    print(f"    Certificate : {CERTIFICATE_FILE}")
    print(f"[+] Certificate subject CN: {x509_get_cn(cert_der)}")
    return True


def load_credentials() -> bool:
    """Load credentials from disk into global variables."""
    global PQC_PRIVATE_KEY, PQC_CERTIFICATE, PQC_CA_CERT_DER

    try:
        for path, label in [(PRIVATE_KEY_FILE, "Private key"),
                            (CERTIFICATE_FILE, "Certificate"),
                            (CA_CERT_FILE,     "CA certificate")]:
            if not os.path.exists(path):
                print(f"[-] {label} not found: {path}")
                return False

        with open(PRIVATE_KEY_FILE, 'r') as f:
            PQC_PRIVATE_KEY = decode_pem(f.read(), "ML-DSA-65 PRIVATE KEY")

        with open(CERTIFICATE_FILE, 'r') as f:
            PQC_CERTIFICATE = decode_pem(f.read(), "CERTIFICATE")

        with open(CA_CERT_FILE, 'r') as f:
            PQC_CA_CERT_DER = decode_pem(f.read(), "CERTIFICATE")

        cn = x509_get_cn(PQC_CERTIFICATE)
        print(f"[+] Loaded credentials from {CREDENTIALS_DIR}/ (CN={cn})")
        return True

    except Exception as e:
        print(f"[-] Failed to load credentials: {e}")
        return False


# ==================== Send / Receive ====================

def send_message(host: str, port: int, message: str) -> bool:
    """Connect to a repetitor and send a message using WolfSSL mTLS."""
    print(f"[*] Connecting to {host}:{port}...")

    pkcs8_key = wolfssl_mldsa.pkcs8_mldsa65_der(PQC_PRIVATE_KEY)

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(30)
            sock.connect((host, port))

            print("[*] Performing WolfSSL mTLS handshake (client)...")
            with wolfssl_mldsa.pqc_tls_client_connect(
                    sock.fileno(), PQC_CERTIFICATE, pkcs8_key, PQC_CA_CERT_DER) as tls:

                peer_der = tls.peer_cert_der()
                peer_cn  = x509_get_cn(peer_der)
                print(f"[+] mTLS established with {peer_cn}")

                # Send message (length-prefixed, plaintext inside TLS)
                msg = {"message": message, "key_ID": ""}
                msg_bytes = json.dumps(msg).encode()
                print(f"[*] Sending: {message}")
                tls.sendmsg(msg_bytes)

                # Receive ACK
                ack = tls.recvmsg()
                print(f"[+] Ack: {ack.decode(errors='replace')}")

        return True

    except ConnectionRefusedError:
        print(f"[-] Connection refused at {host}:{port}")
        return False
    except Exception as e:
        print(f"[-] Error: {e}")
        import traceback
        traceback.print_exc()
        return False


def receive_message(port: int) -> bool:
    """Listen for one message from a repetitor using WolfSSL mTLS."""
    print(f"[*] Listening on 0.0.0.0:{port}...")

    pkcs8_key = wolfssl_mldsa.pkcs8_mldsa65_der(PQC_PRIVATE_KEY)

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_sock:
            server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_sock.bind(("0.0.0.0", port))
            server_sock.listen(5)

            print("[*] Waiting for connection...")
            conn, addr = server_sock.accept()
            print(f"[*] Connection from {addr}")

            try:
                print("[*] Performing WolfSSL mTLS handshake (server)...")
                with wolfssl_mldsa.pqc_tls_server_accept(
                        conn.fileno(), PQC_CERTIFICATE, pkcs8_key, PQC_CA_CERT_DER) as tls:

                    peer_der = tls.peer_cert_der()
                    peer_cn  = x509_get_cn(peer_der)
                    print(f"[+] mTLS from {peer_cn}")

                    # Receive message (length-prefixed, plaintext inside TLS)
                    msg_bytes = tls.recvmsg()
                    msg = json.loads(msg_bytes.decode())

                    print(f"\n{'='*50}")
                    print(f"MESSAGE FROM {peer_cn}")
                    print(f"{'='*50}")
                    print(f"Content: {msg.get('message', '(empty)')}")
                    if msg.get('key_ID'):
                        print(f"Key ID: {msg['key_ID']}")
                    print(f"{'='*50}\n")

                    # Send ACK
                    tls.sendmsg(b"RECEIVED")

            finally:
                conn.close()

        return True

    except Exception as e:
        print(f"[-] Error: {e}")
        import traceback
        traceback.print_exc()
        return False


# ==================== Main ====================

def main():
    parser = argparse.ArgumentParser(
        description="PQC Test Client for QKD Relay (WolfSSL mTLS + X.509)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate credentials (one time, requires pqc_ca/ to exist):
  python test_client_pqc.py --generate-credentials

  # Send message to left edge (DR0):
  python test_client_pqc.py --send --target 127.0.0.1:9000 --message "Hello!"

  # Send message to right edge (DR2):
  python test_client_pqc.py --send --target 127.0.0.1:9002 --message "Hello!"

  # Listen for messages on port 8998:
  python test_client_pqc.py --receive --port 8998

  # Both generate credentials and listen:
  python test_client_pqc.py --generate-credentials --receive --port 8998
"""
    )

    parser.add_argument("--generate-credentials", action="store_true",
                        help="Generate test client credentials using PQC CA")
    parser.add_argument("--send", action="store_true",
                        help="Send a message to a repetitor")
    parser.add_argument("--receive", action="store_true",
                        help="Listen for an incoming message from a repetitor")
    parser.add_argument("--target", type=str, default="127.0.0.1:9000",
                        help="Target host:port for --send (default: 127.0.0.1:9000)")
    parser.add_argument("--port", type=int, default=8998,
                        help="Listen port for --receive (default: 8998)")
    parser.add_argument("--message", "-m", type=str,
                        default="Hello from test client!",
                        help="Message to send (default: 'Hello from test client!')")

    args = parser.parse_args()

    print("=" * 50)
    print("PQC Test Client (WolfSSL mTLS)")
    print("=" * 50)

    if args.generate_credentials:
        if not generate_credentials():
            sys.exit(1)
        if not args.send and not args.receive:
            sys.exit(0)

    if args.send or args.receive:
        if not load_credentials():
            print("\n[-] Run with --generate-credentials first")
            sys.exit(1)

    if args.send:
        parts = args.target.split(":")
        host  = parts[0]
        port  = int(parts[1]) if len(parts) > 1 else 9000
        print(f"\n[*] Sending to {host}:{port}...")
        if not send_message(host, port, args.message):
            sys.exit(1)

    if args.receive:
        print(f"\n[*] Starting listener on port {args.port}...")
        if not receive_message(args.port):
            sys.exit(1)

    if not args.generate_credentials and not args.send and not args.receive:
        parser.print_help()


if __name__ == "__main__":
    main()
