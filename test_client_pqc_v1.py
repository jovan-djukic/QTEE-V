#!/usr/bin/env python3
"""
PQC Test Client for QKD Relay

Simple client that sends/receives messages using the PQC protocol
(Kyber-768 for key exchange, ML-DSA-65 for authentication).

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
import hashlib
import json
import os
import socket
import struct
import sys
from datetime import datetime, timedelta
from typing import Tuple, Optional, List

try:
    import oqs
except ImportError:
    print("Error: liboqs-python not installed")
    print("Install with: pip install liboqs-python")
    sys.exit(1)

# === ADD THIS BLOCK ===
# Use WolfSSL for ML-DSA signatures (compatible with C repetitors)
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
except ImportError:
    print("[*] WolfSSL ML-DSA not available, using liboqs")
# === END BLOCK ===


from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend


# ==================== Configuration ====================

CLIENT_ID = "test_client"

KYBER_ALGORITHM = "ML-KEM-768"
MLDSA_ALGORITHM = "ML-DSA-65"

# File paths
CREDENTIALS_DIR = "./test_client_creds"
PRIVATE_KEY_FILE = f"{CREDENTIALS_DIR}/private_key.pem"
CERTIFICATE_FILE = f"{CREDENTIALS_DIR}/certificate.pem"
CA_CERT_FILE = "./pqc_ca/ca_certificate.pem"
CA_KEY_FILE = "./pqc_ca/ca_private_key.pem"

# Global credentials
PQC_PRIVATE_KEY: Optional[bytes] = None
PQC_CERTIFICATE: Optional[str] = None
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


# ==================== ML-DSA-65 Signatures ====================

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


# ==================== AES Encryption ====================

def aes_encrypt_bytes(plaintext: bytes, key: bytes) -> bytes:
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    return iv + ciphertext


def aes_decrypt_bytes(data: bytes, key: bytes) -> bytes:
    iv = data[:16]
    ciphertext = data[16:]
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


# ==================== PQC Certificate Handling ====================

def verify_pqc_certificate(cert_pem: str, ca_cert_pem: str) -> Tuple[bool, str, bytes]:
    """Verify a PQC certificate. Returns (is_valid, subject_cn, public_key)."""
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
        
        return True, subject_cn, public_key
        
    except Exception as e:
        print(f"Certificate verification failed: {e}")
        return False, "", b""


def create_and_sign_certificate(
    subject_cn: str,
    public_key: bytes,
    ca_private_key: bytes,
    ca_cert_pem: str
) -> str:
    """Create and sign a PQC certificate."""
    # Get issuer CN from CA cert
    ca_data = decode_pem(ca_cert_pem, "PQC CERTIFICATE")
    ca_json = json.loads(ca_data.decode('utf-8'))
    issuer_cn = ca_json["tbs_certificate"]["subject"]["CN"]
    
    not_before = datetime.utcnow()
    not_after = not_before + timedelta(days=365)
    serial_number = int.from_bytes(os.urandom(16), 'big')
    
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
            "basic_constraints": {"ca": False, "path_length": None},
            "key_usage": ["digital_signature"]
        }
    }
    
    tbs_json = json.dumps(cert_data, sort_keys=True, separators=(',', ':'))
    tbs_bytes = tbs_json.encode('utf-8')
    signature = mldsa_sign(ca_private_key, tbs_bytes)
    
    full_cert = {
        "tbs_certificate": cert_data,
        "signature_algorithm": "ML-DSA-65",
        "signature": base64.b64encode(signature).decode('ascii')
    }
    
    cert_bytes = json.dumps(full_cert, indent=2).encode('utf-8')
    return encode_pem(cert_bytes, "PQC CERTIFICATE")


# ==================== Credential Management ====================

def generate_credentials():
    """Generate test client credentials signed by the PQC CA."""
    print("[*] Generating test client credentials...")
    
    # Check CA files exist
    if not os.path.exists(CA_CERT_FILE):
        print(f"[-] CA certificate not found: {CA_CERT_FILE}")
        print("    Run: python generate_pqc_ca.py --output-dir ./pqc_ca")
        return False
    
    if not os.path.exists(CA_KEY_FILE):
        print(f"[-] CA private key not found: {CA_KEY_FILE}")
        return False
    
    # Load CA
    with open(CA_CERT_FILE, 'r') as f:
        ca_cert = f.read()
    with open(CA_KEY_FILE, 'r') as f:
        ca_key_pem = f.read()
    ca_private_key = decode_pem(ca_key_pem, "ML-DSA-65 PRIVATE KEY")
    
    print(f"[+] Loaded CA certificate")
    
    # Generate keypair
    print("[*] Generating ML-DSA-65 keypair...")
    public_key, private_key = mldsa_generate_keypair()
    
    # Create certificate
    print("[*] Creating certificate...")
    certificate = create_and_sign_certificate(
        subject_cn=CLIENT_ID,
        public_key=public_key,
        ca_private_key=ca_private_key,
        ca_cert_pem=ca_cert
    )
    
    # Save credentials
    os.makedirs(CREDENTIALS_DIR, exist_ok=True)
    
    with open(PRIVATE_KEY_FILE, 'w') as f:
        f.write(encode_pem(private_key, "ML-DSA-65 PRIVATE KEY"))
    
    with open(CERTIFICATE_FILE, 'w') as f:
        f.write(certificate)
    
    print(f"[+] Credentials saved to {CREDENTIALS_DIR}/")
    print(f"    Private key: {PRIVATE_KEY_FILE}")
    print(f"    Certificate: {CERTIFICATE_FILE}")
    
    # Verify certificate
    valid, cn, _ = verify_pqc_certificate(certificate, ca_cert)
    print(f"[+] Certificate verification: {'✓' if valid else '✗'} (CN={cn})")
    
    return True


def load_credentials() -> bool:
    """Load credentials from files."""
    global PQC_PRIVATE_KEY, PQC_CERTIFICATE, PQC_CA_CERTIFICATE
    
    try:
        if not os.path.exists(PRIVATE_KEY_FILE):
            print(f"[-] Private key not found: {PRIVATE_KEY_FILE}")
            return False
        
        if not os.path.exists(CERTIFICATE_FILE):
            print(f"[-] Certificate not found: {CERTIFICATE_FILE}")
            return False
        
        if not os.path.exists(CA_CERT_FILE):
            print(f"[-] CA certificate not found: {CA_CERT_FILE}")
            return False
        
        with open(PRIVATE_KEY_FILE, 'r') as f:
            key_pem = f.read()
        PQC_PRIVATE_KEY = decode_pem(key_pem, "ML-DSA-65 PRIVATE KEY")
        
        with open(CERTIFICATE_FILE, 'r') as f:
            PQC_CERTIFICATE = f.read()
        
        with open(CA_CERT_FILE, 'r') as f:
            PQC_CA_CERTIFICATE = f.read()
        
        print(f"[+] Loaded credentials from {CREDENTIALS_DIR}/")
        return True
        
    except Exception as e:
        print(f"[-] Failed to load credentials: {e}")
        return False


# ==================== PQC Channel Protocol ====================

def send_length_prefixed(sock: socket.socket, data: bytes):
    length = struct.pack('>I', len(data))
    sock.sendall(length + data)


def recv_length_prefixed(sock: socket.socket) -> bytes:
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


def pqc_client_handshake(sock: socket.socket) -> Tuple[bytes, str]:
    """Client-side PQC handshake. Returns (session_key, peer_cn)."""
    
    # Receive server's hello
    server_hello = recv_length_prefixed(sock)
    server_data = json.loads(server_hello.decode())
    
    server_kyber_pk = base64.b64decode(server_data["kyber_pk"])
    server_cert = server_data["certificate"]
    server_sig = base64.b64decode(server_data["signature"])
    
    # Verify server certificate
    valid, peer_cn, peer_pk = verify_pqc_certificate(server_cert, PQC_CA_CERTIFICATE)
    if not valid:
        raise ValueError("Invalid server certificate")
    
    print(f"[+] Server certificate verified: {peer_cn}")
    
    # Verify server's signature on Kyber public key
    if not mldsa_verify(peer_pk, server_kyber_pk, server_sig):
        raise ValueError("Invalid server signature")
    
    # Encapsulate to server's Kyber public key
    kyber_ct, shared_secret = kyber_encapsulate(server_kyber_pk)
    
    # Sign the ciphertext
    signature = mldsa_sign(PQC_PRIVATE_KEY, kyber_ct)
    
    # Send response
    client_hello = json.dumps({
        "kyber_ciphertext": base64.b64encode(kyber_ct).decode(),
        "certificate": PQC_CERTIFICATE,
        "signature": base64.b64encode(signature).decode()
    }).encode()
    send_length_prefixed(sock, client_hello)
    
    # Derive session key using HKDF (matches C implementation)
    session_key = derive_session_key(shared_secret)
    
    return session_key, peer_cn


def pqc_server_handshake(sock: socket.socket, whitelist: List[str] = None) -> Tuple[bytes, str]:
    """Server-side PQC handshake. Returns (session_key, peer_cn)."""
    
    # Generate ephemeral Kyber keypair
    kyber_pk, kyber_sk = kyber_generate_keypair()
    
    # Sign Kyber public key
    signature = mldsa_sign(PQC_PRIVATE_KEY, kyber_pk)
    
    # Send hello
    server_hello = json.dumps({
        "kyber_pk": base64.b64encode(kyber_pk).decode(),
        "certificate": PQC_CERTIFICATE,
        "signature": base64.b64encode(signature).decode()
    }).encode()
    send_length_prefixed(sock, server_hello)
    
    # Receive client response
    client_hello = recv_length_prefixed(sock)
    client_data = json.loads(client_hello.decode())
    
    kyber_ct = base64.b64decode(client_data["kyber_ciphertext"])
    client_cert = client_data["certificate"]
    client_sig = base64.b64decode(client_data["signature"])
    
    # Verify client certificate
    valid, peer_cn, peer_pk = verify_pqc_certificate(client_cert, PQC_CA_CERTIFICATE)
    if not valid:
        raise ValueError("Invalid client certificate")
    
    if whitelist and peer_cn not in whitelist:
        raise ValueError(f"Client {peer_cn} not in whitelist")
    
    print(f"[+] Client certificate verified: {peer_cn}")
    
    # Verify signature
    if not mldsa_verify(peer_pk, kyber_ct, client_sig):
        raise ValueError("Invalid client signature")
    
    # Decapsulate
    shared_secret = kyber_decapsulate(kyber_sk, kyber_ct)
    # Derive session key using HKDF (matches C implementation)
    session_key = derive_session_key(shared_secret)
    
    return session_key, peer_cn


# ==================== Send/Receive ====================

def send_message(host: str, port: int, message: str) -> bool:
    """Send a message to a repetitor."""
    
    print(f"[*] Connecting to {host}:{port}...")
    
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(30)
            sock.connect((host, port))
            
            print("[*] Performing PQC handshake...")
            session_key, peer_cn = pqc_client_handshake(sock)
            
            print(f"[+] Secure channel established with {peer_cn}")
            
            # Send message (plaintext - no QKD at edge)
            msg = {"message": message, "key_ID": ""}
            msg_json = json.dumps(msg).encode()
            encrypted = aes_encrypt_bytes(msg_json, session_key)
            
            print(f"[*] Sending: {message}")
            send_length_prefixed(sock, encrypted)
            
            # Receive ack
            ack_encrypted = recv_length_prefixed(sock)
            ack = aes_decrypt_bytes(ack_encrypted, session_key)
            
            print(f"[+] Response: {ack.decode()}")
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
    """Listen for incoming messages."""
    
    print(f"[*] Listening on 0.0.0.0:{port}...")
    
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_sock:
            server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_sock.bind(("0.0.0.0", port))
            server_sock.listen(5)
            
            print("[*] Waiting for connection...")
            
            conn, addr = server_sock.accept()
            conn.settimeout(30)
            
            print(f"[*] Connection from {addr}")
            
            try:
                print("[*] Performing PQC handshake...")
                session_key, peer_cn = pqc_server_handshake(conn)
                
                print(f"[+] Secure channel established with {peer_cn}")
                
                # Receive message
                encrypted = recv_length_prefixed(conn)
                msg_json = aes_decrypt_bytes(encrypted, session_key)
                msg = json.loads(msg_json.decode())
                
                print(f"\n{'='*50}")
                print(f"MESSAGE FROM {peer_cn}")
                print(f"{'='*50}")
                print(f"Content: {msg.get('message', '(empty)')}")
                if msg.get('key_ID'):
                    print(f"Key ID: {msg.get('key_ID')}")
                print(f"{'='*50}\n")
                
                # Send ack
                ack = b"RECEIVED"
                ack_encrypted = aes_encrypt_bytes(ack, session_key)
                send_length_prefixed(conn, ack_encrypted)
                
                return True
                
            finally:
                conn.close()
                
    except Exception as e:
        print(f"[-] Error: {e}")
        import traceback
        traceback.print_exc()
        return False


# ==================== Main ====================

def main():
    parser = argparse.ArgumentParser(
        description="PQC Test Client for QKD Relay",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate credentials (one time):
  python test_client_pqc.py --generate-credentials
  
  # Send message to left edge (DR0):
  python test_client_pqc.py --send --target 127.0.0.1:9000 --message "Hello!"
  
  # Send message to right edge (DR2):
  python test_client_pqc.py --send --target 127.0.0.1:9002 --message "Hello!"
  
  # Listen for messages on port 8998:
  python test_client_pqc.py --receive --port 8998
  
  # Listen on port 8999 (right side):
  python test_client_pqc.py --receive --port 8999
"""
    )
    
    parser.add_argument("--generate-credentials", action="store_true",
                        help="Generate test client credentials using PQC CA")
    parser.add_argument("--send", action="store_true",
                        help="Send a message")
    parser.add_argument("--receive", action="store_true",
                        help="Listen for incoming messages")
    parser.add_argument("--target", type=str, default="127.0.0.1:9000",
                        help="Target host:port (default: 127.0.0.1:9000)")
    parser.add_argument("--port", type=int, default=8998,
                        help="Listen port (default: 8998)")
    parser.add_argument("--message", "-m", type=str, default="Hello from test client!",
                        help="Message to send")
    
    args = parser.parse_args()
    
    print("="*50)
    print("PQC Test Client")
    print("="*50)
    
    # Generate credentials if requested
    if args.generate_credentials:
        if not generate_credentials():
            sys.exit(1)
        if not args.send and not args.receive:
            sys.exit(0)
    
    # Load credentials for send/receive
    if args.send or args.receive:
        if not load_credentials():
            print("\n[-] Run with --generate-credentials first")
            sys.exit(1)
    
    # Send
    if args.send:
        host, port = args.target.split(":")
        print(f"\n[*] Sending to {host}:{port}...")
        if not send_message(host, int(port), args.message):
            sys.exit(1)
    
    # Receive
    if args.receive:
        print(f"\n[*] Starting listener on port {args.port}...")
        if not receive_message(args.port):
            sys.exit(1)
    
    if not args.generate_credentials and not args.send and not args.receive:
        parser.print_help()


if __name__ == "__main__":
    main()
