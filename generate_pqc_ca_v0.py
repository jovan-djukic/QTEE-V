#!/usr/bin/env python3
"""
Generate Post-Quantum CA Certificate and Key using ML-DSA-65 

This script generates:
  - CA private key (ML-DSA-65)
  - CA public key (ML-DSA-65)
  - Self-signed CA certificate

Requirements:
  pip install liboqs-python cryptography

Usage:
  python generate_pqc_ca.py [--output-dir ./pqc_ca] [--cn "QKD Relay PQC CA"]

Output files:
  - ca_private_key.pem   (ML-DSA private key, PEM-like format)
  - ca_public_key.pem    (ML-DSA public key, PEM-like format)
  - ca_certificate.pem   (Self-signed certificate with ML-DSA signature)
"""

import argparse
import base64
import hashlib
import json
import os
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path

try:
    import oqs
    # === WOLFSSL SHIM ===
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
    except ImportError as e:
        print(f"[*] WolfSSL ML-DSA not available ({e}), using liboqs")
    # === END WOLFSSL SHIM ===
except ImportError:
    print("Error: liboqs-python not installed")
    print("Install with: pip install liboqs-python")
    sys.exit(1)


# ML-DSA-65 is called "ML-DSA-65" in liboqs
ALGORITHM = "ML-DSA-65"


def generate_keypair():
    """Generate ML-DSA-65 keypair."""
    signer = oqs.Signature(ALGORITHM)
    public_key = signer.generate_keypair()
    private_key = signer.export_secret_key()
    return private_key, public_key


def sign_data(private_key: bytes, data: bytes) -> bytes:
    """Sign data with ML-DSA-65 private key."""
    signer = oqs.Signature(ALGORITHM, private_key)
    return signer.sign(data)


def verify_signature(public_key: bytes, data: bytes, signature: bytes) -> bool:
    """Verify ML-DSA-65 signature."""
    verifier = oqs.Signature(ALGORITHM)
    return verifier.verify(data, signature, public_key)


def encode_pem(data: bytes, label: str) -> str:
    """Encode binary data as PEM-like format."""
    b64 = base64.b64encode(data).decode('ascii')
    lines = [b64[i:i+64] for i in range(0, len(b64), 64)]
    return f"-----BEGIN {label}-----\n" + "\n".join(lines) + f"\n-----END {label}-----\n"


def decode_pem(pem_str: str, label: str) -> bytes:
    """Decode PEM-like format to binary data."""
    lines = pem_str.strip().split('\n')
    # Remove header and footer
    b64_lines = [line for line in lines if not line.startswith('-----')]
    b64_data = ''.join(b64_lines)
    return base64.b64decode(b64_data)


def create_certificate(
    subject_cn: str,
    issuer_cn: str,
    public_key: bytes,
    signing_key: bytes,
    serial_number: int,
    not_before: datetime,
    not_after: datetime,
    is_ca: bool = True
) -> bytes:
    """
    Create a simplified X.509-like certificate structure.
    
    Since standard X.509 libraries don't support ML-DSA yet,
    we use a custom JSON-based format that contains all necessary fields.
    """
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
            "basic_constraints": {"ca": is_ca, "path_length": 0 if is_ca else None},
            "key_usage": ["digital_signature", "key_cert_sign", "crl_sign"] if is_ca 
                        else ["digital_signature"]
        }
    }
    
    # TBS (To Be Signed) certificate
    tbs_json = json.dumps(cert_data, sort_keys=True, separators=(',', ':'))
    tbs_bytes = tbs_json.encode('utf-8')
    
    # Sign with ML-DSA
    signature = sign_data(signing_key, tbs_bytes)
    
    # Complete certificate
    full_cert = {
        "tbs_certificate": cert_data,
        "signature_algorithm": "ML-DSA-65",
        "signature": base64.b64encode(signature).decode('ascii')
    }
    
    return json.dumps(full_cert, indent=2).encode('utf-8')


def verify_certificate(cert_pem: str, ca_public_key: bytes) -> bool:
    """Verify a certificate's signature."""
    cert_json = cert_pem
    if cert_pem.startswith("-----BEGIN"):
        cert_json = decode_pem(cert_pem, "PQC CERTIFICATE").decode('utf-8')
    
    cert = json.loads(cert_json)
    tbs_json = json.dumps(cert["tbs_certificate"], sort_keys=True, separators=(',', ':'))
    tbs_bytes = tbs_json.encode('utf-8')
    signature = base64.b64decode(cert["signature"])
    
    return verify_signature(ca_public_key, tbs_bytes, signature)


def main():
    parser = argparse.ArgumentParser(
        description="Generate Post-Quantum CA using ML-DSA-65 "
    )
    parser.add_argument(
        "--output-dir", "-o",
        default="./pqc_ca",
        help="Output directory for CA files (default: ./pqc_ca)"
    )
    parser.add_argument(
        "--cn", "-c",
        default="QKD Relay PQC CA",
        help="Common Name for CA certificate (default: 'QKD Relay PQC CA')"
    )
    parser.add_argument(
        "--validity-years", "-y",
        type=int,
        default=10,
        help="Certificate validity in years (default: 10)"
    )
    parser.add_argument(
        "--verify", "-v",
        action="store_true",
        help="Verify generated certificate after creation"
    )
    
    args = parser.parse_args()
    
    # Create output directory
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    print(f"Generating ML-DSA-65  CA keypair...")
    print(f"  Algorithm: {ALGORITHM}")
    
    # Generate keypair
    private_key, public_key = generate_keypair()
    
    print(f"  Private key size: {len(private_key)} bytes")
    print(f"  Public key size: {len(public_key)} bytes")
    
    # Create self-signed certificate
    print(f"\nCreating self-signed CA certificate...")
    print(f"  Subject/Issuer: CN={args.cn}")
    
    not_before = datetime.utcnow()
    not_after = not_before + timedelta(days=365 * args.validity_years)
    serial_number = int.from_bytes(os.urandom(16), 'big')
    
    cert_bytes = create_certificate(
        subject_cn=args.cn,
        issuer_cn=args.cn,
        public_key=public_key,
        signing_key=private_key,
        serial_number=serial_number,
        not_before=not_before,
        not_after=not_after,
        is_ca=True
    )
    
    print(f"  Valid from: {not_before.isoformat()}")
    print(f"  Valid until: {not_after.isoformat()}")
    print(f"  Serial: {hex(serial_number)[:20]}...")
    
    # Save files
    private_key_path = output_dir / "ca_private_key.pem"
    public_key_path = output_dir / "ca_public_key.pem"
    cert_path = output_dir / "ca_certificate.pem"
    
    # Save private key
    private_key_pem = encode_pem(private_key, "ML-DSA-65 PRIVATE KEY")
    private_key_path.write_text(private_key_pem)
    os.chmod(private_key_path, 0o600)  # Restrict permissions
    
    # Save public key
    public_key_pem = encode_pem(public_key, "ML-DSA-65 PUBLIC KEY")
    public_key_path.write_text(public_key_pem)
    
    # Save certificate
    cert_pem = encode_pem(cert_bytes, "PQC CERTIFICATE")
    cert_path.write_text(cert_pem)
    
    print(f"\nFiles created:")
    print(f"  {private_key_path} (KEEP SECRET!)")
    print(f"  {public_key_path}")
    print(f"  {cert_path}")
    
    # Verify if requested
    if args.verify:
        print(f"\nVerifying certificate signature...")
        if verify_certificate(cert_pem, public_key):
            print("  ✓ Certificate signature is valid")
        else:
            print("  ✗ Certificate signature verification FAILED")
            sys.exit(1)
    
    # Print fingerprint
    cert_fingerprint = hashlib.sha256(cert_bytes).hexdigest()
    print(f"\nCertificate fingerprint (SHA-256):")
    print(f"  {cert_fingerprint[:32]}")
    print(f"  {cert_fingerprint[32:]}")
    
    print("\nDone!")
    print("\nTo use with controller_pqc.py:")
    print(f"  python controller_pqc.py --ca-cert {cert_path} --ca-key {private_key_path}")


if __name__ == "__main__":
    main()
