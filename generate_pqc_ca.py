#!/usr/bin/env python3
"""
Generate Post-Quantum CA Certificate and Key using ML-DSA-65

This script generates:
  - CA private key (ML-DSA-65, raw bytes in PEM wrapper)
  - Self-signed CA certificate (standard X.509 DER, -----BEGIN CERTIFICATE-----)

Requirements:
  wolfssl_mldsa.py / libwolfssl_mldsa.so (build_wolfssl_mldsa_so.sh)

Usage:
  python generate_pqc_ca.py [--output-dir ./pqc_ca] [--cn "QKD Relay PQC CA"]

Output files:
  - ca_private_key.pem   (ML-DSA-65 private key, PEM wrapper around raw bytes)
  - ca_certificate.pem   (Self-signed X.509 certificate, standard PEM)
"""

import argparse
import base64
import hashlib
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import wolfssl_mldsa

ALGORITHM = "ML-DSA-65"

# ML-DSA-65 OID: 2.16.840.1.101.3.4.3.18 (NIST FIPS 204)
_OID_MLDSA65 = bytes([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12])
_OID_CN      = bytes([0x55, 0x04, 0x03])


# ==================== DER primitives ====================

def _enc_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    enc = []
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
    enc = []
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
    return _tlv(0x03, b'\x00' + data)

def _ctx0(*items: bytes) -> bytes:
    return _tlv(0xA0, b''.join(items))

def _mldsa65_alg_id() -> bytes:
    return _seq(_oid(_OID_MLDSA65))

def _x509_name(cn: str) -> bytes:
    return _seq(_set(_seq(_oid(_OID_CN), _utf8str(cn))))

def _spki(pk: bytes) -> bytes:
    return _seq(_mldsa65_alg_id(), _bitstr(pk))


# ==================== DER parser (for verify) ====================

def _read_len(data: bytes, pos: int):
    first = data[pos]; pos += 1
    if first < 0x80:
        return first, pos
    n_bytes = first & 0x7F
    length = 0
    for _ in range(n_bytes):
        length = (length << 8) | data[pos]; pos += 1
    return length, pos

def _read_tlv(data: bytes, pos: int):
    tag = data[pos]; pos += 1
    length, pos = _read_len(data, pos)
    return tag, data[pos:pos + length], pos + length


# ==================== Certificate builder ====================

def _sign(private_key: bytes, data: bytes) -> bytes:
    signer = wolfssl_mldsa.Signature(ALGORITHM, private_key)
    return signer.sign(data)

def build_ca_cert_der(cn: str, public_key: bytes, private_key: bytes,
                      serial: int, not_before: datetime, not_after: datetime) -> bytes:
    """Build a self-signed X.509 v3 CA certificate in DER format."""
    tbs = _seq(
        _ctx0(_int_der(2)),                               # version v3
        _int_der(serial),                                 # serialNumber
        _mldsa65_alg_id(),                                # signature algorithm
        _x509_name(cn),                                   # issuer
        _seq(_utctime(not_before), _utctime(not_after)),  # validity
        _x509_name(cn),                                   # subject (== issuer for self-signed)
        _spki(public_key),                                # subjectPublicKeyInfo
    )
    sig = _sign(private_key, tbs)
    return _seq(tbs, _mldsa65_alg_id(), _bitstr(sig))


# ==================== PEM helpers ====================

def encode_pem(data: bytes, label: str) -> str:
    b64 = base64.b64encode(data).decode('ascii')
    lines = [b64[i:i+64] for i in range(0, len(b64), 64)]
    return f"-----BEGIN {label}-----\n" + "\n".join(lines) + f"\n-----END {label}-----\n"


# ==================== Verify helper ====================

def verify_cert(cert_der: bytes, public_key: bytes) -> bool:
    """Verify the self-signed certificate's ML-DSA-65 signature."""
    _, cert_val, _ = _read_tlv(cert_der, 0)
    pos = 0
    tbs_start = pos
    _, _, pos = _read_tlv(cert_val, pos)
    tbs_raw = cert_val[tbs_start:pos]
    _, _, pos = _read_tlv(cert_val, pos)       # skip signatureAlgorithm
    _, sig_bs, _ = _read_tlv(cert_val, pos)
    signature = sig_bs[1:]                     # skip unused-bits byte

    verifier = wolfssl_mldsa.Signature(ALGORITHM)
    return verifier.verify(tbs_raw, signature, public_key)


# ==================== Main ====================

def main():
    parser = argparse.ArgumentParser(
        description="Generate Post-Quantum CA using ML-DSA-65 (standard X.509)"
    )
    parser.add_argument("--output-dir", "-o", default="./pqc_ca",
                        help="Output directory (default: ./pqc_ca)")
    parser.add_argument("--cn", "-c", default="QKD Relay PQC CA",
                        help="Common Name (default: 'QKD Relay PQC CA')")
    parser.add_argument("--validity-years", "-y", type=int, default=10,
                        help="Validity in years (default: 10)")
    parser.add_argument("--verify", "-v", action="store_true",
                        help="Verify the certificate after creation")
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"Generating ML-DSA-65 CA keypair...")
    print(f"  Algorithm: {ALGORITHM}")

    signer = wolfssl_mldsa.Signature(ALGORITHM)
    public_key  = signer.generate_keypair()
    private_key = signer.export_secret_key()

    print(f"  Private key size: {len(private_key)} bytes")
    print(f"  Public key size:  {len(public_key)} bytes")

    print(f"\nBuilding self-signed X.509 CA certificate...")
    print(f"  Subject/Issuer: CN={args.cn}")

    not_before    = datetime.now(timezone.utc).replace(tzinfo=None)
    not_after     = not_before + timedelta(days=365 * args.validity_years)
    serial_number = int.from_bytes(os.urandom(16), 'big')

    cert_der = build_ca_cert_der(
        cn=args.cn,
        public_key=public_key,
        private_key=private_key,
        serial=serial_number,
        not_before=not_before,
        not_after=not_after,
    )
    cert_pem = encode_pem(cert_der, "CERTIFICATE")

    print(f"  Valid from:  {not_before.strftime('%Y-%m-%d %H:%M:%S')} UTC")
    print(f"  Valid until: {not_after.strftime('%Y-%m-%d %H:%M:%S')} UTC")
    print(f"  Serial:      {hex(serial_number)[:20]}...")
    print(f"  DER size:    {len(cert_der)} bytes")

    # Save files
    key_path  = output_dir / "ca_private_key.pem"
    cert_path = output_dir / "ca_certificate.pem"

    key_path.write_text(encode_pem(private_key, "ML-DSA-65 PRIVATE KEY"))
    os.chmod(key_path, 0o600)

    cert_path.write_text(cert_pem)

    print(f"\nFiles created:")
    print(f"  {key_path}  (KEEP SECRET!)")
    print(f"  {cert_path}")

    if args.verify:
        print(f"\nVerifying certificate signature...")
        if verify_cert(cert_der, public_key):
            print("  ✓ Certificate signature is valid")
        else:
            print("  ✗ Certificate signature verification FAILED")
            sys.exit(1)

    fingerprint = hashlib.sha256(cert_der).hexdigest()
    print(f"\nCertificate fingerprint (SHA-256):")
    print(f"  {fingerprint[:32]}")
    print(f"  {fingerprint[32:]}")

    print("\nDone!")
    print("\nTo use with controller.py:")
    print(f"  python controller.py --pqc-ca-cert {cert_path} --pqc-ca-key {key_path}")


if __name__ == "__main__":
    main()
