#!/usr/bin/env python3
"""
Test script to check what Kyber/ML-KEM algorithms liboqs supports
"""

import oqs

print("=== liboqs Algorithm Check ===\n")
print(f"liboqs version info available through oqs module")

# Get all supported KEMs
supported_kems = oqs.get_enabled_kem_mechanisms()
print(f"\nTotal supported KEM algorithms: {len(supported_kems)}")

# Filter for Kyber/ML-KEM
print("\nKyber/ML-KEM algorithms:")
for kem in sorted(supported_kems):
    if 'kyber' in kem.lower() or 'ml-kem' in kem.lower() or 'mlkem' in kem.lower():
        print(f"  - {kem}")

# Try to instantiate each potential algorithm name
print("\n=== Testing Algorithm Names ===")
potential_names = [
    "ML-KEM-768",
    "Kyber768", 
    "MLKEM768",
    "ml-kem-768",
    "Kyber-768",
]

for name in potential_names:
    try:
        kem = oqs.KeyEncapsulation(name)
        pk = kem.generate_keypair()
        print(f"  {name}: ✓ WORKS (public key size: {len(pk)} bytes)")
    except Exception as e:
        print(f"  {name}: ✗ FAILED ({e})")

# Also check Dilithium/ML-DSA
print("\n=== Dilithium/ML-DSA algorithms ===")
supported_sigs = oqs.get_enabled_sig_mechanisms()
for sig in sorted(supported_sigs):
    if 'dilithium' in sig.lower() or 'ml-dsa' in sig.lower():
        print(f"  - {sig}")

potential_sig_names = [
    "ML-DSA-65",
    "Dilithium3",
    "MLDSA65",
]

for name in potential_sig_names:
    try:
        sig = oqs.Signature(name)
        pk = sig.generate_keypair()
        print(f"  {name}: ✓ WORKS (public key size: {len(pk)} bytes)")
    except Exception as e:
        print(f"  {name}: ✗ FAILED ({e})")
