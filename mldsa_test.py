#!/usr/bin/env python3
"""
ML-DSA Compatibility Test between liboqs and WolfSSL

This script tests if liboqs's ML-DSA-65 can verify signatures
created by WolfSSL's Dilithium implementation.

Run mldsa_test.c first to get the test data, then paste the values here.
"""

import oqs
import base64

# Test with liboqs-only first
print("=== liboqs ML-DSA-65 Self-Test ===\n")

# Generate keypair with liboqs
signer = oqs.Signature("ML-DSA-65")
pk = signer.generate_keypair()
sk = signer.export_secret_key()

print(f"Public key size: {len(pk)} bytes")
print(f"Private key size: {len(sk)} bytes")

# Sign a message
message = b"Test message for ML-DSA signature"
signature = signer.sign(message)
print(f"Signature size: {len(signature)} bytes")
print(f"Signature (first 32 bytes): {signature[:32].hex()}")

# Verify
verifier = oqs.Signature("ML-DSA-65")
result = verifier.verify(message, signature, pk)
print(f"Self-verification: {'OK' if result else 'FAILED'}")

# Export for C testing
print("\n=== Copy these to test with C/WolfSSL ===\n")
print(f"Public key (base64):\n{base64.b64encode(pk).decode()}\n")
print(f"Private key (base64):\n{base64.b64encode(sk).decode()}\n")

print("\n=== Test WolfSSL signature with liboqs ===\n")
print("After running mldsa_test.c, paste the values below:")
print("(Uncomment and fill in the values)")
print()

# UNCOMMENT AND PASTE VALUES FROM mldsa_test.c OUTPUT:
# wolfssl_pk_b64 = "..."  # Public key from WolfSSL
# wolfssl_sig_b64 = "..."  # Signature from WolfSSL
# wolfssl_msg = b"Test message for ML-DSA signature"
#
# wolfssl_pk = base64.b64decode(wolfssl_pk_b64)
# wolfssl_sig = base64.b64decode(wolfssl_sig_b64)
#
# print(f"WolfSSL public key size: {len(wolfssl_pk)} bytes")
# print(f"WolfSSL signature size: {len(wolfssl_sig)} bytes")
#
# verifier = oqs.Signature("ML-DSA-65")
# result = verifier.verify(wolfssl_msg, wolfssl_sig, wolfssl_pk)
# print(f"WolfSSL signature verification with liboqs: {'OK' if result else 'FAILED'}")
#
# if not result:
#     print("\n!!! INCOMPATIBILITY DETECTED !!!")
#     print("WolfSSL and liboqs ML-DSA-65 implementations are NOT compatible.")
#     print("You will need to use the same library on both sides.")
