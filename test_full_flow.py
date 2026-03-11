#!/usr/bin/env python3
import hashlib
import hmac
import base64

# Simulate what the QKD system returns - let's test with a base64 key
# This is what would come from the KME
test_key_b64 = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="  # 32 bytes of 0x01

print("=== Python Full Flow Test ===")
print(f"key_text (from KME): '{test_key_b64}'")

# Decode master key (simulating decode_master_key)
# Check if it's hex or base64
stripped = test_key_b64.strip()
is_all_hex = len(stripped) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in stripped)

if is_all_hex:
    master_key = bytes.fromhex(stripped)
    print("Detected as: HEX")
else:
    master_key = base64.b64decode(stripped)
    print("Detected as: BASE64")

print(f"master_key length: {len(master_key)}")
print(f"master_key (hex): {master_key.hex()}")

# Derive keys
aes_key = hashlib.sha256(master_key).digest()
hmac_key = hashlib.sha256(master_key + b"Mac").digest()

print(f"aes_key (hex): {aes_key.hex()}")
print(f"hmac_key (hex): {hmac_key.hex()}")

# Test HMAC on a ciphertext-like string
test_ciphertext_b64 = "CCbCLbaQFddNs93xHsyU4BzJKHm0ai+DUSLYHFqwiP4="
hmac_result = hmac.new(hmac_key, test_ciphertext_b64.encode('ascii'), hashlib.sha256).digest()
print(f"\nHMAC of ciphertext_b64 '{test_ciphertext_b64}':")
print(f"  {hmac_result.hex()}")
