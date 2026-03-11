#!/usr/bin/env python3
import hashlib
import hmac

# Test with same known key
master_key = bytes([0x01] * 32)

print("=== Python Test ===")
print(f"master_key (hex): {master_key.hex()}")

# Derive AES key = SHA256(master_key)
aes_key = hashlib.sha256(master_key).digest()
print(f"aes_key (hex): {aes_key.hex()}")

# Derive HMAC key = SHA256(master_key || "Mac")
hmac_key = hashlib.sha256(master_key + b"Mac").digest()
print(f"hmac_key (hex): {hmac_key.hex()}")

# Test HMAC-SHA256 on same known string
test_data = "TestCiphertext123"
hmac_result = hmac.new(hmac_key, test_data.encode('ascii'), hashlib.sha256).digest()
print(f"HMAC of '{test_data}': {hmac_result.hex()}")
