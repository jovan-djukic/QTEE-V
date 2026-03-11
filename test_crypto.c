#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Test with a known key and data
int main() {
    // Test key (128 bytes = 1024 bits, base64 encoded would be ~172 chars)
    // Using a simple test: 32 bytes of 0x01
    unsigned char master_key[32];
    memset(master_key, 0x01, 32);
    size_t key_length = 32;

    printf("=== C WolfCrypt Test ===\n");
    printf("master_key (hex): ");
    for (int i = 0; i < 32; i++) printf("%02x", master_key[i]);
    printf("\n");

    // Derive AES key = SHA256(master_key)
    unsigned char aes_key[32] = {0};
    Sha256 sha_aes;
    wc_InitSha256(&sha_aes);
    wc_Sha256Update(&sha_aes, master_key, key_length);
    wc_Sha256Final(&sha_aes, aes_key);
    wc_Sha256Free(&sha_aes);

    printf("aes_key (hex): ");
    for (int i = 0; i < 32; i++) printf("%02x", aes_key[i]);
    printf("\n");

    // Derive HMAC key = SHA256(master_key || "Mac")
    unsigned char hmac_key[32] = {0};
    Sha256 sha_hmac;
    wc_InitSha256(&sha_hmac);
    wc_Sha256Update(&sha_hmac, master_key, key_length);
    wc_Sha256Update(&sha_hmac, (const unsigned char*)"Mac", 3);
    wc_Sha256Final(&sha_hmac, hmac_key);
    wc_Sha256Free(&sha_hmac);

    printf("hmac_key (hex): ");
    for (int i = 0; i < 32; i++) printf("%02x", hmac_key[i]);
    printf("\n");

    // Test HMAC-SHA256 on a known string
    const char* test_data = "TestCiphertext123";
    unsigned char hmac_result[32] = {0};
    
    Hmac hmac;
    wc_HmacInit(&hmac, NULL, INVALID_DEVID);
    wc_HmacSetKey(&hmac, WC_SHA256, hmac_key, 32);
    wc_HmacUpdate(&hmac, (const unsigned char*)test_data, strlen(test_data));
    wc_HmacFinal(&hmac, hmac_result);
    wc_HmacFree(&hmac);

    printf("HMAC of '%s': ", test_data);
    for (int i = 0; i < 32; i++) printf("%02x", hmac_result[i]);
    printf("\n");

    return 0;
}
