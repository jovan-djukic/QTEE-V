/*
 * ML-DSA / Dilithium Compatibility Test
 * 
 * This tests if WolfSSL's Dilithium can verify signatures
 * or if signatures need to be generated with liboqs for liboqs verification.
 * 
 * Compile:
 *   gcc -o mldsa_test mldsa_test.c \
 *       -I/home/dj/Desktop/wolfssl/_install_linux/include \
 *       -L/home/dj/Desktop/wolfssl/_install_linux/lib \
 *       -lwolfssl -lm
 */

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/dilithium.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/coding.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ML-DSA-65 sizes */
#define MLDSA65_PUBLIC_KEY_SIZE     1952
#define MLDSA65_SECRET_KEY_SIZE     4032
#define MLDSA65_SIGNATURE_SIZE      3309

static WC_RNG g_rng;

void print_hex(const char *label, const unsigned char *data, int len) {
    printf("%s (%d bytes): ", label, len);
    for (int i = 0; i < (len < 32 ? len : 32); i++) {
        printf("%02x", data[i]);
    }
    if (len > 32) printf("...");
    printf("\n");
}

char *base64_encode(const unsigned char *input, int length) {
    word32 outLen = 0;
    Base64_Encode_NoNl(input, length, NULL, &outLen);
    char *output = malloc(outLen + 1);
    Base64_Encode_NoNl(input, length, (byte*)output, &outLen);
    output[outLen] = '\0';
    return output;
}

int main(void) {
    dilithium_key key;
    unsigned char pk[MLDSA65_PUBLIC_KEY_SIZE];
    unsigned char sk[MLDSA65_SECRET_KEY_SIZE];
    unsigned char signature[MLDSA65_SIGNATURE_SIZE];
    word32 pk_len = MLDSA65_PUBLIC_KEY_SIZE;
    word32 sk_len = MLDSA65_SECRET_KEY_SIZE;
    word32 sig_len = MLDSA65_SIGNATURE_SIZE;
    int ret, verified;
    
    const char *message = "Test message for ML-DSA signature";
    int msg_len = strlen(message);
    
    printf("=== ML-DSA / Dilithium Compatibility Test ===\n\n");
    
    /* Initialize RNG */
    ret = wc_InitRng(&g_rng);
    if (ret != 0) {
        printf("ERROR: wc_InitRng failed: %d\n", ret);
        return 1;
    }
    
    /* Initialize key */
    ret = wc_dilithium_init(&key);
    if (ret != 0) {
        printf("ERROR: wc_dilithium_init failed: %d\n", ret);
        return 1;
    }
    
    /* Set level 3 (ML-DSA-65) */
    ret = wc_dilithium_set_level(&key, 3);
    if (ret != 0) {
        printf("ERROR: wc_dilithium_set_level(3) failed: %d (%s)\n", ret, wc_GetErrorString(ret));
        printf("Your WolfSSL may not have ML-DSA-65 / Dilithium3 enabled.\n");
        wc_dilithium_free(&key);
        return 1;
    }
    printf("Set level 3 (ML-DSA-65 / Dilithium3): OK\n");
    
    /* Generate keypair */
    ret = wc_dilithium_make_key(&key, &g_rng);
    if (ret != 0) {
        printf("ERROR: wc_dilithium_make_key failed: %d\n", ret);
        wc_dilithium_free(&key);
        return 1;
    }
    printf("Key generation: OK\n");
    
    /* Export keys */
    ret = wc_dilithium_export_public(&key, pk, &pk_len);
    if (ret != 0) {
        printf("ERROR: wc_dilithium_export_public failed: %d\n", ret);
        wc_dilithium_free(&key);
        return 1;
    }
    
    ret = wc_dilithium_export_private(&key, sk, &sk_len);
    if (ret != 0) {
        printf("ERROR: wc_dilithium_export_private failed: %d\n", ret);
        wc_dilithium_free(&key);
        return 1;
    }
    
    printf("\nKey sizes:\n");
    printf("  Public key:  %d bytes (expected %d)\n", pk_len, MLDSA65_PUBLIC_KEY_SIZE);
    printf("  Private key: %d bytes (expected %d)\n", sk_len, MLDSA65_SECRET_KEY_SIZE);
    
    /* Sign message */
    ret = wc_dilithium_sign_msg((const byte*)message, msg_len, signature, &sig_len, &key, &g_rng);
    if (ret != 0) {
        printf("ERROR: wc_dilithium_sign_msg failed: %d\n", ret);
        wc_dilithium_free(&key);
        return 1;
    }
    printf("\nSignature:\n");
    printf("  Size: %d bytes (expected max %d)\n", sig_len, MLDSA65_SIGNATURE_SIZE);
    print_hex("  First 32 bytes", signature, 32);
    
    /* Verify signature */
    ret = wc_dilithium_verify_msg(signature, sig_len, (const byte*)message, msg_len, &verified, &key);
    if (ret != 0 || !verified) {
        printf("ERROR: wc_dilithium_verify_msg failed: ret=%d, verified=%d\n", ret, verified);
        wc_dilithium_free(&key);
        return 1;
    }
    printf("\nSelf-verification: OK\n");
    
    wc_dilithium_free(&key);
    
    /* Output base64 for testing with Python */
    printf("\n=== Copy these to test with Python/liboqs ===\n\n");
    
    char *pk_b64 = base64_encode(pk, pk_len);
    char *sig_b64 = base64_encode(signature, sig_len);
    
    printf("Public key (base64):\n%s\n\n", pk_b64);
    printf("Signature (base64):\n%s\n\n", sig_b64);
    printf("Message: %s\n\n", message);
    
    printf("=== Python test code ===\n");
    printf("import oqs\n");
    printf("import base64\n");
    printf("\n");
    printf("pk = base64.b64decode('%s')\n", pk_b64);
    printf("sig = base64.b64decode('%s')\n", sig_b64);
    printf("msg = b'%s'\n", message);
    printf("\n");
    printf("verifier = oqs.Signature('ML-DSA-65')\n");
    printf("result = verifier.verify(msg, sig, pk)\n");
    printf("print(f'Verification result: {result}')\n");
    
    free(pk_b64);
    free(sig_b64);
    wc_FreeRng(&g_rng);
    
    printf("\n=== Test Complete ===\n");
    return 0;
}
