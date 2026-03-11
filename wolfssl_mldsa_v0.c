// wolfssl_mldsa.c

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/dilithium.h>
#include <wolfssl/wolfcrypt/random.h>
#include <string.h>
#include <stdlib.h>

static WC_RNG g_rng;
static int g_initialized = 0;

int mldsa_init(void) {
    if (g_initialized) return 0;
    int ret = wc_InitRng(&g_rng);
    if (ret == 0) g_initialized = 1;
    return ret;
}

void mldsa_cleanup(void) {
    if (g_initialized) {
        wc_FreeRng(&g_rng);
        g_initialized = 0;
    }
}

int mldsa_keygen(unsigned char *pk, unsigned int *pk_len,
                 unsigned char *sk, unsigned int *sk_len) {
    dilithium_key key;
    int ret;
    
    ret = wc_dilithium_init(&key);
    if (ret != 0) return ret;
    
    ret = wc_dilithium_set_level(&key, 3);
    if (ret != 0) { wc_dilithium_free(&key); return ret; }
    
    ret = wc_dilithium_make_key(&key, &g_rng);
    if (ret != 0) { wc_dilithium_free(&key); return ret; }
    
    ret = wc_dilithium_export_public(&key, pk, pk_len);
    if (ret != 0) { wc_dilithium_free(&key); return ret; }
    
    ret = wc_dilithium_export_private(&key, sk, sk_len);
    wc_dilithium_free(&key);
    return ret;
}

int mldsa_sign(const unsigned char *sk, unsigned int sk_len,
               const unsigned char *msg, unsigned int msg_len,
               unsigned char *sig, unsigned int *sig_len) {
    dilithium_key key;
    int ret;
    
    ret = wc_dilithium_init(&key);
    if (ret != 0) return ret;
    
    ret = wc_dilithium_set_level(&key, 3);
    if (ret != 0) { wc_dilithium_free(&key); return ret; }
    
    ret = wc_dilithium_import_private(sk, sk_len, &key);
    if (ret != 0) { wc_dilithium_free(&key); return ret; }
    
    ret = wc_dilithium_sign_msg(msg, msg_len, sig, sig_len, &key, &g_rng);
    wc_dilithium_free(&key);
    return ret;
}

int mldsa_verify(const unsigned char *pk, unsigned int pk_len,
                 const unsigned char *msg, unsigned int msg_len,
                 const unsigned char *sig, unsigned int sig_len) {
    dilithium_key key;
    int ret;
    
    ret = wc_dilithium_init(&key);
    if (ret != 0) return ret;
    
    ret = wc_dilithium_set_level(&key, 3);
    if (ret != 0) { wc_dilithium_free(&key); return ret; }
    
    ret = wc_dilithium_import_public(pk, pk_len, &key);
    if (ret != 0) { wc_dilithium_free(&key); return ret; }
    
    int verified = 0;
    ret = wc_dilithium_verify_msg(sig, sig_len, msg, msg_len, &verified, &key);
    wc_dilithium_free(&key);
    
    return (ret == 0 && verified == 1) ? 0 : -1;
}

unsigned int mldsa_pk_size(void) { return 1952; }
unsigned int mldsa_sk_size(void) { return 4032; }
unsigned int mldsa_sig_size(void) { return 3309; }