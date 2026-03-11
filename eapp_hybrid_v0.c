/*
 * QKD Relay Repetitor - Hybrid PQC/RSA Version (Complete C Implementation)
 * 
 * Converted from repetitor_hybrid_single_thread.py
 * 
 * Uses WolfSSL with ML-KEM (Kyber) and ML-DSA (Dilithium) support
 * 
 * Compile:
 *   gcc -o eapp_hybrid eapp_hybrid.c \
 *       -I/path/to/wolfssl/_install_linux/include \
 *       -L/path/to/wolfssl/_install_linux/lib \
 *       -lwolfssl -lm -lpthread
 */

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/coding.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

/* ML-KEM (Kyber) - new API */
#include <wolfssl/wolfcrypt/wc_mlkem.h>

/* ML-DSA (Dilithium) */
#include <wolfssl/wolfcrypt/dilithium.h>

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>

/* ==================== Constants ==================== */

#define SYMMETRIC_KEY_SIZE      32
#define AES_IV_SIZE             16
#define AES_BLOCK_SIZE          16

/* ML-KEM-768 (Kyber768) sizes */
#define MLKEM768_PUBLIC_KEY_SIZE    1184
#define MLKEM768_SECRET_KEY_SIZE    2400
#define MLKEM768_CIPHERTEXT_SIZE    1088
#define MLKEM768_SHARED_SECRET_SIZE 32

/* ML-DSA-65 (Dilithium3) sizes */
#define MLDSA65_PUBLIC_KEY_SIZE     1952
#define MLDSA65_SECRET_KEY_SIZE     4032
#define MLDSA65_SIGNATURE_SIZE      3309

#define MAX_BUFFER_SIZE     131072
#define MAX_CERT_SIZE       32768
#define MAX_JSON_SIZE       131072
#define MAX_URL_SIZE        256
#define MAX_CN_SIZE         128
#define MAX_HTTP_RESPONSE   131072

/* ==================== CA Certificates ==================== */

const char *QKD_CA_CERTIFICATE = "-----BEGIN CERTIFICATE-----\n"
"MIIDbTCCAlWgAwIBAgIQCzuhkEQXTouuETnIFrtF1jANBgkqhkiG9w0BAQsFADBn\n"
"MSwwKgYDVQQDDCNhY2N0LTI1NjMuZXRzaS1xa2QtYXBpLnF1a2F5ZGVlLmNvbTEe\n"
"MBwGA1UECgwVUXVLYXlEZWUgYWNjb3VudCAyNTYzMRcwFQYDVQQLDA5TZXJ2ZXIg\n"
"cm9vdCBDQTAgFw0yNTA1MjYwODMxMzlaGA8yMTI1MDUwMzA4MzEzOVowZzEsMCoG\n"
"A1UEAwwjYWNjdC0yNTYzLmV0c2ktcWtkLWFwaS5xdWtheWRlZS5jb20xHjAcBgNV\n"
"BAoMFVF1S2F5RGVlIGFjY291bnQgMjU2MzEXMBUGA1UECwwOU2VydmVyIHJvb3Qg\n"
"Q0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC6fv8Hp8hL7P6Rs3Zc\n"
"X3oHL6hEXbx5hmSPLFvSIpLnF1iZepdlJtXJiq2oVZNcdtDgnYA5ugl6CGQE8v3A\n"
"79hxrWOSSfysYryoIBBYSvaEPEN16TSKcY7+cAnSU8fu736uRhKwz2jeJw2g+4pb\n"
"lcmsJhLq40F23Px+XkpA99DPIGHWWy2ZelcddnP1M99/l937V2AvGaM+P71NMS9a\n"
"F/K/2iiDOiAQ3XZXVIjmsdSMHth2780U80wiAaH2PsOILMbKNLdxDLYIJa5awmXY\n"
"1D8Dik9Ot7e0It+ZfdaXxUHBxnTj7CgajqhOvd78p2PCwMhZ61DO+5subpzhywxE\n"
"t92/AgMBAAGjEzARMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEB\n"
"AAuWsi3TFKGn1H6raS0aSw6JqE5c/PUMGRTBDzmSpIUMjnaG/9Ise1SGxujAYvpm\n"
"ahExKKFkgTuSV4GmYL1n4Yakls3sr9hbP40L2wJLus+psfGKsN+Xa3hwyFrQVyKY\n"
"dNpIH+AIhH/nI2WKyYnhv0dE2PR/UzR3AtCum/uu8C2JnY0qnBlQ3ooOopti0+MK\n"
"zEHJBAK2jxm9vjEgHs+zHKIxOiuCM6jmPZsG4PdBWkcf1C6Coof0kfO3vednsE/B\n"
"0Q1c9TemcUbH6OR0kDxJFV/Alsim2wolJ722QOlBB2+m88POeSqN9JLxcj3pQe53\n"
"wkKhllHrkuVRW7pw4wXXn8w=\n"
"-----END CERTIFICATE-----";

static char *g_pqc_ca_certificate = NULL;

const char *CONTROLLER_HOST = "127.0.0.1";
const char *CONTROLLER_PORT = "8000";
const char *KME_PORT = "443";

static volatile int keep_running = 1;

/* ==================== Data Structures ==================== */

typedef struct {
    char *left_repetitor_url;
    char *right_repetitor_url;
    char *left_repetitor_id;
    char *right_repetitor_id;
    char *left_kme;
    char *right_kme;
    char *left_cn;
    char *right_cn;
    char *left_kme_peer;
    char *right_kme_peer;
    char *whitelist;
    
    /* PQC credentials */
    unsigned char pqc_private_key[MLDSA65_SECRET_KEY_SIZE];
    unsigned char pqc_public_key[MLDSA65_PUBLIC_KEY_SIZE];
    char *pqc_certificate;
    
    /* RSA credentials for KME */
    unsigned char *left_rsa_key_der;
    int left_rsa_key_der_len;
    char *left_rsa_cert;
    unsigned char *right_rsa_key_der;
    int right_rsa_key_der_len;
    char *right_rsa_cert;
} repetitor_config_t;

typedef struct {
    char *message;
    char *sender_cn;
} pqc_message_t;

/* Global RNG */
static WC_RNG g_rng;
static int g_rng_initialized = 0;

/* ==================== Signal Handler ==================== */

void handle_sigint(int sig) { (void)sig; keep_running = 0; }

/* ==================== Utility Functions ==================== */

void get_timestamp(char *buf, size_t len) {
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    strftime(buf, len, "%H:%M:%S", tm_info);
}

static int init_rng(void) {
    if (!g_rng_initialized) {
        if (wc_InitRng(&g_rng) != 0) return -1;
        g_rng_initialized = 1;
    }
    return 0;
}

static void cleanup_rng(void) {
    if (g_rng_initialized) { wc_FreeRng(&g_rng); g_rng_initialized = 0; }
}

static int random_bytes(unsigned char *buffer, int length) {
    if (init_rng() != 0) return -1;
    return wc_RNG_GenerateBlock(&g_rng, buffer, length);
}

/* ==================== JSON Parsing ==================== */

char *extract_json_string(const char *json, const char *field) {
    char pattern[256];
    snprintf(pattern, sizeof(pattern), "\"%s\"", field);
    
    const char *pos = strstr(json, pattern);
    if (!pos) return NULL;
    
    pos += strlen(pattern);
    while (*pos == ' ' || *pos == '\t' || *pos == ':') pos++;
    if (*pos != '"') return NULL;
    pos++;
    
    const char *end = pos;
    while (*end && *end != '"') {
        if (*end == '\\' && *(end+1)) end += 2;
        else end++;
    }
    if (*end != '"') return NULL;
    
    size_t len = end - pos;
    char *result = malloc(len + 1);
    if (!result) return NULL;
    
    char *out = result;
    const char *in = pos;
    while (in < end) {
        if (*in == '\\' && in + 1 < end) {
            in++;
            switch (*in) {
                case 'n': *out++ = '\n'; break;
                case 'r': *out++ = '\r'; break;
                case 't': *out++ = '\t'; break;
                case '"': *out++ = '"'; break;
                case '\\': *out++ = '\\'; break;
                default: *out++ = *in; break;
            }
            in++;
        } else {
            *out++ = *in++;
        }
    }
    *out = '\0';
    return result;
}

char *json_escape(const char *str) {
    size_t len = strlen(str);
    char *escaped = malloc(len * 2 + 1);
    if (!escaped) return NULL;
    
    char *out = escaped;
    for (const char *in = str; *in; in++) {
        if (*in == '"' || *in == '\\') *out++ = '\\';
        else if (*in == '\n') { *out++ = '\\'; *out++ = 'n'; continue; }
        else if (*in == '\r') { *out++ = '\\'; *out++ = 'r'; continue; }
        *out++ = *in;
    }
    *out = '\0';
    return escaped;
}

/* ==================== Base64 Functions ==================== */

char *base64_encode(const unsigned char *input, int length) {
    word32 outLen = 0;
    int ret = Base64_Encode_NoNl(input, length, NULL, &outLen);
    if (ret != LENGTH_ONLY_E && ret != 0) return NULL;
    
    char *output = malloc(outLen + 1);
    if (!output) return NULL;
    
    if (Base64_Encode_NoNl(input, length, (byte*)output, &outLen) != 0) {
        free(output); return NULL;
    }
    output[outLen] = '\0';
    return output;
}

unsigned char *base64_decode(const char *input, size_t *out_len) {
    size_t in_len = strlen(input);
    size_t padding = (4 - (in_len & 3)) & 3;
    
    char *padded = malloc(in_len + padding + 1);
    if (!padded) return NULL;
    strcpy(padded, input);
    memset(padded + in_len, '=', padding);
    padded[in_len + padding] = '\0';
    
    word32 dec_len = ((in_len + padding) * 3) / 4;
    unsigned char *output = malloc(dec_len + 1);
    if (!output) { free(padded); return NULL; }
    
    int ret = Base64_Decode((const byte*)padded, (word32)strlen(padded), output, &dec_len);
    free(padded);
    
    if (ret != 0) { free(output); return NULL; }
    *out_len = dec_len;
    return output;
}

/* ==================== Hex Functions ==================== */

void bytes_to_hex(const unsigned char *bytes, size_t len, char *hex) {
    static const char *h = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        hex[i*2] = h[bytes[i] >> 4];
        hex[i*2+1] = h[bytes[i] & 0x0F];
    }
    hex[len*2] = '\0';
}

int hex_to_bytes(const char *hex, unsigned char *bytes, size_t max_len) {
    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0 || hex_len / 2 > max_len) return -1;
    for (size_t i = 0; i < hex_len / 2; i++) {
        if (sscanf(hex + i*2, "%2hhx", &bytes[i]) != 1) return -1;
    }
    return (int)(hex_len / 2);
}


/* Escape a string for JSON embedding */
char *certificate_json_escape(const char *str) {
    if (!str) return strdup("");
    
    /* Calculate escaped length */
    size_t len = 0;
    for (const char *p = str; *p; p++) {
        switch (*p) {
            case '"': case '\\': case '\n': case '\r': case '\t':
                len += 2;
                break;
            default:
                len += 1;
        }
    }
    
    char *escaped = malloc(len + 1);
    if (!escaped) return NULL;
    
    char *out = escaped;
    for (const char *p = str; *p; p++) {
        switch (*p) {
            case '"':  *out++ = '\\'; *out++ = '"';  break;
            case '\\': *out++ = '\\'; *out++ = '\\'; break;
            case '\n': *out++ = '\\'; *out++ = 'n';  break;
            case '\r': *out++ = '\\'; *out++ = 'r';  break;
            case '\t': *out++ = '\\'; *out++ = 't';  break;
            default:   *out++ = *p;
        }
    }
    *out = '\0';
    return escaped;
}

void parse_url(const char *url, char *host, int *port) {
    const char *colon = strchr(url, ':');
    if (colon) {
        size_t host_len = colon - url;
        strncpy(host, url, host_len);
        host[host_len] = '\0';
        *port = atoi(colon + 1);
    } else {
        strcpy(host, url);
        *port = 443;
    }
}

/* ==================== AES-256-CBC Functions ==================== */

static int pkcs7_pad(unsigned char *data, int data_len, int block_size) {
    int pad_len = block_size - (data_len % block_size);
    for (int i = 0; i < pad_len; i++) data[data_len + i] = (unsigned char)pad_len;
    return data_len + pad_len;
}

static int pkcs7_unpad(unsigned char *data, int data_len) {
    if (data_len == 0) return -1;
    int pad_len = data[data_len - 1];
    if (pad_len < 1 || pad_len > 16) return -1;
    for (int i = 0; i < pad_len; i++) {
        if (data[data_len - 1 - i] != pad_len) return -1;
    }
    return data_len - pad_len;
}

char *aes_encrypt_string(const char *plaintext, const unsigned char *key) {
    unsigned char iv[AES_IV_SIZE];
    if (random_bytes(iv, AES_IV_SIZE) != 0) return NULL;
    
    int pt_len = strlen(plaintext);
    int padded_len = pt_len + (AES_BLOCK_SIZE - (pt_len % AES_BLOCK_SIZE));
    
    unsigned char *padded = calloc(padded_len, 1);
    if (!padded) return NULL;
    memcpy(padded, plaintext, pt_len);
    pkcs7_pad(padded, pt_len, AES_BLOCK_SIZE);
    
    unsigned char *ciphertext = malloc(padded_len);
    if (!ciphertext) { free(padded); return NULL; }
    
    Aes aes;
    wc_AesInit(&aes, NULL, INVALID_DEVID);
    wc_AesSetKey(&aes, key, SYMMETRIC_KEY_SIZE, iv, AES_ENCRYPTION);
    wc_AesCbcEncrypt(&aes, ciphertext, padded, padded_len);
    wc_AesFree(&aes);
    free(padded);
    
    int combined_len = AES_IV_SIZE + padded_len;
    unsigned char *combined = malloc(combined_len);
    memcpy(combined, iv, AES_IV_SIZE);
    memcpy(combined + AES_IV_SIZE, ciphertext, padded_len);
    free(ciphertext);
    
    char *result = base64_encode(combined, combined_len);
    free(combined);
    return result;
}

char *aes_decrypt_string(const char *ciphertext_b64, const unsigned char *key) {
    size_t combined_len;
    unsigned char *combined = base64_decode(ciphertext_b64, &combined_len);
    if (!combined || combined_len < AES_IV_SIZE + AES_BLOCK_SIZE) {
        free(combined); return NULL;
    }
    
    unsigned char *iv = combined;
    unsigned char *ciphertext = combined + AES_IV_SIZE;
    int ct_len = combined_len - AES_IV_SIZE;
    
    unsigned char *plaintext = malloc(ct_len + 1);
    if (!plaintext) { free(combined); return NULL; }
    
    Aes aes;
    wc_AesInit(&aes, NULL, INVALID_DEVID);
    wc_AesSetKey(&aes, key, SYMMETRIC_KEY_SIZE, iv, AES_DECRYPTION);
    wc_AesCbcDecrypt(&aes, plaintext, ciphertext, ct_len);
    wc_AesFree(&aes);
    free(combined);
    
    int unpadded_len = pkcs7_unpad(plaintext, ct_len);
    if (unpadded_len < 0) { free(plaintext); return NULL; }
    
    plaintext[unpadded_len] = '\0';
    return (char*)plaintext;
}

int aes_encrypt_bytes(const unsigned char *plaintext, int pt_len,
                      const unsigned char *key, unsigned char *output, int *out_len) {
    unsigned char iv[AES_IV_SIZE];
    if (random_bytes(iv, AES_IV_SIZE) != 0) return -1;
    
    int padded_len = pt_len + (AES_BLOCK_SIZE - (pt_len % AES_BLOCK_SIZE));
    unsigned char *padded = calloc(padded_len, 1);
    if (!padded) return -1;
    memcpy(padded, plaintext, pt_len);
    pkcs7_pad(padded, pt_len, AES_BLOCK_SIZE);
    
    Aes aes;
    wc_AesInit(&aes, NULL, INVALID_DEVID);
    wc_AesSetKey(&aes, key, SYMMETRIC_KEY_SIZE, iv, AES_ENCRYPTION);
    memcpy(output, iv, AES_IV_SIZE);
    wc_AesCbcEncrypt(&aes, output + AES_IV_SIZE, padded, padded_len);
    wc_AesFree(&aes);
    free(padded);
    
    *out_len = AES_IV_SIZE + padded_len;
    return 0;
}

int aes_decrypt_bytes(const unsigned char *input, int in_len,
                      const unsigned char *key, unsigned char *output, int *out_len) {
    if (in_len < AES_IV_SIZE + AES_BLOCK_SIZE) return -1;
    
    const unsigned char *iv = input;
    const unsigned char *ciphertext = input + AES_IV_SIZE;
    int ct_len = in_len - AES_IV_SIZE;
    
    Aes aes;
    wc_AesInit(&aes, NULL, INVALID_DEVID);
    wc_AesSetKey(&aes, key, SYMMETRIC_KEY_SIZE, iv, AES_DECRYPTION);
    wc_AesCbcDecrypt(&aes, output, ciphertext, ct_len);
    wc_AesFree(&aes);
    
    int unpadded = pkcs7_unpad(output, ct_len);
    if (unpadded < 0) return -1;
    *out_len = unpadded;
    return 0;
}

/* ==================== ML-KEM-768 (Kyber) Functions ==================== */
/* Using the NEW WolfSSL ML-KEM API (MlKemKey, wc_MlKemKey_*) */

int pqc_mlkem_generate_keypair(unsigned char *pk, unsigned char *sk) {
    MlKemKey key;
    int ret;
    
    /* Initialize with ML-KEM-768 */
    ret = wc_MlKemKey_Init(&key, WC_ML_KEM_768, NULL, INVALID_DEVID);
    if (ret != 0) {
        fprintf(stderr, "[ERROR] wc_MlKemKey_Init failed: %d (%s)\n", ret, wc_GetErrorString(ret));
        return ret;
    }
    
    /* Generate key pair */
    ret = wc_MlKemKey_MakeKey(&key, &g_rng);
    if (ret != 0) { 
        fprintf(stderr, "[ERROR] wc_MlKemKey_MakeKey failed: %d (%s)\n", ret, wc_GetErrorString(ret));
        wc_MlKemKey_Free(&key); 
        return ret; 
    }
    
    /* Export public key */
    word32 pk_len = MLKEM768_PUBLIC_KEY_SIZE;
    ret = wc_MlKemKey_EncodePublicKey(&key, pk, pk_len);
    if (ret != 0) { 
        fprintf(stderr, "[ERROR] wc_MlKemKey_EncodePublicKey failed: %d (%s)\n", ret, wc_GetErrorString(ret));
        wc_MlKemKey_Free(&key); 
        return ret; 
    }
    
    /* Export private key */
    word32 sk_len = MLKEM768_SECRET_KEY_SIZE;
    ret = wc_MlKemKey_EncodePrivateKey(&key, sk, sk_len);
    if (ret != 0) {
        fprintf(stderr, "[ERROR] wc_MlKemKey_EncodePrivateKey failed: %d (%s)\n", ret, wc_GetErrorString(ret));
    }
    
    wc_MlKemKey_Free(&key);
    return ret;
}

int pqc_mlkem_encapsulate(const unsigned char *pk, unsigned char *ct, unsigned char *ss) {
    MlKemKey key;
    int ret;
    
    ret = wc_MlKemKey_Init(&key, WC_ML_KEM_768, NULL, INVALID_DEVID);
    if (ret != 0) return ret;
    
    ret = wc_MlKemKey_DecodePublicKey(&key, pk, MLKEM768_PUBLIC_KEY_SIZE);
    if (ret != 0) { wc_MlKemKey_Free(&key); return ret; }
    
    ret = wc_MlKemKey_Encapsulate(&key, ct, ss, &g_rng);
    wc_MlKemKey_Free(&key);
    return ret;
}

int pqc_mlkem_decapsulate(const unsigned char *sk, const unsigned char *ct, unsigned char *ss) {
    MlKemKey key;
    int ret;
    
    ret = wc_MlKemKey_Init(&key, WC_ML_KEM_768, NULL, INVALID_DEVID);
    if (ret != 0) return ret;
    
    ret = wc_MlKemKey_DecodePrivateKey(&key, sk, MLKEM768_SECRET_KEY_SIZE);
    if (ret != 0) { wc_MlKemKey_Free(&key); return ret; }
    
    ret = wc_MlKemKey_Decapsulate(&key, ss, ct, MLKEM768_CIPHERTEXT_SIZE);
    wc_MlKemKey_Free(&key);
    return ret;
}

/* ==================== ML-DSA-65 (Dilithium) Functions ==================== */

int pqc_mldsa_generate_keypair(unsigned char *pk, unsigned char *sk) {
    dilithium_key key;
    int ret;
    
    ret = wc_dilithium_init(&key);
    if (ret != 0) {
        fprintf(stderr, "[ERROR] wc_dilithium_init failed: %d (%s)\n", ret, wc_GetErrorString(ret));
        return ret;
    }
    
    /* Level 3 = ML-DSA-65 */
    ret = wc_dilithium_set_level(&key, 3);
    if (ret != 0) { 
        fprintf(stderr, "[ERROR] wc_dilithium_set_level failed: %d (%s)\n", ret, wc_GetErrorString(ret));
        wc_dilithium_free(&key); 
        return ret; 
    }
    
    ret = wc_dilithium_make_key(&key, &g_rng);
    if (ret != 0) { 
        fprintf(stderr, "[ERROR] wc_dilithium_make_key failed: %d (%s)\n", ret, wc_GetErrorString(ret));
        wc_dilithium_free(&key); 
        return ret; 
    }
    
    word32 pk_len = MLDSA65_PUBLIC_KEY_SIZE;
    word32 sk_len = MLDSA65_SECRET_KEY_SIZE;
    
    ret = wc_dilithium_export_public(&key, pk, &pk_len);
    if (ret != 0) { 
        fprintf(stderr, "[ERROR] wc_dilithium_export_public failed: %d (%s)\n", ret, wc_GetErrorString(ret));
        wc_dilithium_free(&key); 
        return ret; 
    }
    
    ret = wc_dilithium_export_private(&key, sk, &sk_len);
    wc_dilithium_free(&key);
    return ret;
}

int pqc_mldsa_sign(const unsigned char *sk, const unsigned char *msg, int msg_len,
               unsigned char *sig, int *sig_len) {
    dilithium_key key;
    int ret = wc_dilithium_init(&key);
    if (ret != 0) return ret;
    
    ret = wc_dilithium_set_level(&key, 3);
    if (ret != 0) { wc_dilithium_free(&key); return ret; }
    
    ret = wc_dilithium_import_private(sk, MLDSA65_SECRET_KEY_SIZE, &key);
    if (ret != 0) { wc_dilithium_free(&key); return ret; }
    
    word32 out_len = MLDSA65_SIGNATURE_SIZE;
    ret = wc_dilithium_sign_msg(msg, msg_len, sig, &out_len, &key, &g_rng);
    *sig_len = out_len;
    
    wc_dilithium_free(&key);
    return ret;
}

int pqc_mldsa_verify(const unsigned char *pk, const unsigned char *msg, int msg_len,
                 const unsigned char *sig, int sig_len) {
    dilithium_key key;
    int ret, verified = 0;
    
    ret = wc_dilithium_init(&key);
    if (ret != 0) return -1;
    
    ret = wc_dilithium_set_level(&key, 3);
    if (ret != 0) { wc_dilithium_free(&key); return -1; }
    
    ret = wc_dilithium_import_public(pk, MLDSA65_PUBLIC_KEY_SIZE, &key);
    if (ret != 0) { wc_dilithium_free(&key); return -1; }
    
    ret = wc_dilithium_verify_msg(sig, sig_len, msg, msg_len, &verified, &key);
    wc_dilithium_free(&key);
    
    return (ret == 0 && verified) ? 0 : -1;
}

/* ==================== Key Derivation ==================== */

void derive_shared_key(const unsigned char *ss1, const unsigned char *ss2,
                       unsigned char *out_key) {
    /* 
     * Use HKDF to match Python's cryptography library:
     *   HKDF(SHA256, salt=None, info="qkd-relay-v1").derive(ss1 + ss2)
     */
    unsigned char combined[64];  /* ss1 (32 bytes) + ss2 (32 bytes) */
    memcpy(combined, ss1, MLKEM768_SHARED_SECRET_SIZE);
    memcpy(combined + MLKEM768_SHARED_SECRET_SIZE, ss2, MLKEM768_SHARED_SECRET_SIZE);
    
    const char *info = "qkd-relay-v1";
    
    int ret = wc_HKDF(
        WC_SHA256,                          /* Hash type */
        combined,                           /* Input key material */
        sizeof(combined),                   /* IKM length (64 bytes) */
        NULL,                               /* Salt (NULL = zero salt per RFC 5869) */
        0,                                  /* Salt length */
        (const unsigned char*)info,         /* Info/context */
        strlen(info),                       /* Info length */
        out_key,                            /* Output */
        32                                  /* Output length */
    );
    
    if (ret != 0) {
        fprintf(stderr, "[ERROR] wc_HKDF failed: %d (%s)\n", ret, wc_GetErrorString(ret));
    }
}

void derive_session_key(const unsigned char *shared_secret, unsigned char *session_key) {
    wc_Sha256 sha;
    wc_InitSha256(&sha);
    wc_Sha256Update(&sha, shared_secret, MLKEM768_SHARED_SECRET_SIZE);
    wc_Sha256Final(&sha, session_key);
    wc_Sha256Free(&sha);
}


/* ==================== RSA Key Generation ==================== */

int rsa_generate_keypair(unsigned char **der_out, int *der_len) {
    RsaKey key;
    int ret = wc_InitRsaKey(&key, NULL);
    if (ret != 0) return ret;
    
    ret = wc_MakeRsaKey(&key, 2048, 65537, &g_rng);
    if (ret != 0) { wc_FreeRsaKey(&key); return ret; }
    
    /* Export private key to DER */
    int estSize = wc_RsaKeyToDer(&key, NULL, 0);
    if (estSize < 0) { wc_FreeRsaKey(&key); return estSize; }
    
    unsigned char *der = malloc(estSize);
    if (!der) { wc_FreeRsaKey(&key); return -1; }
    
    *der_len = wc_RsaKeyToDer(&key, der, estSize);
    wc_FreeRsaKey(&key);
    
    if (*der_len < 0) { free(der); return *der_len; }
    
    *der_out = der;
    return 0;
}

/* Generate CSR in PEM format */
char *rsa_create_csr(const unsigned char *key_der, int key_der_len, const char *cn) {
    RsaKey key;
    int ret = wc_InitRsaKey(&key, NULL);
    if (ret != 0) return NULL;
    
    word32 idx = 0;
    ret = wc_RsaPrivateKeyDecode(key_der, &idx, &key, key_der_len);
    if (ret != 0) { wc_FreeRsaKey(&key); return NULL; }
    
    Cert req;
    wc_InitCert(&req);
    strncpy(req.subject.commonName, cn, CTC_NAME_SIZE - 1);
    req.sigType = CTC_SHA256wRSA;
    
    unsigned char der[4096];
    int derSz = wc_MakeCertReq(&req, der, sizeof(der), &key, NULL);
    if (derSz < 0) { wc_FreeRsaKey(&key); return NULL; }
    
    derSz = wc_SignCert(req.bodySz, req.sigType, der, sizeof(der), &key, NULL, &g_rng);
    wc_FreeRsaKey(&key);
    if (derSz < 0) return NULL;
    
    /* Convert to PEM */
    int pemSz = wc_DerToPem(der, derSz, NULL, 0, CERTREQ_TYPE);
    if (pemSz < 0) return NULL;
    
    char *pem = malloc(pemSz + 1);
    if (!pem) return NULL;
    
    pemSz = wc_DerToPem(der, derSz, (byte*)pem, pemSz, CERTREQ_TYPE);
    if (pemSz < 0) { free(pem); return NULL; }
    
    pem[pemSz] = '\0';
    return pem;
}

/* Convert RSA private key DER to PEM */
char *rsa_key_to_pem(const unsigned char *der, int der_len) {
    int pemSz = wc_DerToPem(der, der_len, NULL, 0, PRIVATEKEY_TYPE);
    if (pemSz < 0) return NULL;
    
    char *pem = malloc(pemSz + 1);
    if (!pem) return NULL;
    
    pemSz = wc_DerToPem(der, der_len, (byte*)pem, pemSz, PRIVATEKEY_TYPE);
    if (pemSz < 0) { free(pem); return NULL; }
    
    pem[pemSz] = '\0';
    return pem;
}

/* ==================== TCP/HTTP Functions ==================== */

int tcp_connect(const char *host, int port) {
    struct sockaddr_in addr;
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;
    
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    
    if (inet_pton(AF_INET, host, &addr.sin_addr) <= 0) {
        struct hostent *he = gethostbyname(host);
        if (!he) { close(sock); return -1; }
        memcpy(&addr.sin_addr, he->h_addr_list[0], he->h_length);
    }
    
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(sock); return -1;
    }
    return sock;
}

/* Simple HTTP POST */
char *http_post(const char *host, int port, const char *path, const char *json_body) {
    int sock = tcp_connect(host, port);
    if (sock < 0) return NULL;
    
    char *request = malloc(strlen(json_body) + 512);
    sprintf(request,
            "POST %s HTTP/1.1\r\n"
            "Host: %s:%d\r\n"
            "Content-Type: application/json\r\n"
            "Content-Length: %zu\r\n"
            "Connection: close\r\n"
            "\r\n%s",
            path, host, port, strlen(json_body), json_body);
    
    send(sock, request, strlen(request), 0);
    free(request);
    
    char *response = malloc(MAX_HTTP_RESPONSE);
    int total = 0;
    int n;
    while ((n = recv(sock, response + total, MAX_HTTP_RESPONSE - total - 1, 0)) > 0) {
        total += n;
    }
    response[total] = '\0';
    close(sock);
    
    /* Find body after \r\n\r\n */
    char *body = strstr(response, "\r\n\r\n");
    if (!body) { free(response); return NULL; }
    body += 4;
    
    char *result = strdup(body);
    free(response);
    return result;
}

/* ==================== Length-Prefixed I/O ==================== */

int send_length_prefixed(int sock, const unsigned char *data, int len) {
    uint32_t net_len = htonl(len);
    if (send(sock, &net_len, 4, 0) != 4) return -1;
    
    int sent = 0;
    while (sent < len) {
        int n = send(sock, data + sent, len - sent, 0);
        if (n <= 0) return -1;
        sent += n;
    }
    return 0;
}

int recv_length_prefixed(int sock, unsigned char *buffer, int max_len) {
    uint32_t net_len;
    int received = 0;
    
    while (received < 4) {
        int n = recv(sock, ((unsigned char*)&net_len) + received, 4 - received, 0);
        if (n <= 0) return -1;
        received += n;
    }
    
    int len = ntohl(net_len);
    if (len > max_len) return -1;
    
    received = 0;
    while (received < len) {
        int n = recv(sock, buffer + received, len - received, 0);
        if (n <= 0) return -1;
        received += n;
    }
    return len;
}

/* ==================== PQC Certificate Verification ==================== */

int verify_pqc_certificate(const char *cert_pem, const char *ca_cert_pem,
                           char *subject_cn, unsigned char *public_key) {
    const char *begin = strstr(cert_pem, "-----BEGIN PQC CERTIFICATE-----");
    const char *end = strstr(cert_pem, "-----END PQC CERTIFICATE-----");
    if (!begin || !end) return -1;
    
    begin += strlen("-----BEGIN PQC CERTIFICATE-----");
    while (*begin == '\n' || *begin == '\r') begin++;
    
    size_t b64_len = end - begin;
    char *b64 = malloc(b64_len + 1);
    if (!b64) return -1;
    
    char *dst = b64;
    for (const char *src = begin; src < end; src++) {
        if (*src != '\n' && *src != '\r') *dst++ = *src;
    }
    *dst = '\0';
    
    size_t json_len;
    unsigned char *json_data = base64_decode(b64, &json_len);
    free(b64);
    if (!json_data) return -1;
    
    char *json = malloc(json_len + 1);
    memcpy(json, json_data, json_len);
    json[json_len] = '\0';
    free(json_data);
    
    char *cn = extract_json_string(json, "CN");
    if (cn) {
        strncpy(subject_cn, cn, MAX_CN_SIZE - 1);
        subject_cn[MAX_CN_SIZE - 1] = '\0';
        free(cn);
    } else {
        strcpy(subject_cn, "unknown");
    }
    
    char *key_b64 = extract_json_string(json, "key");
    if (key_b64) {
        size_t pk_len;
        unsigned char *pk_data = base64_decode(key_b64, &pk_len);
        free(key_b64);
        if (pk_data && pk_len == MLDSA65_PUBLIC_KEY_SIZE) {
            memcpy(public_key, pk_data, MLDSA65_PUBLIC_KEY_SIZE);
            free(pk_data);
        } else {
            free(pk_data);
            free(json);
            return -1;
        }
    }
    
    free(json);
    return 0;
}

/* ==================== Attestation ==================== */

char *get_attestation_report(const char *nonce, const unsigned char *kyber_pk) {
    wc_Sha256 sha;
    unsigned char hash[32];
    char hash_hex[65];
    
    wc_InitSha256(&sha);
    wc_Sha256Update(&sha, (unsigned char*)nonce, strlen(nonce));
    wc_Sha256Update(&sha, kyber_pk, KYBER768_PUBLIC_KEY_SIZE);
    wc_Sha256Final(&sha, hash);
    wc_Sha256Free(&sha);
    
    bytes_to_hex(hash, 32, hash_hex);
    
    char *report = malloc(128);
    sprintf(report, "attestation_report:%s", hash_hex);
    return report;
}

/* ==================== Controller Configuration Protocol ==================== */

int get_configuration_hybrid(const char *controller_host, int controller_port,
                             const char *repetitor_id, const char *repetitor_url,
                             repetitor_config_t *config) {
    char ts[32];
    get_timestamp(ts, sizeof(ts));
    
    /* Step 1: Generate ML-KEM keypair */
    fprintf(stderr, "[DEBUG] Generating ML-KEM-768 keypair...\n");
    unsigned char mlkem_pk[MLKEM768_PUBLIC_KEY_SIZE];
    unsigned char mlkem_sk[MLKEM768_SECRET_KEY_SIZE];
    
    if (pqc_mlkem_generate_keypair(mlkem_pk, mlkem_sk) != 0) {
        fprintf(stderr, "[ERROR] Failed to generate ML-KEM keypair\n");
        return -1;
    }
    fprintf(stderr, "[DEBUG] ML-KEM keypair generated successfully\n");
    
    /* Send to controller */
    char *mlkem_pk_b64 = base64_encode(mlkem_pk, MLKEM768_PUBLIC_KEY_SIZE);
    char *step1_body = malloc(4096);
    sprintf(step1_body,
            "{\"repetitor_id\":\"%s\",\"repetitor_url\":\"%s\",\"kyber_public_key\":\"%s\"}",
            repetitor_id, repetitor_url, mlkem_pk_b64);
    free(mlkem_pk_b64);
    
    fprintf(stderr, "[DEBUG] Sending ML-KEM public key to controller...\n");
    char *step1_resp = http_post(controller_host, controller_port, "/key_exchange_step1", step1_body);
    free(step1_body);
    
    if (!step1_resp) {
        fprintf(stderr, "[ERROR] Failed to contact controller at %s:%d\n", controller_host, controller_port);
        return -1;
    }
    
    /* Parse response */
    char *ctrl_pk_b64 = extract_json_string(step1_resp, "kyber_public_key");
    char *ctrl_ct_b64 = extract_json_string(step1_resp, "kyber_ciphertext");
    char *nonce = extract_json_string(step1_resp, "nonce");
    free(step1_resp);
    
    if (!ctrl_pk_b64 || !ctrl_ct_b64 || !nonce) {
        free(ctrl_pk_b64); free(ctrl_ct_b64); free(nonce);
        fprintf(stderr, "[ERROR] Invalid step1 response\n");
        return -1;
    }
    
    fprintf(stderr, "[DEBUG] Received controller's ML-KEM public key\n");
    fprintf(stderr, "[DEBUG] Nonce: %s\n", nonce);
    
    /* Decode controller's keys */
    size_t ctrl_pk_len, ctrl_ct_len;
    unsigned char *ctrl_pk = base64_decode(ctrl_pk_b64, &ctrl_pk_len);
    unsigned char *ctrl_ct = base64_decode(ctrl_ct_b64, &ctrl_ct_len);
    free(ctrl_pk_b64);
    free(ctrl_ct_b64);
    
    /* Step 2: Decapsulate and encapsulate */
    fprintf(stderr, "[DEBUG] Decapsulating controller's ciphertext...\n");
    unsigned char ss1[MLKEM768_SHARED_SECRET_SIZE];
    if (pqc_mlkem_decapsulate(mlkem_sk, ctrl_ct, ss1) != 0) {
        free(ctrl_pk); free(ctrl_ct); free(nonce);
        fprintf(stderr, "[ERROR] Decapsulation failed\n");
        return -1;
    }
    free(ctrl_ct);
    
    fprintf(stderr, "[DEBUG] Encapsulating to controller's public key...\n");
    unsigned char my_ct[MLKEM768_CIPHERTEXT_SIZE];
    unsigned char ss2[MLKEM768_SHARED_SECRET_SIZE];
    if (pqc_mlkem_encapsulate(ctrl_pk, my_ct, ss2) != 0) {
        free(ctrl_pk); free(nonce);
        fprintf(stderr, "[ERROR] Encapsulation failed\n");
        return -1;
    }
    free(ctrl_pk);
    
    /* Derive shared key */
    unsigned char shared_key[32];
    derive_shared_key(ss1, ss2, shared_key);
    fprintf(stderr, "[DEBUG] Derived shared key\n");
    
    /* Step 3: Send attestation */
    char *attestation_report = get_attestation_report(nonce, mlkem_pk);
    
    /* Compute commitment */
    wc_Sha256 sha;
    unsigned char commit_hash[32];
    char commit_hex[65];
    wc_InitSha256(&sha);
    wc_Sha256Update(&sha, mlkem_pk, MLKEM768_PUBLIC_KEY_SIZE);
    wc_Sha256Update(&sha, (unsigned char*)repetitor_id, strlen(repetitor_id));
    wc_Sha256Final(&sha, commit_hash);
    wc_Sha256Free(&sha);
    bytes_to_hex(commit_hash, 32, commit_hex);
    
    char *attestation_payload = malloc(512);
    sprintf(attestation_payload, "{\"attestation_report\":\"%s\",\"commitment\":\"%s\"}",
            attestation_report, commit_hex);
    free(attestation_report);
    
    char *encrypted_attestation = aes_encrypt_string(attestation_payload, shared_key);
    free(attestation_payload);
    
    char *my_ct_b64 = base64_encode(my_ct, MLKEM768_CIPHERTEXT_SIZE);
    char *step2_body = malloc(8192);
    sprintf(step2_body,
            "{\"repetitor_id\":\"%s\",\"kyber_ciphertext\":\"%s\",\"encrypted_payload\":\"%s\"}",
            repetitor_id, my_ct_b64, encrypted_attestation);
    free(my_ct_b64);
    free(encrypted_attestation);
    
    fprintf(stderr, "[DEBUG] Sending attestation...\n");
    char *step2_resp = http_post(controller_host, controller_port, "/key_exchange_step2", step2_body);
    free(step2_body);
    
    if (!step2_resp) {
        free(nonce);
        fprintf(stderr, "[ERROR] Step2 failed\n");
        return -1;
    }

    fprintf(stderr, "[ERROR] Step2 response: %s\n", step2_resp);
    
    /* Decrypt response */
    char *enc_resp = extract_json_string(step2_resp, "encrypted_response");
    free(step2_resp);
    
    char *ack_json = aes_decrypt_string(enc_resp, shared_key);
    free(enc_resp);
    
    char *status = extract_json_string(ack_json, "status");
    free(ack_json);
    
    if (!status || strcmp(status, "authenticated") != 0) {
        free(status); free(nonce);
        fprintf(stderr, "[ERROR] Authentication failed\n");
        return -1;
    }
    free(status);
    fprintf(stderr, "[DEBUG] Authenticated with controller\n");
    
    /* Step 4: Get configuration */
    fprintf(stderr, "[DEBUG] Requesting configuration...\n");
    char config_req[256];
    sprintf(config_req, "{\"repetitor_id\":\"%s\"}", repetitor_id);
    char *enc_config_req = aes_encrypt_string(config_req, shared_key);
    
    char *config_body = malloc(strlen(enc_config_req) + 64);
    sprintf(config_body, "{\"encrypted_payload\":\"%s\"}", enc_config_req);
    free(enc_config_req);
    
    char *config_resp = http_post(controller_host, controller_port, "/configuration", config_body);
    free(config_body);
    
    if (!config_resp) {
        free(nonce);
        fprintf(stderr, "[ERROR] Configuration request failed\n");
        return -1;
    }
    
    char *enc_config = extract_json_string(config_resp, "encrypted_response");
    free(config_resp);
    
    char *config_json = aes_decrypt_string(enc_config, shared_key);
    free(enc_config);
    
    fprintf(stderr, "[DEBUG] Received configuration\n");
    
    /* Parse configuration */
    config->left_repetitor_url = extract_json_string(config_json, "left_repetitor_url");
    config->right_repetitor_url = extract_json_string(config_json, "right_repetitor_url");
    config->left_repetitor_id = extract_json_string(config_json, "left_repetitor_id");
    config->right_repetitor_id = extract_json_string(config_json, "right_repetitor_id");
    config->left_kme = extract_json_string(config_json, "left_kme");
    config->right_kme = extract_json_string(config_json, "right_kme");
    config->left_cn = extract_json_string(config_json, "left_cn");
    config->right_cn = extract_json_string(config_json, "right_cn");
    config->left_kme_peer = extract_json_string(config_json, "left_kme_peer");
    config->right_kme_peer = extract_json_string(config_json, "right_kme_peer");
    config->whitelist = extract_json_string(config_json, "whitelist");
    
    char *pqc_ca = extract_json_string(config_json, "pqc_ca_certificate");
    if (pqc_ca) {
        g_pqc_ca_certificate = pqc_ca;
    }
    
    free(config_json);
    
    /* Step 5: Generate ML-DSA keys and request certificates */
    fprintf(stderr, "[DEBUG] Generating ML-DSA-65 keypair...\n");
    if (pqc_mldsa_generate_keypair(config->pqc_public_key, config->pqc_private_key) != 0) {
        free(nonce);
        fprintf(stderr, "[ERROR] Failed to generate ML-DSA keypair\n");
        return -1;
    }
    fprintf(stderr, "[DEBUG] ML-DSA keypair generated successfully\n");
    
    /* Request certificates */
    char *pqc_pk_b64 = base64_encode(config->pqc_public_key, MLDSA65_PUBLIC_KEY_SIZE);
    
    char *cert_req = malloc(MAX_JSON_SIZE);
    sprintf(cert_req,
            "{\"repetitor_id\":\"%s\","
            "\"pqc_csr\":{\"subject_cn\":\"%s\",\"public_key\":\"%s\"},"
            "\"left_rsa_csr\":\"\","
            "\"right_rsa_csr\":\"\"}",
            repetitor_id, repetitor_id, pqc_pk_b64);
    free(pqc_pk_b64);
    
    fprintf(stderr, "[DEBUG] Requesting certificates...\n");
    char *enc_cert_req = aes_encrypt_string(cert_req, shared_key);
    free(cert_req);
    
    char *cert_body = malloc(strlen(enc_cert_req) + 64);
    sprintf(cert_body, "{\"encrypted_payload\":\"%s\"}", enc_cert_req);
    free(enc_cert_req);
    
    char *cert_resp = http_post(controller_host, controller_port, "/generate_certificates", cert_body);
    free(cert_body);
    free(nonce);
    
    if (!cert_resp) {
        fprintf(stderr, "[ERROR] Certificate request failed\n");
        return -1;
    }
    
    char *enc_certs = extract_json_string(cert_resp, "encrypted_response");
    free(cert_resp);
    
    char *certs_json = aes_decrypt_string(enc_certs, shared_key);
    free(enc_certs);
    
    fprintf(stderr, "[DEBUG] Received certificates\n");
    
    config->pqc_certificate = extract_json_string(certs_json, "pqc_certificate");
    config->left_rsa_cert = extract_json_string(certs_json, "left_rsa_certificate");
    config->right_rsa_cert = extract_json_string(certs_json, "right_rsa_certificate");
    
    free(certs_json);
    
    return 0;
}


/* ==================== KME Communication (mTLS) ==================== */

char *kme_request(const unsigned char *key_der, int key_der_len,
                  const char *cert_pem, const char *ca_pem,
                  const char *kme_host, int kme_port,
                  const char *path) {
    /* Initialize WolfSSL */
    WOLFSSL_CTX *ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method());
    if (!ctx) return NULL;
    
    /* Load CA certificate */
    if (wolfSSL_CTX_load_verify_buffer(ctx, (unsigned char*)ca_pem, strlen(ca_pem),
                                        SSL_FILETYPE_PEM) != SSL_SUCCESS) {
        wolfSSL_CTX_free(ctx);
        return NULL;
    }
    
    /* Load client certificate */
    if (wolfSSL_CTX_use_certificate_buffer(ctx, (unsigned char*)cert_pem, strlen(cert_pem),
                                            SSL_FILETYPE_PEM) != SSL_SUCCESS) {
        wolfSSL_CTX_free(ctx);
        return NULL;
    }
    
    /* Load client private key */
    if (wolfSSL_CTX_use_PrivateKey_buffer(ctx, key_der, key_der_len,
                                           SSL_FILETYPE_ASN1) != SSL_SUCCESS) {
        wolfSSL_CTX_free(ctx);
        return NULL;
    }
    
    /* Connect */
    int sock = tcp_connect(kme_host, kme_port);
    if (sock < 0) {
        wolfSSL_CTX_free(ctx);
        return NULL;
    }
    
    WOLFSSL *ssl = wolfSSL_new(ctx);
    if (!ssl) {
        close(sock);
        wolfSSL_CTX_free(ctx);
        return NULL;
    }
    
    wolfSSL_set_fd(ssl, sock);
    
    /* SNI */
    wolfSSL_UseSNI(ssl, WOLFSSL_SNI_HOST_NAME, kme_host, strlen(kme_host));
    
    if (wolfSSL_connect(ssl) != SSL_SUCCESS) {
        wolfSSL_free(ssl);
        close(sock);
        wolfSSL_CTX_free(ctx);
        return NULL;
    }
    
    /* Send HTTP request */
    char request[1024];
    sprintf(request,
            "GET %s HTTP/1.1\r\n"
            "Host: %s\r\n"
            "Connection: close\r\n"
            "\r\n",
            path, kme_host);
    
    wolfSSL_write(ssl, request, strlen(request));
    
    /* Read response */
    char *response = malloc(MAX_HTTP_RESPONSE);
    int total = 0;
    int n;
    while ((n = wolfSSL_read(ssl, response + total, MAX_HTTP_RESPONSE - total - 1)) > 0) {
        total += n;
    }
    response[total] = '\0';
    
    wolfSSL_shutdown(ssl);
    wolfSSL_free(ssl);
    close(sock);
    wolfSSL_CTX_free(ctx);
    
    /* Find body */
    char *body = strstr(response, "\r\n\r\n");
    if (!body) { free(response); return NULL; }
    body += 4;
    
    char *result = strdup(body);
    free(response);
    return result;
}

char *kme_get_key(const unsigned char *key_der, int key_der_len,
                  const char *cert, const char *ca,
                  const char *kme_host, const char *kme_peer) {
    char path[512];
    sprintf(path, "/api/v1/keys/%s/enc_keys", kme_peer);
    return kme_request(key_der, key_der_len, cert, ca, kme_host, 443, path);
}

char *kme_get_key_with_id(const unsigned char *key_der, int key_der_len,
                          const char *cert, const char *ca,
                          const char *kme_host, const char *kme_peer,
                          const char *key_id) {
    char path[512];
    sprintf(path, "/api/v1/keys/%s/dec_keys?key_ID=%s", kme_peer, key_id);
    return kme_request(key_der, key_der_len, cert, ca, kme_host, 443, path);
}

/* ==================== QKD Encryption/Decryption ==================== */

void derive_qkd_keys(const unsigned char *master_key, int key_len,
                     unsigned char *aes_key, unsigned char *hmac_key) {
    wc_Sha256 sha;
    wc_InitSha256(&sha);
    wc_Sha256Update(&sha, master_key, key_len);
    wc_Sha256Final(&sha, aes_key);
    wc_Sha256Free(&sha);
    
    wc_InitSha256(&sha);
    wc_Sha256Update(&sha, master_key, key_len);
    wc_Sha256Update(&sha, (unsigned char*)"Mac", 3);
    wc_Sha256Final(&sha, hmac_key);
    wc_Sha256Free(&sha);
}

int decode_qkd_key(const char *text, unsigned char *key, int max_len) {
    size_t len = strlen(text);
    int is_hex = 1;
    for (size_t i = 0; i < len && is_hex; i++) {
        if (!isxdigit(text[i])) is_hex = 0;
    }
    
    if (is_hex && len % 2 == 0 && len <= 128) {
        return hex_to_bytes(text, key, max_len);
    } else {
        size_t dec_len;
        unsigned char *dec = base64_decode(text, &dec_len);
        if (!dec || (int)dec_len > max_len) { free(dec); return -1; }
        memcpy(key, dec, dec_len);
        free(dec);
        return (int)dec_len;
    }
}

char *qkd_encrypt(const char *plaintext, const char *key_text) {
    unsigned char master_key[64];
    int key_len = decode_qkd_key(key_text, master_key, sizeof(master_key));
    if (key_len < 0) return NULL;
    
    unsigned char aes_key[32], hmac_key[32];
    derive_qkd_keys(master_key, key_len, aes_key, hmac_key);
    
    unsigned char iv[16];
    random_bytes(iv, 16);
    char iv_hex[33];
    bytes_to_hex(iv, 16, iv_hex);
    
    int pt_len = strlen(plaintext);
    int padded_len = pt_len + (16 - (pt_len % 16));
    unsigned char *padded = calloc(padded_len, 1);
    memcpy(padded, plaintext, pt_len);
    pkcs7_pad(padded, pt_len, 16);
    
    unsigned char *ciphertext = malloc(padded_len);
    Aes aes;
    wc_AesInit(&aes, NULL, INVALID_DEVID);
    wc_AesSetKey(&aes, aes_key, 32, iv, AES_ENCRYPTION);
    wc_AesCbcEncrypt(&aes, ciphertext, padded, padded_len);
    wc_AesFree(&aes);
    free(padded);
    
    char *ct_b64 = base64_encode(ciphertext, padded_len);
    free(ciphertext);
    
    unsigned char tag[32];
    Hmac hmac;
    wc_HmacInit(&hmac, NULL, INVALID_DEVID);
    wc_HmacSetKey(&hmac, WC_SHA256, hmac_key, 32);
    wc_HmacUpdate(&hmac, (unsigned char*)ct_b64, strlen(ct_b64));
    wc_HmacFinal(&hmac, tag);
    wc_HmacFree(&hmac);
    
    char tag_hex[65];
    bytes_to_hex(tag, 32, tag_hex);
    
    char *blob = malloc(strlen(iv_hex) + strlen(ct_b64) + strlen(tag_hex) + 1);
    sprintf(blob, "%s%s%s", iv_hex, ct_b64, tag_hex);
    free(ct_b64);
    
    char *result = base64_encode((unsigned char*)blob, strlen(blob));
    free(blob);
    return result;
}

char *qkd_decrypt(const char *blob_b64, const char *key_text) {
    unsigned char master_key[64];
    int key_len = decode_qkd_key(key_text, master_key, sizeof(master_key));
    if (key_len < 0) return NULL;
    
    unsigned char aes_key[32], hmac_key[32];
    derive_qkd_keys(master_key, key_len, aes_key, hmac_key);
    
    size_t blob_len;
    unsigned char *blob_raw = base64_decode(blob_b64, &blob_len);
    if (!blob_raw) return NULL;
    
    char *blob = malloc(blob_len + 1);
    memcpy(blob, blob_raw, blob_len);
    blob[blob_len] = '\0';
    free(blob_raw);
    
    if (blob_len < 96) { free(blob); return NULL; }
    
    char iv_hex[33], tag_hex[65];
    strncpy(iv_hex, blob, 32); iv_hex[32] = '\0';
    strncpy(tag_hex, blob + blob_len - 64, 64); tag_hex[64] = '\0';
    
    size_t ct_b64_len = blob_len - 96;
    char *ct_b64 = malloc(ct_b64_len + 1);
    strncpy(ct_b64, blob + 32, ct_b64_len);
    ct_b64[ct_b64_len] = '\0';
    free(blob);
    
    /* Verify HMAC */
    unsigned char calc_tag[32];
    Hmac hmac;
    wc_HmacInit(&hmac, NULL, INVALID_DEVID);
    wc_HmacSetKey(&hmac, WC_SHA256, hmac_key, 32);
    wc_HmacUpdate(&hmac, (unsigned char*)ct_b64, ct_b64_len);
    wc_HmacFinal(&hmac, calc_tag);
    wc_HmacFree(&hmac);
    
    char calc_tag_hex[65];
    bytes_to_hex(calc_tag, 32, calc_tag_hex);
    
    if (strcasecmp(calc_tag_hex, tag_hex) != 0) {
        fprintf(stderr, "[ERROR] HMAC mismatch\n");
        free(ct_b64);
        return NULL;
    }
    
    unsigned char iv[16];
    hex_to_bytes(iv_hex, iv, 16);
    
    size_t ct_len;
    unsigned char *ciphertext = base64_decode(ct_b64, &ct_len);
    free(ct_b64);
    if (!ciphertext) return NULL;
    
    unsigned char *plaintext = malloc(ct_len + 1);
    Aes aes;
    wc_AesInit(&aes, NULL, INVALID_DEVID);
    wc_AesSetKey(&aes, aes_key, 32, iv, AES_DECRYPTION);
    wc_AesCbcDecrypt(&aes, plaintext, ciphertext, ct_len);
    wc_AesFree(&aes);
    free(ciphertext);
    
    int unpadded = pkcs7_unpad(plaintext, ct_len);
    if (unpadded < 0) { free(plaintext); return NULL; }
    
    plaintext[unpadded] = '\0';
    return (char*)plaintext;
}

/* ==================== PQC Channel Protocol ==================== */

int pqc_server_handshake(int sock, const unsigned char *my_sk,
                         const char *my_cert, const char *ca_cert,
                         const char *whitelist, unsigned char *session_key, char *peer_cn) {
    unsigned char mlkem_pk[MLKEM768_PUBLIC_KEY_SIZE];
    unsigned char mlkem_sk[MLKEM768_SECRET_KEY_SIZE];
    unsigned char signature[MLDSA65_SIGNATURE_SIZE];
    int sig_len;
    
    if (pqc_mlkem_generate_keypair(mlkem_pk, mlkem_sk) != 0) return -1;
    if (pqc_mldsa_sign(my_sk, mlkem_pk, MLKEM768_PUBLIC_KEY_SIZE, signature, &sig_len) != 0) return -1;
    
    char *pk_b64 = base64_encode(mlkem_pk, MLKEM768_PUBLIC_KEY_SIZE);
    char *sig_b64 = base64_encode(signature, sig_len);
    char *cert_escaped = certificate_json_escape(my_cert);
    
    char *hello = malloc(MAX_JSON_SIZE);
    sprintf(hello, "{\"kyber_pk\":\"%s\",\"certificate\":\"%s\",\"signature\":\"%s\"}",
            pk_b64, cert_escaped ? cert_escaped : "", sig_b64);
    free(pk_b64); free(sig_b64); free(cert_escaped);
    
    if (send_length_prefixed(sock, (unsigned char*)hello, strlen(hello)) != 0) {
        free(hello); return -1;
    }
    free(hello);
    
    unsigned char *client_hello = malloc(MAX_JSON_SIZE);
    int len = recv_length_prefixed(sock, client_hello, MAX_JSON_SIZE - 1);
    if (len <= 0) { free(client_hello); return -1; }
    client_hello[len] = '\0';
    
    char *ct_b64 = extract_json_string((char*)client_hello, "kyber_ciphertext");
    char *client_cert = extract_json_string((char*)client_hello, "certificate");
    free(client_hello);
    
    if (!ct_b64) { free(ct_b64); free(client_cert); return -1; }
    
    unsigned char peer_pk[MLDSA65_PUBLIC_KEY_SIZE];
    if (client_cert && ca_cert && strlen(client_cert) > 0) {
        if (verify_pqc_certificate(client_cert, ca_cert, peer_cn, peer_pk) != 0) {
            free(ct_b64); free(client_cert);
            return -1;
        }
        if (whitelist && strlen(whitelist) > 0 && !strstr(whitelist, peer_cn)) {
            free(ct_b64); free(client_cert);
            return -1;
        }
    } else {
        strcpy(peer_cn, "unknown");
    }
    free(client_cert);
    
    size_t ct_len;
    unsigned char *mlkem_ct = base64_decode(ct_b64, &ct_len);
    free(ct_b64);
    
    unsigned char ss[MLKEM768_SHARED_SECRET_SIZE];
    if (pqc_mlkem_decapsulate(mlkem_sk, mlkem_ct, ss) != 0) { free(mlkem_ct); return -1; }
    free(mlkem_ct);
    
    derive_session_key(ss, session_key);
    return 0;
}

int pqc_client_handshake(int sock, const unsigned char *my_sk,
                         const char *my_cert, const char *ca_cert,
                         unsigned char *session_key, char *peer_cn) {
    unsigned char *server_hello = malloc(MAX_JSON_SIZE);
    int len = recv_length_prefixed(sock, server_hello, MAX_JSON_SIZE - 1);
    if (len <= 0) { free(server_hello); return -1; }
    server_hello[len] = '\0';
    
    char *pk_b64 = extract_json_string((char*)server_hello, "kyber_pk");
    char *server_cert = extract_json_string((char*)server_hello, "certificate");
    free(server_hello);
    
    if (!pk_b64) { free(pk_b64); free(server_cert); return -1; }
    
    size_t pk_len;
    unsigned char *server_pk = base64_decode(pk_b64, &pk_len);
    free(pk_b64);
    
    if (!server_pk || pk_len != MLKEM768_PUBLIC_KEY_SIZE) {
        free(server_pk); free(server_cert); return -1;
    }
    
    unsigned char peer_pk[MLDSA65_PUBLIC_KEY_SIZE];
    if (server_cert && ca_cert && strlen(server_cert) > 0) {
        if (verify_pqc_certificate(server_cert, ca_cert, peer_cn, peer_pk) != 0) {
            free(server_pk); free(server_cert); return -1;
        }
    } else {
        strcpy(peer_cn, "unknown");
    }
    free(server_cert);
    
    unsigned char ct[MLKEM768_CIPHERTEXT_SIZE];
    unsigned char ss[MLKEM768_SHARED_SECRET_SIZE];
    if (pqc_mlkem_encapsulate(server_pk, ct, ss) != 0) { free(server_pk); return -1; }
    free(server_pk);
    
    unsigned char signature[MLDSA65_SIGNATURE_SIZE];
    int sig_len;
    if (pqc_mldsa_sign(my_sk, ct, MLKEM768_CIPHERTEXT_SIZE, signature, &sig_len) != 0) return -1;
    
    char *ct_b64 = base64_encode(ct, MLKEM768_CIPHERTEXT_SIZE);
    char *sig_b64 = base64_encode(signature, sig_len);
    
    char *hello = malloc(MAX_JSON_SIZE);
    char *cert_escaped = certificate_json_escape(my_cert);
    sprintf(hello, "{\"kyber_ciphertext\":\"%s\",\"certificate\":\"%s\",\"signature\":\"%s\"}",
            ct_b64, cert_escaped ? cert_escaped : "", sig_b64);
    free(ct_b64); free(sig_b64); free(cert_escaped);

    int ret = send_length_prefixed(sock, (unsigned char*)hello, strlen(hello));
    free(hello);
    if (ret != 0) return -1;
    
    derive_session_key(ss, session_key);
    return 0;
}

int pqc_send_message(const char *host, int port, const unsigned char *my_sk,
                     const char *my_cert, const char *ca_cert,
                     const char *msg_json, const char *rep_id) {
    char ts[32];
    get_timestamp(ts, sizeof(ts));
    
    int sock = tcp_connect(host, port);
    if (sock < 0) return -1;
    
    unsigned char session_key[32];
    char peer_cn[MAX_CN_SIZE];
    
    if (pqc_client_handshake(sock, my_sk, my_cert, ca_cert, session_key, peer_cn) != 0) {
        close(sock); return -1;
    }
    
    get_timestamp(ts, sizeof(ts));
    fprintf(stderr, "[%s][%s] PQC connected to %s\n", ts, rep_id, peer_cn);
    
    int msg_len = strlen(msg_json);
    unsigned char *enc = malloc(msg_len + 64);
    int enc_len;
    if (aes_encrypt_bytes((unsigned char*)msg_json, msg_len, session_key, enc, &enc_len) != 0) {
        free(enc); close(sock); return -1;
    }
    
    if (send_length_prefixed(sock, enc, enc_len) != 0) {
        free(enc); close(sock); return -1;
    }
    free(enc);
    
    unsigned char ack_buf[256];
    int ack_len = recv_length_prefixed(sock, ack_buf, sizeof(ack_buf));
    if (ack_len > 0) {
        unsigned char ack[128];
        int dec_len;
        if (aes_decrypt_bytes(ack_buf, ack_len, session_key, ack, &dec_len) == 0) {
            ack[dec_len] = '\0';
            get_timestamp(ts, sizeof(ts));
            fprintf(stderr, "[%s][%s] Ack: %s\n", ts, rep_id, ack);
        }
    }
    
    close(sock);
    return 0;
}

pqc_message_t pqc_receive_message(int port, const unsigned char *my_sk,
                                  const char *my_cert, const char *ca_cert,
                                  const char *whitelist, const char *rep_id) {
    pqc_message_t result = {NULL, NULL};
    char ts[32];
    
    int server = socket(AF_INET, SOCK_STREAM, 0);
    if (server < 0) return result;
    
    int opt = 1;
    setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    
    if (bind(server, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(server); return result;
    }
    if (listen(server, 5) < 0) { close(server); return result; }
    
    get_timestamp(ts, sizeof(ts));
    fprintf(stderr, "[%s][%s] Listening on port %d\n", ts, rep_id, port);
    
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    int client = accept(server, (struct sockaddr*)&client_addr, &client_len);
    if (client < 0) { close(server); return result; }
    
    get_timestamp(ts, sizeof(ts));
    fprintf(stderr, "[%s][%s] Connection from %s\n", ts, rep_id, inet_ntoa(client_addr.sin_addr));
    
    unsigned char session_key[32];
    char peer_cn[MAX_CN_SIZE];
    
    if (pqc_server_handshake(client, my_sk, my_cert, ca_cert, whitelist, session_key, peer_cn) != 0) {
        close(client); close(server); return result;
    }
    
    get_timestamp(ts, sizeof(ts));
    fprintf(stderr, "[%s][%s] PQC from %s\n", ts, rep_id, peer_cn);
    
    unsigned char *enc = malloc(MAX_BUFFER_SIZE);
    int enc_len = recv_length_prefixed(client, enc, MAX_BUFFER_SIZE);
    if (enc_len <= 0) { free(enc); close(client); close(server); return result; }
    
    unsigned char *dec = malloc(enc_len);
    int dec_len;
    if (aes_decrypt_bytes(enc, enc_len, session_key, dec, &dec_len) != 0) {
        free(enc); free(dec); close(client); close(server); return result;
    }
    free(enc);
    dec[dec_len] = '\0';
    
    unsigned char ack_enc[128];
    int ack_enc_len;
    aes_encrypt_bytes((unsigned char*)"RECEIVED", 8, session_key, ack_enc, &ack_enc_len);
    send_length_prefixed(client, ack_enc, ack_enc_len);
    
    close(client);
    close(server);
    
    result.message = (char*)dec;
    result.sender_cn = strdup(peer_cn);
    return result;
}

/* ==================== Cleanup ==================== */

void free_config(repetitor_config_t *c) {
    if (!c) return;
    free(c->left_repetitor_url); free(c->right_repetitor_url);
    free(c->left_repetitor_id); free(c->right_repetitor_id);
    free(c->left_kme); free(c->right_kme);
    free(c->left_cn); free(c->right_cn);
    free(c->left_kme_peer); free(c->right_kme_peer);
    free(c->whitelist); free(c->pqc_certificate);
    free(c->left_rsa_key_der); free(c->left_rsa_cert);
    free(c->right_rsa_key_der); free(c->right_rsa_cert);
    free(c);
}

/* ==================== Main ==================== */

int main(int argc, char *argv[]) {
    char *repetitor_id = "DR1";
    int port = 9001;
    
    if (argc >= 3) {
        repetitor_id = argv[1];
        port = atoi(argv[2]);
    }
    
    char ts[32];
    fprintf(stderr, "========================================\n");
    fprintf(stderr, "QKD Relay Repetitor (Hybrid PQC/RSA)\n");
    fprintf(stderr, "Repetitor ID: %s, Port: %d\n", repetitor_id, port);
    fprintf(stderr, "========================================\n");
    
    wolfSSL_Init();
    if (init_rng() != 0) { fprintf(stderr, "RNG init failed\n"); return 1; }
    
    repetitor_config_t *config = calloc(1, sizeof(repetitor_config_t));
    if (!config) { cleanup_rng(); wolfSSL_Cleanup(); return 1; }
    
    /* Get configuration from controller */
    char rep_url[64];
    sprintf(rep_url, "127.0.0.1:%d", port);
    
    if (get_configuration_hybrid(CONTROLLER_HOST, atoi(CONTROLLER_PORT),
                                  repetitor_id, rep_url, config) != 0) {
        fprintf(stderr, "[ERROR] Failed to get configuration\n");
        free_config(config);
        cleanup_rng();
        wolfSSL_Cleanup();
        return 1;
    }
    
    get_timestamp(ts, sizeof(ts));
    fprintf(stderr, "[%s][%s] Configuration received\n", ts, repetitor_id);
    fprintf(stderr, "[%s][%s] Left: %s (%s)\n", ts, repetitor_id,
            config->left_repetitor_id ? config->left_repetitor_id : "none",
            config->left_repetitor_url ? config->left_repetitor_url : "");
    fprintf(stderr, "[%s][%s] Right: %s (%s)\n", ts, repetitor_id,
            config->right_repetitor_id ? config->right_repetitor_id : "none",
            config->right_repetitor_url ? config->right_repetitor_url : "");
    
    signal(SIGINT, handle_sigint);
    
    get_timestamp(ts, sizeof(ts));
    fprintf(stderr, "[%s][%s] Ready - entering relay loop\n", ts, repetitor_id);
    
    while (keep_running) {
        pqc_message_t msg = pqc_receive_message(port, config->pqc_private_key,
                                                 config->pqc_certificate, g_pqc_ca_certificate,
                                                 config->whitelist, repetitor_id);
        
        if (!msg.message || !msg.sender_cn) {
            free(msg.message); free(msg.sender_cn);
            continue;
        }
        
        get_timestamp(ts, sizeof(ts));
        fprintf(stderr, "[%s][%s] From %s\n", ts, repetitor_id, msg.sender_cn);
        
        char *from_ct = extract_json_string(msg.message, "message");
        char *from_key_id = extract_json_string(msg.message, "key_ID");
        
        int is_from_left = config->left_repetitor_id &&
                           strcmp(msg.sender_cn, config->left_repetitor_id) == 0;
        
        /* KME info */
        const char *kme_dec = is_from_left ? config->left_kme : config->right_kme;
        const char *kme_dec_peer = is_from_left ? config->left_kme_peer : config->right_kme_peer;
        unsigned char *kme_dec_key = is_from_left ? config->left_rsa_key_der : config->right_rsa_key_der;
        int kme_dec_key_len = is_from_left ? config->left_rsa_key_der_len : config->right_rsa_key_der_len;
        const char *kme_dec_cert = is_from_left ? config->left_rsa_cert : config->right_rsa_cert;
        
        const char *kme_enc = is_from_left ? config->right_kme : config->left_kme;
        const char *kme_enc_peer = is_from_left ? config->right_kme_peer : config->left_kme_peer;
        unsigned char *kme_enc_key = is_from_left ? config->right_rsa_key_der : config->left_rsa_key_der;
        int kme_enc_key_len = is_from_left ? config->right_rsa_key_der_len : config->left_rsa_key_der_len;
        const char *kme_enc_cert = is_from_left ? config->right_rsa_cert : config->left_rsa_cert;
        
        const char *to_url = is_from_left ? config->right_repetitor_url : config->left_repetitor_url;
        
        char *plaintext = NULL;
        
        /* Decrypt with KME key */
        if (kme_dec && strlen(kme_dec) > 0 && kme_dec_key && from_key_id && strlen(from_key_id) > 0) {
            fprintf(stderr, "[%s][%s] Getting key from KME %s...\n", ts, repetitor_id, kme_dec);
            char *key_resp = kme_get_key_with_id(kme_dec_key, kme_dec_key_len,
                                                  kme_dec_cert, QKD_CA_CERTIFICATE,
                                                  kme_dec, kme_dec_peer, from_key_id);
            if (key_resp) {
                /* Parse key from response - find first "key" field */
                char *key_val = extract_json_string(key_resp, "key");
                if (key_val) {
                    fprintf(stderr, "[%s][%s] Decrypting with QKD key...\n", ts, repetitor_id);
                    plaintext = qkd_decrypt(from_ct, key_val);
                    free(key_val);
                }
                free(key_resp);
            }
        }
        
        if (!plaintext) plaintext = from_ct ? strdup(from_ct) : strdup("");
        
        get_timestamp(ts, sizeof(ts));
        fprintf(stderr, "[%s][%s] Plaintext: %.50s...\n", ts, repetitor_id, plaintext);
        
        char *to_ct = NULL;
        char *to_key_id = NULL;
        
        /* Encrypt with KME key */
        if (kme_enc && strlen(kme_enc) > 0 && kme_enc_key) {
            fprintf(stderr, "[%s][%s] Getting key from KME %s...\n", ts, repetitor_id, kme_enc);
            char *key_resp = kme_get_key(kme_enc_key, kme_enc_key_len,
                                          kme_enc_cert, QKD_CA_CERTIFICATE,
                                          kme_enc, kme_enc_peer);
            if (key_resp) {
                char *key_val = extract_json_string(key_resp, "key");
                to_key_id = extract_json_string(key_resp, "key_ID");
                if (key_val) {
                    fprintf(stderr, "[%s][%s] Encrypting with QKD key...\n", ts, repetitor_id);
                    to_ct = qkd_encrypt(plaintext, key_val);
                    free(key_val);
                }
                free(key_resp);
            }
        }
        
        if (!to_ct) to_ct = strdup(plaintext);
        if (!to_key_id) to_key_id = strdup("");
        
        free(plaintext);
        free(from_ct);
        free(from_key_id);
        
        /* Forward */
        char to_msg[MAX_BUFFER_SIZE];
        snprintf(to_msg, sizeof(to_msg), "{\"message\":\"%s\",\"key_ID\":\"%s\"}", to_ct, to_key_id);
        free(to_ct);
        free(to_key_id);
        
        char to_host[128];
        int to_port;
        parse_url(to_url, to_host, &to_port);
        
        get_timestamp(ts, sizeof(ts));
        fprintf(stderr, "[%s][%s] Forwarding to %s...\n", ts, repetitor_id, to_url);
        
        int ret = pqc_send_message(to_host, to_port, config->pqc_private_key,
                                    config->pqc_certificate, g_pqc_ca_certificate,
                                    to_msg, repetitor_id);
        
        get_timestamp(ts, sizeof(ts));
        fprintf(stderr, "[%s][%s] %s\n", ts, repetitor_id,
                ret == 0 ? "Forwarded OK" : "Forward FAILED");
        
        free(msg.message);
        free(msg.sender_cn);
    }
    
    free_config(config);
    free(g_pqc_ca_certificate);
    cleanup_rng();
    wolfSSL_Cleanup();
    
    fprintf(stderr, "Shutdown complete\n");
    return 0;
}
