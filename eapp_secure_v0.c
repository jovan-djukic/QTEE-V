#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/coding.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>

/* Define WOLFSSL_LOAD_FLAG_DATE_ERR_OKAY if not defined */
/* This flag tells WolfSSL to ignore certificate date validation errors */
/* Needed for VMs/enclaves with incorrect system clocks */
#ifndef WOLFSSL_LOAD_FLAG_DATE_ERR_OKAY
#define WOLFSSL_LOAD_FLAG_DATE_ERR_OKAY 0x00000001
#endif

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

const char *REPETITOR_CA_CERTIFICATE = "-----BEGIN CERTIFICATE-----\n"
"MIIDrzCCApegAwIBAgIUXeRoaA0s2FWtqv9KV6xjUPLMHgkwDQYJKoZIhvcNAQEL\n"
"BQAwXjELMAkGA1UEBhMCUlMxCzAJBgNVBAgTAlJTMREwDwYDVQQHEwhCZWxncmFk\n"
"ZTEMMAoGA1UEChMDRVRGMQwwCgYDVQQLEwNSVEkxEzARBgNVBAMTCk15IFJvb3Qg\n"
"Q0EwHhcNMjUwOTA2MTAyNzAwWhcNMzAwOTA1MTAyNzAwWjBeMQswCQYDVQQGEwJS\n"
"UzELMAkGA1UECBMCUlMxETAPBgNVBAcTCEJlbGdyYWRlMQwwCgYDVQQKEwNFVEYx\n"
"DDAKBgNVBAsTA1JUSTETMBEGA1UEAxMKTXkgUm9vdCBDQTCCASIwDQYJKoZIhvcN\n"
"AQEBBQADggEPADCCAQoCggEBANtfOpPGqxY8mkRxlNMRQn6wVQ0aUeO9zjLANhZ9\n"
"bG81fV1uP9i5pJ/wgUEx2B3b1kj0nD/a51xp++Y+/12y52ZbGPpYBOJu5cb5aFTw\n"
"J95OB+ri8c1uqFwRA2mxrSRUgrlRuZKsbPLnZeNC/2t5anR37GncsZWgWppgJ8nO\n"
"UXXymXy2QK1k2hMAhO4uIGVmzG8eHvpCMEMMj+9hlhE2y8jId0GyHA2EWyuQNOe3\n"
"T7go91MotJY+/uPsEY8uSajRrN/fUcXqQrBysZDMbPiHlvaG/NyVGI+vQBPEULNE\n"
"ebG/47G79h542xwpflz6H9VOpboXjBgzgyvzLuGlJzSL+20CAwEAAaNlMGMwDgYD\n"
"VR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFIS8fn+Ob/PH\n"
"pPC5AIgKR7GWKOJFMCEGA1UdEQQaMBiHBH8AAAGHEAAAAAAAAAAAAAAAAAAAAAEw\n"
"DQYJKoZIhvcNAQELBQADggEBAHmXsmyq+KJTm2/+lXoZnpB/fM16T9dqypQdzIme\n"
"K0PcrNzcJzxF4dxi7IJWr97ICRJfSqKppUVLBWGVYXau6Prtbf+dXs9KM0Juzo9a\n"
"GYD3tNfdlAmI4ZSMt4H/EwaCO5MiXMSwvtg6qMpWjDXjJOvTIyDdWIe0JE+Soz2T\n"
"cGr1d8RyvYUAL0whxbAqAVAKBe9c4MTm1rlS5hMrpTVTSmI+HKPJyzZvvoiemzZg\n"
"Aw8+YxNOFwljTCl4ZCi5/PME9utT3IWqQUhrGwa4LMduRaieSnjIstNurvNsOBnd\n"
"tGAHFnSILfyZq0Z4vpnMhr4D6UmLvsis0W/lBAMkVlSJvKQ=\n"
"-----END CERTIFICATE-----";

const char *CONTROLLER_HOST                = "192.168.100.2";
const char *CONTROLLER_PORT                = "8000";
const char *CONTROLLER_GET_NONCE_PATH      = "/get_nonce";
const char *CONTROLLER_REGISTER_PATH       = "/register";
const char *CONTROLLER_CONFIGURATION_PATH  = "/configuration";

const char *KME_PORT = "443";

static volatile int keep_running = 1;

/* ========== Data Structures ========== */

typedef struct {
    char *ca_url_host;
    char *ca_url_port;
    char *ca_url_path;
    char *left_repetitor_url;
    char *right_repetitor_url;
    char *left_repetitor_id;
    char *right_repetitor_id;
    char *left_kme;
    char *right_kme;
    char *left_kme_url;
    char *right_kme_url;
    char *left_cn;
    char *right_cn;
    char *left_kme_peer;
    char *right_kme_peer;
    char *whitelist;
} repetitor_configuration_t;

typedef struct {
    char *message;
    char *subject;
} message_t;

/* Key pair stored as PEM strings */
typedef struct {
    char *private_key_pem;
    char *certificate_pem;
} key_pair_t;

/* Global RNG */
static WC_RNG g_rng;
static int g_rng_initialized = 0;

void handle_sigint ( int signal ) {
    ( void ) signal;
    keep_running = 0;
}


/* ========== RNG Functions ========== */

static int init_rng ( ) {
    if ( !g_rng_initialized ) {
        if ( wc_InitRng ( &g_rng ) != 0 ) {
            return -1;
        }
        g_rng_initialized = 1;
    }
    return 0;
}

static void cleanup_rng ( ) {
    if (g_rng_initialized) {
        wc_FreeRng(&g_rng);
        g_rng_initialized = 0;
    }
}

static int random_bytes ( unsigned char *buffer, int length ) {
    if ( init_rng ( ) != 0 ) {
        return -1;
    }

    return wc_RNG_GenerateBlock ( &g_rng, buffer, length );
}

/* ========== Utility Functions ========== */

char* get_last_line ( char* text ) {
    if (text == NULL || *text == '\0') {
        return NULL;
    }
    const char* last_newline = strrchr ( text, '\n' );
    if (last_newline == NULL) {
        return strdup ( text );
    }

    return strdup ( last_newline + 1 );
}

char *extract_field_from_json ( const char *json, const char *field ) {
    size_t field_length = strlen ( field );
    char pattern[256] = {0};

    if ( field_length + 3 >= sizeof ( pattern ) ) {
        return NULL;
    }

    pattern[0] = '"';
    memcpy ( pattern + 1, field, field_length );
    pattern[field_length + 1] = '"';
    pattern[field_length + 2] = '\0';

    const char *position = strstr ( json, pattern );
    if ( position == NULL ) {
        return NULL;
    }

    position += field_length + 2;

    while ( *position == ' ' || *position == '\t' ) {
        ++position;
    }

    if ( *position != ':' ) {
        return NULL;
    }
    ++position;

    while ( *position == ' ' || *position == '\t' ) {
        ++position;
    }

    if (  *position != '"' ) {
        return NULL;
    }
    ++position;

    char *result = malloc ( strlen ( json ) + 1 );
    if ( result == NULL ) {
        return NULL;
    }

    char *current = result;
    for ( ; ; ++position) {
        if ( *position == '\0' ) { free ( result ); return NULL; }
        if ( *position == '"' )  { break; }

        if ( *position == '\\' && *(position + 1) == 'n' ) { *current++ = '\n'; ++position; }
        else if ( *position == '\\' && *(position + 1) == '"' ) { *current++ = '"';  ++position; }
        else { *current++ = *position; }
    }

    *current = '\0';
    return result;
}

char* extract_http_body ( const char *response, long response_length, long *body_length ) {
    if ( response == NULL || response_length <= 0 ) {
        return NULL;
    }
    
    const char *body_start = NULL;
    for ( long i = 0; i < response_length - 3; ++i ) {
        if ( response[i] == '\r' && response[i+1] == '\n' && response[i+2] == '\r' && response[i+3] == '\n' ) {
            body_start = response + i + 4;
            break;
        }
    }
    
    if ( body_start == NULL ) {
        return NULL;
    }
    
    long length = response_length - ( body_start - response );
    if ( length <= 0 ) {
        return NULL;
    }
    
    char *body = malloc ( length + 1 );
    if ( body == NULL ) {
        return NULL;
    }
    
    memcpy ( body, body_start, length );
    body[length] = '\0';
    
    if ( body_length != NULL ) {
        *body_length = length;
    }
    
    return body;
}

char* get_ip_address ( const char *url ) {
    const char *colon = strchr ( url, ':' );
    size_t length = colon ? ( size_t ) ( colon - url ) : strlen ( url );
    
    char *ip = malloc ( length + 1 );
    if ( ip == NULL ) {
        return NULL;
    }
    
    memcpy ( ip, url, length );
    ip[length] = '\0';
    
    return ip;
}

char* get_port ( const char *url ) {
    const char *colon = strchr ( url, ':' );
    if ( colon == NULL ) {
        return strdup ( KME_PORT );
    }

    return strdup ( colon + 1 );
}

void bytes_to_hex ( const unsigned char *bytes, size_t length, char *hex ) {
    static const char *hex_map = "0123456789abcdef";
    for ( size_t i = 0; i < length; ++i ) {
        hex[i * 2]     = hex_map[bytes[i] >> 4];
        hex[i * 2 + 1] = hex_map[bytes[i] & 0x0F];
    }

    hex[length * 2] = '\0';
}

unsigned char* hex_to_binary ( const char *hex, size_t *output_length ) {
    size_t hex_length = strlen ( hex );
    if ( hex_length % 2 != 0 ) {
        return NULL;
    }

    unsigned char *buffer = malloc(hex_length / 2);
    if (buffer == NULL) {
        return NULL;
    }

    for (size_t i = 0; i < hex_length / 2; ++i) {
        if (sscanf(hex + i * 2, "%2hhx", &buffer[i]) != 1) {
            free(buffer);
            return NULL;
        }
    }

    *output_length = hex_length / 2;
    return buffer;
}

#define SYSCALL(which, arg0, arg1, arg2, arg3, arg4)           \
  ({                                                           \
    register uintptr_t a0 asm("a0") = (uintptr_t)(arg0);       \
    register uintptr_t a1 asm("a1") = (uintptr_t)(arg1);       \
    register uintptr_t a2 asm("a2") = (uintptr_t)(arg2);       \
    register uintptr_t a3 asm("a3") = (uintptr_t)(arg3);       \
    register uintptr_t a4 asm("a4") = (uintptr_t)(arg4);       \
    register uintptr_t a7 asm("a7") = (uintptr_t)(which);      \
    asm volatile("ecall"                                       \
                 : "+r"(a0)                                    \
                 : "r"(a1), "r"(a2), "r"(a3), "r"(a4), "r"(a7) \
                 : "memory");                                  \
    a0;                                                        \
  })

#define SYSCALL_3(which, arg0, arg1, arg2) \
  SYSCALL(which, arg0, arg1, arg2, 0, 0)

#define RUNTIME_SYSCALL_ATTEST_ENCLAVE      1003

int attest_enclave(void* report, void* data, size_t size) {
  return SYSCALL_3(RUNTIME_SYSCALL_ATTEST_ENCLAVE, report, data, size);
}

char* get_attestation_report ( char *nonce, int nonce_length ) {
    char *attestation_report = malloc ( 2048 );
    if ( attestation_report == NULL ) {
        return NULL;
    }

    attest_enclave((void*)attestation_report, nonce, nonce_length );

    fprintf ( stderr, "Attestation report obtained:\n%s\n", attestation_report );
    fprintf ( stderr, "CHECK\n" );

    return attestation_report;
}


/* ========== Base64 (Native WolfCrypt) ========== */

char* base64_encode(const unsigned char* input, int length) {
    word32 outLen = 0;
    
    /* First call to get required size */
    int ret = Base64_Encode_NoNl(input, length, NULL, &outLen);
    if (ret != LENGTH_ONLY_E && ret != 0) {
        return NULL;
    }
    
    char *output = malloc(outLen + 1);
    if (output == NULL) {
        return NULL;
    }
    
    if (Base64_Encode_NoNl(input, length, (byte*)output, &outLen) != 0) {
        free(output);
        return NULL;
    }
    
    output[outLen] = '\0';
    return output;
}

char* base64_decode(const char *base64, size_t *output_length) {
    size_t base64_length = strlen(base64);
    
    /* Add padding if needed */
    size_t padding = (4 - (base64_length & 3)) & 3;
    
    char *tmp = malloc(base64_length + padding + 1);
    if (tmp == NULL) {
        return NULL;
    }
    
    strcpy(tmp, base64);
    memset(tmp + base64_length, '=', padding);
    tmp[base64_length + padding] = '\0';
    
    word32 out_len = ((base64_length + padding) * 3) / 4;
    
    unsigned char *buffer = malloc(out_len + 1);
    if (buffer == NULL) {
        free(tmp);
        return NULL;
    }
    
    int ret = Base64_Decode((const byte*)tmp, (word32)strlen(tmp), buffer, &out_len);
    free(tmp);
    
    if (ret != 0) {
        free(buffer);
        return NULL;
    }
    
    *output_length = out_len;
    return (char*)buffer;
}

char* decode_key(char *text, size_t *len_out) {
    int all_hex = 1;
    for (char *p = text; *p; ++p) {
        if (!isxdigit((unsigned char)*p)) {
            all_hex = 0;
            break;
        }
    }

    if (all_hex && (strlen(text) & 1) == 0) {
        return (char*)hex_to_binary(text, len_out);
    }

    return base64_decode(text, len_out);
}

/* ========== HMAC-SHA256 (Native WolfCrypt) ========== */

static int hmac_sha256(
    const unsigned char* key, int key_len,
    const unsigned char* data, int data_len,
    unsigned char out[32]
) {
    Hmac hmac;
    int ret;

    ret = wc_HmacInit(&hmac, NULL, INVALID_DEVID);
    if (ret != 0) return ret;

    ret = wc_HmacSetKey(&hmac, WC_SHA256, key, key_len);
    if (ret != 0) { wc_HmacFree(&hmac); return ret; }

    ret = wc_HmacUpdate(&hmac, data, data_len);
    if (ret != 0) { wc_HmacFree(&hmac); return ret; }

    ret = wc_HmacFinal(&hmac, out);
    wc_HmacFree(&hmac);
    return ret;
}

/* ========== AES-256-CBC (Native WolfCrypt) ========== */

static int pkcs7_pad(unsigned char *data, int data_len, int block_size) {
    int pad_len = block_size - (data_len % block_size);
    for (int i = 0; i < pad_len; i++) {
        data[data_len + i] = (unsigned char)pad_len;
    }
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

char *decrypt(const char *base64_cipher, const char *key_text) {
    size_t key_length = 0;
    unsigned char *key_binary = (unsigned char*)decode_key((char*)key_text, &key_length);
    if (key_binary == NULL) {
        return NULL;
    }

    unsigned char aes_key[32] = {0};
    unsigned char hmac_key[32] = {0};
    
    /* aes_key = SHA256(master_key) */
    wc_Sha256 sha;
    wc_InitSha256(&sha);
    wc_Sha256Update(&sha, key_binary, (word32)key_length);
    wc_Sha256Final(&sha, aes_key);
    wc_Sha256Free(&sha);
    
    /* hmac_key = SHA256(master_key || "Mac") */
    wc_InitSha256(&sha);
    wc_Sha256Update(&sha, key_binary, (word32)key_length);
    wc_Sha256Update(&sha, (const unsigned char*)"Mac", 3);
    wc_Sha256Final(&sha, hmac_key);
    wc_Sha256Free(&sha);
    free(key_binary);

    size_t blob_length = 0;
    unsigned char *blob = (unsigned char*)base64_decode(base64_cipher, &blob_length);
    if (blob == NULL || blob_length < 32 + 64) {
        free(blob);
        return NULL;
    }

    char iv_hex[33] = {0};
    memcpy(iv_hex, blob, 32);

    const char *tag_hex = (char*)blob + blob_length - 64;
    size_t ciphertext_length = blob_length - 32 - 64;

    char *ciphertext_base64 = malloc(ciphertext_length + 1);
    if (ciphertext_base64 == NULL) {
        free(blob);
        return NULL;
    }
    memcpy(ciphertext_base64, blob + 32, ciphertext_length);
    ciphertext_base64[ciphertext_length] = '\0';

    unsigned char calculated_tag[32] = {0};
    hmac_sha256(hmac_key, 32, (unsigned char*)ciphertext_base64, (int)ciphertext_length, calculated_tag);

    char calculated_tag_hex[65] = {0};
    bytes_to_hex(calculated_tag, 32, calculated_tag_hex);

    if (memcmp(calculated_tag_hex, tag_hex, 64) != 0) {
        free(blob);
        free(ciphertext_base64);
        return NULL;
    }

    size_t iv_binary_length = 0;
    unsigned char *iv_binary = hex_to_binary(iv_hex, &iv_binary_length);
    if (iv_binary == NULL || iv_binary_length != 16) {
        free(blob);
        free(ciphertext_base64);
        free(iv_binary);
        return NULL;
    }

    size_t ciphertext_binary_length = 0;
    unsigned char *ciphertext_binary = (unsigned char*)base64_decode(ciphertext_base64, &ciphertext_binary_length);
    free(ciphertext_base64);
    free(blob);

    if (ciphertext_binary == NULL) {
        free(iv_binary);
        return NULL;
    }

    Aes aes;
    unsigned char *plaintext = malloc(ciphertext_binary_length + 1);

    if (plaintext == NULL) {
        free(iv_binary);
        free(ciphertext_binary);
        return NULL;
    }

    if (wc_AesInit(&aes, NULL, INVALID_DEVID) != 0) {
        free(iv_binary);
        free(ciphertext_binary);
        free(plaintext);
        return NULL;
    }

    if (wc_AesSetKey(&aes, aes_key, 32, iv_binary, AES_DECRYPTION) != 0) {
        wc_AesFree(&aes);
        free(iv_binary);
        free(ciphertext_binary);
        free(plaintext);
        return NULL;
    }

    if (wc_AesCbcDecrypt(&aes, plaintext, ciphertext_binary, (word32)ciphertext_binary_length) != 0) {
        wc_AesFree(&aes);
        free(iv_binary);
        free(ciphertext_binary);
        free(plaintext);
        return NULL;
    }

    wc_AesFree(&aes);
    free(iv_binary);
    free(ciphertext_binary);

    int unpadded_len = pkcs7_unpad(plaintext, (int)ciphertext_binary_length);
    if (unpadded_len < 0) {
        free(plaintext);
        return NULL;
    }

    plaintext[unpadded_len] = '\0';
    return (char*)plaintext;
}

char *encrypt(const char *plaintext, const char *key_text) {
    size_t key_length = 0;
    unsigned char *key_binary = (unsigned char*)decode_key((char*)key_text, &key_length);
    if (key_binary == NULL) {
        return NULL;
    }

    unsigned char aes_key[32] = {0};
    unsigned char hmac_key[32] = {0};

    wc_Sha256 sha;
    wc_InitSha256(&sha);
    wc_Sha256Update(&sha, key_binary, (word32)key_length);
    wc_Sha256Final(&sha, aes_key);
    wc_Sha256Free(&sha);

    wc_InitSha256(&sha);
    wc_Sha256Update(&sha, key_binary, (word32)key_length);
    wc_Sha256Update(&sha, (const unsigned char*)"Mac", 3);
    wc_Sha256Final(&sha, hmac_key);
    wc_Sha256Free(&sha);
    free(key_binary);

    unsigned char iv_binary[16] = {0};
    if (random_bytes(iv_binary, 16) != 0) {
        return NULL;
    }

    char iv_hex[33] = {0};
    bytes_to_hex(iv_binary, 16, iv_hex);

    int plaintext_length = (int)strlen(plaintext);
    int padded_length = plaintext_length + (16 - (plaintext_length % 16));
    
    unsigned char *padded_plaintext = calloc(padded_length, 1);
    if (padded_plaintext == NULL) {
        return NULL;
    }
    memcpy(padded_plaintext, plaintext, plaintext_length);
    pkcs7_pad(padded_plaintext, plaintext_length, 16);

    unsigned char *ciphertext_binary = malloc(padded_length);
    if (ciphertext_binary == NULL) {
        free(padded_plaintext);
        return NULL;
    }

    Aes aes;
    if (wc_AesInit(&aes, NULL, INVALID_DEVID) != 0) {
        free(padded_plaintext);
        free(ciphertext_binary);
        return NULL;
    }

    if (wc_AesSetKey(&aes, aes_key, 32, iv_binary, AES_ENCRYPTION) != 0) {
        wc_AesFree(&aes);
        free(padded_plaintext);
        free(ciphertext_binary);
        return NULL;
    }

    if (wc_AesCbcEncrypt(&aes, ciphertext_binary, padded_plaintext, padded_length) != 0) {
        wc_AesFree(&aes);
        free(padded_plaintext);
        free(ciphertext_binary);
        return NULL;
    }

    wc_AesFree(&aes);
    free(padded_plaintext);

    char *ciphertext_base64 = base64_encode(ciphertext_binary, padded_length);
    free(ciphertext_binary);

    if (ciphertext_base64 == NULL) {
        return NULL;
    }

    unsigned char tag_binary[32] = {0};
    if (hmac_sha256(hmac_key, 32, (unsigned char*)ciphertext_base64, (int)strlen(ciphertext_base64), tag_binary) != 0) {
        free(ciphertext_base64);
        return NULL;
    }

    char tag_hex[65] = {0};
    bytes_to_hex(tag_binary, 32, tag_hex);

    size_t blob_raw_length = 32 + strlen(ciphertext_base64) + 64;
    char *blob_raw = malloc(blob_raw_length + 1);
    if (blob_raw == NULL) {
        free(ciphertext_base64);
        return NULL;
    }

    sprintf(blob_raw, "%s%s%s", iv_hex, ciphertext_base64, tag_hex);
    free(ciphertext_base64);

    char *blob_base64 = base64_encode((unsigned char*)blob_raw, (int)blob_raw_length);
    free(blob_raw);

    return blob_base64;
}


/* ========== Network Functions ========== */

int tcp_connect(const char* ip, const char *port_string) {
    int port = atoi(port_string);
    if (port <= 0 || port > 65535) {
        fprintf(stderr, "bad port: %d\n", port);
        return -1;
    }

    int socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd < 0) {
        perror("socket");
        return -1;
    }

    struct sockaddr_in socket_address_in;
    memset(&socket_address_in, 0, sizeof(socket_address_in));
    socket_address_in.sin_family = AF_INET;
    socket_address_in.sin_port = htons((uint16_t)port);

    if (inet_pton(AF_INET, ip, &socket_address_in.sin_addr) != 1) {
        fprintf(stderr, "inet_pton failed for ip=%s\n", ip);
        close(socket_fd);
        return -1;
    }

    if (connect(socket_fd, (struct sockaddr*)&socket_address_in, sizeof(socket_address_in)) != 0) {
        perror("connect");
        close(socket_fd);
        return -1;
    }

    return socket_fd;
}

int create_listen_socket(uint16_t port) {
    int socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd < 0) {
        return -1;
    }

    int option = 1;
    if (setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option)) < 0) {
        close(socket_fd);
        return -1;
    }

    struct sockaddr_in address = {
        .sin_family      = AF_INET,
        .sin_port        = htons(port),
        .sin_addr.s_addr = INADDR_ANY
    };

    if (bind(socket_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        close(socket_fd);
        return -1;
    }

    if (listen(socket_fd, SOMAXCONN) < 0) {
        close(socket_fd);
        return -1;
    }

    return socket_fd;
}

/* ========== Plain HTTP (raw sockets, no BIO) ========== */

char* http_get_plain(const char *host, const char *port, const char *path, const char *query, long *out_length) {
    int socket_fd = tcp_connect(host, port);
    if (socket_fd < 0) {
        return NULL;
    }

    char request[1024] = {0};
    int header_length = snprintf(request, sizeof(request),
        "GET %s?%s HTTP/1.1\r\nHost: %s\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n",
        path, query, host);

    if (send(socket_fd, request, header_length, 0) <= 0) {
        close(socket_fd);
        return NULL;
    }

    size_t capacity = 8192;
    size_t length = 0;
    char *response = malloc(capacity);
    if (response == NULL) {
        close(socket_fd);
        return NULL;
    }

    while (1) {
        char buffer[4096];
        ssize_t bytes_read = recv(socket_fd, buffer, sizeof(buffer), 0);
        if (bytes_read <= 0) break;

        if (length + bytes_read + 1 > capacity) {
            capacity = capacity * 2;
            char *tmp = realloc(response, capacity);
            if (tmp == NULL) {
                free(response);
                close(socket_fd);
                return NULL;
            }
            response = tmp;
        }

        memcpy(response + length, buffer, bytes_read);
        length += bytes_read;
    }

    response[length] = '\0';
    *out_length = (long)length;

    close(socket_fd);
    return response;
}

char* http_post_plain(const char *host, const char *port, const char *path, const char *body, long *out_length) {
    int socket_fd = tcp_connect(host, port);
    if (socket_fd < 0) {
        return NULL;
    }

    char request[2048] = {0};
    int body_length = (int)strlen(body);
    int header_length = snprintf(request, sizeof(request),
        "POST %s HTTP/1.1\r\nHost: %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n",
        path, host, body_length);

    if (send(socket_fd, request, header_length, 0) <= 0) {
        close(socket_fd);
        return NULL;
    }

    if (send(socket_fd, body, body_length, 0) <= 0) {
        close(socket_fd);
        return NULL;
    }

    size_t capacity = 8192;
    size_t length = 0;
    char *response = malloc(capacity);
    if (response == NULL) {
        close(socket_fd);
        return NULL;
    }

    while (1) {
        char buffer[4096];
        ssize_t bytes_read = recv(socket_fd, buffer, sizeof(buffer), 0);
        if (bytes_read <= 0) break;

        if (length + bytes_read + 1 > capacity) {
            capacity = capacity * 2;
            char *tmp = realloc(response, capacity);
            if (tmp == NULL) {
                free(response);
                close(socket_fd);
                return NULL;
            }
            response = tmp;
        }

        memcpy(response + length, buffer, bytes_read);
        length += bytes_read;
    }

    response[length] = '\0';
    *out_length = (long)length;

    close(socket_fd);
    return response;
}


/* ========== SSL/TLS Functions (Native WolfSSL) ========== */

/* 
 * Note: WolfSSL's WOLFSSL_CTX and WOLFSSL types are native, not compatibility layer.
 * The functions wolfSSL_CTX_new(), wolfSSL_new(), etc. are native WolfSSL API.
 * We use buffer-based certificate loading instead of X509 objects.
 */

/* Custom verification callback */
static int verify_callback(int preverify, WOLFSSL_X509_STORE_CTX *ctx) {
    char subject[256] = {0};
    char issuer[256] = {0};
    
    WOLFSSL_X509 *cert = wolfSSL_X509_STORE_CTX_get_current_cert(ctx);
    int depth = wolfSSL_X509_STORE_CTX_get_error_depth(ctx);
    int err = wolfSSL_X509_STORE_CTX_get_error(ctx);
    
    if (cert) {
        WOLFSSL_X509_NAME *subj = wolfSSL_X509_get_subject_name(cert);
        WOLFSSL_X509_NAME *iss = wolfSSL_X509_get_issuer_name(cert);
        if (subj) wolfSSL_X509_NAME_oneline(subj, subject, sizeof(subject));
        if (iss) wolfSSL_X509_NAME_oneline(iss, issuer, sizeof(issuer));
    }

    fprintf(stderr, "[DEBUG] verify_callback: depth=%d preverify=%d err=%d\n", depth, preverify, err);
    fprintf(stderr, "[DEBUG]   subject: %s\n", subject);
    fprintf(stderr, "[DEBUG]   issuer:  %s\n", issuer);

    if (!preverify) {
        /* Accept self-signed root CA */
        if (depth > 0 && strcmp(subject, issuer) == 0) {
            fprintf(stderr, "[DEBUG] Accepting self-signed root CA\n");
            return 1;
        }
        
        /* Accept date errors (clock skew in VMs) */
        /* WolfSSL native error codes */
        if (err == -150 || err == -151) {  /* ASN_BEFORE_DATE_E, ASN_AFTER_DATE_E */
            fprintf(stderr, "[DEBUG] Accepting certificate despite date error\n");
            return 1;
        }
    }

    return preverify;
}

/* Create SSL context with PEM buffers (native WolfSSL) */
WOLFSSL_CTX* create_ssl_context_native(
    int is_server,
    const char *cert_pem,
    const char *key_pem,
    const char *ca_pem,
    int skip_verify
) {
    WOLFSSL_METHOD *method;
    
    if (is_server) {
        method = wolfTLSv1_2_server_method();
    } else {
        method = wolfTLSv1_2_client_method();
    }
    
    if (method == NULL) {
        fprintf(stderr, "[DEBUG] wolfTLS method creation failed\n");
        return NULL;
    }

    WOLFSSL_CTX *ctx = wolfSSL_CTX_new(method);
    if (ctx == NULL) {
        fprintf(stderr, "[DEBUG] wolfSSL_CTX_new failed\n");
        return NULL;
    }

    /* Load certificate from PEM buffer */
    if (cert_pem != NULL) {
        int ret = wolfSSL_CTX_use_certificate_buffer(ctx,
            (const unsigned char*)cert_pem,
            (long)strlen(cert_pem),
            WOLFSSL_FILETYPE_PEM);
        if (ret != WOLFSSL_SUCCESS) {
            fprintf(stderr, "[DEBUG] wolfSSL_CTX_use_certificate_buffer failed: %d\n", ret);
            wolfSSL_CTX_free(ctx);
            return NULL;
        }
    }

    /* Load private key from PEM buffer */
    if (key_pem != NULL) {
        int ret = wolfSSL_CTX_use_PrivateKey_buffer(ctx,
            (const unsigned char*)key_pem,
            (long)strlen(key_pem),
            WOLFSSL_FILETYPE_PEM);
        if (ret != WOLFSSL_SUCCESS) {
            fprintf(stderr, "[DEBUG] wolfSSL_CTX_use_PrivateKey_buffer failed: %d\n", ret);
            wolfSSL_CTX_free(ctx);
            return NULL;
        }
    }

    /* Load CA certificate from PEM buffer */
    /* Use _ex version with WOLFSSL_LOAD_FLAG_DATE_ERR_OKAY to ignore date errors */
    /* This is needed because VMs/enclaves often have incorrect system clocks */
    if (ca_pem != NULL) {
        /* Try the _ex version first (ignores date errors) */
        int ret = wolfSSL_CTX_load_verify_buffer_ex(ctx,
            (const unsigned char*)ca_pem,
            (long)strlen(ca_pem),
            WOLFSSL_FILETYPE_PEM,
            0,  /* userChain = 0 (not a chain file) */
            WOLFSSL_LOAD_FLAG_DATE_ERR_OKAY);  /* Ignore date validation errors */
        if (ret != WOLFSSL_SUCCESS) {
            fprintf(stderr, "[DEBUG] wolfSSL_CTX_load_verify_buffer_ex failed: %d\n", ret);
            wolfSSL_CTX_free(ctx);
            return NULL;
        }
        fprintf(stderr, "[DEBUG] Loaded CA certificate successfully (with date tolerance)\n");
    }

    /* Set verification mode */
    if (skip_verify) {
        wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_NONE, NULL);
        fprintf(stderr, "[DEBUG] SSL context created with VERIFY_NONE\n");
    } else {
        wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, verify_callback);
        fprintf(stderr, "[DEBUG] SSL context created with VERIFY_PEER\n");
    }

    return ctx;
}

/* Get peer common name from SSL connection */
char* get_peer_cn(WOLFSSL *ssl) {
    if (ssl == NULL) {
        return NULL;
    }

    WOLFSSL_X509 *cert = wolfSSL_get_peer_certificate(ssl);
    if (cert == NULL) {
        return NULL;
    }

    WOLFSSL_X509_NAME *subject = wolfSSL_X509_get_subject_name(cert);
    if (subject == NULL) {
        wolfSSL_X509_free(cert);
        return NULL;
    }

    char cn[256] = {0};
    int ret = wolfSSL_X509_NAME_get_text_by_NID(subject, NID_commonName, cn, sizeof(cn));
    
    wolfSSL_X509_free(cert);
    
    if (ret <= 0) {
        return NULL;
    }
    
    return strdup(cn);
}

/* HTTPS GET with client certificate */
char* https_get_with_client(
    const char *host, 
    const char *port, 
    const char *path,
    const char *host_sni,
    const char *ca_pem, 
    const char *cert_pem,
    const char *key_pem,
    long *out_length
) {
    fprintf(stderr, "[DEBUG] https_get_with_client: host=%s port=%s path=%s\n", host, port, path);
    
    /* Create context with skip_verify=1 for KME connections */
    WOLFSSL_CTX *ctx = create_ssl_context_native(0, cert_pem, key_pem, ca_pem, 1);
    if (ctx == NULL) {
        return NULL;
    }

    int socket_fd = tcp_connect(host, port);
    if (socket_fd < 0) {
        wolfSSL_CTX_free(ctx);
        return NULL;
    }
    fprintf(stderr, "[DEBUG] tcp_connect succeeded: fd=%d\n", socket_fd);

    WOLFSSL *ssl = wolfSSL_new(ctx);
    if (ssl == NULL) {
        close(socket_fd);
        wolfSSL_CTX_free(ctx);
        return NULL;
    }

    wolfSSL_set_fd(ssl, socket_fd);

    /* Set SNI */
    int sni_result = wolfSSL_UseSNI(ssl, WOLFSSL_SNI_HOST_NAME, host_sni, (word16)strlen(host_sni));
    fprintf(stderr, "[DEBUG] wolfSSL_UseSNI result: %d\n", sni_result);

    /* Disable verification during handshake */
    wolfSSL_set_verify(ssl, WOLFSSL_VERIFY_NONE, NULL);

    int connect_result = wolfSSL_connect(ssl);
    if (connect_result != WOLFSSL_SUCCESS) {
        int err = wolfSSL_get_error(ssl, connect_result);
        fprintf(stderr, "[DEBUG] wolfSSL_connect failed: %d, error: %d\n", connect_result, err);
        wolfSSL_free(ssl);
        close(socket_fd);
        wolfSSL_CTX_free(ctx);
        return NULL;
    }
    fprintf(stderr, "[DEBUG] wolfSSL_connect succeeded\n");

    /* Debug: print peer certificate info */
    WOLFSSL_X509 *peer_cert = wolfSSL_get_peer_certificate(ssl);
    if (peer_cert) {
        WOLFSSL_X509_NAME *subject = wolfSSL_X509_get_subject_name(peer_cert);
        char subject_str[256] = {0};
        if (subject) wolfSSL_X509_NAME_oneline(subject, subject_str, sizeof(subject_str));
        fprintf(stderr, "[DEBUG] Peer cert subject: %s\n", subject_str);
        wolfSSL_X509_free(peer_cert);
    }

    /* Build and send request */
    char request[1024] = {0};
    int header_length = snprintf(request, sizeof(request),
        "GET %s HTTP/1.1\r\nHost: %s\r\nAccept: application/json\r\nConnection: close\r\n\r\n",
        path, host_sni);

    int write_result = wolfSSL_write(ssl, request, header_length);
    if (write_result <= 0) {
        wolfSSL_free(ssl);
        close(socket_fd);
        wolfSSL_CTX_free(ctx);
        return NULL;
    }

    /* Read response */
    size_t capacity = 8192;
    size_t length = 0;
    char *response = calloc(capacity, 1);
    if (response == NULL) {
        wolfSSL_free(ssl);
        close(socket_fd);
        wolfSSL_CTX_free(ctx);
        return NULL;
    }

    while (1) {
        char buffer[4096] = {0};
        int bytes_read = wolfSSL_read(ssl, buffer, sizeof(buffer));
        if (bytes_read <= 0) break;

        if (length + (size_t)bytes_read + 1 > capacity) {
            capacity = capacity * 2;
            char *tmp = realloc(response, capacity);
            if (tmp == NULL) {
                free(response);
                wolfSSL_free(ssl);
                close(socket_fd);
                wolfSSL_CTX_free(ctx);
                return NULL;
            }
            response = tmp;
        }

        memcpy(response + length, buffer, bytes_read);
        length += bytes_read;
    }

    response[length] = '\0';
    *out_length = (long)length;

    wolfSSL_shutdown(ssl);
    wolfSSL_free(ssl);
    close(socket_fd);
    wolfSSL_CTX_free(ctx);

    return response;
}


/* ========== RSA Key Generation (Native WolfCrypt) ========== */

/* Generate RSA key pair and return as PEM string */
char* generate_rsa_key_pem(int bits) {
    RsaKey key;
    int ret;
    
    if (init_rng() != 0) {
        return NULL;
    }
    
    ret = wc_InitRsaKey(&key, NULL);
    if (ret != 0) {
        return NULL;
    }
    
    ret = wc_MakeRsaKey(&key, bits, 65537, &g_rng);
    if (ret != 0) {
        wc_FreeRsaKey(&key);
        return NULL;
    }
    
    /* Export to DER first */
    int derSz = wc_RsaKeyToDer(&key, NULL, 0);
    if (derSz < 0) {
        wc_FreeRsaKey(&key);
        return NULL;
    }
    
    byte *derBuf = malloc(derSz);
    if (derBuf == NULL) {
        wc_FreeRsaKey(&key);
        return NULL;
    }
    
    derSz = wc_RsaKeyToDer(&key, derBuf, derSz);
    wc_FreeRsaKey(&key);
    
    if (derSz < 0) {
        free(derBuf);
        return NULL;
    }
    
    /* Convert DER to PEM */
    int pemSz = wc_DerToPem(derBuf, derSz, NULL, 0, PRIVATEKEY_TYPE);
    if (pemSz < 0) {
        free(derBuf);
        return NULL;
    }
    
    char *pemBuf = malloc(pemSz + 1);
    if (pemBuf == NULL) {
        free(derBuf);
        return NULL;
    }
    
    pemSz = wc_DerToPem(derBuf, derSz, (byte*)pemBuf, pemSz, PRIVATEKEY_TYPE);
    free(derBuf);
    
    if (pemSz < 0) {
        free(pemBuf);
        return NULL;
    }
    
    pemBuf[pemSz] = '\0';
    return pemBuf;
}

/* Create CSR and return as PEM string */
char* create_csr_pem(const char *key_pem, const char *common_name) {
    /* Decode PEM key to DER */
    int keyDerSz = wc_KeyPemToDer((const byte*)key_pem, (int)strlen(key_pem), NULL, 0, NULL);
    if (keyDerSz < 0) {
        fprintf(stderr, "[DEBUG] wc_KeyPemToDer size failed: %d\n", keyDerSz);
        return NULL;
    }
    
    byte *keyDer = malloc(keyDerSz);
    if (keyDer == NULL) {
        return NULL;
    }
    
    keyDerSz = wc_KeyPemToDer((const byte*)key_pem, (int)strlen(key_pem), keyDer, keyDerSz, NULL);
    if (keyDerSz < 0) {
        free(keyDer);
        return NULL;
    }
    
    /* Initialize RSA key from DER */
    RsaKey rsaKey;
    if (wc_InitRsaKey(&rsaKey, NULL) != 0) {
        free(keyDer);
        return NULL;
    }
    
    word32 idx = 0;
    if (wc_RsaPrivateKeyDecode(keyDer, &idx, &rsaKey, keyDerSz) != 0) {
        free(keyDer);
        wc_FreeRsaKey(&rsaKey);
        return NULL;
    }
    free(keyDer);
    
    /* Create CSR */
    Cert cert;
    wc_InitCert(&cert);
    
    /* Set subject */
    strncpy(cert.subject.commonName, common_name, CTC_NAME_SIZE - 1);
    cert.subject.commonName[CTC_NAME_SIZE - 1] = '\0';
    
    /* Set signature algorithm */
    cert.sigType = CTC_SHA256wRSA;
    
    /* Generate CSR DER */
    if (init_rng() != 0) {
        wc_FreeRsaKey(&rsaKey);
        return NULL;
    }
    
    byte csrDer[4096];
    int csrDerSz = wc_MakeCertReq(&cert, csrDer, sizeof(csrDer), &rsaKey, NULL);
    if (csrDerSz < 0) {
        fprintf(stderr, "[DEBUG] wc_MakeCertReq failed: %d\n", csrDerSz);
        wc_FreeRsaKey(&rsaKey);
        return NULL;
    }
    
    /* Sign CSR */
    csrDerSz = wc_SignCert(cert.bodySz, cert.sigType, csrDer, sizeof(csrDer), &rsaKey, NULL, &g_rng);
    wc_FreeRsaKey(&rsaKey);
    
    if (csrDerSz < 0) {
        fprintf(stderr, "[DEBUG] wc_SignCert failed: %d\n", csrDerSz);
        return NULL;
    }
    
    /* Convert to PEM */
    int pemSz = wc_DerToPem(csrDer, csrDerSz, NULL, 0, CERTREQ_TYPE);
    if (pemSz < 0) {
        return NULL;
    }
    
    char *pemBuf = malloc(pemSz + 1);
    if (pemBuf == NULL) {
        return NULL;
    }
    
    pemSz = wc_DerToPem(csrDer, csrDerSz, (byte*)pemBuf, pemSz, CERTREQ_TYPE);
    if (pemSz < 0) {
        free(pemBuf);
        return NULL;
    }
    
    pemBuf[pemSz] = '\0';
    return pemBuf;
}

/* JSON-escape PEM string */
char* pem_to_json_escaped(const char *pem) {
    size_t length = strlen(pem);
    size_t max_out = length * 2 + 1;
    
    char *out = malloc(max_out);
    if (out == NULL) {
        return NULL;
    }
    
    char *pout = out;
    for (size_t i = 0; i < length; ++i) {
        char c = pem[i];
        if      (c == '\n') { *pout++ = '\\'; *pout++ = 'n'; }
        else if (c == '"')  { *pout++ = '\\'; *pout++ = '"'; }
        else if (c == '\\') { *pout++ = '\\'; *pout++ = '\\'; }
        else                { *pout++ = c; }
    }
    
    *pout = '\0';
    return out;
}


/* ========== Configuration Functions ========== */

void free_repetitor_configuration(repetitor_configuration_t *config) {
    if (config == NULL) return;
    free(config->ca_url_host);
    free(config->ca_url_path);
    free(config->ca_url_port);
    free(config->left_repetitor_url);
    free(config->right_repetitor_url);
    free(config->left_repetitor_id);
    free(config->right_repetitor_id);
    free(config->left_kme);
    free(config->right_kme);
    free(config->left_kme_url);
    free(config->right_kme_url);
    free(config->left_cn);
    free(config->right_cn);
    free(config->left_kme_peer);
    free(config->right_kme_peer);
    free(config->whitelist);
    free(config);
}

repetitor_configuration_t* get_repetitor_configuration(
    const char *controller_host, 
    const char *controller_port, 
    const char *controller_get_nonce_path,
    const char *controller_register_path,
    const char *controller_configuration_path,
    const char *repetitor_id,
    const char *repetitor_url
) {
    /* Get nonce from controller */
    char get_nonce_query[64] = {0};
    sprintf(get_nonce_query, "repetitor_id=%s", repetitor_id);

    long get_nonce_out_length = 0;
    char *nonce_response = http_get_plain(
        controller_host, controller_port, controller_get_nonce_path,
        get_nonce_query, &get_nonce_out_length
    );
    
    if (nonce_response == NULL) {
        return NULL;
    }
    
    long nonce_body_length = 0;
    char *nonce = extract_http_body(nonce_response, get_nonce_out_length, &nonce_body_length);
    free(nonce_response);
    
    if (nonce == NULL || nonce_body_length != 32) {
        free(nonce);
        return NULL;
    }
    
    char *attestation_report = get_attestation_report(nonce, (int)nonce_body_length);
    if (attestation_report == NULL) {
        free(nonce);
        return NULL;
    }
    
    char *b64_attestation_report = base64_encode((unsigned char*)attestation_report, 2048);
    free(attestation_report);
    free(nonce);
    
    if (b64_attestation_report == NULL) {
        return NULL;
    }

    char post_body[4096] = {0};
    sprintf(post_body, 
        "{\"attestation_report\":\"%s\", \"repetitor_id\":\"%s\", \"repetitor_url\":\"%s\"}", 
        b64_attestation_report, repetitor_id, repetitor_url);
    
    /* Register */
    long register_out_length = 0;
    char *register_response = http_post_plain(
        controller_host, controller_port, controller_register_path,
        post_body, &register_out_length
    );
    free(register_response);
    
    /* Get configuration */
    long configuration_out_length = 0;
    char *configuration_response = http_post_plain(
        controller_host, controller_port, controller_configuration_path,
        post_body, &configuration_out_length
    );
    free(b64_attestation_report);
    
    if (configuration_response == NULL) {
        return NULL;
    }
    
    char *text = get_last_line(configuration_response);
    free(configuration_response);
    
    if (text == NULL) {
        return NULL;
    }

    repetitor_configuration_t *result = malloc(sizeof(repetitor_configuration_t));
    if (result == NULL) {
        free(text);
        return NULL;
    }
    
    result->ca_url_host         = extract_field_from_json(text, "ca_url_host");
    result->ca_url_path         = extract_field_from_json(text, "ca_url_path");
    result->ca_url_port         = extract_field_from_json(text, "ca_url_port");
    result->left_repetitor_url  = extract_field_from_json(text, "left_repetitor_url");
    result->right_repetitor_url = extract_field_from_json(text, "right_repetitor_url");
    result->left_repetitor_id   = extract_field_from_json(text, "left_repetitor_id");
    result->right_repetitor_id  = extract_field_from_json(text, "right_repetitor_id");
    result->left_kme            = extract_field_from_json(text, "left_kme");
    result->right_kme           = extract_field_from_json(text, "right_kme");
    result->left_kme_url        = extract_field_from_json(text, "left_kme_url");
    result->right_kme_url       = extract_field_from_json(text, "right_kme_url");
    result->left_cn             = extract_field_from_json(text, "left_cn");
    result->right_cn            = extract_field_from_json(text, "right_cn");
    result->left_kme_peer       = extract_field_from_json(text, "left_kme_peer");
    result->right_kme_peer      = extract_field_from_json(text, "right_kme_peer");
    result->whitelist           = extract_field_from_json(text, "whitelist");

    free(text);
    return result;
}

/* Generate certificate via CA */
key_pair_t* generate_certificate(repetitor_configuration_t *config, const char *common_name) {
    /* Generate RSA key */
    char *key_pem = generate_rsa_key_pem(2048);
    if (key_pem == NULL) {
        fprintf(stderr, "[DEBUG] generate_rsa_key_pem failed\n");
        return NULL;
    }
    
    /* Create CSR */
    char *csr_pem = create_csr_pem(key_pem, common_name);
    if (csr_pem == NULL) {
        fprintf(stderr, "[DEBUG] create_csr_pem failed\n");
        free(key_pem);
        return NULL;
    }
    
    /* JSON escape CSR */
    char *escaped = pem_to_json_escaped(csr_pem);
    free(csr_pem);
    
    if (escaped == NULL) {
        free(key_pem);
        return NULL;
    }
    
    /* Build request body */
    size_t body_size = strlen(escaped) + 64;
    char *body = malloc(body_size);
    if (body == NULL) {
        free(escaped);
        free(key_pem);
        return NULL;
    }
    
    snprintf(body, body_size, "{\"certificate_request\":\"%s\"}", escaped);
    free(escaped);
    
    /* Send to CA */
    long response_length = 0;
    char *response = http_post_plain(
        config->ca_url_host, config->ca_url_port, config->ca_url_path,
        body, &response_length
    );
    free(body);
    
    if (response == NULL) {
        free(key_pem);
        return NULL;
    }
    
    /* Extract certificate from response */
    char *cert_pem = extract_field_from_json(response, "certificate");
    free(response);
    
    if (cert_pem == NULL) {
        free(key_pem);
        return NULL;
    }
    
    key_pair_t *result = malloc(sizeof(key_pair_t));
    if (result == NULL) {
        free(key_pem);
        free(cert_pem);
        return NULL;
    }
    
    result->private_key_pem = key_pem;
    result->certificate_pem = cert_pem;
    
    return result;
}

void free_key_pair(key_pair_t *kp) {
    if (kp == NULL) return;
    free(kp->private_key_pem);
    free(kp->certificate_pem);
    free(kp);
}


/* ========== KME Functions ========== */

int get_status_of_kme(
    const char *key_pem,
    const char *cert_pem,
    const char *ca_pem,
    const char *kme_host,
    const char *kme_port,
    const char *kme_host_sni,
    const char *kme_slave    
) {
    fprintf(stderr, "[DEBUG] get_status_of_kme: host=%s sni=%s slave=%s\n", 
            kme_host, kme_host_sni, kme_slave);
    
    char status_path[128] = {0};
    snprintf(status_path, sizeof(status_path), "/api/v1/keys/%s/status", kme_slave);

    long status_length = 0;
    char *status_response = https_get_with_client(
        kme_host, kme_port, status_path, kme_host_sni,
        ca_pem, cert_pem, key_pem, &status_length
    );
    
    printf("STATUS: %s\n", status_response ? status_response : "(null)");
    
    int result = 1;
    if (status_response != NULL) {
        result = strstr(status_response, "200 OK") != NULL ? 0 : 1;
        free(status_response);
    }

    return result;
}

char* get_key_with_id(
    const char *key_pem,
    const char *cert_pem,
    const char *ca_pem,
    const char *kme_host,
    const char *kme_port,
    const char *kme_host_sni,
    const char *kme_master,
    const char *key_id    
) {
    char dec_keys_path[256] = {0};
    snprintf(dec_keys_path, sizeof(dec_keys_path), "/api/v1/keys/%s/dec_keys?key_ID=%s", kme_master, key_id);

    long response_length = 0;
    char *response = https_get_with_client(
        kme_host, kme_port, dec_keys_path, kme_host_sni,
        ca_pem, cert_pem, key_pem, &response_length
    );
    
    if (response == NULL) {
        return NULL;
    }
    
    char *body = get_last_line(response);
    free(response);
    
    if (body == NULL) {
        return NULL;
    }
    
    char *key = extract_field_from_json(body, "key");
    free(body);

    return key;
}

void get_key(
    const char *key_pem,
    const char *cert_pem,
    const char *ca_pem,
    const char *kme_host,
    const char *kme_port,
    const char *kme_host_sni,
    const char *kme_slave,
    int key_count,
    int key_size,
    char **out_key,
    char **out_key_id
) {
    char enc_keys_path[256] = {0};
    snprintf(enc_keys_path, sizeof(enc_keys_path), 
             "/api/v1/keys/%s/enc_keys?number=%d&size=%d", kme_slave, key_count, key_size);

    long response_length = 0;
    char *response = https_get_with_client(
        kme_host, kme_port, enc_keys_path, kme_host_sni,
        ca_pem, cert_pem, key_pem, &response_length
    );
    
    if (response == NULL) {
        *out_key = NULL;
        *out_key_id = NULL;
        return;
    }
    
    fprintf(stderr, "[DEBUG] get_key: response=%s\n", response);
    
    char *body = get_last_line(response);
    free(response);
    
    if (body == NULL) {
        *out_key = NULL;
        *out_key_id = NULL;
        return;
    }
    
    *out_key = extract_field_from_json(body, "key");
    *out_key_id = extract_field_from_json(body, "key_ID");
    
    free(body);
}


/* ========== Message Functions ========== */

int send_message(
    const char *key_pem,
    const char *cert_pem,
    const char *ca_pem,
    const char *host,
    const char *port,
    const char *body
) {
    WOLFSSL_CTX *ctx = create_ssl_context_native(0, cert_pem, key_pem, ca_pem, 0);
    if (ctx == NULL) {
        return 1;
    }

    int socket_fd = tcp_connect(host, port);
    if (socket_fd < 0) {
        wolfSSL_CTX_free(ctx);
        return -1;
    }

    WOLFSSL *ssl = wolfSSL_new(ctx);
    if (ssl == NULL) {
        close(socket_fd);
        wolfSSL_CTX_free(ctx);
        return -1;
    }

    wolfSSL_set_fd(ssl, socket_fd);

    if (wolfSSL_connect(ssl) != WOLFSSL_SUCCESS) {
        wolfSSL_free(ssl);
        close(socket_fd);
        wolfSSL_CTX_free(ctx);
        return -1;
    }

    size_t body_length = strlen(body);
    const char *ptr = body;
    while (body_length > 0) {
        int written = wolfSSL_write(ssl, ptr, (int)body_length);
        if (written <= 0) {
            wolfSSL_free(ssl);
            close(socket_fd);
            wolfSSL_CTX_free(ctx);
            return -1;
        }
        ptr += written;
        body_length -= written;
    }

    /* Read response */
    char read_buffer[1024] = {0};
    wolfSSL_read(ssl, read_buffer, sizeof(read_buffer));

    wolfSSL_shutdown(ssl);
    wolfSSL_free(ssl);
    close(socket_fd);
    wolfSSL_CTX_free(ctx);

    return 0;
}

message_t read_message(WOLFSSL_CTX *ctx, int client_socket_fd) {
    message_t result = { .message = NULL, .subject = NULL };

    WOLFSSL *ssl = wolfSSL_new(ctx);
    if (ssl == NULL) {
        fprintf(stderr, "[DEBUG] read_message: wolfSSL_new failed\n");
        return result;
    }

    wolfSSL_set_fd(ssl, client_socket_fd);

    fprintf(stderr, "[DEBUG] read_message: calling wolfSSL_accept\n");

    int accept_result = wolfSSL_accept(ssl);
    if (accept_result != WOLFSSL_SUCCESS) {
        int err = wolfSSL_get_error(ssl, accept_result);
        fprintf(stderr, "[DEBUG] read_message: wolfSSL_accept failed: %d, error: %d\n", accept_result, err);
        wolfSSL_free(ssl);
        return result;
    }
    fprintf(stderr, "[DEBUG] read_message: wolfSSL_accept succeeded\n");

    result.subject = get_peer_cn(ssl);
    if (result.subject == NULL) {
        fprintf(stderr, "[DEBUG] read_message: get_peer_cn returned NULL\n");
        wolfSSL_shutdown(ssl);
        wolfSSL_free(ssl);
        return result;
    }
    fprintf(stderr, "[DEBUG] read_message: peer subject = %s\n", result.subject);

    char read_buffer[1024] = {0};
    int bytes = wolfSSL_read(ssl, read_buffer, sizeof(read_buffer) - 1);
    
    char write_buffer[] = "RECEIVED";
    wolfSSL_write(ssl, write_buffer, (int)strlen(write_buffer));

    if (bytes > 0) {
        result.message = calloc(bytes + 1, 1);
        if (result.message != NULL) {
            memcpy(result.message, read_buffer, bytes);
            result.message[bytes] = '\0';
        }
    }

    wolfSSL_shutdown(ssl);
    wolfSSL_free(ssl);
    
    return result;
}


/* ========== Main Function ========== */

int main(int argc, char *argv[]) {
    // if (argc < 3) {
    //     fprintf(stderr, "Usage: %s <repetitor_id> <port>\n", argv[0]);
    //     return 1;
    // }

    // const char *repetitor_id = argv[1];
    // int port = atoi(argv[2]);
    // 
    char *repetitor_id = "riscv-repetitor-1";
    int port =  9001;
    char repetitor_url[64] = {0};
    snprintf(repetitor_url, sizeof(repetitor_url), "127.0.0.1:%d", port);

    /* Initialize WolfSSL */
    wolfSSL_Init();
    
    /* Get configuration from controller */
    fprintf(stderr, "Getting configuration...\n");
    repetitor_configuration_t *config = get_repetitor_configuration(
        CONTROLLER_HOST, CONTROLLER_PORT,
        CONTROLLER_GET_NONCE_PATH, CONTROLLER_REGISTER_PATH, CONTROLLER_CONFIGURATION_PATH,
        repetitor_id, repetitor_url
    );
    
    if (config == NULL) {
        fprintf(stderr, "Failed to get configuration\n");
        wolfSSL_Cleanup();
        return 1;
    }
    fprintf(stderr, "Configuration loaded\n");

    /* Generate keys */
    fprintf(stderr, "Generating keys...\n");
    key_pair_t *left_kp = generate_certificate(config, config->left_cn);
    key_pair_t *right_kp = generate_certificate(config, config->right_cn);
    key_pair_t *repetitor_kp = generate_certificate(config, repetitor_id);
    
    if (left_kp == NULL || right_kp == NULL || repetitor_kp == NULL) {
        fprintf(stderr, "Failed to generate certificates\n");
        free_key_pair(left_kp);
        free_key_pair(right_kp);
        free_key_pair(repetitor_kp);
        free_repetitor_configuration(config);
        wolfSSL_Cleanup();
        return 1;
    }
    fprintf(stderr, "Keys generated\nCertificates generated\n");

    /* Check KME status */
    if (strlen(config->left_kme) > 0) {
        int status = get_status_of_kme(
            left_kp->private_key_pem, left_kp->certificate_pem,
            QKD_CA_CERTIFICATE, config->left_kme_url, KME_PORT,
            config->left_kme, config->left_kme_peer
        );
        if (status != 0) {
            fprintf(stderr, "Left KME status check failed\n");
            goto cleanup;
        }
    }

    if (strlen(config->right_kme) > 0) {
        int status = get_status_of_kme(
            right_kp->private_key_pem, right_kp->certificate_pem,
            QKD_CA_CERTIFICATE, config->right_kme_url, KME_PORT,
            config->right_kme, config->right_kme_peer
        );
        if (status != 0) {
            fprintf(stderr, "Right KME status check failed\n");
            goto cleanup;
        }
    }

    /* Create listen socket */
    int listen_fd = create_listen_socket((uint16_t)port);
    if (listen_fd < 0) {
        fprintf(stderr, "Failed to create listen socket\n");
        goto cleanup;
    }

    /* Create server SSL context */
    WOLFSSL_CTX *server_ctx = create_ssl_context_native(
        1, repetitor_kp->certificate_pem, repetitor_kp->private_key_pem,
        REPETITOR_CA_CERTIFICATE, 0
    );
    
    if (server_ctx == NULL) {
        fprintf(stderr, "Failed to create server SSL context\n");
        close(listen_fd);
        goto cleanup;
    }
    fprintf(stderr, "[DEBUG] Server listening on port %d\n", port);

    signal(SIGINT, handle_sigint);

    /* Main loop */
    while (keep_running) {
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);

        int client_fd = accept(listen_fd, (struct sockaddr*)&client_addr, &addr_len);
        if (client_fd < 0) {
            if (errno == EINTR && !keep_running) break;
            continue;
        }

        fprintf(stderr, "[DEBUG] Accepted connection from %s:%d\n",
                inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

        message_t msg = read_message(server_ctx, client_fd);
        close(client_fd);

        if (msg.message == NULL || msg.subject == NULL) {
            free(msg.message);
            free(msg.subject);
            continue;
        }

        if (strstr(config->whitelist, msg.subject) == NULL) {
            fprintf(stderr, "[DEBUG] Subject %s not in whitelist\n", msg.subject);
            free(msg.message);
            free(msg.subject);
            continue;
        }

        fprintf(stderr, "[DEBUG] Read message: %s from %s\n", msg.message, msg.subject);

        int is_left = strcmp(msg.subject, config->left_repetitor_id) == 0;
        
        const char *to_url = is_left ? config->right_repetitor_url : config->left_repetitor_url;
        const char *kme_master = is_left ? config->left_kme : config->right_kme;
        const char *kme_slave = is_left ? config->right_kme : config->left_kme;
        const char *kme_master_url = is_left ? config->left_kme_url : config->right_kme_url;
        const char *kme_slave_url = is_left ? config->right_kme_url : config->left_kme_url;
        const char *kme_master_sni = is_left ? config->left_kme : config->right_kme;
        const char *kme_slave_sni = is_left ? config->right_kme : config->left_kme;
        const char *kme_master_peer = is_left ? config->left_kme_peer : config->right_kme_peer;
        const char *kme_slave_peer = is_left ? config->right_kme_peer : config->left_kme_peer;
        key_pair_t *master_kp = is_left ? left_kp : right_kp;
        key_pair_t *slave_kp = is_left ? right_kp : left_kp;

        char *from_key_id = extract_field_from_json(msg.message, "key_ID");
        char *from_ciphertext = extract_field_from_json(msg.message, "message");
        
        char *plaintext = NULL;
        
        if (strlen(kme_master) > 0 && from_key_id && strlen(from_key_id) > 0) {
            char *from_key = get_key_with_id(
                master_kp->private_key_pem, master_kp->certificate_pem,
                QKD_CA_CERTIFICATE, kme_master_url, KME_PORT,
                kme_master_sni, kme_master_peer, from_key_id
            );
            
            if (from_key != NULL) {
                plaintext = decrypt(from_ciphertext, from_key);
                free(from_key);
            }
        } else if (from_ciphertext) {
            plaintext = strdup(from_ciphertext);
        }
        
        free(from_key_id);
        free(from_ciphertext);

        if (plaintext == NULL) {
            free(msg.message);
            free(msg.subject);
            continue;
        }

        fprintf(stderr, "[DEBUG] Decrypted message: %s\n", plaintext);

        char *to_ciphertext = NULL;
        char *to_key_id = NULL;

        if (strlen(kme_slave) > 0) {
            char *to_key = NULL;
            get_key(
                slave_kp->private_key_pem, slave_kp->certificate_pem,
                QKD_CA_CERTIFICATE, kme_slave_url, KME_PORT,
                kme_slave_sni, kme_slave_peer, 1, 1024,
                &to_key, &to_key_id
            );
            
            if (to_key != NULL) {
                to_ciphertext = encrypt(plaintext, to_key);
                free(to_key);
            }
        } else {
            to_ciphertext = strdup(plaintext);
            to_key_id = strdup("");
        }
        
        free(plaintext);

        if (to_ciphertext == NULL) {
            free(to_key_id);
            free(msg.message);
            free(msg.subject);
            continue;
        }

        char body[2048] = {0};
        snprintf(body, sizeof(body), "{\"message\":\"%s\",\"key_ID\":\"%s\"}\n",
                 to_ciphertext, to_key_id ? to_key_id : "");
        
        free(to_ciphertext);
        free(to_key_id);

        fprintf(stderr, "[DEBUG] Sending body: %s\n", body);

        char *to_ip = get_ip_address(to_url);
        char *to_port = get_port(to_url);
        
        if (to_ip && to_port) {
            send_message(
                repetitor_kp->private_key_pem, repetitor_kp->certificate_pem,
                REPETITOR_CA_CERTIFICATE, to_ip, to_port, body
            );
            fprintf(stderr, "[DEBUG] Message sent\n");
        }
        
        free(to_ip);
        free(to_port);
        free(msg.message);
        free(msg.subject);
    }

    wolfSSL_CTX_free(server_ctx);
    close(listen_fd);

cleanup:
    free_key_pair(left_kp);
    free_key_pair(right_kp);
    free_key_pair(repetitor_kp);
    free_repetitor_configuration(config);
    cleanup_rng();
    wolfSSL_Cleanup();

    return 0;
}
