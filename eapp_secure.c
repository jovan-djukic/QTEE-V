/*
 * QKD Relay Repetitor - Secure Communication Protocol
 * 
 * Implements encrypted communication with the controller:
 * 1. Initial key exchange encrypted with controller's RSA public key
 * 2. All subsequent messages encrypted with AES symmetric key
 * 3. Controller acts as CA for certificate generation
 */

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

#ifndef WOLFSSL_LOAD_FLAG_DATE_ERR_OKAY
#define WOLFSSL_LOAD_FLAG_DATE_ERR_OKAY 0x00000001
#endif

#define SYMMETRIC_KEY_SIZE 32
#define AES_IV_SIZE 16

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

// const char *CONTROLLER_HOST = "192.168.100.2";
const char *CONTROLLER_HOST = "127.0.0.1";
const char *CONTROLLER_PORT = "8000";
const char *CONTROLLER_GET_NONCE_PATH = "/get_nonce";
const char *CONTROLLER_GET_CONFIGURATION_PATH = "/configuration";
const char *CONTROLLER_GENERATE_CERTIFICATES_PATH = "/generate_certificates";

const char *KME_PORT = "443";

static volatile int keep_running = 1;

/* ========== Data Structures ========== */

typedef struct {
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
    /* Keys and certificates are stored separately */
    char *left_private_key;
    char *left_certificate;
    char *right_private_key;
    char *right_certificate;
    char *repetitor_private_key;
    char *repetitor_certificate;
} repetitor_configuration_t;

typedef struct {
    char *message;
    char *subject;
} message_t;

/* Global RNG */
static WC_RNG g_rng;
static int g_rng_initialized = 0;

void handle_sigint(int signal) {
    (void)signal;
    keep_running = 0;
}

/* ========== RNG Functions ========== */

static int init_rng(void) {
    if (!g_rng_initialized) {
        if (wc_InitRng(&g_rng) != 0) {
            return -1;
        }
        g_rng_initialized = 1;
    }
    return 0;
}

static void cleanup_rng(void) {
    if (g_rng_initialized) {
        wc_FreeRng(&g_rng);
        g_rng_initialized = 0;
    }
}

static int random_bytes(unsigned char *buffer, int length) {
    if (init_rng() != 0) return -1;
    return wc_RNG_GenerateBlock(&g_rng, buffer, length);
}


/* ========== Utility Functions ========== */

char* get_last_line(char* text) {
    if (text == NULL || *text == '\0') return NULL;
    const char* last_newline = strrchr(text, '\n');
    if (last_newline == NULL) return strdup(text);
    return strdup(last_newline + 1);
}

char *extract_field_from_json(const char *json, const char *field) {
    size_t field_length = strlen(field);
    char pattern[256] = {0};

    if (field_length + 3 >= sizeof(pattern)) return NULL;

    pattern[0] = '"';
    memcpy(pattern + 1, field, field_length);
    pattern[field_length + 1] = '"';
    pattern[field_length + 2] = '\0';

    const char *position = strstr(json, pattern);
    if (position == NULL) return NULL;

    position += field_length + 2;
    while (*position == ' ' || *position == '\t') ++position;
    if (*position != ':') return NULL;
    ++position;
    while (*position == ' ' || *position == '\t') ++position;
    if (*position != '"') return NULL;
    ++position;

    char *result = malloc(strlen(json) + 1);
    if (result == NULL) return NULL;

    char *current = result;
    for (;; ++position) {
        if (*position == '\0') { free(result); return NULL; }
        if (*position == '"') break;
        if (*position == '\\') {
            char next = *(position + 1);
            switch (next) {
                case 'n':  *current++ = '\n'; ++position; break;
                case 'r':  *current++ = '\r'; ++position; break;
                case 't':  *current++ = '\t'; ++position; break;
                case '"':  *current++ = '"';  ++position; break;
                case '\\': *current++ = '\\'; ++position; break;
                case '/':  *current++ = '/';  ++position; break;
                default:   *current++ = *position; break;  /* Unknown escape, copy as-is */
            }
        } else {
            *current++ = *position;
        }
    }
    *current = '\0';
    return result;
}

char* extract_http_body(const char *response, long response_length, long *body_length) {
    if (response == NULL || response_length <= 0) return NULL;
    
    const char *body_start = NULL;
    for (long i = 0; i < response_length - 3; ++i) {
        if (response[i] == '\r' && response[i+1] == '\n' && 
            response[i+2] == '\r' && response[i+3] == '\n') {
            body_start = response + i + 4;
            break;
        }
    }
    if (body_start == NULL) return NULL;
    
    long len = response_length - (body_start - response);
    if (len <= 0) return NULL;
    
    char *body = malloc(len + 1);
    if (body == NULL) return NULL;
    memcpy(body, body_start, len);
    body[len] = '\0';
    if (body_length) *body_length = len;
    return body;
}

char* get_ip_address(const char *url) {
    const char *colon = strchr(url, ':');
    size_t len = colon ? (size_t)(colon - url) : strlen(url);
    char *ip = malloc(len + 1);
    if (ip == NULL) return NULL;
    memcpy(ip, url, len);
    ip[len] = '\0';
    return ip;
}

char* get_port(const char *url) {
    const char *colon = strchr(url, ':');
    if (colon == NULL) return strdup("443");
    return strdup(colon + 1);
}

void bytes_to_hex(const unsigned char *bytes, size_t length, char *hex) {
    static const char *hex_map = "0123456789abcdef";
    for (size_t i = 0; i < length; ++i) {
        hex[i * 2] = hex_map[bytes[i] >> 4];
        hex[i * 2 + 1] = hex_map[bytes[i] & 0x0F];
    }
    hex[length * 2] = '\0';
}

unsigned char* hex_to_binary(const char *hex, size_t *output_length) {
    size_t hex_length = strlen(hex);
    if (hex_length % 2 != 0) return NULL;

    unsigned char *buffer = malloc(hex_length / 2);
    if (buffer == NULL) return NULL;

    for (size_t i = 0; i < hex_length / 2; ++i) {
        if (sscanf(hex + i * 2, "%2hhx", &buffer[i]) != 1) {
            free(buffer);
            return NULL;
        }
    }
    *output_length = hex_length / 2;
    return buffer;
}

char* get_attestation_report(char *nonce, int nonce_length) {
    char *attestation_report = malloc(nonce_length + 1);
    if (attestation_report == NULL) return NULL;
    memcpy(attestation_report, nonce, nonce_length);
    attestation_report[nonce_length] = '\0';
    return attestation_report;
}

/* ========== Base64 Functions ========== */

char* base64_encode(const unsigned char* input, int length) {
    word32 outLen = 0;
    int ret = Base64_Encode_NoNl(input, length, NULL, &outLen);
    if (ret != LENGTH_ONLY_E && ret != 0) return NULL;
    
    char *output = malloc(outLen + 1);
    if (output == NULL) return NULL;
    
    if (Base64_Encode_NoNl(input, length, (byte*)output, &outLen) != 0) {
        free(output);
        return NULL;
    }
    output[outLen] = '\0';
    return output;
}

char* base64_decode(const char *base64, size_t *output_length) {
    size_t base64_length = strlen(base64);
    size_t padding = (4 - (base64_length & 3)) & 3;
    
    char *tmp = malloc(base64_length + padding + 1);
    if (tmp == NULL) return NULL;
    strcpy(tmp, base64);
    memset(tmp + base64_length, '=', padding);
    tmp[base64_length + padding] = '\0';
    
    word32 out_len = ((base64_length + padding) * 3) / 4;
    unsigned char *buffer = malloc(out_len + 1);
    if (buffer == NULL) { free(tmp); return NULL; }
    
    int ret = Base64_Decode((const byte*)tmp, (word32)strlen(tmp), buffer, &out_len);
    free(tmp);
    
    if (ret != 0) { free(buffer); return NULL; }
    *output_length = out_len;
    return (char*)buffer;
}

/* ========== AES Symmetric Encryption ========== */

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

/* Encrypt with AES-256-CBC, returns base64(IV + ciphertext) */
char* aes_encrypt(const char *plaintext, const unsigned char *key) {
    unsigned char iv[AES_IV_SIZE];
    if (random_bytes(iv, AES_IV_SIZE) != 0) return NULL;

    int plaintext_len = (int)strlen(plaintext);
    int padded_len = plaintext_len + (16 - (plaintext_len % 16));
    
    unsigned char *padded = calloc(padded_len, 1);
    if (padded == NULL) return NULL;
    memcpy(padded, plaintext, plaintext_len);
    pkcs7_pad(padded, plaintext_len, 16);

    unsigned char *ciphertext = malloc(padded_len);
    if (ciphertext == NULL) { free(padded); return NULL; }

    Aes aes;
    if (wc_AesInit(&aes, NULL, INVALID_DEVID) != 0) {
        free(padded); free(ciphertext); return NULL;
    }
    if (wc_AesSetKey(&aes, key, SYMMETRIC_KEY_SIZE, iv, AES_ENCRYPTION) != 0) {
        wc_AesFree(&aes); free(padded); free(ciphertext); return NULL;
    }
    if (wc_AesCbcEncrypt(&aes, ciphertext, padded, padded_len) != 0) {
        wc_AesFree(&aes); free(padded); free(ciphertext); return NULL;
    }
    wc_AesFree(&aes);
    free(padded);

    /* Combine IV + ciphertext */
    int combined_len = AES_IV_SIZE + padded_len;
    unsigned char *combined = malloc(combined_len);
    if (combined == NULL) { free(ciphertext); return NULL; }
    memcpy(combined, iv, AES_IV_SIZE);
    memcpy(combined + AES_IV_SIZE, ciphertext, padded_len);
    free(ciphertext);

    char *result = base64_encode(combined, combined_len);
    free(combined);
    return result;
}

/* Decrypt AES-256-CBC from base64(IV + ciphertext) */
char* aes_decrypt(const char *ciphertext_b64, const unsigned char *key) {
    size_t combined_len;
    unsigned char *combined = (unsigned char*)base64_decode(ciphertext_b64, &combined_len);
    if (combined == NULL || combined_len < AES_IV_SIZE + 16) {
        free(combined);
        return NULL;
    }

    unsigned char *iv = combined;
    unsigned char *ciphertext = combined + AES_IV_SIZE;
    int ciphertext_len = (int)(combined_len - AES_IV_SIZE);

    unsigned char *plaintext = malloc(ciphertext_len + 1);
    if (plaintext == NULL) { free(combined); return NULL; }

    Aes aes;
    if (wc_AesInit(&aes, NULL, INVALID_DEVID) != 0) {
        free(combined); free(plaintext); return NULL;
    }
    if (wc_AesSetKey(&aes, key, SYMMETRIC_KEY_SIZE, iv, AES_DECRYPTION) != 0) {
        wc_AesFree(&aes); free(combined); free(plaintext); return NULL;
    }
    if (wc_AesCbcDecrypt(&aes, plaintext, ciphertext, ciphertext_len) != 0) {
        wc_AesFree(&aes); free(combined); free(plaintext); return NULL;
    }
    wc_AesFree(&aes);
    free(combined);

    int unpadded_len = pkcs7_unpad(plaintext, ciphertext_len);
    if (unpadded_len < 0) { free(plaintext); return NULL; }
    
    plaintext[unpadded_len] = '\0';
    return (char*)plaintext;
}


/* ========== RSA Public Key Encryption ========== */

/* Extract RSA public key from PEM certificate and encrypt data */
char* rsa_encrypt_with_cert(const unsigned char *data, int data_len, const char *cert_pem) {
    /* Decode PEM certificate to get public key */
    /* DER is always smaller than PEM, so PEM length is a safe upper bound */
    int pemLen = (int)strlen(cert_pem);
    byte *certDer = malloc(pemLen);
    if (certDer == NULL) return NULL;
    
    int certDerSz = wc_CertPemToDer((const byte*)cert_pem, pemLen, certDer, pemLen, CERT_TYPE);
    if (certDerSz < 0) {
        fprintf(stderr, "[DEBUG] wc_CertPemToDer failed: %d\n", certDerSz);
        free(certDer);
        return NULL;
    }

    /* Extract public key from certificate */
    DecodedCert decoded;
    wc_InitDecodedCert(&decoded, certDer, certDerSz, NULL);
    int ret = wc_ParseCert(&decoded, CERT_TYPE, NO_VERIFY, NULL);
    if (ret != 0) {
        fprintf(stderr, "[DEBUG] wc_ParseCert failed: %d\n", ret);
        wc_FreeDecodedCert(&decoded);
        free(certDer);
        return NULL;
    }

    /* Initialize RSA key from public key in certificate */
    RsaKey rsaKey;
    ret = wc_InitRsaKey(&rsaKey, NULL);
    if (ret != 0) {
        wc_FreeDecodedCert(&decoded);
        free(certDer);
        return NULL;
    }

    word32 idx = 0;
    ret = wc_RsaPublicKeyDecode(decoded.publicKey, &idx, &rsaKey, decoded.pubKeySize);
    wc_FreeDecodedCert(&decoded);
    free(certDer);
    
    if (ret != 0) {
        fprintf(stderr, "[DEBUG] wc_RsaPublicKeyDecode failed: %d\n", ret);
        wc_FreeRsaKey(&rsaKey);
        return NULL;
    }

    /* Encrypt with RSA OAEP */
    int encSz = wc_RsaEncryptSize(&rsaKey);
    byte *encrypted = malloc(encSz);
    if (encrypted == NULL) {
        wc_FreeRsaKey(&rsaKey);
        return NULL;
    }

    if (init_rng() != 0) {
        free(encrypted);
        wc_FreeRsaKey(&rsaKey);
        return NULL;
    }

    ret = wc_RsaPublicEncrypt(data, data_len, encrypted, encSz, &rsaKey, &g_rng);
    wc_FreeRsaKey(&rsaKey);
    
    if (ret < 0) {
        fprintf(stderr, "[DEBUG] wc_RsaPublicEncrypt failed: %d\n", ret);
        free(encrypted);
        return NULL;
    }

    char *result = base64_encode(encrypted, ret);
    free(encrypted);
    return result;
}

/* ========== Network Functions ========== */

int tcp_connect(const char* ip, const char *port_string) {
    int port = atoi(port_string);
    if (port <= 0 || port > 65535) return -1;

    int socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd < 0) return -1;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);

    if (inet_pton(AF_INET, ip, &addr.sin_addr) != 1) {
        close(socket_fd);
        return -1;
    }

    if (connect(socket_fd, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        close(socket_fd);
        return -1;
    }

    return socket_fd;
}

int create_listen_socket(uint16_t port) {
    int socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd < 0) return -1;

    int option = 1;
    setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));

    struct sockaddr_in address = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
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

char* http_post_plain(const char *host, const char *port, const char *path, const char *body, long *out_length) {
    int socket_fd = tcp_connect(host, port);
    if (socket_fd < 0) return NULL;

    char request[2048] = {0};
    int body_length = (int)strlen(body);
    int header_length = snprintf(request, sizeof(request),
        "POST %s HTTP/1.1\r\nHost: %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n",
        path, host, body_length);

    if (send(socket_fd, request, header_length, 0) <= 0) { close(socket_fd); return NULL; }
    if (send(socket_fd, body, body_length, 0) <= 0) { close(socket_fd); return NULL; }

    size_t capacity = 8192;
    size_t length = 0;
    char *response = malloc(capacity);
    if (response == NULL) { close(socket_fd); return NULL; }

    while (1) {
        char buffer[4096];
        ssize_t bytes_read = recv(socket_fd, buffer, sizeof(buffer), 0);
        if (bytes_read <= 0) break;

        if (length + bytes_read + 1 > capacity) {
            capacity *= 2;
            char *tmp = realloc(response, capacity);
            if (tmp == NULL) { free(response); close(socket_fd); return NULL; }
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


/* ========== SSL/TLS Functions ========== */

static int verify_callback(int preverify, WOLFSSL_X509_STORE_CTX *ctx) {
    int depth = wolfSSL_X509_STORE_CTX_get_error_depth(ctx);
    int err = wolfSSL_X509_STORE_CTX_get_error(ctx);

    if (!preverify) {
        if (depth > 0) return 1;  /* Accept root CA */
        if (err == -150 || err == -151) return 1;  /* Accept date errors */
    }
    return preverify;
}

WOLFSSL_CTX* create_ssl_context_native(
    int is_server,
    const char *cert_pem,
    const char *key_pem,
    const char *ca_pem,
    int skip_verify
) {
    WOLFSSL_METHOD *method = is_server ? wolfTLSv1_2_server_method() : wolfTLSv1_2_client_method();
    if (method == NULL) return NULL;

    WOLFSSL_CTX *ctx = wolfSSL_CTX_new(method);
    if (ctx == NULL) return NULL;

    if (cert_pem != NULL) {
        if (wolfSSL_CTX_use_certificate_buffer(ctx, (const unsigned char*)cert_pem,
            (long)strlen(cert_pem), WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS) {
            wolfSSL_CTX_free(ctx);
            return NULL;
        }
    }

    if (key_pem != NULL) {
        if (wolfSSL_CTX_use_PrivateKey_buffer(ctx, (const unsigned char*)key_pem,
            (long)strlen(key_pem), WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS) {
            wolfSSL_CTX_free(ctx);
            return NULL;
        }
    }

    if (ca_pem != NULL) {
        if (wolfSSL_CTX_load_verify_buffer_ex(ctx, (const unsigned char*)ca_pem,
            (long)strlen(ca_pem), WOLFSSL_FILETYPE_PEM, 0,
            WOLFSSL_LOAD_FLAG_DATE_ERR_OKAY) != WOLFSSL_SUCCESS) {
            wolfSSL_CTX_free(ctx);
            return NULL;
        }
    }

    if (skip_verify) {
        wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_NONE, NULL);
    } else {
        wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, verify_callback);
    }

    return ctx;
}

char* get_peer_cn(WOLFSSL *ssl) {
    if (ssl == NULL) return NULL;

    WOLFSSL_X509 *cert = wolfSSL_get_peer_certificate(ssl);
    if (cert == NULL) return NULL;

    WOLFSSL_X509_NAME *subject = wolfSSL_X509_get_subject_name(cert);
    if (subject == NULL) { wolfSSL_X509_free(cert); return NULL; }

    char cn[256] = {0};
    int ret = wolfSSL_X509_NAME_get_text_by_NID(subject, NID_commonName, cn, sizeof(cn));
    wolfSSL_X509_free(cert);
    
    if (ret <= 0) return NULL;
    return strdup(cn);
}

/* ========== Key and CSR Generation ========== */

char* generate_rsa_key_pem(int bits) {
    RsaKey key;
    
    if (init_rng() != 0) return NULL;
    if (wc_InitRsaKey(&key, NULL) != 0) return NULL;
    if (wc_MakeRsaKey(&key, bits, 65537, &g_rng) != 0) {
        wc_FreeRsaKey(&key);
        return NULL;
    }
    
    int derSz = wc_RsaKeyToDer(&key, NULL, 0);
    if (derSz < 0) { wc_FreeRsaKey(&key); return NULL; }
    
    byte *derBuf = malloc(derSz);
    if (derBuf == NULL) { wc_FreeRsaKey(&key); return NULL; }
    
    derSz = wc_RsaKeyToDer(&key, derBuf, derSz);
    wc_FreeRsaKey(&key);
    if (derSz < 0) { free(derBuf); return NULL; }
    
    int pemSz = wc_DerToPem(derBuf, derSz, NULL, 0, PRIVATEKEY_TYPE);
    if (pemSz < 0) { free(derBuf); return NULL; }
    
    char *pemBuf = malloc(pemSz + 1);
    if (pemBuf == NULL) { free(derBuf); return NULL; }
    
    pemSz = wc_DerToPem(derBuf, derSz, (byte*)pemBuf, pemSz, PRIVATEKEY_TYPE);
    free(derBuf);
    if (pemSz < 0) { free(pemBuf); return NULL; }
    
    pemBuf[pemSz] = '\0';
    return pemBuf;
}

char* create_csr_pem(const char *key_pem, const char *common_name) {
    int keyDerSz = wc_KeyPemToDer((const byte*)key_pem, (int)strlen(key_pem), NULL, 0, NULL);
    if (keyDerSz < 0) return NULL;
    
    byte *keyDer = malloc(keyDerSz);
    if (keyDer == NULL) return NULL;
    
    keyDerSz = wc_KeyPemToDer((const byte*)key_pem, (int)strlen(key_pem), keyDer, keyDerSz, NULL);
    if (keyDerSz < 0) { free(keyDer); return NULL; }
    
    RsaKey rsaKey;
    if (wc_InitRsaKey(&rsaKey, NULL) != 0) { free(keyDer); return NULL; }
    
    word32 idx = 0;
    if (wc_RsaPrivateKeyDecode(keyDer, &idx, &rsaKey, keyDerSz) != 0) {
        free(keyDer);
        wc_FreeRsaKey(&rsaKey);
        return NULL;
    }
    free(keyDer);
    
    Cert cert;
    wc_InitCert(&cert);
    strncpy(cert.subject.commonName, common_name, CTC_NAME_SIZE - 1);
    cert.sigType = CTC_SHA256wRSA;
    
    if (init_rng() != 0) { wc_FreeRsaKey(&rsaKey); return NULL; }
    
    byte csrDer[4096];
    int csrDerSz = wc_MakeCertReq(&cert, csrDer, sizeof(csrDer), &rsaKey, NULL);
    if (csrDerSz < 0) { wc_FreeRsaKey(&rsaKey); return NULL; }
    
    csrDerSz = wc_SignCert(cert.bodySz, cert.sigType, csrDer, sizeof(csrDer), &rsaKey, NULL, &g_rng);
    wc_FreeRsaKey(&rsaKey);
    if (csrDerSz < 0) return NULL;
    
    int pemSz = wc_DerToPem(csrDer, csrDerSz, NULL, 0, CERTREQ_TYPE);
    if (pemSz < 0) return NULL;
    
    char *pemBuf = malloc(pemSz + 1);
    if (pemBuf == NULL) return NULL;
    
    pemSz = wc_DerToPem(csrDer, csrDerSz, (byte*)pemBuf, pemSz, CERTREQ_TYPE);
    if (pemSz < 0) { free(pemBuf); return NULL; }
    
    pemBuf[pemSz] = '\0';
    return pemBuf;
}

char* pem_to_json_escaped(const char *pem) {
    size_t length = strlen(pem);
    char *out = malloc(length * 2 + 1);
    if (out == NULL) return NULL;
    
    char *pout = out;
    for (size_t i = 0; i < length; ++i) {
        char c = pem[i];
        if (c == '\n') { *pout++ = '\\'; *pout++ = 'n'; }
        else if (c == '"') { *pout++ = '\\'; *pout++ = '"'; }
        else if (c == '\\') { *pout++ = '\\'; *pout++ = '\\'; }
        else { *pout++ = c; }
    }
    *pout = '\0';
    return out;
}


/* ========== Secure Configuration Protocol ========== */

void free_repetitor_configuration(repetitor_configuration_t *config) {
    if (config == NULL) return;
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
    free(config->left_private_key);
    free(config->left_certificate);
    free(config->right_private_key);
    free(config->right_certificate);
    free(config->repetitor_private_key);
    free(config->repetitor_certificate);
    free(config);
}

repetitor_configuration_t* get_repetitor_configuration(
    const char *controller_host,
    const char *controller_port,
    const char *controller_get_nonce_path,
    const char *controller_get_configuration_path,
    const char *controller_generate_certificates_path,
    const char *repetitor_id,
    const char *repetitor_url
) {
    repetitor_configuration_t *config = NULL;
    unsigned char symmetric_key[SYMMETRIC_KEY_SIZE];
    
    /* Step 1: Generate symmetric key */
    fprintf(stderr, "[DEBUG] Generating symmetric key...\n");
    if (random_bytes(symmetric_key, SYMMETRIC_KEY_SIZE) != 0) {
        fprintf(stderr, "[ERROR] Failed to generate symmetric key\n");
        return NULL;
    }
    
    char *symmetric_key_b64 = base64_encode(symmetric_key, SYMMETRIC_KEY_SIZE);
    if (symmetric_key_b64 == NULL) {
        fprintf(stderr, "[ERROR] Failed to encode symmetric key\n");
        return NULL;
    }

    /* Step 2: Create initial payload with repetitor_id and symmetric_key */
    char initial_payload[1024];
    snprintf(initial_payload, sizeof(initial_payload),
        "{\"repetitor_id\":\"%s\",\"symmetric_key\":\"%s\",\"repetitor_url\":\"%s\"}",
        repetitor_id, symmetric_key_b64, repetitor_url);
    
    /* Encrypt initial payload with controller's public key (from CA certificate) */
    fprintf(stderr, "[DEBUG] Encrypting initial payload with controller public key...\n");
    char *encrypted_initial = rsa_encrypt_with_cert(
        (unsigned char*)initial_payload, (int)strlen(initial_payload),
        REPETITOR_CA_CERTIFICATE);
    
    if (encrypted_initial == NULL) {
        fprintf(stderr, "[ERROR] Failed to RSA encrypt initial payload\n");
        free(symmetric_key_b64);
        return NULL;
    }
    
    /* Step 3: Send to get_nonce endpoint */
    char nonce_request[8192];
    snprintf(nonce_request, sizeof(nonce_request), "{\"encrypted_payload\":\"%s\"}", encrypted_initial);
    free(encrypted_initial);
    
    long response_length = 0;
    fprintf(stderr, "[DEBUG] Requesting nonce from controller...\n");
    char *nonce_response = http_post_plain(controller_host, controller_port,
        controller_get_nonce_path, nonce_request, &response_length);
    
    if (nonce_response == NULL) {
        fprintf(stderr, "[ERROR] Failed to get nonce from controller\n");
        free(symmetric_key_b64);
        return NULL;
    }
    
    /* Extract body and decrypt */
    long body_length = 0;
    char *body = extract_http_body(nonce_response, response_length, &body_length);
    free(nonce_response);
    
    if (body == NULL) {
        fprintf(stderr, "[ERROR] Failed to extract HTTP body\n");
        free(symmetric_key_b64);
        return NULL;
    }
    
    char *encrypted_nonce = extract_field_from_json(body, "encrypted_response");
    free(body);
    
    if (encrypted_nonce == NULL) {
        fprintf(stderr, "[ERROR] Failed to extract encrypted_response\n");
        free(symmetric_key_b64);
        return NULL;
    }
    
    char *nonce_json = aes_decrypt(encrypted_nonce, symmetric_key);
    free(encrypted_nonce);
    
    if (nonce_json == NULL) {
        fprintf(stderr, "[ERROR] Failed to decrypt nonce response\n");
        free(symmetric_key_b64);
        return NULL;
    }
    
    char *nonce = extract_field_from_json(nonce_json, "nonce");
    free(nonce_json);
    
    if (nonce == NULL) {
        fprintf(stderr, "[ERROR] Failed to extract nonce\n");
        free(symmetric_key_b64);
        return NULL;
    }
    fprintf(stderr, "[DEBUG] Received nonce: %s\n", nonce);

    /* Step 4: Get attestation report */
    char *attestation_report = get_attestation_report(nonce, (int)strlen(nonce));
    char *attestation_b64 = base64_encode((unsigned char*)attestation_report, (int)strlen(attestation_report));
    free(attestation_report);
    free(nonce);

    /* Step 5: Request configuration */
    char config_payload[2048];
    snprintf(config_payload, sizeof(config_payload),
        "{\"repetitor_id\":\"%s\",\"attestation_report\":\"%s\"}",
        repetitor_id, attestation_b64);
    free(attestation_b64);
    
    char *encrypted_config_payload = aes_encrypt(config_payload, symmetric_key);
    if (encrypted_config_payload == NULL) {
        fprintf(stderr, "[ERROR] Failed to encrypt config payload\n");
        free(symmetric_key_b64);
        return NULL;
    }
    
    char config_request[8192];
    snprintf(config_request, sizeof(config_request), "{\"encrypted_payload\":\"%s\"}", encrypted_config_payload);
    free(encrypted_config_payload);
    
    fprintf(stderr, "[DEBUG] Requesting configuration...\n");
    char *config_response = http_post_plain(controller_host, controller_port,
        controller_get_configuration_path, config_request, &response_length);
    
    if (config_response == NULL) {
        fprintf(stderr, "[ERROR] Failed to get configuration\n");
        free(symmetric_key_b64);
        return NULL;
    }
    
    body = extract_http_body(config_response, response_length, &body_length);
    free(config_response);
    
    char *encrypted_config = extract_field_from_json(body, "encrypted_response");
    free(body);
    
    char *config_json = aes_decrypt(encrypted_config, symmetric_key);
    free(encrypted_config);
    
    if (config_json == NULL) {
        fprintf(stderr, "[ERROR] Failed to decrypt configuration\n");
        free(symmetric_key_b64);
        return NULL;
    }
    fprintf(stderr, "[DEBUG] Received configuration\n");

    /* Parse configuration */
    config = calloc(1, sizeof(repetitor_configuration_t));
    if (config == NULL) {
        free(config_json);
        free(symmetric_key_b64);
        return NULL;
    }
    
    config->left_repetitor_url = extract_field_from_json(config_json, "left_repetitor_url");
    config->right_repetitor_url = extract_field_from_json(config_json, "right_repetitor_url");
    config->left_repetitor_id = extract_field_from_json(config_json, "left_repetitor_id");
    config->right_repetitor_id = extract_field_from_json(config_json, "right_repetitor_id");
    config->left_kme = extract_field_from_json(config_json, "left_kme");
    config->right_kme = extract_field_from_json(config_json, "right_kme");
    config->left_kme_url = extract_field_from_json(config_json, "left_kme_url");
    config->right_kme_url = extract_field_from_json(config_json, "right_kme_url");
    config->left_cn = extract_field_from_json(config_json, "left_cn");
    config->right_cn = extract_field_from_json(config_json, "right_cn");
    config->left_kme_peer = extract_field_from_json(config_json, "left_kme_peer");
    config->right_kme_peer = extract_field_from_json(config_json, "right_kme_peer");
    config->whitelist = extract_field_from_json(config_json, "whitelist");
    free(config_json);

    /* Step 6: Generate keys and CSRs */
    fprintf(stderr, "[DEBUG] Generating keys and CSRs...\n");
    
    char *left_key = generate_rsa_key_pem(2048);
    char *right_key = generate_rsa_key_pem(2048);
    char *repetitor_key = generate_rsa_key_pem(2048);
    
    if (left_key == NULL || right_key == NULL || repetitor_key == NULL) {
        fprintf(stderr, "[ERROR] Failed to generate keys\n");
        free(left_key); free(right_key); free(repetitor_key);
        free_repetitor_configuration(config);
        free(symmetric_key_b64);
        return NULL;
    }
    
    config->left_private_key = left_key;
    config->right_private_key = right_key;
    config->repetitor_private_key = repetitor_key;
    
    char *left_csr = create_csr_pem(left_key, config->left_cn);
    char *right_csr = create_csr_pem(right_key, config->right_cn);
    char *repetitor_csr = create_csr_pem(repetitor_key, repetitor_id);
    
    if (left_csr == NULL || right_csr == NULL || repetitor_csr == NULL) {
        fprintf(stderr, "[ERROR] Failed to generate CSRs\n");
        free(left_csr); free(right_csr); free(repetitor_csr);
        free_repetitor_configuration(config);
        free(symmetric_key_b64);
        return NULL;
    }

    /* JSON-escape the CSRs */
    char *left_csr_escaped = pem_to_json_escaped(left_csr);
    char *right_csr_escaped = pem_to_json_escaped(right_csr);
    char *repetitor_csr_escaped = pem_to_json_escaped(repetitor_csr);
    free(left_csr); free(right_csr); free(repetitor_csr);

    /* Step 7: Request certificates */
    size_t cert_payload_size = strlen(left_csr_escaped) + strlen(right_csr_escaped) + 
                               strlen(repetitor_csr_escaped) + 512;
    char *cert_payload = malloc(cert_payload_size);
    snprintf(cert_payload, cert_payload_size,
        "{\"repetitor_id\":\"%s\",\"left_csr\":\"%s\",\"right_csr\":\"%s\",\"repetitor_csr\":\"%s\"}",
        repetitor_id, left_csr_escaped, right_csr_escaped, repetitor_csr_escaped);
    free(left_csr_escaped); free(right_csr_escaped); free(repetitor_csr_escaped);
    
    char *encrypted_cert_payload = aes_encrypt(cert_payload, symmetric_key);
    free(cert_payload);
    
    if (encrypted_cert_payload == NULL) {
        fprintf(stderr, "[ERROR] Failed to encrypt certificate payload\n");
        free_repetitor_configuration(config);
        free(symmetric_key_b64);
        return NULL;
    }
    
    size_t cert_request_size = strlen(encrypted_cert_payload) + 64;
    char *cert_request = malloc(cert_request_size);
    snprintf(cert_request, cert_request_size, "{\"encrypted_payload\":\"%s\"}", encrypted_cert_payload);
    free(encrypted_cert_payload);
    
    fprintf(stderr, "[DEBUG] Requesting certificates...\n");
    char *cert_response = http_post_plain(controller_host, controller_port,
        controller_generate_certificates_path, cert_request, &response_length);
    free(cert_request);
    
    if (cert_response == NULL) {
        fprintf(stderr, "[ERROR] Failed to get certificates\n");
        free_repetitor_configuration(config);
        free(symmetric_key_b64);
        return NULL;
    }
    
    body = extract_http_body(cert_response, response_length, &body_length);
    free(cert_response);
    
    char *encrypted_certs = extract_field_from_json(body, "encrypted_response");
    free(body);
    
    char *certs_json = aes_decrypt(encrypted_certs, symmetric_key);
    free(encrypted_certs);
    free(symmetric_key_b64);
    
    if (certs_json == NULL) {
        fprintf(stderr, "[ERROR] Failed to decrypt certificates response\n");
        free_repetitor_configuration(config);
        return NULL;
    }
    
    config->left_certificate = extract_field_from_json(certs_json, "left_certificate");
    config->right_certificate = extract_field_from_json(certs_json, "right_certificate");
    config->repetitor_certificate = extract_field_from_json(certs_json, "repetitor_certificate");
    free(certs_json);
    
    if (config->left_certificate == NULL || config->right_certificate == NULL || 
        config->repetitor_certificate == NULL) {
        fprintf(stderr, "[ERROR] Failed to extract certificates\n");
        free_repetitor_configuration(config);
        return NULL;
    }
    
    fprintf(stderr, "[DEBUG] Successfully received all certificates\n");
    return config;
}


/* ========== HTTPS and KME Functions ========== */

char* https_get_with_client(
    const char *host, const char *port, const char *path,
    const char *host_sni, const char *ca_pem, 
    const char *cert_pem, const char *key_pem, long *out_length
) {
    WOLFSSL_CTX *ctx = create_ssl_context_native(0, cert_pem, key_pem, ca_pem, 1);
    if (ctx == NULL) return NULL;

    int socket_fd = tcp_connect(host, port);
    if (socket_fd < 0) { wolfSSL_CTX_free(ctx); return NULL; }

    WOLFSSL *ssl = wolfSSL_new(ctx);
    if (ssl == NULL) { close(socket_fd); wolfSSL_CTX_free(ctx); return NULL; }

    wolfSSL_set_fd(ssl, socket_fd);
    wolfSSL_UseSNI(ssl, WOLFSSL_SNI_HOST_NAME, host_sni, (word16)strlen(host_sni));
    wolfSSL_set_verify(ssl, WOLFSSL_VERIFY_NONE, NULL);

    if (wolfSSL_connect(ssl) != WOLFSSL_SUCCESS) {
        wolfSSL_free(ssl); close(socket_fd); wolfSSL_CTX_free(ctx);
        return NULL;
    }

    char request[1024];
    int header_len = snprintf(request, sizeof(request),
        "GET %s HTTP/1.1\r\nHost: %s\r\nAccept: application/json\r\nConnection: close\r\n\r\n",
        path, host_sni);

    if (wolfSSL_write(ssl, request, header_len) <= 0) {
        wolfSSL_free(ssl); close(socket_fd); wolfSSL_CTX_free(ctx);
        return NULL;
    }

    size_t capacity = 8192, length = 0;
    char *response = calloc(capacity, 1);
    if (response == NULL) {
        wolfSSL_free(ssl); close(socket_fd); wolfSSL_CTX_free(ctx);
        return NULL;
    }

    while (1) {
        char buffer[4096];
        int bytes_read = wolfSSL_read(ssl, buffer, sizeof(buffer));
        if (bytes_read <= 0) break;
        if (length + bytes_read + 1 > capacity) {
            capacity *= 2;
            char *tmp = realloc(response, capacity);
            if (tmp == NULL) { free(response); break; }
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

int get_status_of_kme(
    const char *key_pem, const char *cert_pem, const char *ca_pem,
    const char *kme_host, const char *kme_port,
    const char *kme_host_sni, const char *kme_slave
) {
    char path[128];
    snprintf(path, sizeof(path), "/api/v1/keys/%s/status", kme_slave);

    long len;
    char *response = https_get_with_client(kme_host, kme_port, path, kme_host_sni,
        ca_pem, cert_pem, key_pem, &len);
    
    printf("STATUS: %s\n", response ? response : "(null)");
    int result = (response && strstr(response, "200 OK")) ? 0 : 1;
    free(response);
    return result;
}

char* get_key_with_id(
    const char *key_pem, const char *cert_pem, const char *ca_pem,
    const char *kme_host, const char *kme_port,
    const char *kme_host_sni, const char *kme_master, const char *key_id
) {
    char path[256];
    snprintf(path, sizeof(path), "/api/v1/keys/%s/dec_keys?key_ID=%s", kme_master, key_id);

    long len;
    char *response = https_get_with_client(kme_host, kme_port, path, kme_host_sni,
        ca_pem, cert_pem, key_pem, &len);
    if (response == NULL) return NULL;
    
    char *body = get_last_line(response);
    free(response);
    if (body == NULL) return NULL;
    
    char *key = extract_field_from_json(body, "key");
    free(body);
    return key;
}

void get_key(
    const char *key_pem, const char *cert_pem, const char *ca_pem,
    const char *kme_host, const char *kme_port,
    const char *kme_host_sni, const char *kme_slave,
    int key_count, int key_size, char **out_key, char **out_key_id
) {
    char path[256];
    snprintf(path, sizeof(path), "/api/v1/keys/%s/enc_keys?number=%d&size=%d",
        kme_slave, key_count, key_size);

    long len;
    char *response = https_get_with_client(kme_host, kme_port, path, kme_host_sni,
        ca_pem, cert_pem, key_pem, &len);
    
    if (response == NULL) { *out_key = NULL; *out_key_id = NULL; return; }
    
    char *body = get_last_line(response);
    free(response);
    if (body == NULL) { *out_key = NULL; *out_key_id = NULL; return; }
    
    *out_key = extract_field_from_json(body, "key");
    *out_key_id = extract_field_from_json(body, "key_ID");
    free(body);
}

/* Encryption/decryption for message relay */
char* decode_key(char *text, size_t *len_out) {
    int all_hex = 1;
    for (char *p = text; *p; ++p) {
        if (!isxdigit((unsigned char)*p)) { all_hex = 0; break; }
    }
    if (all_hex && (strlen(text) & 1) == 0) {
        return (char*)hex_to_binary(text, len_out);
    }
    return base64_decode(text, len_out);
}

static int hmac_sha256(const unsigned char* key, int key_len,
    const unsigned char* data, int data_len, unsigned char out[32]) {
    Hmac hmac;
    if (wc_HmacInit(&hmac, NULL, INVALID_DEVID) != 0) return -1;
    if (wc_HmacSetKey(&hmac, WC_SHA256, key, key_len) != 0) { wc_HmacFree(&hmac); return -1; }
    if (wc_HmacUpdate(&hmac, data, data_len) != 0) { wc_HmacFree(&hmac); return -1; }
    int ret = wc_HmacFinal(&hmac, out);
    wc_HmacFree(&hmac);
    return ret;
}

char *decrypt(const char *base64_cipher, const char *key_text) {
    size_t key_length = 0;
    unsigned char *key_binary = (unsigned char*)decode_key((char*)key_text, &key_length);
    if (key_binary == NULL) return NULL;

    unsigned char aes_key[32] = {0}, hmac_key[32] = {0};
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

    size_t blob_length = 0;
    unsigned char *blob = (unsigned char*)base64_decode(base64_cipher, &blob_length);
    if (blob == NULL || blob_length < 32 + 64) { free(blob); return NULL; }

    char iv_hex[33] = {0};
    memcpy(iv_hex, blob, 32);
    const char *tag_hex = (char*)blob + blob_length - 64;
    size_t ct_len = blob_length - 32 - 64;

    char *ct_b64 = malloc(ct_len + 1);
    memcpy(ct_b64, blob + 32, ct_len);
    ct_b64[ct_len] = '\0';

    unsigned char calc_tag[32];
    hmac_sha256(hmac_key, 32, (unsigned char*)ct_b64, (int)ct_len, calc_tag);
    char calc_tag_hex[65];
    bytes_to_hex(calc_tag, 32, calc_tag_hex);
    if (memcmp(calc_tag_hex, tag_hex, 64) != 0) { free(blob); free(ct_b64); return NULL; }

    size_t iv_len;
    unsigned char *iv = hex_to_binary(iv_hex, &iv_len);
    size_t ct_bin_len;
    unsigned char *ct_bin = (unsigned char*)base64_decode(ct_b64, &ct_bin_len);
    free(ct_b64); free(blob);

    unsigned char *pt = malloc(ct_bin_len + 1);
    Aes aes;
    wc_AesInit(&aes, NULL, INVALID_DEVID);
    wc_AesSetKey(&aes, aes_key, 32, iv, AES_DECRYPTION);
    wc_AesCbcDecrypt(&aes, pt, ct_bin, (word32)ct_bin_len);
    wc_AesFree(&aes);
    free(iv); free(ct_bin);

    int unpad = pkcs7_unpad(pt, (int)ct_bin_len);
    if (unpad < 0) { free(pt); return NULL; }
    pt[unpad] = '\0';
    return (char*)pt;
}

char *encrypt(const char *plaintext, const char *key_text) {
    size_t key_length = 0;
    unsigned char *key_binary = (unsigned char*)decode_key((char*)key_text, &key_length);
    if (key_binary == NULL) return NULL;

    unsigned char aes_key[32] = {0}, hmac_key[32] = {0};
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

    unsigned char iv[16];
    random_bytes(iv, 16);
    char iv_hex[33];
    bytes_to_hex(iv, 16, iv_hex);

    int pt_len = (int)strlen(plaintext);
    int pad_len = pt_len + (16 - (pt_len % 16));
    unsigned char *padded = calloc(pad_len, 1);
    memcpy(padded, plaintext, pt_len);
    pkcs7_pad(padded, pt_len, 16);

    unsigned char *ct = malloc(pad_len);
    Aes aes;
    wc_AesInit(&aes, NULL, INVALID_DEVID);
    wc_AesSetKey(&aes, aes_key, 32, iv, AES_ENCRYPTION);
    wc_AesCbcEncrypt(&aes, ct, padded, pad_len);
    wc_AesFree(&aes);
    free(padded);

    char *ct_b64 = base64_encode(ct, pad_len);
    free(ct);

    unsigned char tag[32];
    hmac_sha256(hmac_key, 32, (unsigned char*)ct_b64, (int)strlen(ct_b64), tag);
    char tag_hex[65];
    bytes_to_hex(tag, 32, tag_hex);

    size_t blob_len = 32 + strlen(ct_b64) + 64;
    char *blob = malloc(blob_len + 1);
    sprintf(blob, "%s%s%s", iv_hex, ct_b64, tag_hex);
    free(ct_b64);

    char *result = base64_encode((unsigned char*)blob, (int)blob_len);
    free(blob);
    return result;
}


/* ========== Message Functions ========== */

int send_message(
    const char *key_pem, const char *cert_pem, const char *ca_pem,
    const char *host, const char *port, const char *body
) {
    WOLFSSL_CTX *ctx = create_ssl_context_native(0, cert_pem, key_pem, ca_pem, 0);
    if (ctx == NULL) return -1;

    int socket_fd = tcp_connect(host, port);
    if (socket_fd < 0) { wolfSSL_CTX_free(ctx); return -1; }

    WOLFSSL *ssl = wolfSSL_new(ctx);
    if (ssl == NULL) { close(socket_fd); wolfSSL_CTX_free(ctx); return -1; }

    wolfSSL_set_fd(ssl, socket_fd);
    if (wolfSSL_connect(ssl) != WOLFSSL_SUCCESS) {
        wolfSSL_free(ssl); close(socket_fd); wolfSSL_CTX_free(ctx);
        return -1;
    }

    size_t len = strlen(body);
    while (len > 0) {
        int written = wolfSSL_write(ssl, body, (int)len);
        if (written <= 0) break;
        body += written;
        len -= written;
    }

    char buf[1024];
    wolfSSL_read(ssl, buf, sizeof(buf));
    wolfSSL_shutdown(ssl);
    wolfSSL_free(ssl);
    close(socket_fd);
    wolfSSL_CTX_free(ctx);
    return 0;
}

message_t read_message(WOLFSSL_CTX *ctx, int client_fd) {
    message_t result = { NULL, NULL };

    WOLFSSL *ssl = wolfSSL_new(ctx);
    if (ssl == NULL) return result;

    wolfSSL_set_fd(ssl, client_fd);
    if (wolfSSL_accept(ssl) != WOLFSSL_SUCCESS) {
        wolfSSL_free(ssl);
        return result;
    }

    result.subject = get_peer_cn(ssl);
    if (result.subject == NULL) {
        wolfSSL_shutdown(ssl);
        wolfSSL_free(ssl);
        return result;
    }

    char buf[1024] = {0};
    int bytes = wolfSSL_read(ssl, buf, sizeof(buf) - 1);
    wolfSSL_write(ssl, "RECEIVED", 8);

    if (bytes > 0) {
        result.message = calloc(bytes + 1, 1);
        memcpy(result.message, buf, bytes);
    }

    wolfSSL_shutdown(ssl);
    wolfSSL_free(ssl);
    return result;
}

/* ========== Main Function ========== */

int main(int argc, char *argv[]) {
    // char *repetitor_id = "riscv-repetitor-1";
    char *repetitor_id = "DR1";
    int port = 9001;
    
    if (argc >= 3) {
        repetitor_id = argv[1];
        port = atoi(argv[2]);
    }

    char repetitor_url[64];
    snprintf(repetitor_url, sizeof(repetitor_url), "127.0.0.1:%d", port);

    wolfSSL_Init();

    wolfSSL_Debugging_ON();
    
    fprintf(stderr, "Getting configuration with secure protocol...\n");
    repetitor_configuration_t *config = get_repetitor_configuration(
        CONTROLLER_HOST, CONTROLLER_PORT,
        CONTROLLER_GET_NONCE_PATH,
        CONTROLLER_GET_CONFIGURATION_PATH,
        CONTROLLER_GENERATE_CERTIFICATES_PATH,
        repetitor_id, repetitor_url
    );
    
    if (config == NULL) {
        fprintf(stderr, "Failed to get configuration\n");
        wolfSSL_Cleanup();
        return 1;
    }
    fprintf(stderr, "Configuration loaded successfully\n");
    fprintf(stderr, "Keys generated\nCertificates received\n");

    /* Check KME status */
    if (config->left_kme && strlen(config->left_kme) > 0) {
        if (get_status_of_kme(config->left_private_key, config->left_certificate,
            QKD_CA_CERTIFICATE, config->left_kme_url, KME_PORT,
            config->left_kme, config->left_kme_peer) != 0) {
            fprintf(stderr, "Left KME status check failed\n");
            goto cleanup;
        }
    }

    if (config->right_kme && strlen(config->right_kme) > 0) {
        if (get_status_of_kme(config->right_private_key, config->right_certificate,
            QKD_CA_CERTIFICATE, config->right_kme_url, KME_PORT,
            config->right_kme, config->right_kme_peer) != 0) {
            fprintf(stderr, "Right KME status check failed\n");
            goto cleanup;
        }
    }

    int listen_fd = create_listen_socket((uint16_t)port);
    if (listen_fd < 0) {
        fprintf(stderr, "Failed to create listen socket\n");
        goto cleanup;
    }

    WOLFSSL_CTX *server_ctx = create_ssl_context_native(1,
        config->repetitor_certificate, config->repetitor_private_key,
        REPETITOR_CA_CERTIFICATE, 0);
    
    if (server_ctx == NULL) {
        fprintf(stderr, "Failed to create server SSL context\n");
        close(listen_fd);
        goto cleanup;
    }
    fprintf(stderr, "[DEBUG] Server listening on port %d\n", port);

    signal(SIGINT, handle_sigint);

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
            free(msg.message); free(msg.subject);
            continue;
        }

        if (config->whitelist == NULL || strstr(config->whitelist, msg.subject) == NULL) {
            fprintf(stderr, "[DEBUG] Subject %s not in whitelist\n", msg.subject);
            free(msg.message); free(msg.subject);
            continue;
        }

        fprintf(stderr, "[DEBUG] Read message: %s from %s\n", msg.message, msg.subject);

        int is_left = config->left_repetitor_id && 
                      strcmp(msg.subject, config->left_repetitor_id) == 0;
        
        const char *to_url = is_left ? config->right_repetitor_url : config->left_repetitor_url;
        const char *kme_master = is_left ? config->left_kme : config->right_kme;
        const char *kme_slave = is_left ? config->right_kme : config->left_kme;
        const char *kme_master_url = is_left ? config->left_kme_url : config->right_kme_url;
        const char *kme_slave_url = is_left ? config->right_kme_url : config->left_kme_url;
        const char *kme_master_sni = is_left ? config->left_kme : config->right_kme;
        const char *kme_slave_sni = is_left ? config->right_kme : config->left_kme;
        const char *kme_master_peer = is_left ? config->left_kme_peer : config->right_kme_peer;
        const char *kme_slave_peer = is_left ? config->right_kme_peer : config->left_kme_peer;
        const char *master_key = is_left ? config->left_private_key : config->right_private_key;
        const char *master_cert = is_left ? config->left_certificate : config->right_certificate;
        const char *slave_key = is_left ? config->right_private_key : config->left_private_key;
        const char *slave_cert = is_left ? config->right_certificate : config->left_certificate;

        char *from_key_id = extract_field_from_json(msg.message, "key_ID");
        char *from_ciphertext = extract_field_from_json(msg.message, "message");
        
        char *plaintext = NULL;
        
        if (kme_master && strlen(kme_master) > 0 && from_key_id && strlen(from_key_id) > 0) {
            char *from_key = get_key_with_id(master_key, master_cert,
                QKD_CA_CERTIFICATE, kme_master_url, KME_PORT,
                kme_master_sni, kme_master_peer, from_key_id);
            
            if (from_key != NULL) {
                plaintext = decrypt(from_ciphertext, from_key);
                free(from_key);
            }
        } else if (from_ciphertext) {
            plaintext = strdup(from_ciphertext);
        }
        
        free(from_key_id); free(from_ciphertext);

        if (plaintext == NULL) {
            free(msg.message); free(msg.subject);
            continue;
        }

        fprintf(stderr, "[DEBUG] Decrypted message: %s\n", plaintext);

        char *to_ciphertext = NULL;
        char *to_key_id = NULL;

        if (kme_slave && strlen(kme_slave) > 0) {
            char *to_key = NULL;
            get_key(slave_key, slave_cert, QKD_CA_CERTIFICATE,
                kme_slave_url, KME_PORT, kme_slave_sni, kme_slave_peer,
                1, 1024, &to_key, &to_key_id);
            
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
            free(to_key_id); free(msg.message); free(msg.subject);
            continue;
        }

        char body[2048];
        snprintf(body, sizeof(body), "{\"message\":\"%s\",\"key_ID\":\"%s\"}\n",
            to_ciphertext, to_key_id ? to_key_id : "");
        free(to_ciphertext); free(to_key_id);

        fprintf(stderr, "[DEBUG] Sending body: %s\n", body);

        char *to_ip = get_ip_address(to_url);
        char *to_port_str = get_port(to_url);
        
        if (to_ip && to_port_str) {
            send_message(config->repetitor_private_key, config->repetitor_certificate,
                REPETITOR_CA_CERTIFICATE, to_ip, to_port_str, body);
            fprintf(stderr, "[DEBUG] Message sent\n");
        }
        
        free(to_ip); free(to_port_str);
        free(msg.message); free(msg.subject);
    }
    
    wolfSSL_Debugging_OFF();

    wolfSSL_CTX_free(server_ctx);
    close(listen_fd);

cleanup:
    free_repetitor_configuration(config);
    cleanup_rng();
    wolfSSL_Cleanup();
    return 0;
}
