/*
 * QKD Relay Repetitor - Hybrid PQC/RSA Version (WolfSSL-only mTLS)
 *
 * Based on eapp_hybrid.c. Key changes:
 *   - liboqs dependency removed; WolfSSL handles ML-KEM, ML-DSA, and TLS
 *   - PQC channel (old manual Kyber+ML-DSA handshake) replaced with WolfSSL mTLS
 *   - PQC certificates are now standard X.509 DER (-----BEGIN CERTIFICATE-----)
 *   - verify_pqc_certificate replaced with X.509 DER parser + WolfSSL ML-DSA verify
 *
 * ============================================================================
 * BUILD INSTRUCTIONS
 * ============================================================================
 *
 *   gcc -o eapp_final eapp_final.c \
 *       -I/home/dj/Desktop/wolfssl/_install_linux/include \
 *       -L/home/dj/Desktop/wolfssl/_install_linux/lib \
 *       -lwolfssl -lm -lpthread
 *
 *   export LD_LIBRARY_PATH=/home/dj/Desktop/wolfssl/_install_linux/lib
 *   ./eapp_final DR1 9001
 *
 * ============================================================================
 */

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/kdf.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/coding.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/wc_mlkem.h>
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
#define MLDSA65_SIG_SIZE            MLDSA65_SIGNATURE_SIZE

#define MAX_BUFFER_SIZE     131072
#define MAX_CERT_SIZE       32768
#define MAX_JSON_SIZE       131072
#define MAX_URL_SIZE        256
#define MAX_CN_SIZE         128
#define MAX_HTTP_RESPONSE   131072

#define CTRL_TLS_PORT       8001    /* WolfSSL TLS port for controller protocol */

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
// const char *CONTROLLER_HOST = "192.168.100.2";
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
    char *left_kme_url;   /* IP address for left KME (avoids gethostbyname / futex) */
    char *right_kme_url;  /* IP address for right KME */
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

static int x509_verify_cert(const unsigned char *cert_der, int cert_len,
                             const unsigned char *ca_pk);

/* ==================== DER Parser ==================== */

/*
 * Read DER length field at d[*pos], advance *pos past it.
 * Returns decoded length, or -1 on error.
 */
static int _der_len(const unsigned char *d, int dlen, int *pos) {
    if (*pos >= dlen) return -1;
    int first = (int)(unsigned char)d[(*pos)++];
    if (first < 0x80) return first;
    int n_bytes = first & 0x7F;
    if (n_bytes == 0 || n_bytes > 3 || *pos + n_bytes > dlen) return -1;
    int length = 0;
    for (int i = 0; i < n_bytes; i++)
        length = (length << 8) | (unsigned char)d[(*pos)++];
    return length;
}

/*
 * Read DER TLV at d[*pos].  After the call:
 *   *vs  = index of value (first byte after tag+length)
 *   *vl  = length of value
 *   *pos == *vs  (caller must advance *pos past value manually)
 * Returns tag byte, or -1 on error.
 */
static int _der_tlv(const unsigned char *d, int dlen, int *pos, int *vs, int *vl) {
    if (*pos >= dlen) return -1;
    int tag = (int)(unsigned char)d[(*pos)++];
    int len = _der_len(d, dlen, pos);
    if (len < 0 || *pos + len > dlen) return -1;
    *vs = *pos;
    *vl = len;
    return tag;
}

/*
 * Skip a complete DER TLV (tag + length + value) at d[*pos].
 * Advances *pos past the whole TLV.
 * Returns 0 on success, -1 on error.
 */
static int _der_skip(const unsigned char *d, int dlen, int *pos) {
    if (*pos >= dlen) return -1;
    (*pos)++;                          /* skip tag */
    int len = _der_len(d, dlen, pos); /* skip length bytes */
    if (len < 0 || *pos + len > dlen) return -1;
    *pos += len;                       /* skip value */
    return 0;
}

/*
 * Parse a DER-encoded X.509 Name (the raw content bytes of a SEQUENCE OF SET).
 * Extracts the CN attribute into cn[].
 */
static void _x509_parse_name(const unsigned char *name, int name_len, char *cn) {
    static const unsigned char cn_oid[] = {0x55, 0x04, 0x03};
    cn[0] = '\0';

    int pos = 0;
    while (pos < name_len) {
        /* Each entry is a SET */
        int set_vs, set_vl;
        int tag = _der_tlv(name, name_len, &pos, &set_vs, &set_vl);
        if (tag < 0) break;
        int after_set = set_vs + set_vl;

        if (tag == 0x31) {
            int seq_pos = set_vs;
            while (seq_pos < after_set) {
                int seq_vs, seq_vl;
                tag = _der_tlv(name, name_len, &seq_pos, &seq_vs, &seq_vl);
                if (tag < 0) break;
                int after_seq = seq_vs + seq_vl;

                if (tag == 0x30) {
                    int attr_pos = seq_vs;

                    /* Read OID */
                    int oid_vs, oid_vl;
                    int oid_tag = _der_tlv(name, name_len, &attr_pos, &oid_vs, &oid_vl);
                    if (oid_tag == 0x06) {
                        attr_pos = oid_vs + oid_vl;  /* advance past OID value */

                        if (oid_vl == 3 && memcmp(name + oid_vs, cn_oid, 3) == 0) {
                            /* Next TLV is the CN value */
                            int val_vs, val_vl;
                            _der_tlv(name, name_len, &attr_pos, &val_vs, &val_vl);
                            if (val_vl > 0 && val_vl < MAX_CN_SIZE) {
                                memcpy(cn, name + val_vs, val_vl);
                                cn[val_vl] = '\0';
                                return;
                            }
                        }
                    }
                }
                seq_pos = after_seq;
            }
        }
        pos = after_set;
    }
}

/*
 * Parse a DER-encoded X.509 certificate.
 *
 * Outputs (all may be NULL to skip):
 *   subject_cn  - null-terminated CN string (MAX_CN_SIZE)
 *   public_key  - raw SubjectPublicKey bytes (without leading 0x00 unused-bits byte)
 *   pub_key_len - length of public_key
 *   tbs_out     - pointer into der[] for TBSCertificate TLV (tag+len+value)
 *   tbs_len_out - byte length of TBSCertificate TLV
 *   sig_out     - pointer into der[] for signature bytes (after unused-bits byte)
 *   sig_len_out - byte length of signature
 *
 * Returns 0 on success, -1 on parse error.
 */
static int x509_parse_cert(const unsigned char *der, int der_len,
                            char *subject_cn,
                            unsigned char *public_key, int *pub_key_len,
                            const unsigned char **tbs_out, int *tbs_len_out,
                            const unsigned char **sig_out, int *sig_len_out) {
    int pos = 0;

    /* Outer Certificate SEQUENCE */
    int cert_vs, cert_vl;
    if (_der_tlv(der, der_len, &pos, &cert_vs, &cert_vl) != 0x30) return -1;

    /* TBSCertificate SEQUENCE starts at cert_vs */
    int tbs_tlv_start = cert_vs;
    pos = cert_vs;

    int tbs_vs, tbs_vl;
    if (_der_tlv(der, der_len, &pos, &tbs_vs, &tbs_vl) != 0x30) return -1;

    /* TBS TLV: der[tbs_tlv_start .. tbs_vs+tbs_vl-1] */
    if (tbs_out)     *tbs_out     = der + tbs_tlv_start;
    if (tbs_len_out) *tbs_len_out = (tbs_vs + tbs_vl) - tbs_tlv_start;

    /* Advance past TBS to signatureAlgorithm */
    pos = tbs_vs + tbs_vl;

    /* Skip signatureAlgorithm */
    if (_der_skip(der, der_len, &pos) != 0) return -1;

    /* Read signature BIT STRING */
    int sig_bs_vs, sig_bs_vl;
    if (_der_tlv(der, der_len, &pos, &sig_bs_vs, &sig_bs_vl) != 0x03) return -1;
    if (sig_bs_vl < 2) return -1;
    if (sig_out)     *sig_out     = der + sig_bs_vs + 1;  /* skip unused-bits byte */
    if (sig_len_out) *sig_len_out = sig_bs_vl - 1;

    /* ----- Parse TBS contents ----- */
    int tbs_pos = tbs_vs;

    /* Skip [0] EXPLICIT version if present */
    if (tbs_pos < tbs_vs + tbs_vl && (unsigned char)der[tbs_pos] == 0xA0) {
        if (_der_skip(der, der_len, &tbs_pos) != 0) return -1;
    }

    /* Skip serialNumber (INTEGER) */
    if (_der_skip(der, der_len, &tbs_pos) != 0) return -1;

    /* Skip signatureAlgorithm (SEQUENCE) */
    if (_der_skip(der, der_len, &tbs_pos) != 0) return -1;

    /* Skip issuer (SEQUENCE) */
    if (_der_skip(der, der_len, &tbs_pos) != 0) return -1;

    /* Skip validity (SEQUENCE) */
    if (_der_skip(der, der_len, &tbs_pos) != 0) return -1;

    /* Subject (SEQUENCE) */
    int subj_vs, subj_vl;
    if (_der_tlv(der, der_len, &tbs_pos, &subj_vs, &subj_vl) != 0x30) return -1;
    tbs_pos = subj_vs + subj_vl;

    if (subject_cn) {
        _x509_parse_name(der + subj_vs, subj_vl, subject_cn);
    }

    /* SubjectPublicKeyInfo (SEQUENCE) */
    int spki_vs, spki_vl;
    if (_der_tlv(der, der_len, &tbs_pos, &spki_vs, &spki_vl) != 0x30) return -1;

    int spki_pos = spki_vs;
    /* Skip AlgorithmIdentifier */
    if (_der_skip(der, der_len, &spki_pos) != 0) return -1;

    /* BIT STRING containing public key */
    int pk_bs_vs, pk_bs_vl;
    if (_der_tlv(der, der_len, &spki_pos, &pk_bs_vs, &pk_bs_vl) != 0x03) return -1;
    if (pk_bs_vl < 1) return -1;

    int pk_len = pk_bs_vl - 1;  /* skip leading unused-bits byte */
    if (public_key && pk_len > 0) {
        memcpy(public_key, der + pk_bs_vs + 1, pk_len);
    }
    if (pub_key_len) *pub_key_len = pk_len;

    return 0;
}

/*
 * WolfSSL's TLS X.509 cert-chain verifier returns ASN_SIG_CONFIRM_E (-155)
 * for ML-DSA-65 certs even when compiled with --enable-dilithium.  The raw
 * crypto works but the X.509/TLS integration does not.  We bypass the
 * handshake-level check with _pqc_verify_accept_all and verify manually
 * after the handshake with _pqc_verify_peer.
 */
static int _pqc_verify_accept_all(int preverify_ok, WOLFSSL_X509_STORE_CTX *ctx)
{
    (void)preverify_ok; (void)ctx;
    return 1;
}

static int _pqc_verify_peer(WOLFSSL *ssl,
                             const unsigned char *ca_der, int ca_len)
{
    WOLFSSL_X509 *peer = wolfSSL_get_peer_certificate(ssl);
    if (!peer) return -1;

    int der_len = 0;
    const unsigned char *der = wolfSSL_X509_get_der(peer, &der_len);
    if (!der || der_len <= 0) { wolfSSL_X509_free(peer); return -1; }

    char ca_cn[MAX_CN_SIZE];
    unsigned char ca_pk[MLDSA65_PUBLIC_KEY_SIZE];
    int ca_pk_len;
    const unsigned char *dummy_tbs, *dummy_sig;
    int dummy_tbs_len, dummy_sig_len;
    if (x509_parse_cert(ca_der, ca_len, ca_cn, ca_pk, &ca_pk_len,
                        &dummy_tbs, &dummy_tbs_len,
                        &dummy_sig, &dummy_sig_len) != 0) {
        wolfSSL_X509_free(peer); return -1;
    }

    int ret = x509_verify_cert(der, der_len, ca_pk);
    wolfSSL_X509_free(peer);
    return ret;
}

/* ==================== WolfSSL TLS Helpers ==================== */

/* Write exactly len bytes to a WolfSSL connection */
static int tls_write_exact(WOLFSSL *ssl, const unsigned char *data, int len) {
    int sent = 0;
    while (sent < len) {
        int n = wolfSSL_write(ssl, data + sent, len - sent);
        if (n <= 0) return -1;
        sent += n;
    }
    return 0;
}

/* Read exactly len bytes from a WolfSSL connection */
static int tls_read_exact(WOLFSSL *ssl, unsigned char *buf, int len) {
    int received = 0;
    while (received < len) {
        int n = wolfSSL_read(ssl, buf + received, len - received);
        if (n <= 0) return -1;
        received += n;
    }
    return 0;
}

/* Receive a length-prefixed message over TLS.
 * Returns heap-allocated buffer (caller must free), sets *msg_len.
 * Returns NULL on error. */
static unsigned char *tls_recv_msg(WOLFSSL *ssl, int *msg_len) {
    uint32_t net_len;
    if (tls_read_exact(ssl, (unsigned char*)&net_len, 4) != 0) return NULL;

    int len = (int)ntohl(net_len);
    if (len <= 0 || len > MAX_BUFFER_SIZE) return NULL;

    unsigned char *buf = malloc(len + 1);
    if (!buf) return NULL;

    if (tls_read_exact(ssl, buf, len) != 0) { free(buf); return NULL; }
    buf[len] = '\0';
    *msg_len = len;
    return buf;
}

/*
 * Build a WolfSSL CTX for mTLS.
 *   is_server  : 1 = server, 0 = client
 *   cert_der   : own certificate (DER)
 *   pkcs8_key  : own private key (PKCS#8 DER)
 *   ca_der     : CA certificate for peer verification (DER)
 */
/* Send a length-prefixed message (4-byte big-endian length header) over TLS */
static int tls_send_msg(WOLFSSL *ssl, const unsigned char *data, int len) {
    uint32_t net_len = htonl((uint32_t)len);
    if (tls_write_exact(ssl, (unsigned char*)&net_len, 4) != 0) return -1;
    return tls_write_exact(ssl, data, len);
}

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

char *extract_json_nested_string(const char *json, const char *parent, const char *field) {
    char parent_pattern[256];
    snprintf(parent_pattern, sizeof(parent_pattern), "\"%s\"", parent);

    const char *parent_pos = strstr(json, parent_pattern);
    if (!parent_pos) return NULL;

    parent_pos += strlen(parent_pattern);
    while (*parent_pos == ' ' || *parent_pos == '\t' || *parent_pos == ':') parent_pos++;

    if (*parent_pos != '{') {
        return extract_json_string(parent_pos, field);
    }

    const char *obj_start = parent_pos;
    int brace_count = 1;
    const char *obj_end = parent_pos + 1;
    while (*obj_end && brace_count > 0) {
        if (*obj_end == '{') brace_count++;
        else if (*obj_end == '}') brace_count--;
        obj_end++;
    }

    size_t obj_len = obj_end - obj_start;
    char *parent_obj = malloc(obj_len + 1);
    if (!parent_obj) return NULL;

    memcpy(parent_obj, obj_start, obj_len);
    parent_obj[obj_len] = '\0';

    char *result = extract_json_string(parent_obj, field);
    free(parent_obj);

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

char *certificate_json_escape(const char *str) {
    if (!str) return strdup("");

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

int pqc_mlkem_generate_keypair(unsigned char *pk, unsigned char *sk) {
    MlKemKey key;
    int ret;

    ret = wc_MlKemKey_Init(&key, WC_ML_KEM_768, NULL, INVALID_DEVID);
    if (ret != 0) {
        fprintf(stderr, "[ERROR] wc_MlKemKey_Init failed: %d (%s)\n", ret, wc_GetErrorString(ret));
        return ret;
    }

    ret = wc_MlKemKey_MakeKey(&key, &g_rng);
    if (ret != 0) {
        fprintf(stderr, "[ERROR] wc_MlKemKey_MakeKey failed: %d (%s)\n", ret, wc_GetErrorString(ret));
        wc_MlKemKey_Free(&key);
        return ret;
    }

    word32 pk_len = MLKEM768_PUBLIC_KEY_SIZE;
    ret = wc_MlKemKey_EncodePublicKey(&key, pk, pk_len);
    if (ret != 0) {
        fprintf(stderr, "[ERROR] wc_MlKemKey_EncodePublicKey failed: %d (%s)\n", ret, wc_GetErrorString(ret));
        wc_MlKemKey_Free(&key);
        return ret;
    }

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

/* ==================== ML-DSA-65 (Dilithium) Functions - WolfSSL ==================== */

int pqc_mldsa_generate_keypair(unsigned char *pk, unsigned char *sk) {
    dilithium_key key;
    int ret;

    ret = wc_dilithium_init(&key);
    if (ret != 0) { fprintf(stderr, "[ERROR] wc_dilithium_init failed: %d\n", ret); return -1; }

    ret = wc_dilithium_set_level(&key, 3);
    if (ret != 0) { fprintf(stderr, "[ERROR] wc_dilithium_set_level failed: %d\n", ret); wc_dilithium_free(&key); return -1; }

    ret = wc_dilithium_make_key(&key, &g_rng);
    if (ret != 0) { fprintf(stderr, "[ERROR] wc_dilithium_make_key failed: %d\n", ret); wc_dilithium_free(&key); return -1; }

    word32 pk_len = MLDSA65_PUBLIC_KEY_SIZE;
    ret = wc_dilithium_export_public(&key, pk, &pk_len);
    if (ret != 0) { fprintf(stderr, "[ERROR] wc_dilithium_export_public failed: %d\n", ret); wc_dilithium_free(&key); return -1; }

    word32 sk_len = MLDSA65_SECRET_KEY_SIZE;
    ret = wc_dilithium_export_private(&key, sk, &sk_len);
    if (ret != 0) { fprintf(stderr, "[ERROR] wc_dilithium_export_private failed: %d\n", ret); wc_dilithium_free(&key); return -1; }

    wc_dilithium_free(&key);
    return 0;
}

int pqc_mldsa_sign(const unsigned char *sk, const unsigned char *msg, int msg_len,
                   unsigned char *sig, int *sig_len) {
    dilithium_key key;
    int ret;

    ret = wc_dilithium_init(&key);
    if (ret != 0) { fprintf(stderr, "[ERROR] wc_dilithium_init failed: %d\n", ret); return -1; }

    ret = wc_dilithium_set_level(&key, 3);
    if (ret != 0) { wc_dilithium_free(&key); return -1; }

    ret = wc_dilithium_import_private(sk, MLDSA65_SECRET_KEY_SIZE, &key);
    if (ret != 0) { fprintf(stderr, "[ERROR] wc_dilithium_import_private failed: %d\n", ret); wc_dilithium_free(&key); return -1; }

    word32 out_len = MLDSA65_SIG_SIZE;
    ret = wc_dilithium_sign_msg(msg, msg_len, sig, &out_len, &key, &g_rng);
    if (ret != 0) { fprintf(stderr, "[ERROR] wc_dilithium_sign_msg failed: %d\n", ret); wc_dilithium_free(&key); return -1; }

    *sig_len = (int)out_len;
    wc_dilithium_free(&key);
    return 0;
}

int pqc_mldsa_verify(const unsigned char *pk, const unsigned char *msg, int msg_len,
                     const unsigned char *sig, int sig_len) {
    dilithium_key key;
    int ret;

    ret = wc_dilithium_init(&key);
    if (ret != 0) { fprintf(stderr, "[ERROR] wc_dilithium_init failed: %d\n", ret); return -1; }

    ret = wc_dilithium_set_level(&key, 3);
    if (ret != 0) { wc_dilithium_free(&key); return -1; }

    ret = wc_dilithium_import_public(pk, MLDSA65_PUBLIC_KEY_SIZE, &key);
    if (ret != 0) { fprintf(stderr, "[ERROR] wc_dilithium_import_public failed: %d\n", ret); wc_dilithium_free(&key); return -1; }

    int verified = 0;
    ret = wc_dilithium_verify_msg(sig, sig_len, msg, msg_len, &verified, &key);
    wc_dilithium_free(&key);

    if (ret != 0) { fprintf(stderr, "[ERROR] wc_dilithium_verify_msg failed: %d\n", ret); return -1; }
    return (verified == 1) ? 0 : -1;
}

/* ==================== Key Derivation ==================== */

void derive_shared_key(const unsigned char *ss1, const unsigned char *ss2,
                       unsigned char *out_key) {
    unsigned char combined[64];
    memcpy(combined, ss1, MLKEM768_SHARED_SECRET_SIZE);
    memcpy(combined + MLKEM768_SHARED_SECRET_SIZE, ss2, MLKEM768_SHARED_SECRET_SIZE);

    const char *info = "qkd-relay-v1";
    unsigned char zero_salt[32] = {0};

    int ret = wc_HKDF(
        WC_SHA256,
        combined,
        sizeof(combined),
        zero_salt,
        sizeof(zero_salt),
        (const unsigned char*)info,
        strlen(info),
        out_key,
        32
    );

    if (ret != 0) {
        fprintf(stderr, "[ERROR] wc_HKDF failed: %d (%s)\n", ret, wc_GetErrorString(ret));
    }
}

/* ==================== RSA Key Generation ==================== */

int rsa_generate_keypair(unsigned char **der_out, int *der_len) {
    RsaKey key;
    int ret = wc_InitRsaKey(&key, NULL);
    if (ret != 0) return ret;

    ret = wc_MakeRsaKey(&key, 2048, 65537, &g_rng);
    if (ret != 0) { wc_FreeRsaKey(&key); return ret; }

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

    int pemSz = wc_DerToPem(der, derSz, NULL, 0, CERTREQ_TYPE);
    if (pemSz < 0) return NULL;

    char *pem = malloc(pemSz + 1);
    if (!pem) return NULL;

    pemSz = wc_DerToPem(der, derSz, (byte*)pem, pemSz, CERTREQ_TYPE);
    if (pemSz < 0) { free(pem); return NULL; }

    pem[pemSz] = '\0';
    return pem;
}

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

    char *body = strstr(response, "\r\n\r\n");
    if (!body) { free(response); return NULL; }
    body += 4;

    char *result = strdup(body);
    free(response);
    return result;
}

/*
 * Simple HTTP GET — used once to fetch the CA cert DER from the controller.
 * Returns raw body bytes (may contain binary data), sets *out_len.
 * Caller must free() the returned pointer.
 */
char *http_get(const char *host, int port, const char *path, int *out_len) {
    int sock = tcp_connect(host, port);
    if (sock < 0) { if (out_len) *out_len = 0; return NULL; }

    char request[512];
    snprintf(request, sizeof(request),
             "GET %s HTTP/1.1\r\nHost: %s:%d\r\nConnection: close\r\n\r\n",
             path, host, port);
    send(sock, request, strlen(request), 0);

    char *response = malloc(MAX_HTTP_RESPONSE);
    int total = 0, n;
    while ((n = recv(sock, response + total, MAX_HTTP_RESPONSE - total - 1, 0)) > 0)
        total += n;
    close(sock);

    char *body = strstr(response, "\r\n\r\n");
    if (!body) { free(response); if (out_len) *out_len = 0; return NULL; }
    body += 4;

    int body_len = total - (int)(body - response);
    char *result = malloc(body_len + 1);
    if (!result) { free(response); if (out_len) *out_len = 0; return NULL; }
    memcpy(result, body, body_len);
    result[body_len] = '\0';
    free(response);

    if (out_len) *out_len = body_len;
    return result;
}

/* ==================== PEM/DER Utilities ==================== */

/*
 * Decode a PEM block (-----BEGIN <label>-----) to raw DER bytes.
 * Returns heap-allocated DER buffer (caller must free), or NULL on error.
 */
static unsigned char *pem_to_der(const char *pem, const char *label, int *der_len) {
    char begin_marker[128], end_marker[128];
    snprintf(begin_marker, sizeof(begin_marker), "-----BEGIN %s-----", label);
    snprintf(end_marker,   sizeof(end_marker),   "-----END %s-----",   label);

    const char *begin = strstr(pem, begin_marker);
    if (!begin) return NULL;
    begin += strlen(begin_marker);
    while (*begin == '\n' || *begin == '\r') begin++;

    const char *end = strstr(begin, end_marker);
    if (!end) return NULL;

    /* Collect base64 chars, stripping whitespace */
    size_t b64_cap = (size_t)(end - begin) + 1;
    char *b64 = malloc(b64_cap);
    if (!b64) return NULL;

    char *dst = b64;
    for (const char *src = begin; src < end; src++) {
        if (*src != '\n' && *src != '\r' && *src != ' ') *dst++ = *src;
    }
    *dst = '\0';

    size_t out_len;
    unsigned char *der = base64_decode(b64, &out_len);
    free(b64);
    if (!der) return NULL;

    *der_len = (int)out_len;
    return der;
}

/*
 * Convert a raw ML-DSA-65 private key to PKCS#8 DER using WolfSSL's own
 * wc_Dilithium_PrivateKeyToDer() — the format that
 * wolfSSL_CTX_use_PrivateKey_buffer() actually accepts.
 *
 * Returns heap-allocated DER (caller must free), or NULL on error.
 */
static unsigned char *pkcs8_mldsa65_der(const unsigned char *raw_key, int raw_len,
                                         int *out_len) {
    dilithium_key key;
    int ret;

    unsigned char *buf = (unsigned char *)malloc(8192);
    if (!buf) return NULL;

    ret = wc_dilithium_init(&key);
    if (ret != 0) { free(buf); return NULL; }

    ret = wc_dilithium_set_level(&key, 3);
    if (ret != 0) { wc_dilithium_free(&key); free(buf); return NULL; }

    ret = wc_dilithium_import_private(raw_key, (word32)raw_len, &key);
    if (ret != 0) { wc_dilithium_free(&key); free(buf); return NULL; }

    ret = wc_Dilithium_PrivateKeyToDer(&key, buf, 8192);
    wc_dilithium_free(&key);
    if (ret <= 0) { free(buf); return NULL; }

    *out_len = ret;
    return buf;
}



/*
 * Verify the ML-DSA-65 signature of cert_der using ca_pk.
 * Returns 0 if valid, -1 if invalid or parse error.
 */
static int x509_verify_cert(const unsigned char *cert_der, int cert_len,
                             const unsigned char *ca_pk) {
    const unsigned char *tbs;
    int tbs_len;
    const unsigned char *sig;
    int sig_len;
    char dummy_cn[MAX_CN_SIZE];
    unsigned char dummy_pk[MLDSA65_PUBLIC_KEY_SIZE];
    int dummy_pk_len;

    if (x509_parse_cert(cert_der, cert_len,
                        dummy_cn, dummy_pk, &dummy_pk_len,
                        &tbs, &tbs_len, &sig, &sig_len) != 0) {
        return -1;
    }

    return pqc_mldsa_verify(ca_pk, tbs, tbs_len, sig, sig_len);
}

/* ==================== PQC Certificate Verification (X.509) ==================== */

/*
 * Verify a standard X.509 PEM certificate (-----BEGIN CERTIFICATE-----) against
 * a CA PEM certificate.  Extracts subject_cn and public_key from the leaf cert.
 *
 * Returns 0 on success (cert is valid), -1 on failure.
 */
static int verify_pqc_certificate_x509(const char *cert_pem, const char *ca_cert_pem,
                                        char *subject_cn, unsigned char *public_key) {
    /* Decode leaf cert */
    int cert_der_len;
    unsigned char *cert_der = pem_to_der(cert_pem, "CERTIFICATE", &cert_der_len);
    if (!cert_der) {
        fprintf(stderr, "[ERROR] verify_pqc_certificate_x509: failed to decode cert PEM\n");
        return -1;
    }

    /* Decode CA cert */
    int ca_der_len;
    unsigned char *ca_der = pem_to_der(ca_cert_pem, "CERTIFICATE", &ca_der_len);
    if (!ca_der) {
        fprintf(stderr, "[ERROR] verify_pqc_certificate_x509: failed to decode CA cert PEM\n");
        free(cert_der);
        return -1;
    }

    /* Extract CA public key */
    char ca_cn[MAX_CN_SIZE];
    unsigned char ca_pk[MLDSA65_PUBLIC_KEY_SIZE];
    int ca_pk_len;
    const unsigned char *dummy_tbs;
    int dummy_tbs_len;
    const unsigned char *dummy_sig;
    int dummy_sig_len;

    if (x509_parse_cert(ca_der, ca_der_len, ca_cn, ca_pk, &ca_pk_len,
                        &dummy_tbs, &dummy_tbs_len, &dummy_sig, &dummy_sig_len) != 0
        || ca_pk_len != MLDSA65_PUBLIC_KEY_SIZE) {
        fprintf(stderr, "[ERROR] verify_pqc_certificate_x509: failed to parse CA cert\n");
        free(cert_der); free(ca_der);
        return -1;
    }
    free(ca_der);

    /* Extract leaf cert subject CN and public key */
    int leaf_pk_len;
    const unsigned char *tbs;
    int tbs_len;
    const unsigned char *sig;
    int sig_len;

    if (x509_parse_cert(cert_der, cert_der_len, subject_cn, public_key, &leaf_pk_len,
                        &tbs, &tbs_len, &sig, &sig_len) != 0) {
        fprintf(stderr, "[ERROR] verify_pqc_certificate_x509: failed to parse leaf cert\n");
        free(cert_der);
        return -1;
    }

    /* Verify signature */
    int ret = pqc_mldsa_verify(ca_pk, tbs, tbs_len, sig, sig_len);
    free(cert_der);

    if (ret != 0) {
        fprintf(stderr, "[ERROR] verify_pqc_certificate_x509: signature invalid\n");
    }
    return ret;
}

/* ==================== Attestation ==================== */

char *get_attestation_report(const char *nonce, const char *repetitor_id) {
    wc_Sha256 sha;
    unsigned char hash[32];
    char hash_hex[65];

    wc_InitSha256(&sha);
    wc_Sha256Update(&sha, (unsigned char*)nonce, strlen(nonce));
    wc_Sha256Update(&sha, (unsigned char*)repetitor_id, strlen(repetitor_id));
    wc_Sha256Final(&sha, hash);
    wc_Sha256Free(&sha);

    bytes_to_hex(hash, 32, hash_hex);

    char *report = malloc(128);
    sprintf(report, "attestation_report:%s", hash_hex);
    return report;
}

/* ==================== Controller TLS Context ==================== */

/*
 * Build a TLS 1.3 client context for the controller channel.
 * Server-only auth: loads CA cert for peer cert verification but does NOT
 * load a client cert/key.  WolfSSL verifies the ML-DSA-65 cert natively
 * when compiled with --enable-dilithium.
 */
static WOLFSSL_CTX *ctrl_make_tls_ctx(const unsigned char *ca_der, int ca_len)
{
    wolfSSL_Init();
    WOLFSSL_CTX *ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
    if (!ctx) {
        fprintf(stderr, "[ERROR] ctrl_make_tls_ctx: wolfSSL_CTX_new failed\n");
        return NULL;
    }

    if (wolfSSL_CTX_load_verify_buffer(ctx, ca_der, ca_len,
                                        WOLFSSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "[ERROR] ctrl_make_tls_ctx: load_verify_buffer failed\n");
        wolfSSL_CTX_free(ctx);
        return NULL;
    }

    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, _pqc_verify_accept_all);
    return ctx;
}

/* ==================== Controller Configuration Protocol ==================== */

int get_configuration_hybrid(const char *controller_host, int controller_port,
                             const char *repetitor_id, const char *repetitor_url,
                             repetitor_config_t *config) {
    /* Declare TLS handles up-front so fail_tls can always clean up. */
    WOLFSSL_CTX *ctrl_ctx = NULL;
    WOLFSSL     *ssl      = NULL;
    int          ctrl_sock = -1;

    /* ── Bootstrap: fetch CA cert via plain HTTP GET ─────────────────────── */
    fprintf(stderr, "[DEBUG] Fetching CA cert from controller (%s:%d/ca_cert)...\n",
            controller_host, controller_port);
    int ca_der_len = 0;
    char *ca_der_raw = http_get(controller_host, controller_port, "/ca_cert", &ca_der_len);
    if (!ca_der_raw || ca_der_len <= 0) {
        fprintf(stderr, "[ERROR] Failed to fetch CA cert from controller\n");
        return -1;
    }
    fprintf(stderr, "[DEBUG] Fetched CA cert (%d bytes)\n", ca_der_len);

    /* ── Open WolfSSL TLS connection to controller:CTRL_TLS_PORT ─────────── */
    fprintf(stderr, "[DEBUG] Connecting to controller TLS on %s:%d...\n",
            controller_host, CTRL_TLS_PORT);
    ctrl_sock = tcp_connect(controller_host, CTRL_TLS_PORT);
    if (ctrl_sock < 0) {
        fprintf(stderr, "[ERROR] TCP connect to controller:%d failed\n", CTRL_TLS_PORT);
        free(ca_der_raw);
        return -1;
    }

    ctrl_ctx = ctrl_make_tls_ctx((unsigned char *)ca_der_raw, ca_der_len);
    if (!ctrl_ctx) { free(ca_der_raw); close(ctrl_sock); return -1; }

    ssl = wolfSSL_new(ctrl_ctx);
    if (!ssl) {
        fprintf(stderr, "[ERROR] wolfSSL_new failed\n");
        free(ca_der_raw);
        goto fail_tls;
    }
    wolfSSL_set_fd(ssl, ctrl_sock);

    if (wolfSSL_connect(ssl) != WOLFSSL_SUCCESS) {
        int err = wolfSSL_get_error(ssl, 0);
        fprintf(stderr, "[ERROR] WolfSSL handshake failed: %d (%s)\n",
                err, wolfSSL_ERR_reason_error_string(err));
        free(ca_der_raw);
        goto fail_tls;
    }

    if (_pqc_verify_peer(ssl, (unsigned char *)ca_der_raw, ca_der_len) != 0) {
        fprintf(stderr, "[ERROR] Controller TLS cert verification failed\n");
        free(ca_der_raw);
        goto fail_tls;
    }
    free(ca_der_raw);
    fprintf(stderr, "[DEBUG] WolfSSL TLS connected to controller, server cert verified\n");

    /* ── Step 1: Register — get nonce ────────────────────────────────────── */
    {
        char *reg_req = malloc(512);
        snprintf(reg_req, 512,
                 "{\"action\":\"register\",\"data\":"
                 "{\"repetitor_id\":\"%s\",\"repetitor_url\":\"%s\"}}",
                 repetitor_id, repetitor_url);

        fprintf(stderr, "[DEBUG] Sending register...\n");
        int ok = tls_send_msg(ssl, (unsigned char *)reg_req, (int)strlen(reg_req));
        free(reg_req);
        if (ok != 0) {
            fprintf(stderr, "[ERROR] tls_send_msg register failed\n");
            goto fail_tls;
        }
    }

    int reg_resp_len;
    char *reg_resp = (char *)tls_recv_msg(ssl, &reg_resp_len);
    if (!reg_resp) { fprintf(stderr, "[ERROR] tls_recv_msg register failed\n"); goto fail_tls; }

    char *nonce = extract_json_string(reg_resp, "nonce");
    free(reg_resp);
    if (!nonce) {
        fprintf(stderr, "[ERROR] Invalid register response (no nonce)\n");
        goto fail_tls;
    }
    fprintf(stderr, "[DEBUG] Received nonce=%s\n", nonce);

    /* ── Step 2: Attest — SHA256(nonce_hex + repetitor_id) ───────────────── */
    {
        char *attestation_report = get_attestation_report(nonce, repetitor_id);
        free(nonce);

        char *attest_req = malloc(512);
        snprintf(attest_req, 512,
                 "{\"action\":\"attest\",\"data\":"
                 "{\"repetitor_id\":\"%s\",\"attestation_report\":\"%s\"}}",
                 repetitor_id, attestation_report);
        free(attestation_report);

        fprintf(stderr, "[DEBUG] Sending attest...\n");
        int ok = tls_send_msg(ssl, (unsigned char *)attest_req, (int)strlen(attest_req));
        free(attest_req);
        if (ok != 0) {
            fprintf(stderr, "[ERROR] tls_send_msg attest failed\n");
            goto fail_tls;
        }
    }

    int attest_resp_len;
    char *attest_resp = (char *)tls_recv_msg(ssl, &attest_resp_len);
    if (!attest_resp) { fprintf(stderr, "[ERROR] tls_recv_msg attest failed\n"); goto fail_tls; }

    {
        char *status = extract_json_string(attest_resp, "status");
        free(attest_resp);
        int auth_ok = (status && strcmp(status, "authenticated") == 0);
        free(status);
        if (!auth_ok) { fprintf(stderr, "[ERROR] Attestation failed\n"); goto fail_tls; }
    }
    fprintf(stderr, "[DEBUG] Authenticated with controller\n");

    /* ── Step 3: Get configuration ────────────────────────────────────────── */
    fprintf(stderr, "[DEBUG] Requesting configuration...\n");
    {
        char *cfg_req = malloc(256);
        snprintf(cfg_req, 256,
                 "{\"action\":\"configuration\",\"data\":"
                 "{\"repetitor_id\":\"%s\"}}",
                 repetitor_id);
        int ok = tls_send_msg(ssl, (unsigned char *)cfg_req, (int)strlen(cfg_req));
        free(cfg_req);
        if (ok != 0) {
            fprintf(stderr, "[ERROR] tls_send_msg configuration failed\n");
            goto fail_tls;
        }
    }

    int cfg_resp_len;
    char *cfg_resp = (char *)tls_recv_msg(ssl, &cfg_resp_len);
    if (!cfg_resp) { fprintf(stderr, "[ERROR] tls_recv_msg configuration failed\n"); goto fail_tls; }

    {
        char *config_json = cfg_resp;  /* response IS the configuration JSON */
        fprintf(stderr, "[DEBUG] Received configuration\n");

        config->left_repetitor_url  = extract_json_string(config_json, "left_repetitor_url");
        config->right_repetitor_url = extract_json_string(config_json, "right_repetitor_url");
        config->left_repetitor_id   = extract_json_string(config_json, "left_repetitor_id");
        config->right_repetitor_id  = extract_json_string(config_json, "right_repetitor_id");
        config->left_kme            = extract_json_string(config_json, "left_kme");
        config->right_kme           = extract_json_string(config_json, "right_kme");
        config->left_kme_url        = extract_json_string(config_json, "left_kme_url");
        config->right_kme_url       = extract_json_string(config_json, "right_kme_url");
        config->left_cn             = extract_json_string(config_json, "left_cn");
        config->right_cn            = extract_json_string(config_json, "right_cn");
        config->left_kme_peer       = extract_json_string(config_json, "left_kme_peer");
        config->right_kme_peer      = extract_json_string(config_json, "right_kme_peer");
        config->whitelist           = extract_json_string(config_json, "whitelist");

        char *pqc_ca = extract_json_string(config_json, "pqc_ca_certificate");
        if (pqc_ca) g_pqc_ca_certificate = pqc_ca;
        free(config_json);
    }

    /* ── Step 4: Generate ML-DSA keys and request certificates ───────────── */
    fprintf(stderr, "[DEBUG] Generating ML-DSA-65 keypair...\n");
    if (pqc_mldsa_generate_keypair(config->pqc_public_key, config->pqc_private_key) != 0) {
        fprintf(stderr, "[ERROR] Failed to generate ML-DSA keypair\n");
        goto fail_tls;
    }
    fprintf(stderr, "[DEBUG] ML-DSA keypair generated successfully\n");

    {
        char *pqc_pk_b64 = base64_encode(config->pqc_public_key, MLDSA65_PUBLIC_KEY_SIZE);

        char *left_rsa_csr = NULL, *right_rsa_csr = NULL;
        char *left_rsa_esc = NULL, *right_rsa_esc = NULL;
        int has_left  = config->left_cn  && strlen(config->left_cn)
                        && strcmp(config->left_cn,  "test_client") != 0;
        int has_right = config->right_cn && strlen(config->right_cn)
                        && strcmp(config->right_cn, "test_client") != 0;

        if (has_left) {
            rsa_generate_keypair(&config->left_rsa_key_der, &config->left_rsa_key_der_len);
            left_rsa_csr = rsa_create_csr(config->left_rsa_key_der,
                                          config->left_rsa_key_der_len, config->left_cn);
            left_rsa_esc = certificate_json_escape(left_rsa_csr);
        }
        if (has_right) {
            rsa_generate_keypair(&config->right_rsa_key_der, &config->right_rsa_key_der_len);
            right_rsa_csr = rsa_create_csr(config->right_rsa_key_der,
                                           config->right_rsa_key_der_len, config->right_cn);
            right_rsa_esc = certificate_json_escape(right_rsa_csr);
        }

        char *cert_req_msg = malloc(MAX_JSON_SIZE);
        snprintf(cert_req_msg, MAX_JSON_SIZE,
                 "{\"action\":\"generate_certificates\",\"data\":"
                 "{\"repetitor_id\":\"%s\","
                 "\"pqc_csr\":{\"subject_cn\":\"%s\",\"public_key\":\"%s\"},"
                 "\"left_rsa_csr\":\"%s\","
                 "\"right_rsa_csr\":\"%s\"}}",
                 repetitor_id, repetitor_id, pqc_pk_b64,
                 left_rsa_esc  ? left_rsa_esc  : "",
                 right_rsa_esc ? right_rsa_esc : "");
        free(pqc_pk_b64);
        if (has_left)  { free(left_rsa_csr);  free(left_rsa_esc);  }
        if (has_right) { free(right_rsa_csr); free(right_rsa_esc); }

        fprintf(stderr, "[DEBUG] Requesting certificates...\n");
        int ok = tls_send_msg(ssl, (unsigned char *)cert_req_msg, (int)strlen(cert_req_msg));
        free(cert_req_msg);
        if (ok != 0) {
            fprintf(stderr, "[ERROR] tls_send_msg generate_certificates failed\n");
            goto fail_tls;
        }
    }

    int cert_resp_len;
    char *cert_resp = (char *)tls_recv_msg(ssl, &cert_resp_len);
    if (!cert_resp) {
        fprintf(stderr, "[ERROR] tls_recv_msg generate_certificates failed\n");
        goto fail_tls;
    }

    {
        char *certs_json = cert_resp;  /* response IS the certs JSON */
        fprintf(stderr, "[DEBUG] Received certificates\n");

        config->pqc_certificate = extract_json_string(certs_json, "pqc_certificate");
        config->left_rsa_cert   = extract_json_string(certs_json, "left_rsa_certificate");
        config->right_rsa_cert  = extract_json_string(certs_json, "right_rsa_certificate");
        free(certs_json);
    }

    wolfSSL_shutdown(ssl);
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctrl_ctx);
    close(ctrl_sock);
    return 0;

fail_tls:
    if (ssl)            wolfSSL_free(ssl);
    if (ctrl_ctx)       wolfSSL_CTX_free(ctrl_ctx);
    if (ctrl_sock >= 0) close(ctrl_sock);
    return -1;
}

/* ==================== KME Communication (mTLS) ==================== */

char *kme_request(const unsigned char *key_der, int key_der_len,
                  const char *cert_pem, const char *ca_pem,
                  const char *kme_host, const char *kme_ip, int kme_port,
                  const char *path) {
    /* kme_ip is the numeric IP address used for tcp_connect() to avoid
     * gethostbyname() which triggers futex/pthreads in Keystone enclaves.
     * kme_host is still used for TLS SNI and the HTTP Host header. */
    const char *connect_addr = (kme_ip && kme_ip[0]) ? kme_ip : kme_host;

    WOLFSSL_CTX *ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method());
    if (!ctx) return NULL;

    if (wolfSSL_CTX_load_verify_buffer(ctx, (unsigned char*)ca_pem, strlen(ca_pem),
                                        SSL_FILETYPE_PEM) != SSL_SUCCESS) {
        wolfSSL_CTX_free(ctx); return NULL;
    }

    if (wolfSSL_CTX_use_certificate_buffer(ctx, (unsigned char*)cert_pem, strlen(cert_pem),
                                            SSL_FILETYPE_PEM) != SSL_SUCCESS) {
        wolfSSL_CTX_free(ctx); return NULL;
    }

    if (wolfSSL_CTX_use_PrivateKey_buffer(ctx, key_der, key_der_len,
                                           SSL_FILETYPE_ASN1) != SSL_SUCCESS) {
        wolfSSL_CTX_free(ctx); return NULL;
    }

    int sock = tcp_connect(connect_addr, kme_port);
    if (sock < 0) { wolfSSL_CTX_free(ctx); return NULL; }

    WOLFSSL *ssl = wolfSSL_new(ctx);
    if (!ssl) { close(sock); wolfSSL_CTX_free(ctx); return NULL; }

    wolfSSL_set_fd(ssl, sock);
    wolfSSL_UseSNI(ssl, WOLFSSL_SNI_HOST_NAME, kme_host, strlen(kme_host));

    if (wolfSSL_connect(ssl) != SSL_SUCCESS) {
        wolfSSL_free(ssl); close(sock); wolfSSL_CTX_free(ctx); return NULL;
    }

    char request[1024];
    sprintf(request,
            "GET %s HTTP/1.1\r\n"
            "Host: %s\r\n"
            "Connection: close\r\n"
            "\r\n",
            path, kme_host);

    wolfSSL_write(ssl, request, strlen(request));

    char *response = malloc(MAX_HTTP_RESPONSE);
    int total = 0, n;
    while ((n = wolfSSL_read(ssl, response + total, MAX_HTTP_RESPONSE - total - 1)) > 0) {
        total += n;
    }
    response[total] = '\0';

    wolfSSL_shutdown(ssl);
    wolfSSL_free(ssl);
    close(sock);
    wolfSSL_CTX_free(ctx);

    char *body = strstr(response, "\r\n\r\n");
    if (!body) { free(response); return NULL; }
    body += 4;

    char *result = strdup(body);
    free(response);
    return result;
}

char *kme_get_key(const unsigned char *key_der, int key_der_len,
                  const char *cert, const char *ca,
                  const char *kme_host, const char *kme_ip, const char *kme_peer) {
    char path[512];
    sprintf(path, "/api/v1/keys/%s/enc_keys", kme_peer);
    return kme_request(key_der, key_der_len, cert, ca, kme_host, kme_ip, 443, path);
}

char *kme_get_key_with_id(const unsigned char *key_der, int key_der_len,
                          const char *cert, const char *ca,
                          const char *kme_host, const char *kme_ip,
                          const char *kme_peer, const char *key_id) {
    char path[512];
    sprintf(path, "/api/v1/keys/%s/dec_keys?key_ID=%s", kme_peer, key_id);
    return kme_request(key_der, key_der_len, cert, ca, kme_host, kme_ip, 443, path);
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




static WOLFSSL_CTX *pqc_make_tls_ctx(int is_server,
    const unsigned char *cert_der, int cert_len,
    const unsigned char *pkcs8_key, int key_len,
    const unsigned char *ca_der, int ca_len)
{
    wolfSSL_Init();  /* idempotent */

    WOLFSSL_CTX *ctx = wolfSSL_CTX_new(
        is_server ? wolfTLSv1_3_server_method() : wolfTLSv1_3_client_method()
    );
    if (!ctx) { fprintf(stderr, "[ERROR] pqc_make_tls_ctx: wolfSSL_CTX_new failed\n"); return NULL; }

    if (wolfSSL_CTX_use_certificate_buffer(ctx, cert_der, cert_len,
                                            WOLFSSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "[ERROR] pqc_make_tls_ctx: use_certificate_buffer failed\n");
        wolfSSL_CTX_free(ctx); return NULL;
    }

    if (wolfSSL_CTX_use_PrivateKey_buffer(ctx, pkcs8_key, key_len,
                                           WOLFSSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "[ERROR] pqc_make_tls_ctx: use_PrivateKey_buffer failed\n");
        wolfSSL_CTX_free(ctx); return NULL;
    }

    if (wolfSSL_CTX_load_verify_buffer(ctx, ca_der, ca_len,
                                        WOLFSSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "[ERROR] pqc_make_tls_ctx: load_verify_buffer failed\n");
        wolfSSL_CTX_free(ctx); return NULL;
    }

    /* Request peer cert; bypass WolfSSL's broken ML-DSA-65 chain verifier.
     * Manual verification happens after the handshake via _pqc_verify_peer(). */
    int verify_flags = WOLFSSL_VERIFY_PEER;
    if (is_server)
        verify_flags |= WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT;
    wolfSSL_CTX_set_verify(ctx, verify_flags, _pqc_verify_accept_all);

    return ctx;
}

/*
 * Extract the CN from the TLS peer's certificate.
 * Uses our X.509 DER parser on the raw cert bytes from WolfSSL.
 */
static void tls_get_peer_cn(WOLFSSL *ssl, char *cn, int cn_max) {
    cn[0] = '\0';

    WOLFSSL_X509 *peer = wolfSSL_get_peer_certificate(ssl);
    if (!peer) return;

    int der_len = 0;
    const unsigned char *der = wolfSSL_X509_get_der(peer, &der_len);
    if (der && der_len > 0) {
        char tmp_cn[MAX_CN_SIZE];
        unsigned char tmp_pk[MLDSA65_PUBLIC_KEY_SIZE];
        int tmp_pk_len;
        const unsigned char *tbs;
        int tbs_len;
        const unsigned char *sig;
        int sig_len;

        tmp_cn[0] = '\0';
        x509_parse_cert(der, der_len, tmp_cn, tmp_pk, &tmp_pk_len,
                        &tbs, &tbs_len, &sig, &sig_len);

        if (tmp_cn[0]) {
            strncpy(cn, tmp_cn, cn_max - 1);
            cn[cn_max - 1] = '\0';
        }
    }
    wolfSSL_X509_free(peer);
}

/* ==================== PQC Channel Protocol (WolfSSL mTLS) ==================== */

/*
 * Send a JSON message to a remote repetitor using WolfSSL mTLS.
 * Acts as TLS client.
 */
int pqc_send_message(const char *host, int port,
                     const unsigned char *my_sk, const char *my_cert,
                     const char *ca_cert, const char *msg_json, const char *rep_id) {
    char ts[32];
    get_timestamp(ts, sizeof(ts));

    /* Decode PEM certificates to DER */
    int cert_der_len, ca_der_len;
    unsigned char *cert_der = pem_to_der(my_cert, "CERTIFICATE", &cert_der_len);
    unsigned char *ca_der   = pem_to_der(ca_cert, "CERTIFICATE", &ca_der_len);
    if (!cert_der || !ca_der) {
        fprintf(stderr, "[ERROR][%s] pqc_send_message: PEM decode failed\n", rep_id);
        free(cert_der); free(ca_der);
        return -1;
    }

    /* Wrap private key in PKCS#8 DER for WolfSSL */
    int pkcs8_len;
    unsigned char *pkcs8_key = pkcs8_mldsa65_der(my_sk, MLDSA65_SECRET_KEY_SIZE, &pkcs8_len);
    if (!pkcs8_key) {
        fprintf(stderr, "[ERROR][%s] pqc_send_message: PKCS#8 wrap failed\n", rep_id);
        free(cert_der); free(ca_der);
        return -1;
    }

    /* Build TLS client context (keep ca_der alive for post-handshake verify) */
    WOLFSSL_CTX *ctx = pqc_make_tls_ctx(0,
        cert_der, cert_der_len, pkcs8_key, pkcs8_len, ca_der, ca_der_len);
    free(cert_der); free(pkcs8_key);
    if (!ctx) {
        fprintf(stderr, "[ERROR][%s] pqc_send_message: TLS context creation failed\n", rep_id);
        free(ca_der);
        return -1;
    }

    /* TCP connect */
    int sock = tcp_connect(host, port);
    if (sock < 0) {
        fprintf(stderr, "[ERROR][%s] pqc_send_message: TCP connect to %s:%d failed\n",
                rep_id, host, port);
        free(ca_der); wolfSSL_CTX_free(ctx);
        return -1;
    }

    WOLFSSL *ssl = wolfSSL_new(ctx);
    if (!ssl) {
        free(ca_der); close(sock); wolfSSL_CTX_free(ctx);
        return -1;
    }
    wolfSSL_set_fd(ssl, sock);

    if (wolfSSL_connect(ssl) != WOLFSSL_SUCCESS) {
        int err = wolfSSL_get_error(ssl, -1);
        char errbuf[80];
        wolfSSL_ERR_error_string(err, errbuf);
        fprintf(stderr, "[ERROR][%s] pqc_send_message: TLS handshake failed: err=%d (%s)\n",
                rep_id, err, errbuf);
        free(ca_der); wolfSSL_free(ssl); close(sock); wolfSSL_CTX_free(ctx);
        return -1;
    }

    if (_pqc_verify_peer(ssl, ca_der, ca_der_len) != 0) {
        fprintf(stderr, "[ERROR][%s] pqc_send_message: peer cert verification failed\n", rep_id);
        free(ca_der); wolfSSL_free(ssl); close(sock); wolfSSL_CTX_free(ctx);
        return -1;
    }
    free(ca_der); ca_der = NULL;

    /* Identify peer */
    char peer_cn[MAX_CN_SIZE];
    tls_get_peer_cn(ssl, peer_cn, MAX_CN_SIZE);
    get_timestamp(ts, sizeof(ts));
    fprintf(stderr, "[%s][%s] PQC TLS connected to %s\n", ts, rep_id, peer_cn);

    /* Send message (length-prefixed) */
    int msg_len = strlen(msg_json);
    if (tls_send_msg(ssl, (unsigned char*)msg_json, msg_len) != 0) {
        fprintf(stderr, "[ERROR][%s] pqc_send_message: send failed\n", rep_id);
        wolfSSL_shutdown(ssl); wolfSSL_free(ssl); close(sock); wolfSSL_CTX_free(ctx);
        return -1;
    }

    /* Receive ACK */
    int ack_len;
    unsigned char *ack = tls_recv_msg(ssl, &ack_len);
    if (ack) {
        get_timestamp(ts, sizeof(ts));
        fprintf(stderr, "[%s][%s] Ack: %s\n", ts, rep_id, (char*)ack);
        free(ack);
    }

    wolfSSL_shutdown(ssl);
    wolfSSL_free(ssl);
    close(sock);
    wolfSSL_CTX_free(ctx);
    return 0;
}

/*
 * Listen for one incoming message from a remote repetitor using WolfSSL mTLS.
 * Acts as TLS server.  Sends "RECEIVED" ACK after receiving.
 */
pqc_message_t pqc_receive_message(int port, const unsigned char *my_sk,
                                  const char *my_cert, const char *ca_cert,
                                  const char *whitelist, const char *rep_id) {
    pqc_message_t result = {NULL, NULL};
    char ts[32];

    /* Decode PEM certificates to DER */
    int cert_der_len, ca_der_len;
    unsigned char *cert_der = pem_to_der(my_cert, "CERTIFICATE", &cert_der_len);
    unsigned char *ca_der   = pem_to_der(ca_cert, "CERTIFICATE", &ca_der_len);
    if (!cert_der || !ca_der) {
        fprintf(stderr, "[ERROR][%s] pqc_receive_message: PEM decode failed\n", rep_id);
        free(cert_der); free(ca_der);
        return result;
    }

    /* Wrap private key in PKCS#8 DER */
    int pkcs8_len;
    unsigned char *pkcs8_key = pkcs8_mldsa65_der(my_sk, MLDSA65_SECRET_KEY_SIZE, &pkcs8_len);
    if (!pkcs8_key) {
        fprintf(stderr, "[ERROR][%s] pqc_receive_message: PKCS#8 wrap failed\n", rep_id);
        free(cert_der); free(ca_der);
        return result;
    }

    /* Build TLS server context (keep ca_der alive for post-handshake verify) */
    WOLFSSL_CTX *ctx = pqc_make_tls_ctx(1,
        cert_der, cert_der_len, pkcs8_key, pkcs8_len, ca_der, ca_der_len);
    free(cert_der); free(pkcs8_key);
    if (!ctx) {
        fprintf(stderr, "[ERROR][%s] pqc_receive_message: TLS context creation failed\n", rep_id);
        free(ca_der);
        return result;
    }

    /* Create listening socket */
    int server = socket(AF_INET, SOCK_STREAM, 0);
    if (server < 0) { free(ca_der); wolfSSL_CTX_free(ctx); return result; }

    int opt = 1;
    setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {0};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons(port);

    if (bind(server, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        free(ca_der); close(server); wolfSSL_CTX_free(ctx); return result;
    }
    if (listen(server, 5) < 0) {
        free(ca_der); close(server); wolfSSL_CTX_free(ctx); return result;
    }

    get_timestamp(ts, sizeof(ts));
    fprintf(stderr, "[%s][%s] PQC TLS listening on port %d\n", ts, rep_id, port);

    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    int client = accept(server, (struct sockaddr*)&client_addr, &client_len);
    if (client < 0) {
        free(ca_der); close(server); wolfSSL_CTX_free(ctx); return result;
    }

    get_timestamp(ts, sizeof(ts));
    fprintf(stderr, "[%s][%s] Connection from %s\n", ts, rep_id, inet_ntoa(client_addr.sin_addr));

    /* TLS handshake */
    WOLFSSL *ssl = wolfSSL_new(ctx);
    if (!ssl) {
        fprintf(stderr, "[ERROR][%s] pqc_receive_message: wolfSSL_new failed\n", rep_id);
        free(ca_der); close(client); close(server); wolfSSL_CTX_free(ctx); return result;
    }
    wolfSSL_set_fd(ssl, client);

    if (wolfSSL_accept(ssl) != WOLFSSL_SUCCESS) {
        int err = wolfSSL_get_error(ssl, -1);
        char errbuf[80];
        wolfSSL_ERR_error_string(err, errbuf);
        fprintf(stderr, "[ERROR][%s] pqc_receive_message: TLS accept failed: err=%d (%s)\n",
                rep_id, err, errbuf);
        free(ca_der); wolfSSL_free(ssl); close(client); close(server); wolfSSL_CTX_free(ctx);
        return result;
    }

    if (_pqc_verify_peer(ssl, ca_der, ca_der_len) != 0) {
        fprintf(stderr, "[ERROR][%s] pqc_receive_message: peer cert verification failed\n", rep_id);
        free(ca_der); wolfSSL_free(ssl); close(client); close(server); wolfSSL_CTX_free(ctx);
        return result;
    }
    free(ca_der); ca_der = NULL;

    /* Identify peer */
    char peer_cn[MAX_CN_SIZE];
    tls_get_peer_cn(ssl, peer_cn, MAX_CN_SIZE);
    get_timestamp(ts, sizeof(ts));
    fprintf(stderr, "[%s][%s] PQC TLS from %s\n", ts, rep_id, peer_cn);

    /* Whitelist check */
    if (whitelist && strlen(whitelist) > 0 && !strstr(whitelist, peer_cn)) {
        fprintf(stderr, "[%s][%s] Rejected: %s not in whitelist\n", ts, rep_id, peer_cn);
        wolfSSL_shutdown(ssl); wolfSSL_free(ssl);
        close(client); close(server); wolfSSL_CTX_free(ctx);
        return result;
    }

    /* Receive message */
    int msg_len;
    unsigned char *msg = tls_recv_msg(ssl, &msg_len);
    if (!msg) {
        fprintf(stderr, "[ERROR][%s] pqc_receive_message: recv failed\n", rep_id);
        wolfSSL_shutdown(ssl); wolfSSL_free(ssl);
        close(client); close(server); wolfSSL_CTX_free(ctx);
        return result;
    }

    /* Send ACK */
    tls_send_msg(ssl, (unsigned char*)"RECEIVED", 8);

    wolfSSL_shutdown(ssl);
    wolfSSL_free(ssl);
    close(client);
    close(server);
    wolfSSL_CTX_free(ctx);

    result.message    = (char*)msg;
    result.sender_cn  = strdup(peer_cn);
    return result;
}

/* ==================== Cleanup ==================== */

void free_config(repetitor_config_t *c) {
    if (!c) return;
    free(c->left_repetitor_url); free(c->right_repetitor_url);
    free(c->left_repetitor_id);  free(c->right_repetitor_id);
    free(c->left_kme);           free(c->right_kme);
    free(c->left_cn);            free(c->right_cn);
    free(c->left_kme_peer);      free(c->right_kme_peer);
    free(c->whitelist);          free(c->pqc_certificate);
    free(c->left_rsa_key_der);   free(c->left_rsa_cert);
    free(c->right_rsa_key_der);  free(c->right_rsa_cert);
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
    fprintf(stderr, "QKD Relay Repetitor (WolfSSL mTLS PQC)\n");
    fprintf(stderr, "Repetitor ID: %s, Port: %d\n", repetitor_id, port);
    fprintf(stderr, "========================================\n");

    wolfSSL_Init();
    if (init_rng() != 0) { fprintf(stderr, "RNG init failed\n"); return 1; }

    repetitor_config_t *config = calloc(1, sizeof(repetitor_config_t));
    if (!config) { cleanup_rng(); wolfSSL_Cleanup(); return 1; }

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
            config->left_repetitor_id  ? config->left_repetitor_id  : "none",
            config->left_repetitor_url ? config->left_repetitor_url : "");
    fprintf(stderr, "[%s][%s] Right: %s (%s)\n", ts, repetitor_id,
            config->right_repetitor_id  ? config->right_repetitor_id  : "none",
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

        char *from_ct     = extract_json_string(msg.message, "message");
        char *from_key_id = extract_json_string(msg.message, "key_ID");

        int is_from_left = config->left_repetitor_id &&
                           strcmp(msg.sender_cn, config->left_repetitor_id) == 0;

        /* KME info */
        const char *kme_dec      = is_from_left ? config->left_kme      : config->right_kme;
        const char *kme_dec_ip   = is_from_left ? config->left_kme_url  : config->right_kme_url;
        const char *kme_dec_peer = is_from_left ? config->left_kme_peer : config->right_kme_peer;
        unsigned char *kme_dec_key     = is_from_left ? config->left_rsa_key_der  : config->right_rsa_key_der;
        int            kme_dec_key_len = is_from_left ? config->left_rsa_key_der_len : config->right_rsa_key_der_len;
        const char *kme_dec_cert = is_from_left ? config->left_rsa_cert  : config->right_rsa_cert;

        const char *kme_enc      = is_from_left ? config->right_kme     : config->left_kme;
        const char *kme_enc_ip   = is_from_left ? config->right_kme_url : config->left_kme_url;
        const char *kme_enc_peer = is_from_left ? config->right_kme_peer : config->left_kme_peer;
        unsigned char *kme_enc_key     = is_from_left ? config->right_rsa_key_der  : config->left_rsa_key_der;
        int            kme_enc_key_len = is_from_left ? config->right_rsa_key_der_len : config->left_rsa_key_der_len;
        const char *kme_enc_cert = is_from_left ? config->right_rsa_cert : config->left_rsa_cert;

        const char *to_url = is_from_left ? config->right_repetitor_url : config->left_repetitor_url;

        char *plaintext = NULL;

        /* Decrypt with KME key */
        if (kme_dec && strlen(kme_dec) > 0 && kme_dec_key && from_key_id && strlen(from_key_id) > 0) {
            fprintf(stderr, "[%s][%s] Getting key from KME %s...\n", ts, repetitor_id, kme_dec);
            char *key_resp = kme_get_key_with_id(kme_dec_key, kme_dec_key_len,
                                                  kme_dec_cert, QKD_CA_CERTIFICATE,
                                                  kme_dec, kme_dec_ip, kme_dec_peer, from_key_id);
            if (key_resp) {
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

        char *to_ct     = NULL;
        char *to_key_id = NULL;

        /* Encrypt with KME key */
        if (kme_enc && strlen(kme_enc) > 0 && kme_enc_key) {
            fprintf(stderr, "[%s][%s] Getting key from KME %s...\n", ts, repetitor_id, kme_enc);
            char *key_resp = kme_get_key(kme_enc_key, kme_enc_key_len,
                                          kme_enc_cert, QKD_CA_CERTIFICATE,
                                          kme_enc, kme_enc_ip, kme_enc_peer);
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

        if (!to_ct)     to_ct     = strdup(plaintext);
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
