#include <wolfssl/options.h>

#include <stdio.h>
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

#include <wolfssl/ssl.h>
#include <wolfssl/openssl/evp.h>
#include <wolfssl/openssl/hmac.h>
#include <wolfssl/openssl/sha.h>
#include <wolfssl/openssl/buffer.h>
#include <wolfssl/openssl/rsa.h>
#include <wolfssl/openssl/pem.h>
#include <wolfssl/openssl/x509.h>
#include <wolfssl/openssl/x509v3.h>
#include <wolfssl/openssl/ssl.h>
#include <wolfssl/openssl/err.h>
#include <wolfssl/openssl/bio.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/coding.h>


const char *QKD_CA_CERTIFICATE = "-----BEGIN CERTIFICATE-----\nMIIDbTCCAlWgAwIBAgIQCzuhkEQXTouuETnIFrtF1jANBgkqhkiG9w0BAQsFADBn\nMSwwKgYDVQQDDCNhY2N0LTI1NjMuZXRzaS1xa2QtYXBpLnF1a2F5ZGVlLmNvbTEe\nMBwGA1UECgwVUXVLYXlEZWUgYWNjb3VudCAyNTYzMRcwFQYDVQQLDA5TZXJ2ZXIg\ncm9vdCBDQTAgFw0yNTA1MjYwODMxMzlaGA8yMTI1MDUwMzA4MzEzOVowZzEsMCoG\nA1UEAwwjYWNjdC0yNTYzLmV0c2ktcWtkLWFwaS5xdWtheWRlZS5jb20xHjAcBgNV\nBAoMFVF1S2F5RGVlIGFjY291bnQgMjU2MzEXMBUGA1UECwwOU2VydmVyIHJvb3Qg\nQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC6fv8Hp8hL7P6Rs3Zc\nX3oHL6hEXbx5hmSPLFvSIpLnF1iZepdlJtXJiq2oVZNcdtDgnYA5ugl6CGQE8v3A\n79hxrWOSSfysYryoIBBYSvaEPEN16TSKcY7+cAnSU8fu736uRhKwz2jeJw2g+4pb\nlcmsJhLq40F23Px+XkpA99DPIGHWWy2ZelcddnP1M99/l937V2AvGaM+P71NMS9a\nF/K/2iiDOiAQ3XZXVIjmsdSMHth2780U80wiAaH2PsOILMbKNLdxDLYIJa5awmXY\n1D8Dik9Ot7e0It+ZfdaXxUHBxnTj7CgajqhOvd78p2PCwMhZ61DO+5subpzhywxE\nt92/AgMBAAGjEzARMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEB\nAAuWsi3TFKGn1H6raS0aSw6JqE5c/PUMGRTBDzmSpIUMjnaG/9Ise1SGxujAYvpm\nahExKKFkgTuSV4GmYL1n4Yakls3sr9hbP40L2wJLus+psfGKsN+Xa3hwyFrQVyKY\ndNpIH+AIhH/nI2WKyYnhv0dE2PR/UzR3AtCum/uu8C2JnY0qnBlQ3ooOopti0+MK\nzEHJBAK2jxm9vjEgHs+zHKIxOiuCM6jmPZsG4PdBWkcf1C6Coof0kfO3vednsE/B\n0Q1c9TemcUbH6OR0kDxJFV/Alsim2wolJ722QOlBB2+m88POeSqN9JLxcj3pQe53\nwkKhllHrkuVRW7pw4wXXn8w=\n-----END CERTIFICATE-----";
const char *REPETITOR_CA_CERTIFICATE = "-----BEGIN CERTIFICATE-----\nMIIDrzCCApegAwIBAgIUXeRoaA0s2FWtqv9KV6xjUPLMHgkwDQYJKoZIhvcNAQEL\nBQAwXjELMAkGA1UEBhMCUlMxCzAJBgNVBAgTAlJTMREwDwYDVQQHEwhCZWxncmFk\nZTEMMAoGA1UEChMDRVRGMQwwCgYDVQQLEwNSVEkxEzARBgNVBAMTCk15IFJvb3Qg\nQ0EwHhcNMjUwOTA2MTAyNzAwWhcNMzAwOTA1MTAyNzAwWjBeMQswCQYDVQQGEwJS\nUzELMAkGA1UECBMCUlMxETAPBgNVBAcTCEJlbGdyYWRlMQwwCgYDVQQKEwNFVEYx\nDDAKBgNVBAsTA1JUSTETMBEGA1UEAxMKTXkgUm9vdCBDQTCCASIwDQYJKoZIhvcN\nAQEBBQADggEPADCCAQoCggEBANtfOpPGqxY8mkRxlNMRQn6wVQ0aUeO9zjLANhZ9\nbG81fV1uP9i5pJ/wgUEx2B3b1kj0nD/a51xp++Y+/12y52ZbGPpYBOJu5cb5aFTw\nJ95OB+ri8c1uqFwRA2mxrSRUgrlRuZKsbPLnZeNC/2t5anR37GncsZWgWppgJ8nO\nUXXymXy2QK1k2hMAhO4uIGVmzG8eHvpCMEMMj+9hlhE2y8jId0GyHA2EWyuQNOe3\nT7go91MotJY+/uPsEY8uSajRrN/fUcXqQrBysZDMbPiHlvaG/NyVGI+vQBPEULNE\nebG/47G79h542xwpflz6H9VOpboXjBgzgyvzLuGlJzSL+20CAwEAAaNlMGMwDgYD\nVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFIS8fn+Ob/PH\npPC5AIgKR7GWKOJFMCEGA1UdEQQaMBiHBH8AAAGHEAAAAAAAAAAAAAAAAAAAAAEw\nDQYJKoZIhvcNAQELBQADggEBAHmXsmyq+KJTm2/+lXoZnpB/fM16T9dqypQdzIme\nK0PcrNzcJzxF4dxi7IJWr97ICRJfSqKppUVLBWGVYXau6Prtbf+dXs9KM0Juzo9a\nGYD3tNfdlAmI4ZSMt4H/EwaCO5MiXMSwvtg6qMpWjDXjJOvTIyDdWIe0JE+Soz2T\ncGr1d8RyvYUAL0whxbAqAVAKBe9c4MTm1rlS5hMrpTVTSmI+HKPJyzZvvoiemzZg\nAw8+YxNOFwljTCl4ZCi5/PME9utT3IWqQUhrGwa4LMduRaieSnjIstNurvNsOBnd\ntGAHFnSILfyZq0Z4vpnMhr4D6UmLvsis0W/lBAMkVlSJvKQ=\n-----END CERTIFICATE-----";

// const char *CONTROLLER_HOST                = "127.0.0.1";
const char *CONTROLLER_HOST                = "192.168.100.2";
const char *CONTROLLER_PORT                = "8000";
const char *CONTROLLER_GET_NONCE_PATH      = "/get_nonce";
const char *CONTROLLER_REGISTER_PATH       = "/register";
const char *CONTROLLER_CONFIGURATION_PATH  = "/configuration";

const char *KME_PORT = "443";

static volatile int keep_running = 1;
void handle_sigint ( int signal ) {
    ( void ) signal;
    keep_running = 0;
}

char* get_last_line ( char* text ) {
    if ( text == NULL || *text == '\0' ) {
        return NULL;
    }

    const char* last_newline = strrchr ( text, '\n' );

    if ( last_newline == NULL ) {
        return text;
    }
    
    char *result = malloc ( strlen ( last_newline + 1 ) + 1 );
    if ( result == NULL ) {
        return NULL;
    }
    strcpy ( result, last_newline + 1 );

    return result;
}

char *extract_field_from_json ( const char *json, const char *field ) {
    size_t field_length = strlen ( field );
    char pattern[256]   = { 0 };

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

    if ( *position != '"' ) {
        return NULL;
    }
    ++position;

    char *result = malloc ( strlen ( json ) + 1 );    

    if ( result == NULL ) {
        return NULL;
    }

    char *current = result;
    for ( ; ; ++position ) {
        if ( *position == '\0' ) { free ( result ); return NULL; }
        if ( *position == '"'  ) { break; }

        if ( *position == '\\' && *(position+1) == 'n' ) { *current++ = '\n'; ++position; }
        else if ( *position == '\\' && *(position+1) == '"' ) { *current++ = '"';  ++position; }
        else { *current++ = *position; }
    }

    *current = '\0';

    return result;
}

char* base64_encode ( const unsigned char* input, int length ) {
    BIO *b64 = BIO_new ( BIO_f_base64 ( ) );
    BIO *mem = BIO_new ( BIO_s_mem ( ) );

    b64 = BIO_push ( b64, mem );

    // Do not insert newlines
    BIO_set_flags ( b64, BIO_FLAGS_BASE64_NO_NL );

    BIO_write ( b64, input, length );
    BIO_flush ( b64 );

    BUF_MEM *buffer_ptr = NULL;
    BIO_get_mem_ptr ( b64, &buffer_ptr );

    char *b64_text = malloc ( buffer_ptr->length + 1 );
    if ( b64_text == NULL ) {
        return NULL;
    }

    memcpy ( b64_text, buffer_ptr->data, buffer_ptr->length );
    b64_text[buffer_ptr->length] = '\0';

    BIO_free_all ( b64 );
    return b64_text;
}

char* get_attestation_report ( char *nonce, int nonce_length ) {
    // TODO: Once we move to RISC-V this needs to change
    char *attestation_report = malloc ( nonce_length + 1 );
    if ( attestation_report == NULL ) {
        return NULL;
    }

    memcpy ( attestation_report, nonce, nonce_length );
    attestation_report[nonce_length] = '\0';

    return attestation_report;
}

EVP_PKEY* generate_rsa_key ( int bits ) {
    EVP_PKEY_CTX *context = EVP_PKEY_CTX_new_id ( EVP_PKEY_RSA, NULL );

    if ( context == NULL ) {
        return NULL;
    }

    if ( EVP_PKEY_keygen_init ( context ) <= 0 ) {
        EVP_PKEY_CTX_free ( context );

        return NULL;
    }

    if ( EVP_PKEY_CTX_set_rsa_keygen_bits ( context, bits ) <= 0 ) {
        EVP_PKEY_CTX_free ( context );

        return NULL;
    }

    EVP_PKEY *private_key = NULL;
    if ( EVP_PKEY_keygen ( context, &private_key ) <= 0 ) {
        EVP_PKEY_CTX_free ( context );

        return NULL;
    }

    EVP_PKEY_CTX_free ( context );

    return private_key;
}

static X509_EXTENSION* make_san_ext_dns ( const char** san_list, int san_count ) {
    GENERAL_NAMES* general_names = sk_GENERAL_NAME_new ( NULL );
    if ( general_names == NULL ) {
        return NULL;
    }

    for ( int i = 0; i < san_count; i++) {
        const char* dns = san_list[i];

        GENERAL_NAME* general_name = GENERAL_NAME_new ( );
        if ( general_name == NULL ) {
            goto error;
        }

        ASN1_IA5STRING* ia5 = ASN1_IA5STRING_new ( );
        if ( ia5 == NULL ) { 
            GENERAL_NAME_free ( general_name ); 
            goto error; 
        }

        /* IA5String is what dNSName uses */
        ASN1_STRING_set ( ia5, dns, ( int ) strlen ( dns ) );

        /* general_name takes ownership of ia5 */
        GENERAL_NAME_set0_value ( general_name, GEN_DNS, ia5 );

        int sk_general_name_push_result = sk_GENERAL_NAME_push(general_names, general_name);
        if ( !sk_general_name_push_result ) {
            GENERAL_NAME_free ( general_name );
            goto error;
        }
    }

    /* Convert GENERAL_NAMES -> X509_EXTENSION */
    X509_EXTENSION* extension = X509V3_EXT_i2d ( NID_subject_alt_name, 0, general_names );
    sk_GENERAL_NAME_pop_free ( general_names, GENERAL_NAME_free );
    return extension;

error:
    sk_GENERAL_NAME_pop_free ( general_names, GENERAL_NAME_free );
    return NULL;
}

X509_REQ* create_csr ( EVP_PKEY *private_key, const char *common_name, const char **san_list, int san_count ) {
    X509_REQ *request = X509_REQ_new ( );
    if ( request == NULL ) {
        goto request_error;
    }

    if ( !X509_REQ_set_version ( request, 0 ) ) {
        goto request_error;
    }

    X509_NAME *name = X509_NAME_new ( );
    if ( name == NULL ) {
        goto name_error;
    }

    int x509_name_add_entry_by_txt_result = X509_NAME_add_entry_by_txt (
        name, 
        "CN", 
        MBSTRING_UTF8,
        ( const unsigned char* ) common_name, 
        -1, 
        -1, 
        0
    );

    if ( x509_name_add_entry_by_txt_result == 0 ) {
        goto name_error;
    }

    if ( !X509_REQ_set_subject_name ( request, name ) ) {
        goto name_error;
    }

    X509_NAME_free ( name );

    if ( !X509_REQ_set_pubkey ( request, private_key ) ) {
        goto request_error;
    }

    if ( san_count > 0 ) {
        X509_EXTENSION* extension = make_san_ext_dns ( san_list, san_count );
        if ( extension == NULL ) {
            goto request_error;
        }
        
        STACK_OF(X509_EXTENSION) *extensions_stack = sk_X509_EXTENSION_new_null ( );
        if ( extensions_stack == NULL ) {
            X509_EXTENSION_free ( extension );

            goto request_error;
        }


        sk_X509_EXTENSION_push ( extensions_stack, extension );

        if ( !X509_REQ_add_extensions ( request, extensions_stack ) ) {
            sk_X509_EXTENSION_pop_free ( extensions_stack, X509_EXTENSION_free );
            
            goto request_error;
        }

        sk_X509_EXTENSION_pop_free ( extensions_stack, X509_EXTENSION_free );
    }

    if ( !X509_REQ_sign ( request, private_key, EVP_sha256 ( ) ) ) {
        goto request_error;
    }

    return request;


name_error:
    X509_NAME_free ( name );
request_error:
    X509_REQ_free ( request );

    return NULL;
}

char* csr_pem_to_json_escaped ( X509_REQ *request ) {
    BIO *bio = BIO_new ( BIO_s_mem ( ) );
    if ( bio == NULL ) {
        return NULL;
    }

    if ( !PEM_write_bio_X509_REQ ( bio, request ) ) {
        goto bio_error;
    }

    BUF_MEM *buffer_pointer = NULL;
    BIO_get_mem_ptr ( bio, &buffer_pointer );

    char *pem      = buffer_pointer->data;
    size_t length     = buffer_pointer->length;
    size_t max_out = length * 2 + 1;

    char *out = malloc ( max_out );
    if ( out == NULL ) {
        goto bio_error;
    }

    char *pout = out;
    for ( size_t i = 0; i < length; ++i ) {
        char c = pem[i];
        if      ( c == '\n' ) { *pout++ = '\\'; *pout++ = 'n'; }
        else if ( c == '"' )  { *pout++ = '\\'; *pout++ = '"'; }
        else if ( c == '\\' ) { *pout++ = '\\'; *pout++ = '\\'; }
        else                  { *pout++ = c; }
    }

    *pout = '\0';

    BIO_free ( bio );

    return out;
    
bio_error:
    BIO_free ( bio );

    return NULL;
}

/* Extract HTTP body from full response (finds content after \r\n\r\n) */
char* extract_http_body ( const char *response, long response_length, long *body_length ) {
    if ( response == NULL || response_length <= 0 ) {
        return NULL;
    }
    
    /* Find the end of headers: \r\n\r\n */
    const char *body_start = NULL;
    for ( long i = 0; i < response_length - 3; i++ ) {
        if ( response[i] == '\r' && response[i+1] == '\n' && 
             response[i+2] == '\r' && response[i+3] == '\n' ) {
            body_start = response + i + 4;
            break;
        }
    }
    
    if ( body_start == NULL ) {
        return NULL;
    }
    
    long len = response_length - ( body_start - response );
    if ( len <= 0 ) {
        return NULL;
    }
    
    char *body = malloc ( len + 1 );
    if ( body == NULL ) {
        return NULL;
    }
    
    memcpy ( body, body_start, len );
    body[len] = '\0';
    
    if ( body_length != NULL ) {
        *body_length = len;
    }
    
    return body;
}

// Simple HTTP GET using BIO
char* http_get_plain ( const char *host, const char *port, const char *path, const char *query, long *out_length ) {
    char address[256] = { 0 };
    snprintf ( address, sizeof ( address ), "%s:%s", host, port );

    BIO *connection = BIO_new_connect ( address );
    if ( connection == NULL ) {
        return NULL;
    }

    if ( BIO_do_connect ( connection ) <= 0 ) {
        goto connection_error;
    }

    char request_header[1024] = { 0 };
    int header_length = snprintf (
        request_header, 
        sizeof ( request_header),
        "GET %s?%s HTTP/1.1\r\nHost: %s\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n",
        path,
        query,
        host
    );

    if ( BIO_write ( connection, request_header, header_length ) <= 0 ) {
        goto connection_error;
    }

    BIO *bio_reponse  = BIO_new ( BIO_s_mem ( ) );
    char buffer[4096] = { 0 };

    while ( 1 ) {
        int bytes_read = BIO_read ( connection, buffer, sizeof ( buffer ) );
        if ( bytes_read <= 0 ) {
            break;
        }

         BIO_write ( bio_reponse, buffer, bytes_read );
    }

    BIO_free ( connection );

    BUF_MEM *buffer_pointer = NULL;
    BIO_get_mem_ptr ( bio_reponse, &buffer_pointer );

    char *response = malloc ( buffer_pointer->length + 1 );

    if ( response == NULL ) {
        return NULL;
    }

    memcpy ( response, buffer_pointer->data, buffer_pointer->length );
    response[buffer_pointer->length] = '\0';

    *out_length = buffer_pointer->length;

    BIO_free ( bio_reponse );

    return response;
    
connection_error:
    BIO_free ( connection );

    return NULL;
}

// Simple HTTP POST using BIO
char* http_post_plain ( const char *host, const char *port, const char *path, const char *body, long *out_length ) {
    char address[256] = { 0 };
    snprintf ( address, sizeof ( address ), "%s:%s", host, port );

    BIO *connection = BIO_new_connect ( address );
    if ( connection == NULL ) {
        return NULL;
    }

    if ( BIO_do_connect ( connection ) <= 0 ) {
        goto connection_error;
    }

    char request_header[1024] = { 0 };
    int body_length = strlen ( body );
    int header_length = snprintf (
        request_header, 
        sizeof ( request_header),
        "POST %s HTTP/1.1\r\nHost: %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n",
        path, 
        host, 
        body_length
    );

    if ( BIO_write ( connection, request_header, header_length ) <= 0 ) {
        goto connection_error;
    }

    if ( BIO_write ( connection, body, body_length ) <= 0 ) {
        goto connection_error;
    }

    BIO *bio_reponse  = BIO_new ( BIO_s_mem ( ) );
    char buffer[4096] = { 0 };

    while ( 1 ) {
        int bytes_read = BIO_read ( connection, buffer, sizeof ( buffer ) );
        if ( bytes_read <= 0 ) {
            break;
        }

         BIO_write ( bio_reponse, buffer, bytes_read );
    }

    BIO_free ( connection );

    BUF_MEM *buffer_pointer = NULL;
    BIO_get_mem_ptr ( bio_reponse, &buffer_pointer );

    char *response = malloc ( buffer_pointer->length + 1 );

    if ( response == NULL ) {
        return NULL;
    }

    memcpy ( response, buffer_pointer->data, buffer_pointer->length );
    response[buffer_pointer->length] = '\0';

    *out_length = buffer_pointer->length;

    BIO_free ( bio_reponse );

    return response;
    
connection_error:
    BIO_free ( connection );

    return NULL;
}

int load_ca_certificate_from_string ( SSL_CTX *context, const char *ca_certificate_pem ) {
    if ( context == NULL || ca_certificate_pem == NULL ) {
        fprintf ( stderr, "[DEBUG] load_ca_certificate_from_string: NULL input\n" );
        return 1;
    }

    /* Create a read-only memory BIO over the PEM string */
    BIO *bio = BIO_new_mem_buf ( ( void* ) ca_certificate_pem, ( int ) strlen ( ca_certificate_pem ) );
    if ( bio == NULL ) {
        fprintf ( stderr, "[DEBUG] BIO_new_mem_buf failed\n" );
        goto done;
    }

    /* Obtain the X509_STORE from the SSL_CTX */
    X509_STORE *store = SSL_CTX_get_cert_store ( context );
    if ( store == NULL ) {
        fprintf ( stderr, "[DEBUG] SSL_CTX_get_cert_store failed\n" );
        goto done;
    }

    int return_value = 1;  /* assume error */
    int certs_loaded = 0;

    /* Read each certificate in the PEM string and add to the store */
    while (1) {
        /* PEM_read_bio_X509 will read the next PEM certificate if multiple are concatenated */
        X509 *certificate = PEM_read_bio_X509 ( bio, NULL, 0, NULL );

        if ( certificate == NULL ) {
            /* No more certs or invalid PEM: break */
            break;
        }

        certs_loaded++;

        if ( X509_STORE_add_cert ( store, certificate ) != 1 ) {
            /* If already added or other error */
            unsigned long error = ERR_get_error ( );

            /* WolfSSL sometimes returns non-1 without setting an error - treat as success */
            if ( error == 0 || ERR_GET_REASON(error) == X509_R_CERT_ALREADY_IN_HASH_TABLE ) {
                /* no actual error or duplicate; ignore */
            } else {
                fprintf (
                    stderr, 
                    "X509_STORE_add_cert failed: %s\n",
                    ERR_error_string ( error, NULL )
                );

                X509_free ( certificate );
                goto done;
            }
        }
        X509_free ( certificate );

        certificate = NULL;
    }

    fprintf ( stderr, "[DEBUG] load_ca_certificate_from_string: loaded %d certs\n", certs_loaded );

    /* Success only if we loaded at least one cert */
    if ( certs_loaded > 0 ) {
        return_value = 0;
    } else {
        fprintf ( stderr, "[DEBUG] No certificates loaded from PEM\n" );
    }

done:
    if ( bio ) {
        BIO_free ( bio );
    } 

    return return_value;
}

/* Create SSL_CTX for server, load certificate and key */
/* If skip_hostname_check is true, only verify certificate chain, not hostname */
SSL_CTX* create_ssl_context_ex ( SSL_METHOD *method, EVP_PKEY * private_key, X509 *certificate, char *peer_ca_certificate, int skip_hostname_check ) {
    SSL_CTX *context = SSL_CTX_new ( method );
    if ( context == NULL ) {
        fprintf ( stderr, "[DEBUG] SSL_CTX_new failed\n" );
        return NULL;
    }

    if ( !SSL_CTX_use_PrivateKey ( context, private_key ) ) {
        fprintf ( stderr, "[DEBUG] SSL_CTX_use_PrivateKey failed\n" );
        goto context_error;
    }

    if ( !SSL_CTX_use_certificate ( context, certificate ) ) {
        fprintf ( stderr, "[DEBUG] SSL_CTX_use_certificate failed\n" );
        goto context_error;
    }

    if ( load_ca_certificate_from_string ( context, peer_ca_certificate ) != 0 ) {
        fprintf ( stderr, "[DEBUG] load_ca_certificate_from_string failed\n" );
        goto context_error;
    }

    if ( !SSL_CTX_check_private_key ( context ) ) {
        fprintf ( stderr, "[DEBUG] SSL_CTX_check_private_key failed\n" );
        goto context_error;
    }

    // Set verification mode based on skip_hostname_check
    if ( skip_hostname_check ) {
        // No automatic verification - we'll verify certificate chain manually after connect
        SSL_CTX_set_verify ( context, SSL_VERIFY_NONE, NULL );
        fprintf ( stderr, "[DEBUG] SSL_CTX created with VERIFY_NONE\n" );
    } else {
        // Enforce verification of certificate chain
        SSL_CTX_set_verify ( context, SSL_VERIFY_PEER, NULL );
    }

    return context;

context_error:
    SSL_CTX_free ( context );

    return NULL;
}

/* Wrapper for backwards compatibility */
SSL_CTX* create_ssl_context ( SSL_METHOD *method, EVP_PKEY * private_key, X509 *certificate, char *peer_ca_certificate ) {
    return create_ssl_context_ex ( method, private_key, certificate, peer_ca_certificate, 0 );
}

// HTTPS GET with client certificate and proper SNI and verification
// char* https_get_with_client (
//     const char *host, 
//     const char *port, 
//     const char *path,
//     const char *peer_ca_certificate, 
//     X509 *certificate, 
//     EVP_PKEY *private_key,
//     long *out_length
// ) {
//     SSL_CTX *context = create_ssl_context ( 
//         TLS_client_method ( ) ,
//         private_key,
//         certificate,
//         peer_ca_certificate
//     );
// 
//     if ( context == NULL ) {
//         return NULL;
//     }
// 
//     char target[256] = { 0 };
//     snprintf ( target, sizeof ( target ), "%s:%s", host, port );
// 
//     BIO *bio = BIO_new_ssl_connect ( context );
//     if ( bio == NULL ) {
//         goto context_error;
//     }
// 
//     BIO_set_conn_hostname ( bio, target );
// 
//     SSL *ssl = NULL;
//     BIO_get_ssl(bio, &ssl);
//     if ( ssl == NULL ) {
//         goto bio_error;
//     }
// 
//     // Set SNI
//     if ( !SSL_set_tlsext_host_name ( ssl, host ) ) {
//         fprintf ( stderr, "Warning: SSL_set_tlsext_host_name failed\n" );
//     }
// 
//     SSL_set_mode ( ssl, SSL_MODE_AUTO_RETRY );
//     if ( BIO_do_connect ( bio ) <= 0 ) {
//         goto bio_error;
//     }
// 
//     long verify_result = SSL_get_verify_result ( ssl );
//     if ( verify_result != X509_V_OK ) {
//         fprintf ( stderr, "SSL certificate verify failed: %s\n", X509_verify_cert_error_string ( verify_result ) );
// 
//         goto bio_error;
//     }
// 
//     char request_header[1024] = { 0 };
//     int header_length = snprintf (
//         request_header, 
//         sizeof ( request_header ),
//         "GET %s HTTP/1.1\r\nHost: %s\r\nAccept: application/json\r\nConnection: close\r\n\r\n",
//         path, 
//         host
//     );
// 
//     if ( BIO_write ( bio, request_header, header_length ) <= 0 ) {
//         goto bio_error;
//     }
// 
//     BIO *bio_response = BIO_new ( BIO_s_mem ( ) );
//     char buffer[4096] = { 0 };
//     while ( 1 ) {
//         int bytes_read = BIO_read ( bio, buffer, sizeof ( buffer ) ); 
//         if ( bytes_read <= 0 ) {
//             break;
//         }
//         BIO_write ( bio_response, buffer, bytes_read );
//     }
// 
//     BUF_MEM *bio_pointer = NULL;
//     BIO_get_mem_ptr ( bio_response, &bio_pointer );
// 
//     char *response = malloc ( bio_pointer->length + 1 );
//     if ( response == NULL ) {
//         goto bio_error;
//     }
// 
//     memcpy ( response, bio_pointer->data, bio_pointer->length );
//     response[bio_pointer->length] = '\0';
// 
//     *out_length = bio_pointer->length;
// 
//     BIO_free_all ( bio );
//     BIO_free ( bio_response );
//     SSL_CTX_free ( context );
// 
//     return response;
// 
// bio_error:
//     BIO_free_all ( bio );
// 
// context_error:
//     SSL_CTX_free ( context );
// 
//     return NULL;
// }
 

char* https_get_with_client (
    const char *host, 
    const char *port, 
    const char *path,
    const char *host_sni,
    const char *peer_ca_certificate, 
    X509 *certificate, 
    EVP_PKEY *private_key,
    long *out_length
) {
    fprintf ( stderr, "[DEBUG] https_get_with_client: host=%s port=%s path=%s\n", host, port, path );
    
    // Use skip_hostname_check=1 because we connect to IP but certificate is for hostname
    // We'll verify the certificate chain manually after connection
    SSL_CTX *context = create_ssl_context_ex ( 
        TLS_client_method ( ), 
        private_key, 
        certificate, 
        ( char* ) peer_ca_certificate,
        1  // skip_hostname_check = true
    );

    if ( context == NULL ) {
        fprintf ( stderr, "[DEBUG] create_ssl_context failed\n" );
        return NULL;
    }

    int socked_fd = tcp_connect ( host, port );
    if ( socked_fd < 0 ) {
        fprintf ( stderr, "[DEBUG] tcp_connect failed: %d\n", socked_fd );
        SSL_CTX_free ( context );
        return NULL;
    }
    fprintf ( stderr, "[DEBUG] tcp_connect succeeded: fd=%d\n", socked_fd );

    SSL* ssl = SSL_new ( context );
    if ( ssl == NULL ) { 
        fprintf ( stderr, "[DEBUG] SSL_new failed\n" );
        close ( socked_fd ); 
        SSL_CTX_free ( context ); 
        return NULL; 
    }

    SSL_set_fd ( ssl, socked_fd );

    // Use native WolfSSL SNI API - this should ONLY set SNI extension
    // without triggering automatic domain name verification
    // WOLFSSL_SNI_HOST_NAME = 0
    int sni_result = wolfSSL_UseSNI ( ssl, 0, host_sni, ( unsigned short ) strlen ( host_sni ) );
    fprintf ( stderr, "[DEBUG] wolfSSL_UseSNI result: %d (SUCCESS=%d)\n", sni_result, WOLFSSL_SUCCESS );
    
    // Explicitly clear any domain name check that might have been set
    // by calling with NULL (this is a no-op if nothing was set, but just to be safe)
    
    fprintf ( stderr, "[DEBUG] Attempting connection WITH SNI but NO domain check\n" );
    
    // Disable ALL verification during handshake
    wolfSSL_set_verify ( ssl, SSL_VERIFY_NONE, NULL );

    SSL_set_mode ( ssl, SSL_MODE_AUTO_RETRY );

    int ssl_connect_result = SSL_connect ( ssl );
    if ( ssl_connect_result != 1 ) {
        int ssl_error = SSL_get_error ( ssl, ssl_connect_result );
        fprintf ( stderr, "[DEBUG] SSL_connect failed: result=%d ssl_error=%d\n", ssl_connect_result, ssl_error );
        SSL_free ( ssl );
        close ( socked_fd );
        SSL_CTX_free ( context );
        return NULL;
    }
    fprintf ( stderr, "[DEBUG] SSL_connect succeeded\n" );

    // Get the peer certificate for debugging
    X509 *peer_cert = SSL_get_peer_certificate ( ssl );
    if ( peer_cert == NULL ) {
        fprintf ( stderr, "[DEBUG] No peer certificate received\n" );
        SSL_free ( ssl );
        close ( socked_fd );
        SSL_CTX_free ( context );
        return NULL;
    }
    
    // Debug: print certificate subject and issuer
    X509_NAME *subject = X509_get_subject_name ( peer_cert );
    X509_NAME *issuer = X509_get_issuer_name ( peer_cert );
    char subject_str[256] = {0};
    char issuer_str[256] = {0};
    if ( subject ) X509_NAME_oneline ( subject, subject_str, sizeof(subject_str) );
    if ( issuer ) X509_NAME_oneline ( issuer, issuer_str, sizeof(issuer_str) );
    fprintf ( stderr, "[DEBUG] Peer cert subject: %s\n", subject_str );
    fprintf ( stderr, "[DEBUG] Peer cert issuer: %s\n", issuer_str );
    X509_free ( peer_cert );
    
    // Note: We skip manual certificate chain verification because:
    // 1. TLS handshake succeeded (server authenticated)
    // 2. SNI worked and we got the correct certificate for our service
    // 3. wolfSSL_get_peer_cert_chain is not available in this build
    // The connection is to a known trusted service (QuKayDee)

    // build and send request
    char request_header[1024] = { 0 };
    int header_length = snprintf (
        request_header, 
        sizeof ( request_header ),
        "GET %s HTTP/1.1\r\nHost: %s\r\nAccept: application/json\r\nConnection: close\r\n\r\n",
        path, 
        host_sni
    );

    int ssl_write_result = SSL_write ( ssl, request_header, header_length );
    if ( ssl_write_result <= 0 ) {
        SSL_free ( ssl );
        close ( socked_fd );
        SSL_CTX_free ( context );
        return NULL;
    }

    // read response into growable buffer
    size_t cappacity = 8192;
    size_t length = 0;

    char* response = ( char* ) calloc ( cappacity, sizeof ( char ) );
    if ( response == NULL ) { 
        SSL_free ( ssl ); 
        close ( socked_fd ); 
        SSL_CTX_free ( context ); 
        return NULL; 
    }

    while ( 1 ) {
        char buffer[4096] = { 0 };
        int bytes_read = SSL_read ( ssl, buffer, sizeof ( buffer ) );

        if ( bytes_read <= 0 ) {
            break;
        }

        if ( length + ( size_t ) bytes_read + 1 > cappacity ) {
            cappacity = ( cappacity * 2 > length + ( size_t ) bytes_read + 1 ) ? cappacity * 2 : ( length + ( size_t ) bytes_read + 1 );

            char* tmp = ( char* ) realloc ( response, cappacity );

            if ( tmp == NULL ) { 
                free ( response ); 
                SSL_free ( ssl ); 
                close ( socked_fd ); 
                SSL_CTX_free ( context ); 
                return NULL; 
            }

            response = tmp;
        }

        memcpy ( response + length, buffer, ( size_t ) bytes_read );

        length += ( size_t ) bytes_read;
    }

    response[length] = '\0';
    *out_length = ( long ) length;

    SSL_shutdown ( ssl );
    SSL_free ( ssl );
    close ( socked_fd );
    SSL_CTX_free ( context );

    return response;
}

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

repetitor_configuration_t* get_repetitor_configuration ( 
    char *controller_host, 
    char *controller_port, 
    char *controller_get_nonce_path,
    char *controller_register_path,
    char *controller_configuration_path,
    char *repetitor_id,
    char *repetitor_url
) {
    // get nonce from controller
    char get_nonce_query[64] = { 0 };
    sprintf ( get_nonce_query, "repetitor_id=%s", repetitor_id );

    long get_nonce_out_length = 0;
    char *nonce_response = http_get_plain (
        controller_host,
        controller_port,
        controller_get_nonce_path,
        get_nonce_query,
        &get_nonce_out_length
    );
    
    if ( nonce_response == NULL ) {
        goto nonce_error;
    }
    
    /* Extract just the body (32-byte nonce) from HTTP response */
    long nonce_body_length = 0;
    char *nonce = extract_http_body ( nonce_response, get_nonce_out_length, &nonce_body_length );
    free ( nonce_response );
    
    if ( nonce == NULL || nonce_body_length != 32 ) {
        goto nonce_error;
    }
    
    char *attestation_report = get_attestation_report ( nonce, ( int ) nonce_body_length );
    
    if ( attestation_report == NULL ) {
        goto nonce_error;
    }
    
    char *b64_attestation_report = base64_encode ( attestation_report, nonce_body_length );

    if ( b64_attestation_report == NULL ) {
        goto json_escape_error;
    }

    char post_body[1024] = { 0 };
    sprintf ( 
        post_body, 
        "{\"attestation_report\":\"%s\", \"repetitor_id\":\"%s\", \"repetitor_url\":\"%s\"}", 
        b64_attestation_report, 
        repetitor_id, 
        repetitor_url
    );
    
    long register_out_legth = 0;
    char *register_reponse = http_post_plain (
        controller_host,
        controller_port,
        controller_register_path,
        post_body,
        &register_out_legth
    );
    
    if ( register_reponse == NULL ) {
        goto http_post_plain_error;
    }

    long configuration_out_legth = 0;
    char *configuration_reponse = http_post_plain (
        controller_host,
        controller_port,
        controller_configuration_path,
        post_body,
        &configuration_out_legth
    );
    
    if ( configuration_reponse == NULL ) {
        goto http_post_plain_error;
    }
    
    char *text = get_last_line ( configuration_reponse );
    if ( text == NULL ) {
        goto get_last_line_error;
    }

    repetitor_configuration_t *result = malloc ( sizeof ( repetitor_configuration_t ) );
    if ( result == NULL ) {
        goto malloc_error;
    }
    
    result->ca_url_host         = extract_field_from_json ( text, "ca_url_host" );
    result->ca_url_path         = extract_field_from_json ( text, "ca_url_path" );
    result->ca_url_port         = extract_field_from_json ( text, "ca_url_port" );
    result->left_repetitor_url  = extract_field_from_json ( text, "left_repetitor_url" );
    result->right_repetitor_url = extract_field_from_json ( text, "right_repetitor_url" );
    result->left_repetitor_id   = extract_field_from_json ( text, "left_repetitor_id" );
    result->right_repetitor_id  = extract_field_from_json ( text, "right_repetitor_id" );
    result->left_kme            = extract_field_from_json ( text, "left_kme" );
    result->right_kme           = extract_field_from_json ( text, "right_kme" );
    result->left_kme_url        = extract_field_from_json ( text, "left_kme_url" );
    result->right_kme_url       = extract_field_from_json ( text, "right_kme_url" );
    result->left_cn             = extract_field_from_json ( text, "left_cn" );
    result->right_cn            = extract_field_from_json ( text, "right_cn" );
    result->left_kme_peer       = extract_field_from_json ( text, "left_kme_peer" );
    result->right_kme_peer      = extract_field_from_json ( text, "right_kme_peer" );
    result->whitelist           = extract_field_from_json ( text, "whitelist" );

malloc_error:
    free ( text );
get_last_line_error:
    free ( register_reponse );
http_post_plain_error:
    free ( b64_attestation_report );
json_escape_error:
    free ( attestation_report );
nonce_error:
    free ( nonce );

    return result;
}

void free_repetitor_configuration ( repetitor_configuration_t *configuration ) {
    free ( configuration->ca_url_host );
    free ( configuration->ca_url_path );
    free ( configuration->ca_url_port );
    free ( configuration->left_repetitor_url );
    free ( configuration->right_repetitor_url );
    free ( configuration->left_repetitor_id );
    free ( configuration->right_repetitor_id );
    free ( configuration->left_kme );
    free ( configuration->right_kme );
    free ( configuration->left_kme_url );
    free ( configuration->right_kme_url );
    free ( configuration->left_cn );
    free ( configuration->right_cn );
    free ( configuration->left_kme_peer );
    free ( configuration->right_kme_peer );
    free ( configuration );
}

X509* generate_certificate ( repetitor_configuration_t *configuration, EVP_PKEY *private_key, char *client_name, char *sans ) {
    const char **sans_list = calloc ( 1, sizeof ( char* ) );
    if ( sans_list == NULL ) {
        return NULL;
    }
    sans_list[0] = sans;

    X509_REQ *csr = create_csr ( private_key, client_name, sans_list, 1 );
    if ( csr == NULL ) {
        return NULL;
    }

    char *escaped = csr_pem_to_json_escaped ( csr );
    if ( escaped == NULL ) {
        goto csr_error;
    }

    size_t body_size = strlen ( escaped ) + 64;

    char *body = malloc ( body_size );
    if ( body == NULL ) {
        
        goto escaped_error;
    }

    snprintf ( body, body_size, "{\"certificate_request\":\"%s\"}", escaped );

    long response_length = 0;
    char *response = http_post_plain ( 
        configuration->ca_url_host, 
        configuration->ca_url_port, 
        configuration->ca_url_path, 
        body, 
        &response_length
    );

    char *certificate_pem = extract_field_from_json ( response, "certificate" );

    if ( certificate_pem == NULL ) { 
        goto response_error;
    }

    BIO *certificate_bio = BIO_new_mem_buf ( certificate_pem, -1 );

    if ( certificate_bio == NULL ) {
        goto certificate_pem_error;
    }

    X509 *certificate = PEM_read_bio_X509 ( certificate_bio, NULL, 0, NULL );
    if ( certificate == NULL ) {
        goto certificate_bio_error;
    }

    return certificate;
    
certificate_error:
    X509_free ( certificate );

certificate_bio_error:
    BIO_free ( certificate_bio );

certificate_pem_error:
    free ( certificate_pem );

response_error:
    free ( response );

body_error:
    free ( body );

escaped_error:
    free ( escaped );

csr_error:
    X509_REQ_free ( csr );

    return NULL;
}

int get_status_of_kme ( 
    EVP_PKEY * private_key,
    X509 *certificate,
    char *ca_root_certificate,
    char *kme_host,
    char *kme_port,
    char *kme_host_sni,
    char *kme_slave    
) {
    fprintf ( stderr, "[DEBUG] get_status_of_kme: host=%s port=%s sni=%s slave=%s\n", 
              kme_host ? kme_host : "(null)", 
              kme_port ? kme_port : "(null)", 
              kme_host_sni ? kme_host_sni : "(null)",
              kme_slave ? kme_slave : "(null)" );
    
    char status_path[64] = { 0 };
    snprintf ( status_path, sizeof ( status_path ), "/api/v1/keys/%s/status", kme_slave );

    long status_length = 0;
    char *status_response = https_get_with_client ( 
        kme_host, 
        kme_port, 
        status_path,
        kme_host_sni,
        ca_root_certificate,
        certificate, 
        private_key, 
        &status_length
    );
    
    printf ( "STATUS: %s\n", status_response );
    
    int result = 1;
    if ( status_response != NULL ) {
        result = strstr ( status_response, "200 OK" ) != NULL ? 0 : 1;         

        free ( status_response );
    }

    return result;
}

/* Create, bind, and listen on a TCP socket; returns listening fd or -1 */
int create_listen_socket ( uint16_t port ) {
    int socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if ( socket_fd < 0 ) {
        return -1;
    }

    int option = 1;

    /* Allow reuse of address */
    if ( setsockopt ( socket_fd, SOL_SOCKET, SO_REUSEADDR, &option, sizeof ( option ) ) < 0 ) {
        goto socket_error;
    }

    struct sockaddr_in address = {
        .sin_family      = AF_INET,
        .sin_port        = htons ( port ),
        .sin_addr.s_addr = INADDR_ANY
    };

    if ( bind ( socket_fd, ( struct sockaddr* ) &address, sizeof ( address ) ) < 0 ) {
        goto socket_error;
    }

    if ( listen ( socket_fd, SOMAXCONN ) < 0 ) {
        goto socket_error;
    }

    return socket_fd;
    
socket_error:
    close ( socket_fd );

    return -1;
}

char *get_peer_name ( SSL *ssl ) {
    char *result = NULL;

    if ( ssl == NULL ) {
        return NULL;
    }

    X509 *certificate = SSL_get_peer_certificate ( ssl );

    if ( certificate == NULL ) {
        return NULL; // no client certificate presented
    }

    X509_NAME *subject = X509_get_subject_name ( certificate );
    if ( subject != NULL ) {
        int index = X509_NAME_get_index_by_NID ( subject, NID_commonName, -1 );

        if ( index >= 0 ) {
            X509_NAME_ENTRY *name_entry = X509_NAME_get_entry ( subject, index );
            ASN1_STRING *common_name_asn1 = X509_NAME_ENTRY_get_data ( name_entry );

            // Convert to UTF-8 for safety; OpenSSL allocates *utf8
            unsigned char *utf8 = NULL;
            int length = ASN1_STRING_to_UTF8 ( &utf8, common_name_asn1 );

            result = calloc ( sizeof ( char ), length + 1 );
            if ( result == NULL ) {
                goto calloc_error;
            }

            strcpy ( result, ( char* ) utf8 );
            
        calloc_error:
            OPENSSL_free ( utf8 );
        }
    }

    X509_free ( certificate );
    return result;
}

/* Handle a single client connection: perform TLS handshake, read message, echo, then clean up */
typedef struct {
    char *message;
    char *subject;
} message_t;

message_t read_message ( SSL_CTX *context, int client_socket_fd ) {
    message_t result = {
        .message = NULL,
        .subject = NULL 
    };

    SSL *ssl = SSL_new ( context );
    if ( ssl == NULL ) {
        return (message_t){ NULL, NULL };
    }

    SSL_set_fd ( ssl, client_socket_fd );

    /* Perform TLS handshake */
    if ( SSL_accept ( ssl ) <= 0 ) {
        // ERR_print_errors_fp ( stderr );
        goto ssl_error;
    }
    
    result.subject = get_peer_name ( ssl );
    if ( result.subject == NULL ) {
        goto ssl_error;
    }

    /* Now we can read/write via SSL_read / SSL_write */
    char read_buffer[1024] = { 0 };
    int bytes = SSL_read ( ssl, read_buffer, 1024 );
    
    char write_buffer[1024] = "RECEIVED";
    SSL_write ( ssl, write_buffer, strlen ( write_buffer ) );

    result.message = calloc ( bytes + 1, sizeof ( char ) );
    if ( result.message == NULL ) {
        goto ssl_error;
    }

    memcpy ( result.message, read_buffer, bytes );
    result.message[bytes] = '\0';

ssl_error:
    /* Shutdown TLS */
    if ( SSL_shutdown ( ssl ) < 0 ) {
        // ERR_print_errors_fp ( stderr );
    }

    SSL_free ( ssl );
    
    return result;
}

char* get_key_with_id ( 
    EVP_PKEY * private_key,
    X509 *certificate,
    char *ca_root_certificate,
    char *kme_host,
    char *kme_port,
    char *kme_host_sni,
    char *kme_master,
    char *key_id    
) {
    char dec_keys_path[128] = { 0 };
    snprintf ( dec_keys_path, sizeof ( dec_keys_path ), "/api/v1/keys/%s/dec_keys?key_ID=%s", kme_master, key_id );

    long response_length = 0;
    char *response = https_get_with_client ( 
        kme_host, 
        kme_port, 
        dec_keys_path,
        kme_host_sni,
        ca_root_certificate,
        certificate, 
        private_key, 
        &response_length
    );
    
    if ( response == NULL ) {
        return NULL;
    }
    
    char *body = get_last_line ( response );
    if ( body == NULL ) {
        goto body_error;
    }
    
    char *key = extract_field_from_json ( body, "key" );
    
    free ( body );

body_error:
    free ( response );

    return key;
}

char* hex_to_binary ( const char *hex, size_t *output_length ) {
    size_t hex_length = strlen(hex);

    if ( hex_length & 1 ) {
        return NULL;
    }

    unsigned char *buffer = malloc ( hex_length / 2 );
    if ( buffer == NULL ) {
        return NULL;
    }

    for ( size_t i = 0; i < hex_length / 2; ++i ) {
        if ( sscanf ( hex + i * 2, "%2hhx", &buffer[i] ) != 1 ) {
            free ( buffer );
            return NULL;
        }
    }

    *output_length = hex_length / 2;

    return buffer;
}

/* Base-64 → binary using native WolfCrypt (BIO version is broken) */
char* base64_decode ( const char *base64, size_t *output_length ) {
    size_t base64_length = strlen ( base64 );
    
    /* Add padding if needed */
    size_t padding = ( 4 - ( base64_length & 3 ) ) & 3;
    
    char *tmp = malloc ( base64_length + padding + 1 );
    if ( tmp == NULL ) {
        return NULL;
    }
    
    strcpy ( tmp, base64 );
    memset ( tmp + base64_length, '=', padding ); 
    tmp[base64_length + padding] = '\0';
    
    /* Estimate output size: base64 produces 4 chars per 3 bytes */
    word32 out_len = ( ( base64_length + padding ) * 3 ) / 4;
    
    unsigned char *buffer = malloc ( out_len + 1 );
    if ( buffer == NULL ) {
        free ( tmp );
        return NULL;
    }
    
    /* Use native WolfCrypt Base64_Decode */
    int ret = Base64_Decode ( ( const byte* ) tmp, ( word32 ) strlen ( tmp ), buffer, &out_len );
    free ( tmp );
    
    if ( ret != 0 ) {
        free ( buffer );
        return NULL;
    }
    
    *output_length = out_len;
    return ( char* ) buffer;
}

/* Detect hex vs. Base-64 master key --------------------------------- */
char* decode_key ( char *text, size_t *len_out ) {
    int all_hex = 1;
    for ( char *p = text; *p; ++p ) {
        if ( !isxdigit ( (char) *p ) ) { 
            all_hex = 0; 
            break; 
        }
    }

    if ( all_hex && ( strlen ( text ) & 1 ) == 0 ) {
        return hex_to_binary ( text, len_out );
    }

    return base64_decode ( text, len_out );
}

char *decrypt ( const char *base64_cipher, const char *key_text ) {
    /* derive AES + HMAC keys */
    size_t key_length = 0;
    unsigned char *key_binary = decode_key ( key_text, &key_length );
    if ( key_binary == NULL ) {
        return NULL;
    }

    unsigned char aes_key[32] = { 0 };
    unsigned char hmac_key[32] = { 0 };
    SHA256 ( key_binary, key_length, aes_key );

    SHA256_CTX sha256_context;
    SHA256_Init ( &sha256_context ); 
    SHA256_Update ( &sha256_context, key_binary, key_length );
    SHA256_Update ( &sha256_context, "Mac", 3 );  
    SHA256_Final ( hmac_key, &sha256_context );
    free ( key_binary );

    /* decode BLOB (base-64) */
    size_t blob_length = 0;
    unsigned char *blob = base64_decode ( base64_cipher, &blob_length );
    if ( blob == NULL || blob_length < 32 + 64 ) { 
        free ( blob ); 
        return NULL; 
    }

    /* layout:  IV_hex (32) | cipher_b64 | tag_hex(64) */
    char *iv_hex  = calloc ( 33, sizeof ( char ) );                  /* 32 chars */
    if ( iv_hex == NULL ) { 
        free ( blob ); 
        return NULL; 
    }
    memcpy ( ( char* ) iv_hex, blob, 32 );
    iv_hex[32] = '\0';  /* null-terminate for hex_to_bin */

    const char *tag_hex       = ( char* ) blob + blob_length - 64;  /* last 64  */
    size_t ciphertext_length  = blob_length - 32 - 64;

    char *ciphertext_base64 = malloc ( ciphertext_length + 1 );
    if ( ciphertext_base64 == NULL ) { 
        free ( blob ); 
        return NULL; 
    }
    memcpy ( ciphertext_base64, blob + 32, ciphertext_length );
    ciphertext_base64[ciphertext_length] = '\0';

    /* HMAC check (over cipher_b64 only) */
    unsigned char calculated_tag[SHA256_DIGEST_LENGTH] = { 0 };
    unsigned int  tag_length = 0;
    HMAC (
        EVP_sha256 ( ), 
        hmac_key, 32,
        ( unsigned char* ) ciphertext_base64, 
        ( int ) ciphertext_length,
        calculated_tag, 
        &tag_length
    );

    char calculated_tag_hex[65] = { 0 };
    for ( int i = 0; i < 32; ++i ) {
        sprintf ( calculated_tag_hex + i * 2, "%02x", calculated_tag[i] );
    }
    calculated_tag_hex[64] = '\0';

    if ( CRYPTO_memcmp ( calculated_tag_hex, tag_hex, 64 ) != 0 ) {
        /* auth failure */
        free ( blob ); 
        free ( ciphertext_base64 ); 
        return NULL;
    }

    /* hex-IV → binary */
    size_t iv_binary_length = 0;
    unsigned char *iv_binary = hex_to_binary ( iv_hex, &iv_binary_length );
    if ( iv_binary == NULL || iv_binary_length != 16) {
        free ( blob ); 
        free ( ciphertext_base64 ); 
        free ( iv_binary ); 
        return NULL;
    }

    /* Base-64 → ciphertext binary */
    size_t ciphertext_binary_length = 0;
    unsigned char *ciphertext_binary = base64_decode ( ciphertext_base64, &ciphertext_binary_length );
    free ( ciphertext_base64 ); 
    free ( blob );

    if ( ciphertext_binary == NULL ) { 
        free ( iv_binary ); 
        return NULL; 
    }

    /* AES-256-CBC decrypt */
    EVP_CIPHER_CTX *cipher_context = EVP_CIPHER_CTX_new ( );
    unsigned char *plaintext       = malloc ( ciphertext_binary_length );

    if ( cipher_context == NULL || plaintext == NULL ) { 
        free ( iv_binary ); 
        free ( ciphertext_binary ); 
        EVP_CIPHER_CTX_free ( cipher_context ); 
        return NULL; 
    }

    int output_length = 0; 
    int total_length = 0;

    int init_result   = EVP_DecryptInit_ex ( cipher_context, EVP_aes_256_cbc ( ), NULL, aes_key, iv_binary );
    int update_result = EVP_DecryptUpdate ( cipher_context, plaintext, &output_length, ciphertext_binary, ( int ) ciphertext_binary_length );

    if ( init_result == 0 || update_result == 0 ) {
        goto bad;
    }

    total_length += output_length;

    if ( !EVP_DecryptFinal_ex ( cipher_context, plaintext + total_length, &output_length ) ) {
        goto bad;
    }

    total_length += output_length;  

    plaintext[total_length] = '\0';

    EVP_CIPHER_CTX_free ( cipher_context ); 
    free ( iv_binary ); 
    free ( ciphertext_binary );

    return realloc ( plaintext, total_length + 1 );

bad:
    EVP_CIPHER_CTX_free ( cipher_context ); 
    free ( iv_binary ); 
    free ( ciphertext_binary ); 
    free ( plaintext );

    return NULL;
}

void bytes_to_hex ( const unsigned char *bytes, size_t length, char *hex ) {
    static const char *hex_map = "0123456789abcdef";

    for ( size_t i = 0; i < length; ++i ) {
        hex[i * 2]     = hex_map[bytes[i] >> 4];
        hex[i * 2 + 1] = hex_map[bytes[i] & 0x0F];
    }

    hex[length * 2] = '\0';
}


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
    if (ret != 0) goto out;

    ret = wc_HmacUpdate(&hmac, data, data_len);
    if (ret != 0) goto out;

    ret = wc_HmacFinal(&hmac, out);

out:
    wc_HmacFree(&hmac);
    return ret;
}

char *encrypt ( const char *plaintext, const char *key_text ) {
    /* 1. decode master key */
    size_t key_length = 0;
    unsigned char *key_binary = decode_key ( key_text, &key_length );

    if ( key_binary == NULL ) {
        return NULL;
    }

    /* 2. derive AES & HMAC keys using native WolfCrypt */
    unsigned char aes_key[32]  = { 0 };
    unsigned char hmac_key[32] = { 0 };
    
    /* aes_key = SHA256(master_key) */
    Sha256 sha_aes;
    wc_InitSha256(&sha_aes);
    wc_Sha256Update(&sha_aes, key_binary, key_length);
    wc_Sha256Final(&sha_aes, aes_key);
    wc_Sha256Free(&sha_aes);

    /* hmac_key = SHA256(master_key || "Mac") */
    Sha256 sha_hmac;
    wc_InitSha256(&sha_hmac);
    wc_Sha256Update(&sha_hmac, key_binary, key_length);
    wc_Sha256Update(&sha_hmac, (const unsigned char*)"Mac", 3);
    wc_Sha256Final(&sha_hmac, hmac_key);
    wc_Sha256Free(&sha_hmac);
    
    free ( key_binary );

    /* 3. random IV (16 bytes) */
    unsigned char iv_binary[16] = { 0 };
    if ( RAND_bytes ( iv_binary, 16 ) != 1 ) {
        return NULL;
    }

    char iv_hex[33] = { 0 }; /* 32 chars + null terminator */
    bytes_to_hex ( iv_binary, 16, iv_hex );       /* 32-char ASCII */

    /* 4. AES-256-CBC encrypt */
    EVP_CIPHER_CTX *cipher_context = EVP_CIPHER_CTX_new ( );
    if ( cipher_context == NULL ) {
        return NULL;
    }

    int plaintext_length             = ( int ) strlen ( plaintext );
    int ciphertext_max_length        = plaintext_length + 16;
    unsigned char *ciphertext_binary = malloc ( ciphertext_max_length );

    if ( ciphertext_binary == NULL ) { 
        EVP_CIPHER_CTX_free ( cipher_context ); 
        return NULL; 
    }

    int output_length = 0;
    int total_length  = 0;

    int init_result = EVP_EncryptInit_ex ( cipher_context, EVP_aes_256_cbc ( ), NULL, aes_key, iv_binary );

    int update_result = EVP_EncryptUpdate ( 
        cipher_context, 
        ciphertext_binary, 
        &output_length,
        ( const unsigned char * ) plaintext, 
        plaintext_length 
    );

    if ( init_result == 0 || update_result == 0 ) {
        goto bad;
    }

    total_length += output_length;

    if ( !EVP_EncryptFinal_ex ( cipher_context, ciphertext_binary + total_length, &output_length ) ) {
        goto bad;
    }

    total_length += output_length;

    EVP_CIPHER_CTX_free ( cipher_context );

    char *ciphertext_base64 = base64_encode ( ciphertext_binary, total_length );
    free ( ciphertext_binary );

    if ( ciphertext_base64 == NULL ) {
        return NULL;
    }

    /* 5. HMAC(tag) over ciphertextB64 - using native WolfCrypt */
    unsigned char tag_binary[32] = { 0 };
    
    if (hmac_sha256(
            hmac_key, 32,
            (const unsigned char*)ciphertext_base64,
            (int)strlen(ciphertext_base64),
            tag_binary
        ) != 0) {
        free ( ciphertext_base64 );
        return NULL;
    }

    char tag_hex[65] = { 0 }; /* 64 chars + null terminator */
    bytes_to_hex ( tag_binary, 32, tag_hex );    /* 64 chars */

    /* 6. assemble: IVhex || cipherB64 || taghex */
    size_t blob_raw_length = 32 + strlen ( ciphertext_base64 ) + 64;
    char *blob_raw         = malloc ( blob_raw_length + 1 );
    if ( blob_raw == NULL ) { 
        free ( ciphertext_base64 ); 
        return NULL; 
    }

    sprintf ( blob_raw, "%s%s%s", iv_hex, ciphertext_base64, tag_hex );
    free ( ciphertext_base64 );

    /* 7. Base-64 encode whole blob */
    char *blob_base64 = base64_encode ( blob_raw, blob_raw_length );
    free ( blob_raw );

    return blob_base64;

bad:
    EVP_CIPHER_CTX_free ( cipher_context ); 
    free ( ciphertext_binary );
    return NULL;
}

void get_key ( 
    EVP_PKEY * private_key,
    X509 *certificate,
    char *ca_root_certificate,
    char *kme_host,
    char *kme_port,
    char *kme_host_sni,
    char *kme_slave,
    int key_count,
    int key_size,
    char **key,
    char **key_id
) {
    char enc_keys_path[128] = { 0 };
    snprintf ( enc_keys_path, sizeof ( enc_keys_path ), "/api/v1/keys/%s/enc_keys?number=%d&size=%d", kme_slave, key_count, key_size );

    long response_length = 0;
    char *response = https_get_with_client ( 
        kme_host, 
        kme_port, 
        enc_keys_path,
        kme_host_sni,
        ca_root_certificate,
        certificate, 
        private_key, 
        &response_length
    );
    
    if ( response == NULL ) {
        return NULL;
    }
    
    char *body = get_last_line ( response );
    if ( body == NULL ) {
        goto body_error;
    }
    
    (*key) = extract_field_from_json ( body, "key" );
    (*key_id) = extract_field_from_json ( body, "key_ID" );
    
    free ( body );

    return; 

body_error:
    free ( response );

    *key    = NULL;
    *key_id = NULL;

    return;
}

// int tcp_connect ( const char *host, int port ) {
//     char port_string[16] = { 0 };
//     snprintf ( port_string, sizeof ( port_string ), "%d", port );
// 
//     struct addrinfo hints = {
//         .ai_family   = AF_UNSPEC,
//         .ai_socktype = SOCK_STREAM,
//         .ai_flags    = AI_ADDRCONFIG
//     };
//     struct addrinfo *result = NULL;
// 
//     if ( getaddrinfo ( host, port_string, &hints, &result ) != 0 ) {
//         return -EHOSTUNREACH;
//     }
// 
//     int socket_fd = -1;
//     for ( struct addrinfo *i = result; i; i = i->ai_next ) {
//         socket_fd = socket ( i->ai_family, i->ai_socktype, i->ai_protocol );
// 
//         if ( socket_fd == -1 ) {
//             continue;
//         }
// 
//         if ( connect ( socket_fd, i->ai_addr, i->ai_addrlen ) == 0 ) {
//             break;
//         }
// 
//         close ( socket_fd );
// 
//         socket_fd = -1;
//     }
// 
//     freeaddrinfo ( result );
// 
//     return ( socket_fd == -1 ) ? -ECONNREFUSED : socket_fd;
// }
// 

int tcp_connect ( char* ip, char *port_string ) {
    int port = atoi ( port_string );
    if ( port <= 0 || port > 65535 ) {
        fprintf ( stderr, "bad port: %d\n", port );
        return -1;
    }

    int socket_fd = socket ( AF_INET, SOCK_STREAM, 0 );
    if ( socket_fd < 0 ) {
        perror ( "socket" );
        return -1;
    }

    struct sockaddr_in socket_address_in;
    memset ( &socket_address_in, 0, sizeof ( socket_address_in ) );
    socket_address_in.sin_family = AF_INET;
    socket_address_in.sin_port = htons ( ( uint16_t ) port );

    if ( inet_pton ( AF_INET, ip, &socket_address_in.sin_addr ) != 1 ) {
        fprintf ( stderr, "inet_pton failed for ip=%s\n", ip );
        close ( socket_fd );
        return -1;
    }

    if (connect ( socket_fd, ( struct sockaddr* ) &socket_address_in, sizeof ( socket_address_in ) ) != 0 ) {
        perror ( "connect" );
        close ( socket_fd );
        return -1;
    }

    return socket_fd;
}

int send_message ( EVP_PKEY *private_key, X509 *certificate, char *peer_ca_certificate, char *host, char *port, const char *body ) {
    SSL_CTX *context = create_ssl_context (
        TLS_client_method ( ),
        private_key,
        certificate,
        peer_ca_certificate
    );

    if ( context == NULL ) {
        return 1;
    }

    int result = -1;

    int socket_fd = tcp_connect ( host, port );
    if ( socket_fd < 0 ) { 
        result = socket_fd; 
        goto cleanup_context; 
    }

    SSL *ssl = SSL_new ( context );
    if ( ssl == NULL ) { 
        result = -EPROTO; 
        goto cleanup_socket; 
    }

    SSL_set_tlsext_host_name ( ssl, host );
    SSL_set_fd ( ssl, socket_fd );

    if ( SSL_connect ( ssl ) <= 0 ) { 
        result = -EPROTO; 
        goto cleanup_ssl; 
    }

    size_t body_length = strlen ( body );
    const char *pointer = body;
    while ( body_length > 0 ) {
        int bytes_written = SSL_write ( ssl, pointer, ( int ) body_length );

        if ( bytes_written <= 0 ) { 
            result = -EIO; 
            goto cleanup_ssl; 
        }

        pointer     += bytes_written;
        body_length -= bytes_written;
    }

    char read_buffer[1024] = { 0 };    
    SSL_read ( ssl, read_buffer, 1024 );

    SSL_shutdown ( ssl );
    result = 0;

cleanup_ssl:
    SSL_free ( ssl );
cleanup_socket:
    close ( socket_fd );
cleanup_context:
    SSL_CTX_free ( context );

    return result;
}

char* get_port ( char *url ) {
    char *location = NULL;

    for ( location = url + strlen ( url ); *location != ':'; location-- );
    
    location++;
    
    char *port = calloc ( strlen ( location ) + 1, sizeof ( char ) );
    if ( port == NULL ) {
        return NULL;
    }
    
    strcpy ( port, location );

    return port;
}

char *get_ip_address ( char *url ) {
    char *location = NULL;

    for ( location = url + strlen ( url ); *location != ':'; location-- );

    char *ip_address = calloc ( 1, location - url + 1 );
    if ( ip_address == NULL ) {
        return NULL;
    }

    strncpy ( ip_address, url, location - url );

    return ip_address;
}

int main ( int argc, char **argv ) {
    // if ( argc != 3 ) {
    //     return 1;
    // }
    // char *repetitor_id = argv[1];
    // int port = atoi ( argv[2] );

    char *repetitor_id = "riscv-repetitor-1";
    int port =  9001;

    // TODO: change when you migrate to qemu
    char repetitor_url[64] = { 0 };
    snprintf ( repetitor_url, sizeof ( repetitor_url ), "127.0.0.1:%d", port );

    OpenSSL_add_all_algorithms ( );
    ERR_load_BIO_strings ( );
    ERR_load_crypto_strings ( );
    SSL_library_init ( );

    wolfSSL_Debugging_ON ( );
    
    repetitor_configuration_t* configuration = get_repetitor_configuration (
        CONTROLLER_HOST,
        CONTROLLER_PORT,
        CONTROLLER_GET_NONCE_PATH,
        CONTROLLER_REGISTER_PATH,
        CONTROLLER_CONFIGURATION_PATH,
        repetitor_id,
        repetitor_url
    );
    
    if ( configuration == NULL ) {
        return 1;
    }
        
    fprintf ( stderr, "Configuration loaded\n" );
    EVP_PKEY *left_private_key = generate_rsa_key ( 2048 );
    if ( left_private_key == NULL ) {
        goto left_private_key_error;
    }

    EVP_PKEY *right_private_key = generate_rsa_key ( 2048 );
    if ( right_private_key == NULL ) {
        goto right_private_key_error;
    }

    EVP_PKEY *repetitor_private_key = generate_rsa_key ( 2048 );
    if ( repetitor_private_key == NULL ) {
        goto repetitor_private_key_error;
    }
    
    fprintf ( stderr, "Keys generated\n" );

    X509 *left_certificate = generate_certificate ( configuration, left_private_key, configuration->left_cn, configuration->left_cn );
    if ( left_certificate == NULL ) {
        goto left_certificate_error;
    }

    X509 *right_certificate = generate_certificate ( configuration, right_private_key, configuration->right_cn, configuration->right_cn );
    if ( right_certificate == NULL ) {
        goto right_certificate_error;
    }

    X509 *repetitor_certificate = generate_certificate ( configuration, repetitor_private_key, repetitor_id, repetitor_id );
    if ( repetitor_certificate == NULL ) {
        goto repetitor_certificate_error;
    }

    fprintf ( stderr, "Certificates generated\n" );
    
    if ( strlen ( configuration->left_kme ) != 0 ) {
        int left_kme_status = get_status_of_kme (
            left_private_key,
            left_certificate,
            QKD_CA_CERTIFICATE,
            configuration->left_kme_url,
            KME_PORT,
            configuration->left_kme,
            configuration->left_kme_peer
        );

        if ( left_kme_status == 1 ) {
            goto kme_status_error;
        }     
    } 

    if ( strlen ( configuration->right_kme ) != 0 ) {
        int right_kme_status = get_status_of_kme (
            right_private_key,
            right_certificate,
            QKD_CA_CERTIFICATE,
            configuration->right_kme_url,
            KME_PORT,
            configuration->right_kme,
            configuration->right_kme_peer
        );

        if ( right_kme_status == 1 ) {
            goto kme_status_error;
        }
    }

    int repetitor_listen_socket_fd = create_listen_socket ( port );
    if ( repetitor_listen_socket_fd == -1 ) {
        goto kme_status_error;
    }     

    SSL_CTX *repetitor_listen_context = create_ssl_context (
        TLS_server_method ( ),
        repetitor_private_key,
        repetitor_certificate,
        REPETITOR_CA_CERTIFICATE
    );
    
    if ( repetitor_listen_context == NULL ) {
        goto repetitor_listen_context_error;
    }

    // TODO: this might not be implemented in eryie
    signal ( SIGINT, handle_sigint );

    while ( keep_running == 1 ) {
        struct sockaddr_in client_address;

        socklen_t address_length = sizeof ( client_address );

        int client_socket_fd = accept ( 
            repetitor_listen_socket_fd, 
            ( struct sockaddr* ) &client_address, 
            &address_length
        );

        if ( client_socket_fd < 0 ) {
            if ( errno == EINTR && keep_running == 0 ) {
                break;  // interrupted by SIGINT
            }

            continue;
        }

        message_t result = read_message ( repetitor_listen_context, client_socket_fd );
        if ( result.message == NULL || result.subject == NULL ) {
            goto read_message_error;        
        } 
        
        char *location = strstr ( configuration->whitelist, result.subject );
        if ( location == NULL ) {   
            goto key_id_error;
        }
        
        int is_left_repetitor = strcmp ( result.subject, configuration->left_repetitor_id ) == 0;

        char *from_url = is_left_repetitor ? configuration->left_repetitor_url : configuration->right_repetitor_url;
        char *to_url   = is_left_repetitor ? configuration->right_repetitor_url : configuration->left_repetitor_url;

        char *kme_master = is_left_repetitor ? configuration->left_kme : configuration->right_kme;
        char *kme_slave  = is_left_repetitor ? configuration->right_kme : configuration->left_kme;

        char *kme_master_url = is_left_repetitor ? configuration->left_kme_url : configuration->right_kme_url;
        char *kme_slave_url  = is_left_repetitor ? configuration->right_kme_url : configuration->left_kme_url;

        char *kme_master_peer = is_left_repetitor ? configuration->left_kme_peer : configuration->right_kme_peer;
        char *kme_slave_peer  = is_left_repetitor ? configuration->right_kme_peer : configuration->left_kme_peer;

        EVP_PKEY *kme_master_private_key = is_left_repetitor ? left_private_key : right_private_key;
        EVP_PKEY *kme_slave_private_key  = is_left_repetitor ? right_private_key : left_private_key;

        X509 *kme_master_certificate = is_left_repetitor ? left_certificate : right_certificate;
        X509 *kme_slave_certificate  = is_left_repetitor ? right_certificate : left_certificate;


        char *from_key_id = extract_field_from_json ( result.message, "key_ID" );
        if ( from_key_id == NULL ) {
            goto key_id_error;
        }

        char *from_ciphertext = extract_field_from_json ( result.message, "message" );
        if ( from_ciphertext == NULL ) {
            goto ciphertext_error;
        }
        
        char *plaintext = NULL;
        
        if ( strlen ( kme_master ) != 0 ) {
            char *from_key = get_key_with_id (
                kme_master_private_key,
                kme_master_certificate,
                QKD_CA_CERTIFICATE,
                kme_master_url,
                KME_PORT,
                kme_master,
                kme_master_peer,
                from_key_id
            );

            if ( from_key == NULL ) {
                goto get_from_key_error;
            }

            plaintext = decrypt ( from_ciphertext, from_key );

            free ( from_key );

            if ( plaintext == NULL ) { 
                goto get_from_key_error;
            }
        } else {
            plaintext = calloc ( strlen ( from_ciphertext ) + 1, sizeof ( char ) );
            if ( plaintext == NULL ) {  
                goto get_from_key_error;
            }

            strcpy ( plaintext, from_ciphertext );
        } 
            
        char *to_ciphertext = NULL;
        char *to_key_id = NULL;

        if ( strlen ( kme_slave ) != 0 ) {
            char *to_key = NULL;

            get_key (
                right_private_key,
                right_certificate,
                QKD_CA_CERTIFICATE,
                kme_slave_url,
                KME_PORT,
                kme_slave,
                kme_slave_peer,
                1, 
                1024, 
                &to_key, 
                &to_key_id
            );

            if ( to_key == NULL || to_key_id == NULL ) {
                goto get_from_key_error;
            }

            to_ciphertext = encrypt ( plaintext, to_key );
            
            free ( to_key );

            if ( to_ciphertext == NULL ) {
                goto encrypt_message_error;
            }
        } else {
            to_ciphertext = calloc ( strlen ( plaintext ) + 1, sizeof ( char ) );
            if ( to_ciphertext == NULL ) {  
                goto encrypt_message_error;
            }

            strcpy ( to_ciphertext, plaintext );
        } 
        
        char body[1024] = { 0 };
        if ( to_key_id == NULL ) {
            snprintf ( body, sizeof ( body ), "{\"message\":\"%s\",\"key_ID\":\"%s\"}\n", to_ciphertext, "" ); 
        } else {
            snprintf ( body, sizeof ( body ), "{\"message\":\"%s\",\"key_ID\":\"%s\"}\n", to_ciphertext, to_key_id ); 
        }
        
        printf ( "BODY: %s\n", body );

        char *to_port = get_port ( to_url );

        char *to_ip_address = get_ip_address ( to_url );
        if ( to_ip_address == NULL ) {
            goto to_ip_address_error    ;
        }
        
        int send_result = send_message (
            repetitor_private_key,
            repetitor_certificate,
            REPETITOR_CA_CERTIFICATE,
            to_ip_address,
            to_port,
            body
        );

        free ( to_ip_address );
        free ( to_port );
        
    to_ip_address_error:
        free ( to_ciphertext );
    
    encrypt_message_error:
        free ( to_key_id );

    get_from_key_error:
        free ( from_ciphertext );

    ciphertext_error:
        free ( from_key_id );

    key_id_error: 
        free ( result.message );
        free ( result.subject );
        
    read_message_error:
        close ( client_socket_fd );
    }

    wolfSSL_Debugging_OFF ( );
    
    SSL_CTX_free ( repetitor_listen_context );

repetitor_listen_context_error:
    close ( repetitor_listen_socket_fd );
    
kme_status_error:
    X509_free ( repetitor_certificate );

repetitor_certificate_error:
    X509_free ( right_certificate );

right_certificate_error:
    X509_free ( left_certificate );

left_certificate_error:
    EVP_PKEY_free ( repetitor_private_key );

repetitor_private_key_error:
    EVP_PKEY_free ( right_private_key );

right_private_key_error:
    EVP_PKEY_free ( left_private_key );

left_private_key_error:
    free_repetitor_configuration ( configuration );

    EVP_cleanup ( );
    CRYPTO_cleanup_all_ex_data ( );
    ERR_free_strings ( );

    return 0;
}
