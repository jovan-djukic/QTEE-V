#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/openssl/bio.h>
#include <wolfssl/openssl/buffer.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

/* Copy of base64_decode from repetitor.c */
char* base64_decode ( const char *base64, size_t *output_length ) {
    size_t base64_length = strlen ( base64 );
    size_t padding       = ( 4 - ( base64_length & 3 ) ) & 3;

    char *tmp = malloc ( base64_length + padding + 1 );
    if ( tmp == NULL ) {
        return NULL;
    }

    strcpy ( tmp, base64 );
    memset ( tmp + base64_length, '=', padding ); 
    tmp[base64_length + padding] = '\0';

    BIO *memory_buffer = BIO_new_mem_buf ( tmp, -1 );
    if ( memory_buffer == NULL ) { 
        BIO_free_all ( memory_buffer ); 
        free ( tmp ); 
        return NULL; 
    }

    BIO *b64f = BIO_new ( BIO_f_base64 ( ) );
    if ( b64f == NULL ) { 
        BIO_free_all ( memory_buffer ); 
        free ( tmp ); 
        return NULL; 
    }

    BIO_set_flags ( b64f, BIO_FLAGS_BASE64_NO_NL );
    memory_buffer = BIO_push ( b64f, memory_buffer );

    size_t estimated_length = ( strlen ( tmp ) * 3 ) / 4 + 1;

    unsigned char *buffer = malloc ( estimated_length );
    if ( buffer == NULL ) { 
        BIO_free_all ( memory_buffer ); 
        free ( tmp ); 
        return NULL; 
    }

    *output_length = BIO_read ( memory_buffer, buffer, estimated_length );

    BIO_free_all ( memory_buffer ); 
    free ( tmp );

    if ( *output_length <= 0 ) { 
        free ( buffer ); 
        return NULL; 
    }

    return (char*)buffer;
}

/* Copy of hex_to_binary from repetitor.c */
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
    return (char*)buffer;
}

/* Copy of decode_key from repetitor.c */
char* decode_key ( char *text, size_t *len_out ) {
    int all_hex = 1;
    for ( char *p = text; *p; ++p ) {
        if ( !isxdigit ( (unsigned char) *p ) ) { 
            all_hex = 0; 
            break; 
        }
    }

    if ( all_hex && ( strlen ( text ) & 1 ) == 0 ) {
        printf("Detected as: HEX\n");
        return hex_to_binary ( text, len_out );
    }

    printf("Detected as: BASE64\n");
    return base64_decode ( text, len_out );
}

int main() {
    // Same base64 key as Python test
    char test_key_b64[] = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
    
    printf("=== C WolfCrypt Full Flow Test ===\n");
    printf("key_text (from KME): '%s'\n", test_key_b64);

    // Decode master key
    size_t key_length = 0;
    unsigned char *master_key = (unsigned char*)decode_key(test_key_b64, &key_length);
    
    if (master_key == NULL) {
        printf("ERROR: decode_key failed!\n");
        return 1;
    }

    printf("master_key length: %zu\n", key_length);
    printf("master_key (hex): ");
    for (size_t i = 0; i < key_length; i++) printf("%02x", master_key[i]);
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

    free(master_key);

    // Test HMAC on the same ciphertext from your error log
    const char* test_ciphertext_b64 = "CCbCLbaQFddNs93xHsyU4BzJKHm0ai+DUSLYHFqwiP4=";
    unsigned char hmac_result[32] = {0};
    
    Hmac hmac;
    wc_HmacInit(&hmac, NULL, INVALID_DEVID);
    wc_HmacSetKey(&hmac, WC_SHA256, hmac_key, 32);
    wc_HmacUpdate(&hmac, (const unsigned char*)test_ciphertext_b64, strlen(test_ciphertext_b64));
    wc_HmacFinal(&hmac, hmac_result);
    wc_HmacFree(&hmac);

    printf("\nHMAC of ciphertext_b64 '%s':\n", test_ciphertext_b64);
    printf("  ");
    for (int i = 0; i < 32; i++) printf("%02x", hmac_result[i]);
    printf("\n");

    return 0;
}
