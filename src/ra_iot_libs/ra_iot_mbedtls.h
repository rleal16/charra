
#include <mbedtls/platform.h>
#include <mbedtls/error.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/bignum.h>
#include <mbedtls/rsa.h>
#include <mbedtls/md.h>

#define mbedtls_printf          printf
#define mbedtls_exit            exit
//#define mbedtls_snprintf        snprintf
//#define MBEDTLS_EXIT_SUCCESS    EXIT_SUCCESS
//#define MBEDTLS_EXIT_FAILURE    EXIT_FAILURE

#define KEY_SIZE 2048
#define EXPONENT 65537


#define KEY_USE(x) ((x) ? "by loading the key" : "without loading the key")

#define LOAD_KEY_ENCRYPT 0 // load the key (or not) in function ra_iot_mbedtls_encrypt
#define LOAD_KEY_DECRYPT 0 // load the key (or not) in function ra_iot_mbedtls_decrypt
#define LOAD_KEY_SIGN 0 // load the key (or not) in function ra_iot_mbedtls_sign
#define LOAD_KEY_VERIFY 0 // load the key (or not) in function ra_iot_mbedtls_verify_sig

// 1 if we want the mbedtls function to read/write from/to files internally; 0 to call an external function
#define READ_INTERNALLY 0 
#define WRITE_INTERNALLY 0 

int ra_iot_mbedtls_gen_rsa_key( char *path );
mbedtls_rsa_context ra_iot_mbedtls_load_pub_key(char *filename);
mbedtls_rsa_context ra_iot_mbedtls_load_priv_key(char *filename);
int ra_iot_mbedtls_encrypt( mbedtls_rsa_context *key, unsigned char input[], unsigned char *buf);
int ra_iot_mbedtls_decrypt(mbedtls_rsa_context *key, unsigned char *data);
int ra_iot_mbedtls_sign(mbedtls_rsa_context *key);
int ra_iot_mbedtls_verify_sig(mbedtls_rsa_context *key);

void ra_iot_mbedtls_print_rsa_pubkey(mbedtls_rsa_context rsa);