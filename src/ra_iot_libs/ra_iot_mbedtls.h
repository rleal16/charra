
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
#define FORCE_EXIT 1 // interrupts the code execution at a given point for testing purposes


// For testing not loading the key file
#define LOAD_KEY_ENCRYPT 0 // load the key (or not) in function ra_iot_mbedtls_encrypt
#define LOAD_KEY_DECRYPT 0 // load the key (or not) in function ra_iot_mbedtls_decrypt
#define LOAD_KEY_SIGN 0 // load the key (or not) in function ra_iot_mbedtls_sign
#define LOAD_KEY_VERIFY 0 // load the key (or not) in function ra_iot_mbedtls_verify_sig

// Ter testing using input/output data in memory instead of reading text files
#define WRITE_ENCR_FILE 1
#define READ_ENCR_FILE_2DECRYPT (!WRITE_ENCR_FILE ? WRITE_ENCR_FILE : 0)
#define READ_ENCR_FILE_2SIGN (!WRITE_ENCR_FILE ? WRITE_ENCR_FILE : 0)
#define READ_ENCR_FILE_2VERIFY (!WRITE_ENCR_FILE ? WRITE_ENCR_FILE : 1)

#define WRITE_SIGD_FILE 1
#define READ_SIGD_FILE_2VERIFY (!WRITE_SIGD_FILE ? WRITE_SIGD_FILE : 1)

int ra_iot_mbedtls_gen_rsa_key( char *path );
mbedtls_rsa_context ra_iot_mbedtls_load_pub_key(char *filename);
mbedtls_rsa_context ra_iot_mbedtls_load_priv_key(char *filename);
int ra_iot_mbedtls_encrypt( mbedtls_rsa_context *key, unsigned char input[], unsigned char *output );
int ra_iot_mbedtls_decrypt( mbedtls_rsa_context *key, unsigned char *encr_data, unsigned char *result );
int ra_iot_mbedtls_sign(mbedtls_rsa_context *key, unsigned char *data, unsigned char *signature);
int ra_iot_mbedtls_verify_sig(mbedtls_rsa_context *key, unsigned char *data);

void ra_iot_mbedtls_print_rsa_pubkey(mbedtls_rsa_context rsa);