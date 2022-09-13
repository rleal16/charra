
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

int ra_iot_mbedtls_gen_rsa_key( char *path );
mbedtls_rsa_context ra_iot_mbedtls_load_key(char *filename);
int ra_iot_mbedtls_encrypt( mbedtls_rsa_context *rsa, unsigned char input[]);
int ra_iot_mbedtls_decrypt(void);
int ra_iot_mbedtls_sign(void);
int ra_iot_mbedtls_verify_sig(void);

void ra_iot_mbedtls_print_rsa_pubkey(mbedtls_rsa_context rsa);