
#include <mbedtls/platform.h>
#include <mbedtls/error.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/bignum.h>
#include <mbedtls/rsa.h>
#include <mbedtls/md.h>
#include <mbedtls/pk.h>

#ifndef RA_IOT_MBEDTLS_H
#define RA_IOT_MBEDTLS_H

#define mbedtls_printf          printf
#define mbedtls_exit            exit
//#define mbedtls_snprintf        snprintf
//#define MBEDTLS_EXIT_SUCCESS    EXIT_SUCCESS
//#define MBEDTLS_EXIT_FAILURE    EXIT_FAILURE

#define KEY_SIZE 2048
#define EXPONENT 65537
#define USE_PK 1


/* public key byte data */
typedef struct {
	uint8_t N[256];
	uint8_t E[256];
} pub_key_dto;

#define FORCE_EXIT 0 // interrupts the code execution at a given point for testing purposes
void print_pub_key_dto(pub_key_dto pk);
void load_ecrypt_from_str(uint8_t *input, int i_len, unsigned char *output);
void save_ecrypt_to_str(uint8_t *input, int i_len, char *output);

int pk_write_rsa_pubkey( unsigned char **p, unsigned char *start, mbedtls_rsa_context *rsa );
int ra_iot_mbedtls_load_pub_key_to_buffer(char *filename, pub_key_dto *pk_bytes);
int ra_iot_mbedtls_load_pub_key_from_buffer(pub_key_dto *pk_buffer, mbedtls_rsa_context *rsa);



int cpm_pub_keys(mbedtls_rsa_context rsa1, mbedtls_rsa_context rsa2);
int ra_iot_mbedtls_gen_rsa_key( char *path );
int ra_iot_mbedtls_load_pub_key(char *filename, mbedtls_rsa_context *rsa);
int ra_iot_mbedtls_load_priv_key(char *filename, mbedtls_rsa_context *rsa);
int ra_iot_mbedtls_encrypt( mbedtls_rsa_context *key, unsigned char input[], size_t i_len, unsigned char *output );
int ra_iot_mbedtls_decrypt( mbedtls_rsa_context *key, unsigned char *encr_data, unsigned char *result );
int ra_iot_mbedtls_sign(mbedtls_rsa_context *key, unsigned char *data, size_t data_len, unsigned char *signature);
int ra_iot_mbedtls_verify_sig(mbedtls_rsa_context *key, unsigned char *data, size_t data_len, unsigned char *signature);

void ra_iot_mbedtls_print_rsa_pubkey(mbedtls_rsa_context rsa);

#endif