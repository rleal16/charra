
#include "ra_iot_mbedtls.h"

#ifndef RA_IOT_CYPTO_H
#define RA_IOT_CYPTO_H
int ra_iot_write_rsa_pubkey( unsigned char **p, unsigned char *start, mbedtls_rsa_context *rsa );
int ra_iot_load_pub_key_to_buffer(char *filename, pub_key_dto *pk_bytes);
int ra_iot_load_pub_key_from_buffer(pub_key_dto *pk_buffer, mbedtls_rsa_context *rsa);

int ra_iot_gen_rsa_key( char *path );
int ra_iot_load_pub_key(char *filename, mbedtls_rsa_context *rsa);
int ra_iot_load_priv_key(char *filename, mbedtls_rsa_context *rsa);
int ra_iot_encrypt(mbedtls_rsa_context *key, unsigned char input[], size_t i_len, unsigned char *output);
int ra_iot_decrypt(mbedtls_rsa_context *key, unsigned char *encr_data, unsigned char *result);
int ra_iot_sign(mbedtls_rsa_context *key, unsigned char *data, size_t data_len, unsigned char *signature);
int ra_iot_verify_sig(mbedtls_rsa_context *key, unsigned char *data, size_t data_len, unsigned char *signature);

/* Encrypts and signs the ecrypted data (if encryption is successful) */
int ra_iot_encrypt_sign(mbedtls_rsa_context *pub_key, mbedtls_rsa_context *priv_key, unsigned char *data, size_t data_len, unsigned char *sig_out, unsigned char *encr_out);

/* Verifies the signature of the encrypted data and, if successful, decrypts the data returning it in <result> */
int ra_iot_verify_decrypt(mbedtls_rsa_context *pub_key, mbedtls_rsa_context *priv_key, unsigned char *data, size_t data_len, unsigned char *signature, unsigned char *result);

/* Generates and returns an rsa keypair */
int ra_iot_gen_rsa_keypair(char *keys_filepath, mbedtls_rsa_context *pub_key, mbedtls_rsa_context *priv_key);

void print_rsa_pub_key(mbedtls_rsa_context rsa);

#endif