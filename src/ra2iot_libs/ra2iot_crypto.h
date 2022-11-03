
#include "ra2iot_mbedtls.h"

#ifndef RA2IOT_CYPTO_H
#define RA2IOT_CYPTO_H
int ra2iot_write_rsa_pubkey( unsigned char **p, unsigned char *start, mbedtls_rsa_context *rsa );
int ra2iot_load_pub_key_to_buffer(char *filename, pub_key_dto *pk_bytes);
int ra2iot_load_pub_key_from_buffer(pub_key_dto *pk_buffer, mbedtls_rsa_context *rsa);

int ra2iot_gen_rsa_key( char *path );
int ra2iot_load_pub_key(char *filename, mbedtls_rsa_context *rsa);
int ra2iot_load_priv_key(char *filename, mbedtls_rsa_context *rsa);
int ra2iot_encrypt(mbedtls_rsa_context *key, unsigned char input[], size_t i_len, unsigned char *output);
int ra2iot_decrypt(mbedtls_rsa_context *key, unsigned char *encr_data, unsigned char *result);
int ra2iot_sign(mbedtls_rsa_context *key, unsigned char *data, size_t data_len, unsigned char *signature);
int ra2iot_verify_sig(mbedtls_rsa_context *key, unsigned char *data, size_t data_len, unsigned char *signature);

/* Encrypts and signs the ecrypted data (if encryption is successful) */
int ra2iot_encrypt_sign(mbedtls_rsa_context *pub_key, mbedtls_rsa_context *priv_key, unsigned char *data, size_t data_len, unsigned char *sig_out, unsigned char *encr_out);

/* Verifies the signature of the encrypted data and, if successful, decrypts the data returning it in <result> */
int ra2iot_verify_decrypt(mbedtls_rsa_context *pub_key, mbedtls_rsa_context *priv_key, unsigned char *data, size_t data_len, unsigned char *signature, unsigned char *result);

/* Generates and returns an rsa keypair */
int ra2iot_gen_rsa_keypair(char *keys_filepath, mbedtls_rsa_context *pub_key, mbedtls_rsa_context *priv_key);

void print_rsa_pub_key(mbedtls_rsa_context rsa);

#endif