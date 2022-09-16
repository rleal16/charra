
#include "ra_iot_mbedtls.h"

int gen_rsa_key( char *path );
mbedtls_rsa_context load_pub_key(char *filename);
mbedtls_rsa_context load_priv_key(char *filename);
int ra_iot_encrypt(mbedtls_rsa_context *key, unsigned char input[], unsigned char *output);
int ra_iot_decrypt(mbedtls_rsa_context *key, unsigned char *encr_data, unsigned char *result);
int ra_iot_sign(mbedtls_rsa_context *key, unsigned char *data, unsigned char *signature);
int ra_iot_verify_sig(mbedtls_rsa_context *key, unsigned char *data, unsigned char *signature);
void print_rsa_pub_key(mbedtls_rsa_context rsa);