
#include "ra_iot_mbedtls.h"

int gen_rsa_key( char *path );
int load_pub_key(char *filename, mbedtls_rsa_context *rsa);
int load_priv_key(char *filename, mbedtls_rsa_context *rsa);
int ra_iot_encrypt(mbedtls_rsa_context *key, unsigned char input[], size_t i_len, unsigned char *output);
int ra_iot_decrypt(mbedtls_rsa_context *key, unsigned char *encr_data, unsigned char *result);
int ra_iot_sign(mbedtls_rsa_context *key, unsigned char *data, size_t data_len, unsigned char *signature);
int ra_iot_verify_sig(mbedtls_rsa_context *key, unsigned char *data, size_t data_len, unsigned char *signature);
void print_rsa_pub_key(mbedtls_rsa_context rsa);


// Testing

void crypto_test(unsigned char *input, size_t i_len);