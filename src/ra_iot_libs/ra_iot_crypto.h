
int gen_rsa_key( char *path );
mbedtls_rsa_context load_key(char *filename);
int ra_iot_encrypt( mbedtls_rsa_context *rsa, unsigned char input[]);
int ra_iot_decrypt(void);
int ra_iot_sign(void);
int ra_iot_verify_sig(void);
void print_rsa_pub_key(mbedtls_rsa_context rsa);