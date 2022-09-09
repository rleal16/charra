
int call_rsa_genkey(void);
int call_load_key(char *file);
int gen_rsa_key( void );
mbedtls_rsa_context load_key(void);
int ra_iot_encrypt( mbedtls_rsa_context *rsa, unsigned char input[]);
int ra_iot_decrypt(void);
int ra_iot_sign(void);