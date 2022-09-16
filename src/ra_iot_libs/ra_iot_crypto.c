#include <stdlib.h>
#include <stdio.h>
#include <string.h>
// Do teste
#include "ra_iot_crypto.h"

int gen_rsa_key( char *path )
{
    return ra_iot_mbedtls_gen_rsa_key(path);
}

int load_pub_key(char *filename, mbedtls_rsa_context *rsa)
{    
    return ra_iot_mbedtls_load_pub_key(filename, rsa);
}


int load_priv_key(char *filename, mbedtls_rsa_context *rsa)
{    
    return ra_iot_mbedtls_load_priv_key(filename, rsa);
}


int ra_iot_encrypt(mbedtls_rsa_context *key, unsigned char input[], size_t i_len, unsigned char *output)
{
    return ra_iot_mbedtls_encrypt(key, input, i_len, output);
}

int ra_iot_decrypt(mbedtls_rsa_context *key, unsigned char *encr_data, unsigned char *result){
    
    return ra_iot_mbedtls_decrypt(key, encr_data, result);
}

int ra_iot_sign(mbedtls_rsa_context *key, unsigned char *data, size_t data_len, unsigned char *signature){
    return ra_iot_mbedtls_sign(key, data, data_len, signature);
}


int ra_iot_verify_sig(mbedtls_rsa_context *key, unsigned char *data, size_t data_len, unsigned char *signature){
    
    return ra_iot_mbedtls_verify_sig(key, data, data_len, signature);
}


void ra_iot_print_pub_key(mbedtls_rsa_context rsa){
    ra_iot_mbedtls_print_rsa_pubkey(rsa);
}


void crypto_test(unsigned char *input, size_t i_len){
    int ret_code;
    unsigned char encrypted[512] = {0}; 
	unsigned char decrypted[512] = {0};
	unsigned char signature[MBEDTLS_MPI_MAX_SIZE] = {0};
	mbedtls_rsa_context rsa_pub;
	mbedtls_rsa_context rsa_priv;
	
	//unsigned char input[100] = "Uma string em C, grande e com algum texto....";
	int val = gen_rsa_key("");
	ret_code = load_pub_key("rsa_pub.txt", &rsa_pub);
	printf("Load public key: %d\n", ret_code);
	ret_code = load_priv_key("rsa_priv.txt", &rsa_priv);
	printf("Load public private key: %d\n", ret_code);
	printf("\n*****************************\n");
	printf("\nChecking keys\n");
	printf("Key Pair is: %s\n", (mbedtls_rsa_check_pub_priv(&rsa_pub, &rsa_priv) == 0 ? "Ok" : "Bad!"));
	printf("Public key is: %s\n", (mbedtls_rsa_check_pubkey(&rsa_pub) == 0 ? "Ok" : "Bad!"));
	printf("Private key is: %s\n", (mbedtls_rsa_check_privkey(&rsa_priv) == 0 ? "Ok" : "Bad!"));
	printf("\n*****************************\n");	

	ret_code = ra_iot_encrypt(&rsa_pub, input, strlen(input), encrypted);
	printf("Encrypt: %d\n", ret_code);
	ret_code = ra_iot_sign(&rsa_priv, encrypted, strlen(encrypted), signature);
	printf("Sign: %d\n", ret_code);
	ret_code = ra_iot_verify_sig(&rsa_pub, encrypted, strlen(encrypted), signature);
	printf("Verification result: %d\n", ret_code);
	printf("Verify sig: %d\n", ret_code);
	ra_iot_decrypt(&rsa_priv, encrypted, decrypted);
	printf("Decrypt sig: %d\n", ret_code);

	printf("[Verifier] The decrypted result is: '%s'\n\n", decrypted);

    printf("Commparing data %d\n", memcmp(decrypted, input, sizeof(input)));


	mbedtls_rsa_free( &rsa_pub );
	mbedtls_rsa_free( &rsa_priv ); 


} 


















