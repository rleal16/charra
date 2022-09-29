#include <stdlib.h>
#include <stdio.h>
#include <string.h>
// Do teste
#include "ra_iot_crypto.h"

/* Static functions */
// TODO: these functions should be static. They're not for testing purposes.
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

int ra_iot_gen_rsa_key( char *path )
{
    return ra_iot_mbedtls_gen_rsa_key(path);
}

int ra_iot_load_pub_key(char *filename, mbedtls_rsa_context *rsa)
{    
    return ra_iot_mbedtls_load_pub_key(filename, rsa);
}


int ra_iot_load_priv_key(char *filename, mbedtls_rsa_context *rsa)
{    
    return ra_iot_mbedtls_load_priv_key(filename, rsa);
}

/* ----------------------------------- */



int ra_iot_write_rsa_pubkey( unsigned char **p, unsigned char *start, mbedtls_rsa_context *rsa ){
	return pk_write_rsa_pubkey( p, start, rsa );
}

int ra_iot_gen_rsa_keypair(char *keys_filepath, char *priv_key_file, mbedtls_rsa_context *pub_key, mbedtls_rsa_context *priv_key){
	if(!ra_iot_gen_rsa_key( keys_filepath ))
		return 0;
	char pub_filename[512];
	char priv_filename[512];
	sprintf(pub_filename, "%srsa_pub.txt", keys_filepath);
	sprintf(priv_filename, "%srsa_priv.txt", keys_filepath);
	
	if(!ra_iot_load_pub_key(pub_filename, pub_key))
		return 0;
	
	if(!ra_iot_load_priv_key(priv_filename, priv_key))
		return 0;
}

void ra_iot_load_pub_key_to_buffer(char *filename, pub_key_dto *pk_bytes){
	ra_iot_mbedtls_load_pub_key_to_buffer(filename, pk_bytes);
}

int ra_iot_load_pub_key_from_buffer(pub_key_dto *pk_buffer, mbedtls_rsa_context *rsa){
	return ra_iot_mbedtls_load_pub_key_from_buffer(pk_buffer, rsa);
}


int ra_iot_verify_decrypt(mbedtls_rsa_context *pub_key, mbedtls_rsa_context *priv_key, unsigned char *data, size_t data_len, unsigned char *signature, unsigned char *result){
	if(ra_iot_verify_sig(pub_key, data, data_len, signature) == 0)
		return 0;
	
	if(ra_iot_decrypt(priv_key, data, result) == 0)
		return 0;
	
	return 1;
}

int ra_iot_encrypt_sign(mbedtls_rsa_context *pub_key, mbedtls_rsa_context *priv_key, unsigned char *data, size_t data_len, unsigned char *sig_out, unsigned char *encr_out){
	if(ra_iot_encrypt(pub_key, data, data_len, encr_out) == 0)
		return 0; 
	
	if(ra_iot_sign(priv_key, data, data_len, sig_out) == 0)
		return 0;
	
	return 1;
} 


void ra_iot_print_pub_key(mbedtls_rsa_context rsa){
    ra_iot_mbedtls_print_rsa_pubkey(rsa);
}





















