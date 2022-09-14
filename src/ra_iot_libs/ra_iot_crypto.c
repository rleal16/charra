#include <stdlib.h>
#include <stdio.h>
#include <string.h>
// Do teste
#include "ra_iot_mbedtls.h"
#include "ra_iot_crypto.h"

int gen_rsa_key( char *path )
{
    return ra_iot_mbedtls_gen_rsa_key(path);
}

mbedtls_rsa_context load_pub_key(char *filename)
{    
    return ra_iot_mbedtls_load_pub_key(filename);
}


mbedtls_rsa_context load_priv_key(char *filename)
{    
    return ra_iot_mbedtls_load_priv_key(filename);
}


int ra_iot_encrypt( mbedtls_rsa_context *rsa, unsigned char input[], unsigned char *result)
{
    return ra_iot_mbedtls_encrypt(rsa, input, result);
}

int ra_iot_decrypt(mbedtls_rsa_context *key, unsigned char *data){
    return ra_iot_mbedtls_decrypt(key, data);
}

int ra_iot_sign(mbedtls_rsa_context *key){
    return ra_iot_mbedtls_sign(key);
}


int ra_iot_verify_sig(mbedtls_rsa_context *key){
    return ra_iot_mbedtls_verify_sig(key);
}


void ra_iot_print_pub_key(mbedtls_rsa_context rsa){
    ra_iot_mbedtls_print_rsa_pubkey(rsa);
}





















