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

mbedtls_rsa_context load_key(char *filename)
{    
    return ra_iot_mbedtls_load_key(filename);
}

int ra_iot_encrypt( mbedtls_rsa_context *rsa, unsigned char input[])
{
    return ra_iot_mbedtls_encrypt(rsa, input);
}

int ra_iot_decrypt(void){
    return ra_iot_mbedtls_decrypt();
}

int ra_iot_sign(void){
    return ra_iot_mbedtls_sign();
}


int ra_iot_verify_sig(void){
    return ra_iot_mbedtls_verify_sig();
}


void ra_iot_print_pub_key(mbedtls_rsa_context rsa){
    ra_iot_mbedtls_print_rsa_pubkey(rsa);
}





















