#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <mbedtls/asn1write.h>
// Do teste
#include "ra_iot_mbedtls.h"
/*
#include <mbedtls/platform.h>
#include <mbedtls/error.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/bignum.h>
#include <mbedtls/rsa.h>
#include <mbedtls/md.h>

#define mbedtls_printf          printf
#define mbedtls_exit            exit
//#define mbedtls_snprintf        snprintf
//#define MBEDTLS_EXIT_SUCCESS    EXIT_SUCCESS
//#define MBEDTLS_EXIT_FAILURE    EXIT_FAILURE

#define KEY_SIZE 2048
#define EXPONENT 65537*/


/****************************************************/
/****************************************************/

int pk_write_rsa_pubkey( unsigned char **p, unsigned char *start,
                                  mbedtls_rsa_context *rsa )
{
    int ret;
    size_t len = 0;
 
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_mpi( p, start, &rsa->E  ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_mpi( p, start, &rsa->N  ) );
 
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( p, start, len ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( p, start, MBEDTLS_ASN1_CONSTRUCTED |
                                                 MBEDTLS_ASN1_SEQUENCE ) );
 
    return( (int) len );
}

void print_pub_key_dto(pub_key_dto pk){
    printf("N = %s\n", pk.N);
    printf("E = %s\n", pk.E);
}

void print_mpi(mbedtls_mpi mpi){
    printf("s: %d\n", mpi.s);
    printf("n: %zu\n", mpi.n);
    printf("p: %" PRIu64 "\n", *(mpi.p));
    //printf("p: %lld\n", (long long)*(mpi.p));
    
}

void ra_iot_mbedtls_print_rsa_pubkey(mbedtls_rsa_context rsa){
    printf("N:\n");
    print_mpi(rsa.N);
    printf("\nE:\n");
    print_mpi(rsa.E);
}

int cpm_pub_keys(mbedtls_rsa_context rsa1, mbedtls_rsa_context rsa2){
    if(mbedtls_mpi_cmp_abs(&(rsa1.N), &(rsa2.N)) !=0){
        return 0;
    }

    if(mbedtls_mpi_cmp_abs(&(rsa1.E), &(rsa2.E)) !=0){
        return 0;
    }
    return 1;
}

/* void load_ecrypt_from_str(uint8_t *input, int i_len, unsigned char *output){
    unsigned c;
    int i;
    for( i = 0; i < i_len; i++ ){
        sscanf( input[i], "%02X", (unsigned char *) &c );
        output[i] = (unsigned char) c;
    }
}

void save_ecrypt_to_str(uint8_t *input, int i_len, char *output){
    printf("[START] save_ecrypt_to_str");
    int i;
    for( i = 0; i < i_len; i++ )
        //sprintf( output[i], "%02X", input[i]);
        printf("%02X", input[i]);
    printf("\r[END] save_ecrypt_to_str\n");
}
 */


/****************************************************/
/****************************************************/




/***************************************************/
/************* Cryptographic Functions *************/
/***************************************************/

int ra_iot_mbedtls_gen_rsa_key( char *path ){

    int ret = 1;
    int exit_code = 0;
    mbedtls_rsa_context rsa;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_mpi N, P, Q, D, E, DP, DQ, QP;
    FILE *fpub  = NULL;
    FILE *fpriv = NULL;
    char priv_path[256];
    char pub_path[256];
    const char *pers = "rsa_genkey";

    mbedtls_ctr_drbg_init( &ctr_drbg );
    mbedtls_rsa_init( &rsa, MBEDTLS_RSA_PKCS_V15, 0 );
    mbedtls_mpi_init( &N ); mbedtls_mpi_init( &P ); mbedtls_mpi_init( &Q );
    mbedtls_mpi_init( &D ); mbedtls_mpi_init( &E ); mbedtls_mpi_init( &DP );
    mbedtls_mpi_init( &DQ ); mbedtls_mpi_init( &QP );

    /* ---- Seeding the random number generator ---- */
    

    mbedtls_entropy_init( &entropy );
    if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
                               (const unsigned char *) pers,
                               strlen( pers ) ) ) != 0 )
    {
        mbedtls_printf( " Seeding the randomm number generator failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret );
        goto exit;
    }

    /* ----- Generating the RSA key ----- */

    if( ( ret = mbedtls_rsa_gen_key( &rsa, mbedtls_ctr_drbg_random, &ctr_drbg, KEY_SIZE,
                                     EXPONENT ) ) != 0 )
    {
        mbedtls_printf( " Generating the RSA key [ %d-bit ] failed\n  ! mbedtls_rsa_gen_key returned %d\n\n", KEY_SIZE, ret );
        goto exit;
    }
    sprintf(pub_path, "%srsa_pub.txt", path);
    /* ----- Exporting the public key to the file ----- */

    if( ( ret = mbedtls_rsa_export    ( &rsa, &N, &P, &Q, &D, &E ) ) != 0 ||
        ( ret = mbedtls_rsa_export_crt( &rsa, &DP, &DQ, &QP ) )      != 0 )
    {
        mbedtls_printf( " Exporting the public  key in %s failed\n  ! could not export RSA parameters\n\n", pub_path );
        goto exit;
    }

    if( ( fpub = fopen( pub_path, "wb+" ) ) == NULL )
    {
        mbedtls_printf( " Exporting the public key failed\n  ! could not open %s for writing\n\n", pub_path );
        goto exit;
    }

    if( ( ret = mbedtls_mpi_write_file( "N = ", &N, 16, fpub ) ) != 0 ||
        ( ret = mbedtls_mpi_write_file( "E = ", &E, 16, fpub ) ) != 0 )
    {
        mbedtls_printf( "Exporting the public key to %s failed\n  ! mbedtls_mpi_write_file returned %d\n\n", pub_path, ret );
        goto exit;
    }

    sprintf(priv_path, "%srsa_priv.txt", path);
    /* ----- Exporting the private key ----- */

    if( ( fpriv = fopen( priv_path, "wb+" ) ) == NULL )
    {
        mbedtls_printf( " Exporting the private key failed\n  ! could not open %s for writing\n",  priv_path);
        goto exit;
    }

    if( ( ret = mbedtls_mpi_write_file( "N = " , &N , 16, fpriv ) ) != 0 ||
        ( ret = mbedtls_mpi_write_file( "E = " , &E , 16, fpriv ) ) != 0 ||
        ( ret = mbedtls_mpi_write_file( "D = " , &D , 16, fpriv ) ) != 0 ||
        ( ret = mbedtls_mpi_write_file( "P = " , &P , 16, fpriv ) ) != 0 ||
        ( ret = mbedtls_mpi_write_file( "Q = " , &Q , 16, fpriv ) ) != 0 ||
        ( ret = mbedtls_mpi_write_file( "DP = ", &DP, 16, fpriv ) ) != 0 ||
        ( ret = mbedtls_mpi_write_file( "DQ = ", &DQ, 16, fpriv ) ) != 0 ||
        ( ret = mbedtls_mpi_write_file( "QP = ", &QP, 16, fpriv ) ) != 0 )
    {
        mbedtls_printf( " Exporting the private key failed\n  ! mbedtls_mpi_write_file returned %d\n\n", ret );
        goto exit;
    }

    exit_code = 1;

exit:

    if( fpub  != NULL )
        fclose( fpub );

    if( fpriv != NULL )
        fclose( fpriv );

    mbedtls_mpi_free( &N ); mbedtls_mpi_free( &P ); mbedtls_mpi_free( &Q );
    mbedtls_mpi_free( &D ); mbedtls_mpi_free( &E ); mbedtls_mpi_free( &DP );
    mbedtls_mpi_free( &DQ ); mbedtls_mpi_free( &QP );
    mbedtls_rsa_free( &rsa );
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );

    return exit_code;
}


int ra_iot_mbedtls_load_pub_key_from_buffer(pub_key_dto *pk_buffer, mbedtls_rsa_context *rsa) 
{

    FILE *f;
    int ret = 1;
    unsigned c;
    int exit_code = 0;
    size_t i;
    //mbedtls_rsa_context rsa;
    unsigned char hash[32];
    unsigned char buf[MBEDTLS_MPI_MAX_SIZE];


    mbedtls_rsa_init( rsa, MBEDTLS_RSA_PKCS_V15, 0 );

    if( ( ret = mbedtls_mpi_read_binary( &(rsa->N), (const unsigned char *) &(pk_buffer->N), 256 ) ) != 0 ||
        ( ret = mbedtls_mpi_read_binary( &(rsa->E), (const unsigned char *) &(pk_buffer->E), 256 ) ) != 0 )
    {
        mbedtls_printf( "Reading public key from the file failed\n  ! mbedtls_mpi_read_file returned %d\n\n", ret );
        //fclose( f );
        goto exit;
    }

    rsa->len = ( mbedtls_mpi_bitlen( &(rsa->N) ) + 7 ) >> 3;
    //fclose( f );
    /* ----- Checking the public key ----- */
    fflush( stdout );
    if( ( ret = mbedtls_rsa_check_pubkey( rsa ) ) != 0 )
    {
        mbedtls_printf( "Reading public key from the file failed\n  ! mbedtls_rsa_check_pubkey failed with -0x%0x\n", (unsigned int) -ret );
        goto exit;
    }
    /* Public Key was loaded!! */
    exit_code = 1;
    
exit:
    return exit_code;

}

/* Load public key from a file to a bufffer */
int ra_iot_mbedtls_load_pub_key_to_buffer(char *filename, pub_key_dto *pk_bytes) 
{

    FILE *f;
    int ret = 1;
    unsigned c;
    int exit_code = 0;
    
    mbedtls_mpi N = {0};
    mbedtls_mpi E = {0};
    mbedtls_mpi_init(&N);
	mbedtls_mpi_init(&E);

    /* ----- Reading public key from the file ----- */

    if( ( f = fopen( filename, "rb" ) ) == NULL )
    {
        mbedtls_printf( " Reading public key from the file failed\n  ! Could not open %s\n\n", filename );
        goto exit;
    }
    
    //mbedtls_printf( "Reading key\n\n");
    fflush(stdout);

    if( ( ret = mbedtls_mpi_read_file( &N, 16, f ) ) != 0 ||
        ( ret = mbedtls_mpi_read_file( &E, 16, f ) ) != 0 )
    {
        mbedtls_printf( "Reading public key from the file failed\n  ! mbedtls_mpi_read_file returned %d\n\n", ret );
        fclose( f );
        goto exit;
    }
    //rsa.len = ( mbedtls_mpi_bitlen( &(rsa.N) ) + 7 ) >> 3;
    //mbedtls_printf( "Writing to binary\n\n");
    fflush(stdout);
    if( ( ret = mbedtls_mpi_write_binary( &N, &(pk_bytes->N), 256 ) ) != 0 ||
        ( ret = mbedtls_mpi_write_binary( &E, &(pk_bytes->E), 256 ) ) != 0 )
    {
        mbedtls_printf( "Writing to binary failed\n  ! mbedtls_mpi_write_binary returned %d\n\n", ret );
        fclose( f );
        goto exit;
    }

    
    fclose( f );

    /* Public Key was loaded!! */
    exit_code = 1;
exit:
    mbedtls_mpi_free(&N);
	mbedtls_mpi_free(&E);
    return exit_code;

}

int ra_iot_mbedtls_load_pub_key(char *filename, mbedtls_rsa_context *rsa) 
{

    FILE *f;
    int ret = 1;
    unsigned c;
    int exit_code = 0;
    size_t i;
    //mbedtls_rsa_context rsa;
    unsigned char hash[32];
    unsigned char buf[MBEDTLS_MPI_MAX_SIZE];


    mbedtls_rsa_init( rsa, MBEDTLS_RSA_PKCS_V15, 0 );

    /* ----- Reading public key from the file ----- */

    if( ( f = fopen( filename, "rb" ) ) == NULL )
    {
        mbedtls_printf( " Reading public key from the file failed\n  ! Could not open %s\n\n", filename );
        goto exit;
    }

    if( ( ret = mbedtls_mpi_read_file( &(rsa->N), 16, f ) ) != 0 ||
        ( ret = mbedtls_mpi_read_file( &(rsa->E), 16, f ) ) != 0 )
    {
        mbedtls_printf( "Reading public key from the file failed\n  ! mbedtls_mpi_read_file returned %d\n\n", ret );
        fclose( f );
        goto exit;
    }

    rsa->len = ( mbedtls_mpi_bitlen( &(rsa->N) ) + 7 ) >> 3;

    fclose( f );

    /* ----- Checking the public key ----- */
    fflush( stdout );
    if( ( ret = mbedtls_rsa_check_pubkey( rsa ) ) != 0 )
    {
        mbedtls_printf( "Reading public key from the file failed\n  ! mbedtls_rsa_check_pubkey failed with -0x%0x\n", (unsigned int) -ret );
        goto exit;
    }

    /* Public Key was loaded!! */
    exit_code = 1;
exit:
    return exit_code;

}

int ra_iot_mbedtls_load_priv_key(char *filename, mbedtls_rsa_context *rsa)
{
    FILE *f;
    int ret = 1;
    unsigned c;
    int exit_code = 0;
    size_t i;
    //mbedtls_rsa_context rsa;
    unsigned char hash[32];
    unsigned char buf[MBEDTLS_MPI_MAX_SIZE];

    mbedtls_mpi N, P, Q, D, E, DP, DQ, QP;

    mbedtls_rsa_init( rsa, MBEDTLS_RSA_PKCS_V15, 0 );

    mbedtls_mpi_init( &N ); mbedtls_mpi_init( &P ); mbedtls_mpi_init( &Q );
    mbedtls_mpi_init( &D ); mbedtls_mpi_init( &E ); mbedtls_mpi_init( &DP );
    mbedtls_mpi_init( &DQ ); mbedtls_mpi_init( &QP );

    /* ----- Reading private key from the file ----- */

    if( ( f = fopen( filename, "rb" ) ) == NULL )
    {
        mbedtls_printf( "Reading private key from the file failed\n  ! Could not open %s\n\n", filename );
        goto exit;
    }

    if( ( ret = mbedtls_mpi_read_file( &N , 16, f ) ) != 0 ||
        ( ret = mbedtls_mpi_read_file( &E , 16, f ) ) != 0 ||
        ( ret = mbedtls_mpi_read_file( &D , 16, f ) ) != 0 ||
        ( ret = mbedtls_mpi_read_file( &P , 16, f ) ) != 0 ||
        ( ret = mbedtls_mpi_read_file( &Q , 16, f ) ) != 0 ||
        ( ret = mbedtls_mpi_read_file( &DP , 16, f ) ) != 0 ||
        ( ret = mbedtls_mpi_read_file( &DQ , 16, f ) ) != 0 ||
        ( ret = mbedtls_mpi_read_file( &QP , 16, f ) ) != 0 )
    {
        mbedtls_printf( "Reading private key from the file failed\n  ! mbedtls_mpi_read_file returned %d\n\n", ret );
        fclose( f );
        goto exit;
    }
    fclose( f );

    if( ( ret = mbedtls_rsa_import( rsa, &N, &P, &Q, &D, &E ) ) != 0 )
    {
        mbedtls_printf( "Reading private key from the file failed\n  ! mbedtls_rsa_import returned %d\n\n", ret );
        goto exit;
    }

    if( ( ret = mbedtls_rsa_complete( rsa ) ) != 0 )
    {
        mbedtls_printf( "Reading private key from the file failed\n  ! mbedtls_rsa_complete returned %d\n\n", ret );
        goto exit;
    }

    /* ----- Checking the private key ----- */
    if( ( ret = mbedtls_rsa_check_privkey( rsa ) ) != 0 )
    {
        mbedtls_printf( " Checking the private key failed\n  ! mbedtls_rsa_check_privkey failed with -0x%0x\n", (unsigned int) -ret );
        goto exit;
    }

    /* Private key was loaded!! */
    exit_code = 1;
exit:
    mbedtls_mpi_free( &N ); mbedtls_mpi_free( &P ); mbedtls_mpi_free( &Q );
    mbedtls_mpi_free( &D ); mbedtls_mpi_free( &E ); mbedtls_mpi_free( &DP );
    mbedtls_mpi_free( &DQ ); mbedtls_mpi_free( &QP );
    return exit_code;

}

int ra_iot_mbedtls_encrypt( mbedtls_rsa_context *key, unsigned char input[], size_t i_len, unsigned char *output)
{    
    
    FILE *f;
    int ret = 1;
    int exit_code = 0;
    size_t i;

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    unsigned char *buf = output;
    const char *pers = "rsa_encrypt";
    
    
    /* ----- Seeding the random number generator ----- */
    fflush( stdout );

    mbedtls_ctr_drbg_init( &ctr_drbg );
    mbedtls_entropy_init( &entropy );

    ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func,
                                 &entropy, (const unsigned char *) pers,
                                 strlen( pers ) );
    if( ret != 0 )
    {
        mbedtls_printf( "Seeding the random number generator failed\n  ! mbedtls_ctr_drbg_seed returned %d\n",
                        ret );
        goto exit;
    }

    //if( strlen(input) > 100 )
    int max_size_allowed = 256-11;
    //if( strlen(input) > max_size_allowed)
    if( i_len > max_size_allowed)
    {
        mbedtls_printf( " Input data larger than %d characters. Size is %d\n\n", max_size_allowed, i_len );
        goto exit;
    }

    /*
     * Calculate the RSA encryption of the hash.
     */
    
    ret = mbedtls_rsa_pkcs1_encrypt( key, mbedtls_ctr_drbg_random,
                                     &ctr_drbg, MBEDTLS_RSA_PUBLIC, i_len, input, buf );

    printf("i_len = %zu\n", i_len);
    if( ret != 0 )
    {
        mbedtls_printf( "Generating the RSA encrypted value failed\n  ! mbedtls_rsa_pkcs1_encrypt returned %d\n\n",
                        ret );
        goto exit;
    }
    

    /* Encryption Done */
    mbedtls_printf("[MBEDTLS] Encryption Done!\n");

    exit_code = 1;

exit:
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );

    return exit_code;
}

int ra_iot_mbedtls_decrypt(mbedtls_rsa_context *key, unsigned char *encr_data, unsigned char *result){
    
    FILE *f;
    int ret = 1;
    int exit_code = 0;
    unsigned c;
    size_t i = 0;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    unsigned char *buf = encr_data;
    const char *pers = "rsa_decrypt";
    memset(result, 0, sizeof( result ) );
    
    /* ----- Seeding the random number generator ----- */

    mbedtls_ctr_drbg_init( &ctr_drbg );
    mbedtls_entropy_init( &entropy );

    ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func,
                                        &entropy, (const unsigned char *) pers,
                                        strlen( pers ) );
    if( ret != 0 )
    {
        mbedtls_printf( "Seeding the random number generator failed\n  ! mbedtls_ctr_drbg_seed returned %d\n",
                        ret );
        goto exit;
    }

    /*
     * Decrypt the encrypted RSA data and print the result.
     */
    
    ret = mbedtls_rsa_pkcs1_decrypt( key, mbedtls_ctr_drbg_random,
                                                &ctr_drbg, MBEDTLS_RSA_PRIVATE, &i,
                                                buf, result, 1024 );

    if( ret != 0 )
    {
        mbedtls_printf( "Decrypting the encrypted data failed\n  ! mbedtls_rsa_pkcs1_decrypt returned %d\n\n",
                        ret );
        goto exit;
    }else{
        mbedtls_printf("[MBEDTLS] Decryption Successfull, size is %zu\n", i);

    }

    exit_code = 1;

exit:
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );

    return exit_code;

}

int ra_iot_mbedtls_sign(mbedtls_rsa_context *key, unsigned char *data, size_t data_len, unsigned char *signature){

    FILE *f;
    int ret = 1;
    int exit_code = 0;
    size_t i;

    unsigned char hash[32];
    unsigned char hash_test[32];

    unsigned char *buf = signature;


    /*
     * Compute the SHA-256 hash of the input file,
     * then calculate the RSA signature of the hash.
     */

    if( ( ret = mbedtls_md(
                    mbedtls_md_info_from_type( MBEDTLS_MD_SHA256 ),
                    data, data_len, hash ) ) != 0 )
    {
        mbedtls_printf( "Generating the RSA/SHA-256 signature failed\n  ! mbedtls_md returned -0x%0x\n\n", (unsigned int) -ret );
        goto exit;
    }


    if( ( ret = mbedtls_rsa_pkcs1_sign( key, NULL, NULL, MBEDTLS_RSA_PRIVATE, MBEDTLS_MD_SHA256,
                                32, hash, buf ) ) != 0 )
    {
        mbedtls_printf( "Generating the RSA/SHA-256 signature failed\n  ! mbedtls_rsa_pkcs1_sign returned -0x%0x\n\n", (unsigned int) -ret );
        goto exit;
    }

    exit_code = 1;
    mbedtls_printf("\t[MBEDTLS] Signature Done\n");

exit:
    return exit_code;
}

int ra_iot_mbedtls_verify_sig(mbedtls_rsa_context *key, unsigned char *data, size_t data_len, unsigned char *signature){

    FILE *f;
    int ret = 1;
    unsigned c;
    int exit_code = 0;
    size_t i;
    unsigned char hash[32];
    unsigned char *buf = signature;

    /*
     * Compute the SHA-256 hash of the input file and
     * verify the signature
     */


    if( ( ret = mbedtls_md(
                    mbedtls_md_info_from_type( MBEDTLS_MD_SHA256 ),
                    data, data_len, hash ) ) != 0 )
    {
        mbedtls_printf( "Verifying the RSA/SHA-256 signature failed\n  ! mbedtls_md returned -0x%0x\n\n", (unsigned int) -ret );
        goto exit;
    }

    if( ( ret = mbedtls_rsa_pkcs1_verify( key, NULL, NULL, MBEDTLS_RSA_PUBLIC, MBEDTLS_MD_SHA256,
                                            32, hash, buf ) ) != 0 )
    {
        mbedtls_printf( "Verifying the RSA/SHA-256 signature failed\n  ! mbedtls_rsa_pkcs1_verify returned -0x%0x\n\n", (unsigned int) -ret );
        goto exit;
    }

    exit_code = 1;

exit:

    return exit_code;

}

/***************************************************/
/************* mbedtls utils functions *************/
/***************************************************/

int ra_iot_mbedtls_gen_rand_bytes(const uint32_t nonce_len, uint8_t* nonce) {
	int ret = 1;
	/* initialize contexts */
	mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    
    mbedtls_ctr_drbg_init( &ctr_drbg );
    mbedtls_entropy_init( &entropy );

	/* add seed */
    if((ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *) "RANDOM_GEN", 10 )) != 0)
    {
        mbedtls_printf( "failed in mbedtls_ctr_drbg_seed: %d\n", ret );
        goto cleanup;
    }
    mbedtls_ctr_drbg_set_prediction_resistance( &ctr_drbg, MBEDTLS_CTR_DRBG_PR_ON );

	ret = mbedtls_ctr_drbg_random( &ctr_drbg, (unsigned char*)nonce, (size_t) nonce_len );
    if( ret != 0 )
    {
        mbedtls_printf("failed!\n");
        goto cleanup;
    }

cleanup:
    mbedtls_printf("\n");

    
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );

    return 1;
}