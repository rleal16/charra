#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
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


/****************************************************/
/****************************************************/




/***************************************************/
/************* Cryptographic Functions *************/
/***************************************************/

int ra_iot_mbedtls_gen_rsa_key( char *path ){
    printf("Calling gen_rsa_key\n");
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

    mbedtls_printf( "\n  . Seeding the random number generator..." );
    fflush( stdout );

    mbedtls_entropy_init( &entropy );
    if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
                               (const unsigned char *) pers,
                               strlen( pers ) ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret );
        goto exit;
    }

    mbedtls_printf( " ok\n  . Generating the RSA key [ %d-bit ]...", KEY_SIZE );
    fflush( stdout );

    if( ( ret = mbedtls_rsa_gen_key( &rsa, mbedtls_ctr_drbg_random, &ctr_drbg, KEY_SIZE,
                                     EXPONENT ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_rsa_gen_key returned %d\n\n", ret );
        goto exit;
    }
    sprintf(pub_path, "%srsa_pub.txt", path);
    mbedtls_printf( " ok\n  . Exporting the public  key in %s....", pub_path );
    fflush( stdout );

    if( ( ret = mbedtls_rsa_export    ( &rsa, &N, &P, &Q, &D, &E ) ) != 0 ||
        ( ret = mbedtls_rsa_export_crt( &rsa, &DP, &DQ, &QP ) )      != 0 )
    {
        mbedtls_printf( " failed\n  ! could not export RSA parameters\n\n" );
        goto exit;
    }

    if( ( fpub = fopen( pub_path, "wb+" ) ) == NULL )
    {
        mbedtls_printf( " failed\n  ! could not open %s for writing\n\n", pub_path );
        goto exit;
    }

    if( ( ret = mbedtls_mpi_write_file( "N = ", &N, 16, fpub ) ) != 0 ||
        ( ret = mbedtls_mpi_write_file( "E = ", &E, 16, fpub ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_mpi_write_file returned %d\n\n", ret );
        goto exit;
    }

    sprintf(priv_path, "%srsa_priv.txt", path);
    mbedtls_printf( " ok\n  . Exporting the private key in %s...", priv_path );
    fflush( stdout );

    if( ( fpriv = fopen( priv_path, "wb+" ) ) == NULL )
    {
        mbedtls_printf( " failed\n  ! could not open %s for writing\n",  priv_path);
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
        mbedtls_printf( " failed\n  ! mbedtls_mpi_write_file returned %d\n\n", ret );
        goto exit;
    }
    mbedtls_printf( " ok\n\n" );

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

    return 0;
}

mbedtls_rsa_context ra_iot_mbedtls_load_pub_key(char *filename)
{
    FILE *f;
    int ret = 1;
    unsigned c;
    int exit_code = MBEDTLS_EXIT_FAILURE;
    size_t i;
    mbedtls_rsa_context rsa;
    unsigned char hash[32];
    unsigned char buf[MBEDTLS_MPI_MAX_SIZE];
    //char filename[512];


    mbedtls_rsa_init( &rsa, MBEDTLS_RSA_PKCS_V15, 0 );

    mbedtls_printf( "\n  . Reading public key from the file %s", filename );
    fflush( stdout );

    //if( ( f = fopen( "rsa_pub.txt", "rb" ) ) == NULL )
    if( ( f = fopen( filename, "rb" ) ) == NULL )
    {
        mbedtls_printf( " failed\n  ! Could not open %s\n" \
                "  ! Please run rsa_genkey first\n\n", filename );
        goto exit;
    }

    if( ( ret = mbedtls_mpi_read_file( &rsa.N, 16, f ) ) != 0 ||
        ( ret = mbedtls_mpi_read_file( &rsa.E, 16, f ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_mpi_read_file returned %d\n\n", ret );
        fclose( f );
        goto exit;
    }

    rsa.len = ( mbedtls_mpi_bitlen( &rsa.N ) + 7 ) >> 3;

    fclose( f );

    mbedtls_printf( "\n  . Checking the public key" );
    fflush( stdout );
    if( ( ret = mbedtls_rsa_check_pubkey( &rsa ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_rsa_check_pubkey failed with -0x%0x\n", (unsigned int) -ret );
        goto exit;
    }

    mbedtls_printf( "\n  . Public Key was loaded!!\n\n" );

exit:
    return rsa;

}

mbedtls_rsa_context ra_iot_mbedtls_load_priv_key(char *filename)
{
    FILE *f;
    int ret = 1;
    unsigned c;
    int exit_code = MBEDTLS_EXIT_FAILURE;
    size_t i;
    mbedtls_rsa_context rsa;
    unsigned char hash[32];
    unsigned char buf[MBEDTLS_MPI_MAX_SIZE];
    //char filename[512];

    mbedtls_mpi N, P, Q, D, E, DP, DQ, QP;

    mbedtls_rsa_init( &rsa, MBEDTLS_RSA_PKCS_V15, 0 );

    mbedtls_mpi_init( &N ); mbedtls_mpi_init( &P ); mbedtls_mpi_init( &Q );
    mbedtls_mpi_init( &D ); mbedtls_mpi_init( &E ); mbedtls_mpi_init( &DP );
    mbedtls_mpi_init( &DQ ); mbedtls_mpi_init( &QP );

    mbedtls_printf( "\n  . Reading private key from the file %s", filename );
    fflush( stdout );

    if( ( f = fopen( filename, "rb" ) ) == NULL )
    {
        mbedtls_printf( " failed\n  ! Could not open %s\n" \
                "  ! Please run rsa_genkey first\n\n", filename );
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
        mbedtls_printf( " failed\n  ! mbedtls_mpi_read_file returned %d\n\n", ret );
        fclose( f );
        goto exit;
    }
    fclose( f );

    if( ( ret = mbedtls_rsa_import( &rsa, &N, &P, &Q, &D, &E ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_rsa_import returned %d\n\n",
                        ret );
        goto exit;
    }

    if( ( ret = mbedtls_rsa_complete( &rsa ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_rsa_complete returned %d\n\n",
                        ret );
        goto exit;
    }

    mbedtls_printf( "\n  . Checking the private key" );
    fflush( stdout );
    if( ( ret = mbedtls_rsa_check_privkey( &rsa ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_rsa_check_privkey failed with -0x%0x\n", (unsigned int) -ret );
        goto exit;
    }

    mbedtls_printf( "\n  . Private key was loaded!!\n\n" );

exit:
    mbedtls_mpi_free( &N ); mbedtls_mpi_free( &P ); mbedtls_mpi_free( &Q );
    mbedtls_mpi_free( &D ); mbedtls_mpi_free( &E ); mbedtls_mpi_free( &DP );
    mbedtls_mpi_free( &DQ ); mbedtls_mpi_free( &QP );
    return rsa;

}


int ra_iot_mbedtls_encrypt( mbedtls_rsa_context *key, unsigned char input[], unsigned char *output)
{    
    printf("***************\nEncrypting \"%s\": %s\n", input, KEY_USE(LOAD_KEY_DECRYPT));
    
    FILE *f;
    int ret = 1;
    int exit_code = 0;
    size_t i;
#if LOAD_KEY_ENCRYPT
    mbedtls_rsa_context rsa;
    mbedtls_mpi N, E;
#endif
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

#if WRITE_ENCR_FILE
    printf("Writing the file with the encryption results\n");
    unsigned char buf[512];
#else
    printf("WITHOUT Writing the file with the encryption results\n");
    unsigned char *buf = output;
#endif

    const char *pers = "rsa_encrypt";
    

    mbedtls_printf( "\n  . Seeding the random number generator..." );
    fflush( stdout );

#if LOAD_KEY_ENCRYPT
    mbedtls_mpi_init( &N ); mbedtls_mpi_init( &E );
    mbedtls_rsa_init( &rsa, MBEDTLS_RSA_PKCS_V15, MBEDTLS_MD_NONE  );
#endif

    mbedtls_ctr_drbg_init( &ctr_drbg );
    mbedtls_entropy_init( &entropy );

    ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func,
                                 &entropy, (const unsigned char *) pers,
                                 strlen( pers ) );
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ctr_drbg_seed returned %d\n",
                        ret );
        goto exit;
    }

    //------------------------------------------------------------------------
    
#if LOAD_KEY_ENCRYPT
    mbedtls_printf( "\n  . Reading public key from rsa_pub.txt" );
    fflush( stdout );


    if( ( f = fopen( "rsa_pub.txt", "rb" ) ) == NULL )
    {
        mbedtls_printf( " failed\n  ! Could not open rsa_pub.txt\n" \
                "  ! Please run rsa_genkey first\n\n" );
        goto exit;
    }

    if( ( ret = mbedtls_mpi_read_file( &N, 16, f ) ) != 0 ||
        ( ret = mbedtls_mpi_read_file( &E, 16, f ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_mpi_read_file returned %d\n\n",
                        ret );
        fclose( f );
        goto exit;
    }
    fclose( f );

    if( ( ret = mbedtls_rsa_import( &rsa, &N, NULL, NULL, NULL, &E ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_rsa_import returned %d\n\n",
                        ret );
        goto exit;
    }
    
    //------------------------------------------------------------------------
#endif


    //if( strlen(input) > 100 )
    int max_size_allowed = 256-11;
    if( strlen(input) > max_size_allowed)
    {
        mbedtls_printf( " Input data larger than %d characters.\n\n", max_size_allowed );
        goto exit;
    }else{
        printf("Input %s\n", input);
    }

    /*
     * Calculate the RSA encryption of the hash.
     */
    mbedtls_printf( "\n  . Generating the RSA encrypted value" );
    fflush( stdout );
#if LOAD_KEY_ENCRYPT
    ret = mbedtls_rsa_pkcs1_encrypt( &rsa, mbedtls_ctr_drbg_random,
                                     &ctr_drbg, MBEDTLS_RSA_PUBLIC, strlen(input), input, buf );
#else
    ret = mbedtls_rsa_pkcs1_encrypt( key, mbedtls_ctr_drbg_random,
                                     &ctr_drbg, MBEDTLS_RSA_PUBLIC, strlen(input), input, buf );
#endif
    
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_rsa_pkcs1_encrypt returned %d\n\n",
                        ret );
        goto exit;
    }
    
    /*
     * Write the signature into result-enc.txt
     */
#if WRITE_ENCR_FILE
    if( ( f = fopen( "result-enc.txt", "wb+" ) ) == NULL )
    {
        mbedtls_printf( " failed\n  ! Could not create %s\n\n", "result-enc.txt" );
        goto exit;
    }
    printf("\nWRITING ecrypted data with len: %zu (or %d) (key_len: %zu [or %d])\n\n", strlen(buf), strlen(buf), key->len, key->len);
    unsigned char res[512];
#if LOAD_KEY_ENCRYPT
    for( i = 0; i < rsa.len; i++ )
#else
    for( i = 0; i < key->len; i++ )
#endif
    {
        mbedtls_fprintf( f, "%02X%s", buf[i],
                 ( i + 1 ) % 16 == 0 ? "\r\n" : " " );
    }
        
    fclose( f );
    memcpy(output, buf, sizeof(buf)); // must save anyway so that we can test others without reading the file!
#endif

    mbedtls_printf( "\n  . Done (created \"%s\")\n\n", "result-enc.txt" );

    exit_code = 1;

exit:
#if LOAD_KEY_ENCRYPT
    //mbedtls_mpi_free( &N ); mbedtls_mpi_free( &E );
#endif
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );

    return exit_code;
}

int ra_iot_mbedtls_decrypt(mbedtls_rsa_context *key, unsigned char *encr_data, unsigned char *result){

    printf("***************\nDecrypting Data: %s\n", KEY_USE(LOAD_KEY_DECRYPT));
    
    FILE *f;
    int ret = 1;
    int exit_code = 0;
    unsigned c;
    size_t i;
#if LOAD_KEY_DECRYPT
    mbedtls_rsa_context rsa;
    mbedtls_mpi N, P, Q, D, E, DP, DQ, QP;
#endif
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

#if READ_ENCR_FILE_2DECRYPT
    printf("\tReading ecrypted data file\n");
    unsigned char buf[512];
#else
    printf("\tNot reading ecrypted data file\n");
    unsigned char *buf = encr_data;
#endif

    const char *pers = "rsa_decrypt";

    memset(result, 0, sizeof( result ) );

    mbedtls_printf( "\n  . Seeding the random number generator..." );
    fflush( stdout );
#if LOAD_KEY_DECRYPT
    mbedtls_rsa_init( &rsa, MBEDTLS_RSA_PKCS_V15, MBEDTLS_MD_NONE  );
#endif
    mbedtls_ctr_drbg_init( &ctr_drbg );
    mbedtls_entropy_init( &entropy );
#if LOAD_KEY_DECRYPT
    mbedtls_mpi_init( &N ); mbedtls_mpi_init( &P ); mbedtls_mpi_init( &Q );
    mbedtls_mpi_init( &D ); mbedtls_mpi_init( &E ); mbedtls_mpi_init( &DP );
    mbedtls_mpi_init( &DQ ); mbedtls_mpi_init( &QP );
#endif

    ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func,
                                        &entropy, (const unsigned char *) pers,
                                        strlen( pers ) );
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ctr_drbg_seed returned %d\n",
                        ret );
        goto exit;
    }

#if LOAD_KEY_DECRYPT
    mbedtls_printf( "\n  . Reading private key from rsa_priv.txt" );
    fflush( stdout );

    if( ( f = fopen( "rsa_priv.txt", "rb" ) ) == NULL )
    {
        mbedtls_printf( " failed\n  ! Could not open rsa_priv.txt\n" \
                "  ! Please run rsa_genkey first\n\n" );
        goto exit;
    }

    if( ( ret = mbedtls_mpi_read_file( &N , 16, f ) )  != 0 ||
        ( ret = mbedtls_mpi_read_file( &E , 16, f ) )  != 0 ||
        ( ret = mbedtls_mpi_read_file( &D , 16, f ) )  != 0 ||
        ( ret = mbedtls_mpi_read_file( &P , 16, f ) )  != 0 ||
        ( ret = mbedtls_mpi_read_file( &Q , 16, f ) )  != 0 ||
        ( ret = mbedtls_mpi_read_file( &DP , 16, f ) ) != 0 ||
        ( ret = mbedtls_mpi_read_file( &DQ , 16, f ) ) != 0 ||
        ( ret = mbedtls_mpi_read_file( &QP , 16, f ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_mpi_read_file returned %d\n\n",
                        ret );
        fclose( f );
        goto exit;
    }
    fclose( f );


    if( ( ret = mbedtls_rsa_import( &rsa, &N, &P, &Q, &D, &E ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_rsa_import returned %d\n\n",
                        ret );
        goto exit;
    }

    if( ( ret = mbedtls_rsa_complete( &rsa ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_rsa_complete returned %d\n\n",
                        ret );
        goto exit;
    }
#endif

#if READ_ENCR_FILE_2DECRYPT
    /*
     * Extract the RSA encrypted value from the text file
     */
    if( ( f = fopen( "result-enc.txt", "rb" ) ) == NULL )
    {
        mbedtls_printf( "\n  ! Could not open %s\n\n", "result-enc.txt" );
        goto exit;
    }

    i = 0;
    
    while( fscanf( f, "%02X", (unsigned int*) &c ) > 0 && i < (int) sizeof( buf ) ){
        buf[i++] = (unsigned char) c;
        //printf("%c ", buf[i-1]);
        //printf("%s", ( i ) % 16 == 0 ? "\r\n" : " " );
    }

    fclose( f );
#if LOAD_KEY_DECRYPT
    if( i != rsa.len )
#else
    printf("\nREADING ecrypted data with (i = %i) len: %zu (or %d) (key_len: %zu [or %d])\n\n", i, strlen(buf), strlen(buf), key->len, key->len);
    if( i != key->len )
#endif
    {
        mbedtls_printf( "\n  ! Invalid RSA signature format\n\n" );
        goto exit;
    }

    printf("COMPARING...: %d\n", memcmp(buf, encr_data, (size_t) i));
#endif

    /*
     * Decrypt the encrypted RSA data and print the result.
     */
    mbedtls_printf( "\n  . Decrypting the encrypted data" );
    fflush( stdout );
#if LOAD_KEY_DECRYPT
    ret = mbedtls_rsa_pkcs1_decrypt( &rsa, mbedtls_ctr_drbg_random,
                                            &ctr_drbg, MBEDTLS_RSA_PRIVATE, &i,
                                            buf, result, 1024 );
#else
    ret = mbedtls_rsa_pkcs1_decrypt( key, mbedtls_ctr_drbg_random,
                                                &ctr_drbg, MBEDTLS_RSA_PRIVATE, &i,
                                                buf, result, 1024 );
#endif
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_rsa_pkcs1_decrypt returned %d\n\n",
                        ret );
        goto exit;
    }

    mbedtls_printf( "\n  . OK\n\n" );

    mbedtls_printf( "The decrypted result is: '%s'\n\n", result );

    exit_code = 1;

exit:
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );
#if LOAD_KEY_DECRYPT
    mbedtls_rsa_free( &rsa );
    mbedtls_mpi_free( &N ); mbedtls_mpi_free( &P ); mbedtls_mpi_free( &Q );
    mbedtls_mpi_free( &D ); mbedtls_mpi_free( &E ); mbedtls_mpi_free( &DP );
    mbedtls_mpi_free( &DQ ); mbedtls_mpi_free( &QP );
#endif

    return exit_code;

}

int ra_iot_mbedtls_sign(mbedtls_rsa_context *key, unsigned char *data, unsigned char *signature){

    //printf("***************\nSigning Data: %s\n", (LOAD_KEY_SIGN ? "by loading the key" : "without loading the key"));
    printf("***************\nSigning Data: %s\n", KEY_USE(LOAD_KEY_SIGN));

    FILE *f;
    int ret = 1;
    int exit_code = 0;
    size_t i;
#if LOAD_KEY_SIGN
    mbedtls_rsa_context rsa;
    mbedtls_mpi N, P, Q, D, E, DP, DQ, QP;
#endif
    unsigned char hash[32];
    unsigned char hash_test[32];

#if WRITE_SIGD_FILE
    printf("\tWriting the signature into a file\n");
    unsigned char buf[MBEDTLS_MPI_MAX_SIZE];
#else
    printf("\tWITHOUT Writing the signature into a file\n");
    unsigned char *buf = signature;
#endif

    printf("MBEDTLS_MPI_MAX_SIZE: %d\n", MBEDTLS_MPI_MAX_SIZE);
    char filename[512] = "result-enc";
    char in_file[512];
    char sig_file[512];

#if LOAD_KEY_SIGN
    mbedtls_rsa_init( &rsa, MBEDTLS_RSA_PKCS_V15, 0 );

    mbedtls_mpi_init( &N ); mbedtls_mpi_init( &P ); mbedtls_mpi_init( &Q );
    mbedtls_mpi_init( &D ); mbedtls_mpi_init( &E ); mbedtls_mpi_init( &DP );
    mbedtls_mpi_init( &DQ ); mbedtls_mpi_init( &QP );


    mbedtls_printf( "\n  . Reading private key from rsa_priv.txt" );
    fflush( stdout );

    if( ( f = fopen( "rsa_priv.txt", "rb" ) ) == NULL )
    {
        mbedtls_printf( " failed\n  ! Could not open rsa_priv.txt\n" \
                "  ! Please run rsa_genkey first\n\n" );
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
        mbedtls_printf( " failed\n  ! mbedtls_mpi_read_file returned %d\n\n", ret );
        fclose( f );
        goto exit;
    }
    fclose( f );

    if( ( ret = mbedtls_rsa_import( &rsa, &N, &P, &Q, &D, &E ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_rsa_import returned %d\n\n",
                        ret );
        goto exit;
    }

    if( ( ret = mbedtls_rsa_complete( &rsa ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_rsa_complete returned %d\n\n",
                        ret );
        goto exit;
    }

    mbedtls_printf( "\n  . Checking the private key" );
    fflush( stdout );
    if( ( ret = mbedtls_rsa_check_privkey( &rsa ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_rsa_check_privkey failed with -0x%0x\n", (unsigned int) -ret );
        goto exit;
    }
#endif

    /*
     * Compute the SHA-256 hash of the input file,
     * then calculate the RSA signature of the hash.
     */

    mbedtls_printf( "\n  . Generating the RSA/SHA-256 signature" );
    fflush( stdout );
#if READ_ENCR_FILE_2SIGN
    printf("\n\tReading data do sign from file\n");
    mbedtls_snprintf( in_file, sizeof(in_file), "%s.txt", filename );

    if( ( ret = mbedtls_md_file(
                    mbedtls_md_info_from_type( MBEDTLS_MD_SHA256 ),
                    in_file, hash ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! Could not open or read %s\n\n", filename );
        goto exit;
    }
    printf("\t\tHash size: %d (%d)\n", strlen(hash), sizeof(hash));    
#else
    printf("\n\tWITHOUT Reading data do sign from file\n");
    if( ( ret = mbedtls_md(
                    mbedtls_md_info_from_type( MBEDTLS_MD_SHA256 ),
                    data, strlen(data), hash ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! Could not open or read %s\n\n", filename );
        goto exit;
    }
    printf("\t\t--Hash size: %d (%d)\n", (int) strlen(hash), (int) sizeof(hash));
#endif



#if LOAD_KEY_SIGN
    if( ( ret = mbedtls_rsa_pkcs1_sign( &rsa, NULL, NULL, MBEDTLS_RSA_PRIVATE, MBEDTLS_MD_SHA256,
                                32, hash, buf ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_rsa_pkcs1_sign returned -0x%0x\n\n", (unsigned int) -ret );
        goto exit;
    }
#else
    if( ( ret = mbedtls_rsa_pkcs1_sign( key, NULL, NULL, MBEDTLS_RSA_PRIVATE, MBEDTLS_MD_SHA256,
                                32, hash, buf ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_rsa_pkcs1_sign returned -0x%0x\n\n", (unsigned int) -ret );
        goto exit;
    }

#endif

#if WRITE_SIGD_FILE
    /*
     * Write the signature into <filename>.sig
     */
    mbedtls_snprintf( sig_file, sizeof(sig_file), "%s.sig", filename );

    if( ( f = fopen( sig_file, "wb+" ) ) == NULL )
    {
        mbedtls_printf( " failed\n  ! Could not create %s\n\n", sig_file );
        goto exit;
    }
#if LOAD_KEY_SIGN
    for( i = 0; i < rsa.len; i++ )
#else
    for( i = 0; i < key->len; i++ )
#endif
        mbedtls_fprintf( f, "%02X%s", buf[i],
                 ( i + 1 ) % 16 == 0 ? "\r\n" : " " );

    fclose( f );
    memcpy(signature, buf, sizeof(buf)); // must save anyway so that we can test others without reading the file!
#endif

    mbedtls_printf( "\n  . Done (created \"%s\")\n\n", sig_file );

    exit_code = 1;

exit:

#if LOAD_KEY_SIGN
    mbedtls_rsa_free( &rsa );
    mbedtls_mpi_free( &N ); mbedtls_mpi_free( &P ); mbedtls_mpi_free( &Q );
    mbedtls_mpi_free( &D ); mbedtls_mpi_free( &E ); mbedtls_mpi_free( &DP );
    mbedtls_mpi_free( &DQ ); mbedtls_mpi_free( &QP );
#endif

    return exit_code;
}

int ra_iot_mbedtls_verify_sig(mbedtls_rsa_context *key, unsigned char *data){

    printf("***************\nVerifying Signature: %s\n", KEY_USE(LOAD_KEY_VERIFY));
    FILE *f;
    int ret = 1;
    unsigned c;
    int exit_code = 0;
    size_t i;
#if LOAD_KEY_VERIFY
    mbedtls_rsa_context rsa;
#endif
    unsigned char hash[32];
    unsigned char buf[MBEDTLS_MPI_MAX_SIZE];
    char in_filename[512] = "result-enc";
    char filename[512];
    char sig_file[512];

#if LOAD_KEY_VERIFY
    mbedtls_rsa_init( &rsa, MBEDTLS_RSA_PKCS_V15, 0 );

    mbedtls_printf( "\n  . Reading public key from rsa_pub.txt" );
    fflush( stdout );

    if( ( f = fopen( "rsa_pub.txt", "rb" ) ) == NULL )
    {
        mbedtls_printf( " failed\n  ! Could not open rsa_pub.txt\n" \
                "  ! Please run rsa_genkey first\n\n" );
        goto exit;
    }

    if( ( ret = mbedtls_mpi_read_file( &rsa.N, 16, f ) ) != 0 ||
        ( ret = mbedtls_mpi_read_file( &rsa.E, 16, f ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_mpi_read_file returned %d\n\n", ret );
        fclose( f );
        goto exit;
    }

    rsa.len = ( mbedtls_mpi_bitlen( &rsa.N ) + 7 ) >> 3;

    fclose( f );
#endif
    /*
     * Extract the RSA signature from the text file
     */
    mbedtls_snprintf( sig_file, sizeof(sig_file), "%s.sig", in_filename );

    if( ( f = fopen( sig_file, "rb" ) ) == NULL )
    {
        mbedtls_printf( "\n  ! Could not open %s\n\n", sig_file );
        goto exit;
    }

    i = 0;
    while( fscanf( f, "%02X", (unsigned int*) &c ) > 0 &&
           i < (int) sizeof( buf ) )
        buf[i++] = (unsigned char) c;

    fclose( f );
#if LOAD_KEY_VERIFY
    if( i != rsa.len )
#else
    if( i != key->len )
#endif
    {
        mbedtls_printf( "\n  ! Invalid RSA signature format\n\n" );
        goto exit;
    }

#if READ_ENCR_FILE_2SIGN
    /*
     * Compute the SHA-256 hash of the input file and
     * verify the signature
     */
    mbedtls_printf( "\n  . Verifying the RSA/SHA-256 signature" );
    fflush( stdout );
    mbedtls_snprintf( filename, sizeof(filename), "%s.txt", in_filename );
    if( ( ret = mbedtls_md_file(
                    mbedtls_md_info_from_type( MBEDTLS_MD_SHA256 ),
                    filename, hash ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! Could not open or read %s\n\n", filename );
        goto exit;
    }
#else
    printf("\n\tWITHOUT Reading data do verify from file\n");
    if( ( ret = mbedtls_md(
                    mbedtls_md_info_from_type( MBEDTLS_MD_SHA256 ),
                    data, strlen(data), hash ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! Could not open or read %s\n\n", filename );
        goto exit;
    }

#endif
    
#if LOAD_KEY_VERIFY
    if( ( ret = mbedtls_rsa_pkcs1_verify( &rsa, NULL, NULL, MBEDTLS_RSA_PUBLIC, MBEDTLS_MD_SHA256,
                                          32, hash, buf ) ) != 0 )
#else
    if( ( ret = mbedtls_rsa_pkcs1_verify( key, NULL, NULL, MBEDTLS_RSA_PUBLIC, MBEDTLS_MD_SHA256,
                                            32, hash, buf ) ) != 0 )
#endif
    {
        mbedtls_printf( " failed\n  ! mbedtls_rsa_pkcs1_verify returned -0x%0x\n\n", (unsigned int) -ret );
        goto exit;
    }

    mbedtls_printf( "\n  . OK (the signature is valid)\n\n" );


    exit_code = 1;

exit:
#if LOAD_KEY_VERIFY
    mbedtls_rsa_free( &rsa );
#endif
    return exit_code;

}

