#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
//#include <stdbool.h>
#include "ra_iot_dto.h"
#include "ra_iot_evidence_mgmt.h"

/* This version just fills event log with a string */
int ra_iot_get_log_data(uint8_t *event_log, uint32_t *event_log_len){
    sprintf(event_log, "Event logs data");
    *event_log_len = strlen((char *)event_log);
    return 1; // SUCCESS
}


int ra_iot_load_ref_values(ref_values_dto *ref_values){
    char ref_vals[512] = "Reference values";
    ref_values->ref_values_len = strlen(ref_vals);
    memcpy(ref_values->ref_values, ref_vals, strlen(ref_vals));
    return 1; //success 
}

bool ra_iot_check_ref_values(const ref_values_dto ref_vals, const ra_iot_attest_dto att_data, attest_res *att_res){
    
    return (
        att_res->valid_against_ref_values = 
            (ref_vals.ref_values_len == att_data.data_len) 
            && (memcmp(ref_vals.ref_values, att_data.data, ref_vals.ref_values_len) == 0)
        );
}

void ra_iot_print_attest_res(attest_res att){

    printf("Signature: %s\n", PRINT_BOOL(att.valid_signature_size));
    printf("Attestation Signature: %s\n", PRINT_BOOL(att.valid_attest_data_signature));
    printf("Nonce: %s\n", PRINT_BOOL(att.valid_nonce));
    printf("Cmp with Ref. Values: %s\n", PRINT_BOOL(att.valid_against_ref_values));
    printf("Event Log: %s\n", PRINT_BOOL(att.valid_event_log));
}

#if 0
int ra_iot_generate_nonce(const uint32_t nonce_len, uint8_t* nonce) {
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
    mbedtls_ctr_drbg_set_prediction_resistance( &ctr_drbg, MBEDTLS_CTR_DRBG_PR_OFF );

	ret = mbedtls_ctr_drbg_random( &ctr_drbg, nonce, (size_t) nonce_len );
    if( ret != 0 )
    {
        mbedtls_printf("failed!\n");
        goto cleanup;
    }

cleanup:
    mbedtls_printf("\n");

    fclose( f );
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );

    return 1;
}

#endif