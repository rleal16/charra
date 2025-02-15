
#include "ra2iot_dto.h"
#include <string.h>
#include <stdio.h>

void print_nonce(const uint32_t nonce_len, const uint8_t *nonce){
    printf("-> Nonce (%d): 0x", nonce_len);
	for(size_t i = 0; i<(size_t)nonce_len; i++)
		printf("%02x ", nonce[i]);
	printf("\n");
}


void print_attest_data(const ra2iot_attest_dto *att_data){
    print_nonce(att_data->nonce_len, att_data->nonce);
    printf("Data (%d): %s\n", att_data->data_len, att_data->data);
    fflush(stdout);
}

void print_attest_response(ra2iot_msg_attestation_response_dto attest_res){
    printf("Attestation Data (%d): %s\n", attest_res.attestation_data_len, attest_res.attestation_data);
    printf("Signature (%d): %s\n", attest_res.attestation_data_len, attest_res.attestation_data);
    printf("Pub. Key (%d): %s\n", attest_res.public_key_len, attest_res.public_key);
    printf("Event Log (%d): %s\n", attest_res.event_log_len, attest_res.event_log);
}

/* 
    Print the parsed claim selections
    Note: For the current version, this function is equal to print_claim_selections, 
    since there is really no parsing involved.
 */
void print_parsed_claim_selections(const parsed_claim_selections cs){
    printf("-> Claim selection len: %d\n", cs.claim_selections_len);
    printf("Claims selections: \n");
    for(int i = 0; i<(int)cs.claim_selections_len; i++)
        printf("\t[%d]: %s\n", cs.claim_selections[i].selection_len, cs.claim_selections[i].selection);
}


// Test function to compare two instances of ra2iot_msg_attestation_response_dto
static int cmp_attestation_attr(uint8_t *attr1, uint8_t *attr2, uint32_t attr1_len, uint32_t attr2_len){
    return (attr1_len == attr2_len) && memcmp(attr1, attr2, attr1_len) == 0;
}

int attest_resp_cmp(ra2iot_msg_attestation_response_dto attest_res1, ra2iot_msg_attestation_response_dto attest_res2){
    return cmp_attestation_attr(attest_res1.attestation_data, attest_res2.attestation_data, attest_res1.attestation_data_len, attest_res2.attestation_data_len) 
        && cmp_attestation_attr(attest_res1.signature, attest_res2.signature, attest_res1.signature_len, attest_res2.signature_len) 
        && cmp_attestation_attr(attest_res1.public_key, attest_res2.public_key, attest_res1.public_key_len, attest_res2.public_key_len)
        && cmp_attestation_attr(attest_res1.event_log, attest_res2.event_log, attest_res1.event_log_len, attest_res2.event_log_len);
}