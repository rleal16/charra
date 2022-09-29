
#include "ra_iot_dto.h"
#include <string.h>
#include <stdio.h>

void print_attest_data(ra_iot_attest_dto att_data){
    printf("Nonce (%d): %s\n", att_data.nonce_len, att_data.nonce);
    printf("Data (%d): %s\n", att_data.data_len, att_data.data);
}

void print_attest_response(ra_iot_msg_attestation_response_dto attest_res){
    printf("Attestation Data (%d): %s\n", attest_res.attestation_data_len, attest_res.attestation_data);
    printf("Signature (%d): %s\n", attest_res.attestation_data_len, attest_res.attestation_data);
    printf("Pub. Key (%d): %s\n", attest_res.public_key_len, attest_res.public_key);
    printf("Event Log (%d): %s\n", attest_res.event_log_len, attest_res.event_log);
}


// Test function to compare two instances of ra_iot_msg_attestation_response_dto
static int cmp_attestation_attr(uint8_t *attr1, uint8_t *attr2, uint32_t attr1_len, uint32_t attr2_len){
    return (attr1_len == attr2_len) && memcmp(attr1, attr2, attr1_len) == 0;
}

int attest_resp_cmp(ra_iot_msg_attestation_response_dto attest_res1, ra_iot_msg_attestation_response_dto attest_res2){
    return cmp_attestation_attr(attest_res1.attestation_data, attest_res2.attestation_data, attest_res1.attestation_data_len, attest_res2.attestation_data_len) 
        && cmp_attestation_attr(attest_res1.signature, attest_res2.signature, attest_res1.signature_len, attest_res2.signature_len) 
        && cmp_attestation_attr(attest_res1.public_key, attest_res2.public_key, attest_res1.public_key_len, attest_res2.public_key_len)
        && cmp_attestation_attr(attest_res1.event_log, attest_res2.event_log, attest_res1.event_log_len, attest_res2.event_log_len);
}