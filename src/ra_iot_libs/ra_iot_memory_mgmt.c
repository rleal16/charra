
#include <stdio.h>
#include <stdlib.h>
#include "ra_iot_memory_mgmt.h"

/* Claim_selection_dto memory management */

claim_selection_dto *new_claim_selection(){
    return malloc(sizeof(claim_selection_dto));
}

void free_claim_selection_dto(claim_selection_dto *cs){
    if(cs)
        free(cs);
}

/* ra_iot_msg_attestation_request_dto memory management */

ra_iot_msg_attestation_request_dto *new_attestation_request(){
    return malloc(sizeof(ra_iot_msg_attestation_request_dto));
}

void free_attestation_request(ra_iot_msg_attestation_request_dto *ar){
    if(ar)
        free(ar);
}

/* ra_iot_msg_attestation_response_dto memory management */

ra_iot_msg_attestation_response_dto *new_attestation_response(){
    return malloc(sizeof(ra_iot_msg_attestation_response_dto));
}

void free_attestation_response(ra_iot_msg_attestation_response_dto *ar){
    if(ar)
        free(ar);
}

/* attest_res memory management */

attest_res *new_attestation_results(){
    return malloc(sizeof(attest_res));
}

void free_attestation_results(attest_res *ar){
    if(ar)
        free(ar);
}

/* ref_values_dto memory management */

ref_values_dto *new_ref_values(){
    return malloc(sizeof(ref_values_dto));
}

void free_ref_values(ref_values_dto *rv){
    if(rv)
        free(rv);
}


/* ra_iot_attest_dto memory management */
ra_iot_attest_dto *new_att_data(){
    return malloc(sizeof(ra_iot_attest_dto));
}

void free_att_data(ra_iot_attest_dto *rv){
    if(rv)
        free(rv);
}