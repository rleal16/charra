#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
//#include <stdbool.h>
#include "ra_iot_dto.h"
#include "ra_iot_mbedtls.h"
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


int ra_iot_generate_nonce(const uint32_t nonce_len, uint8_t* nonce) {
	
    return ra_iot_mbedtls_gen_rand_bytes(nonce_len, nonce);
}

int verify_nonce(const uint32_t nonce_len, const uint8_t* nonce, const uint32_t ref_nonce_len, const uint8_t* ref_nonce){
    if(nonce_len != ref_nonce_len)
        return 0;
    if(memcmp(nonce, ref_nonce, ref_nonce_len) != 0)
        return 0;
    return 1; 
}


int ra_iot_create_attestation_request(ra_iot_msg_attestation_request_dto *req){
    req->nonce_len = 20;
    ra_iot_generate_nonce(req->nonce_len, &(req->nonce));
    
    req->claim_selections_len = 5;
    for(int i = 0; i<(int)req->claim_selections_len; i++){
        sprintf(req->claim_selections[i].selection, "Claim Selection %d", ((i*275)%120));   
        
        req->claim_selections[i].selection_len = strlen(req->claim_selections[i].selection);
    }
    
    /* memcpy(req->claim_selections[1].selection, "Claim Selection 2", strlen("Claim Selection 2"));
    req->claim_selections[1].selection_len = strlen(req->claim_selections[1].selection); */
    req->get_logs = true;

    return 1; //attestation request was created with success!

}

int ra_iot_parse_claim_selections(const uint32_t claim_selection_len, const claim_selection_dto *claim_selections, parsed_claim_selections *parsed_res){
    printf("Parsing Claim Selections!!\n");
    parsed_res->claim_selections_len = claim_selection_len;
    int i;
    for(i=0; i<claim_selection_len; i++){
        parsed_res->claim_selections[i].selection_len = claim_selections[i].selection_len;
        memcpy(parsed_res->claim_selections[i].selection, claim_selections[i].selection, claim_selections[i].selection_len);
    }
    return 0;
}

void print_claim_selections(const uint32_t claim_selection_len, const claim_selection_dto *claim_selections){
    printf("-> Claim selection len: %d\n", claim_selection_len);
    printf("Claims selections: \n");
    for(int i = 0; i<(int)claim_selection_len; i++)
        printf("\t[%d]: %s\n", claim_selections[i].selection_len, claim_selections[i].selection);
}

void print_attestation_request(const ra_iot_msg_attestation_request_dto req){
    int i;
    //printf("Nonce (%d): %s\n", req.nonce_len, req.nonce);
    print_nonce(req.nonce_len, req.nonce);
    print_claim_selections(req.claim_selections_len, req.claim_selections);
    /* printf("Claim selection len: %d\n", req.claim_selections_len);
    printf("Claims selections: \n");
    for(i = 0; i<(int)req.claim_selections_len; i++)
        printf("\t[%d]: %s\n", req.claim_selections[i].selection_len, req.claim_selections[i].selection); */
    printf("Get logs: %s\n", (req.get_logs ? "True" : "False"));
}