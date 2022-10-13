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
    sprintf((char*)event_log, "Event logs data");
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
    for(i=0; i<(int)claim_selection_len; i++){
        parsed_res->claim_selections[i].selection_len = claim_selections[i].selection_len;
        memcpy(parsed_res->claim_selections[i].selection, claim_selections[i].selection, claim_selections[i].selection_len);
    }
    return 1;
}

static void get_substr(const char *str, char *substr, size_t start, size_t end){
    strncpy(substr, str + start, end - start);
}

static int ra_iot_get_evidence_data(const parsed_claim_selections claim_selection, ra_iot_attest_dto *att_data){
    char data[256], substr[256];
    int len_aux;
    int i;
    memset(substr, 0, sizeof(char)*256);
    sprintf(data, "l[%u]: \n", claim_selection.claim_selections_len);
    
    for(i = 0; i<(int)claim_selection.claim_selections_len-1; i++){
        strcat(data, "\tClaim ");
        
        get_substr(claim_selection.claim_selections[i].selection, substr, strlen("Claim Selection "), strlen(claim_selection.claim_selections[i].selection));
        strcat(data, substr);
        memset(substr, 0, sizeof(char)*256);
        
        strcat(data, ",\n");
    }
    
    strcat(data, "\tClaim ");
    get_substr(claim_selection.claim_selections[i].selection, substr, strlen("Claim Selection "), claim_selection.claim_selections[i].selection_len);
    strcat(data, substr);
    memset(substr, 0, sizeof(char)*256);
    
    //strcat(data, ",\n");
    

    sprintf(att_data->data, "%s", data);
    att_data->data_len = (uint32_t)strlen((char*)att_data->data);

    return 1;
}


int ra_iot_gen_evidence(const ra_iot_msg_attestation_request_dto req, ra_iot_attest_dto *att_data){
    parsed_claim_selections parsed_cs;
    int ret_code;
    /* Copy the nonce */
    att_data->nonce_len = req.nonce_len;
    memcpy(att_data->nonce, req.nonce, att_data->nonce_len);

    /* Parse (interpret) the claim selections */
    if(ra_iot_parse_claim_selections(req.claim_selections_len, req.claim_selections, &parsed_cs)!=1)
        return 0;

    /* Get the evidence data */
    if(ra_iot_get_evidence_data(parsed_cs, att_data)!=1)
        return 0;

    return 1; // Success
}


/**********************************
*********** IO Functions **********
***********************************/


void print_claim_selections(const uint32_t claim_selection_len, const claim_selection_dto *claim_selections){
    
    printf("-> Claim selection len: %d\n", claim_selection_len);
    printf("Claims selections: \n");
    for(int i = 0; i<(int)claim_selection_len; i++)
        printf("\t[%d]: %s\n", claim_selections[i].selection_len, claim_selections[i].selection);
}
