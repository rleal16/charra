#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
//#include <stdbool.h>
#include "ra2iot_dto.h"
#include "ra2iot_mbedtls.h"
#include "ra2iot_evidence_mgmt.h"


static void get_substr(const char *str, char *substr, size_t start, size_t end){
    strncpy(substr, str + start, end - start);
}

/* This version just fills event log with a string */
int ra2iot_get_log_data(uint8_t *event_log, uint32_t *event_log_len){
    sprintf((char*)event_log, "Event logs data");
    *event_log_len = strlen((char *)event_log)+1;
    return 1; // SUCCESS
}


int ra2iot_load_ref_values(const ra2iot_msg_attestation_request_dto req, ref_values_dto *ref_values){
    char data[256], substr[256];
    int i;
    printf("\t\t\tInside: Reference values\n");
    parsed_claim_selections claim_selection;
    
    if(!ra2iot_parse_claim_selections(req.claim_selections_len, req.claim_selections, &claim_selection)){
        printf("Loading Reference Values: Error parsing claim selections\n");
        return 0;
    }
    print_parsed_claim_selections(claim_selection);
    memset(data, 0, sizeof(char)*256);
    memset(substr, 0, sizeof(char)*256);
    sprintf(data, "l[%u]: \n", claim_selection.claim_selections_len);
    
    for(i = 0; i<(int)claim_selection.claim_selections_len-1; i++){
        strcat(data, "\tClaim ");
        
        get_substr((char*)claim_selection.claim_selections[i].selection, substr, strlen("Claim Selection "), strlen((char*)claim_selection.claim_selections[i].selection));
        strcat(data, substr);
        memset(substr, 0, sizeof(char)*256);
        
        strcat(data, ",\n");
        
    }
    
    strcat(data, "\tClaim ");
    get_substr((char*)claim_selection.claim_selections[i].selection, substr, strlen("Claim Selection "), claim_selection.claim_selections[i].selection_len);
    strcat(data, substr);
    memset(substr, 0, sizeof(char)*256);
    
    //strcat(data, ",\n");

    sprintf((char*)ref_values->ref_values, "%s", data);
    ref_values->ref_values_len = (uint32_t)strlen((char*)ref_values->ref_values);

    
    /* Print Reference Values */
    printf("-> Ref values len: %ld\n", ref_values->ref_values_len);
    printf("-> Ref Values: %s\n", ref_values->ref_values);
    printf("\n-----\n");
    print_parsed_claim_selections(claim_selection);
    printf("\t\t\tEnd of: Reference values\n");
    return 1;
}


bool ra2iot_check_ref_values(const ref_values_dto ref_vals, const ra2iot_attest_dto att_data, attest_res *att_res){
    
    return (
        att_res->valid_against_ref_values = 
            (ref_vals.ref_values_len == att_data.data_len) 
            && (memcmp(ref_vals.ref_values, att_data.data, ref_vals.ref_values_len) == 0)
        );
}

void ra2iot_print_attest_res(attest_res att){

    //printf("Signature: %s\n", PRINT_BOOL(att.valid_signature_size));
    printf("Attestation Signature: %s\n", PRINT_BOOL(att.valid_attest_data_signature));
    printf("Nonce: %s\n", PRINT_BOOL(att.valid_nonce));
    printf("Cmp with Ref. Values: %s\n", PRINT_BOOL(att.valid_against_ref_values));
    printf("Valid Claims: %s\n", PRINT_BOOL(att.valid_claims));
}

int ra2iot_generate_nonce(const uint32_t nonce_len, uint8_t* nonce) {
	
    return ra2iot_mbedtls_gen_rand_bytes(nonce_len, nonce);
}

int verify_nonce(const uint32_t nonce_len, const uint8_t* nonce, const uint32_t ref_nonce_len, const uint8_t* ref_nonce){
    if(nonce_len != ref_nonce_len){
        printf("Nonces have different lengths!!\n");
        return 0;
    }
    if(memcmp(nonce, ref_nonce, ref_nonce_len) != 0){
        printf("Nonces are different!!\n");
        return 0;
    }
    return 1; 
}

int ra2iot_create_attestation_request(ra2iot_msg_attestation_request_dto *req, mbedtls_rsa_context *pub_key){
    req->nonce_len = 20;
    ra2iot_generate_nonce(req->nonce_len, (unsigned char *) &(req->nonce));
    
    req->claim_selections_len = 5;
    for(int i = 0; i<(int)req->claim_selections_len; i++){
        //sprintf(req->claim_selections[i].selection, "Claim Selection %d\0", ((i*275)%120));
        sprintf(req->claim_selections[i].selection, "Claim Selection %d\0", i);   
        req->claim_selections[i].selection_len = strlen((char*)req->claim_selections[i].selection)+1;
    }

    pub_key_dto pk_bytes;
    printf("Writing the signing public key to \"buffer structure\" for marshalling\n");
    int res = ra2iot_load_pub_key_to_buffer("verifier_keys/rsa_pub.txt", &pk_bytes);
    printf("\tWriting to binary %s\n", (res ? "was Successful!" : "Failed!"));


    /* Store the verifier's public key for encryption */
    //req->public_key = {0};
    req->public_key_len = sizeof(pk_bytes);
    memcpy(req->public_key, &pk_bytes, sizeof(pk_bytes));

    /* memcpy(req->claim_selections[1].selection, "Claim Selection 2", strlen("Claim Selection 2"));
    req->claim_selections[1].selection_len = strlen(req->claim_selections[1].selection); */
    req->get_logs = true;

    return 1; //attestation request was created with success!

}

int ra2iot_parse_claim_selections(const uint32_t claim_selection_len, const claim_selection_dto *claim_selections, parsed_claim_selections *parsed_res){
    printf("In ra2iot_parse_claim_selections\n");
    parsed_res->claim_selections_len = claim_selection_len;
    int i;
    for(i=0; i<(int)claim_selection_len; i++){
        parsed_res->claim_selections[i].selection_len = claim_selections[i].selection_len;
        memcpy(parsed_res->claim_selections[i].selection, claim_selections[i].selection, claim_selections[i].selection_len);
        //strcpy(parsed_res->claim_selections[i].selection, claim_selections[i].selection);
    }
    return 1;
}


static int ra2iot_get_evidence_data(const parsed_claim_selections claim_selection, ra2iot_attest_dto *att_data){
    char data[256], substr[256];
    int i;
    
    memset(data, 0, sizeof(data));
    memset(substr, 0, sizeof(substr));
    //memset(substr, 0, sizeof(char)*256);

    sprintf(data, "l[%u]: \n", claim_selection.claim_selections_len);
    
    for(i = 0; i<(int)claim_selection.claim_selections_len-1; i++){
        strcat(data, "\tClaim ");
        
        get_substr(claim_selection.claim_selections[i].selection, substr, strlen("Claim Selection "), strlen(claim_selection.claim_selections[i].selection));
        strcat(data, substr);
        
        memset(substr, 0, sizeof(substr));
        
        strcat(data, ",\n");
    }
    
    strcat(data, "\tClaim ");
    get_substr(claim_selection.claim_selections[i].selection, substr, strlen("Claim Selection "), claim_selection.claim_selections[i].selection_len);
    strcat(data, substr);
    memset(substr, 0, sizeof(char)*256);
    
    //strcat(data, ",\n");
    memset(att_data->data, 0, sizeof(uint8_t)*210);
    sprintf(att_data->data, "%s\0", data);
    att_data->data_len = (uint32_t)strlen((char*)att_data->data);

    printf("Inside the function\n");
    print_attest_data(att_data);
    printf("\n-------######--------\n");

    return 1;
}

int ra2iot_gen_evidence(const ra2iot_msg_attestation_request_dto req, ra2iot_attest_dto *att_data){
    parsed_claim_selections parsed_cs;

    /* Copy the nonce */
    att_data->nonce_len = req.nonce_len;
    memcpy(att_data->nonce, req.nonce, req.nonce_len);
    //ra2iot_parse_claim_selections(req.claim_selections_len, req.claim_selections, &parsed_cs2);
    
    /* Parse (interpret) the claim selections */
    if(ra2iot_parse_claim_selections(req.claim_selections_len, req.claim_selections, &parsed_cs)!=1)
        return 0;
    printf("\n\tAFTER: Parsed Claims selections output\n");
    print_claim_selections(req.claim_selections_len, req.claim_selections);
    printf("\n\t--------------------------------------\n");
    /* Get the evidence data */
    if(ra2iot_get_evidence_data(parsed_cs, att_data)!=1)
        return 0;

    return 1; // Success
}


int appraise_evidence(const ra2iot_msg_attestation_request_dto ref_req, const ra2iot_attest_dto data, attest_res *res){
    ref_values_dto ref_values;
    // Compare the nonces using the one in ref_req as reference
    if(!(res->valid_nonce = (bool) verify_nonce(data.nonce_len, data.nonce, ref_req.nonce_len, ref_req.nonce))){
        printf("Nonces are different!\n");
        return 0;
    }
    
    if(!ra2iot_load_ref_values(ref_req, &ref_values)){
        printf("Error loading reference values\n");
        res->valid_against_ref_values = false;
        return 0;
    }

    /* Print Reference Values */
    printf("-> Ref values len: %ld\n", ref_values.ref_values_len);
    printf("-> Ref Values: %s\n", ref_values.ref_values);


    if(!ra2iot_check_ref_values(ref_values, data, res))
        return 0;

    return 1;
}

bool get_attest_results_overall(const attest_res res){
    return (
        res.valid_against_ref_values &&
        res.valid_attest_data_signature &&
        res.valid_claims &&
        res.valid_nonce
    );
}

/**********************************
*********** IO Functions **********
***********************************/


void print_claim_selections(const uint32_t claim_selection_len, const claim_selection_dto *claim_selections){
    
    printf("-> Claim selection len: %d\n", claim_selection_len);
    printf("Claims selections: \n");
    for(int i = 0; i<(int)claim_selection_len; i++)
        printf("\t[%d]: %s\n", claim_selections[i].selection_len, claim_selections[i].selection);
    fflush(stdout);
}

void print_attestation_request(const ra2iot_msg_attestation_request_dto req){
    
    //printf("Nonce (%d): %s\n", req.nonce_len, req.nonce);
    print_nonce(req.nonce_len, req.nonce);
    print_claim_selections(req.claim_selections_len, req.claim_selections);
    /* printf("Claim selection len: %d\n", req.claim_selections_len);
    printf("Claims selections: \n");
    for(i = 0; i<(int)req.claim_selections_len; i++)
        printf("\t[%d]: %s\n", req.claim_selections[i].selection_len, req.claim_selections[i].selection); */
    printf("Get logs: %s\n", (req.get_logs ? "True" : "False"));
}

int cmp_attestation_request(const ra2iot_msg_attestation_request_dto ref_req, const ra2iot_msg_attestation_request_dto req){
    // Compare the nonces using the one in ref_req as reference
    if(!verify_nonce(req.nonce_len, req.nonce, ref_req.nonce_len, ref_req.nonce))
        return 0;
    
    
    if(ref_req.claim_selections_len != req.claim_selections_len){
        printf("claim_selections_len are different!\n");
        return 0;
    }

    for(int i = 0; i<(int)ref_req.claim_selections_len; i++){

        if(ref_req.claim_selections[i].selection_len != req.claim_selections[i].selection_len){
            printf("claim_selections have different lengths!\n");
            return 0;
        }

        if(memcmp(ref_req.claim_selections[i].selection, req.claim_selections[i].selection, ref_req.claim_selections[i].selection_len) != 0){
            printf("claim_selections are different!\n");
            return 0;
        }
    }
    return 1;
}