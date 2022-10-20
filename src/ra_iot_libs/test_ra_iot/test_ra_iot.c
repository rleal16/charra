#include "test_ra_iot.h"
#include <string.h>
#include <assert.h>

#define PRINT_RES(x) (x ? "Ok!" : "Failed!")

#define SECTION printf("\n\t\t\t####################################################################################################\n\n\n");

#pragma region debug_functions

int t_equal_attest_res_lens(ra_iot_msg_attestation_response_dto attest1, ra_iot_msg_attestation_response_dto attest2){
    int eq = 1;
    if((int) attest1.attestation_data_len != (int) attest2.attestation_data_len){
        printf("Attestation Data Lengths are different (%d - %d)!\n", (int)attest1.attestation_data_len, (int)attest2.attestation_data_len);
        eq = 0;
    
    }
    if((int) attest1.signature_len != (int) attest2.signature_len){
        printf("Signature Lengths are different (%d - %d)!\n", (int)attest1.signature_len, (int)attest2.signature_len);
        eq = 0;
    }

    if((int)attest1.public_key_len != (int)attest2.public_key_len){
        printf("Public Key Lengths are different (%d - %d)!\n", (int)attest1.public_key_len, (int)attest2.public_key_len);
        eq = 0;
    }

    if((int)attest1.event_log_len != (int)attest2.event_log_len){
        printf("Even log Lengths are different (%d - %d)!\n", (int)attest1.event_log_len, (int)attest2.event_log_len);
        eq = 0;
    }
    return eq;
}

int t_eq_data(uint8_t *dt1, uint8_t *dt2){
    return memcmp(dt1, dt2, sizeof(*dt1)) == 0;
}

int t_equal_attest_res_data(ra_iot_msg_attestation_response_dto attest1, ra_iot_msg_attestation_response_dto attest2){
    int eq = 1;
    if(t_eq_data(attest1.attestation_data, attest2.attestation_data) != 1){
        printf("Attestation data are different!\n");
        eq = 0;
    }
    if(t_eq_data(attest1.signature, attest2.signature) != 1){
        printf("Signatures are different!\n");
        eq = 0;
    }
    if(t_eq_data(attest1.public_key, attest2.public_key) != 1){
        printf("Public Keys are different!\n");
        eq = 0;
    }
    if(t_eq_data(attest1.event_log, attest2.event_log) != 1){
        printf("Event Logs are different!\n");
        eq = 0;
    }
    return eq;
}


int t_attest_res_equal(ra_iot_msg_attestation_response_dto attest1, ra_iot_msg_attestation_response_dto attest2){
    printf("\nComparing attestation results...\n");
    int eq = t_equal_attest_res_lens(attest1, attest2);
    eq = eq && t_equal_attest_res_data(attest1, attest2);
    return eq;
}

#pragma endregion


void ra_iot_pipeline_test(){
    int res;

    printf("/* ************************************************** */\n");
    printf("/* **************** Pipeline Testing **************** */\n");
    printf("/* ************************************************** */\n");

#pragma region keys_setup
    printf("\n********** Initial Set Up **********\n\n");
    mbedtls_rsa_context encr_pub_key, encr_priv_key; // (verifier's) keys for encryption/decryption
    mbedtls_rsa_context sig_pub_key, sig_priv_key; // (attester's) keys for signing/signature verifications
    
    mbedtls_rsa_context new_pub_key;
    
    /* Generate encryption and signature keys */
    printf("********** Generate encryption and signature keys ********** \n");
#if 0
    ra_iot_gen_rsa_key("attester_keys/"); // generate the attester's keys
    ra_iot_load_pub_key("attester_keys/rsa_pub.txt", &sig_pub_key);
    ra_iot_load_priv_key("attester_keys/rsa_priv.txt", &sig_priv_key);
#else
    res = ra_iot_gen_rsa_keypair("attester_keys/", &sig_pub_key, &sig_priv_key);
    printf("\nAttester's key generation: %s\n", PRINT_RES(res));
#endif


    printf("\nChecking Attester keys\n");
    printf("\tKey Pair is: %s\n", PRINT_RES(mbedtls_rsa_check_pub_priv(&sig_pub_key, &sig_priv_key) == 0));
    printf("\tPublic key is: %s\n", PRINT_RES(mbedtls_rsa_check_pubkey(&sig_pub_key) == 0));
    printf("\tPrivate key is: %s\n", PRINT_RES(mbedtls_rsa_check_privkey(&sig_priv_key) == 0));

#if 0
    ra_iot_gen_rsa_key("verifier_keys/"); // generate the verifiers's keys
    ra_iot_load_pub_key("verifier_keys/rsa_pub.txt", &encr_pub_key);
    ra_iot_load_priv_key("verifier_keys/rsa_priv.txt", &encr_priv_key);
#else
    res = ra_iot_gen_rsa_keypair("verifier_keys/", &encr_pub_key, &encr_priv_key);
    printf("\nVerifier's key generation: %s\n", PRINT_RES(res));
#endif
    printf("\nChecking Verifier keys\n");
    printf("\tKey Pair is: %s\n", PRINT_RES(mbedtls_rsa_check_pub_priv(&encr_pub_key, &encr_priv_key) == 0));
    printf("\tPublic key is: %s\n", PRINT_RES(mbedtls_rsa_check_pubkey(&encr_pub_key) == 0));
    printf("\tPrivate key is: %s\n", PRINT_RES(mbedtls_rsa_check_privkey(&encr_priv_key) == 0));

    printf("\nCross Checking keys\n");
    printf("\tKey Pair (encr_pub, sig_priv) is: %s\n", (mbedtls_rsa_check_pub_priv(&encr_pub_key, &sig_priv_key) == 0 ? "Match" : "No Match!"));
    printf("\tKey Pair (sig_pub, encr_priv) is: %s\n", (mbedtls_rsa_check_pub_priv(&sig_pub_key, &encr_priv_key) == 0 ? "Match" : "No Match!"));

#pragma endregion

#pragma region verifier_challenge
    SECTION;
    
    /* ****************************************************************************************************** */
    /* ****************************************************************************************************** */
    /*                                                                                                        */
    /*                                   Verifier Side -- Attestation Request                                 */
    /*                                                                                                        */
    /* ****************************************************************************************************** */
    /* ****************************************************************************************************** */

    /* Generate Attestation Request */
    printf("\t\t********************************************************************\n");
    printf("\t\t********** Generating and \"Sending\" Attestation Request **********\n");
    printf("\t\t********************************************************************\n\n");
    ra_iot_msg_attestation_request_dto req = {0};

    uint32_t req_buf_len = 0;
    uint8_t* req_buf = NULL;

    printf("Creating the Attestation Request\n");
    res = ra_iot_create_attestation_request(&req, &encr_pub_key);
    print_attestation_request(req);
    printf("----------------------------------------\n\n");
    
    
    printf("Marshalling the Attestation Request\n"); // tested later, when unmarshalling
    res = ra_iot_marshal_attestation_request(&req, &req_buf_len, &req_buf);
    printf("Marshalling seems %s\n", (res ? "OK!" : "Bad!"));

    printf("----------------------------------------\n\n");
#pragma endregion

#pragma region Attester
    SECTION;
    /* ****************************************************************************************************** */
    /* ****************************************************************************************************** */
    /*                                                                                                        */
    /*                           Attester Side -- Upon Receiving Attestation Request                          */
    /*                                                                                                        */
    /* ****************************************************************************************************** */
    /* ****************************************************************************************************** */

    printf("\t\t***************************************************\n");
    printf("\t\t*********** Reading Attestation Request ***********\n");
    printf("\t\t***************************************************\n\n");
    
    #pragma region unmarshal_attestation_request
    
    /* Unmarshalling the Attestation Request */
    printf("Unmarshal Attestation Request\n");
    ra_iot_msg_attestation_request_dto out_req = {0};
    res = ra_iot_unmarshal_attestation_request(req_buf_len, req_buf, &out_req);
    printf("\tAtt. Request UnMarshalling seems %s\n", (res ? "OK!" : "Bad!"));


    /* Load signature key */
    pub_key_dto encr_key_bytes;
    mbedtls_rsa_context ver_key;
    printf("Converting the unmarshalled Verifier's public key to a intermediate \"buffer structure\"\n");
    memcpy(&encr_key_bytes, out_req.public_key, sizeof(out_req.public_key));
    printf("Converting Verifiers's public key from bytes to mbedtls_rsa_context for encryption\n");
    res = ra_iot_load_pub_key_from_buffer(&encr_key_bytes, &ver_key);
    printf("Converting bytes to mbedtls_rsa_context: %s\n", (res ? "Ok!" : "Failed!"));

    // verifying the unmarshaled public key
    printf("TESTING Verifier's the public key\n");
	printf("\tNEW Public key is: %s\n", (mbedtls_rsa_check_pubkey(&ver_key) == 0 ? "Ok" : "Wrong!"));

    // verifying if the unmarshaled attester's public key matches the attester's private key
    printf("\tNEW Key Pair is: %s\n", (mbedtls_rsa_check_pub_priv(&ver_key, &encr_priv_key) == 0 ? "Ok" : "Wrong!"));
    printf("----------------------------------------\n");

    /* TEST */
    printf("TESTING Cmp unmarshaled att. request with original one\n");
    res = cmp_attestation_request(req, out_req);
    printf("\tAttestation Requests are %s\n", (res ? "EQUAL!" : "DIFFERENT!"));
    
    //printf("\n\t(Changing original nonce a byte :D)\n");
    //uint8_t aux = req.nonce[0]; // Just for a simple test. Used to restore the nonce's changed value.
    //req.nonce[0] = 'g';
    
    res = verify_nonce(out_req.nonce_len, out_req.nonce, req.nonce_len, req.nonce);
    //printf("\t\tNonces are %s\n", (res ? "EQUAL??! (not expected)" : "DIFFERENT as expected!"));
    printf("\t\tNonces are %s\n", (res ? "EQUAL!!" : "DIFFERENT!"));
    
    //printf("\n\tOld Attestation Request \n");
    //print_attestation_request(req);
    printf("\n\tReceived Attestation Request \n");
    print_attestation_request(out_req);
    //req.nonce[0] = aux;

    printf("----------------------------------------\n\n");    
    
    #pragma endregion
    /* Generate attestation response data */
    
    printf("\n\nGenerate attestation response data...\n");
    
    #pragma region attester_public_key_preparation

    pub_key_dto pk_bytes;
    printf("Writing the signing public key to \"buffer structure\" for marshalling\n");
    res = ra_iot_load_pub_key_to_buffer("attester_keys/rsa_pub.txt", &pk_bytes);
    printf("\tWriting to binary %s\n", (res ? "was Successful!" : "Failed!"));
    
    #pragma endregion

    #pragma region evidence_gen

    printf("\n\n************ Parsing Claim Selections and Generating Evidence ************\n\n");
    ra_iot_attest_dto att_data;
    res = ra_iot_gen_evidence(out_req, &att_data);
    printf("Reading and parsing the evidence: %s\n", (res ? "Ok!!": "Failed!!"));
    print_attest_data(&att_data);
    
    printf("----------------------------------------\n");
    
    #pragma endregion

    #pragma region perp_attesation_data
    /* Encrypt and sign attestation data */
    printf("\n\n********** Preparing Attestation Data for Encryption and Signing **********\n");
    int i;
    size_t attest_data_buf_len = sizeof(ra_iot_attest_dto);
    uint8_t attest_data_buf[sizeof(ra_iot_attest_dto)];

    memset(attest_data_buf, 0, attest_data_buf_len);
    memcpy((void *)attest_data_buf, (void *)&att_data, sizeof(ra_iot_attest_dto));

    printf("----------------------------------------\n");
    uint8_t encr_attest_data[256];
    uint32_t encr_attest_data_len = sizeof(encr_attest_data); // encryption function returns a 256 byte size ecrypted data
    memset(encr_attest_data, 0, sizeof(uint8_t)*256);

    uint8_t decryted_data[256] = {0};
    uint8_t encr2[256] = {0};

    size_t max_size = MBEDTLS_PK_SIGNATURE_MAX_SIZE;
    uint8_t signature[max_size];
    size_t signature_len = max_size; // redundant
    
    printf("\n\n********** Encrypting and Signing attestation data **********\n");

#if 0
    // estava a usar isto para encriptar: strlen((char*)attest_data_buf)

    if(ra_iot_encrypt(&encr_pub_key, attest_data_buf, sizeof(ra_iot_attest_dto), encr_attest_data) != 1){
        printf("Error encrypting!!\n");
        
    }else{
        printf("Key size is %zu\n", encr_pub_key.len);
        printf("Data was encrypted! Size was: %zu\n", sizeof(ra_iot_attest_dto));

    }
    
    printf("----------------------------------------\n");
    
    /* Sign the encrypted attestation data */

    if(ra_iot_sign(&sig_priv_key, encr_attest_data, encr_attest_data_len, signature) != 1){

        printf("Error signing!!\n");
        goto exit;
    }else{
        printf("Data was signed!! Size was: %zu\n", sizeof(encr_attest_data));
        printf("\t2: signature_len = %zu\n\tencr_attest_data = %zu\n", signature_len, sizeof(encr_attest_data));
        
    }
#else
    
    res = ra_iot_encrypt_sign(&ver_key, &sig_priv_key, attest_data_buf, attest_data_buf_len, signature, encr_attest_data);
    printf("\tEncrypting and Signing: %s\n", (res ? "Ok!!": "Failed!!"));
#endif

    printf("----------------------------------------\n");

    printf("\n********** Get the logs **********\n\n");

    uint8_t *event_log = malloc(sizeof(uint8_t)*128);
    uint32_t event_log_len;
    if(out_req.get_logs){
        printf("Getting the logs!\n");
        ra_iot_get_log_data(event_log, &event_log_len);
        printf("-> Event log generated: [%d]: %s\n", event_log_len, event_log);   
    }
    printf("----------------------------------------\n");

    #pragma endregion
    
    #pragma region creating_marshall_attest_response
    printf("\n\n********** Creating the attestation response **********\n");
    
    /* Create attestation response */
    ra_iot_msg_attestation_response_dto attest_start = {
        .attestation_data = {0},
        .attestation_data_len = encr_attest_data_len,
        .signature = {0},
        .signature_len = signature_len,
        .public_key = {0},
        .public_key_len = sizeof(pk_bytes),
        .event_log = event_log,
        .event_log_len = event_log_len
    };

    memcpy(attest_start.public_key, &pk_bytes, sizeof(pk_bytes));

    memcpy(attest_start.attestation_data, encr_attest_data, attest_start.attestation_data_len);
    
    memcpy(attest_start.signature, signature, signature_len);
    
    assert(attest_start.attestation_data != NULL);
    assert(attest_start.signature != NULL);
    assert(attest_start.public_key != NULL);
    assert(attest_start.event_log != NULL);
    
    printf("----------------------------------------\n");

    printf("********** Marshalling the attestation response **********\n");

    /* Marshal attestation response */
    uint32_t res_buf_len = 0;
    uint8_t* res_buf = NULL;
    if (ra_iot_marshal_attestation_response(&attest_start, &res_buf_len, &res_buf) != 1) {
        printf("Error marshaling data.");
        goto exit;
    }else{
        printf("Attestation Response Successfully Marshalled!\n");
    }
    
    printf("----------------------------------------\n");
    #pragma endregion

#pragma endregion

#pragma region Verifier
    
    #pragma region unmarshall_response
    /* ---------------------------------------------------------------------------------------------------------------- */
    /* ---------------------------------------- Unmarshal Attestation response ---------------------------------------- */
    /* ---------------------------------------------------------------------------------------------------------------- */
    
    SECTION;
    printf("\t\t******************************************************\n");
    printf("\t\t*********** Unmarshal Attestation response ***********\n");
    printf("\t\t******************************************************\n\n");
    
    /* unmarshal data */
    ra_iot_msg_attestation_response_dto attest_unmarshaled;
    res = ra_iot_unmarshal_attestation_response(res_buf_len, res_buf, &attest_unmarshaled);
    printf("Unmarshaling Attestation Response: %s\n", PRINT_RES(res));
    printf("----------------------------------------\n");


    printf("********** Verifrying UNmarshalled attestation response **********\n");
    /* Compare unmarshalled Attestation Response with the original one */
    printf("The attestation results are %s\n", (t_attest_res_equal(attest_start, attest_unmarshaled) ? "EQUAL!" : "DIFFERENT!"));
    
    printf("----------------------------------------\n");
    /* ------------------------------ */
    /* Verifying Unmarsheled data */
    
    /* Load signature key */
    pub_key_dto pk_bytes2;
    mbedtls_rsa_context unmarshaled_key;
    printf("Converting the unmarshalled Attester's public key to a intermediate \"buffer structure\"\n");
    memcpy(&pk_bytes2, attest_unmarshaled.public_key, sizeof(attest_unmarshaled.public_key));
    printf("Converting Attester's public key from bytes to mbedtls_rsa_context\n");
    res = ra_iot_load_pub_key_from_buffer(&pk_bytes2, &unmarshaled_key);
    printf("Converting bytes to mbedtls_rsa_context: %s\n", (res ? "Ok!" : "Failed!"));

    // verifying the unmarshaled public key
    printf("TESTING the public key\n");
	printf("\tNEW Public key is: %s\n", (mbedtls_rsa_check_pubkey(&unmarshaled_key) == 0 ? "Ok" : "Wrong!"));

    // verifying if the unmarshaled attester's public key matches the attester's private key
    printf("\tNEW Key Pair is: %s\n", (mbedtls_rsa_check_pub_priv(&unmarshaled_key, &sig_priv_key) == 0 ? "Ok" : "Wrong!"));
    printf("----------------------------------------\n");
    
    /* Verify the event log -- if the results were the expected, not as it should be done in Remote Attestation */
    printf("TESTING (visualy) if the unmarshaled event log corresponds to the original one and if no pointers are shared\n");
    if(attest_unmarshaled.event_log != NULL){

        //size_t event_log2_len = attest_unmarshaled.event_log_len;
        //char event_log2[event_log2_len+1];
        //memcpy(event_log2, attest_unmarshaled.event_log, attest_unmarshaled.event_log_len);
        //char *event_log2 = (char*)attest_unmarshaled.event_log;
        //event_log2[attest_unmarshaled.event_log_len] = '\0';
        
        //event_log2[0] = 'H'; 
        
        strcat(event_log, " +"); // a small chage to ensure that pointers are not being shared
        event_log_len = strlen((char *)event_log);
        printf("-> Original Event log [%d]: %s\n", event_log_len, event_log);
        printf("-> Unmarshalled Event log [%d]: %s\n", attest_unmarshaled.event_log_len, attest_unmarshaled.event_log);
        
        //printf("-> Event log 2: %s\n", event_log2);
        
    }
    printf("----------------------------------------\n");
    // Verify signature of the encrypted attestation data
    printf("Compare original and unmarshaled signatures\n\tThey are: %s\n", (memcmp(signature, attest_unmarshaled.signature, attest_unmarshaled.signature_len) == 0 ? "Equal" : "Different!"));
    printf("----------------------------------------\n");

    #pragma endregion unmarshall_response

    #pragma region unmarshall_attestation_data
    
    printf("\nUnmarshal attestation data:\n\t I.e. verifying the signature and decrypting the data\n");
    ra_iot_attest_dto attest_dto_unmarshaled;

    int unmarshal_res = ra_iot_unmarshal_attestion_data(&unmarshaled_key, &encr_priv_key, &attest_unmarshaled, &attest_dto_unmarshaled);
    printf("ra_iot_unmarshal_attestion_data: %s\n", (unmarshal_res ? "Ok!" : "Bad!"));
    
    printf("\t(Changing old data a byte :D)\n");
    //att_data.nonce[0] = 'f';

    res = verify_nonce(attest_dto_unmarshaled.nonce_len, attest_dto_unmarshaled.nonce, att_data.nonce_len, att_data.nonce);
    printf("\t\tNonces are %s\n", (res ? "EQUAL??! (not expected)" : "DIFFERENT as expected!"));
    
    printf("\n\tOld Attestation Data \n");
    print_attest_data(&att_data);
    
    printf("\n\tUnmashalled Attestation Data \n");
    print_attest_data(&attest_dto_unmarshaled);
    
    printf("----------------------------------------\n");
    
    #pragma endregion unmarshall_attestation_data

    #pragma region appraise_evidence
    printf("\t\t******************************************************\n");
    printf("\t\t**************** Appraising Evidence! ****************\n");
    printf("\t\t******************************************************\n\n");

    attest_res results = {
        .valid_nonce = false,
        .valid_attest_data_signature = (bool) unmarshal_res, // if unmarshal was successful, the signature was valid; otherwise, we (temporarily) consider it invalid (until return codes are not defined)
        .valid_against_ref_values = false,
        .valid_event_log = false
    };

    res = check_claims_integrity(attest_unmarshaled.event_log, attest_unmarshaled.event_log_len, attest_dto_unmarshaled, &results);
    printf("\tClaim Integrity Results: %s\n", (res ? "Ok!" : "Failed!"));

    
    res = appraise_evidence(req, attest_dto_unmarshaled, &results);
    printf("\tEvidence Appraisal Overall Result: %s\n", (res ? "Ok!" : "Failed!"));
    #pragma endregion appraise_evidence

    ra_iot_print_attest_res(results);
    printf("********** DONE!! **********\n");
#pragma #endregion

 exit:   

    //free(attest_start.attestation_data);
    //free(att_data.data);
    //free(att_data.nonce);
    free(event_log);
    mbedtls_rsa_free( &unmarshaled_key);
    mbedtls_rsa_free( &sig_pub_key );
    mbedtls_rsa_free( &sig_priv_key );
	mbedtls_rsa_free( &encr_pub_key );
    mbedtls_rsa_free( &encr_priv_key );
    
}

