
#include "ra2iot_test.h"
#include "ra2iot_dto.h"
#include "ra2iot_crypto.h"
#include <string.h>
#include <assert.h>



int equal_attest_res_lens(ra2iot_msg_attestation_response_dto attest1, ra2iot_msg_attestation_response_dto attest2){
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

int eq_data(uint8_t *dt1, uint8_t *dt2){
    return memcmp(dt1, dt2, sizeof(*dt1)) == 0;
}

int equal_attest_res_data(ra2iot_msg_attestation_response_dto attest1, ra2iot_msg_attestation_response_dto attest2){
    int eq = 1;
    if(eq_data(attest1.attestation_data, attest2.attestation_data) != 1){
        printf("Attestation data are different!\n");
        eq = 0;
    }
    if(eq_data(attest1.signature, attest2.signature) != 1){
        printf("Signatures are different!\n");
        eq = 0;
    }
    if(eq_data(attest1.public_key, attest2.public_key) != 1){
        printf("Public Keys are different!\n");
        eq = 0;
    }
    if(eq_data(attest1.event_log, attest2.event_log) != 1){
        printf("Event Logs are different!\n");
        eq = 0;
    }
    return eq;
}


int attest_res_equal(ra2iot_msg_attestation_response_dto attest1, ra2iot_msg_attestation_response_dto attest2){
    printf("\nComparing attestation results...\n");
    printf("\nChecking Lengths:\n");
    int eq = equal_attest_res_lens(attest1, attest2);
    printf("\n--------\n");
    printf("\nChecking Data:\n");
    eq = eq && equal_attest_res_data(attest1, attest2);
    printf("\n--------\n");
    
    return eq;
}


void attest_res_marshall_unmarshal_test(){
    int res;
    printf("/* ************************************************** */\n");
    printf("/* ******* attest_res_marshall_unmarshal_test ******* */\n");
    printf("/* ************************************************** */\n");
    mbedtls_rsa_context encr_pub_key, encr_priv_key; // (verifier's) keys for encryption/decryption
    mbedtls_rsa_context sig_pub_key, sig_priv_key; // (attester's) keys for signing/signature verifications
    
    mbedtls_rsa_context new_pub_key;
    


    /* Generate encryption and signature keys */
    ra2iot_gen_rsa_key("attester_keys/"); // generate the attester's keys
    ra2iot_load_pub_key("attester_keys/rsa_pub.txt", &sig_pub_key);
    ra2iot_load_priv_key("attester_keys/rsa_priv.txt", &sig_priv_key);

    printf("\nChecking Attester keys\n");
	printf("Key Pair is: %s\n", (mbedtls_rsa_check_pub_priv(&sig_pub_key, &sig_priv_key) == 0 ? "Ok" : "Bad!"));
	printf("Public key is: %s\n", (mbedtls_rsa_check_pubkey(&sig_pub_key) == 0 ? "Ok" : "Bad!"));
	printf("Private key is: %s\n", (mbedtls_rsa_check_privkey(&sig_priv_key) == 0 ? "Ok" : "Bad!"));
    
    printf("key size: %zu\n", sizeof(sig_pub_key));

    ra2iot_gen_rsa_key("verifier_keys/"); // generate the verifiers's keys
    ra2iot_load_pub_key("verifier_keys/rsa_pub.txt", &encr_pub_key);
    ra2iot_load_priv_key("verifier_keys/rsa_priv.txt", &encr_priv_key);

    printf("\nChecking Verifier keys\n");
	printf("Key Pair is: %s\n", (mbedtls_rsa_check_pub_priv(&encr_pub_key, &encr_priv_key) == 0 ? "Ok" : "Bad!"));
	printf("Public key is: %s\n", (mbedtls_rsa_check_pubkey(&encr_pub_key) == 0 ? "Ok" : "Bad!"));
	printf("Private key is: %s\n", (mbedtls_rsa_check_privkey(&encr_priv_key) == 0 ? "Ok" : "Bad!"));

    printf("\nCross Checking keys\n");
    pub_key_dto pk_bytes;
    ra2iot_load_pub_key_to_buffer("attester_keys/rsa_pub.txt", &pk_bytes);


    /* Generate attestation response data */
    printf("\tGenerate attestation data\n");
#if 0
    uint8_t *event_log = malloc(sizeof(uint8_t)*128);
    strcpy(event_log, "This is an event log!");
    //uint8_t *event_log = strdup("This is an event log!");
	size_t event_log_len = strlen(event_log);
    printf("Event log FIRST: %s\n", event_log);
#else
    uint8_t *event_log = malloc(sizeof(uint8_t)*128);
    uint32_t event_log_len;
    ra2iot_get_log_data(event_log, &event_log_len);
#endif

    ra2iot_attest_dto att_data, new_att_data;
    att_data.nonce_len = 20;
    ra2iot_generate_nonce(att_data.nonce_len, &(att_data.nonce));
    
    /* sprintf(att_data.nonce, "O Nonce...");
    att_data.nonce_len = (uint32_t)strlen((char*)att_data.nonce); */
    
    sprintf(att_data.data, "Attestation Data ..");
    att_data.data_len = (uint32_t)strlen((char*)att_data.data);
    att_data.data[att_data.data_len+1]='\0';
    
    printf("\n+-+-+-+-+-+-+-+-+-+-+-+-\n");
    printf("Len %d\n", att_data.data_len);
    print_attest_data(&att_data);
    /* Encrypt attestation data */

    size_t attest_data_buf_len = sizeof(ra2iot_attest_dto);
    uint8_t attest_data_buf[sizeof(ra2iot_attest_dto)];
    
    printf("\n>>>>>>>>>>>>>>>>>>>>>>>\n");
    memset(attest_data_buf, 0, attest_data_buf_len);
    memcpy((void *)attest_data_buf, (void *)&att_data, sizeof(ra2iot_attest_dto));
    ra2iot_attest_dto dt2;
    memcpy(&dt2, attest_data_buf, sizeof(ra2iot_attest_dto));
    print_attest_data(&dt2);
    
    printf("\n\n+++++++++++++++++++++++++++++++++\n");
    printf("Encryption test\n");
    uint8_t encr_attest_data[256];
    uint32_t encr_attest_data_len = 256; // encryption function returns a 256 byte size ecrypted data
    memset(encr_attest_data, 0, sizeof(uint8_t)*256);

    uint8_t decryted_data[256] = {0};
    uint8_t encr2[256] = {0};
    int i;
    // estava a usar isto para encriptar: strlen((char*)attest_data_buf)
    if(ra2iot_encrypt(&encr_pub_key, attest_data_buf, sizeof(ra2iot_attest_dto), encr_attest_data) != 1){
        printf("Error encrypting!!\n");
        
    }else{
        // my drill
        printf("Data was encrypted!\n");
        printf("Decrypting the data... ");

        res = ra2iot_mbedtls_decrypt(&encr_priv_key, encr_attest_data, decryted_data);
        printf("\rInitial Decryption was %s\n", (res ? "Successfull!" : "Wrong!"));
        ra2iot_attest_dto dt;

        memcpy(&dt, decryted_data, sizeof(ra2iot_attest_dto));
        printf("\n++++++++++++++++++++\n");
        print_attest_data(&dt);
        printf("\n--------------------\n");

    }
    
    
    /* Sign the encrypted attestation data */
    int max_size = MBEDTLS_PK_SIGNATURE_MAX_SIZE;
    uint8_t signature[MBEDTLS_PK_SIGNATURE_MAX_SIZE];
    size_t signature_len = MBEDTLS_PK_SIGNATURE_MAX_SIZE;
    //encr_attest_data_len = sizeof(ra2iot_attest_dto);
    printf("ALL RELEVANT SIZES:\n\tsizeof(ra2iot_attest_dto) = %zu\n\tsizeof(encr_attest_data) = %zu\n\tstrlen(encr_attest_data) = %zu\n\tstrlen((char*)encr_attest_data) = %zu\n", 
    sizeof(ra2iot_attest_dto), sizeof(encr_attest_data), strlen(encr_attest_data), strlen((char*)encr_attest_data));
    if(ra2iot_sign(&sig_priv_key, encr_attest_data, encr_attest_data_len, signature) != 1){
        printf("Error signing!!\n");
        goto exit;
    }else{
        printf("Data was signed!!\n\tVerifying Signature:\n");
        res = ra2iot_verify_sig(&sig_pub_key, encr_attest_data, encr_attest_data_len, signature);
        printf("Initial Signature is %s\n", (res ? "Correct!" : "Wrong!"));

    }
    printf("Ainda dentro da função AQuI\n");
    
    
    /* Create attestation response */
    ra2iot_msg_attestation_response_dto attest_start = {
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
    
    //attest_start.attestation_data_len = strlen("Should be encrypted data!");
    
    memcpy(attest_start.signature, signature, signature_len);
    
    assert(attest_start.attestation_data != NULL);
	assert(attest_start.signature != NULL);
	assert(attest_start.public_key != NULL);
	assert(attest_start.event_log != NULL);
	

    printf("Attestation Response Size: %ld\n", sizeof(attest_start));
    /* Marshal attestation response */
    uint32_t res_buf_len = 0;
	uint8_t* res_buf = NULL;
	if (ra2iot_marshal_attestation_response(&attest_start, &res_buf_len, &res_buf) != 1) {
		printf("Error marshaling data.");
		goto exit;
	}
    
    
    /* ------------------------------ */
    /* Unmarshal Attestation response */
    /* ------------------------------ */

    pub_key_dto pk_bytes2;
    mbedtls_rsa_context rsa_test;
    ra2iot_msg_attestation_response_dto attest_unmarshaled;

    ra2iot_unmarshal_attestation_response(res_buf_len, res_buf, &attest_unmarshaled);
    
    /* Compare unmarshalled Attestation Response with the original one */
    int cmp = attest_res_equal(attest_start, attest_unmarshaled);
    printf("The attestation results are %s\n", (cmp ? "EQUAL!" : "DIFFERENT!"));
    
    /* ------------------------------ */
    /* Verifying Unmarsheled data */
    
    // Compare public key
    printf("\n----\n");
    printf("Printing pk bytes\n");
    ra2iot_load_pub_key_to_buffer("attester_keys/rsa_priv.txt", &pk_bytes);
    print_pub_key_dto(pk_bytes);
    
    memcpy(&pk_bytes2, attest_unmarshaled.public_key, sizeof(attest_unmarshaled.public_key));
    ra2iot_load_pub_key_from_buffer(&pk_bytes2, &rsa_test);
    printf("NEW Key Pair is: %s\n", (mbedtls_rsa_check_pub_priv(&rsa_test, &sig_priv_key) == 0 ? "Ok" : "Bad!"));
	printf("NEW Public key is: %s\n", (mbedtls_rsa_check_pubkey(&rsa_test) == 0 ? "Ok" : "Bad!"));
    
    
    // Compare event log
    if(attest_unmarshaled.event_log != NULL){
        size_t event_log2_len = attest_unmarshaled.event_log_len;
        char event_log2[event_log2_len+1];
        memcpy(event_log2, attest_unmarshaled.event_log, attest_unmarshaled.event_log_len);
        //char *event_log2 = (char*)attest_unmarshaled.event_log;
        event_log2[attest_unmarshaled.event_log_len] = '\0';
        
        event_log2[0] = 'H';
        
        //strcat(event_log, " isto!");
        free(event_log);
        printf("-> Event log Orig: %s\n", event_log);
        printf("-> Event log Unmarshalled: %s\n", attest_unmarshaled.event_log);
        printf("-> Event log 2: %s\n", event_log2);
        
    }
    
    // Verify signature of the encrypted attestation data
    printf("Compare signature: %d\n", memcmp(signature, attest_unmarshaled.signature, attest_unmarshaled.signature_len ));

    printf("\n****************************************\n");
    printf("\n**** Unmarshaling with the function ****\n");
    ra2iot_attest_dto attest_dto_unmarshaled;
    int r = ra2iot_unmarshal_attestion_data(&rsa_test, &encr_priv_key, &attest_unmarshaled, &attest_dto_unmarshaled);
    //strcat(att_data.nonce, " nc");
    //att_data.nonce_len += strlen(" nc");
    printf("ra2iot_unmarshal_attestion_data: %s\n", (r ? "Ok!" : "Bad!"));
    print_attest_data(&attest_dto_unmarshaled);
    printf("\n****************************************\n");
    
    printf("\t\n****************************************\n");
    printf("\n**** Unmarshaling without the function ****\n");
    //res = ra2iot_verify_sig(&rsa_test, encr_attest_data, attest_data_buf_len, attest_unmarshaled.signature);
    res = ra2iot_verify_sig(&rsa_test, attest_unmarshaled.attestation_data, attest_unmarshaled.attestation_data_len, attest_unmarshaled.signature);
    printf("=> Signature is %s\n", (res ? "Correct!" : "Wrong!"));
    
    uint8_t decr_res[512];
    res = ra2iot_decrypt(&encr_priv_key, attest_unmarshaled.attestation_data, decr_res);
    printf("Decrypting: %s\n", (res ? "Ok!" : "Bad!"));
    att_data.nonce[0] = 'f';
    printf("\n\t\t Old Nonce \n");
    print_attest_data(&att_data);
    printf("\n*******************\n");
    memcpy(&new_att_data, decr_res, sizeof(ra2iot_attest_dto));
    print_attest_data(&new_att_data);
    printf("\n*****\n");
    printf("Ainda dentro da função\n");


 exit:   

    //free(attest_start.attestation_data);
    //free(att_data.data);
    //free(att_data.nonce);
    //free(event_log);
    mbedtls_rsa_free( &sig_pub_key );
    mbedtls_rsa_free( &sig_priv_key );
	mbedtls_rsa_free( &encr_pub_key );
    mbedtls_rsa_free( &encr_priv_key );
    
}

// uses other version of the load_ref_values function
#if 0
void test_ref_values(){
    printf("Testing reference values loading\n");
	ref_values_dto ref_values;
	ra2iot_load_ref_values(&ref_values);
	printf("Reference values are:\n");
	printf("\tReference values are (%zu): %s\n", ref_values.ref_values_len, (char*)ref_values.ref_values);

    printf("\nGenerating Evidence\n");
    ra2iot_attest_dto att_data;
    sprintf(att_data.nonce, "O Nonce...");
    att_data.nonce_len = (uint32_t)strlen((char*)att_data.nonce);
    sprintf(att_data.data, "Reference values");
    att_data.data_len = (uint32_t)strlen((char*)att_data.data);
    print_attest_data(&att_data);
    printf("\n+-+-+-+-+-+-+-+-+-+-+-+-\n");

    printf("Generating attestation results\n");
    attest_res att_res;
    // initialize the fields no related with this test, to use the whole ra2iot_print_attest_res function.
    att_res.valid_signature_size = att_res.valid_attest_data_signature = att_res.valid_nonce = att_res.valid_event_log = true;
    att_res.valid_against_ref_values = false;
    printf("Checking reference values... The result is: %s\n", PRINT_BOOL(ra2iot_check_ref_values(ref_values, att_data, &att_res)));
    printf("\n\tAttesation Results...\n");
    ra2iot_print_attest_res(att_res);
}
#endif

void test_generate_nonce(){
    uint32_t nonce_len = 20;
	uint8_t nonce[nonce_len];
	
	uint32_t nonce_len2 = 20;
	uint8_t nonce2[nonce_len2];
	
    ra2iot_generate_nonce(nonce_len, nonce);
	printf("Nonce (%d) 0x", (uint32_t)strlen(nonce));
	for(size_t i = 0; i<nonce_len; i++)
		printf("%02x ", nonce[i]);
	printf("\n");
	memcpy(nonce2, nonce, nonce_len);
	//ra2iot_generate_nonce(nonce_len2, nonce2);
	int v_nonce = verify_nonce(nonce_len2, nonce2, nonce_len, nonce);
	printf("Nonce is valid: %d\n", v_nonce);
}


void crypto_test(unsigned char *input, size_t i_len){
    int ret_code;
    unsigned char encrypted[512] = {0}; 
	unsigned char decrypted[512] = {0};
	unsigned char signature[MBEDTLS_MPI_MAX_SIZE] = {0};
	mbedtls_rsa_context rsa_pub;
	mbedtls_rsa_context rsa_priv;
	
	//unsigned char input[100] = "Uma string em C, grande e com algum texto....";
	int val = ra2iot_gen_rsa_key("");
	ret_code = ra2iot_load_pub_key("rsa_pub.txt", &rsa_pub);
	printf("Load public key: %d\n", ret_code);
	ret_code = ra2iot_load_priv_key("rsa_priv.txt", &rsa_priv);
	printf("Load public private key: %d\n", ret_code);
	printf("\n*****************************\n");
	printf("\nChecking keys\n");
	printf("Key Pair is: %s\n", (mbedtls_rsa_check_pub_priv(&rsa_pub, &rsa_priv) == 0 ? "Ok" : "Bad!"));
	printf("Public key is: %s\n", (mbedtls_rsa_check_pubkey(&rsa_pub) == 0 ? "Ok" : "Bad!"));
	printf("Private key is: %s\n", (mbedtls_rsa_check_privkey(&rsa_priv) == 0 ? "Ok" : "Bad!"));
	printf("\n*****************************\n");	

	ret_code = ra2iot_encrypt(&rsa_pub, input, strlen(input), encrypted);
	printf("Encrypt: %d\n", ret_code);
	ret_code = ra2iot_sign(&rsa_priv, encrypted, strlen(encrypted), signature);
	printf("Sign: %d\n", ret_code);
	ret_code = ra2iot_verify_sig(&rsa_pub, encrypted, strlen(encrypted), signature);
	printf("Verification result: %d\n", ret_code);
	printf("Verify sig: %d\n", ret_code);
	ra2iot_decrypt(&rsa_priv, encrypted, decrypted);
	printf("Decrypt sig: %d\n", ret_code);

	printf("[Verifier] The decrypted result is: '%s'\n\n", decrypted);

    printf("Commparing data %d\n", memcmp(decrypted, input, sizeof(input)));


	mbedtls_rsa_free( &rsa_pub );
	mbedtls_rsa_free( &rsa_priv ); 

} 

/* 
void attest_request_marshall_unmarshal_test(){
    printf("Testing attestation request (un) marshalling \n");
    ra2iot_msg_attestation_request_dto req = {0};
    uint32_t req_buf_len = 0;
    uint8_t* req_buf = NULL;

    int res = ra2iot_create_attestation_request(&req);
    res = ra2iot_marshal_attestation_request(&req, &req_buf_len, &req_buf);
    printf("Marshalling seems %s\n", (res ? "OK!" : "Bad!"));
    req.nonce[2] = 'L';
    req.claim_selections[2].selection[2] = '_';
    req.claim_selections[2].selection[3] = '_';
    req.claim_selections[2].selection[4] = '_';
    ra2iot_msg_attestation_request_dto out_req = {0};
    res = ra2iot_unmarshal_attestation_request(req_buf_len, req_buf, &out_req);
    printf("UnMarshalling seems %s\n", (res ? "OK!" : "Bad!"));

    free(req_buf);
    req_buf = NULL;
    req_buf_len = 0;

    /* printf("\n\tMarshalling Again!!\n");
    res = ra2iot_marshal_attestation_request(&out_req, &req_buf_len, &req_buf);
    printf("(%zu) Marshalling seems %s\n", sizeof(uint8_t), (res ? "Successfull!" : "Bad!")); 
    printf("*Original* Attestation Request\n");
    print_attestation_request(req);
    printf("Unmarshalled Attestation Request\n");
    print_attestation_request(out_req);
    printf("\n\n\t *******************************************\n");
    printf("\n\n\t ********** Generate the evidence **********\n\n");
    
    ra2iot_attest_dto att_data;
    ra2iot_gen_evidence(out_req, &att_data);
    print_attest_data(&att_data);
    
}
 */