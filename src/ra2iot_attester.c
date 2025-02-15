/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2019, Fraunhofer Institute for Secure Information Technology SIT.
 * All rights reserved.
 ****************************************************************************/

/**
 * @file attester.c
 * @note This code is based on the corresponding code in https://github.com/Fraunhofer-SIT/charra
 * @author Michael Eckel (michael.eckel@sit.fraunhofer.de) (CHARRA Author)
 * @brief
 * @version 0.1
 * @date 2019-09-19
 *
 * @copyright Copyright 2019, Fraunhofer Institute for Secure Information
 * Technology SIT. All rights reserved.
 *
 * @license BSD 3-Clause "New" or "Revised" License (SPDX-License-Identifier:
 * BSD-3-Clause).
 */


#include <arpa/inet.h>
#include <coap2/coap.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tinydtls/session.h>


#include "common/ra2iot_log.h"
#include "common/ra2iot_macro.h"


#include "util/cbor_util.h"
#include "util/cli_util.h"
#include "util/coap_util.h"
#include "util/io_util.h"

// ADDED to comunicate with hardened encryption
#include <sys/socket.h>
#include <unistd.h>


#define PRINT_RES(x) (x ? "Ok!" : "Failed!")

/* ---------- Arcadian IoT Remote Attestation Libraries */

#include "ra2iot_libs/ra2iot_dto.h"
#include "ra2iot_libs/ra2iot_memory_mgmt.h"
#include "ra2iot_libs/ra2iot_crypto.h"
#include "ra2iot_libs/ra2iot_evidence_mgmt.h"
#include "ra2iot_libs/ra2iot_marshaling.h"
#include "ra2iot_libs/ra2iot_security.h"
#include "ra2iot_libs/test_ra2iot/test_ra2iot.h"


#define RA2IOT_UNUSED __attribute__((unused))

/* --- config ------------------------------------------------------------- */

/* quit signal */
static bool quit = false;

/* logging */
#define LOG_NAME "ra2iot_attester"
coap_log_t coap_log_level = LOG_INFO;
// #define LOG_LEVEL_CBOR LOG_DEBUG
ra2iot_log_t ra2iot_log_level = RA2IOT_LOG_INFO;

/* config */
static const char LISTEN_ADDRESS[] = "0.0.0.0";
static unsigned int port = COAP_DEFAULT_PORT; // default port 5683
#define CBOR_ENCODER_BUFFER_LENGTH 20480	  // 20 KiB should be sufficient


bool use_dtls_psk = false;
char* dtls_psk_key = "Charra DTLS Key";
char* dtls_psk_hint = "Charra Attester";

// for DTLS-RPK
bool use_dtls_rpk = false;
char* dtls_rpk_private_key_path = "keys/attester.der";
char* dtls_rpk_public_key_path = "keys/attester.pub.der";
char* dtls_rpk_peer_public_key_path = "keys/verifier.pub.der";
bool dtls_rpk_verify_peer_public_key = true;

// For socket comunication with HE
int server_sock = 0, clnt_fd;
struct sockaddr_in server_addr;
char host_addr[16] = "172.24.0.3";
unsigned int host_port = 1234;

/**
 * @brief SIGINT handler: set quit to 1 for graceful termination.
 *
 * @param signum the signal number.
 */
static void handle_sigint(int signum);

static void release_data(
	struct coap_session_t* session RA2IOT_UNUSED, void* app_ptr);

static void coap_attest_handler(struct coap_context_t* ctx,
	struct coap_resource_t* resource, struct coap_session_t* session,
	struct coap_pdu_t* in_pdu, struct coap_binary_t* token,
	struct coap_string_t* query, struct coap_pdu_t* out_pdu);


/* --- Static Variables --------------- */
mbedtls_rsa_context pub_key, priv_key; // key-pair for signing
int attestation_count;
/* --- main --------------------------------------------------------------- */

int main(int argc, char** argv) {
	int result = EXIT_FAILURE;
	int res;
	attestation_count = 0;
	/* handle SIGINT */
	signal(SIGINT, handle_sigint);

	printf("\n\n\t\t\tATTESTER RA2IOT!!\n\n\n");

	/* check environment variables */
	ra2iot_log_level_from_str(
		(const char*)getenv("LOG_LEVEL_RA2IOT"), &ra2iot_log_level);
	ra2iot_coap_log_level_from_str(
		(const char*)getenv("LOG_LEVEL_COAP"), &coap_log_level);

	/* initialize structures to pass to the CLI parser */
	cli_config cli_config = {
		.caller = ATTESTER,
		.common_config =
			{
				.ra2iot_log_level = &ra2iot_log_level,
				.coap_log_level = &coap_log_level,
				.port = &port,
				.use_dtls_psk = &use_dtls_psk,
				.dtls_psk_key = &dtls_psk_key,
				.use_dtls_rpk = &use_dtls_rpk,
				.dtls_rpk_private_key_path = &dtls_rpk_private_key_path,
				.dtls_rpk_public_key_path = &dtls_rpk_public_key_path,
				.dtls_rpk_peer_public_key_path = &dtls_rpk_peer_public_key_path,
				.dtls_rpk_verify_peer_public_key =
					&dtls_rpk_verify_peer_public_key,
			},
		.attester_config =
			{
				.dtls_psk_hint = &dtls_psk_hint,
			},
	};

	/* parse CLI arguments */
	if ((result = parse_command_line_arguments(argc, argv, &cli_config)) != 0) {
		// 1 means help message is displayed, -1 means error
		return (result == 1) ? EXIT_SUCCESS : EXIT_FAILURE;
	}

	/* set RA2IOT and libcoap log levels */
	ra2iot_log_set_level(ra2iot_log_level);
	coap_set_log_level(coap_log_level);

	ra2iot_log_debug("[" LOG_NAME "] Attester Configuration:");
	ra2iot_log_debug("[" LOG_NAME "]     Used local port: %d", port);
	ra2iot_log_debug("[" LOG_NAME "]     DTLS-PSK enabled: %s",
		(use_dtls_psk == true) ? "true" : "false");
	if (use_dtls_psk) {
		ra2iot_log_debug("[" LOG_NAME "]         Pre-shared key: '%s'",
			dtls_psk_key);
		ra2iot_log_debug(
			"[" LOG_NAME "]         Hint: '%s'", dtls_psk_hint);
	}
	ra2iot_log_debug("[" LOG_NAME "]     DTLS-RPK enabled: %s",
		(use_dtls_rpk == true) ? "true" : "false");
	if (use_dtls_rpk) {
		ra2iot_log_debug("[" LOG_NAME
						 "]         Private key path: '%s'",
			dtls_rpk_private_key_path);
		ra2iot_log_debug("[" LOG_NAME
						 "]         Public key path: '%s'",
			dtls_rpk_public_key_path);
		ra2iot_log_debug("[" LOG_NAME
						 "]         Peers' public key path: '%s'",
			dtls_rpk_peer_public_key_path);
	}

	/* set varaibles here such that they are valid in case of an 'goto error' */
	coap_context_t* coap_context = NULL;
	coap_endpoint_t* coap_endpoint = NULL;

	if (use_dtls_psk && use_dtls_rpk) {
		ra2iot_log_error(
			"[" LOG_NAME "] Configuration enables both DTSL with PSK "
			"and DTSL with PKI. Aborting!");
		goto error;
	}

	if (use_dtls_psk || use_dtls_rpk) {
		// print TLS version when in debug mode
		coap_show_tls_version(LOG_DEBUG);
	}

	if ((use_dtls_psk || use_dtls_psk) && !coap_dtls_is_supported()) {
		ra2iot_log_error("[" LOG_NAME "] CoAP does not support DTLS but the "
						 "configuration enables DTLS. Aborting!");
		goto error;
	}

	ra2iot_log_info("[" LOG_NAME "] Initializing CoAP in block-wise mode.");
	if ((coap_context = ra2iot_coap_new_context(true)) == NULL) {
		ra2iot_log_error("[" LOG_NAME "] Cannot create CoAP context.");
		goto error;
	}

	if (use_dtls_psk) {
		ra2iot_log_info(
			"[" LOG_NAME "] Creating CoAP server endpoint using DTLS-PSK.");
		if (!coap_context_set_psk(coap_context, dtls_psk_hint,
				(uint8_t*)dtls_psk_key, strlen(dtls_psk_key))) {
			ra2iot_log_error(
				"[" LOG_NAME "] Error while configuring CoAP to use DTLS-PSK.");
			goto error;
		}

		if ((coap_endpoint = ra2iot_coap_new_endpoint(coap_context,
				 LISTEN_ADDRESS, port, COAP_PROTO_DTLS)) == NULL) {
			ra2iot_log_error(
				"[" LOG_NAME
				"] Cannot create CoAP server endpoint based on DTLS-PSK.\n");
			goto error;
		}
	} else if (use_dtls_rpk) {
		ra2iot_log_info(
			"[" LOG_NAME "] Creating CoAP server endpoint using DTLS-RPK.");
		coap_dtls_pki_t dtls_pki = {0};

		RA2IOT_RC rc = ra2iot_coap_setup_dtls_pki_for_rpk(&dtls_pki,
			dtls_rpk_private_key_path, dtls_rpk_public_key_path,
			dtls_rpk_peer_public_key_path, dtls_rpk_verify_peer_public_key);
		if (rc != RA2IOT_RC_SUCCESS) {
			ra2iot_log_error(
				"[" LOG_NAME "] Error while setting up DTLS-RPK structure.");
			goto error;
		}

		if (!coap_context_set_pki(coap_context, &dtls_pki)) {
			ra2iot_log_error(
				"[" LOG_NAME "] Error while configuring CoAP to use DTLS-RPK.");
			goto error;
		}

		if ((coap_endpoint = ra2iot_coap_new_endpoint(coap_context,
				 LISTEN_ADDRESS, port, COAP_PROTO_DTLS)) == NULL) {
			ra2iot_log_error(
				"[" LOG_NAME
				"] Cannot create CoAP server endpoint based on DTLS-RPK.\n");
			goto error;
		}
	} else {
		ra2iot_log_info(
			"[" LOG_NAME "] Creating CoAP server endpoint using UDP.");
		if ((coap_endpoint = ra2iot_coap_new_endpoint(
				 coap_context, LISTEN_ADDRESS, port, COAP_PROTO_UDP)) == NULL) {
			ra2iot_log_error(
				"[" LOG_NAME
				"] Cannot create CoAP server endpoint based on UDP.\n");
			goto error;
		}
	}



	/* ********************************************** */
	/* Preparing comunication with HE through sockets */
	/* ********************************************** */
	/* ra2iot_log_info("[" LOG_NAME "] Comunicating with HE Server...");
    if ((server_sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("\n Socket creation error \n");
        return -1;
    }
	
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(1245);
 
    // Convert IPv4 and IPv6 addresses from text to binary
    // form
    if (inet_pton(AF_INET, "172.24.0.5", &server_addr.sin_addr) <= 0) {
        printf("\nInvalid address/ Address not supported \n");
        return -1;
    }
 
    if ((clnt_fd = connect(server_sock, (struct sockaddr*)&server_addr, sizeof(server_addr))) < 0) {
        printf("\nConnection Failed \n");
        return -1;
    } */


	/* Create Signing key pair */
	mbedtls_rsa_init( &pub_key, MBEDTLS_RSA_PKCS_V15, 0 );
	mbedtls_rsa_init( &priv_key, MBEDTLS_RSA_PKCS_V15, 0 );

	ra2iot_log_info("[" LOG_NAME "] Generating Attester's key");
	res = ra2iot_gen_rsa_keypair("attester_keys/", &pub_key, &priv_key);
    ra2iot_log_info("[" LOG_NAME "] \tAttester's key generation: %s", PRINT_RES(res));
	ra2iot_log_info("[" LOG_NAME "] Checking Attester keys");
    ra2iot_log_info("[" LOG_NAME "] \tKey Pair is: %s", PRINT_RES(mbedtls_rsa_check_pub_priv(&pub_key, &priv_key) == 0));
    ra2iot_log_info("[" LOG_NAME "] \tPublic key is: %s", PRINT_RES(mbedtls_rsa_check_pubkey(&pub_key) == 0));
    ra2iot_log_info("[" LOG_NAME "] \tPrivate key is: %s", PRINT_RES(mbedtls_rsa_check_privkey(&priv_key) == 0));



	/* register CoAP resource and resource handler */
	ra2iot_log_info("[" LOG_NAME "] Registering CoAP resources.");
	ra2iot_coap_add_resource(
		coap_context, COAP_REQUEST_FETCH, "attest", coap_attest_handler);

	/* enter main loop */
	ra2iot_log_debug("[" LOG_NAME "] Entering main loop.");
	while (!quit) {
		/* process CoAP I/O */
		if (coap_io_process(coap_context, COAP_IO_WAIT) == -1) {
			ra2iot_log_error(
				"[" LOG_NAME "] Error during CoAP I/O processing.");
			goto error;
		}
		
	}

	result = EXIT_SUCCESS;
	goto finish;

error:
	result = EXIT_FAILURE;

finish:
	/* free CoAP memory */
	ra2iot_free_and_null_ex(coap_endpoint, coap_free_endpoint);
	ra2iot_free_and_null_ex(coap_context, coap_free_context);
	coap_cleanup();
	mbedtls_rsa_free( &pub_key );
    mbedtls_rsa_free( &priv_key );
	close(clnt_fd);

	return result;
}

/* --- function definitions ----------------------------------------------- */

static void handle_sigint(int signum RA2IOT_UNUSED) { quit = true; }

static void release_data(
	struct coap_session_t* session RA2IOT_UNUSED, void* app_ptr) {
	ra2iot_free_and_null(app_ptr);
}

static void coap_attest_handler(struct coap_context_t* ctx RA2IOT_UNUSED,
	struct coap_resource_t* resource, struct coap_session_t* session,
	struct coap_pdu_t* in, struct coap_binary_t* token,
	struct coap_string_t* query, struct coap_pdu_t* out) {

	char msg[256];
	sprintf(msg, "Do attester... fiz %d attestações\n", attestation_count+1);

	// Um teste absurdo
	ra2iot_log_info("[" LOG_NAME "] Comunicating with HE Server...");
	
	//request_he("172.24.0.3", 1245, msg);
	//request_he("172.24.0.3", 1245, "\te mais isto...");

/*     if ((server_sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("\n Socket creation error \n");
        return -1;
    }
	
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(1245);
 
    // Convert IPv4 and IPv6 addresses from text to binary
    // form
    if (inet_pton(AF_INET, "172.24.0.5", &server_addr.sin_addr) <= 0) {
        printf("\nInvalid address/ Address not supported \n");
        return -1;
    }
 
    if ((clnt_fd = connect(server_sock, (struct sockaddr*)&server_addr, sizeof(server_addr))) < 0) {
        printf("\nConnection Failed \n");
        return -1;
    }
 */

	/* char buffer[1024] = { 0 };
	
	uint8_t msg[128] = "sent from the attester...";
    send(server_sock, msg, strlen(msg), 0);
	//send(sock, msg2, strlen(msg2), 0);
    ra2iot_log_info("[" LOG_NAME "] Messange sent to Hardened Encrpytion\n");
    int valread = read(server_sock, buffer, 1024);
    printf("%s\n", buffer);
	fflush(stdout); */


	int coap_r = 0;
	int res;
		
	printf("\n\n\n");
	/* --- receive incoming data --- */
	ra2iot_log_info("[" LOG_NAME "] ********** ********** ********** **********");
	ra2iot_log_info(
		"[" LOG_NAME "] Resource '%s': Received message.", "attest");
	coap_show_pdu(LOG_DEBUG, in);

	/* get data */
	size_t data_len = 0;
	const uint8_t* data = NULL;
	size_t data_offset = 0;
	size_t data_total_len = 0;
	if ((coap_r = coap_get_data_large(
			 in, &data_len, &data, &data_offset, &data_total_len)) == 0) {
		ra2iot_log_error("[" LOG_NAME "] Could not get CoAP PDU data.");
		goto error;
	} else {
		ra2iot_log_info(
			"[" LOG_NAME "] Received data of length %zu.", data_len);
		ra2iot_log_info("[" LOG_NAME "] Received data of total length %zu.",
			data_total_len);
	}

	/* unmarshal data */
	ra2iot_log_info("[" LOG_NAME "] Parsing received CBOR data.");
	ra2iot_msg_attestation_request_dto request = {0};
	if (ra2iot_unmarshal_attestation_request(data_len, data, &request) != 1) {
		ra2iot_log_error("[" LOG_NAME "] Could not parse CBOR data.");
		goto error;
	}

	/* --- Evidence --- */

	ra2iot_log_info("[" LOG_NAME "] Preparing attestation data (evidence).");

	/* nonce */
	ra2iot_log_info("Received nonce of length %d:", request.nonce_len);
	ra2iot_print_hex(RA2IOT_LOG_INFO, request.nonce_len, request.nonce,
		"                                   0x", "\n", false);


	/* Load Verifier's key for encryption */
	pub_key_dto verifier_key_bytes = {0};
    mbedtls_rsa_context verifier_key;
	mbedtls_rsa_init( &verifier_key, MBEDTLS_RSA_PKCS_V15, 0 );
    ra2iot_log_info("[" LOG_NAME "] Converting the unmarshalled Verifier's public key to a intermediate \"buffer structure\"");
    memcpy(&verifier_key_bytes, request.public_key, sizeof(request.public_key));
    ra2iot_log_info("[" LOG_NAME "] Converting Verifiers's public key from bytes to mbedtls_rsa_context for encryption");
    res = ra2iot_load_pub_key_from_buffer(&verifier_key_bytes, &verifier_key);
    ra2iot_log_info("[" LOG_NAME "] \tConverting bytes to mbedtls_rsa_context: %s", (res ? "Ok!" : "Failed!"));

	
	/* Prepare (encryption) public key for the attestation response */
	pub_key_dto pk_bytes;
    ra2iot_log_info("[" LOG_NAME "] Writing the signing public key to \"buffer structure\" for marshalling");
    res = ra2iot_load_pub_key_to_buffer("attester_keys/rsa_pub.txt", &pk_bytes);
    ra2iot_log_info("[" LOG_NAME "] \tWriting to binary %s\n", (res ? "was Successful!" : "Failed!"));
	

	/* Copy received nonce and get evidence */
	ra2iot_log_info("[" LOG_NAME "] \n\n************ Parsing Claim Selections and Generating Evidence ************\n\n");
    ra2iot_attest_dto attest_data;
    res = ra2iot_gen_evidence(request, &attest_data);
    ra2iot_log_info("[" LOG_NAME "] Reading and parsing the evidence: %s\n", (res ? "Ok!!": "Failed!!"));

	printf("\n\n Attestation DATA!!\n");
	print_attest_data(&attest_data);
	printf("\n-------------------\n");

	/* --- send response data --- */
	/* Preparing attestation data for encryption and signing */
	ra2iot_log_info("[" LOG_NAME "] \n********** Preparing Attestation Data for Encryption and Signing **********");
    
    size_t attest_data_buf_len = sizeof(ra2iot_attest_dto);
    uint8_t attest_data_buf[sizeof(ra2iot_attest_dto)];
    memset(attest_data_buf, 0, attest_data_buf_len);
	
    memcpy((void *)attest_data_buf, (void *)&attest_data, sizeof(ra2iot_attest_dto));

    uint8_t encr_attest_data[256] = {0};
    uint32_t encr_attest_data_len = sizeof(encr_attest_data); // encryption function returns a 256 byte size ecrypted data
    memset(encr_attest_data, 0, sizeof(uint8_t)*256);

    //size_t max_size = 2048;
    uint8_t signature[MBEDTLS_PK_SIGNATURE_MAX_SIZE] = {0};
    size_t signature_len = MBEDTLS_PK_SIGNATURE_MAX_SIZE; // redundant
	ra2iot_log_info("[" LOG_NAME "] \tVerifier key is: %s", PRINT_RES(mbedtls_rsa_check_pubkey(&verifier_key) == 0));
	ra2iot_log_info("[" LOG_NAME "] \tPrivate key is: %s", PRINT_RES(mbedtls_rsa_check_privkey(&priv_key) == 0));
	res = ra2iot_encrypt_sign(&verifier_key, &priv_key, attest_data_buf, attest_data_buf_len, signature, encr_attest_data);
    ra2iot_log_info("[" LOG_NAME "] \tEncrypting and Signing: %s", (res ? "Ok!!": "Failed!!"));


	/* Read the event logs, if requested */
	uint8_t *event_log = malloc(sizeof(uint8_t)*128);
    uint32_t event_log_len;
    if(request.get_logs){
        ra2iot_log_info("[" LOG_NAME "] Getting the logs!");
        ra2iot_get_log_data(event_log, &event_log_len);
        ra2iot_log_info("[" LOG_NAME "] \t -> Event log generated: [%d]: %s", event_log_len, event_log);   
    }


	/* prepare response */
	ra2iot_log_info("[" LOG_NAME "] Preparing response.");

	/* Create attestation response */
    ra2iot_msg_attestation_response_dto response = {
        .attestation_data = {0},
        .attestation_data_len = encr_attest_data_len,
        .signature = {0},
        .signature_len = signature_len,
        .public_key = {0},
        .public_key_len = sizeof(pk_bytes),
        .event_log = event_log,
        .event_log_len = event_log_len
    };

    memcpy(response.public_key, &pk_bytes, sizeof(pk_bytes));
    memcpy(response.attestation_data, encr_attest_data, response.attestation_data_len);
    memcpy(response.signature, signature, signature_len);



	/* marshal response */
	ra2iot_log_info("[" LOG_NAME "] Marshaling response to CBOR.");
	uint32_t res_buf_len = 0;
	uint8_t* res_buf = NULL;
	if (ra2iot_marshal_attestation_response(&response, &res_buf_len, &res_buf) != 1) {
        ra2iot_log_error("[" LOG_NAME "] Error marshaling data.");
        goto error;
    }else{
        ra2iot_log_info("[" LOG_NAME "] Attestation Response Successfully Marshalled!");
    }
	ra2iot_log_info(
		"[" LOG_NAME "] Size of marshaled response is %d bytes.", res_buf_len);

	/* add response data to outgoing PDU and send it */
	ra2iot_log_info(
		"[" LOG_NAME
		"] Adding marshaled data to CoAP response PDU and send it.");
	out->code = COAP_RESPONSE_CODE_CONTENT;
	if ((coap_r = coap_add_data_large_response(resource, session, in, out,
			 token, query, COAP_MEDIATYPE_APPLICATION_CBOR, -1, 0, res_buf_len,
			 res_buf, release_data, res_buf)) == 0) {
		ra2iot_log_error(
			"[" LOG_NAME "] Error invoking coap_add_data_large_response().");
		goto error;
	}else
		attestation_count++;
	ra2iot_log_info(" => [" LOG_NAME "] Performed %d attestations so far...", attestation_count);
error:
	/* Free heap objects */
	/* clean up */
	if(event_log)
		free(event_log);
	

}
