/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2019, Fraunhofer Institute for Secure Information Technology SIT.
 * All rights reserved.
 ****************************************************************************/

/**
 * @file verifier.c
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
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "common/ra2iot_log.h"
#include "common/ra2iot_macro.h"
#include "util/cli_util.h"
#include "util/coap_util.h"
#include "util/io_util.h"


// ADDED to comunicate with hardened encryption
#include <sys/socket.h>


/* ---------- Arcadian IoT Remote Attestation Libraries */
#include "ra2iot_libs/ra2iot_dto.h"
#include "ra2iot_libs/ra2iot_memory_mgmt.h"
#include "ra2iot_libs/ra2iot_crypto.h"
#include "ra2iot_libs/ra2iot_evidence_mgmt.h"
#include "ra2iot_libs/ra2iot_marshaling.h"
#include "ra2iot_libs/ra2iot_security.h"

#include "ra2iot_libs/test_ra2iot/test_ra2iot.h"

#define FORCE_EXIT 0 // interrupts the code execution at a given point for testing purposes
#define PRINT_RES(x) (x ? "Ok!" : "Failed!")

#define RA2IOT_UNUSED __attribute__((unused))

/* --- config ------------------------------------------------------------- */

/* quit signal */
static bool quit = false;
static bool processing_response = false;
static RA2IOT_RC attestation_rc = RA2IOT_RC_ERROR;

/* logging */
#define LOG_NAME "ra2iot_verifier"
coap_log_t coap_log_level = LOG_INFO;
// #define LOG_LEVEL_CBOR LOG_DEBUG
ra2iot_log_t ra2iot_log_level = RA2IOT_LOG_INFO;

/* config */
//char dst_host[16] = "127.0.0.1";	 // 15 characters for IPv4 plus \0
char dst_host[16] = "172.24.0.4";
unsigned int dst_port = 5683;		 // default port

//char server_host[16] = "172.24.0.3";
//unsigned int server_port = 1234;

/* Um teste... */
coap_context_t* coap_context_test = NULL;
coap_session_t* coap_session_test = NULL;
coap_optlist_t* coap_options_test = NULL;



#define COAP_IO_PROCESS_TIME_MS 2000 // CoAP IO process time in milliseconds
#define PERIODIC_ATTESTATION_WAIT_TIME_S                                       \
	2 // Wait time between attestations in seconds

static uint32_t claim_selection_len = 9;

uint16_t attestation_response_timeout =
	30; // timeout when waiting for attestation answer in seconds

// for DTLS-PSK
bool use_dtls_psk = false;
char* dtls_psk_key = "Charra DTLS Key";
char* dtls_psk_identity = "Charra Verifier";

// for DTLS-RPK
bool use_dtls_rpk = false;
char* dtls_rpk_private_key_path = "keys/verifier.der";
char* dtls_rpk_public_key_path = "keys/verifier.pub.der";
char* dtls_rpk_peer_public_key_path = "keys/attester.pub.der";
bool dtls_rpk_verify_peer_public_key = true;

// For socket comunication
//int sock = 0, valread, client_fd;
//struct sockaddr_in serv_addr;

// For socket comunication with HE
int server_sock = 0, clnt_fd;
struct sockaddr_in srvr_addr;
char server_addr[16] = "172.24.0.4";
unsigned int server_port = 1245;

/* --- function forward declarations -------------------------------------- */

/**
 * @brief SIGINT handler: set quit to 1 for graceful termination.
 *
 * @param signum the signal number.
 */
static void handle_sigint(int signum);

static coap_response_t coap_attest_handler(struct coap_context_t* context,
	coap_session_t* session, coap_pdu_t* sent, coap_pdu_t* received,
	const coap_mid_t mid);


static coap_response_t coap_response_test_handler(
	struct coap_context_t* context,
	coap_session_t* session, coap_pdu_t* sent,
	coap_pdu_t* in, const coap_mid_t mid);

/* --- static variables --------------------------------------------------- */
// key-pair for encryption/decryption
mbedtls_rsa_context pub_key; // public key
mbedtls_rsa_context priv_key; // private key
static attest_res att_results; // attestation results structure
static ra2iot_msg_attestation_request_dto last_request = {0};
static ra2iot_msg_attestation_response_dto last_response = {0};

/* --- main --------------------------------------------------------------- */

int main(int argc, char** argv) {
	RA2IOT_RC result = EXIT_FAILURE;

	int res;
	printf("\n\n\t\t\tVERIFIER RA2IOT!!\n\n\n");
	/* handle SIGINT */
	signal(SIGINT, handle_sigint);

	/* check environment variables */
	ra2iot_log_level_from_str(
		(const char*)getenv("LOG_LEVEL_RA2IOT"), &ra2iot_log_level);
	ra2iot_coap_log_level_from_str(
		(const char*)getenv("LOG_LEVEL_COAP"), &coap_log_level);

	/* initialize structures to pass to the CLI parser */
	cli_config cli_config = {
		.caller = VERIFIER,
		.common_config =
			{
				.ra2iot_log_level = &ra2iot_log_level,
				.coap_log_level = &coap_log_level,
				.port = &dst_port,
				.use_dtls_psk = &use_dtls_psk,
				.dtls_psk_key = &dtls_psk_key,
				.use_dtls_rpk = &use_dtls_rpk,
				.dtls_rpk_private_key_path = &dtls_rpk_private_key_path,
				.dtls_rpk_public_key_path = &dtls_rpk_public_key_path,
				.dtls_rpk_peer_public_key_path = &dtls_rpk_peer_public_key_path,
				.dtls_rpk_verify_peer_public_key =
					&dtls_rpk_verify_peer_public_key,
			},
		.verifier_config =
			{
				.dst_host = dst_host,
				.timeout = &attestation_response_timeout,
				.dtls_psk_identity = &dtls_psk_identity,
			},
	};

	/* set log level before parsing CLI to be able to print errors. */
	ra2iot_log_set_level(ra2iot_log_level);
	coap_set_log_level(coap_log_level);

	/* parse CLI arguments */
	if ((result = parse_command_line_arguments(argc, argv, &cli_config)) != 0) {
		// 1 means help message was displayed (thus exit), -1 means error
		return (result == 1) ? RA2IOT_RC_SUCCESS : RA2IOT_RC_CLI_ERROR;
	}

	/* set RA2IOT and libcoap log levels again in case CLI changed these */
	ra2iot_log_set_level(ra2iot_log_level);
	coap_set_log_level(coap_log_level);

	ra2iot_log_debug("[" LOG_NAME "] Verifier Configuration:");
	ra2iot_log_debug("[" LOG_NAME "]     Destination port: %d", dst_port);
	ra2iot_log_debug("[" LOG_NAME "]     Destination host: %s", dst_host);
	ra2iot_log_debug("[" LOG_NAME
					 "]     Timeout when waiting for attestation response: %ds",
		attestation_response_timeout);
	
	ra2iot_log_debug("[" LOG_NAME "]     Claim selection with length %d:",
		claim_selection_len);
	
	ra2iot_log_log_raw(RA2IOT_LOG_DEBUG, "                                                      ");

	ra2iot_log_debug("[" LOG_NAME "]     DTLS with PSK enabled: %s",
		(use_dtls_psk == true) ? "true" : "false");
	if (use_dtls_psk) {
		ra2iot_log_debug("[" LOG_NAME "]         Pre-shared key: '%s'",
			dtls_psk_key);
		ra2iot_log_debug("[" LOG_NAME "]         Identity: '%s'",
			dtls_psk_identity);
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

	/* set varaibles here such that they are valid in case of an 'goto cleanup'
	 */
	coap_context_t* coap_context = NULL;
	coap_session_t* coap_session = NULL;
	coap_optlist_t* coap_options = NULL;
	uint8_t* req_buf = NULL;



	if (use_dtls_psk && use_dtls_rpk) {
		ra2iot_log_error(
			"[" LOG_NAME "] Configuration enables both DTSL with PSK "
			"and DTSL with PKI. Aborting!");
		goto cleanup;
	}

	if (use_dtls_psk || use_dtls_rpk) {
		// print TLS version when in debug mode
		coap_show_tls_version(LOG_DEBUG);
	}

	if (use_dtls_psk && !coap_dtls_is_supported()) {
		ra2iot_log_error("[" LOG_NAME "] CoAP does not support DTLS but the "
						 "configuration enables DTLS. Aborting!");
		goto cleanup;
	}

	/* create CoAP context */

	ra2iot_log_info("[" LOG_NAME "] Initializing CoAP in block-wise mode.");
	if ((coap_context = ra2iot_coap_new_context(true)) == NULL) {
		ra2iot_log_error("[" LOG_NAME "] Cannot create CoAP context.");
		result = RA2IOT_RC_COAP_ERROR;
		goto cleanup;
	}

	ra2iot_log_info("[" LOG_NAME "] Initializing CoAP in block-wise mode.");
	if ((coap_context_test = ra2iot_coap_new_context(true)) == NULL) {
		ra2iot_log_error("[" LOG_NAME "] Cannot create CoAP context.");
		result = RA2IOT_RC_COAP_ERROR;
		goto cleanup;
	}

	/* register CoAP response handler */
	ra2iot_log_info("[" LOG_NAME "] Registering CoAP response handler.");
	coap_register_response_handler(coap_context, coap_attest_handler);

	//coap_register_response_handler(coap_context_test, coap_response_test_handler);

	if (use_dtls_psk) {
		ra2iot_log_info(
			"[" LOG_NAME "] Creating CoAP client session using DTLS with PSK.");
		if ((coap_session = ra2iot_coap_new_client_session_psk(coap_context,
				 dst_host, dst_port, COAP_PROTO_DTLS, dtls_psk_identity,
				 (uint8_t*)dtls_psk_key, strlen(dtls_psk_key))) == NULL) {
			ra2iot_log_error(
				"[" LOG_NAME
				"] Cannot create client session based on DTLS-PSK.");
			result = RA2IOT_RC_ERROR;
			goto cleanup;
		}
	} else if (use_dtls_rpk) {
		ra2iot_log_info(
			"[" LOG_NAME "] Creating CoAP client session using DTLS-RPK.");
		coap_dtls_pki_t dtls_pki = {0};

		result = ra2iot_coap_setup_dtls_pki_for_rpk(&dtls_pki,
			dtls_rpk_private_key_path, dtls_rpk_public_key_path,
			dtls_rpk_peer_public_key_path, dtls_rpk_verify_peer_public_key);
		if (result != RA2IOT_RC_SUCCESS) {
			ra2iot_log_error(
				"[" LOG_NAME "] Error while setting up DTLS-RPK structure.");
			goto cleanup;
		}

		if ((coap_session = ra2iot_coap_new_client_session_pki(coap_context,
				 dst_host, dst_port, COAP_PROTO_DTLS, &dtls_pki)) == NULL) {
			ra2iot_log_error(
				"[" LOG_NAME
				"] Cannot create client session based on DTLS-RPK.");
			result = RA2IOT_RC_ERROR;
			goto cleanup;
		}
	} else {
		ra2iot_log_info(
			"[" LOG_NAME "] Creating CoAP client session using UDP.");
		if ((coap_session = ra2iot_coap_new_client_session(
				 coap_context, dst_host, dst_port, COAP_PROTO_UDP)) == NULL) {
			ra2iot_log_error(
				"[" LOG_NAME "] Cannot create client session based on UDP.");
			result = RA2IOT_RC_COAP_ERROR;
			goto cleanup;
		}


		//TEST
		/* ra2iot_log_info(
			"[" LOG_NAME "] Creating CoAP client session using UDP.");
		if ((coap_session_test = ra2iot_coap_new_client_session(
				 coap_context_test, server_host, server_port, COAP_PROTO_UDP)) == NULL) {
			ra2iot_log_error(
				"[" LOG_NAME "] Cannot create client session based on UDP.");
			result = RA2IOT_RC_COAP_ERROR;
			goto cleanup;
		} */


	}

	/* ********************************************** */
	/* Preparing comunication with HE through sockets */
	/* ********************************************** */
	ra2iot_log_info("[" LOG_NAME "] Comunicating with HE Server...");
    if ((server_sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("\n Socket creation error \n");
        return -1;
    }
	
    /* server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(1245);
  */
    // Convert IPv4 and IPv6 addresses from text to binary
    // form
   /*  if (inet_pton(AF_INET, "172.24.0.4", &server_addr.sin_addr) <= 0) {
        printf("\nInvalid address/ Address not supported \n");
        return -1;
    }
 
    if ((clnt_fd = connect(server_sock, (struct sockaddr*)&server_addr, sizeof(server_addr))) < 0) {
        printf("\nConnection Failed \n");
        return -1;
    }
 */
	/* uint8_t msg[128] = "this is a text the i sent..";
	printf("Sock is: %d\n", sock);
    send(sock, msg, strlen(msg), 0);
    printf("Hello message sent\n");
    valread = read(sock, buffer, 1024);
    printf("%s\n", buffer); */
 
    // closing the connected socket
    //close(client_fd);



	/* Create key-pair for encryption/decryption */
	ra2iot_log_info("[" LOG_NAME "] Generating RSA key.");
	res = ra2iot_gen_rsa_keypair("verifier_keys/", &pub_key, &priv_key);
    
	ra2iot_log_info("[" LOG_NAME "] Verifier's key generation: %s", PRINT_RES(res));
    
	ra2iot_log_info("[" LOG_NAME "] Checking Verifier keys");
    ra2iot_log_info("[" LOG_NAME "] \tKey Pair is: %s", PRINT_RES(mbedtls_rsa_check_pub_priv(&pub_key, &priv_key) == 0));
    ra2iot_log_info("[" LOG_NAME "] \tPublic key is: %s", PRINT_RES(mbedtls_rsa_check_pubkey(&pub_key) == 0));
    ra2iot_log_info("[" LOG_NAME "] \tPrivate key is: %s", PRINT_RES(mbedtls_rsa_check_privkey(&priv_key) == 0));

	// register device
	/* 
	["auth1:at1", "auth1:at2"]
	["auth2:at1", "auth2:at2"]
	["auth3:at1", "auth3:at2"] 
	*/
	printf("\nRegistering...\n");
	char server_addr[16] = "172.24.0.3";
	unsigned int server_port = 1245;
	ra2iot_register(server_addr, server_port, "gid1", "auth1:at1,auth2:at2,auth3:at1");


	/* define needed variables */
	ra2iot_msg_attestation_request_dto req = {0};

	uint32_t req_buf_len = 0;
	coap_pdu_t* pdu = NULL;
	coap_pdu_t* pdu2 = NULL;
	coap_mid_t mid = COAP_INVALID_MID;
	int coap_io_process_time = -1;

	/* create CoAP option for content type */
	uint8_t coap_mediatype_cbor_buf[4] = {0};
	unsigned int coap_mediatype_cbor_buf_len = 0;
	if ((coap_mediatype_cbor_buf_len = coap_encode_var_safe(
			 coap_mediatype_cbor_buf, sizeof(coap_mediatype_cbor_buf),
			 COAP_MEDIATYPE_APPLICATION_CBOR)) == 0) {
		ra2iot_log_error(
			"[" LOG_NAME "] Cannot create option for CONTENT_TYPE.");
		result = RA2IOT_RC_COAP_ERROR;
		goto cleanup;
	}

	/* enter  periodic attestation loop */
	// TODO enable periodic attestations
	// ra2iot_log_info("[" LOG_NAME "] Entering periodic attestation loop.");
	// while (!quit) {
	// 	/* cleanup */
	// 	memset(&req, 0, sizeof(req));
	// 	if (coap_options != NULL) {
	// 		coap_delete_optlist(coap_options);
	// 		coap_options = NULL;
	// 	}


	/* create attestation request */
	ra2iot_log_info("[" LOG_NAME "] Creating attestation request.");
	if ((result = ra2iot_create_attestation_request(&req, &pub_key)) != 1) {
		ra2iot_log_error("[" LOG_NAME "] Cannot create attestation request.");
		goto cleanup;
	} else {
		ra2iot_log_info("[" LOG_NAME "] Attestation Request Created!");
		/* store request data */
		last_request = req;
	}

	/* marshal attestation request */
	ra2iot_log_info(
		"[" LOG_NAME "] Marshaling attestation request data to CBOR.");
	if ((result = ra2iot_marshal_attestation_request(
			 &req, &req_buf_len, &req_buf)) != 1) {
		ra2iot_log_error(
			"[" LOG_NAME "] Marshaling attestation request data failed.");
		goto cleanup;
	}

	/* CoAP options */

	// DuP

	ra2iot_log_info("[" LOG_NAME "] Adding CoAP option URI_PATH.");
	if (coap_insert_optlist(
			&coap_options, coap_new_optlist(COAP_OPTION_URI_PATH, 6,
							   (const uint8_t*)"attest")) != 1) {
		ra2iot_log_error("[" LOG_NAME "] Cannot add CoAP option URI_PATH.");
		result = RA2IOT_RC_COAP_ERROR;
		goto cleanup;
	}
	ra2iot_log_info("[" LOG_NAME "] Adding CoAP option CONTENT_TYPE.");
	if (coap_insert_optlist(&coap_options,
			coap_new_optlist(COAP_OPTION_CONTENT_TYPE,
				coap_mediatype_cbor_buf_len, coap_mediatype_cbor_buf)) != 1) {
		ra2iot_log_error("[" LOG_NAME "] Cannot add CoAP option CONTENT_TYPE.");
		result = RA2IOT_RC_COAP_ERROR;
		goto cleanup;
	}



	ra2iot_log_info("[" LOG_NAME "] Adding CoAP option URI_PATH.");
	if (coap_insert_optlist(
			&coap_options_test, coap_new_optlist(COAP_OPTION_URI_PATH, 6,
							   (const uint8_t*)"attest")) != 1) {
		ra2iot_log_error("[" LOG_NAME "] Cannot add CoAP option URI_PATH.");
		result = RA2IOT_RC_COAP_ERROR;
		goto cleanup;
	}
	
	/* ra2iot_log_info("[" LOG_NAME "] Adding CoAP option CONTENT_TYPE.");
	if (coap_insert_optlist(&coap_options_test,
			coap_new_optlist(COAP_OPTION_CONTENT_TYPE,
				coap_mediatype_cbor_buf_len, coap_mediatype_cbor_buf)) != 1) {
		ra2iot_log_error("[" LOG_NAME "] Cannot add CoAP option CONTENT_TYPE.");
		result = RA2IOT_RC_COAP_ERROR;
		goto cleanup;
	} */



	/* new CoAP request PDU */
	//dup
	ra2iot_log_info("[" LOG_NAME "] Creating request PDU.");
	if ((pdu = ra2iot_coap_new_request(coap_session, COAP_MESSAGE_TYPE_CON,
			 COAP_REQUEST_FETCH, &coap_options, req_buf, req_buf_len)) ==
		NULL) {
		ra2iot_log_error("[" LOG_NAME "] Cannot create request PDU.");
		result = RA2IOT_RC_ERROR;
		goto cleanup;
	}

	/* uint8_t my_msg[] = "uma mensagem";
	uint32_t my_msg_len = strlen(my_msg);
	ra2iot_log_info("[" LOG_NAME "] Creating request PDU.");
	if ((pdu2 = ra2iot_coap_new_request(coap_session_test, COAP_MESSAGE_TYPE_CON,
			 COAP_REQUEST_FETCH, &coap_options_test, my_msg, my_msg_len)) ==
		NULL) {
		ra2iot_log_error("[" LOG_NAME "] Cannot create request PDU.");
		result = RA2IOT_RC_ERROR;
		goto cleanup;
	} */

	/* set timeout length */
	coap_fixed_point_t coap_timeout = {attestation_response_timeout, 0};
	coap_session_set_ack_timeout(coap_session, coap_timeout);
	//TEST
	//coap_session_set_ack_timeout(coap_session_test, coap_timeout);

	/* send CoAP PDU */
	ra2iot_log_info("[" LOG_NAME "] Sending CoAP message.");
	if ((mid = coap_send_large(coap_session, pdu)) == COAP_INVALID_MID) {
		ra2iot_log_error("[" LOG_NAME "] Cannot send CoAP message.");
		result = RA2IOT_RC_COAP_ERROR;
		goto cleanup;
	}

	/* processing and waiting for response */
	ra2iot_log_info("[" LOG_NAME "] Processing and waiting for response ...");
	uint16_t response_wait_time = 0;
	while (!processing_response && !coap_can_exit(coap_context)) {
		/* process CoAP I/O */
		if ((coap_io_process_time = coap_io_process(
				 coap_context, COAP_IO_PROCESS_TIME_MS)) == -1) {
			ra2iot_log_error(
				"[" LOG_NAME "] Error during CoAP I/O processing.");
			result = RA2IOT_RC_COAP_ERROR;
			goto cleanup;
		}
		/* This wait time is not 100% accurate, it only includes the elapsed
		 * time inside the coap_io_process function. But should be good enough.
		 */
		response_wait_time += coap_io_process_time;
		if (response_wait_time >= (attestation_response_timeout * 1000)) {
			ra2iot_log_error("[" LOG_NAME
							 "] Timeout after %d ms while waiting for or "
							 "processing attestation response.",
				response_wait_time);
			result = RA2IOT_RC_TIMEOUT;
			goto cleanup;
		}
	}

	// normal exit from processing loop, set result to result of attestation
	result = attestation_rc;
	ra2iot_log_info("[" LOG_NAME "] Printing Attestation Results:\n");
	ra2iot_print_attest_res(att_results);
	
	/* wait until next attestation */
	// TODO enable periodic attestations
	// ra2iot_log_info(
	// 	"[" LOG_NAME
	// 	"] Waiting %d seconds until next attestation request ...",
	// 	PERIODIC_ATTESTATION_WAIT_TIME_S);
	// sleep(PERIODIC_ATTESTATION_WAIT_TIME_S);
	// }

	// TEST
	/* send CoAP PDU TEST 
	ra2iot_log_info("[" LOG_NAME "] Sending CoAP message. with TEST......!!!!");
	if ((mid = coap_send_large(coap_session_test, pdu2)) == COAP_INVALID_MID) {
		ra2iot_log_error("[" LOG_NAME "] Cannot send CoAP message.");
		result = RA2IOT_RC_COAP_ERROR;
		goto cleanup;
	}

	/* processing and waiting for response 
	ra2iot_log_info("[" LOG_NAME "] Processing and waiting for response ...");
	//uint16_t response_wait_time = 0;
	while (!processing_response && !coap_can_exit(coap_context_test)) {
		/* process CoAP I/O 
		if ((coap_io_process_time = coap_io_process(
				 coap_context_test, COAP_IO_PROCESS_TIME_MS)) == -1) {
			ra2iot_log_error(
				"[" LOG_NAME "] Error during CoAP I/O processing.");
			result = RA2IOT_RC_COAP_ERROR;
			goto cleanup;
		}
		/* This wait time is not 100% accurate, it only includes the elapsed
		 * time inside the coap_io_process function. But should be good enough.
		 
		response_wait_time += coap_io_process_time;
		if (response_wait_time >= (attestation_response_timeout * 1000)) {
			ra2iot_log_error("[" LOG_NAME
							 "] Timeout after %d ms while waiting for or "
							 "processing attestation response.",
				response_wait_time);
			result = RA2IOT_RC_TIMEOUT;
			goto cleanup;
		} 
	}

	// normal exit from processing loop, set result to result of attestation
	result = attestation_rc;
	ra2iot_log_info("[" LOG_NAME "] Printing Attestation Results:\n");
	ra2iot_print_attest_res(att_results);*/

cleanup:
	/* free CoAP memory */
	ra2iot_free_if_not_null_ex(coap_options, coap_delete_optlist);
	ra2iot_free_if_not_null_ex(coap_session, coap_session_release);
	
	ra2iot_free_if_not_null_ex(coap_context, coap_free_context);

	/* free variables */
	ra2iot_free_if_not_null(req_buf);

	// closing the connected socket
    //close(clnt_fd);

	coap_cleanup();

	return result;
}

/* --- function definitions ----------------------------------------------- */

static void handle_sigint(int signum RA2IOT_UNUSED) { quit = true; }


/* --- resource handler definitions --------------------------------------- */

static coap_response_t coap_attest_handler(
	struct coap_context_t* context RA2IOT_UNUSED,
	coap_session_t* session RA2IOT_UNUSED, coap_pdu_t* sent RA2IOT_UNUSED,
	coap_pdu_t* in, const coap_mid_t mid RA2IOT_UNUSED) {
	int coap_r = 0;
	int res;

	processing_response = true;
	printf("\n\n\n");
	ra2iot_log_info("[" LOG_NAME "] ********** ********** ********** **********");
	ra2iot_log_info("[" LOG_NAME "] Processing Attestation Response\n");

	ra2iot_log_info(
		"[" LOG_NAME "] Resource '%s': Received message.", "attest");
	coap_show_pdu(LOG_DEBUG, in);

	/* --- receive incoming data --- */

	/* get data */
	size_t data_len = 0;
	const uint8_t* data = NULL;
	size_t data_offset = 0;
	size_t data_total_len = 0;
	if ((coap_r = coap_get_data_large(in, &data_len, &data, &data_offset, &data_total_len)) == 0) {
		ra2iot_log_error("[" LOG_NAME "] Could not get CoAP PDU data.");
		attestation_rc = RA2IOT_RC_ERROR;
		goto cleanup;
	} else {
		ra2iot_log_info(
			"[" LOG_NAME "] Received data of length %zu.", data_len);
		ra2iot_log_info("[" LOG_NAME "] Received data of total length %zu.",
			data_total_len);
	}

	/* unmarshal data */
	ra2iot_log_info("[" LOG_NAME "] Parsing received CBOR data.");
	
	ra2iot_msg_attestation_response_dto response = {0};
	if ((attestation_rc = ra2iot_unmarshal_attestation_response(
			 data_len, data, &response)) != 1) {
		ra2iot_log_error("[" LOG_NAME "] Could not parse CBOR data.");
		goto cleanup;
	}	
	
	/* store last response */
	last_response = response;


	ra2iot_log_info("[" LOG_NAME "] Starting verification.");

	ra2iot_log_info("[" LOG_NAME "] Sending data to the HE server.");
	
	



	/* load public part of attester's signature key */
	pub_key_dto pk_bytes;
    mbedtls_rsa_context attester_key;
	mbedtls_rsa_init( &attester_key, MBEDTLS_RSA_PKCS_V15, 0 );

    ra2iot_log_info("[" LOG_NAME "] Converting the unmarshalled Attester's public key to a intermediate \"buffer structure\"\n");
	memcpy(&pk_bytes, response.public_key, response.public_key_len);
    ra2iot_log_info("[" LOG_NAME "] Converting Attester's public key from bytes to mbedtls_rsa_context\n");
    res = ra2iot_load_pub_key_from_buffer(&pk_bytes, &attester_key);
    ra2iot_log_info("[" LOG_NAME "] Converting bytes to mbedtls_rsa_context: %s\n", (res ? "Ok!" : "Failed!"));


	
	/* unmarshal attestation data */
	ra2iot_attest_dto att_data;
	int unmarshal_res = ra2iot_unmarshal_attestion_data(&attester_key, &priv_key, &response, &att_data);
    ra2iot_log_info("[" LOG_NAME "] Unmarshaling Attesation Data: %s\n", (unmarshal_res ? "Ok!" : "Bad!"));

	//request_he(server_addr, server_port, att_data.nonce);
	/* char buffer[1024] = { 0 };
	
	uint8_t msg[128] = "sent from the verifier...";
    send(server_sock, msg, strlen(msg), 0);
	//send(sock, msg2, strlen(msg2), 0);
    ra2iot_log_info("[" LOG_NAME "] Messange sent to Hardened Encrpytion\n");
    int valread = read(server_sock, buffer, 1024);
    printf("%s\n", buffer); */

	//request_he(server_addr, server_port, "Test do pipe no verifier");

	//test_he_func(sock);


	/* Initialize the attestation data structure */
	att_results.valid_nonce = false;
	
	// if unmarshal was successful, the signature was valid; otherwise, we (temporarily) consider it invalid (until return codes are not defined)
	att_results.valid_attest_data_signature = (bool) unmarshal_res; 
    att_results.valid_against_ref_values = false;
	att_results.valid_claims = false;
    
	printf("\n\nAttestation data\n");
	print_attest_data(&att_data);
	printf("****************\n");

	/* Verify the claims integrity, using the logs (maybe) */
    res = check_claims_integrity(response.event_log, response.event_log_len, att_data, &att_results);
    ra2iot_log_info("[" LOG_NAME "] Claim Integrity Results: %s\n", (res ? "Ok!" : "Failed!"));

    /* Appraise evidence */
    res = appraise_evidence(last_request, att_data, &att_results);
    ra2iot_log_info("[" LOG_NAME "] Evidence Appraisal Overall Result: %s\n", (res ? "Ok!" : "Failed!"));

    //ra2iot_print_attest_res(att_results);

	/* --- output result --- */

	bool attestation_result = get_attest_results_overall(att_results);

	/* print attestation result */
	ra2iot_log_info("[" LOG_NAME "] +----------------------------+");
	if (attestation_result) {
		attestation_rc = RA2IOT_RC_SUCCESS;
		ra2iot_log_info("[" LOG_NAME "] |   ATTESTATION SUCCESSFUL   |");
	} else {
		attestation_rc = RA2IOT_RC_VERIFICATION_FAILED;
		ra2iot_log_info("[" LOG_NAME "] |     ATTESTATION FAILED     |");
	}
	ra2iot_log_info("[" LOG_NAME "] +----------------------------+");

cleanup:
	
	/* free event log */
	// TODO: Provide function ra2iot_free_msg_attestation_response_dto()
	ra2iot_free_if_not_null(response.event_log);
    mbedtls_rsa_free( &attester_key);
    mbedtls_rsa_free( &pub_key );
    mbedtls_rsa_free( &priv_key );  

	processing_response = false;
	return COAP_RESPONSE_OK;
}



/* 
void coap_response_test_handler(int sockaddr, uint8_t *msg, uint32_t msg_len) {
	
	char buff[MAX];
    int n;
    for (;;) {
        bzero(buff, sizeof(buff));
        printf("Enter the string : ");
        n = 0;
        while ((buff[n++] = getchar()) != '\n')
            ;
        write(sockfd, buff, sizeof(buff));
        bzero(buff, sizeof(buff));
        read(sockfd, buff, sizeof(buff));
        printf("From Server : %s", buff);
        if ((strncmp(buff, "exit", 4)) == 0) {
            printf("Client Exit...\n");
            break;
        }
    }
} */