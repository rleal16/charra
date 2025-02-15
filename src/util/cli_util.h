/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2021, Fraunhofer Institute for Secure Information Technology SIT.
 * All rights reserved.
 ****************************************************************************/

/**
 * @file command_line_util.h
 * @note This code is based on the corresponding code in https://github.com/Fraunhofer-SIT/charra
 * @author Michael Eckel (michael.eckel@sit.fraunhofer.de) (CHARRA Author)
 * @brief Provides command line parsing for verifier & attester.
 * @version 0.1
 * @date 2021-02-18
 *
 * @copyright Copyright 2021, Fraunhofer Institute for Secure Information
 * Technology SIT. All rights reserved.
 *
 * @license BSD 3-Clause "New" or "Revised" License (SPDX-License-Identifier:
 * BSD-3-Clause).
 */

#include "../common/ra2iot_log.h"
#include <coap2/coap.h>
#include <stdbool.h>

typedef enum {
	VERIFIER,
	ATTESTER,
} cli_parser_caller;

/**
 * A structure holding pointers to common variables of attester and verifier
 * which might geht modified by the CLI parser
 */
typedef struct {
	ra2iot_log_t* ra2iot_log_level;
	coap_log_t* coap_log_level;
	unsigned int* port;
	bool* use_dtls_psk;
	char** dtls_psk_key;
	bool* use_dtls_rpk;
	char** dtls_rpk_private_key_path;
	char** dtls_rpk_public_key_path;
	char** dtls_rpk_peer_public_key_path;
	bool* dtls_rpk_verify_peer_public_key;
} cli_config_common;

/**
 * A structure holding pointers to variables of the attester
 * which might geht modified by the CLI parser
 */
typedef struct {
	char** dtls_psk_hint;
} cli_config_attester;

/**
 * A structure holding pointers to variables of the verifier
 * which might geht modified by the CLI parser
 */
typedef struct {
	char* dst_host;
	uint16_t* timeout;
	char** dtls_psk_identity;
} cli_config_verifier;

/**
 * A structure holding the pointers to all config parameters which might get
 * modified by the CLI parser
 */
typedef struct {
	cli_parser_caller caller;
	cli_config_common common_config;
	cli_config_attester attester_config;
	cli_config_verifier verifier_config;
} cli_config;

/**
*  @brief parses command line interface arguments
*
* @param argc The number of arguments which were given to the CLI.
* @param argv The arguments which were given to the CLI.
* @param variables A struct holding a caller identifier and pointers to config
				   variables which might get modified depending on the CLI
arguments.
* @return 0 on success, -1 on parse error, 1 when help message was displayed
*/
int parse_command_line_arguments(int argc, char** argv, cli_config* variables);
