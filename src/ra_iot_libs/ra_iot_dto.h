#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include "ra_iot_crypto.h"


#define KEY_SIZE 2048

#ifndef RA_IOT_DTO_H
#define RA_IOT_DTO_H

/* General structure that contains information related with a set of reference values */
typedef struct {
	uint8_t ref_values[512]; // in the future, this should be an array or the structure holding the set of reference values
	size_t ref_values_len;
}ref_values_dto;

/* Structure that holds data related with a given claim selection */
typedef struct {
	uint32_t selection_len;
	uint8_t selection[1];
} claim_selection_dto;


/* Attestation data */
typedef struct {
	uint8_t nonce[16]; // o nonce que é suposto ter
	uint32_t nonce_len; // o tamanho do nonce
	uint8_t data[128]; // por agora é uma dummy variable representando os dados
	uint32_t data_len; // o tamanho dos dados
} ra_iot_attest_dto;


// Struct to save the attestation results
typedef struct {
	bool valid_signature_size; // signa
	//bool valid_eSIM_crt; // verifica se alguma das CAs certificou o eSIM
	//bool eSIM_keys_match; // true se a chave pública do eSIM é a mesma que a que está no certificado`
	bool valid_attest_data_signature; // true a assinatura dos dados de atestação são válidos`
	bool valid_nonce; // true se o nonce for válido`
	bool valid_against_ref_values; // true se a evidência for válida quando comparada com o valores de referência`
	bool valid_event_log; // true se os dados do event log foram válidos -- seja lá o que isso quer dizer`
	//bool valid_claims;
}attest_res;




typedef struct {
	size_t nonce_len;
	uint8_t nonce[128]; // temporary length
	uint32_t claim_selections_len; // number of claim selections
	claim_selection_dto claim_selections[2]; // 2 for testing
	bool get_logs; // true if the verifier wants logs
} ra_iot_msg_attestation_request_dto;


typedef struct {
	uint32_t attestation_data_len;
	uint8_t attestation_data[256]; // a instância de attest_dto encriptada (apenas) 

	uint32_t signature_len;
	uint8_t signature[MBEDTLS_PK_SIGNATURE_MAX_SIZE]; // a assinatura da instância de attest_dto encriptada

	uint32_t public_key_len;
	uint8_t public_key[KEY_SIZE]; //chave pública usada para assinar que corresponde (futuramente) à chave do eSIM.

	uint32_t event_log_len; // o tamanho dos logs
	uint8_t* event_log; // por agora é uma dummy variable representando os dados do logs
} ra_iot_msg_attestation_response_dto;


// Test functions
int attest_resp_cmp(ra_iot_msg_attestation_response_dto attest_res1, ra_iot_msg_attestation_response_dto attest_res2);
void print_attest_data(ra_iot_attest_dto att_data);

#endif