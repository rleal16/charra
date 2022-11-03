#include <qcbor/UsefulBuf.h>
#include <qcbor/qcbor.h>
#include "ra2iot_dto.h"
#include "ra2iot_memory_mgmt.h"
#include "ra2iot_evidence_mgmt.h"

#ifndef RA2IOT_MARSHALING_H
#define RA2IOT_MARSHALING_H

int ra2iot_marshal_attestation_response_size(
	const ra2iot_msg_attestation_response_dto* attestation_response,
	size_t* marshaled_data_len);


int ra2iot_marshal_attestation_response(
	const ra2iot_msg_attestation_response_dto* attestation_response,
	uint32_t* marshaled_data_len, uint8_t** marshaled_data);

int ra2iot_unmarshal_attestation_response(
	const uint32_t marshaled_data_len, const uint8_t* marshaled_data,
	ra2iot_msg_attestation_response_dto* attestation_response);

int ra2iot_unmarshal_attestion_data(
	mbedtls_rsa_context *sig_key, 
	mbedtls_rsa_context *encr_key, 
	ra2iot_msg_attestation_response_dto *req, 
	ra2iot_attest_dto *att_data);

/* **************************************************************************** */
/* ***************** (Un) Marshalling the attestation request ***************** */
/* **************************************************************************** */

int ra2iot_marshal_attestation_request_size(
	const ra2iot_msg_attestation_request_dto* attestation_request,
	size_t* marshaled_data_len);

int ra2iot_marshal_attestation_request(
	const ra2iot_msg_attestation_request_dto* attestation_request,
	uint32_t* marshaled_data_len, uint8_t** marshaled_data);

int ra2iot_unmarshal_attestation_request(
	const uint32_t marshaled_data_len, const uint8_t* marshaled_data,
	ra2iot_msg_attestation_request_dto* attestation_request);

#endif