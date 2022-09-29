#include <qcbor/UsefulBuf.h>
#include <qcbor/qcbor.h>
#include "ra_iot_dto.h"
#include "ra_iot_memory_mgmt.h"
#include "ra_iot_evidence_mgmt.h"

#ifndef RA_IOT_MARSHALING_H
#define RA_IOT_MARSHALING_H

int ra_iot_marshal_attestation_response_size(
	const ra_iot_msg_attestation_response_dto* attestation_response,
	size_t* marshaled_data_len);


int ra_iot_marshal_attestation_response(
	const ra_iot_msg_attestation_response_dto* attestation_response,
	uint32_t* marshaled_data_len, uint8_t** marshaled_data);

int ra_iot_unmarshal_attestation_response(
	const uint32_t marshaled_data_len, const uint8_t* marshaled_data,
	ra_iot_msg_attestation_response_dto* attestation_response);

#endif