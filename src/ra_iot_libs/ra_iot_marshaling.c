#include "ra_iot_marshaling.h"

#include <assert.h>
#include <inttypes.h>
#include <qcbor/UsefulBuf.h>
#include <qcbor/qcbor.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "ra_iot_dto.h"
#include "ra_iot_memory_mgmt.h"
#include "ra_iot_evidence_mgmt.h"

#include "../util/cbor_util.h" // temporary include for unmarshalling functions

#define marshal_verifier_pub_key 1
/* ********************************************************************** */
/* ***************** Unmarshalling the attestation data ***************** */
/* ********************************************************************** */

int ra_iot_unmarshal_attestion_data(mbedtls_rsa_context *sig_key, mbedtls_rsa_context *encr_key, ra_iot_msg_attestation_response_dto *req, ra_iot_attest_dto *att_data){
	int res = 0;
	uint8_t decr_res[512];

	res = ra_iot_verify_decrypt(sig_key, encr_key, req->attestation_data, req->attestation_data_len, req->signature, decr_res);
	if(res == 0)
		return 0;

    printf("ra_iot_verify_decrypt: %s\n", (res ? "Ok!" : "Bad!"));
    memcpy(att_data, decr_res, sizeof(ra_iot_attest_dto));
	
    return res;
}

/* *************************************************************************** */
/* **************** (Un) Marshalling the attestation response **************** */
/* *************************************************************************** */

static int ra_iot_marshal_attestation_response_internal(
	const ra_iot_msg_attestation_response_dto* attestation_response, UsefulBuf buf_in,
	UsefulBufC* buf_out) {
	//ra_iot_log_trace("<ENTER> %s()", __func__);
	printf("In ra_iot_marshal_attestation_response_internal\n");
	/* verify input */
	assert(attestation_response != NULL);
	assert(attestation_response->attestation_data != NULL);
	assert(attestation_response->signature != NULL);
	assert(attestation_response->public_key != NULL);
	if (attestation_response->event_log_len != 0) {
		assert(attestation_response->event_log != NULL);
	}

	QCBOREncodeContext ec = {0};

	QCBOREncode_Init(&ec, buf_in);

	/* root array */
	QCBOREncode_OpenArray(&ec);
	/* encode "attestation data" */
	UsefulBufC attestation_data = {
		.ptr = attestation_response->attestation_data,
		.len = attestation_response->attestation_data_len};
	QCBOREncode_AddBytes(&ec, attestation_data);

	/* encode "signature" */
	UsefulBufC signature = {.ptr = attestation_response->signature,
		.len = attestation_response->signature_len};
	QCBOREncode_AddBytes(&ec, signature);

	/* encode "key signature" */
	UsefulBufC public_key = {.ptr = attestation_response->public_key,
		.len = attestation_response->public_key_len};
	QCBOREncode_AddBytes(&ec, public_key);

	/* encode "event-log" */
	UsefulBufC event_log = {.ptr = attestation_response->event_log,
		.len = attestation_response->event_log_len};
	QCBOREncode_AddBytes(&ec, event_log);

	/* close array: root_array_encoder */
	QCBOREncode_CloseArray(&ec);

	if (QCBOREncode_Finish(&ec, buf_out) == QCBOR_SUCCESS) {
		return 1;
	}

    return 0;
	
}


int ra_iot_marshal_attestation_response_size(
	const ra_iot_msg_attestation_response_dto* attestation_response,
	size_t* marshaled_data_len) {
	//ra_iot_log_trace("<ENTER> %s()", __func__);

    int ret_code = 0;

	/* passing this buffer instructs QCBOR to return only the size and do no
	 * actual encoding */
	UsefulBuf buf_in = {.len = SIZE_MAX, .ptr = NULL};
	UsefulBufC buf_out = {0};

	if ((ret_code = ra_iot_marshal_attestation_response_internal(
			 attestation_response, buf_in, &buf_out)) == 1) {
		*marshaled_data_len = buf_out.len;
	}

	return ret_code;
}


int ra_iot_marshal_attestation_response(
	const ra_iot_msg_attestation_response_dto* attestation_response,
	uint32_t* marshaled_data_len, uint8_t** marshaled_data) {
	//ra_iot_log_trace("<ENTER> %s()", __func__);

	int ret_code = 1;

	/* verify input */
	/* assert(attestation_response != NULL);
	assert(attestation_response->attestation_data != NULL);
	assert(attestation_response->signature != NULL);
	assert(attestation_response->public_key != NULL);
	if (attestation_response->event_log_len != 0) {
		assert(attestation_response->event_log != NULL);
	} */

	/* compute size of marshaled data */
	UsefulBuf buf_in = {.len = 0, .ptr = NULL};
	if ((ret_code = ra_iot_marshal_attestation_response_size(
			 attestation_response, &(buf_in.len))) != 1) {
		printf("Could not compute size of marshaled data.\n");
		return ret_code;
	}
	printf("Size of marshaled data is %zu bytes.\n", buf_in.len);

	/* allocate buffer size */
	if ((buf_in.ptr = malloc(buf_in.len)) == NULL) {
		printf("Allocating %zu bytes of memory failed.\n", buf_in.len);
		return ret_code;
	}
	printf("Allocated %zu bytes of memory.\n", buf_in.len);

	/* encode */
	UsefulBufC buf_out = {.len = 0, .ptr = NULL};
	if ((ret_code = ra_iot_marshal_attestation_response_internal(
			 attestation_response, buf_in, &buf_out)) != 1) {
		printf("Could not marshal data.\n");
		return ret_code;
	}

	/* set output parameters */
	*marshaled_data_len = buf_out.len;
	*marshaled_data = (uint8_t*)buf_out.ptr;

	return ret_code;
}

int ra_iot_unmarshal_attestation_response(
	const uint32_t marshaled_data_len, const uint8_t* marshaled_data,
	ra_iot_msg_attestation_response_dto* attestation_response) {
	ra_iot_msg_attestation_response_dto res = {0};

	QCBORError cborerr = QCBOR_SUCCESS;
	UsefulBufC marshaled_data_buf = {marshaled_data, marshaled_data_len};
	QCBORDecodeContext dc = {0};
	QCBORItem item = {0};

	QCBORDecode_Init(&dc, marshaled_data_buf, QCBOR_DECODE_MODE_NORMAL);

	/* parse root array */
	if ((cborerr = ra_iot_cbor_get_next(&dc, &item, QCBOR_TYPE_ARRAY)))
		goto cbor_parse_error;

	/* parse "attestation-data" (bytes) */
	if ((cborerr = ra_iot_cbor_get_next(&dc, &item, QCBOR_TYPE_BYTE_STRING)))
		goto cbor_parse_error;
	res.attestation_data_len = item.val.string.len;
	memcpy(&(res.attestation_data), item.val.string.ptr, res.attestation_data_len);

	/* parse "signature" (bytes) */
	if ((cborerr = ra_iot_cbor_get_next(&dc, &item, QCBOR_TYPE_BYTE_STRING)))
		goto cbor_parse_error;
	res.signature_len = item.val.string.len;
	memcpy(&(res.signature), item.val.string.ptr, res.signature_len);

	/* parse "public_key" (bytes) */
	if ((cborerr = ra_iot_cbor_get_next(&dc, &item, QCBOR_TYPE_BYTE_STRING)))
		goto cbor_parse_error;
	res.public_key_len = item.val.string.len;
	memcpy(
		&(res.public_key), item.val.string.ptr, res.public_key_len);

	/* parse "event-log" (bytes) */
	if ((cborerr = ra_iot_cbor_get_next(&dc, &item, QCBOR_TYPE_BYTE_STRING)))
		goto cbor_parse_error;
	res.event_log_len = item.val.string.len;
	uint8_t* event_log = (uint8_t*)malloc(res.event_log_len);
	if (event_log == NULL) {
		goto cbor_parse_error;
	} else {
		res.event_log = event_log;
		if (memcpy(res.event_log, item.val.string.ptr, res.event_log_len) == NULL) {
			goto cbor_parse_error;
		}
	}

	if ((cborerr = QCBORDecode_Finish(&dc))) {
		printf("CBOR parser: expected end of input, but could not "
						 "find it. Continuing.");
		goto cbor_parse_error;
	}

	/* set output */
	*attestation_response = res;

	return 1;

cbor_parse_error:
	printf("CBOR parser: %s", qcbor_err_to_str(cborerr));
	printf("CBOR parser: skipping parsing.");

	/* clean up */
    if(event_log != NULL)
	    free(event_log);

	return 0;
}






/* **************************************************************************** */
/* ***************** (Un) Marshalling the attestation request ***************** */
/* **************************************************************************** */

static int ra_iot_marshal_attestation_request_internal(
	const ra_iot_msg_attestation_request_dto* attestation_request, UsefulBuf buf_in,
	UsefulBufC* buf_out) {

	/* verify input */
	assert(attestation_request != NULL);
	assert(attestation_request->claim_selections_len <= 20);
	assert(attestation_request->claim_selections != NULL);

	/* Checking the data inside of the first claim selection */
	assert(attestation_request->claim_selections->selection_len <= 512);
	assert(attestation_request->claim_selections->selection != NULL);

	assert(attestation_request->nonce_len <= 20); // is defined as 128 in the structure, but is 20 in the ra_iot_attest_dto structure -- to be fixed!
	assert(attestation_request->nonce != NULL);

	/* No need to check get_logs, currently */

	QCBOREncodeContext ec = {0};

	QCBOREncode_Init(&ec, buf_in);

	/* root array -> representing the attestation request's structure */
	QCBOREncode_OpenArray(&ec);

	/* encode "nonce" */
	UsefulBufC nonce = {
		attestation_request->nonce, attestation_request->nonce_len};
	QCBOREncode_AddBytes(&ec, nonce);
	
	
	//QCBOREncode_AddUInt64(&ec, attestation_request->claim_selections_len);
	/* encode "claim_selections" */
	UsefulBufC claim;
	QCBOREncode_OpenArray(&ec);
	for (uint32_t i = 0; i < attestation_request->claim_selections_len; ++i) {
		claim.ptr = attestation_request->claim_selections[i].selection;
		claim.len = attestation_request->claim_selections[i].selection_len;
		QCBOREncode_AddBytes(&ec, claim);
	}
	/* close array: pcr_selections_array_encoder */
	QCBOREncode_CloseArray(&ec);

#if marshal_verifier_pub_key
	/* encode "key for encryption" */
	UsefulBufC public_key = {.ptr = attestation_request->public_key,
		.len = attestation_request->public_key_len};
	QCBOREncode_AddBytes(&ec, public_key);
#endif
	/* encode bool "get_logs" -> indicating if the attester should send logs (or something of sorts) */
	QCBOREncode_AddBool(&ec, attestation_request->get_logs);

	/* close array: root_array_encoder */
	QCBOREncode_CloseArray(&ec);

	if (QCBOREncode_Finish(&ec, buf_out) == QCBOR_SUCCESS) {
		return 1;
	} else {
		return 0;
	}
}


int ra_iot_marshal_attestation_request_size(
	const ra_iot_msg_attestation_request_dto* attestation_request,
	size_t* marshaled_data_len) {

	int ret_code = 1;

	/* passing this buffer instructs QCBOR to return only the size and do no
	 * actual encoding */
	UsefulBuf buf_in = {.len = SIZE_MAX, .ptr = NULL};
	UsefulBufC buf_out = {0};

	if ((ret_code = ra_iot_marshal_attestation_request_internal(
			 attestation_request, buf_in, &buf_out)) == 1) {
		*marshaled_data_len = buf_out.len;
	}

	return ret_code;
}

int ra_iot_marshal_attestation_request(
	const ra_iot_msg_attestation_request_dto* attestation_request,
	uint32_t* marshaled_data_len, uint8_t** marshaled_data) {

	int ret_code = 1;

	/* verify input */
	assert(attestation_request != NULL);

	assert(attestation_request->claim_selections_len <= 20);
	assert(attestation_request->claim_selections != NULL);

	/* Checking the data inside of the first claim selection */
	assert(attestation_request->claim_selections->selection_len <= 512);
	assert(attestation_request->claim_selections->selection != NULL);

	assert(attestation_request->nonce_len <= 20); // is defined as 128 in the structure, but is 20 in the ra_iot_attest_dto structure -- to be fixed!
	assert(attestation_request->nonce != NULL);

	/* compute size of marshaled data */
	UsefulBuf buf_in = {.len = 0, .ptr = NULL};
	if ((ret_code = ra_iot_marshal_attestation_request_size(
			 attestation_request, &(buf_in.len))) != 1) {
		printf("Could not compute size of marshaled data.\n");
		return ret_code;
	}
	printf("Size of marshaled data is %zu bytes.\n", buf_in.len);

	/* allocate buffer size */
	if ((buf_in.ptr = malloc(buf_in.len)) == NULL) {
		printf("Allocating %zu bytes of memory failed.\n", buf_in.len);
		return 0;
	}
	printf("Allocated %zu bytes of memory.\n", buf_in.len);

	/* encode */
	UsefulBufC buf_out = {.len = 0, .ptr = NULL};
	if ((ret_code = ra_iot_marshal_attestation_request_internal(
			 attestation_request, buf_in, &buf_out)) != 1) {
		printf("Could not marshal data.\n");
		return ret_code;
	}

	/* set output parameters */
	*marshaled_data_len = buf_out.len;
	*marshaled_data = (uint8_t*)buf_out.ptr;

	return ret_code;
}


int ra_iot_unmarshal_attestation_request(
	const uint32_t marshaled_data_len, const uint8_t* marshaled_data,
	ra_iot_msg_attestation_request_dto* attestation_request) {
	ra_iot_msg_attestation_request_dto req = {0};

	QCBORError cborerr = QCBOR_SUCCESS;
	UsefulBufC marshaled_data_buf = {marshaled_data, marshaled_data_len};
	QCBORDecodeContext dc = {0};
	QCBORItem item = {0};

	QCBORDecode_Init(&dc, marshaled_data_buf, QCBOR_DECODE_MODE_NORMAL);

	if (ra_iot_cbor_get_next(&dc, &item, QCBOR_TYPE_ARRAY))
		goto cbor_parse_error;

	/* parse "nonce" (bytes) */
	if ((cborerr = ra_iot_cbor_get_next(&dc, &item, QCBOR_TYPE_BYTE_STRING)))
		goto cbor_parse_error;
	req.nonce_len = item.val.string.len;
	memcpy(&(req.nonce), item.val.string.ptr, req.nonce_len);


	/* if ((cborerr = ra_iot_cbor_get_next(&dc, &item, QCBOR_TYPE_INT64)))
		goto cbor_parse_error;
	req.claim_selections_len = (uint32_t)item.val.uint64; */

	/* parse array "claim selections" */
	if ((cborerr = ra_iot_cbor_get_next(&dc, &item, QCBOR_TYPE_ARRAY)))
		goto cbor_parse_error;

	/* initialize array and array length */
	req.claim_selections_len = (uint32_t)item.val.uCount;

	/* go through all elements */
	for (uint32_t i = 0; i < req.claim_selections_len; ++i) {
		if ((cborerr = ra_iot_cbor_get_next(&dc, &item, QCBOR_TYPE_BYTE_STRING)))
			goto cbor_parse_error;
		req.claim_selections[i].selection_len = item.val.string.len;
		memcpy(&(req.claim_selections[i].selection), item.val.string.ptr, req.claim_selections[i].selection_len);
	}
#if marshal_verifier_pub_key
	/* parse "public_key" (bytes) */
	 if ((cborerr = ra_iot_cbor_get_next(&dc, &item, QCBOR_TYPE_BYTE_STRING)))
		goto cbor_parse_error;
	req.public_key_len = item.val.string.len;
	memcpy(
		&(req.public_key), item.val.string.ptr, req.public_key_len); 
#endif

	/* parse "get_logs" (bool) */
	if ((cborerr = ra_iot_cbor_get_next(&dc, &item, RA_IOT_CBOR_TYPE_BOOLEAN)))
		goto cbor_parse_error;
	req.get_logs = ra_iot_cbor_get_bool_val(&item);

	/* expect end of CBOR data */
	if ((cborerr = QCBORDecode_Finish(&dc))) {
		printf("CBOR parser: expected end of input, but could not "
						 "find it. Continuing.\n");
		goto cbor_parse_error;
	}

	/* set output */
	*attestation_request = req;

	return 1;

cbor_parse_error:
	printf("CBOR parser: %s\n", qcbor_err_to_str(cborerr));
	printf("CBOR parser: skipping parsing.\n");

	return 0;
}


