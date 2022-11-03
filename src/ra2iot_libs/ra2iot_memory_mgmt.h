#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "ra2iot_dto.h"

#ifndef RA2IOT_MEMORY_MGMT_H
#define RA2IOT_MEMORY_MGMT_H

/* Claim_selection_dto memory management */

claim_selection_dto *new_claim_selection();
void free_claim_selection_dto(claim_selection_dto *cs);

/* ra2iot_msg_attestation_request_dto memory management */

ra2iot_msg_attestation_request_dto *new_attestation_request();
void free_attestation_request(ra2iot_msg_attestation_request_dto *ar);

/* ra2iot_msg_attestation_response_dto memory management */

ra2iot_msg_attestation_response_dto *new_attestation_response();
void free_attestation_response(ra2iot_msg_attestation_response_dto *ar);

/* attest_res memory management */

attest_res *new_attestation_results();
void free_attestation_results(attest_res *ar);

/* ref_values_dto memory management */

ref_values_dto *new_ref_values();
void free_ref_values(ref_values_dto *rv);

/* ra2iot_attest_dto memory management */

ra2iot_attest_dto *new_att_data();
void free_att_data(ra2iot_attest_dto *rv);

#endif