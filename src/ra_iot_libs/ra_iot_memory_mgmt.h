#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "ra_iot_dto.h"

#ifndef RA_IOT_MEMORY_MGMT_H
#define RA_IOT_MEMORY_MGMT_H

/* Claim_selection_dto memory management */

claim_selection_dto *new_claim_selection();
void free_claim_selection_dto(claim_selection_dto *cs);

/* ra_iot_msg_attestation_request_dto memory management */

ra_iot_msg_attestation_request_dto *new_attestation_request();
void free_attestation_request(ra_iot_msg_attestation_request_dto *ar);

/* ra_iot_msg_attestation_response_dto memory management */

ra_iot_msg_attestation_response_dto *new_attestation_response();
void free_attestation_response(ra_iot_msg_attestation_response_dto *ar);

/* attest_res memory management */

attest_res *new_attestation_results();
void free_attestation_results(attest_res *ar);

/* ref_values_dto memory management */

ref_values_dto *new_ref_values();
void free_ref_values(ref_values_dto *rv);

/* ra_iot_attest_dto memory management */

ra_iot_attest_dto *new_att_data();
void free_att_data(ra_iot_attest_dto *rv);

#endif