
#ifndef RA_IOT_EVIDENCE_MGMT_H
#define RA_IOT_EVIDENCE_MGMT_H

#define PRINT_BOOL(x) (x ? "Ok!" : "Wrong!")
/* 
This represents a function that extracts information from the system 
to be used by the verifier to assess the trustworthiness of the attester and attester's providaded information.
*/
int ra_iot_get_log_data(uint8_t *event_log, uint32_t *event_log_len);

/* Placeholder function to load reference values */
int ra_iot_load_ref_values(ref_values_dto *ref_values);


/* Checks if the attestation data is valid. Assigns the result to the reference values structure and returns the result */
bool ra_iot_check_ref_values(const ref_values_dto ref_vals, const ra_iot_attest_dto att_data, attest_res *att_res);

/* Print the attestation results */
void ra_iot_print_attest_res(attest_res att);

#endif