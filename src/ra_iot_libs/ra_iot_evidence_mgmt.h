
/* 
This represents a function that extracts information from the system 
to be used by the verifier to assess the trustworthiness of the attester and attester's providaded information.
*/
int ra_iot_get_log_data(uint8_t *event_log, uint32_t *event_log_len);

/* Placeholder function to load reference values */
int ra_iot_load_ref_values(ref_values_dto *ref_values);