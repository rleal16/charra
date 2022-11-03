#include "ra2iot_dto.h"

/* 
Use log data to assess claim integrity.
"Inpired" by TPM-based attestation, where the logs are used to reproduce the attesation data (that why att_data is given).
Please, note that there might be other ways of assessing the integrity of the claims, without using the claims themselves; 
In fact, in some of those cases, we might be assessing the device integrity instead of its claims (directly).
*/
int check_claims_integrity(const uint8_t *event_logs, const uint32_t event_logs_len, const ra2iot_attest_dto att_data, attest_res *att_results);
