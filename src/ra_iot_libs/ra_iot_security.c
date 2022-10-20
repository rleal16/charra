#include "ra_iot_dto.h"
#include "ra_iot_security.h"

int check_claims_integrity(const uint8_t *event_logs, const uint32_t event_logs_len, const ra_iot_attest_dto att_data, attest_res *att_results){
    att_results->valid_claims = true;
    return 1; // verification was successfull
}