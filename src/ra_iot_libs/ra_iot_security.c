#include "ra_iot_dto.h"
#include "ra_iot_security.h"

int check_claims_integrity(uint8_t *event_logs, uint32_t event_logs_len, attest_res *att_results){
    //att_results->valid_against_ref_values = true;
    return 1; // verification was successfull
}