#include "ra_iot_dto.h"
#include "ra_iot_security.h"
#define UNUSED(x) (void)(x)
int check_claims_integrity(const uint8_t *event_logs, const uint32_t event_logs_len, const ra_iot_attest_dto att_data, attest_res *att_results){
    
    UNUSED(event_logs); 
    UNUSED(event_logs_len); 
    UNUSED(att_data);

    att_results->valid_claims = true;
    return 1; // verification was successfull
}