#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include "ra_iot_dto.h"

#include "ra_iot_evidence_mgmt.h"

/* This version just fills event log with a string */
int ra_iot_get_log_data(uint8_t *event_log, uint32_t *event_log_len){
    sprintf(event_log, "Event logs data");
    *event_log_len = strlen((char *)event_log);
    return 1; // SUCCESS
}


int ra_iot_load_ref_values(ref_values_dto *ref_values){
    char ref_vals[512] = "Reference values";
    ref_values->ref_values_len = strlen(ref_vals);
    memcpy(ref_values->ref_values, ref_vals, strlen(ref_vals));
    return 1; //success 
}
