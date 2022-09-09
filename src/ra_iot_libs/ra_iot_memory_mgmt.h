#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>

#include "ra_iot_dto.h"
#include "../common/charra_error.h"

#ifndef RA_IOT_MEMORY_MGMT_H
#define RA_IOT_MEMORY_MGMT_H

CHARRA_RC new_attest_dto(ra_iot_attest_dto **att_dto);
void free_attest_dto(ra_iot_attest_dto **att_dto);
void alloc_nonce(uint8_t **nonce);
void print_test();
#endif