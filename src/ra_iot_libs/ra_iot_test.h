#include "ra_iot_dto.h"
#include "ra_iot_memory_mgmt.h"
#include "ra_iot_crypto.h"
#include "ra_iot_evidence_mgmt.h"
#include "ra_iot_marshaling.h"

#define TEST_MARSHALLING 0

/* Testing marshall/unmarshall pipeline */
void attest_res_marshall_unmarshal_test(void);

/* Testing cryptographic functions */
void crypto_test(unsigned char *input, size_t i_len);