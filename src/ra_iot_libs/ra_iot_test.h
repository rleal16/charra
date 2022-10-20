#include "ra_iot_dto.h"
#include "ra_iot_memory_mgmt.h"
#include "ra_iot_crypto.h"
#include "ra_iot_evidence_mgmt.h"
#include "ra_iot_marshaling.h"

#define TEST_MARSHALLING 0

/* Testing marshall/unmarshall pipeline for attestation response */
void attest_res_marshall_unmarshal_test(void);

/* Testing ref values generation and comparison with evidence */
void test_ref_values(void);

/* Testing cryptographic functions */
void crypto_test(unsigned char *input, size_t i_len);

/* Testing the generation of the nonce */
void test_generate_nonce(void);

/* Testing marshall/unmarshall pipeline for attestation request */
void attest_request_marshall_unmarshal_test();
