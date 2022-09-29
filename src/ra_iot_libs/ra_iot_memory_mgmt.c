
#include <stdio.h>
#include <stdlib.h>
#include "ra_iot_memory_mgmt.h"

// just for testing
void alloc_nonce(uint8_t **nonce){
	*nonce = malloc(sizeof(int)*3);
}

/* 
CHARRA_RC new_attest_dto(ra_iot_attest_dto **att_dto){
    *att_dto = malloc(sizeof(ra_iot_attest_dto));
    (*att_dto)->nonce = malloc(sizeof(int)*2);
    (*att_dto)->nonce[0] = -2;
    (*att_dto)->nonce[1] = 43;
    return CHARRA_RC_SUCCESS;
}
 */
void free_attest_dto(ra_iot_attest_dto **att_dto){
    printf("\n\n[FREE] Nonce: %d\n",(*att_dto)->nonce_len);
    free((*att_dto)->nonce);
    free(*att_dto);
    *att_dto = NULL;
}

void print_test(){
    printf("Print test\n");
}