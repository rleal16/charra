#include <stdio.h>
#include <stdlib.h>
// Arcadian-IoT libraries
//#include "mbedtls_api.h"
#include "../ra_iot_dto.h"
#include "../ra_iot_memory_mgmt.h"
#include "my_rsa_genkey.h"


int main(int argc, char** argv) {

	//int status = call_rsa_genkey();
    //printf("Status is: %d\n", status);
	printf("\n\n");
    printf("\n\n\n[ ==>> In VERIFER's Main!]\n");
	ra_iot_attest_dto *stuff;
	new_attest_dto(&stuff);
	stuff->nonce_len=100000;
	printf("A new nonce_len appears: %d\n", stuff->nonce_len);
	printf("The nonce is [%d], [%d]\n\n\n", stuff->nonce[0], stuff->nonce[1]);
	free_attest_dto(&stuff);

	printf("Nonce Test 2\n");
	ra_iot_attest_dto new_stuff;
	new_stuff.nonce_len = 234;
	alloc_nonce(&(new_stuff.nonce));
	new_stuff.nonce[0] = 9;
	new_stuff.nonce[1] = 8;
	new_stuff.nonce[2] = 7;
	printf("A new nonce_len appears: %d\n", new_stuff.nonce_len);
	printf("The nonce is [%d], [%d], [%d]\n\n\n", new_stuff.nonce[0], new_stuff.nonce[1], new_stuff.nonce[2]);
	free(new_stuff.nonce);
	printf("\n\n\n[In VERIFER's Main! ==>>]\n");

    return 0;
}