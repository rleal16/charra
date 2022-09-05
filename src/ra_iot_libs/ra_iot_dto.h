#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>

#ifndef RA_IOT_DTO_H
#define RA_IOT_DTO_H


/*
typedef struct {
	uint8_t* nonce; // o nonce que é suposto ter
	uint32_t nonce_len; // o tamanho do nonce
	uint32_t data_len; // o tamanho dos dados
	uint8_t* data; // por agora é uma dummy variable representando os dados
} ra_iot_attest_dto;
*/

typedef struct {
	uint8_t* nonce;
	uint32_t nonce_len; // o tamanho do nonce
} ra_iot_attest_dto;
#endif