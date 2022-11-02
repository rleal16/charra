/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2019, Fraunhofer Institute for Secure Information Technology SIT.
 * All rights reserved.
 ****************************************************************************/

/**
 * @file io_util.c
 * @author Michael Eckel (michael.eckel@sit.fraunhofer.de)
 * @brief Provides I/O functions, including print.
 * @version 0.1
 * @date 2019-12-22
 *
 * @copyright Copyright 2019, Fraunhofer Institute for Secure Information
 * Technology SIT. All rights reserved.
 *
 * @license BSD 3-Clause "New" or "Revised" License (SPDX-License-Identifier:
 * BSD-3-Clause).
 */

#include "io_util.h"
#include "../common/charra_log.h"
#include "../common/charra_macro.h"


#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>


void charra_print_hex(const charra_log_t level, const size_t buf_len,
	const uint8_t* const buf, const char* prefix, const char* postfix,
	const bool upper_case) {
	const char* const hex_case = upper_case ? "%02X" : "%02x";

	charra_log_log_raw(level, "%s", prefix);
	/* print upper case */
	for (size_t i = 0; i < buf_len; ++i) {
		charra_log_log_raw(level, hex_case, buf[i]);
	}
	charra_log_log_raw(level, "%s", postfix);
}


void charra_print_str(const charra_log_t level, const size_t buf_len,
	const uint8_t* const buf, const char* prefix, const char* postfix) {

	charra_log_log_raw(level, "%s", prefix);
	/* print upper case */
	for (size_t i = 0; i < buf_len; ++i) {
		charra_log_log_raw(level, "%c", buf[i]);
	}
	charra_log_log_raw(level, "%s", postfix);
}

CHARRA_RC check_file_existence(const char* filename) {
	FILE* fp = NULL;
	if ((fp = fopen(filename, "r")) == NULL) {
		return CHARRA_RC_ERROR;
	}
	return CHARRA_RC_SUCCESS;
}


CHARRA_RC charra_io_read_file(
	const char* filename, char** file_content, size_t* file_content_len) {
	FILE* fp = NULL;
	if ((fp = fopen(filename, "r")) == NULL) {
		charra_log_error("Cannot open file '%s'.", filename);
		return CHARRA_RC_ERROR;
	}
	fseek(fp, 0L, SEEK_END);
	size_t file_size = ftell(fp);
	fseek(fp, 0L, SEEK_SET);
	char* file_buffer = malloc(file_size * sizeof(char));
	size_t read_size = fread(file_buffer, sizeof(*file_buffer), file_size, fp);
	if (read_size < file_size) {
		charra_log_error(
			"Error while reading file '%s', expected size %d, got size %d.",
			filename, file_size, read_size);
		charra_free_if_not_null(file_buffer);
		return CHARRA_RC_ERROR;
	}
	/* flush and close file */
	if (fflush(fp) != 0) {
		charra_log_error("Error flushing file '%s'.", filename);
		charra_free_if_not_null(file_buffer);
		return CHARRA_RC_ERROR;
	}
	if (fclose(fp) != 0) {
		charra_log_error("Error closing file '%s'.", filename);
		charra_free_if_not_null(file_buffer);
		return CHARRA_RC_ERROR;
	}
	*file_content = file_buffer;
	*file_content_len = read_size;
	return CHARRA_RC_SUCCESS;
}

void charra_free_file_buffer(char** file_content) {
	charra_free_if_not_null(*file_content);
}

