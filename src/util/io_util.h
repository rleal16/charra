/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2019, Fraunhofer Institute for Secure Information Technology SIT.
 * All rights reserved.
 ****************************************************************************/

/**
 * @file io_util.h
 * @note This code is based on the corresponding code in https://github.com/Fraunhofer-SIT/charra
 * @author Michael Eckel (michael.eckel@sit.fraunhofer.de) (CHARRA Author)
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



#ifndef IO_UTIL_H
#define IO_UTIL_H


#include "../common/ra2iot_error.h"
#include "../common/ra2iot_log.h"


#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>



#define RA2IOT_BYTE_TO_BINARY_PATTERN "%c%c%c%c%c%c%c%c"
#define RA2IOT_BYTE_TO_BINARY(byte)                                            \
	(byte & 0x80 ? '1' : '0'), (byte & 0x40 ? '1' : '0'),                      \
		(byte & 0x20 ? '1' : '0'), (byte & 0x10 ? '1' : '0'),                  \
		(byte & 0x08 ? '1' : '0'), (byte & 0x04 ? '1' : '0'),                  \
		(byte & 0x02 ? '1' : '0'), (byte & 0x01 ? '1' : '0')

/**
 * @brief
 *
 * @param level the log level to print at
 * @param buf_len Length of the buffer to be printed.
 * @param buf The buffer to be printed.
 * @param prefix A prefix to the output, e.g. "0x", or leave it empty ("").
 * @param postfix  A postfix to the output, e.g. "\n", or leave it empty ("").
 * @param upper_case true: print in uppercase (e.g. "012..ABCDEF"); false: print
 * in lowercase (e.g. "012..abcdef").
 */
void ra2iot_print_hex(const ra2iot_log_t level, const size_t buf_len,
	const uint8_t* const buf, const char* prefix, const char* postfix,
	const bool upper_case);

/**
 * @brief
 *
 * @param level the log level to print at
 * @param buf_len Length of the buffer to be printed.
 * @param buf The buffer to be printed.
 * @param prefix A prefix to the output, e.g. an indentation ("  "), or leave it
 * empty ("").
 * @param postfix  A postfix to the output, e.g. "\n", or leave it empty ("").
 */
void ra2iot_print_str(const ra2iot_log_t level, const size_t buf_len,
	const uint8_t* const buf, const char* prefix, const char* postfix);

/**
 * @brief Checks if file is existing.
 *
 * @param filename the path of the file
 */
RA2IOT_RC check_file_existence(const char* filename);

/**
 * @brief read file into a buffer. The buffer will be initialized in this
 * function.
 *
 * @param[in] filename the path of the file to read
 * @param[out] file_content A pointer to the buffer, assumed to be uninitialized
 * upon calling.
 * @param[out] file_content_len The actual length of the file (aka the size of
 * file_content).
 * @return RA2IOT_RC RA2IOT_RC_SUCCESS on success, otherwise RA2IOT_RC_ERROR
 */
RA2IOT_RC ra2iot_io_read_file(
	const char* filename, char** file_content, size_t* file_content_len);

/**
 * @brief free buffer holding the file content. Alternatively
 * free(*file_content) can be called directly.
 *
 * @param[in] file_content A pointer to the buffer.
 */
void ra2iot_free_file_buffer(char** file_content);

#endif /* IO_UTIL_H */
