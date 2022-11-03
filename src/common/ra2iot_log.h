/* SPDX-License-Identifier: MIT */
/*****************************************************************************
 * Copyright (c) 2017 rxi.
 ****************************************************************************/

/**
 * @file ra2iot_log.h
 * @author rxi (https://github.com/rxi) (original author)
 * @note This code is based on the corresponding code in https://github.com/Fraunhofer-SIT/charra
 * @author Michael Eckel (michael.eckel@sit.fraunhofer.de) (CHARRA Author)
 * @brief
 * @version 0.1
 * @date 2019-09-19
 *
 * @copyright Copyright (c) 2017 rxi.
 *
 * @license MIT License (SPDX-License-Identifier: MIT).
 */

#ifndef RA2IOT_LOG_H
#define RA2IOT_LOG_H

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#define RA2IOT_LOG_VERSION "1.0.0"

typedef void (*ra2iot_log_LockFn)(void* udata, int lock);

typedef enum ra2iot_log_t {
	RA2IOT_LOG_TRACE = 0,
	RA2IOT_LOG_DEBUG = 1,
	RA2IOT_LOG_INFO = 2,
	RA2IOT_LOG_WARN = 3,
	RA2IOT_LOG_ERROR = 4,
	RA2IOT_LOG_FATAL = 5,ka
} ra2iot_log_t;

#if (!RA2IOT_LOG_DISABLE)
#define ra2iot_log_trace(...)                                                  \
	ra2iot_log_log(RA2IOT_LOG_TRACE, __FILE__, __LINE__, __VA_ARGS__)
#define ra2iot_log_debug(...)                                                  \
	ra2iot_log_log(RA2IOT_LOG_DEBUG, __FILE__, __LINE__, __VA_ARGS__)
#define ra2iot_log_info(...)                                                   \
	ra2iot_log_log(RA2IOT_LOG_INFO, __FILE__, __LINE__, __VA_ARGS__)
#define ra2iot_log_warn(...)                                                   \
	ra2iot_log_log(RA2IOT_LOG_WARN, __FILE__, __LINE__, __VA_ARGS__)
#define ra2iot_log_error(...)                                                  \
	ra2iot_log_log(RA2IOT_LOG_ERROR, __FILE__, __LINE__, __VA_ARGS__)
#define ra2iot_log_fatal(...)                                                  \
	ra2iot_log_log(RA2IOT_LOG_FATAL, __FILE__, __LINE__, __VA_ARGS__)
#else
#define ra2iot_log_trace(...)                                                  \
	{ ; }
#define ra2iot_log_debug(...)                                                  \
	{ ; }
#define ra2iot_log_info(...)                                                   \
	{ ; }
#define ra2iot_log_warn(...)                                                   \
	{ ; }
#define ra2iot_log_error(...)                                                  \
	{ ; }
#define ra2iot_log_fatal(...)                                                  \
	{ ; }
#endif

void ra2iot_log_set_udata(void* udata);
void ra2iot_log_set_lock(ra2iot_log_LockFn fn);
void ra2iot_log_set_fp(FILE* fp);
void ra2iot_log_set_level(ra2iot_log_t level);
void ra2iot_log_set_quiet(int enable);

void ra2iot_log_log(
	ra2iot_log_t level, const char* file, int line, const char* fmt, ...);

/**
 * @brief the same as ra2iot_log_log(), but does not append filename, timestamp
 * or '\n' to the output.
 */
void ra2iot_log_log_raw(ra2iot_log_t level, const char* fmt, ...);

/**
 * @brief Parses the RA2IOT log level from string and writes the result into
 * variable log_level. In case of an parsing error nothing is written and the
 * function returns -1.
 *
 * @param[in] log_level_str the RA2IOT log level string.
 * @param[out] log_level the variable into which the result is written.
 * @return 0 on success, -1 on error.
 */
int ra2iot_log_level_from_str(
	const char* log_level_str, ra2iot_log_t* log_level);

#endif /* RA2IOT_LOG_H */
