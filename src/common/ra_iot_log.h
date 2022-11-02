/* SPDX-License-Identifier: MIT */
/*****************************************************************************
 * Copyright (c) 2017 rxi.
 ****************************************************************************/

/**
 * @file ra_iot_log.h
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

#ifndef RA_IOT_LOG_H
#define RA_IOT_LOG_H

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#define RA_IOT_LOG_VERSION "1.0.0"

typedef void (*ra_iot_log_LockFn)(void* udata, int lock);

typedef enum ra_iot_log_t {
	RA_IOT_LOG_TRACE = 0,
	RA_IOT_LOG_DEBUG = 1,
	RA_IOT_LOG_INFO = 2,
	RA_IOT_LOG_WARN = 3,
	RA_IOT_LOG_ERROR = 4,
	RA_IOT_LOG_FATAL = 5,ka
} ra_iot_log_t;

#if (!RA_IOT_LOG_DISABLE)
#define ra_iot_log_trace(...)                                                  \
	ra_iot_log_log(RA_IOT_LOG_TRACE, __FILE__, __LINE__, __VA_ARGS__)
#define ra_iot_log_debug(...)                                                  \
	ra_iot_log_log(RA_IOT_LOG_DEBUG, __FILE__, __LINE__, __VA_ARGS__)
#define ra_iot_log_info(...)                                                   \
	ra_iot_log_log(RA_IOT_LOG_INFO, __FILE__, __LINE__, __VA_ARGS__)
#define ra_iot_log_warn(...)                                                   \
	ra_iot_log_log(RA_IOT_LOG_WARN, __FILE__, __LINE__, __VA_ARGS__)
#define ra_iot_log_error(...)                                                  \
	ra_iot_log_log(RA_IOT_LOG_ERROR, __FILE__, __LINE__, __VA_ARGS__)
#define ra_iot_log_fatal(...)                                                  \
	ra_iot_log_log(RA_IOT_LOG_FATAL, __FILE__, __LINE__, __VA_ARGS__)
#else
#define ra_iot_log_trace(...)                                                  \
	{ ; }
#define ra_iot_log_debug(...)                                                  \
	{ ; }
#define ra_iot_log_info(...)                                                   \
	{ ; }
#define ra_iot_log_warn(...)                                                   \
	{ ; }
#define ra_iot_log_error(...)                                                  \
	{ ; }
#define ra_iot_log_fatal(...)                                                  \
	{ ; }
#endif

void ra_iot_log_set_udata(void* udata);
void ra_iot_log_set_lock(ra_iot_log_LockFn fn);
void ra_iot_log_set_fp(FILE* fp);
void ra_iot_log_set_level(ra_iot_log_t level);
void ra_iot_log_set_quiet(int enable);

void ra_iot_log_log(
	ra_iot_log_t level, const char* file, int line, const char* fmt, ...);

/**
 * @brief the same as ra_iot_log_log(), but does not append filename, timestamp
 * or '\n' to the output.
 */
void ra_iot_log_log_raw(ra_iot_log_t level, const char* fmt, ...);

/**
 * @brief Parses the RA_IOT log level from string and writes the result into
 * variable log_level. In case of an parsing error nothing is written and the
 * function returns -1.
 *
 * @param[in] log_level_str the RA_IOT log level string.
 * @param[out] log_level the variable into which the result is written.
 * @return 0 on success, -1 on error.
 */
int ra_iot_log_level_from_str(
	const char* log_level_str, ra_iot_log_t* log_level);

#endif /* RA_IOT_LOG_H */
