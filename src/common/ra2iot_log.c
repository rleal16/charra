/* SPDX-License-Identifier: MIT */
/*****************************************************************************
 * Copyright (c) 2017 rxi.
 ****************************************************************************/

/**
 * @file ra2iot_log.c
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

#include "ra2iot_log.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static struct {
	void* udata;
	ra2iot_log_LockFn lock;
	FILE* fp;
	ra2iot_log_t level;
	int quiet;
} L;

static const char* const ra2iot_level_names[6] = {[RA2IOT_LOG_TRACE] = "TRACE",
	[RA2IOT_LOG_DEBUG] = "DEBUG",
	[RA2IOT_LOG_INFO] = "INFO",
	[RA2IOT_LOG_WARN] = "WARN",
	[RA2IOT_LOG_ERROR] = "ERROR",
	[RA2IOT_LOG_FATAL] = "FATAL"};

#ifndef RA2IOT_LOG_DISABLE_COLOR
static const char* ra2iot_level_colors[] = {
	"\x1b[94m", "\x1b[36m", "\x1b[32m", "\x1b[33m", "\x1b[31m", "\x1b[35m"};
#endif

static void ra2iot_log_lock(void) {
	if (L.lock) {
		L.lock(L.udata, 1);
	}
}

static void ra2iot_log_unlock(void) {
	if (L.lock) {
		L.lock(L.udata, 0);
	}
}

void ra2iot_log_set_udata(void* udata) { L.udata = udata; }

void ra2iot_log_set_lock(ra2iot_log_LockFn fn) { L.lock = fn; }

void ra2iot_log_set_fp(FILE* fp) { L.fp = fp; }

void ra2iot_log_set_level(ra2iot_log_t level) { L.level = level; }

void ra2iot_log_set_quiet(int enable) { L.quiet = enable ? 1 : 0; }

void ra2iot_log_log(
	ra2iot_log_t level, const char* file, int line, const char* fmt, ...) {
	if (level < L.level) {
		return;
	}

	/* acquire lock */
	ra2iot_log_lock();

	/* get current time */
	time_t t = time(NULL);
	struct tm* lt = localtime(&t);

	/* log to stderr */
	if (!L.quiet) {
		va_list args;
		char buf[16];
		buf[strftime(buf, sizeof(buf), "%H:%M:%S", lt)] = '\0';
#ifndef RA2IOT_LOG_DISABLE_COLOR
		fprintf(stderr, "%s %s%-5s\x1b[0m \x1b[90m%s:%d:\x1b[0m ", buf,
			ra2iot_level_colors[level], ra2iot_level_names[level], file, line);
#else
		fprintf(stderr, "%s %-5s %s:%d: ", buf, ra2iot_level_names[level], file,
			line);
#endif
		va_start(args, fmt);
		vfprintf(stderr, fmt, args);
		va_end(args);
		fprintf(stderr, "\n");
		fflush(stderr);
	}

	/* log to file */
	if (L.fp) {
		va_list args;
		char buf[32];
		buf[strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", lt)] = '\0';
		fprintf(L.fp, "%s %-5s %s:%d: ", buf, ra2iot_level_names[level], file,
			line);
		va_start(args, fmt);
		vfprintf(L.fp, fmt, args);
		va_end(args);
		fprintf(L.fp, "\n");
		fflush(L.fp);
	}

	/* release lock */
	ra2iot_log_unlock();
}

void ra2iot_log_log_raw(ra2iot_log_t level, const char* fmt, ...) {
	if (level < L.level) {
		return;
	}

	/* acquire lock */
	ra2iot_log_lock();

	/* log to stderr */
	if (!L.quiet) {
		va_list args;
		va_start(args, fmt);
		vfprintf(stderr, fmt, args);
		va_end(args);
		fflush(stderr);
	}

	/* log to file */
	if (L.fp) {
		va_list args;
		va_start(args, fmt);
		vfprintf(L.fp, fmt, args);
		va_end(args);
		fflush(L.fp);
	}

	/* release lock */
	ra2iot_log_unlock();
}

int ra2iot_log_level_from_str(
	const char* log_level_str, ra2iot_log_t* log_level) {
	if (log_level_str != NULL) {
		int array_size =
			sizeof(ra2iot_level_names) / sizeof(ra2iot_level_names[0]);
		for (int i = 0; i < array_size; i++) {
			const char* name = ra2iot_level_names[i];
			if (name == NULL) {
				continue;
			}
			if (strcmp(name, log_level_str) == 0) {
				*log_level = i;
				return 0;
			}
		}
		return -1;
	}

	return -1;
}
