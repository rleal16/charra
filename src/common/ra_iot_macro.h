/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2021, Fraunhofer Institute for Secure Information Technology SIT.
 * All rights reserved.
 ****************************************************************************/

/**
 * @file ra_iot_macro.h
 * @note This code is based on the corresponding code in https://github.com/Fraunhofer-SIT/charra
 * @author Michael Eckel (michael.eckel@sit.fraunhofer.de) (CHARRA Author)
 * @version 0.1
 * @date 2021-03-17
 *
 * @copyright Copyright 2019, Fraunhofer Institute for Secure Information
 * Technology SIT. All rights reserved.
 *
 * @license BSD 3-Clause "New" or "Revised" License (SPDX-License-Identifier:
 * BSD-3-Clause).
 */

#ifndef RA_IOT_MACRO_H
#define RA_IOT_MACRO_H

#include <stdlib.h>

#define ra_iot_free_and_null_ex(var, func_name)                                \
	{                                                                          \
		func_name(var);                                                        \
		var = NULL;                                                            \
	}

#define ra_iot_free_and_null(var)                                              \
	{ ra_iot_free_and_null_ex(var, free); }

#define ra_iot_free_if_not_null_ex(var, func_name)                             \
	{                                                                          \
		if (var != NULL) {                                                     \
			ra_iot_free_and_null_ex(var, func_name);                           \
		}                                                                      \
	}

#define ra_iot_free_if_not_null(var)                                           \
	{ ra_iot_free_if_not_null_ex(var, free); }

#endif /* RA_IOT_MACRO_H */
