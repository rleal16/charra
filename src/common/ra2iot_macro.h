/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2021, Fraunhofer Institute for Secure Information Technology SIT.
 * All rights reserved.
 ****************************************************************************/

/**
 * @file ra2iot_macro.h
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

#ifndef RA2IOT_MACRO_H
#define RA2IOT_MACRO_H

#include <stdlib.h>

#define ra2iot_free_and_null_ex(var, func_name)                                \
	{                                                                          \
		func_name(var);                                                        \
		var = NULL;                                                            \
	}

#define ra2iot_free_and_null(var)                                              \
	{ ra2iot_free_and_null_ex(var, free); }

#define ra2iot_free_if_not_null_ex(var, func_name)                             \
	{                                                                          \
		if (var != NULL) {                                                     \
			ra2iot_free_and_null_ex(var, func_name);                           \
		}                                                                      \
	}

#define ra2iot_free_if_not_null(var)                                           \
	{ ra2iot_free_if_not_null_ex(var, free); }

#endif /* RA2IOT_MACRO_H */
