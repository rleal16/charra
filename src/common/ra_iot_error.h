/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2019, Fraunhofer Institute for Secure Information Technology SIT.
 * All rights reserved.
 ****************************************************************************/

/**
 * @file RA_IOT_error.h
 * @note This code is based on the corresponding code in https://github.com/Fraunhofer-SIT/charra
 * @author Michael Eckel (michael.eckel@sit.fraunhofer.de) (CHARRA Author)
 * @brief
 * @version 0.1
 * @date 2019-09-19
 *
 * @copyright Copyright 2019, Fraunhofer Institute for Secure Information
 * Technology SIT. All rights reserved.
 *
 * @license BSD 3-Clause "New" or "Revised" License (SPDX-License-Identifier:
 * BSD-3-Clause).
 */

#ifndef RA_IOT_ERROR_H
#define RA_IOT_ERROR_H

#include <inttypes.h>

typedef uint32_t RA_IOT_RC;
#define RA_IOT_RC_SUCCESS ((RA_IOT_RC)0x00000000)
#define RA_IOT_RC_ERROR ((RA_IOT_RC)0x00000001)
#define RA_IOT_RC_CRYPTO_ERROR ((RA_IOT_RC)0x0001ffff)
#define RA_IOT_RC_NOT_YET_IMPLEMENTED ((RA_IOT_RC)0xeeeeee)
#define RA_IOT_RC_BAD_ARGUMENT ((RA_IOT_RC)0x0000ffff)
#define RA_IOT_RC_MARSHALING_ERROR ((RA_IOT_RC)0x0000fffe)
#define RA_IOT_RC_VERIFICATION_FAILED ((RA_IOT_RC)0x000000ff)
#define RA_IOT_RC_NO_MATCH ((RA_IOT_RC)0x01010101)
#define RA_IOT_RC_CLI_ERROR ((RA_IOT_RC)0x0000aaaa)
#define RA_IOT_RC_COAP_ERROR ((RA_IOT_RC)0x0000C0AF)
#define RA_IOT_RC_TIMEOUT ((RA_IOT_RC)0x0000000f)

#endif /* RA_IOT_ERROR_H */
