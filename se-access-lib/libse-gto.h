/*****************************************************************************
 * Copyright Gemalto, unpublished work, created 2014. This computer program
 * includes Confidential, Proprietary Information and is a Trade Secret of
 * Gemalto. All use, disclosure, and/or reproduction is prohibited unless
 * authorised in writing by an officer of Gemalto. All Rights Reserved.
 *
 * Gemalto licenses this file to you under the libse-gto Gemalto License.
 * See NOTICE file for more information regarding copyright ownership.
 * A copy of libse-gto Gemalto License is available in LICENSE file included
 * in source code distribution of libse-gto Gemalto. You can ask a copy of the
 * License by contacting Gemalto (http://www.gemalto.com).
 ****************************************************************************/

/**
 * @file
 * $Author$
 * $Revision$
 * $Date$
 *
 * libse-gto to dialog with device T=1 protocol over SPI.
 *
 * This library is not thread safe on same context.
 */

#ifndef LIBSE_GTO_H
#define LIBSE_GTO_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * library user context - reads the config and system
 * environment, user variables, allows custom logging.
 *
 * Default struct se_gto_ctx log to stderr file stream.
 * Content is opaque to user.
 */
struct se_gto_ctx;

/** Function callback to display log line.
 * @s nul terminated string.
 */

typedef void se_gto_log_fn (struct se_gto_ctx *ctx, const char *s);


/********************************* Core *************************************/

/** Create se-gto library context.
 *
 * This fills in the default values. Device node for eSE GTO is "@c /dev/gto".
 *
 * Use environment variable SE_GTO_LOG to alter default log level globally.
 * SE_GTO_LOG=n with n from 0 to 4, or choice of SE_GTO_LOG to err, info, debug.
 *
 * @returns a new se-gto library context
 */
int se_gto_new(struct se_gto_ctx **ctx);

/** Allocates resources from environment and kernel.
 *
 * @c errno is set on error.
 *
 * @return -1 on error, 0 otherwise.
 */
int se_gto_open(struct se_gto_ctx *ctx);

/** Release resources.
 *
 * @c errno is set on error.
 * @return -1 on error, 0 otherwise.
 */
int se_gto_close(struct se_gto_ctx *ctx);

/******************************* Facilities *********************************/

/** Returns current log level.
 *
 * @param ctx: se-gto library context
 *
 * @returns the current logging level
 **/
int se_gto_get_log_level(struct se_gto_ctx *ctx);

/**
 * Set the current logging level.
 *
 * @param ctx   se-gto library context
 * @param level the new logging level
 *
 * @c level controls which messages are logged:
 *   0 : error
 *   1 : warning
 *   2 : notice
 *   3 : info
 *   4 : debug
 **/
void se_gto_set_log_level(struct se_gto_ctx *ctx, int level);

/** Get current function callback for log entries.
 *
 * Use this function if you want to chain log entries and replace current
 * function by yours.
 *
 * @param ctx se-gto library context.
 *
 * @return current function for log string.
 */
se_gto_log_fn *se_gto_get_log_fn(struct se_gto_ctx *ctx);

/** Set function callback for log entries.
 *
 * @param ctx se-gto library context.
 * @param fn Function to dump nul terminated string.
 */
void se_gto_set_log_fn(struct se_gto_ctx *ctx, se_gto_log_fn *fn);

void *se_gto_get_userdata(struct se_gto_ctx *ctx);

/** Store custom userdata in the library context.
 *
 * @param ctx      se-gto library context
 * @param userdata data pointer
 **/
void se_gto_set_userdata(struct se_gto_ctx *ctx, void *userdata);

/**************************** HW configuration ******************************/

/** Returns current device node for eSE.
 *
 * Returned string must not be modified. Copy returned string if you need to
 * use it later.
 *
 * @param ctx se-gto library context.
 *
 * @returns nul terminated string.
 */
const char *se_gto_get_gtodev(struct se_gto_ctx *ctx);

/** Set device node used for eSE.
 *
 * @c gtodev is copied se-gto library. You can use a volatile string.
 *
 * @param ctx    se-gto library context.
 * @param gtodev full path to device node.
 */
void se_gto_set_gtodev(struct se_gto_ctx *ctx, const char *gtodev);

/****************************** APDU protocol *******************************/

/** Send reset command to Secure Element and return ATR bytes.
 *
 * @param ctx se-gto library context
 * @param atr byte buffer to receive ATR content
 * @param r   length of ATR byte buffer.
 *
 * @c errno is set on error.
 *
 * @returns number of bytes in @c atr buffer or -1 on error.
 */
int se_gto_reset(struct se_gto_ctx *ctx, void *atr, size_t r);

/** Transmit APDU to Secure Element
 *
 * If needed to comply with request from command, multiple ISO7816 Get
 * Response can be emitted to collect the full response.
 *
 * @param ctx  se-gto library context
 * @param apdu APDU command to send
 * @param n    length of APDU command
 * @param resp Response buffer
 * @param r    length of response buffer.
 *
 * @c errno is set on error.
 *
 * @returns number of bytes filled in @c resp buffer. -1 on error.
 *
 * @resp buffer last two bytes are SW1 and SW2 respectively. Response length
 * will always be at least 2 bytes. Maximum response size will be 257 bytes.
 *
 * Slave timeout is used waiting for APDU response. Each Extension Time packet
 * will restart response timeout.
 */
int se_gto_apdu_transmit(struct se_gto_ctx *ctx, const void *apdu, int n, void *resp, int r);


int se_gto_speed(struct se_gto_ctx *ctx,int speed);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* ifndef LIBSE_GTO_H */
