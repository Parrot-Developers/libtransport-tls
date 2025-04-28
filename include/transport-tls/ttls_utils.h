/**
 * Copyright (c) 2021 Parrot Drones SAS
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *   * Neither the name of the Parrot Drones SAS Company nor the
 *     names of its contributors may be used to endorse or promote products
 *     derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE PARROT DRONES SAS COMPANY BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _TTLS_UTILS_H_
#define _TTLS_UTILS_H_

#include <transport-tls/ttls.h>

struct ulog_cookie;


/**
 * Log all SSL recorded errors using implicit tag,
 * ulog.h must be included before this header in order to use this macro.
 * Calling this macro empties the error queue.
 */
#ifdef __ULOG_COOKIE
#	define TTLS_ULOG_ERRORS() ttls_ulog_errors(&__ULOG_COOKIE)
#endif


/**
 * Log all SSL recorded errors using the given tag.
 * Calling this function empties the error queue.
 */
TTLS_API void ttls_ulog_errors(struct ulog_cookie *cookie);


/**
 * Load certificate and private key into a context
 */

TTLS_API int ttls_ctx_use_certificate(struct ssl_ctx_st *ssl_ctx,
				      const char *cert_uri,
				      const char *pkey_uri);


/**
 * Add a single CA to a context
 */

TTLS_API int ttls_ctx_load_ca(struct ssl_ctx_st *ssl_ctx, const char *ca_uri);


/**
 * Add comma separated list of CAs to a context
 */

TTLS_API int ttls_ctx_load_ca_list(struct ssl_ctx_st *ssl_ctx,
				   const char *ca_list);

#endif /* !_TTLS_UTILS_H_ */
