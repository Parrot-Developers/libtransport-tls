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

#ifndef _TTLS_H_
#define _TTLS_H_

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* To be used for all public API */
#ifdef TTLS_API_EXPORTS
#	ifdef _WIN32
#		define TTLS_API __declspec(dllexport)
#	else /* !_WIN32 */
#		define TTLS_API __attribute__((visibility("default")))
#	endif /* !_WIN32 */
#else /* !TSCTP_API_EXPORTS */
#	define TTLS_API
#endif /* !TTLS_API_EXPORTS */

struct tskt_socket;
struct ssl_st; /* SSL */
struct ssl_ctx_st; /* SSL_CTX */


/**
 * Initialize the TLS transport library.
 * This function must be called once by the application
 * before calling any other TLS API function.
 * OpenSSL library must have been initialized before calling
 * this function.
 * @return 0 on success, negative errno value in case of error.
 */
TTLS_API int ttls_init(void);


/**
 * Deinitialize the TLS transport library.
 * This function releases any resource allocated by ttls_init().
 * @return 0 on success, negative errno value in case of error.
 */
TTLS_API int ttls_deinit(void);


/**
 * Create a TLS socket object using the given SSL socket ssl and
 * the transport socket sock.
 * On success the SSL and transport sockets are owned by the TLS
 * socket object that is returned through the ret_obj parameter.
 * When no longer needed, the object must be freed using the
 * tskt_socket_destroy() function, this will also free the
 * used SSL and transport sockets.
 * If the connection is in client mode, the TLS handshake will be
 * automatically started, otherwise the server socket is made ready
 * for accepting a connection.
 * All socket functions can return the -EPROTO error code in case
 * of a SSL protocol error, use ttls_socket_get_last_ssl_error() or
 * ERR_get_error() functions to obtain the detailed SSL error code.
 * @param ssl: SSL socket to use
 * @param sock: transport socket to use
 * @param ret_obj: TLS socket object handle (output)
 * @return 0 on success, negative errno value in case of error
 */
TTLS_API int ttls_socket_new(struct ssl_st *ssl,
			     struct tskt_socket *sock,
			     struct tskt_socket **ret_obj);


/**
 * Create a TLS socket object using the given SSL context ssl_ctx
 * and the transport socket sock.
 * See also ttls_socket_new().
 * @param ssl_ctx: SSL context to use
 * @param sock: transport socket to use
 * @param ret_obj: TLS socket object handle (output)
 * @return 0 on success, negative errno value in case of error
 */
TTLS_API int ttls_socket_new_with_ctx(struct ssl_ctx_st *ssl_ctx,
				      struct tskt_socket *sock,
				      struct tskt_socket **ret_obj);


/**
 * Get the SSL socket used by the TLS socket.
 * @param self: TLS socket object handle
 * @return SSL socket on success, NULL in case of error
 */
TTLS_API struct ssl_st *ttls_socket_get_ssl(struct tskt_socket *self);


/**
 * Get the transport socket used by the TLS socket.
 * @param self: TLS socket object handle
 * @return transport socket on success, NULL in case of error
 */
TTLS_API struct tskt_socket *ttls_socket_get_socket(struct tskt_socket *self);


/**
 * Get the last SSL error that occured on the TLS socket.
 * @param self: TLS socket object handle
 * @return SSL error code, 0 if no SSL error has occured,
 *         (-1) if self is not a TLS socket
 */
TTLS_API unsigned long ttls_socket_get_last_ssl_error(struct tskt_socket *self);


/**
 * Shutdown an active TLS connection, this sends the close_notify
 * shutdown alert to the peer.
 * @param self: TLS socket object handle
 * @return 0 on success, negative errno value in case of error
 */
TTLS_API int ttls_socket_shutdown(struct tskt_socket *self);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* !_TTLS_H_ */
