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

#include <errno.h>
#include <transport-socket/tskt.h>

#include "ttls_bio.h"

#define ULOG_TAG ttls_bio
#include <ulog.h>
ULOG_DECLARE_TAG(ttls_bio);

#define TTLS_BIO_NAME "libtransport-tls socket"

/* Added in OpenSSL 1.1.1e */
#ifndef BIO_FLAGS_IN_EOF
#	define BIO_FLAGS_IN_EOF 0x800
#endif

static bool ttls_bio_should_retry(int err)
{
	switch (err) {
	case EAGAIN:
	case EINPROGRESS:
	case EINTR:
	case ENOTCONN:
		return true;
	default:
		return false;
	}
}

static int ttls_bio_read(BIO *b, char *buf, int len)
{
	struct tskt_socket *sock = (struct tskt_socket *)BIO_get_data(b);
	int ret;

	/* check parameters */
	if (!sock || !buf || len <= 0) {
		ULOG_ERRNO("ttls_bio_read", EINVAL);
		return -1;
	}

	/* clear BIO retry flags */
	BIO_clear_retry_flags(b);

	/* read data from transport socket */
	ret = tskt_socket_read(sock, buf, len, NULL);
	if (ret < 0) {
		if (ttls_bio_should_retry(-ret))
			BIO_set_retry_read(b);
		errno = -ret;
	} else if (ret == 0) {
		BIO_set_flags(b, BIO_FLAGS_IN_EOF);
	}
	return ret >= 0 ? ret : -1;
}

static int ttls_bio_write(BIO *b, const char *buf, int len)
{
	struct tskt_socket *sock = (struct tskt_socket *)BIO_get_data(b);
	int ret;

	/* check parameters */
	if (!sock || !buf || len <= 0) {
		ULOG_ERRNO("ttls_bio_write", EINVAL);
		return -1;
	}

	/* clear BIO retry flags */
	BIO_clear_retry_flags(b);

	/* write data to transport socket */
	ret = tskt_socket_write(sock, buf, len);
	if (ret < 0) {
		if (ttls_bio_should_retry(-ret))
			BIO_set_retry_write(b);
		errno = -ret;
	}
	return ret >= 0 ? ret : -1;
}

static long ttls_bio_ctrl(BIO *b, int cmd, long num, void *ptr)
{
	int ret = 1;

	switch (cmd) {
	case BIO_CTRL_GET_CLOSE:
		ret = BIO_get_shutdown(b);
		break;
	case BIO_CTRL_SET_CLOSE:
		BIO_set_shutdown(b, (int)num);
		break;
	case BIO_CTRL_FLUSH:
		ret = 1;
		break;
	case BIO_CTRL_EOF:
		ret = BIO_test_flags(b, BIO_FLAGS_IN_EOF) != 0 ? 1 : 0;
		break;
	default:
		ret = 0;
		break;
	}
	return ret;
}

static int ttls_bio_create(BIO *b)
{
	return 1;
}

static int ttls_bio_destroy(BIO *b)
{
	if (b == NULL)
		return 0;
	if (BIO_get_shutdown(b)) {
		struct tskt_socket *sock =
			(struct tskt_socket *)BIO_get_data(b);
		if (sock != NULL)
			tskt_socket_destroy(sock);
	}
	return 1;
}

static BIO_METHOD *ttls_bio_method_ptr;

int ttls_bio_method_init(void)
{
	ttls_bio_method_ptr = BIO_meth_new(BIO_get_new_index(), TTLS_BIO_NAME);
	if (!ttls_bio_method_ptr) {
		ULOGC("ttls_bio_method_init: cannot create method");
		return -ENOMEM;
	}
	BIO_meth_set_write(ttls_bio_method_ptr, ttls_bio_write);
	BIO_meth_set_read(ttls_bio_method_ptr, ttls_bio_read);
	BIO_meth_set_ctrl(ttls_bio_method_ptr, ttls_bio_ctrl);
	BIO_meth_set_create(ttls_bio_method_ptr, ttls_bio_create);
	BIO_meth_set_destroy(ttls_bio_method_ptr, ttls_bio_destroy);
	return 0;
}

void ttls_bio_method_deinit(void)
{
	BIO_meth_free(ttls_bio_method_ptr);
}

BIO *ttls_bio_new(struct tskt_socket *sock)
{
	BIO *bio = BIO_new(ttls_bio_method_ptr);
	if (!bio) {
		ULOGE("ttls_bio_new: failed to create BIO");
		return NULL;
	}
	BIO_set_data(bio, sock);
	BIO_set_init(bio, 1);
	return bio;
}
