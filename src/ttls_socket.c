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

#include <libpomp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdbool.h>
#include <transport-packet/tpkt.h>
#include <transport-socket/tskt_ops.h>
#include <transport-tls/ttls.h>

#include "ttls_async.h"
#include "ttls_bio.h"

#define ULOG_TAG ttls_socket
#include <ulog.h>
ULOG_DECLARE_TAG(ttls_socket);

/* max nb of async file descriptors,
 * should be enough in all cases */
#define MAX_ASYNC_FDS 8

/* set write buffer size to max TLS record size (16KB)
 * minus some space for header and MAC */
#define TTLS_WRITE_MAX (16384 - 256)

struct ttls_socket {
	struct tskt_socket sock;
	struct tskt_socket *tsock;
	struct pomp_loop *loop;
	SSL *ssl;
	int async_fds[MAX_ASYNC_FDS];
	size_t async_fds_count;
	/* active events to report to application callback */
	uint32_t events;
	/* events to wait for on the transport socket after a SSL read
	 * has returned WANT_READ or WANT_WRITE, will report EVENT_IN */
	uint32_t in_events;
	/* events to wait for on the transport socket after a SSL write
	 * has returned WANT_READ or WANT_WRITE, will report EVENT_OUT */
	uint32_t out_events;
	/* events to report after a SSL function has returned WANT_ASYNC */
	uint32_t async_events;
	/* events set by socket_set_event_cb/socket_update_events */
	uint32_t user_events;
	bool handshake_done;
	bool do_shutdown;
	bool notify;
	struct pomp_evt *notify_event;
	int error;
	unsigned long ssl_error;
	tskt_socket_event_cb_t cb;
	void *userdata;
	const void *wptr;
	size_t wlen;
	struct tpkt_packet *wpkt;
	char wbuf[TTLS_WRITE_MAX];
};

static int ttls_socket_destroy(struct tskt_socket *sock);
static struct pomp_loop *ttls_socket_get_loop(struct tskt_socket *sock);
static int ttls_socket_get_fd(struct tskt_socket *sock);
static int ttls_socket_set_fd_cb(struct tskt_socket *sock,
				 pomp_fd_event_cb_t fd_cb,
				 void *userdata);
static int ttls_socket_get_local_addr(struct tskt_socket *sock,
				      char *str,
				      size_t len,
				      uint16_t *port);
static int ttls_socket_get_remote_addr(struct tskt_socket *sock,
				       char *str,
				       size_t len,
				       uint16_t *port);
static int ttls_socket_set_remote_addr(struct tskt_socket *sock,
				       const char *addr,
				       uint16_t port);
static int ttls_socket_get_option(struct tskt_socket *sock,
				  enum tskt_option option);
static int ttls_socket_set_option(struct tskt_socket *sock,
				  enum tskt_option option,
				  int value);
static ssize_t ttls_socket_read(struct tskt_socket *sock,
				void *buf,
				size_t cap,
				uint64_t *ts_us);
static ssize_t
ttls_socket_write(struct tskt_socket *sock, const void *buf, size_t len);
static ssize_t ttls_socket_readv(struct tskt_socket *sock,
				 const struct iovec *iov,
				 size_t iov_len,
				 uint64_t *ts_us);
static ssize_t ttls_socket_writev(struct tskt_socket *sock,
				  const struct iovec *iov,
				  size_t iov_len);
static int ttls_socket_read_pkt(struct tskt_socket *sock,
				struct tpkt_packet *pkt);
static int ttls_socket_write_pkt(struct tskt_socket *sock,
				 struct tpkt_packet *pkt);
static int ttls_socket_set_event_cb(struct tskt_socket *sock,
				    uint32_t events,
				    tskt_socket_event_cb_t cb,
				    void *userdata);
static int ttls_socket_update_events(struct tskt_socket *sock,
				     uint32_t events_to_add,
				     uint32_t events_to_remove);

static const struct tskt_socket_ops ttls_socket_ops = {
	.destroy = ttls_socket_destroy,
	.get_loop = ttls_socket_get_loop,
	.get_local_addr = ttls_socket_get_local_addr,
	.get_remote_addr = ttls_socket_get_remote_addr,
	.get_option = ttls_socket_get_option,
	.set_option = ttls_socket_set_option,
	.read = ttls_socket_read,
	.write = ttls_socket_write,
	.readv = ttls_socket_readv,
	.writev = ttls_socket_writev,
	.read_pkt = ttls_socket_read_pkt,
	.write_pkt = ttls_socket_write_pkt,
	.set_event_cb = ttls_socket_set_event_cb,
	.update_events = ttls_socket_update_events,
};


static void async_wait_fds_remove(struct ttls_socket *ttls, int nofd);

static int ttls_io_return(struct ttls_socket *ttls, int ret, uint32_t events);

static int
ttls_socket_raw_write(struct ttls_socket *ttls, const void *buf, size_t len);


static void ttls_update_events(struct ttls_socket *ttls)
{
	/* check if some user events are signaled */
	bool notify = (ttls->events & ttls->user_events) != 0;

	if (notify == ttls->notify)
		return; /* no change */

	/* update state of notification event fd */
	ttls->notify = notify;
	int ret;
	if (notify)
		ret = pomp_evt_signal(ttls->notify_event);
	else
		ret = pomp_evt_clear(ttls->notify_event);
	if (ret < 0)
		ULOG_ERRNO("pomp_evt_%s", -ret, notify ? "signal" : "clear");
}


static void ttls_notify_event_cb(struct pomp_evt *evt, void *userdata)
{
	struct ttls_socket *ttls = userdata;
	int ret;

	if (ttls->cb == NULL || ttls->events == 0) {
		ULOGW("spurious notify event");
		ttls->notify = false;
		return;
	}

	/* rearm event (events must be explicitely cleared by application) */
	ret = pomp_evt_signal(ttls->notify_event);
	if (ret < 0)
		ULOG_ERRNO("pomp_evt_signal", -ret);

	/* user events processing callback */
	ttls->cb(&ttls->sock, ttls->events, ttls->userdata);
}


static void ttls_flush_write(struct ttls_socket *ttls)
{
	/* try to write pending data if any */
	if (ttls->wlen == 0)
		return;

	if (ttls_socket_raw_write(ttls, ttls->wbuf, ttls->wlen) < 0)
		return;

	ttls->wlen = 0;
	if (ttls->wpkt != NULL) {
		tpkt_unref(ttls->wpkt);
		ttls->wpkt = NULL;
	}

	/* check for pending shutdown */
	if (ttls->do_shutdown)
		(void)ttls_socket_shutdown(&ttls->sock);
}


static void ttls_check_handshake(struct ttls_socket *ttls)
{
	/* get handshake status */
	(void)ttls_io_return(ttls,
			     SSL_do_handshake(ttls->ssl),
			     POMP_FD_EVENT_IN | POMP_FD_EVENT_OUT);

	ttls_update_events(ttls);
}


static void
tsock_event_cb(struct tskt_socket *self, uint32_t revents, void *userdata)
{
	struct ttls_socket *ttls = userdata;

	/* clear events */
	tskt_socket_update_events(ttls->tsock, 0, revents);

	if (revents & POMP_FD_EVENT_ERR) {
		/* socket error, remove handler */
		tskt_socket_set_event_cb(ttls->tsock, 0, NULL, NULL);
		if (ttls->error == 0)
			ttls->error = tskt_socket_get_error(ttls->tsock);
		ttls->events |= POMP_FD_EVENT_ERR;
	}
	if (revents & ttls->in_events) {
		ttls->in_events &= ~revents;
		ttls->events |= POMP_FD_EVENT_IN;
	}
	if (revents & ttls->out_events) {
		ttls->out_events &= ~revents;
		ttls->events |= POMP_FD_EVENT_OUT;
		ttls_flush_write(ttls);
	}

	if (!ttls->handshake_done)
		ttls_check_handshake(ttls);
	else
		ttls_update_events(ttls);
}


static void async_cb(int fd, void *userdata)
{
	struct ttls_socket *ttls = userdata;

	/* remove other fds, the signaled one
	 * is automatically removed by ttls_async */
	async_wait_fds_remove(ttls, fd);

	uint32_t events = ttls->async_events;
	ttls->async_events = 0;

	if (events == 0)
		return;

	ttls->events |= events;

	ttls_check_handshake(ttls);
}


static void async_wait_fds_remove(struct ttls_socket *ttls, int nofd)
{
	size_t i;

	/* remove all fds except the one specified by nofd */
	for (i = 0; i < ttls->async_fds_count; i++) {
		if (ttls->async_fds[i] != nofd)
			ttls_async_wait_fd_remove(
				ttls->loop, ttls->async_fds[i], async_cb, ttls);
	}

	/* clear the whole list, nofd was already removed by caller */
	ttls->async_fds_count = 0;
}


static int ttls_want_async(struct ttls_socket *ttls, uint32_t events)
{
#ifdef _WIN32
	ULOGE("async not supported under win32");
	return -EPROTO;
#else
	size_t async_fds_count;
	size_t i;

	/* get number of file descriptor */
	if (!SSL_get_all_async_fds(ttls->ssl, NULL, &async_fds_count)) {
		ULOGE("SSL_get_all_async_fds() "
		      "failed to retrieve async fds count");
		return -EPROTO;
	}

	/* no async fds ? */
	if (async_fds_count == 0) {
		ULOGW("SSL_get_all_async_fds() "
		      "returned no file descriptor !");
		return -EPROTO;
	}

	/* too many fds? */
	if (async_fds_count > MAX_ASYNC_FDS) {
		ULOGW("SSL_get_all_async_fds() "
		      "returned too many file descriptors");
		return -ENOMEM;
	}

	if (!SSL_get_all_async_fds(
		    ttls->ssl, ttls->async_fds, &async_fds_count)) {
		ULOGE("SSL_get_all_async_fds() "
		      "failed to retrieve async fds");
		return -EPROTO;
	}
	ttls->async_fds_count = 0;

	for (i = 0; i < async_fds_count; i++, ttls->async_fds_count++) {
		int err = ttls_async_wait_fd_add(
			ttls->loop, ttls->async_fds[i], async_cb, ttls);
		if (err < 0)
			return err;
	}

	ttls->async_events |= events;
	return -EAGAIN;
#endif
}


static int ttls_io_return(struct ttls_socket *ttls, int ret, uint32_t events)
{
	if (ret <= 0) {
		uint32_t tevents = 0;
		/* get SSL error */
		switch (SSL_get_error(ttls->ssl, ret)) {
		case SSL_ERROR_NONE:
		case SSL_ERROR_ZERO_RETURN:
			ERR_clear_error();
			ret = 0;
			break;
		case SSL_ERROR_WANT_READ:
			ERR_clear_error();
			tevents = POMP_FD_EVENT_IN;
			ret = -EAGAIN;
			break;
		case SSL_ERROR_WANT_WRITE:
			ERR_clear_error();
			tevents = POMP_FD_EVENT_OUT;
			ret = -EAGAIN;
			break;
		case SSL_ERROR_WANT_ASYNC:
			ERR_clear_error();
			if (ttls->handshake_done) {
				/* async mode should have been disabled
				 * after the handshake completion */
				ULOGE("invalid WANT_ASYNC return");
				ret = -EINVAL;
			} else {
				ret = ttls_want_async(ttls, events);
			}
			break;
		case SSL_ERROR_SYSCALL:
			ret = -errno;
			break;
		case SSL_ERROR_SSL:
			ttls->ssl_error = ERR_peek_last_error();
			/* fallthrough */
		default:
			ret = -EPROTO;
			break;
		}
		if (tevents != 0) {
			/* update transport socket events */
			tskt_socket_update_events(ttls->tsock, tevents, 0);
			if (events & POMP_FD_EVENT_IN)
				ttls->in_events |= tevents;
			if (events & POMP_FD_EVENT_OUT)
				ttls->out_events |= tevents;
		}
	} else {
		ERR_clear_error();
	}
	/* update tls socket events to report */
	if (ret == -EAGAIN) {
		ttls->events &= ~events;
	} else {
		if (!ttls->handshake_done) {
			/* handshake completed or failed */
			ttls->handshake_done = true;
			/* keep only async mode during handshake */
			SSL_clear_mode(ttls->ssl, SSL_MODE_ASYNC);
		}
		if (ret < 0) {
			if (ttls->error == 0)
				ttls->error = -ret;
			ttls->events |= POMP_FD_EVENT_ERR;
		} else {
			ttls->events |= events;
		}
	}

	ttls_update_events(ttls);

	return ret;
}


int ttls_socket_new(struct ssl_st *ssl,
		    struct tskt_socket *sock,
		    struct tskt_socket **ret_obj)
{
	struct ttls_socket *ttls;
	int ret;
	BIO *bio;

	/* check arguments */
	if (!ssl || !sock || !ret_obj) {
		ULOGE("new: invalid arguments");
		return -EINVAL;
	}

	/* allocate socket data */
	ttls = calloc(1, sizeof(*ttls));
	if (!ttls) {
		ULOGE("new: failed to allocate socket");
		return -ENOMEM;
	}

	/* initialize socket data */
	ttls->sock.ops = &ttls_socket_ops;
	ttls->ssl = ssl;
	ttls->tsock = sock;
	ttls->loop = tskt_socket_get_loop(sock);
	if (!ttls->loop) {
		ULOGE("new: invalid transport socket (NULL pomp loop)");
		ret = -EINVAL;
		goto error;
	}
	ret = tskt_socket_set_event_cb(sock, 0, tsock_event_cb, ttls);
	if (ret < 0) {
		ULOG_ERRNO("new: tskt_socket_set_event_cb", -ret);
		goto error;
	}

	/* create notification event */
	ttls->notify_event = pomp_evt_new();
	if (!ttls->notify_event) {
		ret = -ENOMEM;
		ULOG_ERRNO("pomp_evt_new", -ret);
		goto error;
	}
	ret = pomp_evt_attach_to_loop(
		ttls->notify_event, ttls->loop, ttls_notify_event_cb, ttls);
	if (ret < 0) {
		ULOG_ERRNO("pomp_evt_attach_to_loop", -ret);
		goto error;
	}

	/* allow to set different buffer pointer after WANT_READ/WRITE */
	SSL_set_mode(ttls->ssl, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

#if !defined(__ANDROID__) && !defined(_WIN32)
	/* allow async mode during handshake */
	SSL_set_mode(ttls->ssl, SSL_MODE_ASYNC);
#endif

	/* create BIO (on success socket is own by bio) */
	bio = ttls_bio_new(sock);
	if (!bio) {
		ULOGE("new: failed to create BIO");
		ret = -ENOMEM;
		goto error;
	}
	SSL_set_bio(ttls->ssl, bio, bio);

	/* start handshake */
	if (SSL_is_server(ttls->ssl))
		SSL_set_accept_state(ttls->ssl);
	else
		SSL_set_connect_state(ttls->ssl);
	ret = ttls_io_return(ttls,
			     SSL_do_handshake(ttls->ssl),
			     POMP_FD_EVENT_IN | POMP_FD_EVENT_OUT);
	if (ret != 0 && ret != -EAGAIN) {
		ULOGE("new: do handshake failed");
		/* do not release socket when freeing BIO */
		BIO_set_shutdown(bio, 0);
		goto error;
	}

	*ret_obj = &ttls->sock;
	return 0;

error:
	tskt_socket_set_event_cb(sock, 0, NULL, NULL);
	async_wait_fds_remove(ttls, -1);
	if (ttls->notify_event) {
		if (pomp_evt_is_attached(ttls->notify_event, ttls->loop))
			(void)pomp_evt_detach_from_loop(ttls->notify_event,
							ttls->loop);
		(void)pomp_evt_destroy(ttls->notify_event);
	}
	free(ttls);
	return ret;
}


int ttls_socket_new_with_ctx(struct ssl_ctx_st *ssl_ctx,
			     struct tskt_socket *sock,
			     struct tskt_socket **ret_obj)
{
	/* check arguments */
	if (!ssl_ctx || !sock || !ret_obj) {
		ULOGE("new_with_ctx: invalid arguments");
		return -EINVAL;
	}

	SSL *ssl = SSL_new(ssl_ctx);
	if (ssl == NULL) {
		ULOGE("SSL_new failed");
		return -EPROTO;
	}
	int res = ttls_socket_new(ssl, sock, ret_obj);
	if (res < 0) {
		SSL_free(ssl);
		return res;
	}
	return 0;
}


static int ttls_socket_destroy(struct tskt_socket *self)
{
	struct ttls_socket *ttls = (struct ttls_socket *)self;

	/* reset transport socket if some data has not been transmitted */
	if (ttls->wlen != 0)
		(void)tskt_socket_set_reset(ttls->tsock, 1);

	/* release resources */
	tskt_socket_set_event_cb(ttls->tsock, 0, NULL, NULL);

	async_wait_fds_remove(ttls, -1);

	SSL_free(ttls->ssl);

	(void)pomp_evt_detach_from_loop(ttls->notify_event, ttls->loop);
	(void)pomp_evt_destroy(ttls->notify_event);

	if (ttls->wpkt)
		tpkt_unref(ttls->wpkt);

	free(ttls);
	return 0;
}


static struct pomp_loop *ttls_socket_get_loop(struct tskt_socket *sock)
{
	struct ttls_socket *ttls = (struct ttls_socket *)sock;

	return ttls->loop;
}


static int ttls_socket_get_local_addr(struct tskt_socket *self,
				      char *str,
				      size_t len,
				      uint16_t *port)
{
	struct ttls_socket *ttls = (struct ttls_socket *)self;

	/* return local address of transport socket */
	return ttls->tsock->ops->get_local_addr(ttls->tsock, str, len, port);
}


static int ttls_socket_get_remote_addr(struct tskt_socket *self,
				       char *str,
				       size_t len,
				       uint16_t *port)
{
	struct ttls_socket *ttls = (struct ttls_socket *)self;

	/* return remote address of transport socket */
	return ttls->tsock->ops->get_remote_addr(ttls->tsock, str, len, port);
}


static int ttls_socket_get_option(struct tskt_socket *self,
				  enum tskt_option option)
{
	struct ttls_socket *ttls = (struct ttls_socket *)self;

	switch (option) {
	case TSKT_OPT_ERROR:
		return ttls->error;
	default:
		/* get option of transport socket */
		return ttls->tsock->ops->get_option(ttls->tsock, option);
	}
}


static int ttls_socket_set_option(struct tskt_socket *self,
				  enum tskt_option option,
				  int value)
{
	struct ttls_socket *ttls = (struct ttls_socket *)self;

	/* set option of transport socket */
	return ttls->tsock->ops->set_option(ttls->tsock, option, value);
}


static int ttls_socket_set_event_cb(struct tskt_socket *self,
				    uint32_t events,
				    tskt_socket_event_cb_t cb,
				    void *userdata)
{
	struct ttls_socket *ttls = (struct ttls_socket *)self;

	ttls->cb = cb;
	if (cb == NULL) {
		ttls->user_events = 0;
	} else {
		ttls->userdata = userdata;
		events &= POMP_FD_EVENT_IN | POMP_FD_EVENT_OUT;
		ttls->user_events = POMP_FD_EVENT_ERR | events;
	}

	ttls_update_events(ttls);

	return 0;
}


static int ttls_socket_update_events(struct tskt_socket *self,
				     uint32_t events_to_add,
				     uint32_t events_to_remove)
{
	struct ttls_socket *ttls = (struct ttls_socket *)self;

	if (ttls->cb == NULL)
		return 0;

	events_to_add &= POMP_FD_EVENT_IN | POMP_FD_EVENT_OUT;
	events_to_remove &= POMP_FD_EVENT_IN | POMP_FD_EVENT_OUT;

	ttls->user_events |= events_to_add;
	ttls->user_events &= ~events_to_remove;

	ttls_update_events(ttls);

	return 0;
}


static ssize_t ttls_socket_read(struct tskt_socket *self,
				void *buf,
				size_t len,
				uint64_t *ts_us)
{
	struct ttls_socket *ttls = (struct ttls_socket *)self;

	ULOG_ERRNO_RETURN_ERR_IF(buf == NULL, EINVAL);
	ULOG_ERRNO_RETURN_ERR_IF(len == 0, EINVAL);

	/* check for handshake completion */
	if (!ttls->handshake_done)
		return -EAGAIN;

	int ret = SSL_read(ttls->ssl, buf, len);
	ret = ttls_io_return(ttls, ret, POMP_FD_EVENT_IN);
	if (ts_us && ret >= 0)
		*ts_us = 0;
	return ret;
}


static ssize_t ttls_socket_readv(struct tskt_socket *self,
				 const struct iovec *iov,
				 size_t iov_len,
				 uint64_t *ts_us)
{
	ULOG_ERRNO_RETURN_ERR_IF(iov_len == 0, EINVAL);
	ULOG_ERRNO_RETURN_ERR_IF(iov[0].iov_len == 0, EINVAL);

	/* XXX there is no SSL_readv */
	return ttls_socket_read(self, iov[0].iov_base, iov[0].iov_len, ts_us);
}


static int
ttls_socket_raw_write(struct ttls_socket *ttls, const void *buf, size_t len)
{
	ULOG_ERRNO_RETURN_ERR_IF(len > INT_MAX, EMSGSIZE);

	int ret = SSL_write(ttls->ssl, buf, (int)len);
	return ttls_io_return(ttls, ret, POMP_FD_EVENT_OUT);
}


static ssize_t
ttls_socket_write(struct tskt_socket *self, const void *buf, size_t len)
{
	struct ttls_socket *ttls = (struct ttls_socket *)self;

	ULOG_ERRNO_RETURN_ERR_IF(len == 0, EINVAL);

	/* check for handhshake completion or write data pending */
	if (!ttls->handshake_done || ttls->wlen != 0)
		return -EAGAIN;

	if (len > TTLS_WRITE_MAX)
		len = TTLS_WRITE_MAX;

	int ret = ttls_socket_raw_write(ttls, buf, len);
	if (ret == -EAGAIN) {
		/* copy data for calling SSL_write again */
		memcpy(ttls->wbuf, buf, len);
		ttls->wptr = ttls->wbuf;
		ttls->wlen = len;
		ret = len;
	}
	return ret;
}


static ssize_t ttls_socket_writev(struct tskt_socket *self,
				  const struct iovec *iov,
				  size_t iov_len)
{
	struct ttls_socket *ttls = (struct ttls_socket *)self;

	ULOG_ERRNO_RETURN_ERR_IF(iov_len == 0, EINVAL);

	if (iov_len == 1)
		return ttls_socket_write(self, iov[0].iov_base, iov[0].iov_len);

	/* check for handhshake completion or write data pending */
	if (!ttls->handshake_done || ttls->wlen != 0)
		return -EAGAIN;

	/* copy data to write buffer */
	size_t total = 0;
	char *p = ttls->wbuf;
	size_t i;
	for (i = 0; i < iov_len; i++) {
		size_t len = iov[i].iov_len;
		if (len == 0)
			continue;
		total += len;
		if (total > TTLS_WRITE_MAX) {
			len -= TTLS_WRITE_MAX - total;
			total = TTLS_WRITE_MAX;
		}
		memcpy(p, iov[i].iov_base, len);
		if (total == TTLS_WRITE_MAX)
			break;
		p += len;
	}
	ULOG_ERRNO_RETURN_ERR_IF(total == 0, EINVAL);
	int ret = ttls_socket_raw_write(ttls, ttls->wbuf, total);
	if (ret == -EAGAIN) {
		ttls->wptr = ttls->wbuf;
		ttls->wlen = total;
		ret = total;
	}
	return ret;
}


static int ttls_socket_read_pkt(struct tskt_socket *self,
				struct tpkt_packet *pkt)
{
	struct ttls_socket *ttls = (struct ttls_socket *)self;

	/* check arguments */
	ULOG_ERRNO_RETURN_ERR_IF(!pkt, EINVAL);

	/* check for handshake completion */
	if (!ttls->handshake_done)
		return -EAGAIN;

	/* get receive buffer */
	void *data;
	size_t maxlen;
	int iret = tpkt_get_data(pkt, &data, NULL, &maxlen);
	if (iret < 0)
		return iret;
	ULOG_ERRNO_RETURN_ERR_IF(maxlen == 0, EINVAL);

	ssize_t ret = ttls_socket_read(self, data, maxlen, NULL);
	if (ret < 0)
		return (int)ret;

	tpkt_set_len(pkt, (size_t)ret);

	return 0;
}


static int ttls_socket_write_pkt(struct tskt_socket *self,
				 struct tpkt_packet *pkt)
{
	struct ttls_socket *ttls = (struct ttls_socket *)self;

	/* check arguments */
	ULOG_ERRNO_RETURN_ERR_IF(!pkt, EINVAL);

	/* check for handhshake completion or write data pending */
	if (!ttls->handshake_done || ttls->wlen != 0)
		return -EAGAIN;

	/* get buffer to send */
	const void *data;
	size_t len;
	int iret = tpkt_get_cdata(pkt, &data, &len, NULL);
	if (iret < 0)
		return iret;
	ULOG_ERRNO_RETURN_ERR_IF(len == 0, EINVAL);

	/* send data */
	ssize_t ret = ttls_socket_raw_write(ttls, data, len);
	if (ret < 0) {
		if (ret == -EAGAIN) {
			/* store reference to packet */
			ttls->wptr = data;
			ttls->wlen = len;
			ttls->wpkt = pkt;
			tpkt_ref(pkt);
			ret = 0;
		}
		return (int)ret;
	}

	return 0;
}


struct ssl_st *ttls_socket_get_ssl(struct tskt_socket *self)
{
	struct ttls_socket *ttls = (struct ttls_socket *)self;

	if (!self || self->ops != &ttls_socket_ops)
		return NULL;

	return ttls->ssl;
}


struct tskt_socket *ttls_socket_get_socket(struct tskt_socket *self)
{
	struct ttls_socket *ttls = (struct ttls_socket *)self;

	if (!self || self->ops != &ttls_socket_ops)
		return NULL;

	return ttls->tsock;
}


unsigned long ttls_socket_get_last_ssl_error(struct tskt_socket *self)
{
	struct ttls_socket *ttls = (struct ttls_socket *)self;

	if (!self || self->ops != &ttls_socket_ops)
		return (unsigned long)-1;

	return ttls->ssl_error;
}


int ttls_socket_shutdown(struct tskt_socket *self)
{
	struct ttls_socket *ttls = (struct ttls_socket *)self;

	if (!self || self->ops != &ttls_socket_ops)
		return -EINVAL;

	/* check for handhshake completion or write data pending */
	if (!ttls->handshake_done || ttls->wlen != 0) {
		/* we must write pending data before doing shutdown */
		ttls->do_shutdown = true;
		return -EAGAIN;
	}

	return ttls_io_return(ttls, SSL_shutdown(ttls->ssl), POMP_FD_EVENT_OUT);
}
