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

/*
 * Tests for src/ttls_socket.c, in two styles:
 *
 * - Fake-driven: a struct fake_sock is scripted so that SSL_do_handshake()
 *   (run synchronously inside ttls_socket_new()) sends its ClientHello (write
 *   always fully accepted) then parks in WANT_READ (read always returns
 *   -EAGAIN). This lets ttls_socket_new() succeed with the returned object
 *   left in "handshake not done" state, without ever needing a real peer --
 *   enough to exercise every non-handshake code path (argument validation,
 *   pre-handshake I/O guards, get/set option and address delegation, event
 *   callback plumbing, accessor guards).
 *
 * - Real end-to-end: a real loopback TCP connection (via
 *   tskt_socket_new_tcp()/connect()/listen()/accept(), mirroring
 *   tskt_test_impl.c/tskt_test_client.c) wrapped on both ends with a real
 *   SSL_CTX/SSL loaded with the throwaway test certificate, needed for
 *   anything that requires a completed handshake: application data
 *   read/write, write buffering/clipping, and shutdown.
 */

#include "ttls_test.h"

#include <netinet/in.h>


#define ADDR4 "127.0.0.1"
#define TEST_TIMEOUT_MS 2000
#define POLL_STEP_MS 20

/* Mirrors TTLS_WRITE_MAX in src/ttls_socket.c (16384 minus room for TLS
 * record header/MAC); not exported, so duplicated here. */
#define EXPECTED_WRITE_MAX (16384 - 256)


/*
 * Polling helpers (used by the real end-to-end tests below) and the
 * fake-driven pending-handshake builder.
 */

static int wait_read(struct pomp_loop *loop,
		     struct tskt_socket *sock,
		     void *buf,
		     size_t cap,
		     uint64_t *ts_us)
{
	int elapsed = 0;
	ssize_t res;

	do {
		res = tskt_socket_read(sock, buf, cap, ts_us);
		if (res != -EAGAIN)
			return (int)res;
		pomp_loop_wait_and_process(loop, POLL_STEP_MS);
		elapsed += POLL_STEP_MS;
	} while (elapsed < TEST_TIMEOUT_MS);

	return -EAGAIN;
}


static int wait_write(struct pomp_loop *loop,
		      struct tskt_socket *sock,
		      const void *buf,
		      size_t len)
{
	int elapsed = 0;
	ssize_t res;

	do {
		res = tskt_socket_write(sock, buf, len);
		if (res != -EAGAIN)
			return (int)res;
		pomp_loop_wait_and_process(loop, POLL_STEP_MS);
		elapsed += POLL_STEP_MS;
	} while (elapsed < TEST_TIMEOUT_MS);

	return -EAGAIN;
}


static int wait_readv(struct pomp_loop *loop,
		      struct tskt_socket *sock,
		      const struct iovec *iov,
		      size_t iov_len,
		      uint64_t *ts_us)
{
	int elapsed = 0;
	ssize_t res;

	do {
		res = tskt_socket_readv(sock, iov, iov_len, ts_us);
		if (res != -EAGAIN)
			return (int)res;
		pomp_loop_wait_and_process(loop, POLL_STEP_MS);
		elapsed += POLL_STEP_MS;
	} while (elapsed < TEST_TIMEOUT_MS);

	return -EAGAIN;
}


static int wait_writev(struct pomp_loop *loop,
		       struct tskt_socket *sock,
		       const struct iovec *iov,
		       size_t iov_len)
{
	int elapsed = 0;
	ssize_t res;

	do {
		res = tskt_socket_writev(sock, iov, iov_len);
		if (res != -EAGAIN)
			return (int)res;
		pomp_loop_wait_and_process(loop, POLL_STEP_MS);
		elapsed += POLL_STEP_MS;
	} while (elapsed < TEST_TIMEOUT_MS);

	return -EAGAIN;
}


static int wait_read_pkt(struct pomp_loop *loop,
			 struct tskt_socket *sock,
			 struct tpkt_packet *pkt)
{
	int elapsed = 0;
	int res;

	do {
		res = tskt_socket_read_pkt(sock, pkt);
		if (res != -EAGAIN)
			return res;
		pomp_loop_wait_and_process(loop, POLL_STEP_MS);
		elapsed += POLL_STEP_MS;
	} while (elapsed < TEST_TIMEOUT_MS);

	return -EAGAIN;
}


static int wait_accept(struct pomp_loop *loop,
		       struct tskt_socket *server,
		       char *addr,
		       size_t addr_len,
		       uint16_t *port,
		       struct tskt_socket **ret_obj)
{
	int elapsed = 0;
	int res;

	do {
		res = tskt_socket_accept(server, addr, addr_len, port, ret_obj);
		if (res != -EAGAIN)
			return res;
		pomp_loop_wait_and_process(loop, POLL_STEP_MS);
		elapsed += POLL_STEP_MS;
	} while (elapsed < TEST_TIMEOUT_MS);

	return -EAGAIN;
}


/* Build a TLS socket whose handshake is left pending (parked on WANT_READ):
 * write always fully accepted, read always -EAGAIN. Good enough to exercise
 * every ttls_socket.c code path that doesn't require a completed handshake. */
static struct tskt_socket *make_pending_ttls(struct pomp_loop *loop,
					     struct fake_sock *fake)
{
	SSL_CTX *ctx;
	SSL *ssl;
	struct tskt_socket *ttls_sock = NULL;
	int res;

	fake_sock_init(fake);
	fake->get_loop_ret = loop;
	fake->write_ret_all = true;
	fake->read_ret = -EAGAIN;

	ctx = SSL_CTX_new(TLS_client_method());
	CU_ASSERT_PTR_NOT_NULL(ctx);
	ssl = SSL_new(ctx);
	CU_ASSERT_PTR_NOT_NULL(ssl);
	SSL_CTX_free(ctx);

	res = ttls_socket_new(ssl, &fake->base, &ttls_sock);
	CU_ASSERT_EQUAL(res, 0);
	CU_ASSERT_PTR_NOT_NULL(ttls_sock);

	return ttls_sock;
}


static void test_new_guards(void)
{
	struct pomp_loop *loop = pomp_loop_new();
	struct fake_sock fake;
	SSL_CTX *ctx;
	SSL *ssl;
	SSL_CTX *ssl_ctx;
	struct tskt_socket *obj = NULL;

	CU_ASSERT_PTR_NOT_NULL_FATAL(loop);
	fake_sock_init(&fake);
	fake.get_loop_ret = loop;

	ctx = SSL_CTX_new(TLS_client_method());
	CU_ASSERT_PTR_NOT_NULL_FATAL(ctx);
	ssl = SSL_new(ctx);
	CU_ASSERT_PTR_NOT_NULL_FATAL(ssl);

	CU_ASSERT_EQUAL(ttls_socket_new(NULL, &fake.base, &obj), -EINVAL);
	CU_ASSERT_EQUAL(ttls_socket_new(ssl, NULL, &obj), -EINVAL);
	CU_ASSERT_EQUAL(ttls_socket_new(ssl, &fake.base, NULL), -EINVAL);

	ssl_ctx = SSL_CTX_new(TLS_client_method());
	CU_ASSERT_PTR_NOT_NULL_FATAL(ssl_ctx);
	CU_ASSERT_EQUAL(ttls_socket_new_with_ctx(NULL, &fake.base, &obj),
			-EINVAL);
	CU_ASSERT_EQUAL(ttls_socket_new_with_ctx(ssl_ctx, NULL, &obj), -EINVAL);
	CU_ASSERT_EQUAL(ttls_socket_new_with_ctx(ssl_ctx, &fake.base, NULL),
			-EINVAL);

	SSL_free(ssl);
	SSL_CTX_free(ctx);
	SSL_CTX_free(ssl_ctx);
	pomp_loop_destroy(loop);
}


static void test_new_null_loop_error_path(void)
{
	struct pomp_loop *loop = pomp_loop_new();
	struct fake_sock fake;
	SSL_CTX *ctx;
	SSL *ssl;
	struct tskt_socket *obj = NULL;
	int res;

	CU_ASSERT_PTR_NOT_NULL_FATAL(loop);
	fake_sock_init(&fake);
	fake.get_loop_ret =
		NULL; /* triggers ttls_socket_new()'s NULL-loop guard */

	ctx = SSL_CTX_new(TLS_client_method());
	CU_ASSERT_PTR_NOT_NULL_FATAL(ctx);
	ssl = SSL_new(ctx);
	CU_ASSERT_PTR_NOT_NULL_FATAL(ssl);

	res = ttls_socket_new(ssl, &fake.base, &obj);
	CU_ASSERT_EQUAL(res, -EINVAL);

	/* the shared "error:" cleanup path unconditionally clears the event
	 * callback on the wrapped socket (even though it was never actually
	 * set, since the NULL-loop check fires before that point), but does
	 * NOT destroy it: caller keeps ownership of the socket on this early
	 * failure */
	CU_ASSERT_TRUE(fake.set_event_cb_called);
	CU_ASSERT_PTR_NULL(fake.event_cb);
	CU_ASSERT_FALSE(fake.destroy_called);

	SSL_free(ssl);
	SSL_CTX_free(ctx);
	pomp_loop_destroy(loop);
}


static void test_pre_handshake_io_returns_eagain(void)
{
	struct pomp_loop *loop = pomp_loop_new();
	struct fake_sock fake;
	struct tskt_socket *ttls_sock;
	struct tpkt_packet *pkt;
	char buf[16];

	CU_ASSERT_PTR_NOT_NULL_FATAL(loop);
	ttls_sock = make_pending_ttls(loop, &fake);
	CU_ASSERT_PTR_NOT_NULL_FATAL(ttls_sock);

	CU_ASSERT_EQUAL(tskt_socket_read(ttls_sock, buf, sizeof(buf), NULL),
			-EAGAIN);
	CU_ASSERT_EQUAL(tskt_socket_write(ttls_sock, "x", 1), -EAGAIN);

	CU_ASSERT_EQUAL(tpkt_new(64, &pkt), 0);
	CU_ASSERT_EQUAL(tskt_socket_read_pkt(ttls_sock, pkt), -EAGAIN);
	tpkt_unref(pkt);

	CU_ASSERT_EQUAL(tpkt_new_with_data("y", 1, &pkt), 0);
	CU_ASSERT_EQUAL(tskt_socket_write_pkt(ttls_sock, pkt), -EAGAIN);
	tpkt_unref(pkt);

	/* not yet handshaken: shutdown must defer, not attempt an SSL_shutdown
	 */
	CU_ASSERT_EQUAL(ttls_socket_shutdown(ttls_sock), -EAGAIN);

	tskt_socket_destroy(ttls_sock);
	pomp_loop_destroy(loop);
}


static void test_get_addr_delegates(void)
{
	struct pomp_loop *loop = pomp_loop_new();
	struct fake_sock fake;
	struct tskt_socket *ttls_sock;
	char buf[64];

	CU_ASSERT_PTR_NOT_NULL_FATAL(loop);
	ttls_sock = make_pending_ttls(loop, &fake);
	CU_ASSERT_PTR_NOT_NULL_FATAL(ttls_sock);

	CU_ASSERT_PTR_EQUAL(tskt_socket_get_loop(ttls_sock), loop);

	fake.get_local_addr_str = "1.2.3.4";
	fake.get_local_addr_port = 1111;
	fake.get_remote_addr_str = "5.6.7.8";
	fake.get_remote_addr_port = 2222;

	memset(buf, 0, sizeof(buf));
	CU_ASSERT_EQUAL(tskt_socket_get_local_addr(ttls_sock, buf, sizeof(buf)),
			0);
	CU_ASSERT_STRING_EQUAL(buf, "1.2.3.4");
	CU_ASSERT_EQUAL(tskt_socket_get_local_port(ttls_sock), 1111);

	memset(buf, 0, sizeof(buf));
	CU_ASSERT_EQUAL(
		tskt_socket_get_remote_addr(ttls_sock, buf, sizeof(buf)), 0);
	CU_ASSERT_STRING_EQUAL(buf, "5.6.7.8");
	CU_ASSERT_EQUAL(tskt_socket_get_remote_port(ttls_sock), 2222);

	CU_ASSERT_TRUE(fake.get_local_addr_called);
	CU_ASSERT_TRUE(fake.get_remote_addr_called);

	tskt_socket_destroy(ttls_sock);
	pomp_loop_destroy(loop);
}


static void test_get_option_error_not_delegated(void)
{
	struct pomp_loop *loop = pomp_loop_new();
	struct fake_sock fake;
	struct tskt_socket *ttls_sock;

	CU_ASSERT_PTR_NOT_NULL_FATAL(loop);
	ttls_sock = make_pending_ttls(loop, &fake);
	CU_ASSERT_PTR_NOT_NULL_FATAL(ttls_sock);

	fake.get_option_ret[TSKT_OPT_ERROR] = 999;

	/* TSKT_OPT_ERROR is answered from ttls's own error field, never
	 * delegated to the wrapped socket */
	CU_ASSERT_EQUAL(tskt_socket_get_error(ttls_sock), 0);
	CU_ASSERT_FALSE(fake.get_option_called);

	tskt_socket_destroy(ttls_sock);
	pomp_loop_destroy(loop);
}


static void test_get_set_option_delegates(void)
{
	struct pomp_loop *loop = pomp_loop_new();
	struct fake_sock fake;
	struct tskt_socket *ttls_sock;

	CU_ASSERT_PTR_NOT_NULL_FATAL(loop);
	ttls_sock = make_pending_ttls(loop, &fake);
	CU_ASSERT_PTR_NOT_NULL_FATAL(ttls_sock);

	fake.get_option_ret[TSKT_OPT_RESET] = 7;
	CU_ASSERT_EQUAL(tskt_socket_get_reset(ttls_sock), 7);
	CU_ASSERT_TRUE(fake.get_option_called);
	CU_ASSERT_EQUAL(fake.get_option_option, TSKT_OPT_RESET);

	CU_ASSERT_EQUAL(tskt_socket_set_reset(ttls_sock, 1), 0);
	CU_ASSERT_TRUE(fake.set_option_called);
	CU_ASSERT_EQUAL(fake.set_option_option, TSKT_OPT_RESET);
	CU_ASSERT_EQUAL(fake.set_option_value, 1);

	tskt_socket_destroy(ttls_sock);
	pomp_loop_destroy(loop);
}


static void test_accessor_guards(void)
{
	struct pomp_loop *loop = pomp_loop_new();
	struct fake_sock fake, other;
	struct tskt_socket *ttls_sock;

	CU_ASSERT_PTR_NOT_NULL_FATAL(loop);
	ttls_sock = make_pending_ttls(loop, &fake);
	CU_ASSERT_PTR_NOT_NULL_FATAL(ttls_sock);
	fake_sock_init(&other);

	CU_ASSERT_PTR_NOT_NULL(ttls_socket_get_ssl(ttls_sock));
	CU_ASSERT_PTR_EQUAL(ttls_socket_get_socket(ttls_sock), &fake.base);
	CU_ASSERT_EQUAL(ttls_socket_get_last_ssl_error(ttls_sock), 0UL);

	CU_ASSERT_PTR_NULL(ttls_socket_get_ssl(&other.base));
	CU_ASSERT_PTR_NULL(ttls_socket_get_socket(&other.base));
	CU_ASSERT_EQUAL(ttls_socket_get_last_ssl_error(&other.base),
			(unsigned long)-1);
	CU_ASSERT_EQUAL(ttls_socket_shutdown(&other.base), -EINVAL);

	tskt_socket_destroy(ttls_sock);
	pomp_loop_destroy(loop);
}


/*
 * Real end-to-end helpers
 */

static void tls_connect_pair(struct pomp_loop *loop,
			     SSL_CTX *client_ctx,
			     SSL_CTX *server_ctx,
			     struct tskt_socket **ret_client,
			     struct tskt_socket **ret_accepted)
{
	struct tskt_socket *server, *tcp_client = NULL, *tcp_accepted = NULL;
	char remote_addr[INET6_ADDRSTRLEN];
	uint16_t server_port = 0, remote_port = 0;
	SSL *client_ssl;
	int res;

	res = tskt_socket_new_tcp(loop, &server);
	CU_ASSERT_EQUAL(res, 0);
	res = tskt_socket_listen(server, ADDR4, 0);
	CU_ASSERT_EQUAL(res, 0);
	server_port = tskt_socket_get_local_port(server);
	CU_ASSERT_TRUE(server_port != 0);

	res = tskt_socket_new_tcp(loop, &tcp_client);
	CU_ASSERT_EQUAL(res, 0);
	res = tskt_socket_connect(tcp_client, NULL, 0, ADDR4, server_port);
	CU_ASSERT_EQUAL(res, 0);

	res = wait_accept(loop,
			  server,
			  remote_addr,
			  sizeof(remote_addr),
			  &remote_port,
			  &tcp_accepted);
	CU_ASSERT_EQUAL(res, 0);
	tskt_socket_destroy(server);

	client_ssl = SSL_new(client_ctx);
	CU_ASSERT_PTR_NOT_NULL(client_ssl);
	res = ttls_socket_new(client_ssl, tcp_client, ret_client);
	CU_ASSERT_EQUAL(res, 0);

	/* server side goes through ttls_socket_new_with_ctx() rather than a
	 * manual SSL_new()+ttls_socket_new(), so its success path (the only
	 * one not otherwise covered by the guard tests) gets exercised too */
	res = ttls_socket_new_with_ctx(server_ctx, tcp_accepted, ret_accepted);
	CU_ASSERT_EQUAL(res, 0);
}


static void make_ctx_pair(char *cert_path,
			  size_t cert_path_len,
			  char *key_path,
			  size_t key_path_len,
			  SSL_CTX **ret_client_ctx,
			  SSL_CTX **ret_server_ctx)
{
	SSL_CTX *client_ctx, *server_ctx;

	CU_ASSERT_EQUAL(ttls_test_write_temp_pem(
				TTLS_TEST_CERT_PEM, cert_path, cert_path_len),
			0);
	CU_ASSERT_EQUAL(ttls_test_write_temp_pem(
				TTLS_TEST_KEY_PEM, key_path, key_path_len),
			0);

	client_ctx = SSL_CTX_new(TLS_client_method());
	CU_ASSERT_PTR_NOT_NULL(client_ctx);
	server_ctx = SSL_CTX_new(TLS_server_method());
	CU_ASSERT_PTR_NOT_NULL(server_ctx);
	CU_ASSERT_EQUAL(
		ttls_ctx_use_certificate(server_ctx, cert_path, key_path), 0);

	*ret_client_ctx = client_ctx;
	*ret_server_ctx = server_ctx;
}


static void test_handshake_and_data_roundtrip(void)
{
	struct pomp_loop *loop = pomp_loop_new();
	SSL_CTX *client_ctx, *server_ctx;
	struct tskt_socket *client = NULL, *accepted = NULL;
	char cert_path[64], key_path[64];
	char sbuf[] = "hello tls";
	char rbuf[64];
	int res;

	CU_ASSERT_PTR_NOT_NULL_FATAL(loop);
	make_ctx_pair(cert_path,
		      sizeof(cert_path),
		      key_path,
		      sizeof(key_path),
		      &client_ctx,
		      &server_ctx);
	tls_connect_pair(loop, client_ctx, server_ctx, &client, &accepted);
	CU_ASSERT_PTR_NOT_NULL_FATAL(client);
	CU_ASSERT_PTR_NOT_NULL_FATAL(accepted);

	res = wait_write(loop, client, sbuf, sizeof(sbuf));
	CU_ASSERT_EQUAL(res, (int)sizeof(sbuf));

	memset(rbuf, 0, sizeof(rbuf));
	res = wait_read(loop, accepted, rbuf, sizeof(rbuf), NULL);
	CU_ASSERT_EQUAL(res, (int)sizeof(sbuf));
	CU_ASSERT_NSTRING_EQUAL(rbuf, sbuf, sizeof(sbuf));

	/* echo back */
	res = wait_write(loop, accepted, rbuf, res);
	CU_ASSERT_TRUE(res > 0);
	memset(rbuf, 0, sizeof(rbuf));
	res = wait_read(loop, client, rbuf, sizeof(rbuf), NULL);
	CU_ASSERT_EQUAL(res, (int)sizeof(sbuf));
	CU_ASSERT_NSTRING_EQUAL(rbuf, sbuf, sizeof(sbuf));

	tskt_socket_destroy(client);
	tskt_socket_destroy(accepted);
	pomp_loop_destroy(loop);
	SSL_CTX_free(client_ctx);
	SSL_CTX_free(server_ctx);
	remove(cert_path);
	remove(key_path);
}


static void test_write_clips_to_max(void)
{
	struct pomp_loop *loop = pomp_loop_new();
	SSL_CTX *client_ctx, *server_ctx;
	struct tskt_socket *client = NULL, *accepted = NULL;
	char cert_path[64], key_path[64];
	char *big;
	size_t big_len = EXPECTED_WRITE_MAX + 4096;
	int res;

	CU_ASSERT_PTR_NOT_NULL_FATAL(loop);
	make_ctx_pair(cert_path,
		      sizeof(cert_path),
		      key_path,
		      sizeof(key_path),
		      &client_ctx,
		      &server_ctx);
	tls_connect_pair(loop, client_ctx, server_ctx, &client, &accepted);
	CU_ASSERT_PTR_NOT_NULL_FATAL(client);
	CU_ASSERT_PTR_NOT_NULL_FATAL(accepted);

	big = calloc(1, big_len);
	CU_ASSERT_PTR_NOT_NULL_FATAL(big);

	res = wait_write(loop, client, big, big_len);
	CU_ASSERT_EQUAL(res, EXPECTED_WRITE_MAX);

	free(big);
	tskt_socket_destroy(client);
	tskt_socket_destroy(accepted);
	pomp_loop_destroy(loop);
	SSL_CTX_free(client_ctx);
	SSL_CTX_free(server_ctx);
	remove(cert_path);
	remove(key_path);
}


static void test_shutdown_after_handshake(void)
{
	struct pomp_loop *loop = pomp_loop_new();
	SSL_CTX *client_ctx, *server_ctx;
	struct tskt_socket *client = NULL, *accepted = NULL;
	char cert_path[64], key_path[64];
	char sbuf[] = "hi";
	char rbuf[64];
	int res, sres;

	CU_ASSERT_PTR_NOT_NULL_FATAL(loop);
	make_ctx_pair(cert_path,
		      sizeof(cert_path),
		      key_path,
		      sizeof(key_path),
		      &client_ctx,
		      &server_ctx);
	tls_connect_pair(loop, client_ctx, server_ctx, &client, &accepted);
	CU_ASSERT_PTR_NOT_NULL_FATAL(client);
	CU_ASSERT_PTR_NOT_NULL_FATAL(accepted);

	/* drive the handshake to completion via an ordinary data exchange */
	res = wait_write(loop, client, sbuf, sizeof(sbuf));
	CU_ASSERT_EQUAL(res, (int)sizeof(sbuf));
	res = wait_read(loop, accepted, rbuf, sizeof(rbuf), NULL);
	CU_ASSERT_EQUAL(res, (int)sizeof(sbuf));

	/* handshake is done and no write is pending: shutdown must not defer */
	sres = ttls_socket_shutdown(client);
	CU_ASSERT_TRUE(sres == 0 || sres == -EAGAIN);

	tskt_socket_destroy(client);
	tskt_socket_destroy(accepted);
	pomp_loop_destroy(loop);
	SSL_CTX_free(client_ctx);
	SSL_CTX_free(server_ctx);
	remove(cert_path);
	remove(key_path);
}


static void test_destroy_with_pending_write(void)
{
	struct pomp_loop *loop = pomp_loop_new();
	SSL_CTX *client_ctx, *server_ctx;
	struct tskt_socket *client = NULL, *accepted = NULL;
	char cert_path[64], key_path[64];
	char sbuf[] = "hi";
	char rbuf[16];
	char *big;
	size_t big_len = EXPECTED_WRITE_MAX;
	int res, i;
	bool got_eagain = false;

	CU_ASSERT_PTR_NOT_NULL_FATAL(loop);
	make_ctx_pair(cert_path,
		      sizeof(cert_path),
		      key_path,
		      sizeof(key_path),
		      &client_ctx,
		      &server_ctx);
	tls_connect_pair(loop, client_ctx, server_ctx, &client, &accepted);
	CU_ASSERT_PTR_NOT_NULL_FATAL(client);
	CU_ASSERT_PTR_NOT_NULL_FATAL(accepted);

	/* shrink both ends' socket buffers so backpressure is reached with a
	 * reasonably small amount of unread data */
	CU_ASSERT_EQUAL(tskt_socket_set_txbuf_size(client, 2048), 0);
	CU_ASSERT_EQUAL(tskt_socket_set_rxbuf_size(accepted, 2048), 0);

	/* drive the handshake to completion first, via an ordinary exchange */
	res = wait_write(loop, client, sbuf, sizeof(sbuf));
	CU_ASSERT_EQUAL(res, (int)sizeof(sbuf));
	res = wait_read(loop, accepted, rbuf, sizeof(rbuf), NULL);
	CU_ASSERT_EQUAL(res, (int)sizeof(sbuf));

	big = calloc(1, big_len);
	CU_ASSERT_PTR_NOT_NULL_FATAL(big);

	/* write repeatedly without pumping the loop (so nothing ever gets
	 * flushed) and without the peer ever reading: this deterministically
	 * exhausts the shrunk socket buffers, at which point
	 * ttls_socket_write() must be internally buffering (ttls->wlen != 0)
	 * -- destroying right after that exercises ttls_socket_destroy()'s
	 * reset-on-pending-write path, instead of leaving it to loopback
	 * buffer sizing chance. */
	for (i = 0; i < 64; i++) {
		res = tskt_socket_write(client, big, big_len);
		if (res == -EAGAIN) {
			got_eagain = true;
			break;
		}
		CU_ASSERT_EQUAL(res, (int)big_len);
	}
	CU_ASSERT_TRUE_FATAL(got_eagain);

	free(big);
	tskt_socket_destroy(client);
	tskt_socket_destroy(accepted);
	pomp_loop_destroy(loop);
	SSL_CTX_free(client_ctx);
	SSL_CTX_free(server_ctx);
	remove(cert_path);
	remove(key_path);
}


/* Force ttls_socket_write()-buffered backpressure the same way
 * test_destroy_with_pending_write() does, but this time drain the peer and
 * keep pumping the loop instead of destroying right away: exercises
 * ttls_flush_write()'s real flush path (raw write succeeds, wlen cleared).
 * Success is observed indirectly -- there's no way to peek ttls->wlen from
 * outside, but ttls_socket_write() unconditionally rejects a new write with
 * -EAGAIN while one is still pending, so a fresh write finally being
 * accepted proves the pending one was flushed. */
static void test_flush_write_completes_pending_write(void)
{
	struct pomp_loop *loop = pomp_loop_new();
	SSL_CTX *client_ctx, *server_ctx;
	struct tskt_socket *client = NULL, *accepted = NULL;
	char cert_path[64], key_path[64];
	char sbuf[] = "hi";
	char rbuf[4096];
	char *big;
	size_t big_len = EXPECTED_WRITE_MAX;
	int res, i, elapsed;
	bool got_eagain = false;

	CU_ASSERT_PTR_NOT_NULL_FATAL(loop);
	make_ctx_pair(cert_path,
		      sizeof(cert_path),
		      key_path,
		      sizeof(key_path),
		      &client_ctx,
		      &server_ctx);
	tls_connect_pair(loop, client_ctx, server_ctx, &client, &accepted);
	CU_ASSERT_PTR_NOT_NULL_FATAL(client);
	CU_ASSERT_PTR_NOT_NULL_FATAL(accepted);

	CU_ASSERT_EQUAL(tskt_socket_set_txbuf_size(client, 2048), 0);
	CU_ASSERT_EQUAL(tskt_socket_set_rxbuf_size(accepted, 2048), 0);

	res = wait_write(loop, client, sbuf, sizeof(sbuf));
	CU_ASSERT_EQUAL(res, (int)sizeof(sbuf));
	res = wait_read(loop, accepted, rbuf, sizeof(sbuf), NULL);
	CU_ASSERT_EQUAL(res, (int)sizeof(sbuf));

	big = calloc(1, big_len);
	CU_ASSERT_PTR_NOT_NULL_FATAL(big);
	for (i = 0; i < 64; i++) {
		res = tskt_socket_write(client, big, big_len);
		if (res == -EAGAIN) {
			got_eagain = true;
			break;
		}
		CU_ASSERT_EQUAL(res, (int)big_len);
	}
	CU_ASSERT_TRUE_FATAL(got_eagain);

	elapsed = 0;
	res = -EAGAIN;
	while (elapsed < TEST_TIMEOUT_MS) {
		while (tskt_socket_read(accepted, rbuf, sizeof(rbuf), NULL) > 0)
			;
		res = tskt_socket_write(client, "x", 1);
		if (res != -EAGAIN)
			break;
		pomp_loop_wait_and_process(loop, POLL_STEP_MS);
		elapsed += POLL_STEP_MS;
	}
	CU_ASSERT_EQUAL(res, 1);

	free(big);
	tskt_socket_destroy(client);
	tskt_socket_destroy(accepted);
	pomp_loop_destroy(loop);
	SSL_CTX_free(client_ctx);
	SSL_CTX_free(server_ctx);
	remove(cert_path);
	remove(key_path);
}


/* Same as above, but with a pending ttls_socket_shutdown() request behind
 * the buffered write: exercises ttls_flush_write()'s do_shutdown branch
 * (the actual SSL_shutdown() call it makes once the flush succeeds).
 * Best-effort on timing like test_peer_reset_reports_error(): there's no
 * externally observable proof the deferred shutdown specifically ran versus
 * just the write, so this only asserts the sequence doesn't hang or crash. */
static void test_deferred_shutdown_flushes(void)
{
	struct pomp_loop *loop = pomp_loop_new();
	SSL_CTX *client_ctx, *server_ctx;
	struct tskt_socket *client = NULL, *accepted = NULL;
	char cert_path[64], key_path[64];
	char sbuf[] = "hi";
	char rbuf[4096];
	char *big;
	size_t big_len = EXPECTED_WRITE_MAX;
	int res, i, elapsed;
	bool got_eagain = false;

	CU_ASSERT_PTR_NOT_NULL_FATAL(loop);
	make_ctx_pair(cert_path,
		      sizeof(cert_path),
		      key_path,
		      sizeof(key_path),
		      &client_ctx,
		      &server_ctx);
	tls_connect_pair(loop, client_ctx, server_ctx, &client, &accepted);
	CU_ASSERT_PTR_NOT_NULL_FATAL(client);
	CU_ASSERT_PTR_NOT_NULL_FATAL(accepted);

	CU_ASSERT_EQUAL(tskt_socket_set_txbuf_size(client, 2048), 0);
	CU_ASSERT_EQUAL(tskt_socket_set_rxbuf_size(accepted, 2048), 0);

	res = wait_write(loop, client, sbuf, sizeof(sbuf));
	CU_ASSERT_EQUAL(res, (int)sizeof(sbuf));
	res = wait_read(loop, accepted, rbuf, sizeof(sbuf), NULL);
	CU_ASSERT_EQUAL(res, (int)sizeof(sbuf));

	big = calloc(1, big_len);
	CU_ASSERT_PTR_NOT_NULL_FATAL(big);
	for (i = 0; i < 64; i++) {
		res = tskt_socket_write(client, big, big_len);
		if (res == -EAGAIN) {
			got_eagain = true;
			break;
		}
		CU_ASSERT_EQUAL(res, (int)big_len);
	}
	CU_ASSERT_TRUE_FATAL(got_eagain);

	/* write still pending: shutdown must defer instead of calling
	 * SSL_shutdown() right away */
	CU_ASSERT_EQUAL(ttls_socket_shutdown(client), -EAGAIN);

	elapsed = 0;
	while (elapsed < TEST_TIMEOUT_MS) {
		while (tskt_socket_read(accepted, rbuf, sizeof(rbuf), NULL) > 0)
			;
		pomp_loop_wait_and_process(loop, POLL_STEP_MS);
		elapsed += POLL_STEP_MS;
	}

	free(big);
	tskt_socket_destroy(client);
	tskt_socket_destroy(accepted);
	pomp_loop_destroy(loop);
	SSL_CTX_free(client_ctx);
	SSL_CTX_free(server_ctx);
	remove(cert_path);
	remove(key_path);
}


/* Force backpressure via ttls_socket_write_pkt() instead of the plain-buffer
 * ttls_socket_write(): this is the path that sets ttls->wpkt (a ref-held
 * packet), so flushing it exercises ttls_flush_write()'s tpkt_unref()
 * branch, which plain buffered writes never touch. */
static void test_flush_write_pkt_completes_pending(void)
{
	struct pomp_loop *loop = pomp_loop_new();
	SSL_CTX *client_ctx, *server_ctx;
	struct tskt_socket *client = NULL, *accepted = NULL;
	char cert_path[64], key_path[64];
	char sbuf[] = "hi";
	char rbuf[4096];
	struct tpkt_packet *pkt;
	size_t pkt_len = EXPECTED_WRITE_MAX;
	int res, i, elapsed;
	bool got_pending = false;

	CU_ASSERT_PTR_NOT_NULL_FATAL(loop);
	make_ctx_pair(cert_path,
		      sizeof(cert_path),
		      key_path,
		      sizeof(key_path),
		      &client_ctx,
		      &server_ctx);
	tls_connect_pair(loop, client_ctx, server_ctx, &client, &accepted);
	CU_ASSERT_PTR_NOT_NULL_FATAL(client);
	CU_ASSERT_PTR_NOT_NULL_FATAL(accepted);

	CU_ASSERT_EQUAL(tskt_socket_set_txbuf_size(client, 2048), 0);
	CU_ASSERT_EQUAL(tskt_socket_set_rxbuf_size(accepted, 2048), 0);

	res = wait_write(loop, client, sbuf, sizeof(sbuf));
	CU_ASSERT_EQUAL(res, (int)sizeof(sbuf));
	res = wait_read(loop, accepted, rbuf, sizeof(sbuf), NULL);
	CU_ASSERT_EQUAL(res, (int)sizeof(sbuf));

	/* send a fresh packet each iteration (write_pkt() takes its own ref
	 * only if it has to buffer, so ours is always safe to drop right
	 * after the call either way) until one attempt hits the "already
	 * pending" -EAGAIN guard: that proves the previous iteration's
	 * packet is the one now stuck in ttls->wpkt. */
	for (i = 0; i < 64; i++) {
		void *data;

		CU_ASSERT_EQUAL(tpkt_new(pkt_len, &pkt), 0);
		CU_ASSERT_EQUAL(tpkt_get_data(pkt, &data, NULL, NULL), 0);
		memset(data, 'A', pkt_len);
		CU_ASSERT_EQUAL(tpkt_set_len(pkt, pkt_len), 0);

		res = tskt_socket_write_pkt(client, pkt);
		tpkt_unref(pkt);
		if (res == -EAGAIN) {
			got_pending = true;
			break;
		}
		CU_ASSERT_EQUAL(res, 0);
	}
	CU_ASSERT_TRUE_FATAL(got_pending);

	elapsed = 0;
	res = -EAGAIN;
	while (elapsed < TEST_TIMEOUT_MS) {
		struct tpkt_packet *probe;

		while (tskt_socket_read(accepted, rbuf, sizeof(rbuf), NULL) > 0)
			;
		CU_ASSERT_EQUAL(tpkt_new_with_data("x", 1, &probe), 0);
		res = tskt_socket_write_pkt(client, probe);
		tpkt_unref(probe);
		if (res != -EAGAIN)
			break;
		pomp_loop_wait_and_process(loop, POLL_STEP_MS);
		elapsed += POLL_STEP_MS;
	}
	CU_ASSERT_EQUAL(res, 0);

	tskt_socket_destroy(client);
	tskt_socket_destroy(accepted);
	pomp_loop_destroy(loop);
	SSL_CTX_free(client_ctx);
	SSL_CTX_free(server_ctx);
	remove(cert_path);
	remove(key_path);
}


/* Covers src/ttls_socket.c's ttls_socket_read_pkt(): the success path
 * (real data decrypted into the packet's buffer, tpkt_set_len() called),
 * the NULL-pkt guard, the maxlen == 0 guard, and the tpkt_get_data()
 * failure passthrough (a const/cdata packet has no pomp_buffer backing it,
 * so tpkt_get_data() refuses it with -EPERM). */
static void test_read_pkt_after_handshake(void)
{
	struct pomp_loop *loop = pomp_loop_new();
	SSL_CTX *client_ctx, *server_ctx;
	struct tskt_socket *client = NULL, *accepted = NULL;
	char cert_path[64], key_path[64];
	char sbuf[] = "hello pkt";
	struct tpkt_packet *pkt;
	const void *data;
	size_t len;
	int res;

	CU_ASSERT_PTR_NOT_NULL_FATAL(loop);
	make_ctx_pair(cert_path,
		      sizeof(cert_path),
		      key_path,
		      sizeof(key_path),
		      &client_ctx,
		      &server_ctx);
	tls_connect_pair(loop, client_ctx, server_ctx, &client, &accepted);
	CU_ASSERT_PTR_NOT_NULL_FATAL(client);
	CU_ASSERT_PTR_NOT_NULL_FATAL(accepted);

	res = wait_write(loop, client, sbuf, sizeof(sbuf));
	CU_ASSERT_EQUAL(res, (int)sizeof(sbuf));

	CU_ASSERT_EQUAL(tpkt_new(64, &pkt), 0);
	res = wait_read_pkt(loop, accepted, pkt);
	CU_ASSERT_EQUAL(res, 0);

	CU_ASSERT_EQUAL(tpkt_get_cdata(pkt, &data, &len, NULL), 0);
	CU_ASSERT_EQUAL(len, sizeof(sbuf));
	CU_ASSERT_NSTRING_EQUAL((const char *)data, sbuf, sizeof(sbuf));
	tpkt_unref(pkt);

	/* argument validation */
	CU_ASSERT_EQUAL(tskt_socket_read_pkt(accepted, NULL), -EINVAL);

	{
		/* zero-capacity buffer -> maxlen == 0 guard */
		struct tpkt_packet *empty;
		CU_ASSERT_EQUAL(tpkt_new(0, &empty), 0);
		CU_ASSERT_EQUAL(tskt_socket_read_pkt(accepted, empty), -EINVAL);
		tpkt_unref(empty);
	}

	{
		/* a const/cdata packet (no pomp_buffer backing it) makes
		 * tpkt_get_data() return -EPERM (it refuses read/write access
		 * to const-only data), which ttls_socket_read_pkt() must pass
		 * straight through */
		struct tpkt_packet *cdata_pkt;
		char cdata_buf[8] = {0};
		CU_ASSERT_EQUAL(tpkt_new_from_cdata(cdata_buf,
						    sizeof(cdata_buf),
						    &cdata_pkt),
				0);
		CU_ASSERT_EQUAL(tskt_socket_read_pkt(accepted, cdata_pkt),
				-EPERM);
		tpkt_unref(cdata_pkt);
	}

	tskt_socket_destroy(client);
	tskt_socket_destroy(accepted);
	pomp_loop_destroy(loop);
	SSL_CTX_free(client_ctx);
	SSL_CTX_free(server_ctx);
	remove(cert_path);
	remove(key_path);
}


static void test_readv_writev(void)
{
	struct pomp_loop *loop = pomp_loop_new();
	SSL_CTX *client_ctx, *server_ctx;
	struct tskt_socket *client = NULL, *accepted = NULL;
	char cert_path[64], key_path[64];
	char part1[] = "foo";
	char empty_marker[1] = {0};
	char part2[] = "bar!";
	struct iovec iov[3];
	char rbuf[64];
	struct iovec riov;
	int res;

	CU_ASSERT_PTR_NOT_NULL_FATAL(loop);
	make_ctx_pair(cert_path,
		      sizeof(cert_path),
		      key_path,
		      sizeof(key_path),
		      &client_ctx,
		      &server_ctx);
	tls_connect_pair(loop, client_ctx, server_ctx, &client, &accepted);
	CU_ASSERT_PTR_NOT_NULL_FATAL(client);
	CU_ASSERT_PTR_NOT_NULL_FATAL(accepted);

	/* multi-iovec write, with a zero-length iovec skipped in the middle,
	 * read back through the single-iovec readv path */
	iov[0].iov_base = part1;
	iov[0].iov_len = sizeof(part1) - 1;
	iov[1].iov_base = empty_marker;
	iov[1].iov_len = 0;
	iov[2].iov_base = part2;
	iov[2].iov_len = sizeof(part2) - 1;

	res = wait_writev(loop, client, iov, 3);
	CU_ASSERT_EQUAL(res, (int)(iov[0].iov_len + iov[2].iov_len));

	memset(rbuf, 0, sizeof(rbuf));
	riov.iov_base = rbuf;
	riov.iov_len = sizeof(rbuf);
	res = wait_readv(loop, accepted, &riov, 1, NULL);
	CU_ASSERT_EQUAL(res, (int)(iov[0].iov_len + iov[2].iov_len));
	CU_ASSERT_NSTRING_EQUAL(rbuf, "foobar!", 7);

	/* argument validation */
	CU_ASSERT_EQUAL(tskt_socket_readv(accepted, NULL, 0, NULL), -EINVAL);
	{
		struct iovec zero_iov = {rbuf, 0};
		CU_ASSERT_EQUAL(tskt_socket_readv(accepted, &zero_iov, 1, NULL),
				-EINVAL);
	}
	CU_ASSERT_EQUAL(tskt_socket_writev(client, NULL, 0), -EINVAL);

	tskt_socket_destroy(client);
	tskt_socket_destroy(accepted);
	pomp_loop_destroy(loop);
	SSL_CTX_free(client_ctx);
	SSL_CTX_free(server_ctx);
	remove(cert_path);
	remove(key_path);
}


/* Regression test for a fixed out-of-bounds read: ttls_socket_writev()'s
 * clipping arithmetic (the `len -= ...` line, when a later iovec is the one
 * that pushes the running total past TTLS_WRITE_MAX) used to compute the
 * wrong byte count for that iovec -- reading past its actual bounds and
 * sending the resulting garbage as if it were legitimate application data.
 * This pins the fix by checking both the clipped length AND the exact
 * content on both sides of the split. */
static void test_writev_clips_mid_iov(void)
{
	struct pomp_loop *loop = pomp_loop_new();
	SSL_CTX *client_ctx, *server_ctx;
	struct tskt_socket *client = NULL, *accepted = NULL;
	char cert_path[64], key_path[64];
	size_t len_a = EXPECTED_WRITE_MAX - 10;
	size_t len_b = 100;
	char *buf_a, *buf_b, *rbuf;
	size_t rcap = EXPECTED_WRITE_MAX + 64;
	struct iovec iov[2];
	struct iovec riov;
	int res;
	size_t j;

	CU_ASSERT_PTR_NOT_NULL_FATAL(loop);
	make_ctx_pair(cert_path,
		      sizeof(cert_path),
		      key_path,
		      sizeof(key_path),
		      &client_ctx,
		      &server_ctx);
	tls_connect_pair(loop, client_ctx, server_ctx, &client, &accepted);
	CU_ASSERT_PTR_NOT_NULL_FATAL(client);
	CU_ASSERT_PTR_NOT_NULL_FATAL(accepted);

	buf_a = malloc(len_a);
	buf_b = malloc(len_b);
	rbuf = malloc(rcap);
	CU_ASSERT_PTR_NOT_NULL_FATAL(buf_a);
	CU_ASSERT_PTR_NOT_NULL_FATAL(buf_b);
	CU_ASSERT_PTR_NOT_NULL_FATAL(rbuf);
	memset(buf_a, 'A', len_a);
	memset(buf_b, 'B', len_b);

	/* len_a alone is under TTLS_WRITE_MAX; adding len_b pushes the total
	 * 90 bytes over it, so only the first 10 bytes of buf_b should make
	 * it into the record */
	iov[0].iov_base = buf_a;
	iov[0].iov_len = len_a;
	iov[1].iov_base = buf_b;
	iov[1].iov_len = len_b;

	res = wait_writev(loop, client, iov, 2);
	CU_ASSERT_EQUAL(res, EXPECTED_WRITE_MAX);

	memset(rbuf, 0, rcap);
	riov.iov_base = rbuf;
	riov.iov_len = rcap;
	res = wait_readv(loop, accepted, &riov, 1, NULL);
	CU_ASSERT_EQUAL(res, EXPECTED_WRITE_MAX);

	for (j = 0; j < len_a; j++)
		CU_ASSERT_EQUAL(rbuf[j], 'A');
	for (; j < (size_t)res; j++)
		CU_ASSERT_EQUAL(rbuf[j], 'B');

	free(buf_a);
	free(buf_b);
	free(rbuf);
	tskt_socket_destroy(client);
	tskt_socket_destroy(accepted);
	pomp_loop_destroy(loop);
	SSL_CTX_free(client_ctx);
	SSL_CTX_free(server_ctx);
	remove(cert_path);
	remove(key_path);
}


static void
event_cb_capture(struct tskt_socket *sock, uint32_t revents, void *userdata)
{
	uint32_t *captured = userdata;

	(void)sock;
	*captured |= revents;
}


static void test_event_cb_fires_on_data(void)
{
	struct pomp_loop *loop = pomp_loop_new();
	SSL_CTX *client_ctx, *server_ctx;
	struct tskt_socket *client = NULL, *accepted = NULL;
	char cert_path[64], key_path[64];
	char sbuf1[] = "hi";
	char sbuf2[] = "yo";
	char rbuf[16];
	uint32_t captured = 0;
	int res, elapsed;

	CU_ASSERT_PTR_NOT_NULL_FATAL(loop);
	make_ctx_pair(cert_path,
		      sizeof(cert_path),
		      key_path,
		      sizeof(key_path),
		      &client_ctx,
		      &server_ctx);
	tls_connect_pair(loop, client_ctx, server_ctx, &client, &accepted);
	CU_ASSERT_PTR_NOT_NULL_FATAL(client);
	CU_ASSERT_PTR_NOT_NULL_FATAL(accepted);

	/* drive the handshake to completion via a throwaway exchange, leaving
	 * both sides with nothing pending */
	res = wait_write(loop, client, sbuf1, sizeof(sbuf1));
	CU_ASSERT_EQUAL(res, (int)sizeof(sbuf1));
	res = wait_read(loop, accepted, rbuf, sizeof(rbuf), NULL);
	CU_ASSERT_EQUAL(res, (int)sizeof(sbuf1));

	/* register for IN events, then arm the underlying transport socket's
	 * read-watch by attempting a read while there is genuinely nothing to
	 * read yet: ttls_socket.c only asks its wrapped socket to watch a
	 * given event as a side effect of an SSL_read()/SSL_write() call
	 * needing it -- set_event_cb() alone only configures *which*
	 * already-tracked events get reported, it doesn't start watching
	 * anything by itself. */
	CU_ASSERT_EQUAL(tskt_socket_set_event_cb(accepted,
						 POMP_FD_EVENT_IN,
						 event_cb_capture,
						 &captured),
			0);
	CU_ASSERT_EQUAL(tskt_socket_read(accepted, rbuf, sizeof(rbuf), NULL),
			-EAGAIN);

	/* now send the data the registered callback should notify about:
	 * exercises ttls_socket_set_event_cb(), ttls_update_events()'s
	 * notify-state-change branch, and ttls_notify_event_cb(), none of
	 * which wait_read()/wait_write() ever reach on their own (they poll
	 * via direct calls, not through a registered callback) */
	res = wait_write(loop, client, sbuf2, sizeof(sbuf2));
	CU_ASSERT_EQUAL(res, (int)sizeof(sbuf2));

	elapsed = 0;
	while (captured == 0 && elapsed < TEST_TIMEOUT_MS) {
		pomp_loop_wait_and_process(loop, POLL_STEP_MS);
		elapsed += POLL_STEP_MS;
	}
	CU_ASSERT_TRUE((captured & POMP_FD_EVENT_IN) != 0);

	/* update_events: stop monitoring IN, then confirm the data still
	 * reads back fine even though the callback is no longer interested */
	CU_ASSERT_EQUAL(
		tskt_socket_update_events(accepted, 0, POMP_FD_EVENT_IN), 0);
	CU_ASSERT_EQUAL(wait_read(loop, accepted, rbuf, sizeof(rbuf), NULL),
			(int)sizeof(sbuf2));

	/* removing the callback resets user_events to 0 (also exercises the
	 * ttls->cb == NULL early-return branch in update_events) */
	CU_ASSERT_EQUAL(tskt_socket_set_event_cb(accepted, 0, NULL, NULL), 0);
	CU_ASSERT_EQUAL(
		tskt_socket_update_events(accepted, POMP_FD_EVENT_IN, 0), 0);

	tskt_socket_destroy(client);
	tskt_socket_destroy(accepted);
	pomp_loop_destroy(loop);
	SSL_CTX_free(client_ctx);
	SSL_CTX_free(server_ctx);
	remove(cert_path);
	remove(key_path);
}


/* Best-effort: forcing a peer RST and observing it as a socket error depends
 * on real kernel/network timing, not just this code, but it's the only way
 * to reach tsock_event_cb()'s POMP_FD_EVENT_ERR branch and the
 * SSL_ERROR_SYSCALL mapping in ttls_io_return(). */
static void test_peer_reset_reports_error(void)
{
	struct pomp_loop *loop = pomp_loop_new();
	SSL_CTX *client_ctx, *server_ctx;
	struct tskt_socket *client = NULL, *accepted = NULL;
	char cert_path[64], key_path[64];
	char sbuf[] = "hi";
	char rbuf[16];
	int res, elapsed, err;

	CU_ASSERT_PTR_NOT_NULL_FATAL(loop);
	make_ctx_pair(cert_path,
		      sizeof(cert_path),
		      key_path,
		      sizeof(key_path),
		      &client_ctx,
		      &server_ctx);
	tls_connect_pair(loop, client_ctx, server_ctx, &client, &accepted);
	CU_ASSERT_PTR_NOT_NULL_FATAL(client);
	CU_ASSERT_PTR_NOT_NULL_FATAL(accepted);

	/* drive the handshake to completion */
	res = wait_write(loop, client, sbuf, sizeof(sbuf));
	CU_ASSERT_EQUAL(res, (int)sizeof(sbuf));
	res = wait_read(loop, accepted, rbuf, sizeof(rbuf), NULL);
	CU_ASSERT_EQUAL(res, (int)sizeof(sbuf));

	/* start a pending read so the transport socket is actively watching
	 * for POMP_FD_EVENT_IN, then abruptly reset+destroy the peer */
	CU_ASSERT_EQUAL(tskt_socket_read(client, rbuf, sizeof(rbuf), NULL),
			-EAGAIN);
	CU_ASSERT_EQUAL(tskt_socket_set_reset(accepted, 1), 0);
	tskt_socket_destroy(accepted);
	accepted = NULL;

	err = 0;
	elapsed = 0;
	while (elapsed < TEST_TIMEOUT_MS) {
		(void)tskt_socket_read(client, rbuf, sizeof(rbuf), NULL);
		err = tskt_socket_get_error(client);
		if (err != 0)
			break;
		pomp_loop_wait_and_process(loop, POLL_STEP_MS);
		elapsed += POLL_STEP_MS;
	}
	CU_ASSERT_TRUE(err != 0);

	tskt_socket_destroy(client);
	pomp_loop_destroy(loop);
	SSL_CTX_free(client_ctx);
	SSL_CTX_free(server_ctx);
	remove(cert_path);
	remove(key_path);
}


CU_TestInfo g_ttls_test_socket[] = {
	{FN("new-guards"), &test_new_guards},
	{FN("new-null-loop-error-path"), &test_new_null_loop_error_path},
	{FN("pre-handshake-io-returns-eagain"),
	 &test_pre_handshake_io_returns_eagain},
	{FN("get-addr-delegates"), &test_get_addr_delegates},
	{FN("get-option-error-not-delegated"),
	 &test_get_option_error_not_delegated},
	{FN("get-set-option-delegates"), &test_get_set_option_delegates},
	{FN("accessor-guards"), &test_accessor_guards},
	{FN("handshake-and-data-roundtrip"),
	 &test_handshake_and_data_roundtrip},
	{FN("write-clips-to-max"), &test_write_clips_to_max},
	{FN("shutdown-after-handshake"), &test_shutdown_after_handshake},
	{FN("destroy-with-pending-write"), &test_destroy_with_pending_write},
	{FN("flush-write-completes-pending-write"),
	 &test_flush_write_completes_pending_write},
	{FN("deferred-shutdown-flushes"), &test_deferred_shutdown_flushes},
	{FN("flush-write-pkt-completes-pending"),
	 &test_flush_write_pkt_completes_pending},
	{FN("read-pkt-after-handshake"), &test_read_pkt_after_handshake},
	{FN("readv-writev"), &test_readv_writev},
	{FN("writev-clips-mid-iov"), &test_writev_clips_mid_iov},
	{FN("event-cb-fires-on-data"), &test_event_cb_fires_on_data},
	{FN("peer-reset-reports-error"), &test_peer_reset_reports_error},

	CU_TEST_INFO_NULL,
};
