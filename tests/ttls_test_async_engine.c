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
 * Tests for src/ttls_socket.c's OpenSSL async-engine support: SSL_MODE_ASYNC,
 * SSL_ERROR_WANT_ASYNC, and the ttls_want_async()/async_cb()/ttls_async.c
 * fd-watch registry machinery that handles it. None of those are reachable
 * without a real async-capable engine actually returning ASYNC_PAUSE from a
 * crypto operation, so this uses OpenSSL's "dasync" test engine to force it.
 *
 * This is opt-in/best-effort: dasync is a testing-only engine that is often
 * NOT compiled into distro-packaged OpenSSL 3.x builds (engine and dynamic
 * engine support are frequently disabled entirely). If it can't be loaded,
 * test_want_async_handshake() simply returns without failing -- there is
 * nothing meaningful to exercise in that environment, the same way this
 * project already treats other infra-dependent paths (real GL rendering,
 * real DNS resolution) as out of scope for unit tests.
 *
 * IMPORTANT: making dasync the default engine (ENGINE_set_default() with
 * ENGINE_METHOD_ALL) affects every crypto operation in this process from
 * that point on, not just this test's own SSL objects -- there is no clean,
 * documented way to fully undo that afterwards. This suite is therefore
 * registered LAST in ttls_test.c's suite list (see ttls_test.h), so no other
 * test in this binary ever runs after it.
 */

/* The ENGINE_* API used below to load the dasync test engine has been
 * deprecated since OpenSSL 3.0 (in favor of providers), but there is no
 * provider-based equivalent for a testing engine like dasync. Pin the API
 * compat level below 3.0 so these calls don't warn; must be defined before
 * any OpenSSL header is pulled in, including transitively via ttls_test.h. */
#define OPENSSL_API_COMPAT 0x10100000L

#include "ttls_test.h"

#include <openssl/engine.h>


#define TEST_TIMEOUT_MS 4000
#define POLL_STEP_MS 20


static ENGINE *load_dasync(void)
{
	ENGINE *e;

	ENGINE_load_dynamic();
	ENGINE_load_builtin_engines();

	e = ENGINE_by_id("dasync");
	if (!e)
		return NULL;

	if (!ENGINE_init(e)) {
		ENGINE_free(e);
		return NULL;
	}

	if (!ENGINE_set_default(e, ENGINE_METHOD_ALL)) {
		ENGINE_finish(e);
		ENGINE_free(e);
		return NULL;
	}

	return e;
}


static void test_want_async_handshake(void)
{
	ENGINE *e = load_dasync();
	struct pomp_loop *loop;
	SSL_CTX *client_ctx, *server_ctx;
	struct tskt_socket *server, *tcp_client = NULL, *tcp_accepted = NULL;
	struct tskt_socket *client = NULL, *accepted = NULL;
	char cert_path[64], key_path[64];
	char sbuf[] = "hi";
	char rbuf[16];
	uint16_t server_port = 0;
	SSL *client_ssl;
	int res, elapsed;

	if (!e) {
		/* dasync unavailable in this OpenSSL build: nothing to test */
		return;
	}

	loop = pomp_loop_new();
	CU_ASSERT_PTR_NOT_NULL_FATAL(loop);

	CU_ASSERT_EQUAL(ttls_test_write_temp_pem(TTLS_TEST_CERT_PEM,
						 cert_path,
						 sizeof(cert_path)),
			0);
	CU_ASSERT_EQUAL(ttls_test_write_temp_pem(
				TTLS_TEST_KEY_PEM, key_path, sizeof(key_path)),
			0);

	client_ctx = SSL_CTX_new(TLS_client_method());
	CU_ASSERT_PTR_NOT_NULL_FATAL(client_ctx);
	server_ctx = SSL_CTX_new(TLS_server_method());
	CU_ASSERT_PTR_NOT_NULL_FATAL(server_ctx);
	CU_ASSERT_EQUAL(
		ttls_ctx_use_certificate(server_ctx, cert_path, key_path), 0);

	/* dasync's dummy RSA async hook only covers the classic RSA
	 * sign/decrypt operations used by TLS <= 1.2's handshake; TLS 1.3's
	 * CertificateVerify goes through the newer RSA-PSS/provider-fetching
	 * signing path instead, which it doesn't intercept. Without this, the
	 * default-negotiated TLS 1.3 handshake completes synchronously and
	 * SSL_ERROR_WANT_ASYNC never happens. */
	CU_ASSERT_TRUE(
		SSL_CTX_set_max_proto_version(client_ctx, TLS1_2_VERSION));
	CU_ASSERT_TRUE(
		SSL_CTX_set_max_proto_version(server_ctx, TLS1_2_VERSION));

	res = tskt_socket_new_tcp(loop, &server);
	CU_ASSERT_EQUAL(res, 0);
	res = tskt_socket_listen(server, "127.0.0.1", 0);
	CU_ASSERT_EQUAL(res, 0);
	server_port = tskt_socket_get_local_port(server);
	CU_ASSERT_TRUE(server_port != 0);

	res = tskt_socket_new_tcp(loop, &tcp_client);
	CU_ASSERT_EQUAL(res, 0);
	res = tskt_socket_connect(
		tcp_client, NULL, 0, "127.0.0.1", server_port);
	CU_ASSERT_EQUAL(res, 0);

	elapsed = 0;
	do {
		res = tskt_socket_accept(server, NULL, 0, NULL, &tcp_accepted);
		if (res != -EAGAIN)
			break;
		pomp_loop_wait_and_process(loop, POLL_STEP_MS);
		elapsed += POLL_STEP_MS;
	} while (elapsed < TEST_TIMEOUT_MS);
	CU_ASSERT_EQUAL(res, 0);
	tskt_socket_destroy(server);

	client_ssl = SSL_new(client_ctx);
	CU_ASSERT_PTR_NOT_NULL_FATAL(client_ssl);
	res = ttls_socket_new(client_ssl, tcp_client, &client);
	CU_ASSERT_EQUAL(res, 0);

	res = ttls_socket_new_with_ctx(server_ctx, tcp_accepted, &accepted);
	CU_ASSERT_EQUAL(res, 0);

	/* with dasync as the default engine, the handshake's private-key
	 * signing operation goes through ASYNC_start_job() and pauses,
	 * surfacing here as SSL_ERROR_WANT_ASYNC -> ttls_want_async()
	 * registering the engine's fds via ttls_async_wait_fd_add(), and
	 * async_cb() resuming the handshake once dasync signals completion */
	elapsed = 0;
	do {
		res = tskt_socket_write(client, sbuf, sizeof(sbuf));
		if (res != -EAGAIN)
			break;
		pomp_loop_wait_and_process(loop, POLL_STEP_MS);
		elapsed += POLL_STEP_MS;
	} while (elapsed < TEST_TIMEOUT_MS);
	CU_ASSERT_EQUAL(res, (int)sizeof(sbuf));

	elapsed = 0;
	do {
		res = tskt_socket_read(accepted, rbuf, sizeof(rbuf), NULL);
		if (res != -EAGAIN)
			break;
		pomp_loop_wait_and_process(loop, POLL_STEP_MS);
		elapsed += POLL_STEP_MS;
	} while (elapsed < TEST_TIMEOUT_MS);
	CU_ASSERT_EQUAL(res, (int)sizeof(sbuf));

	tskt_socket_destroy(client);
	tskt_socket_destroy(accepted);
	pomp_loop_destroy(loop);
	SSL_CTX_free(client_ctx);
	SSL_CTX_free(server_ctx);
	remove(cert_path);
	remove(key_path);

	ENGINE_finish(e);
	ENGINE_free(e);
}


CU_TestInfo g_ttls_test_async_engine[] = {
	{FN("want-async-handshake"), &test_want_async_handshake},

	CU_TEST_INFO_NULL,
};
