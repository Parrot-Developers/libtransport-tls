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
 * Tests for src/ttls_utils.c: certificate/key/CA loading into an SSL_CTX,
 * plus the ttls_ulog_errors() helper. The throwaway self-signed test
 * certificate/key (certs/ttls_test_certs.h) is written out to temporary
 * files via ttls_test_write_temp_pem(), since these functions take a
 * cert_uri/pkey_uri/ca_uri filesystem path, not raw PEM data.
 */

#include "ttls_test.h"

#define ULOG_TAG ttls_test_utils
#include <ulog.h>
ULOG_DECLARE_TAG(ttls_test_utils);


static void test_use_certificate_success(void)
{
	SSL_CTX *ctx;
	char cert_path[64], key_path[64];

	CU_ASSERT_EQUAL(ttls_test_write_temp_pem(TTLS_TEST_CERT_PEM,
						 cert_path,
						 sizeof(cert_path)),
			0);
	CU_ASSERT_EQUAL(ttls_test_write_temp_pem(
				TTLS_TEST_KEY_PEM, key_path, sizeof(key_path)),
			0);

	ctx = SSL_CTX_new(TLS_server_method());
	CU_ASSERT_PTR_NOT_NULL_FATAL(ctx);

	CU_ASSERT_EQUAL(ttls_ctx_use_certificate(ctx, cert_path, key_path), 0);

	SSL_CTX_free(ctx);
	remove(cert_path);
	remove(key_path);
}


static void test_use_certificate_guards(void)
{
	SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
	CU_ASSERT_PTR_NOT_NULL_FATAL(ctx);

	CU_ASSERT_EQUAL(ttls_ctx_use_certificate(NULL, "a", "b"), -EINVAL);
	CU_ASSERT_EQUAL(ttls_ctx_use_certificate(ctx, NULL, "b"), -EINVAL);
	CU_ASSERT_EQUAL(ttls_ctx_use_certificate(ctx, "a", NULL), -EINVAL);

	SSL_CTX_free(ctx);
}


static void test_use_certificate_missing_file(void)
{
	SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
	CU_ASSERT_PTR_NOT_NULL_FATAL(ctx);

	CU_ASSERT_TRUE(ttls_ctx_use_certificate(ctx,
						"/nonexistent/test-cert.pem",
						"/nonexistent/test-key.pem") <
		       0);

	SSL_CTX_free(ctx);
}


static void test_use_certificate_mismatched_key(void)
{
	SSL_CTX *ctx;
	char cert_path[64], key_path[64];

	CU_ASSERT_EQUAL(ttls_test_write_temp_pem(TTLS_TEST_CERT_PEM,
						 cert_path,
						 sizeof(cert_path)),
			0);
	CU_ASSERT_EQUAL(
		ttls_test_write_temp_pem(
			TTLS_TEST_CERT_PEM /* not a key: guaranteed mismatch */,
			key_path,
			sizeof(key_path)),
		0);

	ctx = SSL_CTX_new(TLS_server_method());
	CU_ASSERT_PTR_NOT_NULL_FATAL(ctx);

	CU_ASSERT_TRUE(ttls_ctx_use_certificate(ctx, cert_path, key_path) < 0);

	SSL_CTX_free(ctx);
	remove(cert_path);
	remove(key_path);
}


static void test_load_ca_success(void)
{
	SSL_CTX *ctx;
	char ca_path[64];

	CU_ASSERT_EQUAL(ttls_test_write_temp_pem(
				TTLS_TEST_CERT_PEM, ca_path, sizeof(ca_path)),
			0);

	ctx = SSL_CTX_new(TLS_client_method());
	CU_ASSERT_PTR_NOT_NULL_FATAL(ctx);

	CU_ASSERT_EQUAL(ttls_ctx_load_ca(ctx, ca_path), 0);

	SSL_CTX_free(ctx);
	remove(ca_path);
}


static void test_load_ca_guards_and_missing_file(void)
{
	SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
	CU_ASSERT_PTR_NOT_NULL_FATAL(ctx);

	CU_ASSERT_EQUAL(ttls_ctx_load_ca(NULL, "a"), -EINVAL);
	CU_ASSERT_EQUAL(ttls_ctx_load_ca(ctx, NULL), -EINVAL);
	CU_ASSERT_TRUE(ttls_ctx_load_ca(ctx, "/nonexistent/ca.pem") < 0);

	SSL_CTX_free(ctx);
}


static void test_load_ca_list_multiple(void)
{
	SSL_CTX *ctx;
	char ca_path_a[64], ca_path_b[64], list[160];

	CU_ASSERT_EQUAL(ttls_test_write_temp_pem(TTLS_TEST_CERT_PEM,
						 ca_path_a,
						 sizeof(ca_path_a)),
			0);
	CU_ASSERT_EQUAL(ttls_test_write_temp_pem(TTLS_TEST_CERT_PEM,
						 ca_path_b,
						 sizeof(ca_path_b)),
			0);

	ctx = SSL_CTX_new(TLS_client_method());
	CU_ASSERT_PTR_NOT_NULL_FATAL(ctx);

	CU_ASSERT_TRUE(
		snprintf(list, sizeof(list), "%s,%s", ca_path_a, ca_path_b) <
		(int)sizeof(list));
	CU_ASSERT_EQUAL(ttls_ctx_load_ca_list(ctx, list), 0);

	SSL_CTX_free(ctx);
	remove(ca_path_a);
	remove(ca_path_b);
}


static void test_load_ca_list_fail_fast(void)
{
	SSL_CTX *ctx;
	char ca_path[64], list[160];

	CU_ASSERT_EQUAL(ttls_test_write_temp_pem(
				TTLS_TEST_CERT_PEM, ca_path, sizeof(ca_path)),
			0);

	ctx = SSL_CTX_new(TLS_client_method());
	CU_ASSERT_PTR_NOT_NULL_FATAL(ctx);

	CU_ASSERT_TRUE(snprintf(list,
				sizeof(list),
				"%s,/nonexistent/ca.pem",
				ca_path) < (int)sizeof(list));
	CU_ASSERT_TRUE(ttls_ctx_load_ca_list(ctx, list) < 0);

	CU_ASSERT_EQUAL(ttls_ctx_load_ca_list(NULL, list), -EINVAL);
	CU_ASSERT_EQUAL(ttls_ctx_load_ca_list(ctx, NULL), -EINVAL);

	SSL_CTX_free(ctx);
	remove(ca_path);
}


static void test_ulog_errors_smoke(void)
{
	/* no pending error: must not crash */
	ttls_ulog_errors(&__ULOG_COOKIE);

	/* with a pending error: must not crash, and must empty the queue */
	ERR_put_error(ERR_LIB_SSL, 0, ERR_R_INTERNAL_ERROR, __FILE__, __LINE__);
	CU_ASSERT_TRUE(ERR_peek_error() != 0);
	ttls_ulog_errors(&__ULOG_COOKIE);
	CU_ASSERT_EQUAL(ERR_peek_error(), 0);
}


CU_TestInfo g_ttls_test_utils[] = {
	{FN("use-certificate-success"), &test_use_certificate_success},
	{FN("use-certificate-guards"), &test_use_certificate_guards},
	{FN("use-certificate-missing-file"),
	 &test_use_certificate_missing_file},
	{FN("use-certificate-mismatched-key"),
	 &test_use_certificate_mismatched_key},
	{FN("load-ca-success"), &test_load_ca_success},
	{FN("load-ca-guards-and-missing-file"),
	 &test_load_ca_guards_and_missing_file},
	{FN("load-ca-list-multiple"), &test_load_ca_list_multiple},
	{FN("load-ca-list-fail-fast"), &test_load_ca_list_fail_fast},
	{FN("ulog-errors-smoke"), &test_ulog_errors_smoke},

	CU_TEST_INFO_NULL,
};
