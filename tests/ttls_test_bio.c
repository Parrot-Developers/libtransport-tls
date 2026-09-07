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
 * Tests for src/ttls_bio.c: a custom OpenSSL BIO_METHOD bridging BIO
 * read/write/ctrl calls onto a struct tskt_socket. No SSL object is involved
 * here at all -- ttls_bio_new() wraps a struct fake_sock directly and tests
 * call BIO_read()/BIO_write()/BIO_ctrl() (via its macro wrappers) on the
 * resulting BIO*.
 */

#include "ttls_test.h"

#include "ttls_bio.h"


static void test_read_success(void)
{
	struct fake_sock fake;
	BIO *bio;
	char buf[16];
	int ret;

	fake_sock_init(&fake);
	fake.read_ret = 5;
	fake.read_data = "hello";
	fake.read_data_len = 5;

	bio = ttls_bio_new(&fake.base);
	CU_ASSERT_PTR_NOT_NULL_FATAL(bio);

	memset(buf, 0, sizeof(buf));
	ret = BIO_read(bio, buf, sizeof(buf));
	CU_ASSERT_EQUAL(ret, 5);
	CU_ASSERT_NSTRING_EQUAL(buf, "hello", 5);
	CU_ASSERT_TRUE(fake.read_called);

	BIO_set_shutdown(bio, 0);
	BIO_free(bio);
}


static void test_read_eof(void)
{
	struct fake_sock fake;
	BIO *bio;
	char buf[16];
	int ret;

	fake_sock_init(&fake);
	fake.read_ret = 0;

	bio = ttls_bio_new(&fake.base);
	CU_ASSERT_PTR_NOT_NULL_FATAL(bio);

	ret = BIO_read(bio, buf, sizeof(buf));
	CU_ASSERT_EQUAL(ret, 0);
	CU_ASSERT_TRUE(BIO_eof(bio));

	BIO_set_shutdown(bio, 0);
	BIO_free(bio);
}


static void test_read_retryable_errno(void)
{
	static const int retryable[] = {EAGAIN, EINPROGRESS, EINTR, ENOTCONN};
	size_t i;

	for (i = 0; i < sizeof(retryable) / sizeof(retryable[0]); i++) {
		struct fake_sock fake;
		BIO *bio;
		char buf[16];
		int ret;

		fake_sock_init(&fake);
		fake.read_ret = -retryable[i];

		bio = ttls_bio_new(&fake.base);
		CU_ASSERT_PTR_NOT_NULL_FATAL(bio);

		ret = BIO_read(bio, buf, sizeof(buf));
		CU_ASSERT_EQUAL(ret, -1);
		CU_ASSERT_TRUE(BIO_should_retry(bio));
		CU_ASSERT_TRUE(BIO_should_retry(bio) && BIO_should_read(bio));

		BIO_set_shutdown(bio, 0);
		BIO_free(bio);
	}
}


static void test_read_non_retryable_errno(void)
{
	struct fake_sock fake;
	BIO *bio;
	char buf[16];
	int ret;

	fake_sock_init(&fake);
	fake.read_ret = -EPROTO;

	bio = ttls_bio_new(&fake.base);
	CU_ASSERT_PTR_NOT_NULL_FATAL(bio);

	ret = BIO_read(bio, buf, sizeof(buf));
	CU_ASSERT_EQUAL(ret, -1);
	CU_ASSERT_FALSE(BIO_should_retry(bio));

	BIO_set_shutdown(bio, 0);
	BIO_free(bio);
}


static void test_write_success(void)
{
	struct fake_sock fake;
	BIO *bio;
	int ret;

	fake_sock_init(&fake);
	fake.write_ret_all = true;

	bio = ttls_bio_new(&fake.base);
	CU_ASSERT_PTR_NOT_NULL_FATAL(bio);

	ret = BIO_write(bio, "abc", 3);
	CU_ASSERT_EQUAL(ret, 3);
	CU_ASSERT_TRUE(fake.write_called);
	CU_ASSERT_EQUAL(fake.write_data_len, (size_t)3);
	CU_ASSERT_NSTRING_EQUAL(fake.write_data, "abc", 3);

	BIO_set_shutdown(bio, 0);
	BIO_free(bio);
}


static void test_write_retryable_errno(void)
{
	struct fake_sock fake;
	BIO *bio;
	int ret;

	fake_sock_init(&fake);
	fake.write_ret = -EAGAIN;

	bio = ttls_bio_new(&fake.base);
	CU_ASSERT_PTR_NOT_NULL_FATAL(bio);

	ret = BIO_write(bio, "abc", 3);
	CU_ASSERT_EQUAL(ret, -1);
	CU_ASSERT_TRUE(BIO_should_retry(bio));
	CU_ASSERT_TRUE(BIO_should_retry(bio) && BIO_should_write(bio));

	BIO_set_shutdown(bio, 0);
	BIO_free(bio);
}


static void test_ctrl_get_set_close(void)
{
	struct fake_sock fake;
	BIO *bio;

	fake_sock_init(&fake);
	bio = ttls_bio_new(&fake.base);
	CU_ASSERT_PTR_NOT_NULL_FATAL(bio);

	/* BIO_set_shutdown() returns void (modern OpenSSL); only
	 * BIO_get_shutdown() returns a value to assert on */
	BIO_set_shutdown(bio, 1);
	CU_ASSERT_EQUAL(BIO_get_shutdown(bio), 1);
	BIO_set_shutdown(bio, 0);
	CU_ASSERT_EQUAL(BIO_get_shutdown(bio), 0);

	BIO_free(bio);
}


static void test_destroy_owns_socket(void)
{
	struct fake_sock fake;
	BIO *bio;

	fake_sock_init(&fake);
	bio = ttls_bio_new(&fake.base);
	CU_ASSERT_PTR_NOT_NULL_FATAL(bio);

	BIO_set_shutdown(bio, 1);
	BIO_free(bio);

	CU_ASSERT_TRUE(fake.destroy_called);
}


static void test_destroy_does_not_own_socket(void)
{
	struct fake_sock fake;
	BIO *bio;

	fake_sock_init(&fake);
	bio = ttls_bio_new(&fake.base);
	CU_ASSERT_PTR_NOT_NULL_FATAL(bio);

	BIO_set_shutdown(bio, 0);
	BIO_free(bio);

	CU_ASSERT_FALSE(fake.destroy_called);
}


CU_TestInfo g_ttls_test_bio[] = {
	{FN("read-success"), &test_read_success},
	{FN("read-eof"), &test_read_eof},
	{FN("read-retryable-errno"), &test_read_retryable_errno},
	{FN("read-non-retryable-errno"), &test_read_non_retryable_errno},
	{FN("write-success"), &test_write_success},
	{FN("write-retryable-errno"), &test_write_retryable_errno},
	{FN("ctrl-get-set-close"), &test_ctrl_get_set_close},
	{FN("destroy-owns-socket"), &test_destroy_owns_socket},
	{FN("destroy-does-not-own-socket"), &test_destroy_does_not_own_socket},

	CU_TEST_INFO_NULL,
};
