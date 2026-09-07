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
 * Tests for src/ttls_async.c: a registry of fd-watch callbacks used to
 * support OpenSSL's async engine mode. No SSL/tskt objects are needed here at
 * all -- a real pomp_loop plus real pipe() fds are enough to exercise the
 * registry's add/remove/fire/cleanup logic.
 */

#include "ttls_test.h"

#include "ttls_async.h"

#include <unistd.h>


#define TEST_TIMEOUT_MS 2000
#define POLL_STEP_MS 20


struct async_ctx {
	int call_count;
	int last_fd;
};


static void async_test_cb(int fd, void *userdata)
{
	struct async_ctx *ctx = userdata;
	ctx->call_count++;
	ctx->last_fd = fd;
}


static bool spin_until(struct pomp_loop *loop, struct async_ctx *ctx, int count)
{
	int elapsed = 0;

	while (ctx->call_count < count) {
		if (elapsed >= TEST_TIMEOUT_MS)
			return false;
		pomp_loop_wait_and_process(loop, POLL_STEP_MS);
		elapsed += POLL_STEP_MS;
	}
	return true;
}


static void test_add_twice_is_noop(void)
{
	struct pomp_loop *loop = pomp_loop_new();
	struct async_ctx ctx = {0};
	int fds[2];

	CU_ASSERT_PTR_NOT_NULL_FATAL(loop);
	CU_ASSERT_EQUAL(pipe(fds), 0);

	CU_ASSERT_EQUAL(
		ttls_async_wait_fd_add(loop, fds[0], async_test_cb, &ctx), 0);
	CU_ASSERT_EQUAL(
		ttls_async_wait_fd_add(loop, fds[0], async_test_cb, &ctx), 0);

	CU_ASSERT_EQUAL(write(fds[1], "x", 1), 1);
	CU_ASSERT_TRUE(spin_until(loop, &ctx, 1));
	/* give a chance for a (bogus) second call to show up */
	pomp_loop_wait_and_process(loop, POLL_STEP_MS);
	CU_ASSERT_EQUAL(ctx.call_count, 1);
	CU_ASSERT_EQUAL(ctx.last_fd, fds[0]);

	close(fds[0]);
	close(fds[1]);
	pomp_loop_destroy(loop);
}


static void test_multiple_callbacks_same_fd(void)
{
	struct pomp_loop *loop = pomp_loop_new();
	struct async_ctx ctx_a = {0}, ctx_b = {0};
	int fds[2];

	CU_ASSERT_PTR_NOT_NULL_FATAL(loop);
	CU_ASSERT_EQUAL(pipe(fds), 0);

	CU_ASSERT_EQUAL(
		ttls_async_wait_fd_add(loop, fds[0], async_test_cb, &ctx_a), 0);
	CU_ASSERT_EQUAL(
		ttls_async_wait_fd_add(loop, fds[0], async_test_cb, &ctx_b), 0);

	CU_ASSERT_EQUAL(write(fds[1], "x", 1), 1);
	CU_ASSERT_TRUE(spin_until(loop, &ctx_a, 1));
	CU_ASSERT_TRUE(spin_until(loop, &ctx_b, 1));
	CU_ASSERT_EQUAL(ctx_a.call_count, 1);
	CU_ASSERT_EQUAL(ctx_b.call_count, 1);

	close(fds[0]);
	close(fds[1]);
	pomp_loop_destroy(loop);
}


static void test_remove_one_leaves_other(void)
{
	struct pomp_loop *loop = pomp_loop_new();
	struct async_ctx ctx_a = {0}, ctx_b = {0};
	int fds[2];

	CU_ASSERT_PTR_NOT_NULL_FATAL(loop);
	CU_ASSERT_EQUAL(pipe(fds), 0);

	CU_ASSERT_EQUAL(
		ttls_async_wait_fd_add(loop, fds[0], async_test_cb, &ctx_a), 0);
	CU_ASSERT_EQUAL(
		ttls_async_wait_fd_add(loop, fds[0], async_test_cb, &ctx_b), 0);

	ttls_async_wait_fd_remove(loop, fds[0], async_test_cb, &ctx_a);

	CU_ASSERT_EQUAL(write(fds[1], "x", 1), 1);
	CU_ASSERT_TRUE(spin_until(loop, &ctx_b, 1));
	/* give ctx_a a chance to (wrongly) fire too */
	pomp_loop_wait_and_process(loop, POLL_STEP_MS);
	CU_ASSERT_EQUAL(ctx_a.call_count, 0);
	CU_ASSERT_EQUAL(ctx_b.call_count, 1);

	close(fds[0]);
	close(fds[1]);
	pomp_loop_destroy(loop);
}


static void test_deinit_cleans_remaining(void)
{
	struct pomp_loop *loop = pomp_loop_new();
	struct async_ctx ctx = {0};
	int fds[2];

	CU_ASSERT_PTR_NOT_NULL_FATAL(loop);
	CU_ASSERT_EQUAL(pipe(fds), 0);

	/* register a waiter but never make fds[0] readable: it must still be
	 * possible to tear everything down cleanly */
	CU_ASSERT_EQUAL(
		ttls_async_wait_fd_add(loop, fds[0], async_test_cb, &ctx), 0);

	ttls_async_deinit();
	CU_ASSERT_EQUAL(ctx.call_count, 0);

	close(fds[0]);
	close(fds[1]);
	pomp_loop_destroy(loop);
}


CU_TestInfo g_ttls_test_async[] = {
	{FN("add-twice-is-noop"), &test_add_twice_is_noop},
	{FN("multiple-callbacks-same-fd"), &test_multiple_callbacks_same_fd},
	{FN("remove-one-leaves-other"), &test_remove_one_leaves_other},
	{FN("deinit-cleans-remaining"), &test_deinit_cleans_remaining},

	CU_TEST_INFO_NULL,
};
