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
#include <futils/list.h>
#include <libpomp.h>
#include <pthread.h>
#include <stdlib.h>

#include "ttls_async.h"

#define ULOG_TAG ttls_async
#include <ulog.h>
ULOG_DECLARE_TAG(ttls_async);


struct async_wait_fd {
	struct list_node node;
	struct pomp_loop *loop;
	int fd;
	struct list_node connl;
};

struct async_wait_conn {
	struct list_node node;
	ttls_async_wait_cb_t cb;
	void *userdata;
};

static pthread_mutex_t async_lock = PTHREAD_MUTEX_INITIALIZER;
static struct list_node async_waitl = list_head_init(async_waitl);


static void async_wait_fd_cb(int fd, uint32_t revents, void *userdata);


static void awc_free(struct async_wait_conn *awc)
{
	list_del(&awc->node);
	free(awc);
}


static void awf_free(struct async_wait_fd *awf)
{
	list_del(&awf->node);
	struct async_wait_conn *awc = NULL, *tmp_awc = NULL;
	list_walk_entry_forward_safe(&awf->connl, awc, tmp_awc, node)
	{
		awc_free(awc);
	}
	if (pomp_loop_has_fd(awf->loop, awf->fd))
		pomp_loop_remove(awf->loop, awf->fd);
	free(awf);
}


static struct async_wait_conn *async_wait_conn_lookup(struct async_wait_fd *awf,
						      ttls_async_wait_cb_t cb,
						      void *userdata)
{
	struct async_wait_conn *awc = NULL;
	list_walk_entry_forward(&awf->connl, awc, node)
	{
		if (awc->cb == cb && awc->userdata == userdata)
			return awc;
	}
	return NULL;
}


static struct async_wait_fd *async_wait_fd_lookup(struct pomp_loop *loop,
						  int fd)
{
	struct async_wait_fd *awf = NULL;
	list_walk_entry_forward(&async_waitl, awf, node)
	{
		if (awf->loop == loop && awf->fd == fd)
			return awf;
	}
	return NULL;
}


/* get a fd descriptor (existing or new one) */
static int async_wait_fd_get(struct pomp_loop *loop,
			     int fd,
			     struct async_wait_fd **awf_res)
{
	struct async_wait_fd *awf;
	int ret;

	awf = async_wait_fd_lookup(loop, fd);
	if (awf)
		goto success;

	awf = calloc(1, sizeof(*awf));
	if (!awf) {
		ret = -ENOMEM;
		ULOG_ERRNO("calloc", -ret);
		return ret;
	}

	list_init(&awf->node);
	awf->loop = loop;
	awf->fd = fd;
	list_init(&awf->connl);
	ret = pomp_loop_add(loop, fd, POMP_FD_EVENT_IN, async_wait_fd_cb, awf);
	if (ret < 0) {
		ULOG_ERRNO("pomp_loop_add", -ret);
		free(awf);
		return ret;
	}
	list_add_before(&async_waitl, &awf->node);

success:
	*awf_res = awf;

	return 0;
}


int ttls_async_init(void)
{
	return 0;
}


void ttls_async_deinit(void)
{
	struct async_wait_fd *awf = NULL, *tmp_awf = NULL;
	list_walk_entry_forward_safe(&async_waitl, awf, tmp_awf, node)
	{
		awf_free(awf);
	}
}


int ttls_async_wait_fd_add(struct pomp_loop *loop,
			   int fd,
			   ttls_async_wait_cb_t cb,
			   void *userdata)
{
	struct async_wait_fd *awf = NULL;
	struct async_wait_conn *awc;
	int ret;

	pthread_mutex_lock(&async_lock);

	/* allocate new fd descriptor or get existing one */
	ret = async_wait_fd_get(loop, fd, &awf);
	if (ret < 0)
		goto done;

	/* check if it's already added ? */
	awc = async_wait_conn_lookup(awf, cb, userdata);
	if (awc) {
		/* adding same connection with same handler: noop */
		goto done;
	}

	awc = calloc(1, sizeof(*awc));
	if (!awc) {
		if (list_is_empty(&awf->connl))
			awf_free(awf);
		ret = -ENOMEM;
		ULOG_ERRNO("calloc", -ret);
		goto done;
	}

	/* append to list of connections for this fd */
	awc->cb = cb;
	awc->userdata = userdata;
	list_add_before(&awf->connl, &awc->node);

done:
	pthread_mutex_unlock(&async_lock);
	return ret;
}


void ttls_async_wait_fd_remove(struct pomp_loop *loop,
			       int fd,
			       ttls_async_wait_cb_t cb,
			       void *userdata)
{
	struct async_wait_fd *awf;
	struct async_wait_conn *awc;

	pthread_mutex_lock(&async_lock);

	/* retrieve fd descriptor */
	awf = async_wait_fd_lookup(loop, fd);
	if (!awf)
		goto done;

	/* search for matching connection */
	awc = async_wait_conn_lookup(awf, cb, userdata);
	if (!awc)
		goto done;

	/* remove connection */
	awc_free(awc);

	/* remove fd from polling if no connection attached */
	if (list_is_empty(&awf->connl))
		awf_free(awf);

done:
	pthread_mutex_unlock(&async_lock);
}


static void async_wait_fd_cb(int fd, uint32_t revents, void *userdata)
{
	struct async_wait_fd *awf = userdata;

	ULOG_ERRNO_RETURN_IF(awf == NULL, EINVAL);

	if (!(revents & (POMP_FD_EVENT_ERR | POMP_FD_EVENT_IN))) {
		ULOGW("async_wait_fd_cb: got unexpected event on fd=%d",
		      awf->fd);
		return;
	}

	/* remove pomp handler */
	pomp_loop_remove(awf->loop, fd);

	/* remove from list of waiters */
	pthread_mutex_lock(&async_lock);
	list_del(&awf->node);
	pthread_mutex_unlock(&async_lock);

	/* call async handlers */
	struct async_wait_conn *awc = NULL, *tmp_awc = NULL;
	list_walk_entry_forward_safe(&awf->connl, awc, tmp_awc, node)
	{
		awc->cb(awf->fd, awc->userdata);
		awc_free(awc);
	}

	/* release waiter */
	free(awf);
}
