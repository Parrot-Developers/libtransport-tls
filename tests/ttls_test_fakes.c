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

#include "ttls_test.h"

#include <string.h>


static inline struct fake_sock *to_fake_sock(struct tskt_socket *self)
{
	return (struct fake_sock *)self;
}


static int fake_sock_destroy(struct tskt_socket *self)
{
	struct fake_sock *fake = to_fake_sock(self);
	fake->destroy_called = true;
	return fake->destroy_ret;
}


static struct pomp_loop *fake_sock_get_loop(struct tskt_socket *self)
{
	struct fake_sock *fake = to_fake_sock(self);
	fake->get_loop_called = true;
	return fake->get_loop_ret;
}


static int fake_sock_get_local_addr(struct tskt_socket *self,
				    char *str,
				    size_t len,
				    uint16_t *port)
{
	struct fake_sock *fake = to_fake_sock(self);
	fake->get_local_addr_called = true;
	fake->get_local_addr_len = len;
	if (str != NULL && len > 0)
		snprintf(str,
			 len,
			 "%s",
			 fake->get_local_addr_str ? fake->get_local_addr_str
						  : "");
	if (port != NULL)
		*port = fake->get_local_addr_port;
	return fake->get_local_addr_ret;
}


static int fake_sock_get_remote_addr(struct tskt_socket *self,
				     char *str,
				     size_t len,
				     uint16_t *port)
{
	struct fake_sock *fake = to_fake_sock(self);
	fake->get_remote_addr_called = true;
	fake->get_remote_addr_len = len;
	if (str != NULL && len > 0)
		snprintf(str,
			 len,
			 "%s",
			 fake->get_remote_addr_str ? fake->get_remote_addr_str
						   : "");
	if (port != NULL)
		*port = fake->get_remote_addr_port;
	return fake->get_remote_addr_ret;
}


static int fake_sock_get_option(struct tskt_socket *self,
				enum tskt_option option)
{
	struct fake_sock *fake = to_fake_sock(self);
	fake->get_option_called = true;
	fake->get_option_option = option;
	return fake->get_option_ret[option];
}


static int fake_sock_set_option(struct tskt_socket *self,
				enum tskt_option option,
				int value)
{
	struct fake_sock *fake = to_fake_sock(self);
	fake->set_option_called = true;
	fake->set_option_option = option;
	fake->set_option_value = value;
	return fake->set_option_ret;
}


static ssize_t
fake_sock_read(struct tskt_socket *self, void *buf, size_t cap, uint64_t *ts_us)
{
	struct fake_sock *fake = to_fake_sock(self);
	size_t n;
	ssize_t ret = fake->read_ret;
	const void *data = fake->read_data;
	size_t data_len = fake->read_data_len;

	fake->read_called = true;
	fake->read_call_count++;
	if (fake->read_call_count > 1 && fake->read_ret2_set) {
		ret = fake->read_ret2;
		data = fake->read_data2;
		data_len = fake->read_data2_len;
	}
	if (buf != NULL && data != NULL && ret > 0) {
		n = data_len < cap ? data_len : cap;
		memcpy(buf, data, n);
	}
	if (ts_us != NULL)
		*ts_us = 0;
	return ret;
}


static ssize_t
fake_sock_write(struct tskt_socket *self, const void *buf, size_t len)
{
	struct fake_sock *fake = to_fake_sock(self);
	size_t n;
	fake->write_called = true;
	fake->write_call_count++;
	if (buf != NULL) {
		n = len < sizeof(fake->write_data) ? len
						   : sizeof(fake->write_data);
		memcpy(fake->write_data, buf, n);
		fake->write_data_len = n;
	}
	return fake->write_ret_all ? (ssize_t)len : fake->write_ret;
}


static ssize_t fake_sock_readv(struct tskt_socket *self,
			       const struct iovec *iov,
			       size_t iov_len,
			       uint64_t *ts_us)
{
	struct fake_sock *fake = to_fake_sock(self);
	(void)iov;
	(void)iov_len;
	fake->readv_called = true;
	if (ts_us != NULL)
		*ts_us = 0;
	return fake->readv_ret;
}


static ssize_t fake_sock_writev(struct tskt_socket *self,
				const struct iovec *iov,
				size_t iov_len)
{
	struct fake_sock *fake = to_fake_sock(self);
	(void)iov;
	(void)iov_len;
	fake->writev_called = true;
	return fake->writev_ret;
}


static int fake_sock_read_pkt(struct tskt_socket *self, struct tpkt_packet *pkt)
{
	struct fake_sock *fake = to_fake_sock(self);
	(void)pkt;
	fake->read_pkt_called = true;
	return fake->read_pkt_ret;
}


static int fake_sock_write_pkt(struct tskt_socket *self,
			       struct tpkt_packet *pkt)
{
	struct fake_sock *fake = to_fake_sock(self);
	(void)pkt;
	fake->write_pkt_called = true;
	return fake->write_pkt_ret;
}


static int fake_sock_set_event_cb(struct tskt_socket *self,
				  uint32_t events,
				  tskt_socket_event_cb_t cb,
				  void *userdata)
{
	struct fake_sock *fake = to_fake_sock(self);
	fake->set_event_cb_called = true;
	fake->set_event_cb_events = events;
	fake->event_cb = cb;
	fake->event_cb_userdata = userdata;
	return fake->set_event_cb_ret;
}


static int fake_sock_update_events(struct tskt_socket *self,
				   uint32_t events_to_add,
				   uint32_t events_to_remove)
{
	struct fake_sock *fake = to_fake_sock(self);
	fake->update_events_called = true;
	fake->update_events_add = events_to_add;
	fake->update_events_remove = events_to_remove;
	return fake->update_events_ret;
}


const struct tskt_socket_ops g_fake_sock_ops = {
	.destroy = fake_sock_destroy,
	.get_loop = fake_sock_get_loop,
	.get_local_addr = fake_sock_get_local_addr,
	.get_remote_addr = fake_sock_get_remote_addr,
	.get_option = fake_sock_get_option,
	.set_option = fake_sock_set_option,
	.read = fake_sock_read,
	.write = fake_sock_write,
	.readv = fake_sock_readv,
	.writev = fake_sock_writev,
	.read_pkt = fake_sock_read_pkt,
	.write_pkt = fake_sock_write_pkt,
	.set_event_cb = fake_sock_set_event_cb,
	.update_events = fake_sock_update_events,
};


void fake_sock_init(struct fake_sock *fake)
{
	memset(fake, 0, sizeof(*fake));
	fake->base.ops = &g_fake_sock_ops;
}
