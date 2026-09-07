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

#ifndef _TTLS_TEST_FAKES_H_
#define _TTLS_TEST_FAKES_H_

#include <stdbool.h>
#include <stdint.h>

#include <transport-socket/tskt_ops.h>


/*
 * Fake tskt_socket_ops implementation, standing in for the transport socket
 * wrapped by a TLS socket (struct ttls_socket's "tsock").
 *
 * Only the ops that src/ttls_socket.c and src/ttls_bio.c actually call on
 * their wrapped tskt_socket are implemented: destroy, get_loop,
 * get_local_addr, get_remote_addr, get_option, set_option, read, write,
 * readv, writev, read_pkt, write_pkt, set_event_cb, update_events.
 *
 * Every op records that it was called (with its arguments, where useful)
 * into the owning struct fake_sock, then returns a scripted value set by the
 * test before the call. This allows driving ttls_socket.c's non-handshake
 * logic, and ttls_bio.c's BIO read/write/ctrl behaviour, without any real
 * socket I/O.
 *
 * Usage: declare a struct fake_sock on the stack or heap, call
 * fake_sock_init() on it, script the *_ret (and, for output parameters, the
 * associated data) fields needed by the test, then pass &fake.base as the
 * struct tskt_socket* to the API under test.
 */
extern const struct tskt_socket_ops g_fake_sock_ops;

struct fake_sock {
	struct tskt_socket
		base; /* must stay first: base.ops = &g_fake_sock_ops */

	bool destroy_called;
	int destroy_ret;

	bool get_loop_called;
	struct pomp_loop *get_loop_ret;

	bool get_local_addr_called;
	size_t get_local_addr_len;
	const char *get_local_addr_str;
	uint16_t get_local_addr_port;
	int get_local_addr_ret;

	bool get_remote_addr_called;
	size_t get_remote_addr_len;
	const char *get_remote_addr_str;
	uint16_t get_remote_addr_port;
	int get_remote_addr_ret;

	bool get_option_called;
	enum tskt_option get_option_option;
	int get_option_ret[TSKT_OPT_RESET + 1];

	bool set_option_called;
	enum tskt_option set_option_option;
	int set_option_value;
	int set_option_ret;

	bool read_called;
	int read_call_count; /* incremented on every ops->read() call */
	ssize_t read_ret;
	const void *read_data;
	size_t read_data_len;
	/* if set, the 2nd and following calls return these instead, to script
	 * a sequence of reads (e.g. a message split across reads) */
	bool read_ret2_set;
	ssize_t read_ret2;
	const void *read_data2;
	size_t read_data2_len;

	bool write_called;
	int write_call_count; /* incremented on every ops->write() call */
	ssize_t write_ret;
	bool write_ret_all; /* if true, return len (full write) instead of
			     * write_ret, without having to guess the exact
			     * encoded length up front */
	uint8_t write_data[16384];
	size_t write_data_len;

	bool readv_called;
	ssize_t readv_ret;

	bool writev_called;
	ssize_t writev_ret;

	bool read_pkt_called;
	int read_pkt_ret;

	bool write_pkt_called;
	int write_pkt_ret;

	bool set_event_cb_called;
	uint32_t set_event_cb_events;
	tskt_socket_event_cb_t event_cb;
	void *event_cb_userdata;
	int set_event_cb_ret;

	bool update_events_called;
	uint32_t update_events_add;
	uint32_t update_events_remove;
	int update_events_ret;
};


/* Reset a fake socket to its default (all zero/false) state and bind it
 * to g_fake_sock_ops. */
void fake_sock_init(struct fake_sock *fake);


#endif /* !_TTLS_TEST_FAKES_H_ */
