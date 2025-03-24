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
#include <fcntl.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libpomp.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <transport-packet/tpkt.h>
#include <transport-socket/tskt.h>
#include <transport-tls/ttls.h>

#define SERVER_TCP_PORT 11111

#define ECHO_PKT_LEN 4096

struct echo_server {
	struct tskt_socket *sock;
	struct tpkt_packet *pkt;
	size_t total;
};

static bool app_stop;

static struct tpkt_packet *new_packet(size_t len)
{
	struct pomp_buffer *buf = pomp_buffer_new(len);
	if (!buf)
		return NULL;
	struct tpkt_packet *pkt;
	int res = tpkt_new_from_buffer(buf, &pkt);
	pomp_buffer_unref(buf);
	if (res < 0)
		return NULL;
	return pkt;
}

static int get_tcp_fd(struct tskt_socket *tls)
{
	return tskt_socket_get_fd(ttls_socket_get_socket(tls));
}

/* tls echo server i/o events handler */
static void
tls_echo_server_cb(struct tskt_socket *sock, uint32_t revents, void *userdata)
{
	struct echo_server *echo = (struct echo_server *)userdata;
	int res;

	if (revents & POMP_FD_EVENT_ERR) {
		/* print socket error */
		printf("socket error(fd=%d): %s\n",
		       get_tcp_fd(echo->sock),
		       strerror(tskt_socket_get_error(echo->sock)));
		/* close socket */
		goto close_socket;
	}

	if (revents & POMP_FD_EVENT_OUT) {
		if (echo->pkt != NULL) {
			/* send pending data */
			res = tskt_socket_write_pkt(echo->sock, echo->pkt);
			if (res < 0) {
				printf("socket_write(fd=%d): %s\n",
				       get_tcp_fd(echo->sock),
				       strerror(-res));
				if (res == -EPROTO)
					ERR_print_errors_fp(stderr);
				goto close_socket;
			}
			tpkt_unref(echo->pkt);
			echo->pkt = NULL;
		}
		/* disable OUT event, re-enable IN event */
		tskt_socket_update_events(
			echo->sock, POMP_FD_EVENT_IN, POMP_FD_EVENT_OUT);
	}

	if (revents & POMP_FD_EVENT_IN) {
		struct tpkt_packet *pkt = new_packet(ECHO_PKT_LEN);
		if (pkt == NULL)
			goto close_socket;

		res = tskt_socket_read_pkt(echo->sock, pkt);
		if (res < 0) {
			tpkt_unref(pkt);
			if (res != -EAGAIN) {
				printf("socket_read(fd=%d): %s\n",
				       get_tcp_fd(echo->sock),
				       strerror(-res));
				if (res == -EPROTO)
					ERR_print_errors_fp(stderr);
				goto close_socket;
			}
		} else {
			size_t len;
			res = tpkt_get_cdata(pkt, NULL, &len, NULL);
			if (res < 0 || len == 0) {
				if (res < 0)
					printf("tpkt_get_cdata(fd=%d): %s\n",
					       get_tcp_fd(echo->sock),
					       strerror(-res));
				else
					printf("connection closed by peer"
					       "(fd=%d)\n",
					       get_tcp_fd(echo->sock));
				tpkt_unref(pkt);
				goto close_socket;
			}
			echo->total += len;
			res = tskt_socket_write_pkt(echo->sock, pkt);
			if (res == -EAGAIN) {
				/* keep reference to packet for sending it later
				 */
				echo->pkt = pkt;
				/* stop reading IN data, wait for OUT event */
				tskt_socket_update_events(echo->sock,
							  POMP_FD_EVENT_OUT,
							  POMP_FD_EVENT_IN);
			} else {
				tpkt_unref(pkt);
				if (res < 0) {
					printf("socket_write(fd=%d): %s\n",
					       get_tcp_fd(echo->sock),
					       strerror(-res));
					if (res == -EPROTO)
						ERR_print_errors_fp(stderr);
					goto close_socket;
				}
			}
		}
	}

	return;

close_socket:
	printf("close socket(fd=%d), received %zu bytes\n",
	       get_tcp_fd(echo->sock),
	       echo->total);
	tpkt_unref(echo->pkt);
	tskt_socket_destroy(echo->sock);
	free(echo);
}

/* tcp server socket events handlers */
static void tls_listen_server_cb(struct tskt_socket *server_sock,
				 uint32_t revents,
				 void *userdata)
{
	SSL_CTX *ssl_ctx = userdata;
	while (1) {
		struct tskt_socket *sock, *ssl_sock;
		char addr[INET_ADDRSTRLEN];
		uint16_t port;
		struct echo_server *echo;
		SSL *ssl;

		int res = tskt_socket_accept(
			server_sock, addr, sizeof(addr), &port, &sock);
		if (res < 0) {
			if (res != -EAGAIN)
				printf("tskt_socket_accept: %s\n",
				       strerror(-res));
			break;
		}

		printf("new connection from %s:%u (fd=%d)\n",
		       addr,
		       port,
		       tskt_socket_get_fd(sock));

		/* create TLS socket */
		ssl = SSL_new(ssl_ctx);
		res = ttls_socket_new(ssl, sock, &ssl_sock);
		if (res < 0) {
			printf("ttls_socket_new: %s\n", strerror(-res));
			tskt_socket_destroy(sock);
			continue;
		}

		/* create echo server */
		echo = calloc(1, sizeof(*echo));
		if (echo == NULL) {
			tskt_socket_destroy(ssl_sock);
			continue;
		}

		echo->sock = ssl_sock;
		/* monitor i/o events */
		res = tskt_socket_set_event_cb(
			echo->sock, POMP_FD_EVENT_IN, tls_echo_server_cb, echo);
		if (res < 0) {
			printf("tskt_socket_set_event_cb: %s\n",
			       strerror(-res));
			tskt_socket_destroy(echo->sock);
			free(echo);
		}
	}
}

/* main function */
int main(int argc, char **argv)
{
	int res;
	SSL_CTX *ssl_ctx;
	char *cert, *key;
#ifndef OPENSSL_NO_ENGINE
	ENGINE *ssl_engine;
	char *engine;
#endif
	bool use_engine = false;

	use_engine = argc >= 2 && strcmp(argv[1], "-engine") == 0;
	if (argc < 3 || (use_engine && argc < 5)) {
		fprintf(stderr,
			"missing argument, usage:\n"
			"ttls-server <cert-file.pem> <key-file.pem>\n"
			"ttls-server -engine <engine-name> <key-name> <cert-file.pem>\n");
		return 1;
	}

	if (use_engine) {
#ifndef OPENSSL_NO_ENGINE
		engine = argv[2];
		key = argv[3];
		cert = argv[4];
#else
		fprintf(stderr, "engine not supported\n");
		return 1;
#endif
	} else {
#ifndef OPENSSL_NO_ENGINE
		engine = NULL;
#endif
		cert = argv[1];
		key = argv[2];
	}

	printf("start TLS test server\n");

	/* initialize openssl and ttls libraries */
	OPENSSL_init_ssl(0, NULL);
	res = ttls_init();
	if (res < 0) {
		fprintf(stderr, "cannot initialize ttls: %s\n", strerror(-res));
		return 1;
	}

	/* create TLS server context */
	ssl_ctx = SSL_CTX_new(TLS_server_method());
	if (!ssl_ctx) {
		fprintf(stderr, "ssl_ctx_new: failed");
		ERR_print_errors_fp(stderr);
		return 1;
	}
	if (SSL_CTX_use_certificate_file(ssl_ctx, cert, SSL_FILETYPE_PEM) !=
	    1) {
		fprintf(stderr, "failed to read certificate '%s'\n", cert);
		ERR_print_errors_fp(stderr);
		return 1;
	}
#ifndef OPENSSL_NO_ENGINE
	if (engine) {
		EVP_PKEY *pkey;
		ssl_engine = ENGINE_by_id(engine);
		if (!ssl_engine) {
			fprintf(stderr,
				"failed to lookup engine '%s'\n",
				engine);
			ERR_print_errors_fp(stderr);
			return 1;
		}
		if (!ENGINE_init(ssl_engine)) {
			fprintf(stderr,
				"failed to initialized engine '%s'\n",
				engine);
			ERR_print_errors_fp(stderr);
			return 1;
		}
		pkey = ENGINE_load_private_key(ssl_engine, key, NULL, NULL);
		if (!pkey) {
			fprintf(stderr,
				"can't load private key '%s' from engine '%s'\n",
				key,
				engine);
			ERR_print_errors_fp(stderr);
			return 1;
		}

		if (!SSL_CTX_use_PrivateKey(ssl_ctx, pkey)) {
			fprintf(stderr,
				"can't used private key '%s' from engine '%s'\n",
				key,
				engine);
			ERR_print_errors_fp(stderr);
			return 1;
		}
	} else {
		ssl_engine = NULL;
#endif
		if (SSL_CTX_use_PrivateKey_file(
			    ssl_ctx, key, SSL_FILETYPE_PEM) != 1) {
			fprintf(stderr,
				"failed to read private key '%s'\n",
				key);
			ERR_print_errors_fp(stderr);
			return 1;
		}
#ifndef OPENSSL_NO_ENGINE
	}
#endif

	/* pomp loop */
	struct pomp_loop *loop = pomp_loop_new();

	/* create tcp socket */
	struct tskt_socket *sock;
	res = tskt_socket_new_tcp(loop, &sock);
	if (res < 0) {
		printf("tskt_socket_new_tcp: %s\n", strerror(-res));
		return 1;
	}

	/* listen for tcp connections */
	res = tskt_socket_listen(sock, NULL, SERVER_TCP_PORT);
	if (res < 0) {
		printf("tskt_socket_listen: %s\n", strerror(-res));
		return 1;
	}

	/* monitor i/o events */
	res = tskt_socket_set_event_cb(
		sock, POMP_FD_EVENT_IN, tls_listen_server_cb, ssl_ctx);
	if (res < 0) {
		printf("tskt_socket_set_event_cb: %s\n", strerror(-res));
		return 1;
	}

	/* main loop */
	while (!app_stop)
		pomp_loop_wait_and_process(loop, -1);

	/* release resources */
	tskt_socket_destroy(sock);
	pomp_loop_destroy(loop);
	SSL_CTX_free(ssl_ctx);
#ifndef OPENSSL_NO_ENGINE
	if (ssl_engine) {
		ENGINE_finish(ssl_engine);
		ENGINE_free(ssl_engine);
	}
#endif
	ttls_deinit();

	return 0;
}
