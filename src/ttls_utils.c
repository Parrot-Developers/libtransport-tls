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

#include <openssl/err.h>
#include <openssl/ssl.h>
#if OPENSSL_VERSION_MAJOR >= 3
#	include <openssl/store.h>
#endif

#define ULOG_TAG ttls_utils
#include <ulog.h>
ULOG_DECLARE_TAG(ttls_utils);

#include <transport-tls/ttls_utils.h>


static int err_log_cb(const char *str, size_t len, void *userdata)
{
	struct ulog_cookie *cookie = userdata;
	ulog_log(ULOG_ERR, cookie, "%.*s", (int)len, str);
	return 1;
}

void ttls_ulog_errors(struct ulog_cookie *cookie)
{
	ERR_print_errors_cb(err_log_cb, cookie);
}


/*
 * Certificates management
 */

#if OPENSSL_VERSION_MAJOR >= 3

static int load_privkey_from_uri(const char *uri, EVP_PKEY **key)
{
	OSSL_STORE_CTX *ctx = NULL;
	int res;

	if (!uri || !key || *key != NULL)
		return -EINVAL;

	ctx = OSSL_STORE_open(uri, NULL, NULL, NULL, NULL);
	if (!ctx) {
		ULOGE("OSSL_STORE_open() failed for %s", uri);
		TTLS_ULOG_ERRORS();
		res = -ENOENT;
		goto finish;
	}

	if (OSSL_STORE_expect(ctx, OSSL_STORE_INFO_PKEY) != 1) {
		ULOGE("OSSL_STORE_expect() on %s failed", uri);
		res = -EINVAL;
		goto finish;
	}

	while (*key == NULL && OSSL_STORE_eof(ctx) != 1) {
		OSSL_STORE_INFO *info = OSSL_STORE_load(ctx);
		if (!info) {
			/* Wrong type for entry, try the next one */
			continue;
		}
		if (OSSL_STORE_INFO_get_type(info) == OSSL_STORE_INFO_PKEY) {
			*key = OSSL_STORE_INFO_get1_PKEY(info);
			if (*key == NULL) {
				ULOGE("failed to load private key from %s",
				      uri);
				TTLS_ULOG_ERRORS();
			}
		}
		OSSL_STORE_INFO_free(info);
		info = NULL;
	}

	if (!*key)
		ULOGE("no private key found at URI %s", uri);
	res = *key != NULL ? 0 : -ENOENT;
finish:
	OSSL_STORE_close(ctx);
	ctx = NULL;
	return res;
}

static int load_cert_from_uri(const char *uri, X509 **cert)
{
	OSSL_STORE_CTX *ctx = NULL;
	int res;

	if (!uri || !cert || *cert != NULL)
		return -EINVAL;

	ctx = OSSL_STORE_open(uri, NULL, NULL, NULL, NULL);
	if (!ctx) {
		ULOGE("OSSL_STORE_open() failed for %s", uri);
		TTLS_ULOG_ERRORS();
		res = -ENOENT;
		goto finish;
	}

	if (OSSL_STORE_expect(ctx, OSSL_STORE_INFO_CERT) != 1) {
		ULOGE("OSSL_STORE_expect() on %s failed", uri);
		res = -EINVAL;
		goto finish;
	}

	while (*cert == NULL && OSSL_STORE_eof(ctx) != 1) {
		OSSL_STORE_INFO *info = OSSL_STORE_load(ctx);
		if (!info) {
			/* Wrong type for entry, try the next one */
			continue;
		}
		if (OSSL_STORE_INFO_get_type(info) == OSSL_STORE_INFO_CERT) {
			*cert = OSSL_STORE_INFO_get1_CERT(info);
			if (*cert == NULL) {
				ULOGE("failed to load certificate from %s",
				      uri);
				TTLS_ULOG_ERRORS();
			}
		}
		OSSL_STORE_INFO_free(info);
		info = NULL;
	}

	if (!*cert)
		ULOGE("no certificate found at URI %s", uri);
	res = *cert != NULL ? 0 : -ENOENT;
finish:
	OSSL_STORE_close(ctx);
	ctx = NULL;
	return res;
}


int ttls_ctx_use_certificate(struct ssl_ctx_st *ssl_ctx,
			     const char *cert_uri,
			     const char *pkey_uri)
{
	EVP_PKEY *key = NULL;
	X509 *cert = NULL;
	int res;

	if (!ssl_ctx || !cert_uri || !pkey_uri)
		return -EINVAL;

	/* Load and set certificate */
	res = load_cert_from_uri(cert_uri, &cert);
	if (res) {
		ULOGE("failed to load cert '%s'", cert_uri);
		goto finish;
	}
	if (SSL_CTX_use_certificate(ssl_ctx, cert) != 1) {
		ULOGE("failed to use certificate '%s'\n", cert_uri);
		TTLS_ULOG_ERRORS();
		res = -EINVAL;
		goto finish;
	}

	/* Load and set private key */
	res = load_privkey_from_uri(pkey_uri, &key);
	if (res) {
		ULOGE("failed to load private key '%s'", pkey_uri);
		goto finish;
	}
	res = SSL_CTX_use_PrivateKey(ssl_ctx, key);
	if (!res) {
		ULOGE("failed to use private key '%s'", pkey_uri);
		TTLS_ULOG_ERRORS();
		res = -EINVAL;
		goto finish;
	}

	/* Success */
	res = 0;

finish:
	EVP_PKEY_free(key);
	key = NULL;
	X509_free(cert);
	cert = NULL;
	return res;
}


int ttls_ctx_load_ca(struct ssl_ctx_st *ssl_ctx, const char *ca_uri)
{
	X509_STORE *store;
	X509 *cert = NULL;
	int res;

	if (!ssl_ctx || !ca_uri)
		return -EINVAL;

	/* Load CA from uri */
	res = load_cert_from_uri(ca_uri, &cert);
	if (res) {
		ULOGE("failed to load ca '%s'", ca_uri);
		return res;
	}

	/* Add CA to store */
	store = SSL_CTX_get_cert_store(ssl_ctx);
	if (!store) {
		ULOGE("cannot get cert store");
		TTLS_ULOG_ERRORS();
		res = -EINVAL;
	} else if (!X509_STORE_add_cert(store, cert)) {
		ULOGE("cannot add ca to store");
		TTLS_ULOG_ERRORS();
		res = -EINVAL;
	}

	X509_free(cert);
	cert = NULL;
	return res;
}

#else
/* OpenSSL 1.x */

static const char *get_filename(const char *uri)
{
	char *p = strchr(uri, ':');
	if (!p)
		return uri;

	/* only 'file:' scheme is supported */
	if ((p - uri) != 4 || strncmp(uri, "file", 4) != 0) {
		ULOGE("uri '%s' not supported in OpenSSL 1.x", uri);
		return NULL;
	}
	return p + 1;
}


int ttls_ctx_use_certificate(struct ssl_ctx_st *ssl_ctx,
			     const char *cert_uri,
			     const char *pkey_uri)
{
	const char *filename;

	if (!ssl_ctx || !cert_uri || !pkey_uri)
		return -EINVAL;

	filename = get_filename(cert_uri);
	if (!filename || SSL_CTX_use_certificate_file(
				 ssl_ctx, filename, SSL_FILETYPE_PEM) != 1) {
		ULOGE("failed to use certificate '%s'", cert_uri);
		TTLS_ULOG_ERRORS();
		return -EINVAL;
	}
	filename = get_filename(pkey_uri);
	if (!filename || SSL_CTX_use_PrivateKey_file(
				 ssl_ctx, filename, SSL_FILETYPE_PEM) != 1) {
		ULOGE("failed to read private key '%s'", pkey_uri);
		TTLS_ULOG_ERRORS();
		return -EINVAL;
	}
	return 0;
}


int ttls_ctx_load_ca(struct ssl_ctx_st *ssl_ctx, const char *ca_uri)
{
	const char *filename;

	if (!ssl_ctx || !ca_uri)
		return -EINVAL;

	filename = get_filename(ca_uri);
	if (!filename ||
	    !SSL_CTX_load_verify_locations(ssl_ctx, filename, NULL)) {
		ULOGE("failed to load CA '%s'", ca_uri);
		TTLS_ULOG_ERRORS();
		return -EINVAL;
	}
	return 0;
}

#endif


int ttls_ctx_load_ca_list(struct ssl_ctx_st *ssl_ctx, const char *ca_list)
{
	if (!ssl_ctx || !ca_list)
		return -EINVAL;

	const char *p = ca_list;
	while (p) {
		char buf[256];
		const char *uri;
		char *sep = strchr(p, ',');
		if (sep) {
			size_t len = sep - p;
			if (len >= sizeof(buf)) {
				ULOGE("uri of CA list too long '%s'", p);
				return -EINVAL;
			}
			memcpy(buf, p, len);
			buf[len] = 0;
			uri = buf;
			p = sep + 1;
		} else {
			uri = p;
			p = NULL;
		}
		int res = ttls_ctx_load_ca(ssl_ctx, uri);
		if (res)
			return res;
	}
	return 0;
}
