/* SPDX-License-Identifier: GPL-2.0 */
/*
 * tunl TLS - OpenSSL wrapper for TLS connections
 */

#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

#include "common.h"

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>

static SSL_CTX *g_server_ctx;
static SSL_CTX *g_client_ctx;

int tunl_tls_init(const char *cert, const char *key)
{
	SSL_library_init();
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();

	g_server_ctx = SSL_CTX_new(TLS_server_method());
	if (!g_server_ctx) {
		tunl_log(TUNL_LOG_ERROR, "tls: server ctx failed");
		return -1;
	}

	SSL_CTX_set_min_proto_version(g_server_ctx, TLS1_2_VERSION);
	SSL_CTX_set_options(g_server_ctx,
		SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 |
		SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);

	if (cert && key) {
		if (access(cert, R_OK) != 0 || access(key, R_OK) != 0) {
			tunl_log(TUNL_LOG_ERROR, "tls: cert/key not readable");
			return -1;
		}

		if (SSL_CTX_use_certificate_file(g_server_ctx, cert,
						 SSL_FILETYPE_PEM) <= 0 ||
		    SSL_CTX_use_PrivateKey_file(g_server_ctx, key,
						SSL_FILETYPE_PEM) <= 0) {
			tunl_log(TUNL_LOG_ERROR, "tls: cert/key load failed");
			return -1;
		}

		if (!SSL_CTX_check_private_key(g_server_ctx)) {
			tunl_log(TUNL_LOG_ERROR, "tls: key mismatch");
			return -1;
		}
	}

	g_client_ctx = SSL_CTX_new(TLS_client_method());
	if (!g_client_ctx) {
		tunl_log(TUNL_LOG_ERROR, "tls: client ctx failed");
		return -1;
	}
	SSL_CTX_set_min_proto_version(g_client_ctx, TLS1_2_VERSION);

	tunl_log(TUNL_LOG_INFO, "tls: initialized");
	return 0;
}

void tunl_tls_cleanup(void)
{
	if (g_server_ctx) {
		SSL_CTX_free(g_server_ctx);
		g_server_ctx = NULL;
	}
	if (g_client_ctx) {
		SSL_CTX_free(g_client_ctx);
		g_client_ctx = NULL;
	}
	EVP_cleanup();
	ERR_free_strings();
}

SSL *tunl_tls_accept(int fd)
{
	SSL *ssl;

	if (!g_server_ctx)
		return NULL;

	ssl = SSL_new(g_server_ctx);
	if (!ssl)
		return NULL;

	SSL_set_fd(ssl, fd);

	if (SSL_accept(ssl) <= 0) {
		SSL_free(ssl);
		return NULL;
	}

	return ssl;
}

SSL *tunl_tls_connect(int fd, const char *hostname)
{
	SSL *ssl;

	if (!g_client_ctx)
		return NULL;

	ssl = SSL_new(g_client_ctx);
	if (!ssl)
		return NULL;

	SSL_set_fd(ssl, fd);

	if (hostname)
		SSL_set_tlsext_host_name(ssl, hostname);

	if (SSL_connect(ssl) <= 0) {
		SSL_free(ssl);
		return NULL;
	}

	return ssl;
}

ssize_t tunl_tls_read(SSL *ssl, void *buf, size_t len)
{
	int n, err;

	if (!ssl || !buf)
		return -1;

	if (len > INT_MAX)
		len = INT_MAX;

	n = SSL_read(ssl, buf, (int)len);
	if (n <= 0) {
		err = SSL_get_error(ssl, n);
		if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
			return 0;
		return -1;
	}
	return (ssize_t)n;
}

ssize_t tunl_tls_write(SSL *ssl, const void *buf, size_t len)
{
	int n, err;

	if (!ssl || !buf)
		return -1;

	if (len > INT_MAX)
		len = INT_MAX;

	n = SSL_write(ssl, buf, (int)len);
	if (n <= 0) {
		err = SSL_get_error(ssl, n);
		if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
			return 0;
		return -1;
	}
	return (ssize_t)n;
}

void tunl_tls_close(SSL *ssl)
{
	if (!ssl)
		return;
	SSL_shutdown(ssl);
	SSL_free(ssl);
}
