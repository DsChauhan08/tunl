#include "common.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>
#include <openssl/sha.h>
#include <string.h>
#include <unistd.h>

static SSL_CTX* g_server_ctx = NULL;
static SSL_CTX* g_client_ctx = NULL;

int tls_init(const char* cert, const char* key) {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    
    g_server_ctx = SSL_CTX_new(TLS_server_method());
    if (!g_server_ctx) {
        spf_log(SPF_LOG_ERROR, "tls: failed to create server ctx");
        return -1;
    }
    
    SSL_CTX_set_min_proto_version(g_server_ctx, TLS1_2_VERSION);
    SSL_CTX_set_options(g_server_ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);

    SSL_CTX_set_mode(g_server_ctx, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    SSL_CTX_set_session_cache_mode(g_server_ctx, SSL_SESS_CACHE_SERVER);
    SSL_CTX_set_timeout(g_server_ctx, 300);
    
    SSL_CTX_set_cipher_list(g_server_ctx, 
        "ECDHE-ECDSA-AES256-GCM-SHA384:"
        "ECDHE-RSA-AES256-GCM-SHA384:"
        "ECDHE-ECDSA-AES128-GCM-SHA256:"
        "ECDHE-RSA-AES128-GCM-SHA256");
    
    if (cert && key) {
        if (access(cert, R_OK) != 0) {
            spf_log(SPF_LOG_ERROR, "tls: cert not readable: %s", cert);
            return -1;
        }
        if (access(key, R_OK) != 0) {
            spf_log(SPF_LOG_ERROR, "tls: key not readable: %s", key);
            return -1;
        }
        
        if (SSL_CTX_use_certificate_file(g_server_ctx, cert, SSL_FILETYPE_PEM) <= 0) {
            spf_log(SPF_LOG_ERROR, "tls: failed to load cert");
            return -1;
        }
        if (SSL_CTX_use_PrivateKey_file(g_server_ctx, key, SSL_FILETYPE_PEM) <= 0) {
            spf_log(SPF_LOG_ERROR, "tls: failed to load key");
            return -1;
        }
        if (!SSL_CTX_check_private_key(g_server_ctx)) {
            spf_log(SPF_LOG_ERROR, "tls: key doesn't match cert");
            return -1;
        }
    }
    
    g_client_ctx = SSL_CTX_new(TLS_client_method());
    if (!g_client_ctx) {
        spf_log(SPF_LOG_ERROR, "tls: failed to create client ctx");
        return -1;
    }
    SSL_CTX_set_min_proto_version(g_client_ctx, TLS1_2_VERSION);
    SSL_CTX_set_mode(g_client_ctx, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    SSL_CTX_set_verify(g_client_ctx, SSL_VERIFY_PEER, NULL);
    if (SSL_CTX_set_default_verify_paths(g_client_ctx) != 1) {
        spf_log(SPF_LOG_WARN, "tls: could not load default client trust store");
    }
    
    spf_log(SPF_LOG_INFO, "tls: initialized");
    return 0;
}

void tls_cleanup(void) {
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

SSL_CTX* tls_get_server_ctx(void) {
    return g_server_ctx;
}

SSL_CTX* tls_get_client_ctx(void) {
    return g_client_ctx;
}

SSL* tls_accept(int fd) {
    if (!g_server_ctx) return NULL;
    
    SSL* ssl = SSL_new(g_server_ctx);
    if (!ssl) return NULL;
    
    SSL_set_fd(ssl, fd);
    
    if (SSL_accept(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        return NULL;
    }
    
    return ssl;
}

SSL* tls_connect(int fd, const char* hostname) {
    if (!g_client_ctx) return NULL;
    
    SSL* ssl = SSL_new(g_client_ctx);
    if (!ssl) return NULL;
    
    SSL_set_fd(ssl, fd);
    
    if (hostname) {
        SSL_set_tlsext_host_name(ssl, hostname);
    }
    
    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        return NULL;
    }
    
    return ssl;
}

SSL* tls_connect_backend(int fd, const char* hostname, const char* ca_path, bool verify_peer) {
    if (!g_client_ctx) return NULL;

    SSL* ssl = SSL_new(g_client_ctx);
    if (!ssl) return NULL;

    SSL_set_fd(ssl, fd);

    if (hostname && *hostname) {
        SSL_set_tlsext_host_name(ssl, hostname);
    }

    if (ca_path && *ca_path) {
        if (SSL_set1_host(ssl, hostname && *hostname ? hostname : NULL) != 1) {
            SSL_free(ssl);
            return NULL;
        }
        if (SSL_CTX_load_verify_locations(g_client_ctx, ca_path, NULL) != 1) {
            spf_log(SPF_LOG_ERROR, "tls: failed to load backend CA: %s", ca_path);
            SSL_free(ssl);
            return NULL;
        }
    }

    if (verify_peer) {
        SSL_set_verify(ssl, SSL_VERIFY_PEER, NULL);
    } else {
        SSL_set_verify(ssl, SSL_VERIFY_NONE, NULL);
    }

    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        return NULL;
    }

    return ssl;
}

ssize_t tls_read(SSL* ssl, void* buf, size_t len) {
    if (!ssl) return -1;
    int n = SSL_read(ssl, buf, len);
    if (n <= 0) {
        int err = SSL_get_error(ssl, n);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            return 0;
        }
        return -1;
    }
    return n;
}

ssize_t tls_write(SSL* ssl, const void* buf, size_t len) {
    if (!ssl) return -1;
    int n = SSL_write(ssl, buf, len);
    if (n <= 0) {
        int err = SSL_get_error(ssl, n);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            return 0;
        }
        return -1;
    }
    return n;
}

void tls_close(SSL* ssl) {
    if (!ssl) return;
    SSL_shutdown(ssl);
    SSL_free(ssl);
}

int tls_set_client_cert(const char* cert, const char* key) {
    if (!g_client_ctx) return -1;
    
    if (SSL_CTX_use_certificate_file(g_client_ctx, cert, SSL_FILETYPE_PEM) <= 0) {
        return -1;
    }
    if (SSL_CTX_use_PrivateKey_file(g_client_ctx, key, SSL_FILETYPE_PEM) <= 0) {
        return -1;
    }
    
    spf_log(SPF_LOG_INFO, "tls: client cert loaded for mtls");
    return 0;
}

int tls_set_client_ca(const char* ca_path) {
    if (!g_server_ctx || !ca_path || !*ca_path) return -1;

    if (SSL_CTX_load_verify_locations(g_server_ctx, ca_path, NULL) != 1) {
        spf_log(SPF_LOG_ERROR, "tls: failed to load client CA: %s", ca_path);
        return -1;
    }

    if (SSL_CTX_set_default_verify_paths(g_server_ctx) != 1) {
        spf_log(SPF_LOG_WARN, "tls: failed to load default verify paths");
    }

    STACK_OF(X509_NAME)* cert_names = SSL_load_client_CA_file(ca_path);
    if (cert_names) {
        SSL_CTX_set_client_CA_list(g_server_ctx, cert_names);
    }

    spf_log(SPF_LOG_INFO, "tls: loaded client CA bundle");
    return 0;
}

int tls_set_backend_trust(const char* ca_path) {
    if (!g_client_ctx || !ca_path || !*ca_path) return -1;
    if (SSL_CTX_load_verify_locations(g_client_ctx, ca_path, NULL) != 1) {
        spf_log(SPF_LOG_ERROR, "tls: failed to load backend CA: %s", ca_path);
        return -1;
    }
    SSL_CTX_set_verify(g_client_ctx, SSL_VERIFY_PEER, NULL);
    return 0;
}

int tls_verify_peer_name(SSL* ssl, const char* expected_name) {
    if (!ssl || !expected_name || !*expected_name) return -1;
    X509* cert = SSL_get_peer_certificate(ssl);
    if (!cert) {
        return -1;
    }

    int ok = X509_check_host(cert, expected_name, 0, 0, NULL);
    X509_free(cert);
    return ok == 1 ? 0 : -1;
}

int tls_verify_peer_pin_sha256(SSL* ssl, const char* expected_hex) {
    if (!ssl || !expected_hex || strlen(expected_hex) != 64) return -1;

    X509* cert = SSL_get_peer_certificate(ssl);
    if (!cert) {
        return -1;
    }

    unsigned char* der = NULL;
    int der_len = i2d_X509(cert, &der);
    if (der_len <= 0) {
        X509_free(cert);
        return -1;
    }

    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256(der, (size_t)der_len, digest);
    OPENSSL_free(der);
    X509_free(cert);

    char hex[65];
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        snprintf(hex + i * 2, 3, "%02x", digest[i]);
    }
    hex[64] = '\0';

    return strncmp(hex, expected_hex, 64) == 0 ? 0 : -1;
}

int tls_require_client_cert(void) {
    if (!g_server_ctx) return -1;
    SSL_CTX_set_verify(g_server_ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    spf_log(SPF_LOG_INFO, "tls: mtls enabled");
    return 0;
}

const char* tls_get_cipher(SSL* ssl) {
    if (!ssl) return "none";
    return SSL_get_cipher(ssl);
}

const char* tls_get_version(SSL* ssl) {
    if (!ssl) return "none";
    return SSL_get_version(ssl);
}
