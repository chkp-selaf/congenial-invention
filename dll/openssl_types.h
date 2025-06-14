#pragma once

// This file contains minimal definitions for OpenSSL/BoringSSL types
// to avoid needing to link against the full library.

// Opaque struct for the SSL connection
typedef struct ssl_st SSL;

// Opaque struct for the SSL context
typedef struct ssl_ctx_st SSL_CTX;

// Function pointer types for the functions we want to hook or call.
// int SSL_write(SSL *ssl, const void *buf, int num);
typedef int(*SSL_write_t)(SSL* ssl, const void* buf, int num);

// int SSL_read(SSL *ssl, void *buf, int num);
typedef int (*SSL_read_t)(SSL* ssl, void* buf, int num);

// const char *SSL_get_servername(const SSL *s, const int type);
// Note: type is TLSEXT_NAMETYPE_host_name (0)
typedef const char* (*SSL_get_servername_t)(const SSL* s, const int type);

// For SSL_CTX_set_keylog_callback
// void SSL_CTX_set_keylog_callback(SSL_CTX *ctx, void (*cb)(const SSL *ssl, const char *line));
typedef void (*ssl_keylog_callback_func_t)(const SSL *ssl, const char *line);
typedef void (*SSL_CTX_set_keylog_callback_t)(SSL_CTX *ctx, ssl_keylog_callback_func_t cb);

// For SSL_new to get SSL_CTX*
// SSL *SSL_new(SSL_CTX *ctx);
typedef SSL* (*SSL_new_t)(SSL_CTX *ctx);

// We will also need to find SSL_get_servername using a pattern scan.
