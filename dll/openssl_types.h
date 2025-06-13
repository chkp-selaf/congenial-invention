#pragma once

// This file contains minimal definitions for OpenSSL/BoringSSL types
// to avoid needing to link against the full library.

// Opaque struct for the SSL connection
typedef struct ssl_st SSL;

// Function pointer types for the functions we want to hook or call.
// int SSL_write(SSL *ssl, const void *buf, int num);
typedef int(*SSL_write_t)(SSL* ssl, const void* buf, int num);

// const char *SSL_get_servername(const SSL *s, const int type);
// Note: type is TLSEXT_NAMETYPE_host_name (0)
typedef const char* (*SSL_get_servername_t)(const SSL* s, const int type);

// We will also need to find SSL_get_servername using a pattern scan.
