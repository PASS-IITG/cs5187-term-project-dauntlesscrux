#ifndef OPENSSL_API_OWNERSHIP_MODEL_H
#define OPENSSL_API_OWNERSHIP_MODEL_H
#include <openssl/crypto.h>
void *CRYPTO_malloc(size_t, const char *, int) __attribute__((ownership_returns(malloc, 1)));
void *CRYPTO_zalloc(size_t, const char *, int) __attribute__((ownership_returns(malloc, 1)));
void *CRYPTO_memdup(const void *, size_t, const char *, int) __attribute__((ownership_returns(malloc, 2)));
char *CRYPTO_strdup(const char *, const char *, int) __attribute__((ownership_returns(malloc)));
char *CRYPTO_strndup(const char *, size_t, const char *, int) __attribute__((ownership_returns(malloc, 2)));
void CRYPTO_free(void *, const char *, int) __attribute__((ownership_takes(malloc, 1)));
void CRYPTO_clear_free(void *, size_t, const char *, int) __attribute__((ownership_takes(malloc, 1)));
void *CRYPTO_secure_malloc(size_t, const char *, int) __attribute__((ownership_returns(openssl_secure, 1)));
void *CRYPTO_secure_zalloc(size_t, const char *, int) __attribute__((ownership_returns(openssl_secure, 1)));
void CRYPTO_secure_free(void *, const char *, int) __attribute__((ownership_takes(openssl_secure, 1)));
void CRYPTO_secure_clear_free(void *, size_t, const char *, int) __attribute__((ownership_takes(openssl_secure, 1)));
#endif
