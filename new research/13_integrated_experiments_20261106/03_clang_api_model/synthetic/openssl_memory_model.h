#ifndef OPENSSL_MEMORY_MODEL_H
#define OPENSSL_MEMORY_MODEL_H
#include <stddef.h>
void *OPENSSL_malloc(size_t) __attribute__((ownership_returns(malloc, 1)));
void *OPENSSL_zalloc(size_t) __attribute__((ownership_returns(malloc, 1)));
void *CRYPTO_malloc(size_t, const char *, int) __attribute__((ownership_returns(malloc, 1)));
void *CRYPTO_zalloc(size_t, const char *, int) __attribute__((ownership_returns(malloc, 1)));
void OPENSSL_free(void *) __attribute__((ownership_takes(malloc, 1)));
void CRYPTO_free(void *, const char *, int) __attribute__((ownership_takes(malloc, 1)));
void model_take(void *) __attribute__((ownership_takes(malloc, 1)));
void model_hold(void *) __attribute__((ownership_holds(malloc, 1)));
#endif
