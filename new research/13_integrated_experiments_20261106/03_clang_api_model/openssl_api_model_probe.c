#include <openssl/crypto.h>
void open_ssl_alloc_free(void) { void *p = OPENSSL_malloc(8); if (p != 0) OPENSSL_free(p); }
void open_ssl_alloc_wrong_free(void) { void *p = OPENSSL_malloc(8); if (p != 0) CRYPTO_secure_free(p, __FILE__, __LINE__); }
