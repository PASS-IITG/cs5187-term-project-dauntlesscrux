void *OPENSSL_malloc(unsigned long);
void OPENSSL_free(void *);
int candidate(int fail) {
    char *p;
    p = OPENSSL_malloc(12);
    if (p == 0) return 0;
    if (fail) return -1; /* candidate to inspect */
    OPENSSL_free(p);
    return 1;
}
int safe(int fail) {
    char *p;
    p = OPENSSL_malloc(12);
    if (p == 0) return 0;
    if (fail) { OPENSSL_free(p); return -1; }
    OPENSSL_free(p);
    return 1;
}
