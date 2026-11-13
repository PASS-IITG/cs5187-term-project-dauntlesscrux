void OPENSSL_free(void *);
void *OPENSSL_malloc(unsigned long);

void repeated_sequential(void *p) {
    OPENSSL_free(p);
    OPENSSL_free(p); /* positive repeated-release control */
}
void mutually_exclusive(void *p, int c) {
    if (c) OPENSSL_free(p);
    else OPENSSL_free(p); /* expected syntactic match, path false positive */
}
void single_release(void *p) {
    OPENSSL_free(p); /* negative control: only one call */
}
void repeated_after_reacquire(void *p) {
    OPENSSL_free(p);
    p = OPENSSL_malloc(8);
    OPENSSL_free(p); /* expected heuristic match, requires lifetime review */
}

void alloc_then_return(int fail) {
    char *p;
    p = OPENSSL_malloc(16);
    if (p == 0) return 0;
    if (fail) return 1; /* positive allocation/return shape */
    OPENSSL_free(p);
    return 2;
}
char *transfer_to_caller(void) {
    char *p;
    p = OPENSSL_malloc(8);
    if (p == 0) return 0;
    return p; /* expected match; ownership transfer */
}
void unreachable_alloc(void) {
    char *p;
    return;
    p = OPENSSL_malloc(8); /* negative: no later return in this function */
}
