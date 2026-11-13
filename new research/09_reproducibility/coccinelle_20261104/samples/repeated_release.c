void OPENSSL_free(void *);
void suspect(void *p) {
    OPENSSL_free(p);
    OPENSSL_free(p);
}
void branches(void *p, int c) {
    if (c) OPENSSL_free(p);
    else OPENSSL_free(p); /* likely false positive: mutually exclusive */
}
