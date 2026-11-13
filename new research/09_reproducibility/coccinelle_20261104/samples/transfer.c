typedef struct bio_st BIO;
typedef struct ssl_st SSL;
void SSL_set0_rbio(SSL *, BIO *);
void BIO_free(BIO *);
void suspect(SSL *s, BIO *b) {
    SSL_set0_rbio(s, b);
    BIO_free(b);
}
void safe_reacquire_reference(SSL *s, BIO *b) {
    BIO_up_ref(b);
    SSL_set0_rbio(s, b);
    BIO_free(b); /* not necessarily wrong: distinct ref was retained */
}
