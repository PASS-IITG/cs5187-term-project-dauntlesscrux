void OPENSSL_free(void *);
struct item { int value; };
void suspect(struct item *p) {
    OPENSSL_free(p);
    consume(p->value);
}
void reset_before_use(struct item *p) {
    OPENSSL_free(p);
    p = get_item();
    consume(p->value);
}
