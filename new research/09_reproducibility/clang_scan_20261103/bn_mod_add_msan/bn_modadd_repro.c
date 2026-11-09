#include <openssl/bn.h>
#include <stdio.h>
#include <string.h>

int BN_mod_add_quick(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
                     const BIGNUM *m);

int main(int argc, char **argv)
{
    BIGNUM *r = BN_new(), *a = BN_new(), *b = BN_new(), *m = BN_new();
    int mode = argc > 1 ? argv[1][0] : 'a';
    int ok;

    if (r == NULL || a == NULL || b == NULL || m == NULL || !BN_set_word(m, 17))
        return 2;
    if (mode == 'b' && !BN_set_word(a, 1))
        return 3;
    /* mode a: a=0,b=0; mode b: a=1,b=0 */
    ok = BN_mod_add_quick(r, a, b, m);
    printf("mode=%c ok=%d result=%lu\n", mode, ok, BN_get_word(r));
    BN_free(r); BN_free(a); BN_free(b); BN_free(m);
    return ok ? 0 : 4;
}
