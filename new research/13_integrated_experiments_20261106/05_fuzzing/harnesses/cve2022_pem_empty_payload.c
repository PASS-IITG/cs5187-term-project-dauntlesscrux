#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/pem.h>
#include <stdio.h>
#include <string.h>

int main(void)
{
    static const char input[] =
        "-----BEGIN CERTIFICATE-----\n-\n-----END CERTIFICATE-----";
    BIO *bio = BIO_new_mem_buf(input, (int)strlen(input));
    char *name = NULL, *header = NULL;
    unsigned char *data = NULL;
    long len = -1;
    int ret;

    if (bio == NULL)
        return 2;
    ret = PEM_read_bio_ex(bio, &name, &header, &data, &len, 0);
    printf("PEM_read_bio_ex ret=%d name=%p header=%p data=%p len=%ld\n",
           ret, (void *)name, (void *)header, (void *)data, len);
    fflush(stdout);
    OPENSSL_free(name);
    OPENSSL_free(header);
    OPENSSL_free(data);
    BIO_free(bio);
    return 0;
}
