#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <string.h>

static int handshake_pair(SSL *client, SSL *server)
{
    int i;
    for (i = 0; i < 10000; ++i) {
        int cr = SSL_do_handshake(client);
        int ce = cr == 1 ? SSL_ERROR_NONE : SSL_get_error(client, cr);
        int sr = SSL_do_handshake(server);
        int se = sr == 1 ? SSL_ERROR_NONE : SSL_get_error(server, sr);
        if (SSL_is_init_finished(client) && SSL_is_init_finished(server))
            return 1;
        if ((cr <= 0 && ce != SSL_ERROR_WANT_READ && ce != SSL_ERROR_WANT_WRITE)
            || (sr <= 0 && se != SSL_ERROR_WANT_READ && se != SSL_ERROR_WANT_WRITE))
            return 0;
    }
    return 0;
}

int main(int argc, char **argv)
{
    const char *cert = argc > 1 ? argv[1] : "test/smime-certs/smrsa3-cert.pem";
    const char *key = argc > 2 ? argv[2] : "test/smime-certs/smrsa3-key.pem";
    SSL_CTX *sc = NULL, *cc = NULL;
    SSL *server = NULL, *client = NULL;
    BIO *cbio = NULL, *sbio = NULL;
    const unsigned char msg[] = "application data not yet fully consumed";
    unsigned char buf[sizeof(msg)];
    size_t n = 0, nr = 0;
    int rc = 2, free_rc;

    OPENSSL_init_ssl(0, NULL);
    sc = SSL_CTX_new(TLS_server_method());
    cc = SSL_CTX_new(TLS_client_method());
    if (!sc || !cc || !SSL_CTX_set_min_proto_version(sc, TLS1_2_VERSION)
        || !SSL_CTX_set_max_proto_version(sc, TLS1_2_VERSION)
        || !SSL_CTX_set_min_proto_version(cc, TLS1_2_VERSION)
        || !SSL_CTX_set_max_proto_version(cc, TLS1_2_VERSION)
        || !SSL_CTX_use_certificate_file(sc, cert, SSL_FILETYPE_PEM)
        || !SSL_CTX_use_PrivateKey_file(sc, key, SSL_FILETYPE_PEM)
        || !SSL_CTX_check_private_key(sc))
        goto done;
    SSL_CTX_set_verify(cc, SSL_VERIFY_NONE, NULL);
    client = SSL_new(cc);
    server = SSL_new(sc);
    if (!client || !server || !BIO_new_bio_pair(&cbio, 0, &sbio, 0))
        goto done;
    SSL_set_bio(client, cbio, cbio);
    SSL_set_bio(server, sbio, sbio);
    cbio = sbio = NULL;
    SSL_set_connect_state(client);
    SSL_set_accept_state(server);
    if (!handshake_pair(client, server)) {
        fprintf(stderr, "handshake failed\n");
        ERR_print_errors_fp(stderr);
        goto done;
    }
    if (!SSL_write_ex(client, msg, sizeof(msg), &n) || n != sizeof(msg)) {
        fprintf(stderr, "SSL_write_ex failed\n");
        ERR_print_errors_fp(stderr);
        goto done;
    }
    if (!SSL_read_ex(server, buf, 1, &nr) || nr != 1) {
        fprintf(stderr, "first partial SSL_read_ex failed, nr=%zu\n", nr);
        ERR_print_errors_fp(stderr);
        goto done;
    }
    printf("first SSL_read_ex returned %zu byte; requesting SSL_free_buffers\n", nr);
    fflush(stdout);
    free_rc = SSL_free_buffers(server);
    printf("SSL_free_buffers returned %d\n", free_rc);
    fflush(stdout);
    if (!SSL_read_ex(server, buf + 1, sizeof(buf) - 1, &nr)) {
        fprintf(stderr, "second SSL_read_ex failed\n");
        ERR_print_errors_fp(stderr);
        goto done;
    }
    printf("second SSL_read_ex returned %zu bytes\n", nr);
    rc = 0;
done:
    BIO_free(cbio);
    BIO_free(sbio);
    SSL_free(client);
    SSL_free(server);
    SSL_CTX_free(cc);
    SSL_CTX_free(sc);
    return rc;
}
