#include "tls.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void
uvv_ssl__init() {
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    ERR_load_crypto_strings();
    ERR_load_BIO_strings();
}

void
uvv_ssl__unit() {
    EVP_cleanup();
    ERR_free_strings();
}

uvv_tls_ctx *
uvv_tls_ctx__create(void) {
    SSL_CTX *ctx;

    ctx = SSL_CTX_new(SSLv23_client_method());
    return ctx;
}

void
uvv_tls_ctx__destroy(uvv_tls_ctx *ctx) {
    SSL_CTX_free(ctx);
}

struct uvv_tls *
uvv_tls__create(uvv_tls_ctx *ctx) {
    struct uvv_tls *tls;

    tls = (struct uvv_tls *)malloc(sizeof *tls);
    memset(tls, 0, sizeof *tls);

    tls->ctx = ctx;
    tls->ssl = SSL_new(tls->ctx);
    tls->bio_in = BIO_new(BIO_s_mem());
    tls->bio_out = BIO_new(BIO_s_mem());
    tls->connected = -1;

    SSL_set_mode(tls->ssl, SSL_MODE_AUTO_RETRY);
    SSL_set_connect_state(tls->ssl);
    SSL_set_bio(tls->ssl, tls->bio_in, tls->bio_out);
    return tls;
}

void
uvv_tls__destroy(struct uvv_tls *tls) {
    if (tls->ssl) {
        SSL_free(tls->ssl);
    }
    if (tls->b.buf) {
        free(tls->b.buf);
    }
    free(tls);
}

void
uvv_tls__shutdown(struct uvv_tls *tls) {
    SSL_shutdown(tls->ssl);
}

int
uvv_tls__connect(struct uvv_tls *tls) {
    int rv;
    int er;

    rv = SSL_do_handshake(tls->ssl);
    if (rv == 1) {
        return -1;
    }

    if (!SSL_is_init_finished(tls->ssl))
        er = SSL_connect(tls->ssl);
    else
        return -1;

    if (er < 0 && SSL_get_error(tls->ssl, er) == SSL_ERROR_WANT_READ)
        return 0;
    else
        return -1;
}

static int
_bio_error(struct uvv_tls *tls, int err) {
    int rv, retry;

    retry = BIO_should_retry(tls->bio_out);
    if (BIO_should_write(tls->bio_out))
        rv = -retry;
    else if (BIO_should_read(tls->bio_out))
        rv = -retry;
    else {
        char ssl_error_buf[512];
        ERR_error_string_n(err, ssl_error_buf, sizeof(ssl_error_buf));
        fprintf(stderr, "[%p] BIO: read failed: (%d) %s\n", tls->ssl, err, ssl_error_buf);
        return err;
    }
    return rv;
}

static int
_ssl_error(struct uvv_tls *tls, int err) {
    int ret, rv;

    rv = SSL_get_error(tls->ssl, err);
    switch (rv) {
    case SSL_ERROR_WANT_READ:
        ret = 1;
        break;
    default:
        ret = -2;
        break;
    }
    return ret;
}

int
uvv_tls__bio_read(struct uvv_tls *tls, int len) {
    int ret;

    if (len == 0) {
        len = sizeof(tls->buf);
    }
    memset(tls->buf, 0, len);
    ret = BIO_read(tls->bio_out, tls->buf, len);
    if (ret >= 0) {
        return ret;
    } else {
        return _bio_error(tls, ret);
    }
}

int
uvv_tls__bio_write(struct uvv_tls *tls, const char *data, int len) {
    int ret;

    ret = BIO_write(tls->bio_in, data, len);
    if (ret >= 0)
        return ret;
    else
        return _bio_error(tls, ret);
}

int
uvv_tls__read(struct uvv_tls *tls) {
    int err, ret, read, done;

    done = SSL_is_init_finished(tls->ssl);
    if (!done) {
        err = SSL_connect(tls->ssl);
        if (err <= 0) {
            return _ssl_error(tls, err);
        }
    }
    if (tls->b.buf) {
        free(tls->b.buf);
        tls->b.buf = 0;
        tls->b.len = 0;
    }
    ret = -1;
    do {
        read = SSL_read(tls->ssl, tls->buf, SSL_CHUNK_SIZE);
        if (read > 0) {
            ret = 0;
            tls->b.buf = realloc(tls->b.buf, tls->b.len + read);
            memcpy(tls->b.buf + tls->b.len, tls->buf, read);
            tls->b.len += read;
        } else {
            _ssl_error(tls, read);
        }
    } while (read > 0);
    if (tls->connected == -1) {
        tls->connected = 1;
    } else {
        ret = 0;
    }
    return ret;
}

int
uvv_tls__write(struct uvv_tls *tls, const char *data, int len) {
    return SSL_write(tls->ssl, data, len);
}
