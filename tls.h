#ifndef _TLS_H_
#define _TLS_H_

#include <openssl/ssl.h>
#include <openssl/err.h>

#define SSL_CHUNK_SIZE 512

typedef SSL_CTX uvv_tls_ctx;

struct uvv_tls {
    SSL_CTX *ctx;
    SSL *ssl;
    BIO *bio_in;
    BIO *bio_out;
    struct {
        char *buf;
        int len;
    }b;
    int connected;
    char *data;
    char buf[SSL_CHUNK_SIZE];
};

void uvv_ssl__init();

void uvv_ssl__unit();

uvv_tls_ctx *uvv_tls_ctx__create(void);

void uvv_tls_ctx__destroy(uvv_tls_ctx *ctx);

struct uvv_tls *uvv_tls__create(uvv_tls_ctx *ctx);

void uvv_tls__shutdown(struct uvv_tls *tls);

void uvv_tls__destroy(struct uvv_tls *tls);

int uvv_tls__connect(struct uvv_tls *tls);

int uvv_tls__bio_read(struct uvv_tls *tls, int len);

int uvv_tls__bio_write(struct uvv_tls *tls, const char *data, int len);

int uvv_tls__read(struct uvv_tls *tls);

int uvv_tls__write(struct uvv_tls *tls, const char *data, int len);

#endif // _TLS_H_
