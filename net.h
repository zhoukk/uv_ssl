#ifndef _NET_H_
#define _NET_H_

#include "uv.h"
#include "tls.h"

struct uvv_net {
    char *host;
    char ip[INET6_ADDRSTRLEN];
    int port;
    int timeout;
    int connected;

    uv_loop_t *loop;
    uv_getaddrinfo_t resolver;
    uv_connect_t conn;
    uv_tcp_t tcp;
    uv_timer_t timer;

    struct uvv_tls *tls;
    int use_ssl;
    int tls_established;

    void *data;
    void (* conn_cb)(struct uvv_net *);
    void (* read_cb)(struct uvv_net *, size_t, const char *);
    void (* error_cb)(struct uvv_net *, int, const char *);
    void (* close_cb)(struct uvv_net *);
};

struct uvv_net *uvv_net__create(uv_loop_t *loop);

void uvv_net__set_tls(struct uvv_net *net, uvv_tls_ctx *ctx);

int uvv_net__connect(struct uvv_net *net, const char *host, int port, int timeout);

int uvv_net__close(struct uvv_net *net);

void uvv_net__destroy(struct uvv_net *net);

void uvv_net__write(struct uvv_net *net, const char *buf, int len);

int uvv_net__is_ssl(struct uvv_net *net);

void uvv_net__resume(struct uvv_net *net);

void uvv_net__pause(struct uvv_net *net);

#endif // _NET_H_

