#include "net.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct uvv_net *
uvv_net__create(uv_loop_t *loop) {
    struct uvv_net *net;

    net = (struct uvv_net *)malloc(sizeof *net);
    memset(net, 0, sizeof *net);
    net->loop = loop;
    net->timer.data = net->tcp.data = net->conn.data = (void *)net;
    uv_timer_init(loop, &net->timer);

    return net;
}

void
uvv_net__destroy(struct uvv_net *net) {
    uv_close((uv_handle_t *)&net->timer, 0);
    if (net->tls)
        uvv_tls__destroy(net->tls);
    if (net->host)
        free(net->host);
    free(net);
}

static void
_write_cb(uv_write_t *req, int stat) {
    free(req);
}

static void
_alloc_cb(uv_handle_t *tcp, size_t size, uv_buf_t *buf) {
    char *base;

    base = (char *)calloc(size, 1);
    *buf = uv_buf_init(base, size);
}

static void
_read_cb(uv_stream_t *tcp, ssize_t nread, const uv_buf_t *buf) {
    struct uvv_net *net;

    net = (struct uvv_net *)tcp->data;
    if (nread < 0) {
        free(buf->base);
        if (nread == UV_EOF) {
            if (net->close_cb) {
                net->close_cb(net);
            } else {
                fprintf(stderr, "close(%s:%d) %s\n", net->host, net->port, uv_strerror(nread));
            }
        } else {
            if (net->error_cb) {
                net->error_cb(net, nread, uv_strerror(nread));
            } else {
                fprintf(stderr, "error(%s:%d) %s\n", net->host, net->port, uv_strerror(nread));
            }
        }
        return;
    }

    if (net->use_ssl) {
        int read, stat;

        uvv_tls__bio_write(net->tls, buf->base, nread);
        free(buf->base);

        read = 0;
        stat = uvv_tls__read(net->tls);
        if (stat == 1) {
            do {
                read = uvv_tls__bio_read(net->tls, 0);
                if (read > 0) {
                    char buff[read];
                    uv_write_t *req;
                    uv_buf_t uvbuf;

                    req = malloc(sizeof *req);
                    req->data = net;
                    memset(buff, 0, read);
                    memcpy(buff, net->tls->buf, read);
                    uvbuf = uv_buf_init(buff, read);
                    uv_write(req, (uv_stream_t *)&net->tcp, &uvbuf, 1, _write_cb);
                }
            } while (read > 0);
        } else {
            if (!net->tls_established) {
                net->tls_established = 1;
                if (net->conn_cb) {
                    net->conn_cb(net);
                }
            }

            if (stat == 0) {
                if (net->tls->b.buf) {
                    if (net->read_cb && net->connected && net->tls_established) {
                        net->read_cb(net, net->tls->b.len, net->tls->b.buf);
                    }
                }
            }
        }
        return;
    }

    if (net->read_cb) {
        net->read_cb(net, nread, buf->base);
    }
    free(buf->base);
}

static void
_timer_cb(uv_timer_t *timer) {
    struct uvv_net *net;
    int rc;

    net = (struct uvv_net *)timer->data;
    uvv_net__close(net);

    rc = UV_ETIMEDOUT;
    if (net->error_cb) {
        net->error_cb(net, rc, uv_strerror(rc));
    } else {
        fprintf(stderr, "error(%s:%d) %s\n", net->host, net->port, uv_strerror(rc));
    }
}

static void
_connect_cb(uv_connect_t *conn, int stat) {
    struct uvv_net *net;
    int read;

    net = (struct uvv_net *)conn->data;

    if (uv_is_active((uv_handle_t *)&net->timer)) {
        uv_timer_stop(&net->timer);
    }
    if (stat < 0) {
        if (net->error_cb) {
            net->error_cb(net, stat, uv_strerror(stat));
        } else {
            fprintf(stderr, "error(%s:%d) %s\n", net->host, net->port, uv_strerror(stat));
        }
        return;
    }

    net->connected = 1;
    uv_read_start((uv_stream_t *)&net->tcp, _alloc_cb, _read_cb);
    if (net->use_ssl == 0 && net->conn_cb) {
        net->conn_cb(net);
    }

    if (net->use_ssl == 1 && uvv_tls__connect(net->tls) == 0) {
        read = 0;
        do {
            read = uvv_tls__bio_read(net->tls, 0);
            if (read > 0) {
                char buf[read];
                uv_write_t *req;
                uv_buf_t uvbuf;

                req = malloc(sizeof *req);
                req->data = net;
                memset(buf, 0, read);
                memcpy(buf, net->tls->buf, read);
                uvbuf = uv_buf_init(buf, read);
                uv_write(req, (uv_stream_t *)&net->tcp, &uvbuf, 1, _write_cb);
            }
        } while (read > 0);
    }
}

static void
_resolve_cb(uv_getaddrinfo_t *rv, int stat, struct addrinfo *ai) {
    struct uvv_net *net;
    struct sockaddr_in dest;
    int ret;

    net = (struct uvv_net *)rv->data;

    if (stat != 0) {
        if (net->error_cb) {
            net->error_cb(net, stat, uv_strerror(stat));
        } else {
            fprintf(stderr, "error(%s:%d) %s\n", net->host, net->port, uv_strerror(stat));
        }
        return;
    }

    uv_ip4_name((struct sockaddr_in *)ai->ai_addr, net->ip, INET6_ADDRSTRLEN);
    uv_ip4_addr(net->ip, net->port, &dest);

    uv_tcp_init(net->loop, &net->tcp);

    if (uv_is_active((uv_handle_t *)&net->timer)) {
        uv_timer_stop(&net->timer);
    }
    if (net->timeout > 0) {
        uv_timer_start(&net->timer, _timer_cb, net->timeout, 0);
    }
    ret = uv_tcp_connect(&net->conn, &net->tcp, (struct sockaddr *)&dest, _connect_cb);
    if (ret != 0) {
        if (net->error_cb) {
            net->error_cb(net, ret, uv_strerror(ret));
        } else {
            fprintf(stderr, "error(%s:%d) %s\n", net->host, net->port, uv_strerror(ret));
        }
        return;
    }
    uv_freeaddrinfo(ai);
}

int
uvv_net__connect(struct uvv_net *net, const char *host, int port, int timeout) {
    struct addrinfo hints;
    char buf[6];

    if (net->host)
        free(net->host);
    net->host = strdup(host);
    net->port = port;
    net->timeout = timeout;
    snprintf(buf, sizeof buf, "%d", net->port);

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = 0;

    net->resolver.data = (void *)net;
    return uv_getaddrinfo(net->loop, &net->resolver, _resolve_cb, net->host, 0, &hints);
}

static void
_close_cb(uv_handle_t *tcp) {
    struct uvv_net *net;

    net = (struct uvv_net *)tcp->data;
    if (net->close_cb) {
        net->close_cb(net);
    }
}

int
uvv_net__close(struct uvv_net* net) {
    int r = net->connected;
    if (r == 1) {
        net->connected = 0;
        net->tls_established = 0;
        if (net->use_ssl) {
            uvv_tls__shutdown(net->tls);
        }
        if (uv_is_active((uv_handle_t *)&net->tcp))
            uv_close((uv_handle_t *)&net->tcp, _close_cb);
        if (net->use_ssl) {
            uvv_tls__destroy(net->tls);
            net->use_ssl = 0;
            net->tls = 0;
        }
    }
    return r;
}

void
uvv_net__write(struct uvv_net *net, const char *buf, int len) {
    uv_write_t *req;
    uv_buf_t uvbuf;

    if (net->use_ssl) {
        int read;

        read = 0;
        uvv_tls__write(net->tls, buf, len);
        do {
            read = uvv_tls__bio_read(net->tls, 0);
            if (read > 0) {
                req = (uv_write_t *)malloc(sizeof *req);
                req->data = net;
                uvbuf = uv_buf_init(net->tls->buf, read);
                uv_write(req, (uv_stream_t *)&net->tcp, &uvbuf, 1, _write_cb);
            }
        } while (read > 0);
    } else {
        req = (uv_write_t *)malloc(sizeof *req);
        req->data = net;
        uvbuf = uv_buf_init((char *)buf, len);
        uv_write(req, (uv_stream_t *)&net->tcp, &uvbuf, 1, _write_cb);
    }
}

void
uvv_net__set_tls(struct uvv_net *net, uvv_tls_ctx *ctx) {
    net->use_ssl = 1;
    if (net->tls) {
        uvv_tls__destroy(net->tls);
    }
    net->tls = uvv_tls__create(ctx);
}

int
uvv_net__is_ssl(struct uvv_net *net) {
    return net->use_ssl;
}

void
uvv_net__resume(struct uvv_net *net) {
    uv_read_start((uv_stream_t *)&net->tcp, _alloc_cb, _read_cb);
}

void
uvv_net__pause(struct uvv_net *net) {
    uv_read_stop((uv_stream_t *)&net->tcp);
}
