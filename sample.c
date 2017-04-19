#include "net.h"
#include "tls.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void
conn_cb(struct uvv_net *net) {
    char buff[] = "GET / HTTP/1.1\r\n\r\n";

    printf("connected\n");
    uvv_net__write(net, buff, sizeof buff);
}

static void
read_cb(struct uvv_net *net, size_t size, const char *buff) {
    printf("%.*s\n", (int)size, buff);
}

static void
error_cb(struct uvv_net *net, int e, const char *msg) {
    printf("%d %s\n", e, msg);
}

static void
close_cb(struct uvv_net *net) {
    printf("closed\n");
}

int
main(int argc, char *argv[]) {
    uvv_tls_ctx *ctx;
    struct uvv_net *net;
    uv_loop_t *loop;

    char *host;
    int port;
    int timeout;

    if (argc < 3) {
        printf("usage: ./sample host port\n");
        exit(0);
    }

    host = argv[1];
    port = atoi(argv[2]);
    timeout = 3000;

    uvv_ssl__init();
    ctx = uvv_tls_ctx__create();

    loop = uv_default_loop();
    net = uvv_net__create(loop);

    net->conn_cb = conn_cb;
    net->close_cb = close_cb;
    net->read_cb = read_cb;
    net->error_cb = error_cb;
    net->data = 0;

    if (port == 443) {
        uvv_net__set_tls(net, ctx);
    }
    uvv_net__connect(net, host, port, timeout);

    uv_run(loop, UV_RUN_DEFAULT);

    uvv_net__destroy(net);
    uvv_tls_ctx__destroy(ctx);
    uvv_ssl__unit();
    return 0;
}
