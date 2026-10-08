#define _POSIX_C_SOURCE 200112L
#include "opentls/opentls.h"
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static long rx(void *ctx, void *p, long n) { return (long)recv(*(int*)ctx, p, (size_t)n, 0); }
static long tx(void *ctx, const void *p, long n) { return (long)send(*(int*)ctx, p, (size_t)n, 0); }

int main(void) {
    struct addrinfo hints, *ai = NULL;
    int fd = -1, rc;
    char err[256], buf[1024];
    OTConfig cfg = { "/etc/ssl/certs/ca-certificates.crt", "http/1.1", 12, 0 };
    OTContext *ctx;
    OTConnection *tls;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo("example.com", "443", &hints, &ai)) return 10;
    fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (fd < 0 || connect(fd, ai->ai_addr, ai->ai_addrlen)) return 11;
    freeaddrinfo(ai);
    ctx = ot_context_new(&cfg, err, sizeof err);
    if (!ctx) { fprintf(stderr, "ctx: %s\n", err); return 12; }
    tls = ot_connection_new(ctx, "example.com", rx, tx, &fd, err, sizeof err);
    if (!tls) { fprintf(stderr, "conn: %s\n", err); return 13; }
    rc = ot_connect(tls);
    if (rc) { fprintf(stderr, "tls: %s\n", ot_error(tls)); return 14; }
    strcpy(buf, "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n");
    if (ot_write(tls, buf, (long)strlen(buf)) <= 0) return 15;
    rc = (int)ot_read(tls, buf, sizeof(buf)-1);
    if (rc <= 0) return 16;
    buf[rc] = 0;
    if (strncmp(buf, "HTTP/1.1", 8)) return 17;
    printf("OPENTLS HOST PASS protocol=%s cipher=%s alpn=%s\n",
           ot_protocol(tls), ot_cipher(tls), ot_alpn_selected(tls));
    ot_shutdown(tls);
    ot_connection_free(tls);
    ot_context_free(ctx);
    close(fd);
    return 0;
}
