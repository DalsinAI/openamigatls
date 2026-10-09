/* opentls_ftps_get: explicit FTPS (RFC 4217) over opentls.library, the
 * pattern OpenFTP uses: AUTH TLS on the control connection, PBSZ 0,
 * PROT P, and each data connection resuming the control connection's TLS
 * session (servers such as vsftpd with require_ssl_reuse insist).
 *
 *   opentls_ftps_get [--ca FILE] [--verify MODE] [--no-reuse] [--transfers N]
 *                    host port user password file
 * Fetches file N times (default 2) and prints key=value lines: each data
 * connection's resumed flag, byte count and a checksum.
 * Same source on the x86 or ARM64 cores and on the Amiga (OpenTLSFTPSGet).
 *
 * MIT licensed and free. Copyright (c) 2026 Dalsin Limited. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __amigaos__
#include <exec/types.h>
#include <proto/exec.h>
#include <proto/bsdsocket.h>
#include <proto/opentls.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
struct Library *OpenTLSBase;
struct Library *SocketBase;
#define CLOSESOCK(s) CloseSocket(s)
#define SOCKBASE SocketBase
#else
#include <exec/types.h>
#include <clib/opentls_protos.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>
#define CLOSESOCK(s) close(s)
#define SOCKBASE NULL
#endif

static long dial(const char *host, int port)
{
#ifdef __amigaos__
    struct hostent *he = gethostbyname((STRPTR)host);
    struct sockaddr_in sa;
    long s;
    if (!he) return -1;
    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) return -1;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    memcpy(&sa.sin_addr, he->h_addr, 4);
    if (connect(s, (struct sockaddr *)&sa, sizeof sa) < 0) { CloseSocket(s); return -1; }
    return s;
#else
    struct addrinfo hints, *ai = NULL;
    char ps[16];
    int s;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    snprintf(ps, sizeof ps, "%d", port);
    if (getaddrinfo(host, ps, &hints, &ai)) return -1;
    s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (s >= 0 && connect(s, ai->ai_addr, ai->ai_addrlen)) { close(s); s = -1; }
    freeaddrinfo(ai);
    return s;
#endif
}

/* the control connection: plain until AUTH TLS, then through OpenTLS */
static long ctl_sock = -1;
static struct OTConnection *ctl_tls;
static char rbuf[4096];
static int rlen;

static int ctl_fill(void)
{
    long n;
    if (rlen >= (int)sizeof rbuf - 1) return 0;
    if (ctl_tls) n = OT_Read(ctl_tls, rbuf + rlen, (LONG)(sizeof rbuf - 1 - rlen));
    else n = recv(ctl_sock, rbuf + rlen, sizeof rbuf - 1 - rlen, 0);
    if (n <= 0) return 0;
    rlen += (int)n;
    return 1;
}

/* one reply (multi-line ones too); answers its code */
static int reply(char *text, int size)
{
    char line[1024];
    int code = 0, first = 1;
    for (;;) {
        char *nl;
        int l;
        while (!(nl = memchr(rbuf, '\n', (size_t)rlen)))
            if (!ctl_fill()) return -1;
        l = (int)(nl - rbuf) + 1;
        memcpy(line, rbuf, (size_t)(l < (int)sizeof line ? l : (int)sizeof line - 1));
        line[l < (int)sizeof line ? l : (int)sizeof line - 1] = 0;
        memmove(rbuf, rbuf + l, (size_t)(rlen - l));
        rlen -= l;
        if (first) {
            code = atoi(line);
            if (text) { strncpy(text, line, (size_t)size - 1); text[size - 1] = 0; }
            first = 0;
        }
        if (strlen(line) >= 4 && atoi(line) == code && line[3] == ' ') return code;
    }
}

static int command(const char *cmd, char *text, int size)
{
    char line[512];
    long n;
    snprintf(line, sizeof line, "%s\r\n", cmd);
    if (ctl_tls) n = OT_Write(ctl_tls, line, (LONG)strlen(line));
    else n = send(ctl_sock, line, strlen(line), 0);
    if (n != (long)strlen(line)) return -1;
    return reply(text, size);
}

int main(int argc, char **argv)
{
    struct OTContextConfig cfg;
    struct OTContext *ctx = NULL;
    struct OTSession *session = NULL;
    const char *ca = NULL, *args[5];
    int nargs = 0, reuse = 1, transfers = 2, verify = OTV_FULL, i, t, ok = 1, port;
    char text[512], cmd[300];
    LONG err;

    for (i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--ca") && i + 1 < argc) ca = argv[++i];
        else if (!strcmp(argv[i], "--no-reuse")) reuse = 0;
        else if (!strcmp(argv[i], "--transfers") && i + 1 < argc) transfers = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--verify") && i + 1 < argc) {
            ++i;
            verify = !strcmp(argv[i], "none") ? OTV_NONE : !strcmp(argv[i], "nohost") ? OTV_NO_HOSTNAME : OTV_FULL;
        }
        else if (nargs < 5) args[nargs++] = argv[i];
    }
    if (nargs != 5) {
        printf("usage: opentls_ftps_get [--ca FILE] [--no-reuse] [--transfers N] host port user password file\n");
        return 20;
    }
    port = atoi(args[1]);
#ifdef __amigaos__
    if (!(SocketBase = OpenLibrary((CONST_STRPTR)"bsdsocket.library", 4))) return 20;
    if (!(OpenTLSBase = OpenLibrary((CONST_STRPTR)"opentls.library", 1))) { CloseLibrary(SocketBase); return 20; }
#endif
    memset(&cfg, 0, sizeof cfg);
    cfg.Size = sizeof cfg;
    cfg.CAFile = (STRPTR)ca;
    cfg.Flags = ca ? OTCF_NO_SYSTEM_TRUST : 0;
    ctx = OT_NewContext(&cfg, &err);
    if (!ctx) { printf("context.error=%ld\n", (long)err); return 10; }

    ctl_sock = dial(args[0], port);
    if (ctl_sock < 0 || reply(text, sizeof text) != 220) { printf("error=connect\n"); return 10; }
    if (command("AUTH TLS", text, sizeof text) != 234) { printf("error=auth %s\n", text); return 10; }
    ctl_tls = OT_NewConnection(ctx, (CONST_STRPTR)args[0], &err);
    OT_SetSocket(ctl_tls, ctl_sock, SOCKBASE);
    OT_SetVerify(ctl_tls, verify);
    if (OT_Handshake(ctl_tls) != OTERR_OK) {
        printf("control.error=%ld\ncontrol.text=%s\n", (long)OT_GetError(ctl_tls),
               (const char *)OT_GetErrorText(ctl_tls));
        return 10;
    }
    printf("control.cipher=%s\n", (const char *)OT_GetCipher(ctl_tls));
    if (reuse) session = OT_GetSession(ctl_tls);
    snprintf(cmd, sizeof cmd, "USER %s", args[2]);
    if (command(cmd, text, sizeof text) == 331) {
        snprintf(cmd, sizeof cmd, "PASS %s", args[3]);
        if (command(cmd, text, sizeof text) != 230) { printf("error=login %s\n", text); return 10; }
    }
    if (command("PBSZ 0", text, sizeof text) != 200 || command("PROT P", text, sizeof text) != 200
        || command("TYPE I", text, sizeof text) != 200) {
        printf("error=prot %s\n", text);
        return 10;
    }
    for (t = 0; t < transfers && ok; ++t) {
        int h1, h2, h3, h4, p1, p2, code;
        char *paren;
        long ds;
        struct OTConnection *data;
        static char buf[8192];
        long n, total = 0;
        unsigned long sum = 0;
        if (command("PASV", text, sizeof text) != 227 || !(paren = strchr(text, '('))
            || sscanf(paren + 1, "%d,%d,%d,%d,%d,%d", &h1, &h2, &h3, &h4, &p1, &p2) != 6) {
            printf("error=pasv %s\n", text);
            ok = 0;
            break;
        }
        ds = dial(args[0], p1 * 256 + p2);    /* the control host, as behind NAT */
        snprintf(cmd, sizeof cmd, "RETR %s", args[4]);
        code = command(cmd, text, sizeof text);
        if (ds < 0 || (code != 150 && code != 125)) { printf("error=retr %s\n", text); ok = 0; break; }
        data = OT_NewConnection(ctx, (CONST_STRPTR)args[0], &err);
        OT_SetSocket(data, ds, SOCKBASE);
        OT_SetVerify(data, verify);
        if (session) OT_SetSession(data, session);
        if (OT_Handshake(data) != OTERR_OK) {
            printf("data%d.error=%ld\ndata%d.text=%s\n", t, (long)OT_GetError(data), t,
                   (const char *)OT_GetErrorText(data));
            ok = 0;
        } else {
            while ((n = OT_Read(data, buf, sizeof buf)) > 0) {
                for (i = 0; i < n; ++i) sum = sum * 31 + (unsigned char)buf[i];
                total += n;
            }
            printf("data%d.resumed=%ld\ndata%d.bytes=%ld\ndata%d.sum=%08lx\ndata%d.end=%s\n",
                   t, (long)OT_SessionResumed(data), t, total, t, sum & 0xFFFFFFFFUL, t,
                   n == 0 ? "close_notify" : "closed");
            OT_Close(data);
        }
        OT_FreeConnection(data);
        CLOSESOCK(ds);
        code = reply(text, sizeof text);
        printf("data%d.reply=%d\n", t, code);
        if (code != 226) ok = 0;
    }
    command("QUIT", text, sizeof text);
    OT_Close(ctl_tls);
    OT_FreeConnection(ctl_tls);
    CLOSESOCK(ctl_sock);
    OT_FreeSession(session);
    OT_FreeContext(ctx);
    printf("result=%s\n", ok ? "ok" : "fail");
#ifdef __amigaos__
    CloseLibrary(OpenTLSBase);
    CloseLibrary(SocketBase);
#endif
    return ok ? 0 : 10;
}
