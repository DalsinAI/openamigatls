/* opentls_client: a small TLS client over opentls.library, for the tests.
 * The same source builds on the x86 or ARM64 cores (over the OpenTLS core,
 * POSIX sockets) and on the Amiga (OpenTLSClient: opentls.library and
 * bsdsocket.library).
 *
 *   opentls_client [options] host port
 *     --ca FILE        trust FILE as well (OTContextConfig.CAFile)
 *     --trust FILE     OT_AddTrustFile()
 *     --no-system      OTCF_NO_SYSTEM_TRUST
 *     --verify MODE    full, nohost, none, pinned
 *     --pin HEX        OT_PinCertificate() (64 hex digits)
 *     --sni NAME       the host name for TLS when it differs from host
 *     --alpn LIST      OT_SetALPN()
 *     --min V --max V  10, 11, 12, 13
 *     --connections N  N connections, each resuming the first one's session
 *     --send TEXT      write TEXT (\r and \n understood), then read to the end
 *     --expect TEXT    fail unless the answer contains TEXT
 *     --no-offload     OTCF_NO_OFFLOAD (all maths as 68k code)
 *     --small          OTCF_SMALL_BUFFERS
 *     --hook           move bytes through an I/O hook, not the socket
 *     --nonblock       a non-blocking socket (calls repeated on WOULDBLOCK)
 *     --repeat N       N handshakes (no resumption) and their mean time
 *     --print          print what --send brought back (the first 64 KB)
 *     --trace          with --hook: each read and write, timed (where a
 *                      handshake's time goes)
 * Prints key=value lines; exit code 0 when all went as asked.
 *
 * MIT licensed and free. Copyright (c) 2026 Dalsin Limited. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __amigaos__
#include <exec/types.h>
#include <exec/libraries.h>
#include <devices/timer.h>
#include <proto/exec.h>
#include <proto/dos.h>
#include <proto/timer.h>
#include <proto/bsdsocket.h>
#include <proto/opentls.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/filio.h>
#include <utility/hooks.h>
struct Library *OpenTLSBase;
struct Library *SocketBase;
struct Device *TimerBase;
static struct timerequest treq;
#define CLOSESOCK(s) CloseSocket(s)
#else
#include <exec/types.h>
#include <utility/hooks.h>
#include <clib/opentls_protos.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#define CLOSESOCK(s) close(s)
#endif

static const char *opt_ca, *opt_trust, *opt_pin, *opt_sni, *opt_alpn, *opt_send, *opt_expect;
static int opt_nosys, opt_verify, opt_min, opt_max, opt_conns = 1, opt_nooff, opt_small,
           opt_hook, opt_nonblock, opt_repeat = 0, opt_trace, opt_print;
static double trace_t0;

static double now_ms(void)
{
#ifdef __amigaos__
    struct EClockVal ev;
    ULONG f;
    if (!TimerBase) return 0;
    f = ReadEClock(&ev);
    return ((double)ev.ev_hi * 4294967296.0 + (double)ev.ev_lo) * 1000.0 / (double)f;
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1e6;
#endif
}

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
    if (opt_nonblock) { long one = 1; IoctlSocket(s, FIONBIO, (char *)&one); }
    return s;
#else
    struct addrinfo hints, *ai = NULL, *p;
    char ps[16];
    int s = -1;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    snprintf(ps, sizeof ps, "%d", port);
    if (getaddrinfo(host, ps, &hints, &ai)) return -1;
    for (p = ai; p; p = p->ai_next) {
        s = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (s < 0) continue;
        if (!connect(s, p->ai_addr, p->ai_addrlen)) break;
        close(s);
        s = -1;
    }
    freeaddrinfo(ai);
    if (s >= 0 && opt_nonblock) fcntl(s, F_SETFL, fcntl(s, F_GETFL) | O_NONBLOCK);
    return s;
#endif
}

static void wait_socket(long s)
{
#ifdef __amigaos__
    fd_set r, w;
    struct timeval tv;
    FD_ZERO(&r); FD_ZERO(&w); FD_SET(s, &r); FD_SET(s, &w);
    tv.tv_sec = 0; tv.tv_usec = 20000;
    WaitSelect(s + 1, &r, &w, NULL, &tv, NULL);
#else
    fd_set r;
    struct timeval tv;
    FD_ZERO(&r); FD_SET((int)s, &r);
    tv.tv_sec = 0; tv.tv_usec = 20000;
    select((int)s + 1, &r, NULL, NULL, &tv);
#endif
}

/* the I/O hook: recv() and send() on the socket in h_Data */
#ifdef __amigaos__
static ULONG hook_io(register struct Hook *h __asm("a0"), register APTR obj __asm("a2"),
                     register struct OTIOMessage *m __asm("a1"))
#else
static ULONG hook_io(struct Hook *h, APTR obj, APTR msgp)
#endif
{
#ifndef __amigaos__
    struct OTIOMessage *m = msgp;
#endif
    long s = (long)h->h_Data, n;
    double before = opt_trace ? now_ms() : 0;
    (void)obj;
    if (m->MethodID == OTIO_READ) n = recv(s, m->Buffer, m->Length, 0);
    else n = send(s, m->Buffer, m->Length, 0);
    if (opt_trace)
        printf("trace %8.2f %s %ld (%.2f ms in the call)\n", before - trace_t0,
               m->MethodID == OTIO_READ ? "read " : "write", n, now_ms() - before);
    if (n < 0) return (ULONG)OTERR_IO;
    return (ULONG)n;
}

static void unescape(char *d, const char *s)
{
    while (*s) {
        if (s[0] == '\\' && s[1] == 'r') { *d++ = '\r'; s += 2; }
        else if (s[0] == '\\' && s[1] == 'n') { *d++ = '\n'; s += 2; }
        else *d++ = *s++;
    }
    *d = 0;
}

static int hexpin(const char *s, UBYTE *out)
{
    int i;
    for (i = 0; i < 32; ++i) {
        unsigned v;
        if (sscanf(s + 2 * i, "%2x", &v) != 1) return 0;
        out[i] = (UBYTE)v;
    }
    return 1;
}

static int version_of(const char *s)
{
    return !strcmp(s, "10") ? OT_TLS10 : !strcmp(s, "11") ? OT_TLS11
         : !strcmp(s, "12") ? OT_TLS12 : !strcmp(s, "13") ? OT_TLS13 : -1;
}

static int one_connection(struct OTContext *ctx, const char *host, const char *name, int port,
                          struct OTSession **session, int index, double *ms)
{
    struct OTConnection *c;
    struct Hook hook;
    LONG err, rc;
    long s = dial(host, port);
    UBYTE fp[32], pin[32];
    double t0, t1;
    int i, ok = 1;

    if (s < 0) { printf("conn%d.error=connect\n", index); return 0; }
    c = OT_NewConnection(ctx, (CONST_STRPTR)name, &err);
    if (!c) { printf("conn%d.error=%ld\n", index, (long)err); CLOSESOCK(s); return 0; }
    if (opt_hook) {
        memset(&hook, 0, sizeof hook);
        hook.h_Entry = (void *)hook_io;
        hook.h_Data = (APTR)s;
        OT_SetIOHook(c, &hook);
    } else {
#ifdef __amigaos__
        OT_SetSocket(c, s, SocketBase);
#else
        OT_SetSocket(c, s, NULL);
#endif
    }
    if (opt_alpn) OT_SetALPN(c, (CONST_STRPTR)opt_alpn);
    if (opt_verify) OT_SetVerify(c, opt_verify);
    if (opt_pin) { if (!hexpin(opt_pin, pin)) return 0; OT_PinCertificate(c, pin); }
    if (*session) OT_SetSession(c, *session);
    t0 = trace_t0 = now_ms();
    while ((rc = OT_Handshake(c)) == OTERR_WOULDBLOCK) wait_socket(s);
    t1 = now_ms();
    if (ms) *ms += t1 - t0;
    if (OT_GetPeerFingerprint(c, fp) == OTERR_OK) {
        printf("conn%d.fingerprint=", index);
        for (i = 0; i < 32; ++i) printf("%02x", fp[i]);
        printf("\n");
        printf("conn%d.peername=%s\n", index, (const char *)OT_GetPeerName(c));
    }
    if (rc != OTERR_OK) {
        printf("conn%d.error=%ld\nconn%d.detail=%ld\nconn%d.text=%s\n", index, (long)rc,
               index, (long)OT_GetErrorDetail(c), index, (const char *)OT_GetErrorText(c));
        OT_FreeConnection(c);
        CLOSESOCK(s);
        return 0;
    }
    printf("conn%d.handshake=ok\nconn%d.protocol=%04lx\nconn%d.cipher=%s\nconn%d.alpn=%s\n"
           "conn%d.resumed=%ld\nconn%d.ms=%.1f\n",
           index, index, (unsigned long)OT_GetProtocol(c), index, (const char *)OT_GetCipher(c),
           index, (const char *)OT_GetALPN(c), index, (long)OT_SessionResumed(c), index, t1 - t0);
    if (!*session) *session = OT_GetSession(c);
    if (opt_send) {
        static char out[1024], in[65536];
        long got = 0, n;
        unescape(out, opt_send);
        for (;;) {
            n = OT_Write(c, out, (LONG)strlen(out));
            if (n == OTERR_WOULDBLOCK) { wait_socket(s); continue; }
            break;
        }
        if (n != (long)strlen(out)) { printf("conn%d.write=%ld\n", index, n); ok = 0; }
        for (;;) {      /* everything, keeping the first 64 KB */
            static char sink[8192];
            char *dst = got < (long)sizeof in - 1 ? in + got : sink;
            long room = got < (long)sizeof in - 1 ? (long)sizeof in - 1 - got : (long)sizeof sink;
            n = OT_Read(c, dst, (LONG)room);
            if (n == OTERR_WOULDBLOCK) { wait_socket(s); continue; }
            if (n <= 0) {
                if (n < 0 && n != OTERR_CLOSED) {
                    printf("conn%d.read=%ld\nconn%d.text=%s\n", index, n, index,
                           (const char *)OT_GetErrorText(c));
                    ok = 0;
                }
                break;
            }
            got += n;
        }
        in[got < (long)sizeof in - 1 ? got : (long)sizeof in - 1] = 0;
        printf("conn%d.received=%ld\n", index, got);
        if (opt_print) printf("%s\n", in);
        if (opt_expect && !strstr(in, opt_expect)) { printf("conn%d.expect=missing\n", index); ok = 0; }
    }
    while (OT_Close(c) == OTERR_WOULDBLOCK) wait_socket(s);
    OT_FreeConnection(c);
    CLOSESOCK(s);
    return ok;
}

int main(int argc, char **argv)
{
    struct OTContextConfig cfg;
    struct OTContext *ctx;
    struct OTSession *session = NULL;
    const char *host = NULL, *name;
    int port = 0, i, ok = 1;
    LONG err;
    double total = 0;

    for (i = 1; i < argc; ++i) {
        const char *a = argv[i], *v = i + 1 < argc ? argv[i + 1] : NULL;
        if (!strcmp(a, "--ca") && v) { opt_ca = v; ++i; }
        else if (!strcmp(a, "--trust") && v) { opt_trust = v; ++i; }
        else if (!strcmp(a, "--no-system")) opt_nosys = 1;
        else if (!strcmp(a, "--verify") && v) {
            opt_verify = !strcmp(v, "nohost") ? OTV_NO_HOSTNAME : !strcmp(v, "none") ? OTV_NONE
                       : !strcmp(v, "pinned") ? OTV_PINNED_ONLY : OTV_FULL;
            ++i;
        }
        else if (!strcmp(a, "--pin") && v) { opt_pin = v; ++i; }
        else if (!strcmp(a, "--sni") && v) { opt_sni = v; ++i; }
        else if (!strcmp(a, "--alpn") && v) { opt_alpn = v; ++i; }
        else if (!strcmp(a, "--min") && v) { opt_min = version_of(v); ++i; }
        else if (!strcmp(a, "--max") && v) { opt_max = version_of(v); ++i; }
        else if (!strcmp(a, "--connections") && v) { opt_conns = atoi(v); ++i; }
        else if (!strcmp(a, "--repeat") && v) { opt_repeat = atoi(v); ++i; }
        else if (!strcmp(a, "--send") && v) { opt_send = v; ++i; }
        else if (!strcmp(a, "--expect") && v) { opt_expect = v; ++i; }
        else if (!strcmp(a, "--no-offload")) opt_nooff = 1;
        else if (!strcmp(a, "--small")) opt_small = 1;
        else if (!strcmp(a, "--hook")) opt_hook = 1;
        else if (!strcmp(a, "--nonblock")) opt_nonblock = 1;
        else if (!strcmp(a, "--trace")) opt_trace = 1;
        else if (!strcmp(a, "--print")) opt_print = 1;
        else if (!host) host = a;
        else port = atoi(a);
    }
    if (!host || port <= 0) {
        printf("usage: opentls_client [options] host port\n");
        return 20;
    }
#ifdef __amigaos__
    if (!(SocketBase = OpenLibrary((CONST_STRPTR)"bsdsocket.library", 4))) { printf("no bsdsocket.library\n"); return 20; }
    if (!(OpenTLSBase = OpenLibrary((CONST_STRPTR)"opentls.library", 1))) { printf("no opentls.library\n"); CloseLibrary(SocketBase); return 20; }
    if (!OpenDevice((CONST_STRPTR)TIMERNAME, UNIT_ECLOCK, (struct IORequest *)&treq, 0))
        TimerBase = treq.tr_node.io_Device;
#endif
    printf("version=%lx\naccelerated=%lx\n", (unsigned long)OT_Version(), (unsigned long)OT_Accelerated());
    memset(&cfg, 0, sizeof cfg);
    cfg.Size = sizeof cfg;
    cfg.Flags = (opt_nosys ? OTCF_NO_SYSTEM_TRUST : 0) | (opt_nooff ? OTCF_NO_OFFLOAD : 0)
              | (opt_small ? OTCF_SMALL_BUFFERS : 0);
    cfg.MinVersion = opt_min > 0 ? opt_min : 0;
    cfg.MaxVersion = opt_max > 0 ? opt_max : 0;
    cfg.CAFile = (STRPTR)opt_ca;
    ctx = OT_NewContext(&cfg, &err);
    if (!ctx) {
        printf("context.error=%ld\ncontext.text=%s\n", (long)err, (const char *)OT_ErrorString(err));
        ok = 0;
    } else {
        if (opt_trust) printf("trust.added=%ld\n", (long)OT_AddTrustFile(ctx, (CONST_STRPTR)opt_trust));
        name = opt_sni ? opt_sni : host;
        if (opt_repeat > 0) {
            for (i = 0; i < opt_repeat && ok; ++i) {
                struct OTSession *none = NULL;
                ok = one_connection(ctx, host, name, port, &none, i, &total);
                OT_FreeSession(none);
            }
            printf("handshakes=%d\nmean_ms=%.1f\n", opt_repeat, total / opt_repeat);
        } else {
            for (i = 0; i < opt_conns && ok; ++i)
                ok = one_connection(ctx, host, name, port, &session, i, NULL);
        }
        OT_FreeSession(session);
        OT_FreeContext(ctx);
    }
    printf("result=%s\n", ok ? "ok" : "fail");
#ifdef __amigaos__
    if (TimerBase) CloseDevice((struct IORequest *)&treq);
    CloseLibrary(OpenTLSBase);
    CloseLibrary(SocketBase);
#endif
    return ok ? 0 : 10;
}
