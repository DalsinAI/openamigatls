/* OpenTLS: memory, locks, files, the clock and socket I/O, on AmigaOS
 * (exec, dos, bsdsocket through the caller's SocketBase) and on the x86 or
 * ARM64 cores for the host tests (POSIX).
 * MIT licensed and free. Copyright (c) 2026 Dalsin Limited. */
#include "ot_internal.h"

#ifdef __amigaos__

#include <exec/memory.h>
#include <exec/semaphores.h>
#include <exec/execbase.h>
#include <dos/dos.h>
#include <dos/dosextens.h>
#include <proto/exec.h>
#include <proto/dos.h>
#include <proto/bsdsocket.h>

extern struct ExecBase *SysBase;
extern struct DosLibrary *DOSBase;

/* bsdsocket.library's errno values (BSD's) */
#define OT_EINTR        4
#define OT_EWOULDBLOCK  35

void *ot_alloc(size_t size)
{
    return AllocVec(size ? size : 1, MEMF_ANY | MEMF_CLEAR);
}

void ot_free(void *p)
{
    if (p) FreeVec(p);
}

void *ot_lock_new(void)
{
    struct SignalSemaphore *s = ot_alloc(sizeof *s);
    if (s) InitSemaphore(s);
    return s;
}

void ot_lock(void *lock) { if (lock) ObtainSemaphore((struct SignalSemaphore *)lock); }
void ot_unlock(void *lock) { if (lock) ReleaseSemaphore((struct SignalSemaphore *)lock); }
void ot_lock_free(void *lock) { ot_free(lock); }

/* No "insert volume" requesters while looking for files that may not be
 * there (AmiSSL: without the assign, for instance). */
static APTR quiet_begin(void)
{
    struct Process *me = (struct Process *)FindTask(NULL);
    APTR old;
    if (me->pr_Task.tc_Node.ln_Type != NT_PROCESS) return NULL;
    old = me->pr_WindowPtr;
    me->pr_WindowPtr = (APTR)-1;
    return old;
}

static void quiet_end(APTR old)
{
    struct Process *me = (struct Process *)FindTask(NULL);
    if (me->pr_Task.tc_Node.ln_Type == NT_PROCESS) me->pr_WindowPtr = old;
}

int ot_read_file(const char *path, unsigned char **data, size_t *length)
{
    APTR old = quiet_begin();
    BPTR fh = Open((CONST_STRPTR)path, MODE_OLDFILE);
    LONG size, got;
    unsigned char *buf;
    int ok = 0;
    *data = NULL;
    *length = 0;
    if (fh) {
        Seek(fh, 0, OFFSET_END);
        size = Seek(fh, 0, OFFSET_BEGINNING);
        if (size > 0 && size < 16L * 1024 * 1024 && (buf = ot_alloc((size_t)size + 1))) {
            got = Read(fh, buf, size);
            if (got == size) {
                *data = buf;
                *length = (size_t)size;
                ok = 1;
            } else {
                ot_free(buf);
            }
        }
        Close(fh);
    }
    quiet_end(old);
    return ok;
}

static int ends_with(const char *s, const char *suffix)
{
    size_t a = strlen(s), b = strlen(suffix), i;
    if (b > a) return 0;
    for (i = 0; i < b; ++i) {
        char x = s[a - b + i], y = suffix[i];
        if (x >= 'A' && x <= 'Z') x += 32;
        if (y >= 'A' && y <= 'Z') y += 32;
        if (x != y) return 0;
    }
    return 1;
}

int ot_each_file(const char *dir, const char *suffix,
                 void (*fn)(const char *path, void *ctx), void *ctx)
{
    APTR old = quiet_begin();
    BPTR lock = Lock((CONST_STRPTR)dir, ACCESS_READ);
    struct FileInfoBlock *fib;
    char path[256];
    int n = 0;
    if (lock) {
        fib = AllocDosObject(DOS_FIB, NULL);
        if (fib) {
            if (Examine(lock, fib) && fib->fib_DirEntryType > 0) {
                while (ExNext(lock, fib)) {
                    if (fib->fib_DirEntryType >= 0) continue;
                    if (!ends_with((const char *)fib->fib_FileName, suffix)) continue;
                    ot_strlcpy(path, dir, sizeof path);
                    if (!AddPart((STRPTR)path, fib->fib_FileName, sizeof path)) continue;
                    fn(path, ctx);
                    ++n;
                }
            }
            FreeDosObject(DOS_FIB, fib);
        }
        UnLock(lock);
    }
    quiet_end(old);
    return n;
}

int ot_now(uint32_t *days, uint32_t *seconds)
{
    struct DateStamp ds;
    DateStamp(&ds);
    /* the Amiga counts from 1 January 1978, 722450 days after year 0
     * (719528 to 1970, then 2922); the clock is local time */
    *days = (uint32_t)ds.ds_Days + 722450UL;
    *seconds = (uint32_t)ds.ds_Minute * 60UL + (uint32_t)ds.ds_Tick / TICKS_PER_SECOND;
    return 1;
}

LONG ot_sock_read(LONG fd, struct Library *socketbase, void *buf, LONG len)
{
    struct Library *SocketBase = socketbase;
    LONG n = recv(fd, buf, len, 0);
    if (n >= 0) return n;
    n = Errno();
    return n == OT_EWOULDBLOCK ? OTERR_WOULDBLOCK : OTERR_IO;
}

LONG ot_sock_write(LONG fd, struct Library *socketbase, const void *buf, LONG len)
{
    struct Library *SocketBase = socketbase;
    LONG n = send(fd, (APTR)buf, len, 0);
    if (n > 0) return n;
    if (n == 0) return OTERR_IO;
    n = Errno();
    return n == OT_EWOULDBLOCK ? OTERR_WOULDBLOCK : OTERR_IO;
}

/* A standard hook: the hook in A0, the object in A2, the message in A1. */
LONG ot_hook_call(struct Hook *hook, void *object, struct OTIOMessage *msg)
{
    register LONG result __asm("d0");
    register struct Hook *a0 __asm("a0") = hook;
    register void *a1 __asm("a1") = msg;
    register void *a2 __asm("a2") = object;
    __asm volatile("move.l 8(%%a0),%%a3\n\tjsr (%%a3)"
                   : "=r"(result), "+r"(a0), "+r"(a1)
                   : "r"(a2)
                   : "d1", "a3", "cc", "memory");
    return result;
}

int ot_platform_entropy(unsigned char *out, size_t len)
{
    (void)out; (void)len;
    return 0;   /* ot_random.c gathers the Amiga's own */
}

int ot_trust_location(int kind, int i, char *buf, size_t size)
{
    static const char *const bundles[] = {
        "ENV:OpenTLS/ca-bundle.pem", "ENVARC:OpenTLS/ca-bundle.pem", NULL };
    static const char *const dirs[] = { "ENV:OpenTLS/certs", NULL };
    static const char *const fallbacks[] = {
        "DEVS:Internet/curl-ca-bundle.crt", "AmiSSL:Certs/ca-bundle.crt", NULL };
    const char *const *list = kind == OT_TRUST_BUNDLE ? bundles
                            : kind == OT_TRUST_DIR ? dirs : fallbacks;
    int k;
    for (k = 0; k < i && list[k]; ++k) {}
    if (!list[k]) return 0;
    ot_strlcpy(buf, list[k], size);
    return 1;
}

#else /* the host tests */

#include <dirent.h>
#include <strings.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>

void *ot_alloc(size_t size) { return calloc(1, size ? size : 1); }
void ot_free(void *p) { free(p); }
/* the host tests use one thread */
void *ot_lock_new(void) { return ot_alloc(1); }
void ot_lock(void *lock) { (void)lock; }
void ot_unlock(void *lock) { (void)lock; }
void ot_lock_free(void *lock) { ot_free(lock); }

int ot_read_file(const char *path, unsigned char **data, size_t *length)
{
    FILE *f = fopen(path, "rb");
    long n;
    unsigned char *buf;
    *data = NULL;
    *length = 0;
    if (!f) return 0;
    if (fseek(f, 0, SEEK_END) || (n = ftell(f)) <= 0 || fseek(f, 0, SEEK_SET)) {
        fclose(f);
        return 0;
    }
    buf = ot_alloc((size_t)n + 1);
    if (!buf || fread(buf, 1, (size_t)n, f) != (size_t)n) {
        ot_free(buf);
        fclose(f);
        return 0;
    }
    fclose(f);
    *data = buf;
    *length = (size_t)n;
    return 1;
}

int ot_each_file(const char *dir, const char *suffix,
                 void (*fn)(const char *path, void *ctx), void *ctx)
{
    DIR *d = opendir(dir);
    struct dirent *e;
    char path[1024];
    size_t sl = strlen(suffix);
    int n = 0;
    if (!d) return 0;
    while ((e = readdir(d))) {
        size_t l = strlen(e->d_name);
        if (l < sl || strcasecmp(e->d_name + l - sl, suffix)) continue;
        snprintf(path, sizeof path, "%s/%s", dir, e->d_name);
        fn(path, ctx);
        ++n;
    }
    closedir(d);
    return n;
}

int ot_now(uint32_t *days, uint32_t *seconds)
{
    time_t t = time(NULL);
    const char *fake = getenv("OPENTLS_TEST_TIME");   /* tests: seconds since 1970 */
    if (fake) t = (time_t)strtoll(fake, NULL, 10);
    *days = (uint32_t)(t / 86400) + 719528UL;
    *seconds = (uint32_t)(t % 86400);
    return 1;
}

LONG ot_sock_read(LONG fd, struct Library *socketbase, void *buf, LONG len)
{
    ssize_t n;
    (void)socketbase;
    do n = recv(fd, buf, (size_t)len, 0); while (n < 0 && errno == EINTR);
    if (n >= 0) return (LONG)n;
    return (errno == EAGAIN || errno == EWOULDBLOCK) ? OTERR_WOULDBLOCK : OTERR_IO;
}

LONG ot_sock_write(LONG fd, struct Library *socketbase, const void *buf, LONG len)
{
    ssize_t n;
    (void)socketbase;
    do n = send(fd, buf, (size_t)len, MSG_NOSIGNAL); while (n < 0 && errno == EINTR);
    if (n > 0) return (LONG)n;
    if (n == 0) return OTERR_IO;
    return (errno == EAGAIN || errno == EWOULDBLOCK) ? OTERR_WOULDBLOCK : OTERR_IO;
}

LONG ot_hook_call(struct Hook *hook, void *object, struct OTIOMessage *msg)
{
    return (LONG)hook->h_Entry(hook, object, msg);
}

int ot_platform_entropy(unsigned char *out, size_t len)
{
    int fd = open("/dev/urandom", O_RDONLY);
    size_t got = 0;
    if (fd < 0) return 0;
    while (got < len) {
        ssize_t n = read(fd, out + got, len - got);
        if (n <= 0) break;
        got += (size_t)n;
    }
    close(fd);
    return got == len;
}

/* OPENTLS_ROOT stands in for ENV:OpenTLS in the host tests. */
int ot_trust_location(int kind, int i, char *buf, size_t size)
{
    const char *root = getenv("OPENTLS_ROOT");
    if (i != 0) return 0;
    if (kind == OT_TRUST_BUNDLE && root) snprintf(buf, size, "%s/ca-bundle.pem", root);
    else if (kind == OT_TRUST_DIR && root) snprintf(buf, size, "%s/certs", root);
    else if (kind == OT_TRUST_FALLBACK && !root) snprintf(buf, size, "/etc/ssl/certs/ca-certificates.crt");
    else return 0;
    return 1;
}

#endif
