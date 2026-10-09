/* OpenTLS: the calls of opentls.library (docs/AutoDocs-OpenTLS.md), over
 * BearSSL's client engine. The library (library/opentls_lib.c) calls these
 * from its register entry points; the host tests call them directly.
 * MIT licensed and free. Copyright (c) 2026 Dalsin Limited. */
#include "ot_internal.h"
#include "inner.h"      /* BearSSL's br_ssl_engine_fail() */
#include <clib/opentls_protos.h>

/* ---- small helpers (no stdio in the library) ---- */

size_t ot_strlcpy(char *dst, const char *src, size_t size)
{
    size_t n = strlen(src);
    if (size) {
        size_t k = n < size - 1 ? n : size - 1;
        memcpy(dst, src, k);
        dst[k] = 0;
    }
    return n;
}

static void cat(char *dst, size_t size, const char *s)
{
    size_t l = strlen(dst);
    if (s && l < size) ot_strlcpy(dst + l, s, size - l);
}

static void fmt_long(char *buf, LONG v)
{
    char tmp[12];
    int i = 0, neg = v < 0;
    unsigned long u = neg ? (unsigned long)(-(v + 1)) + 1UL : (unsigned long)v;
    do { tmp[i++] = (char)('0' + (int)(u % 10UL)); u /= 10UL; } while (u);
    if (neg) *buf++ = '-';
    while (i) *buf++ = tmp[--i];
    *buf = 0;
}

static int lower(int ch) { return ch >= 'A' && ch <= 'Z' ? ch + 32 : ch; }

static int same_host(const char *a, const char *b)
{
    while (*a && lower(*a) == lower(*b)) { ++a; ++b; }
    return *a == *b;
}

void ot_set_error(struct OTConnection *c, LONG code, LONG detail, const char *a,
                  const char *b, const char *d)
{
    if (!c) return;
    c->error = code;
    c->detail = detail;
    c->text[0] = 0;
    cat(c->text, sizeof c->text, a);
    cat(c->text, sizeof c->text, b);
    cat(c->text, sizeof c->text, d);
}

static LONG fail(struct OTConnection *c, LONG code, LONG detail, const char *a,
                 const char *b, const char *d)
{
    ot_set_error(c, code, detail, a, b, d);
    if (code != OTERR_WOULDBLOCK) c->state = OTS_FAILED;
    return code;
}

/* ---- addresses ---- */

static int parse_ipv4(const char *s, unsigned char out[4])
{
    int part = 0, digits = 0;
    unsigned v = 0;
    for (;; ++s) {
        if (*s >= '0' && *s <= '9') {
            v = v * 10 + (unsigned)(*s - '0');
            if (v > 255 || ++digits > 3) return 0;
        } else if (*s == '.' || *s == 0) {
            if (!digits || part > 3) return 0;
            out[part++] = (unsigned char)v;
            v = 0;
            digits = 0;
            if (*s == 0) break;
        } else {
            return 0;
        }
    }
    return part == 4;
}

static int hexval(int ch)
{
    if (ch >= '0' && ch <= '9') return ch - '0';
    ch = lower(ch);
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    return -1;
}

static int parse_ipv6(const char *s, unsigned char out[16])
{
    unsigned short w[8];
    int n = 0, gap = -1, i;
    if (s[0] == ':' && s[1] == ':') { gap = 0; s += 2; }
    while (*s) {
        unsigned v = 0;
        int digits = 0, h;
        if (n == 8) return 0;
        if (strchr(s, '.') && !strchr(s, ':')) {      /* ::ffff:1.2.3.4 */
            unsigned char v4[4];
            if (n > 6 || !parse_ipv4(s, v4)) return 0;
            w[n++] = (unsigned short)((v4[0] << 8) | v4[1]);
            w[n++] = (unsigned short)((v4[2] << 8) | v4[3]);
            break;
        }
        while ((h = hexval(*s)) >= 0) {
            v = (v << 4) | (unsigned)h;
            if (++digits > 4) return 0;
            ++s;
        }
        if (!digits) return 0;
        w[n++] = (unsigned short)v;
        if (*s == ':') {
            ++s;
            if (*s == ':') {
                if (gap >= 0) return 0;
                gap = n;
                ++s;
            } else if (*s == 0) {
                return 0;
            }
        } else if (*s) {
            return 0;
        }
    }
    if (gap < 0 && n != 8) return 0;
    if (gap >= 0 && n == 8) return 0;
    memset(out, 0, 16);
    if (gap < 0) gap = n;
    for (i = 0; i < gap; ++i) { out[2 * i] = (unsigned char)(w[i] >> 8); out[2 * i + 1] = (unsigned char)w[i]; }
    for (i = gap; i < n; ++i) {
        int j = 8 - (n - i);
        out[2 * j] = (unsigned char)(w[i] >> 8);
        out[2 * j + 1] = (unsigned char)w[i];
    }
    return 1;
}

/* ---- names ---- */

static const char *alert_name(int alert)
{
    switch (alert) {
    case 10: return "unexpected message";
    case 20: return "bad record MAC";
    case 40: return "handshake failure";
    case 42: return "bad certificate";
    case 43: return "unsupported certificate";
    case 44: return "certificate revoked";
    case 45: return "certificate expired";
    case 46: return "certificate unknown";
    case 47: return "illegal parameter";
    case 48: return "unknown CA";
    case 50: return "decode error";
    case 51: return "decrypt error";
    case 70: return "protocol version";
    case 71: return "insufficient security";
    case 80: return "internal error";
    case 86: return "inappropriate fallback";
    case 90: return "user canceled";
    case 109: return "missing extension";
    case 110: return "unsupported extension";
    case 112: return "unrecognized name";
    case 116: return "certificate required";
    case 120: return "no application protocol";
    default: return "an alert";
    }
}

static const struct { uint16_t id; const char *name; } suite_names[] = {
    { BR_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, "ECDHE-ECDSA-CHACHA20-POLY1305" },
    { BR_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, "ECDHE-RSA-CHACHA20-POLY1305" },
    { BR_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, "ECDHE-ECDSA-AES128-GCM-SHA256" },
    { BR_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, "ECDHE-RSA-AES128-GCM-SHA256" },
    { BR_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, "ECDHE-ECDSA-AES256-GCM-SHA384" },
    { BR_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, "ECDHE-RSA-AES256-GCM-SHA384" },
    { BR_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, "ECDHE-ECDSA-AES128-SHA256" },
    { BR_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, "ECDHE-RSA-AES128-SHA256" },
    { BR_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384, "ECDHE-ECDSA-AES256-SHA384" },
    { BR_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384, "ECDHE-RSA-AES256-SHA384" },
    { BR_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, "ECDHE-ECDSA-AES128-SHA" },
    { BR_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, "ECDHE-RSA-AES128-SHA" },
    { BR_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, "ECDHE-ECDSA-AES256-SHA" },
    { BR_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, "ECDHE-RSA-AES256-SHA" },
    { BR_TLS_RSA_WITH_AES_128_GCM_SHA256, "AES128-GCM-SHA256" },
    { BR_TLS_RSA_WITH_AES_256_GCM_SHA384, "AES256-GCM-SHA384" },
    { BR_TLS_RSA_WITH_AES_128_CBC_SHA256, "AES128-SHA256" },
    { BR_TLS_RSA_WITH_AES_256_CBC_SHA256, "AES256-SHA256" },
    { BR_TLS_RSA_WITH_AES_128_CBC_SHA, "AES128-SHA" },
    { BR_TLS_RSA_WITH_AES_256_CBC_SHA, "AES256-SHA" },
};
#define SUITE_COUNT (sizeof suite_names / sizeof suite_names[0])

/* ---- error mapping ---- */

static void cert_error(struct OTConnection *c, LONG code, int err)
{
    char name[96], num[12];
    switch (code) {
    case OTERR_HOSTNAME:
        ot_cert_name(c->x509.leaf_ok ? c->x509.leaf : NULL, c->x509.leaf_len, name, sizeof name);
        if (name[0]) {
            ot_set_error(c, code, err, "The server's certificate is for ", name, ", not ");
            cat(c->text, sizeof c->text, c->host);
            cat(c->text, sizeof c->text, ".");
        } else {
            ot_set_error(c, code, err, "The server's certificate is not for ", c->host, ".");
        }
        break;
    case OTERR_EXPIRED:
        ot_set_error(c, code, err, err == BR_ERR_X509_TIME_UNKNOWN
            ? "The Amiga's clock is not set, so certificate dates cannot be checked."
            : "A certificate in the server's chain is expired or not yet valid (check the Amiga's clock).",
            NULL, NULL);
        break;
    case OTERR_UNTRUSTED:
        ot_set_error(c, code, err, "The server's certificate is not signed by a trusted authority.", NULL, NULL);
        break;
    case OTERR_PINNED:
        ot_set_error(c, code, err, "The server's certificate is not the one remembered for ", c->host, ".");
        break;
    default:
        fmt_long(num, err);
        ot_set_error(c, OTERR_BADCERT, err, "The server's certificate could not be used (X.509 error ", num, ").");
        break;
    }
}

/* the engine's error code to ours, with its text */
static LONG engine_error(struct OTConnection *c, int err)
{
    char num[12];
    c->state = OTS_FAILED;
    if (err >= BR_ERR_SEND_FATAL_ALERT) {
        fmt_long(num, err - BR_ERR_SEND_FATAL_ALERT);
        ot_set_error(c, OTERR_PROTOCOL, err, "OpenTLS ended the connection (alert ", num, ").");
    } else if (err >= BR_ERR_RECV_FATAL_ALERT) {
        int alert = err - BR_ERR_RECV_FATAL_ALERT;
        fmt_long(num, alert);
        if (alert == 70) {
            ot_set_error(c, OTERR_VERSION, alert,
                "The server refused the protocol version (it may want TLS 1.3 only).", NULL, NULL);
        } else {
            ot_set_error(c, OTERR_ALERT, alert, "The server ended the connection: ", alert_name(alert), " (alert ");
            cat(c->text, sizeof c->text, num);
            cat(c->text, sizeof c->text, ").");
        }
    } else if (err == BR_ERR_X509_BAD_SERVER_NAME || err == OT_X509_IP) {
        cert_error(c, OTERR_HOSTNAME, err);
    } else if (err == BR_ERR_X509_EXPIRED || err == BR_ERR_X509_TIME_UNKNOWN) {
        cert_error(c, OTERR_EXPIRED, err);
    } else if (err == BR_ERR_X509_NOT_TRUSTED) {
        if (!c->ctx->merged_count)
            ot_set_error(c, OTERR_TRUSTSTORE, err,
                "No trusted certificates: install the CA bundle as S:OpenTLS/ca-bundle.pem.", NULL, NULL);
        else
            cert_error(c, OTERR_UNTRUSTED, err);
    } else if (err == OT_X509_PINNED) {
        cert_error(c, OTERR_PINNED, err);
    } else if (err >= BR_ERR_X509_OK && err < 64) {
        cert_error(c, OTERR_BADCERT, err);
    } else if (err == BR_ERR_UNSUPPORTED_VERSION || err == BR_ERR_BAD_VERSION) {
        ot_set_error(c, OTERR_VERSION, err, "The server and OpenTLS have no protocol version in common.", NULL, NULL);
    } else if (err == BR_ERR_BAD_CIPHER_SUITE || err == BR_ERR_INVALID_ALGORITHM) {
        ot_set_error(c, OTERR_CIPHER, err, "The server chose a cipher suite, curve or signature OpenTLS does not offer.", NULL, NULL);
    } else if (err == BR_ERR_NO_RANDOM) {
        ot_set_error(c, OTERR_RANDOM, err, "No random numbers for the handshake.", NULL, NULL);
    } else if (err == BR_ERR_BAD_SIGNATURE) {
        ot_set_error(c, OTERR_PROTOCOL, err, "The server's handshake signature does not verify.", NULL, NULL);
    } else if (err == BR_ERR_IO) {
        ot_set_error(c, OTERR_IO, err, "The connection failed.", NULL, NULL);
    } else {
        fmt_long(num, err);
        ot_set_error(c, OTERR_PROTOCOL, err, "The server broke the TLS protocol (engine error ", num, ").");
    }
    return c->error;
}

/* ---- I/O and the engine pump ---- */

static LONG io(struct OTConnection *c, int write, unsigned char *buf, size_t len)
{
    LONG n;
    if (len > 0x7FFFFFFFUL) len = 0x7FFFFFFFUL;
    if (c->hook) {
        struct OTIOMessage m;
        m.MethodID = write ? OTIO_WRITE : OTIO_READ;
        m.Buffer = buf;
        m.Length = (LONG)len;
        n = ot_hook_call(c->hook, c, &m);
        if (n > (LONG)len) n = OTERR_IO;
        if (n < 0 && n != OTERR_WOULDBLOCK) n = OTERR_IO;
        return n;
    }
    return write ? ot_sock_write(c->fd, c->socketbase, buf, (LONG)len)
                 : ot_sock_read(c->fd, c->socketbase, buf, (LONG)len);
}

/* Records go out gathered: BearSSL hands over one record at a time, and
 * a handshake flight sent as several small segments meets Nagle's
 * algorithm and the peer's delayed ACK (40 ms or more for each flight).
 * Small records collect in c->out and leave in one send when the engine
 * waits for the peer, or when they would not fit. */
static LONG out_flush(struct OTConnection *c)
{
    while (c->out_sent < c->out_len) {
        LONG n = io(c, 1, c->out + c->out_sent, c->out_len - c->out_sent);
        if (n == OTERR_WOULDBLOCK)
            return fail(c, OTERR_WOULDBLOCK, 0, "The socket would block.", NULL, NULL);
        if (n <= 0) {
            br_ssl_engine_fail(&c->cc.eng, BR_ERR_IO);
            return fail(c, OTERR_IO, 0, "Sending to the server failed.", NULL, NULL);
        }
        c->out_sent += (size_t)n;
    }
    c->out_len = c->out_sent = 0;
    return OTERR_OK;
}

/* takes what the engine has to send; OTERR_OK when it took some */
static LONG out_take(struct OTConnection *c)
{
    br_ssl_engine_context *e = &c->cc.eng;
    size_t len;
    unsigned char *buf = br_ssl_engine_sendrec_buf(e, &len);
    LONG n, rc;
    if (c->out_len + len <= OT_OUT_MAX) {
        memcpy(c->out + c->out_len, buf, len);
        c->out_len += len;
        br_ssl_engine_sendrec_ack(e, len);
        return OTERR_OK;
    }
    if (c->out_len && (rc = out_flush(c)) != OTERR_OK) return rc;
    if (len <= OT_OUT_MAX) return OTERR_OK;          /* gathered next time round */
    n = io(c, 1, buf, len);                          /* a big record: as it is */
    if (n == OTERR_WOULDBLOCK)
        return fail(c, OTERR_WOULDBLOCK, 0, "The socket would block.", NULL, NULL);
    if (n <= 0) {
        br_ssl_engine_fail(e, BR_ERR_IO);
        return fail(c, OTERR_IO, 0, "Sending to the server failed.", NULL, NULL);
    }
    br_ssl_engine_sendrec_ack(e, (size_t)n);
    return OTERR_OK;
}

/* Runs the engine until its state has one of the target bits, writing and
 * reading records as it asks. OTERR_OK, OTERR_WOULDBLOCK or an error. */
static LONG pump(struct OTConnection *c, unsigned target)
{
    br_ssl_engine_context *e = &c->cc.eng;
    for (;;) {
        unsigned st = br_ssl_engine_current_state(e);
        size_t len;
        unsigned char *buf;
        LONG n;
        if (st & BR_SSL_CLOSED) {
            int err = br_ssl_engine_last_error(e);
            if (c->out_len) out_flush(c);    /* an alert or close_notify, if it can go */
            if (err == BR_ERR_OK) {
                c->clean_close = 1;
                c->state = OTS_CLOSED;
                return OTERR_CLOSED;     /* the callers turn this into 0 */
            }
            return engine_error(c, err);
        }
        if (st & BR_SSL_SENDREC) {
            if ((n = out_take(c)) != OTERR_OK) return n;
            continue;
        }
        if (st & target) return c->out_len ? out_flush(c) : OTERR_OK;
        if (st & BR_SSL_RECVAPP) {   /* data to read first: not a target here */
            ot_set_error(c, OTERR_STATE, 0, "Read the data waiting before writing more.", NULL, NULL);
            return OTERR_STATE;
        }
        if (st & BR_SSL_RECVREC) {
            if (c->out_len && (n = out_flush(c)) != OTERR_OK) return n;
            buf = br_ssl_engine_recvrec_buf(e, &len);
            n = io(c, 0, buf, len);
            if (n == OTERR_WOULDBLOCK)
                return fail(c, OTERR_WOULDBLOCK, 0, "The socket would block.", NULL, NULL);
            if (n == 0) {
                br_ssl_engine_fail(e, BR_ERR_IO);
                return fail(c, OTERR_CLOSED, 0, c->state == OTS_HANDSHAKE
                    ? "The server closed the connection during the handshake."
                    : "The server closed the connection without close_notify.", NULL, NULL);
            }
            if (n < 0) {
                br_ssl_engine_fail(e, BR_ERR_IO);
                return fail(c, OTERR_IO, 0, "Receiving from the server failed.", NULL, NULL);
            }
            br_ssl_engine_recvrec_ack(e, (size_t)n);
            continue;
        }
        br_ssl_engine_flush(e, 0);
    }
}

/* sends whatever records are waiting */
static LONG flush_out(struct OTConnection *c)
{
    br_ssl_engine_context *e = &c->cc.eng;
    LONG rc;
    while (br_ssl_engine_current_state(e) & BR_SSL_SENDREC)
        if ((rc = out_take(c)) != OTERR_OK) return rc;
    return c->out_len ? out_flush(c) : OTERR_OK;
}

/* ---- contexts ---- */

#define CFG_HAS(cfg, field) \
    ((cfg)->Size >= offsetof(struct OTContextConfig, field) + sizeof((cfg)->field))

struct merged_block { struct merged_block *next; };

ULONG OT_Version(VOID)
{
    return ((ULONG)OT_LIB_VERSION << 16) | OT_LIB_REVISION;
}

struct OTContext *OT_NewContext(CONST struct OTContextConfig *config, LONG *error)
{
    struct OTContext *x;
    LONG minv = OT_TLS12, maxv = OT_TLS12, rc;
    if (error) *error = OTERR_OK;
    if (config && config->Size < 2 * sizeof(ULONG)) { if (error) *error = OTERR_ARGS; return NULL; }
    if (config && CFG_HAS(config, MinVersion) && config->MinVersion) minv = config->MinVersion;
    if (config && CFG_HAS(config, MaxVersion) && config->MaxVersion) maxv = config->MaxVersion;
    if (minv > OT_TLS12 && minv <= OT_TLS13) { if (error) *error = OTERR_UNSUPPORTED; return NULL; }
    if (minv < OT_TLS10 || maxv < OT_TLS10 || maxv > OT_TLS13 || minv > OT_TLS13 || maxv < minv) {
        if (error) *error = OTERR_ARGS;
        return NULL;
    }
    if (minv > OT_TLS12) { if (error) *error = OTERR_UNSUPPORTED; return NULL; }
    if (maxv > OT_TLS12) maxv = OT_TLS12;       /* TLS 1.3 comes later */
    x = ot_alloc(sizeof *x);
    if (!x || !(x->lock = ot_lock_new())) {
        ot_free(x);
        if (error) *error = OTERR_NOMEM;
        return NULL;
    }
    x->flags = config ? config->Flags : 0;
    x->min_version = minv;
    x->max_version = maxv;
    if (config && CFG_HAS(config, ALPN) && config->ALPN && config->ALPN[0]) {
        size_t l = strlen((const char *)config->ALPN);
        x->alpn = ot_alloc(l + 1);
        if (!x->alpn) { OT_FreeContext(x); if (error) *error = OTERR_NOMEM; return NULL; }
        memcpy(x->alpn, config->ALPN, l);
    }
    if (config && CFG_HAS(config, CAFile) && config->CAFile) {
        rc = ot_anchors_add_file(&x->extra, (const char *)config->CAFile);
        if (rc <= 0) {
            OT_FreeContext(x);
            if (error) *error = rc < 0 ? rc : OTERR_TRUSTSTORE;
            return NULL;
        }
    }
    return x;
}

VOID OT_FreeContext(struct OTContext *x)
{
    struct merged_block *b, *n;
    if (!x) return;
    /* every array made, newest first: a handshake may have used an older one */
    if (x->merged) {
        for (b = ((struct merged_block *)(void *)x->merged) - 1; b; b = n) {
            n = b->next;
            ot_free(b);
        }
    }
    ot_anchors_free(&x->extra);
    ot_free(x->alpn);
    ot_lock_free(x->lock);
    ot_free(x);
}

/* the trust anchors for a handshake: the system's and the context's own */
static void merged_anchors(struct OTContext *x, const br_x509_trust_anchor **ta, size_t *n)
{
    ot_lock(x->lock);
    if (!x->merged_ok) {
        const struct ot_anchors *sys = (x->flags & OTCF_NO_SYSTEM_TRUST) ? NULL : ot_system_anchors();
        size_t count = (sys ? sys->count : 0) + x->extra.count;
        struct merged_block *b = ot_alloc(sizeof(br_x509_trust_anchor) * (count ? count : 1)
                                          + sizeof(br_x509_trust_anchor));
        if (b) {
            br_x509_trust_anchor *arr = (br_x509_trust_anchor *)(void *)(b + 1);
            /* the block header sits just before the array; keep the old ones */
            b->next = x->merged ? ((struct merged_block *)(void *)x->merged) - 1 : NULL;
            if (sys && sys->count) memcpy(arr, sys->ta, sys->count * sizeof *arr);
            if (x->extra.count)
                memcpy(arr + (sys ? sys->count : 0), x->extra.ta, x->extra.count * sizeof *arr);
            x->merged = arr;
            x->merged_count = count;
            x->merged_ok = 1;
            x->system_missing = !(x->flags & OTCF_NO_SYSTEM_TRUST) && !sys;
        }
    }
    *ta = x->merged;
    *n = x->merged ? x->merged_count : 0;
    ot_unlock(x->lock);
}

LONG OT_AddTrustPEM(struct OTContext *x, CONST_APTR pem, LONG length)
{
    LONG rc;
    if (!x || !pem || length <= 0) return OTERR_ARGS;
    ot_lock(x->lock);
    rc = ot_anchors_add_pem(&x->extra, pem, (size_t)length);
    x->merged_ok = 0;
    ot_unlock(x->lock);
    return rc;
}

LONG OT_AddTrustFile(struct OTContext *x, CONST_STRPTR path)
{
    LONG rc;
    if (!x || !path) return OTERR_ARGS;
    ot_lock(x->lock);
    rc = ot_anchors_add_file(&x->extra, (const char *)path);
    x->merged_ok = 0;
    ot_unlock(x->lock);
    return rc;
}

/* ---- connections ---- */

static LONG set_alpn(struct OTConnection *c, const char *list)
{
    size_t l;
    char *p;
    ot_free(c->alpn);
    c->alpn = NULL;
    c->alpn_count = 0;
    if (!list || !list[0]) return OTERR_OK;
    l = strlen(list);
    c->alpn = ot_alloc(l + 1);
    if (!c->alpn) return OTERR_NOMEM;
    memcpy(c->alpn, list, l);
    for (p = c->alpn; *p && c->alpn_count < OT_ALPN_MAX; ) {
        char *start = p;
        while (*p && *p != ',') ++p;
        if (*p) *p++ = 0;
        if (*start && strlen(start) < 256) c->alpn_names[c->alpn_count++] = start;
    }
    return OTERR_OK;
}

struct OTConnection *OT_NewConnection(struct OTContext *x, CONST_STRPTR hostname, LONG *error)
{
    struct OTConnection *c;
    const char *h = (const char *)hostname;
    size_t l;
    if (error) *error = OTERR_OK;
    if (!x || !h || !h[0] || (l = strlen(h)) > OT_HOST_MAX) { if (error) *error = OTERR_ARGS; return NULL; }
    c = ot_alloc(sizeof *c);
    if (!c) { if (error) *error = OTERR_NOMEM; return NULL; }
    c->ctx = x;
    c->fd = -1;
    c->iobuf_len = (x->flags & OTCF_SMALL_BUFFERS) ? BR_SSL_BUFSIZE_MONO : BR_SSL_BUFSIZE_BIDI;
    c->iobuf = ot_alloc(c->iobuf_len + OT_OUT_MAX);
    if (!c->iobuf) { ot_free(c); if (error) *error = OTERR_NOMEM; return NULL; }
    c->out = c->iobuf + c->iobuf_len;
    if (h[0] == '[' && h[l - 1] == ']' && l - 2 < sizeof c->host) {   /* [v6] */
        memcpy(c->host, h + 1, l - 2);
        c->host[l - 2] = 0;
    } else {
        ot_strlcpy(c->host, h, sizeof c->host);
    }
    if (parse_ipv4(c->host, c->ip)) c->ip_len = 4;
    else if (strchr(c->host, ':') && parse_ipv6(c->host, c->ip)) c->ip_len = 16;
    else if (strchr(c->host, ':')) { OT_FreeConnection(c); if (error) *error = OTERR_ARGS; return NULL; }
    if (set_alpn(c, x->alpn) != OTERR_OK) { OT_FreeConnection(c); if (error) *error = OTERR_NOMEM; return NULL; }
    c->state = OTS_NEW;
    return c;
}

VOID OT_FreeConnection(struct OTConnection *c)
{
    if (!c) return;
    ot_x509_free(&c->x509);
    if (c->iobuf) {
        memset(c->iobuf, 0, c->iobuf_len + OT_OUT_MAX);
        ot_free(c->iobuf);
    }
    ot_free(c->alpn);
    memset(c, 0, sizeof *c);       /* the session's keys go too */
    ot_free(c);
}

#define BEFORE_HANDSHAKE(c) do { if (!(c)) return OTERR_ARGS; \
    if ((c)->state != OTS_NEW) return OTERR_STATE; } while (0)

LONG OT_SetSocket(struct OTConnection *c, LONG socket, struct Library *socketBase)
{
    BEFORE_HANDSHAKE(c);
#ifdef __amigaos__
    if (!socketBase) return OTERR_ARGS;
#endif
    if (socket < 0) return OTERR_ARGS;
    c->fd = socket;
    c->socketbase = socketBase;
    c->hook = NULL;
    c->have_io = 1;
    return OTERR_OK;
}

LONG OT_SetIOHook(struct OTConnection *c, struct Hook *hook)
{
    BEFORE_HANDSHAKE(c);
    if (!hook) return OTERR_ARGS;
    c->hook = hook;
    c->have_io = 1;
    return OTERR_OK;
}

LONG OT_SetALPN(struct OTConnection *c, CONST_STRPTR protocols)
{
    BEFORE_HANDSHAKE(c);
    return set_alpn(c, (const char *)protocols);
}

LONG OT_SetVerify(struct OTConnection *c, LONG mode)
{
    BEFORE_HANDSHAKE(c);
    if (mode < OTV_FULL || mode > OTV_PINNED_ONLY) return OTERR_ARGS;
    c->verify = mode;
    return OTERR_OK;
}

LONG OT_PinCertificate(struct OTConnection *c, CONST UBYTE *sha256)
{
    BEFORE_HANDSHAKE(c);
    if (!sha256) { c->pinned = 0; return OTERR_OK; }
    memcpy(c->pin, sha256, 32);
    c->pinned = 1;
    return OTERR_OK;
}

LONG OT_SetSession(struct OTConnection *c, struct OTSession *s)
{
    BEFORE_HANDSHAKE(c);
    if (!s) { c->offer_session = 0; return OTERR_OK; }
    if (!same_host(s->host, c->host)) return OTERR_ARGS;
    c->offered = s->params;
    c->offer_session = 1;
    return OTERR_OK;
}

static const uint16_t ot_suites[] = {
    BR_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    BR_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    BR_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    BR_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    BR_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    BR_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    BR_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
    BR_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
    BR_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
    BR_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
    BR_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
    BR_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
    BR_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
    BR_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
    BR_TLS_RSA_WITH_AES_128_GCM_SHA256,
    BR_TLS_RSA_WITH_AES_256_GCM_SHA384,
    BR_TLS_RSA_WITH_AES_128_CBC_SHA256,
    BR_TLS_RSA_WITH_AES_256_CBC_SHA256,
    BR_TLS_RSA_WITH_AES_128_CBC_SHA,
    BR_TLS_RSA_WITH_AES_256_CBC_SHA,
};

static LONG start_handshake(struct OTConnection *c)
{
    struct OTContext *x = c->ctx;
    br_ssl_engine_context *e = &c->cc.eng;
    const br_x509_trust_anchor *ta = NULL;
    size_t ta_count = 0;
    unsigned char seed[32];
    int need_trust = c->verify == OTV_FULL || c->verify == OTV_NO_HOSTNAME;

    if (!c->have_io)
        return fail(c, OTERR_STATE, 0, "No socket or I/O hook was given.", NULL, NULL);
    /* With no trust store the handshake still runs as far as the server's
     * certificate, so that the caller can show it and offer to trust it
     * (OT_GetPeerFingerprint, OT_GetPeerName); it then fails with
     * OTERR_TRUSTSTORE unless the certificate is pinned. */
    if (need_trust) merged_anchors(x, &ta, &ta_count);
    ot_glue_select(&c->impls, !(x->flags & OTCF_NO_OFFLOAD));

    br_ssl_client_zero(&c->cc);
    br_ssl_engine_set_versions(e, (unsigned)x->min_version, (unsigned)x->max_version);
    br_ssl_engine_set_suites(e, ot_suites, sizeof ot_suites / sizeof ot_suites[0]);
    br_ssl_engine_set_hash(e, br_md5_ID, &br_md5_vtable);
    br_ssl_engine_set_hash(e, br_sha1_ID, &br_sha1_vtable);
    br_ssl_engine_set_hash(e, br_sha224_ID, &br_sha224_vtable);
    br_ssl_engine_set_hash(e, br_sha256_ID, c->impls.sha256);
    br_ssl_engine_set_hash(e, br_sha384_ID, c->impls.sha384);
    br_ssl_engine_set_hash(e, br_sha512_ID, c->impls.sha512);
    br_ssl_engine_set_prf10(e, &br_tls10_prf);
    br_ssl_engine_set_prf_sha256(e, &br_tls12_sha256_prf);
    br_ssl_engine_set_prf_sha384(e, &br_tls12_sha384_prf);
    br_ssl_engine_set_rsavrfy(e, c->impls.rsa_vrfy);
    br_ssl_client_set_rsapub(&c->cc, c->impls.rsa_pub);
    br_ssl_engine_set_ecdsa(e, c->impls.ecdsa_vrfy);
    br_ssl_engine_set_ec(e, c->impls.ec);
    br_ssl_engine_set_cbc(e, &br_sslrec_in_cbc_vtable, &br_sslrec_out_cbc_vtable);
    br_ssl_engine_set_aes_cbc(e, c->impls.aes_cbcenc, c->impls.aes_cbcdec);
    br_ssl_engine_set_gcm(e, &br_sslrec_in_gcm_vtable, &br_sslrec_out_gcm_vtable);
    br_ssl_engine_set_aes_ctr(e, c->impls.aes_ctr);
    br_ssl_engine_set_ghash(e, c->impls.ghash);
    br_ssl_engine_set_chapol(e, &br_sslrec_in_chapol_vtable, &br_sslrec_out_chapol_vtable);
    br_ssl_engine_set_chacha20(e, c->impls.chacha20);
    br_ssl_engine_set_poly1305(e, c->impls.poly1305);

    ot_x509_init(&c->x509, c, &c->impls, ta, ta_count);
    br_ssl_engine_set_x509(e, &c->x509.vtable);
    br_ssl_engine_set_buffer(e, c->iobuf, c->iobuf_len, !(x->flags & OTCF_SMALL_BUFFERS));
    if (c->alpn_count)
        br_ssl_engine_set_protocol_names(e, c->alpn_names, (size_t)c->alpn_count);
    if (c->offer_session)
        br_ssl_engine_set_session_parameters(e, &c->offered);
    if (ot_random(seed, sizeof seed) != OTERR_OK)
        return fail(c, OTERR_RANDOM, 0, "No random numbers for the handshake.", NULL, NULL);
    br_ssl_engine_inject_entropy(e, seed, sizeof seed);
    memset(seed, 0, sizeof seed);
    c->state = OTS_HANDSHAKE;
    if (!br_ssl_client_reset(&c->cc, c->ip_len ? NULL : c->host, c->offer_session))
        return engine_error(c, br_ssl_engine_last_error(e));
    return OTERR_OK;
}

LONG OT_Handshake(struct OTConnection *c)
{
    LONG rc;
    const char *alpn;
    if (!c) return OTERR_ARGS;
    if (c->state == OTS_OPEN) return OTERR_OK;
    if (c->state == OTS_FAILED) return c->error;
    if (c->state == OTS_CLOSED) return OTERR_STATE;
    if (c->state == OTS_NEW && (rc = start_handshake(c)) != OTERR_OK) return rc;
    rc = pump(c, BR_SSL_SENDAPP | BR_SSL_RECVAPP);
    if (rc == OTERR_CLOSED && c->clean_close) {
        c->state = OTS_FAILED;
        return fail(c, OTERR_CLOSED, 0, "The server closed the connection during the handshake.", NULL, NULL);
    }
    if (rc != OTERR_OK) return rc;
    c->state = OTS_OPEN;
    c->error = OTERR_OK;
    c->text[0] = 0;
    alpn = br_ssl_engine_get_selected_protocol(&c->cc.eng);
    ot_strlcpy(c->alpn_selected, alpn ? alpn : "", sizeof c->alpn_selected);
    if (c->offer_session && c->offered.session_id_len) {
        br_ssl_session_parameters now;
        br_ssl_engine_get_session_parameters(&c->cc.eng, &now);
        c->resumed = now.session_id_len == c->offered.session_id_len
                  && !memcmp(now.session_id, c->offered.session_id, now.session_id_len);
    }
    return OTERR_OK;
}

LONG OT_Read(struct OTConnection *c, APTR buffer, LONG length)
{
    LONG rc;
    size_t avail;
    unsigned char *buf;
    if (!c || length < 0 || (!buffer && length)) return OTERR_ARGS;
    if (c->state == OTS_CLOSED) return c->clean_close ? 0 : OTERR_STATE;
    if (c->state == OTS_FAILED) return c->error;
    if (c->state != OTS_OPEN) return OTERR_STATE;
    if (!length) return 0;
    rc = pump(c, BR_SSL_RECVAPP);
    if (rc == OTERR_CLOSED && c->clean_close) return 0;
    if (rc != OTERR_OK) return rc;
    buf = br_ssl_engine_recvapp_buf(&c->cc.eng, &avail);
    if ((size_t)length > avail) length = (LONG)avail;
    memcpy(buffer, buf, (size_t)length);
    br_ssl_engine_recvapp_ack(&c->cc.eng, (size_t)length);
    return length;
}

LONG OT_Write(struct OTConnection *c, CONST_APTR buffer, LONG length)
{
    const unsigned char *p = buffer;
    LONG total = 0, rc;
    if (!c || length < 0 || (!buffer && length)) return OTERR_ARGS;
    if (c->state == OTS_FAILED) return c->error;
    if (c->state != OTS_OPEN) return OTERR_STATE;
    while (total < length) {
        size_t room, n;
        unsigned char *buf;
        rc = pump(c, BR_SSL_SENDAPP);
        if (rc == OTERR_WOULDBLOCK) return total ? total : rc;
        if (rc == OTERR_CLOSED && c->clean_close) {
            c->state = OTS_FAILED;
            return fail(c, OTERR_CLOSED, 0, "The server closed the connection.", NULL, NULL);
        }
        if (rc != OTERR_OK) return rc;
        buf = br_ssl_engine_sendapp_buf(&c->cc.eng, &room);
        n = (size_t)(length - total) < room ? (size_t)(length - total) : room;
        memcpy(buf, p + total, n);
        br_ssl_engine_sendapp_ack(&c->cc.eng, n);
        total += (LONG)n;
    }
    br_ssl_engine_flush(&c->cc.eng, 0);
    rc = flush_out(c);
    if (rc == OTERR_WOULDBLOCK) { c->state = OTS_OPEN; c->error = OTERR_OK; return total; }
    return rc == OTERR_OK ? total : rc;
}

LONG OT_Pending(struct OTConnection *c)
{
    size_t avail = 0;
    if (!c || c->state != OTS_OPEN) return 0;
    if (br_ssl_engine_current_state(&c->cc.eng) & BR_SSL_RECVAPP)
        br_ssl_engine_recvapp_buf(&c->cc.eng, &avail);
    return (LONG)avail;
}

LONG OT_Close(struct OTConnection *c)
{
    LONG rc;
    if (!c) return OTERR_ARGS;
    if (c->state == OTS_CLOSED) return OTERR_OK;
    if (c->state != OTS_OPEN) return OTERR_STATE;
    br_ssl_engine_close(&c->cc.eng);
    rc = flush_out(c);
    if (rc == OTERR_WOULDBLOCK) { c->state = OTS_OPEN; return rc; }
    if (rc != OTERR_OK) return rc;
    c->state = OTS_CLOSED;
    c->clean_close = 1;
    return OTERR_OK;
}

/* ---- sessions ---- */

struct OTSession *OT_GetSession(struct OTConnection *c)
{
    struct OTSession *s;
    if (!c || (c->state != OTS_OPEN && c->state != OTS_CLOSED)) return NULL;
    s = ot_alloc(sizeof *s);
    if (!s) return NULL;
    br_ssl_engine_get_session_parameters(&c->cc.eng, &s->params);
    if (!s->params.session_id_len) { ot_free(s); return NULL; }
    ot_strlcpy(s->host, c->host, sizeof s->host);
    return s;
}

VOID OT_FreeSession(struct OTSession *s)
{
    if (!s) return;
    memset(s, 0, sizeof *s);       /* the master secret */
    ot_free(s);
}

LONG OT_SessionResumed(struct OTConnection *c)
{
    return c && c->state != OTS_NEW && c->resumed ? 1 : 0;
}

/* ---- information ---- */

LONG OT_GetError(struct OTConnection *c) { return c ? c->error : OTERR_ARGS; }
LONG OT_GetErrorDetail(struct OTConnection *c) { return c ? c->detail : 0; }

CONST_STRPTR OT_GetErrorText(struct OTConnection *c)
{
    if (!c) return (CONST_STRPTR)"No connection.";
    if (!c->error) return (CONST_STRPTR)"No error.";
    if (!c->text[0]) return OT_ErrorString(c->error);
    return (CONST_STRPTR)c->text;
}

CONST_STRPTR OT_ErrorString(LONG error)
{
    static const char *const names[] = {
        "No error.",
        "Bad arguments.",
        "Out of memory.",
        "The connection failed.",
        "The peer closed the connection without close_notify.",
        "The socket would block: call again.",
        "The peer broke the TLS protocol.",
        "No protocol version in common.",
        "No cipher suite in common.",
        "The peer sent a fatal alert.",
        "The certificate is not signed by a trusted authority.",
        "The certificate is not for this host.",
        "The certificate is expired or not yet valid.",
        "The certificate is malformed or cannot be used.",
        "No trusted certificates could be read.",
        "Call out of order.",
        "No random numbers.",
        "Not supported by this version of OpenTLS.",
        "Internal error in OpenTLS.",
        "The certificate is not the pinned one.",
    };
    if (error > 0 || error < -(LONG)(sizeof names / sizeof names[0]) + 1)
        return (CONST_STRPTR)"Unknown error.";
    return (CONST_STRPTR)names[-error];
}

LONG OT_GetProtocol(struct OTConnection *c)
{
    if (!c || (c->state != OTS_OPEN && c->state != OTS_CLOSED)) return 0;
    return (LONG)br_ssl_engine_get_version(&c->cc.eng);
}

CONST_STRPTR OT_GetCipher(struct OTConnection *c)
{
    br_ssl_session_parameters p;
    size_t i;
    if (!c || (c->state != OTS_OPEN && c->state != OTS_CLOSED)) return (CONST_STRPTR)"";
    br_ssl_engine_get_session_parameters(&c->cc.eng, &p);
    for (i = 0; i < SUITE_COUNT; ++i)
        if (suite_names[i].id == p.cipher_suite) return (CONST_STRPTR)suite_names[i].name;
    return (CONST_STRPTR)"";
}

CONST_STRPTR OT_GetALPN(struct OTConnection *c)
{
    return (CONST_STRPTR)(c ? c->alpn_selected : "");
}

LONG OT_GetPeerFingerprint(struct OTConnection *c, UBYTE *sha256)
{
    if (!c || !sha256) return OTERR_ARGS;
    if (!c->x509.have_fingerprint) return OTERR_STATE;
    memcpy(sha256, c->x509.fingerprint, 32);
    return OTERR_OK;
}

LONG OT_GetPeerCertificate(struct OTConnection *c, APTR buffer, LONG length)
{
    if (!c) return OTERR_ARGS;
    if (!c->x509.have_fingerprint || !c->x509.leaf_ok || !c->x509.leaf_len) return OTERR_STATE;
    if (!buffer) return (LONG)c->x509.leaf_len;
    if (length < (LONG)c->x509.leaf_len) return OTERR_ARGS;
    memcpy(buffer, c->x509.leaf, c->x509.leaf_len);
    return (LONG)c->x509.leaf_len;
}

CONST_STRPTR OT_GetPeerName(struct OTConnection *c)
{
    if (!c || !c->x509.have_fingerprint || !c->x509.leaf_ok) return (CONST_STRPTR)"";
    if (!c->peer_name_done) {
        ot_cert_name(c->x509.leaf, c->x509.leaf_len, c->peer_name, sizeof c->peer_name);
        c->peer_name_done = 1;
    }
    return (CONST_STRPTR)c->peer_name;
}

LONG OT_Random(APTR buffer, LONG length)
{
    if (length < 0 || (!buffer && length)) return OTERR_ARGS;
    return ot_random(buffer, (size_t)length);
}

ULONG OT_Accelerated(VOID)
{
    return ot_glue_accelerated();
}
