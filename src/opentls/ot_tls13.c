/* OpenTLS: the TLS 1.3 client, written from RFC 8446.
 *
 * One ClientHello offers TLS 1.3 and, when the caller's range allows, TLS
 * 1.0 to 1.2 as well. If the server answers with TLS 1.3, this file does
 * the rest of the connection; if it answers with TLS 1.2 or older,
 * ot_tls13_bridge.c hands the same connection to BearSSL, which was set up
 * as usual and believes it sent that ClientHello itself.
 *
 * What is supported: X25519 (the key share sent at once) and P-256 (after
 * a HelloRetryRequest), the three cipher suites, certificates with ECDSA
 * (P-256, P-384, P-521), RSA-PSS (rsa_pss_rsae_*) and Ed25519 keys, ALPN,
 * resumption with tickets (psk_dhe_ke), KeyUpdate in both directions and
 * the middlebox compatibility mode (RFC 8446 appendix D.4). No 0-RTT, no
 * client certificates (a CertificateRequest gets an empty Certificate).
 *
 * Buffers: until the ServerHello, records come into the connection's
 * BearSSL buffer (BearSSL is waiting for the ServerHello and holds
 * nothing) and leave from the gathering buffer. Once TLS 1.3 is chosen
 * BearSSL is not used again, so its buffer holds the record being read and,
 * when large enough (not OTCF_SMALL_BUFFERS), the records being written.
 *
 * MIT licensed and free. Copyright (c) 2026 The AmigaChrome Team. */
#include "ot_tls13.h"
#include <clib/opentls_protos.h>

#define HS_CLIENT_HELLO       1
#define HS_SERVER_HELLO       2
#define HS_NEW_SESSION_TICKET 4
#define HS_ENCRYPTED_EXT      8
#define HS_CERTIFICATE        11
#define HS_CERT_REQUEST       13
#define HS_CERT_VERIFY        15
#define HS_FINISHED           20
#define HS_KEY_UPDATE         24
#define HS_MESSAGE_HASH       254

#define EXT_SERVER_NAME       0
#define EXT_GROUPS            10
#define EXT_POINT_FORMATS     11
#define EXT_SIGALGS           13
#define EXT_ALPN              16
#define EXT_PSK               41
#define EXT_VERSIONS          43
#define EXT_COOKIE            44
#define EXT_PSK_MODES         45
#define EXT_KEY_SHARE         51
#define EXT_RENEGOTIATION     0xFF01

#define GROUP_P256            23
#define GROUP_P384            24
#define GROUP_P521            25
#define GROUP_X25519          29

#define ALERT_CLOSE_NOTIFY        0
#define ALERT_UNEXPECTED_MESSAGE  10
#define ALERT_BAD_RECORD_MAC      20
#define ALERT_RECORD_OVERFLOW     22
#define ALERT_HANDSHAKE_FAILURE   40
#define ALERT_BAD_CERTIFICATE     42
#define ALERT_UNSUPPORTED_CERT    43
#define ALERT_CERT_EXPIRED        45
#define ALERT_ILLEGAL_PARAMETER   47
#define ALERT_UNKNOWN_CA          48
#define ALERT_DECODE_ERROR        50
#define ALERT_DECRYPT_ERROR       51
#define ALERT_PROTOCOL_VERSION    70
#define ALERT_INTERNAL_ERROR      80
#define ALERT_USER_CANCELED       90
#define ALERT_MISSING_EXTENSION   109
#define ALERT_UNSUPPORTED_EXT     110
#define ALERT_NO_APP_PROTOCOL     120

/* SHA-256 of "HelloRetryRequest": a ServerHello with this random is one */
static const unsigned char hrr_random[32] = {
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C
};

/* the signature schemes offered, most wanted first */
static const uint16_t sigalgs[] = {
    0x0403, 0x0503, 0x0603,          /* ECDSA P-256/SHA-256, P-384/SHA-384, P-521/SHA-512 */
    0x0807,                          /* Ed25519 (when the glue has it) */
    0x0804, 0x0805, 0x0806,          /* RSA-PSS with an rsaEncryption key */
    0x0401, 0x0501, 0x0601,          /* RSA PKCS #1 v1.5: certificates and TLS 1.2 only */
    0x0203, 0x0201                   /* SHA-1: old certificates and TLS 1.2 only */
};

static const uint16_t suites13[] = {
    OT13_CHACHA20_POLY1305_SHA256, OT13_AES_128_GCM_SHA256, OT13_AES_256_GCM_SHA384
};

/* ---- small helpers ---- */

static unsigned get16(const unsigned char *p) { return ((unsigned)p[0] << 8) | p[1]; }
static size_t get24(const unsigned char *p) { return ((size_t)p[0] << 16) | ((size_t)p[1] << 8) | p[2]; }
static uint32_t get32(const unsigned char *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}
static void put16(unsigned char *p, size_t v) { p[0] = (unsigned char)(v >> 8); p[1] = (unsigned char)v; }
static void put24(unsigned char *p, size_t v) { p[0] = (unsigned char)(v >> 16); put16(p + 1, v); }
static void put32(unsigned char *p, uint32_t v) { put16(p, v >> 16); put16(p + 2, v & 0xFFFF); }

static int ct_equal(const unsigned char *a, const unsigned char *b, size_t n)
{
    unsigned char d = 0;
    size_t i;
    for (i = 0; i < n; ++i) d |= (unsigned char)(a[i] ^ b[i]);
    return d == 0;
}

static size_t hlen_of(const br_hash_class *h)
{
    return (h->desc >> BR_HASHDESC_OUT_OFF) & BR_HASHDESC_OUT_MASK;
}

/* a reader over a message: every get checks the length, and a short read
 * sets bad, so a parser checks once at its end */
struct rd { const unsigned char *p; size_t n; int bad; };

static unsigned rd8(struct rd *r)
{
    if (r->n < 1) { r->bad = 1; return 0; }
    --r->n;
    return *r->p++;
}
static unsigned rd16(struct rd *r)
{
    unsigned v;
    if (r->n < 2) { r->bad = 1; r->n = 0; return 0; }
    v = get16(r->p); r->p += 2; r->n -= 2;
    return v;
}
static size_t rd24(struct rd *r)
{
    size_t v;
    if (r->n < 3) { r->bad = 1; r->n = 0; return 0; }
    v = get24(r->p); r->p += 3; r->n -= 3;
    return v;
}
/* the next len bytes as a sub-reader */
static struct rd rdsub(struct rd *r, size_t len)
{
    struct rd s;
    if (r->n < len) { r->bad = 1; len = r->n; }
    s.p = r->p; s.n = len; s.bad = r->bad;
    r->p += len; r->n -= len;
    return s;
}

/* ---- the transcript ---- */

static void th_update(struct ot13 *t, const void *data, size_t len)
{
    if (!t->hash || t->hash == &br_sha256_vtable) br_sha256_update(&t->th256, data, len);
    if (!t->hash || t->hash == &br_sha384_vtable) br_sha384_update(&t->th384, data, len);
}

/* the hash of the messages so far, in h (the suite's, or a PSK's) */
static void th_out(struct ot13 *t, const br_hash_class *h, unsigned char *out)
{
    if (h == &br_sha384_vtable) br_sha384_out(&t->th384, out);
    else br_sha256_out(&t->th256, out);
}

/* ---- errors and alerts ---- */

static LONG tx_flush(struct OTConnection *c);

static void queue_alert(struct OTConnection *c, int level, int desc);

/* ends the handshake or connection: sends the alert (when it can go at
 * once) and fails with code and the text */
static LONG abort13(struct OTConnection *c, int alert, LONG code, const char *what)
{
    struct ot13 *t = c->t13;
    if (alert >= 0 && t && !t->close_sent) {
        queue_alert(c, 2, alert);
        tx_flush(c);
    }
    if (code == OTERR_PROTOCOL)
        return ot_fail(c, code, alert, "The server broke the TLS 1.3 protocol: ", what, ".");
    return ot_fail(c, code, alert, what, NULL, NULL);
}

/* ---- records out ---- */

static LONG tx_flush(struct OTConnection *c)
{
    struct ot13 *t = c->t13;
    while (t->tx_sent < t->tx_len) {
        LONG n = ot_io(c, 1, t->tx + t->tx_sent, t->tx_len - t->tx_sent);
        if (n == OTERR_WOULDBLOCK)
            return ot_fail(c, OTERR_WOULDBLOCK, 0, "The socket would block.", NULL, NULL);
        if (n <= 0) return ot_fail(c, OTERR_IO, 0, "Sending to the server failed.", NULL, NULL);
        t->tx_sent += (size_t)n;
    }
    t->tx_len = t->tx_sent = 0;
    return OTERR_OK;
}

/* room for a record of len bytes of content, sealed; NULL when there is none */
static unsigned char *tx_room(struct ot13 *t, size_t len)
{
    if (t->tx_sent == t->tx_len) t->tx_len = t->tx_sent = 0;
    if (t->tx_len + 5 + len + 1 + 16 > t->tx_cap) return NULL;
    return t->tx + t->tx_len;
}

/* puts a record of len bytes (already at rec + 5) in the queue: sealed
 * once the keys are on, else in the clear */
static void tx_record(struct ot13 *t, unsigned char *rec, int type, size_t len)
{
    if (t->wr_on) {
        t->tx_len += ot13_seal(&t->wr, rec, type, len);
    } else {
        rec[0] = (unsigned char)type;
        rec[1] = 3;
        rec[2] = 3;
        put16(rec + 3, len);
        t->tx_len += 5 + len;
    }
}

static void queue_alert(struct OTConnection *c, int level, int desc)
{
    struct ot13 *t = c->t13;
    unsigned char *rec = tx_room(t, 2);
    if (!rec) {            /* full: drop what is waiting, the alert matters more */
        t->tx_len = t->tx_sent = 0;
        rec = tx_room(t, 2);
        if (!rec) return;
    }
    rec[5] = (unsigned char)level;
    rec[6] = (unsigned char)desc;
    tx_record(t, rec, BR_SSL_ALERT, 2);
    if (desc == ALERT_CLOSE_NOTIFY || level == 2) t->close_sent = 1;
}

/* the middlebox compatibility mode's ChangeCipherSpec, once */
static void queue_ccs(struct ot13 *t)
{
    unsigned char *rec;
    if (t->ccs_sent || !(rec = tx_room(t, 1))) return;
    rec[0] = BR_SSL_CHANGE_CIPHER_SPEC;
    rec[1] = 3;
    rec[2] = 3;
    put16(rec + 3, 1);
    rec[5] = 1;
    t->tx_len += 6;
    t->ccs_sent = 1;
}

/* ---- key shares ---- */

static LONG make_x25519(struct OTConnection *c, unsigned char *pub)
{
    struct ot13 *t = c->t13;
    if (ot_random(t->x25519, 32) != OTERR_OK) return OTERR_RANDOM;
    t->x25519[0] &= 0xF8;
    t->x25519[31] &= 0x7F;
    t->x25519[31] |= 0x40;
    if (c->impls.ec->mulgen(pub, t->x25519, 32, BR_EC_curve25519) != 32) return OTERR_INTERNAL;
    return OTERR_OK;
}

static LONG make_p256(struct OTConnection *c, unsigned char *pub)
{
    struct ot13 *t = c->t13;
    const unsigned char *order;
    size_t olen, i;
    do {        /* 0 < k < n; the first draw is almost always right */
        int below = 0, zero = 1;
        if (ot_random(t->p256, 32) != OTERR_OK) return OTERR_RANDOM;
        order = c->impls.ec->order(BR_EC_secp256r1, &olen);
        for (i = 0; i < 32; ++i) {
            if (t->p256[i]) zero = 0;
            if (t->p256[i] != order[i]) { below = t->p256[i] < order[i]; break; }
        }
        if (below && !zero) break;
    } while (1);
    if (c->impls.ec->mulgen(pub, t->p256, 32, BR_EC_secp256r1) != 65) return OTERR_INTERNAL;
    return OTERR_OK;
}

/* the shared secret with the server's share; its length, 0 if refused */
static size_t ecdhe(struct OTConnection *c, unsigned group, const unsigned char *share, size_t len,
                    unsigned char *out)
{
    struct ot13 *t = c->t13;
    unsigned char g[65], acc = 0;
    size_t xlen, xoff, i;
    if (group == GROUP_X25519) {
        if (len != 32) return 0;
        memcpy(g, share, 32);
        if (!c->impls.ec->mul(g, 32, t->x25519, 32, BR_EC_curve25519)) return 0;
        for (i = 0; i < 32; ++i) acc |= g[i];
        if (!acc) return 0;             /* a small-order point */
        memcpy(out, g, 32);
        return 32;
    }
    if (len != 65 || share[0] != 4) return 0;
    memcpy(g, share, 65);
    if (!c->impls.ec->mul(g, 65, t->p256, 32, BR_EC_secp256r1)) return 0;
    xoff = c->impls.ec->xoff(BR_EC_secp256r1, &xlen);
    memcpy(out, g + xoff, xlen);
    return xlen;
}

/* ---- the ClientHello ---- */

static int offer_ticket(struct OTConnection *c, uint32_t *age)
{
    const struct ot13_ticket *k = c->offer13;
    uint32_t days, secs;
    if (!k || !ot13_suite(k->suite)) return 0;
    *age = 0;
    if (ot_now(&days, &secs) && k->days) {
        uint32_t now = days * 86400UL + secs, then = k->days * 86400UL + k->seconds;
        uint32_t s = now >= then ? now - then : 0;
        if (s > k->lifetime || s > 7 * 86400UL) return 0;
        *age = s * 1000UL;
    }
    return 1;
}

/* writes the ClientHello as a record at t->tx; the record's length, or a
 * negative error */
static LONG build_client_hello(struct OTConnection *c)
{
    struct ot13 *t = c->t13;
    struct OTContext *x = c->ctx;
    unsigned char *rec, *m, *p, *ext, *binders = NULL;
    const struct ot13_suite *ps = NULL;
    uint32_t age = 0;
    size_t i, hl;
    LONG rc;
    int v, minv = (int)c->min_version, k;
    /* what it can take at most, without the ticket: it must fit (a long
     * cookie from the server may not), and the ticket is left out when
     * it would not */
    size_t most = 5 + 4 + 2 + 32 + 1 + 32 + 2 + 2 * (3 + ot_suites12_count) + 2 + 2
                + 9 + strlen(c->host) + 5 + 8 + 14 + 6 + 6 + 2 * 12 + 6 + 5 + 10 + 65 + 6
                + (t->cookie ? 6 + t->cookie_len : 0) + 22;

    (void)x;
    for (k = 0; k < c->alpn_count; ++k) most += 1 + strlen(c->alpn_names[k]);
    if (most > t->tx_cap) return OTERR_INTERNAL;
    t->tx_len = t->tx_sent = 0;
    rec = t->tx;
    m = rec + 5;
    p = m + 4;
    *p++ = 3; *p++ = 3;                         /* legacy_version: TLS 1.2 */
    memcpy(p, t->random, 32); p += 32;
    *p++ = (unsigned char)t->sid_len;
    memcpy(p, t->sid, t->sid_len); p += t->sid_len;
    /* cipher suites: ours, then TLS 1.2's (BearSSL's list) */
    {
        size_t n = sizeof suites13 / sizeof suites13[0] + (t->offer12 ? ot_suites12_count : 0);
        put16(p, 2 * n); p += 2;
        for (i = 0; i < sizeof suites13 / sizeof suites13[0]; ++i) { put16(p, suites13[i]); p += 2; }
        if (t->offer12)
            for (i = 0; i < ot_suites12_count; ++i) { put16(p, ot_suites12[i]); p += 2; }
    }
    *p++ = 1; *p++ = 0;                         /* compression: none */
    ext = p;
    p += 2;
    if (!c->ip_len) {                           /* server_name */
        size_t hl2 = strlen(c->host);
        put16(p, EXT_SERVER_NAME); put16(p + 2, hl2 + 5); put16(p + 4, hl2 + 3);
        p[6] = 0; put16(p + 7, hl2);
        memcpy(p + 9, c->host, hl2);
        p += 9 + hl2;
    }
    /* supported_versions: 1.3, then what TLS 1.2 down to the minimum allows */
    {
        unsigned char *l = p + 4;
        put16(p, EXT_VERSIONS);
        p += 5;
        put16(p, OT_TLS13); p += 2;
        if (t->offer12)
            for (v = OT_TLS12; v >= minv && v >= OT_TLS10; --v) { put16(p, (size_t)v); p += 2; }
        *l = (unsigned char)(p - l - 1);
        put16(l - 2, (size_t)(p - l));
    }
    put16(p, EXT_GROUPS);                       /* supported_groups */
    put16(p + 2, t->offer12 ? 10 : 8);
    put16(p + 4, t->offer12 ? 8 : 6);
    put16(p + 6, GROUP_X25519); put16(p + 8, GROUP_P256); put16(p + 10, GROUP_P384);
    p += 12;
    if (t->offer12) { put16(p, GROUP_P521); p += 2; }
    if (t->offer12) {                           /* ec_point_formats: uncompressed */
        put16(p, EXT_POINT_FORMATS); put16(p + 2, 2); p[4] = 1; p[5] = 0;
        p += 6;
    }
    {                                           /* signature_algorithms */
        unsigned char *l = p + 2;
        put16(p, EXT_SIGALGS);
        p += 6;
        for (i = 0; i < sizeof sigalgs / sizeof sigalgs[0]; ++i) {
            if (sigalgs[i] == 0x0807 && !t->sigalgs_ed25519) continue;
            put16(p, sigalgs[i]); p += 2;
        }
        put16(l, (size_t)(p - l - 2));
        put16(l + 2, (size_t)(p - l - 4));
    }
    if (c->alpn_count) {                        /* ALPN */
        unsigned char *l = p + 2;
        put16(p, EXT_ALPN);
        p += 6;
        for (k = 0; k < c->alpn_count; ++k) {
            size_t n = strlen(c->alpn_names[k]);
            *p++ = (unsigned char)n;
            memcpy(p, c->alpn_names[k], n);
            p += n;
        }
        put16(l, (size_t)(p - l - 2));
        put16(l + 2, (size_t)(p - l - 4));
    }
    if (t->offer12) {                           /* renegotiation_info: empty */
        put16(p, EXT_RENEGOTIATION); put16(p + 2, 1); p[4] = 0;
        p += 5;
    }
    {                                           /* key_share: one share */
        size_t kl = t->group == GROUP_X25519 ? 32 : 65;
        put16(p, EXT_KEY_SHARE); put16(p + 2, kl + 6); put16(p + 4, kl + 4);
        put16(p + 6, t->group); put16(p + 8, kl);
        rc = t->group == GROUP_X25519 ? make_x25519(c, p + 10) : make_p256(c, p + 10);
        if (rc != OTERR_OK) return rc;
        p += 10 + kl;
    }
    put16(p, EXT_PSK_MODES); put16(p + 2, 2); p[4] = 1; p[5] = 1;   /* psk_dhe_ke */
    p += 6;
    if (t->cookie) {
        put16(p, EXT_COOKIE); put16(p + 2, t->cookie_len + 2); put16(p + 4, t->cookie_len);
        memcpy(p + 6, t->cookie, t->cookie_len);
        p += 6 + t->cookie_len;
    }
    /* pre_shared_key, last: a ticket whose hash suits the HelloRetryRequest's suite */
    if (offer_ticket(c, &age) && most + 8 + c->offer13->len + 4 + 3 + OT13_HASH_MAX <= t->tx_cap) {
        ps = ot13_suite(c->offer13->suite);
        if (t->hrr && ps->hash != t->hash) ps = NULL;
    }
    if (ps) {
        const struct ot13_ticket *k = c->offer13;
        hl = ps->hash_len;
        put16(p, EXT_PSK);
        put16(p + 2, 2 + 2 + k->len + 4 + 2 + 1 + hl);
        put16(p + 4, 2 + k->len + 4);
        put16(p + 6, k->len);
        memcpy(p + 8, k->data, k->len);
        put32(p + 8 + k->len, age + k->age_add);
        p += 8 + k->len + 4;
        binders = p;
        put16(p, 1 + hl);
        p[2] = (unsigned char)hl;
        p += 3 + hl;
    }
    put16(ext, (size_t)(p - ext - 2));
    m[0] = HS_CLIENT_HELLO;
    put24(m + 1, (size_t)(p - m - 4));
    if (ps) {
        /* the binder: HMAC over the transcript up to the identities */
        unsigned char early[OT13_HASH_MAX], bkey[OT13_HASH_MAX], th[OT13_HASH_MAX];
        br_sha256_context s256 = t->th256;
        br_sha384_context s384 = t->th384;
        ot13_extract(ps->hash, NULL, c->offer13->psk, ps->hash_len, early);
        ot13_derive(ps->hash, early, "res binder", NULL, bkey);
        if (ps->hash == &br_sha384_vtable) {
            br_sha384_update(&s384, m, (size_t)(binders - m));
            br_sha384_out(&s384, th);
        } else {
            br_sha256_update(&s256, m, (size_t)(binders - m));
            br_sha256_out(&s256, th);
        }
        ot13_finished(ps->hash, bkey, th, binders + 3);
        memset(early, 0, sizeof early);
        memset(bkey, 0, sizeof bkey);
        t->offer = c->offer13;
    } else {
        t->offer = NULL;
    }
    rec[0] = BR_SSL_HANDSHAKE;
    rec[1] = 3;
    rec[2] = t->hrr ? 3 : 1;                    /* the first one says TLS 1.0, as is usual */
    put16(rec + 3, (size_t)(p - m));
    th_update(t, m, (size_t)(p - m));
    if (t->offer12 && !t->hrr) {
        /* BearSSL hashed the ClientHello it made; it must hash this one */
        br_multihash_init(&c->cc.eng.mhash);
        br_multihash_update(&c->cc.eng.mhash, m, (size_t)(p - m));
    }
    t->tx_len = (size_t)(p - rec);
    return (LONG)t->tx_len;
}

/* ---- set-up ---- */

int ot13_wanted(struct OTConnection *c)
{
    return c->max_version >= OT_TLS13;
}

int ot13_active(struct OTConnection *c)
{
    return c->t13 && c->t13->st != T13_BRIDGE && c->t13->st >= T13_WAIT_EE;
}

LONG ot13_start(struct OTConnection *c)
{
    struct ot13 *t = ot_alloc(sizeof *t);
    br_ssl_engine_context *e = &c->cc.eng;
    LONG rc;
    if (!t) return ot_fail(c, OTERR_NOMEM, 0, "Out of memory.", NULL, NULL);
    c->t13 = t;
    t->offer12 = c->min_version <= OT_TLS12;
    t->group = GROUP_X25519;
    t->sigalgs_ed25519 = ot_glue_has_ed25519();
    t->update_after = ot_key_update_after();
    br_sha256_init(&t->th256);
    br_sha384_init(&t->th384);
    t->rx = c->iobuf;
    t->tx = c->out;
    t->tx_cap = OT_OUT_MAX;
    if (t->offer12) {
        /* BearSSL made its ClientHello: keep its random and session ID
         * (a TLS 1.2 session offered) and drop the message */
        size_t len;
        memcpy(t->random, e->client_random, 32);
        t->sid_len = e->session.session_id_len;
        memcpy(t->sid, e->session.session_id, t->sid_len);
        while (br_ssl_engine_current_state(e) & BR_SSL_SENDREC) {
            br_ssl_engine_sendrec_buf(e, &len);
            br_ssl_engine_sendrec_ack(e, len);
        }
        if (!(br_ssl_engine_current_state(e) & BR_SSL_RECVREC))
            return ot_engine_error(c, br_ssl_engine_last_error(e));
    } else if (ot_random(t->random, 32) != OTERR_OK) {
        return ot_fail(c, OTERR_RANDOM, 0, "No random numbers for the handshake.", NULL, NULL);
    }
    if (!t->sid_len) {            /* compatibility mode: a session ID of our own */
        if (ot_random(t->sid, 32) != OTERR_OK)
            return ot_fail(c, OTERR_RANDOM, 0, "No random numbers for the handshake.", NULL, NULL);
        t->sid_len = 32;
    }
    rc = build_client_hello(c);
    if (rc < 0) {
        if (rc == OTERR_RANDOM) return ot_fail(c, rc, 0, "No random numbers for the handshake.", NULL, NULL);
        return ot_fail(c, rc, 0, "The ClientHello could not be made.", NULL, NULL);
    }
    t->st = T13_WAIT_SH;
    return OTERR_OK;
}

/* ---- records in ---- */

/* reads one whole record into t->rx; OTERR_OK, OTERR_WOULDBLOCK or an error */
static LONG read_record(struct OTConnection *c)
{
    struct ot13 *t = c->t13;
    for (;;) {
        size_t need = 5;
        LONG n;
        if (t->rx_have >= 5) {
            size_t len = get16(t->rx + 3);
            if (t->rx[1] != 3 || len > (t->rd_on ? 16384 + 256 : 16384) || len == 0)
                return abort13(c, len ? ALERT_RECORD_OVERFLOW : ALERT_DECODE_ERROR, OTERR_PROTOCOL,
                               "a malformed record");
            need = 5 + len;
            if (t->rx_have == need) return OTERR_OK;
        }
        n = ot_io(c, 0, t->rx + t->rx_have, need - t->rx_have);
        if (n == OTERR_WOULDBLOCK)
            return ot_fail(c, OTERR_WOULDBLOCK, 0, "The socket would block.", NULL, NULL);
        if (n == 0)
            return ot_fail(c, OTERR_CLOSED, 0, t->st < T13_OPEN
                ? "The server closed the connection during the handshake."
                : "The server closed the connection without close_notify.", NULL, NULL);
        if (n < 0) return ot_fail(c, OTERR_IO, 0, "Receiving from the server failed.", NULL, NULL);
        t->rx_have += (size_t)n;
    }
}

/* the record in t->rx, opened: t->pt, t->pt_len, t->pt_type */
static LONG open_record(struct OTConnection *c)
{
    struct ot13 *t = c->t13;
    size_t len = get16(t->rx + 3);
    int type = t->rx[0];
    t->rx_have = 0;           /* the next read starts a new record */
    if (type == BR_SSL_APPLICATION_DATA && t->rd_on) {
        int err = ot13_open(&t->rd, t->rx, 5 + len, &type, &len);
        if (err == BR_ERR_BAD_MAC)
            return abort13(c, ALERT_BAD_RECORD_MAC, OTERR_PROTOCOL, "a record does not decrypt");
        if (err)
            return abort13(c, err == BR_ERR_TOO_LARGE ? ALERT_RECORD_OVERFLOW : ALERT_UNEXPECTED_MESSAGE,
                           OTERR_PROTOCOL, "a malformed record");
        if (type == BR_SSL_CHANGE_CIPHER_SPEC)
            return abort13(c, ALERT_UNEXPECTED_MESSAGE, OTERR_PROTOCOL, "an encrypted ChangeCipherSpec");
    } else if (type == BR_SSL_CHANGE_CIPHER_SPEC) {
        /* the compatibility mode's: one byte 1, between the ServerHello and Finished */
        if (len != 1 || t->rx[5] != 1 || t->st < T13_WAIT_SH || t->st >= T13_OPEN
            || (t->st == T13_WAIT_SH && !t->hrr))
            return abort13(c, ALERT_UNEXPECTED_MESSAGE, OTERR_PROTOCOL, "an unexpected ChangeCipherSpec");
        t->pt_len = 0;
        t->pt_type = type;
        return OTERR_OK;
    } else if (t->rd_on && type != BR_SSL_ALERT) {
        return abort13(c, ALERT_UNEXPECTED_MESSAGE, OTERR_PROTOCOL, "a record in the clear");
    } else if (type != BR_SSL_HANDSHAKE && type != BR_SSL_ALERT) {
        return abort13(c, ALERT_UNEXPECTED_MESSAGE, OTERR_PROTOCOL, "an unexpected record");
    }
    t->pt = t->rx + 5;
    t->pt_len = len;
    t->pt_type = type;
    if (type == BR_SSL_APPLICATION_DATA && t->st != T13_OPEN)
        return abort13(c, ALERT_UNEXPECTED_MESSAGE, OTERR_PROTOCOL, "application data before Finished");
    if (type != BR_SSL_HANDSHAKE && t->hs_len)
        return abort13(c, ALERT_UNEXPECTED_MESSAGE, OTERR_PROTOCOL, "a handshake message cut short");
    return OTERR_OK;
}

static LONG handle_alert(struct OTConnection *c, const unsigned char *p, size_t len)
{
    if (len != 2) return abort13(c, ALERT_DECODE_ERROR, OTERR_PROTOCOL, "a malformed alert");
    if (p[1] == ALERT_CLOSE_NOTIFY) {
        c->clean_close = 1;
        c->state = OTS_CLOSED;
        return OTERR_CLOSED;
    }
    if (p[1] == ALERT_USER_CANCELED) return OTERR_OK;    /* close_notify follows */
    return ot_engine_error(c, BR_ERR_RECV_FATAL_ALERT + p[1]);
}

/* ---- certificate checks and signatures ---- */

static void hash_once(const br_hash_class *h, const void *d, size_t n, unsigned char *out)
{
    br_hash_compat_context hc;
    h->init(&hc.vtable);
    h->update(&hc.vtable, d, n);
    h->out(&hc.vtable, out);
}
static void pss_sha256(const void *d, size_t n, uint8_t *o) { hash_once(&br_sha256_vtable, d, n, o); }
static void pss_sha384(const void *d, size_t n, uint8_t *o) { hash_once(&br_sha384_vtable, d, n, o); }
static void pss_sha512(const void *d, size_t n, uint8_t *o) { hash_once(&br_sha512_vtable, d, n, o); }

int ot13_rsa_pss(const struct ot_impls *m, const br_rsa_public_key *pk, const br_hash_class *h,
                 const unsigned char *hash, const unsigned char *sig, size_t siglen)
{
    unsigned char *em;
    const unsigned char *n = pk->n;
    size_t nlen = pk->nlen, bits, hl = hlen_of(h);
    int ok;
    oc_hash_fn fn = h == &br_sha384_vtable ? pss_sha384 : h == &br_sha512_vtable ? pss_sha512 : pss_sha256;
    while (nlen && !n[0]) { ++n; --nlen; }
    if (!nlen || siglen != nlen || nlen > OC_RSA_MAX_BYTES) return 0;
    for (bits = 8 * nlen; !(n[0] & (0x80 >> (8 * nlen - bits))); --bits) {}
    em = ot_alloc(nlen);
    if (!em) return 0;
    memcpy(em, sig, nlen);
    ok = m->rsa_pub(em, nlen, pk) && oc_emsa_pss_verify(em, nlen, bits, hash, hl, (long)hl, fn);
    ot_free(em);
    return ok;
}

int ot13_verify_cv(const struct ot_impls *m, unsigned scheme, const br_x509_pkey *pk,
                   const unsigned char *ed25519, const unsigned char *thash, size_t thlen,
                   const unsigned char *sig, size_t siglen)
{
    static const char ctx[] = "TLS 1.3, server CertificateVerify";
    unsigned char content[64 + sizeof ctx + OT13_HASH_MAX], h[64];
    const br_hash_class *hc;
    size_t cl = 64 + sizeof ctx + thlen;       /* sizeof includes the 0 separator */
    memset(content, 0x20, 64);
    memcpy(content + 64, ctx, sizeof ctx);
    memcpy(content + 64 + sizeof ctx, thash, thlen);
    if (scheme == 0x0807) {
        if (!ed25519 || siglen != 64) return BR_ERR_INVALID_ALGORITHM;
        return ot_glue_ed25519(sig, ed25519, content, cl) == 1 ? 0 : BR_ERR_BAD_SIGNATURE;
    }
    if (!pk) return BR_ERR_INVALID_ALGORITHM;
    switch (scheme) {
    case 0x0403: case 0x0804: hc = &br_sha256_vtable; break;
    case 0x0503: case 0x0805: hc = &br_sha384_vtable; break;
    case 0x0603: case 0x0806: hc = &br_sha512_vtable; break;
    default: return BR_ERR_INVALID_ALGORITHM;
    }
    hash_once(hc, content, cl, h);
    if ((scheme & 0xFF) == 3) {
        int curve = scheme == 0x0403 ? BR_EC_secp256r1 : scheme == 0x0503 ? BR_EC_secp384r1 : BR_EC_secp521r1;
        if (pk->key_type != BR_KEYTYPE_EC || pk->key.ec.curve != curve) return BR_ERR_INVALID_ALGORITHM;
        return m->ecdsa_vrfy(m->ec, h, hlen_of(hc), &pk->key.ec, sig, siglen) ? 0 : BR_ERR_BAD_SIGNATURE;
    }
    if (pk->key_type != BR_KEYTYPE_RSA) return BR_ERR_INVALID_ALGORITHM;
    return ot13_rsa_pss(m, &pk->key.rsa, hc, h, sig, siglen) ? 0 : BR_ERR_BAD_SIGNATURE;
}

static int cert_alert(int err)
{
    switch (err) {
    case BR_ERR_X509_NOT_TRUSTED: return ALERT_UNKNOWN_CA;
    case BR_ERR_X509_EXPIRED: return ALERT_CERT_EXPIRED;
    case BR_ERR_X509_UNSUPPORTED: return ALERT_UNSUPPORTED_CERT;
    default: return ALERT_BAD_CERTIFICATE;
    }
}

static LONG cert_failed(struct OTConnection *c, int err)
{
    queue_alert(c, 2, cert_alert(err));
    tx_flush(c);
    return ot_engine_error(c, err);
}

/* ---- the handshake messages ---- */

static LONG derive_handshake_keys(struct OTConnection *c, const unsigned char *shared, size_t slen)
{
    struct ot13 *t = c->t13;
    const br_hash_class *h = t->hash;
    unsigned char early[OT13_HASH_MAX], derived[OT13_HASH_MAX], th[OT13_HASH_MAX];
    ot13_extract(h, NULL, t->psk_used ? t->offer->psk : NULL, t->suite->hash_len, early);
    ot13_derive(h, early, "derived", NULL, derived);
    ot13_extract(h, derived, shared, slen, t->hs_secret);
    th_out(t, h, th);
    ot13_derive(h, t->hs_secret, "c hs traffic", th, t->c_hs);
    ot13_derive(h, t->hs_secret, "s hs traffic", th, t->s_hs);
    memset(early, 0, sizeof early);
    memset(derived, 0, sizeof derived);
    if (ot13_keys_set(&t->rd, t->suite, &c->impls, t->s_hs) || ot13_keys_set(&t->wr, t->suite, &c->impls, t->c_hs))
        return abort13(c, ALERT_INTERNAL_ERROR, OTERR_INTERNAL, "The AES table does not fit.");
    t->rd_on = t->wr_on = 1;
    return OTERR_OK;
}

static int offered_suite(unsigned id)
{
    size_t i;
    for (i = 0; i < sizeof suites13 / sizeof suites13[0]; ++i)
        if (suites13[i] == id) return 1;
    return 0;
}

/* ServerHello or HelloRetryRequest. msg is the whole message (header
 * included); rest and rest_len what follows it in the record. */
static LONG server_hello(struct OTConnection *c, const unsigned char *msg, size_t mlen,
                         const unsigned char *rest, size_t rest_len)
{
    struct ot13 *t = c->t13;
    struct rd r, ex;
    const unsigned char *random, *share = NULL;
    unsigned version = 0, suite, group = 0, sel_psk = 0xFFFF;
    size_t sid_len, share_len = 0, i;
    int hrr, have_versions = 0, have_share = 0, have_psk = 0;
    const unsigned char *cookie = NULL;
    size_t cookie_len = 0;
    unsigned char shared[66];
    size_t slen;
    LONG rc;

    r.p = msg + 4; r.n = mlen - 4; r.bad = 0;
    rd16(&r);                                  /* legacy_version */
    random = r.p;
    rdsub(&r, 32);
    sid_len = rd8(&r);
    {
        struct rd sid = rdsub(&r, sid_len);
        if (!r.bad && (sid_len != t->sid_len || memcmp(sid.p, t->sid, sid_len))) {
            /* a TLS 1.2 server answers with its own session ID */
            sid_len = (size_t)-1;
        }
    }
    suite = rd16(&r);
    if (rd8(&r) != 0) r.bad = 1;               /* compression */
    hrr = !r.bad && !memcmp(random, hrr_random, 32);
    if (!r.bad && r.n) {
        ex = rdsub(&r, rd16(&r));
        while (ex.n && !ex.bad) {
            unsigned type = rd16(&ex);
            struct rd d = rdsub(&ex, rd16(&ex));
            switch (type) {
            case EXT_VERSIONS:
                version = rd16(&d);
                have_versions = 1;
                break;
            case EXT_KEY_SHARE:
                group = rd16(&d);
                if (!hrr) {
                    share_len = rd16(&d);
                    share = d.p;
                    rdsub(&d, share_len);
                }
                have_share = 1;
                break;
            case EXT_PSK:
                if (hrr) { r.bad = 2; break; }
                sel_psk = rd16(&d);
                have_psk = 1;
                break;
            case EXT_COOKIE:
                if (!hrr) { r.bad = 2; break; }
                cookie_len = rd16(&d);
                cookie = d.p;
                rdsub(&d, cookie_len);
                if (!cookie_len) d.bad = 1;
                break;
            default:
                /* a TLS 1.2 ServerHello may carry its own; BearSSL judges those */
                if (have_versions || hrr) r.bad = 2;
                d.n = 0;
                break;
            }
            if (d.bad || d.n) ex.bad = 1;
        }
        if (ex.bad) r.bad = 1;
    }
    if (r.bad == 1) return abort13(c, ALERT_DECODE_ERROR, OTERR_PROTOCOL, "a malformed ServerHello");

    if (!have_versions) {
        /* TLS 1.2 or older */
        if (hrr || t->hrr)
            return abort13(c, ALERT_ILLEGAL_PARAMETER, OTERR_PROTOCOL, "TLS 1.2 after a HelloRetryRequest");
        if (!t->offer12)
            return abort13(c, ALERT_PROTOCOL_VERSION, OTERR_VERSION,
                           "The server does not speak TLS 1.3, and the connection allows nothing older.");
        /* RFC 8446 section 4.1.3: a TLS 1.3 server that is made to answer
         * with 1.2 or less says so in the last 8 bytes of its random */
        if (!memcmp(random + 24, "DOWNGRD", 7) && (random[31] == 0 || random[31] == 1))
            return abort13(c, ALERT_ILLEGAL_PARAMETER, OTERR_VERSION,
                           "The connection was pushed down from TLS 1.3 (an attack, or a broken middlebox).");
        t->st = T13_BRIDGE;
        return ot13_bridge_start(c, msg, mlen, rest, rest_len);
    }
    if (r.bad == 2) return abort13(c, ALERT_UNSUPPORTED_EXT, OTERR_PROTOCOL, "an extension it was not offered");
    if (version != OT_TLS13)
        return abort13(c, ALERT_ILLEGAL_PARAMETER, OTERR_PROTOCOL, "a version it was not offered");
    if (sid_len == (size_t)-1)
        return abort13(c, ALERT_ILLEGAL_PARAMETER, OTERR_PROTOCOL, "a session ID that is not ours");
    if (!offered_suite(suite) || (t->hrr && suite != t->hrr_suite))
        return abort13(c, ALERT_ILLEGAL_PARAMETER, OTERR_CIPHER,
                       "The server chose a cipher suite OpenTLS did not offer.");
    if (rest_len)
        return abort13(c, ALERT_UNEXPECTED_MESSAGE, OTERR_PROTOCOL, "a message after the ServerHello");

    if (hrr) {
        unsigned char ch1[OT13_HASH_MAX + 4];
        const struct ot13_suite *s = ot13_suite(suite);
        if (t->hrr) return abort13(c, ALERT_UNEXPECTED_MESSAGE, OTERR_PROTOCOL, "a second HelloRetryRequest");
        if (have_share && ((group != GROUP_X25519 && group != GROUP_P256) || group == t->group))
            return abort13(c, ALERT_ILLEGAL_PARAMETER, OTERR_CIPHER,
                           "The server asked for a key exchange group OpenTLS did not offer.");
        if (!have_share && !cookie)
            return abort13(c, ALERT_ILLEGAL_PARAMETER, OTERR_PROTOCOL, "a HelloRetryRequest that changes nothing");
        t->hrr = 1;
        t->hrr_suite = (uint16_t)suite;
        t->suite = s;
        t->hash = s->hash;
        /* the transcript starts again from message_hash(ClientHello1) */
        ch1[0] = HS_MESSAGE_HASH;
        put24(ch1 + 1, s->hash_len);
        th_out(t, t->hash, ch1 + 4);
        if (t->hash == &br_sha384_vtable) br_sha384_init(&t->th384);
        else br_sha256_init(&t->th256);
        th_update(t, ch1, 4 + s->hash_len);
        th_update(t, msg, mlen);
        if (have_share) t->group = group;
        if (cookie) {
            ot_free(t->cookie);
            t->cookie = ot_alloc(cookie_len);
            if (!t->cookie) return abort13(c, ALERT_INTERNAL_ERROR, OTERR_NOMEM, "Out of memory.");
            memcpy(t->cookie, cookie, cookie_len);
            t->cookie_len = cookie_len;
        }
        queue_ccs(t);
        {
            size_t at = t->tx_len;
            unsigned char *save = t->tx;
            t->tx += at;                       /* the ClientHello after the CCS */
            t->tx_cap -= at;
            rc = build_client_hello(c);
            t->tx = save;
            t->tx_cap += at;
            if (rc < 0) return abort13(c, ALERT_INTERNAL_ERROR, rc, "The second ClientHello could not be made.");
            t->tx_len = at + (size_t)rc;
        }
        return OTERR_OK;
    }

    if (!have_share || group != t->group)
        return abort13(c, have_share ? ALERT_ILLEGAL_PARAMETER : ALERT_MISSING_EXTENSION, OTERR_PROTOCOL,
                       "no key share, or one for a group it was not sent");
    if (have_psk) {
        const struct ot13_suite *ps = t->offer ? ot13_suite(t->offer->suite) : NULL;
        if (!ps || sel_psk != 0 || ps->hash != ot13_suite(suite)->hash)
            return abort13(c, ALERT_ILLEGAL_PARAMETER, OTERR_PROTOCOL, "a ticket it was not offered");
        t->psk_used = 1;
    }
    t->suite = ot13_suite(suite);
    t->hash = t->suite->hash;
    th_update(t, msg, mlen);
    slen = ecdhe(c, group, share, share_len, shared);
    for (i = 0; i < sizeof t->x25519; ++i) t->x25519[i] = t->p256[i] = 0;
    if (!slen) return abort13(c, ALERT_ILLEGAL_PARAMETER, OTERR_PROTOCOL, "a bad key share");
    rc = derive_handshake_keys(c, shared, slen);
    memset(shared, 0, sizeof shared);
    if (rc != OTERR_OK) return rc;
    /* BearSSL is done with: its buffer is ours */
    if (t->tx_len == 0 && c->iobuf_len >= OT13_RX_MAX + 5 + OT13_RECORD_MAX + 17 + OT13_TX_SPARE) {
        t->tx = c->iobuf + OT13_RX_MAX;
        t->tx_cap = c->iobuf_len - OT13_RX_MAX;
    }
    t->st = T13_WAIT_EE;
    return OTERR_OK;
}

static int offered_alpn(struct OTConnection *c, const unsigned char *p, size_t n)
{
    int k;
    for (k = 0; k < c->alpn_count; ++k)
        if (strlen(c->alpn_names[k]) == n && !memcmp(c->alpn_names[k], p, n)) return 1;
    return 0;
}

static LONG encrypted_extensions(struct OTConnection *c, struct rd *r)
{
    struct ot13 *t = c->t13;
    struct rd ex = rdsub(r, rd16(r));
    unsigned seen = 0;
    while (ex.n && !ex.bad) {
        unsigned type = rd16(&ex);
        struct rd d = rdsub(&ex, rd16(&ex));
        unsigned bit = type == EXT_ALPN ? 1 : type == EXT_SERVER_NAME ? 2 : type == EXT_GROUPS ? 4 : 0;
        if (!bit) return abort13(c, ALERT_UNSUPPORTED_EXT, OTERR_PROTOCOL, "an extension it was not offered");
        if (seen & bit) return abort13(c, ALERT_ILLEGAL_PARAMETER, OTERR_PROTOCOL, "an extension twice");
        seen |= bit;
        if (type == EXT_ALPN) {
            struct rd l = rdsub(&d, rd16(&d));
            size_t n = rd8(&l);
            const unsigned char *name = l.p;
            rdsub(&l, n);
            if (l.bad || l.n || !n || !c->alpn_count) d.bad = 1;
            else if (!offered_alpn(c, name, n))
                return abort13(c, ALERT_ILLEGAL_PARAMETER, OTERR_PROTOCOL, "an application protocol it was not offered");
            else {
                memcpy(c->alpn_selected, name, n < sizeof c->alpn_selected ? n : sizeof c->alpn_selected - 1);
                c->alpn_selected[n < sizeof c->alpn_selected ? n : sizeof c->alpn_selected - 1] = 0;
            }
        } else if (type == EXT_SERVER_NAME) {
            if (d.n || c->ip_len) d.bad = 1;
        } else {
            d.n = 0;            /* the server's preference among the groups: noted, not used */
        }
        if (d.bad || d.n) ex.bad = 1;
    }
    if (ex.bad || r->n) return abort13(c, ALERT_DECODE_ERROR, OTERR_PROTOCOL, "malformed EncryptedExtensions");
    t->st = t->psk_used ? T13_WAIT_FIN : T13_WAIT_CERT_CR;
    return OTERR_OK;
}

static LONG certificate_request(struct OTConnection *c, struct rd *r)
{
    struct ot13 *t = c->t13;
    size_t n = rd8(r);
    struct rd ctx = rdsub(r, n);
    rdsub(r, rd16(r));                         /* extensions: we answer with no certificate */
    if (r->bad || r->n) return abort13(c, ALERT_DECODE_ERROR, OTERR_PROTOCOL, "a malformed CertificateRequest");
    memcpy(t->cr_ctx, ctx.p, n);
    t->cr_ctx_len = n;
    t->cert_req = 1;
    t->st = T13_WAIT_CERT;
    return OTERR_OK;
}

static LONG certificate(struct OTConnection *c, struct rd *r)
{
    struct ot13 *t = c->t13;
    const br_x509_class **xc = &c->x509.vtable;
    struct rd list;
    unsigned err;
    int count = 0;
    if (rd8(r) != 0) return abort13(c, ALERT_ILLEGAL_PARAMETER, OTERR_PROTOCOL, "a certificate context");
    list = rdsub(r, rd24(r));
    if (r->bad || r->n) return abort13(c, ALERT_DECODE_ERROR, OTERR_PROTOCOL, "a malformed Certificate");
    c->x509.tls13 = 1;
    (*xc)->start_chain(xc, c->host);
    while (list.n && !list.bad) {
        size_t len = rd24(&list);
        struct rd der = rdsub(&list, len);
        rdsub(&list, rd16(&list));             /* the entry's extensions (OCSP, SCT): not used */
        if (list.bad || !len) break;
        (*xc)->start_cert(xc, (uint32_t)len);
        (*xc)->append(xc, der.p, len);
        (*xc)->end_cert(xc);
        ++count;
    }
    if (list.bad || !count)
        return abort13(c, ALERT_DECODE_ERROR, OTERR_PROTOCOL, count ? "a malformed Certificate" : "no certificate");
    err = (*xc)->end_chain(xc);
    if (err) return cert_failed(c, (int)err);
    if (!c->x509.leaf_ed25519) {
        unsigned usages = 0;
        if (!(*xc)->get_pkey(xc, &usages)) return cert_failed(c, BR_ERR_X509_UNSUPPORTED);
        if (!(usages & BR_KEYTYPE_SIGN)) return cert_failed(c, BR_ERR_WRONG_KEY_USAGE);
    }
    t->have_cert = 1;
    t->st = T13_WAIT_CV;
    return OTERR_OK;
}

static LONG certificate_verify(struct OTConnection *c, struct rd *r, const unsigned char *thash)
{
    struct ot13 *t = c->t13;
    const br_x509_class **xc = &c->x509.vtable;
    unsigned scheme = rd16(r);
    size_t n = rd16(r), i;
    const unsigned char *sig = r->p;
    int err, offered = 0;
    rdsub(r, n);
    if (r->bad || r->n) return abort13(c, ALERT_DECODE_ERROR, OTERR_PROTOCOL, "a malformed CertificateVerify");
    for (i = 0; i < 7; ++i)                    /* the first seven: TLS 1.3's own */
        if (sigalgs[i] == scheme && (scheme != 0x0807 || t->sigalgs_ed25519)) offered = 1;
    if (!offered)
        return abort13(c, ALERT_ILLEGAL_PARAMETER, OTERR_CIPHER,
                       "The server signed with a scheme OpenTLS did not offer.");
    err = ot13_verify_cv(&c->impls, scheme,
                         c->x509.leaf_ed25519 ? NULL : (*xc)->get_pkey(xc, NULL),
                         c->x509.leaf_ed25519 ? c->x509.ed25519 : NULL,
                         thash, t->suite->hash_len, sig, n);
    if (err == BR_ERR_INVALID_ALGORITHM)
        return abort13(c, ALERT_ILLEGAL_PARAMETER, OTERR_CIPHER,
                       "The server's signature scheme does not suit its key.");
    if (err) {
        queue_alert(c, 2, ALERT_DECRYPT_ERROR);
        tx_flush(c);
        return ot_engine_error(c, BR_ERR_BAD_SIGNATURE);
    }
    t->st = T13_WAIT_FIN;
    return OTERR_OK;
}

/* the client's second flight: [Certificate], Finished; then the
 * application keys */
static LONG client_finished(struct OTConnection *c)
{
    struct ot13 *t = c->t13;
    const br_hash_class *h = t->hash;
    size_t hl = t->suite->hash_len;
    unsigned char th[OT13_HASH_MAX], *rec;
    queue_ccs(t);
    if (t->cert_req) {                         /* no certificate of ours */
        rec = tx_room(t, 4 + 1 + t->cr_ctx_len + 3);
        if (!rec) return abort13(c, ALERT_INTERNAL_ERROR, OTERR_INTERNAL, "No room for the Certificate.");
        rec[5] = HS_CERTIFICATE;
        put24(rec + 6, 1 + t->cr_ctx_len + 3);
        rec[9] = (unsigned char)t->cr_ctx_len;
        memcpy(rec + 10, t->cr_ctx, t->cr_ctx_len);
        put24(rec + 10 + t->cr_ctx_len, 0);
        th_update(t, rec + 5, 4 + 1 + t->cr_ctx_len + 3);
        tx_record(t, rec, BR_SSL_HANDSHAKE, 4 + 1 + t->cr_ctx_len + 3);
    }
    rec = tx_room(t, 4 + hl);
    if (!rec) return abort13(c, ALERT_INTERNAL_ERROR, OTERR_INTERNAL, "No room for Finished.");
    th_out(t, h, th);
    rec[5] = HS_FINISHED;
    put24(rec + 6, hl);
    ot13_finished(h, t->c_hs, th, rec + 9);
    th_update(t, rec + 5, 4 + hl);
    tx_record(t, rec, BR_SSL_HANDSHAKE, 4 + hl);
    th_out(t, h, th);
    ot13_derive(h, t->master, "res master", th, t->res_master);
    if (ot13_keys_set(&t->wr, t->suite, &c->impls, t->c_ap))
        return abort13(c, ALERT_INTERNAL_ERROR, OTERR_INTERNAL, "The AES table does not fit.");
    memset(t->hs_secret, 0, sizeof t->hs_secret);
    memset(t->c_hs, 0, sizeof t->c_hs);
    memset(t->s_hs, 0, sizeof t->s_hs);
    memset(t->master, 0, sizeof t->master);
    t->st = T13_OPEN;
    return OTERR_OK;
}

static LONG server_finished(struct OTConnection *c, struct rd *r, const unsigned char *thash)
{
    struct ot13 *t = c->t13;
    const br_hash_class *h = t->hash;
    size_t hl = t->suite->hash_len;
    unsigned char want[OT13_HASH_MAX];
    if (r->n != hl) return abort13(c, ALERT_DECODE_ERROR, OTERR_PROTOCOL, "a malformed Finished");
    ot13_finished(h, t->s_hs, thash, want);
    if (!ct_equal(want, r->p, hl)) {
        queue_alert(c, 2, ALERT_DECRYPT_ERROR);
        tx_flush(c);
        return ot_fail(c, OTERR_PROTOCOL, BR_ERR_BAD_FINISHED,
                       "The server's Finished message does not verify.", NULL, NULL);
    }
    return OTERR_OK;
}

/* after the server's Finished is in the transcript */
static LONG application_keys(struct OTConnection *c)
{
    struct ot13 *t = c->t13;
    const br_hash_class *h = t->hash;
    unsigned char derived[OT13_HASH_MAX], th[OT13_HASH_MAX];
    ot13_derive(h, t->hs_secret, "derived", NULL, derived);
    ot13_extract(h, derived, NULL, 0, t->master);
    th_out(t, h, th);
    ot13_derive(h, t->master, "c ap traffic", th, t->c_ap);
    ot13_derive(h, t->master, "s ap traffic", th, t->s_ap);
    memset(derived, 0, sizeof derived);
    if (ot13_keys_set(&t->rd, t->suite, &c->impls, t->s_ap))
        return abort13(c, ALERT_INTERNAL_ERROR, OTERR_INTERNAL, "The AES table does not fit.");
    return client_finished(c);
}

/* fills the sessions that wait for a ticket (OT_GetSession before one came) */
static void tickets_out(struct OTConnection *c);

static LONG new_session_ticket(struct OTConnection *c, struct rd *r)
{
    struct ot13 *t = c->t13;
    uint32_t lifetime, age_add, days = 0, secs = 0;
    size_t nlen, tlen;
    const unsigned char *nonce, *ticket;
    struct ot13_ticket *k;
    if (r->n < 8) return abort13(c, ALERT_DECODE_ERROR, OTERR_PROTOCOL, "a malformed NewSessionTicket");
    lifetime = get32(r->p);
    age_add = get32(r->p + 4);
    rdsub(r, 8);
    nlen = rd8(r);
    nonce = r->p;
    rdsub(r, nlen);
    tlen = rd16(r);
    ticket = r->p;
    rdsub(r, tlen);
    rdsub(r, rd16(r));                         /* extensions: early_data, not used */
    if (r->bad || r->n || !tlen || lifetime > 7 * 86400UL)
        return abort13(c, ALERT_DECODE_ERROR, OTERR_PROTOCOL, "a malformed NewSessionTicket");
    if (!lifetime || tlen > OT13_TICKET_MAX) return OTERR_OK;     /* not kept */
    k = ot_alloc(sizeof *k + tlen);
    if (!k) return OTERR_OK;
    k->suite = t->suite->id;
    ot13_expand_label(t->hash, t->res_master, "resumption", nonce, nlen, k->psk, t->suite->hash_len);
    k->age_add = age_add;
    k->lifetime = lifetime;
    if (ot_now(&days, &secs)) { k->days = days; k->seconds = secs; }
    k->len = tlen;
    memcpy(k->data, ticket, tlen);
    if (t->ticket) {
        memset(t->ticket, 0, sizeof *t->ticket);
        ot_free(t->ticket);
    }
    t->ticket = k;
    tickets_out(c);
    return OTERR_OK;
}

static LONG key_update(struct OTConnection *c, struct rd *r, int last)
{
    struct ot13 *t = c->t13;
    unsigned req = rd8(r);
    if (r->bad || r->n || req > 1) return abort13(c, ALERT_DECODE_ERROR, OTERR_PROTOCOL, "a malformed KeyUpdate");
    if (!last) return abort13(c, ALERT_UNEXPECTED_MESSAGE, OTERR_PROTOCOL, "data after a KeyUpdate");
    if (ot13_keys_next(&t->rd))
        return abort13(c, ALERT_INTERNAL_ERROR, OTERR_INTERNAL, "The AES table does not fit.");
    if (req && !t->close_sent) {
        /* answer with ours, under the old key, then move on */
        unsigned char *rec = tx_room(t, 5);
        if (!rec) return abort13(c, ALERT_INTERNAL_ERROR, OTERR_INTERNAL, "No room for KeyUpdate.");
        rec[5] = HS_KEY_UPDATE;
        put24(rec + 6, 1);
        rec[9] = 0;
        tx_record(t, rec, BR_SSL_HANDSHAKE, 5);
        if (ot13_keys_next(&t->wr))
            return abort13(c, ALERT_INTERNAL_ERROR, OTERR_INTERNAL, "The AES table does not fit.");
        t->updates_sent++;
    }
    t->updates_received++;
    return OTERR_OK;
}

/* one whole handshake message; last says it ends its record */
static LONG handshake_message(struct OTConnection *c, const unsigned char *msg, size_t len, int last)
{
    struct ot13 *t = c->t13;
    struct rd r;
    unsigned type = msg[0];
    unsigned char th[OT13_HASH_MAX];
    LONG rc;
    r.p = msg + 4; r.n = len - 4; r.bad = 0;
    if (t->st == T13_OPEN) {
        if (type == HS_NEW_SESSION_TICKET) return new_session_ticket(c, &r);
        if (type == HS_KEY_UPDATE) return key_update(c, &r, last);
        return abort13(c, ALERT_UNEXPECTED_MESSAGE, OTERR_PROTOCOL, "an unexpected message after the handshake");
    }
    /* the transcript before this message, for CertificateVerify and Finished */
    if (type == HS_CERT_VERIFY || type == HS_FINISHED) th_out(t, t->hash, th);
    switch (t->st) {
    case T13_WAIT_EE:
        if (type != HS_ENCRYPTED_EXT) goto unexpected;
        th_update(t, msg, len);
        return encrypted_extensions(c, &r);
    case T13_WAIT_CERT_CR:
        if (type == HS_CERT_REQUEST) {
            th_update(t, msg, len);
            return certificate_request(c, &r);
        }
        /* fall through */
    case T13_WAIT_CERT:
        if (type != HS_CERTIFICATE) goto unexpected;
        th_update(t, msg, len);
        return certificate(c, &r);
    case T13_WAIT_CV:
        if (type != HS_CERT_VERIFY) goto unexpected;
        if ((rc = certificate_verify(c, &r, th)) != OTERR_OK) return rc;
        th_update(t, msg, len);
        return OTERR_OK;
    case T13_WAIT_FIN:
        if (type != HS_FINISHED) goto unexpected;
        if (!last) return abort13(c, ALERT_UNEXPECTED_MESSAGE, OTERR_PROTOCOL, "data after Finished");
        if ((rc = server_finished(c, &r, th)) != OTERR_OK) return rc;
        th_update(t, msg, len);
        return application_keys(c);
    default:
        break;
    }
unexpected:
    return abort13(c, ALERT_UNEXPECTED_MESSAGE, OTERR_PROTOCOL, "a message out of order");
}

/* the handshake bytes of the current record, message by message; those of
 * a message that goes on in the next record wait in t->hs */
static LONG handshake_bytes(struct OTConnection *c)
{
    struct ot13 *t = c->t13;
    while (t->pt_len) {
        const unsigned char *p = t->pt;
        size_t avail = t->pt_len, need, take;
        LONG rc;
        if (!t->hs_len && avail >= 4 && avail >= 4 + get24(p + 1)) {
            /* a whole message in the record: handled where it is */
            need = 4 + get24(p + 1);
            t->pt += need;
            t->pt_len -= need;
            if (t->st == T13_WAIT_SH) {
                if (p[0] != HS_SERVER_HELLO)
                    return abort13(c, ALERT_UNEXPECTED_MESSAGE, OTERR_PROTOCOL, "no ServerHello");
                rc = server_hello(c, p, need, t->pt, t->pt_len);
                t->pt_len = 0;
            } else {
                rc = handshake_message(c, p, need, t->pt_len == 0);
            }
            if (rc != OTERR_OK) return rc;
            continue;
        }
        /* part of a message: collect it */
        need = t->hs_len < 4 ? 4 : 4 + get24(t->hs + 1);
        if (t->hs_len >= 4 && need > OT13_HS_MAX)
            return abort13(c, ALERT_RECORD_OVERFLOW, OTERR_PROTOCOL, "a handshake message too long");
        if (need > t->hs_cap) {
            size_t cap = need < 4096 ? 4096 : need;
            unsigned char *n = ot_alloc(cap);
            if (!n) return abort13(c, ALERT_INTERNAL_ERROR, OTERR_NOMEM, "Out of memory.");
            if (t->hs_len) memcpy(n, t->hs, t->hs_len);
            ot_free(t->hs);
            t->hs = n;
            t->hs_cap = cap;
        }
        take = need - t->hs_len < avail ? need - t->hs_len : avail;
        memcpy(t->hs + t->hs_len, p, take);
        t->hs_len += take;
        t->pt += take;
        t->pt_len -= take;
        if (t->hs_len >= 4 && t->hs_len == 4 + get24(t->hs + 1)) {
            t->hs_len = 0;
            if (t->st == T13_WAIT_SH) {
                if (t->hs[0] != HS_SERVER_HELLO)
                    return abort13(c, ALERT_UNEXPECTED_MESSAGE, OTERR_PROTOCOL, "no ServerHello");
                rc = server_hello(c, t->hs, need, t->pt, t->pt_len);
                t->pt_len = 0;
            } else {
                rc = handshake_message(c, t->hs, need, t->pt_len == 0);
            }
            if (rc != OTERR_OK) return rc;
        }
    }
    return OTERR_OK;
}

/* reads and handles one record */
static LONG one_record(struct OTConnection *c)
{
    struct ot13 *t = c->t13;
    LONG rc = read_record(c);
    if (rc != OTERR_OK) return rc;
    if ((rc = open_record(c)) != OTERR_OK) return rc;
    switch (t->pt_type) {
    case BR_SSL_CHANGE_CIPHER_SPEC:
        return OTERR_OK;
    case BR_SSL_ALERT:
        return handle_alert(c, t->pt, t->pt_len);
    case BR_SSL_HANDSHAKE:
        if (!t->pt_len) return abort13(c, ALERT_UNEXPECTED_MESSAGE, OTERR_PROTOCOL, "an empty record");
        return handshake_bytes(c);
    default:                                   /* application data */
        t->app = t->pt;
        t->app_len = t->pt_len;
        return OTERR_OK;
    }
}

/* ---- the calls ---- */

LONG ot13_handshake(struct OTConnection *c)
{
    struct ot13 *t = c->t13;
    LONG rc;
    for (;;) {
        if (t->tx_sent < t->tx_len && (rc = tx_flush(c)) != OTERR_OK) return rc;
        if (t->st == T13_OPEN || t->st == T13_BRIDGE) return OTERR_OK;
        rc = one_record(c);
        if (rc == OTERR_CLOSED && c->clean_close)
            return ot_fail(c, OTERR_CLOSED, 0, "The server closed the connection during the handshake.", NULL, NULL);
        if (rc != OTERR_OK) return rc;
        if (t->app_len) return abort13(c, ALERT_UNEXPECTED_MESSAGE, OTERR_PROTOCOL, "early application data");
    }
}

LONG ot13_read(struct OTConnection *c, unsigned char *buf, LONG len)
{
    struct ot13 *t = c->t13;
    LONG rc;
    for (;;) {
        if (t->app_len) {
            size_t n = (size_t)len < t->app_len ? (size_t)len : t->app_len;
            memcpy(buf, t->app, n);
            t->app += n;
            t->app_len -= n;
            return (LONG)n;
        }
        if (c->state == OTS_CLOSED) return c->clean_close ? 0 : OTERR_STATE;
        /* a KeyUpdate's answer waiting: send it if the socket takes it now */
        if (t->tx_sent < t->tx_len) {
            rc = tx_flush(c);
            if (rc == OTERR_WOULDBLOCK) { c->state = OTS_OPEN; c->error = OTERR_OK; }
            else if (rc != OTERR_OK) return rc;
        }
        rc = one_record(c);
        if (rc == OTERR_CLOSED && c->clean_close) return 0;
        if (rc != OTERR_OK) return rc;
    }
}

LONG ot13_write(struct OTConnection *c, const unsigned char *buf, LONG len)
{
    struct ot13 *t = c->t13;
    LONG total = 0, rc;
    if (t->tx_sent < t->tx_len) {
        rc = tx_flush(c);
        if (rc == OTERR_WOULDBLOCK) { c->state = OTS_OPEN; return rc; }
        if (rc != OTERR_OK) return rc;
    }
    if (t->close_sent) return ot_fail(c, OTERR_STATE, 0, "The connection is closing.", NULL, NULL);
    while (total < len) {
        size_t n = (size_t)(len - total), room;
        unsigned char *rec;
        /* new keys long before AES-GCM's limit (RFC 8446 section 5.5) */
        if (t->wr.seq >= t->update_after) {
            rec = tx_room(t, 5);
            if (rec) {
                rec[5] = HS_KEY_UPDATE;
                put24(rec + 6, 1);
                rec[9] = 0;
                tx_record(t, rec, BR_SSL_HANDSHAKE, 5);
                if (ot13_keys_next(&t->wr))
                    return abort13(c, ALERT_INTERNAL_ERROR, OTERR_INTERNAL, "The AES table does not fit.");
                t->updates_sent++;
            }
        }
        room = t->tx_cap - t->tx_len;
        room = room > 5 + 17 + OT13_TX_SPARE ? room - 5 - 17 - OT13_TX_SPARE : 0;
        if (room > OT13_RECORD_MAX) room = OT13_RECORD_MAX;
        if (n > room) n = room;
        if (n) {
            rec = t->tx + t->tx_len;
            memcpy(rec + 5, buf + total, n);
            tx_record(t, rec, BR_SSL_APPLICATION_DATA, n);
            total += (LONG)n;
        }
        rc = tx_flush(c);
        if (rc == OTERR_WOULDBLOCK) { c->state = OTS_OPEN; c->error = OTERR_OK; return total ? total : rc; }
        if (rc != OTERR_OK) return rc;
    }
    return total;
}

LONG ot13_pending(struct OTConnection *c)
{
    return c->t13 ? (LONG)c->t13->app_len : 0;
}

LONG ot13_close(struct OTConnection *c)
{
    struct ot13 *t = c->t13;
    LONG rc;
    if (!t->close_sent) queue_alert(c, 1, ALERT_CLOSE_NOTIFY);
    rc = tx_flush(c);
    if (rc == OTERR_WOULDBLOCK) { c->state = OTS_OPEN; return rc; }
    return rc;
}

/* ---- tickets and sessions ---- */

struct ot13_ticket *ot13_ticket_copy(const struct ot13_ticket *k)
{
    struct ot13_ticket *n;
    if (!k) return NULL;
    n = ot_alloc(sizeof *n + k->len);
    if (n) memcpy(n, k, sizeof *n + k->len);
    return n;
}

static void tickets_out(struct OTConnection *c)
{
    struct ot13 *t = c->t13;
    struct OTSession *s;
    ot_session_lock();
    for (s = t->waiting; s; s = s->next_waiting) {
        struct ot13_ticket *n = ot13_ticket_copy(t->ticket);
        if (!n) continue;
        if (s->t13) { memset(s->t13, 0, sizeof *s->t13); ot_free(s->t13); }
        s->t13 = n;
    }
    ot_session_unlock();
}

void ot13_session_wait(struct OTConnection *c, struct OTSession *s)
{
    struct ot13 *t = c->t13;
    ot_session_lock();
    s->source = c;
    s->next_waiting = t->waiting;
    t->waiting = s;
    ot_session_unlock();
}

void ot13_session_unwait(struct OTSession *s)
{
    struct OTSession **pp;
    ot_session_lock();
    if (s->source && s->source->t13) {
        for (pp = &s->source->t13->waiting; *pp; pp = &(*pp)->next_waiting)
            if (*pp == s) { *pp = s->next_waiting; break; }
    }
    s->source = NULL;
    s->next_waiting = NULL;
    ot_session_unlock();
}

void ot13_free(struct OTConnection *c)
{
    struct ot13 *t = c->t13;
    struct OTSession *s, *n;
    if (!t) return;
    ot_session_lock();
    for (s = t->waiting; s; s = n) {          /* they keep what they have */
        n = s->next_waiting;
        s->source = NULL;
        s->next_waiting = NULL;
    }
    t->waiting = NULL;
    ot_session_unlock();
    ot13_bridge_free(c);
    if (t->ticket) { memset(t->ticket, 0, sizeof *t->ticket); ot_free(t->ticket); }
    if (t->hs) { memset(t->hs, 0, t->hs_cap); ot_free(t->hs); }
    ot_free(t->cookie);
    memset(t, 0, sizeof *t);
    ot_free(t);
    c->t13 = NULL;
}
