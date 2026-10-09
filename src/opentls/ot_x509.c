/* OpenTLS: certificate checks. BearSSL's "minimal" X.509 engine does the
 * chain, the dates and DNS names; this wrapper around it adds what OpenTLS
 * promises on top: the server's certificate and its SHA-256 fingerprint
 * kept for the caller, pinned certificates, the verify modes, and
 * certificates for IP addresses (which the minimal engine does not match).
 * MIT licensed and free. Copyright (c) 2026 Dalsin Limited. */
#include "ot_internal.h"

/* ---- a small DER reader, for the subjectAltName and CN ---- */

struct der { const unsigned char *p; size_t len; };

/* the next element of d: its tag and contents; 0 at the end or on an error */
static int der_next(struct der *d, unsigned *tag, struct der *content)
{
    size_t i = 2, l, n;
    if (d->len < 2) return 0;
    *tag = d->p[0];
    l = d->p[1];
    if (l & 0x80) {
        n = l & 0x7F;
        if (n == 0 || n > 3 || d->len < 2 + n) return 0;
        for (l = 0; n; --n) l = (l << 8) | d->p[i++];
    }
    if (l > d->len - i) return 0;
    content->p = d->p + i;
    content->len = l;
    d->p += i + l;
    d->len -= i + l;
    return 1;
}

/* the contents of the TBSCertificate */
static int der_tbs(const unsigned char *der, size_t len, struct der *tbs)
{
    struct der d = { der, len }, cert;
    unsigned tag;
    if (!der_next(&d, &tag, &cert) || tag != 0x30) return 0;
    if (!der_next(&cert, &tag, tbs) || tag != 0x30) return 0;
    return 1;
}

static int der_san(const unsigned char *der, size_t len, struct der *names)
{
    static const unsigned char oid_san[] = { 0x55, 0x1D, 0x11 };
    struct der tbs, e, exts, seq, x;
    unsigned tag;
    if (!der_tbs(der, len, &tbs)) return 0;
    while (der_next(&tbs, &tag, &e)) {
        if (tag != 0xA3) continue;
        if (!der_next(&e, &tag, &exts) || tag != 0x30) return 0;
        while (der_next(&exts, &tag, &seq)) {
            if (tag != 0x30 || !der_next(&seq, &tag, &x) || tag != 0x06) continue;
            if (x.len != sizeof oid_san || memcmp(x.p, oid_san, sizeof oid_san)) continue;
            if (!der_next(&seq, &tag, &x)) return 0;
            if (tag == 0x01 && !der_next(&seq, &tag, &x)) return 0;
            if (tag != 0x04) return 0;
            if (!der_next(&x, &tag, names) || tag != 0x30) return 0;
            return 1;
        }
    }
    return 0;
}

int ot_cert_has_ip(const unsigned char *der, size_t len, const unsigned char *ip, size_t iplen)
{
    struct der names, n;
    unsigned tag;
    if (!der || !der_san(der, len, &names)) return 0;
    while (der_next(&names, &tag, &n))
        if (tag == 0x87 && n.len == iplen && !memcmp(n.p, ip, iplen)) return 1;
    return 0;
}

static void copy_name(const struct der *n, char *out, size_t outlen)
{
    size_t l = n->len < outlen - 1 ? n->len : outlen - 1, i;
    for (i = 0; i < l; ++i) {
        unsigned char ch = n->p[i];
        out[i] = (ch >= 32 && ch < 127) ? (char)ch : '?';
    }
    out[l] = 0;
}

void ot_cert_name(const unsigned char *der, size_t len, char *out, size_t outlen)
{
    static const unsigned char oid_cn[] = { 0x55, 0x04, 0x03 };
    struct der names, n, tbs, e, set, atv, x;
    unsigned tag;
    int field = 0;
    if (!outlen) return;
    out[0] = 0;
    if (!der) return;
    if (der_san(der, len, &names))
        while (der_next(&names, &tag, &n))
            if (tag == 0x82) { copy_name(&n, out, outlen); return; }
    /* the subject's CN: version [0] (optional), serial, algorithm,
     * issuer, validity, subject */
    if (!der_tbs(der, len, &tbs)) return;
    while (der_next(&tbs, &tag, &e)) {
        if (tag == 0xA0) continue;
        if (++field != 5) continue;
        while (der_next(&e, &tag, &set)) {
            while (der_next(&set, &tag, &atv)) {
                if (!der_next(&atv, &tag, &x) || tag != 0x06) continue;
                if (x.len != sizeof oid_cn || memcmp(x.p, oid_cn, sizeof oid_cn)) continue;
                if (der_next(&atv, &tag, &x)) { copy_name(&x, out, outlen); return; }
            }
        }
        return;
    }
}

/* ---- the wrapper engine ---- */

#define INNER(x) (&(x)->minimal.vtable)

static void xw_start_chain(const br_x509_class **ctx, const char *server_name)
{
    struct ot_x509 *x = (struct ot_x509 *)(void *)ctx;
    struct OTConnection *c = x->conn;
    (void)server_name;
    x->cert_index = -1;
    x->accepted = 0;
    x->leaf_ok = 0;
    x->leaf_len = 0;
    x->have_fingerprint = 0;
    c->peer_name_done = 0;
    /* the minimal engine checks DNS names only: none for an address, none
     * when the caller turned the check off */
    (*INNER(x))->start_chain(INNER(x),
        (c->verify == OTV_FULL && !c->ip_len) ? c->host : NULL);
}

static void xw_start_cert(const br_x509_class **ctx, uint32_t length)
{
    struct ot_x509 *x = (struct ot_x509 *)(void *)ctx;
    if (++x->cert_index == 0) {
        br_x509_decoder_init(&x->leaf_decoder, NULL, NULL);
        br_sha256_init(&x->leaf_hash);
        x->leaf_len = 0;
        x->leaf_ok = 1;
        if (length > x->leaf_cap) {
            ot_free(x->leaf);
            x->leaf = NULL;
            x->leaf_cap = 0;
            if (length <= OT_LEAF_MAX && (x->leaf = ot_alloc(length)))
                x->leaf_cap = length;
        }
        if (length > x->leaf_cap) x->leaf_ok = 0;
    }
    (*INNER(x))->start_cert(INNER(x), length);
}

static void xw_append(const br_x509_class **ctx, const unsigned char *buf, size_t len)
{
    struct ot_x509 *x = (struct ot_x509 *)(void *)ctx;
    if (x->cert_index == 0) {
        br_sha256_update(&x->leaf_hash, buf, len);
        br_x509_decoder_push(&x->leaf_decoder, buf, len);
        if (x->leaf_ok && x->leaf_len + len <= x->leaf_cap) {
            memcpy(x->leaf + x->leaf_len, buf, len);
            x->leaf_len += len;
        } else {
            x->leaf_ok = 0;
        }
    }
    (*INNER(x))->append(INNER(x), buf, len);
}

static void xw_end_cert(const br_x509_class **ctx)
{
    struct ot_x509 *x = (struct ot_x509 *)(void *)ctx;
    if (x->cert_index == 0) {
        br_sha256_out(&x->leaf_hash, x->fingerprint);
        x->have_fingerprint = 1;
    }
    (*INNER(x))->end_cert(INNER(x));
}

static unsigned xw_end_chain(const br_x509_class **ctx)
{
    struct ot_x509 *x = (struct ot_x509 *)(void *)ctx;
    struct OTConnection *c = x->conn;
    unsigned err = (*INNER(x))->end_chain(INNER(x));
    int leaf_key = x->have_fingerprint && br_x509_decoder_get_pkey(&x->leaf_decoder) != NULL;

    if (c->pinned && leaf_key && !memcmp(x->fingerprint, c->pin, 32)) {
        x->accepted = 1;     /* the caller trusts exactly this certificate */
        return 0;
    }
    if (c->verify == OTV_PINNED_ONLY) return OT_X509_PINNED;
    if (c->verify == OTV_NONE) {
        if (!leaf_key) return err ? err : BR_ERR_X509_INVALID_VALUE;
        x->accepted = 1;
        return 0;
    }
    if (err) return err;
    if (c->ip_len && c->verify == OTV_FULL
        && !(x->leaf_ok && ot_cert_has_ip(x->leaf, x->leaf_len, c->ip, (size_t)c->ip_len)))
        return OT_X509_IP;
    return 0;
}

static const br_x509_pkey *xw_get_pkey(const br_x509_class *const *ctx, unsigned *usages)
{
    struct ot_x509 *x = (struct ot_x509 *)(void *)ctx;
    if (x->accepted) {
        if (usages) *usages = BR_KEYTYPE_KEYX | BR_KEYTYPE_SIGN;
        return br_x509_decoder_get_pkey(&x->leaf_decoder);
    }
    return (*INNER(x))->get_pkey((const br_x509_class *const *)INNER(x), usages);
}

static const br_x509_class ot_x509_vtable = {
    sizeof(struct ot_x509),
    xw_start_chain, xw_start_cert, xw_append, xw_end_cert, xw_end_chain, xw_get_pkey
};

void ot_x509_init(struct ot_x509 *x, struct OTConnection *conn,
                  const struct ot_impls *m,
                  const br_x509_trust_anchor *ta, size_t ta_count)
{
    uint32_t days, seconds;
    x->vtable = &ot_x509_vtable;
    x->conn = conn;
    br_x509_minimal_init(&x->minimal, m->sha256, ta, ta_count);
    br_x509_minimal_set_hash(&x->minimal, br_sha1_ID, &br_sha1_vtable);
    br_x509_minimal_set_hash(&x->minimal, br_sha224_ID, &br_sha224_vtable);
    br_x509_minimal_set_hash(&x->minimal, br_sha256_ID, m->sha256);
    br_x509_minimal_set_hash(&x->minimal, br_sha384_ID, m->sha384);
    br_x509_minimal_set_hash(&x->minimal, br_sha512_ID, m->sha512);
    br_x509_minimal_set_rsa(&x->minimal, m->rsa_vrfy);
    br_x509_minimal_set_ecdsa(&x->minimal, m->ec, m->ecdsa_vrfy);
    if (ot_now(&days, &seconds)) br_x509_minimal_set_time(&x->minimal, days, seconds);
}

void ot_x509_free(struct ot_x509 *x)
{
    ot_free(x->leaf);
    x->leaf = NULL;
    x->leaf_cap = x->leaf_len = 0;
}
