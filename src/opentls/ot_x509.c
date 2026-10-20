/* OpenTLS: certificate checks. BearSSL's "minimal" X.509 engine does the
 * chain, the dates and DNS names; this wrapper around it adds what OpenTLS
 * promises on top: the server's certificate and its SHA-256 fingerprint
 * kept for the caller, pinned certificates, the verify modes, and
 * certificates for IP addresses (which the minimal engine does not match),
 * and for TLS 1.3 server certificates with Ed25519 keys (which it cannot
 * read at all; 20 October 2026).
 * MIT licensed and free. Copyright (c) 2026 AmigaChrome Team. */
#include "ot_internal.h"

#define INNER(x) (&(x)->minimal.vtable)

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

/* ---- an Ed25519 leaf (TLS 1.3) ----
 *
 * BearSSL's minimal engine knows RSA and EC keys only. When the server's
 * certificate has an Ed25519 key, the engine is given the chain from the
 * second certificate on (treated as its end entity, with no name check),
 * which takes that certificate to a trusted CA as usual; the leaf is
 * checked here: that the certificate after it is a CA, that its issuer
 * name is that CA's subject, its signature under the CA's key, its dates,
 * and the host name or address. A leaf issued straight by a trust anchor
 * is checked against the anchor. */

/* the next element whole (tag and length too): where it starts and ends */
static int der_whole(struct der *d, unsigned *tag, struct der *content, struct der *whole)
{
    const unsigned char *start = d->p;
    if (!der_next(d, tag, content)) return 0;
    whole->p = start;
    whole->len = (size_t)(d->p - start);
    return 1;
}

struct leaf_parts {
    struct der tbs;          /* whole, for the signature */
    struct der issuer;       /* whole */
    struct der validity;     /* contents */
    struct der subject;      /* whole */
    struct der spki;         /* contents */
    struct der exts;         /* contents of [3], or empty */
    struct der sigalg;       /* the outer algorithm's OID */
    struct der sig;          /* the BIT STRING's bytes, past the unused-bits count */
};

static int leaf_parse(const unsigned char *der, size_t len, struct leaf_parts *lp)
{
    struct der d = { der, len }, cert, tbs, e, w, alg, oid;
    unsigned tag;
    int field = 0;
    memset(lp, 0, sizeof *lp);
    if (!der_next(&d, &tag, &cert) || tag != 0x30) return 0;
    if (!der_whole(&cert, &tag, &tbs, &lp->tbs) || tag != 0x30) return 0;
    while (der_whole(&tbs, &tag, &e, &w)) {
        if (tag == 0xA0 && field == 0) continue;            /* version */
        switch (field++) {
        case 2: lp->issuer = w; break;
        case 3: lp->validity = e; break;
        case 4: lp->subject = w; break;
        case 5: lp->spki = e; break;
        default:
            if (tag == 0xA3) {
                struct der x;
                if (!der_next(&e, &tag, &x) || tag != 0x30) return 0;
                lp->exts = x;
            }
            break;
        }
    }
    if (field < 6) return 0;
    if (!der_next(&cert, &tag, &alg) || tag != 0x30) return 0;
    if (!der_next(&alg, &tag, &oid) || tag != 0x06) return 0;
    lp->sigalg = oid;
    if (!der_next(&cert, &tag, &lp->sig) || tag != 0x03 || lp->sig.len < 2 || lp->sig.p[0]) return 0;
    ++lp->sig.p;
    --lp->sig.len;
    return 1;
}

/* the key, when the SubjectPublicKeyInfo is Ed25519's (1.3.101.112) */
static int spki_ed25519(const struct der *spki, unsigned char *key)
{
    static const unsigned char oid[] = { 0x2B, 0x65, 0x70 };
    struct der s = *spki, alg, o, bits;
    unsigned tag;
    if (!der_next(&s, &tag, &alg) || tag != 0x30) return 0;
    if (!der_next(&alg, &tag, &o) || tag != 0x06 || o.len != 3 || memcmp(o.p, oid, 3)) return 0;
    if (!der_next(&s, &tag, &bits) || tag != 0x03 || bits.len != 33 || bits.p[0]) return 0;
    memcpy(key, bits.p + 1, 32);
    return 1;
}

/* an extension's value (inside its OCTET STRING), by the last byte of
 * its 2.5.29.x OID */
static int find_ext(const struct der *exts, unsigned char id, struct der *value)
{
    struct der all = *exts, ext, oid, v;
    unsigned tag;
    while (der_next(&all, &tag, &ext)) {
        if (tag != 0x30 || !der_next(&ext, &tag, &oid) || tag != 0x06) continue;
        if (oid.len != 3 || oid.p[0] != 0x55 || oid.p[1] != 0x1D || oid.p[2] != id) continue;
        if (!der_next(&ext, &tag, &v)) return 0;
        if (tag == 0x01 && !der_next(&ext, &tag, &v)) return 0;
        if (tag != 0x04) return 0;
        *value = v;
        return 1;
    }
    return 0;
}

/* a CA: basicConstraints with cA true, and keyCertSign if keyUsage is there */
static int is_ca(const unsigned char *der, size_t len)
{
    struct leaf_parts lp;
    struct der v, seq, b;
    unsigned tag;
    if (!leaf_parse(der, len, &lp) || !find_ext(&lp.exts, 19, &v)) return 0;
    if (!der_next(&v, &tag, &seq) || tag != 0x30) return 0;
    if (!der_next(&seq, &tag, &b) || tag != 0x01 || b.len != 1 || !b.p[0]) return 0;
    if (find_ext(&lp.exts, 15, &v)) {
        if (!der_next(&v, &tag, &b) || tag != 0x03 || b.len < 2 || !(b.p[1] & 0x04)) return 0;
    }
    return 1;
}

/* days since 1 January of year 0 (proleptic Gregorian), as ot_now() */
static uint32_t days_of(uint32_t y, uint32_t m, uint32_t d)
{
    static const uint16_t before[12] = { 0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334 };
    uint32_t leaps = y ? (y - 1) / 4 - (y - 1) / 100 + (y - 1) / 400 + 1 : 0;
    uint32_t n = 365 * y + leaps + before[m - 1] + d - 1;
    if (m > 2 && (y % 4 == 0 && (y % 100 != 0 || y % 400 == 0))) ++n;
    return n;
}

static int read_time(struct der *v, uint32_t *days, uint32_t *secs)
{
    struct der t;
    unsigned tag, i, n[7];
    const unsigned char *p;
    size_t digits;
    if (!der_next(v, &tag, &t)) return 0;
    digits = tag == 0x17 ? 12 : tag == 0x18 ? 14 : 0;
    if (!digits || t.len != digits + 1 || t.p[digits] != 'Z') return 0;
    for (i = 0; i < digits; ++i)
        if (t.p[i] < '0' || t.p[i] > '9') return 0;
    p = t.p;
    if (tag == 0x17) {
        n[0] = (unsigned)((p[0] - '0') * 10 + (p[1] - '0'));
        n[0] += n[0] < 50 ? 2000 : 1900;
        p += 2;
    } else {
        n[0] = (unsigned)((p[0] - '0') * 1000 + (p[1] - '0') * 100 + (p[2] - '0') * 10 + (p[3] - '0'));
        p += 4;
    }
    for (i = 1; i < 6; ++i, p += 2) n[i] = (unsigned)((p[0] - '0') * 10 + (p[1] - '0'));
    if (n[1] < 1 || n[1] > 12 || n[2] < 1 || n[2] > 31 || n[3] > 23 || n[4] > 59 || n[5] > 60) return 0;
    *days = days_of(n[0], n[1], n[2]);
    *secs = n[3] * 3600UL + n[4] * 60UL + n[5];
    return 1;
}

static int lowerc(int ch) { return ch >= 'A' && ch <= 'Z' ? ch + 32 : ch; }

/* a DNS name in a certificate against the host: no case, and "*" only as
 * the whole first label, standing for exactly one label */
static int name_matches(const unsigned char *pat, size_t plen, const char *host)
{
    size_t hlen = strlen(host), i;
    if (plen >= 2 && pat[0] == '*' && pat[1] == '.') {
        const char *dot = strchr(host, '.');
        if (!dot || dot == host) return 0;
        pat += 1; plen -= 1;
        hlen -= (size_t)(dot - host);
        host = dot;
    }
    if (plen != hlen) return 0;
    for (i = 0; i < plen; ++i)
        if (lowerc(pat[i]) != lowerc((unsigned char)host[i])) return 0;
    return 1;
}

static int leaf_names(const unsigned char *der, size_t len, const char *host)
{
    struct der names, n;
    unsigned tag;
    if (!der_san(der, len, &names)) return 0;
    while (der_next(&names, &tag, &n))
        if (tag == 0x82 && name_matches(n.p, n.len, host)) return 1;
    return 0;
}

/* the leaf's signature under the issuer's key */
static unsigned leaf_signature(struct ot_x509 *x, const struct leaf_parts *lp, const br_x509_pkey *pk)
{
    static const unsigned char ecdsa[] = { 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03 };
    static const unsigned char rsa[] = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01 };
    const struct ot_impls *m = x->impls;
    const br_hash_class *h = NULL;
    const unsigned char *oid = NULL;
    unsigned char hv[64], got[64];
    br_hash_compat_context hc;
    size_t hl;
    unsigned last = lp->sigalg.len ? lp->sigalg.p[lp->sigalg.len - 1] : 0;
    int is_ec = lp->sigalg.len == 8 && !memcmp(lp->sigalg.p, ecdsa, 7);
    int is_rsa = lp->sigalg.len == 9 && !memcmp(lp->sigalg.p, rsa, 8);
    if (is_ec) {
        h = last == 2 ? m->sha256 : last == 3 ? m->sha384 : last == 4 ? m->sha512 : NULL;
    } else if (is_rsa) {
        h = last == 11 ? m->sha256 : last == 12 ? m->sha384 : last == 13 ? m->sha512 : NULL;
        oid = last == 11 ? BR_HASH_OID_SHA256 : last == 12 ? BR_HASH_OID_SHA384 : BR_HASH_OID_SHA512;
    }
    if (!h) return BR_ERR_X509_UNSUPPORTED;
    hl = (h->desc >> BR_HASHDESC_OUT_OFF) & BR_HASHDESC_OUT_MASK;
    h->init(&hc.vtable);
    h->update(&hc.vtable, lp->tbs.p, lp->tbs.len);
    h->out(&hc.vtable, hv);
    if (is_ec) {
        if (pk->key_type != BR_KEYTYPE_EC) return BR_ERR_X509_WRONG_KEY_TYPE;
        return m->ecdsa_vrfy(m->ec, hv, hl, &pk->key.ec, lp->sig.p, lp->sig.len)
            ? 0 : BR_ERR_X509_BAD_SIGNATURE;
    }
    if (pk->key_type != BR_KEYTYPE_RSA) return BR_ERR_X509_WRONG_KEY_TYPE;
    if (!m->rsa_vrfy(lp->sig.p, lp->sig.len, oid, hl, &pk->key.rsa, got) || memcmp(got, hv, hl))
        return BR_ERR_X509_BAD_SIGNATURE;
    return 0;
}

static unsigned ed25519_leaf_check(struct ot_x509 *x)
{
    struct OTConnection *c = x->conn;
    struct leaf_parts lp, ip;
    struct der v;
    uint32_t nb_d, nb_s, na_d, na_s, days, secs;
    const br_x509_pkey *pk = NULL;
    unsigned err;
    size_t i;

    if (!leaf_parse(x->leaf, x->leaf_len, &lp)) return BR_ERR_X509_INVALID_VALUE;
    if (x->cert_index == 0) {
        /* no other certificate: the leaf's issuer must be a trust anchor */
        for (i = 0; i < x->ta_count; ++i) {
            const br_x509_trust_anchor *ta = &x->ta[i];
            if ((ta->flags & BR_X509_TA_CA) && ta->dn.len == lp.issuer.len
                && !memcmp(ta->dn.data, lp.issuer.p, lp.issuer.len)) {
                pk = &ta->pkey;
                break;
            }
        }
        if (!pk) return BR_ERR_X509_NOT_TRUSTED;
    } else {
        err = (*INNER(x))->end_chain(INNER(x));
        if (err) return err;
        if (!x->issuer_ok || !leaf_parse(x->issuer, x->issuer_len, &ip)) return BR_ERR_X509_INVALID_VALUE;
        if (!is_ca(x->issuer, x->issuer_len)) return BR_ERR_X509_NOT_CA;
        if (ip.subject.len != lp.issuer.len || memcmp(ip.subject.p, lp.issuer.p, lp.issuer.len))
            return BR_ERR_X509_DN_MISMATCH;
        pk = (*INNER(x))->get_pkey((const br_x509_class *const *)INNER(x), NULL);
        if (!pk) return BR_ERR_X509_NOT_TRUSTED;
    }
    if ((err = leaf_signature(x, &lp, pk)) != 0) return err;
    v = lp.validity;
    if (!read_time(&v, &nb_d, &nb_s) || !read_time(&v, &na_d, &na_s)) return BR_ERR_X509_BAD_TIME;
    if (!ot_now(&days, &secs)) return BR_ERR_X509_TIME_UNKNOWN;
    if (days < nb_d || (days == nb_d && secs < nb_s) || days > na_d || (days == na_d && secs > na_s))
        return BR_ERR_X509_EXPIRED;
    if (c->verify == OTV_FULL) {
        if (c->ip_len) {
            if (!ot_cert_has_ip(x->leaf, x->leaf_len, c->ip, (size_t)c->ip_len)) return OT_X509_IP;
        } else if (!leaf_names(x->leaf, x->leaf_len, c->host)) {
            return BR_ERR_X509_BAD_SERVER_NAME;
        }
    }
    return 0;
}

/* ---- the wrapper engine ---- */

#define INNER_NAME(x) ((x)->conn->verify == OTV_FULL && !(x)->conn->ip_len ? (x)->conn->host : NULL)

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
    x->deferred = 0;
    x->leaf_ed25519 = 0;
    x->issuer_ok = 0;
    x->issuer_len = 0;
    x->inner_started = 0;
    c->peer_name_done = 0;
}

/* the minimal engine checks DNS names only: none for an address, none
 * when the caller turned the check off, none for an Ed25519 leaf's CA */
static void inner_start(struct ot_x509 *x, const char *name)
{
    if (x->inner_started) return;
    (*INNER(x))->start_chain(INNER(x), name);
    x->inner_started = 1;
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
        /* a leaf kept whole goes to the engine at its end, once its key
         * type is known (TLS 1.3 only: BearSSL's handshake wants it streamed) */
        x->deferred = x->tls13 && x->leaf_ok;
        if (x->deferred) return;
        inner_start(x, INNER_NAME(x));
    } else if (x->cert_index == 1 && x->leaf_ed25519) {
        x->issuer_len = 0;
        x->issuer_ok = 0;
        if (length > x->issuer_cap) {
            ot_free(x->issuer);
            x->issuer_cap = 0;
            if (length <= OT_LEAF_MAX && (x->issuer = ot_alloc(length))) x->issuer_cap = length;
        }
        x->issuer_ok = length <= x->issuer_cap;
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
        if (x->deferred) return;
    } else if (x->cert_index == 1 && x->leaf_ed25519) {
        if (x->issuer_ok && x->issuer_len + len <= x->issuer_cap) {
            memcpy(x->issuer + x->issuer_len, buf, len);
            x->issuer_len += len;
        } else {
            x->issuer_ok = 0;
        }
    }
    (*INNER(x))->append(INNER(x), buf, len);
}

static void xw_end_cert(const br_x509_class **ctx)
{
    struct ot_x509 *x = (struct ot_x509 *)(void *)ctx;
    if (x->cert_index == 0) {
        struct leaf_parts lp;
        br_sha256_out(&x->leaf_hash, x->fingerprint);
        x->have_fingerprint = 1;
        if (x->deferred) {
            if (x->leaf_ok && leaf_parse(x->leaf, x->leaf_len, &lp) && spki_ed25519(&lp.spki, x->ed25519)) {
                x->leaf_ed25519 = 1;
                inner_start(x, NULL);          /* from the next certificate */
                return;
            }
            inner_start(x, INNER_NAME(x));
            (*INNER(x))->start_cert(INNER(x), (uint32_t)x->leaf_len);
            (*INNER(x))->append(INNER(x), x->leaf, x->leaf_len);
        }
    }
    (*INNER(x))->end_cert(INNER(x));
}

static unsigned xw_end_chain(const br_x509_class **ctx)
{
    struct ot_x509 *x = (struct ot_x509 *)(void *)ctx;
    struct OTConnection *c = x->conn;
    unsigned err;
    int leaf_key;

    inner_start(x, INNER_NAME(x));
    if (x->leaf_ed25519) {
        if (c->pinned && x->have_fingerprint && !memcmp(x->fingerprint, c->pin, 32)) {
            x->accepted = 1;
            return 0;
        }
        if (c->verify == OTV_PINNED_ONLY) return OT_X509_PINNED;
        if (c->verify == OTV_NONE) {
            x->accepted = 1;
            return 0;
        }
        return ed25519_leaf_check(x);
    }
    err = (*INNER(x))->end_chain(INNER(x));
    leaf_key = x->have_fingerprint && br_x509_decoder_get_pkey(&x->leaf_decoder) != NULL;

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
    if (x->leaf_ed25519) {
        if (usages) *usages = BR_KEYTYPE_SIGN;
        return NULL;            /* the key is x->ed25519 */
    }
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
    x->impls = m;
    x->ta = ta;
    x->ta_count = ta_count;
    x->tls13 = 0;
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
    ot_free(x->issuer);
    x->issuer = NULL;
    x->issuer_cap = x->issuer_len = 0;
}
