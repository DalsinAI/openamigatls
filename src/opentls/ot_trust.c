/* OpenTLS: trust anchors from PEM certificates, and the system trust store
 * (ENV:OpenTLS/ca-bundle.pem and ENV:OpenTLS/certs/, docs/AutoDocs-OpenTLS.md),
 * loaded once and shared by every context.
 * MIT licensed and free. Copyright (c) 2026 Dalsin Limited. */
#include "ot_internal.h"

struct growbuf {
    unsigned char *data;
    size_t len, cap;
    int failed;
};

static void grow_append(void *ctx, const void *buf, size_t len)
{
    struct growbuf *g = ctx;
    if (g->failed) return;
    if (g->len + len > g->cap) {
        size_t cap = g->cap ? g->cap * 2 : 2048;
        unsigned char *p;
        while (cap < g->len + len) cap *= 2;
        p = ot_alloc(cap);
        if (!p) { g->failed = 1; return; }
        if (g->len) memcpy(p, g->data, g->len);
        ot_free(g->data);
        g->data = p;
        g->cap = cap;
    }
    memcpy(g->data + g->len, buf, len);
    g->len += len;
}

/* One certificate (DER) to a trust anchor. Answers 1 added, 0 skipped
 * (a key BearSSL does not take), or OTERR_NOMEM. */
static LONG add_der(struct ot_anchors *a, const unsigned char *der, size_t len)
{
    br_x509_decoder_context dc;
    struct growbuf dn;
    const br_x509_pkey *pk;
    br_x509_trust_anchor *ta;
    unsigned char *block;
    size_t need;

    memset(&dn, 0, sizeof dn);
    br_x509_decoder_init(&dc, grow_append, &dn);
    br_x509_decoder_push(&dc, der, len);
    pk = br_x509_decoder_get_pkey(&dc);
    if (dn.failed) { ot_free(dn.data); return OTERR_NOMEM; }
    if (!pk || !dn.len) { ot_free(dn.data); return 0; }
    if (a->count == a->cap) {
        size_t cap = a->cap ? a->cap * 2 : 64;
        br_x509_trust_anchor *n = ot_alloc(cap * sizeof *n);
        if (!n) { ot_free(dn.data); return OTERR_NOMEM; }
        if (a->count) memcpy(n, a->ta, a->count * sizeof *n);
        ot_free(a->ta);
        a->ta = n;
        a->cap = cap;
    }
    need = dn.len;
    if (pk->key_type == BR_KEYTYPE_RSA) need += pk->key.rsa.nlen + pk->key.rsa.elen;
    else if (pk->key_type == BR_KEYTYPE_EC) need += pk->key.ec.qlen;
    else { ot_free(dn.data); return 0; }
    block = ot_alloc(need);
    if (!block) { ot_free(dn.data); return OTERR_NOMEM; }
    ta = &a->ta[a->count];
    memset(ta, 0, sizeof *ta);
    memcpy(block, dn.data, dn.len);
    ta->dn.data = block;
    ta->dn.len = dn.len;
    ta->flags = br_x509_decoder_isCA(&dc) ? BR_X509_TA_CA : 0;
    ta->pkey.key_type = pk->key_type;
    if (pk->key_type == BR_KEYTYPE_RSA) {
        unsigned char *p = block + dn.len;
        memcpy(p, pk->key.rsa.n, pk->key.rsa.nlen);
        ta->pkey.key.rsa.n = p;
        ta->pkey.key.rsa.nlen = pk->key.rsa.nlen;
        p += pk->key.rsa.nlen;
        memcpy(p, pk->key.rsa.e, pk->key.rsa.elen);
        ta->pkey.key.rsa.e = p;
        ta->pkey.key.rsa.elen = pk->key.rsa.elen;
    } else {
        unsigned char *p = block + dn.len;
        memcpy(p, pk->key.ec.q, pk->key.ec.qlen);
        ta->pkey.key.ec.curve = pk->key.ec.curve;
        ta->pkey.key.ec.q = p;
        ta->pkey.key.ec.qlen = pk->key.ec.qlen;
    }
    ++a->count;
    ot_free(dn.data);
    return 1;
}

static int is_cert_name(const char *name)
{
    return !strcmp(name, "CERTIFICATE") || !strcmp(name, "X509 CERTIFICATE")
        || !strcmp(name, "TRUSTED CERTIFICATE");
}

LONG ot_anchors_add_pem(struct ot_anchors *a, const unsigned char *pem, size_t len)
{
    br_pem_decoder_context pc;
    struct growbuf der;
    LONG added = 0, rc;
    int inobj = 0, final_newline = 0;

    if (!a || (!pem && len)) return OTERR_ARGS;
    memset(&der, 0, sizeof der);
    br_pem_decoder_init(&pc);
    while (len > 0 || !final_newline) {
        size_t used;
        if (len == 0) {     /* BearSSL wants the last line ended */
            pem = (const unsigned char *)"\n";
            len = 1;
            final_newline = 1;
        }
        used = br_pem_decoder_push(&pc, pem, len);
        pem += used;
        len -= used;
        switch (br_pem_decoder_event(&pc)) {
        case BR_PEM_BEGIN_OBJ:
            inobj = is_cert_name(br_pem_decoder_name(&pc));
            der.len = 0;
            der.failed = 0;
            br_pem_decoder_setdest(&pc, inobj ? grow_append : NULL, inobj ? &der : NULL);
            break;
        case BR_PEM_END_OBJ:
            if (inobj) {
                if (der.failed) { ot_free(der.data); return OTERR_NOMEM; }
                rc = add_der(a, der.data, der.len);
                if (rc < 0) { ot_free(der.data); return rc; }
                added += rc;
            }
            inobj = 0;
            break;
        case BR_PEM_ERROR:
            ot_free(der.data);
            return added ? added : OTERR_ARGS;
        default:
            break;
        }
    }
    ot_free(der.data);
    return added;
}

LONG ot_anchors_add_file(struct ot_anchors *a, const char *path)
{
    unsigned char *data;
    size_t len;
    LONG rc;
    if (!a || !path) return OTERR_ARGS;
    if (!ot_read_file(path, &data, &len)) return OTERR_TRUSTSTORE;
    rc = ot_anchors_add_pem(a, data, len);
    ot_free(data);
    return rc;
}

void ot_anchors_free(struct ot_anchors *a)
{
    size_t i;
    if (!a) return;
    for (i = 0; i < a->count; ++i) ot_free(a->ta[i].dn.data);
    ot_free(a->ta);
    memset(a, 0, sizeof *a);
}

/* ---- the system store ---- */

static struct ot_anchors ot_sys;
static int ot_sys_loaded;
static void *ot_sys_lock;

static void add_dir_file(const char *path, void *ctx)
{
    ot_anchors_add_file(ctx, path);
}

int ot_trust_init(void)
{
    if (!ot_sys_lock) ot_sys_lock = ot_lock_new();
    return ot_sys_lock != NULL;
}

const struct ot_anchors *ot_system_anchors(void)
{
    char path[256];
    int i, have_bundle = 0;
    if (!ot_sys_lock) {
        /* first use; the library makes it at init, the host tests here */
        ot_sys_lock = ot_lock_new();
        if (!ot_sys_lock) return NULL;
    }
    ot_lock(ot_sys_lock);
    if (!ot_sys_loaded) {
        ot_sys_loaded = 1;
        for (i = 0; ot_trust_location(OT_TRUST_BUNDLE, i, path, sizeof path); ++i)
            if (ot_anchors_add_file(&ot_sys, path) > 0) { have_bundle = 1; break; }
        if (!have_bundle)
            for (i = 0; ot_trust_location(OT_TRUST_FALLBACK, i, path, sizeof path); ++i)
                if (ot_anchors_add_file(&ot_sys, path) > 0) break;
        /* the first directory with certificates: ENV:, else ENVARC: */
        for (i = 0; ot_trust_location(OT_TRUST_DIR, i, path, sizeof path); ++i)
            if (ot_each_file(path, ".pem", add_dir_file, &ot_sys) > 0) break;
    }
    ot_unlock(ot_sys_lock);
    return ot_sys.count ? &ot_sys : NULL;
}

void ot_system_anchors_free(void)
{
    ot_anchors_free(&ot_sys);
    ot_sys_loaded = 0;
    ot_lock_free(ot_sys_lock);
    ot_sys_lock = NULL;
}
