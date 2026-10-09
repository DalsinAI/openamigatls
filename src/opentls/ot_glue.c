/* OpenTLS: BearSSL's pluggable maths, done by OpenCrypto.
 *
 * BearSSL takes its hash functions, block ciphers, ChaCha20/Poly1305, RSA,
 * ECDSA and elliptic curves through function tables. Where OpenCrypto has
 * the same operation and it runs on the x86 or ARM64 cores
 * (opencrypto.library's OC_Accelerated()), these tables send it there;
 * everything else, and everything on a real Amiga, stays BearSSL's own
 * constant-time 68k code. The host tests build these tables over
 * OpenCrypto's portable C, so both paths are tested on every run.
 *
 * MIT licensed and free. Copyright (c) 2026 Dalsin Limited. */
#include "ot_internal.h"
#include "inner.h"      /* BearSSL's br_rsa_pkcs1_sig_unpad() */

#ifdef __amigaos__
#include <exec/execbase.h>
#include <proto/exec.h>
#include <libraries/opencrypto.h>
#include <inline/opencrypto.h>
struct Library *OpenCryptoBase;
#else
#include <opencrypto/opencrypto.h>
#endif

/* ---- the calls into OpenCrypto ---- */

#ifdef __amigaos__
static ULONG oc_flags;
static int oc_tried;

static void oc_open(void)
{
    if (oc_tried) return;
    Forbid();
    if (!oc_tried) {
        oc_tried = 1;
        OpenCryptoBase = OpenLibrary((CONST_STRPTR)"opencrypto.library", 2);
        oc_flags = OpenCryptoBase ? OC_Accelerated() : 0;
    }
    Permit();
}

void ot_glue_cleanup(void)
{
    if (OpenCryptoBase) CloseLibrary(OpenCryptoBase);
    OpenCryptoBase = NULL;
    oc_tried = 0;
    oc_flags = 0;
}

static void g_sha256_blocks(unsigned char *state, const void *data, size_t n)
{
    struct OCBlocksRequest r;
    r.state = state; r.data = data; r.blocks = n;
    OC_SHA256Blocks(&r);
}

static void g_sha512_blocks(unsigned char *state, const void *data, size_t n)
{
    struct OCBlocksRequest r;
    r.state = state; r.data = data; r.blocks = n;
    OC_SHA512Blocks(&r);
}

static int g_aes(unsigned char *buf, size_t len, const unsigned char *key, size_t keylen,
                 const unsigned char *iv, int mode)
{
    struct OCAESRequest r;
    r.buf = buf; r.length = len; r.key = key; r.key_length = keylen;
    r.iv = iv; r.mode = (ULONG)mode;
    return OC_AES(&r);
}

static void g_chacha(unsigned char *buf, size_t len, const unsigned char *key,
                     const unsigned char *nonce, uint64_t counter)
{
    struct OCChaChaRequest r;
    r.out = buf; r.in = buf; r.length = len; r.key = key; r.nonce = nonce;
    r.counter_hi = (ULONG)(counter >> 32); r.counter_lo = (ULONG)counter;
    OC_ChaCha20(&r);
}

static void g_poly(unsigned char *tag, const void *data, size_t len, const unsigned char *key)
{
    struct OCPolyRequest r;
    r.tag = tag; r.data = data; r.length = len; r.key = key;
    OC_Poly1305(&r);
}

static int g_x25519(unsigned char *out, const unsigned char *scalar, const unsigned char *point)
{
    struct OCX25519Request r;
    r.out = out; r.scalar = scalar; r.point = point;
    return OC_X25519(&r);
}

static int g_rsa(unsigned char *out, const unsigned char *x, const unsigned char *n, size_t nlen,
                 const unsigned char *e, size_t elen)
{
    struct OCRSARequest r;
    r.out = out; r.sig = x; r.n = n; r.n_length = nlen; r.e = e; r.e_length = elen;
    return OC_RSAPublic(&r);
}

static int g_ecdsa(int curve, const unsigned char *qx, const unsigned char *qy,
                   const unsigned char *rr, const unsigned char *ss,
                   const unsigned char *hash, size_t hlen)
{
    struct OCECDSARequest r;
    r.curve = curve; r.qx = qx; r.qy = qy; r.r = rr; r.s = ss;
    r.hash = hash; r.hash_length = hlen;
    return OC_ECDSAVerify(&r);
}

ULONG ot_glue_accelerated(void)
{
    ULONG f = 0;
    oc_open();
    if ((oc_flags & (OCF_SHA256 | OCF_SHA512)) == (OCF_SHA256 | OCF_SHA512)) f |= OTACC_HASH;
    if (oc_flags & OCF_AES) f |= OTACC_AES;
    if ((oc_flags & (OCF_CHACHA20 | OCF_POLY1305)) == (OCF_CHACHA20 | OCF_POLY1305)) f |= OTACC_CHACHA;
    if (oc_flags & OCF_X25519) f |= OTACC_X25519;
    if (oc_flags & OCF_RSA) f |= OTACC_RSA;
    if (oc_flags & OCF_ECDSA) f |= OTACC_ECDSA;
    return f;
}

#else /* the host tests: OpenCrypto's portable C */

void ot_glue_cleanup(void) {}

static void g_sha256_blocks(unsigned char *state, const void *data, size_t n)
{ oc_sha256_blocks(state, data, n); }
static void g_sha512_blocks(unsigned char *state, const void *data, size_t n)
{ oc_sha512_blocks(state, data, n); }
static int g_aes(unsigned char *buf, size_t len, const unsigned char *key, size_t keylen,
                 const unsigned char *iv, int mode)
{ return oc_aes(buf, len, key, keylen, iv, mode); }
static void g_chacha(unsigned char *buf, size_t len, const unsigned char *key,
                     const unsigned char *nonce, uint64_t counter)
{ oc_chacha20_xor(buf, buf, len, key, nonce, counter); }
static void g_poly(unsigned char *tag, const void *data, size_t len, const unsigned char *key)
{ oc_poly1305(tag, data, len, key); }
static int g_x25519(unsigned char *out, const unsigned char *scalar, const unsigned char *point)
{
    if (!point) { oc_x25519_base(out, scalar); return 0; }
    return oc_x25519(out, scalar, point);
}
static int g_rsa(unsigned char *out, const unsigned char *x, const unsigned char *n, size_t nlen,
                 const unsigned char *e, size_t elen)
{ return oc_rsa_public(out, x, n, nlen, e, elen); }
static int g_ecdsa(int curve, const unsigned char *qx, const unsigned char *qy,
                   const unsigned char *rr, const unsigned char *ss,
                   const unsigned char *hash, size_t hlen)
{ return oc_ecdsa_verify(curve, qx, qy, rr, ss, hash, hlen); }

ULONG ot_glue_accelerated(void)
{
    return OTACC_HASH | OTACC_AES | OTACC_CHACHA | OTACC_X25519 | OTACC_RSA | OTACC_ECDSA;
}
#endif

/* ---- SHA-256, SHA-384, SHA-512 over OpenCrypto's block functions ---- */

typedef struct {
    const br_hash_class *vtable;
    unsigned char buf[128];
    uint64_t count;
    unsigned char state[64];
} ot_sha_context;

static const br_hash_class ot_sha256_vtable, ot_sha384_vtable, ot_sha512_vtable;

static size_t sha_block(const ot_sha_context *c)
{
    return c->vtable == &ot_sha256_vtable ? 64 : 128;
}

static void sha_blocks(const ot_sha_context *c, unsigned char *state, const void *data, size_t n)
{
    if (c->vtable == &ot_sha256_vtable) g_sha256_blocks(state, data, n);
    else g_sha512_blocks(state, data, n);
}

static void sha_init(const br_hash_class **ctx)
{
    ot_sha_context *c = (ot_sha_context *)(void *)ctx;
    br_sha512_context ref;    /* large enough for each of the three */
    /* BearSSL's own initial state, as bytes: the IVs come from one place */
    if (*ctx == &ot_sha256_vtable) {
        br_sha256_init((br_sha256_context *)(void *)&ref);
        br_sha256_state((br_sha256_context *)(void *)&ref, c->state);
    } else if (*ctx == &ot_sha384_vtable) {
        br_sha384_init(&ref);
        br_sha384_state(&ref, c->state);
    } else {
        br_sha512_init(&ref);
        br_sha512_state(&ref, c->state);
    }
    c->count = 0;
}

static void sha256_init(const br_hash_class **ctx) { *ctx = &ot_sha256_vtable; sha_init(ctx); }
static void sha384_init(const br_hash_class **ctx) { *ctx = &ot_sha384_vtable; sha_init(ctx); }
static void sha512_init(const br_hash_class **ctx) { *ctx = &ot_sha512_vtable; sha_init(ctx); }

static void sha_update(const br_hash_class **ctx, const void *data, size_t len)
{
    ot_sha_context *c = (ot_sha_context *)(void *)ctx;
    const unsigned char *p = data;
    size_t bl = sha_block(c), ptr = (size_t)c->count & (bl - 1), n;
    c->count += len;
    if (ptr) {
        n = bl - ptr < len ? bl - ptr : len;
        memcpy(c->buf + ptr, p, n);
        p += n; len -= n; ptr += n;
        if (ptr < bl) return;
        sha_blocks(c, c->state, c->buf, 1);
    }
    n = len / bl;
    if (n) {
        sha_blocks(c, c->state, p, n);
        p += n * bl;
        len -= n * bl;
    }
    if (len) memcpy(c->buf, p, len);
}

static void sha_out(const br_hash_class *const *ctx, void *dst)
{
    const ot_sha_context *c = (const ot_sha_context *)(const void *)ctx;
    unsigned char buf[256], state[64];
    size_t bl = sha_block(c), ptr = (size_t)c->count & (bl - 1), total, i;
    size_t lenbytes = bl == 64 ? 8 : 16;
    size_t outlen = (c->vtable->desc >> BR_HASHDESC_OUT_OFF) & BR_HASHDESC_OUT_MASK;
    uint64_t bits = c->count << 3;
    memcpy(state, c->state, sizeof state);
    memcpy(buf, c->buf, ptr);
    buf[ptr] = 0x80;
    total = ptr + 1 + lenbytes <= bl ? bl : 2 * bl;
    memset(buf + ptr + 1, 0, total - ptr - 1);
    for (i = 0; i < 8; ++i)
        buf[total - 1 - i] = (unsigned char)(bits >> (8 * i));
    sha_blocks(c, state, buf, total / bl);
    memcpy(dst, state, outlen);
}

static uint64_t sha_state(const br_hash_class *const *ctx, void *dst)
{
    const ot_sha_context *c = (const ot_sha_context *)(const void *)ctx;
    memcpy(dst, c->state, sha_block(c) == 64 ? 32 : 64);
    return c->count;
}

/* BearSSL calls set_state on a context it never initialised (multihash,
 * HMAC), so each class's set_state puts its own table in */
static void sha_set_state(const br_hash_class **ctx, const void *stb, uint64_t count)
{
    ot_sha_context *c = (ot_sha_context *)(void *)ctx;
    memcpy(c->state, stb, sha_block(c) == 64 ? 32 : 64);
    c->count = count;
}

static void sha256_set_state(const br_hash_class **ctx, const void *stb, uint64_t count)
{ *ctx = &ot_sha256_vtable; sha_set_state(ctx, stb, count); }
static void sha384_set_state(const br_hash_class **ctx, const void *stb, uint64_t count)
{ *ctx = &ot_sha384_vtable; sha_set_state(ctx, stb, count); }
static void sha512_set_state(const br_hash_class **ctx, const void *stb, uint64_t count)
{ *ctx = &ot_sha512_vtable; sha_set_state(ctx, stb, count); }

#define OT_SHA_DESC(id, out, st, lblen, extra) \
    (BR_HASHDESC_ID(id) | BR_HASHDESC_OUT(out) | BR_HASHDESC_STATE(st) \
     | BR_HASHDESC_LBLEN(lblen) | BR_HASHDESC_MD_PADDING | BR_HASHDESC_MD_PADDING_BE | (extra))

static const br_hash_class ot_sha256_vtable = {
    sizeof(ot_sha_context), OT_SHA_DESC(br_sha256_ID, 32, 32, 6, 0),
    sha256_init, sha_update, sha_out, sha_state, sha256_set_state
};
static const br_hash_class ot_sha384_vtable = {
    sizeof(ot_sha_context), OT_SHA_DESC(br_sha384_ID, 48, 64, 7, BR_HASHDESC_MD_PADDING_128),
    sha384_init, sha_update, sha_out, sha_state, sha384_set_state
};
static const br_hash_class ot_sha512_vtable = {
    sizeof(ot_sha_context), OT_SHA_DESC(br_sha512_ID, 64, 64, 7, BR_HASHDESC_MD_PADDING_128),
    sha512_init, sha_update, sha_out, sha_state, sha512_set_state
};

/* ---- AES: CBC and CTR (GCM's counter mode) ---- */

typedef struct {
    const void *vtable;
    unsigned char key[32];
    size_t key_len;
} ot_aes_context;

static void aes_set(void *ctx, const void *key, size_t len)
{
    ot_aes_context *c = ctx;
    if (len > sizeof c->key) len = 0;     /* the run then refuses */
    memcpy(c->key, key, len);
    c->key_len = len;
}

static const br_block_cbcenc_class ot_aes_cbcenc_vtable;
static const br_block_cbcdec_class ot_aes_cbcdec_vtable;
static const br_block_ctr_class ot_aes_ctr_vtable;

static void aes_cbcenc_init(const br_block_cbcenc_class **ctx, const void *key, size_t len)
{ *ctx = &ot_aes_cbcenc_vtable; aes_set(ctx, key, len); }
static void aes_cbcdec_init(const br_block_cbcdec_class **ctx, const void *key, size_t len)
{ *ctx = &ot_aes_cbcdec_vtable; aes_set(ctx, key, len); }
static void aes_ctr_init(const br_block_ctr_class **ctx, const void *key, size_t len)
{ *ctx = &ot_aes_ctr_vtable; aes_set(ctx, key, len); }

static void aes_cbcenc_run(const br_block_cbcenc_class *const *ctx, void *iv, void *data, size_t len)
{
    const ot_aes_context *c = (const void *)ctx;
    if (!len) return;
    if (g_aes(data, len, c->key, c->key_len, iv, OC_AES_CBC_ENCRYPT) != 0)
        memset(data, 0, len);   /* never send what was not encrypted */
    memcpy(iv, (unsigned char *)data + len - 16, 16);
}

static void aes_cbcdec_run(const br_block_cbcdec_class *const *ctx, void *iv, void *data, size_t len)
{
    const ot_aes_context *c = (const void *)ctx;
    unsigned char next[16];
    if (!len) return;
    memcpy(next, (unsigned char *)data + len - 16, 16);
    g_aes(data, len, c->key, c->key_len, iv, OC_AES_CBC_DECRYPT);
    memcpy(iv, next, 16);
}

static uint32_t aes_ctr_run(const br_block_ctr_class *const *ctx, const void *iv, uint32_t cc,
                            void *data, size_t len)
{
    const ot_aes_context *c = (const void *)ctx;
    unsigned char block[16];
    memcpy(block, iv, 12);
    br_enc32be(block + 12, cc);
    if (len && g_aes(data, len, c->key, c->key_len, block, OC_AES_CTR) != 0)
        memset(data, 0, len);   /* never send what was not encrypted */
    return cc + (uint32_t)((len + 15) >> 4);
}

static const br_block_cbcenc_class ot_aes_cbcenc_vtable = {
    sizeof(ot_aes_context), 16, 4, aes_cbcenc_init, aes_cbcenc_run
};
static const br_block_cbcdec_class ot_aes_cbcdec_vtable = {
    sizeof(ot_aes_context), 16, 4, aes_cbcdec_init, aes_cbcdec_run
};
static const br_block_ctr_class ot_aes_ctr_vtable = {
    sizeof(ot_aes_context), 16, 4, aes_ctr_init, aes_ctr_run
};

/* ---- ChaCha20 and Poly1305 (RFC 7539's AEAD, as TLS uses) ---- */

/* RFC 7539's 32-bit counter and 96-bit nonce are the original's 64-bit
 * counter (cc, then the nonce's first word) and 64-bit nonce (the rest). */
static uint32_t ot_chacha20_run(const void *key, const void *iv, uint32_t cc, void *data, size_t len)
{
    const unsigned char *v = iv;
    uint64_t counter = (uint64_t)cc | ((uint64_t)br_dec32le(v) << 32);
    if (len) g_chacha(data, len, key, v + 4, counter);
    return cc + (uint32_t)((len + 63) >> 6);
}

static void ot_poly1305_run(const void *key, const void *iv, void *data, size_t len,
                            const void *aad, size_t aad_len, void *tag,
                            br_chacha20_run ichacha, int encrypt)
{
    unsigned char pkey[32], small[512], *mac;
    size_t apad = (aad_len + 15) & ~(size_t)15, dpad = (len + 15) & ~(size_t)15;
    size_t total = apad + dpad + 16;
    mac = total <= sizeof small ? small : ot_alloc(total);
    if (!mac) {
        /* no memory for the one-shot MAC: BearSSL's own, as on a real Amiga */
        br_poly1305_ctmul32_run(key, iv, data, len, aad, aad_len, tag, ichacha, encrypt);
        return;
    }
    memset(pkey, 0, sizeof pkey);
    ichacha(key, iv, 0, pkey, sizeof pkey);
    if (encrypt) ichacha(key, iv, 1, data, len);
    memset(mac, 0, total);
    memcpy(mac, aad, aad_len);
    memcpy(mac + apad, data, len);
    br_enc64le(mac + apad + dpad, (uint64_t)aad_len);
    br_enc64le(mac + apad + dpad + 8, (uint64_t)len);
    g_poly(tag, mac, total, pkey);
    if (mac != small) ot_free(mac);
    if (!encrypt) ichacha(key, iv, 1, data, len);
    memset(pkey, 0, sizeof pkey);
}

/* ---- RSA ---- */

static int rsa_trim(const br_rsa_public_key *pk, const unsigned char **n, size_t *nlen)
{
    *n = pk->n;
    *nlen = pk->nlen;
    while (*nlen && **n == 0) { ++*n; --*nlen; }
    return *nlen > 0 && *nlen <= 1024;
}

static uint32_t ot_rsa_public(unsigned char *x, size_t xlen, const br_rsa_public_key *pk)
{
    const unsigned char *n;
    size_t nlen;
    unsigned char *out;
    int rc;
    if (!rsa_trim(pk, &n, &nlen) || xlen != nlen) return 0;
    out = ot_alloc(nlen);
    if (!out) return 0;
    rc = g_rsa(out, x, n, nlen, pk->e, pk->elen);
    if (rc == 0) memcpy(x, out, nlen);
    ot_free(out);
    return rc == 0;
}

static uint32_t ot_rsa_pkcs1_vrfy(const unsigned char *x, size_t xlen,
                                  const unsigned char *hash_oid, size_t hash_len,
                                  const br_rsa_public_key *pk, unsigned char *hash_out)
{
    const unsigned char *n;
    size_t nlen;
    unsigned char *sig;
    uint32_t ok = 0;
    if (!rsa_trim(pk, &n, &nlen) || xlen != nlen) return 0;
    sig = ot_alloc(nlen);
    if (!sig) return 0;
    if (g_rsa(sig, x, n, nlen, pk->e, pk->elen) == 0)
        ok = br_rsa_pkcs1_sig_unpad(sig, nlen, hash_oid, hash_len, hash_out);
    ot_free(sig);
    return ok;
}

/* ---- ECDSA verification (P-256, P-384, P-521) ---- */

static uint32_t ot_ecdsa_vrfy_asn1(const br_ec_impl *impl, const void *hash, size_t hash_len,
                                   const br_ec_public_key *pk, const void *sig, size_t sig_len)
{
    unsigned char raw[160], r[66], s[66];
    size_t flen, rlen, half;
    int bits;
    (void)impl;
    switch (pk->curve) {
    case BR_EC_secp256r1: bits = 256; flen = 32; break;
    case BR_EC_secp384r1: bits = 384; flen = 48; break;
    case BR_EC_secp521r1: bits = 521; flen = 66; break;
    default: return 0;
    }
    if (pk->qlen != 1 + 2 * flen || pk->q[0] != 0x04 || sig_len > sizeof raw) return 0;
    memcpy(raw, sig, sig_len);
    rlen = br_ecdsa_asn1_to_raw(raw, sig_len);
    if (rlen == 0 || (rlen & 1)) return 0;
    half = rlen / 2;
    if (half > flen) return 0;
    memset(r, 0, sizeof r);
    memset(s, 0, sizeof s);
    memcpy(r + flen - half, raw, half);
    memcpy(s + flen - half, raw + half, half);
    return g_ecdsa(bits, pk->q + 1, pk->q + 1 + flen, r, s, hash, hash_len) == 1;
}

/* ---- elliptic curves: X25519 through OpenCrypto, NIST curves BearSSL's ---- */

static const br_ec_impl *ec_base(void)
{
#ifdef OT_LOMUL
    return &br_ec_all_m15;
#else
    return &br_ec_all_m31;
#endif
}

static const unsigned char *ot_ec_generator(int curve, size_t *len)
{ return ec_base()->generator(curve, len); }
static const unsigned char *ot_ec_order(int curve, size_t *len)
{ return ec_base()->order(curve, len); }
static size_t ot_ec_xoff(int curve, size_t *len)
{ return ec_base()->xoff(curve, len); }

static uint32_t ot_ec_mul(unsigned char *G, size_t Glen, const unsigned char *x, size_t xlen, int curve)
{
    unsigned char k[32], out[32];
    int rc;
    if (curve != BR_EC_curve25519) return ec_base()->mul(G, Glen, x, xlen, curve);
    if (Glen != 32 || xlen > 32) return 0;
    memcpy(k, x, xlen);
    memset(k + xlen, 0, 32 - xlen);
    G[31] &= 0x7F;
    rc = g_x25519(out, k, G);
    memcpy(G, out, 32);
    memset(k, 0, sizeof k);
    return rc == 0;     /* an all-zero shared secret is refused */
}

static size_t ot_ec_mulgen(unsigned char *R, const unsigned char *x, size_t xlen, int curve)
{
    unsigned char k[32];
    if (curve != BR_EC_curve25519) return ec_base()->mulgen(R, x, xlen, curve);
    if (xlen > 32) return 0;
    memcpy(k, x, xlen);
    memset(k + xlen, 0, 32 - xlen);
    g_x25519(R, k, NULL);
    memset(k, 0, sizeof k);
    return 32;
}

static uint32_t ot_ec_muladd(unsigned char *A, const unsigned char *B, size_t len,
                             const unsigned char *x, size_t xlen,
                             const unsigned char *y, size_t ylen, int curve)
{ return ec_base()->muladd(A, B, len, x, xlen, y, ylen, curve); }

static const br_ec_impl ot_ec_impl = {
    (uint32_t)0x23800000,     /* P-256, P-384, P-521 and Curve25519, as br_ec_all_m31 */
    ot_ec_generator, ot_ec_order, ot_ec_xoff, ot_ec_mul, ot_ec_mulgen, ot_ec_muladd
};

/* ---- the choice ---- */

void ot_glue_select(struct ot_impls *m, int offload)
{
    ULONG acc = offload ? ot_glue_accelerated() : 0;
#ifdef OT_GLUE_MASK          /* measuring: leave some operations to BearSSL */
    acc &= ~(ULONG)(OT_GLUE_MASK);
#endif

    m->sha256 = (acc & OTACC_HASH) ? &ot_sha256_vtable : &br_sha256_vtable;
    m->sha384 = (acc & OTACC_HASH) ? &ot_sha384_vtable : &br_sha384_vtable;
    m->sha512 = (acc & OTACC_HASH) ? &ot_sha512_vtable : &br_sha512_vtable;
#ifdef OT_LOMUL
    m->rsa_vrfy = br_rsa_i15_pkcs1_vrfy;
    m->rsa_pub = br_rsa_i15_public;
    m->ecdsa_vrfy = br_ecdsa_i15_vrfy_asn1;
    m->ghash = br_ghash_ctmul32;
    m->poly1305 = br_poly1305_ctmul32_run;
#else
    m->rsa_vrfy = br_rsa_i31_pkcs1_vrfy;
    m->rsa_pub = br_rsa_i31_public;
    m->ecdsa_vrfy = br_ecdsa_i31_vrfy_asn1;
    m->ghash = br_ghash_ctmul;
    m->poly1305 = br_poly1305_ctmul_run;
#endif
    m->ec = ec_base();
    m->aes_cbcenc = &br_aes_ct_cbcenc_vtable;
    m->aes_cbcdec = &br_aes_ct_cbcdec_vtable;
    m->aes_ctr = &br_aes_ct_ctr_vtable;
    m->chacha20 = br_chacha20_ct_run;

    if (acc & OTACC_RSA) { m->rsa_vrfy = ot_rsa_pkcs1_vrfy; m->rsa_pub = ot_rsa_public; }
    if (acc & OTACC_ECDSA) m->ecdsa_vrfy = ot_ecdsa_vrfy_asn1;
    if (acc & OTACC_X25519) m->ec = &ot_ec_impl;
    if (acc & OTACC_AES) {
        m->aes_cbcenc = &ot_aes_cbcenc_vtable;
        m->aes_cbcdec = &ot_aes_cbcdec_vtable;
        m->aes_ctr = &ot_aes_ctr_vtable;
    }
    if (acc & OTACC_CHACHA) { m->chacha20 = ot_chacha20_run; m->poly1305 = ot_poly1305_run; }
}
