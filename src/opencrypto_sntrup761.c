/* OpenCrypto: Streamlined NTRU Prime sntrup761, the KEM of SSH's
 * sntrup761x25519-sha512 key exchange (as OpenSSH and PuTTY have it:
 * NTRU Prime round 3, with the 32-byte confirmation hash on the
 * ciphertext and implicit rejection).
 * Copyright (c) 2026 Dalsin Limited. MIT.
 *
 * Written from the NTRU Prime specification (round 3, sections 3 and 4):
 * the ring Z[x]/(x^p - x - 1), q = 4591, weight w = 286; reciprocals by
 * constant-time division steps; the variable-radix Encode/Decode; Hash =
 * the first 32 bytes of SHA-512 over a prefix byte and the input.
 *
 * Constant time: no branch or memory index depends on a secret. The one
 * loop that repeats (key generation's g, drawn until it is invertible
 * mod 3, about once in a few hundred draws) depends only on that discarded
 * draw. Division appears only by public constants (q, 3, the encoding's
 * radices); 0x80000000 / m is computed from those.
 *
 * Memory: everything is on the caller's stack (about 24 KB at the
 * deepest, in key generation), so calls from several tasks at once are
 * safe; opencrypto.library runs these on a stack of its own.
 *
 * Randomness: the caller gives a 32-byte seed, expanded with ChaCha20
 * (oc_expand_seed), so the same seed gives the same keys on every machine
 * (AC090's host code and the 68k code give identical bytes). */
#include "opencrypto/opencrypto.h"

#include <string.h>

#define P 761
#define Q 4591
#define W 286
#define Q12 ((Q - 1) / 2)
#define SMALL_BYTES ((P + 3) / 4)            /* 191 */
#define RQ_BYTES 1158
#define ROUNDED_BYTES 1007
#define HASH_BYTES 32
#define PK_BYTES RQ_BYTES
#define SK_BYTES (2 * SMALL_BYTES + PK_BYTES + SMALL_BYTES + HASH_BYTES)   /* 1763 */
#define CT_BYTES (ROUNDED_BYTES + HASH_BYTES)                              /* 1039 */

typedef int8_t small;
typedef int16_t Fq;

/* ---- constant-time arithmetic ---- */

/* x = q m + r, 0 <= r < m, for 0 < m < 16384 */
static void u32_divmod_u14(uint32_t *qo, uint16_t *ro, uint32_t x, uint16_t m)
{
    uint32_t v = 0x80000000u, qpart, mask, q = 0;
    v /= m;
    qpart = (uint32_t)(((uint64_t)x * v) >> 31);
    x -= qpart * m; q += qpart;
    qpart = (uint32_t)(((uint64_t)x * v) >> 31);
    x -= qpart * m; q += qpart;
    x -= m; q += 1;
    mask = -(x >> 31);
    x += mask & (uint32_t)m; q += mask;
    *qo = q;
    *ro = (uint16_t)x;
}

static uint16_t u32_mod_u14(uint32_t x, uint16_t m)
{
    uint32_t q;
    uint16_t r;
    u32_divmod_u14(&q, &r, x, m);
    return r;
}

/* x mod m for a signed x, in [0, m) */
static uint16_t i32_mod_u14(int32_t x, uint16_t m)
{
    uint32_t uq, uq2;
    uint16_t ur, ur2;
    uint32_t mask;
    u32_divmod_u14(&uq, &ur, 0x80000000u + (uint32_t)x, m);
    u32_divmod_u14(&uq2, &ur2, 0x80000000u, m);
    ur -= ur2;
    mask = -(uint32_t)(ur >> 15);
    ur += mask & m;
    return ur;
}

static int nonzero_mask16(int16_t x)        /* -1 if x != 0, else 0 */
{
    uint32_t v = (uint16_t)x;
    v = -v;
    v >>= 31;
    return -(int)v;
}

static int negative_mask16(int16_t x)       /* -1 if x < 0, else 0 */
{
    uint16_t u = (uint16_t)x;
    u >>= 15;
    return -(int)u;
}

Fq Fq_freeze(int32_t x) { return (Fq)(i32_mod_u14(x + Q12, Q) - Q12); }
static small F3_freeze(int32_t x) { return (small)(i32_mod_u14(x + 1, 3) - 1); }

Fq Fq_recip(Fq a1)
{
    int i = 1;
    Fq ai = a1;
    while (i < Q - 2) {
        ai = Fq_freeze(a1 * (int32_t)ai);
        i += 1;
    }
    return ai;
}

/* ---- the ring ---- */

static void Rq_mult_small(Fq *h, const Fq *f, const small *g)
{
    Fq fg[P + P - 1];
    int32_t r;
    int i, j;
    for (i = 0; i < P; ++i) {
        r = 0;
        for (j = 0; j <= i; ++j) r = Fq_freeze(r + f[j] * (int32_t)g[i - j]);
        fg[i] = (Fq)r;
    }
    for (i = P; i < P + P - 1; ++i) {
        r = 0;
        for (j = i - P + 1; j < P; ++j) r = Fq_freeze(r + f[j] * (int32_t)g[i - j]);
        fg[i] = (Fq)r;
    }
    for (i = P + P - 2; i >= P; --i) {
        fg[i - P] = Fq_freeze(fg[i - P] + fg[i]);
        fg[i - P + 1] = Fq_freeze(fg[i - P + 1] + fg[i]);
    }
    for (i = 0; i < P; ++i) h[i] = fg[i];
    memset(fg, 0, sizeof fg);
}

static void R3_mult(small *h, const small *f, const small *g)
{
    small fg[P + P - 1];
    small r;
    int i, j;
    for (i = 0; i < P; ++i) {
        r = 0;
        for (j = 0; j <= i; ++j) r = F3_freeze(r + f[j] * g[i - j]);
        fg[i] = r;
    }
    for (i = P; i < P + P - 1; ++i) {
        r = 0;
        for (j = i - P + 1; j < P; ++j) r = F3_freeze(r + f[j] * g[i - j]);
        fg[i] = r;
    }
    for (i = P + P - 2; i >= P; --i) {
        fg[i - P] = F3_freeze(fg[i - P] + fg[i]);
        fg[i - P + 1] = F3_freeze(fg[i - P + 1] + fg[i]);
    }
    for (i = 0; i < P; ++i) h[i] = fg[i];
    memset(fg, 0, sizeof fg);
}

/* The polynomial shifts below are memmove calls, not loops: the os32 GCC
 * 16 stove (m68k-amigaos-gcc 16.2.0b) turns the loop
 *     for (i = P; i > 0; --i) v[i] = v[i - 1];
 * at -O2 into an inline FORWARD copy (loop distribution makes it a
 * memmove, which that back end expands as memcpy), corrupting v. An
 * explicit memmove() goes to the C library's, which is right. Found
 * 8 October 2026: sntrup761 gave wrong keys on the 68k (and in qemu-m68k
 * from the same object, so not AC090). */

/* out = 1/in in R/3; 0 if invertible, else -1 */
static int R3_recip(small *out, const small *in)
{
    small f[P + 1], g[P + 1], v[P + 1], r[P + 1];
    int i, loop, delta, sign, swap, t;

    for (i = 0; i < P + 1; ++i) v[i] = 0;
    for (i = 0; i < P + 1; ++i) r[i] = 0;
    r[0] = 1;
    for (i = 0; i < P; ++i) f[i] = 0;
    f[0] = 1; f[P - 1] = f[P] = -1;
    for (i = 0; i < P; ++i) g[P - 1 - i] = in[i];
    g[P] = 0;
    delta = 1;
    for (loop = 0; loop < 2 * P - 1; ++loop) {
        memmove(v + 1, v, P * sizeof v[0]);     /* v = x v (see the note above R3_recip) */
        v[0] = 0;
        sign = -g[0] * f[0];
        swap = negative_mask16((int16_t)-delta) & nonzero_mask16(g[0]);
        delta ^= swap & (delta ^ -delta);
        delta += 1;
        for (i = 0; i < P + 1; ++i) {
            t = swap & (f[i] ^ g[i]); f[i] ^= (small)t; g[i] ^= (small)t;
            t = swap & (v[i] ^ r[i]); v[i] ^= (small)t; r[i] ^= (small)t;
        }
        for (i = 0; i < P + 1; ++i) g[i] = F3_freeze(g[i] + sign * f[i]);
        for (i = 0; i < P + 1; ++i) r[i] = F3_freeze(r[i] + sign * v[i]);
        memmove(g, g + 1, P * sizeof g[0]);     /* g = g / x */
        g[P] = 0;
    }
    sign = f[0];
    for (i = 0; i < P; ++i) out[i] = (small)(sign * v[P - 1 - i]);
    t = nonzero_mask16((int16_t)delta);
    memset(f, 0, sizeof f); memset(g, 0, sizeof g); memset(v, 0, sizeof v); memset(r, 0, sizeof r);
    return t;
}

/* out = 1/(3 in) in R/q; 0 if invertible, else -1 */
static int Rq_recip3(Fq *out, const small *in)
{
    Fq f[P + 1], g[P + 1], v[P + 1], r[P + 1];
    int i, loop, delta, swap, t;
    int32_t f0, g0;
    Fq scale;

    for (i = 0; i < P + 1; ++i) v[i] = 0;
    for (i = 0; i < P + 1; ++i) r[i] = 0;
    r[0] = Fq_recip(3);
    for (i = 0; i < P; ++i) f[i] = 0;
    f[0] = 1; f[P - 1] = f[P] = -1;
    for (i = 0; i < P; ++i) g[P - 1 - i] = in[i];
    g[P] = 0;
    delta = 1;
    for (loop = 0; loop < 2 * P - 1; ++loop) {
        memmove(v + 1, v, P * sizeof v[0]);     /* v = x v (see the note above R3_recip) */
        v[0] = 0;
        swap = negative_mask16((int16_t)-delta) & nonzero_mask16(g[0]);
        delta ^= swap & (delta ^ -delta);
        delta += 1;
        for (i = 0; i < P + 1; ++i) {
            t = swap & (f[i] ^ g[i]); f[i] ^= (Fq)t; g[i] ^= (Fq)t;
            t = swap & (v[i] ^ r[i]); v[i] ^= (Fq)t; r[i] ^= (Fq)t;
        }
        f0 = f[0];
        g0 = g[0];
        for (i = 0; i < P + 1; ++i) g[i] = Fq_freeze(f0 * g[i] - g0 * f[i]);
        for (i = 0; i < P + 1; ++i) r[i] = Fq_freeze(f0 * r[i] - g0 * v[i]);
        memmove(g, g + 1, P * sizeof g[0]);     /* g = g / x */
        g[P] = 0;
    }
    scale = Fq_recip(f[0]);
    for (i = 0; i < P; ++i) out[i] = Fq_freeze(scale * (int32_t)v[P - 1 - i]);
    t = nonzero_mask16((int16_t)delta);
    memset(f, 0, sizeof f); memset(g, 0, sizeof g); memset(v, 0, sizeof v); memset(r, 0, sizeof r);
    return t;
}

/* ---- encodings ---- */

static void Encode(uint8_t *out, const uint16_t *R, const uint16_t *M, int len)
{
    if (len == 1) {
        uint16_t r = R[0], m = M[0];
        while (m > 1) {
            *out++ = (uint8_t)r;
            r >>= 8;
            m = (uint16_t)((m + 255) >> 8);
        }
    }
    if (len > 1) {
        uint16_t R2[(len + 1) / 2], M2[(len + 1) / 2];
        int i;
        for (i = 0; i < len - 1; i += 2) {
            uint32_t m0 = M[i];
            uint32_t r = R[i] + R[i + 1] * m0;
            uint32_t m = M[i + 1] * m0;
            while (m >= 16384) {
                *out++ = (uint8_t)r;
                r >>= 8;
                m = (m + 255) >> 8;
            }
            R2[i / 2] = (uint16_t)r;
            M2[i / 2] = (uint16_t)m;
        }
        if (i < len) {
            R2[i / 2] = R[i];
            M2[i / 2] = M[i];
        }
        Encode(out, R2, M2, (len + 1) / 2);
    }
}

static void Decode(uint16_t *out, const uint8_t *S, const uint16_t *M, int len)
{
    if (len == 1) {
        if (M[0] == 1)
            *out = 0;
        else if (M[0] <= 256)
            *out = u32_mod_u14(S[0], M[0]);
        else
            *out = u32_mod_u14(S[0] + (((uint16_t)S[1]) << 8), M[0]);
    }
    if (len > 1) {
        uint16_t R2[(len + 1) / 2], M2[(len + 1) / 2], bottomr[len / 2];
        uint32_t bottomt[len / 2];
        int i;
        for (i = 0; i < len - 1; i += 2) {
            uint32_t m = M[i] * (uint32_t)M[i + 1];
            if (m > 256 * 16383) {
                bottomt[i / 2] = 256 * 256;
                bottomr[i / 2] = (uint16_t)(S[0] + 256 * S[1]);
                S += 2;
                M2[i / 2] = (uint16_t)((((m + 255) >> 8) + 255) >> 8);
            } else if (m >= 16384) {
                bottomt[i / 2] = 256;
                bottomr[i / 2] = S[0];
                S += 1;
                M2[i / 2] = (uint16_t)((m + 255) >> 8);
            } else {
                bottomt[i / 2] = 1;
                bottomr[i / 2] = 0;
                M2[i / 2] = (uint16_t)m;
            }
        }
        if (i < len)
            M2[i / 2] = M[i];
        Decode(R2, S, M2, (len + 1) / 2);
        for (i = 0; i < len - 1; i += 2) {
            uint32_t r = bottomr[i / 2], r1;
            uint16_t r0;
            r += bottomt[i / 2] * R2[i / 2];
            u32_divmod_u14(&r1, &r0, r, M[i]);
            r1 = u32_mod_u14(r1, M[i + 1]);   /* only for invalid input */
            *out++ = r0;
            *out++ = (uint16_t)r1;
        }
        if (i < len)
            *out++ = R2[i / 2];
    }
}

static void Small_encode(uint8_t *s, const small *f)
{
    int i;
    for (i = 0; i < P / 4; ++i) {
        unsigned x = (unsigned)(*f++ + 1);
        x += (unsigned)(*f++ + 1) << 2;
        x += (unsigned)(*f++ + 1) << 4;
        x += (unsigned)(*f++ + 1) << 6;
        *s++ = (uint8_t)x;
    }
    *s++ = (uint8_t)(*f++ + 1);
}

static void Small_decode(small *f, const uint8_t *s)
{
    uint8_t x;
    int i;
    for (i = 0; i < P / 4; ++i) {
        x = *s++;
        *f++ = (small)((x & 3) - 1); x >>= 2;
        *f++ = (small)((x & 3) - 1); x >>= 2;
        *f++ = (small)((x & 3) - 1); x >>= 2;
        *f++ = (small)((x & 3) - 1);
    }
    x = *s++;
    *f++ = (small)((x & 3) - 1);
}

static void Rq_encode(uint8_t *s, const Fq *r)
{
    uint16_t R[P], M[P];
    int i;
    for (i = 0; i < P; ++i) R[i] = (uint16_t)(r[i] + Q12);
    for (i = 0; i < P; ++i) M[i] = Q;
    Encode(s, R, M, P);
}

static void Rq_decode(Fq *r, const uint8_t *s)
{
    uint16_t R[P], M[P];
    int i;
    for (i = 0; i < P; ++i) M[i] = Q;
    Decode(R, s, M, P);
    for (i = 0; i < P; ++i) r[i] = (Fq)(((Fq)R[i]) - Q12);
}

static void Rounded_encode(uint8_t *s, const Fq *r)
{
    uint16_t R[P], M[P];
    int i;
    for (i = 0; i < P; ++i) R[i] = (uint16_t)(((r[i] + Q12) * 10923) >> 15);
    for (i = 0; i < P; ++i) M[i] = (Q + 2) / 3;
    Encode(s, R, M, P);
}

static void Rounded_decode(Fq *r, const uint8_t *s)
{
    uint16_t R[P], M[P];
    int i;
    for (i = 0; i < P; ++i) M[i] = (Q + 2) / 3;
    Decode(R, s, M, P);
    for (i = 0; i < P; ++i) r[i] = (Fq)(R[i] * 3 - Q12);
}

/* ---- randomness, from a seed ---- */

typedef struct {
    uint8_t buf[4 * P];
    size_t at;
    uint8_t seed[OC_SEED_BYTES];
    uint64_t block;
} oc_rng;

static void rng_init(oc_rng *g, const uint8_t seed[OC_SEED_BYTES])
{
    memcpy(g->seed, seed, OC_SEED_BYTES);
    g->at = sizeof g->buf;
    g->block = 0;
}

static void rng_bytes(oc_rng *g, uint8_t *out, size_t n)
{
    while (n) {
        size_t k;
        if (g->at == sizeof g->buf) {
            /* the stream in pieces: the 8-byte nonce is "sntrup76", the
             * ChaCha20 counter continues across them */
            static const uint8_t label[8] = { 's','n','t','r','u','p','7','6' };
            memset(g->buf, 0, sizeof g->buf);
            oc_chacha20_xor(g->buf, NULL, sizeof g->buf, g->seed, label, g->block);
            g->block += sizeof g->buf / 64;
            g->at = 0;
        }
        k = sizeof g->buf - g->at;
        if (k > n) k = n;
        memcpy(out, g->buf + g->at, k);
        g->at += k;
        out += k;
        n -= k;
    }
}

static uint32_t urandom32(oc_rng *g)
{
    uint8_t c[4];
    rng_bytes(g, c, 4);
    return (uint32_t)c[0] | (uint32_t)c[1] << 8 | (uint32_t)c[2] << 16 | (uint32_t)c[3] << 24;
}

#define MINMAX(a, b) do {                                          \
        int32_t ab_ = (b) ^ (a), c_ = (int32_t)((int64_t)(b) - (int64_t)(a)); \
        c_ ^= ab_ & (c_ ^ (b));                                     \
        c_ >>= 31;                                                  \
        c_ &= ab_;                                                  \
        (a) ^= c_;                                                  \
        (b) ^= c_;                                                  \
    } while (0)

/* djbsort's portable network: constant time */
static void sort_int32(int32_t *x, int n)
{
    int top, p, q, r, i;
    if (n < 2) return;
    top = 1;
    while (top < n - top) top += top;
    for (p = top; p > 0; p >>= 1) {
        for (i = 0; i < n - p; ++i)
            if (!(i & p))
                MINMAX(x[i], x[i + p]);
        i = 0;
        for (q = top; q > p; q >>= 1) {
            for (; i < n - q; ++i) {
                if (!(i & p)) {
                    int32_t a = x[i + p];
                    for (r = q; r > p; r >>= 1)
                        MINMAX(a, x[i + r]);
                    x[i + p] = a;
                }
            }
        }
    }
}

static void sort_uint32(uint32_t *x, int n)
{
    int j;
    for (j = 0; j < n; ++j) x[j] ^= 0x80000000u;
    sort_int32((int32_t *)x, n);
    for (j = 0; j < n; ++j) x[j] ^= 0x80000000u;
}

static void Short_random(small *out, oc_rng *g)
{
    uint32_t L[P];
    int i;
    for (i = 0; i < P; ++i) L[i] = urandom32(g);
    for (i = 0; i < W; ++i) L[i] = L[i] & (uint32_t)-2;
    for (i = W; i < P; ++i) L[i] = (L[i] & (uint32_t)-3) | 1;
    sort_uint32(L, P);
    for (i = 0; i < P; ++i) out[i] = (small)((L[i] & 3) - 1);
    memset(L, 0, sizeof L);
}

static void Small_random(small *out, oc_rng *g)
{
    int i;
    for (i = 0; i < P; ++i) out[i] = (small)((((urandom32(g) & 0x3fffffff) * 3) >> 30) - 1);
}

/* ---- hashes ---- */

static void Hash_prefix(uint8_t *out, int b, const uint8_t *in, size_t inlen)
{
    OCSHA512 ctx;
    uint8_t h[64], pre = (uint8_t)b;
    oc_sha512_init(&ctx);
    oc_sha512_update(&ctx, &pre, 1);
    oc_sha512_update(&ctx, in, inlen);
    oc_sha512_final(&ctx, h);
    memcpy(out, h, 32);
    oc_cleanse(h, sizeof h);
}

static void HashConfirm(uint8_t *h, const uint8_t *r_enc, const uint8_t *cache)
{
    uint8_t x[HASH_BYTES * 2];
    Hash_prefix(x, 3, r_enc, SMALL_BYTES);
    memcpy(x + HASH_BYTES, cache, HASH_BYTES);
    Hash_prefix(h, 2, x, sizeof x);
}

static void HashSession(uint8_t *k, int b, const uint8_t *y, const uint8_t *z)
{
    uint8_t x[HASH_BYTES + CT_BYTES];
    Hash_prefix(x, 3, y, SMALL_BYTES);
    memcpy(x + HASH_BYTES, z, CT_BYTES);
    Hash_prefix(k, b, x, sizeof x);
}

/* ---- the KEM ---- */

static int Weightw_mask(const small *r)
{
    int weight = 0, i;
    for (i = 0; i < P; ++i) weight += r[i] & 1;
    return nonzero_mask16((int16_t)(weight - W));
}

/* c = Round(h r), encoded, then the confirmation hash */
static void Hide(uint8_t *c, uint8_t *r_enc, const small *r, const uint8_t *pk,
                 const uint8_t *cache)
{
    Fq h[P], hr[P];
    int i;
    Small_encode(r_enc, r);
    Rq_decode(h, pk);
    Rq_mult_small(hr, h, r);
    for (i = 0; i < P; ++i) hr[i] = (Fq)(hr[i] - F3_freeze(hr[i]));
    Rounded_encode(c, hr);
    HashConfirm(c + ROUNDED_BYTES, r_enc, cache);
    memset(hr, 0, sizeof hr);
}

void oc_sntrup761_keypair(uint8_t pk[OC_SNTRUP761_PK_BYTES], uint8_t sk[OC_SNTRUP761_SK_BYTES],
                          const uint8_t seed[OC_SEED_BYTES])
{
    small f[P], g[P], v[P];
    Fq finv[P], h[P];
    oc_rng rng;
    rng_init(&rng, seed);
    do {
        Small_random(g, &rng);
    } while (R3_recip(v, g) != 0);
    Short_random(f, &rng);
    Rq_recip3(finv, f);
    Rq_mult_small(h, finv, g);
    Rq_encode(pk, h);
    Small_encode(sk, f);
    Small_encode(sk + SMALL_BYTES, v);
    memcpy(sk + 2 * SMALL_BYTES, pk, PK_BYTES);
    rng_bytes(&rng, sk + 2 * SMALL_BYTES + PK_BYTES, SMALL_BYTES);              /* rho */
    Hash_prefix(sk + 2 * SMALL_BYTES + PK_BYTES + SMALL_BYTES, 4, pk, PK_BYTES); /* cache */
    oc_cleanse(f, sizeof f); oc_cleanse(g, sizeof g); oc_cleanse(v, sizeof v);
    oc_cleanse(finv, sizeof finv); oc_cleanse(&rng, sizeof rng);
}

void oc_sntrup761_enc(uint8_t ct[OC_SNTRUP761_CT_BYTES], uint8_t ss[OC_SNTRUP761_SS_BYTES],
                      const uint8_t pk[OC_SNTRUP761_PK_BYTES], const uint8_t seed[OC_SEED_BYTES])
{
    small r[P];
    oc_rng rng;
    uint8_t r_enc[SMALL_BYTES], cache[HASH_BYTES];
    Hash_prefix(cache, 4, pk, PK_BYTES);
    rng_init(&rng, seed);
    Short_random(r, &rng);
    Hide(ct, r_enc, r, pk, cache);
    HashSession(ss, 1, r_enc, ct);
    oc_cleanse(r, sizeof r); oc_cleanse(r_enc, sizeof r_enc); oc_cleanse(&rng, sizeof rng);
}

void oc_sntrup761_dec(uint8_t ss[OC_SNTRUP761_SS_BYTES], const uint8_t ct[OC_SNTRUP761_CT_BYTES],
                      const uint8_t sk[OC_SNTRUP761_SK_BYTES])
{
    small f[P], v[P], e[P], ev[P], r[P];
    Fq c[P], cf[P];
    uint8_t cnew[CT_BYTES];
    const uint8_t *pk = sk + 2 * SMALL_BYTES;
    const uint8_t *rho = pk + PK_BYTES;
    const uint8_t *cache = rho + SMALL_BYTES;
    uint8_t r_enc[SMALL_BYTES];
    uint16_t diff = 0;
    int mask, i;

    Small_decode(f, sk);
    Small_decode(v, sk + SMALL_BYTES);
    Rounded_decode(c, ct);
    Rq_mult_small(cf, c, f);
    for (i = 0; i < P; ++i) cf[i] = Fq_freeze(3 * cf[i]);
    for (i = 0; i < P; ++i) e[i] = F3_freeze(cf[i]);
    R3_mult(ev, e, v);
    mask = Weightw_mask(ev);              /* 0 if weight w, else -1 */
    for (i = 0; i < W; ++i) r[i] = (small)(((ev[i] ^ 1) & ~mask) ^ 1);
    for (i = W; i < P; ++i) r[i] = (small)(ev[i] & ~mask);

    Hide(cnew, r_enc, r, pk, cache);
    for (i = 0; i < CT_BYTES; ++i) diff |= (uint16_t)(ct[i] ^ cnew[i]);
    mask = (int)(1 & ((diff - 1) >> 8)) - 1;   /* 0 if the same, else -1 */
    for (i = 0; i < SMALL_BYTES; ++i) r_enc[i] ^= (uint8_t)(mask & (r_enc[i] ^ rho[i]));
    HashSession(ss, 1 + mask, r_enc, ct);

    oc_cleanse(f, sizeof f); oc_cleanse(v, sizeof v); oc_cleanse(e, sizeof e);
    oc_cleanse(ev, sizeof ev); oc_cleanse(r, sizeof r); oc_cleanse(cf, sizeof cf);
    oc_cleanse(r_enc, sizeof r_enc); oc_cleanse(cnew, sizeof cnew);
}
