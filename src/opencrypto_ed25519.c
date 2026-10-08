/* OpenCrypto: Ed25519 signature verification (RFC 8032, section 5.1.7).
 * Copyright (c) 2026 Dalsin Limited. MIT.
 *
 * Verification handles only public values (a host key, a signature, the
 * signed data), so it need not run in constant time. The check is the
 * cofactorless one OpenSSH and PuTTY make: encode([S]B - [k]A) == R, with
 * S below L and A and R canonical. */
#include "opencrypto/opencrypto.h"
#include "oc_fe25519.h"

/* d = -121665/121666, 2d and sqrt(-1), as 32 bytes little-endian */
static const uint8_t ed_d[32] = {
    0xa3,0x78,0x59,0x13,0xca,0x4d,0xeb,0x75,0xab,0xd8,0x41,0x41,0x4d,0x0a,0x70,0x00,
    0x98,0xe8,0x79,0x77,0x79,0x40,0xc7,0x8c,0x73,0xfe,0x6f,0x2b,0xee,0x6c,0x03,0x52 };
static const uint8_t ed_d2[32] = {
    0x59,0xf1,0xb2,0x26,0x94,0x9b,0xd6,0xeb,0x56,0xb1,0x83,0x82,0x9a,0x14,0xe0,0x00,
    0x30,0xd1,0xf3,0xee,0xf2,0x80,0x8e,0x19,0xe7,0xfc,0xdf,0x56,0xdc,0xd9,0x06,0x24 };
static const uint8_t ed_sqrtm1[32] = {
    0xb0,0xa0,0x0e,0x4a,0x27,0x1b,0xee,0xc4,0x78,0xe4,0x2f,0xad,0x06,0x18,0x43,0x2f,
    0xa7,0xd7,0xfb,0x3d,0x99,0x00,0x4d,0x2b,0x0b,0xdf,0xc1,0x4f,0x80,0x24,0x83,0x2b };
/* the base point B, encoded: y = 4/5, x even */
static const uint8_t ed_base[32] = {
    0x58,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,
    0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66 };
/* the group order L = 2^252 + 27742317777372353535851937790883648493 */
static const uint8_t ed_L[32] = {
    0xed,0xd3,0xf5,0x5c,0x1a,0x63,0x12,0x58,0xd6,0x9c,0xf7,0xa2,0xde,0xf9,0xde,0x14,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x10 };

/* a point in extended coordinates: X, Y, Z, T with x = X/Z, y = Y/Z, xy = T/Z */
typedef oc_gf ge[4];

static int gf_equal(const oc_gf a, const oc_gf b)
{
    uint8_t x[32], y[32];
    gf_pack(x, a);
    gf_pack(y, b);
    return oc_ct_equal(x, y, 32);
}

static int gf_parity(const oc_gf a)
{
    uint8_t x[32];
    gf_pack(x, a);
    return x[0] & 1;
}

static void ge_add(ge p, ge q)
{
    oc_gf a, b, c, d, t, e, f, g, h, d2;
    gf_unpack(d2, ed_d2);
    gf_sub(a, p[1], p[0]); gf_sub(t, q[1], q[0]); gf_mul(a, a, t);
    gf_add(b, p[0], p[1]); gf_add(t, q[0], q[1]); gf_mul(b, b, t);
    gf_mul(c, p[3], q[3]); gf_mul(c, c, d2);
    gf_mul(d, p[2], q[2]); gf_add(d, d, d);
    gf_sub(e, b, a); gf_sub(f, d, c); gf_add(g, d, c); gf_add(h, b, a);
    gf_mul(p[0], e, f); gf_mul(p[1], h, g); gf_mul(p[2], g, f); gf_mul(p[3], e, h);
}

static void ge_cswap(ge p, ge q, int bit)
{
    int i;
    for (i = 0; i < 4; ++i) gf_cswap(p[i], q[i], bit);
}

/* p = [s]q for a 256-bit little-endian s; q is used up */
static void ge_scalarmult(ge p, ge q, const uint8_t s[32])
{
    int i, bit;
    gf_zero(p[0]); gf_one(p[1]); gf_one(p[2]); gf_zero(p[3]);
    for (i = 255; i >= 0; --i) {
        bit = (s[i >> 3] >> (i & 7)) & 1;
        ge_cswap(p, q, bit);
        ge_add(q, p);
        ge_add(p, p);
        ge_cswap(p, q, bit);
    }
}

static void ge_encode(uint8_t r[32], ge p)
{
    oc_gf tx, ty, zi;
    gf_inv(zi, p[2]);
    gf_mul(tx, p[0], zi);
    gf_mul(ty, p[1], zi);
    gf_pack(r, ty);
    r[31] ^= (uint8_t)(gf_parity(tx) << 7);
}

/* RFC 8032 section 5.1.3; 0 when s is not a point's canonical encoding */
static int ge_decode(ge p, const uint8_t s[32])
{
    oc_gf u, v, v3, x, t, chk, d, one, neg;
    uint8_t y[32];
    int sign = s[31] >> 7;

    gf_unpack(p[1], s);
    gf_pack(y, p[1]);
    y[31] |= (uint8_t)(sign << 7);
    if (!oc_ct_equal(y, s, 32))
        return 0;                       /* y >= p */
    gf_one(one);
    gf_one(p[2]);
    gf_unpack(d, ed_d);
    gf_sqr(u, p[1]);
    gf_mul(v, u, d);
    gf_sub(u, u, one);                  /* u = y^2 - 1 */
    gf_add(v, v, one);                  /* v = d y^2 + 1 */
    gf_sqr(v3, v);
    gf_mul(v3, v3, v);                  /* v^3 */
    gf_sqr(t, v3);
    gf_mul(t, t, v);
    gf_mul(t, t, u);                    /* u v^7 */
    gf_pow2523(t, t);
    gf_mul(t, t, v3);
    gf_mul(x, t, u);                    /* u v^3 (u v^7)^((p-5)/8) */
    gf_sqr(chk, x);
    gf_mul(chk, chk, v);
    if (!gf_equal(chk, u)) {
        gf_zero(neg);
        gf_sub(neg, neg, u);
        if (!gf_equal(chk, neg))
            return 0;
        gf_unpack(t, ed_sqrtm1);
        gf_mul(x, x, t);
    }
    gf_zero(neg);
    if (gf_equal(x, neg) && sign)
        return 0;
    if (gf_parity(x) != sign)
        gf_sub(x, neg, x);
    gf_set(p[0], x);
    gf_mul(p[3], p[0], p[1]);
    return 1;
}

/* a < L, both 32 bytes little-endian */
static int sc_below_L(const uint8_t a[32])
{
    int i;
    for (i = 31; i >= 0; --i) {
        if (a[i] < ed_L[i]) return 1;
        if (a[i] > ed_L[i]) return 0;
    }
    return 0;
}

/* out = h mod L, h 64 bytes little-endian: bit by bit, high first */
static void sc_reduce64(uint8_t out[32], const uint8_t h[64])
{
    uint32_t r[9], l[9], t[9];
    int bit, i;
    uint64_t c;
    for (i = 0; i < 9; ++i) r[i] = 0;
    for (i = 0; i < 8; ++i)
        l[i] = (uint32_t)ed_L[4 * i] | (uint32_t)ed_L[4 * i + 1] << 8 |
               (uint32_t)ed_L[4 * i + 2] << 16 | (uint32_t)ed_L[4 * i + 3] << 24;
    l[8] = 0;
    for (bit = 511; bit >= 0; --bit) {
        /* r = 2r + bit */
        for (i = 8; i > 0; --i) r[i] = r[i] << 1 | r[i - 1] >> 31;
        r[0] = r[0] << 1 | ((h[bit >> 3] >> (bit & 7)) & 1);
        /* r -= L when r >= L */
        c = 0;
        for (i = 0; i < 9; ++i) {
            uint64_t d = (uint64_t)r[i] - l[i] - c;
            t[i] = (uint32_t)d;
            c = (d >> 32) & 1;
        }
        if (!c)
            for (i = 0; i < 9; ++i) r[i] = t[i];
    }
    for (i = 0; i < 32; ++i) out[i] = (uint8_t)(r[i >> 2] >> (8 * (i & 3)));
}

int oc_ed25519_verify(const uint8_t sig[64], const uint8_t pk[32],
                      const void *msg, size_t length)
{
    ge a, b, p;
    OCSHA512 ctx;
    uint8_t h[64], k[32], check[32];
    oc_gf zero;

    if (!sc_below_L(sig + 32))
        return 0;
    if (!ge_decode(a, pk))
        return 0;
    /* -A */
    gf_zero(zero);
    gf_sub(a[0], zero, a[0]);
    gf_sub(a[3], zero, a[3]);
    oc_sha512_init(&ctx);
    oc_sha512_update(&ctx, sig, 32);
    oc_sha512_update(&ctx, pk, 32);
    oc_sha512_update(&ctx, msg, length);
    oc_sha512_final(&ctx, h);
    sc_reduce64(k, h);
    ge_scalarmult(p, a, k);             /* [k](-A) */
    if (!ge_decode(b, ed_base))
        return 0;
    ge_scalarmult(a, b, sig + 32);      /* [S]B */
    ge_add(p, a);
    ge_encode(check, p);
    return oc_ct_equal(check, sig, 32) ? 1 : 0;
}
