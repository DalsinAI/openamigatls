/* OpenCrypto: arithmetic in GF(2^255 - 19), shared by X25519 and Ed25519.
 * Internal to OpenCrypto (each user includes it once).
 * Copyright (c) 2026 Dalsin Limited. MIT.
 *
 * Sixteen limbs of 16 bits, signed, as TweetNaCl lays them out, kept in
 * 32-bit ints between operations; a product is summed in 64 bits. Every
 * operation does the same work whatever the values (no branch or index on
 * a secret), so X25519 runs in constant time. A product of two 32-bit ints
 * into 64 bits is one MULS.L on a 68020 to 68040 (and host code on
 * AmigaChrome); 68060 builds call libgcc for it. */
#ifndef OC_FE25519_H
#define OC_FE25519_H

#include <stdint.h>
#include <string.h>

typedef int32_t oc_gf[16];

static void gf_set(oc_gf r, const oc_gf a)
{
    int i;
    for (i = 0; i < 16; ++i) r[i] = a[i];
}

static void gf_zero(oc_gf r)
{
    int i;
    for (i = 0; i < 16; ++i) r[i] = 0;
}

static void gf_one(oc_gf r)
{
    gf_zero(r);
    r[0] = 1;
}

/* limbs to [0, 2^16), the carry out of the top one folded back as 38
 * times itself (2^256 = 38 mod p); the arithmetic shifts floor */
static void gf_carry64(int64_t t[16])
{
    int i;
    int64_t c;
    for (i = 0; i < 16; ++i) {
        c = t[i] >> 16;
        t[i] -= c * 65536;
        if (i < 15) t[i + 1] += c;
        else t[0] += 38 * c;
    }
}

static void gf_add(oc_gf o, const oc_gf a, const oc_gf b)
{
    int i;
    for (i = 0; i < 16; ++i) o[i] = a[i] + b[i];
}

static void gf_sub(oc_gf o, const oc_gf a, const oc_gf b)
{
    int i;
    for (i = 0; i < 16; ++i) o[i] = a[i] - b[i];
}

static void gf_mul(oc_gf o, const oc_gf a, const oc_gf b)
{
    int64_t t[31];
    int i, j;
    for (i = 0; i < 31; ++i) t[i] = 0;
    for (i = 0; i < 16; ++i)
        for (j = 0; j < 16; ++j)
            t[i + j] += (int64_t)a[i] * b[j];
    for (i = 0; i < 15; ++i) t[i] += 38 * t[i + 16];
    gf_carry64(t);
    gf_carry64(t);
    for (i = 0; i < 16; ++i) o[i] = (int32_t)t[i];
}

static void gf_sqr(oc_gf o, const oc_gf a)
{
    gf_mul(o, a, a);
}

/* r = a, b = b when bit is 0; swapped when it is 1 (bit is 0 or 1) */
static void gf_cswap(oc_gf a, oc_gf b, int bit)
{
    int32_t mask = -(int32_t)bit, t;
    int i;
    for (i = 0; i < 16; ++i) {
        t = mask & (a[i] ^ b[i]);
        a[i] ^= t;
        b[i] ^= t;
    }
}

/* the canonical 32 bytes (little-endian, below p) */
static void gf_pack(uint8_t o[32], const oc_gf n)
{
    int64_t t[16], m[16], c, mask;
    int i, k;
    for (i = 0; i < 16; ++i) t[i] = n[i];
    gf_carry64(t);
    gf_carry64(t);
    /* add 2p = 2^256 - 38, so the value is positive */
    t[0] += 0xffda;
    for (i = 1; i < 16; ++i) t[i] += 0xffff;
    /* fold everything at and above bit 255 back in as 19 times itself */
    for (k = 0; k < 3; ++k) {
        for (i = 0; i < 15; ++i) {
            c = t[i] >> 16;
            t[i] -= c * 65536;
            t[i + 1] += c;
        }
        c = t[15] >> 15;
        t[15] -= c * 32768;
        t[0] += 19 * c;
    }
    for (i = 0; i < 15; ++i) {
        c = t[i] >> 16;
        t[i] -= c * 65536;
        t[i + 1] += c;
    }
    /* now 0 <= t < 2^255: take p away when t >= p (t + 19 reaches 2^255) */
    for (i = 0; i < 16; ++i) m[i] = t[i];
    m[0] += 19;
    for (i = 0; i < 15; ++i) {
        c = m[i] >> 16;
        m[i] -= c * 65536;
        m[i + 1] += c;
    }
    c = m[15] >> 15;
    m[15] -= c * 32768;
    mask = -c;
    for (i = 0; i < 16; ++i) t[i] ^= mask & (t[i] ^ m[i]);
    for (i = 0; i < 16; ++i) {
        o[2 * i] = (uint8_t)(t[i] & 0xff);
        o[2 * i + 1] = (uint8_t)((t[i] >> 8) & 0xff);
    }
}

/* 32 bytes, the top bit ignored */
static void gf_unpack(oc_gf o, const uint8_t n[32])
{
    int i;
    for (i = 0; i < 16; ++i) o[i] = n[2 * i] | ((int32_t)n[2 * i + 1] << 8);
    o[15] &= 0x7fff;
}

/* a^(p-2) = 1/a (0 for 0) */
static void gf_inv(oc_gf o, const oc_gf a)
{
    oc_gf c;
    int i;
    gf_set(c, a);
    for (i = 253; i >= 0; --i) {
        gf_sqr(c, c);
        if (i != 2 && i != 4) gf_mul(c, c, a);
    }
    gf_set(o, c);
}

/* a^((p-5)/8) = a^(2^252 - 3), for square roots */
static __attribute__((unused)) void gf_pow2523(oc_gf o, const oc_gf a)
{
    oc_gf c;
    int i;
    gf_set(c, a);
    for (i = 250; i >= 0; --i) {
        gf_sqr(c, c);
        if (i != 1) gf_mul(c, c, a);
    }
    gf_set(o, c);
}

#endif
