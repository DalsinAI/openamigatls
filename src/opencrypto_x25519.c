/* OpenCrypto: X25519 (RFC 7748), constant time.
 * Copyright (c) 2026 Dalsin Limited. MIT.
 *
 * The Montgomery ladder over the u coordinate, 255 steps whatever the
 * scalar, with conditional swaps by mask (no branch on a secret bit). */
#include "opencrypto/opencrypto.h"
#include "oc_fe25519.h"

static const oc_gf gf_121665 = { 0xDB41, 1 };

int oc_x25519(uint8_t out[OC_X25519_BYTES], const uint8_t scalar[OC_X25519_BYTES],
              const uint8_t point[OC_X25519_BYTES])
{
    uint8_t z[32];
    oc_gf x, a, b, c, d, e, f;
    int i, bit;
    uint8_t zero = 0;

    for (i = 0; i < 32; ++i) z[i] = scalar[i];
    z[31] = (uint8_t)((z[31] & 127) | 64);
    z[0] &= 248;
    gf_unpack(x, point);
    gf_set(b, x);
    gf_zero(c);
    gf_zero(d);
    gf_one(a);
    gf_one(d);
    for (i = 254; i >= 0; --i) {
        bit = (z[i >> 3] >> (i & 7)) & 1;
        gf_cswap(a, b, bit);
        gf_cswap(c, d, bit);
        gf_add(e, a, c);
        gf_sub(a, a, c);
        gf_add(c, b, d);
        gf_sub(b, b, d);
        gf_sqr(d, e);
        gf_sqr(f, a);
        gf_mul(a, c, a);
        gf_mul(c, b, e);
        gf_add(e, a, c);
        gf_sub(a, a, c);
        gf_sqr(b, a);
        gf_sub(c, d, f);
        gf_mul(a, c, gf_121665);
        gf_add(a, a, d);
        gf_mul(c, c, a);
        gf_mul(a, d, f);
        gf_mul(d, b, x);
        gf_sqr(b, e);
        gf_cswap(a, b, bit);
        gf_cswap(c, d, bit);
    }
    gf_inv(c, c);
    gf_mul(a, a, c);
    gf_pack(out, a);
    oc_cleanse(z, sizeof z);
    oc_cleanse(a, sizeof a); oc_cleanse(b, sizeof b); oc_cleanse(c, sizeof c);
    oc_cleanse(d, sizeof d); oc_cleanse(e, sizeof e); oc_cleanse(f, sizeof f);
    /* an all-zero result (a small-order point) is refused, as RFC 7748
     * section 6.1 allows and SSH requires; the test is constant time */
    for (i = 0; i < 32; ++i) zero |= out[i];
    return zero ? 0 : -1;
}

void oc_x25519_base(uint8_t out[OC_X25519_BYTES], const uint8_t scalar[OC_X25519_BYTES])
{
    static const uint8_t nine[32] = { 9 };
    (void)oc_x25519(out, scalar, nine);
}
