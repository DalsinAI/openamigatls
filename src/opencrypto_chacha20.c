/* OpenCrypto: ChaCha20 (the original 64-bit nonce and counter, as SSH's
 * chacha20-poly1305@openssh.com uses it), Poly1305, and the seed
 * expansion the key generators use. Constant time.
 * Copyright (c) 2026 Dalsin Limited. MIT. */
#include "opencrypto/opencrypto.h"

#include <string.h>

static uint32_t le32(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static void put_le32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

#define ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define QR(a, b, c, d)                                 \
    a += b; d ^= a; d = ROTL(d, 16);                   \
    c += d; b ^= c; b = ROTL(b, 12);                   \
    a += b; d ^= a; d = ROTL(d, 8);                    \
    c += d; b ^= c; b = ROTL(b, 7)

static void chacha20_block(uint8_t out[64], const uint32_t in[16])
{
    uint32_t x[16];
    int i;
    for (i = 0; i < 16; ++i) x[i] = in[i];
    for (i = 0; i < 10; ++i) {
        QR(x[0], x[4], x[8], x[12]);
        QR(x[1], x[5], x[9], x[13]);
        QR(x[2], x[6], x[10], x[14]);
        QR(x[3], x[7], x[11], x[15]);
        QR(x[0], x[5], x[10], x[15]);
        QR(x[1], x[6], x[11], x[12]);
        QR(x[2], x[7], x[8], x[13]);
        QR(x[3], x[4], x[9], x[14]);
    }
    for (i = 0; i < 16; ++i) put_le32(out + 4 * i, x[i] + in[i]);
}

void oc_chacha20_xor(uint8_t *out, const uint8_t *in, size_t length,
                     const uint8_t key[32], const uint8_t nonce[8], uint64_t counter)
{
    uint32_t s[16];
    uint8_t ks[64];
    size_t i, n;
    s[0] = 0x61707865u; s[1] = 0x3320646eu; s[2] = 0x79622d32u; s[3] = 0x6b206574u;
    for (i = 0; i < 8; ++i) s[4 + i] = le32(key + 4 * i);
    s[14] = le32(nonce);
    s[15] = le32(nonce + 4);
    while (length) {
        s[12] = (uint32_t)counter;
        s[13] = (uint32_t)(counter >> 32);
        chacha20_block(ks, s);
        n = length < 64 ? length : 64;
        for (i = 0; i < n; ++i) out[i] = (uint8_t)(in ? in[i] ^ ks[i] : ks[i]);
        out += n;
        if (in) in += n;
        length -= n;
        ++counter;
    }
    oc_cleanse(s, sizeof s);
    oc_cleanse(ks, sizeof ks);
}

void oc_expand_seed(uint8_t *out, size_t length, const uint8_t seed[OC_SEED_BYTES],
                    const char label[8])
{
    oc_chacha20_xor(out, NULL, length, seed, (const uint8_t *)label, 0);
}

/* Poly1305 in five 26-bit limbs (as poly1305-donna's 32-bit version) */
void oc_poly1305(uint8_t tag[16], const void *data, size_t length, const uint8_t key[32])
{
    const uint8_t *m = (const uint8_t *)data;
    uint32_t r0, r1, r2, r3, r4, s1, s2, s3, s4;
    uint32_t h0 = 0, h1 = 0, h2 = 0, h3 = 0, h4 = 0, c, g0, g1, g2, g3, g4, mask;
    uint64_t d0, d1, d2, d3, d4, f;
    uint8_t last[16];
    const uint32_t m26 = 0x3ffffff;

    r0 = le32(key) & 0x3ffffff;
    r1 = (le32(key + 3) >> 2) & 0x3ffff03;
    r2 = (le32(key + 6) >> 4) & 0x3ffc0ff;
    r3 = (le32(key + 9) >> 6) & 0x3f03fff;
    r4 = (le32(key + 12) >> 8) & 0x00fffff;
    s1 = r1 * 5; s2 = r2 * 5; s3 = r3 * 5; s4 = r4 * 5;

    while (length) {
        const uint8_t *b = m;
        uint32_t hibit = 1u << 24;
        if (length < 16) {
            memset(last, 0, sizeof last);
            memcpy(last, m, length);
            last[length] = 1;
            b = last;
            hibit = 0;
        }
        h0 += le32(b) & m26;
        h1 += (le32(b + 3) >> 2) & m26;
        h2 += (le32(b + 6) >> 4) & m26;
        h3 += (le32(b + 9) >> 6) & m26;
        h4 += (le32(b + 12) >> 8) | hibit;
        d0 = (uint64_t)h0 * r0 + (uint64_t)h1 * s4 + (uint64_t)h2 * s3 + (uint64_t)h3 * s2 + (uint64_t)h4 * s1;
        d1 = (uint64_t)h0 * r1 + (uint64_t)h1 * r0 + (uint64_t)h2 * s4 + (uint64_t)h3 * s3 + (uint64_t)h4 * s2;
        d2 = (uint64_t)h0 * r2 + (uint64_t)h1 * r1 + (uint64_t)h2 * r0 + (uint64_t)h3 * s4 + (uint64_t)h4 * s3;
        d3 = (uint64_t)h0 * r3 + (uint64_t)h1 * r2 + (uint64_t)h2 * r1 + (uint64_t)h3 * r0 + (uint64_t)h4 * s4;
        d4 = (uint64_t)h0 * r4 + (uint64_t)h1 * r3 + (uint64_t)h2 * r2 + (uint64_t)h3 * r1 + (uint64_t)h4 * r0;
        c = (uint32_t)(d0 >> 26); h0 = (uint32_t)d0 & m26;
        d1 += c; c = (uint32_t)(d1 >> 26); h1 = (uint32_t)d1 & m26;
        d2 += c; c = (uint32_t)(d2 >> 26); h2 = (uint32_t)d2 & m26;
        d3 += c; c = (uint32_t)(d3 >> 26); h3 = (uint32_t)d3 & m26;
        d4 += c; c = (uint32_t)(d4 >> 26); h4 = (uint32_t)d4 & m26;
        h0 += c * 5; c = h0 >> 26; h0 &= m26;
        h1 += c;
        if (length < 16) break;
        m += 16;
        length -= 16;
    }

    c = h1 >> 26; h1 &= m26;
    h2 += c; c = h2 >> 26; h2 &= m26;
    h3 += c; c = h3 >> 26; h3 &= m26;
    h4 += c; c = h4 >> 26; h4 &= m26;
    h0 += c * 5; c = h0 >> 26; h0 &= m26;
    h1 += c;

    g0 = h0 + 5; c = g0 >> 26; g0 &= m26;
    g1 = h1 + c; c = g1 >> 26; g1 &= m26;
    g2 = h2 + c; c = g2 >> 26; g2 &= m26;
    g3 = h3 + c; c = g3 >> 26; g3 &= m26;
    g4 = h4 + c - (1u << 26);

    mask = (g4 >> 31) - 1;              /* all ones when h >= 2^130 - 5 */
    g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask;
    mask = ~mask;
    h0 = (h0 & mask) | g0; h1 = (h1 & mask) | g1; h2 = (h2 & mask) | g2;
    h3 = (h3 & mask) | g3; h4 = (h4 & mask) | g4;

    h0 = h0 | (h1 << 26);
    h1 = (h1 >> 6) | (h2 << 20);
    h2 = (h2 >> 12) | (h3 << 14);
    h3 = (h3 >> 18) | (h4 << 8);

    f = (uint64_t)h0 + le32(key + 16);              put_le32(tag, (uint32_t)f);
    f = (uint64_t)h1 + le32(key + 20) + (f >> 32);  put_le32(tag + 4, (uint32_t)f);
    f = (uint64_t)h2 + le32(key + 24) + (f >> 32);  put_le32(tag + 8, (uint32_t)f);
    f = (uint64_t)h3 + le32(key + 28) + (f >> 32);  put_le32(tag + 12, (uint32_t)f);
    oc_cleanse(last, sizeof last);
}
