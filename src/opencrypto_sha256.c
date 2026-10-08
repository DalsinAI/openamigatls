#include "opencrypto/opencrypto.h"

#include <string.h>

static uint32_t rotr(uint32_t x, unsigned n)
{
    return (x >> n) | (x << (32 - n));
}

static uint32_t load_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) |
           ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) |
           (uint32_t)p[3];
}

static void store_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static void transform(OCSHA256 *ctx, const uint8_t block[64])
{
    static const uint32_t k[64] = {
        0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,
        0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
        0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,
        0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
        0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,
        0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
        0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,
        0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
        0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,
        0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
        0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,
        0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
        0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,
        0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
        0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,
        0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u
    };
    uint32_t w[64];
    uint32_t a,b,c,d,e,f,g,h;
    unsigned i;

    for (i = 0; i < 16; ++i)
        w[i] = load_be32(block + i * 4);
    for (i = 16; i < 64; ++i) {
        uint32_t s0 = rotr(w[i-15],7) ^ rotr(w[i-15],18) ^ (w[i-15] >> 3);
        uint32_t s1 = rotr(w[i-2],17) ^ rotr(w[i-2],19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }

    a=ctx->h[0]; b=ctx->h[1]; c=ctx->h[2]; d=ctx->h[3];
    e=ctx->h[4]; f=ctx->h[5]; g=ctx->h[6]; h=ctx->h[7];

    for (i = 0; i < 64; ++i) {
        uint32_t S1 = rotr(e,6) ^ rotr(e,11) ^ rotr(e,25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t t1 = h + S1 + ch + k[i] + w[i];
        uint32_t S0 = rotr(a,2) ^ rotr(a,13) ^ rotr(a,22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = S0 + maj;
        h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }

    ctx->h[0]+=a; ctx->h[1]+=b; ctx->h[2]+=c; ctx->h[3]+=d;
    ctx->h[4]+=e; ctx->h[5]+=f; ctx->h[6]+=g; ctx->h[7]+=h;
}

void oc_sha256_init(OCSHA256 *ctx)
{
    static const uint32_t iv[8] = {
        0x6a09e667u,0xbb67ae85u,0x3c6ef372u,0xa54ff53au,
        0x510e527fu,0x9b05688cu,0x1f83d9abu,0x5be0cd19u
    };
    memcpy(ctx->h, iv, sizeof iv);
    ctx->total_bytes = 0;
    ctx->block_used = 0;
}

void oc_sha256_update(OCSHA256 *ctx, const void *data, size_t length)
{
    const uint8_t *p = (const uint8_t *)data;
    ctx->total_bytes += length;
    while (length) {
        size_t n = 64 - ctx->block_used;
        if (n > length) n = length;
        memcpy(ctx->block + ctx->block_used, p, n);
        ctx->block_used += n;
        p += n;
        length -= n;
        if (ctx->block_used == 64) {
            transform(ctx, ctx->block);
            ctx->block_used = 0;
        }
    }
}

void oc_sha256_final(OCSHA256 *ctx, uint8_t out[32])
{
    uint64_t bits = ctx->total_bytes * 8u;
    unsigned i;

    ctx->block[ctx->block_used++] = 0x80;
    if (ctx->block_used > 56) {
        memset(ctx->block + ctx->block_used, 0, 64 - ctx->block_used);
        transform(ctx, ctx->block);
        ctx->block_used = 0;
    }
    memset(ctx->block + ctx->block_used, 0, 56 - ctx->block_used);
    for (i = 0; i < 8; ++i)
        ctx->block[63 - i] = (uint8_t)(bits >> (i * 8));
    transform(ctx, ctx->block);
    for (i = 0; i < 8; ++i)
        store_be32(out + i * 4, ctx->h[i]);
    oc_cleanse(ctx, sizeof *ctx);
}

void oc_sha256(const void *data, size_t length, uint8_t out[32])
{
    OCSHA256 ctx;
    oc_sha256_init(&ctx);
    oc_sha256_update(&ctx, data, length);
    oc_sha256_final(&ctx, out);
}

void oc_hmac_sha256(const void *key, size_t key_length,
                    const void *data, size_t data_length,
                    uint8_t out[32])
{
    uint8_t key_block[64], inner[32], ipad[64], opad[64];
    OCSHA256 ctx;
    size_t i;

    memset(key_block, 0, sizeof key_block);
    if (key_length > 64) {
        oc_sha256(key, key_length, key_block);
    } else if (key_length) {
        memcpy(key_block, key, key_length);
    }
    for (i = 0; i < 64; ++i) {
        ipad[i] = (uint8_t)(key_block[i] ^ 0x36);
        opad[i] = (uint8_t)(key_block[i] ^ 0x5c);
    }

    oc_sha256_init(&ctx);
    oc_sha256_update(&ctx, ipad, sizeof ipad);
    oc_sha256_update(&ctx, data, data_length);
    oc_sha256_final(&ctx, inner);

    oc_sha256_init(&ctx);
    oc_sha256_update(&ctx, opad, sizeof opad);
    oc_sha256_update(&ctx, inner, sizeof inner);
    oc_sha256_final(&ctx, out);

    oc_cleanse(key_block, sizeof key_block);
    oc_cleanse(inner, sizeof inner);
    oc_cleanse(ipad, sizeof ipad);
    oc_cleanse(opad, sizeof opad);
}

int oc_hkdf_sha256(const void *salt, size_t salt_length,
                   const void *ikm, size_t ikm_length,
                   const void *info, size_t info_length,
                   void *out, size_t out_length)
{
    uint8_t zero_salt[32] = {0};
    uint8_t prk[32], t[32];
    uint8_t *dst = (uint8_t *)out;
    size_t done = 0, tlen = 0;
    unsigned counter = 1;

    if (!out && out_length)
        return -1;
    if (out_length > 255u * 32u)
        return -1;
    if (!salt && !salt_length) {
        salt = zero_salt;
        salt_length = sizeof zero_salt;
    }
    oc_hmac_sha256(salt, salt_length, ikm, ikm_length, prk);

    while (done < out_length) {
        uint8_t block[32 + 1024 + 1];
        size_t n = 0, take;
        if (info_length > 1024) {
            oc_cleanse(prk, sizeof prk);
            return -1;
        }
        if (tlen) {
            memcpy(block + n, t, tlen);
            n += tlen;
        }
        if (info_length) {
            memcpy(block + n, info, info_length);
            n += info_length;
        }
        block[n++] = (uint8_t)counter;
        oc_hmac_sha256(prk, sizeof prk, block, n, t);
        tlen = sizeof t;
        take = out_length - done;
        if (take > sizeof t) take = sizeof t;
        memcpy(dst + done, t, take);
        done += take;
        ++counter;
        oc_cleanse(block, sizeof block);
    }

    oc_cleanse(prk, sizeof prk);
    oc_cleanse(t, sizeof t);
    return 0;
}

int oc_ct_equal(const void *a, const void *b, size_t length)
{
    const volatile uint8_t *x = (const volatile uint8_t *)a;
    const volatile uint8_t *y = (const volatile uint8_t *)b;
    uint8_t diff = 0;
    while (length--)
        diff |= (uint8_t)(*x++ ^ *y++);
    return diff == 0;
}

void oc_cleanse(void *p, size_t length)
{
    volatile uint8_t *q = (volatile uint8_t *)p;
    while (length--)
        *q++ = 0;
}
