#include "opencrypto/opencrypto.h"

#include <string.h>

static uint64_t rotr64(uint64_t x, unsigned n)
{
    return (x >> n) | (x << (64 - n));
}

static uint64_t load_be64(const uint8_t *p)
{
    return ((uint64_t)p[0] << 56) |
           ((uint64_t)p[1] << 48) |
           ((uint64_t)p[2] << 40) |
           ((uint64_t)p[3] << 32) |
           ((uint64_t)p[4] << 24) |
           ((uint64_t)p[5] << 16) |
           ((uint64_t)p[6] << 8) |
           (uint64_t)p[7];
}

static void store_be64(uint8_t *p, uint64_t v)
{
    p[0] = (uint8_t)(v >> 56);
    p[1] = (uint8_t)(v >> 48);
    p[2] = (uint8_t)(v >> 40);
    p[3] = (uint8_t)(v >> 32);
    p[4] = (uint8_t)(v >> 24);
    p[5] = (uint8_t)(v >> 16);
    p[6] = (uint8_t)(v >> 8);
    p[7] = (uint8_t)v;
}

static void sha512_transform(OCSHA512 *ctx, const uint8_t block[128])
{
    static const uint64_t k[80] = {
        UINT64_C(0x428a2f98d728ae22),UINT64_C(0x7137449123ef65cd),
        UINT64_C(0xb5c0fbcfec4d3b2f),UINT64_C(0xe9b5dba58189dbbc),
        UINT64_C(0x3956c25bf348b538),UINT64_C(0x59f111f1b605d019),
        UINT64_C(0x923f82a4af194f9b),UINT64_C(0xab1c5ed5da6d8118),
        UINT64_C(0xd807aa98a3030242),UINT64_C(0x12835b0145706fbe),
        UINT64_C(0x243185be4ee4b28c),UINT64_C(0x550c7dc3d5ffb4e2),
        UINT64_C(0x72be5d74f27b896f),UINT64_C(0x80deb1fe3b1696b1),
        UINT64_C(0x9bdc06a725c71235),UINT64_C(0xc19bf174cf692694),
        UINT64_C(0xe49b69c19ef14ad2),UINT64_C(0xefbe4786384f25e3),
        UINT64_C(0x0fc19dc68b8cd5b5),UINT64_C(0x240ca1cc77ac9c65),
        UINT64_C(0x2de92c6f592b0275),UINT64_C(0x4a7484aa6ea6e483),
        UINT64_C(0x5cb0a9dcbd41fbd4),UINT64_C(0x76f988da831153b5),
        UINT64_C(0x983e5152ee66dfab),UINT64_C(0xa831c66d2db43210),
        UINT64_C(0xb00327c898fb213f),UINT64_C(0xbf597fc7beef0ee4),
        UINT64_C(0xc6e00bf33da88fc2),UINT64_C(0xd5a79147930aa725),
        UINT64_C(0x06ca6351e003826f),UINT64_C(0x142929670a0e6e70),
        UINT64_C(0x27b70a8546d22ffc),UINT64_C(0x2e1b21385c26c926),
        UINT64_C(0x4d2c6dfc5ac42aed),UINT64_C(0x53380d139d95b3df),
        UINT64_C(0x650a73548baf63de),UINT64_C(0x766a0abb3c77b2a8),
        UINT64_C(0x81c2c92e47edaee6),UINT64_C(0x92722c851482353b),
        UINT64_C(0xa2bfe8a14cf10364),UINT64_C(0xa81a664bbc423001),
        UINT64_C(0xc24b8b70d0f89791),UINT64_C(0xc76c51a30654be30),
        UINT64_C(0xd192e819d6ef5218),UINT64_C(0xd69906245565a910),
        UINT64_C(0xf40e35855771202a),UINT64_C(0x106aa07032bbd1b8),
        UINT64_C(0x19a4c116b8d2d0c8),UINT64_C(0x1e376c085141ab53),
        UINT64_C(0x2748774cdf8eeb99),UINT64_C(0x34b0bcb5e19b48a8),
        UINT64_C(0x391c0cb3c5c95a63),UINT64_C(0x4ed8aa4ae3418acb),
        UINT64_C(0x5b9cca4f7763e373),UINT64_C(0x682e6ff3d6b2b8a3),
        UINT64_C(0x748f82ee5defb2fc),UINT64_C(0x78a5636f43172f60),
        UINT64_C(0x84c87814a1f0ab72),UINT64_C(0x8cc702081a6439ec),
        UINT64_C(0x90befffa23631e28),UINT64_C(0xa4506cebde82bde9),
        UINT64_C(0xbef9a3f7b2c67915),UINT64_C(0xc67178f2e372532b),
        UINT64_C(0xca273eceea26619c),UINT64_C(0xd186b8c721c0c207),
        UINT64_C(0xeada7dd6cde0eb1e),UINT64_C(0xf57d4f7fee6ed178),
        UINT64_C(0x06f067aa72176fba),UINT64_C(0x0a637dc5a2c898a6),
        UINT64_C(0x113f9804bef90dae),UINT64_C(0x1b710b35131c471b),
        UINT64_C(0x28db77f523047d84),UINT64_C(0x32caab7b40c72493),
        UINT64_C(0x3c9ebe0a15c9bebc),UINT64_C(0x431d67c49c100d4c),
        UINT64_C(0x4cc5d4becb3e42b6),UINT64_C(0x597f299cfc657e2a),
        UINT64_C(0x5fcb6fab3ad6faec),UINT64_C(0x6c44198c4a475817)
    };
    uint64_t w[80];
    uint64_t a,b,c,d,e,f,g,h;
    unsigned i;

    for (i = 0; i < 16; ++i)
        w[i] = load_be64(block + i * 8);
    for (i = 16; i < 80; ++i) {
        uint64_t s0 = rotr64(w[i-15],1) ^ rotr64(w[i-15],8) ^ (w[i-15] >> 7);
        uint64_t s1 = rotr64(w[i-2],19) ^ rotr64(w[i-2],61) ^ (w[i-2] >> 6);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }

    a=ctx->h[0]; b=ctx->h[1]; c=ctx->h[2]; d=ctx->h[3];
    e=ctx->h[4]; f=ctx->h[5]; g=ctx->h[6]; h=ctx->h[7];

    for (i = 0; i < 80; ++i) {
        uint64_t S1 = rotr64(e,14) ^ rotr64(e,18) ^ rotr64(e,41);
        uint64_t ch = (e & f) ^ ((~e) & g);
        uint64_t t1 = h + S1 + ch + k[i] + w[i];
        uint64_t S0 = rotr64(a,28) ^ rotr64(a,34) ^ rotr64(a,39);
        uint64_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint64_t t2 = S0 + maj;
        h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }

    ctx->h[0]+=a; ctx->h[1]+=b; ctx->h[2]+=c; ctx->h[3]+=d;
    ctx->h[4]+=e; ctx->h[5]+=f; ctx->h[6]+=g; ctx->h[7]+=h;
}

static void sha512_init_common(OCSHA512 *ctx, int sha384)
{
    static const uint64_t iv512[8] = {
        UINT64_C(0x6a09e667f3bcc908),UINT64_C(0xbb67ae8584caa73b),
        UINT64_C(0x3c6ef372fe94f82b),UINT64_C(0xa54ff53a5f1d36f1),
        UINT64_C(0x510e527fade682d1),UINT64_C(0x9b05688c2b3e6c1f),
        UINT64_C(0x1f83d9abfb41bd6b),UINT64_C(0x5be0cd19137e2179)
    };
    static const uint64_t iv384[8] = {
        UINT64_C(0xcbbb9d5dc1059ed8),UINT64_C(0x629a292a367cd507),
        UINT64_C(0x9159015a3070dd17),UINT64_C(0x152fecd8f70e5939),
        UINT64_C(0x67332667ffc00b31),UINT64_C(0x8eb44a8768581511),
        UINT64_C(0xdb0c2e0d64f98fa7),UINT64_C(0x47b5481dbefa4fa4)
    };
    memcpy(ctx->h, sha384 ? iv384 : iv512, sizeof ctx->h);
    ctx->total_bytes = 0;
    ctx->block_used = 0;
}

static void sha512_update(OCSHA512 *ctx, const void *data, size_t length)
{
    const uint8_t *p = (const uint8_t *)data;
    ctx->total_bytes += (uint64_t)length;
    while (length) {
        size_t n = 128 - ctx->block_used;
        if (n > length) n = length;
        memcpy(ctx->block + ctx->block_used, p, n);
        ctx->block_used += n;
        p += n;
        length -= n;
        if (ctx->block_used == 128) {
            sha512_transform(ctx, ctx->block);
            ctx->block_used = 0;
        }
    }
}

static void sha512_final_common(OCSHA512 *ctx, uint8_t *out, size_t out_bytes)
{
    uint64_t bits = ctx->total_bytes << 3;
    unsigned i;

    ctx->block[ctx->block_used++] = 0x80;
    if (ctx->block_used > 112) {
        memset(ctx->block + ctx->block_used, 0, 128 - ctx->block_used);
        sha512_transform(ctx, ctx->block);
        ctx->block_used = 0;
    }
    memset(ctx->block + ctx->block_used, 0, 112 - ctx->block_used);
    memset(ctx->block + 112, 0, 8);
    store_be64(ctx->block + 120, bits);
    sha512_transform(ctx, ctx->block);

    for (i = 0; i < out_bytes / 8; ++i)
        store_be64(out + i * 8, ctx->h[i]);
    oc_cleanse(ctx, sizeof *ctx);
}

void oc_sha512_init(OCSHA512 *ctx)
{
    sha512_init_common(ctx, 0);
}

void oc_sha512_update(OCSHA512 *ctx, const void *data, size_t length)
{
    sha512_update(ctx, data, length);
}

void oc_sha512_final(OCSHA512 *ctx, uint8_t out[OC_SHA512_BYTES])
{
    sha512_final_common(ctx, out, 64);
}

/* The compression function over whole blocks, the chaining value kept as
 * 64 bytes, big-endian (the same bytes on every host): what a caller with
 * its own buffering (PuTTY's SHA-512) needs, and AC090's host code. */
void oc_sha512_blocks(uint8_t state[OC_SHA512_BYTES], const void *data, size_t nblocks)
{
    OCSHA512 ctx;
    const uint8_t *p = (const uint8_t *)data;
    unsigned i;
    for (i = 0; i < 8; ++i)
        ctx.h[i] = load_be64(state + i * 8);
    for (; nblocks; --nblocks, p += 128)
        sha512_transform(&ctx, p);
    for (i = 0; i < 8; ++i)
        store_be64(state + i * 8, ctx.h[i]);
    oc_cleanse(&ctx, sizeof ctx);
}

void oc_sha384(const void *data, size_t length, uint8_t out[48])
{
    OCSHA512 ctx;
    sha512_init_common(&ctx, 1);
    sha512_update(&ctx, data, length);
    sha512_final_common(&ctx, out, 48);
}

void oc_sha512(const void *data, size_t length, uint8_t out[64])
{
    OCSHA512 ctx;
    sha512_init_common(&ctx, 0);
    sha512_update(&ctx, data, length);
    sha512_final_common(&ctx, out, 64);
}

void oc_hmac_sha384(const void *key, size_t key_length,
                    const void *data, size_t data_length,
                    uint8_t out[48])
{
    uint8_t key_block[128], inner[48], ipad[128], opad[128];
    OCSHA512 ctx;
    size_t i;

    memset(key_block, 0, sizeof key_block);
    if (key_length > sizeof key_block)
        oc_sha384(key, key_length, key_block);
    else if (key_length)
        memcpy(key_block, key, key_length);

    for (i = 0; i < sizeof key_block; ++i) {
        ipad[i] = (uint8_t)(key_block[i] ^ 0x36);
        opad[i] = (uint8_t)(key_block[i] ^ 0x5c);
    }

    sha512_init_common(&ctx, 1);
    sha512_update(&ctx, ipad, sizeof ipad);
    sha512_update(&ctx, data, data_length);
    sha512_final_common(&ctx, inner, sizeof inner);

    sha512_init_common(&ctx, 1);
    sha512_update(&ctx, opad, sizeof opad);
    sha512_update(&ctx, inner, sizeof inner);
    sha512_final_common(&ctx, out, 48);

    oc_cleanse(key_block, sizeof key_block);
    oc_cleanse(inner, sizeof inner);
    oc_cleanse(ipad, sizeof ipad);
    oc_cleanse(opad, sizeof opad);
}

int oc_hkdf_sha384(const void *salt, size_t salt_length,
                   const void *ikm, size_t ikm_length,
                   const void *info, size_t info_length,
                   void *out, size_t out_length)
{
    uint8_t zero_salt[48] = {0};
    uint8_t prk[48], t[48];
    uint8_t *dst = (uint8_t *)out;
    size_t done = 0, tlen = 0;
    unsigned counter = 1;

    if (!out && out_length)
        return -1;
    if (out_length > 255u * 48u || info_length > 1024)
        return -1;
    if (!salt && !salt_length) {
        salt = zero_salt;
        salt_length = sizeof zero_salt;
    }

    oc_hmac_sha384(salt, salt_length, ikm, ikm_length, prk);

    while (done < out_length) {
        uint8_t block[48 + 1024 + 1];
        size_t n = 0, take;
        if (tlen) {
            memcpy(block + n, t, tlen);
            n += tlen;
        }
        if (info_length) {
            memcpy(block + n, info, info_length);
            n += info_length;
        }
        block[n++] = (uint8_t)counter;
        oc_hmac_sha384(prk, sizeof prk, block, n, t);
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
