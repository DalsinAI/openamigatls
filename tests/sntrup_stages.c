/* sntrup761's stages, one hash each, for comparing two machines (the PC
 * and the 68k): the same output means the same arithmetic.
 *   sntrup_stages > out.txt   (on both, then diff)
 * Copyright (c) 2026 Dalsin Limited. MIT. */
#include <stdio.h>
#ifdef __amigaos__
#include <proto/exec.h>
#endif
#include "../src/opencrypto_sntrup761.c"

static void h(const char *name, const void *p, size_t n)
{
    uint8_t d[32];
    int i;
    oc_sha256(p, n, d);
    printf("%-20s ", name);
    for (i = 0; i < 8; i++) printf("%02x", d[i]);
    printf("\n");
}

int main(void)
{
    static small f[P], g[P], v[P], r[P], e[P];
    static Fq finv[P], hh[P], c[P];
    static uint8_t pk[PK_BYTES], sk[SK_BYTES], ct[CT_BYTES], ss[32], ss2[32];
    static uint32_t L[P];
    uint8_t seed[32], buf[64];
    oc_rng rng;
    int i, rc, tries = 0;
    uint32_t acc = 0, q;
    uint16_t rr;

#ifdef __amigaos__
    {
        struct Task *t = FindTask(NULL);
        UBYTE here;
        printf("%-20s %lu of %lu\n", "stack free", (unsigned long)((ULONG)&here - (ULONG)t->tc_SPLower),
               (unsigned long)((ULONG)t->tc_SPUpper - (ULONG)t->tc_SPLower));
    }
#endif
    printf("code at %p, data at %p, stack at %p\n", (void *)oc_sntrup761_keypair, (void *)pk, (void *)seed);
    /* the small helpers on many values */
    for (i = 0; i < 200000; i++) {
        uint32_t x = (uint32_t)i * 2654435761u;
        u32_divmod_u14(&q, &rr, x, 4591);
        acc = acc * 31 + q * 7 + rr;
        acc = acc * 31 + i32_mod_u14((int32_t)x, 3);
        acc = acc * 31 + (uint16_t)Fq_freeze((int32_t)(x >> 6) - (1 << 25));
        acc = acc * 31 + (uint8_t)F3_freeze((int32_t)(x >> 16) - 30000);
    }
    printf("%-20s %08lx\n", "helpers", (unsigned long)acc);
    for (i = 0; i < P; i++) L[i] = (uint32_t)i * 2654435761u;
    sort_uint32(L, P);
    h("sort", L, sizeof L);
    printf("%-20s %d\n", "Fq_recip(3)", Fq_recip(3));

    for (i = 0; i < 32; i++) seed[i] = (uint8_t)i;
    rng_init(&rng, seed);
    rng_bytes(&rng, buf, 64);
    h("rng first 64", buf, 64);
    rng_init(&rng, seed);
    do {
        Small_random(g, &rng);
        rc = R3_recip(v, g);
        tries++;
    } while (rc != 0);
    printf("%-20s %d\n", "g tries", tries);
    h("g", g, sizeof g);
    h("v = 1/g mod 3", v, sizeof v);
    R3_mult(e, g, v);
    h("g v (want 1)", e, sizeof e);
    printf("%-20s %d %d %d\n", "g v [0..2]", e[0], e[1], e[2]);
    Short_random(f, &rng);
    h("f", f, sizeof f);
    Rq_recip3(finv, f);
    h("finv", finv, sizeof finv);
    Rq_mult_small(hh, finv, g);
    h("h", hh, sizeof hh);
    Rq_encode(pk, hh);
    h("pk", pk, PK_BYTES);
    Rq_decode(c, pk);
    printf("%-20s %d\n", "Rq decode == h", !memcmp(c, hh, sizeof c));
    for (i = 0; i < P; i++) c[i] = (Fq)(hh[i] - F3_freeze(hh[i]));
    Rounded_encode(ct, c);
    h("rounded", ct, ROUNDED_BYTES);
    {
        static Fq c2[P];
        Rounded_decode(c2, ct);
        printf("%-20s %d\n", "Rounded round trip", !memcmp(c2, c, sizeof c));
    }
    oc_sntrup761_keypair(pk, sk, seed);
    h("keypair pk", pk, PK_BYTES);
    h("keypair sk", sk, SK_BYTES);
    seed[0] ^= 0x80;
    oc_sntrup761_enc(ct, ss, pk, seed);
    h("enc ct", ct, CT_BYTES);
    oc_sntrup761_dec(ss2, ct, sk);
    printf("%-20s %d\n", "dec == enc", !memcmp(ss, ss2, 32));
    (void)r;
    return 0;
}
