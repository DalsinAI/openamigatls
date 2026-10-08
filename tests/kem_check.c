/* sntrup761 through its public calls only (the file compiled on its own),
 * hashes printed for comparing machines.
 * Copyright (c) 2026 Dalsin Limited. MIT. */
#include <stdio.h>
#include <string.h>
#include "opencrypto/opencrypto.h"

static void h(const char *name, const void *p, size_t n)
{
    uint8_t d[32];
    int i;
    oc_sha256(p, n, d);
    printf("%-12s ", name);
    for (i = 0; i < 8; i++) printf("%02x", d[i]);
    printf("\n");
}

int main(void)
{
    static uint8_t pk[OC_SNTRUP761_PK_BYTES], sk[OC_SNTRUP761_SK_BYTES], ct[OC_SNTRUP761_CT_BYTES];
    uint8_t seed[32], ss[32], ss2[32];
    int i;
    printf("code at %p, data at %p, stack at %p\n", (void *)oc_sntrup761_keypair, (void *)pk, (void *)seed);
    for (i = 0; i < 32; i++) seed[i] = (uint8_t)i;
    oc_sntrup761_keypair(pk, sk, seed);
    h("pk", pk, sizeof pk);
    h("sk", sk, sizeof sk);
    seed[0] ^= 0x80;
    oc_sntrup761_enc(ct, ss, pk, seed);
    h("ct", ct, sizeof ct);
    h("ss", ss, 32);
    oc_sntrup761_dec(ss2, ct, sk);
    h("ss2", ss2, 32);
    printf("dec == enc   %d\n", !memcmp(ss, ss2, 32));
    return 0;
}
