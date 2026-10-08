/* OpenCrypto's sntrup761 against PuTTY's own (crypto/ntru.c, PuTTY 0.85,
 * itself interoperable with OpenSSH), on the PC: each side's key pair with
 * the other side's encapsulation, the shared secrets compared.
 *   tests/interop_putty.sh builds it against a PuTTY build tree.
 * Copyright (c) 2026 Dalsin Limited. MIT. PuTTY is MIT, Simon Tatham et al. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "putty.h"
#include "ssh.h"
#include "opencrypto/opencrypto.h"

/* PuTTY's code asks for random bytes here */
void random_read(void *buf, size_t size)
{
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f || fread(buf, 1, size, f) != size) { fprintf(stderr, "no /dev/urandom\n"); exit(2); }
    fclose(f);
}

void modalfatalbox(const char *fmt, ...)
{
    (void)fmt;
    fprintf(stderr, "PuTTY: fatal error\n");
    exit(2);
}

static void seed(uint8_t s[32]) { random_read(s, 32); }

int main(int argc, char **argv)
{
    int rounds = argc > 1 ? atoi(argv[1]) : 50, i, fails = 0;
    for (i = 0; i < rounds; ++i) {
        /* PuTTY's key pair, OpenCrypto's encapsulation, PuTTY's decapsulation */
        strbuf *ek = strbuf_new(), *k = strbuf_new();
        uint8_t ct[OC_SNTRUP761_CT_BYTES], ss[32], sd[32], pk[OC_SNTRUP761_PK_BYTES], sk[OC_SNTRUP761_SK_BYTES];
        pq_kem_dk *dk = pq_kem_keygen(&ssh_ntru, BinarySink_UPCAST(ek));
        if (ek->len != OC_SNTRUP761_PK_BYTES) { printf("PuTTY's pk is %u bytes\n", (unsigned)ek->len); return 2; }
        seed(sd);
        oc_sntrup761_enc(ct, ss, ek->u, sd);
        if (!pq_kem_decaps(dk, BinarySink_UPCAST(k), make_ptrlen(ct, sizeof ct)) || k->len != 32 || memcmp(k->u, ss, 32)) {
            printf("round %d: PuTTY's key pair, OpenCrypto's encapsulation: secrets differ\n", i);
            ++fails;
        }
        pq_kem_free_dk(dk);
        strbuf_free(ek);
        strbuf_free(k);

        /* OpenCrypto's key pair, PuTTY's encapsulation, OpenCrypto's decapsulation */
        {
            strbuf *c = strbuf_new(), *k2 = strbuf_new();
            seed(sd);
            oc_sntrup761_keypair(pk, sk, sd);
            if (!pq_kem_encaps(&ssh_ntru, BinarySink_UPCAST(c), BinarySink_UPCAST(k2), make_ptrlen(pk, sizeof pk))
                || c->len != OC_SNTRUP761_CT_BYTES) {
                printf("round %d: PuTTY refused OpenCrypto's public key\n", i);
                ++fails;
            } else {
                oc_sntrup761_dec(ss, c->u, sk);
                if (memcmp(ss, k2->u, 32)) {
                    printf("round %d: OpenCrypto's key pair, PuTTY's encapsulation: secrets differ\n", i);
                    ++fails;
                }
                /* PuTTY's ciphertext changed: OpenCrypto must not give PuTTY's secret */
                c->u[7] ^= 1;
                oc_sntrup761_dec(ss, c->u, sk);
                if (!memcmp(ss, k2->u, 32)) {
                    printf("round %d: a changed ciphertext still gave the secret\n", i);
                    ++fails;
                }
            }
            strbuf_free(c);
            strbuf_free(k2);
        }
    }
    printf("sntrup761 interop with PuTTY 0.85: %d rounds each way, %d failures\n", rounds, fails);
    return fails ? 1 : 0;
}
