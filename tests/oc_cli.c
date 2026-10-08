/* OpenCrypto: a line-at-a-time front end for tests/differential.py, which
 * checks OpenCrypto against Python's cryptography package (OpenSSL) on
 * random inputs. Each line: an operation and its arguments in hex ("-" is
 * empty); the answer: hex, or 0/1.
 * Copyright (c) 2026 Dalsin Limited. MIT. */
#include "opencrypto/opencrypto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static size_t unhex(uint8_t *out, const char *s)
{
    size_t i, n;
    if (!strcmp(s, "-")) return 0;
    n = strlen(s) / 2;
    for (i = 0; i < n; ++i) {
        unsigned v;
        sscanf(s + 2 * i, "%2x", &v);
        out[i] = (uint8_t)v;
    }
    return n;
}

static void put(const uint8_t *b, size_t n)
{
    size_t i;
    for (i = 0; i < n; ++i) printf("%02x", b[i]);
    if (!n) printf("-");
    printf("\n");
}

int main(void)
{
    static char line[1 << 20];
    static uint8_t a[1 << 17], b[1 << 17], c[1 << 17], d[1 << 17], e[1 << 17], f[1 << 17], out[1 << 17];
    char *w[8];
    while (fgets(line, sizeof line, stdin)) {
        int n = 0;
        char *p = strtok(line, " \n");
        while (p && n < 8) { w[n++] = p; p = strtok(NULL, " \n"); }
        if (!n) continue;
        if (!strcmp(w[0], "x25519")) {
            unhex(a, w[1]); unhex(b, w[2]);
            int r = oc_x25519(out, a, b);
            if (r) printf("refused\n"); else put(out, 32);
        } else if (!strcmp(w[0], "ed25519")) {
            size_t ml = unhex(c, w[3]);
            unhex(a, w[1]); unhex(b, w[2]);
            printf("%d\n", oc_ed25519_verify(a, b, c, ml));
        } else if (!strcmp(w[0], "chacha")) {       /* key nonce counter(hex u64) data */
            size_t l = unhex(c, w[4]);
            unhex(a, w[1]); unhex(b, w[2]);
            oc_chacha20_xor(out, c, l, a, b, strtoull(w[3], NULL, 16));
            put(out, l);
        } else if (!strcmp(w[0], "poly")) {
            size_t l = unhex(b, w[2]);
            unhex(a, w[1]);
            oc_poly1305(out, b, l, a);
            put(out, 16);
        } else if (!strcmp(w[0], "aes")) {          /* mode key iv data */
            size_t kl = unhex(a, w[2]), l = unhex(out, w[4]);
            unhex(b, w[3]);
            if (oc_aes(out, l, a, kl, b, atoi(w[1]))) printf("refused\n"); else put(out, l);
        } else if (!strcmp(w[0], "rsa")) {          /* n e sig */
            size_t nl = unhex(a, w[1]), el = unhex(b, w[2]);
            unhex(c, w[3]);
            if (oc_rsa_public(out, c, a, nl, b, el)) printf("refused\n"); else put(out, nl);
        } else if (!strcmp(w[0], "ecdsa")) {        /* curve qx qy r s hash */
            size_t hl;
            unhex(a, w[2]); unhex(b, w[3]); unhex(c, w[4]); unhex(d, w[5]);
            hl = unhex(e, w[6]);
            printf("%d\n", oc_ecdsa_verify(atoi(w[1]), a, b, c, d, e, hl));
        } else if (!strcmp(w[0], "sha256")) {
            size_t l = unhex(a, w[1]);
            oc_sha256(a, l, out); put(out, 32);
        } else if (!strcmp(w[0], "sha512")) {
            size_t l = unhex(a, w[1]);
            oc_sha512(a, l, out); put(out, 64);
        } else if (!strcmp(w[0], "kem")) {          /* seed seed2: pk, then ct, ss, then dec ss */
            static uint8_t pk[OC_SNTRUP761_PK_BYTES], sk[OC_SNTRUP761_SK_BYTES], ct[OC_SNTRUP761_CT_BYTES];
            uint8_t ss[32], ss2[32];
            unhex(a, w[1]); unhex(b, w[2]);
            oc_sntrup761_keypair(pk, sk, a);
            oc_sntrup761_enc(ct, ss, pk, b);
            oc_sntrup761_dec(ss2, ct, sk);
            printf("%d\n", !memcmp(ss, ss2, 32));
        } else {
            printf("unknown\n");
        }
        (void)f;
        fflush(stdout);
    }
    return 0;
}
