/* OpenCrypto: the SSH primitives against published vectors, built for the
 * PC (ctest) and for the Amiga (build-amiga.sh: OpenCryptoVectors), so the
 * same checks run on both.
 *   X25519        RFC 7748 section 5.2 (two vectors, 1 and 1,000 iterations)
 *                 and section 6.1 (Alice and Bob)
 *   Ed25519       RFC 8032 section 7.1, tests 1 to 3, and altered copies
 *   ChaCha20      RFC 8439 section 2.3.2 (its block, in the 64-bit nonce form)
 *   Poly1305      RFC 8439 section 2.5.2
 *   SHA-256/512   FIPS 180 "abc" through the block functions
 *   sntrup761     key pair, encapsulation and decapsulation agree; a changed
 *                 ciphertext gives the implicit-rejection secret; and fixed
 *                 seeds give fixed bytes (OpenCrypto's own known answers, the
 *                 same on every machine: the PC's and the 68k's must match)
 *   AES           FIPS 197 appendix C (128, 192, 256), and each mode's
 *                 round trip
 *   RSA           a 2048-bit public operation against Python's pow()
 *   ECDSA         a P-256 signature from RFC 6979 section A.2.5
 * Copyright (c) 2026 Dalsin Limited. MIT. */
#include "opencrypto/opencrypto.h"
#include "vectors.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

static int failures, checks;

static void unhex(uint8_t *out, const char *s)
{
    size_t i, n = strlen(s) / 2;
    for (i = 0; i < n; ++i) {
        unsigned v;
        sscanf(s + 2 * i, "%2x", &v);
        out[i] = (uint8_t)v;
    }
}

static void tohex(char *out, const uint8_t *b, size_t n)
{
    size_t i;
    for (i = 0; i < n; ++i) sprintf(out + 2 * i, "%02x", b[i]);
}

static void check(int ok, const char *what)
{
    ++checks;
    if (!ok) {
        ++failures;
        printf("FAIL %s\n", what);
    }
}

static void check_hex(const uint8_t *got, size_t n, const char *want, const char *what)
{
    uint8_t w[512];
    unhex(w, want);
    check(strlen(want) == 2 * n && !memcmp(got, w, n), what);
    if (memcmp(got, w, n)) {
        char h[1025];
        tohex(h, got, n);
        printf("     got  %s\n     want %s\n", h, want);
    }
}

static void test_x25519(void)
{
    uint8_t k[32], u[32], out[32], a[32], b[32], pa[32], pb[32], s1[32], s2[32];
    int i;
    unhex(k, "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
    unhex(u, "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
    oc_x25519(out, k, u);
    check_hex(out, 32, "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552", "X25519 RFC 7748 5.2 vector 1");
    unhex(k, "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d");
    unhex(u, "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493");
    oc_x25519(out, k, u);
    check_hex(out, 32, "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957", "X25519 RFC 7748 5.2 vector 2");
    /* iterated: k = X25519(k, u), u = old k */
    memset(k, 0, 32); k[0] = 9;
    memcpy(u, k, 32);
    for (i = 1; i <= 1000; ++i) {
        oc_x25519(out, k, u);
        memcpy(u, k, 32);
        memcpy(k, out, 32);
        if (i == 1)
            check_hex(k, 32, "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079", "X25519 RFC 7748 5.2 after 1 iteration");
    }
    check_hex(k, 32, "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51", "X25519 RFC 7748 5.2 after 1,000 iterations");
    unhex(a, "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    unhex(b, "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
    oc_x25519_base(pa, a);
    oc_x25519_base(pb, b);
    check_hex(pa, 32, "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a", "X25519 RFC 7748 6.1 Alice's public key");
    check_hex(pb, 32, "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f", "X25519 RFC 7748 6.1 Bob's public key");
    oc_x25519(s1, a, pb);
    oc_x25519(s2, b, pa);
    check_hex(s1, 32, "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742", "X25519 RFC 7748 6.1 shared secret (Alice)");
    check_hex(s2, 32, "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742", "X25519 RFC 7748 6.1 shared secret (Bob)");
    /* a small-order point is refused */
    memset(u, 0, 32);
    check(oc_x25519(out, a, u) == -1, "X25519 refuses the zero point");
}

static void test_ed25519(void)
{
    static const struct { const char *pk, *msg, *sig; } v[] = {
        { "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
          "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b" },
        { "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
          "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00" },
        { "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025", "af82",
          "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a" },
    };
    uint8_t pk[32], msg[2], sig[64];
    size_t i;
    for (i = 0; i < sizeof v / sizeof v[0]; ++i) {
        char what[80];
        unhex(pk, v[i].pk);
        unhex(msg, v[i].msg);
        unhex(sig, v[i].sig);
        sprintf(what, "Ed25519 RFC 8032 7.1 test %u", (unsigned)i + 1);
        check(oc_ed25519_verify(sig, pk, msg, strlen(v[i].msg) / 2) == 1, what);
        sig[5] ^= 1;
        sprintf(what, "Ed25519 test %u with R altered: refused", (unsigned)i + 1);
        check(oc_ed25519_verify(sig, pk, msg, strlen(v[i].msg) / 2) == 0, what);
        sig[5] ^= 1;
        sig[40] ^= 1;
        sprintf(what, "Ed25519 test %u with S altered: refused", (unsigned)i + 1);
        check(oc_ed25519_verify(sig, pk, msg, strlen(v[i].msg) / 2) == 0, what);
        sig[40] ^= 1;
        sprintf(what, "Ed25519 test %u with the message altered: refused", (unsigned)i + 1);
        check(oc_ed25519_verify(sig, pk, (const uint8_t *)"x", 1) == 0, what);
    }
    /* S + L (non-canonical) refused */
    unhex(pk, v[0].pk);
    unhex(sig, v[0].sig);
    {
        static const uint8_t L[32] = { 0xed,0xd3,0xf5,0x5c,0x1a,0x63,0x12,0x58,0xd6,0x9c,0xf7,0xa2,0xde,0xf9,0xde,0x14,
                                       0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x10 };
        unsigned c = 0;
        for (i = 0; i < 32; ++i) {
            c += sig[32 + i] + L[i];
            sig[32 + i] = (uint8_t)c;
            c >>= 8;
        }
        check(oc_ed25519_verify(sig, pk, msg, 0) == 0, "Ed25519 refuses S + L");
    }
}

static void test_chacha_poly(void)
{
    uint8_t key[32], nonce[8], out[64], tag[16], pkey[32];
    static const char msg[] = "Cryptographic Forum Research Group";
    int i;
    for (i = 0; i < 32; ++i) key[i] = (uint8_t)i;
    unhex(nonce, "0000004a00000000");
    oc_chacha20_xor(out, NULL, 64, key, nonce, 0x0900000000000001ull);
    check_hex(out, 64, "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e"
                       "d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e",
              "ChaCha20 RFC 8439 2.3.2 block");
    unhex(pkey, "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b");
    oc_poly1305(tag, msg, strlen(msg), pkey);
    check_hex(tag, 16, "a8061dc1305136c6c22b8baf0c0127a9", "Poly1305 RFC 8439 2.5.2");
}

static void test_sha_blocks(void)
{
    uint8_t blk[128], st[64];
    memset(blk, 0, sizeof blk);
    memcpy(blk, "abc", 3);
    blk[3] = 0x80;
    blk[63] = 24;
    unhex(st, "6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19");
    oc_sha256_blocks(st, blk, 1);
    check_hex(st, 32, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "SHA-256 blocks, \"abc\"");
    memset(blk, 0, sizeof blk);
    memcpy(blk, "abc", 3);
    blk[3] = 0x80;
    blk[127] = 24;
    unhex(st, "6a09e667f3bcc908bb67ae8584caa73b3c6ef372fe94f82ba54ff53a5f1d36f1"
              "510e527fade682d19b05688c2b3e6c1f1f83d9abfb41bd6b5be0cd19137e2179");
    oc_sha512_blocks(st, blk, 1);
    check_hex(st, 64, "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
                      "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f", "SHA-512 blocks, \"abc\"");
}

static void test_sntrup761(void)
{
    static uint8_t pk[OC_SNTRUP761_PK_BYTES], sk[OC_SNTRUP761_SK_BYTES], ct[OC_SNTRUP761_CT_BYTES];
    uint8_t ss1[32], ss2[32], seed[32], h[32];
    OCSHA256 hc;
    int i;
    clock_t t0, t1, t2, t3;

    for (i = 0; i < 32; ++i) seed[i] = (uint8_t)i;
    t0 = clock();
    oc_sntrup761_keypair(pk, sk, seed);
    t1 = clock();
    seed[0] ^= 0x80;
    oc_sntrup761_enc(ct, ss1, pk, seed);
    t2 = clock();
    oc_sntrup761_dec(ss2, ct, sk);
    t3 = clock();
    check(!memcmp(ss1, ss2, 32), "sntrup761 decapsulation gives the encapsulated secret");
    printf("     sntrup761 key pair %ld ms, encapsulation %ld ms, decapsulation %ld ms\n",
           (long)((t1 - t0) * 1000 / CLOCKS_PER_SEC), (long)((t2 - t1) * 1000 / CLOCKS_PER_SEC),
           (long)((t3 - t2) * 1000 / CLOCKS_PER_SEC));

    /* OpenCrypto's known answers: SHA-256 over pk, sk, ct and ss for seeds
     * 00..1f and (80)01..1f; computed on the PC, the same on the 68k */
    oc_sha256_init(&hc);
    oc_sha256_update(&hc, pk, sizeof pk);
    oc_sha256_update(&hc, sk, sizeof sk);
    oc_sha256_update(&hc, ct, sizeof ct);
    oc_sha256_update(&hc, ss1, sizeof ss1);
    oc_sha256_final(&hc, h);
    check_hex(h, 32, OC_SNTRUP761_KAT, "sntrup761 known answer (OpenCrypto's, seeds 00..1f)");

    ct[100] ^= 4;
    oc_sntrup761_dec(ss2, ct, sk);
    check(memcmp(ss1, ss2, 32) != 0, "sntrup761 changed ciphertext: a different secret");
    {
        /* implicit rejection: H(0, H(3, rho) || ct) */
        uint8_t x[1 + 32 + OC_SNTRUP761_CT_BYTES], hh[64], y[1 + 191];
        y[0] = 3;
        memcpy(y + 1, sk + 2 * 191 + OC_SNTRUP761_PK_BYTES, 191);
        oc_sha512(y, sizeof y, hh);
        x[0] = 0;
        memcpy(x + 1, hh, 32);
        memcpy(x + 33, ct, OC_SNTRUP761_CT_BYTES);
        oc_sha512(x, sizeof x, hh);
        check(!memcmp(hh, ss2, 32), "sntrup761 changed ciphertext: the implicit-rejection secret");
    }
}

static void test_aes(void)
{
    static const char *const want[3] = { "69c4e0d86a7b0430d8cdb78070b4c55a",
        "dda97ca4864cdfe06eaf70a0ec0d7191", "8ea2b7ca516745bfeafc49904b496089" };
    uint8_t key[32], blk[16], iv[16], buf[80], orig[80];
    int i, k;
    for (i = 0; i < 32; ++i) key[i] = (uint8_t)i;
    for (k = 0; k < 3; ++k) {
        char what[64];
        unhex(blk, "00112233445566778899aabbccddeeff");
        oc_aes(blk, 16, key, 16 + 8 * (size_t)k, blk, OC_AES_ECB_ENCRYPT);
        sprintf(what, "AES-%d FIPS 197 appendix C", 128 + 64 * k);
        check_hex(blk, 16, want[k], what);
    }
    for (i = 0; i < 80; ++i) orig[i] = buf[i] = (uint8_t)(i * 7);
    for (i = 0; i < 16; ++i) iv[i] = (uint8_t)(0xf0 + i);
    oc_aes(buf, 80, key, 32, iv, OC_AES_CBC_ENCRYPT);
    oc_aes(buf, 80, key, 32, iv, OC_AES_CBC_DECRYPT);
    check(!memcmp(buf, orig, 80), "AES-256 CBC round trip");
    oc_aes(buf, 77, key, 16, iv, OC_AES_CTR);
    check(memcmp(buf, orig, 77) != 0, "AES-128 CTR changes the data");
    oc_aes(buf, 77, key, 16, iv, OC_AES_CTR);
    check(!memcmp(buf, orig, 80), "AES-128 CTR round trip, 77 bytes");
}

static void test_rsa(void)
{
    /* n = 2048-bit modulus, e = 65537, s chosen; want = pow(s, e, n) by Python */
    static uint8_t n[256], s[256], out[256];
    static const uint8_t e[3] = { 1, 0, 1 };
    unhex(n, OC_TEST_RSA_N);
    unhex(s, OC_TEST_RSA_S);
    check(oc_rsa_public(out, s, n, 256, e, 3) == 0, "RSA-2048 public operation runs");
    check_hex(out, 256, OC_TEST_RSA_WANT, "RSA-2048 public operation, against Python's pow()");
    check(oc_rsa_public(out, n, n, 256, e, 3) == -1, "RSA refuses sig >= n");
}

static void test_ecdsa(void)
{
    /* RFC 6979 A.2.5 (P-256), SHA-256, message "sample" */
    uint8_t qx[32], qy[32], r[32], s[32], h[32];
    unhex(qx, "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6");
    unhex(qy, "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299");
    unhex(r, "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716");
    unhex(s, "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8");
    oc_sha256("sample", 6, h);
    check(oc_ecdsa_verify(256, qx, qy, r, s, h, 32) == 1, "ECDSA P-256 RFC 6979 A.2.5 (SHA-256, \"sample\")");
    h[0] ^= 1;
    check(oc_ecdsa_verify(256, qx, qy, r, s, h, 32) == 0, "ECDSA P-256 with the hash altered: refused");
    h[0] ^= 1;
    qy[31] ^= 1;
    check(oc_ecdsa_verify(256, qx, qy, r, s, h, 32) == 0, "ECDSA P-256 with a point off the curve: refused");
}

int main(int argc, char **argv)
{
    if (argc > 1 && !strcmp(argv[1], "sntrup761")) {     /* that one alone */
        test_sntrup761();
        printf("OpenCrypto sntrup761: %d of %d checks passed\n", checks - failures, checks);
        return failures ? 20 : 0;
    }
    test_x25519();
    test_ed25519();
    test_chacha_poly();
    test_sha_blocks();
    test_sntrup761();
    test_aes();
    test_rsa();
    test_ecdsa();
    printf("OpenCrypto SSH primitives: %d of %d checks passed\n", checks - failures, checks);
    return failures ? 20 : 0;
}
