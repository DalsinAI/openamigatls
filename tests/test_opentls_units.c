/* OpenTLS unit tests: every function table OpenCrypto fills in for BearSSL
 * (ot_glue.c) against BearSSL's own, on random inputs; and the address
 * parser, the session rules and the error names.
 * MIT licensed and free. Copyright (c) 2026 Dalsin Limited. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ot_internal.h"
#include <clib/opentls_protos.h>

static int failures;
#define CHECK(cond, what) do { if (!(cond)) { printf("FAIL %s (line %d)\n", what, __LINE__); ++failures; } } while (0)

static br_hmac_drbg_context rng;
static void rnd(void *p, size_t n) { br_hmac_drbg_generate(&rng, p, n); }
static size_t rnd_below(size_t n) { uint32_t v; rnd(&v, sizeof v); return n ? v % n : 0; }

static void test_hashes(const struct ot_impls *m)
{
    const br_hash_class *mine[3] = { m->sha256, m->sha384, m->sha512 };
    const br_hash_class *ref[3] = { &br_sha256_vtable, &br_sha384_vtable, &br_sha512_vtable };
    static unsigned char data[3000];
    int k, round;
    for (k = 0; k < 3; ++k) {
        CHECK(mine[k] != ref[k], "OpenCrypto hash selected");
        for (round = 0; round < 200; ++round) {
            br_hash_compat_context a, b;
            unsigned char oa[64], ob[64], sa[64], sb[64];
            size_t len = rnd_below(sizeof data), cut = rnd_below(len + 1), done;
            uint64_t ca, cb;
            rnd(data, len);
            mine[k]->init(&a.vtable);
            ref[k]->init(&b.vtable);
            for (done = 0; done < cut; ) {        /* uneven pieces */
                size_t piece = 1 + rnd_below(200);
                if (piece > cut - done) piece = cut - done;
                mine[k]->update(&a.vtable, data + done, piece);
                done += piece;
            }
            ref[k]->update(&b.vtable, data, cut);
            mine[k]->out(&a.vtable, oa);          /* out leaves the state alone */
            mine[k]->update(&a.vtable, data + cut, len - cut);
            ref[k]->update(&b.vtable, data + cut, len - cut);
            mine[k]->out(&a.vtable, oa);
            ref[k]->out(&b.vtable, ob);
            CHECK(!memcmp(oa, ob, (ref[k]->desc >> BR_HASHDESC_OUT_OFF) & BR_HASHDESC_OUT_MASK), "hash output");
            /* state and set_state, at a block boundary, as HMAC uses them */
            mine[k]->init(&a.vtable);
            ref[k]->init(&b.vtable);
            mine[k]->update(&a.vtable, data, 256);
            ref[k]->update(&b.vtable, data, 256);
            ca = mine[k]->state(&a.vtable, sa);
            cb = ref[k]->state(&b.vtable, sb);
            CHECK(ca == cb && !memcmp(sa, sb, k ? 64 : 32), "hash state");
            memset(&a, 0, sizeof a);               /* as BearSSL does: no init first */
            mine[k]->set_state(&a.vtable, sb, cb);
            mine[k]->update(&a.vtable, data, 77);
            ref[k]->update(&b.vtable, data, 77);
            mine[k]->out(&a.vtable, oa);
            ref[k]->out(&b.vtable, ob);
            CHECK(!memcmp(oa, ob, (ref[k]->desc >> BR_HASHDESC_OUT_OFF) & BR_HASHDESC_OUT_MASK), "hash set_state");
        }
    }
}

static void test_aes(const struct ot_impls *m)
{
    int round;
    for (round = 0; round < 200; ++round) {
        br_aes_gen_cbcenc_keys ea, eb;
        br_aes_gen_cbcdec_keys da, db;
        br_aes_gen_ctr_keys ta, tb;
        unsigned char key[32], iva[16], ivb[16], a[1024], b[1024];
        size_t klen = 16 + 8 * rnd_below(3), blocks = 1 + rnd_below(60), len = 16 * blocks;
        uint32_t cc, ra, rb;
        rnd(key, sizeof key);
        rnd(iva, 16);
        memcpy(ivb, iva, 16);
        rnd(a, len);
        memcpy(b, a, len);
        m->aes_cbcenc->init(&ea.vtable, key, klen);
        br_aes_ct_cbcenc_vtable.init(&eb.vtable, key, klen);
        m->aes_cbcenc->run(&ea.vtable, iva, a, len);
        br_aes_ct_cbcenc_vtable.run(&eb.vtable, ivb, b, len);
        CHECK(!memcmp(a, b, len) && !memcmp(iva, ivb, 16), "AES-CBC encrypt");
        m->aes_cbcdec->init(&da.vtable, key, klen);
        br_aes_ct_cbcdec_vtable.init(&db.vtable, key, klen);
        rnd(iva, 16);
        memcpy(ivb, iva, 16);
        m->aes_cbcdec->run(&da.vtable, iva, a, len);
        br_aes_ct_cbcdec_vtable.run(&db.vtable, ivb, b, len);
        CHECK(!memcmp(a, b, len) && !memcmp(iva, ivb, 16), "AES-CBC decrypt");
        len = rnd_below(sizeof a);                 /* CTR: any length */
        rnd(a, len);
        memcpy(b, a, len);
        rnd(&cc, sizeof cc);
        cc &= 0xFFFF;
        m->aes_ctr->init(&ta.vtable, key, klen);
        br_aes_ct_ctr_vtable.init(&tb.vtable, key, klen);
        ra = m->aes_ctr->run(&ta.vtable, iva, cc, a, len);
        rb = br_aes_ct_ctr_vtable.run(&tb.vtable, ivb, cc, b, len);
        CHECK(ra == rb && !memcmp(a, b, len), "AES-CTR");
    }
}

static void test_chapol(const struct ot_impls *m)
{
    int round;
    for (round = 0; round < 200; ++round) {
        unsigned char key[32], iv[12], a[2000], b[2000], aad[13], tga[16], tgb[16];
        size_t len = rnd_below(sizeof a);
        uint32_t cc, ra, rb;
        int enc = (int)rnd_below(2);
        rnd(key, 32); rnd(iv, 12); rnd(aad, 13); rnd(a, len);
        memcpy(b, a, len);
        rnd(&cc, sizeof cc);
        cc &= 0xFFFFF;
        ra = m->chacha20(key, iv, cc, a, len);
        rb = br_chacha20_ct_run(key, iv, cc, b, len);
        CHECK(ra == rb && !memcmp(a, b, len), "ChaCha20");
        m->poly1305(key, iv, a, len, aad, sizeof aad, tga, m->chacha20, enc);
        br_poly1305_ctmul_run(key, iv, b, len, aad, sizeof aad, tgb, br_chacha20_ct_run, enc);
        CHECK(!memcmp(a, b, len) && !memcmp(tga, tgb, 16), "ChaCha20-Poly1305");
    }
}

static void test_x25519(const struct ot_impls *m)
{
    int round;
    for (round = 0; round < 50; ++round) {
        unsigned char ka[32], kb[32], pa[32], pb[32], sa[32], sb[32];
        size_t la, lb;
        rnd(ka, 32); rnd(kb, 32);
        la = m->ec->mulgen(pa, ka, 32, BR_EC_curve25519);
        lb = br_ec_c25519_m31.mulgen(pb, ka, 32, BR_EC_curve25519);
        CHECK(la == 32 && lb == 32 && !memcmp(pa, pb, 32), "X25519 public key");
        br_ec_c25519_m31.mulgen(pb, kb, 32, BR_EC_curve25519);
        memcpy(sa, pb, 32);
        memcpy(sb, pb, 32);
        CHECK(m->ec->mul(sa, 32, ka, 32, BR_EC_curve25519) == 1, "X25519 mul");
        br_ec_c25519_m31.mul(sb, 32, ka, 32, BR_EC_curve25519);
        CHECK(!memcmp(sa, sb, 32), "X25519 shared secret");
    }
}

static void rng_seeder(const br_prng_class **ctx, void *out, size_t len) { (void)ctx; rnd(out, len); }

static void test_rsa(const struct ot_impls *m)
{
    static unsigned char kbuf_priv[BR_RSA_KBUF_PRIV_SIZE(2048)], kbuf_pub[BR_RSA_KBUF_PUB_SIZE(2048)];
    br_rsa_private_key sk;
    br_rsa_public_key pk;
    br_hmac_drbg_context krng;
    unsigned char seed[32], hash[32], sig[256], out[32], x[256], y[256];
    int round;
    (void)rng_seeder;
    rnd(seed, sizeof seed);
    br_hmac_drbg_init(&krng, &br_sha256_vtable, seed, sizeof seed);
    CHECK(br_rsa_i31_keygen(&krng.vtable, &sk, kbuf_priv, &pk, kbuf_pub, 2048, 65537), "RSA keygen");
    for (round = 0; round < 20; ++round) {
        rnd(hash, 32);
        CHECK(br_rsa_i31_pkcs1_sign(BR_HASH_OID_SHA256, hash, 32, &sk, sig), "RSA sign");
        CHECK(m->rsa_vrfy(sig, 256, BR_HASH_OID_SHA256, 32, &pk, out) && !memcmp(out, hash, 32), "RSA verify");
        sig[rnd_below(256)] ^= 1;
        CHECK(!m->rsa_vrfy(sig, 256, BR_HASH_OID_SHA256, 32, &pk, out) || memcmp(out, hash, 32), "RSA altered");
        rnd(x, 256);
        x[0] &= 0x3F;
        memcpy(y, x, 256);
        CHECK(m->rsa_pub(x, 256, &pk) && br_rsa_i31_public(y, 256, &pk) && !memcmp(x, y, 256), "RSA public");
    }
}

static void test_ecdsa(const struct ot_impls *m)
{
    static const int curves[3] = { BR_EC_secp256r1, BR_EC_secp384r1, BR_EC_secp521r1 };
    int k, round;
    for (k = 0; k < 3; ++k) {
        unsigned char skb[BR_EC_KBUF_PRIV_MAX_SIZE], pkb[BR_EC_KBUF_PUB_MAX_SIZE];
        br_ec_private_key sk;
        br_ec_public_key pk;
        br_hmac_drbg_context krng;
        unsigned char seed[32], hash[48], sig[160];
        size_t slen;
        rnd(seed, sizeof seed);
        br_hmac_drbg_init(&krng, &br_sha256_vtable, seed, sizeof seed);
        CHECK(br_ec_keygen(&krng.vtable, &br_ec_all_m31, &sk, skb, curves[k]), "EC keygen");
        CHECK(br_ec_compute_pub(&br_ec_all_m31, &pk, pkb, &sk), "EC public");
        for (round = 0; round < 10; ++round) {
            rnd(hash, sizeof hash);
            slen = br_ecdsa_i31_sign_asn1(&br_ec_all_m31, &br_sha384_vtable, hash, &sk, sig);
            CHECK(slen > 0, "ECDSA sign");
            CHECK(m->ecdsa_vrfy(m->ec, hash, 48, &pk, sig, slen) == 1, "ECDSA verify");
            hash[0] ^= 1;
            CHECK(m->ecdsa_vrfy(m->ec, hash, 48, &pk, sig, slen) == 0, "ECDSA altered");
        }
    }
}

static void test_api(void)
{
    struct OTContextConfig cfg;
    struct OTContext *x;
    struct OTConnection *c;
    LONG err;
    static const unsigned char v6[16] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };

    memset(&cfg, 0, sizeof cfg);
    cfg.Size = sizeof cfg;
    cfg.Flags = OTCF_NO_SYSTEM_TRUST;
    cfg.MinVersion = OT_TLS13;
    CHECK(!OT_NewContext(&cfg, &err) && err == OTERR_UNSUPPORTED, "TLS 1.3 minimum refused for now");
    cfg.MinVersion = OT_TLS12;
    cfg.MaxVersion = OT_TLS11;
    CHECK(!OT_NewContext(&cfg, &err) && err == OTERR_ARGS, "bad range");
    cfg.MaxVersion = 0;
    cfg.ALPN = (STRPTR)"h2,http/1.1";
    x = OT_NewContext(&cfg, &err);
    CHECK(x && err == OTERR_OK, "context");
    if (!x) return;

    c = OT_NewConnection(x, (CONST_STRPTR)"192.168.1.20", &err);
    CHECK(c && c->ip_len == 4 && c->ip[3] == 20, "IPv4 address");
    CHECK(c && c->alpn_count == 2 && !strcmp(c->alpn_names[1], "http/1.1"), "ALPN list from the context");
    CHECK(OT_Read(c, &err, 1) == OTERR_STATE, "read before handshake");
    CHECK(OT_Handshake(c) == OTERR_STATE, "handshake without a socket");
    OT_FreeConnection(c);
    c = OT_NewConnection(x, (CONST_STRPTR)"[2001:db8::1]", &err);
    CHECK(c && c->ip_len == 16 && !memcmp(c->ip, v6, 16) && !strcmp(c->host, "2001:db8::1"), "IPv6 address");
    OT_FreeConnection(c);
    c = OT_NewConnection(x, (CONST_STRPTR)"ftp.example.org", &err);
    CHECK(c && c->ip_len == 0, "a host name");
    CHECK(OT_SetVerify(c, 9) == OTERR_ARGS, "bad verify mode");
    {
        struct OTSession s;
        memset(&s, 0, sizeof s);
        strcpy(s.host, "other.example.org");
        CHECK(OT_SetSession(c, &s) == OTERR_ARGS, "session for another host refused");
        strcpy(s.host, "FTP.example.org");
        CHECK(OT_SetSession(c, &s) == OTERR_OK, "session for the same host");
    }
    OT_FreeConnection(c);
    CHECK(OT_NewConnection(x, (CONST_STRPTR)"fe80::zz", &err) == NULL && err == OTERR_ARGS, "bad address");
    OT_FreeContext(x);
    CHECK(!strcmp((const char *)OT_ErrorString(OTERR_HOSTNAME), "The certificate is not for this host."), "error names");
    CHECK(!strcmp((const char *)OT_ErrorString(-99), "Unknown error."), "unknown error name");
    {
        unsigned char r1[32], r2[32];
        CHECK(OT_Random(r1, 32) == OTERR_OK && OT_Random(r2, 32) == OTERR_OK && memcmp(r1, r2, 32), "random");
    }
}

int main(void)
{
    struct ot_impls m, plain;
    unsigned char seed[32] = { 1, 2, 3 };
    br_hmac_drbg_init(&rng, &br_sha256_vtable, seed, sizeof seed);
    ot_glue_select(&m, 1);
    ot_glue_select(&plain, 0);
    CHECK(plain.sha256 == &br_sha256_vtable && plain.chacha20 == br_chacha20_ct_run, "no offload: BearSSL's own");
    test_hashes(&m);
    test_aes(&m);
    test_chapol(&m);
    test_x25519(&m);
    test_rsa(&m);
    test_ecdsa(&m);
    test_api();
    printf("%s (%d failures)\n", failures ? "OPENTLS UNITS FAIL" : "OPENTLS UNITS PASS", failures);
    return failures ? 1 : 0;
}
