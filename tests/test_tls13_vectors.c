/* OpenTLS: the TLS 1.3 key schedule, record protection, Finished, PSK
 * binder and CertificateVerify (ot_tls13_keys.c, ot_tls13.c) against the
 * traces of RFC 8448 (tests/rfc8448.h), with both function tables
 * (OpenCrypto's and BearSSL's); and records sealed with one table and
 * opened with the other, for the suites RFC 8448 does not show.
 * MIT licensed and free. Copyright (c) 2026 The AmigaChrome Team. */
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ot_tls13.h"
#include "rfc8448.h"

static int failures, checks;
#define CHECK(cond, what) do { ++checks; if (!(cond)) { printf("FAIL %s: %s (line %d)\n", label, what, __LINE__); ++failures; } } while (0)
static const char *label = "";

struct buf { unsigned char *p; size_t n; };

static struct buf hex(const char *s)
{
    struct buf b;
    size_t i;
    b.n = strlen(s) / 2;
    b.p = malloc(b.n ? b.n : 1);
    for (i = 0; i < b.n; ++i) {
        unsigned v;
        sscanf(s + 2 * i, "%2x", &v);
        b.p[i] = (unsigned char)v;
    }
    return b;
}

static int same(const unsigned char *a, const char *want)
{
    struct buf w = hex(want);
    int ok = !memcmp(a, w.p, w.n);
    free(w.p);
    return ok;
}

/* the SHA-256 of the concatenation of the messages given (NULL-terminated) */
static void thash(unsigned char *out, ...)
{
    br_sha256_context h;
    va_list ap;
    const char *m;
    br_sha256_init(&h);
    va_start(ap, out);
    while ((m = va_arg(ap, const char *)) != NULL) {
        struct buf b = hex(m);
        br_sha256_update(&h, b.p, b.n);
        free(b.p);
    }
    va_end(ap);
    br_sha256_out(&h, out);
}

static void test_rfc8448_s3(const struct ot_impls *m)
{
    const br_hash_class *h = &br_sha256_vtable;
    const struct ot13_suite *s = ot13_suite(OT13_AES_128_GCM_SHA256);
    struct buf priv = hex(RFC8448_C_X25519_PRIV), spub = hex(RFC8448_S_X25519_PUB);
    unsigned char g[32], early[32], derived[32], hs[32], th[32], c_hs[32], s_hs[32], master[32];
    unsigned char c_ap[32], s_ap[32], fin[32], res[32], psk[32];
    struct ot13_keys k;
    struct buf rec, flight, cv, cert;
    int type, i;
    size_t len;

    /* (EC)DHE */
    memcpy(g, spub.p, 32);
    CHECK(m->ec->mul(g, 32, priv.p, 32, BR_EC_curve25519), "X25519");
    CHECK(same(g, RFC8448_ECDHE), "X25519 shared secret");

    /* the handshake secrets */
    ot13_extract(h, NULL, NULL, 0, early);
    CHECK(same(early, RFC8448_EARLY), "early secret");
    ot13_derive(h, early, "derived", NULL, derived);
    ot13_extract(h, derived, g, 32, hs);
    CHECK(same(hs, RFC8448_HS_SECRET), "handshake secret");
    thash(th, RFC8448_CH, RFC8448_SH, (char *)NULL);
    CHECK(same(th, RFC8448_THASH_SH), "transcript to ServerHello");
    ot13_derive(h, hs, "c hs traffic", th, c_hs);
    ot13_derive(h, hs, "s hs traffic", th, s_hs);
    CHECK(same(c_hs, RFC8448_C_HS), "client handshake traffic secret");
    CHECK(same(s_hs, RFC8448_S_HS), "server handshake traffic secret");
    ot13_derive(h, hs, "derived", NULL, derived);
    ot13_extract(h, derived, NULL, 0, master);
    CHECK(same(master, RFC8448_MASTER), "master secret");

    /* the server's encrypted flight */
    CHECK(ot13_keys_set(&k, s, m, s_hs) == 0, "keys");
    CHECK(same(k.key, RFC8448_S_HS_KEY) && same(k.iv, RFC8448_S_HS_IV), "server handshake key and IV");
    rec = hex(RFC8448_S_FLIGHT_REC);
    flight = hex(RFC8448_S_FLIGHT);
    CHECK(ot13_open(&k, rec.p, rec.n, &type, &len) == 0, "server flight opens");
    CHECK(type == BR_SSL_HANDSHAKE && len == flight.n && !memcmp(rec.p + 5, flight.p, len), "server flight");
    /* and sealed again, the same */
    CHECK(ot13_keys_set(&k, s, m, s_hs) == 0, "keys");
    {
        unsigned char *again = malloc(flight.n + 5 + 17);
        struct buf want = hex(RFC8448_S_FLIGHT_REC);
        memcpy(again + 5, flight.p, flight.n);
        CHECK(ot13_seal(&k, again, BR_SSL_HANDSHAKE, flight.n) == want.n && !memcmp(again, want.p, want.n),
              "server flight sealed");
        /* one bit changed: refused */
        CHECK(ot13_keys_set(&k, s, m, s_hs) == 0, "keys");
        again[20] ^= 1;
        CHECK(ot13_open(&k, again, want.n, &type, &len) == BR_ERR_BAD_MAC, "a changed record is refused");
        free(again);
        free(want.p);
    }

    /* CertificateVerify: RSA-PSS with SHA-256 under the RFC's server key */
    cv = hex(RFC8448_CV);
    cert = hex(RFC8448_CERT);
    thash(th, RFC8448_CH, RFC8448_SH, RFC8448_EE, RFC8448_CERT, (char *)NULL);
    {
        struct buf n = hex(RFC8448_RSA_N);
        static const unsigned char e[] = { 1, 0, 1 };
        br_x509_pkey pk;
        pk.key_type = BR_KEYTYPE_RSA;
        pk.key.rsa.n = n.p;
        pk.key.rsa.nlen = n.n;
        pk.key.rsa.e = (unsigned char *)e;
        pk.key.rsa.elen = 3;
        CHECK(get16be(cv.p + 4) == 0x0804, "the RFC's scheme");
        CHECK(ot13_verify_cv(m, 0x0804, &pk, NULL, th, 32, cv.p + 8, get16be(cv.p + 6)) == 0,
              "CertificateVerify verifies");
        cv.p[20] ^= 0x10;
        CHECK(ot13_verify_cv(m, 0x0804, &pk, NULL, th, 32, cv.p + 8, get16be(cv.p + 6)) == BR_ERR_BAD_SIGNATURE,
              "a changed CertificateVerify does not");
        cv.p[20] ^= 0x10;
        CHECK(ot13_verify_cv(m, 0x0403, &pk, NULL, th, 32, cv.p + 8, get16be(cv.p + 6)) == BR_ERR_INVALID_ALGORITHM,
              "ECDSA scheme with an RSA key");
        free(n.p);
    }

    /* Finished, both ways */
    thash(th, RFC8448_CH, RFC8448_SH, RFC8448_EE, RFC8448_CERT, RFC8448_CV, (char *)NULL);
    ot13_finished(h, s_hs, th, fin);
    CHECK(same(fin, RFC8448_S_FIN), "server Finished");
    thash(th, RFC8448_CH, RFC8448_SH, RFC8448_S_FLIGHT, (char *)NULL);
    CHECK(same(th, RFC8448_THASH_SFIN), "transcript to the server's Finished");
    ot13_derive(h, master, "c ap traffic", th, c_ap);
    ot13_derive(h, master, "s ap traffic", th, s_ap);
    CHECK(same(c_ap, RFC8448_C_AP) && same(s_ap, RFC8448_S_AP), "application traffic secrets");
    ot13_finished(h, c_hs, th, fin);
    CHECK(same(fin, RFC8448_C_FIN), "client Finished");
    CHECK(ot13_keys_set(&k, s, m, c_hs) == 0, "keys");
    {
        struct buf msg = hex(RFC8448_C_FIN_MSG), want = hex(RFC8448_C_FIN_REC);
        unsigned char r[128];
        memcpy(r + 5, msg.p, msg.n);
        CHECK(ot13_seal(&k, r, BR_SSL_HANDSHAKE, msg.n) == want.n && !memcmp(r, want.p, want.n),
              "client Finished record");
        free(msg.p);
        free(want.p);
    }

    /* resumption */
    thash(th, RFC8448_CH, RFC8448_SH, RFC8448_S_FLIGHT, RFC8448_C_FIN_MSG, (char *)NULL);
    ot13_derive(h, master, "res master", th, res);
    CHECK(same(res, RFC8448_RES_MASTER), "resumption master secret");
    {
        struct buf nonce = hex(RFC8448_TICKET_NONCE);
        ot13_expand_label(h, res, "resumption", nonce.p, nonce.n, psk, 32);
        CHECK(same(psk, RFC8448_RES_PSK), "ticket PSK");
        free(nonce.p);
    }

    /* application data: the ticket in, data and an alert out */
    CHECK(ot13_keys_set(&k, s, m, s_ap) == 0, "keys");
    CHECK(same(k.key, RFC8448_S_AP_KEY) && same(k.iv, RFC8448_S_AP_IV), "server application key and IV");
    {
        struct buf r = hex(RFC8448_NST_REC), nst = hex(RFC8448_NST);
        CHECK(ot13_open(&k, r.p, r.n, &type, &len) == 0 && type == BR_SSL_HANDSHAKE && len == nst.n
              && !memcmp(r.p + 5, nst.p, len), "NewSessionTicket record");
        free(r.p);
        free(nst.p);
    }
    CHECK(ot13_keys_set(&k, s, m, c_ap) == 0, "keys");
    CHECK(same(k.key, RFC8448_C_AP_KEY) && same(k.iv, RFC8448_C_AP_IV), "client application key and IV");
    for (i = 0; i < 2; ++i) {
        struct buf msg = hex(i ? RFC8448_C_ALERT : RFC8448_C_APP), want = hex(i ? RFC8448_C_ALERT_REC : RFC8448_C_APP_REC);
        unsigned char r[128];
        memcpy(r + 5, msg.p, msg.n);
        CHECK(ot13_seal(&k, r, i ? BR_SSL_ALERT : BR_SSL_APPLICATION_DATA, msg.n) == want.n
              && !memcmp(r, want.p, want.n), i ? "close_notify record (sequence 1)" : "application data record");
        free(msg.p);
        free(want.p);
    }
    free(priv.p); free(spub.p); free(rec.p); free(flight.p); free(cv.p); free(cert.p);
}

static void test_rfc8448_s4(void)
{
    const br_hash_class *h = &br_sha256_vtable;
    struct buf psk = hex(RFC8448_R_PSK);
    unsigned char early[32], bkey[32], th[32], binder[32];
    ot13_extract(h, NULL, psk.p, psk.n, early);
    CHECK(same(early, RFC8448_R_EARLY), "early secret from the PSK");
    ot13_derive(h, early, "res binder", NULL, bkey);
    CHECK(same(bkey, RFC8448_R_BINDER_KEY), "binder key");
    thash(th, RFC8448_R_CH_PREFIX, (char *)NULL);
    CHECK(same(th, RFC8448_R_BINDER_HASH), "binder transcript");
    ot13_finished(h, bkey, th, binder);
    CHECK(same(binder, RFC8448_R_BINDER), "PSK binder");
    free(psk.p);
}

static void test_rfc8448_s5(const struct ot_impls *m)
{
    const br_hash_class *h = &br_sha256_vtable;
    struct buf priv = hex(RFC8448_H_C_P256_PRIV), spub = hex(RFC8448_H_S_P256_PUB);
    unsigned char pub[65], g[65], ch1[4 + 32], th[32], early[32], derived[32], hs[32], c_hs[32];
    br_sha256_context t;
    size_t xlen, xoff;
    CHECK(m->ec->mulgen(pub, priv.p, 32, BR_EC_secp256r1) == 65 && same(pub, RFC8448_H_C_P256_PUB),
          "P-256 public key");
    memcpy(g, spub.p, 65);
    CHECK(m->ec->mul(g, 65, priv.p, 32, BR_EC_secp256r1), "P-256");
    xoff = m->ec->xoff(BR_EC_secp256r1, &xlen);
    CHECK(xlen == 32 && same(g + xoff, RFC8448_H_ECDHE), "P-256 shared secret");
    /* the transcript after a HelloRetryRequest: message_hash(ClientHello1) */
    thash(ch1 + 4, RFC8448_H_CH1, (char *)NULL);
    ch1[0] = 254; ch1[1] = 0; ch1[2] = 0; ch1[3] = 32;
    br_sha256_init(&t);
    br_sha256_update(&t, ch1, sizeof ch1);
    {
        const char *rest[3] = { RFC8448_H_HRR, RFC8448_H_CH2, RFC8448_H_SH };
        int i;
        for (i = 0; i < 3; ++i) {
            struct buf b = hex(rest[i]);
            br_sha256_update(&t, b.p, b.n);
            free(b.p);
        }
    }
    br_sha256_out(&t, th);
    CHECK(same(th, RFC8448_H_THASH_SH), "transcript after HelloRetryRequest");
    ot13_extract(h, NULL, NULL, 0, early);
    ot13_derive(h, early, "derived", NULL, derived);
    ot13_extract(h, derived, g + xoff, 32, hs);
    ot13_derive(h, hs, "c hs traffic", th, c_hs);
    CHECK(same(c_hs, RFC8448_H_C_HS), "client handshake secret after HelloRetryRequest");
    free(priv.p);
    free(spub.p);
}

/* every suite: sealed with one table, opened with the other; KeyUpdate */
static void test_cross(const struct ot_impls *a, const struct ot_impls *b)
{
    static const unsigned ids[3] = { OT13_AES_128_GCM_SHA256, OT13_AES_256_GCM_SHA384,
                                     OT13_CHACHA20_POLY1305_SHA256 };
    static unsigned char rec[5 + OT13_RECORD_MAX + 17], plain[OT13_RECORD_MAX];
    unsigned char secret[48];
    size_t sizes[5] = { 0, 1, 15, 1000, OT13_RECORD_MAX }, i, j, len;
    int n, type;
    for (i = 0; i < sizeof plain; ++i) plain[i] = (unsigned char)(i * 13 + 7);
    for (i = 0; i < sizeof secret; ++i) secret[i] = (unsigned char)(i + 1);
    for (n = 0; n < 3; ++n) {
        const struct ot13_suite *s = ot13_suite(ids[n]);
        struct ot13_keys w, r;
        label = s->name;
        CHECK(ot13_keys_set(&w, s, a, secret) == 0 && ot13_keys_set(&r, s, b, secret) == 0, "keys");
        for (j = 0; j < 3; ++j) {         /* three generations: KeyUpdate */
            for (i = 0; i < 5; ++i) {
                size_t sz = sizes[i];
                memcpy(rec + 5, plain, sz);
                len = ot13_seal(&w, rec, BR_SSL_APPLICATION_DATA, sz);
                CHECK(len == 5 + sz + 17, "record length");
                if (sz == 0) {     /* empty content: the type alone, then nothing after it */
                    CHECK(ot13_open(&r, rec, len, &type, &len) == 0 && type == BR_SSL_APPLICATION_DATA && len == 0,
                          "empty record");
                    continue;
                }
                CHECK(ot13_open(&r, rec, len, &type, &len) == 0 && type == BR_SSL_APPLICATION_DATA && len == sz
                      && !memcmp(rec + 5, plain, sz), "sealed by one table, opened by the other");
            }
            CHECK(ot13_keys_next(&w) == 0 && ot13_keys_next(&r) == 0, "next keys");
            CHECK(!memcmp(w.key, r.key, s->key_len) && !memcmp(w.iv, r.iv, 12) && w.seq == 0, "KeyUpdate");
        }
        /* a record from the old generation no longer opens */
        {
            struct ot13_keys old;
            CHECK(ot13_keys_set(&old, s, a, secret) == 0, "keys");
            memcpy(rec + 5, plain, 100);
            len = ot13_seal(&old, rec, BR_SSL_APPLICATION_DATA, 100);
            CHECK(ot13_open(&r, rec, len, &type, &len) == BR_ERR_BAD_MAC, "the old key is refused");
        }
    }
}

int main(void)
{
    struct ot_impls oc, bear;
    ot_glue_select(&oc, 1);
    ot_glue_select(&bear, 0);
    label = "RFC 8448 3, OpenCrypto";
    test_rfc8448_s3(&oc);
    label = "RFC 8448 3, BearSSL";
    test_rfc8448_s3(&bear);
    label = "RFC 8448 4";
    test_rfc8448_s4();
    label = "RFC 8448 5, OpenCrypto";
    test_rfc8448_s5(&oc);
    label = "RFC 8448 5, BearSSL";
    test_rfc8448_s5(&bear);
    test_cross(&oc, &bear);
    test_cross(&bear, &oc);
    printf("TLS 1.3 VECTORS %s (%d checks, %d failures)\n", failures ? "FAIL" : "PASS", checks, failures);
    return failures ? 1 : 0;
}
