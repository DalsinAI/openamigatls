/* OpenTLS: TLS 1.3's key schedule and record protection (RFC 8446
 * sections 5.2, 7.1 and 7.3), written from the RFC. HKDF is HMAC over
 * BearSSL's hash classes; the records are AES-GCM (put together here from
 * the connection's AES-CTR and GHASH tables), or ChaCha20-Poly1305 over its ChaCha20 and
 * Poly1305 ones (ot_glue.c chooses: OpenCrypto's where AC090 runs them as
 * host code, BearSSL's constant-time 68k code otherwise).
 * tests/test_tls13_vectors.c checks all of it against RFC 8448.
 * MIT licensed and free. Copyright (c) 2026 The AmigaChrome Team. */
#include "ot_tls13.h"

static const struct ot13_suite suites[] = {
    { OT13_AES_128_GCM_SHA256, "TLS_AES_128_GCM_SHA256", 0, 16, &br_sha256_vtable, 32 },
    { OT13_AES_256_GCM_SHA384, "TLS_AES_256_GCM_SHA384", 0, 32, &br_sha384_vtable, 48 },
    { OT13_CHACHA20_POLY1305_SHA256, "TLS_CHACHA20_POLY1305_SHA256", 1, 32, &br_sha256_vtable, 32 },
};

const struct ot13_suite *ot13_suite(unsigned id)
{
    size_t i;
    for (i = 0; i < sizeof suites / sizeof suites[0]; ++i)
        if (suites[i].id == id) return &suites[i];
    return NULL;
}

static size_t hash_len(const br_hash_class *h)
{
    return (h->desc >> BR_HASHDESC_OUT_OFF) & BR_HASHDESC_OUT_MASK;
}

/* ---- HKDF (RFC 5869) and the TLS 1.3 labels ---- */

void ot13_extract(const br_hash_class *h, const unsigned char *salt,
                  const unsigned char *ikm, size_t ikm_len, unsigned char *prk)
{
    static const unsigned char zeros[OT13_HASH_MAX];
    br_hmac_key_context kc;
    br_hmac_context hc;
    size_t hl = hash_len(h);
    br_hmac_key_init(&kc, h, salt ? salt : zeros, hl);
    br_hmac_init(&hc, &kc, 0);
    br_hmac_update(&hc, ikm ? ikm : zeros, ikm ? ikm_len : hl);
    br_hmac_out(&hc, prk);
    memset(&kc, 0, sizeof kc);
    memset(&hc, 0, sizeof hc);
}

void ot13_expand_label(const br_hash_class *h, const unsigned char *secret, const char *label,
                       const unsigned char *context, size_t context_len,
                       unsigned char *out, size_t out_len)
{
    /* HkdfLabel: length (2), "tls13 " + label (1 + n), context (1 + n) */
    unsigned char info[2 + 1 + 6 + 32 + 1 + OT13_HASH_MAX], t[OT13_HASH_MAX], ctr = 1;
    size_t ll = strlen(label), il = 0, hl = hash_len(h), done = 0, n;
    br_hmac_key_context kc;
    br_hmac_context hc;
    if (ll > 32 || context_len > OT13_HASH_MAX) return;     /* never with ours */
    info[il++] = (unsigned char)(out_len >> 8);
    info[il++] = (unsigned char)out_len;
    info[il++] = (unsigned char)(6 + ll);
    memcpy(info + il, "tls13 ", 6);
    memcpy(info + il + 6, label, ll);
    il += 6 + ll;
    info[il++] = (unsigned char)context_len;
    if (context_len) memcpy(info + il, context, context_len);
    il += context_len;
    br_hmac_key_init(&kc, h, secret, hl);
    while (done < out_len) {
        br_hmac_init(&hc, &kc, 0);
        if (done) br_hmac_update(&hc, t, hl);
        br_hmac_update(&hc, info, il);
        br_hmac_update(&hc, &ctr, 1);
        br_hmac_out(&hc, t);
        n = out_len - done < hl ? out_len - done : hl;
        memcpy(out + done, t, n);
        done += n;
        ++ctr;
    }
    memset(t, 0, sizeof t);
    memset(&kc, 0, sizeof kc);
    memset(&hc, 0, sizeof hc);
}

void ot13_derive(const br_hash_class *h, const unsigned char *secret, const char *label,
                 const unsigned char *thash, unsigned char *out)
{
    unsigned char empty[OT13_HASH_MAX];
    size_t hl = hash_len(h);
    if (!thash) {
        br_hash_compat_context hc;
        h->init(&hc.vtable);
        h->out(&hc.vtable, empty);
        thash = empty;
    }
    ot13_expand_label(h, secret, label, thash, hl, out, hl);
}

void ot13_finished(const br_hash_class *h, const unsigned char *base,
                   const unsigned char *thash, unsigned char *out)
{
    unsigned char fk[OT13_HASH_MAX];
    br_hmac_key_context kc;
    br_hmac_context hc;
    size_t hl = hash_len(h);
    ot13_expand_label(h, base, "finished", NULL, 0, fk, hl);
    br_hmac_key_init(&kc, h, fk, hl);
    br_hmac_init(&hc, &kc, 0);
    br_hmac_update(&hc, thash, hl);
    br_hmac_out(&hc, out);
    memset(fk, 0, sizeof fk);
    memset(&kc, 0, sizeof kc);
}

/* ---- traffic keys ---- */

static int keys_from_secret(struct ot13_keys *k)
{
    const struct ot13_suite *s = k->suite;
    ot13_expand_label(s->hash, k->secret, "key", NULL, 0, k->key, s->key_len);
    ot13_expand_label(s->hash, k->secret, "iv", NULL, 0, k->iv, 12);
    k->seq = 0;
    if (!s->chacha) {
        const br_block_ctr_class *ctr = k->impls->aes_ctr;
        if (ctr->context_size > sizeof k->ctr) return -1;
        ctr->init(&k->ctr.vtable, k->key, s->key_len);
        memset(k->h, 0, 16);
        ctr->run(&k->ctr.vtable, k->h, 0, k->h, 16);     /* the block 0: counter 0, IV 0 */
    }
    return 0;
}

int ot13_keys_set(struct ot13_keys *k, const struct ot13_suite *s,
                  const struct ot_impls *impls, const unsigned char *secret)
{
    k->suite = s;
    k->impls = impls;
    memcpy(k->secret, secret, s->hash_len);
    return keys_from_secret(k);
}

int ot13_keys_next(struct ot13_keys *k)
{
    unsigned char next[OT13_HASH_MAX];
    ot13_expand_label(k->suite->hash, k->secret, "traffic upd", NULL, 0, next, k->suite->hash_len);
    memcpy(k->secret, next, k->suite->hash_len);
    memset(next, 0, sizeof next);
    return keys_from_secret(k);
}

void ot13_keys_clear(struct ot13_keys *k)
{
    memset(k, 0, sizeof *k);
}

/* ---- records ---- */

static void nonce(const struct ot13_keys *k, unsigned char *n)
{
    int i;
    memcpy(n, k->iv, 12);
    for (i = 0; i < 8; ++i)
        n[11 - i] ^= (unsigned char)(k->seq >> (8 * i));
}

/* AES-GCM (NIST SP 800-38D) with a 96-bit nonce: the data runs in CTR
 * mode from counter 2, the tag is GHASH(aad, ciphertext, lengths) masked
 * with the counter 1 block */
static void gcm(struct ot13_keys *k, int encrypt, const unsigned char *n, const unsigned char *aad,
                size_t alen, unsigned char *data, size_t len, unsigned char *tag)
{
    const br_block_ctr_class *ctr = k->ctr.vtable;
    unsigned char y[16], lens[16], mask[16];
    int i;
    memset(y, 0, 16);
    k->impls->ghash(y, k->h, aad, alen);
    if (!encrypt) k->impls->ghash(y, k->h, data, len);
    ctr->run(&k->ctr.vtable, n, 2, data, len);
    if (encrypt) k->impls->ghash(y, k->h, data, len);
    memset(lens, 0, 16);
    for (i = 0; i < 8; ++i) {
        lens[7 - i] = (unsigned char)(((uint64_t)alen << 3) >> (8 * i));
        lens[15 - i] = (unsigned char)(((uint64_t)len << 3) >> (8 * i));
    }
    k->impls->ghash(y, k->h, lens, 16);
    memset(mask, 0, 16);
    ctr->run(&k->ctr.vtable, n, 1, mask, 16);
    for (i = 0; i < 16; ++i) tag[i] = (unsigned char)(y[i] ^ mask[i]);
}

size_t ot13_seal(struct ot13_keys *k, unsigned char *rec, int type, size_t len)
{
    unsigned char n[12], *data = rec + 5;
    size_t clen = len + 1 + 16;
    data[len++] = (unsigned char)type;
    rec[0] = BR_SSL_APPLICATION_DATA;
    rec[1] = 3;
    rec[2] = 3;
    rec[3] = (unsigned char)(clen >> 8);
    rec[4] = (unsigned char)clen;
    nonce(k, n);
    if (k->suite->chacha) {
        k->impls->poly1305(k->key, n, data, len, rec, 5, data + len, k->impls->chacha20, 1);
    } else {
        gcm(k, 1, n, rec, 5, data, len, data + len);
    }
    ++k->seq;
    return 5 + clen;
}

int ot13_open(struct ot13_keys *k, unsigned char *rec, size_t reclen, int *type, size_t *len)
{
    unsigned char n[12], tag[16], *data = rec + 5, diff = 0;
    size_t clen, i;
    if (reclen < 5 + 17 || reclen > OT13_RX_MAX) return BR_ERR_BAD_PARAM;
    clen = reclen - 5 - 16;
    nonce(k, n);
    if (k->suite->chacha) {
        k->impls->poly1305(k->key, n, data, clen, rec, 5, tag, k->impls->chacha20, 0);
    } else {
        gcm(k, 0, n, rec, 5, data, clen, tag);
    }
    for (i = 0; i < 16; ++i) diff |= (unsigned char)(tag[i] ^ data[clen + i]);
    if (diff) return BR_ERR_BAD_MAC;
    ++k->seq;
    /* TLSInnerPlaintext: content, the type, zeros */
    while (clen && data[clen - 1] == 0) --clen;
    if (!clen) return BR_ERR_BAD_PARAM;
    *type = data[--clen];
    if (clen > OT13_RECORD_MAX) return BR_ERR_TOO_LARGE;
    *len = clen;
    return 0;
}
