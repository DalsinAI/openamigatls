/* OpenCrypto: RSASSA-PSS signature checking, the EMSA-PSS-VERIFY steps of
 * RFC 8017 section 9.1.2 with MGF1 over the same hash. TLS 1.3 needs it
 * for RSA certificates (rsa_pss_rsae_sha256 and _sha384). Public values
 * only, so written for clarity, not constant time.
 *
 * This file stands alone: the hash comes in as a function, so that
 * opentls.library can build it over its own hashes without the rest of
 * OpenCrypto. oc_rsa_pss_verify() (opencrypto_pubkey.c) puts it together
 * with RSA's public operation and OpenCrypto's SHA-2.
 *
 * MIT licensed and free. Copyright (c) 2026 The AmigaChrome Team. */
#include "opencrypto/opencrypto.h"

#include <string.h>

#define PSS_HASH_MAX 64

/* MGF1: mask ^= the first len bytes of Hash(seed || 0) || Hash(seed || 1) ... */
static void mgf1_xor(uint8_t *mask, size_t len, const uint8_t *seed, size_t hlen, oc_hash_fn hash)
{
    uint8_t in[PSS_HASH_MAX + 4], out[PSS_HASH_MAX];
    uint32_t counter = 0;
    size_t done = 0, i, n;
    memcpy(in, seed, hlen);
    while (done < len) {
        in[hlen] = (uint8_t)(counter >> 24);
        in[hlen + 1] = (uint8_t)(counter >> 16);
        in[hlen + 2] = (uint8_t)(counter >> 8);
        in[hlen + 3] = (uint8_t)counter;
        hash(in, hlen + 4, out);
        n = len - done < hlen ? len - done : hlen;
        for (i = 0; i < n; ++i) mask[done + i] ^= out[i];
        done += n;
        ++counter;
    }
}

int oc_emsa_pss_verify(const uint8_t *em, size_t em_length, size_t mod_bits,
                       const uint8_t *mhash, size_t hash_length, long salt_length,
                       oc_hash_fn hash)
{
    uint8_t db[OC_RSA_MAX_BYTES], mp[8 + PSS_HASH_MAX + OC_RSA_MAX_BYTES], h2[PSS_HASH_MAX];
    size_t em_bits, len, db_len, i, slen;
    uint8_t top, diff = 0;

    if (!em || !mhash || !hash || !mod_bits || hash_length == 0 || hash_length > PSS_HASH_MAX)
        return 0;
    /* EM is the signature's representative in em_bits = mod_bits - 1 bits;
     * it may be a byte shorter than the modulus, whose first byte is then 0 */
    em_bits = mod_bits - 1;
    len = (em_bits + 7) / 8;
    if (em_length < len || len > sizeof db) return 0;
    for (i = 0; i < em_length - len; ++i)
        if (em[i]) return 0;
    em += em_length - len;
    if (len < hash_length + 2 || em[len - 1] != 0xBC) return 0;
    db_len = len - hash_length - 1;
    top = (uint8_t)(0xFF >> (8 * len - em_bits));
    if (em[0] & ~top) return 0;
    memcpy(db, em, db_len);
    mgf1_xor(db, db_len, em + db_len, hash_length, hash);
    db[0] &= top;
    /* DB = PS (zeros) || 0x01 || salt */
    for (i = 0; i < db_len && db[i] == 0; ++i) {}
    if (i == db_len || db[i] != 0x01) return 0;
    slen = db_len - i - 1;
    if (salt_length >= 0 && slen != (size_t)salt_length) return 0;
    memset(mp, 0, 8);
    memcpy(mp + 8, mhash, hash_length);
    memcpy(mp + 8 + hash_length, db + i + 1, slen);
    hash(mp, 8 + hash_length + slen, h2);
    for (i = 0; i < hash_length; ++i) diff |= (uint8_t)(h2[i] ^ em[db_len + i]);
    return diff == 0;
}
