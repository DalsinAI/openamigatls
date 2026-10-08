#include "opencrypto/opencrypto.h"

#include <stdio.h>
#include <string.h>

static int hex(uint8_t *out, size_t n, const char *s)
{
    size_t i;
    for (i = 0; i < n; ++i) {
        unsigned x;
        if (sscanf(s + i * 2, "%2x", &x) != 1)
            return 0;
        out[i] = (uint8_t)x;
    }
    return 1;
}

static int check_sha(const char *msg, const char *want_hex)
{
    uint8_t got[32], want[32];
    oc_sha256(msg, strlen(msg), got);
    return hex(want, sizeof want, want_hex) && oc_ct_equal(got, want, sizeof got);
}

int main(void)
{
    uint8_t got[64], want[64];
    static const char fox[] = "The quick brown fox jumps over the lazy dog";
    static const uint8_t ikm[22] = {
        0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,
        0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b
    };
    static const uint8_t salt[13] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c
    };
    static const uint8_t info[10] = {
        0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,0xf8,0xf9
    };

    if (!check_sha("", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"))
        return 1;
    if (!check_sha("abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"))
        return 2;

    oc_hmac_sha256("key", 3, fox, strlen(fox), got);
    if (!hex(want, 32, "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8")
        || !oc_ct_equal(got, want, 32))
        return 3;

    if (oc_hkdf_sha256(salt, sizeof salt, ikm, sizeof ikm,
                       info, sizeof info, got, 42))
        return 4;
    if (!hex(want, 42,
        "3cb25f25faacd57a90434f64d0362f2a"
        "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865")
        || !oc_ct_equal(got, want, 42))
        return 5;

    got[0] = 0xaa;
    oc_cleanse(got, sizeof got);
    for (size_t i = 0; i < sizeof got; ++i)
        if (got[i]) return 6;

    puts("OPENCRYPTO PASS sha256 hmac-sha256 hkdf-sha256 ct-cleanse");
    return 0;
}
