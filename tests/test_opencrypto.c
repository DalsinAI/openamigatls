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

static int check_sha256(const char *msg, const char *want_hex)
{
    uint8_t got[32], want[32];
    oc_sha256(msg, strlen(msg), got);
    return hex(want, sizeof want, want_hex) && oc_ct_equal(got, want, sizeof got);
}

static int check_sha384(const char *msg, const char *want_hex)
{
    uint8_t got[48], want[48];
    oc_sha384(msg, strlen(msg), got);
    return hex(want, sizeof want, want_hex) && oc_ct_equal(got, want, sizeof got);
}

static int check_sha512(const char *msg, const char *want_hex)
{
    uint8_t got[64], want[64];
    oc_sha512(msg, strlen(msg), got);
    return hex(want, sizeof want, want_hex) && oc_ct_equal(got, want, sizeof got);
}

int main(void)
{
    uint8_t got[96], want[96];
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

    if (!check_sha256("", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"))
        return 1;
    if (!check_sha256("abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"))
        return 2;

    if (!check_sha384("abc",
        "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded163"
        "1a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"))
        return 3;

    if (!check_sha512("",
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc"
        "83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f"
        "63b931bd47417a81a538327af927da3e"))
        return 4;

    oc_hmac_sha256("key", 3, fox, strlen(fox), got);
    if (!hex(want, 32, "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8")
        || !oc_ct_equal(got, want, 32))
        return 5;

    oc_hmac_sha384("key", 3, fox, strlen(fox), got);
    if (!hex(want, 48,
        "d7f4727e2c0b39ae0f1e40cc96f60242d5b7801841cea6fc"
        "592c5d3e1ae50700582a96cf35e1e554995fe4e03381c237")
        || !oc_ct_equal(got, want, 48))
        return 6;

    if (oc_hkdf_sha256(salt, sizeof salt, ikm, sizeof ikm,
                       info, sizeof info, got, 42))
        return 7;
    if (!hex(want, 42,
        "3cb25f25faacd57a90434f64d0362f2a"
        "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865")
        || !oc_ct_equal(got, want, 42))
        return 8;

    if (oc_hkdf_sha384(salt, sizeof salt, ikm, sizeof ikm,
                       info, sizeof info, got, 42))
        return 9;
    if (!hex(want, 42,
        "9b5097a86038b805309076a44b3a9f38063e25b516dcbf36"
        "9f394cfab43685f748b6457763e4f0204fc5")
        || !oc_ct_equal(got, want, 42))
        return 10;

    got[0] = 0xaa;
    oc_cleanse(got, sizeof got);
    for (size_t i = 0; i < sizeof got; ++i)
        if (got[i]) return 11;

    puts("OPENCRYPTO PASS sha256 sha384 sha512 hmac hkdf ct-cleanse");
    return 0;
}
