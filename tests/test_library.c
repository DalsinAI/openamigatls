#include <exec/types.h>
#include <exec/libraries.h>
#include <proto/exec.h>
#include <proto/opencrypto.h>

#include <stdio.h>
#include <string.h>

struct Library *OpenCryptoBase;

static int same_hex(const UBYTE *data, ULONG length, const char *hex)
{
    ULONG i;
    for (i = 0; i < length; ++i) {
        unsigned v;
        if (sscanf(hex + i * 2, "%2x", &v) != 1 || data[i] != (UBYTE)v)
            return 0;
    }
    return 1;
}

#define CHECK(x) do { if (!(x)) {     printf("OPENCRYPTOLIB FAIL line=%d expr=%s\n", __LINE__, #x);     rc = 20; goto done; } } while (0)

int main(void)
{
    int rc = 0;
    ULONG i;
    UBYTE out[64];
    struct OCBufferHash hash;
    struct OCHmacRequest hmac;
    struct OCCompareRequest cmp;
    struct OCCleanseRequest clean;

    OpenCryptoBase = OpenLibrary((CONST_STRPTR)OPENCRYPTOLIB_NAME,
                                 OPENCRYPTOLIB_VERSION);
    CHECK(OpenCryptoBase != NULL);
    CHECK((OC_Version() >> 16) == OPENCRYPTOLIB_VERSION);

    hash.data = "abc";
    hash.length = 3;
    hash.out = out;
    OC_SHA256(&hash);
    CHECK(same_hex(out, 32,
        "ba7816bf8f01cfea414140de5dae2223"
        "b00361a396177a9cb410ff61f20015ad"));

    OC_SHA384(&hash);
    CHECK(same_hex(out, 48,
        "cb00753f45a35e8bb5a03d699ac65007"
        "272c32ab0eded1631a8b605a43ff5bed"
        "8086072ba1e7cc2358baeca134c825a7"));

    hmac.key = "key";
    hmac.key_length = 3;
    hmac.data = "The quick brown fox jumps over the lazy dog";
    hmac.data_length = (ULONG)strlen((const char *)hmac.data);
    hmac.out = out;
    OC_HMAC_SHA256(&hmac);
    CHECK(same_hex(out, 32,
        "f7bc83f430538424b13298e6aa6fb143"
        "ef4d59a14946175997479dbc2d1a3cd8"));

    cmp.a = out;
    cmp.b = out;
    cmp.length = 32;
    CHECK(OC_CtEqual(&cmp) == 1);

    clean.data = out;
    clean.length = sizeof out;
    OC_Cleanse(&clean);
    for (i = 0; i < sizeof out; ++i)
        CHECK(out[i] == 0);

    puts("OPENCRYPTOLIB PASS sha256 sha384 hmac ct-cleanse");

done:
    if (OpenCryptoBase)
        CloseLibrary(OpenCryptoBase);
    return rc;
}
