#ifndef LIBRARIES_OPENCRYPTO_H
#define LIBRARIES_OPENCRYPTO_H

#include <exec/types.h>
#include <opencrypto/opencrypto.h>

#define OPENCRYPTOLIB_NAME "opencrypto.library"
#define OPENCRYPTOLIB_VERSION 1
#define OPENCRYPTOLIB_REVISION 0

struct OCBufferHash {
    const void *data;
    ULONG length;
    UBYTE *out;
};

struct OCHmacRequest {
    const void *key;
    ULONG key_length;
    const void *data;
    ULONG data_length;
    UBYTE *out;
};

struct OCHKDFRequest {
    const void *salt;
    ULONG salt_length;
    const void *ikm;
    ULONG ikm_length;
    const void *info;
    ULONG info_length;
    void *out;
    ULONG out_length;
};

struct OCCompareRequest {
    const void *a;
    const void *b;
    ULONG length;
};

struct OCCleanseRequest {
    void *data;
    ULONG length;
};

#endif
