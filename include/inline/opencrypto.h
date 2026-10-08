#ifndef INLINE_OPENCRYPTO_H
#define INLINE_OPENCRYPTO_H

#ifndef __INLINE_MACROS_H
#include <inline/macros.h>
#endif

#ifndef OPENCRYPTO_BASE_NAME
#define OPENCRYPTO_BASE_NAME OpenCryptoBase
#endif

#define OC_Version() LP0(0x1e, ULONG, OC_Version, , OPENCRYPTO_BASE_NAME)
#define OC_SHA256(req) LP1NR(0x24, OC_SHA256, struct OCBufferHash *, req, a0, , OPENCRYPTO_BASE_NAME)
#define OC_SHA384(req) LP1NR(0x2a, OC_SHA384, struct OCBufferHash *, req, a0, , OPENCRYPTO_BASE_NAME)
#define OC_SHA512(req) LP1NR(0x30, OC_SHA512, struct OCBufferHash *, req, a0, , OPENCRYPTO_BASE_NAME)
#define OC_HMAC_SHA256(req) LP1NR(0x36, OC_HMAC_SHA256, struct OCHmacRequest *, req, a0, , OPENCRYPTO_BASE_NAME)
#define OC_HMAC_SHA384(req) LP1NR(0x3c, OC_HMAC_SHA384, struct OCHmacRequest *, req, a0, , OPENCRYPTO_BASE_NAME)
#define OC_HKDF_SHA256(req) LP1(0x42, LONG, OC_HKDF_SHA256, struct OCHKDFRequest *, req, a0, , OPENCRYPTO_BASE_NAME)
#define OC_HKDF_SHA384(req) LP1(0x48, LONG, OC_HKDF_SHA384, struct OCHKDFRequest *, req, a0, , OPENCRYPTO_BASE_NAME)
#define OC_CtEqual(req) LP1(0x4e, LONG, OC_CtEqual, struct OCCompareRequest *, req, a0, , OPENCRYPTO_BASE_NAME)
#define OC_Cleanse(req) LP1NR(0x54, OC_Cleanse, struct OCCleanseRequest *, req, a0, , OPENCRYPTO_BASE_NAME)

#endif
