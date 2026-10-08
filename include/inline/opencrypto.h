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

#define OC_Accelerated() LP0(0x5a, ULONG, OC_Accelerated, , OPENCRYPTO_BASE_NAME)
#define OC_X25519(req) LP1(0x60, LONG, OC_X25519, struct OCX25519Request *, req, a0, , OPENCRYPTO_BASE_NAME)
#define OC_Ed25519Verify(req) LP1(0x66, LONG, OC_Ed25519Verify, struct OCEd25519Request *, req, a0, , OPENCRYPTO_BASE_NAME)
#define OC_SNTRUP761KeyPair(req) LP1(0x6c, LONG, OC_SNTRUP761KeyPair, struct OCKemRequest *, req, a0, , OPENCRYPTO_BASE_NAME)
#define OC_SNTRUP761Enc(req) LP1(0x72, LONG, OC_SNTRUP761Enc, struct OCKemRequest *, req, a0, , OPENCRYPTO_BASE_NAME)
#define OC_SNTRUP761Dec(req) LP1(0x78, LONG, OC_SNTRUP761Dec, struct OCKemRequest *, req, a0, , OPENCRYPTO_BASE_NAME)
#define OC_SHA256Blocks(req) LP1(0x7e, LONG, OC_SHA256Blocks, struct OCBlocksRequest *, req, a0, , OPENCRYPTO_BASE_NAME)
#define OC_SHA512Blocks(req) LP1(0x84, LONG, OC_SHA512Blocks, struct OCBlocksRequest *, req, a0, , OPENCRYPTO_BASE_NAME)
#define OC_ChaCha20(req) LP1(0x8a, LONG, OC_ChaCha20, struct OCChaChaRequest *, req, a0, , OPENCRYPTO_BASE_NAME)
#define OC_Poly1305(req) LP1(0x90, LONG, OC_Poly1305, struct OCPolyRequest *, req, a0, , OPENCRYPTO_BASE_NAME)
#define OC_AES(req) LP1(0x96, LONG, OC_AES, struct OCAESRequest *, req, a0, , OPENCRYPTO_BASE_NAME)
#define OC_RSAPublic(req) LP1(0x9c, LONG, OC_RSAPublic, struct OCRSARequest *, req, a0, , OPENCRYPTO_BASE_NAME)
#define OC_ECDSAVerify(req) LP1(0xa2, LONG, OC_ECDSAVerify, struct OCECDSARequest *, req, a0, , OPENCRYPTO_BASE_NAME)

#endif
