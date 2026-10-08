/* OpenCrypto's magic functions (oc_magic.h): the tags, and the 68k bodies,
 * which call the same C the host runs. Built with -fno-lto.
 * Copyright (c) 2026 Dalsin Limited. MIT. */
#include <string.h>

#include "opencrypto/opencrypto.h"
#include "oc_magic.h"

AC_MAGIC(ocm_probe, AC_MAGIC_OC_PROBE)
AC_MAGIC_KEEP uint32_t AC_MAGIC_BODY(ocm_probe)(void)
{
    return 0;                       /* as 68k code, nothing is host code */
}

AC_MAGIC(ocm_x25519, AC_MAGIC_OC_X25519)
AC_MAGIC_KEEP int32_t AC_MAGIC_BODY(ocm_x25519)(uint8_t *out, const uint8_t *scalar, const uint8_t *point)
{
    return oc_x25519(out, scalar, point);
}

AC_MAGIC(ocm_ed25519_verify, AC_MAGIC_OC_ED25519_VERIFY)
AC_MAGIC_KEEP int32_t AC_MAGIC_BODY(ocm_ed25519_verify)(const uint8_t *sig, const uint8_t *pk,
                                                      const uint8_t *msg, uint32_t len)
{
    return oc_ed25519_verify(sig, pk, msg, len);
}

AC_MAGIC(ocm_sntrup761_keypair, AC_MAGIC_OC_SNTRUP761_KEYPAIR)
AC_MAGIC_KEEP int32_t AC_MAGIC_BODY(ocm_sntrup761_keypair)(uint8_t *out, const uint8_t *seed)
{
    oc_sntrup761_keypair(out, out + OC_SNTRUP761_PK_BYTES, seed);
    return 0;
}

AC_MAGIC(ocm_sntrup761_enc, AC_MAGIC_OC_SNTRUP761_ENC)
AC_MAGIC_KEEP int32_t AC_MAGIC_BODY(ocm_sntrup761_enc)(uint8_t *out, const uint8_t *pk, const uint8_t *seed)
{
    oc_sntrup761_enc(out, out + OC_SNTRUP761_CT_BYTES, pk, seed);
    return 0;
}

AC_MAGIC(ocm_sntrup761_dec, AC_MAGIC_OC_SNTRUP761_DEC)
AC_MAGIC_KEEP int32_t AC_MAGIC_BODY(ocm_sntrup761_dec)(uint8_t *out, const uint8_t *ct, const uint8_t *sk)
{
    oc_sntrup761_dec(out, ct, sk);
    return 0;
}

AC_MAGIC(ocm_sha256_blocks, AC_MAGIC_OC_SHA256_BLOCKS)
AC_MAGIC_KEEP int32_t AC_MAGIC_BODY(ocm_sha256_blocks)(uint8_t *state, const uint8_t *data, uint32_t nblocks)
{
    oc_sha256_blocks(state, data, nblocks);
    return 0;
}

AC_MAGIC(ocm_sha512_blocks, AC_MAGIC_OC_SHA512_BLOCKS)
AC_MAGIC_KEEP int32_t AC_MAGIC_BODY(ocm_sha512_blocks)(uint8_t *state, const uint8_t *data, uint32_t nblocks)
{
    oc_sha512_blocks(state, data, nblocks);
    return 0;
}

AC_MAGIC(ocm_chacha20, AC_MAGIC_OC_CHACHA20)
AC_MAGIC_KEEP int32_t AC_MAGIC_BODY(ocm_chacha20)(uint8_t *out, const uint8_t *in, uint32_t len, const uint8_t *p)
{
    uint64_t ctr = 0;
    int i;
    for (i = 0; i < 8; ++i) ctr = ctr << 8 | p[40 + i];
    oc_chacha20_xor(out, in, len, p, p + 32, ctr);
    return 0;
}

AC_MAGIC(ocm_poly1305, AC_MAGIC_OC_POLY1305)
AC_MAGIC_KEEP int32_t AC_MAGIC_BODY(ocm_poly1305)(uint8_t *tag, const uint8_t *data, uint32_t len, const uint8_t *key)
{
    oc_poly1305(tag, data, len, key);
    return 0;
}

AC_MAGIC(ocm_aes, AC_MAGIC_OC_AES)
AC_MAGIC_KEEP int32_t AC_MAGIC_BODY(ocm_aes)(uint8_t *buf, uint32_t len, const uint8_t *key, uint32_t keylen,
                                           const uint8_t *iv, uint32_t mode)
{
    return oc_aes(buf, len, key, keylen, iv, (int)mode);
}

AC_MAGIC(ocm_rsa_public, AC_MAGIC_OC_RSA_PUBLIC)
AC_MAGIC_KEEP int32_t AC_MAGIC_BODY(ocm_rsa_public)(uint8_t *out, const uint8_t *sig, const uint8_t *n,
                                                  uint32_t nlen, const uint8_t *e, uint32_t elen)
{
    return oc_rsa_public(out, sig, n, nlen, e, elen);
}

AC_MAGIC(ocm_ecdsa_verify, AC_MAGIC_OC_ECDSA_VERIFY)
AC_MAGIC_KEEP int32_t AC_MAGIC_BODY(ocm_ecdsa_verify)(int32_t curve, const uint8_t *qx, const uint8_t *qy,
                                                    const uint8_t *r, const uint8_t *s,
                                                    const uint8_t *hash, uint32_t hlen)
{
    return oc_ecdsa_verify(curve, qx, qy, r, s, hash, hlen);
}
