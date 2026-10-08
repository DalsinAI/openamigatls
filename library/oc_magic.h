/* OpenCrypto's magic functions: each heavy operation is a function of
 * ours that AC090 (AmigaChrome's 68k core) runs as host code, and that
 * runs as its own 68k code everywhere else (a real Amiga, a PiStorm,
 * another emulator).
 * Copyright (c) 2026 Dalsin Limited. MIT.
 *
 * The tag is AmigaChrome's published one (amigachrome-guest
 * common/amiga/ac_magic.h, version 1): the function's entry is
 *     BRA.S *+12; DC.L 'ACMF'; DC.W $0001; DC.L id; JMP body
 * and the ids below are in ac_magic.h's list and in AC090's table
 * (machines/cpus/m68k-ac090/native/jit_magic.c, magic_defs), added
 * together. AC090 checks every call (plain RAM only, the sizes, no
 * overlap) and runs the 68k body when it declines; AC090_MAGIC=verify
 * runs both and compares, so each body here must do byte for byte what
 * the host does: they are the same C (src/), compiled twice.
 *
 * The rules (ac_magic.h): GCC's stack convention (not -mregparm), 32-bit
 * arguments, the result in D0; each function writes one range (its first
 * argument) and nothing else but its stack; built with -fno-lto. */
#ifndef OC_MAGIC_H
#define OC_MAGIC_H

#include <stdint.h>

#define AC_MAGIC_OC_PROBE           0x00010200
#define AC_MAGIC_OC_X25519          0x00010201
#define AC_MAGIC_OC_ED25519_VERIFY  0x00010202
#define AC_MAGIC_OC_SNTRUP761_KEYPAIR 0x00010203
#define AC_MAGIC_OC_SNTRUP761_ENC   0x00010204
#define AC_MAGIC_OC_SNTRUP761_DEC   0x00010205
#define AC_MAGIC_OC_SHA256_BLOCKS   0x00010206
#define AC_MAGIC_OC_SHA512_BLOCKS   0x00010207
#define AC_MAGIC_OC_CHACHA20        0x00010208
#define AC_MAGIC_OC_POLY1305        0x00010209
#define AC_MAGIC_OC_AES             0x0001020a
#define AC_MAGIC_OC_RSA_PUBLIC      0x0001020b
#define AC_MAGIC_OC_ECDSA_VERIFY    0x0001020c

#define AC_MAGIC_STR_(x) #x
#define AC_MAGIC_STR(x) AC_MAGIC_STR_(x)
#ifdef __USER_LABEL_PREFIX__
#define AC_MAGIC_SYM(name) AC_MAGIC_STR(__USER_LABEL_PREFIX__) #name
#else
#define AC_MAGIC_SYM(name) #name
#endif
#define AC_MAGIC_BODY(name) name##_acbody
#define AC_MAGIC_KEEP __attribute__((used, noinline))
#define AC_MAGIC(name, id)                                                   \
    __attribute__((used, noinline, noclone)) static void name##_actag(void) \
    {                                                                        \
        __asm__ volatile("\t.globl\t" AC_MAGIC_SYM(name) "\n"                \
                         AC_MAGIC_SYM(name) ":\n"                            \
                         "\t.short\t0x600a\n"                                \
                         "\t.long\t0x41434d46\n"                             \
                         "\t.short\t0x0001\n"                                \
                         "\t.long\t" AC_MAGIC_STR(id) "\n"                   \
                         "\tjmp\t" AC_MAGIC_SYM(name##_acbody) "\n");        \
    }

/* The tagged functions. Byte arrays throughout; what each writes is its
 * first argument, of the size given.
 *   ocm_probe()                                -> which of OCF_* run as host code (0 as 68k code)
 *   ocm_x25519(out[32], scalar[32], point[32]) -> oc_x25519's answer
 *   ocm_ed25519_verify(sig[64], pk[32], msg, len) -> 1 valid, 0 not (writes nothing)
 *   ocm_sntrup761_keypair(out[1158 + 1763] = pk || sk, seed[32])
 *   ocm_sntrup761_enc(out[1039 + 32] = ct || ss, pk[1158], seed[32])
 *   ocm_sntrup761_dec(out[32] = ss, ct[1039], sk[1763])
 *   ocm_sha256_blocks(state[32], data, nblocks)   (state big-endian)
 *   ocm_sha512_blocks(state[64], data, nblocks)
 *   ocm_chacha20(out[len], in, len, p[48] = key[32] || nonce[8] || counter, 8 bytes big-endian)
 *   ocm_poly1305(tag[16], data, len, key[32])
 *   ocm_aes(buf[len], len, key, keylen, iv[16], mode) -> oc_aes's answer
 *   ocm_rsa_public(out[nlen], sig[nlen], n, nlen, e, elen) -> oc_rsa_public's answer
 *   ocm_ecdsa_verify(curve, qx, qy, r, s, hash, hlen) -> 1 valid, 0 not (writes nothing) */
uint32_t ocm_probe(void);
int32_t ocm_x25519(uint8_t *out, const uint8_t *scalar, const uint8_t *point);
int32_t ocm_ed25519_verify(const uint8_t *sig, const uint8_t *pk, const uint8_t *msg, uint32_t len);
int32_t ocm_sntrup761_keypair(uint8_t *out, const uint8_t *seed);
int32_t ocm_sntrup761_enc(uint8_t *out, const uint8_t *pk, const uint8_t *seed);
int32_t ocm_sntrup761_dec(uint8_t *out, const uint8_t *ct, const uint8_t *sk);
int32_t ocm_sha256_blocks(uint8_t *state, const uint8_t *data, uint32_t nblocks);
int32_t ocm_sha512_blocks(uint8_t *state, const uint8_t *data, uint32_t nblocks);
int32_t ocm_chacha20(uint8_t *out, const uint8_t *in, uint32_t len, const uint8_t *p);
int32_t ocm_poly1305(uint8_t *tag, const uint8_t *data, uint32_t len, const uint8_t *key);
int32_t ocm_aes(uint8_t *buf, uint32_t len, const uint8_t *key, uint32_t keylen, const uint8_t *iv, uint32_t mode);
int32_t ocm_rsa_public(uint8_t *out, const uint8_t *sig, const uint8_t *n, uint32_t nlen, const uint8_t *e, uint32_t elen);
int32_t ocm_ecdsa_verify(int32_t curve, const uint8_t *qx, const uint8_t *qy, const uint8_t *r,
                         const uint8_t *s, const uint8_t *hash, uint32_t hlen);

#endif
