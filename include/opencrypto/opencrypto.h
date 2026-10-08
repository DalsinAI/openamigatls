#ifndef OPENCRYPTO_OPENCRYPTO_H
#define OPENCRYPTO_OPENCRYPTO_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define OC_SHA256_BYTES 32
#define OC_SHA256_BLOCK_BYTES 64
#define OC_SHA384_BYTES 48
#define OC_SHA512_BYTES 64
#define OC_SHA512_BLOCK_BYTES 128

typedef struct OCSHA256 {
    uint32_t h[8];
    uint64_t total_bytes;
    uint8_t block[OC_SHA256_BLOCK_BYTES];
    size_t block_used;
} OCSHA256;

typedef struct OCSHA512 {
    uint64_t h[8];
    uint64_t total_bytes;
    uint8_t block[OC_SHA512_BLOCK_BYTES];
    size_t block_used;
} OCSHA512;

void oc_sha256_init(OCSHA256 *ctx);
void oc_sha256_update(OCSHA256 *ctx, const void *data, size_t length);
void oc_sha256_final(OCSHA256 *ctx, uint8_t out[OC_SHA256_BYTES]);
void oc_sha256(const void *data, size_t length, uint8_t out[OC_SHA256_BYTES]);

void oc_hmac_sha256(const void *key, size_t key_length,
                    const void *data, size_t data_length,
                    uint8_t out[OC_SHA256_BYTES]);

int oc_hkdf_sha256(const void *salt, size_t salt_length,
                   const void *ikm, size_t ikm_length,
                   const void *info, size_t info_length,
                   void *out, size_t out_length);

void oc_sha384(const void *data, size_t length, uint8_t out[OC_SHA384_BYTES]);
void oc_sha512(const void *data, size_t length, uint8_t out[OC_SHA512_BYTES]);

void oc_hmac_sha384(const void *key, size_t key_length,
                    const void *data, size_t data_length,
                    uint8_t out[OC_SHA384_BYTES]);

int oc_hkdf_sha384(const void *salt, size_t salt_length,
                   const void *ikm, size_t ikm_length,
                   const void *info, size_t info_length,
                   void *out, size_t out_length);

void oc_sha512_init(OCSHA512 *ctx);
void oc_sha512_update(OCSHA512 *ctx, const void *data, size_t length);
void oc_sha512_final(OCSHA512 *ctx, uint8_t out[OC_SHA512_BYTES]);

/* The compression functions over whole blocks; the chaining value is kept
 * as big-endian bytes (32 for SHA-256, 64 for SHA-512), the same on every
 * machine. For callers that do their own buffering and padding. */
void oc_sha256_blocks(uint8_t state[OC_SHA256_BYTES], const void *data, size_t nblocks);
void oc_sha512_blocks(uint8_t state[OC_SHA512_BYTES], const void *data, size_t nblocks);

/* ---- for SSH's key exchanges, host keys and default cipher (8 Oct 2026) ---- */

#define OC_SEED_BYTES 32
#define OC_X25519_BYTES 32
#define OC_ED25519_PUBLIC_BYTES 32
#define OC_ED25519_SIGNATURE_BYTES 64
#define OC_SNTRUP761_PK_BYTES 1158
#define OC_SNTRUP761_SK_BYTES 1763
#define OC_SNTRUP761_CT_BYTES 1039
#define OC_SNTRUP761_SS_BYTES 32

/* X25519 (RFC 7748), constant time: out = scalar * point. 0, or -1 when
 * the result is all zeros (a small-order point; the caller refuses it). */
int oc_x25519(uint8_t out[OC_X25519_BYTES], const uint8_t scalar[OC_X25519_BYTES],
              const uint8_t point[OC_X25519_BYTES]);
void oc_x25519_base(uint8_t out[OC_X25519_BYTES], const uint8_t scalar[OC_X25519_BYTES]);

/* Ed25519 verification (RFC 8032): 1 when sig is pk's signature of msg. */
int oc_ed25519_verify(const uint8_t sig[OC_ED25519_SIGNATURE_BYTES],
                      const uint8_t pk[OC_ED25519_PUBLIC_BYTES],
                      const void *msg, size_t length);

/* sntrup761 as SSH's sntrup761x25519-sha512 uses it, constant time. The
 * randomness comes from a 32-byte seed (expanded with ChaCha20), so the
 * caller supplies fresh secret random bytes for every call. */
void oc_sntrup761_keypair(uint8_t pk[OC_SNTRUP761_PK_BYTES], uint8_t sk[OC_SNTRUP761_SK_BYTES],
                          const uint8_t seed[OC_SEED_BYTES]);
void oc_sntrup761_enc(uint8_t ct[OC_SNTRUP761_CT_BYTES], uint8_t ss[OC_SNTRUP761_SS_BYTES],
                      const uint8_t pk[OC_SNTRUP761_PK_BYTES], const uint8_t seed[OC_SEED_BYTES]);
void oc_sntrup761_dec(uint8_t ss[OC_SNTRUP761_SS_BYTES], const uint8_t ct[OC_SNTRUP761_CT_BYTES],
                      const uint8_t sk[OC_SNTRUP761_SK_BYTES]);

/* ChaCha20 with a 64-bit nonce and 64-bit block counter (Bernstein's
 * original, as chacha20-poly1305@openssh.com uses); in may be NULL for the
 * key stream itself, or equal to out. Poly1305 (RFC 8439 section 2.5). */
void oc_chacha20_xor(uint8_t *out, const uint8_t *in, size_t length,
                     const uint8_t key[32], const uint8_t nonce[8], uint64_t counter);
void oc_poly1305(uint8_t tag[16], const void *data, size_t length, const uint8_t key[32]);
/* length bytes from a seed: ChaCha20's key stream, the label as nonce */
void oc_expand_seed(uint8_t *out, size_t length, const uint8_t seed[OC_SEED_BYTES],
                    const char label[8]);

/* AES-128/192/256 (FIPS 197), constant time. buf is changed in place;
 * iv is the IV (CBC) or the first counter block (CTR: a 128-bit big-endian
 * counter, SSH's SDCTR); the caller moves its IV or counter on itself.
 * CBC and ECB take whole blocks. 0, or -1 for a bad key length or mode. */
#define OC_AES_CTR 0
#define OC_AES_CBC_ENCRYPT 1
#define OC_AES_CBC_DECRYPT 2
#define OC_AES_ECB_ENCRYPT 3
int oc_aes(uint8_t *buf, size_t length, const uint8_t *key, size_t keylen,
           const uint8_t iv[16], int mode);

/* RSA (PKCS #1 v1.5 or anything else built on it): out = sig^e mod n, all
 * big-endian, out as long as n. Public values only: not constant time.
 * 0, or -1 when sig >= n, n is even or longer than OC_RSA_MAX_BYTES. */
#define OC_RSA_MAX_BYTES 1024
int oc_rsa_public(uint8_t *out, const uint8_t *sig, const uint8_t *n, size_t n_length,
                  const uint8_t *e, size_t e_length);

/* ECDSA verification on NIST P-256, P-384 and P-521 (curve = 256, 384,
 * 521): the public point and the signature's r and s as big-endian
 * integers of the curve's size ((bits + 7) / 8 bytes), the hash as it came
 * (truncated to the curve's size as FIPS 186 says). 1 when valid. */
int oc_ecdsa_verify(int curve, const uint8_t *qx, const uint8_t *qy,
                    const uint8_t *r, const uint8_t *s,
                    const uint8_t *hash, size_t hash_length);

/* What opencrypto.library's OC_Accelerated() answers: the operations this
 * machine runs as host code (AmigaChrome's AC090); 0 on a real Amiga. */
#define OCF_X25519    (1u << 0)
#define OCF_ED25519   (1u << 1)
#define OCF_SNTRUP761 (1u << 2)
#define OCF_SHA256    (1u << 3)
#define OCF_SHA512    (1u << 4)
#define OCF_CHACHA20  (1u << 5)
#define OCF_POLY1305  (1u << 6)
#define OCF_AES       (1u << 7)
#define OCF_RSA       (1u << 8)
#define OCF_ECDSA     (1u << 9)

int oc_ct_equal(const void *a, const void *b, size_t length);
void oc_cleanse(void *p, size_t length);

#ifdef __cplusplus
}
#endif

#endif
