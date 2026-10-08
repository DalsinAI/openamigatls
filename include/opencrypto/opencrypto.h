#ifndef OPENCRYPTO_OPENCRYPTO_H
#define OPENCRYPTO_OPENCRYPTO_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define OC_SHA256_BYTES 32
#define OC_SHA256_BLOCK_BYTES 64

typedef struct OCSHA256 {
    uint32_t h[8];
    uint64_t total_bytes;
    uint8_t block[OC_SHA256_BLOCK_BYTES];
    size_t block_used;
} OCSHA256;

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

int oc_ct_equal(const void *a, const void *b, size_t length);
void oc_cleanse(void *p, size_t length);

#ifdef __cplusplus
}
#endif

#endif
