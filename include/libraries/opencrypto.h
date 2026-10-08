#ifndef LIBRARIES_OPENCRYPTO_H
#define LIBRARIES_OPENCRYPTO_H

#include <exec/types.h>
#include <opencrypto/opencrypto.h>

#define OPENCRYPTOLIB_NAME "opencrypto.library"
#define OPENCRYPTOLIB_VERSION 2
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

/* ---- version 2 (8 Oct 2026): SSH's key exchanges, host keys and ciphers ----
 * Each call answers 0 when done (or 1/0 for a verification) and a
 * negative number when it refused: OCERR_ARGS for bad sizes or a NULL
 * pointer, OCERR_STACK when the calling task has less stack free than the
 * operation needs (OC_STACK_NEEDED: sntrup761 builds its polynomials on
 * the stack, so that several tasks can call at once). OC_Accelerated()
 * says which operations this machine runs as host code (OCF_*, in
 * <opencrypto/opencrypto.h>): on AmigaChrome all of them, on a real Amiga
 * none, where every call runs as 68k code. */
#define OCERR_ARGS (-1)
#define OCERR_STACK (-2)
#define OC_STACK_NEEDED 32768

struct OCX25519Request {          /* out = scalar * point; point NULL: the base point (9) */
    UBYTE *out;                   /* 32 bytes */
    const UBYTE *scalar;          /* 32 bytes */
    const UBYTE *point;           /* 32 bytes or NULL */
};                                /* 0; -1 for an all-zero result (refuse it) */

struct OCEd25519Request {
    const UBYTE *sig;             /* 64 bytes */
    const UBYTE *pk;              /* 32 bytes */
    const void *msg;
    ULONG length;
};                                /* 1 valid, 0 not */

struct OCKemRequest {             /* sntrup761 */
    UBYTE *pk;                    /* 1158 bytes: KeyPair's output, Enc's input */
    UBYTE *sk;                    /* 1763 bytes: KeyPair's output, Dec's input */
    UBYTE *ct;                    /* 1039 bytes: Enc's output, Dec's input */
    UBYTE *ss;                    /* 32 bytes: Enc's and Dec's output */
    const UBYTE *seed;            /* 32 fresh secret random bytes (KeyPair, Enc) */
};

struct OCBlocksRequest {          /* SHA-256 (64-byte blocks) or SHA-512 (128) */
    UBYTE *state;                 /* 32 or 64 bytes, big-endian; changed */
    const void *data;
    ULONG blocks;
};

struct OCChaChaRequest {          /* ChaCha20, 64-bit nonce and counter */
    UBYTE *out;
    const UBYTE *in;              /* may be out; NULL for the key stream */
    ULONG length;
    const UBYTE *key;             /* 32 bytes */
    const UBYTE *nonce;           /* 8 bytes */
    ULONG counter_hi, counter_lo; /* the first block's number */
};

struct OCPolyRequest {
    UBYTE *tag;                   /* 16 bytes */
    const void *data;
    ULONG length;
    const UBYTE *key;             /* 32 bytes, once only */
};

struct OCAESRequest {
    UBYTE *buf;                   /* changed in place */
    ULONG length;                 /* CBC, ECB: whole blocks */
    const UBYTE *key;
    ULONG key_length;             /* 16, 24 or 32 */
    const UBYTE *iv;              /* 16 bytes: the IV or the first counter block */
    ULONG mode;                   /* OC_AES_CTR, _CBC_ENCRYPT, _CBC_DECRYPT, _ECB_ENCRYPT */
};

struct OCRSARequest {             /* out = sig^e mod n, big-endian */
    UBYTE *out;                   /* n_length bytes */
    const UBYTE *sig;             /* n_length bytes */
    const UBYTE *n;
    ULONG n_length;               /* up to OC_RSA_MAX_BYTES */
    const UBYTE *e;
    ULONG e_length;
};

struct OCECDSARequest {
    LONG curve;                   /* 256, 384 or 521 */
    const UBYTE *qx, *qy, *r, *s; /* (curve + 7) / 8 bytes each, big-endian */
    const UBYTE *hash;
    ULONG hash_length;
};                                /* 1 valid, 0 not */

#endif
