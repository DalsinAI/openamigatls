/* opencrypto.library 2.0
 * Copyright (c) 2026 Dalsin Limited. MIT.
 *
 * Version 2 (8 Oct 2026) adds what SSH needs: X25519, sntrup761, Ed25519,
 * RSA and ECDSA verification, SHA-2 block runs, ChaCha20, Poly1305 and
 * AES. Each goes through a magic function (oc_magic.h): host code on
 * AmigaChrome, the 68k body elsewhere. */
#include <exec/types.h>
#include <exec/resident.h>
#include <exec/libraries.h>
#include <exec/execbase.h>
#include <exec/memory.h>
#include <dos/dos.h>
#include <proto/exec.h>

#include "../include/libraries/opencrypto.h"
#include "oc_magic.h"

#define REG(r, decl) register decl __asm(#r)
#define LIB_VERSION OPENCRYPTOLIB_VERSION
#define LIB_REVISION OPENCRYPTOLIB_REVISION

struct OpenCryptoLibBase {
    struct Library lib;
    BPTR seglist;
};

struct ExecBase *SysBase;

int start(void) { return -1; }

static const char lib_name[] = OPENCRYPTOLIB_NAME;
static const char lib_id[] =
    "opencrypto.library 2.0 (8.10.2026) OpenCrypto, Dalsin Limited\r\n";

static struct Library *lib_init(REG(d0, struct OpenCryptoLibBase *base),
                                REG(a0, BPTR seglist),
                                REG(a6, struct ExecBase *sys));
static struct Library *lib_open(REG(a6, struct OpenCryptoLibBase *base));
static BPTR lib_close(REG(a6, struct OpenCryptoLibBase *base));
static BPTR lib_expunge(REG(a6, struct OpenCryptoLibBase *base));
static ULONG lib_null(void);

static ULONG OC_Version(REG(a6, struct OpenCryptoLibBase *base));
static void OC_SHA256(REG(a0, struct OCBufferHash *r), REG(a6, struct OpenCryptoLibBase *base));
static void OC_SHA384(REG(a0, struct OCBufferHash *r), REG(a6, struct OpenCryptoLibBase *base));
static void OC_SHA512(REG(a0, struct OCBufferHash *r), REG(a6, struct OpenCryptoLibBase *base));
static void OC_HMAC_SHA256(REG(a0, struct OCHmacRequest *r), REG(a6, struct OpenCryptoLibBase *base));
static void OC_HMAC_SHA384(REG(a0, struct OCHmacRequest *r), REG(a6, struct OpenCryptoLibBase *base));
static LONG OC_HKDF_SHA256(REG(a0, struct OCHKDFRequest *r), REG(a6, struct OpenCryptoLibBase *base));
static LONG OC_HKDF_SHA384(REG(a0, struct OCHKDFRequest *r), REG(a6, struct OpenCryptoLibBase *base));
static LONG OC_CtEqual(REG(a0, struct OCCompareRequest *r), REG(a6, struct OpenCryptoLibBase *base));
static void OC_Cleanse(REG(a0, struct OCCleanseRequest *r), REG(a6, struct OpenCryptoLibBase *base));
static ULONG OC_Accelerated(REG(a6, struct OpenCryptoLibBase *base));
#define DECL(name, type) static LONG name(REG(a0, type *r), REG(a6, struct OpenCryptoLibBase *base))
DECL(OC_X25519, struct OCX25519Request);
DECL(OC_Ed25519Verify, struct OCEd25519Request);
DECL(OC_SNTRUP761KeyPair, struct OCKemRequest);
DECL(OC_SNTRUP761Enc, struct OCKemRequest);
DECL(OC_SNTRUP761Dec, struct OCKemRequest);
DECL(OC_SHA256Blocks, struct OCBlocksRequest);
DECL(OC_SHA512Blocks, struct OCBlocksRequest);
DECL(OC_ChaCha20, struct OCChaChaRequest);
DECL(OC_Poly1305, struct OCPolyRequest);
DECL(OC_AES, struct OCAESRequest);
DECL(OC_RSAPublic, struct OCRSARequest);
DECL(OC_ECDSAVerify, struct OCECDSARequest);

static const APTR lib_vectors[] = {
    (APTR)lib_open, (APTR)lib_close, (APTR)lib_expunge, (APTR)lib_null,
    (APTR)OC_Version,
    (APTR)OC_SHA256, (APTR)OC_SHA384, (APTR)OC_SHA512,
    (APTR)OC_HMAC_SHA256, (APTR)OC_HMAC_SHA384,
    (APTR)OC_HKDF_SHA256, (APTR)OC_HKDF_SHA384,
    (APTR)OC_CtEqual, (APTR)OC_Cleanse,
    (APTR)OC_Accelerated, (APTR)OC_X25519, (APTR)OC_Ed25519Verify,
    (APTR)OC_SNTRUP761KeyPair, (APTR)OC_SNTRUP761Enc, (APTR)OC_SNTRUP761Dec,
    (APTR)OC_SHA256Blocks, (APTR)OC_SHA512Blocks, (APTR)OC_ChaCha20, (APTR)OC_Poly1305,
    (APTR)OC_AES, (APTR)OC_RSAPublic, (APTR)OC_ECDSAVerify,
    (APTR)-1
};

static const struct {
    ULONG size;
    const APTR *vectors;
    APTR data;
    APTR init;
} lib_inittable = {
    sizeof(struct OpenCryptoLibBase), lib_vectors, NULL, (APTR)lib_init
};

const struct Resident lib_romtag = {
    RTC_MATCHWORD, (struct Resident *)&lib_romtag, (APTR)(&lib_romtag + 1),
    RTF_AUTOINIT, LIB_VERSION, NT_LIBRARY, 0,
    (char *)lib_name, (char *)lib_id, (APTR)&lib_inittable
};

static struct Library *lib_init(REG(d0, struct OpenCryptoLibBase *base),
                                REG(a0, BPTR seglist),
                                REG(a6, struct ExecBase *sys))
{
    SysBase = sys;
    base->seglist = seglist;
    base->lib.lib_Revision = LIB_REVISION;
    return &base->lib;
}

static struct Library *lib_open(REG(a6, struct OpenCryptoLibBase *base))
{
    base->lib.lib_OpenCnt++;
    base->lib.lib_Flags &= ~LIBF_DELEXP;
    return &base->lib;
}

static BPTR lib_close(REG(a6, struct OpenCryptoLibBase *base))
{
    base->lib.lib_OpenCnt--;
    if (base->lib.lib_OpenCnt == 0 && (base->lib.lib_Flags & LIBF_DELEXP))
        return lib_expunge(base);
    return 0;
}

static BPTR lib_expunge(REG(a6, struct OpenCryptoLibBase *base))
{
    BPTR seglist;
    if (base->lib.lib_OpenCnt) {
        base->lib.lib_Flags |= LIBF_DELEXP;
        return 0;
    }
    seglist = base->seglist;
    Remove(&base->lib.lib_Node);
    FreeMem((UBYTE *)base - base->lib.lib_NegSize,
            base->lib.lib_NegSize + base->lib.lib_PosSize);
    return seglist;
}

static ULONG lib_null(void) { return 0; }

static ULONG OC_Version(REG(a6, struct OpenCryptoLibBase *base))
{
    (void)base;
    return (OPENCRYPTOLIB_VERSION << 16) | OPENCRYPTOLIB_REVISION;
}

static void OC_SHA256(REG(a0, struct OCBufferHash *r), REG(a6, struct OpenCryptoLibBase *base))
{
    (void)base;
    if (r && r->out && (r->data || !r->length))
        oc_sha256(r->data, r->length, r->out);
}

static void OC_SHA384(REG(a0, struct OCBufferHash *r), REG(a6, struct OpenCryptoLibBase *base))
{
    (void)base;
    if (r && r->out && (r->data || !r->length))
        oc_sha384(r->data, r->length, r->out);
}

static void OC_SHA512(REG(a0, struct OCBufferHash *r), REG(a6, struct OpenCryptoLibBase *base))
{
    (void)base;
    if (r && r->out && (r->data || !r->length))
        oc_sha512(r->data, r->length, r->out);
}

static void OC_HMAC_SHA256(REG(a0, struct OCHmacRequest *r), REG(a6, struct OpenCryptoLibBase *base))
{
    (void)base;
    if (r && r->out && (r->key || !r->key_length) && (r->data || !r->data_length))
        oc_hmac_sha256(r->key, r->key_length, r->data, r->data_length, r->out);
}

static void OC_HMAC_SHA384(REG(a0, struct OCHmacRequest *r), REG(a6, struct OpenCryptoLibBase *base))
{
    (void)base;
    if (r && r->out && (r->key || !r->key_length) && (r->data || !r->data_length))
        oc_hmac_sha384(r->key, r->key_length, r->data, r->data_length, r->out);
}

static LONG OC_HKDF_SHA256(REG(a0, struct OCHKDFRequest *r), REG(a6, struct OpenCryptoLibBase *base))
{
    (void)base;
    if (!r) return -1;
    return (LONG)oc_hkdf_sha256(r->salt, r->salt_length, r->ikm, r->ikm_length,
                                r->info, r->info_length, r->out, r->out_length);
}

static LONG OC_HKDF_SHA384(REG(a0, struct OCHKDFRequest *r), REG(a6, struct OpenCryptoLibBase *base))
{
    (void)base;
    if (!r) return -1;
    return (LONG)oc_hkdf_sha384(r->salt, r->salt_length, r->ikm, r->ikm_length,
                                r->info, r->info_length, r->out, r->out_length);
}

static LONG OC_CtEqual(REG(a0, struct OCCompareRequest *r), REG(a6, struct OpenCryptoLibBase *base))
{
    (void)base;
    if (!r || (!r->a && r->length) || (!r->b && r->length))
        return 0;
    return oc_ct_equal(r->a, r->b, r->length) ? 1 : 0;
}

static void OC_Cleanse(REG(a0, struct OCCleanseRequest *r), REG(a6, struct OpenCryptoLibBase *base))
{
    (void)base;
    if (r && r->data)
        oc_cleanse(r->data, r->length);
}

/* ---- version 2 ---- */

/* the calling task's free stack, roughly: from here down to its bottom */
static int stack_ok(ULONG need)
{
    struct Task *t = FindTask(NULL);
    UBYTE here;
    ULONG lower = (ULONG)t->tc_SPLower;
    /* a process run from a Shell may be on its CLI's own stack */
    if ((ULONG)&here < lower || (ULONG)&here > (ULONG)t->tc_SPUpper)
        return 1;
    return (ULONG)&here - lower >= need;
}

static ULONG OC_Accelerated(REG(a6, struct OpenCryptoLibBase *base))
{
    (void)base;
    return ocm_probe();
}

DECL(OC_X25519, struct OCX25519Request)
{
    static const UBYTE nine[32] = { 9 };
    (void)base;
    if (!r || !r->out || !r->scalar) return OCERR_ARGS;
    return ocm_x25519(r->out, r->scalar, r->point ? r->point : nine);
}

DECL(OC_Ed25519Verify, struct OCEd25519Request)
{
    (void)base;
    if (!r || !r->sig || !r->pk || (!r->msg && r->length)) return 0;
    if (!stack_ok(8192)) return OCERR_STACK;
    return ocm_ed25519_verify(r->sig, r->pk, (const uint8_t *)r->msg, r->length);
}

DECL(OC_SNTRUP761KeyPair, struct OCKemRequest)
{
    UBYTE out[OC_SNTRUP761_PK_BYTES + OC_SNTRUP761_SK_BYTES];
    (void)base;
    if (!r || !r->pk || !r->sk || !r->seed) return OCERR_ARGS;
    if (!stack_ok(OC_STACK_NEEDED)) return OCERR_STACK;
    ocm_sntrup761_keypair(out, r->seed);
    CopyMem(out, r->pk, OC_SNTRUP761_PK_BYTES);
    CopyMem(out + OC_SNTRUP761_PK_BYTES, r->sk, OC_SNTRUP761_SK_BYTES);
    oc_cleanse(out, sizeof out);
    return 0;
}

DECL(OC_SNTRUP761Enc, struct OCKemRequest)
{
    UBYTE out[OC_SNTRUP761_CT_BYTES + OC_SNTRUP761_SS_BYTES];
    (void)base;
    if (!r || !r->pk || !r->ct || !r->ss || !r->seed) return OCERR_ARGS;
    if (!stack_ok(OC_STACK_NEEDED)) return OCERR_STACK;
    ocm_sntrup761_enc(out, r->pk, r->seed);
    CopyMem(out, r->ct, OC_SNTRUP761_CT_BYTES);
    CopyMem(out + OC_SNTRUP761_CT_BYTES, r->ss, OC_SNTRUP761_SS_BYTES);
    oc_cleanse(out, sizeof out);
    return 0;
}

DECL(OC_SNTRUP761Dec, struct OCKemRequest)
{
    (void)base;
    if (!r || !r->ss || !r->ct || !r->sk) return OCERR_ARGS;
    if (!stack_ok(OC_STACK_NEEDED)) return OCERR_STACK;
    return ocm_sntrup761_dec(r->ss, r->ct, r->sk);
}

DECL(OC_SHA256Blocks, struct OCBlocksRequest)
{
    (void)base;
    if (!r || !r->state || (!r->data && r->blocks)) return OCERR_ARGS;
    return r->blocks ? ocm_sha256_blocks(r->state, (const uint8_t *)r->data, r->blocks) : 0;
}

DECL(OC_SHA512Blocks, struct OCBlocksRequest)
{
    (void)base;
    if (!r || !r->state || (!r->data && r->blocks)) return OCERR_ARGS;
    return r->blocks ? ocm_sha512_blocks(r->state, (const uint8_t *)r->data, r->blocks) : 0;
}

DECL(OC_ChaCha20, struct OCChaChaRequest)
{
    UBYTE p[48];
    int i;
    (void)base;
    if (!r || !r->out || !r->key || !r->nonce) return OCERR_ARGS;
    CopyMem((APTR)r->key, p, 32);
    CopyMem((APTR)r->nonce, p + 32, 8);
    for (i = 0; i < 4; ++i) {
        p[40 + i] = (UBYTE)(r->counter_hi >> (24 - 8 * i));
        p[44 + i] = (UBYTE)(r->counter_lo >> (24 - 8 * i));
    }
    i = r->length ? ocm_chacha20(r->out, r->in, r->length, p) : 0;
    oc_cleanse(p, sizeof p);
    return i;
}

DECL(OC_Poly1305, struct OCPolyRequest)
{
    (void)base;
    if (!r || !r->tag || !r->key || (!r->data && r->length)) return OCERR_ARGS;
    return ocm_poly1305(r->tag, (const uint8_t *)r->data, r->length, r->key);
}

DECL(OC_AES, struct OCAESRequest)
{
    (void)base;
    if (!r || !r->buf || !r->key || !r->iv) return OCERR_ARGS;
    if (!r->length) return 0;
    return ocm_aes(r->buf, r->length, r->key, r->key_length, r->iv, r->mode) ? OCERR_ARGS : 0;
}

DECL(OC_RSAPublic, struct OCRSARequest)
{
    (void)base;
    if (!r || !r->out || !r->sig || !r->n || !r->e) return OCERR_ARGS;
    if (!stack_ok(16384)) return OCERR_STACK;
    return ocm_rsa_public(r->out, r->sig, r->n, r->n_length, r->e, r->e_length) ? OCERR_ARGS : 0;
}

DECL(OC_ECDSAVerify, struct OCECDSARequest)
{
    (void)base;
    if (!r || !r->qx || !r->qy || !r->r || !r->s || !r->hash) return 0;
    if (!stack_ok(8192)) return OCERR_STACK;
    return ocm_ecdsa_verify(r->curve, r->qx, r->qy, r->r, r->s, r->hash, r->hash_length);
}
