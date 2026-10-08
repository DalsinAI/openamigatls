/* opencrypto.library 1.0
 * Copyright (c) 2026 Dalsin Limited. MIT.
 */
#include <exec/types.h>
#include <exec/resident.h>
#include <exec/libraries.h>
#include <exec/execbase.h>
#include <exec/memory.h>
#include <proto/exec.h>

#include "../include/libraries/opencrypto.h"

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
    "opencrypto.library 1.0 (8.10.2026) OpenCrypto, Dalsin Limited\r\n";

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

static const APTR lib_vectors[] = {
    (APTR)lib_open, (APTR)lib_close, (APTR)lib_expunge, (APTR)lib_null,
    (APTR)OC_Version,
    (APTR)OC_SHA256, (APTR)OC_SHA384, (APTR)OC_SHA512,
    (APTR)OC_HMAC_SHA256, (APTR)OC_HMAC_SHA384,
    (APTR)OC_HKDF_SHA256, (APTR)OC_HKDF_SHA384,
    (APTR)OC_CtEqual, (APTR)OC_Cleanse,
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
