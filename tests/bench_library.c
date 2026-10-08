/* OpenCryptoBench: opencrypto.library 2's operations, checked and timed on
 * the Amiga. Prints which run as host code (OC_Accelerated), then for each
 * operation a check against a fixed answer and its time.
 *   OpenCryptoBench [ROUNDS]
 * Copyright (c) 2026 Dalsin Limited. MIT. */
#include <exec/types.h>
#include <exec/libraries.h>
#include <devices/timer.h>
#include <proto/exec.h>
#include <proto/timer.h>
#include <proto/opencrypto.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct Library *OpenCryptoBase;
struct Device *TimerBase;
static struct timerequest treq;

/* microseconds (only differences matter), from the E clock */
static ULONG now(void)
{
    struct EClockVal ev;
    ULONG freq = ReadEClock(&ev);
    unsigned long long t = ((unsigned long long)ev.ev_hi << 32) | ev.ev_lo;
    return (ULONG)(t * 1000000ULL / freq);
}

static void unhex(UBYTE *out, const char *s)
{
    size_t i, n = strlen(s) / 2;
    for (i = 0; i < n; ++i) {
        unsigned v;
        sscanf(s + 2 * i, "%2x", &v);
        out[i] = (UBYTE)v;
    }
}

static int fails;
static void report(const char *what, int ok, ULONG us, int n)
{
    ULONG each = us / (ULONG)n;
    printf("%-34s %s  %6lu.%03lu ms each\n", what, ok ? "ok  " : "FAIL", (unsigned long)(each / 1000), (unsigned long)(each % 1000));
    if (!ok) ++fails;
}

int main(int argc, char **argv)
{
    static UBYTE pk[OC_SNTRUP761_PK_BYTES], sk[OC_SNTRUP761_SK_BYTES], ct[OC_SNTRUP761_CT_BYTES];
    static UBYTE buf[16384];
    UBYTE out[64], k[32], u[32], ss[32], ss2[32], seed[32], sig[64], epk[32], st[64];
    int n = argc > 1 ? atoi(argv[1]) : 3, i;
    ULONG acc;
    ULONG t;

    setvbuf(stdout, NULL, _IONBF, 0);   /* each line as it comes: a hang shows where */
    if (OpenDevice((CONST_STRPTR)TIMERNAME, UNIT_MICROHZ, (struct IORequest *)&treq, 0)) return 20;
    TimerBase = treq.tr_node.io_Device;
    OpenCryptoBase = OpenLibrary((CONST_STRPTR)OPENCRYPTOLIB_NAME, 2);
    if (!OpenCryptoBase) {
        puts("OpenCryptoBench: no opencrypto.library 2");
        CloseDevice((struct IORequest *)&treq);
        return 20;
    }
    acc = OC_Accelerated();
    printf("opencrypto.library %u.%u; host code (AC090) for: %s%s%s%s%s%s%s%s%s%s%s\n",
           (unsigned)OpenCryptoBase->lib_Version, (unsigned)OpenCryptoBase->lib_Revision,
           acc ? "" : "nothing (68k code)",
           acc & OCF_X25519 ? "X25519 " : "", acc & OCF_SNTRUP761 ? "sntrup761 " : "",
           acc & OCF_ED25519 ? "Ed25519 " : "", acc & OCF_ECDSA ? "ECDSA " : "",
           acc & OCF_RSA ? "RSA " : "", acc & OCF_SHA256 ? "SHA-256 " : "",
           acc & OCF_SHA512 ? "SHA-512 " : "", acc & OCF_AES ? "AES " : "",
           acc & OCF_CHACHA20 ? "ChaCha20 " : "", acc & OCF_POLY1305 ? "Poly1305" : "");

    {   /* X25519, RFC 7748 6.1 */
        struct OCX25519Request x;
        unhex(k, "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        x.out = out; x.scalar = k; x.point = NULL;
        t = now();
        for (i = 0; i < n; ++i) OC_X25519(&x);
        t = now() - t;
        unhex(u, "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
        report("X25519 (RFC 7748 6.1)", !memcmp(out, u, 32), t, n);
    }
    {   /* Ed25519, RFC 8032 test 1 */
        struct OCEd25519Request e;
        int ok = 1;
        unhex(epk, "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        unhex(sig, "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");
        e.sig = sig; e.pk = epk; e.msg = ""; e.length = 0;
        t = now();
        for (i = 0; i < n; ++i) ok &= OC_Ed25519Verify(&e) == 1;
        t = now() - t;
        sig[3] ^= 1;
        ok &= OC_Ed25519Verify(&e) == 0;
        report("Ed25519 verify (RFC 8032 test 1)", ok, t, n);
    }
    {   /* sntrup761: the known answer of test_ssh_primitives.c, then timings */
        struct OCKemRequest q;
        OCSHA256 hc;
        UBYTE h[32], want[32];
        ULONG tk, te, td;
        for (i = 0; i < 32; ++i) seed[i] = (UBYTE)i;
        q.pk = pk; q.sk = sk; q.ct = ct; q.ss = ss; q.seed = seed;
        tk = now(); i = (int)OC_SNTRUP761KeyPair(&q); tk = now() - tk;
        if (i) printf("sntrup761 key pair refused: %d\n", i);
        seed[0] ^= 0x80;
        te = now(); OC_SNTRUP761Enc(&q); te = now() - te;
        q.ss = ss2;
        td = now(); OC_SNTRUP761Dec(&q); td = now() - td;
        oc_sha256_init(&hc);
        oc_sha256_update(&hc, pk, sizeof pk);
        oc_sha256_update(&hc, sk, sizeof sk);
        oc_sha256_update(&hc, ct, sizeof ct);
        oc_sha256_update(&hc, ss, sizeof ss);
        oc_sha256_final(&hc, h);
        unhex(want, "3cd67f3b59ab9c4916563f5bd821f3f86273cd6772f42482afefd789d611b9f2");
        report("sntrup761 key pair (known answer)", !memcmp(h, want, 32), tk, 1);
        report("sntrup761 encapsulation", !memcmp(h, want, 32), te, 1);
        report("sntrup761 decapsulation", !memcmp(ss, ss2, 32), td, 1);
    }
    {   /* SHA-256 and SHA-512 over 16 KB of blocks */
        struct OCBlocksRequest b;
        for (i = 0; i < (int)sizeof buf; ++i) buf[i] = (UBYTE)i;
        memset(st, 0, sizeof st);
        b.state = st; b.data = buf; b.blocks = sizeof buf / 64;
        t = now(); OC_SHA256Blocks(&b); t = now() - t;
        report("SHA-256, 16 KB", 1, t, 1);
        b.blocks = sizeof buf / 128;
        t = now(); OC_SHA512Blocks(&b); t = now() - t;
        report("SHA-512, 16 KB", 1, t, 1);
    }
    {   /* AES-256-CTR and ChaCha20 over 16 KB, round trips */
        struct OCAESRequest a;
        struct OCChaChaRequest c;
        int ok;
        memset(k, 7, 32);
        memset(u, 9, 16);
        a.buf = buf; a.length = sizeof buf; a.key = k; a.key_length = 32; a.iv = u; a.mode = OC_AES_CTR;
        t = now(); OC_AES(&a); t = now() - t;
        OC_AES(&a);
        ok = buf[1000] == (UBYTE)1000 && buf[16383] == (UBYTE)16383;
        report("AES-256-CTR, 16 KB", ok, t, 1);
        c.out = buf; c.in = buf; c.length = sizeof buf; c.key = k; c.nonce = u; c.counter_hi = 0; c.counter_lo = 1;
        t = now(); OC_ChaCha20(&c); t = now() - t;
        OC_ChaCha20(&c);
        ok = buf[1000] == (UBYTE)1000 && buf[16383] == (UBYTE)16383;
        report("ChaCha20, 16 KB", ok, t, 1);
    }
    printf("OpenCryptoBench: %s\n", fails ? "FAILED" : "all checks passed");
    CloseLibrary(OpenCryptoBase);
    CloseDevice((struct IORequest *)&treq);
    return fails ? 20 : 0;
}
