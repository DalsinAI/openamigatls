#include "opentls/opentls.h"
#include "opencrypto/opencrypto.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#ifdef __amigaos__
#include <exec/execbase.h>
#include <exec/memory.h>
#include <devices/timer.h>
#include <dos/dos.h>
#include <proto/exec.h>
#include <proto/dos.h>
#include <proto/timer.h>

extern struct ExecBase *SysBase;
extern struct DosLibrary *DOSBase;
struct Device *TimerBase;
static struct timerequest ot_timer_request;
static uint8_t ot_pool[32];
static ULONG ot_stirs;

static void ot_stir(void)
{
    struct {
        struct EClockVal clock;
        ULONG idle, dispatches, task, free_mem, stirs;
        struct DateStamp date;
        uint8_t pool[32];
    } sample;
    memset(&sample, 0, sizeof sample);
    if (!TimerBase && !OpenDevice((CONST_STRPTR)TIMERNAME, UNIT_ECLOCK,
                                     (struct IORequest *)&ot_timer_request, 0))
        TimerBase = ot_timer_request.tr_node.io_Device;
    if (TimerBase)
        ReadEClock(&sample.clock);
    sample.idle = SysBase ? SysBase->IdleCount : 0;
    sample.dispatches = SysBase ? SysBase->DispCount : 0;
    sample.task = (ULONG)FindTask(NULL);
    sample.free_mem = AvailMem(MEMF_ANY);
    sample.stirs = ++ot_stirs;
    if (DOSBase)
        DateStamp(&sample.date);
    memcpy(sample.pool, ot_pool, sizeof ot_pool);
    oc_sha256(&sample, sizeof sample, ot_pool);
    oc_cleanse(&sample, sizeof sample);
}

int ot_random_bytes(void *buffer, size_t length)
{
    uint8_t *out = (uint8_t *)buffer;
    uint8_t block[32];
    uint8_t seed[40];
    ULONG counter = 0;
    int i;
    if (!out && length) return OT_ERR_ARGUMENT;
    ot_stir();
    /* Initial key-grade seed: collect scheduler/E-clock jitter across frames. */
    if (ot_stirs < 2) {
        for (i = 0; i < 64; ++i) {
            Delay(1);
            ot_stir();
        }
    }
    while (length) {
        size_t n = length < sizeof block ? length : sizeof block;
        struct EClockVal clock;
        memset(&clock, 0, sizeof clock);
        if (TimerBase) ReadEClock(&clock);
        memcpy(seed, ot_pool, 32);
        memcpy(seed + 32, &counter, 4);
        memcpy(seed + 36, &clock.ev_lo, 4);
        oc_sha256(seed, sizeof seed, block);
        memcpy(out, block, n);
        out += n;
        length -= n;
        counter++;
        /* Backtracking resistance: evolve the pool after every emitted block. */
        oc_sha256(block, sizeof block, ot_pool);
    }
    ot_stir();
    oc_cleanse(block, sizeof block);
    oc_cleanse(seed, sizeof seed);
    return OT_OK;
}
#else
int ot_random_bytes(void *buffer, size_t length)
{
    FILE *f;
    unsigned char *p = (unsigned char *)buffer;
    size_t n;
    if (!p && length) return OT_ERR_ARGUMENT;
    f = fopen("/dev/urandom", "rb");
    if (!f) return OT_ERR_RANDOM;
    while (length) {
        n = fread(p, 1, length, f);
        if (!n) { fclose(f); return OT_ERR_RANDOM; }
        p += n;
        length -= n;
    }
    fclose(f);
    return OT_OK;
}
#endif

int opentls_wolf_seed(unsigned char *buffer, unsigned int length)
{
    return ot_random_bytes(buffer, (size_t)length) == OT_OK ? 0 : -1;
}
