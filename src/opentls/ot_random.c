/* OpenTLS: the random generator. HMAC-DRBG (SHA-256, BearSSL's), seeded
 * from the platform: on AmigaOS from the jitter between the E-clock and
 * the scheduler, sampled many times and hashed; in the host tests from
 * /dev/urandom. Fresh samples are mixed in at every call.
 * MIT licensed and free. Copyright (c) 2026 Dalsin Limited. */
#include "ot_internal.h"

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
static struct timerequest ot_timer;
static int ot_timer_open;

struct ot_sample {
    struct EClockVal clock;
    ULONG idle, dispatches, task, chip, fast, counter, spin;
    struct DateStamp date;
};

static void take_sample(struct ot_sample *s, ULONG counter)
{
    struct EClockVal start;
    ULONG spin = 0;
    memset(s, 0, sizeof *s);
    if (TimerBase) {
        /* spin until the E-clock moves: how far we get is the jitter */
        ReadEClock(&start);
        do {
            ReadEClock(&s->clock);
            ++spin;
        } while (s->clock.ev_lo == start.ev_lo && spin < 100000UL);
    }
    s->spin = spin;
    s->idle = SysBase->IdleCount;
    s->dispatches = SysBase->DispCount;
    s->task = (ULONG)FindTask(NULL);
    s->chip = AvailMem(MEMF_CHIP);
    s->fast = AvailMem(MEMF_FAST);
    s->counter = counter;
    if (DOSBase) DateStamp(&s->date);
}

static int gather(unsigned char out[32], int rounds)
{
    br_sha256_context h;
    struct ot_sample s;
    int i;
    if (!ot_timer_open) {
        if (OpenDevice((CONST_STRPTR)TIMERNAME, UNIT_ECLOCK, (struct IORequest *)&ot_timer, 0) == 0) {
            TimerBase = ot_timer.tr_node.io_Device;
            ot_timer_open = 1;
        }
    }
    br_sha256_init(&h);
    for (i = 0; i < rounds; ++i) {
        take_sample(&s, (ULONG)i);
        br_sha256_update(&h, &s, sizeof s);
    }
    br_sha256_out(&h, out);
    return TimerBase != NULL;
}

static void close_platform(void)
{
    if (ot_timer_open) {
        CloseDevice((struct IORequest *)&ot_timer);
        ot_timer_open = 0;
        TimerBase = NULL;
    }
}
#else
static int gather(unsigned char out[32], int rounds)
{
    (void)rounds;
    return ot_platform_entropy(out, 32);
}
static void close_platform(void) {}
#endif

static br_hmac_drbg_context ot_drbg;
static int ot_seeded;
static void *ot_rng_lock;
static unsigned long ot_calls;

int ot_random_init(void)
{
    if (!ot_rng_lock) ot_rng_lock = ot_lock_new();
    return ot_rng_lock != NULL;
}

void ot_random_cleanup(void)
{
    ot_lock(ot_rng_lock);
    memset(&ot_drbg, 0, sizeof ot_drbg);
    ot_seeded = 0;
    close_platform();
    ot_unlock(ot_rng_lock);
    ot_lock_free(ot_rng_lock);
    ot_rng_lock = NULL;
}

LONG ot_random(void *buf, size_t len)
{
    unsigned char seed[32];
    if (!buf && len) return OTERR_ARGS;
    if (!ot_rng_lock && !ot_random_init()) return OTERR_NOMEM;
    ot_lock(ot_rng_lock);
    if (!ot_seeded) {
        if (!gather(seed, 512)) {
            ot_unlock(ot_rng_lock);
            return OTERR_RANDOM;
        }
        br_hmac_drbg_init(&ot_drbg, &br_sha256_vtable, seed, sizeof seed);
        ot_seeded = 1;
    } else {
        /* a few fresh samples each time; the state carries the rest */
        gather(seed, 4);
        ++ot_calls;
        seed[0] ^= (unsigned char)ot_calls;
        seed[1] ^= (unsigned char)(ot_calls >> 8);
        seed[2] ^= (unsigned char)(ot_calls >> 16);
        seed[3] ^= (unsigned char)(ot_calls >> 24);
        br_hmac_drbg_update(&ot_drbg, seed, sizeof seed);
    }
    br_hmac_drbg_generate(&ot_drbg, buf, len);
    memset(seed, 0, sizeof seed);
    ot_unlock(ot_rng_lock);
    return OTERR_OK;
}
